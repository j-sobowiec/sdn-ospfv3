"""A02: differential contract tests of topology vs frozen C07 production snapshot.

No Containernet or Docker is started here: all network commands and FRR file contents
are captured as ordered events; the actual topology must still be tested in Ubuntu.
"""

import ast
import inspect
import os
from pathlib import Path
import random
import shlex
import unittest


TESTS = Path(__file__).resolve().parent
BASE = TESTS.parent
OLD = TESTS / "_a02_topology_reference.py"
NEW = BASE / "topology.py"
ALLOWED = {"make_frr_config", "main"}


class SimulatedFailure(RuntimeError):
    pass


class OvsSwitch:
    pass


class RemoteController:
    pass


def _load(source):
    """Execute real source AST minus unavailable Mininet import statements."""
    tree = ast.parse(source, filename="topology.py")
    tree.body = [n for n in tree.body
                 if not (isinstance(n, ast.ImportFrom) and n.module.startswith("mininet."))]
    ast.fix_missing_locations(tree)
    scope = {"__name__": "a02_test_topology",
             "OVSSwitch": OvsSwitch, "RemoteController": RemoteController}
    exec(compile(tree, "topology.py", "exec"), scope)
    return scope


def _simulate(source, *, wait=True, startup="started\n", sockets="zebra.vty ospf6d.vty",
              fail_on=None):
    scope = _load(source)
    events = []

    def event(*value):
        events.append(value)
        if fail_on == value[0] or (isinstance(fail_on, str) and
                                   len(value) >= 3 and isinstance(value[-1], str) and
                                   fail_on in value[-1]):
            raise SimulatedFailure(f"injected failure at {value[0]}")

    class Node:
        def __init__(self, name):
            self.name = name

        def cmd(self, command):
            event("cmd", self.name, command)
            if command == "cat /tmp/frr-start.log 2>/dev/null":
                return startup
            if command == "ls /run/frr/*.vty 2>/dev/null":
                return sockets
            if command == "ovs-vsctl get-controller s1":
                return "tcp:127.0.0.1:6653"
            if command == "ovs-ofctl -O OpenFlow13 dump-flows s1":
                return "OFPST_FLOW reply"
            return ""

    class Net:
        def __init__(self, **kwargs):
            event("net_ctor", kwargs)

        def addController(self, name, **kwargs):
            event("controller", name, kwargs)
            return Node(name)

        def addDocker(self, name, **kwargs):
            event("docker", name, kwargs)
            return Node(name)

        def addSwitch(self, name, **kwargs):
            event("switch", name, kwargs)
            return Node(name)

        def addHost(self, name, **kwargs):
            event("host", name, kwargs)
            return Node(name)

        def addLink(self, left, right, **kwargs):
            event("link", left.name, right.name, kwargs)

        def start(self):
            event("start")

        def waitConnected(self, **kwargs):
            event("wait_connected", kwargs)
            return wait

        def stop(self):
            event("stop")

    scope["Containernet"] = Net
    scope["info"] = lambda msg: event("info", msg)
    scope["CLI"] = lambda net: event("CLI")
    scope["time"] = type("FakeTime", (), {"sleep": staticmethod(lambda seconds: event("sleep", seconds))})
    try:
        scope["main"]()
        outcome = ("ok",)
    except Exception as exc:
        outcome = (type(exc).__name__, str(exc))
    return events, outcome


class TestA02TopologyEquivalence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_source = OLD.read_text(encoding="utf8")
        cls.new_source = NEW.read_text(encoding="utf8")
        cls.original = _load(cls.old_source)
        cls.current = _load(cls.new_source)

    def assert_traces_identical(self, **kwargs):
        old_events, old_result = _simulate(self.old_source, **kwargs)
        new_events, new_result = _simulate(self.new_source, **kwargs)
        self.assertEqual(old_result, new_result)
        self.assertEqual(old_events, new_events)
        return new_events

    def test_reference_is_production_topology(self):
        self.assertIn("def make_frr_config", self.old_source)
        self.assertIn("def main", self.old_source)
        self.assertNotEqual(self.old_source, self.new_source)

    def test_public_function_signatures_and_docs(self):
        for name in ("write_file", "make_frr_config", "configure_router", "start_frr", "main"):
            with self.subTest(name=name):
                a, b = self.original[name], self.current[name]
                self.assertEqual(inspect.signature(a), inspect.signature(b))
                self.assertEqual(a.__doc__, b.__doc__)
        self.assertEqual(self.original["DAEMONS"], self.current["DAEMONS"])
        self.assertEqual(self.original["FRR_IMAGE"], self.current["FRR_IMAGE"])

    def test_no_unrelated_ast_changes(self):
        """Freeze every global constant and function besides the two scoped edits."""
        def scoped(source):
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.FunctionDef) and node.name in ALLOWED:
                    node.body = [ast.Pass()]
            return ast.dump(tree, include_attributes=False)
        self.assertEqual(scoped(self.old_source), scoped(self.new_source))

    def test_frr_config_golden_default_text(self):
        a = self.current["make_frr_config"](
            "r1", "1.1.1.1", ("r1-eth0", "r1-eth1", "r1-eth2"))
        self.assertEqual(a, self.original["make_frr_config"](
            "r1", "1.1.1.1", ("r1-eth0", "r1-eth1", "r1-eth2")))
        self.assertEqual(a.count(" ipv6 ospf6 network point-to-point\n"), 3)
        self.assertIn(" ospf6 router-id 1.1.1.1\n", a)
        self.assertEqual(a[-1], "\n")

    def test_frr_config_mixed_active_and_passive_order(self):
        args = ("test", "1.2.3.4", ("eth2", "eth1"), ("eth4", "eth3"))
        before = self.original["make_frr_config"](*args)
        after = self.current["make_frr_config"](*args)
        self.assertEqual(before.encode(), after.encode())
        self.assertLess(after.index("interface eth2"), after.index("interface eth1"))
        self.assertLess(after.index("interface eth1"), after.index("interface eth4"))
        self.assertLess(after.index("interface eth4"), after.index("interface eth3"))
        self.assertEqual(after.count(" ipv6 ospf6 passive\n"), 2)

    def test_frr_config_empty_and_duplicates(self):
        for active, passive in (((), ()), (("x", "x"), ()), ((), ("x", "x")),
                                (("x",), ("x",)), (("%", "é"), ("*",))):
            with self.subTest(active=active, passive=passive):
                before = self.original["make_frr_config"]("host", "0.0.0.0", active, passive)
                after = self.current["make_frr_config"]("host", "0.0.0.0", active, passive)
                self.assertEqual(before.encode(), after.encode())

    def test_frr_config_generators_consumption(self):
        def trace(f):
            actions = []
            def gen(label):
                for item in (label + "1", label + "2"):
                    actions.append(item)
                    yield item
            return f("test", "1.1.1.1", gen("a"), gen("p")), actions
        self.assertEqual(trace(self.original["make_frr_config"]),
                         trace(self.current["make_frr_config"]))

    def test_randomized_frr_configuration_equivalence(self):
        rng = random.Random(20261019)
        items = ["eth0", "eth1", "eth2", "r1-eth0", "ipv6-étude", "!"]
        for _ in range(5000):
            active = rng.choices(items, k=rng.randrange(7))
            passive = rng.choices(items, k=rng.randrange(5))
            args = (rng.choice(["r1", "r2", "r3", "space in name"]),
                    rng.choice(["1.1.1.1", "2.2.2.2", "0.0.0.0"]), active, passive)
            self.assertEqual(self.original["make_frr_config"](*args).encode(),
                             self.current["make_frr_config"](*args).encode())

    def test_exact_full_network_startup_event_order(self):
        events = self.assert_traces_identical()
        links = [e for e in events if e[0] == "link"]
        self.assertEqual([(x[1], x[2]) for x in links],
                         [("r1", "r2"), ("r2", "r3"), ("r3", "r1"),
                          ("r1", "s1"), ("s1", "h1")])
        self.assertEqual(sum(x[0] == "sleep" for x in events), 3)
        self.assertEqual(events[-3][0], "CLI")
        self.assertEqual(events[-2], ("info", "Stopping network\n"))
        self.assertEqual(events[-1][0], "stop")

    def test_exact_three_router_frr_files(self):
        events = self.assert_traces_identical()
        configs = [e for e in events if e[0] == "cmd" and
                   e[-1].startswith("printf '%s' ") and
                   e[-1].endswith("> /etc/frr/frr.conf")]
        self.assertEqual([c[1] for c in configs], ["r1", "r2", "r3"])
        for router, rid in zip(("r1", "r2", "r3"), ("1.1.1.1", "2.2.2.2", "3.3.3.3")):
            cmd = next(c[-1] for c in configs if c[1] == router)
            self.assertIn(f"ospf6 router-id {rid}", cmd)

    def test_host_gateway_and_interface_addresses(self):
        events = self.assert_traces_identical()
        commands = [(e[1], e[2]) for e in events if e[0] == "cmd"]
        self.assertIn(("h1", "ip -6 route replace default via 2001:db8:1::1 dev h1-eth0"), commands)
        addresses = {
            "r1": (("r1-eth0", "2001:db8:12::1/64"), ("r1-eth1", "2001:db8:31::1/64"),
                   ("r1-eth2", "2001:db8:10::1/64")),
            "r2": (("r2-eth0", "2001:db8:12::2/64"), ("r2-eth1", "2001:db8:23::2/64")),
            "r3": (("r3-eth0", "2001:db8:23::3/64"), ("r3-eth1", "2001:db8:31::3/64")),
        }
        for router, pairs in addresses.items():
            for interface, address in pairs:
                self.assertIn((router, f"ip -6 addr replace {address} dev {interface}"), commands)

    def test_switch_protocol_flags_and_docker_capabilities(self):
        events = self.assert_traces_identical()
        switch = next(e for e in events if e[0] == "switch")
        self.assertEqual(switch[2]["protocols"], "OpenFlow13")
        self.assertEqual(switch[2]["failMode"], "secure")
        self.assertEqual(switch[2]["dpid"], "0000000000000001")
        self.assertEqual([e[1] for e in events if e[0] == "docker"], ["r1", "r2", "r3"])
        for docker in (e for e in events if e[0] == "docker"):
            self.assertEqual(docker[2]["cap_add"], ["net_admin", "net_raw", "sys_admin"])
            self.assertEqual(docker[2]["sysctls"]["net.ipv6.conf.all.forwarding"], "1")

    def test_switch_connection_timeout_cleanup_order(self):
        events = self.assert_traces_identical(wait=False)
        self.assertEqual(events[-1][0], "stop")
        self.assertFalse(any(e[0] == "CLI" for e in events))
        self.assertFalse(any(e[0] == "sleep" for e in events))

    def test_missing_vty_and_nonempty_startup_output(self):
        events = self.assert_traces_identical(sockets="zebra.vty", startup="warning from FRR\n")
        self.assertEqual(sum(e[0] == "info" and "WARNING: no VTY" in e[1]
                             for e in events), 3)
        self.assertEqual(sum(e[0] == "info" and "warning from FRR" in e[1]
                             for e in events), 3)

    def test_failure_cleanup_and_exception_order(self):
        cases = ("docker", "start", "CLI", "ip -6 addr replace 2001:db8:23::2/64",
                 "ip -6 addr replace 2001:db8:1::100/64",
                 "cat /tmp/frr-start.log", "ls /run/frr/*.vty")
        for fail in cases:
            with self.subTest(fail=fail):
                events = self.assert_traces_identical(fail_on=fail)
                self.assertEqual(events[-1][0], "stop")

    def test_randomized_full_trace(self):
        rng = random.Random(70104)
        for _ in range(250):
            self.assert_traces_identical(
                wait=rng.choice((True, True, True, False)),
                startup=rng.choice(("", "ok\n", "some error text\n")),
                sockets=rng.choice(("zebra.vty ospf6d.vty", "zebra.vty", "", "ospf6d.vty")))


if __name__ == "__main__":
    unittest.main()
