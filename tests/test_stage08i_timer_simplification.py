"""08I: exact source pins and old/new timer side-effect equivalence.

Tests execute isolated timer mixins with a deterministic clock and hub;
no Ryu, Scapy, Mininet, network privileges, or actual sleeps are needed.
"""

import ast
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "tests/_stage08i_timers_reference.py"
NEW = ROOT / "ospfv3/controller_timers.py"
EXPECTED_OLD = "0da0daf65c0dab5a410eaa98c3bc05f616734738f04aad112e90ac3a5cec2423"
EXPECTED_NEW = "d56470416af29d3474a06f7b6d74fde7dc5d6c92b0a4ec91ef4c881d52fd3fc4"


class EndLoop(Exception):
    pass


class Hub:
    def __init__(self, events, steps):
        self.events, self.steps, self.calls = events, steps, 0

    def sleep(self, seconds):
        self.calls += 1
        self.events.append(("sleep", seconds))
        if self.calls > self.steps:
            raise EndLoop()


class Clock:
    def __init__(self, events, now):
        self.events, self.now = events, now

    def monotonic(self):
        self.events.append(("monotonic",))
        return self.now


class Logger:
    def __init__(self, events):
        self.events = events

    def info(self, *args):
        self.events.append(("info", args))

    def warning(self, *args):
        self.events.append(("warning", args))


class Neighbor:
    def __init__(self, events, dead, exchanged, requests):
        self.events, self.dead, self.dbd_exchange_complete = events, dead, exchanged
        self.request_list, self.port, self.router_id = requests, 1, "1.1.1.1"

    def dead_interval_expired(self, interval):
        self.events.append(("expired", interval))
        return self.dead

    def reset_adjacency(self):
        self.events.append(("reset_adjacency",))


class LSDB:
    def __init__(self, events, populated=True, purge=True):
        self.events, self.populated, self.purge = events, populated, purge

    def __bool__(self):
        return self.populated

    def clear_remote(self, router):
        self.events.append(("clear_remote", router))

    def purge_expired(self):
        self.events.append(("purge_expired",))
        return self.purge


class LocalLSA:
    def __init__(self, items):
        self.items = items

    def __bool__(self):
        return bool(self.items)

    def values(self):
        return self.items


def build(path, scenario):
    events = []
    hub = Hub(events, scenario.get("steps", 1))
    clock = Clock(events, scenario.get("now", 100.0))
    cfg = SimpleNamespace(HELLO_INTERVAL=10, DEAD_INTERVAL=40,
                          RETRANSMIT_INTERVAL=5, LS_REFRESH_TIME=60,
                          ROUTER_ID="10.10.10.10")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == "OSPFTimerMixin")
    module = ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[]))
    scope = {"hub": hub, "time": clock, "cfg": cfg}
    exec(compile(module, str(path), "exec"), scope)
    controller = scope["OSPFTimerMixin"]()
    controller.logger = Logger(events)
    controller.datapath = object() if scenario.get("datapath", True) else None
    controller.neighbor = Neighbor(events, scenario.get("dead", False),
                                   scenario.get("exchanged", True),
                                   scenario.get("requests", []))
    controller.lsdb = LSDB(events, purge=scenario.get("purge", True))
    controller.local_lsa = LocalLSA(scenario.get("lsas", [{"_originated_at": 0}]))
    controller.local_lsa_ack_pending = scenario.get("pending", {})
    controller.local_lsu_last_tx = scenario.get("last_tx", 90.0)
    controller.local_lsu_sent = True
    controller.data_plane = SimpleNamespace(
        reset_transit=lambda: events.append(("reset_transit",)))
    controller.send_ospfv3_hello = lambda: events.append(("send_hello",))
    controller.withdraw_all_ipv6_host_flows = lambda: events.append(("withdraw",))
    controller.send_local_lsa_retransmission = lambda: events.append(("retransmit",))
    controller.reoriginate_local_lsas = lambda reason: events.append(("reoriginate", reason))
    return controller, events


def replay(path, method, scenario):
    controller, events = build(path, scenario)
    with unittest.TestCase().assertRaises(EndLoop):
        getattr(controller, method)()
    return (events, controller.local_lsa_ack_pending,
            controller.local_lsu_last_tx, controller.local_lsu_sent)


class Stage08ITimerContract(unittest.TestCase):
    def test_exact_sources_and_actual_reduction(self):
        self.assertEqual(hashlib.sha256(OLD.read_bytes()).hexdigest(), EXPECTED_OLD)
        self.assertEqual(hashlib.sha256(NEW.read_bytes()).hexdigest(), EXPECTED_NEW)
        self.assertGreaterEqual(len(OLD.read_text().splitlines()) -
                                len(NEW.read_text().splitlines()), 20)

    def test_public_timers_and_signatures_preserved(self):
        def methods(path):
            tree = ast.parse(path.read_text())
            cls = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                       and n.name == "OSPFTimerMixin")
            return {n.name: [a.arg for a in n.args.args]
                    for n in cls.body if isinstance(n, ast.FunctionDef)}
        self.assertEqual(methods(OLD), methods(NEW))

    def test_old_and_new_side_effects_match(self):
        cases = (
            ("hello_loop", {}),
            ("hello_loop", {"datapath": False}),
            ("neighbor_dead_loop", {"dead": True}),
            ("neighbor_dead_loop", {"dead": False}),
            ("lsdb_aging_loop", {}),
            ("lsdb_aging_loop", {"purge": False}),
            ("local_lsa_retransmission_loop", {"pending": {}}),
            ("local_lsa_retransmission_loop", {"pending": {1: 2}, "last_tx": None}),
            ("local_lsa_retransmission_loop", {"pending": {1: 2}, "last_tx": 99}),
            ("local_lsa_retransmission_loop", {"pending": {1: 2}, "last_tx": 90}),
            ("local_lsa_refresh_loop", {}),
            ("local_lsa_refresh_loop", {"lsas": []}),
            ("local_lsa_refresh_loop", {"lsas": [{}]}),
            ("local_lsa_refresh_loop", {"lsas": [{"_originated_at": None}]}),
            ("local_lsa_refresh_loop", {"lsas": [{"_originated_at": 80}]}),
            ("local_lsa_refresh_loop", {"lsas": [{"_originated_at": 50},
                                                   {"_originated_at": 30}]}),
            ("local_lsa_refresh_loop", {"lsas": [{"_originated_at": 30}],
                                        "exchanged": False}),
            ("local_lsa_refresh_loop", {"lsas": [{"_originated_at": 30}],
                                        "requests": [1]}),
            ("local_lsa_refresh_loop", {"lsas": [{"_originated_at": 30}],
                                        "pending": {1: 2}}),
        )
        for method, scenario in cases:
            with self.subTest(method=method, scenario=scenario):
                self.assertEqual(replay(OLD, method, scenario),
                                 replay(NEW, method, scenario))


if __name__ == "__main__":
    unittest.main()
