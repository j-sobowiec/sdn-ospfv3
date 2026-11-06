"""Stage 02: FRRouting owns forwarding route lookup; Ryu keeps OSPFv3."""

import ast
import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "ryu_sdn.py",
    "ospfv3/controller_rx.py",
    "ospfv3/controller_timers.py",
    "ospfv3/controller_diagnostics.py"
)
STAGE01_OPENFLOW_SHA = (
    "be7c836a2154c574834bf0d299cb2c5890dbaebc8a93c97ee54ad5c180018ed3"
)
STAGE08B_OPENFLOW_SHA = "09c2499e6a3edccb017c9c7006afd9cd80bb5a1bf7adc304585a205f43ed0d4c"
STAGE08B_CONTRACT_SHA = "c4e45dda919ec88b916aa4488b5b7921960e65cbe081dbd1d857a83cc31d4185"


def methods(path, class_name):
    tree = ast.parse((ROOT / path).read_text(encoding="utf8"))
    klass = next(
        n for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == class_name
    )
    return {
        n.name: n for n in klass.body
        if isinstance(n, ast.FunctionDef)
    }


def method_calls(method):
    return [
        node.func.attr for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
    ]


class Stage02SPFContract(unittest.TestCase):
    def test_no_production_spf_execution(self):
        banned = ("run_spf(", "build_ipv6_routing_table(",
                  "recompute_routing_state(", "get_ospf_transit_routes(",
                  "log_spf_result(", "log_ipv6_routing_table(")
        for path in SOURCES:
            with self.subTest(source=path):
                content = (ROOT / path).read_text(encoding="utf8")
                for expression in banned:
                    self.assertNotIn(expression, content)

    def test_controller_owns_neighbor_lsdb_and_local_lsa_not_routing(self):
        text = (ROOT / "ryu_sdn.py").read_text(encoding="utf8")
        for expected in ("Neighbor(self.logger)", "LSDB(self.logger)",
                         "LocalLSA(self.lsdb, self.logger)",
                         "self.lsdb.clear_remote(cfg.ROUTER_ID)",
                         "self.neighbor.reset()"):
            self.assertIn(expected, text)
        self.assertNotIn("from ospfv3.routing import Routing", text)
        self.assertNotIn("self.ipv6_routing_table", text)

    def test_received_remote_lsas_are_still_installed_and_acknowledged(self):
        rx = methods("ospfv3/controller_rx.py", "OSPFReceiveMixin")
        self.assertIn("handle_ospf_lsu", rx)
        calls = method_calls(rx["handle_ospf_lsu"])
        for required in ("update", "send_ls_ack", "initialize"):
            self.assertIn(required, calls)
        self.assertNotIn("recompute_routing_state", calls)

    def test_neighbor_dead_withdraws_both_flow_directions(self):
        timers = methods("ospfv3/controller_timers.py", "OSPFTimerMixin")
        dead = timers["neighbor_dead_loop"]
        calls = method_calls(dead)
        for required in ("clear_remote", "withdraw_all_ipv6_host_flows",
                         "reset_transit", "reset_adjacency"):
            self.assertIn(required, calls)
        self.assertNotIn("recompute_routing_state", calls)
        order = [
            (node.lineno, node.func.attr) for node in ast.walk(dead)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        ]
        order = dict((attr, line) for line, attr in order)
        self.assertLess(order["withdraw_all_ipv6_host_flows"],
                        order["reset_transit"])

    def test_lsdb_aging_remains_without_spf(self):
        timers = methods("ospfv3/controller_timers.py", "OSPFTimerMixin")
        calls = method_calls(timers["lsdb_aging_loop"])
        self.assertIn("purge_expired", calls)
        self.assertNotIn("recompute_routing_state", calls)

    def test_ipv6_packet_in_and_protocol_mixin_remain(self):
        controller = methods("ryu_sdn.py", "OSPFv3Controller")
        for required in ("packet_in_handler", "switch_features_handler",
                         "barrier_reply_handler"):
            self.assertIn(required, controller)
        for protocol in ("handle_ospf_hello", "handle_ospf_dbd",
                         "handle_ospf_lsr", "handle_ospf_lsu",
                         "handle_ospf_lsack"):
            self.assertIn(protocol, (ROOT / "ryu_sdn.py").read_text(encoding="utf8"))

    def test_openflow_source_identical_to_verified_stage01(self):
        # Stage08B removes only two unused legacy deletion methods. Accept its
        # exact payload only with a verified differential test and frozen copy.
        expected = STAGE01_OPENFLOW_SHA
        contract = ROOT / "tests/test_stage08b_openflow_cleanup.py"
        if contract.is_file():
            self.assertEqual(hashlib.sha256(contract.read_bytes()).hexdigest(),
                             STAGE08B_CONTRACT_SHA)
            old = ROOT / "tests/_stage08b_openflow_reference.py"
            self.assertEqual(hashlib.sha256(old.read_bytes()).hexdigest(),
                             STAGE01_OPENFLOW_SHA)
            expected = STAGE08B_OPENFLOW_SHA
        self.assertEqual(
            hashlib.sha256((ROOT / "controller_openflow.py").read_bytes()).hexdigest(),
            expected
        )

    def test_spf_module_removed_after_detachment(self):
        # Historical SPF reference implementations remain under tests/.
        self.assertFalse((ROOT / "ospfv3/routing.py").exists())


if __name__ == "__main__":
    unittest.main()
