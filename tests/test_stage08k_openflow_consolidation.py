"""08K: compare complete OpenFlow events after removing constructor boilerplate."""

import ast
import hashlib
from pathlib import Path
import random
import unittest

import b5_3_harness as h
from test_stage08b_openflow_cleanup import canonical
from test_stage08c_openflow_refactor import make_controller


ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "tests/_stage08k_openflow_reference.py"
NEW = ROOT / "controller_openflow.py"
OLD_SHA = "5a45925519d6544a2044a8df9f2bb481feeae1f91ce8c5101221dc2955400014"
NEW_SHA = "b790613eb1e395c8fa00de7603e81c6c232dc6ae7a3f32cb09b2f471f9bb2365"
MODIFIED = {"_send_action_flow", "_send_strict_delete",
            "install_ipv6_host_flows", "send_frame"}


def methods(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    klass = next(node for node in tree.body
                 if isinstance(node, ast.ClassDef) and node.name == "OpenFlowMixin")
    return {node.name: ast.dump(node, include_attributes=False)
            for node in klass.body if isinstance(node, ast.FunctionDef)}


class RecordingParser:
    """Record constructor call order, forwarding the actual mock constructor."""

    def __init__(self, base):
        self.base, self.events = base, []

    def __getattr__(self, name):
        function = getattr(self.base, name)

        def record(*args, **kwargs):
            self.events.append(name)
            return function(*args, **kwargs)
        return record


def pair():
    old, new = make_controller(OLD), make_controller(NEW)
    for ctl in (old, new):
        ctl.datapath.ofproto_parser = RecordingParser(ctl.datapath.ofproto_parser)
    return old, new


def assert_equal_events(test, old, new):
    test.assertEqual(canonical(old.datapath.sent), canonical(new.datapath.sent))
    test.assertEqual(old.datapath.ofproto_parser.events,
                     new.datapath.ofproto_parser.events)
    test.assertEqual(old.installed_ipv6_host_flows,
                     new.installed_ipv6_host_flows)


class Stage08KOpenFlowConsolidation(unittest.TestCase):
    def test_pinned_sources_and_reduction(self):
        self.assertEqual(hashlib.sha256(OLD.read_bytes()).hexdigest(), OLD_SHA)
        self.assertEqual(hashlib.sha256(NEW.read_bytes()).hexdigest(), NEW_SHA)
        self.assertEqual(len(OLD.read_text().splitlines()) -
                         len(NEW.read_text().splitlines()), 36)

    def test_only_four_methods_reorganized(self):
        before, after = methods(OLD), methods(NEW)
        self.assertEqual(before.keys(), after.keys())
        for name in before.keys() - MODIFIED:
            with self.subTest(name=name):
                self.assertEqual(before[name], after[name])

    def test_idempotency_mac_change_transit_change_and_withdrawal(self):
        rng = random.Random(80811)
        for index in range(50):
            old, new = pair()
            host_count = rng.randint(2, 5)
            for ctl in (old, new):
                self.assertFalse(ctl.try_install_ipv6_host_flows())
                for host_index in range(1, host_count):
                    host = f"2001:db8:1::{100+host_index}"
                    ctl.data_plane.learn_lan_host(2, host,
                                                  f"02:00:00:01:00:{host_index:02x}")
                self.assertFalse(ctl.try_install_ipv6_host_flows())
                ctl.data_plane.learn_transit_router(1, h.TRANSIT_IP, h.TRANSIT_MAC)
                self.assertTrue(ctl.try_install_ipv6_host_flows())
                self.assertFalse(ctl.try_install_ipv6_host_flows())
                ctl.data_plane.learn_transit_router(3, "fe80::3", "02:00:00:00:0a:03")
                self.assertTrue(ctl.try_install_ipv6_host_flows())
                ctl.data_plane.learn_lan_host(2, h.LAN_IP, "02:00:00:00:0b:01")
                self.assertTrue(ctl.try_install_ipv6_host_flows())
                ctl.withdraw_all_ipv6_host_flows()
                ctl.withdraw_all_ipv6_host_flows()
            with self.subTest(index=index):
                assert_equal_events(self, old, new)

    def test_packetout_and_missing_datapath_events(self):
        old, new = pair()
        for ctl in (old, new):
            self.assertTrue(ctl.send_frame(b"raw-frame", 7))
            self.assertTrue(ctl.send_frame(b"\0raw", 65533))
            ctl.datapath.send_msg(ctl.datapath.ofproto_parser.OFPMatch(in_port=7))
        assert_equal_events(self, old, new)
        for ctl in (old, new):
            ctl.datapath = None
            self.assertFalse(ctl.send_frame(b"raw-frame", 7))
            self.assertIsNone(ctl._delete_host_protocol_flows(
                "2001:db8:1::100", ("aa", 2, "bb", 1)))


if __name__ == "__main__":
    unittest.main()
