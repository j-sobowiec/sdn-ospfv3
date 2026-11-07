"""09B: frozen prior DataPlane vs current observable NDP/IPv6 behavior.

The old transit_neighbors dict is explicitly NOT part of the external
contract.  Port, MAC, IPv6, LAN state, return values and packet bytes are.
"""
import ast
import hashlib
from pathlib import Path
import unittest

from test_stage04c_io_contract import DATAPLANE_ENV, NewDP, dp_snapshot, inbound, read_class

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "tests/_stage09b_dataplane_reference.py"
NEW = ROOT / "dataplane.py"
OLD_SHA = "427f13c283d3d68217b51e37430689b8f69e7cb81c44208235264d05e0b36cf6"
NEW_SHA = "c03330784a272df7bd9692644b10f5bc1752fb52b3f7fe68d23a545888abf52a"
OldDP = read_class(OLD, "DataPlane", DATAPLANE_ENV)


class Stage09BTransitState(unittest.TestCase):
    def test_pinned_old_and_new_and_no_stored_neighbors(self):
        self.assertEqual(hashlib.sha256(OLD.read_bytes()).hexdigest(), OLD_SHA)
        self.assertEqual(hashlib.sha256(NEW.read_bytes()).hexdigest(), NEW_SHA)
        self.assertNotIn("transit_neighbors", NEW.read_text())
        self.assertFalse(hasattr(NewDP(), "transit_neighbors"))

    def test_only_four_dead_bookkeeping_statements_removed(self):
        old_tree = ast.parse(OLD.read_text())
        new_tree = ast.parse(NEW.read_text())
        old_class = next(n for n in old_tree.body if isinstance(n, ast.ClassDef))
        new_class = next(n for n in new_tree.body if isinstance(n, ast.ClassDef))
        old_methods = {n.name:n for n in old_class.body if isinstance(n, ast.FunctionDef)}
        new_methods = {n.name:n for n in new_class.body if isinstance(n, ast.FunctionDef)}
        self.assertEqual(old_methods.keys(), new_methods.keys())
        # Outside these methods nothing can change at all.
        for name in old_methods.keys() - {"__init__", "learn_transit_router", "reset_transit", "handle_ndp"}:
            self.assertEqual(ast.dump(old_methods[name], include_attributes=False),
                             ast.dump(new_methods[name], include_attributes=False), name)
        self.assertEqual(len(OLD.read_text().splitlines()) -
                         len(NEW.read_text().splitlines()), 4)

    def compare(self, actions):
        old, new = OldDP(), NewDP()
        self.assertEqual(dp_snapshot(old), dp_snapshot(new))
        for name, args in actions:
            with self.subTest(name=name, args=str(args)[:100]):
                old_result = getattr(old, name)(*args)
                new_result = getattr(new, name)(*args)
                self.assertEqual(old_result, new_result)
                self.assertEqual(dp_snapshot(old), dp_snapshot(new))
        self.assertFalse(hasattr(new, "transit_neighbors"))

    def test_transit_learning_relearning_and_reset_same_effect(self):
        self.compare([
            ("learn_transit_router", (1, "fe80::1", "aa:bb:cc:00:00:01")),
            ("learn_transit_router", (1, "fe80::1", "aa:bb:cc:00:00:01")),
            ("learn_transit_router", (1, "fe80::1", "aa:bb:cc:00:00:02")),
            ("learn_transit_router", (3, "fe80::1", "aa:bb:cc:00:00:02")),
            ("learn_transit_router", (3, "fe80::2", "aa:bb:cc:00:00:02")),
            ("reset_transit", ()),
            ("learn_transit_router", (2, "fe80::1", "aa:bb:cc:00:00:01")),
            ("reset", ())
        ])

    def test_valid_and_spoofed_transit_ns_same_frame_and_state(self):
        good = inbound(target="fe80::10", source="fe80::1", mac="aa:bb:cc:00:00:01")
        badmac = inbound(target="fe80::10", source="fe80::1", mac="aa:bb:cc:00:00:02")
        badip = inbound(target="fe80::10", source="fe80::2", mac="aa:bb:cc:00:00:01")
        self.compare([
            ("learn_transit_router", (1, "fe80::1", "aa:bb:cc:00:00:01")),
            ("handle_ndp", (*good, 1)),
            ("handle_ndp", (*badmac, 1)),
            ("handle_ndp", (*badip, 1)),
            ("handle_ndp", (*good, 2)),
        ])

    def test_lan_ns_and_echo_same_response(self):
        self.compare([
            ("handle_ndp", (*inbound(), 2)),
            ("handle_ndp", (*inbound(source="2001:db8:2::100"), 2)),
            ("learn_lan_host", (2, "2001:db8:1::101", "aa:bb:cc:dd:ee:02")),
            ("reset", ())
        ])


if __name__ == "__main__":
    unittest.main()
