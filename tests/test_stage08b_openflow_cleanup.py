"""Stage08B: frozen differential contract for removing unused SPF flow APIs.

The reference is the exact Stage07 OpenFlow module. Active methods are required
to have unchanged ASTs and unchanged FlowMod sequences under the mock switch.
"""

import ast
import hashlib
import logging
from pathlib import Path
import unittest

import b5_3_harness as h


ROOT = Path(__file__).resolve().parents[1]
# Stage08C keeps the exact post-08B source as a frozen historical milestone.
# The current production module is checked by Stage08C's new differential test.
CURRENT = (ROOT / "tests/_stage08c_openflow_reference.py"
           if (ROOT / "tests/test_stage08c_openflow_refactor.py").is_file()
           else ROOT / "controller_openflow.py")
REFERENCE = ROOT / "tests/_stage08b_openflow_reference.py"
OLD_SHA = "be7c836a2154c574834bf0d299cb2c5890dbaebc8a93c97ee54ad5c180018ed3"
NEW_SHA = "09c2499e6a3edccb017c9c7006afd9cd80bb5a1bf7adc304585a205f43ed0d4c"
REMOVED = {"delete_ipv6_route_flow", "delete_ipv6_reverse_flow"}


def class_ast(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    klass = next(node for node in tree.body
                 if isinstance(node, ast.ClassDef) and node.name == "OpenFlowMixin")
    return tree, klass


def canonical(value):
    """Capture complete FlowMod/Match/Instruction/Action data, ignoring dp identity."""
    if isinstance(value, h.Switch):
        return "datapath"
    if isinstance(value, h.OFMsg):
        return (value.kind, tuple(canonical(v) for v in value.args),
                tuple(sorted((key, canonical(val)) for key, val in vars(value).items()
                             if key != "kind")))
    if isinstance(value, (list, tuple)):
        return tuple(canonical(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((key, canonical(val)) for key, val in value.items()))
    return value


def controller_class(source):
    mixin = h.load_class(source, "OpenFlowMixin", h.BASE)
    return type("Stage08BController", (mixin,), {})


def prepared(klass):
    ctl = klass.__new__(klass)
    ctl.logger = logging.getLogger("stage08b")
    ctl.datapath = h.Switch()
    ctl.data_plane = h.DataPlane()
    ctl.installed_ipv6_host_flows = {}
    ctl.data_plane.learn_lan_host(2, h.LAN_IP, h.LAN_MAC)
    ctl.data_plane.learn_transit_router(1, h.TRANSIT_IP, h.TRANSIT_MAC)
    return ctl


class Stage08BOpenFlowContract(unittest.TestCase):
    def test_exact_frozen_reference_and_payload(self):
        self.assertEqual(hashlib.sha256(REFERENCE.read_bytes()).hexdigest(), OLD_SHA)
        self.assertEqual(hashlib.sha256(CURRENT.read_bytes()).hexdigest(), NEW_SHA)

    def test_only_two_legacy_methods_removed(self):
        original_tree, original_class = class_ast(REFERENCE)
        current_tree, current_class = class_ast(CURRENT)
        before = {n.name: n for n in original_class.body if isinstance(n, ast.FunctionDef)}
        after = {n.name: n for n in current_class.body if isinstance(n, ast.FunctionDef)}
        self.assertEqual(set(before) - set(after), REMOVED)
        self.assertEqual(set(after) - set(before), set())
        for name, method in after.items():
            with self.subTest(method=name):
                self.assertEqual(ast.dump(method, include_attributes=False),
                                 ast.dump(before[name], include_attributes=False))
        self.assertEqual(
            ast.dump(ast.Module(body=[x for x in original_tree.body if x is not original_class],
                                type_ignores=[]), include_attributes=False),
            ast.dump(ast.Module(body=[x for x in current_tree.body if x is not current_class],
                                type_ignores=[]), include_attributes=False),
        )

    def test_legacy_methods_not_called_by_production(self):
        sources = [ROOT / "ryu_sdn.py", ROOT / "dataplane.py", ROOT / "controller_openflow.py"]
        sources.extend((ROOT / "ospfv3").glob("*.py"))
        for path in sources:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            calls = [n.func.attr for n in ast.walk(tree)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
            with self.subTest(source=path.name):
                self.assertFalse(REMOVED.intersection(calls))

    def test_install_reinstall_transit_change_and_r1_withdrawal_identical(self):
        current = prepared(controller_class(CURRENT))
        frozen = prepared(controller_class(REFERENCE))

        for ctl in (current, frozen):
            self.assertTrue(ctl.install_ipv6_host_flows(h.LAN_IP, h.LAN_MAC))
            self.assertFalse(ctl.install_ipv6_host_flows(h.LAN_IP, h.LAN_MAC))
            ctl.data_plane.learn_transit_router(3, "fe80::2", "02:aa:bb:cc:dd:ee")
            self.assertTrue(ctl.install_ipv6_host_flows(h.LAN_IP, h.LAN_MAC))
            ctl.withdraw_all_ipv6_host_flows()
            self.assertFalse(ctl.installed_ipv6_host_flows)

        self.assertEqual(canonical(current.datapath.sent),
                         canonical(frozen.datapath.sent))
        self.assertEqual(len(h.flowmods(current.datapath, h.OFP.OFPFC_DELETE_STRICT)), 32)

    def test_multi_host_sequences_identical(self):
        current = prepared(controller_class(CURRENT))
        frozen = prepared(controller_class(REFERENCE))
        for ctl in (current, frozen):
            ctl.data_plane.learn_lan_host(2, "2001:db8:1::101", "02:00:00:00:01:01")
            self.assertTrue(ctl.try_install_ipv6_host_flows())
        self.assertEqual(canonical(current.datapath.sent),
                         canonical(frozen.datapath.sent))
        self.assertEqual(sum(msg.priority == 110 for msg in h.flowmods(current.datapath)), 16)


if __name__ == "__main__":
    unittest.main()
