"""Stage 08F-2: first PacketOut and installed FlowMod share router actions.

Uses the existing Stage07 event emulator and reads the actual OpenFlow helper
without importing Ryu or requiring root. Historical reference sources remain
frozen in separate files. Full Containernet validation is still mandatory.
"""

import ast
import copy
import hashlib
from pathlib import Path
import unittest

import test_stage07_event_contract as events


ROOT = Path(__file__).resolve().parents[1]
CURRENT_RYU = ROOT / "ryu_sdn.py"
CURRENT_OF = ROOT / "controller_openflow.py"
OLD_RYU = ROOT / "tests/_stage08f_ryu_sdn_reference.py"
OLD_TEST = ROOT / "tests/_stage08f_stage07_contract_reference.py"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def real_forward_actions(parser, destination_mac, out_port):
    """Evaluate only the actual helper's AST using the existing fake parser."""
    tree = ast.parse(CURRENT_OF.read_text(encoding="utf-8"))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == "OpenFlowMixin")
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                  and node.name == "_forwarding_actions")
    method = copy.deepcopy(method)
    method.decorator_list = []
    scope = {"cfg": events.CFG}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                 str(CURRENT_OF), "exec"), scope)
    return scope["_forwarding_actions"](parser, destination_mac, out_port)


class Stage08FPacketOutContract(unittest.TestCase):
    def test_frozen_ryu_and_old_stage07_test_preserved(self):
        self.assertEqual(sha(OLD_RYU),
                         "08402606b119fee072c2bcfe39cd05242f804008cf9c1cb85ea9353753644538")
        self.assertEqual(sha(OLD_TEST),
                         "476a62ad777507b1c3f5efad9822dbfa41985d02ed0fcda30cdd1e09b3bf2750")

    def test_first_packet_routes_use_actual_openflow_builder(self):
        for nxt, icmp_type in ((6, None), (17, None), (58, 128), (58, 129)):
            def prepare(controller):
                controller.data_plane.host_valid = True
                events.packet_fixture(nxt=nxt, icmp_type=icmp_type)
                controller.packet_in_handler(events.event(b"RAW_UNCHANGED", controller.datapath))

            with self.subTest(nxt=nxt, icmp_type=icmp_type):
                state = events.execute(events.SIMPLIFIED, prepare)
                output = [msg for msg in state["sent"]
                          if msg.get("kind") == "OFPPacketOut"]
                self.assertEqual(len(output), 1)
                self.assertEqual(output[0]["kwargs"]["data"], ("bytes", b"RAW_UNCHANGED".hex()))
                self.assertEqual(output[0]["kwargs"]["in_port"], 2)
                expected = events.normalize(real_forward_actions(
                    events.Parser(), "aa:bb:cc:dd:ee:ff", 1))
                self.assertEqual(output[0]["kwargs"]["actions"], expected)

    def test_ndp_and_ospf_are_not_sent_as_data_packetout(self):
        for nxt, icmp_type in ((89, None), (58, 135), (58, 136)):
            def prepare(controller):
                controller.data_plane.host_valid = True
                events.packet_fixture(nxt=nxt, icmp_type=icmp_type)
                controller.packet_in_handler(events.event(b"CONTROL", controller.datapath))

            with self.subTest(nxt=nxt, icmp_type=icmp_type):
                state = events.execute(events.SIMPLIFIED, prepare)
                self.assertFalse([msg for msg in state["sent"]
                                  if msg.get("kind") == "OFPPacketOut"])

    def test_source_contains_one_shared_builder_call(self):
        tree = ast.parse(CURRENT_RYU.read_text(encoding="utf-8"))
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == "OSPFv3Controller")
        handler = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                       and node.name == "packet_in_handler")
        attrs = [node.func.attr for node in ast.walk(handler)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        self.assertEqual(attrs.count("_forwarding_actions"), 1)
        self.assertNotIn("OFPActionDecNwTtl", attrs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
