"""Stage09C-1: OSPFv3 PacketIn envelope moved into parser without wire changes.

The frozen 08F/08J/Stage07 sources and deterministic Scapy/Ryu fakes are
executed alongside the refactored code. Real Ryu/Containernet is tested later.
"""
import ast
import hashlib
import ipaddress
from pathlib import Path
import random
import unittest

import test_stage07_event_contract as events

ROOT = Path(__file__).resolve().parents[1]
OLD_RYU = ROOT / "tests/_stage09c_ryu_reference.py"
OLD_PARSER = ROOT / "tests/_stage09c_parser_reference.py"
NEW_RYU = ROOT / "ryu_sdn.py"
NEW_PARSER = ROOT / "ospfv3/parser.py"
FROZEN = {
    OLD_RYU: "c7b7ecb6f9021728190cd59f2e62f5c0006c80d8a29e4bd67608048214a11dcd",
    OLD_PARSER: "36d7846c52a0e102c534a2a60d951be9ed29f17cccd5260fa8460785d6a4e155",
    ROOT / "tests/_stage09c_stage07_reference.py":
        "ca36d0b030d1c0c079823a5e9fb47cb97aebe205d204aaa691ebbe165519e487",
    ROOT / "tests/_stage09c_stage08j_reference.py":
        "e5c59240a16cea0ecf53b4bd34df709a3c9d44e7e8e30fe1875983d5fc2df40e",
    ROOT / "tests/_stage09c_stage04a_reference.py":
        "e81f1f6d20fdd8759c1f45ee6b4e31b81acac79312e1b7d774ed5bc93c59ac3c",
}
AFTER = {
    NEW_RYU: "dec517bc3fd92042cb00047dc53cd8bff8cd602e8ac9e41c8c52e35d95064c17",
    NEW_PARSER: "8a83496abd344f888890c5f28d57fa7a63df9e4c320ff47d1c0ce711e2a8dfc9",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def methods(path):
    return {node.name: ast.dump(node, include_attributes=False)
            for node in ast.parse(path.read_text()).body
            if isinstance(node, ast.FunctionDef)}


class Stage09CPacketIn(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy = events.load_class(OLD_RYU)
        cls.new = events.SIMPLIFIED

    def test_exact_frozen_sources_and_expected_new_sources(self):
        for path, expected in (FROZEN | AFTER).items():
            with self.subTest(path=path.name):
                self.assertEqual(sha(path), expected)

    def test_all_existing_parser_functions_same_ast(self):
        old, new = methods(OLD_PARSER), methods(NEW_PARSER)
        self.assertEqual(new.keys() - old.keys(), {"validate_ospfv3_transport"})
        self.assertEqual(old.keys() - new.keys(), set())
        for name in old:
            with self.subTest(method=name):
                self.assertEqual(old[name], new[name])

    def test_ryu_still_has_the_same_handlers_and_mro(self):
        def get_class(path):
            tree = ast.parse(path.read_text())
            return next(node for node in tree.body
                        if isinstance(node, ast.ClassDef) and node.name == "OSPFv3Controller")
        old, new = get_class(OLD_RYU), get_class(NEW_RYU)
        self.assertEqual([ast.unparse(b) for b in old.bases],
                         [ast.unparse(b) for b in new.bases])
        old_methods = {n.name: ast.dump(n, include_attributes=False)
                       for n in old.body if isinstance(n, ast.FunctionDef)}
        new_methods = {n.name: ast.dump(n, include_attributes=False)
                       for n in new.body if isinstance(n, ast.FunctionDef)}
        self.assertEqual(old_methods.keys(), new_methods.keys())
        for name in old_methods.keys() - {"packet_in_handler"}:
            self.assertEqual(old_methods[name], new_methods[name])
        self.assertIn("validate_ospfv3_transport", new_methods["packet_in_handler"])
        self.assertNotIn("OSPFv3_Hdr", new_methods["packet_in_handler"])
        self.assertNotIn("calculate_ospfv3_checksum", new_methods["packet_in_handler"])

    def compare(self, **kwargs):
        # The same packet fixture is replayed with independently constructed
        # controllers; check both side effects and all warning/info logs.
        def scenario(controller):
            events.packet_fixture(**kwargs)
            controller.packet_in_handler(events.event(b"RAW", controller.datapath))
        before = events.execute(self.legacy, scenario)
        after = events.execute(self.new, scenario)
        self.assertEqual(before, after, kwargs)
        return after

    def test_ospf_five_message_types_and_unknown(self):
        for kind in (1, 2, 3, 4, 5, 6, 255):
            with self.subTest(kind=kind):
                data = events.RyuEventsContract.ospf(kind)
                state = self.compare(nxt=89, src="fe80::1", dst="ff02::5",
                                     ospf_data=data)
                self.assertEqual(len(state["events"]), kind <= 5)

    def test_invalid_header_checksum_area_instance_version_and_hop_limit(self):
        rng = random.Random(901)
        for _ in range(200):
            kind = rng.randrange(1, 8)
            area = rng.choice((events.CFG.AREA_ID, "0.0.0.1"))
            instance = rng.choice((0, 1))
            checksum = rng.choice((0x1234, 0))
            version = rng.choice((3, 2))
            src = rng.choice(("fe80::1", "2001:db8:1::5", "x"))
            dst = rng.choice(("ff02::5", "ff02::6", "fe80::10", "x"))
            hop = rng.choice((1, 2, 0))
            data = events.RyuEventsContract.ospf(
                kind, size=rng.choice((12, 15, 16, 20, 28, 36, 44)),
                area=area, instance=instance,
                checksum=checksum, version=version)
            self.compare(nxt=89, src=src, dst=dst, ospf_data=data, hop_limit=hop)

    def test_malformed_and_missing_ospf_payload(self):
        for payload in (b"", b"\x00", b"A" * 15, b"X" * 16,
                        bytearray(b"X" * 20), events.Obj(invalid=True), None):
            with self.subTest(payload=repr(payload)[:50]):
                self.compare(nxt=89, src="fe80::1", dst="ff02::5",
                             ospf_data=payload)

    def test_data_path_untouched(self):
        for protocol, icmp_type in ((6, None), (17, None),
                                    (58, 135), (58, 128), (58, 129)):
            def scenario(controller):
                controller.data_plane.host_valid = True
                events.packet_fixture(nxt=protocol, icmp_type=icmp_type)
                controller.packet_in_handler(events.event(b"DATA", controller.datapath))
            self.assertEqual(events.execute(self.legacy, scenario),
                             events.execute(self.new, scenario))


if __name__ == "__main__":
    unittest.main()
