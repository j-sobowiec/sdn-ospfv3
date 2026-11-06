"""08G: pinned, executable OSPF receive/transmit behavior preservation.

The old source remains frozen, and the existing 04B/04C tests continue to
validate side effects. These checks need no Ryu, Scapy or root privileges.
"""

import ast
import hashlib
from pathlib import Path
import socket
import struct
import types
import unittest

import test_stage04b_rx_contract as rx_contract
import test_stage04c_io_contract as tx_contract


ROOT = Path(__file__).resolve().parents[1]
RX_OLD = ROOT / "tests/_stage08g_rx_reference.py"
TX_OLD = ROOT / "tests/_stage08g_tx_reference.py"
RX_NEW = ROOT / "ospfv3/controller_rx.py"
TX_NEW = ROOT / "ospfv3/controller_tx.py"
PINS = {
    RX_OLD: "5ee6e527ee840f7d0ed10c56c721b73bc3b54e1548faabdec734bf930397e59d",
    TX_OLD: "959fe3a3c51ed5dbbe199039a071b5796adbc2de019e81e15771b79bcd7b4f35",
    RX_NEW: "b424cf0a0bf0012f17a3b29a6dc46995f8506130b58db57ae0832f966575d72e",
    TX_NEW: "29107e2f9eabae47edad29e33b77c0c6e39369bc7f397d6714b8f0e3d54abe04",
}


def method_nodes(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == name)
    return {node.name: node for node in cls.body if isinstance(node, ast.FunctionDef)}, cls


def load_old_rx():
    _, node = method_nodes(RX_OLD, "OSPFReceiveMixin")
    cfg = types.SimpleNamespace(ROUTER_ID="10.10.10.10", HELLO_INTERVAL=10,
                                DEAD_INTERVAL=40, INTERFACE_MTU=1500)

    def parser(data, _length):
        if isinstance(data, Exception):
            raise data
        return data

    namespace = {"socket": socket, "struct": struct, "cfg": cfg}
    namespace.update({name: parser for name in (
        "parse_hello", "parse_dbd", "parse_lsr", "parse_lsu", "parse_lsack")})
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                 str(RX_OLD), "exec"), namespace)
    return namespace["OSPFReceiveMixin"]


class RecordingLogger:
    def __init__(self):
        self.events = []

    def info(self, *args):
        self.events.append(("info", args))

    def warning(self, *args):
        self.events.append(("warning", args))


class Stage08GProtocolDedup(unittest.TestCase):
    def test_exact_sources_and_frozen_history(self):
        for path, expected in PINS.items():
            with self.subTest(path=path.name):
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)

    def test_only_expected_mixin_methods_changed(self):
        before_rx, _ = method_nodes(RX_OLD, "OSPFReceiveMixin")
        after_rx, _ = method_nodes(RX_NEW, "OSPFReceiveMixin")
        self.assertEqual(after_rx.keys() - before_rx.keys(), {"_parse_or_log"})
        for name in before_rx.keys() - {
                "handle_ospf_hello", "handle_ospf_dbd", "handle_ospf_lsr",
                "handle_ospf_lsu", "handle_ospf_lsack"}:
            self.assertEqual(ast.dump(before_rx[name], include_attributes=False),
                             ast.dump(after_rx[name], include_attributes=False))
        before_tx, _ = method_nodes(TX_OLD, "OSPFTransmitMixin")
        after_tx, _ = method_nodes(TX_NEW, "OSPFTransmitMixin")
        self.assertEqual(before_tx.keys() - after_tx.keys(), {"_build_ospf_unicast_frame"})
        for name in after_tx.keys() - {
                "send_link_state_request", "send_ls_ack", "send_local_ls_update",
                "send_local_lsr_response", "send_local_lsa_retransmission"}:
            self.assertEqual(ast.dump(before_tx[name], include_attributes=False),
                             ast.dump(after_tx[name], include_attributes=False))

    def test_parser_errors_have_identical_logs_and_state(self):
        old_rx = load_old_rx()
        old_controller = type("OldController", (old_rx, rx_contract.Controller), {})
        methods = ("hello", "dbd", "lsr", "lsu", "lsack")
        for method in methods:
            original, updated = old_controller(), rx_contract.Controller()
            original.logger, updated.logger = RecordingLogger(), RecordingLogger()
            ipv6 = types.SimpleNamespace(src="fe80::1")
            router_id, area_id = "1.1.1.1", "0.0.0.0"
            if method == "hello":
                args = (1, types.SimpleNamespace(src="aa"), ipv6,
                        ValueError("invalid payload"), 56, router_id, area_id)
            elif method == "dbd":
                args = (1, ipv6, ValueError("invalid payload"), 28,
                        0x01010101, router_id, area_id)
            else:
                args = (1, ipv6, ValueError("invalid payload"), 28,
                        router_id, area_id)
            with self.subTest(method=method):
                self.assertIsNone(getattr(original, "handle_ospf_" + method)(*args))
                self.assertIsNone(getattr(updated, "handle_ospf_" + method)(*args))
                self.assertEqual(original.logger.events, updated.logger.events)
                self.assertEqual(original.events, updated.events)
                self.assertEqual(vars(original.neighbor), vars(updated.neighbor))

    def test_transmit_events_still_equal_to_04c_frozen_reference(self):
        # All original 04C TX contract cases run separately during discovery.
        # Repeat a focused sequence here as an explicit gate for 08G.
        original, current = tx_contract.OldController(), tx_contract.NewController()
        local_lsa = tx_contract.FakeLocalLSA([])[(0x2001, 0, "10.10.10.10")]
        actions = (
            ("send_ospfv3_hello", ()),
            ("send_link_state_request", ()),
            ("send_ls_ack", ([{"ls_type": 0x2001, "link_state_id": 1,
                               "advertising_router": "1.1.1.1"}],)),
            ("send_local_ls_update", ()),
            ("send_local_lsr_response", ([local_lsa],)),
            ("send_local_lsa_retransmission", ()),
        )
        for name, args in actions:
            with self.subTest(method=name):
                self.assertEqual(getattr(original, name)(*args),
                                 getattr(current, name)(*args))
                self.assertEqual(tx_contract.tx_snapshot(original),
                                 tx_contract.tx_snapshot(current))


if __name__ == "__main__":
    unittest.main()
