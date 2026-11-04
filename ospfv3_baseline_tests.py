"""Byte-for-byte baseline for the pre-Scapy OSPFv3 codec.

Run from the project root before and after replacing the packet codec:
    python3 -m unittest -v ospfv3_baseline_tests.py

Fixtures assume the values in ospfv3/config.py included in the project handoff.
This is not a substitute for integration tests with Ryu, FRR, and OpenFlow.
"""

import hashlib
import logging
import socket
import struct
import unittest

from ospfv3 import config as cfg
from ospfv3.local_lsa import LocalLSA
from ospfv3.packet import (
    build_ospfv3_dbd_frame,
    build_ospfv3_hello_frame,
    build_ospfv3_lsack_frame,
    build_ospfv3_lsr_frame,
    build_ospfv3_lsu_frame,
    calculate_ospfv3_checksum,
)
from ospfv3.parser import parse_dbd, parse_hello, parse_lsack, parse_lsr, parse_lsu


class FakeLSDB:
    def values(self):
        return [
            {
                "ls_type": 0x2001,
                "advertising_router": "1.1.1.1",
                "router_lsa": {
                    "links": [
                        {
                            "type": 1,
                            "neighbor_router_id": cfg.ROUTER_ID,
                            "neighbor_interface_id": "0.0.0.1",
                            "interface_id": "0.0.3.40",
                        }
                    ]
                },
            }
        ]


class CodecBaselineTests(unittest.TestCase):
    EXPECTED_FRAME_HASHES = {
        1: "b1fb335f3be855a3",
        2: "ebfdfc3a990b4cd2",
        3: "eec3e34b0f75dad0",
        4: "4e7c58e373f050da",
        5: "01ce33e15b2dae6b",
    }
    EXPECTED_LSA_HASHES = {
        0x0008: "f4c3805e716c1302",
        0x2001: "aa39fbf505f38296",
        0x2009: "af0827e03f4c5957",
    }

    @staticmethod
    def digest(data):
        return hashlib.sha256(data).hexdigest()[:16]

    def check_frame(self, frame, expected_type):
        self.assertEqual(frame[12:14], b"\x86\xdd")
        self.assertEqual(frame[20], 89)
        self.assertEqual(frame[21], 1)
        self.assertEqual(frame[54], 3)
        self.assertEqual(frame[55], expected_type)
        self.assertEqual(struct.unpack("!H", frame[56:58])[0], len(frame) - 54)
        ospf = bytearray(frame[54:])
        actual_checksum = struct.unpack("!H", ospf[12:14])[0]
        ospf[12:14] = b"\x00\x00"
        src = socket.inet_ntop(socket.AF_INET6, frame[22:38])
        dst = socket.inet_ntop(socket.AF_INET6, frame[38:54])
        self.assertEqual(
            actual_checksum,
            calculate_ospfv3_checksum(src, dst, bytes(ospf)),
        )
        self.assertEqual(
            self.digest(frame), self.EXPECTED_FRAME_HASHES[expected_type]
        )

    def setUp(self):
        self.local = LocalLSA(FakeLSDB(), logging.getLogger("ospfv3-baseline"))
        self.assertTrue(self.local.initialize("1.1.1.1"))

    def test_local_lsa_wire_format(self):
        for _, entry in self.local.items():
            self.assertEqual(
                self.digest(entry["raw_lsa"]),
                self.EXPECTED_LSA_HASHES[entry["ls_type"]],
            )
        self.assertEqual(len(self.local.entries), 3)

    def test_hello(self):
        frame = build_ospfv3_hello_frame(["1.1.1.1"])
        self.check_frame(frame, 1)
        self.assertEqual(parse_hello(frame[54:], len(frame) - 54)["neighbors"], ["1.1.1.1"])

    def test_dbd(self):
        frame = build_ospfv3_dbd_frame(0x12345678, 0x07)
        self.check_frame(frame, 2)
        dbd = parse_dbd(frame[54:], len(frame) - 54)
        self.assertTrue(dbd["i_bit"] and dbd["m_bit"] and dbd["ms_bit"])
        self.assertEqual(dbd["dd_sequence"], 0x12345678)

    def test_lsr(self):
        frame = build_ospfv3_lsr_frame(
            [{"ls_type": 0x2001, "link_state_id": "0.0.0.0", "advertising_router": "1.1.1.1"}],
            "fe80::1", "aa:bb:cc:dd:ee:ff"
        )
        self.check_frame(frame, 3)
        self.assertEqual(parse_lsr(frame[54:], len(frame) - 54)[0]["ls_type"], 0x2001)

    def test_lsu_and_lsack(self):
        frame = build_ospfv3_lsu_frame(
            self.local.build_update_body(), "fe80::1", "aa:bb:cc:dd:ee:ff"
        )
        self.check_frame(frame, 4)
        lsas = parse_lsu(frame[54:], len(frame) - 54)
        self.assertEqual({lsa["ls_type"] for lsa in lsas}, set(self.EXPECTED_LSA_HASHES))
        ack = build_ospfv3_lsack_frame(lsas, "fe80::1", "aa:bb:cc:dd:ee:ff")
        self.check_frame(ack, 5)
        self.assertEqual(len(parse_lsack(ack[54:], len(ack) - 54)), 3)


if __name__ == "__main__":
    unittest.main()
