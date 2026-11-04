"""S04: differential receive-parser regression against the pre-S04 snapshot.

Run on Ubuntu with Scapy 2.7.0 using Python's unittest discovery. The reference
is a frozen copy of ospfv3/parser.py before S04; both use the current LSA codec.
"""

import random
import socket
import struct
import unittest

from ospfv3 import parser as current
import _s04_parser_reference as reference
from ospfv3.local_lsa import LocalLSA
from ospfv3.lsa import finalize_ospfv3_lsa_checksum
from test_parser_scapy import LSDBFixture, lsa_header, ospf_packet, router_id
import logging


PARSERS = (
    (current.parse_hello, reference.parse_hello),
    (current.parse_dbd, reference.parse_dbd),
    (current.parse_lsr, reference.parse_lsr),
    (current.parse_lsu, reference.parse_lsu),
    (current.parse_lsack, reference.parse_lsack),
)


class TestS04ParserEquivalence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.local = LocalLSA(LSDBFixture(), logging.getLogger("s04"))
        assert cls.local.initialize("1.1.1.1")
        cls.update_body = cls.local.build_update_body()

    @staticmethod
    def make_packets():
        hello = ospf_packet(1, struct.pack(
            "!IB3sHHII", 1001, 7, b"\x00\x00\x13", 5, 40,
            router_id("10.10.10.10"), router_id("2.2.2.2"),
        ) + socket.inet_aton("1.1.1.1") + socket.inet_aton("3.3.3.3"))
        dbd = ospf_packet(2, struct.pack(
            "!B3sHBBI", 0, b"\x00\x00\x13", 1500, 0, 7, 0xabcdef12,
        ) + lsa_header(ls_type=0x0008) + lsa_header(ls_type=0x2001))
        lsr = ospf_packet(3, b"".join(
            struct.pack("!HHII", 0, t, 0, router_id("1.1.1.1"))
            for t in (0x2001, 0x0008, 0x2009)
        ))
        lsack = ospf_packet(5, b"".join(lsa_header(ls_type=t)
                                              for t in (0x0008, 0x2001, 0x2009)))
        return (hello, dbd, lsr, ospf_packet(4, TestS04ParserEquivalence.update_body), lsack)

    def compare(self, index, packet, declared_length=None):
        got, old = PARSERS[index]
        length = len(packet) if declared_length is None else declared_length
        try:
            expected = old(packet, length)
        except Exception as exc:
            with self.assertRaises(type(exc)) as result:
                got(packet, length)
            self.assertEqual(str(result.exception), str(exc))
        else:
            actual = got(packet, length)
            self.assertEqual(actual, expected)
            self.assertEqual(type(actual), type(expected))

    def test_five_packet_types(self):
        for i, packet in enumerate(self.make_packets()):
            with self.subTest(ospf_type=i + 1):
                self.compare(i, packet)
                self.compare(i, packet + b"\x00" * 8, len(packet))

    def test_known_unknown_lsu_and_exact_headers(self):
        unknown = finalize_ospfv3_lsa_checksum(
            lsa_header(ls_type=0x200b, length=24) + b"\x00\x11\x22\x33")
        existing = self.update_body
        count = struct.unpack("!I", existing[:4])[0]
        for body in (
            b"\x00\x00\x00\x00",
            existing,
            struct.pack("!I", count + 1) + existing[4:] + unknown,
            struct.pack("!I", 1) + unknown,
        ):
            with self.subTest(size=len(body)):
                self.compare(3, ospf_packet(4, body))

    def test_all_known_lsa_errors_and_indices(self):
        body = self.update_body
        count = struct.unpack("!I", body[:4])[0]
        self.assertEqual(count, 3)
        offset = 4
        for index in range(count):
            ls_length = struct.unpack("!H", body[offset + 18:offset + 20])[0]
            corrupted = bytearray(body)
            corrupted[offset + min(ls_length - 1, 20)] ^= 0x08
            self.compare(3, ospf_packet(4, bytes(corrupted)))
            with self.subTest(corrupt_lsa=index + 1):
                with self.assertRaisesRegex(ValueError, f"checksum #{index + 1}"):
                    current.parse_lsu(ospf_packet(4, bytes(corrupted)), 16 + len(body))
            offset += ls_length

    def test_randomized_corrupt_wire_equivalence(self):
        rng = random.Random(0x50404)
        for i, packet in enumerate(self.make_packets()):
            for iteration in range(140):
                mutated = bytearray(packet)
                if iteration % 4 == 0:
                    mutated[rng.randrange(len(mutated))] ^= (1 << rng.randrange(8))
                elif iteration % 4 == 1:
                    mutated = mutated[:-rng.randint(1, min(6, len(mutated)))]
                elif iteration % 4 == 2:
                    mutated.extend(b"\x00" * rng.randint(1, 12))
                else:
                    mutated[2:4] = rng.randrange(0, 80).to_bytes(2, "big")
                with self.subTest(packet_type=i + 1, mutation=iteration):
                    self.compare(i, bytes(mutated), len(packet) if iteration % 4 == 2 else None)

    def test_invalid_lengths_and_misalignment(self):
        for i, packet in enumerate(self.make_packets()):
            for length in (0, 1, 15, 16, len(packet) - 1, len(packet) + 1):
                with self.subTest(packet_type=i + 1, pkt_len=length):
                    self.compare(i, packet, length)
            self.compare(i, packet + b"\xff")


if __name__ == "__main__":
    unittest.main()
