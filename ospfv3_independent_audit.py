"""Additional independent checks for the OSPFv3 wire format.

Run from the root of the SDN project, with Scapy installed in the Ryu venv:
    python -m unittest -v ospfv3_independent_audit

Unlike the original baseline tests, this file does NOT use the project's
OSPFv3 packet checksum implementation or reference SHA hashes.
It checks RFC-format invariants, parameter variations and corruption detection.
It does not replace FRR/Ryu/Containernet integration tests.
"""

import logging
import socket
import struct
import unittest

from ospfv3 import config as cfg
from ospfv3.local_lsa import LocalLSA
from ospfv3.packet import (
    build_ospfv3_hello_frame,
    build_ospfv3_dbd_frame,
    build_ospfv3_lsr_frame,
    build_ospfv3_lsu_frame,
    build_ospfv3_lsack_frame,
    build_ospfv3_packet,
    build_ospfv3_frame,
)
from ospfv3.parser import parse_hello, parse_dbd, parse_lsr, parse_lsu, parse_lsack


def ipv6(packet):
    return socket.inet_ntop(socket.AF_INET6, packet)


def check_internet_checksum(payload):
    """Independent one's-complement checksum verifier: valid -> 0xffff."""
    if len(payload) % 2:
        payload += b"\x00"
    total = sum(int.from_bytes(payload[i:i + 2], 'big') for i in range(0, len(payload), 2))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total == 0xffff


def valid_ospfv3_checksum(frame):
    source, destination = frame[22:38], frame[38:54]
    ospf = frame[54:]
    pseudo = source + destination + struct.pack('!I3xB', len(ospf), 89)
    return check_internet_checksum(pseudo + ospf)


def fletcher_ok(lsa):
    """Independent residue check; age bytes excluded, checksum included."""
    c0 = c1 = 0
    for byte in lsa[2:]:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return c0 == 0 and c1 == 0


class FakeLSDB:
    def values(self):
        return [{
            'ls_type': 0x2001,
            'advertising_router': '1.1.1.1',
            'router_lsa': {'links': [{
                'type': 1,
                'neighbor_router_id': cfg.ROUTER_ID,
                'neighbor_interface_id': '0.0.0.1',
                'interface_id': '0.0.3.40',
            }]},
        }]


class IndependentAuditTests(unittest.TestCase):
    def setUp(self):
        self.local = LocalLSA(FakeLSDB(), logging.getLogger('audit'))
        self.assertTrue(self.local.initialize('1.1.1.1'))

    def assert_frame(self, frame, packet_type, destination):
        self.assertEqual(frame[12:14], b'\x86\xdd')
        self.assertEqual(frame[14] >> 4, 6)
        self.assertEqual(frame[20], 89)
        self.assertEqual(frame[21], 1)
        self.assertEqual(ipv6(frame[22:38]), cfg.LINK_LOCAL)
        self.assertEqual(ipv6(frame[38:54]), destination)
        self.assertEqual(int.from_bytes(frame[18:20], 'big'), len(frame) - 54)
        ospf = frame[54:]
        self.assertEqual(ospf[0], 3)
        self.assertEqual(ospf[1], packet_type)
        self.assertEqual(int.from_bytes(ospf[2:4], 'big'), len(ospf))
        self.assertEqual(ospf[4:8], socket.inet_aton(cfg.ROUTER_ID))
        self.assertEqual(ospf[8:12], socket.inet_aton(cfg.AREA_ID))
        self.assertEqual(ospf[14], cfg.INSTANCE_ID)
        self.assertEqual(ospf[15], 0)
        self.assertTrue(valid_ospfv3_checksum(frame), f'invalid OSPFv3 checksum, type {packet_type}')
        return ospf

    def test_hello_zero_one_many(self):
        for peers in ((), ('1.1.1.1',), ('1.1.1.1', '2.2.2.2', '3.3.3.3')):
            with self.subTest(peers=peers):
                raw = self.assert_frame(build_ospfv3_hello_frame(peers), 1, 'ff02::5')
                body = raw[16:]
                self.assertEqual(len(body), 20 + 4 * len(peers))
                self.assertEqual(int.from_bytes(body[0:4], 'big'), cfg.INTERFACE_ID)
                self.assertEqual(body[4], cfg.ROUTER_PRIORITY)
                self.assertEqual(int.from_bytes(body[5:8], 'big'), cfg.OPTIONS)
                self.assertEqual(int.from_bytes(body[8:10], 'big'), cfg.HELLO_INTERVAL)
                self.assertEqual(int.from_bytes(body[10:12], 'big'), cfg.DEAD_INTERVAL)
                self.assertEqual(body[12:20], b'\0' * 8)
                self.assertEqual([socket.inet_ntoa(body[i:i+4]) for i in range(20, len(body), 4)], list(peers))
                self.assertEqual(parse_hello(raw, len(raw))['neighbors'], list(peers))

    def test_dbd_flag_and_sequence_variations(self):
        for flags, seq in ((0, 0), (1, 0x12345678), (2, 0xffffffff), (4, 1), (7, 0x80000001)):
            with self.subTest(flags=flags, seq=seq):
                raw = self.assert_frame(build_ospfv3_dbd_frame(seq, flags), 2, 'ff02::5')
                body = raw[16:]
                self.assertEqual(len(body), 12)
                self.assertEqual(body[0], 0)
                self.assertEqual(int.from_bytes(body[1:4], 'big'), cfg.OPTIONS)
                self.assertEqual(int.from_bytes(body[4:6], 'big'), cfg.INTERFACE_MTU)
                self.assertEqual(body[6], 0)
                self.assertEqual(body[7], flags)
                self.assertEqual(int.from_bytes(body[8:12], 'big'), seq)
                self.assertEqual(parse_dbd(raw, len(raw))['dd_sequence'], seq)

    def test_multiple_lsr_requests(self):
        req = [
            {'ls_type':0x0008,'link_state_id':'0.0.3.40','advertising_router':'1.1.1.1'},
            {'ls_type':0x2001,'link_state_id':'0.0.0.0','advertising_router':'2.2.2.2'},
            {'ls_type':0x2009,'link_state_id':'0.0.0.0','advertising_router':'3.3.3.3'},
        ]
        raw = self.assert_frame(
            build_ospfv3_lsr_frame(req, 'fe80::1', 'aa:bb:cc:dd:ee:ff'), 3, 'fe80::1'
        )
        self.assertEqual(len(raw[16:]), len(req) * 12)
        for i, requested in enumerate(req):
            fragment = raw[16 + i*12 : 28 + i*12]
            self.assertEqual(fragment[0:2], b'\x00\x00')
            self.assertEqual(int.from_bytes(fragment[2:4], 'big'), requested['ls_type'])
            self.assertEqual(fragment[4:8], socket.inet_aton(requested['link_state_id']))
            self.assertEqual(fragment[8:12], socket.inet_aton(requested['advertising_router']))
        self.assertEqual(parse_lsr(raw, len(raw)), req)

    def test_three_local_lsa_checksums(self):
        self.assertEqual({lsa['ls_type'] for lsa in self.local.values()}, {0x0008, 0x2001, 0x2009})
        for entry in self.local.values():
            with self.subTest(kind=entry['ls_type']):
                lsa = entry['raw_lsa']
                self.assertEqual(int.from_bytes(lsa[18:20], 'big'), len(lsa))
                self.assertEqual(int.from_bytes(lsa[2:4], 'big'), entry['ls_type'])
                self.assertEqual(lsa[4:8], socket.inet_aton(entry['link_state_id']))
                self.assertEqual(lsa[8:12], socket.inet_aton(cfg.ROUTER_ID))
                self.assertTrue(fletcher_ok(lsa))

    def test_lsu_and_lsack_independent_wire_checks(self):
        local_list = [entry for _, entry in sorted(self.local.items())]
        body = self.local.build_update_body()
        self.assertEqual(int.from_bytes(body[:4], 'big'), 3)
        self.assertEqual(body[4:], b''.join(lsa['raw_lsa'] for lsa in local_list))
        frame = build_ospfv3_lsu_frame(body, 'fe80::1', 'aa:bb:cc:dd:ee:ff')
        ospf = self.assert_frame(frame, 4, 'fe80::1')
        self.assertEqual(ospf[16:], body)
        parsed = parse_lsu(ospf, len(ospf))
        self.assertEqual(len(parsed), 3)
        ack = build_ospfv3_lsack_frame(parsed, 'fe80::1', 'aa:bb:cc:dd:ee:ff')
        ospf_ack = self.assert_frame(ack, 5, 'fe80::1')
        self.assertEqual(ospf_ack[16:], b''.join(lsa['raw_header'] for lsa in parsed))
        self.assertEqual(len(parse_lsack(ospf_ack, len(ospf_ack))), 3)

    def test_packet_checksum_detects_corruption(self):
        frame = bytearray(build_ospfv3_hello_frame(('1.1.1.1',)))
        self.assertTrue(valid_ospfv3_checksum(frame))
        frame[54 + 16 + 4] ^= 1
        self.assertFalse(valid_ospfv3_checksum(frame))

    def test_ipv6_address_is_covered_by_checksum(self):
        frame = bytearray(build_ospfv3_hello_frame())
        self.assertTrue(valid_ospfv3_checksum(frame))
        frame[37] ^= 1  # last source IPv6 byte
        self.assertFalse(valid_ospfv3_checksum(frame))

    def test_lsa_checksum_detects_corruption_and_excludes_age(self):
        lsa = bytearray(next(iter(self.local.values()))['raw_lsa'])
        self.assertTrue(fletcher_ok(lsa))
        lsa[0] ^= 1  # age intentionally excluded
        self.assertTrue(fletcher_ok(lsa))
        lsa[20] ^= 1
        self.assertFalse(fletcher_ok(lsa))

    def test_raw_common_header_and_frame_wrapping(self):
        body = b'\x00\x00\x00\x00'
        for kind in range(1, 6):
            with self.subTest(kind=kind):
                ospf = build_ospfv3_packet(kind, body, 'fe80::1')
                self.assertEqual(ospf[16:], body)
                frame = build_ospfv3_frame(ospf, 'fe80::1', 'aa:bb:cc:dd:ee:ff')
                self.assertEqual(self.assert_frame(frame, kind, 'fe80::1'), ospf)
                self.assertEqual(frame[:6], bytes.fromhex('aabbccddeeff'))
                self.assertEqual(frame[6:12], bytes.fromhex(cfg.ROUTER_MAC.replace(':', '')))


if __name__ == '__main__':
    unittest.main()
