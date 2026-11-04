"""D02 differential regression: original S03 LocalLSA vs Scapy header version.

Scapy 2.7.0 and project runtime required. Run:
  python -m unittest discover -s tests -p 'test_d02_local_lsa_equivalence.py' -v
"""

import importlib.util
import ipaddress
import logging
from pathlib import Path
import random
import socket
import struct
import unittest
from unittest.mock import patch

from ospfv3 import config as cfg
from ospfv3.local_lsa import LocalLSA


def load_reference():
    path = Path(__file__).with_name("_d02_local_lsa_reference.py")
    spec = importlib.util.spec_from_file_location("d02_local_lsa_reference", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.LocalLSA


OriginalLocalLSA = load_reference()
LOGGER = logging.getLogger("d02-regression")
NEIGHBOR = "1.1.1.1"


class FakeLSDB:
    def __init__(self, neighbor_id=NEIGHBOR, peer_if_id=808):
        self.neighbor_id = neighbor_id
        self.peer_if_id = peer_if_id

    def values(self):
        return [{
            "ls_type": 0x2001,
            "advertising_router": self.neighbor_id,
            "router_lsa": {"links": [{
                "type": 1,
                "neighbor_router_id": cfg.ROUTER_ID,
                "neighbor_interface_id": socket.inet_ntoa(
                    struct.pack("!I", cfg.INTERFACE_ID)
                ),
                "interface_id": socket.inet_ntoa(
                    struct.pack("!I", self.peer_if_id)
                ),
            }]},
        }]


def pair(lsdb=None):
    if lsdb is None:
        lsdb = FakeLSDB()
    return LocalLSA(lsdb, LOGGER), OriginalLocalLSA(lsdb, LOGGER)


class D02HeaderEquivalence(unittest.TestCase):
    def assert_install_equal(self, data):
        new, old = pair()
        with patch("time.monotonic", return_value=1724.25):
            self.assertIsNone(new.install(data))
            self.assertIsNone(old.install(data))
        self.assertEqual(new.entries, old.entries)
        self.assertEqual(len(new.entries), 1)
        self.assertIs(next(iter(new.entries.values()))["raw_lsa"], data)

    def test_native_scapy_header_layout(self):
        from scapy.contrib.ospf import OSPFv3_LSA_Hdr
        header = OSPFv3_LSA_Hdr(
            struct.pack("!HHIIIHH", 42, 0x2001, 0x12345678,
                        0x0A0A0A0A, 0x80000003, 0xCAFE, 40)
        )
        self.assertEqual((header.age, header.type, header.id,
                          header.adrouter, header.seq, header.chksum,
                          header.len),
                         (42, 0x2001, "18.52.86.120", "10.10.10.10",
                          0x80000003, 0xCAFE, 40))

    def test_three_generated_lsa_headers(self):
        new, old = pair()
        for raw in (old.build_router(NEIGHBOR), old.build_link(), old.build_prefix()):
            with self.subTest(type=struct.unpack("!H", raw[2:4])[0]):
                self.assert_install_equal(raw)
                self.assert_install_equal(raw + b"EXTRA_PADDING")

    def test_untouched_arbitrary_headers_and_length_mismatch(self):
        # LocalLSA.install is a storage helper, not a full on-wire verifier.
        rng = random.Random(0xD02)
        for index in range(700):
            header = struct.pack("!HHIIIHH",
                rng.randrange(0x10000),
                rng.randrange(0x10000),
                rng.getrandbits(32),
                rng.getrandbits(32),
                rng.getrandbits(32),
                rng.randrange(0x10000),
                rng.randrange(0x10000))
            data = header + rng.randbytes(index % 67)
            with self.subTest(index=index):
                self.assert_install_equal(data)

    def test_short_inputs_preserve_exception_and_state(self):
        for size in range(20):
            with self.subTest(length=size):
                new, old = pair()
                for impl in (new, old):
                    with self.assertRaisesRegex(ValueError, "^Local LSA is too short$"):
                        impl.install(bytes(range(size)))
                    self.assertEqual(impl.entries, {})
        self.assert_install_equal(bytes(20))

    def test_non_bytes_buffers_keep_original_identity(self):
        raw = struct.pack("!HHIIIHH", 65535, 0x9fff, 1,
                          0xFFFFFFFF, 0x80000001, 0, 0)
        self.assert_install_equal(raw)
        self.assert_install_equal(bytearray(raw))
        self.assert_install_equal(memoryview(raw))

    def test_interface_id_ipv4_conversion_and_recovery(self):
        for interface_id in (0, 1, 37, 0x12345678, 0xFFFFFFFF):
            with self.subTest(interface_id=interface_id):
                with patch.object(cfg, "INTERFACE_ID", interface_id):
                    new, old = pair(FakeLSDB(peer_if_id=0xAABBCCDD))
                    self.assertEqual(new.get_neighbor_interface_id(NEIGHBOR),
                                     old.get_neighbor_interface_id(NEIGHBOR))
                    self.assertEqual(new.build_link(), old.build_link())
                    interface_lsid = str(ipaddress.IPv4Address(interface_id))
                    headers = [
                        {"ls_type": typ, "link_state_id": ls_id,
                         "advertising_router": cfg.ROUTER_ID,
                         "ls_sequence": 0x80000030}
                        for typ, ls_id in (
                            (0x2001, "0.0.0.0"),
                            (0x0008, interface_lsid),
                            (0x2009, "0.0.0.0"),
                        )
                    ]
                    self.assertEqual(new.recover_sequences(headers, True),
                                     old.recover_sequences(headers, True))
                    self.assertEqual(
                        (new.router_sequence, new.link_sequence, new.prefix_sequence),
                        (old.router_sequence, old.link_sequence, old.prefix_sequence))
                    self.assertEqual(new.build_router(NEIGHBOR), old.build_router(NEIGHBOR))

    def test_initialize_reoriginate_and_retransmit(self):
        new, old = pair()
        with patch("time.monotonic", return_value=234.5):
            self.assertEqual(new.initialize(NEIGHBOR), old.initialize(NEIGHBOR))
            self.assertEqual(new.entries, old.entries)
            self.assertEqual(new.build_update_body(), old.build_update_body())
            pending = {
                key: {"ls_sequence": value["ls_sequence"],
                      "ls_checksum": value["ls_checksum"]}
                for key, value in new.entries.items()
            }
            self.assertEqual(new.build_pending_body(pending), old.build_pending_body(pending))
            self.assertEqual(new.reoriginate(NEIGHBOR, "d02-differential"),
                             old.reoriginate(NEIGHBOR, "d02-differential"))
            self.assertEqual(new.entries, old.entries)
            self.assertEqual(new.build_update_body(), old.build_update_body())


if __name__ == "__main__":
    unittest.main()
