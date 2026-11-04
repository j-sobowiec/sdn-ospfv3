"""S01: differential regression against frozen legacy checksum / LSA ordering.

Run with the project's real Scapy 2.7.0 (not a mocked Scapy module).
Reference functions below replicate the original algorithm from baseline SHA
5356dda7c898e774878bafe27eee4335d339abf2.
"""

import random
import unittest

import scapy
from scapy.utils import fletcher16_checksum

from ospfv3 import config as cfg
from ospfv3.lsa import (
    compare_lsa_instances,
    finalize_ospfv3_lsa_checksum,
    ospfv3_lsa_checksum,
)


def legacy_checksum(raw):
    if len(raw) < 20:
        raise ValueError("LSA is too short for checksum calculation")
    buf = bytearray(raw)
    buf[16:18] = b"\x00\x00"
    c0 = c1 = 0
    for b in buf[2:]:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    x = ((len(buf) - 17) * c0 - c1) % 255
    if x <= 0:
        x += 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    return x << 8 | y


def legacy_comparison(first, second):
    signed = lambda n: n - (1 << 32) if n & (1 << 31) else n
    a, b = signed(first["ls_sequence"]), signed(second["ls_sequence"])
    if a > b:
        return 1
    if a < b:
        return -1
    if first["ls_checksum"] > second["ls_checksum"]:
        return 1
    if first["ls_checksum"] < second["ls_checksum"]:
        return -1
    a, b = first["ls_age"], second["ls_age"]
    if a == cfg.MAX_AGE and b != cfg.MAX_AGE:
        return 1
    if b == cfg.MAX_AGE and a != cfg.MAX_AGE:
        return -1
    if abs(a - b) > cfg.MAX_AGE_DIFF:
        if a < b:
            return 1
        if a > b:
            return -1
    return 0


class TestS01Checksum(unittest.TestCase):
    def test_scapy_version(self):
        self.assertEqual(scapy.__version__, "2.7.0")

    def test_short_input_exceptions(self):
        for length in (0, 1, 16, 17, 18, 19):
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "LSA is too short for checksum calculation"):
                    ospfv3_lsa_checksum(bytes(length))
                with self.assertRaisesRegex(ValueError, "LSA is too short"):
                    finalize_ospfv3_lsa_checksum(bytes(length))

    def test_differential_checksum_and_finalizer(self):
        rng = random.Random(20261018)
        sizes = [20, 21, 24, 28, 32, 36, 40, 44, 48, 52, 80, 128, 256, 1500]
        # Random payloads also exercise nonzero existing checksum bytes and
        # nonstandard/unknown LS types (the checksum API is type-independent).
        for i in range(600):
            size = sizes[i % len(sizes)]
            payload = rng.randbytes(size)
            for raw in (payload, bytearray(payload), memoryview(payload)):
                with self.subTest(index=i, form=type(raw).__name__):
                    original = bytes(raw)
                    expected = legacy_checksum(original)
                    self.assertEqual(ospfv3_lsa_checksum(raw), expected)
                    result = finalize_ospfv3_lsa_checksum(raw)
                    self.assertIsInstance(result, bytes)
                    self.assertEqual(result, original[:16] + expected.to_bytes(2, "big") + original[18:])
                    self.assertEqual(finalize_ospfv3_lsa_checksum(result), result)
                    self.assertEqual(bytes(raw), original)  # no mutation
                    # Fletcher checkbytes embedded in the LSA yield zero residue.
                    self.assertEqual(fletcher16_checksum(result[2:]), 0)

    def test_age_excluded(self):
        raw = bytearray(range(40))
        baseline = ospfv3_lsa_checksum(raw)
        for age in (0, 1, 3600, 65535):
            raw[:2] = age.to_bytes(2, "big")
            self.assertEqual(ospfv3_lsa_checksum(raw), baseline)


class TestS01Ordering(unittest.TestCase):
    def test_differential_comparison(self):
        rng = random.Random(5356)
        edge_seqs = [0, 1, 0x7fffffff, 0x80000000, 0x80000001, 0xfffffffe, 0xffffffff]
        ages = [0, 1, cfg.MAX_AGE_DIFF, cfg.MAX_AGE_DIFF + 1, cfg.MAX_AGE - 1, cfg.MAX_AGE]
        for i in range(2500):
            seq1 = rng.choice(edge_seqs) if i % 2 else rng.getrandbits(32)
            seq2 = seq1 if i % 3 else rng.choice(edge_seqs)
            c1 = rng.randrange(65536)
            c2 = c1 if i % 2 else rng.randrange(65536)
            a1, a2 = rng.choice(ages), rng.choice(ages)
            first = {"ls_sequence": seq1, "ls_checksum": c1, "ls_age": a1}
            second = {"ls_sequence": seq2, "ls_checksum": c2, "ls_age": a2}
            with self.subTest(i=i):
                self.assertEqual(compare_lsa_instances(first, second), legacy_comparison(first, second))
                self.assertEqual(compare_lsa_instances(second, first), legacy_comparison(second, first))


if __name__ == "__main__":
    unittest.main()
