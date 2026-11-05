"""S03: Scapy auto length/checksum must preserve local OSPFv3 LSA bytes.

These tests compare the current builders against the independent, pre-Scapy
implementation already retained in tests/local_lsa_before_scapy.py.
"""

import random
import struct
import unittest
from unittest.mock import patch

from ospfv3 import config as cfg
from test_local_lsa_scapy import FakeLSDB, NEIGHBOR, new_pair, fletcher_residue


class TestS03NativeScapySerialization(unittest.TestCase):
    def assert_three_wire_formats(self, new, old):
        for name in ('build_router', 'build_link', 'build_prefix'):
            with self.subTest(builder=name):
                args = (NEIGHBOR,) if name == 'build_router' else ()
                got = getattr(new, name)(*args)
                reference = getattr(old, name)(*args)
                self.assertEqual(got, reference)
                self.assertIs(type(got), bytes)
                self.assertEqual(struct.unpack('!H', got[18:20])[0], len(got))
                self.assertNotEqual(got[16:18], b'\x00\x00')
                self.assertEqual(fletcher_residue(got), (0, 0))

    def test_default_three_lsas_byte_for_byte(self):
        new, old = new_pair()
        self.assert_three_wire_formats(new, old)

    def test_sequences_and_prefix_boundaries_byte_for_byte(self):
        rng = random.Random(20261019)
        lengths = (0, 1, 32, 33, 64, 65, 96, 127, 128)
        for iteration in range(36):
            length1 = lengths[iteration % len(lengths)]
            length2 = lengths[(iteration * 5) % len(lengths)]
            sequence = rng.choice((0x80000001, 0x80000002, 0x80000500, 0x7ffffffe))
            with self.subTest(iteration=iteration, lan_len=length1, transit_len=length2):
                with patch.multiple(
                    cfg,
                    LAN_PREFIX_LEN=length1,
                    TRANSIT_PREFIX_LEN=length2,
                    OPTIONS=rng.randrange(1 << 24),
                    LAN_PREFIX_METRIC=rng.randrange(1, 1000),
                    ROUTER_PRIORITY=rng.randrange(256),
                    INTERFACE_COST=rng.randrange(1, 1000),
                ):
                    new, old = new_pair(FakeLSDB(neighbor_interface=808 + iteration))
                    for instance in (new, old):
                        instance.router_sequence = sequence
                        instance.link_sequence = sequence
                        instance.prefix_sequence = sequence
                    self.assert_three_wire_formats(new, old)

    def test_initialize_update_and_reoriginated_lsas_equal(self):
        new, old = new_pair()
        self.assertTrue(new.initialize(NEIGHBOR))
        self.assertTrue(old.initialize(NEIGHBOR))
        self.assertEqual(new.build_update_body(), old.build_update_body())
        self.assertTrue(new.reoriginate(NEIGHBOR, 's03-regression'))
        self.assertTrue(old.reoriginate(NEIGHBOR, 's03-regression'))
        self.assertEqual(new.build_update_body(), old.build_update_body())
        self.assertEqual(
            {k: v['raw_lsa'] for k, v in new.entries.items()},
            {k: v['raw_lsa'] for k, v in old.entries.items()},
        )


if __name__ == '__main__':
    unittest.main()
