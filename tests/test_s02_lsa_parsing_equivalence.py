"""S02: differential Router/Link/Intra-Area-Prefix decoding (Scapy 2.7.0).

Compare against the independent pre-Scapy parser saved with the project.
Run from the project root with Scapy installed:
    PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -p 'test_s02_lsa_parsing_equivalence.py' -v
"""

import ipaddress
import random
import unittest

from ospfv3 import lsa as current
from scapy.contrib.ospf import OSPFv3_Link, OSPFv3_Prefix_Item
import test_lsa_scapy as fixtures


PARSERS = (
    (current.parse_ospfv3_router_lsa, fixtures.reference.parse_ospfv3_router_lsa),
    (current.parse_ospfv3_link_lsa, fixtures.reference.parse_ospfv3_link_lsa),
    (current.parse_ospfv3_intra_area_prefix_lsa,
     fixtures.reference.parse_ospfv3_intra_area_prefix_lsa),
)


class TestS02ParsingEquivalence(unittest.TestCase):
    def assert_exact(self, actual, expected):
        self.assertEqual(type(actual), type(expected))
        if isinstance(expected, dict):
            self.assertEqual(actual.keys(), expected.keys())
            for key in expected:
                self.assert_exact(actual[key], expected[key])
        elif isinstance(expected, list):
            self.assertEqual(len(actual), len(expected))
            for left, right in zip(actual, expected):
                self.assert_exact(left, right)
        else:
            self.assertEqual(actual, expected)

    def compare_parser(self, index, packet):
        actual_parser, reference_parser = PARSERS[index]
        self.assert_exact(actual_parser(packet), reference_parser(packet))

    def test_router_link_ids_and_all_link_types(self):
        rng = random.Random(0x5202)
        for _ in range(100):
            links = [fixtures.router_link(
                link_type=rng.choice([1, 2, 3, 4, 99, 255]),
                metric=rng.randrange(65536),
                intid=rng.getrandbits(32),
                neighintid=rng.getrandbits(32),
                neighbor=str(ipaddress.IPv4Address(rng.getrandbits(32))),
                reserved=rng.randrange(256),
            ) for _ in range(rng.randrange(5))]
            self.compare_parser(0, fixtures.make_router(
                links, flags=rng.randrange(256), options=rng.getrandbits(24)))

    def test_prefix_lengths_and_addresses(self):
        rng = random.Random(0x6202)
        for _ in range(100):
            prefixes = []
            for _ in range(rng.randrange(6)):
                length = rng.choice([0, 1, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128])
                address = str(ipaddress.IPv6Address(rng.getrandbits(128)))
                prefixes.append(fixtures.prefix_item(
                    length, address, options=rng.randrange(256), word=rng.randrange(65536)))
            self.compare_parser(1, fixtures.make_link(prefixes, priority=rng.randrange(256)))
            self.compare_parser(2, fixtures.make_intra(prefixes))

    def test_no_ipv6_address_truncation(self):
        """Previously S02 mistakenly returned the first character of each prefix."""
        for length, address in ((0, '::'), (64, '2001:db8:1::'), (128, '2001:db8::1')):
            with self.subTest(length=length):
                prefix = fixtures.prefix_item(length, address)
                self.compare_parser(1, fixtures.make_link([prefix]))
                self.compare_parser(2, fixtures.make_intra([prefix]))

    def test_frr_advertised_prefixes_with_cidr_are_decoded(self):
        """Scapy 2.7.0 exposes IP6PrefixField as 'address/prefixlen'."""
        prefixes = [
            fixtures.prefix_item(64, prefix)
            for prefix in ('2001:db8:10::', '2001:db8:12::', '2001:db8:31::')
        ]
        for index, constructor in ((1, fixtures.make_link), (2, fixtures.make_intra)):
            with self.subTest(lsa_type=index):
                raw_lsa = constructor(prefixes)
                self.compare_parser(index, raw_lsa)
                decoded = PARSERS[index][0](raw_lsa)
                self.assertEqual(
                    [item['prefix'] for item in decoded['prefixes']],
                    ['2001:db8:10::', '2001:db8:12::', '2001:db8:31::'],
                )

    def test_scapy_fields_have_expected_decoded_types(self):
        """Confirm the Scapy 2.7.0 decoded field shapes actually observed."""
        link = OSPFv3_Link(fixtures.router_link(1, 10, 0xFFFFFFFF, 0, '1.2.3.4'))
        self.assertIs(type(link.intid), int)
        self.assertIs(type(link.neighintid), int)
        self.assertIs(type(link.type), int)
        self.assertIs(type(link.metric), int)
        for prefixlen in (0, 1, 32, 33, 64, 65, 128):
            with self.subTest(prefixlen=prefixlen):
                item = OSPFv3_Prefix_Item(fixtures.prefix_item(prefixlen, '2001:db8::1234'))
                self.assertIs(type(item.prefix), str)
                self.assertIs(type(item.prefixlen), int)
                self.assertIs(type(item.metric), int)

    def test_malformed_prefixes_still_rejected(self):
        for index, constructor, count_offset, count_size, offset in (
            (1, fixtures.make_link, 40, 4, 44),
            (2, fixtures.make_intra, 20, 2, 32),
        ):
            parser = PARSERS[index][0]
            with self.subTest(index=index):
                valid = constructor([fixtures.prefix_item(128, '2001:db8::1')])
                for prefix_length in (129, 255):
                    damaged = bytearray(valid)
                    damaged[offset] = prefix_length
                    with self.assertRaises(ValueError):
                        parser(bytes(damaged))
                for count in (0, 2, 65535):
                    damaged = bytearray(valid)
                    damaged[count_offset:count_offset+count_size] = count.to_bytes(count_size, 'big')
                    with self.assertRaises(ValueError):
                        parser(bytes(damaged))
                for cut in (1, 2, 4):
                    damaged = bytearray(valid[:-cut])
                    damaged[18:20] = len(damaged).to_bytes(2, 'big')
                    with self.assertRaises(ValueError):
                        parser(bytes(damaged))
                damaged = bytearray(valid + b'\x00' * 4)
                damaged[18:20] = len(damaged).to_bytes(2, 'big')
                with self.assertRaises(ValueError):
                    parser(bytes(damaged))

    def test_ospfv3_lsa_parsers_keep_legacy_api(self):
        for index, packet in enumerate((
            fixtures.make_router(), fixtures.make_link(), fixtures.make_intra(),
        )):
            with self.subTest(index=index):
                self.compare_parser(index, packet)
        self.assertEqual(current.parse_ospfv3_router_lsa(fixtures.make_router())['links'], [])
        self.assertEqual(current.parse_ospfv3_link_lsa(fixtures.make_link())['prefixes'], [])
        self.assertEqual(current.parse_ospfv3_intra_area_prefix_lsa(fixtures.make_intra())['prefixes'], [])


if __name__ == '__main__':
    unittest.main()
