"""M02: byte-for-byte tests for typed Scapy LSU encoding with opaque LSA bytes.

This test intentionally uses a frozen pre-M02 reference and a no-Scapy
serializer trace for offline checks; real Scapy 2.7.0 tests run on Ubuntu.
"""
import ast
import copy
import hashlib
import importlib
import inspect
import logging
import random
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / 'ospfv3' / 'local_lsa.py'
PACKET = ROOT / 'ospfv3' / 'packet.py'
REFERENCE = Path(__file__).with_name('_m02_lsu_reference.py')
METHODS = ('build_update_body', 'build_pending_body')


class StubRaw:
    def __init__(self, load):
        self.load = load

    def __bytes__(self):
        return self.load


class StubLSUpd:
    calls = []

    def __init__(self, *, lsalist):
        self.lsalist = lsalist
        self.calls.append(self)

    def __bytes__(self):
        return struct.pack('!I', len(self.lsalist)) + b''.join(
            bytes(item) for item in self.lsalist
        )


def frozen_methods(path, klass_name, methods, env=None):
    tree = ast.parse(path.read_text(encoding='utf8'))
    klass = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                 and n.name == klass_name)
    functions = [copy.deepcopy(n) for n in klass.body
                 if isinstance(n, ast.FunctionDef) and n.name in methods]
    assert {n.name for n in functions} == set(methods)
    name = 'LocalTest'
    cls = ast.ClassDef(name=name, bases=[], keywords=[], body=functions,
                       decorator_list=[])
    module = ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[]))
    namespace = dict(env or {})
    exec(compile(module, str(path), 'exec'), namespace)
    return namespace[name]


def isolated_codec():
    tree = ast.parse(PACKET.read_text(encoding='utf8'))
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                and n.name == 'encode_ospfv3_lsu_body')
    names = {'Raw': StubRaw, 'OSPFv3_LSUpd': StubLSUpd}
    exec(compile(ast.fix_missing_locations(ast.Module(
        body=[copy.deepcopy(func)], type_ignores=[])), str(PACKET), 'exec'), names)
    return names['encode_ospfv3_lsu_body']


def scenario(entries, pending=None):
    # Preserve insertion ordering and original data types to catch differences.
    from _m02_lsu_reference import OriginalLocalLSA
    old = OriginalLocalLSA()
    new_cls = frozen_methods(LOCAL, 'LocalLSA', METHODS,
                             {'encode_ospfv3_lsu_body': isolated_codec()})
    new = new_cls()
    old.entries = entries.copy()
    new.entries = entries.copy()
    return old, new, pending


def call(obj, method, *args):
    try:
        return ('ok', getattr(obj, method)(*args))
    except Exception as ex:
        return ('error', type(ex).__name__, str(ex))


def rand_lsa(rng, length):
    return rng.randbytes(length)


class TestM02Offline(unittest.TestCase):
    def setUp(self):
        StubLSUpd.calls = []
        self.codec = isolated_codec()

    def same(self, entries, pending=None):
        old, new, pending = scenario(entries, pending)
        self.assertEqual(call(old, 'build_update_body'),
                         call(new, 'build_update_body'))
        if pending is not None:
            self.assertEqual(call(old, 'build_pending_body', copy.deepcopy(pending)),
                             call(new, 'build_pending_body', copy.deepcopy(pending)))
        self.assertEqual(old.entries, new.entries)
        return call(new, 'build_update_body')

    def test_01_frozen_reference_is_the_original_struct_join(self):
        t = REFERENCE.read_text(encoding='utf8')
        self.assertIn('struct.pack("!I", len(lsas))', t)
        self.assertIn('b"".join(lsas)', t)
        self.assertNotIn('encode_ospfv3_lsu_body', t)

    def test_02_unchanged_method_public_signatures(self):
        from _m02_lsu_reference import OriginalLocalLSA
        cls = frozen_methods(LOCAL, 'LocalLSA', METHODS,
                             {'encode_ospfv3_lsu_body': self.codec})
        for method in METHODS:
            self.assertEqual(inspect.signature(getattr(OriginalLocalLSA, method)),
                             inspect.signature(getattr(cls, method)))

    def test_03_empty_entries_and_empty_pending(self):
        self.same({}, {})
        self.same({}, {('none',): {'ls_sequence': 1, 'ls_checksum': 2}})
        self.same({('a',): {'raw_lsa': b'abc', 'ls_sequence': 1,
                            'ls_checksum': 2}}, {})

    def test_04_three_lsa_types_sorted_and_exact_count(self):
        entries = {
            (0x2009, 'x'): {'raw_lsa': b'prefix', 'ls_sequence': 3, 'ls_checksum': 3},
            (0x0008, 'x'): {'raw_lsa': b'link', 'ls_sequence': 2, 'ls_checksum': 2},
            (0x2001, 'x'): {'raw_lsa': b'router', 'ls_sequence': 1, 'ls_checksum': 1},
        }
        pending = {k: {'ls_sequence': v['ls_sequence'],
                       'ls_checksum': v['ls_checksum']} for k, v in entries.items()}
        result = self.same(entries, pending)
        self.assertEqual(result, ('ok', struct.pack('!I', 3)
                                  + b'linkrouterprefix'))
        self.assertTrue(StubLSUpd.calls)
        self.assertTrue(all(isinstance(p, StubRaw) for p in StubLSUpd.calls[0].lsalist))

    def test_05_unknown_and_malformed_lsa_bytes(self):
        rng = random.Random(0xE205)
        for length in (0, 1, 2, 3, 4, 19, 20, 21, 47, 64, 255):
            self.same({('a',): {'raw_lsa': rand_lsa(rng, length),
                                 'ls_sequence': 8, 'ls_checksum': 9}},
                      {('a',): {'ls_sequence': 8, 'ls_checksum': 9}})

    def test_06_buffers_bytes_bytearray_memoryview(self):
        raw = bytes(range(20))
        for source in (raw, bytearray(raw), memoryview(raw)):
            self.same({1: {'raw_lsa': source, 'ls_sequence': 1,
                            'ls_checksum': 1}},
                      {1: {'ls_sequence': 1, 'ls_checksum': 1}})

    def test_07_stale_pending_and_missing_entry(self):
        e = {1: {'raw_lsa': b'A' * 20, 'ls_sequence': 7, 'ls_checksum': 42}}
        for pending in ({1: {'ls_sequence': 7, 'ls_checksum': 41}},
                        {1: {'ls_sequence': 6, 'ls_checksum': 42}},
                        {2: {'ls_sequence': 7, 'ls_checksum': 42}},
                        {1: {'ls_sequence': 7, 'ls_checksum': 42},
                         2: {'ls_sequence': 7, 'ls_checksum': 42}}):
            self.same(e, pending)

    def test_08_type_errors_match_original_join(self):
        for val in (123, None, 'text', {}, 1.5, object()):
            entries = {1: {'raw_lsa': val, 'ls_sequence': 1, 'ls_checksum': 1}}
            old, new, _ = scenario(entries)
            self.assertEqual(call(old, 'build_update_body'),
                             call(new, 'build_update_body'))
            pending = {1: {'ls_sequence': 1, 'ls_checksum': 1}}
            self.assertEqual(call(old, 'build_pending_body', pending),
                             call(new, 'build_pending_body', pending))

    def test_09_error_priority_bad_entries(self):
        for entries in ({1: {}}, {1: {'ls_sequence': 1, 'ls_checksum': 2}},
                        {2: {'raw_lsa': b'x'}}):
            old, new, _ = scenario(entries)
            self.assertEqual(call(old, 'build_update_body'),
                             call(new, 'build_update_body'))

    def test_10_empty_opaque_lsa_still_counts(self):
        result = self.same({1: {'raw_lsa': b'', 'ls_sequence': 1,
                                 'ls_checksum': 1}},
                           {1: {'ls_sequence': 1, 'ls_checksum': 1}})
        self.assertEqual(result, ('ok', b'\x00\x00\x00\x01'))

    def test_11_direct_helper_can_encode_generators(self):
        lsas = [b'first', b'', b'last']
        self.assertEqual(self.codec(lsa for lsa in lsas),
                         struct.pack('!I', 3) + b''.join(lsas))

    def test_12_randomized_equivalence(self):
        rng = random.Random(20261020)
        for _ in range(1600):
            entries = {}
            pending = {}
            for index in range(rng.randrange(6)):
                key = index * 7 + rng.randrange(7)
                raw = rand_lsa(rng, rng.choice([0, 1, 4, 19, 20, 27, 36, 48, 100]))
                seq = rng.randrange(0xFFFFFFFF)
                ck = rng.randrange(0x10000)
                entries[key] = {'raw_lsa': raw, 'ls_sequence': seq,
                                'ls_checksum': ck}
                if rng.randrange(3):
                    pending[key] = {'ls_sequence': seq if rng.randrange(3) else seq+1,
                                    'ls_checksum': ck if rng.randrange(3) else ck+1}
            self.same(entries, pending)

    def test_13_no_existing_packet_functions_modified(self):
        # The codec is an additive helper, not a new implementation of TX frames.
        tree = ast.parse(PACKET.read_text(encoding='utf8'))
        names = [node.name for node in tree.body if isinstance(node,ast.FunctionDef)]
        self.assertEqual(names.count('encode_ospfv3_lsu_body'), 1)
        self.assertIn('build_ospfv3_lsu', names)
        self.assertIn('build_ospfv3_frame', names)

    def test_14_scapy_field_count_and_raw_calls_in_stub(self):
        data = [memoryview(b'\x01'), bytearray(b'\x02\x03'), b'\xff']
        self.assertEqual(self.codec(data), b'\x00\x00\x00\x03\x01\x02\x03\xff')
        self.assertEqual(len(StubLSUpd.calls), 1)
        self.assertEqual(len(StubLSUpd.calls[0].lsalist), 3)


class TestM02RealScapy(unittest.TestCase):
    def require_scapy(self):
        try:
            import scapy
            from ospfv3 import packet, local_lsa
        except ImportError as exc:
            self.skipTest('Scapy not installed in the analysis environment: ' + str(exc))
        self.assertEqual(scapy.__version__, '2.7.0')
        return packet, local_lsa

    def test_15_real_scapy_lsu_packetlist_wire_bytes(self):
        packet, _ = self.require_scapy()
        from scapy.contrib.ospf import OSPFv3_LSUpd
        from scapy.packet import Raw
        rng = random.Random(0xE205)
        for _ in range(500):
            lsas = [rng.randbytes(rng.choice((0, 1, 3, 19, 20, 24, 56, 170)))
                    for _ in range(rng.randrange(7))]
            expected = struct.pack('!I', len(lsas)) + b''.join(lsas)
            self.assertEqual(packet.encode_ospfv3_lsu_body(lsas), expected)
            self.assertEqual(bytes(OSPFv3_LSUpd(lsalist=[Raw(load=l) for l in lsas])),
                             expected)

    def test_16_real_scapy_real_local_lsa_builders(self):
        packet, local_lsa = self.require_scapy()
        from ospfv3 import config as cfg
        owner = local_lsa.LocalLSA(None, logging.getLogger('M02-real'))
        owner.get_neighbor_interface_id = lambda neighbor: 808
        raw = [owner.build_router('1.1.1.1'), owner.build_link(), owner.build_prefix()]
        for entry in raw:
            self.assertIsInstance(entry, bytes)
            self.assertGreaterEqual(len(entry), 20)
        owner.entries = {
            (typ,): {'raw_lsa': data, 'ls_sequence': 3, 'ls_checksum': 4}
            for typ, data in zip((0x2001, 0x0008, 0x2009), raw)
        }
        expected = struct.pack('!I', 3) + b''.join(raw[i] for i in (1, 0, 2))
        self.assertEqual(owner.build_update_body(), expected)
        pending = {key: {'ls_sequence': 3, 'ls_checksum': 4}
                   for key in owner.entries}
        self.assertEqual(owner.build_pending_body(pending), (expected, 3))

    def test_17_real_scapy_ospf_frame_and_checksum_unchanged(self):
        packet, _ = self.require_scapy()
        from ospfv3 import config as cfg
        raw_lsas = [struct.pack('!HHIIIHH', 3600, 0xABCD, 1,
                                0x01010101, 0x80000001, 0xFFFF, 20),
                    b'\x00', b'']
        body = packet.encode_ospfv3_lsu_body(raw_lsas)
        self.assertEqual(body, struct.pack('!I', 3) + b''.join(raw_lsas))
        old = packet.build_ospfv3_lsu(struct.pack('!I', 3) + b''.join(raw_lsas),
                                     'fe80::1')
        new = packet.build_ospfv3_lsu(body, 'fe80::1')
        self.assertEqual(old, new)
        self.assertEqual(len(old), 16 + len(body))


if __name__ == '__main__':
    unittest.main()
