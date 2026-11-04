"""W02b: LSDB snapshots of parsed LSA mappings, with frozen W02a baseline.

Offline tests execute real production LSDB methods from AST, substituting only
Scapy-dependent imports and the clock. Real integration uses ospfv3.lsdb and
Routing from the installed environment on Ubuntu.
"""
import ast
import copy
import logging
import random
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
CURRENT = ROOT / 'ospfv3' / 'lsdb.py'
FROZEN = Path(__file__).with_name('_w02b_lsdb_reference.py')
DIAGNOSTICS = Path(__file__).with_name('diagnose_b5_1_known_issues.py')
D03 = Path(__file__).with_name('test_d03_lsdb_equivalence.py')


def class_methods(path):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'LSDB')
    return {n.name: n for n in klass.body if isinstance(n, ast.FunctionDef)}


def cmp_instances(new, old):
    # Deterministic comparator for offline trace-equivalence only. Real protocol
    # ordering is covered by existing B5.1 / D03 tests using actual LSA code.
    lhs = (new['ls_sequence'], new['ls_checksum'])
    rhs = (old['ls_sequence'], old['ls_checksum'])
    return (lhs > rhs) - (lhs < rhs)


class Clock:
    def __init__(self):
        self.value = 500.0
        self.calls = 0

    def monotonic(self):
        self.calls += 1
        return self.value


class Log:
    def __init__(self):
        self.trace = []

    def info(self, message, *args):
        self.trace.append((message, args))


def load_offline(path):
    """Compile original/updated *production class* without altering its AST."""
    clock = Clock()
    source = ast.parse(path.read_text(encoding='utf-8'))
    klass = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == 'LSDB')
    namespace = {
        'copy': copy,
        'time': SimpleNamespace(monotonic=clock.monotonic),
        'cfg': SimpleNamespace(MAX_AGE=3600),
        'compare_lsa_instances': cmp_instances,
        'ospfv3_lsa_type_description': lambda kind: f'LSA-{kind}',
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[klass], type_ignores=[])), str(path), 'exec'), namespace)
    result = namespace['LSDB'](Log())
    return result, clock


def lsa(kind=0x2001, seq=0x80000001, age=1, checksum=123, body=None, router='1.1.1.1'):
    payload = {'links': [{'metric': 10, 'extra': ['aa', 'bb']}]} if body is None else body
    key = 'router_lsa' if kind == 0x2001 else ('intra_area_prefix_lsa' if kind == 0x2009 else 'payload')
    return dict(ls_type=kind, link_state_id='0.0.0.0', advertising_router=router,
                ls_sequence=seq, ls_checksum=checksum, ls_age=age,
                ls_length=100, **{key: payload})


def key(entry):
    return entry['ls_type'], entry['link_state_id'], entry['advertising_router']


class TestW02bSnapshot(unittest.TestCase):
    def setUp(self):
        self.new, self.clock = load_offline(CURRENT)
        self.old, self.old_clock = load_offline(FROZEN)

    def test_01_only_install_ast_changed(self):
        old, new = class_methods(FROZEN), class_methods(CURRENT)
        self.assertEqual(set(old), set(new))
        for name in sorted(old):
            if name != '_install':
                self.assertEqual(ast.dump(old[name], include_attributes=False),
                                 ast.dump(new[name], include_attributes=False), name)
        install_src = ast.get_source_segment(CURRENT.read_text(), new['_install'])
        self.assertIn('copy.deepcopy(lsa)', install_src)
        self.assertNotIn('dict(lsa)', install_src)

    def test_02_frozen_original_is_shallow(self):
        self.assertIn('entry = dict(lsa)', FROZEN.read_text())
        self.assertNotIn('copy.deepcopy(lsa)', FROZEN.read_text())
        entry = lsa()
        self.old.update([entry])
        self.assertIs(self.old.get(key(entry))['router_lsa'], entry['router_lsa'])

    def test_03_router_lsa_nested_links_snapshot(self):
        entry = lsa()
        self.assertTrue(self.new.update([entry]))
        saved = self.new.get(key(entry))
        entry['router_lsa']['links'][0]['metric'] = 99
        entry['router_lsa']['links'][0]['extra'].append('cc')
        self.assertEqual(saved['router_lsa']['links'][0], {'metric': 10, 'extra': ['aa', 'bb']})

    def test_04_prefix_lsa_nested_prefixes_snapshot(self):
        payload = dict(prefixes=[{'prefix': '2001:db8:1::', 'prefix_options': 0, 'metric': 10}])
        entry = lsa(kind=0x2009, body=payload)
        self.new.update([entry])
        payload['prefixes'][0]['metric'] = 111
        payload['prefixes'][0]['prefix_options'] = 1
        self.assertEqual(self.new.get(key(entry))['intra_area_prefix_lsa']['prefixes'][0]['metric'], 10)
        self.assertEqual(self.new.get(key(entry))['intra_area_prefix_lsa']['prefixes'][0]['prefix_options'], 0)

    def test_05_link_lsa_nested_prefixes_snapshot(self):
        payload = {'prefixes': [{'prefix': '2001:db8:12::', 'meta': [1, 2]}]}
        entry = lsa(kind=8, body=payload)
        self.assertFalse(self.new.update([entry]))
        payload['prefixes'][0]['meta'].append(3)
        self.assertEqual(self.new.get(key(entry))['payload']['prefixes'][0]['meta'], [1, 2])

    def test_06_unknown_lsa_preserves_nested_bytes(self):
        entry = lsa(kind=0x200b, body={'opaque': b'\x00\xff\x01', 'unknown': [1, {'x': 2}]})
        self.assertFalse(self.new.update([entry]))
        entry['payload']['unknown'][1]['x'] = 100
        self.assertEqual(self.new.get(key(entry))['payload']['opaque'], b'\x00\xff\x01')
        self.assertEqual(self.new.get(key(entry))['payload']['unknown'][1]['x'], 2)

    def test_07_shared_subtrees_remain_shared_in_snapshot_but_detached(self):
        common = {'metric': [10]}
        entry = lsa(body={'links': [common, common]})
        self.new.update([entry])
        result = self.new.get(key(entry))['router_lsa']['links']
        self.assertIs(result[0], result[1])
        self.assertIsNot(result[0], common)
        common['metric'].append(50)
        self.assertEqual(result[0]['metric'], [10])

    def test_08_bytearray_payload_is_cloned_and_bytes_remain_equal(self):
        entry = lsa(body={'raw': b'header\x00', 'buffer': bytearray(b'body')})
        self.new.update([entry])
        entry['router_lsa']['buffer'][0] = 0
        saved = self.new.get(key(entry))
        self.assertEqual(saved['router_lsa']['buffer'], bytearray(b'body'))
        self.assertEqual(saved['router_lsa']['raw'], b'header\x00')

    def test_09_input_untouched_and_metadata_unchanged(self):
        entry = lsa(age=99)
        before = copy.deepcopy(entry)
        self.new.update([entry])
        self.assertEqual(entry, before)
        self.assertNotIn('_age_base', entry)
        saved = self.new.get(key(entry))
        self.assertEqual(saved['_age_base'], 99)
        self.assertEqual(saved['_age_timestamp'], 500.0)
        self.assertEqual(self.clock.calls, 1)

    def test_10_duplicate_ignored_identity_and_no_clock(self):
        entry = lsa()
        self.new.update([entry])
        before = self.new.get(key(entry))
        self.clock.calls = 0
        self.assertFalse(self.new.update([copy.deepcopy(entry)]))
        self.assertIs(self.new.get(key(entry)), before)
        self.assertEqual(self.clock.calls, 1)  # get_age of current entry

    def test_11_newer_lsa_replaces_with_independent_snapshot(self):
        first = lsa()
        self.new.update([first])
        newer = lsa(seq=0x80000002)
        self.assertTrue(self.new.update([newer]))
        newer['router_lsa']['links'][0]['metric'] = 700
        self.assertEqual(self.new.get(key(newer))['router_lsa']['links'][0]['metric'], 10)
        self.assertEqual(self.new.get(key(newer))['ls_sequence'], 0x80000002)

    def test_12_maxage_flush_and_no_install(self):
        expired = lsa(age=3600)
        self.assertFalse(self.new.update([expired]))
        self.assertFalse(self.new)
        first = lsa()
        self.new.update([first])
        self.assertTrue(self.new.update([lsa(age=3600)]))
        self.assertEqual(len(self.new), 0)

    def test_13_log_and_clock_trace_on_valid_lsas(self):
        batch = [lsa(kind=0x2001), lsa(kind=0x2009), lsa(kind=8)]
        self.assertEqual(self.old.update(copy.deepcopy(batch)), self.new.update(copy.deepcopy(batch)))
        self.assertEqual(self.old.logger.trace, self.new.logger.trace)
        self.assertEqual(self.old_clock.calls, self.clock.calls)
        self.assertEqual(self.old.entries, self.new.entries)

    def test_14_generator_and_snapshot_of_each_install(self):
        entries = [lsa(router=f'1.1.1.{i}') for i in range(1, 5)]
        self.assertTrue(self.new.update(iter(entries)))
        for entry in entries:
            entry['router_lsa']['links'].clear()
            self.assertEqual(len(self.new.get(key(entry))['router_lsa']['links']), 1)

    def test_15_randomized_equivalence_without_external_mutation(self):
        rng = random.Random(0xB02B)
        for step in range(800):
            self.clock.value = self.old_clock.value = 500.0 + step
            if step % 17 == 0:
                ret_old = self.old.purge_expired()
                ret_new = self.new.purge_expired()
            elif step % 29 == 0:
                ret_old = self.old.clear_remote('1.1.1.1')
                ret_new = self.new.clear_remote('1.1.1.1')
            else:
                item = lsa(kind=rng.choice((0x2001, 0x2009, 8, 0x2010)),
                           router=rng.choice(('1.1.1.1', '2.2.2.2', '3.3.3.3')),
                           seq=rng.choice((0x80000001, 0x80000002, 0x80000003)),
                           age=rng.choice((0, 1, 100, 3598, 3600)),
                           checksum=rng.randrange(1000),
                           body={'links': [{'metric': rng.randint(1, 65535)}]})
                ret_old = self.old.update([copy.deepcopy(item)])
                ret_new = self.new.update([copy.deepcopy(item)])
            self.assertEqual(ret_old, ret_new, step)
            self.assertEqual(self.old.entries, self.new.entries, step)
            self.assertEqual(self.old.logger.trace, self.new.logger.trace, step)
            self.assertEqual(self.old_clock.calls, self.clock.calls, step)

    def test_16_fixed_d03_test_keeps_nonalias_equivalence(self):
        source = D03.read_text()
        self.assertIn("self.assertIsNot(new_entry['body'], new_original['body'])", source)
        self.assertIn("self.assertIs(old_entry['body'], old_original['body'])", source)
        self.assertIn("self.assertEqual(self.old_log.records, self.new_log.records)", source)
        self.assertIn('test_randomized_updates_and_expirations', source)

    def test_17_real_scapy_lsdb_routing_and_diagnostic(self):
        try:
            from ospfv3.lsdb import LSDB
            from ospfv3.routing import Routing
            from test_lsdb_spf_b5_1 import R1, ROOT, link, router_lsa, prefix_lsa
        except ImportError as exc:
            self.skipTest(f'real Scapy environment missing: {exc}')
        db = LSDB(logging.getLogger('W02b.real'))
        received = router_lsa(R1, link(ROOT, 10))
        db.update([received])
        received['router_lsa']['links'][0]['metric'] = 99
        stored = next(v for v in db.values() if v['ls_type'] == 0x2001)
        self.assertEqual(stored['router_lsa']['links'][0]['metric'], 10)
        p = prefix_lsa(R1, ('2001:db8:88::', 64, 10))
        db.update([p])
        self.assertIn(('2001:db8:88::', 64), Routing(db).build_ipv6_routing_table())
        diag = DIAGNOSTICS.read_text()
        self.assertNotIn('    @unittest.expectedFailure\n    def test_lsdb_nested_content_is_snapshot_at_installation', diag)
        self.assertNotIn('    @unittest.expectedFailure\n    def test_nu_bit_prefix_not_installed_as_unicast_route', diag)


if __name__ == '__main__':
    unittest.main()
