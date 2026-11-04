"""D03: differential regression against the unchanged pre-D03 LSDB.

The reference is a frozen copy of ospfv3/lsdb.py from the original repository;
D01/D02/S01-S04 did not change that file. Runs with real ospfv3.lsa and
ospfv3.routing under the user's Scapy/Ryu environment.
"""

import copy
import random
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from _d03_lsdb_reference import LSDB as ReferenceLSDB
import _d03_lsdb_reference as reference_module
from ospfv3 import config as cfg
from ospfv3.lsdb import LSDB
import ospfv3.lsdb as candidate_module
from ospfv3.routing import Routing


class LogCapture:
    def __init__(self):
        self.records = []

    def info(self, message, *args):
        self.records.append((message, args, message % args))


class Clock:
    def __init__(self):
        self.now = 100.0
        self.calls = 0

    def monotonic(self):
        self.calls += 1
        return self.now


def make_lsa(kind=0x2001, router='1.1.1.1', lsid='0.0.0.0', seq=0x80000001,
             checksum=123, age=1, **additional):
    entry = {
        'ls_type': kind,
        'advertising_router': router,
        'link_state_id': lsid,
        'ls_sequence': seq,
        'ls_checksum': checksum,
        'ls_age': age,
        'ls_length': 24,
    }
    entry.update(additional)
    return entry


class PairedLSDB(unittest.TestCase):
    def setUp(self):
        self.old_log, self.new_log = LogCapture(), LogCapture()
        self.old, self.new = ReferenceLSDB(self.old_log), LSDB(self.new_log)
        self.old_clock, self.new_clock = Clock(), Clock()
        self.old_patcher = patch.object(reference_module, 'time',
                                        SimpleNamespace(monotonic=self.old_clock.monotonic))
        self.new_patcher = patch.object(candidate_module, 'time',
                                        SimpleNamespace(monotonic=self.new_clock.monotonic))
        self.old_patcher.start()
        self.new_patcher.start()
        self.addCleanup(self.new_patcher.stop)
        self.addCleanup(self.old_patcher.stop)

    def at(self, time_value):
        self.old_clock.now = self.new_clock.now = time_value

    def equivalent(self):
        self.assertEqual(self.old.entries, self.new.entries)
        self.assertEqual(self.old_log.records, self.new_log.records)
        self.assertEqual(self.old_clock.calls, self.new_clock.calls)
        self.assertEqual(bool(self.old), bool(self.new))
        self.assertEqual(len(self.old), len(self.new))
        self.assertEqual(list(self.old.items()), list(self.new.items()))
        self.assertEqual(list(self.old.values()), list(self.new.values()))

    def update_both(self, entries):
        old_result = self.old.update(copy.deepcopy(entries))
        new_result = self.new.update(copy.deepcopy(entries))
        self.assertIs(type(old_result), bool)
        self.assertEqual(old_result, new_result)
        self.equivalent()
        return new_result

    def purge_both(self):
        self.assertEqual(self.old.purge_expired(), self.new.purge_expired())
        self.equivalent()

    def clear_both(self, local):
        self.assertEqual(self.old.clear_remote(local), self.new.clear_remote(local))
        self.equivalent()

    def test_install_update_flush_and_logging(self):
        for kind in (0x2001, 0x2009, 0x0008, 0x200b):
            with self.subTest(kind=kind):
                first = make_lsa(kind=kind)
                self.update_both([first])
                self.update_both([first])
                self.update_both([make_lsa(kind=kind, seq=0x80000002)])
                self.update_both([make_lsa(kind=kind, seq=0x80000001,
                                           age=cfg.MAX_AGE)])  # older flush rejected
                self.update_both([make_lsa(kind=kind, seq=0x80000002,
                                           age=cfg.MAX_AGE)])  # equal flush accepted
                self.update_both([make_lsa(kind=kind, age=cfg.MAX_AGE)])  # absent

    def test_randomized_updates_and_expirations(self):
        rng = random.Random(0xD03)
        kinds = (0x2001, 0x2009, 0x0008, 0x2010, 0x200b)
        for step in range(1700):
            self.at(100 + step * rng.choice((0, 0.02, 0.99, 1, 5, 40)))
            if step % 17 == 0:
                self.purge_both()
            elif step % 41 == 0:
                self.clear_both('10.10.10.10')
            else:
                amount = rng.randint(1, 4)
                items = [make_lsa(
                    kind=rng.choice(kinds),
                    router=rng.choice(('10.10.10.10', '1.1.1.1', '2.2.2.2')),
                    lsid=rng.choice(('0.0.0.0', '0.0.0.1')),
                    seq=rng.choice((0x80000001, 0x80000002, 0x80000003, 0x7fffffff)),
                    checksum=rng.randint(0, 65535),
                    age=rng.choice((0, 1, 20, 899, 1000, cfg.MAX_AGE - 1,
                                    cfg.MAX_AGE, cfg.MAX_AGE + 1)),
                ) for _ in range(amount)]
                self.update_both(items)

    def test_aging_boundaries_and_clock_calls(self):
        self.update_both([make_lsa(age=cfg.MAX_AGE - 3)])
        for instant in (99.0, 100.0, 100.999, 101.0, 102.999, 103.0, 10000.0):
            with self.subTest(instant=instant):
                self.at(instant)
                for key in list(self.old.entries):
                    self.assertEqual(self.old.get_age(self.old.get(key)),
                                     self.new.get_age(self.new.get(key)))
                self.equivalent()
        self.purge_both()
        self.assertFalse(self.new)

    def test_maxage_threshold_and_sequence_priority(self):
        self.update_both([make_lsa(age=2000, checksum=0xFFFF)])
        self.at(1300)
        self.update_both([make_lsa(age=1, checksum=0xFFFF)])
        self.update_both([make_lsa(age=cfg.MAX_AGE, checksum=0xFFFE)])
        self.update_both([make_lsa(age=cfg.MAX_AGE, checksum=0xFFFF)])
        self.assertFalse(self.new)
        self.update_both([make_lsa(seq=0x80000001, checksum=1)])
        self.update_both([make_lsa(seq=0x7fffffff, checksum=0)])
        self.update_both([make_lsa(seq=0x80000002, checksum=65535)])

    def test_purge_preserves_original_order_and_log_format(self):
        items = [make_lsa(kind=kind, router=str(n) + '.1.1.1',
                          age=cfg.MAX_AGE - n)
                 for n, kind in enumerate((0x2001, 0x0008, 0x2009, 0x200b), 1)]
        self.update_both(items)
        self.at(105)
        self.purge_both()
        self.assertEqual(len(self.new_log.records), len(self.old_log.records))

    def test_clear_remote_idempotent_and_preserves_local(self):
        self.update_both([
            make_lsa(router='10.10.10.10', kind=0x2001),
            make_lsa(router='1.1.1.1', kind=0x2001),
            make_lsa(router='2.2.2.2', kind=0x0008),
        ])
        self.clear_both('10.10.10.10')
        self.clear_both('10.10.10.10')
        self.assertEqual(len(self.new), 1)

    def test_shallow_copy_and_ignored_instance_identity(self):
        original = make_lsa(body={'mutable': [1, 2]})
        key = (original['ls_type'], original['link_state_id'],
               original['advertising_router'])
        old_original, new_original = copy.deepcopy(original), copy.deepcopy(original)
        self.old.update([old_original])
        self.new.update([new_original])
        old_entry, new_entry = self.old.get(key), self.new.get(key)
        self.assertIsNot(old_entry, old_original)
        self.assertIsNot(new_entry, new_original)
        self.assertIs(old_entry['body'], old_original['body'])
        # W02b: previously shared nested payload is intentionally isolated.
        self.assertIsNot(new_entry['body'], new_original['body'])
        old_original['body']['mutable'].append(3)
        new_original['body']['mutable'].append(3)
        self.assertEqual(old_entry['body']['mutable'], [1, 2, 3])
        self.assertEqual(new_entry['body']['mutable'], [1, 2])
        old_original['ls_sequence'] = new_original['ls_sequence'] = 0x7fffffff
        self.assertEqual(old_entry['ls_sequence'], 0x80000001)
        self.assertEqual(new_entry['ls_sequence'], 0x80000001)
        old_identity, new_identity = id(old_entry), id(new_entry)
        self.assertFalse(self.old.update([copy.deepcopy(original)]))
        self.assertFalse(self.new.update([copy.deepcopy(original)]))
        self.assertEqual(id(self.old.get(key)), old_identity)
        self.assertEqual(id(self.new.get(key)), new_identity)
        # Original D03 reference deliberately aliases nested dictionaries.
        # Other differential tests still check data, age, logs, SPF, and updates.
        self.assertEqual(self.old.get(key)['body']['mutable'], [1, 2, 3])
        self.assertEqual(self.new.get(key)['body']['mutable'], [1, 2])
        self.assertEqual(self.old_log.records, self.new_log.records)
        self.assertEqual(self.old_clock.calls, self.new_clock.calls)

    def test_generator_and_multiple_same_key_in_one_batch(self):
        values = ((0x80000001, 1), (0x80000003, 1),
                  (0x80000002, 10), (0x80000003, 5))
        self.assertEqual(
            self.old.update(make_lsa(seq=seq, checksum=checksum)
                            for seq, checksum in values),
            self.new.update(make_lsa(seq=seq, checksum=checksum)
                            for seq, checksum in values),
        )
        self.equivalent()
        self.assertEqual(self.new.get((0x2001, '0.0.0.0', '1.1.1.1'))['ls_sequence'],
                         0x80000003)
        self.assertEqual(self.new.get((0x2001, '0.0.0.0', '1.1.1.1'))['ls_checksum'], 5)

    def test_get_age_uninstalled_and_timestamp_none(self):
        for entry in (make_lsa(age=17),
                      make_lsa(age=17, _age_base=31, _age_timestamp=None)):
            self.assertEqual(self.old.get_age(entry), self.new.get_age(entry))
        self.equivalent()

    def test_spf_and_routing_tables_equal(self):
        local = '10.10.10.10'
        r1, r2 = '1.1.1.1', '2.2.2.2'
        def p2p(peer, metric=10):
            return {'type': 1, 'neighbor_router_id': peer,
                    'metric': metric, 'interface_id': '0.0.0.1',
                    'neighbor_interface_id': '0.0.0.2'}
        self.update_both([
            make_lsa(router=r1, router_lsa={'links': [p2p(local), p2p(r2)]}),
            make_lsa(router=r2, router_lsa={'links': [p2p(r1)]}),
            make_lsa(kind=0x2009, router=r2, intra_area_prefix_lsa={
                'prefixes': [{'prefix': '2001:db8:77::', 'prefix_length': 64,
                              'prefix_options': 0, 'metric': 10}],
                'referenced_advertising_router': r2,
                'referenced_ls_type': 0x2001,
                'referenced_link_state_id': '0.0.0.0',
            }),
        ])
        old_route, new_route = Routing(self.old), Routing(self.new)
        self.assertEqual(old_route.build_router_graph(), new_route.build_router_graph())
        self.assertEqual(old_route.run_spf(), new_route.run_spf())
        self.assertEqual(old_route.build_ipv6_routing_table(),
                         new_route.build_ipv6_routing_table())
        self.at(4000)
        self.purge_both()
        self.assertEqual(old_route.build_ipv6_routing_table(),
                         new_route.build_ipv6_routing_table())


if __name__ == '__main__':
    unittest.main()
