"""D04 differential regression: current Neighbor vs frozen pre-D04 reference.

Run with the project's real ospfv3.lsa comparator (Scapy installed on Ubuntu):
    python -m unittest discover -s tests -p 'test_d04_neighbor_equivalence.py' -v
"""

import copy
import logging
import random
import unittest
from unittest.mock import Mock, patch

from ospfv3 import config as cfg
from ospfv3.neighbor import Neighbor
from _d04_neighbor_reference import Neighbor as OriginalNeighbor


SEQUENCES = (0x80000001, 0x80000002, 0x80000003, 0x7ffffffe, 0x7fffffff)
AGES = (0, 1, 100, cfg.MAX_AGE_DIFF + 100, cfg.MAX_AGE)


def lsa(*, index=0, seq=0x80000001, checksum=0x1234, age=100):
    return {
        "ls_type": (0x2001, 0x2008, 0x2009)[index % 3],
        "link_state_id": f"0.0.0.{index % 7}",
        "advertising_router": f"10.0.0.{index % 5}",
        "ls_sequence": seq,
        "ls_checksum": checksum,
        "ls_age": age,
    }


class TestD04Differential(unittest.TestCase):
    def setUp(self):
        self.new_log = Mock(spec=logging.Logger)
        self.old_log = Mock(spec=logging.Logger)
        with patch("time.time", return_value=4321.125):
            self.new = Neighbor(self.new_log)
            self.old = OriginalNeighbor(self.old_log)
        self.assert_state_equal()

    def assert_state_equal(self):
        self.assertEqual(
            {k: v for k, v in vars(self.new).items() if k != "logger"},
            {k: v for k, v in vars(self.old).items() if k != "logger"},
        )
        self.assertEqual(self.new_log.mock_calls, self.old_log.mock_calls)

    def set_requests(self, values):
        self.new.request_list = copy.deepcopy(values)
        self.old.request_list = copy.deepcopy(values)

    def update_both(self, received):
        self.new.update_request_list(copy.deepcopy(received))
        self.old.update_request_list(copy.deepcopy(received))
        self.assert_state_equal()

    def test_initial_sequence_millisecond_and_mask(self):
        for clock in (0, 1.567, 4321.125, 4_300_000.0, 1_000_000_000.0):
            with self.subTest(clock=clock), patch("time.time", return_value=clock):
                self.assertEqual(self.new._new_dbd_sequence(), self.old._new_dbd_sequence())

    def test_dead_interval_exact_boundary_and_clock_calls(self):
        for last_hello in (None, 0.0, 100.0):
            for offset in (-0.001, 0, 0.001):
                self.new.last_hello_received = self.old.last_hello_received = last_hello
                tick = 100.0 + cfg.DEAD_INTERVAL + offset
                with self.subTest(last=last_hello, offset=offset):
                    with patch("time.monotonic", return_value=tick) as timer:
                        a = self.new.dead_interval_expired(cfg.DEAD_INTERVAL)
                        b = self.old.dead_interval_expired(cfg.DEAD_INTERVAL)
                        self.assertEqual(a, b)
                        self.assertEqual(timer.call_count, 0 if last_hello is None else 2)
        self.assert_state_equal()

    def test_mark_hello_reset_disables_timer(self):
        with patch("time.monotonic", return_value=777.125):
            self.new.mark_hello_received()
            self.old.mark_hello_received()
        self.assert_state_equal()
        with patch("time.time", return_value=4321.125):
            self.new.reset_adjacency()
            self.old.reset_adjacency()
        self.assert_state_equal()
        with patch("time.monotonic", return_value=10000.0):
            self.assertEqual(self.new.dead_interval_expired(40), self.old.dead_interval_expired(40))

    def test_reset_exchange_wrap_and_preservation(self):
        for previous, proposed in ((4, 5), (7, 7), (0xffffffff, 0xffffffff), (1, 0)):
            for instance in (self.new, self.old):
                instance.port = 4
                instance.router_id = "1.1.1.1"
                instance.ipv6 = "fe80::1"
                instance.mac = "02:00:00:00:00:01"
                instance.router_ids = ["1.1.1.1", "2.2.2.2"]
                instance.last_hello_received = 12.0
                instance.dbd_sequence = previous
                instance.dbd_negotiated = True
                instance.dbd_exchange_complete = True
                instance.request_list = [lsa()]
                instance.lsr_sent = True
            old_new = self.new.request_list
            old_old = self.old.request_list
            with patch.object(Neighbor, "_new_dbd_sequence", return_value=proposed), \
                 patch.object(OriginalNeighbor, "_new_dbd_sequence", return_value=proposed):
                self.new.reset_exchange()
                self.old.reset_exchange()
            with self.subTest(previous=previous, proposed=proposed):
                self.assert_state_equal()
                self.assertIsNot(self.new.request_list, old_new)
                self.assertIsNot(self.old.request_list, old_old)
                self.assertEqual(old_new, old_old)

    def test_reset_adjacency_vs_complete_reset(self):
        for instance in (self.new, self.old):
            instance.port = 9
            instance.router_id = "2.2.2.2"
            instance.router_ids = ["2.2.2.2"]
            instance.ipv6 = "fe80::2"
            instance.mac = "02:00:00:00:00:02"
            instance.request_list = [lsa(index=1)]
        with patch("time.time", return_value=8888.5):
            self.new.reset_adjacency()
            self.old.reset_adjacency()
        self.assert_state_equal()
        self.assertEqual(self.new.port, 9)
        with patch("time.time", return_value=8888.5):
            self.new.reset()
            self.old.reset()
        self.assert_state_equal()
        self.assertIsNone(self.new.port)

    def test_noop_with_empty_request_list_keeps_identity(self):
        before_new = self.new.request_list
        before_old = self.old.request_list
        self.update_both([lsa()])
        self.assertIs(self.new.request_list, before_new)
        self.assertIs(self.old.request_list, before_old)
        self.new_log.info.assert_not_called()

    def test_request_identity_and_short_circuit_on_missing_fields(self):
        request = lsa()
        self.set_requests([request])
        # If ls_type differs, neither implementation may access missing identity fields.
        partial_received = [{"ls_type": 0x9999}]
        self.update_both(partial_received)
        self.assertEqual(self.new.request_list, [request])
        for missing in ("ls_type", "link_state_id", "advertising_router"):
            received = lsa()
            received.pop(missing)
            if missing == "ls_type":
                # Original accesses request["ls_type"] before received["ls_type"].
                pass
            self.set_requests([request])
            with self.subTest(missing=missing):
                with self.assertRaises(KeyError) as actual:
                    self.new.update_request_list([received])
                with self.assertRaises(KeyError) as expected:
                    self.old.update_request_list([received])
                self.assertEqual(actual.exception.args, expected.exception.args)
                self.assert_state_equal()

    def test_duplicates_order_and_logging_messages(self):
        req = lsa(index=1)
        old = lsa(index=2, seq=0x80000003)
        third = lsa(index=3)
        self.set_requests([req, copy.deepcopy(req), old, third])
        self.update_both([
            lsa(index=99), lsa(index=2, seq=0x80000001),
            lsa(index=1, seq=0x80000002), lsa(index=3),
        ])
        self.assertEqual(len(self.new.request_list), 1)
        self.assertEqual(len(self.new_log.info.call_args_list), 1)
        self.update_both([lsa(index=2, seq=0x80000003)])
        self.assertEqual(self.new.request_list, [])
        self.assertEqual(len(self.new_log.info.call_args_list), 3)

    def test_retained_entries_same_objects_and_original_list_not_mutated(self):
        requests = [lsa(index=1), lsa(index=2, seq=0x80000003), lsa(index=3)]
        self.set_requests(requests)
        old_new = self.new.request_list
        old_old = self.old.request_list
        held_new = self.new.request_list[1]
        held_old = self.old.request_list[1]
        self.update_both([lsa(index=1), lsa(index=2, seq=0x80000001)])
        self.assertIsNot(self.new.request_list, old_new)
        self.assertIsNot(self.old.request_list, old_old)
        self.assertIs(self.new.request_list[0], held_new)
        self.assertIs(self.old.request_list[0], held_old)
        self.assertEqual(old_new, old_old)
        self.assertEqual(len(old_new), 3)

    def test_received_generator_semantics_unchanged(self):
        reqs = [lsa(index=1), lsa(index=2), lsa(index=3)]
        self.set_requests(reqs)
        received = [lsa(index=3), lsa(index=1)]
        self.new.update_request_list(iter(copy.deepcopy(received)))
        self.old.update_request_list(iter(copy.deepcopy(received)))
        self.assert_state_equal()
        # Deliberately avoid consuming/replaying received generators across requests.
        self.assertEqual(len(self.new.request_list), 2)

    def test_comparator_invocation_order_on_matching_identity(self):
        requests = [lsa(index=1, seq=0x80000003), lsa(index=2)]
        received = [lsa(index=1, seq=0x80000001), lsa(index=99),
                    lsa(index=1, seq=0x80000003), lsa(index=2)]
        self.set_requests(requests)
        from ospfv3.lsa import compare_lsa_instances as real_comparator
        calls_new, calls_old = [], []

        def spy(calls):
            def wrapped(first, second):
                calls.append((copy.deepcopy(first), copy.deepcopy(second)))
                return real_comparator(first, second)
            return wrapped

        with patch("ospfv3.neighbor.compare_lsa_instances", new=spy(calls_new)), \
             patch("_d04_neighbor_reference.compare_lsa_instances", new=spy(calls_old)):
            self.update_both(received)
        self.assertEqual(calls_new, calls_old)
        self.assertEqual(len(calls_new), 3)

    def test_seeded_randomized_request_batches(self):
        rng = random.Random(20261019)
        for iteration in range(1200):
            requests = [lsa(index=rng.randrange(24), seq=rng.choice(SEQUENCES),
                            checksum=rng.randrange(0x10000), age=rng.choice(AGES))
                        for _ in range(rng.randrange(0, 11))]
            received = [lsa(index=rng.randrange(24), seq=rng.choice(SEQUENCES),
                            checksum=rng.randrange(0x10000), age=rng.choice(AGES))
                        for _ in range(rng.randrange(0, 18))]
            if requests and rng.random() < 0.8:
                received.append(copy.deepcopy(rng.choice(requests)))
            self.set_requests(requests)
            self.new_log.reset_mock()
            self.old_log.reset_mock()
            with self.subTest(iteration=iteration):
                self.update_both(received)


if __name__ == "__main__":
    unittest.main()
