"""C07: compare logging traces with the frozen C06 method implementations.

The production controller is not imported except by one optional real-Ryu test.
No networking, RyuApp instantiation, or mutation of production files.
"""
import ast
import inspect
import random
import unittest
from pathlib import Path
from types import SimpleNamespace

from _c07_logging_reference import (
    LoggingReference, cfg, ospfv3_lsa_type_description,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE = PROJECT_ROOT / 'ospfv3' / 'controller_diagnostics.py'
METHODS = ('log_dbd', 'log_spf_result')
_MISSING = object()


def current_logging_class():
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    controller = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                      and n.name == 'OSPFDiagnosticsMixin')
    names = [n for n in controller.body if isinstance(n, ast.FunctionDef)
             and n.name in METHODS]
    assert sorted(n.name for n in names) == sorted(METHODS)
    klass = ast.ClassDef(name='CurrentLogging', bases=[], keywords=[],
                         body=names, decorator_list=[])
    module = ast.fix_missing_locations(ast.Module(body=[klass], type_ignores=[]))
    namespace = {'cfg': cfg,
                 'ospfv3_lsa_type_description': ospfv3_lsa_type_description}
    exec(compile(module, str(SOURCE), 'exec'), namespace)
    return namespace['CurrentLogging']


CurrentLogging = current_logging_class()


class EventRecorder:
    def __init__(self, events, fail_at=None):
        self.events = events
        self.count = 0
        self.fail_at = fail_at

    def info(self, format_string, *args):
        self.count += 1
        self.events.append(('info', format_string, args))
        if self.count == self.fail_at:
            raise RuntimeError('logger unavailable')


class RoutingRecorder:
    def __init__(self, events, distances, previous, fail=None):
        self.events = events
        self.distances = distances
        self.previous = previous
        self.fail = fail

    def run_spf(self):
        self.events.append(('run_spf',))
        return self.distances, self.previous

    def get_spf_next_hop(self, router_id, previous):
        self.events.append(('get_next_hop', router_id, previous is self.previous))
        if self.fail == router_id:
            raise RuntimeError('next-hop unavailable')
        return f'via:{router_id}'


class TracingFlag:
    def __init__(self, name, truthy, calls, fail=False):
        self.name = name
        self.truthy = truthy
        self.calls = calls
        self.fail = fail

    def __bool__(self):
        self.calls.append(('bool', self.name))
        if self.fail:
            raise ValueError('bad flag ' + self.name)
        return self.truthy


def run_dbd(cls, flags=(0, 0, 0), headers=_MISSING, fail_at=None,
            packet=SimpleNamespace(src='fe80::1'), mtu=1500, seq=42,
            call_trace=None):
    if headers is _MISSING:
        headers = []
    events = []
    ctrl = cls()
    ctrl.logger = EventRecorder(events, fail_at)
    try:
        ctrl.log_dbd(4, packet, '1.1.1.1', '0.0.0.0', mtu, 7,
                     flags[0], flags[1], flags[2], seq, headers)
        outcome = ('return', None)
    except Exception as exc:
        outcome = (type(exc).__name__, str(exc))
    return outcome, events, call_trace


def run_spf(cls, distances, previous, fail_at=None, fail_next=None):
    events = []
    ctrl = cls()
    ctrl.logger = EventRecorder(events, fail_at)
    ctrl.routing = RoutingRecorder(events, distances, previous, fail_next)
    try:
        ctrl.log_spf_result()
        outcome = ('return', None)
    except Exception as exc:
        outcome = (type(exc).__name__, str(exc))
    return outcome, events


class TestC07LoggingEquivalence(unittest.TestCase):
    def assert_dbd_same(self, **kwargs):
        self.assertEqual(run_dbd(LoggingReference, **kwargs),
                         run_dbd(CurrentLogging, **kwargs))

    def assert_spf_same(self, distances, previous, **kwargs):
        self.assertEqual(run_spf(LoggingReference, distances, previous, **kwargs),
                         run_spf(CurrentLogging, distances, previous, **kwargs))

    def test_01_method_signatures_and_docstrings(self):
        for name in METHODS:
            a, b = getattr(LoggingReference, name), getattr(CurrentLogging, name)
            self.assertEqual(inspect.signature(a), inspect.signature(b))
            self.assertEqual(a.__doc__, b.__doc__)

    def test_02_all_eight_dbd_flag_combinations(self):
        for flags in range(8):
            bits = ((flags >> 2) & 1, (flags >> 1) & 1, flags & 1)
            with self.subTest(flags=bits):
                self.assert_dbd_same(flags=bits)

    def test_03_dbd_header_details_and_order(self):
        headers = [
            {'ls_type': 0x2001, 'advertising_router': '10.10.10.10',
             'link_state_id': '0.0.0.0', 'ls_sequence': 0x80000001},
            {'ls_type': 0x0008, 'advertising_router': '1.1.1.1',
             'link_state_id': '0.0.0.1', 'ls_sequence': 0x80000002},
        ]
        self.assert_dbd_same(headers=headers, flags=(1, 0, 1), seq=0xffffffff)

    def test_04_dbd_truth_evaluation_order(self):
        def run(cls):
            calls = []
            flags = [TracingFlag(n, True, calls) for n in 'abc']
            result = run_dbd(cls, flags=flags)
            return result, calls
        self.assertEqual(run(LoggingReference), run(CurrentLogging))
        self.assertEqual([('bool', 'a'), ('bool', 'b'), ('bool', 'c')],
                         run(CurrentLogging)[1])

    def test_05_dbd_invalid_flags_and_exception_order(self):
        for failed in range(3):
            def run(cls):
                calls = []
                flags = [TracingFlag(str(j), j % 2, calls, fail=(j == failed))
                         for j in range(3)]
                return run_dbd(cls, flags=flags), calls
            self.assertEqual(run(LoggingReference), run(CurrentLogging))

    def test_06_dbd_logger_error_positions(self):
        for step in (1, 2, 3, 4):
            self.assert_dbd_same(
                flags=(1, 0, 0), fail_at=step,
                headers=[{'ls_type': 0x2001, 'advertising_router': 'a',
                          'link_state_id': 'b', 'ls_sequence': 3},
                         {'ls_type': 8, 'advertising_router': 'c',
                          'link_state_id': 'd', 'ls_sequence': 5}])

    def test_07_dbd_malformed_lsa_and_lengths(self):
        for headers in ([], [{}], [{'ls_type': 8}],
                        [{'ls_type': 8, 'advertising_router': 1}], None):
            self.assert_dbd_same(headers=headers)
        self.assert_dbd_same(headers=[{'ls_type': 8, 'advertising_router': 1,
                                      'link_state_id': 0, 'ls_sequence': 'bad'}])

    def test_08_randomized_dbd_traces(self):
        rng = random.Random(20261019)
        for i in range(1300):
            flags = tuple(rng.choice([None, True, False, 0, 1, 2]) for _ in range(3))
            headers = [{'ls_type': rng.choice([8, 0x2001, 0x2009]),
                        'advertising_router': str(rng.randint(0, 50)),
                        'link_state_id': str(rng.randint(0, 50)),
                        'ls_sequence': rng.randrange(1 << 32)}
                       for _ in range(rng.randrange(6))]
            with self.subTest(case=i):
                self.assert_dbd_same(flags=flags, headers=headers,
                                     seq=rng.randrange(1 << 32),
                                     fail_at=rng.choice([None, None, 1, 2, 3, 4]))

    def test_09_spf_root_only_and_no_root(self):
        root = cfg.ROUTER_ID
        self.assert_spf_same({root: 0}, {root: None})
        self.assert_spf_same({}, {})

    def test_10_spf_router_order_and_next_hop(self):
        root = cfg.ROUTER_ID
        distances = {'9.9.9.9': 18, '2.2.2.2': 10,
                     root: 0, '3.3.3.3': 10}
        previous = {rid: (None if rid == root else root)
                    for rid in distances}
        self.assert_spf_same(distances, previous)
        events = run_spf(CurrentLogging, distances, previous)[1]
        hop_ids = [e[1] for e in events if e[0] == 'get_next_hop']
        self.assertEqual(hop_ids, [root, '2.2.2.2', '3.3.3.3', '9.9.9.9'])

    def test_11_spf_exception_and_logger_failure(self):
        root = cfg.ROUTER_ID
        d = {root: 0, '2.2.2.2': 5}
        self.assert_spf_same(d, {root: None})  # missing predecessor
        for fail_at in (1, 2, 3, 4):
            self.assert_spf_same(d, {root: None, '2.2.2.2': root},
                                 fail_at=fail_at)
        self.assert_spf_same(d, {root: None, '2.2.2.2': root},
                             fail_next='2.2.2.2')

    def test_12_spf_randomized_topology_traces(self):
        rng = random.Random(20261020)
        for i in range(1300):
            root = cfg.ROUTER_ID
            ids = [root] + [f'{v}.{v}.{v}.{v}' for v in rng.sample(range(1, 50), 8)]
            d = {rid: rng.randint(0, 1000) for rid in ids[:rng.randint(1, 9)]}
            prev = {rid: (None if rid == root else root) for rid in d}
            if rng.randrange(12) == 0:
                prev.pop(rng.choice(list(prev)))
            with self.subTest(case=i):
                self.assert_spf_same(d, prev,
                                     fail_at=rng.choice([None, None, 1, 2, 4]))



if __name__ == '__main__':
    unittest.main()
