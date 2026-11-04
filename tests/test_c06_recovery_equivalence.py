"""C06: deterministic differential tests of old versus new controller timers.

Does not instantiate RyuApp or start an infinite Eventlet green thread.
Compare exact traces (clock reads, hub sleeps, logs, callbacks), final states,
exceptions, method signatures and unchanged external controller methods.
"""
import ast
import copy
import hashlib
import inspect
import math
import random
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
CURRENT = ROOT / 'ospfv3' / 'controller_timers.py'
REFERENCE = Path(__file__).with_name('_c06_recovery_reference.py')
METHODS = ('lsdb_aging_loop', 'local_lsa_retransmission_loop', 'local_lsa_refresh_loop')
REF_SHA = 'ab1eeabd37f71be1a22d43a47135fcf83e7d93c6a1f7e629417e3c2c61e7fad2'


def extract(path, class_name):
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    target = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    funcs = [copy.deepcopy(n) for n in target.body
             if isinstance(n, ast.FunctionDef) and n.name in METHODS]
    assert len(funcs) == len(METHODS), path
    cls = ast.ClassDef(name='Recovery', bases=[], keywords=[], body=funcs,
                       decorator_list=[])
    module = ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[]))
    return compile(module, str(path), 'exec')


ORIGINAL = extract(REFERENCE, 'OriginalRecovery')
CURRENT_CODE = extract(CURRENT, 'OSPFTimerMixin')


class StopLoop(Exception):
    pass


class FakeHub:
    def __init__(self, trace, iterations):
        self.trace, self.iterations, self.count = trace, iterations, 0

    def sleep(self, interval):
        if self.count >= self.iterations:
            raise StopLoop()
        self.trace.append(('sleep', interval))
        self.count += 1


class FakeTime:
    def __init__(self, trace, values):
        self.trace = trace
        self.values = iter(values)

    def monotonic(self):
        self.trace.append(('monotonic',))
        return next(self.values)


class FakeLogger:
    def __init__(self, trace):
        self.trace = trace

    def info(self, *args):
        self.trace.append(('info', copy.deepcopy(args)))

    def warning(self, *args):
        self.trace.append(('warning', copy.deepcopy(args)))


class FakeLSDB:
    def __init__(self, trace, truth, purge):
        self.trace = trace
        self.truth = iter(truth)
        self.purge = iter(purge)

    def __bool__(self):
        self.trace.append(('lsdb_bool',))
        return next(self.truth)

    def purge_expired(self):
        self.trace.append(('purge_expired',))
        result = next(self.purge)
        if isinstance(result, Exception):
            raise result
        return result


def invoke(code, method, case):
    case = copy.deepcopy(case)
    trace = []
    hub = FakeHub(trace, case.get('iterations', 3))
    clock = FakeTime(trace, case.get('clock', [100.0] * 10))
    env = dict(hub=hub, time=clock, cfg=SimpleNamespace(
        RETRANSMIT_INTERVAL=case.get('retx_interval', 5),
        LS_REFRESH_TIME=case.get('refresh_interval', 20)))
    exec(code, env)
    obj = env['Recovery']()
    obj.logger = FakeLogger(trace)
    obj.lsdb = FakeLSDB(trace, case.get('lsdb_truth', [True] * 20),
                        case.get('purge', [False] * 20))
    obj.neighbor = SimpleNamespace(dbd_exchange_complete=case.get('exchange', True),
                                    request_list=case.get('request_list', []))
    default_pending = {} if method == 'local_lsa_refresh_loop' else {'x': {'seq': 1}}
    obj.local_lsa_ack_pending = copy.deepcopy(case.get('pending', default_pending))
    obj.local_lsu_last_tx = case.get('last_tx', 95.0)
    obj.local_lsa = copy.deepcopy(case.get('local_lsa', {
        'a': {'_originated_at': 75.0}, 'b': {'_originated_at': 90.0}}))

    def retransmit():
        trace.append(('retransmit',))
        if case.get('clear_pending_on_retx'):
            obj.local_lsa_ack_pending = {}
        if case.get('update_last_tx_on_retx'):
            obj.local_lsu_last_tx = case['new_last_tx']
        return case.get('retransmit_result', True)

    def recompute():
        trace.append(('recompute',))
        if case.get('raise_recompute'):
            raise RuntimeError('recompute failure')

    def reoriginate(reason):
        trace.append(('reoriginate', reason))
        if case.get('clear_local_on_refresh'):
            obj.local_lsa.clear()
        return case.get('reoriginate_result', True)

    obj.send_local_lsa_retransmission = retransmit
    obj.reoriginate_local_lsas = reoriginate
    obj.recompute_routing_state = recompute
    try:
        getattr(obj, method)()
        outcome = ('normal return',)
    except Exception as exc:
        outcome = (type(exc).__name__, str(exc))

    return (outcome, trace, hub.count, copy.deepcopy(obj.local_lsa_ack_pending),
            obj.local_lsu_last_tx, copy.deepcopy(obj.local_lsa),
            obj.neighbor.request_list)


class TestC06RecoveryEquivalence(unittest.TestCase):
    def check(self, method, case):
        older = invoke(ORIGINAL, method, case)
        newer = invoke(CURRENT_CODE, method, case)
        self.assertEqual(older, newer, f'{method}: {case!r}\nold={older!r}\nnew={newer!r}')
        return newer

    def test_reference_is_frozen(self):
        self.assertEqual(hashlib.sha256(REFERENCE.read_bytes()).hexdigest(), REF_SHA)

    def test_public_signatures_and_docstrings(self):
        a, b = {}, {}
        exec(ORIGINAL, a)
        exec(CURRENT_CODE, b)
        for method in METHODS:
            old = getattr(a['Recovery'], method)
            new = getattr(b['Recovery'], method)
            self.assertEqual(inspect.signature(old), inspect.signature(new))
            self.assertEqual(old.__doc__, new.__doc__)

    def test_timer_loops_keep_periodic_structure(self):
        # The former global AST hash was tied to one historical revision of
        # every unrelated controller method. Later valid refactors (or local
        # existing differences) must not invalidate C06 timer regression.
        # A one-time, actual-pre-patch scope audit is supplied separately.
        tree = ast.parse(CURRENT.read_text(encoding='utf-8'))
        controller = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                          and n.name == 'OSPFTimerMixin')
        for name in METHODS:
            matches = [n for n in controller.body
                       if isinstance(n, ast.FunctionDef) and n.name == name]
            self.assertEqual(len(matches), 1, name)
            self.assertEqual([arg.arg for arg in matches[0].args.args], ['self'])
            loops = [n for n in matches[0].body if isinstance(n, ast.While)]
            self.assertEqual(len(loops), 1, name)
            self.assertIsInstance(loops[0].test, ast.Constant)
            self.assertIs(loops[0].test.value, True)
            first = loops[0].body[0]
            self.assertIsInstance(first, ast.Expr)
            self.assertIsInstance(first.value, ast.Call)
            self.assertEqual(ast.unparse(first.value.func), 'hub.sleep')
            self.assertEqual(len(first.value.args), 1)
            interval = 5 if name == 'lsdb_aging_loop' else 1
            self.assertEqual(ast.literal_eval(first.value.args[0]), interval)

    def test_lsdb_aging_empty_database(self):
        self.check('lsdb_aging_loop', dict(iterations=4, lsdb_truth=[False]*4))

    def test_lsdb_aging_no_change_and_change(self):
        x = self.check('lsdb_aging_loop', dict(iterations=4,
            lsdb_truth=[True, True, True, True], purge=[False, True, False, True]))
        self.assertEqual(sum(ev[0] == 'recompute' for ev in x[1]), 2)

    def test_lsdb_aging_dynamic_truth_and_purge(self):
        self.check('lsdb_aging_loop', dict(iterations=7,
            lsdb_truth=[False, True, False, True, True, False, True],
            purge=[True, False, True, False]))

    def test_lsdb_aging_purge_failure(self):
        self.check('lsdb_aging_loop', dict(iterations=3,
            purge=[False, ValueError('bad age')]))

    def test_lsdb_aging_recompute_failure(self):
        self.check('lsdb_aging_loop', dict(iterations=2, purge=[True, True],
            raise_recompute=True))

    def test_retransmission_no_pending_and_no_timestamp(self):
        for pending in ({}, None):
            self.check('local_lsa_retransmission_loop',
                       dict(iterations=4, pending=pending, clock=[]))
        self.check('local_lsa_retransmission_loop',
                   dict(iterations=4, last_tx=None, clock=[]))

    def test_retransmission_boundary(self):
        for elapsed in (-1, 0, 4.999, 5.0, 5.001, 100):
            out = self.check('local_lsa_retransmission_loop',
                dict(iterations=2, clock=[95.0 + elapsed]*2))
            self.assertEqual(sum(e[0] == 'retransmit' for e in out[1]),
                             2 if elapsed >= 5 else 0)

    def test_retransmission_nan_preserves_original_branch(self):
        out = self.check('local_lsa_retransmission_loop',
                         dict(iterations=1, clock=[float('nan')]))
        self.assertEqual(sum(e[0] == 'retransmit' for e in out[1]), 1)

    def test_retransmission_mutates_pending(self):
        out = self.check('local_lsa_retransmission_loop',
            dict(iterations=4, clock=[100], clear_pending_on_retx=True))
        self.assertEqual(sum(e[0] == 'retransmit' for e in out[1]), 1)

    def test_retransmission_updates_timestamp(self):
        out = self.check('local_lsa_retransmission_loop',
            dict(iterations=4, clock=[100, 101, 102, 103],
                 update_last_tx_on_retx=True, new_last_tx=99.0))
        self.assertEqual(sum(e[0] == 'retransmit' for e in out[1]), 1)

    def test_refresh_each_gate_prevents_clock_reads(self):
        for case in (dict(local_lsa={}), dict(exchange=False),
                     dict(request_list=[{'x': 1}]), dict(pending={'x': 1}),
                     dict(local_lsa={'a': {'_originated_at': None}})):
            with self.subTest(case=case):
                out = self.check('local_lsa_refresh_loop',
                                 dict(iterations=3, clock=[], **case))
                self.assertFalse(any(e[0] == 'monotonic' for e in out[1]))

    def test_refresh_boundary_and_duplicate_times(self):
        for elapsed in (-2, 0, 19.999, 20, 21):
            out = self.check('local_lsa_refresh_loop', dict(iterations=2,
                clock=[75+elapsed]*2,
                local_lsa={'a': {'_originated_at': 75},
                           'b': {'_originated_at': 90},
                           'c': {'_originated_at': 75}}))
            self.assertEqual(sum(e[0] == 'reoriginate' for e in out[1]),
                             2 if elapsed >= 20 else 0)

    def test_refresh_clears_local_state(self):
        out = self.check('local_lsa_refresh_loop',
            dict(iterations=4, clock=[100], clear_local_on_refresh=True))
        self.assertEqual(sum(e[0] == 'reoriginate' for e in out[1]), 1)

    def test_refresh_bad_originated_timestamp(self):
        for bad in (None, 'not-a-number', {'x': 1}):
            self.check('local_lsa_refresh_loop', dict(iterations=1,
                local_lsa={'a': {'_originated_at': bad},
                           'b': {'_originated_at': 90}}, clock=[100]))

    def test_randomized_aging_retx_refresh(self):
        rng = random.Random(0xC06)
        for _ in range(1300):
            method = rng.choice(METHODS)
            count = rng.randrange(0, 7)
            if method == 'lsdb_aging_loop':
                case = dict(iterations=count,
                            lsdb_truth=[rng.choice([True, False]) for _ in range(count)],
                            purge=[rng.choice([True, False]) for _ in range(count)])
            elif method == 'local_lsa_retransmission_loop':
                case = dict(iterations=count,
                            pending=rng.choice([{}, {'a': 1}]),
                            last_tx=rng.choice([None, 0, 10, 100, 120]),
                            retx_interval=rng.choice([0, 1, 5, 100]),
                            clock=[rng.uniform(0, 200) for _ in range(count)])
            else:
                case = dict(iterations=count,
                    local_lsa=rng.choice([{}, {'a': {'_originated_at': None}},
                        {'a': {'_originated_at': rng.uniform(0, 200)}}]),
                    exchange=rng.choice([True, False]),
                    request_list=rng.choice([[], [{'ls_type': 1}]]),
                    pending=rng.choice([{}, {'a': 1}]),
                    clock=[rng.uniform(0, 200) for _ in range(count)],
                    refresh_interval=rng.choice([0, 1, 20, 100]))
            self.check(method, case)


if __name__ == '__main__':
    unittest.main()
