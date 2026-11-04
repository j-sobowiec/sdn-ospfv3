"""M01: verify safe migration of all five diagnostic methods into a mixin.

The offline tests use AST and deterministic log trace comparison to freeze
signatures, exception order, source logic and formatting. The optional final
test checks actual Python method resolution on real Ryu/Scapy installations.
"""
import ast
import copy
import importlib.util
import inspect
import ipaddress
from pathlib import Path
import random
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parent.parent
BEFORE = ROOT / 'tests' / '_m01_diagnostics_reference.py'
MIXIN = ROOT / 'ospfv3' / 'controller_diagnostics.py'
CONTROLLER = ROOT / 'ryu_sdn.py'
METHODS = ('log_hello', 'log_dbd', 'log_lsu',
           'log_spf_result', 'log_ipv6_routing_table')


def class_node(path, name):
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    return next(n for n in tree.body if isinstance(n, ast.ClassDef)
                and n.name == name)


def method_nodes(path, name):
    return {n.name: n for n in class_node(path, name).body
            if isinstance(n, ast.FunctionDef)}


def isolated_class(path, name):
    klass = copy.deepcopy(class_node(path, name))
    klass.bases = []
    klass.keywords = []
    klass.decorator_list = []
    klass.name = 'Diagnostics'
    module = ast.fix_missing_locations(ast.Module(body=[klass], type_ignores=[]))
    env = {
        'cfg': SimpleNamespace(ROUTER_ID='10.10.10.10'),
        'ospfv3_lsa_type_description': lambda x: f'TYPE<{x}>',
        'ipaddress': ipaddress,
    }
    exec(compile(module, str(path), 'exec'), env)
    return env['Diagnostics']


class LogRecorder:
    def __init__(self, calls, fail_at=None):
        self.calls = calls
        self.fail_at = fail_at

    def info(self, *args):
        self.calls.append(('info', args))
        if self.fail_at == len(self.calls):
            raise RuntimeError('logger stopped')


class SPFRecorder:
    def __init__(self, calls, distances, previous, error_at=None):
        self.calls = calls
        self.distances = distances
        self.previous = previous
        self.error_at = error_at

    def run_spf(self):
        self.calls.append(('run_spf',))
        return self.distances, self.previous

    def get_spf_next_hop(self, router_id, previous):
        self.calls.append(('next_hop', router_id, previous is self.previous))
        if self.error_at == router_id:
            raise ValueError('no hop')
        return 'via:' + str(router_id)


def invoke(cls, method, args=(), *, distances=None, previous=None,
           routes=None, fail_at=None, error_at=None):
    calls = []
    obj = cls()
    obj.logger = LogRecorder(calls, fail_at=fail_at)
    obj.routing = SPFRecorder(calls, distances if distances is not None else {},
                              previous if previous is not None else {}, error_at)
    obj.ipv6_routing_table = routes if routes is not None else {}
    try:
        value = getattr(obj, method)(*args)
        result = ('return', value)
    except Exception as exc:
        result = (type(exc).__name__, str(exc))
    return result, calls


class TestM01Architecture(unittest.TestCase):
    def setUp(self):
        self.old = isolated_class(BEFORE, 'OriginalDiagnostics')
        self.new = isolated_class(MIXIN, 'OSPFDiagnosticsMixin')

    def same(self, method, args=(), **kwargs):
        self.assertEqual(invoke(self.old, method, args, **kwargs),
                         invoke(self.new, method, args, **kwargs))

    def test_all_five_method_bodies_unchanged(self):
        old = method_nodes(BEFORE, 'OriginalDiagnostics')
        new = method_nodes(MIXIN, 'OSPFDiagnosticsMixin')
        self.assertEqual(tuple(new), METHODS)
        self.assertEqual(tuple(old), METHODS)
        for name in METHODS:
            self.assertEqual(ast.dump(old[name], include_attributes=False),
                             ast.dump(new[name], include_attributes=False), name)

    def test_exact_public_signatures_and_docstrings(self):
        for name in METHODS:
            self.assertEqual(inspect.signature(getattr(self.old, name)),
                             inspect.signature(getattr(self.new, name)))
            self.assertEqual(getattr(self.old, name).__doc__,
                             getattr(self.new, name).__doc__)

    def test_controller_inherits_mixin_before_ryuapp(self):
        klass = class_node(CONTROLLER, 'OSPFv3Controller')
        bases = [ast.unparse(x) for x in klass.bases]
        self.assertEqual(bases, ['OSPFDiagnosticsMixin', 'OSPFReceiveMixin', 'OSPFTransmitMixin', 'OSPFTimerMixin', 'OpenFlowMixin', 'app_manager.RyuApp'])
        source = ast.parse(CONTROLLER.read_text(encoding='utf8'))
        self.assertTrue(any(isinstance(n, ast.ImportFrom)
                            and n.module == 'ospfv3.controller_diagnostics'
                            and any(x.name == 'OSPFDiagnosticsMixin' for x in n.names)
                            for n in source.body))
        declared = {n.name for n in klass.body if isinstance(n, ast.FunctionDef)}
        self.assertTrue(set(METHODS).isdisjoint(declared))
        self.assertIn('packet_in_handler', declared)
        self.assertNotIn('handle_ospf_lsu', declared)
        self.assertTrue(any(isinstance(n, ast.ImportFrom)
                            and n.module == 'ospfv3.controller_rx'
                            and any(x.name == 'OSPFReceiveMixin' for x in n.names)
                            for n in source.body))
        self.assertNotIn('send_local_ls_update', declared)  # M05: now in TX mixin

    def test_diagnostics_module_has_no_ryu_events_or_state_init(self):
        text = MIXIN.read_text(encoding='utf8')
        self.assertNotIn('from ryu', text)
        self.assertNotIn('hub.spawn', text)
        self.assertNotIn('@set_ev_cls', text)
        self.assertNotIn('def __init__', text)

    def test_hello_trace_no_neighbors_and_some_neighbors(self):
        ipv6 = SimpleNamespace(src='fe80::abc')
        for neighbors in ([], ['1.1.1.1'], ['1.1.1.1', '2.2.2.2'], None):
            args = (7, ipv6, 56, '2.2.2.2', '0.0.0.0', 3, 1, 19, 10, 40, neighbors)
            self.same('log_hello', args)
            for fail_at in (1, 2):
                self.same('log_hello', args, fail_at=fail_at)

    def test_dbd_every_flags_combo(self):
        ipv6 = SimpleNamespace(src='fe80::abc')
        for f in range(8):
            flags = [(f >> 2) & 1, (f >> 1) & 1, f & 1]
            args = (7, ipv6, '2.2.2.2', '0.0.0.0', 1500, 19,
                    *flags, 0x80000001, [])
            self.same('log_dbd', args)

    def test_lsu_all_lsa_types_and_bad_data(self):
        ipv6 = SimpleNamespace(src='fe80::abc')
        h = lambda t: {'ls_type': t, 'advertising_router': '1.1.1.1',
                       'link_state_id': '0.0.0.0', 'ls_sequence': 5, 'ls_age': 12}
        cases = [[], [h(0x1234)], [{}], None]
        router = h(0x2001)
        router['router_lsa'] = {'links': [dict(neighbor_router_id='1.1.1.1',
                                              metric=5, interface_id=1,
                                              neighbor_interface_id=2)],
                                'flags': 1, 'options': 2}
        link = h(8)
        link['link_lsa'] = {'link_local_address': 'fe80::1', 'router_priority': 1,
                            'number_of_prefixes': 1,
                            'prefixes': [{'prefix': '2001:db8::', 'prefix_length': 64}]}
        intra = h(0x2009)
        intra['intra_area_prefix_lsa'] = {'referenced_ls_type': 0x2001,
                    'referenced_advertising_router': '2.2.2.2',
                    'number_of_prefixes': 1,
                    'prefixes': [{'prefix': '2001:db8::', 'prefix_length': 64,
                                  'metric': 7}]}
        cases.append([router, link, intra, h(77)])
        for lsas in cases:
            args = (7, ipv6, 99, '1.1.1.1', '0.0.0.0', lsas)
            self.same('log_lsu', args)
            for fail_at in (1, 2, 3, 4):
                self.same('log_lsu', args, fail_at=fail_at)

    def test_spf_all_routes_and_exceptions(self):
        root = '10.10.10.10'
        d = {root: 0, '1.1.1.1': 5, '2.2.2.2': 10}
        p = {root: None, '1.1.1.1': root, '2.2.2.2': '1.1.1.1'}
        for distances, previous in ((d, p), ({}, {}), (d, {root: None})):
            for error in (None, '1.1.1.1'):
                for fail in (None, 1, 2, 3):
                    self.same('log_spf_result', (), distances=distances,
                              previous=previous, fail_at=fail, error_at=error)

    def test_routing_table_connected_ospf_and_invalid(self):
        cases = [{}, {'one': {'prefix': '2001:db8:1::', 'prefix_length': 64,
                               'source': 'connected', 'interface': 'lan'}},
                 {'a': {'prefix': '2001:db8:2::', 'prefix_length': 64,
                         'source': 'ospf', 'total_cost': 20,
                         'advertising_router': '3.3.3.3',
                         'next_hop': 'fe80::3', 'interface': 'transit'},
                  'b': {'prefix': '2001:db8:1::', 'prefix_length': 64,
                         'source': 'connected', 'interface': 'lan'}},
                 {'x': {'prefix': 'not ipv6', 'prefix_length': 64}}]
        for routes in cases:
            for fail in (None, 1, 2, 3, 5):
                self.same('log_ipv6_routing_table', (), routes=routes,
                          fail_at=fail)

    def test_randomized_traces_all_five_methods(self):
        rng = random.Random(20261020)
        ipv6 = SimpleNamespace(src='fe80::10')
        root = '10.10.10.10'
        for _ in range(1100):
            op = rng.choice(METHODS)
            if op == 'log_hello':
                args = (3, ipv6, rng.randrange(50), root, '0.0.0.0', 3, 1,
                        0, 10, 40, [str(i) for i in range(rng.randrange(5))])
                kw = {}
            elif op == 'log_dbd':
                args = (3, ipv6, root, '0.0.0.0', 1500, 7,
                        rng.choice([0, 1]), rng.choice([0, 1]),
                        rng.choice([0, 1]), rng.randrange(100), [])
                kw = {}
            elif op == 'log_lsu':
                args = (3, ipv6, rng.randrange(100), root, '0.0.0.0', [])
                kw = {}
            elif op == 'log_spf_result':
                ids = [root] + [f'{i}.{i}.{i}.{i}' for i in rng.sample(range(1,20),3)]
                dist = {i:rng.randint(0, 100) for i in ids}
                prev = {i:(None if i==root else root) for i in ids}
                args = ()
                kw = {'distances':dist, 'previous':prev}
            else:
                args = ()
                kw = {'routes':{}}
            kw['fail_at'] = rng.choice([None, None, 1, 2, 3, 5])
            self.same(op, args, **kw)

    def test_real_import_and_mro_if_ryu_present(self):
        if importlib.util.find_spec('ryu') is None or importlib.util.find_spec('scapy') is None:
            self.skipTest('Real Ryu and Scapy not available in isolated environment')
        from ryu_sdn import OSPFv3Controller
        from ospfv3.controller_diagnostics import OSPFDiagnosticsMixin
        self.assertIs(OSPFv3Controller.__bases__[0], OSPFDiagnosticsMixin)
        for name in METHODS:
            self.assertIs(getattr(OSPFv3Controller, name),
                          getattr(OSPFDiagnosticsMixin, name))


if __name__ == '__main__':
    unittest.main()
