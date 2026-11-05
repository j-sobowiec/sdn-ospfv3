"""C05: differential RX handler behavior versus frozen C04 AST methods.

Compare state, calls/logs ordering and exceptions, including malformed input.
The production RyuApp is not instantiated, so no hub background jobs start.
"""
import ast
import copy
import hashlib
import inspect
import ipaddress
import random
import socket
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
CURRENT = ROOT / 'ospfv3' / 'controller_rx.py'
REFERENCE = Path(__file__).with_name('_c05_ospf_rx_reference.py')
METHODS = ['handle_ospf_dbd', 'handle_ospf_lsr', 'handle_ospf_lsu', 'handle_ospf_lsack']
HELPERS = ['is_current_ospf_neighbor', '_reject_noncurrent_ospf_neighbor',
           '_split_ospf_lsa_by_origin']
REF_HASH = 'faf80689d92155608a9cafc1b3f0f504e80c422f398e3ffc3a22d11588e0a3a4'


def extract(path, class_name, selected):
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    klass = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                 and node.name == class_name)
    funcs = [copy.deepcopy(node) for node in klass.body
             if isinstance(node, ast.FunctionDef) and node.name in selected]
    assert set(selected) == {node.name for node in funcs}, (path, selected)
    # Method attributes and decorators must retain semantics (e.g. staticmethod).
    fake_class = ast.ClassDef(name='RX', bases=[], keywords=[], body=funcs,
                              decorator_list=[])
    mod = ast.fix_missing_locations(ast.Module(body=[fake_class], type_ignores=[]))
    return compile(mod, str(path), 'exec')


OLD_CODE = extract(REFERENCE, 'OriginalRX', METHODS + HELPERS[:1])
NEW_CODE = extract(CURRENT, 'OSPFReceiveMixin', METHODS + HELPERS)


def sample_lsa(i=1, adv='1.1.1.1', seq=0x80000001, checksum=0x1234):
    return {'ls_type': 0x2001, 'link_state_id': f'0.0.0.{i}',
            'advertising_router': adv, 'ls_sequence': seq,
            'ls_checksum': checksum, 'ls_age': 10}


class Logged:
    def __init__(self, trace):
        self.trace = trace

    def info(self, *args):
        self.trace.append(('info', copy.deepcopy(args)))

    def warning(self, *args):
        self.trace.append(('warning', tuple(str(a) for a in args)))


class RXNeighbor:
    def __init__(self, trace, case):
        self.trace = trace
        self.port = case.get('port', 7)
        self.ipv6 = case.get('ip', 'fe80::1')
        self.mac = '02:00:00:00:00:01'
        self.router_id = case.get('rid', '1.1.1.1')
        self.router_ids = list(case.get('ids', ['1.1.1.1']))
        self.dbd_negotiated = case.get('negotiated', False)
        self.dbd_exchange_complete = case.get('exchange_complete', False)
        self.dbd_sequence = case.get('dbd_seq', 7)
        self.request_list = copy.deepcopy(case.get('request_list', []))
        self.lsr_sent = case.get('lsr_sent', False)

    def update_request_list(self, lsas):
        self.trace.append(('update_request_list', copy.deepcopy(lsas)))
        if lsas and self.request_list:
            # Deterministic stand-in; both variants call with identical data.
            self.request_list = []


class RXLocalLSA(dict):
    def __init__(self, trace, case):
        items = case.get('local', [sample_lsa(1, '10.10.10.10')])
        super().__init__({(i['ls_type'], i['link_state_id'], i['advertising_router']): copy.deepcopy(i)
                          for i in items})
        self.trace = trace
        self.case = case

    def recover_sequences(self, lsas, *, prepare_next):
        self.trace.append(('recover_sequences', copy.deepcopy(lsas), prepare_next))
        return self.case.get('seq_changed', False), self.case.get('recovered', len(lsas))

    def reoriginate(self, router_id, reason):
        self.trace.append(('reoriginate', router_id, reason))
        return self.case.get('reoriginate_ok', True)

    def initialize(self, router_id):
        self.trace.append(('initialize', router_id))
        self[sample_key] = sample_lsa(1, '10.10.10.10')


sample_key = (0x2001, '0.0.0.1', '10.10.10.10')


class RXLSDB:
    def __init__(self, trace, case):
        self.trace, self.case = trace, case

    def update(self, lsas):
        self.trace.append(('lsdb_update', copy.deepcopy(lsas)))
        return self.case.get('routing_changed', False)


def invoke(code, method, case):
    trace = []
    def make_parser(name):
        def parse(data, size):
            trace.append(('parse', name, bytes(data), size))
            if case.get('parse_exception'):
                raise ValueError(case['parse_exception'])
            return copy.deepcopy(case.get('parsed', []))
        return parse

    env = dict(
        cfg=SimpleNamespace(ROUTER_ID='10.10.10.10', INTERFACE_MTU=1500),
        struct=struct, socket=socket,
        parse_dbd=make_parser('dbd'), parse_lsr=make_parser('lsr'),
        parse_lsu=make_parser('lsu'), parse_lsack=make_parser('lsack'),
        ospfv3_lsa_type_description=lambda x: f'LSA({x})',
    )
    exec(code, env)
    obj = env['RX']()
    obj.logger = Logged(trace)
    obj.neighbor = RXNeighbor(trace, case)
    obj.local_lsa = RXLocalLSA(trace, case)
    obj.lsdb = RXLSDB(trace, case)
    obj.local_lsa_ack_pending = copy.deepcopy(case.get('pending', {}))
    obj.local_lsu_last_tx = 99
    obj.local_lsu_sent = case.get('local_lsu_sent', False)
    obj.local_lsa_rebuild_required = case.get('rebuild_required', False)

    def record(name, return_value=None):
        def f(*args, **kwargs):
            trace.append((name, copy.deepcopy(args), copy.deepcopy(kwargs)))
            return return_value
        return f
    for name in ('log_dbd', 'log_lsu', 'reset_dbd_state', 'send_initial_dbd',
                 'send_exchange_dbd', 'send_link_state_request',
                 'send_local_lsr_response', 'send_ls_ack', 'recompute_routing_state'):
        setattr(obj, name, record(name))
    obj.send_local_ls_update = record('send_local_ls_update', case.get('send_update_ok', True))

    args = [case.get('incoming_port', 7),
            SimpleNamespace(src=case.get('incoming_ip', 'fe80::1')),
            case.get('ospf_data', b'ospf'), case.get('packet_length', 28)]
    if method == 'handle_ospf_dbd':
        args.append(case.get('peer_int', int(ipaddress.IPv4Address('1.1.1.1'))))
    args.extend([case.get('peer_text', '1.1.1.1'), '0.0.0.0'])
    try:
        result = getattr(obj, method)(*args)
        error = None
    except Exception as exc:
        result = None
        error = (type(exc).__name__, str(exc))
    # A deep copy makes later mutations unable to hide a difference.
    return (result, error, copy.deepcopy(trace),
            {k: copy.deepcopy(v) for k, v in vars(obj.neighbor).items() if k != 'trace'},
            copy.deepcopy(dict(obj.local_lsa)),
            copy.deepcopy(obj.local_lsa_ack_pending), obj.local_lsu_last_tx,
            obj.local_lsu_sent, obj.local_lsa_rebuild_required)


class TestC05RXEquivalence(unittest.TestCase):
    def check(self, method, case):
        a, b = invoke(OLD_CODE, method, case), invoke(NEW_CODE, method, case)
        self.assertEqual(a, b, f'{method} inputs={case!r}')
        return b

    def test_reference_is_frozen(self):
        self.assertEqual(hashlib.sha256(REFERENCE.read_bytes()).hexdigest(), REF_HASH)

    def test_public_signatures_unchanged(self):
        a, b = {}, {}
        exec(OLD_CODE, a)
        exec(NEW_CODE, b)
        for method in METHODS:
            self.assertEqual(str(inspect.signature(getattr(a['RX'], method))),
                             str(inspect.signature(getattr(b['RX'], method))))

    def test_unknown_neighbor_no_parser_or_state_mutation(self):
        for method in METHODS:
            for changed in [dict(incoming_port=8), dict(incoming_ip='fe80::2'),
                            dict(peer_text='9.9.9.9'), dict(rid=None), dict(ids=[]),
                            dict(ip=None), dict(port=None)]:
                with self.subTest(method=method, changed=changed):
                    trace = self.check(method, changed)[2]
                    self.assertEqual([x[0] for x in trace], ['warning'])

    def test_parser_value_errors_same_messages(self):
        for method in METHODS:
            for msg in ('bad checksum', 'wrong size', ''):
                with self.subTest(method=method, msg=msg):
                    self.check(method, dict(parse_exception=msg or ' '))

    def test_dbd_initial_and_restart(self):
        for neg in (True, False):
            for complete in (True, False):
                self.check('handle_ospf_dbd', dict(
                    negotiated=neg, exchange_complete=complete, packet_length=28,
                    parsed=dict(interface_mtu=1500, options=0, i_bit=True,
                                m_bit=True, ms_bit=True, dd_sequence=8,
                                lsa_headers=[])))

    def test_dbd_mtu_and_roles(self):
        for mtu in (-1, 0, 1, 1500, 1501, 9000):
            for peer in (0, int(ipaddress.IPv4Address('1.1.1.1')),
                         int(ipaddress.IPv4Address('11.0.0.1'))):
                self.check('handle_ospf_dbd', dict(peer_int=peer,
                    parsed=dict(interface_mtu=mtu, options=2, i_bit=True,
                                m_bit=True, ms_bit=True, dd_sequence=7,
                                lsa_headers=[])))

    def test_dbd_negotiation_self_remote_split(self):
        lsas = [sample_lsa(2, '1.1.1.1'), sample_lsa(1, '10.10.10.10'),
                sample_lsa(3, '2.2.2.2'), sample_lsa(4, '10.10.10.10')]
        for changed in (False, True):
            for local in ([], [sample_lsa(1, '10.10.10.10')]):
                self.check('handle_ospf_dbd', dict(
                    parsed=dict(interface_mtu=1500, options=0, i_bit=False,
                                m_bit=True, ms_bit=False, dd_sequence=7,
                                lsa_headers=lsas), seq_changed=changed, local=local))

    def test_dbd_exchange_and_request_send(self):
        for lsrsent in (False, True):
            for req in ([], [sample_lsa(1)]):
                self.check('handle_ospf_dbd', dict(negotiated=True,
                    lsr_sent=lsrsent, request_list=req,
                    parsed=dict(interface_mtu=1500, options=0, i_bit=False,
                                m_bit=False, ms_bit=False, dd_sequence=7,
                                lsa_headers=[])))

    def test_lsr_empty_duplicates_missing_and_bad_values(self):
        values = [[], [sample_lsa(1, '10.10.10.10')],
                  [sample_lsa(1, '10.10.10.10')]*3,
                  [sample_lsa(2, '1.1.1.1'), sample_lsa(1, '10.10.10.10')],
                  [{'ls_type': 1}], [None]]
        for lsas in values:
            self.check('handle_ospf_lsr', dict(parsed=lsas))

    def test_lsu_empty_and_remote_update(self):
        for changed in (True, False):
            for lsas in ([], [sample_lsa(1, '1.1.1.1')],
                         [sample_lsa(1, '10.10.10.10')],
                         [sample_lsa(1, '10.10.10.10'), sample_lsa(2, '1.1.1.1')]):
                self.check('handle_ospf_lsu', dict(parsed=lsas, routing_changed=changed))

    def test_lsu_reorigination_and_transmit(self):
        for good in (False, True):
            for sent in (False, True):
                for local in ([], [sample_lsa(1, '10.10.10.10')]):
                    self.check('handle_ospf_lsu', dict(
                        parsed=[sample_lsa(1, '10.10.10.10'), sample_lsa(1, '2.2.2.2')],
                        exchange_complete=True, local=local,
                        rebuild_required=True, reoriginate_ok=good,
                        send_update_ok=sent))

    def test_lsack_match_and_pending_clear(self):
        lsa = sample_lsa(1, '10.10.10.10')
        p = {(lsa['ls_type'], lsa['link_state_id'], lsa['advertising_router']): lsa}
        for pending in ({}, p):
            for xs in ([], [lsa], [lsa, lsa],
                       [sample_lsa(1, '10.10.10.10', seq=3)],
                       [sample_lsa(1, '10.10.10.10', checksum=0x1235)]):
                self.check('handle_ospf_lsack', dict(parsed=xs, pending=pending))

    def test_lsack_short_and_malformed(self):
        for value in ([{}], [None], [sample_lsa(2)], [sample_lsa(1, '10.10.10.10')]):
            self.check('handle_ospf_lsack', dict(parsed=value))

    def test_randomized_rx_traces(self):
        rng = random.Random(20261019)
        for _ in range(1300):
            method = rng.choice(METHODS)
            lsas = [sample_lsa(rng.randrange(1, 6), rng.choice(
                ['1.1.1.1', '2.2.2.2', '10.10.10.10']),
                seq=rng.randrange(1, 100)) for _ in range(rng.randrange(6))]
            case = dict(parsed=lsas, local=(lsas or [sample_lsa()]),
                        routing_changed=bool(rng.randrange(2)),
                        negotiated=bool(rng.randrange(2)),
                        exchange_complete=bool(rng.randrange(2)),
                        send_update_ok=bool(rng.randrange(2)),
                        local_lsu_sent=bool(rng.randrange(2)),
                        rebuild_required=bool(rng.randrange(2)))
            if method == 'handle_ospf_dbd':
                case['parsed'] = dict(interface_mtu=rng.choice([0, 1492, 1500, 1600]),
                    options=0, i_bit=bool(rng.randrange(2)),
                    m_bit=bool(rng.randrange(2)), ms_bit=bool(rng.randrange(2)),
                    dd_sequence=rng.choice([7, 8, 0xffffffff]), lsa_headers=lsas)
            if method == 'handle_ospf_lsack':
                local_lsa = sample_lsa(1, '10.10.10.10')
                case['local'] = [local_lsa]
                key = (local_lsa['ls_type'], local_lsa['link_state_id'],
                       local_lsa['advertising_router'])
                case['pending'] = {key: local_lsa}
            self.check(method, case)

    def test_real_scapy_ospfv3_parser_if_available(self):
        try:
            from scapy.contrib.ospf import OSPFv3_Hdr
            from ospfv3 import parser
            from ospfv3 import packet
        except ImportError as exc:
            self.skipTest(f'Real Scapy not available: {exc}')
        # Real packet parsing through the same public parser before comparing
        # the two controller handlers (their data-plane/FSM behavior is isolated).
        from ospfv3.config import ROUTER_ID
        self.assertEqual(ROUTER_ID, '10.10.10.10')
        frame = packet.build_ospfv3_dbd_frame(0x1234, flags=0x01)
        # Ethernet (14B) + IPv6 (40B) precede the OSPFv3 payload.
        self.assertIsInstance(frame, bytes)
        self.assertGreaterEqual(len(frame), 14 + 40 + 28)
        ospf_bytes = frame[54:]
        size = int.from_bytes(ospf_bytes[2:4], 'big')
        decoded = parser.parse_dbd(ospf_bytes, size)
        self.assertIsInstance(OSPFv3_Hdr(ospf_bytes), OSPFv3_Hdr)
        self.check('handle_ospf_dbd', dict(parsed=decoded))


if __name__ == '__main__':
    unittest.main()
