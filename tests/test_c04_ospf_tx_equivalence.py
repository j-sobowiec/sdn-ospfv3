"""C04: compare TX methods byte-for-byte and side effect order against C03.

The reference is a frozen verbatim copy of the original TX methods. These
unit tests do not instantiate the Ryu app or spawn background threads.
"""
import ast
import copy
import ipaddress
import random
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
CURRENT = ROOT / 'ospfv3' / 'controller_tx.py'
REFERENCE = Path(__file__).with_name('_c04_ospf_tx_reference.py')
METHODS = [
    'send_ospfv3_hello', 'send_initial_dbd', 'send_exchange_dbd',
    'send_link_state_request', 'send_ls_ack', 'send_local_ls_update',
    'send_local_lsr_response', 'send_local_lsa_retransmission',
]
HELPERS = ['_ospf_unicast_ready', '_build_ospf_unicast_frame', '_send_dbd_frame']


def selected_class(path, klass_name, methods):
    tree = ast.parse(path.read_text(encoding='utf8'), filename=str(path))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef)
               and n.name == klass_name)
    functions = [copy.deepcopy(n) for n in cls.body
                 if isinstance(n, ast.FunctionDef) and n.name in methods]
    assert {n.name for n in functions} == set(methods), path
    for func in functions:
        func.decorator_list = []
    cls2 = ast.ClassDef(name='TX', bases=[], keywords=[], body=functions,
                        decorator_list=[])
    return compile(ast.fix_missing_locations(ast.Module(
        body=[cls2], type_ignores=[])), str(path), 'exec')


ORIG_CODE = selected_class(REFERENCE, 'OriginalTX', METHODS)
NEW_CODE = selected_class(CURRENT, 'OSPFTransmitMixin', METHODS + HELPERS)


class LocalLSA(dict):
    def __init__(self, items, body, pending_body, trace):
        super().__init__(items)
        self.body, self.pending_body, self.trace = body, pending_body, trace

    def build_update_body(self):
        self.trace.append(('UPDATE_BODY',))
        return self.body

    def build_pending_body(self, pending):
        self.trace.append(('PENDING_BODY', copy.deepcopy(pending)))
        return self.pending_body


class Logger:
    def __init__(self, trace, error=False):
        self.trace, self.error = trace, error

    def info(self, *args):
        self.trace.append(('INFO', args))
        if self.error:
            raise RuntimeError('logger unavailable')


def lsa(i=1):
    return {
        'ls_type': 0x2001, 'advertising_router': '1.1.1.1',
        'link_state_id': f'0.0.0.{i}', 'raw_lsa': bytes((i,))*20,
        'raw_header': struct.pack('!HHIIIHH', 1, 0x2001, i,
                                  int(ipaddress.IPv4Address('1.1.1.1')),
                                  0x80000001, 0xABCD, 20),
        'ls_sequence': 0x80000001, 'ls_checksum': 0xABCD,
    }


class Case:
    def __init__(self, *, port=8, ipv6='fe80::1', mac='02:00:00:00:00:01',
                 router_ids=('1.1.1.1',), seq=0x80000001,
                 requests=None, headers=None, lsas=None,
                 body=b'\x00\x00\x00\x01' + bytes(20),
                 pending_body=None, pending=None, send_ok=True,
                 broken_builder=None, broken_send=False, broken_log=False):
        self.port, self.ipv6, self.mac, self.router_ids, self.seq = (
            port, ipv6, mac, router_ids, seq)
        self.requests = [lsa(1)] if requests is None else requests
        self.headers = [lsa(1)] if headers is None else headers
        self.lsas = [lsa(1)] if lsas is None else lsas
        self.body = body
        self.pending_body = ((body, 1) if pending_body is None else pending_body)
        self.pending = ({('a',1): {'ls_sequence':1,'ls_checksum':2}}
                        if pending is None else pending)
        self.send_ok, self.broken_builder = send_ok, broken_builder
        self.broken_send, self.broken_log = broken_send, broken_log


def invoke(code, name, case, real_builders=False):
    trace = []
    names = ('build_ospfv3_hello_frame', 'build_ospfv3_dbd_frame',
             'build_ospfv3_lsr_frame', 'build_ospfv3_lsack_frame',
             'build_ospfv3_lsu_frame')
    if real_builders:
        from ospfv3 import packet
        funcs = {key:getattr(packet,key) for key in names}
    else:
        funcs = {}
        for key in names:
            def builder(*args, _name=key, **kwargs):
                trace.append(('BUILD',_name,copy.deepcopy(args),copy.deepcopy(kwargs)))
                if case.broken_builder == _name:
                    raise ValueError('builder failed')
                return (_name + repr(args) + repr(kwargs)).encode('utf8')
            funcs[key] = builder
    def checksum_desc(value):
        trace.append(('DESCRIPTION',value))
        return f'LSA({value})'
    def fake_monotonic():
        trace.append(('MONOTONIC',))
        return 123.456
    env = dict(funcs, struct=struct,
               time=SimpleNamespace(monotonic=fake_monotonic),
               ospfv3_lsa_type_description=checksum_desc)
    exec(code,env)
    obj = env['TX']()
    obj.neighbor = SimpleNamespace(port=case.port, ipv6=case.ipv6,
                                   mac=case.mac, router_ids=case.router_ids,
                                   dbd_sequence=case.seq,
                                   request_list=copy.deepcopy(case.requests),
                                   lsr_sent=False)
    obj.local_lsa = LocalLSA(
        {(x['ls_type'],x['link_state_id'],x['advertising_router']):copy.deepcopy(x)
         for x in case.lsas},case.body,case.pending_body,trace)
    obj.local_lsa_ack_pending = copy.deepcopy(case.pending)
    obj.local_lsu_last_tx = 55
    obj.logger = Logger(trace,case.broken_log)
    def send_frame(frame,port):
        trace.append(('SEND',frame,port,copy.deepcopy(obj.local_lsa_ack_pending)))
        if case.broken_send:
            raise RuntimeError('send unavailable')
        return case.send_ok
    obj.send_frame = send_frame
    args = {
        'send_ospfv3_hello': (None,),
        'send_ls_ack': (case.headers,),
        'send_local_lsr_response': (case.lsas,),
    }.get(name,())
    try:
        ret = getattr(obj,name)(*copy.deepcopy(args))
        error = None
    except Exception as exc:
        ret=None
        error=(type(exc).__name__,str(exc))
    return (ret,error,trace,copy.deepcopy(obj.neighbor.__dict__),
            copy.deepcopy(obj.local_lsa_ack_pending), obj.local_lsu_last_tx)


class TestC04Differential(unittest.TestCase):
    def check(self,name,case,real=False):
        before=invoke(ORIG_CODE,name,case,real)
        after=invoke(NEW_CODE,name,case,real)
        self.assertEqual(before,after, f'{name}: {vars(case)}')
        return after

    def test_reference_is_frozen(self):
        self.assertIn('class OriginalTX:', REFERENCE.read_text())
        self.assertNotIn('_ospf_unicast_ready', REFERENCE.read_text())

    def test_api_signatures_unchanged(self):
        import inspect
        a,b={},{}
        exec(ORIG_CODE,a); exec(NEW_CODE,b)
        for name in METHODS:
            self.assertEqual(str(inspect.signature(getattr(a['TX'],name))),
                             str(inspect.signature(getattr(b['TX'],name))))

    def test_all_methods_happy_path(self):
        for name in METHODS:
            with self.subTest(name=name):
                self.check(name,Case())

    def test_no_port_for_all_methods(self):
        for name in METHODS:
            with self.subTest(name=name):
                self.check(name,Case(port=None))

    def test_unicast_missing_ipv6_or_mac(self):
        for field in ('ipv6','mac'):
            for name in METHODS[3:]:
                with self.subTest(field=field,name=name):
                    self.check(name,Case(**{field:None}))

    def test_sender_false_paths(self):
        for name in METHODS:
            with self.subTest(name=name):
                self.check(name,Case(send_ok=False))

    def test_builder_failures_preserve_state(self):
        mapping={'send_ospfv3_hello':'build_ospfv3_hello_frame',
                 'send_initial_dbd':'build_ospfv3_dbd_frame',
                 'send_exchange_dbd':'build_ospfv3_dbd_frame',
                 'send_link_state_request':'build_ospfv3_lsr_frame',
                 'send_ls_ack':'build_ospfv3_lsack_frame',
                 'send_local_ls_update':'build_ospfv3_lsu_frame',
                 'send_local_lsr_response':'build_ospfv3_lsu_frame',
                 'send_local_lsa_retransmission':'build_ospfv3_lsu_frame'}
        for name, builder in mapping.items():
            with self.subTest(name=name):
                self.check(name,Case(broken_builder=builder))

    def test_send_exceptions_preserve_state(self):
        for name in METHODS:
            with self.subTest(name=name):
                self.check(name,Case(broken_send=True))

    def test_logger_exceptions(self):
        for name in METHODS:
            with self.subTest(name=name):
                self.check(name,Case(broken_log=True))

    def test_empty_payloads(self):
        for name,kwargs in [
            ('send_link_state_request',dict(requests=[])),
            ('send_ls_ack',dict(headers=[])),
            ('send_local_lsr_response',dict(lsas=[])),
            ('send_local_ls_update',dict(body=None)),
            ('send_local_lsa_retransmission',dict(pending_body=None)),
        ]:
            if name == 'send_local_lsa_retransmission':
                c=Case();c.pending_body=None
            else:c=Case(**kwargs)
            with self.subTest(name=name):self.check(name,c)

    def test_dbd_sequence_limits_and_frame_order(self):
        for seq in (0,1,0x7fffffff,0x80000000,0xffffffff):
            for name in ('send_initial_dbd','send_exchange_dbd'):
                self.check(name,Case(seq=seq))

    def test_ack_pending_timestamp_and_lsr_sent_side_effect_order(self):
        frame = self.check('send_local_ls_update',Case())
        self.assertIn(('MONOTONIC',),frame[2]); self.assertNotEqual(frame[4],{})
        self.assertLess(next(i for i,e in enumerate(frame[2]) if e[0]=='BUILD'),
                        next(i for i,e in enumerate(frame[2]) if e[0]=='SEND'))
        sent=self.check('send_link_state_request',Case())
        self.assertTrue(sent[3]['lsr_sent'])
        refused=self.check('send_link_state_request',Case(send_ok=False))
        self.assertFalse(refused[3]['lsr_sent'])

    def test_randomized_full_trace(self):
        rand=random.Random(0xC04)
        for i in range(1400):
            name=rand.choice(METHODS)
            port=rand.choice((None,3,8,17,65535))
            ipv6=rand.choice((None,'fe80::1','fe80::2'))
            mac=rand.choice((None,'02:00:00:00:00:01','02:00:00:00:00:ff'))
            requests=[lsa(k) for k in range(rand.randrange(0,5))]
            headers=[lsa(k) for k in range(rand.randrange(0,5))]
            local=[lsa(k) for k in range(rand.randrange(0,5))]
            body=rand.choice((None,b'\x00\x00\x00\x00',b'\x00\x00\x00\x01' + bytes(20)))
            case=Case(port=port,ipv6=ipv6,mac=mac, seq=rand.randrange(0,2**32),
                      requests=requests,headers=headers,lsas=local,body=body,
                      send_ok=rand.choice((False,True)),
                      router_ids=tuple(f'{k}.{k}.{k}.{k}' for k in range(rand.randrange(4))))
            self.check(name,case)

    def test_real_scapy_wire_bytes_all_five_ospf_types(self):
        try:
            from scapy.contrib.ospf import OSPFv3_Hdr
            from ospfv3 import packet
        except ImportError as exc:
            self.skipTest(f'requires real Scapy 2.7.0: {exc}')
        self.assertIsNotNone(OSPFv3_Hdr)
        for name in METHODS:
            case=Case(body=b'\x00\x00\x00\x00',pending_body=(b'\x00\x00\x00\x00',0))
            with self.subTest(name=name):
                trace=self.check(name,case,True)[2]
                for e in trace:
                    if e[0]=='SEND':
                        self.assertIsInstance(e[1],bytes)
                        self.assertGreater(len(e[1]),54)
                        self.assertEqual(e[1][12:14],b'\x86\xdd')

if __name__ == '__main__':
    unittest.main()
