"""M04: freeze relocated receive-side code, MRO, and exact state/trace behavior.

The reference contains the eight M03 production method bodies, unmodified.
No RyuApp threads are started in deterministic differential tests.
"""
import ast
import copy
import importlib.util
import inspect
import hashlib
from functools import lru_cache
import ipaddress
import pathlib
import random
import socket
import struct
import unittest
from types import SimpleNamespace as NS

from test_c05_ospf_rx_equivalence import invoke as invoke_c05

ROOT = pathlib.Path(__file__).resolve().parents[1]
BEFORE = ROOT / 'tests' / '_m04_rx_reference.py'
AFTER = ROOT / 'ospfv3' / 'controller_rx.py'
APP = ROOT / 'ryu_sdn.py'
METHODS = ('handle_ospf_hello', 'is_current_ospf_neighbor',
           '_reject_noncurrent_ospf_neighbor', '_split_ospf_lsa_by_origin',
           'handle_ospf_dbd', 'handle_ospf_lsr', 'handle_ospf_lsu', 'handle_ospf_lsack')
HANDLERS = ('handle_ospf_hello', 'handle_ospf_dbd', 'handle_ospf_lsr',
            'handle_ospf_lsu', 'handle_ospf_lsack')


def klass(path, name):
    mod=ast.parse(path.read_text(encoding='utf8'))
    return next(node for node in mod.body if isinstance(node, ast.ClassDef) and node.name==name)


def methods(path, name):
    return {n.name:n for n in klass(path,name).body if isinstance(n,ast.FunctionDef)}


@lru_cache(maxsize=4)
def _isolated_code(path, name):
    source=klass(path,name)
    body=[copy.deepcopy(m) for m in source.body if isinstance(m,ast.FunctionDef)]
    tree=ast.fix_missing_locations(ast.Module(body=[ast.ClassDef(name='Rx',bases=[],keywords=[],body=body,decorator_list=[])],type_ignores=[]))
    return compile(tree,str(path),'exec')


def isolated(path, name, cfg):
    compiled=_isolated_code(path,name)
    trace=[]
    def parse_hello(data, length):
        trace.append(('parse_hello',bytes(data),length))
        if cfg.get('parse_error'):
            raise ValueError('hello invalid')
        return copy.deepcopy(cfg.get('parsed', dict(interface_id=5,router_priority=1,
            options=19,hello_interval=10,dead_interval=40,neighbors=['10.10.10.10'])))
    env={'cfg':NS(ROUTER_ID='10.10.10.10',HELLO_INTERVAL=10,DEAD_INTERVAL=40),
         'parse_hello':parse_hello,'parse_dbd':None,'parse_lsr':None,
         'parse_lsu':None,'parse_lsack':None,
         'socket':socket,'struct':struct,
         'ospfv3_lsa_type_description':lambda n:str(n)}
    exec(compiled,env)
    return env['Rx'](),trace


class Logger:
    def __init__(self,trace,fail=None):self.trace=trace;self.fail=fail
    def info(self,*a):
        self.trace.append(('info',copy.deepcopy(a)))
        if self.fail=='info':raise RuntimeError('logging info error')
    def warning(self,*a):
        self.trace.append(('warning',tuple((type(x).__name__,str(x)) if isinstance(x, BaseException) else copy.deepcopy(x) for x in a)))
        if self.fail=='warning':raise RuntimeError('logging warning error')


class Neighbor:
    def __init__(self,trace,cfg):
        self.trace=trace
        self.port=cfg.get('port')
        self.ipv6=cfg.get('ip')
        self.mac=cfg.get('mac')
        self.router_id=cfg.get('rid')
        self.router_ids=list(cfg.get('ids',[]))
    def mark_hello_received(self):
        self.trace.append(('mark_hello_received',))


class DataPlane:
    def __init__(self,trace,cfg):self.trace=trace;self.cfg=cfg
    def learn_transit_router(self,**kw):
        self.trace.append(('learn_transit_router',copy.deepcopy(kw)))
        if self.cfg.get('learn_error'):
            raise RuntimeError('learn failed')
        return self.cfg.get('learn',True)


def hello_run(source,name,cfg):
    cfg=copy.deepcopy(cfg)
    obj,trace=isolated(source,name,cfg)
    obj.logger=Logger(trace,cfg.get('logger_fail'))
    obj.neighbor=Neighbor(trace,cfg)
    obj.data_plane=DataPlane(trace,cfg)
    obj.ospf_resync_required=cfg.get('resync',False)
    obj.log_hello=lambda *a:trace.append(('log_hello',copy.deepcopy(a)))
    obj.try_install_ipv6_host_flows=lambda:trace.append(('try_install_ipv6_host_flows',))
    obj.send_ospfv3_hello=lambda *a,**kw:trace.append(('send_ospfv3_hello',copy.deepcopy(a),copy.deepcopy(kw)))
    eth=NS(src='02:00:00:00:00:02');ipv6=NS(src='fe80::2')
    try:
        result=obj.handle_ospf_hello(7,eth,ipv6,b'hello',36,'2.2.2.2','0.0.0.0')
        status=('return',result)
    except Exception as e:
        status=('exception',type(e).__name__,str(e))
    return status,trace,{x:copy.deepcopy(getattr(obj.neighbor,x)) for x in ('port','ipv6','mac','router_id','router_ids')},obj.ospf_resync_required


class TestM04Architecture(unittest.TestCase):
    def test_01_all_eight_methods_identical_ast(self):
        old,new=methods(BEFORE,'OriginalRX'),methods(AFTER,'OSPFReceiveMixin')
        self.assertEqual(tuple(old),METHODS)
        self.assertEqual(tuple(new),METHODS)
        for name in METHODS:
            self.assertEqual(ast.dump(old[name],include_attributes=False),
                             ast.dump(new[name],include_attributes=False),name)

    def test_15_reference_fingerprint_is_frozen(self):
        self.assertEqual(hashlib.sha256(BEFORE.read_bytes()).hexdigest(),
                         '698951f63638410149b597ecaa822f17abe3e983762bb9724fbc9b027ea000f6')

    def test_02_signatures_and_documentation(self):
        cfg={}
        old,_=isolated(BEFORE,'OriginalRX',cfg)
        new,_=isolated(AFTER,'OSPFReceiveMixin',cfg)
        for name in METHODS:
            self.assertEqual(inspect.signature(getattr(old,name)),
                             inspect.signature(getattr(new,name)))
            self.assertEqual(getattr(old,name).__doc__,getattr(new,name).__doc__)

    def test_03_receivers_not_in_ryuapp_class(self):
        c=klass(APP,'OSPFv3Controller')
        declared={n.name for n in c.body if isinstance(n,ast.FunctionDef)}
        self.assertFalse(declared.intersection(METHODS))
        self.assertEqual([ast.unparse(x) for x in c.bases],
                         ['OSPFDiagnosticsMixin','OSPFReceiveMixin','OSPFTransmitMixin','OSPFTimerMixin','OpenFlowMixin','app_manager.RyuApp'])
        for name in ('packet_in_handler','switch_features_handler','barrier_reply_handler'):
            node=next(n for n in c.body if isinstance(n,ast.FunctionDef) and n.name==name)
            self.assertTrue(node.decorator_list)
        txt=APP.read_text()
        self.assertIn('from ospfv3.controller_rx import OSPFReceiveMixin',txt)

    def test_04_no_rx_ryu_hooks_or_state_initialization(self):
        text=AFTER.read_text()
        self.assertNotIn('from ryu',text)
        self.assertNotIn('hub.spawn',text)
        self.assertNotIn('@set_ev_cls',text)
        self.assertNotIn('def __init__',text)
        self.assertNotIn('def packet_in_handler',text)

    def check_hello(self, cfg):
        a=hello_run(BEFORE,'OriginalRX',cfg)
        b=hello_run(AFTER,'OSPFReceiveMixin',cfg)
        self.assertEqual(a,b,cfg)
        return b

    def test_05_hello_normal_discovery_and_learning(self):
        result=self.check_hello(dict(parsed=dict(interface_id=7,router_priority=1,options=0,
                                   hello_interval=10,dead_interval=40,neighbors=[])))
        self.assertIn(('mark_hello_received',),result[1])
        self.assertTrue(any(item[0]=='send_ospfv3_hello' for item in result[1]))

    def test_06_hello_mismatched_intervals_and_parse_failures(self):
        for cfg in (dict(parse_error=True),
                    dict(parsed=dict(interface_id=1,router_priority=1,options=1,hello_interval=12,dead_interval=40,neighbors=[])),
                    dict(parsed=dict(interface_id=1,router_priority=1,options=1,hello_interval=10,dead_interval=44,neighbors=[]))):
            result=self.check_hello(cfg)
            self.assertFalse(any(x[0]=='mark_hello_received' for x in result[1]))

    def test_07_resync_one_way_hello_preserved(self):
        result=self.check_hello(dict(resync=True))
        sends=[x for x in result[1] if x[0]=='send_ospfv3_hello']
        self.assertEqual(len(sends),1)
        self.assertEqual(sends[0][2],{'neighbors':[]})
        self.assertFalse(result[3])

    def test_08_hello_needs_no_duplicate_hello_when_known(self):
        self.check_hello(dict(ids=['2.2.2.2'],resync=False,learn=False))
        self.check_hello(dict(ids=['2.2.2.2'],resync=True,learn=False))

    def test_09_hello_errors_logger_learning_and_missing_fields(self):
        for cfg in (dict(logger_fail='info',resync=True),dict(logger_fail='warning',parse_error=True),
                    dict(learn_error=True),dict(parsed={'interface_id':2}),
                    dict(parsed=dict(interface_id=5,router_priority=1,options=19,hello_interval=10,dead_interval=40,neighbors=None),resync=True)):
            self.check_hello(cfg)

    def test_10_randomized_hello_trace_and_state(self):
        rng=random.Random(20261020)
        for _ in range(500):
            opts=dict(parsed=dict(interface_id=rng.randint(0,65535),router_priority=rng.randrange(256),
                                  options=rng.randrange(2**24),hello_interval=rng.choice([10,11,12]),
                                  dead_interval=rng.choice([40,41]),
                                  neighbors=rng.choice([[],['10.10.10.10'],['1.1.1.1'],None])),
                      ids=rng.choice([[],['2.2.2.2'],['1.1.1.1']]),learn=rng.choice([True,False]),
                      resync=rng.choice([True,False]),logger_fail=rng.choice([None,None,None,'info']))
            self.check_hello(opts)

    def test_11_dbd_lsr_lsu_lsack_differential(self):
        # Reuse the production trace harness from C05, but compare M03 -> M04
        # rather than the original C04 -> current implementation.
        import test_c05_ospf_rx_equivalence as h
        selected=list(h.METHODS)+list(h.HELPERS)
        before=h.extract(BEFORE,'OriginalRX',selected)
        after=h.extract(AFTER,'OSPFReceiveMixin',selected)
        rng=random.Random(29410)
        for method in h.METHODS:
            for _ in range(300):
                case=dict(incoming_port=rng.choice([7,7,8]),
                          incoming_ip=rng.choice(['fe80::1','fe80::2']),
                          rid=rng.choice(['1.1.1.1',None,'3.3.3.3']),
                          parsed=[h.sample_lsa(rng.randint(1,10),
                                             rng.choice(['10.10.10.10','1.1.1.1']))
                                  for _ in range(rng.randrange(3))],
                          negotiated=rng.choice([True,False]),
                          exchange_complete=rng.choice([True,False]),
                          dbd_seq=rng.randrange(3,15),
                          send_update_ok=rng.choice([True,False]))
                self.assertEqual(h.invoke(before,method,case),h.invoke(after,method,case), (method,case))

    def test_12_existing_parser_and_helper_calls_only(self):
        methods_new=methods(AFTER,'OSPFReceiveMixin')
        for n in methods_new.values():
            self.assertFalse(any(isinstance(node,(ast.Import,ast.ImportFrom)) for node in ast.walk(n)))
        source=AFTER.read_text()
        for name in ('parse_hello','parse_dbd','parse_lsr','parse_lsu','parse_lsack'):
            self.assertIn(name,source)

    def test_13_real_ryu_import_and_mro(self):
        if importlib.util.find_spec('ryu') is None or importlib.util.find_spec('scapy') is None:
            self.skipTest('requires real Ryu and Scapy')
        from ryu_sdn import OSPFv3Controller
        from ospfv3.controller_rx import OSPFReceiveMixin
        from ospfv3.controller_diagnostics import OSPFDiagnosticsMixin
        from controller_openflow import OpenFlowMixin
        from ospfv3.controller_tx import OSPFTransmitMixin
        from ospfv3.controller_timers import OSPFTimerMixin
        from ryu.base.app_manager import RyuApp
        self.assertEqual(OSPFv3Controller.__bases__,
                         (OSPFDiagnosticsMixin,OSPFReceiveMixin,OSPFTransmitMixin,OSPFTimerMixin,OpenFlowMixin,RyuApp))
        for name in METHODS:
            self.assertIs(getattr(OSPFv3Controller,name),getattr(OSPFReceiveMixin,name))

    def test_14_hello_packet_dispatch_stays_in_controller(self):
        ctrl=klass(APP,'OSPFv3Controller')
        pi=next(x for x in ctrl.body if isinstance(x,ast.FunctionDef) and x.name=='packet_in_handler')
        calls={x.attr for x in ast.walk(pi) if isinstance(x,ast.Attribute)}
        self.assertTrue(set(HANDLERS).issubset(calls) or 'getattr' in {x.id for x in ast.walk(pi) if isinstance(x,ast.Name)})

if __name__=='__main__':unittest.main()
