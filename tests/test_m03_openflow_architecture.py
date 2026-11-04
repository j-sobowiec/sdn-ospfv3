"""M03: exact migration of the OpenFlow methods into a stateless mixin.

This compares frozen, *actual M02* production code against the relocated
production methods, including sent OpenFlow messages, exceptions and state.
The historical B5.3/C01 tests continue to execute real AST method bodies.
"""
import ast
import copy
import importlib.util
import inspect
import random
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

import b5_3_harness as h

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'ryu_sdn.py'
MIXIN = ROOT / 'controller_openflow.py'
BEFORE = Path(__file__).with_name('_m03_openflow_reference.py')
METHODS = ('_send_action_flow', '_send_strict_delete',
           'try_install_ipv6_host_flows', 'install_ipv6_host_flows',
           'delete_ipv6_route_flow', 'delete_ipv6_reverse_flow', 'send_frame')


def get_class(file, name):
    tree = ast.parse(file.read_text(encoding='utf-8'))
    return next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name)


def method_map(node):
    return {n.name: n for n in node.body if isinstance(n, ast.FunctionDef)}


ReferenceMethods = h.load_class(BEFORE, 'OriginalOpenFlow', h.BASE)
class OldController(ReferenceMethods, h.Controller):
    pass


class Log:
    def __init__(self): self.events = []
    def info(self, *a, **kw): self.events.append(('info', a, kw))
    def warning(self, *a, **kw): self.events.append(('warning', a, kw))
    def error(self, *a, **kw): self.events.append(('error', a, kw))
    debug = info


def canon(v):
    if hasattr(v, 'kind') and hasattr(v, 'args'):
        return (v.kind, tuple(canon(x) for x in v.args),
                tuple((k, canon(w)) for k, w in vars(v).items() if k not in ('kind','args')))
    if isinstance(v, dict): return tuple((canon(k), canon(w)) for k, w in v.items())
    if isinstance(v, (tuple, list)): return tuple(canon(x) for x in v)
    if isinstance(v, set): return tuple(sorted((canon(x) for x in v), key=repr))
    if hasattr(v, 'sent') and hasattr(v, 'ofproto_parser'): return '<datapath>'
    return v


def state(c):
    return (canon(c.datapath.sent) if c.datapath else None,
            canon(c.installed_ipv6_host_flows), canon(c.data_plane.lan_hosts),
            canon(c.pending_ndp_barriers), canon(c.ipv6_routing_table),
            c.logger.events[:])


def pair(route=True, ready=True):
    a=h.make_controller(route=route, ready=ready)
    a.__class__=OldController
    b=h.make_controller(route=route, ready=ready)
    a.logger=Log(); b.logger=Log()
    return a,b


def compare(case, a, b, method, *args):
    values=[]
    for obj in (a,b):
        try: values.append(('return', getattr(obj, method)(*args)))
        except Exception as exc: values.append(('error', type(exc).__name__, str(exc)))
    case.assertEqual(values[0],values[1],method)
    case.assertEqual(state(a),state(b),method)
    return values[0]


class TestM03Architecture(unittest.TestCase):
    def test_01_seven_methods_moved_exact_ast(self):
        old=method_map(get_class(BEFORE,'OriginalOpenFlow'))
        new=method_map(get_class(MIXIN,'OpenFlowMixin'))
        self.assertEqual(list(old),list(METHODS))
        self.assertEqual(list(new),list(METHODS))
        for name in METHODS:
            self.assertEqual(ast.dump(old[name],include_attributes=False),
                             ast.dump(new[name],include_attributes=False), name)

    def test_02_signatures_and_docstrings_unchanged(self):
        for name in METHODS:
            self.assertEqual(inspect.signature(getattr(ReferenceMethods,name)),
                             inspect.signature(getattr(h.Controller,name)))
            self.assertEqual(getattr(ReferenceMethods,name).__doc__,
                             getattr(h.Controller,name).__doc__)

    def test_03_controller_keeps_ryu_event_handlers(self):
        cls=get_class(SRC,'OSPFv3Controller')
        old=method_map(get_class(BEFORE,'OriginalOpenFlow'))
        self.assertFalse(set(old).intersection(method_map(cls)))
        for event in ('switch_features_handler','barrier_reply_handler','packet_in_handler'):
            node=method_map(cls)[event]
            self.assertTrue(node.decorator_list,event)
        self.assertEqual([ast.unparse(x) for x in cls.bases],
                         ['OSPFDiagnosticsMixin','OSPFReceiveMixin','OSPFTransmitMixin','OSPFTimerMixin','OpenFlowMixin','app_manager.RyuApp'])

    def test_04_mixin_is_stateless_no_events_or_threads(self):
        cls=get_class(MIXIN,'OpenFlowMixin')
        self.assertFalse(any(n.name=='__init__' for n in cls.body if isinstance(n,ast.FunctionDef)))
        text=MIXIN.read_text()
        self.assertNotIn('@set_ev_cls',text)
        self.assertNotIn('hub.spawn',text)
        self.assertNotIn('def packet_in_handler',text)
        self.assertNotIn('def switch_features_handler',text)

    def test_05_ast_harness_executes_rel_nonstub_methods(self):
        self.assertIn(h.OpenFlowMixin, h.Controller.__bases__)  # M05: transport mixins added
        self.assertEqual(ast.dump(method_map(get_class(MIXIN,'OpenFlowMixin'))['send_frame'], include_attributes=False),
                         ast.dump(method_map(get_class(BEFORE,'OriginalOpenFlow'))['send_frame'], include_attributes=False))
        self.assertTrue(callable(h.Controller.send_frame))

    def test_06_send_frame_and_disconnected_paths(self):
        for frame in (b'',b'abc',b'\xff'*100):
            for port in (0,2,0xffffffff):
                a,b=pair(); compare(self,a,b,'send_frame',frame,port)
                a,b=pair(); a.datapath=None;b.datapath=None
                compare(self,a,b,'send_frame',frame,port)

    def test_07_flow_mod_add_and_strict_delete_message_trace(self):
        a,b=pair()
        for name in ('_send_action_flow','_send_strict_delete'):
            match=h.OFParser.OFPMatch(in_port=2,eth_type=0x86dd)
            args=(a.datapath,match,100,[h.OFParser.OFPActionOutput(2)]) if name=='_send_action_flow' else (a.datapath,match,110)
            values=[]
            for ctrl in (a,b):
                arg=(ctrl.datapath,)+args[1:]
                getattr(ctrl,name)(*arg)
                values.append(canon(ctrl.datapath.sent))
            self.assertEqual(values[0],values[1])

    def test_08_install_host_routes_and_cache(self):
        for route,ready in ((True,True),(False,True),(True,False),(False,False)):
            a,b=pair(route,ready)
            compare(self,a,b,'try_install_ipv6_host_flows')
            compare(self,a,b,'try_install_ipv6_host_flows')
            if ready:
                compare(self,a,b,'install_ipv6_host_flows',h.LAN_IP,h.LAN_MAC)

    def test_09_withdrawn_routes_strict_delete_order(self):
        a,b=pair()
        compare(self,a,b,'try_install_ipv6_host_flows')
        a.ipv6_routing_table.clear();b.ipv6_routing_table.clear()
        compare(self,a,b,'try_install_ipv6_host_flows')

    def test_10_reverse_route_delete_and_invalid_network(self):
        for name,args in (('delete_ipv6_reverse_flow',(h.LAN_IP,1)),
                          ('delete_ipv6_reverse_flow',(h.LAN_IP,None)),
                          ('delete_ipv6_route_flow',(h.LAN_IP,'2001:db8:23::',64,2)),
                          ('delete_ipv6_route_flow',(h.LAN_IP,'bad prefix',64,2))):
            a,b=pair();compare(self,a,b,name,*args)

    def test_11_logger_failures_are_identical(self):
        class Broken(Log):
            def info(self,*a,**kw):
                super().info(*a,**kw)
                raise RuntimeError('logger stopped')
        for name,args in (('try_install_ipv6_host_flows',()),
                          ('delete_ipv6_reverse_flow',(h.LAN_IP,1)),
                          ('delete_ipv6_route_flow',(h.LAN_IP,'2001:db8:23::',64,2))):
            a,b=pair();a.logger=Broken();b.logger=Broken()
            compare(self,a,b,name,*args)

    def test_12_packet_out_parser_error_and_sender_error(self):
        for error_at in ('OFPActionOutput','OFPPacketOut','send_msg'):
            a,b=pair()
            for ctl in (a,b):
                if error_at=='send_msg':
                    def fail(_):raise RuntimeError('send failed')
                    ctl.datapath.send_msg=fail
                else:
                    def fail(*args,**kwargs):raise ValueError(error_at)
                    setattr(ctl.datapath.ofproto_parser,error_at,fail)
            compare(self,a,b,'send_frame',b'\x11',2)

    def test_13_randomized_host_route_wires(self):
        rng=random.Random(20261020)
        for _ in range(600):
            a,b=pair(route=True,ready=True)
            host='2001:db8:1::%x'%rng.randrange(2,0xfffe)
            mac='02:00:00:%02x:%02x:%02x'%tuple(rng.randrange(256) for _ in range(3))
            withdraw = rng.random() < 0.5
            for obj in (a,b):
                obj.data_plane.lan_hosts.clear()
                obj.data_plane.lan_hosts[host]=mac
                if withdraw:
                    obj.ipv6_routing_table.clear()
            compare(self,a,b,'try_install_ipv6_host_flows')

    def test_14_real_import_and_mro_if_ryu(self):
        if importlib.util.find_spec('ryu') is None or importlib.util.find_spec('scapy') is None:
            self.skipTest('real Ryu/Scapy required')
        from ryu_sdn import OSPFv3Controller
        from controller_openflow import OpenFlowMixin
        from ospfv3.controller_diagnostics import OSPFDiagnosticsMixin
        from ospfv3.controller_rx import OSPFReceiveMixin
        from ospfv3.controller_tx import OSPFTransmitMixin
        from ospfv3.controller_timers import OSPFTimerMixin
        self.assertEqual(OSPFv3Controller.__bases__,
                         (OSPFDiagnosticsMixin,OSPFReceiveMixin,OSPFTransmitMixin,OSPFTimerMixin,OpenFlowMixin,__import__('ryu.base.app_manager',fromlist=['RyuApp']).RyuApp))
        for name in METHODS:
            self.assertIs(getattr(OSPFv3Controller,name),getattr(OpenFlowMixin,name))
