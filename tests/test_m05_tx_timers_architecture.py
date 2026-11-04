"""M05: exact M04 TX/timers relocation and differential integration tests.

No RyuApp instance or eventlet thread is instantiated by isolated tests.
The actual Ryu/Scapy import is checked separately on the Ubuntu host.
"""
import ast
import copy
import hashlib
import importlib.util
import inspect
import random
import unittest
from pathlib import Path

from test_c04_ospf_tx_equivalence import Case, invoke as tx_invoke, selected_class
from test_c06_recovery_equivalence import invoke as timer_invoke

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ryu_sdn.py'
TX = ROOT / 'ospfv3/controller_tx.py'
TIMERS = ROOT / 'ospfv3/controller_timers.py'
REF = Path(__file__).with_name('_m05_transport_reference.py')
TX_NAMES = ('send_ospfv3_hello', '_ospf_unicast_ready', '_build_ospf_unicast_frame',
            '_send_dbd_frame', 'send_initial_dbd', 'send_exchange_dbd',
            'reset_dbd_state', 'send_link_state_request', 'send_ls_ack',
            'send_local_ls_update', 'send_local_lsr_response',
            'send_local_lsa_retransmission', 'reoriginate_local_lsas')
TIMER_NAMES = ('hello_loop', 'neighbor_dead_loop', 'lsdb_aging_loop',
               'local_lsa_retransmission_loop', 'local_lsa_refresh_loop')
MRO = ('OSPFDiagnosticsMixin','OSPFReceiveMixin','OSPFTransmitMixin',
       'OSPFTimerMixin','OpenFlowMixin','app_manager.RyuApp')
REF_HASH = 'ac037a7ea08869af92fc868ea9b64a13bad9b5c598000a180c8e55b0a2a1b46c'

def classnode(path,name):
    matches=[x for x in ast.parse(path.read_text(encoding='utf8')).body
             if isinstance(x,ast.ClassDef) and x.name==name]
    assert len(matches)==1,path
    return matches[0]

def methodmap(klass):
    return {x.name:x for x in klass.body if isinstance(x,ast.FunctionDef)}

def same(a,b):
    return ast.dump(a,include_attributes=False)==ast.dump(b,include_attributes=False)

def recovery_code(path, cls):
    """Compile only the 3 real periodic functions for C06 trace harness."""
    fs=[copy.deepcopy(n) for n in classnode(path,cls).body
        if isinstance(n,ast.FunctionDef) and n.name in
        ('lsdb_aging_loop','local_lsa_retransmission_loop','local_lsa_refresh_loop')]
    assert len(fs)==3
    obj=ast.ClassDef(name='Recovery', bases=[], keywords=[],body=fs,decorator_list=[])
    return compile(ast.fix_missing_locations(ast.Module(body=[obj],type_ignores=[])),str(path),'exec')

OLD_TX = selected_class(REF,'OriginalTX',list(TX_NAMES))
NEW_TX = selected_class(TX,'OSPFTransmitMixin',list(TX_NAMES))
OLD_TIMERS = recovery_code(REF,'OriginalTimers')
NEW_TIMERS = recovery_code(TIMERS,'OSPFTimerMixin')

class TestM05Architecture(unittest.TestCase):
    def test_01_exactly_18_moved_methods_ast_identical(self):
        old_tx=methodmap(classnode(REF,'OriginalTX'))
        old_timers=methodmap(classnode(REF,'OriginalTimers'))
        new_tx=methodmap(classnode(TX,'OSPFTransmitMixin'))
        new_timers=methodmap(classnode(TIMERS,'OSPFTimerMixin'))
        self.assertEqual(set(old_tx),set(TX_NAMES))
        self.assertEqual(set(old_timers),set(TIMER_NAMES))
        self.assertEqual(set(new_tx),set(TX_NAMES))
        self.assertEqual(set(new_timers),set(TIMER_NAMES))
        for k in TX_NAMES:self.assertTrue(same(old_tx[k],new_tx[k]),k)
        for k in TIMER_NAMES:self.assertTrue(same(old_timers[k],new_timers[k]),k)

    def test_02_reference_is_frozen(self):
        self.assertEqual(hashlib.sha256(REF.read_bytes()).hexdigest(),REF_HASH)

    def test_03_no_transport_methods_remain_in_app(self):
        own=methodmap(classnode(APP,'OSPFv3Controller'))
        self.assertFalse((set(TX_NAMES)|set(TIMER_NAMES)) & set(own))
        self.assertEqual(set(own), {'__init__','switch_features_handler',
            'barrier_reply_handler','packet_in_handler','recompute_routing_state',
            'get_ospf_transit_routes'})
        self.assertEqual([ast.unparse(x) for x in classnode(APP,'OSPFv3Controller').bases],list(MRO))

    def test_04_ryuapp_owns_all_event_hooks(self):
        own=methodmap(classnode(APP,'OSPFv3Controller'))
        for name in ('switch_features_handler','barrier_reply_handler','packet_in_handler'):
            self.assertTrue(own[name].decorator_list,name)
        for module,cls in ((TX,'OSPFTransmitMixin'),(TIMERS,'OSPFTimerMixin')):
            node=classnode(module,cls)
            self.assertFalse([x for x in node.body if isinstance(x,ast.FunctionDef) and x.name=='__init__'])
            self.assertFalse(any(x.decorator_list for x in node.body if isinstance(x,ast.FunctionDef)))
            self.assertNotIn('hub.spawn',module.read_text())
            self.assertNotIn('set_ev_cls',module.read_text())

    def test_05_thread_lifecycle_exact_five_spawn_orders(self):
        own=methodmap(classnode(APP,'OSPFv3Controller'))
        init=own['__init__']
        xs=[x for x in ast.walk(init) if isinstance(x,ast.Call) and ast.unparse(x.func)=='hub.spawn']
        self.assertEqual(len(xs),5)
        expected=['hello_loop','neighbor_dead_loop','lsdb_aging_loop',
                  'local_lsa_retransmission_loop','local_lsa_refresh_loop']
        self.assertEqual([x.args[0].attr for x in sorted(xs,key=lambda x:x.lineno)],expected)

    def test_06_public_signatures_docs_and_mro(self):
        for oldname,newname,oldpath,newpath,names in (
                ('OriginalTX','OSPFTransmitMixin',REF,TX,TX_NAMES),
                ('OriginalTimers','OSPFTimerMixin',REF,TIMERS,TIMER_NAMES)):
            old=methodmap(classnode(oldpath,oldname));new=methodmap(classnode(newpath,newname))
            for n in names:
                self.assertEqual(ast.dump(old[n].args),ast.dump(new[n].args),n)
                self.assertEqual(ast.get_docstring(old[n]),ast.get_docstring(new[n]),n)

    def test_07_dbd_tx_and_hello_exact_traces(self):
        for method in ('send_ospfv3_hello','send_initial_dbd','send_exchange_dbd'):
            for case in (Case(),Case(port=None),Case(send_ok=False),Case(broken_send=True),Case(broken_log=True)):
                self.assertEqual(tx_invoke(OLD_TX,method,case),tx_invoke(NEW_TX,method,case),method)

    def test_08_lsr_lsack_lsu_exact_traces(self):
        for method in ('send_link_state_request','send_ls_ack',
                       'send_local_ls_update','send_local_lsr_response',
                       'send_local_lsa_retransmission'):
            for case in (Case(),Case(port=None),Case(ipv6=None),Case(mac=None),
                         Case(send_ok=False),Case(broken_send=True),Case(broken_log=True),
                         Case(body=None),Case(requests=[]),Case(headers=[]),Case(lsas=[])):
                self.assertEqual(tx_invoke(OLD_TX,method,case),tx_invoke(NEW_TX,method,case),method)

    def test_09_500_randomized_tx_traces(self):
        r=random.Random(0xB0505)
        ms=('send_ospfv3_hello','send_initial_dbd','send_exchange_dbd',
            'send_link_state_request','send_ls_ack','send_local_ls_update',
            'send_local_lsr_response','send_local_lsa_retransmission')
        for _ in range(500):
            m=r.choice(ms)
            c=Case(port=r.choice([None,0,1,7]),ipv6=r.choice([None,'fe80::1']),
                   mac=r.choice([None,'00:01:02:03:04:05']),send_ok=r.choice([True,False]),
                   broken_send=r.randrange(10)==0, broken_log=r.randrange(10)==0)
            self.assertEqual(tx_invoke(OLD_TX,m,c),tx_invoke(NEW_TX,m,c),m)

    def test_10_reset_dbd_state_side_effects(self):
        # Same exact body and call order (AST frozen above); real behavior through
        # isolated old/new classes with mocked Neighbor and Logger.
        def call(code):
            env={};exec(code,env);cls=env['TX'];o=cls();events=[]
            class Neigh:
                dbd_sequence=22
                def reset_exchange(self):events.append(('reset_exchange',))
            class Log:
                def warning(self,*args):events.append(('warning',args))
            o.neighbor=Neigh();o.logger=Log();o.local_lsa_ack_pending={'x':1}
            o.local_lsu_last_tx=1;o.local_lsu_sent=True
            o.reset_dbd_state('rx restart')
            return events,o.local_lsa_ack_pending,o.local_lsu_last_tx,o.local_lsu_sent
        self.assertEqual(call(OLD_TX),call(NEW_TX))

    def test_11_reoriginate_local_lsa_paths(self):
        def call(code,pending,ok):
            env={};exec(code,env);obj=env['TX']();trace=[]
            class Local:
                def reoriginate(self,*args):trace.append(('reoriginate',args));return ok
            class Logger:
                def warning(self,*args):trace.append(('warning',args))
            obj.local_lsa_ack_pending=pending;obj.local_lsa=Local()
            obj.neighbor=type('N',(),dict(router_id='1.1.1.1'))()
            obj.logger=Logger();obj.send_local_ls_update=lambda:trace.append(('send',)) or True
            result=obj.reoriginate_local_lsas('reason')
            return result,trace
        for pending in ({},{'pending':1}):
            for ok in (True,False):self.assertEqual(call(OLD_TX,pending,ok),call(NEW_TX,pending,ok))

    def test_12_periodic_timer_traces(self):
        cases=[('lsdb_aging_loop',dict(iterations=4,lsdb_truth=[True]*4,purge=[False,True,False,False])),
               ('local_lsa_retransmission_loop',dict(iterations=4,clock=[100]*4)),
               ('local_lsa_refresh_loop',dict(iterations=3,clock=[100]*3))]
        for method,c in cases:
            self.assertEqual(timer_invoke(OLD_TIMERS,method,c),timer_invoke(NEW_TIMERS,method,c),method)

    def test_13_600_randomized_timer_traces(self):
        r=random.Random(0xC0505)
        for _ in range(600):
            it=r.randrange(6);name=r.choice(('lsdb_aging_loop','local_lsa_retransmission_loop','local_lsa_refresh_loop'))
            cfg=dict(iterations=it,clock=[r.uniform(0,200) for _ in range(max(6,it))])
            if name=='lsdb_aging_loop':
                cfg.update(lsdb_truth=[r.choice([True,False]) for _ in range(10)],purge=[r.choice([True,False]) for _ in range(10)])
            elif name=='local_lsa_retransmission_loop':
                cfg.update(pending=r.choice([{}, {'x':1}]),last_tx=r.choice([None,0,100]),retx_interval=r.choice([0,5,100]))
            else:
                cfg.update(pending=r.choice([{}, {'x':1}]),exchange=r.choice([True,False]),
                           request_list=r.choice([[],[1]]),refresh_interval=r.choice([0,10,50]))
            self.assertEqual(timer_invoke(OLD_TIMERS,name,cfg),timer_invoke(NEW_TIMERS,name,cfg),name)

    def test_14_dead_neighbor_exact_recovery_and_error_order(self):
        from types import SimpleNamespace as NS
        before=selected_class(REF,'OriginalTimers',['neighbor_dead_loop'])
        after=selected_class(TIMERS,'OSPFTimerMixin',['neighbor_dead_loop'])
        class Stop(Exception):pass
        def run(code,expire=True,fail=None):
            trace=[]
            def sleep(n):trace.append(('sleep',n));raise Stop()
            env={'hub':NS(sleep=sleep),'cfg':NS(ROUTER_ID='10.10.10.10',DEAD_INTERVAL=40)}
            exec(code,env)
            o=env['TX']()
            class Log:
                def warning(self,*args):trace.append(('warn',args))
            class Neighbor:
                router_id='1.1.1.1'
                def dead_interval_expired(self,n):trace.append(('expired',n));return expire
                def reset_adjacency(self):trace.append(('reset_adjacency',))
            class LSDB:
                def clear_remote(self,rid):
                    trace.append(('clear_remote',rid))
                    if fail=='clear_remote':raise RuntimeError('bad LSDB')
            class DP:
                transit_port=8
                lan_hosts={'2001:db8:1::100':'02:00:00:00:00:99'}
                def reset_transit(self):trace.append(('reset_transit',));self.transit_port=None
            o.neighbor=Neighbor();o.logger=Log();o.lsdb=LSDB();o.data_plane=DP()
            o.local_lsa_ack_pending={'lsa':1};o.local_lsu_last_tx=5
            o.local_lsu_sent=True
            o.recompute_routing_state=lambda:trace.append(('recompute',))
            o.delete_ipv6_reverse_flow=lambda *a:trace.append(('delete_reverse',a))
            try:o.neighbor_dead_loop()
            except Exception as exc: outcome=(type(exc).__name__,str(exc))
            return outcome,trace,o.local_lsa_ack_pending,o.local_lsu_last_tx,o.local_lsu_sent,o.data_plane.transit_port
        for expire,fail in ((False,None),(True,None),(True,'clear_remote')):
            a=run(before,expire,fail);b=run(after,expire,fail)
            self.assertEqual(a,b,(expire,fail))
            if expire and fail is None:
                self.assertIn(('delete_reverse',('2001:db8:1::100',8)),a[1])

    def test_15_real_ryu_import_mro_and_inherited_api(self):
        if importlib.util.find_spec('ryu') is None or importlib.util.find_spec('scapy') is None:
            self.skipTest('requires real Ryu and Scapy')
        from ryu_sdn import OSPFv3Controller
        from ryu.base.app_manager import RyuApp
        from ospfv3.controller_rx import OSPFReceiveMixin
        from ospfv3.controller_diagnostics import OSPFDiagnosticsMixin
        from ospfv3.controller_tx import OSPFTransmitMixin
        from ospfv3.controller_timers import OSPFTimerMixin
        from controller_openflow import OpenFlowMixin
        self.assertEqual(OSPFv3Controller.__bases__,
            (OSPFDiagnosticsMixin,OSPFReceiveMixin,OSPFTransmitMixin,OSPFTimerMixin,OpenFlowMixin,RyuApp))
        for m in TX_NAMES:self.assertIs(getattr(OSPFv3Controller,m),getattr(OSPFTransmitMixin,m))
        for m in TIMER_NAMES:self.assertIs(getattr(OSPFv3Controller,m),getattr(OSPFTimerMixin,m))

    def test_16_no_duplicated_transport_definitions_in_other_mixins(self):
        from pathlib import Path
        others=[ROOT/'ospfv3/controller_rx.py',ROOT/'ospfv3/controller_diagnostics.py',ROOT/'controller_openflow.py']
        names=set(TX_NAMES)|set(TIMER_NAMES)
        for p in others:
            for n in ast.walk(ast.parse(p.read_text())):
                if isinstance(n,ast.FunctionDef):self.assertNotIn(n.name,names,str(p))

    def test_17_real_scapy_transmission_wire_if_available(self):
        if importlib.util.find_spec('scapy') is None:self.skipTest('requires real Scapy')
        # Existing C04 harness builds actual OSPFv3 frames through Scapy.
        # Equality here proves the M05 relocation changes no raw bytes.
        from test_c04_ospf_tx_equivalence import lsa
        for method in ('send_initial_dbd','send_exchange_dbd','send_ls_ack',
                       'send_local_ls_update','send_local_lsr_response'):
            case=Case(body=b'\x00\x00\x00\x01'+lsa()['raw_lsa'])
            self.assertEqual(tx_invoke(OLD_TX,method,case,True),
                             tx_invoke(NEW_TX,method,case,True),method)

if __name__=='__main__':unittest.main()
