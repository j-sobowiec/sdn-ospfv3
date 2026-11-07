"""09C-2: executable old/new diagnostic contract and transparent RX inheritance.

Old Mixin, 08G RX and 09C-1 Ryu are frozen verbatim. Historical tests exercise
those old stages; this test proves current source adds exactly three log methods.
"""
import ast
import hashlib
from pathlib import Path
import random
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
OLD_DIAG = ROOT/'tests/_stage09c2_diagnostics_reference.py'
OLD_RX = ROOT/'tests/_stage09c2_rx_reference.py'
OLD_RYU = ROOT/'tests/_stage09c2_ryu_reference.py'
RX = ROOT/'ospfv3/controller_rx.py'
RYU = ROOT/'ryu_sdn.py'
NAMES = ('log_hello','log_dbd','log_lsu')


def klass(path,name):
    tree=ast.parse(path.read_text(encoding='utf8'))
    nodes=[x for x in tree.body if isinstance(x,ast.ClassDef) and x.name==name]
    assert len(nodes)==1
    return nodes[0]


def methods(node):
    return {x.name:x for x in node.body if isinstance(x,ast.FunctionDef)}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_only(node):
    node=ast.ClassDef(name='Isolated',bases=[],keywords=[],body=node.body,
                      decorator_list=[])
    scope={}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),
                 '<09C-2 isolated>', 'exec'),scope)
    return scope['Isolated']


class LogRecorder:
    def __init__(self):
        self.records=[]
    def info(self,*args):
        self.records.append(('info',args))
    def warning(self,*args):
        self.records.append(('warning',args))


class Stage09C2Diagnostics(unittest.TestCase):
    def test_frozen_exact_source_and_removed_module(self):
        self.assertEqual(sha(OLD_RX),
                         'b424cf0a0bf0012f17a3b29a6dc46995f8506130b58db57ae0832f966575d72e')
        self.assertEqual(sha(OLD_RYU),
                         'dec517bc3fd92042cb00047dc53cd8bff8cd602e8ac9e41c8c52e35d95064c17')
        data=OLD_DIAG.read_bytes()
        git_blob=hashlib.sha1(('blob %d\0'%len(data)).encode()+data).hexdigest()
        self.assertEqual(git_blob,'8825560da450647c408625d710ca51ee28eacf1c')
        self.assertFalse((ROOT/'ospfv3/controller_diagnostics.py').exists())

    def test_only_three_exact_diagnostic_bodies_added_to_receive(self):
        old,new=methods(klass(OLD_RX,'OSPFReceiveMixin')),methods(klass(RX,'OSPFReceiveMixin'))
        diag=methods(klass(OLD_DIAG,'OSPFDiagnosticsMixin'))
        self.assertEqual(set(new)-set(old),set(NAMES))
        self.assertEqual(set(diag),set(NAMES))
        for name,method in old.items():
            with self.subTest(name=name):
                self.assertEqual(ast.dump(method,include_attributes=False),
                                 ast.dump(new[name],include_attributes=False))
        for name,method in diag.items():
            with self.subTest(log=name):
                self.assertEqual(ast.dump(method,include_attributes=False),
                                 ast.dump(new[name],include_attributes=False))

    def test_controller_only_loses_diagnostics_mixin(self):
        before=klass(OLD_RYU,'OSPFv3Controller')
        after=klass(RYU,'OSPFv3Controller')
        self.assertEqual([ast.unparse(b) for b in before.bases],
            ['OSPFDiagnosticsMixin','OSPFReceiveMixin','OSPFTransmitMixin',
             'OSPFTimerMixin','OpenFlowMixin','app_manager.RyuApp'])
        self.assertEqual([ast.unparse(b) for b in after.bases],
            ['OSPFReceiveMixin','OSPFTransmitMixin','OSPFTimerMixin',
             'OpenFlowMixin','app_manager.RyuApp'])
        old_methods,new_methods=methods(before),methods(after)
        self.assertEqual(set(old_methods),set(new_methods))
        for name in old_methods:
            self.assertEqual(ast.dump(old_methods[name],include_attributes=False),
                             ast.dump(new_methods[name],include_attributes=False),name)
        imports=ast.parse(RYU.read_text(encoding='utf8'))
        self.assertFalse(any(isinstance(n,ast.ImportFrom)
                             and n.module=='ospfv3.controller_diagnostics'
                             for n in imports.body))

    def test_300_randomized_log_calls_identical(self):
        Old=load_only(klass(OLD_DIAG,'OSPFDiagnosticsMixin'))
        New=load_only(klass(RX,'OSPFReceiveMixin'))
        old,new=Old(),New()
        old.logger=LogRecorder();new.logger=LogRecorder()
        rng=random.Random(902)
        for index in range(300):
            src=types.SimpleNamespace(src=rng.choice(['fe80::1','fe80::a','invalid']))
            router=rng.choice(['1.1.1.1','2.2.2.2'])
            area=rng.choice(['0.0.0.0','0.0.0.1'])
            port=rng.randrange(1,16)
            length=rng.randrange(20,1500)
            kind=rng.choice(NAMES)
            if kind=='log_hello':
                args=(port,src,length,router,area,rng.randrange(1,16),1,19,
                      rng.choice([10,20]),rng.choice([40,80]),['1.1.1.1']*rng.randrange(5))
            elif kind=='log_dbd':
                args=(port,src,router,area,rng.choice([1280,1500]),19,
                      *[rng.choice([True,False]) for _ in range(3)],
                      rng.getrandbits(32),[{}]*rng.randrange(5))
            else:
                args=(port,src,length,router,area,
                      [{'ls_type':rng.randrange(0,65536)} for _ in range(rng.randrange(5))])
            try:
                a=getattr(old,kind)(*args)
                before=('return',a)
            except Exception as ex:
                before=('error',type(ex).__name__,str(ex))
            try:
                b=getattr(new,kind)(*args)
                after=('return',b)
            except Exception as ex:
                after=('error',type(ex).__name__,str(ex))
            self.assertEqual(before,after,(index,kind))
        self.assertEqual(old.logger.records,new.logger.records)
        self.assertEqual(len(old.logger.records),300)


if __name__=='__main__':
    unittest.main()
