"""09C-2 hotfix: frozen Stage02 check and moved diagnostics stay visible.

The original Stage02 test still verifies every banned SPF symbol; it now scans
an immutable diagnostic reference rather than a removed production module.
"""
import ast
import hashlib
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
OLD=ROOT/'tests/_stage09c2_stage02_reference.py'
NEW=ROOT/'tests/test_stage02_spf_detach.py'
DIAG_REF=ROOT/'tests/_stage09c2_diagnostics_reference.py'
DIAG_RUNTIME=ROOT/'ospfv3/controller_diagnostics.py'
RX=ROOT/'ospfv3/controller_rx.py'
RYU=ROOT/'ryu_sdn.py'
ORIGINAL_BLOB='5a058bb591d1d537d499eed54be3d4bfa3bebe07'


def blob(data):
    return hashlib.sha1(f'blob {len(data)}\0'.encode()+data).hexdigest()


class Stage09C2HotfixStage02(unittest.TestCase):
    def test_original_stage02_is_immutable(self):
        self.assertEqual(blob(OLD.read_bytes()),ORIGINAL_BLOB)
        self.assertTrue(NEW.is_file())

    def test_all_spf_absence_checks_remain_active(self):
        old=OLD.read_text(encoding='utf8')
        new=NEW.read_text(encoding='utf8')
        self.assertEqual(new,old.replace(
            '    "ospfv3/controller_diagnostics.py"\n)',
            '    "tests/_stage09c2_diagnostics_reference.py"\n)'))
        ns={}
        for n in ast.parse(new).body:
            if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCES' for t in n.targets):
                self.assertEqual(ast.literal_eval(n.value),(
                    'ryu_sdn.py','ospfv3/controller_rx.py',
                    'ospfv3/controller_timers.py',
                    'tests/_stage09c2_diagnostics_reference.py'))
                break
        else:
            self.fail('Brak listy SOURCES w Stage02')

    def test_diagnostics_moved_without_resurrecting_module(self):
        self.assertFalse(DIAG_RUNTIME.exists())
        self.assertTrue(DIAG_REF.is_file())
        rx=ast.parse(RX.read_text(encoding='utf8'))
        cls=next(n for n in rx.body if isinstance(n,ast.ClassDef) and n.name=='OSPFReceiveMixin')
        methods={n.name for n in cls.body if isinstance(n,ast.FunctionDef)}
        self.assertTrue({'log_hello','log_dbd','log_lsu'}.issubset(methods))
        ryu=RYU.read_text(encoding='utf8')
        self.assertNotIn('from ospfv3.controller_diagnostics import',ryu)
        self.assertNotIn('OSPFDiagnosticsMixin',ryu)


if __name__=='__main__':
    unittest.main()
