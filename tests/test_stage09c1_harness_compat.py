"""09C-1 hotfix: run the genuine moved parser validator in the legacy AST harness."""
import ast
import hashlib
import types
from pathlib import Path
import unittest

import b5_3_harness as h

ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / 'ospfv3/parser.py'
BASELINE = ROOT / 'tests/_stage09c1_b53_reference.py'
BLOB = '42ce14186232c73c80e12ff0acd9a29eb9822b9f'


class Stage09C1HarnessCompat(unittest.TestCase):
    def test_historical_harness_preserved_exactly(self):
        data = BASELINE.read_bytes()
        blob = hashlib.sha1(('blob %d\0' % len(data)).encode()+data).hexdigest()
        self.assertEqual(blob, BLOB)

    def test_validator_is_real_parser_function_injected_into_ast_harness(self):
        source = PARSER.read_text(encoding='utf8')
        tree = ast.parse(source, filename=str(PARSER))
        fn = next(x for x in tree.body if isinstance(x, ast.FunctionDef)
                  and x.name == 'validate_ospfv3_transport')
        actual = h.ControllerAST.packet_in_handler.__globals__['validate_ospfv3_transport']
        self.assertIsInstance(actual, types.FunctionType)
        self.assertEqual(actual.__code__.co_filename, str(PARSER))
        self.assertEqual(actual.__code__.co_firstlineno, fn.lineno)
        self.assertEqual(actual.__name__, fn.name)

    def test_empty_or_truncated_ospf_drops_without_packetout(self):
        for payload in (None, b'', b'123456789012345'):
            with self.subTest(payload=payload):
                ctl = h.make_controller(route=False, ready=True)
                h.packet_in(ctl, h.ns(proto=89, data=payload))
                self.assertFalse(any(x.kind == 'packet_out' for x in ctl.datapath.sent))

    def test_ndp_control_frames_still_do_not_enter_data_path(self):
        for kind in (134,136):
            with self.subTest(icmp_type=kind):
                ctl = h.make_controller(route=False, ready=True)
                h.packet_in(ctl, h.ns(proto=58, data=h.ICMP(type_=kind)))
                self.assertFalse(any(x.kind == 'packet_out' for x in ctl.datapath.sent))


if __name__ == '__main__':
    unittest.main()
