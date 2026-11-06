"""Stage04A logging contract, compatible with the explicitly pinned Stage04B RX."""

import ast
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
PIN = "e4ed0fa4f83cfc8ece8487f91023e3b8e5289e7d"
DIAGNOSTICS = ROOT / "ospfv3/controller_diagnostics.py"
FROZEN_PRODUCTION = {
    "ryu_sdn.py": "8f9eaa95700bf07183b4e01088002144f0e9f51c5bc0176358744c451f09c4e5",
    "controller_openflow.py": "be7c836a2154c574834bf0d299cb2c5890dbaebc8a93c97ee54ad5c180018ed3",
    "ospfv3/controller_timers.py": "0da0daf65c0dab5a410eaa98c3bc05f616734738f04aad112e90ac3a5cec2423",
}
RX_04A_SHA = "126d54c81e1c73825f284910eeb4e73018ba0fdab2b1099c4378dde859a37e3c"
RX_04B_SHA = "5ee6e527ee840f7d0ed10c56c721b73bc3b54e1548faabdec734bf930397e59d"
RX_04B_TEST_SHA = "0dab530d3eec94381a23902e1db53e851ce07c20d446d5b8d5d37a2a0fa39ad2"


def method_args(tree):
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef)
               and node.name == "OSPFDiagnosticsMixin")
    return {node.name: [arg.arg for arg in node.args.args]
            for node in cls.body if isinstance(node, ast.FunctionDef)}


class Recorder:
    def __init__(self):
        self.events = []

    def info(self, *args):
        self.events.append(args)


class Stage04AContract(unittest.TestCase):
    def test_original_method_arguments_preserved(self):
        old = subprocess.check_output(
            ["git", "-C", str(ROOT), "show",
             PIN + ":ospfv3/controller_diagnostics.py"]
        ).decode("utf8")
        actual = DIAGNOSTICS.read_text(encoding="utf8")
        before = method_args(ast.parse(old))
        after = method_args(ast.parse(actual))
        self.assertEqual(set(after), {"log_hello", "log_dbd", "log_lsu"})
        self.assertEqual(after, {name: before[name] for name in after})

    def test_no_ospf_processing_or_openflow_sources_modified(self):
        for name, expected in FROZEN_PRODUCTION.items():
            with self.subTest(file=name):
                self.assertEqual(
                    hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                    expected
                )
        # Stage04B deliberately replaces ONLY RX. Do not weaken this to a
        # generic hash allowlist: require the exact Stage04B contract as well.
        rx_contract = ROOT / "tests/test_stage04b_rx_contract.py"
        expected_rx = RX_04A_SHA
        if rx_contract.is_file():
            with self.subTest(file="tests/test_stage04b_rx_contract.py"):
                self.assertEqual(hashlib.sha256(rx_contract.read_bytes()).hexdigest(),
                                 RX_04B_TEST_SHA)
            expected_rx = RX_04B_SHA
        with self.subTest(file="ospfv3/controller_rx.py"):
            self.assertEqual(
                hashlib.sha256((ROOT / "ospfv3/controller_rx.py").read_bytes()).hexdigest(),
                expected_rx
            )

    def test_logs_one_summary_per_hello_dbd_lsu(self):
        spec = importlib.util.spec_from_file_location("stage04a_diag", DIAGNOSTICS)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        recorder = Recorder()
        target = module.OSPFDiagnosticsMixin()
        target.logger = recorder
        ipv6 = SimpleNamespace(src="fe80::1")
        target.log_hello(1, ipv6, 36, "1.1.1.1", "0.0.0.0",
                         12, 1, 0x13, 10, 40, ("10.10.10.10",))
        target.log_dbd(1, ipv6, "1.1.1.1", "0.0.0.0", 1500, 0x13,
                       True, False, True, 42, ())
        target.log_lsu(1, ipv6, 128, "1.1.1.1", "0.0.0.0", (
            {"ls_type": 0x2001}, {"ls_type": 0x200b}
        ))
        self.assertEqual(len(recorder.events), 3)
        self.assertIn("HELLO RX", recorder.events[0][0])
        self.assertIn("DBD RX", recorder.events[1][0])
        self.assertIn("LSU RX", recorder.events[2][0])

    def test_empty_lsu_and_unknown_lsa_do_not_crash_diagnostics(self):
        spec = importlib.util.spec_from_file_location("stage04a_diag2", DIAGNOSTICS)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target = module.OSPFDiagnosticsMixin()
        target.logger = Recorder()
        target.log_lsu(1, SimpleNamespace(src="fe80::1"), 20,
                       "1.1.1.1", "0.0.0.0", ())
        self.assertEqual(len(target.logger.events), 1)
        self.assertIn("types=%s", target.logger.events[0][0])


if __name__ == "__main__":
    unittest.main()
