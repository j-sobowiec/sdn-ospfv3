"""Stage04A logging contract with verified Stage04B RX and Stage07 Ryu event consolidation."""

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
STAGE07_RYU_SHA = "08402606b119fee072c2bcfe39cd05242f804008cf9c1cb85ea9353753644538"
STAGE07_TEST_SHA = "476a62ad777507b1c3f5efad9822dbfa41985d02ed0fcda30cdd1e09b3bf2750"
STAGE07_REFERENCE_SHA = "8f9eaa95700bf07183b4e01088002144f0e9f51c5bc0176358744c451f09c4e5"
STAGE08B_OPENFLOW_SHA = "09c2499e6a3edccb017c9c7006afd9cd80bb5a1bf7adc304585a205f43ed0d4c"
STAGE08B_CONTRACT_SHA = "c4e45dda919ec88b916aa4488b5b7921960e65cbe081dbd1d857a83cc31d4185"
STAGE08C_OPENFLOW_SHA = "5a45925519d6544a2044a8df9f2bb481feeae1f91ce8c5101221dc2955400014"
STAGE08C_CONTRACT_SHA = "55fc4448e54a881d37b0e681d02f56cb1a6070d02e3fc4e0a4cd43344db135de"
STAGE08C_UPDATED_08B_SHA = "d80e2ad9a4db77bbbaf5f34f4ac0567f11ca36291b6e24ce81477e39482f3e75"
STAGE08F_RYU_SHA = "c7b7ecb6f9021728190cd59f2e62f5c0006c80d8a29e4bd67608048214a11dcd"
STAGE08F_STAGE07_TEST_SHA = "ca36d0b030d1c0c079823a5e9fb47cb97aebe205d204aaa691ebbe165519e487"
STAGE08F_CONTRACT_SHA = "4086b5529e8b15dcea7a0547fd48aa353445817c83ef00d02510534eeb6af24b"
STAGE08F_ORIGINAL_04A_SHA = "a0a19d4673981290643b1b3895911a09a7b779fcce07ba334816af61d4f46966"
STAGE08G_RX_SHA = "b424cf0a0bf0012f17a3b29a6dc46995f8506130b58db57ae0832f966575d72e"
STAGE08G_CONTRACT_SHA = "a5d270d8df137be0fc00022407f906c1e2cbe76a121f121a17dfc84bb62928c5"
STAGE08G_04A_REFERENCE_SHA = "6d5c90ec40edd122f83400d64bae495bca2f9fc56ca868e0dddefba241dcc720"
STAGE08I_TIMERS_SHA = "d56470416af29d3474a06f7b6d74fde7dc5d6c92b0a4ec91ef4c881d52fd3fc4"
STAGE08I_CONTRACT_SHA = "56d31446c838e579b93156cde3c1430bde4bfae228061f4129cad580f7bbded0"
STAGE08I_04A_REFERENCE_SHA = "d703f482901b7f0c0cc49db278af8bbf202a90e729ccf24e46d20ebb34c16149"
STAGE08K_OPENFLOW_SHA = "b790613eb1e395c8fa00de7603e81c6c232dc6ae7a3f32cb09b2f471f9bb2365"
STAGE08K_08C_CONTRACT_SHA = "01c6524525d8b5afdf8e0e656ce7dbdf348830eb6edfdf8dd13e50b1c2c51b74"
STAGE08K_CONTRACT_SHA = "98fce6a93079293a370c78bd9425ac531bed3045103aa4aa9385351cbfb2c83c"
STAGE08K_ORIGINAL_04A_SHA = "89453431cd75bf8cc39eaf8e040510f8809ad734d7804474f487d665eb8b16de"
STAGE09C_RYU_SHA = "dec517bc3fd92042cb00047dc53cd8bff8cd602e8ac9e41c8c52e35d95064c17"
STAGE09C_STAGE07_SHA = "6168f38454ff9458ac0b92d6519c8722a8d1eab7042128a85dfc68a193fcf8a7"
STAGE09C_08J_SHA = "6ed34f04d99adbab2091b45a044b6281bc7455997a329f9780cf28b699a470a5"
STAGE09C_TEST_SHA = "50b1c32d9d105f94b87c88fc8f45590c4d90b0bfd87fa29e51acb52c57abf1fb"



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
        # Stage07 intentionally consolidates Ryu's event handler. Accept that
        # precise new source ONLY when its executable differential contract
        # and the pinned pre-Stage07 reference are both intact.
        stage07_contract = ROOT / "tests/test_stage07_event_contract.py"
        stage08f_contract = ROOT / "tests/test_stage08f_packetout_contract.py"
        stage08i_contract = ROOT / "tests/test_stage08i_timer_simplification.py"
        expected_ryu_sha = FROZEN_PRODUCTION["ryu_sdn.py"]
        expected_openflow_sha = FROZEN_PRODUCTION["controller_openflow.py"]
        expected_timer_sha = FROZEN_PRODUCTION["ospfv3/controller_timers.py"]
        if stage08i_contract.is_file():
            for name, expected in (
                ("tests/test_stage08i_timer_simplification.py", STAGE08I_CONTRACT_SHA),
                ("tests/_stage08i_timers_reference.py", expected_timer_sha),
                ("tests/_stage08i_stage04a_reference.py", STAGE08I_04A_REFERENCE_SHA),
            ):
                with self.subTest(file=name):
                    self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                                     expected)
            expected_timer_sha = STAGE08I_TIMERS_SHA
        if stage07_contract.is_file():
            with self.subTest(file="tests/test_stage07_event_contract.py"):
                current_09c = ROOT / "tests/test_stage09c_packetin.py"
                self.assertEqual(hashlib.sha256(stage07_contract.read_bytes()).hexdigest(),
                                 (STAGE09C_STAGE07_SHA if current_09c.is_file()
                                  else STAGE08F_STAGE07_TEST_SHA if stage08f_contract.is_file()
                                  else STAGE07_TEST_SHA))
            with self.subTest(file="tests/_stage07_ryu_sdn_reference.py"):
                reference = ROOT / "tests/_stage07_ryu_sdn_reference.py"
                self.assertEqual(hashlib.sha256(reference.read_bytes()).hexdigest(),
                                 STAGE07_REFERENCE_SHA)
            expected_ryu_sha = STAGE07_RYU_SHA
        if stage08f_contract.is_file():
            for name, expected in (
                ("tests/test_stage08f_packetout_contract.py", STAGE08F_CONTRACT_SHA),
                ("tests/_stage08f_ryu_sdn_reference.py", STAGE07_RYU_SHA),
                ("tests/_stage08f_stage07_contract_reference.py", STAGE07_TEST_SHA),
                ("tests/_stage08f_stage04a_reference.py", STAGE08F_ORIGINAL_04A_SHA),
            ):
                with self.subTest(file=name):
                    self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                                     expected)
            expected_ryu_sha = STAGE08F_RYU_SHA
        stage09c_contract = ROOT / "tests/test_stage09c_packetin.py"
        if stage09c_contract.is_file():
            for name, expected in (
                ("tests/test_stage09c_packetin.py", STAGE09C_TEST_SHA),
                ("tests/test_stage08j_parser_dedup.py", STAGE09C_08J_SHA),
                ("tests/_stage09c_ryu_reference.py", STAGE08F_RYU_SHA),
                ("tests/_stage09c_parser_reference.py",
                 "36d7846c52a0e102c534a2a60d951be9ed29f17cccd5260fa8460785d6a4e155"),
                ("tests/_stage09c_stage07_reference.py", STAGE08F_STAGE07_TEST_SHA),
                ("tests/_stage09c_stage08j_reference.py",
                 "e5c59240a16cea0ecf53b4bd34df709a3c9d44e7e8e30fe1875983d5fc2df40e"),
                ("tests/_stage09c_stage04a_reference.py",
                 "e81f1f6d20fdd8759c1f45ee6b4e31b81acac79312e1b7d774ed5bc93c59ac3c"),
            ):
                with self.subTest(file=name):
                    self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                                     expected)
            expected_ryu_sha = STAGE09C_RYU_SHA
        stage08b_contract = ROOT / "tests/test_stage08b_openflow_cleanup.py"
        stage08c_contract = ROOT / "tests/test_stage08c_openflow_refactor.py"
        stage08k_contract = ROOT / "tests/test_stage08k_openflow_consolidation.py"
        if stage08b_contract.is_file():
            with self.subTest(file="tests/test_stage08b_openflow_cleanup.py"):
                expected_08b_contract = (STAGE08C_UPDATED_08B_SHA
                                         if stage08c_contract.is_file()
                                         else STAGE08B_CONTRACT_SHA)
                self.assertEqual(hashlib.sha256(stage08b_contract.read_bytes()).hexdigest(),
                                 expected_08b_contract)
            old = ROOT / "tests/_stage08b_openflow_reference.py"
            with self.subTest(file="tests/_stage08b_openflow_reference.py"):
                self.assertEqual(hashlib.sha256(old.read_bytes()).hexdigest(),
                                 FROZEN_PRODUCTION["controller_openflow.py"])
            expected_openflow_sha = STAGE08B_OPENFLOW_SHA
        if stage08c_contract.is_file():
            with self.subTest(file="tests/test_stage08c_openflow_refactor.py"):
                self.assertEqual(hashlib.sha256(stage08c_contract.read_bytes()).hexdigest(),
                                 (STAGE08K_08C_CONTRACT_SHA if stage08k_contract.is_file()
                                  else STAGE08C_CONTRACT_SHA))
            with self.subTest(file="tests/_stage08c_openflow_reference.py"):
                frozen = ROOT / "tests/_stage08c_openflow_reference.py"
                self.assertEqual(hashlib.sha256(frozen.read_bytes()).hexdigest(),
                                 STAGE08B_OPENFLOW_SHA)
            with self.subTest(file="tests/_stage08c_stage08b_contract_reference.py"):
                frozen = ROOT / "tests/_stage08c_stage08b_contract_reference.py"
                self.assertEqual(hashlib.sha256(frozen.read_bytes()).hexdigest(),
                                 STAGE08B_CONTRACT_SHA)
            expected_openflow_sha = STAGE08C_OPENFLOW_SHA
        if stage08k_contract.is_file():
            for name, expected in (
                ("tests/test_stage08k_openflow_consolidation.py", STAGE08K_CONTRACT_SHA),
                ("tests/_stage08k_openflow_reference.py", STAGE08C_OPENFLOW_SHA),
                ("tests/_stage08k_stage08c_contract_reference.py", STAGE08C_CONTRACT_SHA),
                ("tests/_stage08k_stage04a_reference.py", STAGE08K_ORIGINAL_04A_SHA),
            ):
                with self.subTest(file=name):
                    self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                                     expected)
            expected_openflow_sha = STAGE08K_OPENFLOW_SHA
        for name, expected in FROZEN_PRODUCTION.items():
            if name == "ryu_sdn.py":
                expected = expected_ryu_sha
            if name == "controller_openflow.py":
                expected = expected_openflow_sha
            if name == "ospfv3/controller_timers.py":
                expected = expected_timer_sha
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
        stage08g_contract = ROOT / "tests/test_stage08g_protocol_dedup.py"
        if stage08g_contract.is_file():
            for name, expected in (
                ("tests/test_stage08g_protocol_dedup.py", STAGE08G_CONTRACT_SHA),
                ("tests/_stage08g_rx_reference.py", RX_04B_SHA),
                ("tests/_stage08g_stage04a_reference.py", STAGE08G_04A_REFERENCE_SHA),
            ):
                with self.subTest(file=name):
                    self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                                     expected)
            expected_rx = STAGE08G_RX_SHA
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
