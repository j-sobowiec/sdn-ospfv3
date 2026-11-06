"""Stage08D: topology startup is exactly equivalent to the frozen Stage08C."""

import ast
import hashlib
from pathlib import Path
import random
import unittest

import test_a02_topology_equivalence as a02


ROOT = Path(__file__).resolve().parents[1]
NEW = ROOT / "topology.py"
OLD = ROOT / "tests/_stage08d_topology_reference.py"
A02 = ROOT / "tests/test_a02_topology_equivalence.py"
A02_REFERENCE = ROOT / "tests/_a02_topology_reference.py"
OLD_SHA = "4c8f267484793ecc54d2a15f7d2d142fe1a0ce0d41644a7a231b69763f61beca"
NEW_SHA = "5f11fe240392b43cc7112c5257be9b3e080e1ca041d3fea17ead9134a0e7acaf"
A02_SHA = "995fd08d86dd1e5a2227437c680d4a3b54de22cadce81693a75743bfc3f37b32"
A02_REFERENCE_SHA = "87bbf86cb1f09eb317b82adb2ea95585c4c86b79487613c74c9e762bdbb098a2"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_both(**conditions):
    before = a02._simulate(OLD.read_text(encoding="utf-8"), **conditions)
    after = a02._simulate(NEW.read_text(encoding="utf-8"), **conditions)
    return before, after


class Stage08DTopologyContract(unittest.TestCase):
    def test_pins_and_historical_tests_preserved(self):
        for path, expected in ((OLD, OLD_SHA), (NEW, NEW_SHA),
                               (A02, A02_SHA), (A02_REFERENCE, A02_REFERENCE_SHA)):
            with self.subTest(file=path.name):
                self.assertEqual(sha(path), expected)

    def test_no_changes_outside_two_allowed_functions(self):
        def unchanged(source):
            tree = ast.parse(source)
            for item in tree.body:
                if isinstance(item, ast.FunctionDef) and item.name in (
                        "make_frr_config", "main"):
                    item.body = [ast.Pass()]
            return ast.dump(tree, include_attributes=False)
        self.assertEqual(unchanged(OLD.read_text(encoding="utf-8")),
                         unchanged(NEW.read_text(encoding="utf-8")))

    def test_exact_startup_commands_links_frr_and_cleanup(self):
        before, after = run_both()
        self.assertEqual(before, after)
        events, outcome = after
        self.assertEqual(outcome, ("ok",))
        self.assertEqual([x[1:3] for x in events if x[0] == "link"],
                         [("r1", "r2"), ("r2", "r3"), ("r3", "r1"),
                          ("r1", "s1"), ("s1", "h1")])
        self.assertEqual(events[-1], ("stop",))

    def test_randomized_frr_config_exact_bytes(self):
        original = a02._load(OLD.read_text(encoding="utf-8"))
        updated = a02._load(NEW.read_text(encoding="utf-8"))
        rng = random.Random(808)
        interfaces = ("eth0", "r1-eth2", "t1", "!", "spacja w nazwie")
        for _ in range(1000):
            args = ("r1", "1.1.1.1",
                    rng.choices(interfaces, k=rng.randrange(6)),
                    rng.choices(interfaces, k=rng.randrange(4)))
            self.assertEqual(original["make_frr_config"](*args).encode(),
                             updated["make_frr_config"](*args).encode())

    def test_connection_timeout_and_failure_cleanup_unchanged(self):
        for conditions in ({"wait": False},
                           {"fail_on": "docker"},
                           {"fail_on": "start"},
                           {"fail_on": "CLI"},
                           {"fail_on": "ls /run/frr/*.vty"}):
            with self.subTest(conditions=conditions):
                before, after = run_both(**conditions)
                self.assertEqual(before, after)
                self.assertEqual(after[0][-1], ("stop",))

    def test_frr_missing_sockets_and_controller_target_unchanged(self):
        before, after = run_both(startup="FRR warning\n", sockets="zebra.vty")
        self.assertEqual(before, after)
        events = after[0]
        self.assertIn(("wait_connected", {"timeout": 15}), events)
        self.assertEqual([e[2]["port"] for e in events if e[0] == "controller"],
                         [6653])
        self.assertEqual(sum("WARNING: no VTY" in e[1]
                             for e in events if e[0] == "info"), 3)


if __name__ == "__main__":
    unittest.main()
