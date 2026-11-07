"""Stage 03: no private SPF in production, OSPFv3/LSDB still maintained."""

import ast
import copy
import logging
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
PIN = "e4ed0fa4f83cfc8ece8487f91023e3b8e5289e7d"
PRODUCTION = (
    "ryu_sdn.py", "controller_openflow.py",
    "ospfv3/controller_rx.py", "ospfv3/controller_timers.py",
    "ospfv3/controller_diagnostics.py", "ospfv3/lsdb.py",
)
REFERENCES = (
    "tests/_d05_routing_reference.py",
    "tests/_w02c_routing_reference.py",
    "tests/test_d03_lsdb_equivalence.py",
    "tests/test_d05_routing_equivalence.py",
    "tests/test_lsdb_spf_b5_1.py",
    "tests/test_w02b_lsdb_snapshot.py",
    "tests/test_w02c_spf_validation.py",
)


def legacy_lsdb():
    """Load the actual LSDB class in isolation; no Scapy/Ryu runtime needed."""
    path = ROOT / "ospfv3/lsdb.py"
    parsed = ast.parse(path.read_text(encoding="utf8"))
    cls = next(node for node in parsed.body
               if isinstance(node, ast.ClassDef) and node.name == "LSDB")
    monotonic = SimpleNamespace(value=100.0)
    context = {
        "copy": copy,
        "time": SimpleNamespace(monotonic=lambda: monotonic.value),
        "cfg": SimpleNamespace(MAX_AGE=3600),
        "compare_lsa_instances": lambda a, b: (
            (a["ls_sequence"] > b["ls_sequence"]) -
            (a["ls_sequence"] < b["ls_sequence"])
        ),
        "ospfv3_lsa_type_description": lambda lsa_type: str(lsa_type),
    }
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(path), "exec"),
         context)
    return context["LSDB"](logging.getLogger("stage03-lsdb")), monotonic


def lsa(lsa_type=0x2001, adv="2.2.2.2", seq=1):
    return {
        "ls_type": lsa_type, "link_state_id": 7,
        "advertising_router": adv, "ls_age": 0,
        "ls_sequence": seq,
    }


class Stage03Contract(unittest.TestCase):
    def test_no_private_spf_module_in_production(self):
        self.assertFalse((ROOT / "ospfv3/routing.py").exists())
        for name in PRODUCTION:
            with self.subTest(file=name):
                source = (ROOT / name).read_text(encoding="utf8")
                self.assertNotIn("from ospfv3.routing", source)
                self.assertNotIn("import ospfv3.routing", source)

    def test_reference_tests_remain_identical_to_pinned_git(self):
        for name in REFERENCES:
            with self.subTest(file=name):
                original = subprocess.check_output(
                    ["git", "-C", str(ROOT), "show", f"{PIN}:{name}"]
                )
                self.assertEqual((ROOT / name).read_bytes(), original)

    def test_frozen_spf_implementations_retain_class(self):
        for name in REFERENCES[:2]:
            with self.subTest(file=name):
                tree = ast.parse((ROOT / name).read_text(encoding="utf8"))
                classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
                self.assertIn("Routing", [c.name for c in classes])

    def test_lsdb_install_and_stale_update(self):
        db, _ = legacy_lsdb()
        self.assertTrue(db.update([lsa(seq=10)]))
        self.assertFalse(db.update([lsa(seq=9)]))
        key = (0x2001, 7, "2.2.2.2")
        self.assertEqual(db.get(key)["ls_sequence"], 10)
        self.assertTrue(db.update([lsa(seq=11)]))
        self.assertEqual(db.get(key)["ls_sequence"], 11)

    def test_lsdb_aging_and_clear_remote(self):
        db, clock = legacy_lsdb()
        self.assertTrue(db.update([lsa(adv="2.2.2.2")]))
        self.assertTrue(db.update([lsa(adv="10.10.10.10")]))
        self.assertTrue(db.clear_remote("10.10.10.10"))
        self.assertEqual(len(db), 1)
        self.assertEqual(next(iter(db.values()))["advertising_router"],
                         "10.10.10.10")
        clock.value += 3600
        self.assertTrue(db.purge_expired())
        self.assertEqual(len(db), 0)

    def test_lsdb_preserves_unrecognized_lsa(self):
        db, _ = legacy_lsdb()
        self.assertFalse(db.update([lsa(lsa_type=0x200b)]))
        self.assertEqual(len(db), 1)

    def test_ospfv3_rx_and_neighbor_recovery_still_present(self):
        rx = (ROOT / "ospfv3/controller_rx.py").read_text(encoding="utf8")
        timers = (ROOT / "ospfv3/controller_timers.py").read_text(encoding="utf8")
        controller = (ROOT / "ryu_sdn.py").read_text(encoding="utf8")
        for token in ("self.lsdb.update(", "self.send_ls_ack("):
            self.assertIn(token, rx)
        for token in ("self.lsdb.clear_remote(",
                      "self.withdraw_all_ipv6_host_flows(",
                      "self.data_plane.reset_transit("):
            self.assertIn(token, timers)
        for token in ("LSDB(self.logger)", "Neighbor(self.logger)",
                      "LocalLSA(self.lsdb, self.logger)"):
            self.assertIn(token, controller)


if __name__ == "__main__":
    unittest.main()
