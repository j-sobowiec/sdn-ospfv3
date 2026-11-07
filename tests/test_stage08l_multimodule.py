"""08L: exact old/new behavior tests for topology, local LSA and neighbor.

The frozen 08K source remains available as *_stage08l_*_reference.py.
No Ryu, Containernet or real Scapy is needed for these differential tests.
"""

import ast
import copy
import hashlib
import itertools
import random
import shlex
import time
import types
import unittest
from pathlib import Path

from test_stage05_lsa_contract import (
    LOCAL_ENV, Logger as LocalLogger, ast_namespace, local_snapshot,
    outcome, peer_database,
)
from test_stage06_protocol_contract import (
    Clock, Logger as NeighborLogger, lsa, load_symbols,
    state_environment,
)

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "topology.py": "tests/_stage08l_topology_reference.py",
    "ospfv3/local_lsa.py": "tests/_stage08l_local_lsa_reference.py",
    "ospfv3/neighbor.py": "tests/_stage08l_neighbor_reference.py",
}
ORIGINALS = {
    "topology.py": "5f11fe240392b43cc7112c5257be9b3e080e1ca041d3fea17ead9134a0e7acaf",
    "ospfv3/local_lsa.py": "8def06aee21768857a80daeafb4e0217f987234cf5e3336ba6b921e95c885924",
    "ospfv3/neighbor.py": "fcbf8a0c85b095243e195d55e18a1bbdc2ecc32a588468416255635e320476a8",
}
# New hashes are generated at packaging time; this test independently pins them.
UPDATED = {'ospfv3/local_lsa.py': 'f6ed23a9d072b7e97f6bcd00632a1bcab8198f4fb54a12e1099c8fd7bbd65e8a',
 'ospfv3/neighbor.py': '0c01fedcb8128836efdce3325f7310603af91d7dd84c091dd4ae9487ca7a8a9c',
 'topology.py': 'eeadbf5de8ad4a4521858ae49c476a1aa7f2760b9ac205d84817ab9ed9ff149e'}


def topology_functions(path, outputs, events):
    source = (ROOT / path).read_text(encoding="utf-8")
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.FunctionDef) and node.name in
             ("write_file", "make_frr_config", "configure_router", "start_frr")]
    env = dict(shlex=shlex, DAEMONS="daemons-stub", info=lambda s: events.append(("info", s)),
               time=types.SimpleNamespace(sleep=lambda v: events.append(("sleep", v))))
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 path, "exec"), env)

    class Router:
        name = "r1"

        def cmd(self, text):
            events.append(("cmd", text))
            if text.startswith("cat /tmp/frr-start"):
                return outputs.get("output", "")
            if text.startswith("ls /run/frr/*.vty"):
                return outputs.get("sockets", "")
            return ""

    return env, Router()


OLD_LOCAL = ast_namespace(ROOT / FILES["ospfv3/local_lsa.py"], ["LocalLSA"],
                          LOCAL_ENV)["LocalLSA"]
NEW_LOCAL = ast_namespace(ROOT / "ospfv3/local_lsa.py", ["LocalLSA"],
                          LOCAL_ENV)["LocalLSA"]
OLD_NEIGHBOR = load_symbols(ROOT / FILES["ospfv3/neighbor.py"],
                            state_environment)["Neighbor"]
NEW_NEIGHBOR = load_symbols(ROOT / "ospfv3/neighbor.py",
                            state_environment)["Neighbor"]


class Stage08LMultiModule(unittest.TestCase):
    def test_pins_and_total_reduction(self):
        for changed, historical in FILES.items():
            self.assertEqual(hashlib.sha256((ROOT / historical).read_bytes()).hexdigest(),
                             ORIGINALS[changed], historical)
            self.assertEqual(hashlib.sha256((ROOT / changed).read_bytes()).hexdigest(),
                             UPDATED[changed], changed)
        saved = sum(len((ROOT / old).read_text().splitlines()) -
                    len((ROOT / new).read_text().splitlines())
                    for new, old in FILES.items())
        self.assertEqual(saved, 29)

    def test_topology_router_config_bytes_and_command_order(self):
        rng = random.Random(8091)
        names = ["r1-eth0", "r1-eth2", "x", "spacja", "!"]
        for _ in range(80):
            address_count = rng.randrange(1, 5)
            addresses = {f"eth{j}": f"2001:db8:{j}::1/64"
                         for j in range(address_count)}
            active = rng.choices(names, k=rng.randrange(5))
            passive = rng.choices(names, k=rng.randrange(5))
            results = []
            for src in (FILES["topology.py"], "topology.py"):
                events = []
                env, router = topology_functions(src, {}, events)
                config = env["make_frr_config"]("r1", "1.1.1.1", active, passive)
                env["configure_router"](router, addresses, "1.1.1.1", active, passive)
                results.append((config, events))
            self.assertEqual(*results)

    def test_topology_frr_start_and_missing_socket_logs(self):
        for output, sockets in itertools.product(("", "FRR started\n"),
                                                  ("", "zebra.vty", "zebra.vty ospf6d.vty")):
            results = []
            for src in (FILES["topology.py"], "topology.py"):
                events = []
                env, router = topology_functions(
                    src, {"output": output, "sockets": sockets}, events)
                env["start_frr"](router)
                results.append(events)
            self.assertEqual(*results)

    def test_topology_complete_startup_simulation(self):
        try:
            import test_a02_topology_equivalence as a02
        except ImportError:
            self.skipTest("Topological Mininet simulation is in the full project")
        before = (ROOT / FILES["topology.py"]).read_text(encoding="utf-8")
        after = (ROOT / "topology.py").read_text(encoding="utf-8")
        for options in ({}, {"wait": False}, {"fail_on": "docker"},
                        {"fail_on": "start"}, {"fail_on": "CLI"},
                        {"startup": "warning\n", "sockets": "zebra.vty"}):
            with self.subTest(options=options):
                self.assertEqual(a02._simulate(before, **options),
                                 a02._simulate(after, **options))

    def test_local_lsa_origination_retransmission_and_recovery(self):
        peer = peer_database()
        original_log, current_log = LocalLogger(), LocalLogger()
        left = OLD_LOCAL(copy.deepcopy(peer), original_log)
        right = NEW_LOCAL(copy.deepcopy(peer), current_log)
        cases = [
            ("get_neighbor_interface_id", ("1.1.1.1",)),
            ("build_router", ("1.1.1.1",)),
            ("build_link", ()), ("build_prefix", ()),
            ("initialize", ("1.1.1.1",)),
            ("build_update_body", ()),
            ("reoriginate", ("1.1.1.1", "refresh")),
            ("build_update_body", ()),
        ]
        for name, args in cases:
            with self.subTest(action=name):
                self.assertEqual(outcome(getattr(left, name), *args),
                                 outcome(getattr(right, name), *args))
                self.assertEqual(local_snapshot(left, original_log),
                                 local_snapshot(right, current_log))
        headers = [
            {"advertising_router": "10.10.10.10", "ls_type": 0x2001,
             "link_state_id": "0.0.0.0", "ls_sequence": 0x80000005},
        ]
        for name, args in (("recover_sequences", (headers, True)),
                           ("recover_sequences", (headers, False))):
            self.assertEqual(outcome(getattr(left, name), *args),
                             outcome(getattr(right, name), *args))
            self.assertEqual(local_snapshot(left, original_log),
                             local_snapshot(right, current_log))
        keys = list(left.entries)
        valid = {key: {"ls_sequence": value["ls_sequence"],
                       "ls_checksum": value["ls_checksum"]}
                 for key, value in left.entries.items()}
        for pending in ({}, valid, {k: valid[k] for k in reversed(keys)},
                        {k: dict(valid[k], ls_checksum=0) for k in keys}):
            self.assertEqual(outcome(left.build_pending_body, pending),
                             outcome(right.build_pending_body, pending))

    def test_local_lsa_rejected_inputs_and_invalid_pending(self):
        for db in ({}, peer_database()):
            for action, args in (("initialize", (None,)),
                                 ("initialize", ("1.1.1.1",)),
                                 ("reoriginate", (None, "test")),
                                 ("install", (b"short",)),
                                 ("build_pending_body", ({(1, 2, 3): {}},))):
                log1, log2 = LocalLogger(), LocalLogger()
                left, right = OLD_LOCAL(copy.deepcopy(db), log1), NEW_LOCAL(copy.deepcopy(db), log2)
                self.assertEqual(outcome(getattr(left, action), *args),
                                 outcome(getattr(right, action), *args))
                self.assertEqual(local_snapshot(left, log1), local_snapshot(right, log2))

    def test_neighbor_request_matching_and_reset(self):
        rng = random.Random(8092)
        for _ in range(120):
            Clock.now, Clock.epoch = 41.0, 1710000.0
            old_log, new_log = NeighborLogger(), NeighborLogger()
            left, right = OLD_NEIGHBOR(old_log), NEW_NEIGHBOR(new_log)
            requests = [lsa(lsa_type=rng.choice((0x2001, 0x0008, 0x2009)),
                            seq=rng.randrange(1, 5)) for _ in range(rng.randrange(0, 5))]
            received = [lsa(lsa_type=rng.choice((0x2001, 0x0008, 0x2009)),
                            seq=rng.randrange(1, 5)) for _ in range(rng.randrange(0, 5))]
            left.request_list = copy.deepcopy(requests)
            right.request_list = copy.deepcopy(requests)
            for action, args in (("update_request_list", (received,)),
                                 ("mark_hello_received", ()),
                                 ("dead_interval_expired", (40,)),
                                 ("reset_exchange", ())):
                self.assertEqual(outcome(getattr(left, action), *args),
                                 outcome(getattr(right, action), *args))
                self.assertEqual({k: v for k, v in vars(left).items() if k != "logger"},
                                 {k: v for k, v in vars(right).items() if k != "logger"})
                self.assertEqual(old_log.events, new_log.events)


if __name__ == "__main__":
    unittest.main()
