"""08E: guard the shared LAN learning and self-originated LSA bookkeeping.

The Stage04C/Stage05 historical reference classes are executed under the
same deterministic protocol fakes.  No Ryu, Scapy, Mininet or root required.
"""

import ast
import copy
import hashlib
import itertools
from pathlib import Path
import unittest

from test_stage04c_io_contract import OldDP, NewDP, inbound, dp_snapshot
from test_stage05_lsa_contract import (
    OldLocal, NewLocal, Logger, CFG, outcome, local_snapshot, peer_database,
)


ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "tests/_stage08e_dataplane_reference.py":
        "3e93588521bc8309b1c0770a259ede6bd27484391600f9f7f50567ab8b760960",
    "tests/_stage08e_local_lsa_reference.py":
        "8e13ddfb965653dfd03b855aa875681eef7ba20c3c244c1659d7681c847d591c",
    "dataplane.py":
        "427f13c283d3d68217b51e37430689b8f69e7cb81c44208235264d05e0b36cf6",
    "ospfv3/local_lsa.py":
        "8def06aee21768857a80daeafb4e0217f987234cf5e3336ba6b921e95c885924",
    "tests/test_stage04c_io_contract.py":
        "1c7f8799f0298e4ac57d9894c80ff22cdfa0e5da8516852ca51355ddf03cbef1",
    "tests/test_stage05_lsa_contract.py":
        "d8673829de0514911c2a975b9fe29f5902fa54e1e4cdff99316ebd6d30080ff3",
}


def class_methods(path, name):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == name)
    return {node.name: ast.dump(node, include_attributes=False)
            for node in cls.body if isinstance(node, ast.FunctionDef)}


class Stage08EStateContract(unittest.TestCase):
    def test_exact_source_and_history_pins(self):
        for path, expected in PINS.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                                 expected)

    def test_no_changes_to_other_dataplane_and_local_lsa_methods(self):
        for name, old_path, new_path, exempt in (
            ("DataPlane", "tests/_stage08e_dataplane_reference.py",
             "dataplane.py", {"handle_ndp"}),
            ("LocalLSA", "tests/_stage08e_local_lsa_reference.py",
             "ospfv3/local_lsa.py", {"recover_sequences", "get_neighbor_interface_id"}),
        ):
            before = class_methods(old_path, name)
            after = class_methods(new_path, name)
            self.assertEqual(before.keys(), after.keys())
            for method in before.keys() - exempt:
                with self.subTest(method=method):
                    self.assertEqual(before[method], after[method])

    def test_ndp_gateway_reuses_exact_host_learning_policy(self):
        inputs = [
            inbound(source="2001:db8:1::100"),
            inbound(source="2001:db8:1::101", mac="aa:bb:cc:dd:ee:02"),
            inbound(source="2001:db8:2::100"),
            inbound(source="::"),
            inbound(source="malformed"),
        ]
        for port in (2, 3):
            for args in inputs:
                old, new = OldDP(), NewDP()
                left = outcome(old.handle_ndp, *args, port)
                right = outcome(new.handle_ndp, *args, port)
                self.assertEqual(left, right)
                self.assertEqual(dp_snapshot(old), dp_snapshot(new))

    def test_ndp_spoofing_transit_and_host_mac_relearning(self):
        old, new = OldDP(), NewDP()
        steps = [
            ("learn_transit_router", (1, "fe80::1", "aa:aa:aa:aa:aa:01")),
            ("handle_ndp", (*inbound(), 1)),
            ("handle_ndp", (*inbound(), 2)),
            ("handle_ndp", (*inbound(mac="aa:bb:cc:dd:ee:99"), 2)),
            ("handle_ndp", (*inbound(), 3)),
            ("handle_ndp", (*inbound(target=CFG.LINK_LOCAL, source="fe80::1",
                                     mac="aa:aa:aa:aa:aa:01"), 1)),
            ("reset", ()),
            ("handle_ndp", (*inbound(), 3)),
        ]
        for method, args in steps:
            with self.subTest(method=method):
                self.assertEqual(outcome(getattr(old, method), *args),
                                 outcome(getattr(new, method), *args))
                self.assertEqual(dp_snapshot(old), dp_snapshot(new))

    def test_lsa_sequence_recovery_all_types_and_wrong_ids(self):
        for prepare_next in (True, False):
            for permutation in itertools.permutations((0x2001, 0x0008, 0x2009)):
                headers = [{"ls_type": kind,
                            "link_state_id": "0.0.0.1" if kind == 0x0008 else "0.0.0.0",
                            "advertising_router": CFG.ROUTER_ID,
                            "ls_sequence": 0x80000010 + i}
                           for i, kind in enumerate(permutation)]
                headers += [dict(headers[0], advertising_router="1.1.1.1"),
                            dict(headers[1], link_state_id="1.2.3.4")]
                left_log, right_log = Logger(), Logger()
                left = OldLocal({}, left_log)
                right = NewLocal({}, right_log)
                self.assertEqual(outcome(left.recover_sequences, headers, prepare_next),
                                 outcome(right.recover_sequences, headers, prepare_next))
                self.assertEqual(local_snapshot(left, left_log),
                                 local_snapshot(right, right_log))

    def test_peer_interface_selection_and_reorigination_unchanged(self):
        database = peer_database()
        database["wrong_router"] = {
            "ls_type": 0x2001, "advertising_router": "2.2.2.2",
            "router_lsa": {"links": [{"type": 1,
                                     "neighbor_router_id": CFG.ROUTER_ID,
                                     "neighbor_interface_id": "0.0.0.1",
                                     "interface_id": "0.0.0.19"}]}}
        database["wrong_kind"] = {"ls_type": 0x2009,
                                  "advertising_router": "1.1.1.1",
                                  "router_lsa": {"links": []}}
        left_log, right_log = Logger(), Logger()
        old, new = (OldLocal(copy.deepcopy(database), left_log),
                    NewLocal(copy.deepcopy(database), right_log))
        for method, args in (("get_neighbor_interface_id", ("1.1.1.1",)),
                             ("initialize", ("1.1.1.1",)),
                             ("reoriginate", ("1.1.1.1", "refresh")),
                             ("build_update_body", ())):
            self.assertEqual(outcome(getattr(old, method), *args),
                             outcome(getattr(new, method), *args))
            self.assertEqual(local_snapshot(old, left_log),
                             local_snapshot(new, right_log))


if __name__ == "__main__":
    unittest.main()
