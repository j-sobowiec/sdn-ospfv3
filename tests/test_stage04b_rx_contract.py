"""Stage04B: protocol side-effect contracts, independent of Ryu/Scapy.

Only the RX mixin AST is loaded.  This isolates its state transitions from
external packet construction while live tests exercise the real wire path.
"""

import ast
from pathlib import Path
import socket
import struct
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_rx():
    source = ROOT / "ospfv3/controller_rx.py"
    tree = ast.parse(source.read_text(encoding="utf8"))
    mixins = [node for node in tree.body if isinstance(node, ast.ClassDef)
              and node.name == "OSPFReceiveMixin"]
    assert len(mixins) == 1
    cfg = types.SimpleNamespace(ROUTER_ID="10.10.10.10", HELLO_INTERVAL=10,
                                DEAD_INTERVAL=40, INTERFACE_MTU=1500)

    def parser(value, _length):
        if isinstance(value, Exception):
            raise value
        return value

    namespace = {"socket": socket, "struct": struct, "cfg": cfg,
                 "parse_hello": parser, "parse_dbd": parser,
                 "parse_lsr": parser, "parse_lsu": parser,
                 "parse_lsack": parser}
    exec(compile(ast.fix_missing_locations(ast.Module(body=mixins,
             type_ignores=[])), str(source), "exec"), namespace)
    return namespace["OSPFReceiveMixin"]


RX = load_rx()


class QuietLogger:
    def warning(self, *args):
        pass

    def info(self, *args):
        pass


class FakeNeighbor:
    def __init__(self, events):
        self.events = events
        self.router_id = "1.1.1.1"
        self.router_ids = ["1.1.1.1"]
        self.ipv6 = "fe80::1"
        self.mac = "aa:bb:cc:dd:ee:ff"
        self.port = 1
        self.dbd_negotiated = False
        self.dbd_exchange_complete = False
        self.dbd_sequence = 17
        self.request_list = []
        self.lsr_sent = False

    def mark_hello_received(self):
        self.events.append(("hello_valid",))

    def update_request_list(self, received):
        self.events.append(("requests_updated", len(received)))
        self.request_list = []


class FakeLSA(dict):
    def __init__(self, events, populated=True, recover_changed=False,
                 reoriginate_ok=True):
        super().__init__()
        self.events = events
        self.recover_changed = recover_changed
        self.reoriginate_ok = reoriginate_ok
        if populated:
            self[(0x2001, 0, "10.10.10.10")] = {
                "ls_sequence": 123, "ls_checksum": 456}

    def recover_sequences(self, headers, prepare_next):
        self.events.append(("recover", len(headers), prepare_next))
        return self.recover_changed, len(headers)

    def initialize(self, router_id):
        self.events.append(("initialize", router_id))
        self[(0x2001, 0, "10.10.10.10")] = {
            "ls_sequence": 123, "ls_checksum": 456}

    def reoriginate(self, router_id, reason):
        self.events.append(("reoriginate", router_id, reason))
        return self.reoriginate_ok


class Controller(RX):
    def __init__(self):
        self.events = []
        self.logger = QuietLogger()
        self.neighbor = FakeNeighbor(self.events)
        self.local_lsa = FakeLSA(self.events)
        self.lsdb = types.SimpleNamespace(update=lambda values:
            self.events.append(("lsdb_update", len(values))))
        self.data_plane = types.SimpleNamespace(learn_transit_router=lambda **kw:
            self.events.append(("learn_transit", kw)) or True)
        self.ospf_resync_required = False
        self.local_lsa_rebuild_required = False
        self.local_lsu_sent = False
        self.local_lsa_ack_pending = {}
        self.local_lsu_last_tx = 123456

    def log_hello(self, *args):
        self.events.append(("log_hello",))

    def log_dbd(self, *args):
        self.events.append(("log_dbd",))

    def log_lsu(self, *args):
        self.events.append(("log_lsu",))

    def try_install_ipv6_host_flows(self):
        self.events.append(("install_flows",))

    def send_ospfv3_hello(self, **kwargs):
        self.events.append(("send_hello", kwargs))

    def send_initial_dbd(self):
        self.events.append(("initial_dbd",))

    def reset_dbd_state(self, reason):
        self.events.append(("dbd_reset", reason))
        self.neighbor.dbd_negotiated = False
        self.neighbor.dbd_exchange_complete = False

    def send_exchange_dbd(self):
        self.events.append(("exchange_dbd",))

    def send_link_state_request(self):
        self.events.append(("send_lsr",))

    def send_local_lsr_response(self, lsas):
        self.events.append(("lsr_response", len(lsas)))

    def send_ls_ack(self, lsas):
        self.events.append(("ls_ack", len(lsas)))

    def send_local_ls_update(self):
        self.events.append(("local_lsu",))
        return True


def header(origin, sequence=123, checksum=456):
    return {"ls_type": 0x2001, "link_state_id": 0,
            "advertising_router": origin, "ls_sequence": sequence,
            "ls_checksum": checksum}


class RxContract(unittest.TestCase):
    def setUp(self):
        self.c = Controller()
        self.ip = types.SimpleNamespace(src="fe80::1")
        self.eth = types.SimpleNamespace(src="11:22:33:44:55:66")

    def hello(self, data, neighbor="1.1.1.1", port=1):
        self.c.handle_ospf_hello(port, self.eth, self.ip, data, 56,
                                 neighbor, "0.0.0.0")

    def packet(self, name, data, neighbor="1.1.1.1", port=1):
        args = (port, self.ip, data, 28, neighbor, "0.0.0.0")
        if name == "dbd":
            args = (port, self.ip, data, 28, 0x01010101,
                    neighbor, "0.0.0.0")
        getattr(self.c, "handle_ospf_" + name)(*args)

    def test_handlers_and_signatures(self):
        for method in ("hello", "dbd", "lsr", "lsu", "lsack"):
            self.assertTrue(callable(getattr(self.c, "handle_ospf_" + method)))
        self.assertTrue(callable(self.c.is_current_ospf_neighbor))

    def test_hello_rejects_wrong_timers_without_learning(self):
        for bad in (dict(hello_interval=11, dead_interval=40),
                    dict(hello_interval=10, dead_interval=39)):
            self.hello(bad)
        self.assertEqual(self.c.events, [])

    def test_hello_learns_transit_only_after_validation(self):
        self.hello(dict(interface_id=7, router_priority=1, options=0,
                        hello_interval=10, dead_interval=40, neighbors=[]),
                   neighbor="2.2.2.2", port=3)
        self.assertEqual([event[0] for event in self.c.events],
                         ["hello_valid", "log_hello", "learn_transit",
                          "install_flows", "send_hello"])
        self.assertEqual(self.c.neighbor.port, 3)
        self.assertEqual(self.c.neighbor.router_ids, ["1.1.1.1", "2.2.2.2"])

    def test_hello_forces_one_way_resync_after_restart(self):
        self.c.ospf_resync_required = True
        self.hello(dict(interface_id=7, router_priority=1, options=0,
                        hello_interval=10, dead_interval=40,
                        neighbors=["10.10.10.10"]), neighbor="2.2.2.2")
        self.assertFalse(self.c.ospf_resync_required)
        self.assertIn(("send_hello", {"neighbors": []}), self.c.events)
        self.assertNotIn("2.2.2.2", self.c.neighbor.router_ids)

    def test_unknown_neighbor_never_changes_state(self):
        for name in ("dbd", "lsr", "lsu", "lsack"):
            self.packet(name, [], port=9)
        self.assertEqual(self.c.events, [])

    def test_bad_parser_payload_is_discarded(self):
        for name in ("dbd", "lsr", "lsu", "lsack"):
            self.packet(name, ValueError("invalid wire"))
        self.hello(ValueError("invalid wire"))
        self.assertEqual(self.c.events, [])

    def dbd(self, **overrides):
        value = dict(interface_mtu=1500, options=0, i_bit=0, m_bit=0,
                     ms_bit=0, dd_sequence=17, lsa_headers=[])
        value.update(overrides)
        self.packet("dbd", value)

    def test_dbd_mtu_rejected(self):
        for mtu in (0, 1501):
            self.dbd(interface_mtu=mtu)
        self.assertEqual(self.c.events, [])

    def test_dbd_exstart_resets_then_sends_initial(self):
        self.c.neighbor.dbd_negotiated = True
        self.dbd(i_bit=1, m_bit=1, ms_bit=1)
        self.assertEqual(self.c.events[-2:],
                         [("dbd_reset", "neighbor restarted ExStart"),
                          ("initial_dbd",)])

    def test_dbd_exchange_recovers_self_lsa_and_requests_remote(self):
        self.c.local_lsa.recover_changed = True
        self.dbd(lsa_headers=[header("10.10.10.10"), header("1.1.1.1")])
        self.assertTrue(self.c.neighbor.dbd_negotiated)
        self.assertTrue(self.c.local_lsa_rebuild_required)
        self.assertEqual(self.c.neighbor.request_list, [header("1.1.1.1")])
        self.assertEqual(self.c.neighbor.dbd_sequence, 18)
        self.assertIn(("recover", 1, False), self.c.events)
        self.assertIn(("exchange_dbd",), self.c.events)

    def test_dbd_finish_requests_missing_lsa(self):
        self.c.neighbor.dbd_negotiated = True
        self.c.neighbor.request_list = [header("1.1.1.1")]
        self.dbd()
        self.assertTrue(self.c.neighbor.dbd_exchange_complete)
        self.assertIn(("send_lsr",), self.c.events)

    def test_lsr_returns_existing_lsas_once(self):
        self.packet("lsr", [header("10.10.10.10"),
                            header("10.10.10.10"), header("1.1.1.1")])
        self.assertEqual(self.c.events, [("lsr_response", 1)])

    def test_lsu_updates_remote_lsdb_and_acks(self):
        self.c.neighbor.dbd_exchange_complete = True
        self.packet("lsu", [header("1.1.1.1")])
        self.assertEqual(self.c.events,
                         [("log_lsu",), ("requests_updated", 1),
                          ("lsdb_update", 1), ("ls_ack", 1),
                          ("local_lsu",)])
        self.assertTrue(self.c.local_lsu_sent)

    def test_lsu_self_sequence_recovery_and_reoriginating(self):
        self.c.local_lsa.recover_changed = True
        self.c.neighbor.dbd_exchange_complete = True
        self.packet("lsu", [header("10.10.10.10"), header("1.1.1.1")])
        self.assertIn(("recover", 1, False), self.c.events)
        self.assertIn(("lsdb_update", 1), self.c.events)
        self.assertIn(("reoriginate", "1.1.1.1",
                       "neighbor session restarted"), self.c.events)
        self.assertLess(self.c.events.index(("ls_ack", 2)),
                        self.c.events.index(("reoriginate", "1.1.1.1",
                                             "neighbor session restarted")))

    def test_lsu_empty_does_not_ack_or_update(self):
        self.packet("lsu", [])
        self.assertEqual(self.c.events, [("log_lsu",)])

    def test_lsack_requires_matching_sequence_and_checksum(self):
        key = (0x2001, 0, "10.10.10.10")
        self.c.local_lsa_ack_pending[key] = header("10.10.10.10")
        self.packet("lsack", [header("10.10.10.10", checksum=999)])
        self.assertIn(key, self.c.local_lsa_ack_pending)
        self.assertEqual(self.c.local_lsu_last_tx, 123456)
        self.packet("lsack", [header("10.10.10.10")])
        self.assertNotIn(key, self.c.local_lsa_ack_pending)
        self.assertIsNone(self.c.local_lsu_last_tx)


if __name__ == "__main__":
    unittest.main()
