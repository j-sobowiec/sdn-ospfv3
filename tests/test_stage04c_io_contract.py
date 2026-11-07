"""Stage04C: compare complete TX/data-plane side effects to frozen references.

The mixin/class AST is loaded with deterministic Ryu and packet-builder fakes.
Live Containernet tests separately prove actual Ethernet/IPv6 wire behaviour.
"""

import ast
import ipaddress
from pathlib import Path
import struct
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
CFG = types.SimpleNamespace(
    LAN_PREFIX="2001:db8:1::", LAN_PREFIX_LEN=64,
    LAN_GATEWAY="2001:db8:1::1", LINK_LOCAL="fe80::10",
    ROUTER_MAC="02:00:00:00:00:01")


class Protocol:
    def __init__(self, **attributes):
        self.__dict__.update(attributes)

    def __repr__(self):
        return repr(sorted(self.__dict__.items()))


class ICMP(Protocol):
    pass


class Neighbor(Protocol):
    pass


class Echo(Protocol):
    pass


class FakePacket:
    def __init__(self):
        self.protocols = []
        self.data = None

    def add_protocol(self, protocol):
        self.protocols.append(protocol)

    def serialize(self):
        self.data = repr(self.protocols).encode("ascii")


ethernet = types.SimpleNamespace(ethernet=Protocol)
ipv6 = types.SimpleNamespace(ipv6=Protocol)
icmpv6 = types.SimpleNamespace(
    icmpv6=ICMP, nd_neighbor=Neighbor, echo=Echo,
    nd_option_tla=Protocol,
    ND_NEIGHBOR_SOLICIT=135, ND_NEIGHBOR_ADVERT=136)
packet = types.SimpleNamespace(Packet=FakePacket)
ether_types = types.SimpleNamespace(ETH_TYPE_IPV6=0x86DD)


def read_class(path, name, namespace):
    tree = ast.parse(path.read_text(encoding="utf8"))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == name]
    assert len(classes) == 1, (path, name)
    scope = dict(namespace)
    exec(compile(ast.fix_missing_locations(ast.Module(
        body=classes, type_ignores=[])), str(path), "exec"), scope)
    return scope[name]


DATAPLANE_ENV = dict(ipaddress=ipaddress, cfg=CFG, ethernet=ethernet,
                     ipv6=ipv6, icmpv6=icmpv6, packet=packet,
                     ether_types=ether_types)
OldDP = read_class(ROOT / "tests/_stage04c_dataplane_reference.py",
                   "DataPlane", DATAPLANE_ENV)
NewDP = read_class(ROOT / "dataplane.py", "DataPlane", DATAPLANE_ENV)


def inbound(icmp_type=135, code=0, target=CFG.LAN_GATEWAY,
            source="2001:db8:1::100", mac="aa:bb:cc:dd:ee:01",
            dest=CFG.LAN_GATEWAY, hop=255):
    data = (Neighbor(dst=target) if icmp_type == 135 else
            Echo(id=1, seq=42, data=b"payload"))
    message = ICMP(type_=icmp_type, code=code, data=data)
    received = types.SimpleNamespace(get_protocol=lambda _typ: message)
    eth = types.SimpleNamespace(src=mac)
    ip = types.SimpleNamespace(src=source, dst=dest, hop_limit=hop)
    return received, eth, ip


def dp_snapshot(dp):
    return (dp.lan_port, dict(dp.lan_hosts), dp.transit_port,
            dp.transit_router_mac,
            dp.transit_router_ipv6, dp.lan_network)


class DataplaneContract(unittest.TestCase):
    def replay(self, actions):
        old, new = OldDP(), NewDP()
        self.assertEqual(dp_snapshot(old), dp_snapshot(new))
        for method, args, kwargs in actions:
            before = getattr(old, method)(*args, **kwargs)
            after = getattr(new, method)(*args, **kwargs)
            self.assertEqual(before, after, method)
            self.assertEqual(dp_snapshot(old), dp_snapshot(new), method)
        return new

    def test_lan_learning_and_reset(self):
        self.replay([
            ("learn_lan_host", (2, "broken-ip", "a"), {}),
            ("learn_lan_host", (2, "2001:db8:7::1", "a"), {}),
            ("learn_lan_host", (2, "2001:db8:1::100", "a"), {}),
            ("learn_lan_host", (3, "2001:db8:1::101", "b"), {}),
            ("learn_lan_host", (2, "2001:db8:1::101", "b"), {}),
            ("reset", (), {}),
            ("learn_lan_host", (3, "2001:db8:1::101", "c"), {})])

    def test_transit_learning_and_clearing(self):
        dp = self.replay([
            ("learn_transit_router", (1, "fe80::1", "a"), {}),
            ("learn_transit_router", (1, "fe80::1", "a"), {}),
            ("learn_transit_router", (1, "fe80::1", "b"), {}),
            ("learn_lan_host", (1, "2001:db8:1::100", "z"), {}),
            ("reset_transit", (), {})])
        self.assertIsNone(dp.transit_router_mac)
        self.assertIsNone(dp.transit_router_ipv6)

    def test_gateway_ndp_rejects_untrusted_packets(self):
        actions = []
        variants = [
            dict(icmp_type=128), dict(code=1), dict(hop=64),
            dict(source="::"), dict(source="2001:db8:2::100"),
            dict(target="2001:db8:1::99")]
        for params in variants:
            args = inbound(**params)
            actions.append(("handle_ndp", (*args, 2), {}))
        dp = self.replay(actions)
        self.assertEqual(dp.lan_hosts, {})

    def test_gateway_ns_responds_and_only_on_learned_port(self):
        args = inbound()
        dp = self.replay([
            ("handle_ndp", (*args, 2), {}),
            ("handle_ndp", (*args, 3), {}),
            ("handle_ndp", (*args, 2), {})])
        self.assertEqual(dp.lan_port, 2)
        self.assertEqual(dp.lan_hosts, {"2001:db8:1::100": "aa:bb:cc:dd:ee:01"})

    def test_link_local_ndp_requires_verified_hello_peer(self):
        valid = inbound(target=CFG.LINK_LOCAL, source="fe80::1", mac="a")
        spoof = inbound(target=CFG.LINK_LOCAL, source="fe80::1", mac="b")
        self.replay([
            ("handle_ndp", (*valid, 1), {}),
            ("learn_transit_router", (1, "fe80::1", "a"), {}),
            ("handle_ndp", (*spoof, 1), {}),
            ("handle_ndp", (*valid, 2), {}),
            ("handle_ndp", (*valid, 1), {})])

    def test_echo_request_local_only_and_payload_preserved(self):
        valid = inbound(icmp_type=128)
        wrong = inbound(icmp_type=128, dest="2001:db8:23::3")
        self.replay([
            ("handle_echo_request", (*wrong, 2), {}),
            ("handle_echo_request", (*valid, 2), {}),
            ("handle_echo_request", (*valid, 3), {})])

    def test_explicit_frames_preserve_wire_inputs(self):
        self.replay([
            ("build_neighbor_advertisement", ("a", "fe80::1", CFG.LINK_LOCAL), {}),
            ("build_echo_reply", ("a", "2001:db8:1::100",
                                  Echo(id=25, seq=41, data=b"echo-data")), {})])


def builder(name):
    def construct(*args, **kwargs):
        return repr((name, args, sorted(kwargs.items()))).encode("ascii")
    return construct


class Logger:
    def __init__(self, events):
        self.events = events

    def info(self, *args):
        self.events.append(("log_info", args))

    def warning(self, *args):
        self.events.append(("log_warning", args))


class FakeNeighbor:
    def __init__(self, events):
        self.events = events
        self.port = 1
        self.ipv6 = "fe80::1"
        self.mac = "aa:bb:cc:dd:ee:01"
        self.router_id = "1.1.1.1"
        self.router_ids = ["1.1.1.1"]
        self.dbd_sequence = 12
        self.request_list = []
        self.lsr_sent = False

    def reset_exchange(self):
        self.events.append(("neighbor_reset",))
        self.dbd_sequence = 13


class FakeLocalLSA(dict):
    def __init__(self, events):
        super().__init__()
        self.events = events
        self.body = b"some local LSAs"
        self.pending_body = (b"pending LSAs", 2)
        self.reoriginate_ok = True
        self[(0x2001, 0, "10.10.10.10")] = {
            "ls_type": 0x2001, "link_state_id": 0,
            "advertising_router": "10.10.10.10",
            "ls_sequence": 7, "ls_checksum": 9, "raw_lsa": b"lsa-byte-string"}

    def build_update_body(self):
        self.events.append(("build_update_body",))
        return self.body

    def build_pending_body(self, pending):
        self.events.append(("build_pending_body", tuple(pending)))
        return self.pending_body

    def reoriginate(self, peer, reason):
        self.events.append(("reoriginate", peer, reason))
        return self.reoriginate_ok


TX_ENV = dict(struct=struct, time=types.SimpleNamespace(monotonic=lambda: 42.5),
              ospfv3_lsa_type_description=lambda kind: f"LSA-{kind}")
for name in ("hello", "dbd", "lsr", "lsu", "lsack"):
    TX_ENV[f"build_ospfv3_{name}_frame"] = builder(name)
OldTX = read_class(ROOT / "tests/_stage04c_tx_reference.py",
                   "OSPFTransmitMixin", TX_ENV)
NewTX = read_class(ROOT / "ospfv3/controller_tx.py",
                   "OSPFTransmitMixin", TX_ENV)


class TxHarness:
    def __init__(self):
        self.events = []
        self.neighbor = FakeNeighbor(self.events)
        self.local_lsa = FakeLocalLSA(self.events)
        self.logger = Logger(self.events)
        self.local_lsa_ack_pending = {}
        self.local_lsu_last_tx = None
        self.local_lsu_sent = True
        self.send_ok = True

    def send_frame(self, frame, port):
        self.events.append(("send_frame", frame, port))
        return self.send_ok


class OldController(OldTX, TxHarness):
    pass


class NewController(NewTX, TxHarness):
    pass


def tx_snapshot(controller):
    peer = controller.neighbor
    return (controller.events, peer.port, peer.ipv6, peer.mac,
            peer.dbd_sequence, peer.lsr_sent, peer.request_list,
            controller.local_lsa_ack_pending, controller.local_lsu_last_tx,
            controller.local_lsu_sent)


class TxContract(unittest.TestCase):
    def replay(self, actions, setup=None):
        original, current = OldController(), NewController()
        if setup:
            setup(original)
            setup(current)
        for name, args in actions:
            left = getattr(original, name)(*args)
            right = getattr(current, name)(*args)
            self.assertEqual(left, right, name)
            self.assertEqual(tx_snapshot(original), tx_snapshot(current), name)
        return current

    def test_hello_and_both_dbd_messages(self):
        self.replay([("send_ospfv3_hello", ()),
                     ("send_ospfv3_hello", ([],)),
                     ("send_initial_dbd", ()),
                     ("send_exchange_dbd", ()),
                     ("reset_dbd_state", ("peer restarted",))])

    def test_no_send_when_neighbor_not_ready(self):
        def setup(c):
            c.neighbor.port = None
        self.replay([("send_ospfv3_hello", ()),
                     ("send_initial_dbd", ()),
                     ("send_exchange_dbd", ()),
                     ("send_link_state_request", ()),
                     ("send_ls_ack", ([{"x": 1}],)),
                     ("send_local_ls_update", ()),
                     ("send_local_lsr_response", ([{"raw_lsa": b"x"}],)),
                     ("send_local_lsa_retransmission", ())], setup)

    def test_request_and_ack_payloads(self):
        lsa = dict(ls_type=0x2001, advertising_router="1.1.1.1",
                   link_state_id=1)
        self.replay([("send_link_state_request", ()),
                     ("send_ls_ack", ([],)),
                     ("send_ls_ack", ([lsa],))],
                    lambda c: setattr(c.neighbor, "request_list", [lsa]))

    def test_failed_send_does_not_advance_neighbor(self):
        lsa = dict(ls_type=0x2001, advertising_router="1.1.1.1",
                   link_state_id=1)
        def setup(c):
            c.send_ok = False
            c.neighbor.request_list = [lsa]
        self.replay([("send_link_state_request", ()),
                     ("send_ls_ack", ([lsa],)),
                     ("send_local_ls_update", ())], setup)

    def test_local_update_pending_ack_and_timer(self):
        state = self.replay([("send_local_ls_update", ())])
        self.assertEqual(state.local_lsu_last_tx, 42.5)
        self.assertEqual(len(state.local_lsa_ack_pending), 1)

    def test_none_local_update_body_does_not_send(self):
        self.replay([("send_local_ls_update", ())],
                    lambda c: setattr(c.local_lsa, "body", None))

    def test_lsr_response_and_retransmission(self):
        lsa = FakeLocalLSA([])[(0x2001, 0, "10.10.10.10")]
        state = self.replay([("send_local_lsr_response", ([lsa],)),
                             ("send_local_lsa_retransmission", ())])
        self.assertEqual(state.local_lsu_last_tx, 42.5)

    def test_empty_lsr_response_and_missing_retransmission(self):
        def setup(c):
            c.local_lsa.pending_body = None
        self.replay([("send_local_lsr_response", ([],)),
                     ("send_local_lsa_retransmission", ())], setup)

    def test_reorigination_waits_for_ack(self):
        def setup(c):
            c.local_lsa_ack_pending[(1, 2, 3)] = {"ls_sequence": 1}
        self.replay([("reoriginate_local_lsas", ("change",))], setup)

    def test_reorigination_and_failed_builder(self):
        state = self.replay([("reoriginate_local_lsas", ("recovery",))])
        self.assertEqual(state.local_lsu_last_tx, 42.5)
        self.replay([("reoriginate_local_lsas", ("recovery",))],
                    lambda c: setattr(c.local_lsa, "reoriginate_ok", False))


if __name__ == "__main__":
    unittest.main()
