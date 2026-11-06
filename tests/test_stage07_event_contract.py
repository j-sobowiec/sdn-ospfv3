"""Stage07: compare Ryu events with immutable post-Stage06 controller.

Load the class AST in instrumented Ryu/Scapy stubs: no Ryu or root privileges
are needed here. The full integration still requires Containernet and restart.
"""

import ast
import ipaddress
from pathlib import Path
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Obj:
    def __init__(self, **attributes):
        self.__dict__.update(attributes)


def normalize(value):
    if isinstance(value, Datapath):
        return ("datapath", value.id)
    if isinstance(value, Exception):
        return (type(value).__name__, str(value))
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    if isinstance(value, Obj):
        return {key: normalize(item) for key, item in value.__dict__.items()}
    if isinstance(value, (list, tuple)):
        return tuple(normalize(item) for item in value)
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    return value


class Logger:
    def __init__(self):
        self.messages = []

    def info(self, *args):
        self.messages.append(("info", normalize(args)))

    def warning(self, *args):
        self.messages.append(("warning", normalize(args)))


class Wire(Obj):
    def __init__(self, kind, args, kwargs):
        super().__init__(kind=kind, args=args, kwargs=kwargs)


class Parser:
    def __getattr__(self, kind):
        return lambda *args, **kwargs: Wire(kind, args, kwargs)


class Datapath:
    def __init__(self):
        self.id = 0xabcdef01
        self.ofproto = Obj(OFPFC_DELETE=3, OFPP_ANY=0xffffffff,
                           OFPG_ANY=0xffffffff, OFPP_CONTROLLER=0xfffffffd,
                           OFPCML_NO_BUFFER=65535, OFP_NO_BUFFER=0xffffffff)
        self.ofproto_parser = Parser()
        self.sent = []
        self.next_xid = 100

    def send_msg(self, msg):
        self.sent.append(normalize(msg))

    def set_xid(self, msg):
        msg.xid = self.next_xid
        self.next_xid += 1


class DataPlane:
    def __init__(self):
        self.events = []
        self.ndp_response = None
        self.echo_response = None
        self.host_valid = False
        self.lan_network = ipaddress.IPv6Network("2001:db8:1::/64")
        self.transit_port = 1
        self.transit_router_mac = "aa:bb:cc:dd:ee:ff"

    def reset(self):
        self.events.append("reset")

    def handle_ndp(self, *args):
        self.events.append(("ndp", normalize(args[1:])))
        return self.ndp_response

    def handle_echo_request(self, *args):
        self.events.append(("echo", normalize(args[1:])))
        return self.echo_response

    def learn_lan_host(self, **kwargs):
        self.events.append(("learn", normalize(kwargs)))
        return self.host_valid


class Neighbor:
    def __init__(self, logger):
        self.logger = logger
        self.resets = 0

    def reset(self):
        self.resets += 1


class LSDB:
    def __init__(self, logger):
        self.logger = logger
        self.clears = []

    def clear_remote(self, router):
        self.clears.append(router)


class LocalLSA:
    def __init__(self, db, logger):
        self.db = db
        self.logger = logger

    def __bool__(self):
        return True


class RyuApp:
    def __init__(self, *args, **kwargs):
        self.logger = Logger()
        self.events = []


class Diagnostics:
    pass


class Receive:
    def handle_ospf_hello(self, *args):
        self.events.append(("hello", normalize(args)))

    def handle_ospf_dbd(self, *args):
        self.events.append(("dbd", normalize(args)))

    def handle_ospf_lsr(self, *args):
        self.events.append(("lsr", normalize(args)))

    def handle_ospf_lsu(self, *args):
        self.events.append(("lsu", normalize(args)))

    def handle_ospf_lsack(self, *args):
        self.events.append(("lsack", normalize(args)))


class Transmit:
    pass


class Timers:
    def hello_loop(self):
        pass

    def neighbor_dead_loop(self):
        pass

    def lsdb_aging_loop(self):
        pass

    def local_lsa_retransmission_loop(self):
        pass

    def local_lsa_refresh_loop(self):
        pass


class OpenFlow:
    _DATA_ICMPV6_TYPES = (1, 2, 3, 4, 128, 129)

    @staticmethod
    def _forwarding_actions(parser, destination_mac, out_port):
        # Stub of the unchanged production OpenFlowMixin helper.
        return [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=CFG.ROUTER_MAC),
            parser.OFPActionSetField(eth_dst=destination_mac),
            parser.OFPActionOutput(out_port),
        ]

    def _send_action_flow(self, dp, match, priority, actions):
        self.events.append(("flow", normalize((match, priority, actions))))

    def try_install_ipv6_host_flows(self):
        self.events.append(("try_flows",))
        return self.flows_installed

    def send_frame(self, frame, port):
        self.events.append(("send_frame", normalize((frame, port))))
        return self.send_success


class Packet:
    current = None

    def __init__(self, raw):
        self.protocols = list(self.current.protocols)
        self.mapping = self.current.mapping

    def get_protocol(self, kind):
        return self.mapping.get(kind)


class Ethernet:
    pass


class IPv6:
    pass


class ICMPv6:
    pass


class ScapyError(Exception):
    pass


class OspfHeader:
    registry = {}

    def __init__(self, raw):
        record = self.registry.get(raw)
        if record is None:
            raise ValueError("broken header")
        self.__dict__.update(record)


CFG = Obj(ROUTER_ID="10.10.10.10", ROUTER_MAC="02:00:00:00:00:01",
          AREA_ID="0.0.0.0", INSTANCE_ID=0)
ENV = {
    "app_manager": Obj(RyuApp=RyuApp),
    "ofp_event": Obj(EventOFPSwitchFeatures=object(),
                     EventOFPBarrierReply=object(), EventOFPPacketIn=object()),
    "CONFIG_DISPATCHER": object(), "MAIN_DISPATCHER": object(),
    "set_ev_cls": lambda *args: lambda f: f,
    "ofproto_v1_3": Obj(OFP_VERSION=4), "packet": Obj(Packet=Packet),
    "ipv6": Obj(ipv6=IPv6), "ethernet": Obj(ethernet=Ethernet),
    "icmpv6": Obj(icmpv6=ICMPv6, ND_NEIGHBOR_SOLICIT=135),
    "hub": Obj(spawn=lambda method: method.__name__),
    "ipaddress": ipaddress, "OSPFv3_Hdr": OspfHeader,
    "Scapy_Exception": ScapyError,
    "DataPlane": DataPlane, "OpenFlowMixin": OpenFlow,
    "cfg": CFG, "LSDB": LSDB, "LocalLSA": LocalLSA,
    "Neighbor": Neighbor, "OSPFDiagnosticsMixin": Diagnostics,
    "OSPFReceiveMixin": Receive, "OSPFTransmitMixin": Transmit,
    "OSPFTimerMixin": Timers,
    "calculate_ospfv3_checksum": lambda *args: 0x1234,
}


def load_class(path):
    tree = ast.parse(path.read_text(encoding="utf8"))
    node = next(node for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == "OSPFv3Controller")
    scope = dict(ENV)
    exec(compile(ast.fix_missing_locations(ast.Module(
        body=[node], type_ignores=[])), str(path), "exec"), scope)
    return scope["OSPFv3Controller"]


ORIGINAL = load_class(ROOT / "tests/_stage07_ryu_sdn_reference.py")
SIMPLIFIED = load_class(ROOT / "ryu_sdn.py")


def snapshot(controller):
    return {
        "events": normalize(controller.events),
        "logs": normalize(controller.logger.messages),
        "dataplane": normalize(controller.data_plane.events),
        "sent": normalize(controller.datapath.sent) if controller.datapath else [],
        "pending": normalize(controller.pending_ndp_barriers),
        "neighbor_reset": controller.neighbor.resets,
        "lsdb_clears": controller.lsdb.clears,
        "ospf_resync": controller.ospf_resync_required,
        "local_lsu_sent": controller.local_lsu_sent,
        "local_lsa_rebuild_required": controller.local_lsa_rebuild_required,
    }


def event(raw, dp):
    return Obj(msg=Obj(data=raw, match={"in_port": 2}, datapath=dp))


def packet_fixture(*, nxt=None, dst="2001:db8:23::3", src="2001:db8:1::100",
                   eth_dst=CFG.ROUTER_MAC, icmp_type=None, ospf_data=None,
                   hop_limit=1):
    eth = Obj(src="aa:aa:aa:aa:aa:aa", dst=eth_dst)
    ip = Obj(src=src, dst=dst, nxt=nxt, hop_limit=hop_limit) if nxt else None
    icmp = Obj(type_=icmp_type) if icmp_type is not None else None
    Packet.current = Obj(protocols=[eth, ip, ospf_data],
                         mapping={Ethernet: eth, IPv6: ip, ICMPv6: icmp})


def execute(controller_cls, prepare):
    controller = controller_cls()
    controller.flows_installed = False
    controller.send_success = True
    controller.datapath = Datapath()
    prepare(controller)
    return snapshot(controller)


class RyuEventsContract(unittest.TestCase):
    def compare(self, prepare):
        old = execute(ORIGINAL, prepare)
        new = execute(SIMPLIFIED, prepare)
        self.assertEqual(new, old)
        return new

    def test_constructor_initializes_all_control_state_and_threads(self):
        left, right = ORIGINAL(), SIMPLIFIED()
        for name in ("hello_thread", "neighbor_dead_thread", "lsdb_aging_thread",
                     "local_lsa_retransmission_thread", "local_lsa_refresh_thread",
                     "ospf_resync_required", "local_lsu_last_tx", "local_lsu_sent"):
            self.assertEqual(getattr(left, name), getattr(right, name), name)

    def test_switch_features_flush_and_table_miss(self):
        def scenario(c):
            dp = Datapath()
            c.switch_features_handler(event(b"switch", dp))
        result = self.compare(scenario)
        self.assertEqual(len(result["sent"]), 1)
        self.assertTrue(result["neighbor_reset"])

    def test_barrier_known_and_unknown(self):
        def scenario(c):
            c.pending_ndp_barriers[44] = {
                "frame": b"NA", "out_port": 2,
                "destination_ipv6": "fe80::1", "destination_mac": "aa"}
            c.barrier_reply_handler(Obj(msg=Obj(xid=99)))
            c.barrier_reply_handler(Obj(msg=Obj(xid=44)))
        result = self.compare(scenario)
        self.assertEqual(result["pending"], {})

    def test_barrier_send_failure_does_not_log_na(self):
        def scenario(c):
            c.send_success = False
            c.pending_ndp_barriers[4] = {
                "frame": b"NA", "out_port": 2,
                "destination_ipv6": "fe80::1", "destination_mac": "bb"}
            c.barrier_reply_handler(Obj(msg=Obj(xid=4)))
        self.compare(scenario)

    def test_packet_in_non_ipv6_is_ignored(self):
        def scenario(c):
            packet_fixture(nxt=None)
            c.packet_in_handler(event(b"noipv6", c.datapath))
        self.compare(scenario)

    def test_ndp_immediate_na_and_barrier(self):
        for installed in (False, True):
            def scenario(c):
                c.flows_installed = installed
                c.data_plane.ndp_response = b"NA"
                packet_fixture(nxt=58, src="fe80::1", icmp_type=135)
                c.packet_in_handler(event(b"ndp", c.datapath))
            with self.subTest(installed=installed):
                result = self.compare(scenario)
                self.assertEqual(bool(result["pending"]), installed)

    def test_echo_reply_and_rejected_ns(self):
        for echo in (b"ECHO", None):
            def scenario(c):
                c.data_plane.echo_response = echo
                packet_fixture(nxt=58, src="fe80::1", icmp_type=135)
                c.packet_in_handler(event(b"ns", c.datapath))
            with self.subTest(echo=echo):
                result = self.compare(scenario)
                self.assertFalse(any(item[0] == "try_flows" for item in result["events"]))

    def test_first_tcp_udp_and_icmp_fast_path(self):
        for proto, icmp_type in ((6, None), (17, None), (58, 128), (58, 129), (58, 1)):
            def scenario(c):
                c.data_plane.host_valid = True
                packet_fixture(nxt=proto, icmp_type=icmp_type)
                c.packet_in_handler(event(b"data", c.datapath))
            with self.subTest(proto=proto, icmp_type=icmp_type):
                result = self.compare(scenario)
                self.assertTrue(result["sent"])

    def test_local_lan_global_scope_and_unknown_traffic_are_not_forwarded(self):
        for proto, dst, host_valid, eth_dst, icmp_type in (
            (6, "2001:db8:1::2", True, CFG.ROUTER_MAC, None),
            (6, "ff02::1", True, CFG.ROUTER_MAC, None),
            (17, "2001:db8:23::3", False, CFG.ROUTER_MAC, None),
            (6, "2001:db8:23::3", True, "ee:ee:ee:ee:ee:ee", None),
            (58, "2001:db8:23::3", True, CFG.ROUTER_MAC, 135),
        ):
            def scenario(c):
                c.data_plane.host_valid = host_valid
                packet_fixture(nxt=proto, dst=dst, eth_dst=eth_dst,
                               icmp_type=icmp_type)
                c.packet_in_handler(event(b"guard", c.datapath))
            with self.subTest(proto=proto, dst=dst, icmp_type=icmp_type):
                result = self.compare(scenario)
                self.assertFalse(result["sent"])

    def test_no_data_forwarding_without_next_hop(self):
        for field in ("transit_port", "transit_router_mac"):
            def scenario(c):
                c.data_plane.host_valid = True
                setattr(c.data_plane, field, None)
                packet_fixture(nxt=6)
                c.packet_in_handler(event(b"waiting", c.datapath))
            with self.subTest(field=field):
                self.compare(scenario)

    @staticmethod
    def ospf(kind=1, *, version=3, size=None, area=CFG.AREA_ID,
             instance=0, checksum=0x1234):
        minimum = {1: 36, 2: 28, 3: 28, 4: 20, 5: 36}.get(kind, 20)
        size = minimum if size is None else size
        data = bytes([kind]) + b"\x00" * (max(size, 16) - 1)
        OspfHeader.registry[data[:16]] = {
            "version": version, "type": kind, "len": size,
            "src": "1.1.1.1", "area": area,
            "chksum": checksum, "instance": instance}
        return data

    def test_ospf_all_five_dispatch_argument_orders(self):
        for kind in range(1, 6):
            def scenario(c):
                data = self.ospf(kind)
                packet_fixture(nxt=89, src="fe80::1", dst="ff02::5",
                               ospf_data=data)
                c.packet_in_handler(event(b"ospf", c.datapath))
            with self.subTest(kind=kind):
                result = self.compare(scenario)
                self.assertEqual(len(result["events"]), 1)

    def test_ospf_invalid_area_instance_checksum_and_version(self):
        for options in ({"area": "0.0.0.1"}, {"instance": 2},
                        {"checksum": 0}, {"version": 2}, {"size": 18}):
            def scenario(c):
                data = self.ospf(4, **options)
                packet_fixture(nxt=89, src="fe80::1", dst="ff02::5",
                               ospf_data=data)
                c.packet_in_handler(event(b"invalid", c.datapath))
            with self.subTest(options=options):
                result = self.compare(scenario)
                self.assertFalse(result["events"])

    def test_ospf_non_linklocal_source_and_wrong_multicast_hop(self):
        for src, hop in (("2001:db8:1::100", 1), ("fe80::1", 2)):
            def scenario(c):
                data = self.ospf(1)
                packet_fixture(nxt=89, src=src, dst="ff02::5",
                               hop_limit=hop, ospf_data=data)
                c.packet_in_handler(event(b"scope", c.datapath))
            with self.subTest(src=src, hop=hop):
                result = self.compare(scenario)
                self.assertFalse(result["events"])

    def test_ospf_malformed_header_and_payload_boundary(self):
        for raw in (b"short", b"broken" * 4):
            def scenario(c):
                packet_fixture(nxt=89, src="fe80::1", dst="ff02::5",
                               ospf_data=raw)
                c.packet_in_handler(event(b"bad", c.datapath))
            with self.subTest(raw=raw):
                self.compare(scenario)

    def test_ospf_unknown_type_and_non_bytes_payload(self):
        for body in (self.ospf(6), Obj(not_bytes=True)):
            def scenario(c):
                packet_fixture(nxt=89, src="fe80::1", dst="ff02::5",
                               ospf_data=body)
                c.packet_in_handler(event(b"unknown", c.datapath))
            with self.subTest(body=type(body).__name__):
                self.compare(scenario)


if __name__ == "__main__":
    unittest.main()
