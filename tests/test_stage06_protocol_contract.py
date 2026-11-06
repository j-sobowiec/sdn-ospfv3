"""Stage06: pinned, executable old/new OSPFv3 wire and state contracts.

AST injection keeps this regression test runnable without a system Ryu or
Scapy installation. Existing Scapy/wire tests remain active separately.
"""

import ast
import copy
import ipaddress
import json
from pathlib import Path
import socket
import struct
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_symbols(path, scope, constants=()):
    tree = ast.parse(path.read_text(encoding="utf8"))
    nodes = [node for node in tree.body
             if isinstance(node, (ast.ClassDef, ast.FunctionDef))
             or (isinstance(node, ast.Assign) and any(
                 isinstance(target, ast.Name) and target.id in constants
                 for target in node.targets))]
    namespace = dict(scope)
    exec(compile(ast.fix_missing_locations(ast.Module(
        body=nodes, type_ignores=[])), str(path), "exec"), namespace)
    return namespace


def pair(module, environment, constants=()):
    old = load_symbols(ROOT / "tests" / f"_stage06_{module}_reference.py",
                       environment, constants)
    new = load_symbols(ROOT / "ospfv3" / f"{module}.py", environment, constants)
    return old, new


def outcome(func, *args):
    try:
        return "return", func(*args)
    except Exception as error:
        return "raise", type(error).__name__, str(error)


class Record:
    def __init__(self, **attributes):
        self.__dict__.update(attributes)


class FakeLsaHeader:
    def __init__(self, data):
        (self.age, self.type, lsid, router, self.seq,
         self.chksum, self.len) = struct.unpack("!HH4s4sIHH", bytes(data)[:20])
        self.id = socket.inet_ntoa(lsid)
        self.adrouter = socket.inet_ntoa(router)


class FakeWire:
    def __init__(self, name, *args, **kwargs):
        self.parts = [(name, args, kwargs)]

    def __truediv__(self, other):
        result = FakeWire("unused")
        result.parts = self.parts + other.parts
        return result

    def __bytes__(self):
        def normalize(value):
            if isinstance(value, FakeWire):
                return [normalize(part) for part in value.parts]
            if isinstance(value, bytes):
                return {"hex": value.hex()}
            if isinstance(value, (tuple, list)):
                return [normalize(item) for item in value]
            if isinstance(value, dict):
                return {key: normalize(item) for key, item in value.items()}
            return value
        return b"\x00" * 40 + json.dumps(
            normalize(self.parts), sort_keys=True, separators=(",", ":")
        ).encode("ascii")


def wire_class(name):
    return type(name, (FakeWire,), {
        "__init__": lambda self, *args, **kwargs: FakeWire.__init__(
            self, name, *args, **kwargs)})


cfg = Record(LINK_LOCAL="fe80::10", ROUTER_ID="10.10.10.10",
             AREA_ID="0.0.0.0", INSTANCE_ID=0, ROUTER_MAC="02:00:00:00:00:01",
             INTERFACE_ID=7, ROUTER_PRIORITY=1, OPTIONS=0x13,
             HELLO_INTERVAL=10, DEAD_INTERVAL=40, INTERFACE_MTU=1500,
             MAX_AGE=3600)

packet_environment = {
    "cfg": cfg, "OSPF_PROTOCOL": 89, "ALL_SPF_ROUTERS": "ff02::5",
    "ALL_SPF_ROUTERS_MAC": "33:33:00:00:00:05",
    "in6_chksum": lambda proto, ipv6, data: len(data) + proto,
}
for name in ("IPv6", "Ether", "Raw", "OSPFv3_Hdr", "OSPFv3_Hello",
             "OSPFv3_DBDesc", "OSPFv3_LSReq", "OSPFv3_LSReq_Item",
             "OSPFv3_LSUpd", "OSPFv3_LSA_Hdr", "OSPFv3_LSAck"):
    packet_environment[name] = wire_class(name)

OLD_PACKET, NEW_PACKET = pair("packet", packet_environment)
for namespace in (OLD_PACKET, NEW_PACKET):
    namespace.update({name: value for name, value in packet_environment.items()
                      if name in ("OSPF_PROTOCOL", "ALL_SPF_ROUTERS", "ALL_SPF_ROUTERS_MAC")})


class PacketContract(unittest.TestCase):
    def compare(self, name, *args):
        # Bytes-like inputs may contain memoryview (not deepcopy-able).
        actual = outcome(NEW_PACKET[name], *args)
        expected = outcome(OLD_PACKET[name], *args)
        self.assertEqual(actual, expected, (name, args))

    def test_checksum_and_opaque_packet_wrapping(self):
        self.compare("calculate_ospfv3_checksum", "fe80::1", "ff02::5", b"\x00" * 20)
        for kind in range(1, 6):
            self.compare("build_ospfv3_packet", kind, b"\x00\xff", "fe80::1")

    def test_hello_dbd_and_multicast_frames(self):
        for neighbors in ((), ("1.1.1.1",), ("1.1.1.1", "2.2.2.2")):
            self.compare("build_ospfv3_hello", neighbors)
            self.compare("build_ospfv3_hello_frame", neighbors)
        for sequence in (0, 1, 0xffffffff):
            for flags in (0, 1, 7):
                self.compare("build_ospfv3_dbd", sequence, flags)
                self.compare("build_ospfv3_dbd_frame", sequence, flags)

    def test_request_ack_and_frames(self):
        requests = [{"ls_type": 0x2001, "link_state_id": "0.0.0.1",
                     "advertising_router": "1.1.1.1"}]
        headers = [{"raw_header": b"\x00" * 20}]
        for items in ([], requests, requests * 2):
            self.compare("build_ospfv3_lsr", items, "fe80::1")
            self.compare("build_ospfv3_lsr_frame", items, "fe80::1", "aa:bb:cc:dd:ee:ff")
        for items in ([], headers, headers * 3):
            self.compare("build_ospfv3_lsack", items, "fe80::1")
            self.compare("build_ospfv3_lsack_frame", items, "fe80::1", "aa:bb:cc:dd:ee:ff")

    def test_lsu_raw_bytes_and_invalid_input(self):
        for items in ([], [b""], [b"\x00" * 20, bytearray(b"foo")],
                      [b"\x01", memoryview(b"\x02")], [17]):
            self.compare("encode_ospfv3_lsu_body", items)
        for body in (b"", b"\x00" * 3, b"\x00" * 4,
                     b"\x00\x00\x00\x01" + b"opaque"):
            self.compare("build_ospfv3_lsu", body, "fe80::1")
            self.compare("build_ospfv3_lsu_frame", body, "fe80::1", "aa:bb:cc:dd:ee:ff")

    def test_ipv6_ethernet_mac_and_hop_limit(self):
        for destination in ("ff02::5", "fe80::1", "2001:db8:1::1"):
            self.compare("build_ospfv3_frame", b"OSPF", destination, "00:11:22:33:44:55")
        frames = bytes(NEW_PACKET["build_ospfv3_frame"](b"x", "ff02::5", "dd"))
        self.assertIn(b"hlim", frames)
        self.assertIn(b"dd", frames)


class FakeHeader:
    registered = {}

    def __init__(self, raw):
        self.payload = self.registered.get(raw)


class FakeHello(Record):
    pass


class FakeDbd(Record):
    pass


class FakeLsr(Record):
    pass


class FakeAck(Record):
    pass


class FakeLsu:
    fields_desc = [Record(getfield=lambda _, raw: (b"", int.from_bytes(raw, "big")))]


def fake_checksum(raw):
    return sum(raw[:16] + raw[18:]) % 65536


def fake_lsa_parser(raw):
    if raw.endswith(b"BAD"):
        raise ValueError("bad LSA body")
    return {"body": raw[20:].hex()}


parser_environment = {
    "IPv4Address": ipaddress.IPv4Address, "struct": struct,
    "OSPFv3_Hdr": FakeHeader, "OSPFv3_Hello": FakeHello,
    "OSPFv3_DBDesc": FakeDbd, "OSPFv3_LSReq": FakeLsr,
    "OSPFv3_LSAck": FakeAck, "OSPFv3_LSUpd": FakeLsu,
    "OSPFv3_LSA_Hdr": FakeLsaHeader, "Scapy_Exception": type("FakeScapyError", (Exception,), {}),
    "parse_ospfv3_router_lsa": fake_lsa_parser,
    "parse_ospfv3_link_lsa": fake_lsa_parser,
    "parse_ospfv3_intra_area_prefix_lsa": fake_lsa_parser,
    "ospfv3_lsa_checksum": fake_checksum,
}
OLD_PARSER, NEW_PARSER = pair("parser", parser_environment, ("_LSA_BODY_PARSERS",))


def ospf_packet(kind, body):
    size = 16 + len(body)
    return bytes((3, kind)) + size.to_bytes(2, "big") + b"\x00" * 12 + body


def lsa_packet(kind, body=b"\x00\x11\x22\x33", bad_checksum=False):
    size = 20 + len(body)
    header = struct.pack("!HH4s4sIHH", 1, kind, socket.inet_aton("0.0.0.1"),
                         socket.inet_aton("1.1.1.1"), 0x80000001, 0, size)
    data = bytearray(header + body)
    checksum = fake_checksum(data) + bool(bad_checksum)
    data[16:18] = checksum.to_bytes(2, "big")
    return bytes(data)


class ParserContract(unittest.TestCase):
    def compare(self, name, raw, length=None):
        length = len(raw) if length is None else length
        self.assertEqual(outcome(NEW_PARSER[name], raw, length),
                         outcome(OLD_PARSER[name], raw, length), (name, raw, length))

    def test_hello_valid_and_neighbor_mismatch(self):
        body = b"\x00" * 20
        raw = ospf_packet(1, body)
        FakeHeader.registered[raw] = FakeHello(
            intid=7, prio=1, options=0x13, hellointerval=10,
            deadinterval=40, router="0.0.0.0", backup="0.0.0.0", neighbors=[])
        self.compare("parse_hello", raw)
        for length in (0, 16, 35, 36, 37, 38, 39, 40):
            self.compare("parse_hello", raw, length)
        raw2 = ospf_packet(1, b"\x00" * 24)
        FakeHeader.registered[raw2] = FakeHello(**{**FakeHeader.registered[raw].__dict__,
                                                    "neighbors": ["1.1.1.1"]})
        self.compare("parse_hello", raw2)
        FakeHeader.registered[raw2].neighbors = []
        self.compare("parse_hello", raw2)

    def test_dbd_flags_and_headers(self):
        for count in (0, 1, 2):
            raw = ospf_packet(2, b"\x00" * (12 + count * 20))
            FakeHeader.registered[raw] = FakeDbd(
                mtu=1500, options=0x13, dbdescr=7, ddseq=99,
                lsaheaders=[FakeLsaHeader(lsa_packet(0x2001)[:20]) for _ in range(count)])
            self.compare("parse_dbd", raw)
            FakeHeader.registered[raw].lsaheaders = []
            self.compare("parse_dbd", raw)
        self.compare("parse_dbd", ospf_packet(2, b"\x00" * 15))

    def test_lsr_and_lsack_counts(self):
        request = Record(type=0x2001, id="0.0.0.1", adrouter="1.1.1.1")
        header = FakeLsaHeader(lsa_packet(0x2001)[:20])
        for count in (0, 1, 2):
            req = ospf_packet(3, b"\x00" * (count * 12))
            ack = ospf_packet(5, b"\x00" * (count * 20))
            FakeHeader.registered[req] = FakeLsr(requests=[request] * count)
            FakeHeader.registered[ack] = FakeAck(lsaheaders=[header] * count)
            self.compare("parse_lsr", req)
            self.compare("parse_lsack", ack)
            FakeHeader.registered[req].requests = []
            FakeHeader.registered[ack].lsaheaders = []
            self.compare("parse_lsr", req)
            self.compare("parse_lsack", ack)
        for kind, fn in ((3, "parse_lsr"), (5, "parse_lsack")):
            self.compare(fn, ospf_packet(kind, b"bad"))

    def test_lsu_valid_opaque_and_supported_lsas(self):
        for types in ((0x200b,), (0x2001,), (0x0008, 0x2009), (0x200b, 0x2001)):
            body = len(types).to_bytes(4, "big") + b"".join(lsa_packet(t) for t in types)
            self.compare("parse_lsu", ospf_packet(4, body))

    def test_lsu_checksum_and_length_guardrails(self):
        cases = [b"\x00" * 3, b"\x00" * 4 + b"trailing",
                 b"\x00\x00\x00\x01", b"\x00\x00\x00\x01" + lsa_packet(0x2001, bad_checksum=True)]
        for body in cases:
            self.compare("parse_lsu", ospf_packet(4, body))
        lsa = bytearray(lsa_packet(0x2001))
        for length in (19, 20, 21, 100):
            lsa[18:20] = length.to_bytes(2, "big")
            self.compare("parse_lsu", ospf_packet(4, b"\x00\x00\x00\x01" + lsa))

    def test_lsu_error_body_parser_propagation(self):
        self.compare("parse_lsu", ospf_packet(4, b"\x00\x00\x00\x01" +
                                            lsa_packet(0x2001, b"BAD")))

    def test_wire_length_and_truncation(self):
        raw = ospf_packet(4, b"\x00" * 4)
        for length in (0, 15, 16, 19, 20, 21, 40):
            self.compare("parse_lsu", raw, length)
        self.compare("parse_lsu", raw + b"pad", 20)


class Clock:
    now = 41.0
    epoch = 1710000.0

    @classmethod
    def monotonic(cls):
        return cls.now

    @classmethod
    def time(cls):
        return cls.epoch


class Logger:
    def __init__(self):
        self.events = []

    def info(self, *args):
        self.events.append(args)


def compare_lsa_instances(a, b):
    for field in ("ls_sequence", "ls_checksum"):
        if a[field] != b[field]:
            return 1 if a[field] > b[field] else -1
    return 0 if a["ls_age"] == b["ls_age"] else (-1 if a["ls_age"] > b["ls_age"] else 1)


state_environment = {
    "cfg": cfg, "copy": copy,
    "time": Clock, "compare_lsa_instances": compare_lsa_instances,
    "ospfv3_lsa_type_description": lambda kind: "type-%04x" % kind,
}
OLD_LSDB, NEW_LSDB = pair("lsdb", state_environment)
OLD_NEIGHBOR, NEW_NEIGHBOR = pair("neighbor", state_environment)


def lsa(lsa_type=0x2001, seq=1, age=1, router="1.1.1.1", lsid="0.0.0.1"):
    return {"ls_type": lsa_type, "link_state_id": lsid,
            "advertising_router": router, "ls_sequence": seq,
            "ls_checksum": 10, "ls_age": age, "router_lsa": {"links": [1]}}


class StateContract(unittest.TestCase):
    def replay_lsdb(self, operations):
        Clock.now = 41.0
        old_log, new_log = Logger(), Logger()
        old = OLD_LSDB["LSDB"](old_log)
        new = NEW_LSDB["LSDB"](new_log)
        for name, args, tick in operations:
            Clock.now = tick
            self.assertEqual(outcome(getattr(old, name), *copy.deepcopy(args)),
                             outcome(getattr(new, name), *copy.deepcopy(args)), name)
            self.assertEqual(old.entries, new.entries, name)
            self.assertEqual(old_log.events, new_log.events, name)
            for method in ("__len__", "__bool__", "values", "items"):
                a, b = getattr(old, method)(), getattr(new, method)()
                self.assertEqual(list(a) if method in ("values", "items") else a,
                                 list(b) if method in ("values", "items") else b, method)

    def test_lsdb_install_replace_and_older_ignore(self):
        self.replay_lsdb([
            ("update", ([lsa()],), 41),
            ("update", ([lsa(seq=1, age=2)],), 42),
            ("update", ([lsa(seq=2, age=3)],), 43),
            ("get_age", (lsa(),), 44),
            ("update", ([lsa(seq=1, age=3)],), 45),
            ("update", ([lsa(0x2009, seq=3), lsa(0x0008, seq=3)],), 46),
        ])

    def test_lsdb_maxage_flush_expiry_and_remote_clear(self):
        self.replay_lsdb([
            ("update", ([lsa(0x2001), lsa(0x0008, router="2.2.2.2")],), 41),
            ("update", ([lsa(age=cfg.MAX_AGE, seq=0)],), 42),
            ("update", ([lsa(age=cfg.MAX_AGE, seq=1)],), 43),
            ("purge_expired", (), 43 + cfg.MAX_AGE),
            ("clear_remote", ("10.10.10.10",), 43 + cfg.MAX_AGE),
        ])

    def test_lsdb_empty_and_maxage_unknown_kind(self):
        self.replay_lsdb([
            ("clear_remote", ("10.10.10.10",), 41),
            ("purge_expired", (), 41),
            ("update", ([lsa(0x200b), lsa(0x200b, seq=2)],), 42),
            ("update", ([lsa(0x200b, age=cfg.MAX_AGE, seq=3)],), 43),
        ])

    def replay_neighbor(self, operations):
        Clock.now = 41.0
        Clock.epoch = 1710000.0
        old_log, new_log = Logger(), Logger()
        old = OLD_NEIGHBOR["Neighbor"](old_log)
        new = NEW_NEIGHBOR["Neighbor"](new_log)
        for name, args, tick in operations:
            Clock.now = tick
            self.assertEqual(outcome(getattr(old, name), *copy.deepcopy(args)),
                             outcome(getattr(new, name), *copy.deepcopy(args)), name)
            self.assertEqual(old.__dict__ | {"logger": None},
                             new.__dict__ | {"logger": None}, name)
            self.assertEqual(old_log.events, new_log.events, name)

    def test_neighbor_hello_dead_and_sequence_wrap(self):
        self.replay_neighbor([
            ("dead_interval_expired", (40,), 41),
            ("mark_hello_received", (), 41),
            ("dead_interval_expired", (40,), 80.9),
            ("dead_interval_expired", (40,), 81),
            ("reset_exchange", (), 81),
            ("reset_adjacency", (), 82),
            ("reset", (), 83),
        ])

    def test_neighbor_lsr_request_match_newer_and_pending(self):
        request = lsa()
        other = lsa(0x0008, seq=2)
        operations = [
            ("update_request_list", ([lsa(seq=2)],), 41),
            ("reset_exchange", (), 42),
        ]
        self.replay_neighbor(operations)
        old_log, new_log = Logger(), Logger()
        left = OLD_NEIGHBOR["Neighbor"](old_log)
        right = NEW_NEIGHBOR["Neighbor"](new_log)
        for subject in (left, right):
            subject.request_list = [copy.deepcopy(request), copy.deepcopy(other)]
        for incoming in ([lsa(seq=0)], [lsa(seq=2)], [other]):
            self.assertEqual(outcome(left.update_request_list, incoming),
                             outcome(right.update_request_list, incoming))
            self.assertEqual(left.request_list, right.request_list)
            self.assertEqual(old_log.events, new_log.events)


if __name__ == "__main__":
    unittest.main()
