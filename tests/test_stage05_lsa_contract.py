"""Stage05: executable comparison with the pinned LSA source implementations.

AST-loads source and reference functions without Scapy/Ryu. Deterministic
Scapy-like objects expose sequence, LSA fields, bytes, logs and side effects.
Real Scapy and wire validation are left to the original tests and Containernet.
"""

import ast
import copy
import ipaddress
from pathlib import Path
import runpy
import socket
import struct
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
CFG = types.SimpleNamespace(**{
    name: value for name, value in runpy.run_path(str(ROOT / "ospfv3/config.py")).items()
    if name.isupper()})


def ast_namespace(path, symbols, namespace):
    tree = ast.parse(path.read_text(encoding="utf8"))
    nodes = [node for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.ClassDef))
             and node.name in symbols]
    assert set(node.name for node in nodes) == set(symbols)
    scope = dict(namespace)
    exec(compile(ast.fix_missing_locations(ast.Module(
        body=nodes, type_ignores=[])), str(path), "exec"), scope)
    return scope


class BaseProtocol:
    def __init__(self, **fields):
        self.__dict__.update(fields)

    def __repr__(self):
        return repr(sorted(self.__dict__.items()))


class FakeLsaHeader:
    def __init__(self, raw):
        self.age, self.type, lsid, adrouter, self.seq, self.chksum, self.len = (
            struct.unpack("!HH4s4sIHH", raw[:20]))
        self.id = socket.inet_ntoa(lsid)
        self.adrouter = socket.inet_ntoa(adrouter)


class FakeLsaBuilder(BaseProtocol):
    def __bytes__(self):
        fields = self.__dict__
        body = repr(sorted(fields.items())).encode("ascii")
        header = struct.pack(
            "!HH4s4sIHH", fields["age"], fields["type"],
            socket.inet_aton(fields["id"]), socket.inet_aton(fields["adrouter"]),
            fields["seq"], sum(body) % 65536, 20 + len(body))
        return header + body


class FakeRouterDecoder:
    def __init__(self, raw):
        self.flags, self.options = 0, 0x13
        self.linklist = [BaseProtocol(
            type=1, reserved=0, metric=10, intid=1,
            neighintid=7, neighbor="1.1.1.1")
            for _ in range((len(raw) - 24) // 16)]


class FakeLinkDecoder:
    def __init__(self, raw):
        self.prio, self.options, self.lladdr = 1, 0x13, "fe80::1"
        self.prefixes = int.from_bytes(raw[40:44], "big")
        self.prefixlist = [BaseProtocol(
            prefixlen=64, prefixoptions=0, metric=0,
            prefix="2001:db8:10::/64") for _ in range(self.prefixes)]


class FakePrefixDecoder:
    def __init__(self, raw):
        self.prefixes = int.from_bytes(raw[20:22], "big")
        self.reflstype, self.reflsid, self.refadrouter = (
            0x2001, "0.0.0.0", CFG.ROUTER_ID)
        self.prefixlist = [BaseProtocol(
            prefixlen=64, prefixoptions=0, metric=10,
            prefix="2001:db8:1::/64") for _ in range(self.prefixes)]


def fake_checksum(raw):
    return (sum(raw[2:]) % 65536).to_bytes(2, "big")


LSA_FUNCTIONS = (
    "ospfv3_lsa_type_description", "_check_lsa_header", "_check_prefixes",
    "_decode_lsa", "parse_ospfv3_router_lsa", "parse_ospfv3_link_lsa",
    "parse_ospfv3_intra_area_prefix_lsa", "lsa_sequence_signed",
    "compare_lsa_instances", "ospfv3_lsa_checksum",
    "next_ospfv3_lsa_sequence", "finalize_ospfv3_lsa_checksum")
LSA_ENV = dict(struct=struct, IPv4Address=ipaddress.IPv4Address,
               IPv6Interface=ipaddress.IPv6Interface, cfg=CFG,
               OSPFv3_Router_LSA=FakeRouterDecoder,
               OSPFv3_Link_LSA=FakeLinkDecoder,
               OSPFv3_Intra_Area_Prefix_LSA=FakePrefixDecoder,
               _scapy_ospf_lsa_checksum=fake_checksum)
OLD_LSA = ast_namespace(ROOT / "tests/_stage05_lsa_reference.py",
                        LSA_FUNCTIONS, LSA_ENV)
NEW_LSA = ast_namespace(ROOT / "ospfv3/lsa.py", LSA_FUNCTIONS, LSA_ENV)


def outcome(fn, *args):
    try:
        return ("return", fn(*args))
    except Exception as exc:
        return ("raise", type(exc).__name__, str(exc))


def raw_lsa(kind, length, prefix_count=0, prefix_length=64):
    raw = bytearray(length)
    if length >= 20:
        raw[2:4] = kind.to_bytes(2, "big")
        raw[18:20] = length.to_bytes(2, "big")
    if kind == 0x0008 and length >= 44:
        raw[40:44] = prefix_count.to_bytes(4, "big")
        if length > 44:
            raw[44] = prefix_length
    if kind == 0x2009 and length >= 32:
        raw[20:22] = prefix_count.to_bytes(2, "big")
        if length > 32:
            raw[32] = prefix_length
    return bytes(raw)


class LsaFunctionContract(unittest.TestCase):
    def compare(self, method, args):
        expected = outcome(OLD_LSA[method], *args)
        actual = outcome(NEW_LSA[method], *args)
        self.assertEqual(actual, expected, (method, args))
        return actual

    def test_all_lsa_types_and_scopes(self):
        for kind in (0, 0x2001, 0x2002, 0x2003, 0x2004,
                     0x4005, 0x2007, 0x0008, 0x2009, 0x600f):
            with self.subTest(kind=kind):
                self.compare("ospfv3_lsa_type_description", (kind,))

    def test_router_lsa_valid_and_rejected_lengths(self):
        for length in (0, 20, 24, 25, 40, 41, 56):
            with self.subTest(length=length):
                self.compare("parse_ospfv3_router_lsa",
                             (raw_lsa(0x2001, length),))

    def test_link_lsa_prefix_boundaries(self):
        cases = [(44, 0, 64), (56, 1, 64), (56, 2, 64),
                 (56, 1, 129), (44, 1, 64), (50, 1, 64)]
        for length, count, prefix_length in cases:
            with self.subTest(length=length, count=count, prefix_length=prefix_length):
                self.compare("parse_ospfv3_link_lsa",
                             (raw_lsa(0x0008, length, count, prefix_length),))

    def test_intra_area_prefix_lsa_boundary_checks(self):
        for length, count in ((32, 0), (44, 1), (44, 2), (33, 1), (44, 0)):
            with self.subTest(length=length, count=count):
                self.compare("parse_ospfv3_intra_area_prefix_lsa",
                             (raw_lsa(0x2009, length, count),))

    def test_lsa_wrong_type_or_declared_length(self):
        data = bytearray(raw_lsa(0x2001, 24))
        for target in ("parse_ospfv3_link_lsa", "parse_ospfv3_intra_area_prefix_lsa"):
            self.compare(target, (bytes(data),))
        data[18:20] = (25).to_bytes(2, "big")
        self.compare("parse_ospfv3_router_lsa", (bytes(data),))

    def test_signed_sequence_and_maxage_comparisons(self):
        for sequence in (0x80000001, 0xffffffff, 0, 0x7fffffff):
            self.compare("lsa_sequence_signed", (sequence,))
        pairs = [
            (0x80000001, 0x80000002, 10, 10, 0, 0),
            (0x80000001, 0x80000001, 10, 11, 0, 0),
            (0x80000001, 0x80000001, 10, 10, CFG.MAX_AGE, 1),
            (0x80000001, 0x80000001, 10, 10, 1, CFG.MAX_AGE),
            (0x80000001, 0x80000001, 10, 10, 10, 1000),
            (0x80000001, 0x80000001, 10, 10, 10, 100),
        ]
        for a, b, c, d, age_a, age_b in pairs:
            self.compare("compare_lsa_instances", (
                {"ls_sequence": a, "ls_checksum": c, "ls_age": age_a},
                {"ls_sequence": b, "ls_checksum": d, "ls_age": age_b}))

    def test_reserved_max_and_invalid_sequence(self):
        for value in (-1, 0, 0x80000000, 0x80000001, 0x7ffffffe,
                      0x7fffffff, 0x100000000):
            self.compare("next_ospfv3_lsa_sequence", (value,))

    def test_checksum_and_finalize_keep_input_unchanged(self):
        for length in (0, 19, 20, 24, 48):
            input_data = bytes(range(length))
            self.compare("ospfv3_lsa_checksum", (input_data,))
            self.compare("finalize_ospfv3_lsa_checksum", (input_data,))


class Logger:
    def __init__(self):
        self.events = []

    def info(self, *args):
        self.events.append(("info", self._normalize(args)))

    def warning(self, *args):
        self.events.append(("warning", self._normalize(args)))

    @staticmethod
    def _normalize(args):
        return tuple((type(value).__name__, str(value))
                     if isinstance(value, Exception) else value for value in args)


def encode_ospfv3_lsu_body(lsas):
    return struct.pack("!I", len(lsas)) + b"".join(lsas)


LOCAL_ENV = dict(ipaddress=ipaddress, socket=socket, struct=struct,
                 time=types.SimpleNamespace(monotonic=lambda: 41.5), cfg=CFG,
                 OSPFv3_Router_LSA=FakeLsaBuilder,
                 OSPFv3_Link_LSA=FakeLsaBuilder,
                 OSPFv3_Intra_Area_Prefix_LSA=FakeLsaBuilder,
                 OSPFv3_Link=BaseProtocol,
                 OSPFv3_Prefix_Item=BaseProtocol,
                 OSPFv3_LSA_Hdr=FakeLsaHeader,
                 encode_ospfv3_lsu_body=encode_ospfv3_lsu_body,
                 next_ospfv3_lsa_sequence=NEW_LSA["next_ospfv3_lsa_sequence"],
                 ospfv3_lsa_type_description=NEW_LSA["ospfv3_lsa_type_description"],
                 lsa_sequence_signed=NEW_LSA["lsa_sequence_signed"])
OldLocal = ast_namespace(ROOT / "tests/_stage05_local_lsa_reference.py",
                         ["LocalLSA"], LOCAL_ENV)["LocalLSA"]
NewLocal = ast_namespace(ROOT / "ospfv3/local_lsa.py",
                         ["LocalLSA"], LOCAL_ENV)["LocalLSA"]


def peer_database():
    return {"peer": {"ls_type": 0x2001,
                     "advertising_router": "1.1.1.1",
                     "router_lsa": {"links": [
                         {"type": 1, "neighbor_router_id": CFG.ROUTER_ID,
                          "neighbor_interface_id": "0.0.0.1",
                          "interface_id": "0.0.0.7"}]}}}


def local_snapshot(store, logger):
    return (copy.deepcopy(store.entries), store.router_sequence,
            store.link_sequence, store.prefix_sequence,
            copy.deepcopy(logger.events))


class LocalLsaContract(unittest.TestCase):
    def replay(self, operations, lsdb=None):
        left_log, right_log = Logger(), Logger()
        left = OldLocal(copy.deepcopy(lsdb or {}), left_log)
        right = NewLocal(copy.deepcopy(lsdb or {}), right_log)
        for name, arguments in operations:
            old_result = outcome(getattr(left, name), *arguments)
            new_result = outcome(getattr(right, name), *arguments)
            self.assertEqual(old_result, new_result, name)
            self.assertEqual(local_snapshot(left, left_log),
                             local_snapshot(right, right_log), name)
        return right

    def test_empty_initialization_requires_neighbor_interface(self):
        store = self.replay([("initialize", ("1.1.1.1",)),
                             ("build_update_body", ())])
        self.assertFalse(store.entries)

    def test_neighbor_interface_id_is_selected_from_correct_router_link(self):
        self.replay([("get_neighbor_interface_id", ("1.1.1.1",)),
                     ("get_neighbor_interface_id", ("2.2.2.2",)),
                     ("get_neighbor_interface_id", (None,))],
                    lsdb=peer_database())

    def test_originate_three_lsas_with_exact_scappy_arguments(self):
        store = self.replay([("build_router", ("1.1.1.1",)),
                             ("build_link", ()), ("build_prefix", ()),
                             ("initialize", ("1.1.1.1",)),
                             ("initialize", ("1.1.1.1",)),
                             ("build_update_body", ())], peer_database())
        self.assertEqual(len(store.entries), 3)
        self.assertEqual(store.router_sequence, CFG.INITIAL_SEQUENCE)

    def test_recover_sequences_after_restart(self):
        headers = [
            {"advertising_router": CFG.ROUTER_ID, "ls_type": 0x2001,
             "link_state_id": "0.0.0.0", "ls_sequence": 0x80000009},
            {"advertising_router": CFG.ROUTER_ID, "ls_type": 0x0008,
             "link_state_id": "0.0.0.1", "ls_sequence": 0x80000010},
            {"advertising_router": CFG.ROUTER_ID, "ls_type": 0x2009,
             "link_state_id": "0.0.0.0", "ls_sequence": 0x80000012},
            {"advertising_router": "1.1.1.1", "ls_type": 0x2001,
             "link_state_id": "0.0.0.0", "ls_sequence": 0x80000020},
            {"advertising_router": CFG.ROUTER_ID, "ls_type": 0x1234,
             "link_state_id": "0.0.0.0", "ls_sequence": 0x80000020}]
        self.replay([("recover_sequences", (headers, True)),
                     ("recover_sequences", (headers, False)),
                     ("initialize", ("1.1.1.1",))], peer_database())

    def test_max_sequence_cannot_be_recovered_with_prepare_next(self):
        header = {"advertising_router": CFG.ROUTER_ID, "ls_type": 0x2001,
                  "link_state_id": "0.0.0.0", "ls_sequence": 0x7fffffff}
        self.replay([("recover_sequences", ([header], True)),
                     ("recover_sequences", ([header], False))])

    def test_install_short_payload_is_rejected(self):
        self.replay([("install", (b"short",))])

    def test_pending_lsa_checks_sequence_checksum_and_order(self):
        store = self.replay([("initialize", ("1.1.1.1",))], peer_database())
        pending = {key: {"ls_sequence": lsa["ls_sequence"],
                         "ls_checksum": lsa["ls_checksum"]}
                   for key, lsa in store.entries.items()}
        self.replay([("initialize", ("1.1.1.1",)),
                     ("build_pending_body", (pending,)),
                     ("build_pending_body", ({},))], peer_database())
        wrong = copy.deepcopy(pending)
        first_key = next(iter(wrong))
        wrong[first_key]["ls_checksum"] += 1
        self.replay([("initialize", ("1.1.1.1",)),
                     ("build_pending_body", (wrong,))], peer_database())

    def test_reoriginate_increments_sequences_and_reinstalls(self):
        store = self.replay([("initialize", ("1.1.1.1",)),
                             ("reoriginate", ("1.1.1.1", "LS refresh")),
                             ("build_update_body", ())], peer_database())
        self.assertEqual(store.router_sequence, CFG.INITIAL_SEQUENCE + 1)
        self.assertEqual(len(store.entries), 3)

    def test_reoriginate_rejects_empty_or_missing_neighbor(self):
        self.replay([("reoriginate", ("1.1.1.1", "test")),
                     ("initialize", ("1.1.1.1",)),
                     ("reoriginate", ("1.1.1.1", "test"))])


if __name__ == "__main__":
    unittest.main()
