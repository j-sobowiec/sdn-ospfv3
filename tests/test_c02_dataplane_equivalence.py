"""C02: independent old/new DataPlane equivalence and real Ryu ICMPv6 bytes.

Full original DataPlane is in _c02_dataplane_reference.py. The stub tests
compare full constructed protocol traces and persistent state; the real Ryu
test compares complete serialized Ethernet+IPv6+ICMPv6 wire bytes.
"""
import ast
import importlib.util
import ipaddress
import random
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

from b5_3_harness import (
    BASE, CFG, DataPlane as CurrentViaHarness, Echo, Ether, FRAMES, ICMP,
    IP6, LAN_IP, LAN_MAC, ND, Pkt, TRANSIT_IP, TRANSIT_MAC, TLA,
    load_class,
)

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(__file__).with_name('_c02_dataplane_reference.py')
CURRENT = ROOT / 'dataplane.py'
OLD = load_class(REFERENCE, 'DataPlane', BASE)
NEW = load_class(CURRENT, 'DataPlane', BASE)


def freeze(value):
    if isinstance(value, (str, int, float, bool, bytes, type(None))):
        return value
    if isinstance(value, (dict,)):
        return tuple(sorted((freeze(k), freeze(v)) for k, v in value.items()))
    if isinstance(value, (tuple, list)):
        return tuple(freeze(x) for x in value)
    if hasattr(value, '__dict__'):
        return (type(value).__name__, tuple(sorted((k, freeze(v)) for k, v in vars(value).items())))
    return str(value)


def outcome(dp, method, *args, **kw):
    try:
        data = getattr(dp, method)(*args, **kw)
        if isinstance(data, bytes):
            result = ('frame', tuple(freeze(x) for x in FRAMES[data].protocols))
        else:
            result = ('return', freeze(data))
    except Exception as exc:
        result = ('exception', type(exc), str(exc))
    return result, freeze(vars(dp))


def ndp_input(src=LAN_IP, mac=LAN_MAC, port=2, target=None,
              typ=135, nd=True, code=0, hop_limit=255):
    pkt = Pkt()
    eth = Ether(src=mac, dst=CFG.ROUTER_MAC, ethertype=0x86dd)
    ip6 = IP6(src=src, dst='ff02::1:ff00:1', nxt=58, hop_limit=hop_limit)
    body = ND(dst=target or CFG.LAN_GATEWAY) if nd else Echo(id_=1, seq=1, data=b'')
    pkt.protocols[:] = [eth, ip6, ICMP(type_=typ, code=code, data=body)]
    return pkt, eth, ip6, port


def echo_input(src=LAN_IP, mac=LAN_MAC, port=2, dest=None,
               typ=128, data=None):
    pkt = Pkt()
    eth = Ether(src=mac, dst=CFG.ROUTER_MAC, ethertype=0x86dd)
    ip6 = IP6(src=src, dst=dest or CFG.LAN_GATEWAY, nxt=58, hop_limit=64)
    pkt.protocols[:] = [eth, ip6, ICMP(type_=typ, code=0,
                                       data=data if data is not None else Echo(id_=7, seq=4, data=b'abc'))]
    return pkt, eth, ip6, port


class TestC02StubEquivalence(unittest.TestCase):
    def assert_equal(self, method, *args, setup=None, **kw):
        older, newer = OLD(), NEW()
        if setup:
            setup(older)
            setup(newer)
        self.assertEqual(outcome(older, method, *args, **kw),
                         outcome(newer, method, *args, **kw))

    def test_old_reference_is_frozen(self):
        self.assertIn('class DataPlane:', REFERENCE.read_text())
        self.assertNotIn('def _icmpv6_packet', REFERENCE.read_text())
        self.assertIn('def _icmpv6_packet', CURRENT.read_text())

    def test_public_method_signatures_identical(self):
        import inspect
        old_methods = {k: str(inspect.signature(v)) for k, v in vars(OLD).items()
                       if callable(v) and not k.startswith('_')}
        new_methods = {k: str(inspect.signature(v)) for k, v in vars(NEW).items()
                       if callable(v) and not k.startswith('_')}
        self.assertEqual(old_methods, new_methods)

    def test_build_na_gateway(self):
        for mac in (LAN_MAC, TRANSIT_MAC, 'ff:ff:ff:ff:ff:ff'):
            for dest in (LAN_IP, '2001:db8:1::abcd', TRANSIT_IP):
                for target in (CFG.LAN_GATEWAY, CFG.LINK_LOCAL):
                    with self.subTest(mac=mac, dest=dest, target=target):
                        self.assert_equal('build_neighbor_advertisement', mac, dest, target)

    def test_build_echo_data_variants(self):
        samples = [b'', b'x', b'\x00' * 300, bytes(range(256)), b'hello world']
        for seq in (0, 1, 65535):
            for blob in samples:
                for mac in (LAN_MAC, TRANSIT_MAC):
                    with self.subTest(seq=seq, blob_len=len(blob), mac=mac):
                        self.assert_equal('build_echo_reply', mac, LAN_IP,
                                          NS(id=seq, seq=seq, data=blob))

    def test_invalid_echo_payload_exception_and_state(self):
        for data in (None, 4, object(), NS(seq=1, data=b''),
                     NS(id=1, data=b''), NS(id=1, seq=1)):
            self.assert_equal('build_echo_reply', LAN_MAC, LAN_IP, data)

    def test_constructor_and_serializer_order_exact(self):
        # Trace packet object creation, protocol constructors, add_protocol,
        # serialization in both implementations; even intermediate order matters.
        def traced(source):
            events = []
            class TracedPacket(Pkt):
                def __init__(self):
                    events.append('packet.new')
                    super().__init__()
                def add_protocol(self, protocol):
                    events.append(('add', type(protocol).__name__))
                    super().add_protocol(protocol)
                def serialize(self):
                    events.append('packet.serialize')
                    super().serialize()
            def traced_cls(cls, name):
                class Wrapped(cls):
                    def __init__(self, *a, **kw):
                        events.append(('create', name, freeze(a), freeze(kw)))
                        super().__init__(*a, **kw)
                Wrapped.__name__ = cls.__name__
                return Wrapped
            env = dict(BASE)
            from types import SimpleNamespace
            env['packet'] = SimpleNamespace(Packet=TracedPacket)
            env['ethernet'] = SimpleNamespace(ethernet=traced_cls(Ether, 'ethernet'))
            env['ipv6'] = SimpleNamespace(ipv6=traced_cls(IP6, 'ipv6'))
            env['icmpv6'] = SimpleNamespace(
                icmpv6=traced_cls(ICMP, 'icmpv6'),
                nd_option_tla=traced_cls(TLA, 'tla'),
                nd_neighbor=traced_cls(ND, 'nd_neighbor'),
                echo=traced_cls(Echo, 'echo'),
                ND_NEIGHBOR_ADVERT=136)
            klass = load_class(source, 'DataPlane', env)
            obj = klass()
            obj.build_neighbor_advertisement(LAN_MAC, LAN_IP, CFG.LAN_GATEWAY)
            na_trace = tuple(events)
            events.clear()
            obj.build_echo_reply(LAN_MAC, LAN_IP, NS(id=55, seq=3, data=b'123'))
            return na_trace, tuple(events)
        self.assertEqual(traced(REFERENCE), traced(CURRENT))

    def test_ndp_learning_and_spoofing_cases(self):
        cases = [
            {}, {'typ': 129}, {'nd': False}, {'src': '::'},
            {'src': '2001:db8:23::5'}, {'port': 3},
            {'target': '2001:db8:1::ffff'},
            {'code': 7}, {'hop_limit': 1},
        ]
        for setup in (None, lambda dp: dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC),
                      lambda dp: dp.learn_lan_host(2, LAN_IP, LAN_MAC)):
            for kw in cases:
                with self.subTest(kw=kw, setup=bool(setup)):
                    if 'code' not in kw and 'hop_limit' not in kw:
                        # C02's original exact equivalence requirement remains
                        # in force for all unchanged NDP input scenarios.
                        self.assert_equal('handle_ndp', *ndp_input(**kw), setup=setup)
                        continue

                    # W02a is an intentional behavioral security fix: the C02
                    # frozen reference used to answer invalid NS packets.
                    # Prove the change explicitly rather than discarding the
                    # invalid cases or changing the reference implementation.
                    older, newer = OLD(), NEW()
                    if setup:
                        setup(older)
                        setup(newer)
                    before = freeze(vars(newer))
                    old_result, _ = outcome(older, 'handle_ndp', *ndp_input(**kw))
                    new_result, after = outcome(newer, 'handle_ndp', *ndp_input(**kw))
                    self.assertEqual(old_result[0], 'frame')
                    self.assertEqual(new_result, ('return', None))
                    self.assertEqual(after, before, 'Invalid NS must not learn or mutate state')

    def test_transit_ns_all_guard_branches(self):
        cases = [
            (1, TRANSIT_IP, TRANSIT_MAC), (2, TRANSIT_IP, TRANSIT_MAC),
            (1, 'fe80::9999', TRANSIT_MAC), (1, TRANSIT_IP, LAN_MAC),
        ]
        for port, src, mac in cases:
            self.assert_equal('handle_ndp', *ndp_input(
                port=port, src=src, mac=mac, target=CFG.LINK_LOCAL),
                setup=lambda dp: dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC))
        self.assert_equal('handle_ndp', *ndp_input(
            port=1, src=TRANSIT_IP, mac=TRANSIT_MAC, target=CFG.LINK_LOCAL))

    def test_echo_learning_and_denied_cases(self):
        for setup in (None, lambda dp: dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC),
                      lambda dp: dp.learn_lan_host(2, LAN_IP, LAN_MAC)):
            for kw in ({}, {'typ': 129}, {'src': '2001:db8:23::4'},
                       {'dest': '2001:db8:10::1'}, {'port': 3}, {'port': 1}):
                self.assert_equal('handle_echo_request', *echo_input(**kw), setup=setup)

    def test_reset_and_learning_contract(self):
        for method in ('reset', 'reset_transit'):
            self.assert_equal(method, setup=lambda dp: (
                dp.learn_lan_host(2, LAN_IP, LAN_MAC),
                dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)))

    def test_randomized_packet_construction(self):
        rng = random.Random(0xC020260)
        for _ in range(900):
            dest = str(ipaddress.IPv6Address(rng.getrandbits(128)))
            mac = ':'.join(f'{rng.randrange(256):02x}' for _ in range(6))
            target = CFG.LAN_GATEWAY if rng.randrange(2) else CFG.LINK_LOCAL
            if rng.randrange(2):
                self.assert_equal('build_neighbor_advertisement', mac, dest, target)
            else:
                data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(80)))
                self.assert_equal('build_echo_reply', mac, dest,
                                  NS(id=rng.randrange(65536), seq=rng.randrange(65536), data=data))


class TestC02RealRyu(unittest.TestCase):
    def test_real_ryu_serialized_ethernet_ipv6_icmpv6_bytes(self):
        try:
            from ryu.lib.packet import packet as ryu_packet
            from ryu.lib.packet import icmpv6 as ryu_icmpv6
        except (ImportError, ModuleNotFoundError):
            self.skipTest('Ryu not installed: full wire comparison required on Ubuntu')
        spec_o = importlib.util.spec_from_file_location('c02_frozen_original', REFERENCE)
        spec_n = importlib.util.spec_from_file_location('c02_new_dataplane', CURRENT)
        original, modified = importlib.util.module_from_spec(spec_o), importlib.util.module_from_spec(spec_n)
        spec_o.loader.exec_module(original)
        spec_n.loader.exec_module(modified)
        a, b = original.DataPlane(), modified.DataPlane()
        rng = random.Random(20261019)
        for i in range(40):
            destination_ipv6 = str(ipaddress.IPv6Address(int(ipaddress.IPv6Address('2001:db8:1::100')) + i))
            destination_mac = '02:00:00:00:%02x:%02x' % (i // 256, i % 256)
            target = CFG.LAN_GATEWAY if i % 2 else CFG.LINK_LOCAL
            n1 = a.build_neighbor_advertisement(destination_mac, destination_ipv6, target)
            n2 = b.build_neighbor_advertisement(destination_mac, destination_ipv6, target)
            self.assertEqual(n1, n2, f'NA bytes mismatch in variant {i}')
            self.assertEqual(ryu_packet.Packet(n2).get_protocol(ryu_icmpv6.icmpv6).type_, 136)
            payload = bytes(rng.getrandbits(8) for _ in range(i * 3))
            echo = NS(id=i * 119, seq=65535 - i, data=payload)
            e1 = a.build_echo_reply(destination_mac, destination_ipv6, echo)
            e2 = b.build_echo_reply(destination_mac, destination_ipv6, echo)
            self.assertEqual(e1, e2, f'Echo bytes mismatch in variant {i}')
            self.assertEqual(ryu_packet.Packet(e2).get_protocol(ryu_icmpv6.icmpv6).type_, 129)


if __name__ == '__main__':
    unittest.main()
