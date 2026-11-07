"""W02a: strict RFC 4861 Neighbor Solicitation validation, with regressions.

Runs the actual production methods through the B5.3 isolated harness; the
real-Ryu test executes the real parser and actual DataPlane if installed.
"""
import ast
import copy
import importlib.util
import ipaddress
import random
import unittest
from pathlib import Path

from b5_3_harness import (CFG, LAN_IP, LAN_MAC, TRANSIT_IP, TRANSIT_MAC,
                          DataPlane, FRAMES, Pkt, Ether, ICMP, IP6, ND,
                          make_controller, incoming, packet_in, ns)
from test_dataplane_b5_3 import make_ndp
from _w02a_ndp_reference import ORIGINAL_NDP, ORIGINAL_PACKET_IN

ROOT = Path(__file__).resolve().parents[1]


def state(dp):
    return (dp.lan_port, dict(dp.lan_hosts), dp.transit_port,
            dp.transit_router_ipv6,
            dp.transit_router_mac)


def make_raw_ns(hl=255, code=0, eth_dst='33:33:ff:00:00:01',
                dest='ff02::1:ff00:1', target=None):
    eth = Ether(src=LAN_MAC, dst=eth_dst, ethertype=0x86dd)
    ip6 = IP6(src=LAN_IP, dst=dest, nxt=58, hop_limit=hl)
    icmp = ICMP(type_=135, code=code, data=ND(dst=target or CFG.LAN_GATEWAY))
    return incoming(eth, ip6, icmp)


class TestW02ANdp(unittest.TestCase):
    def test_01_only_two_production_methods_changed(self):
        old_dp = ast.parse('class X:\n' + ORIGINAL_NDP)
        old_ctl = ast.parse('class X:\n' + ORIGINAL_PACKET_IN)
        for relative, cls, method, old in (
            ('dataplane.py', 'DataPlane', 'handle_ndp', old_dp),
            ('ryu_sdn.py', 'OSPFv3Controller', 'packet_in_handler', old_ctl),
        ):
            tree = ast.parse((ROOT / relative).read_text(encoding='utf-8'))
            klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls)
            new = next(n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == method)
            prior = old.body[0].body[0]
            self.assertEqual(len(prior.args.args), len(new.args.args))
            self.assertNotEqual(ast.dump(prior, include_attributes=False),
                                ast.dump(new, include_attributes=False))

    def test_02_valid_lan_ns_still_answers_and_learns(self):
        dp = DataPlane()
        pkt, eth, ip6, port = make_ndp()
        result = dp.handle_ndp(pkt, eth, ip6, port)
        self.assertIsInstance(result, bytes)
        self.assertEqual((dp.lan_port, dp.lan_hosts[LAN_IP]), (2, LAN_MAC))

    def test_03_bad_hop_limit_no_learning_and_no_na(self):
        for hop in (0, 1, 64, 254, 256, None):
            with self.subTest(hop=hop):
                dp = DataPlane()
                pkt, eth, ip6, port = make_ndp()
                ip6.hop_limit = hop
                before = state(dp)
                self.assertIsNone(dp.handle_ndp(pkt, eth, ip6, port))
                self.assertEqual(state(dp), before)

    def test_04_bad_icmp_code_no_learning_and_no_na(self):
        for code in (-1, 1, 2, 255, None):
            with self.subTest(code=code):
                dp = DataPlane()
                pkt, eth, ip6, port = make_ndp()
                pkt.get_protocol(ICMP).code = code
                before = state(dp)
                self.assertIsNone(dp.handle_ndp(pkt, eth, ip6, port))
                self.assertEqual(state(dp), before)

    def test_05_bad_packets_do_not_alter_already_learned_host(self):
        dp = DataPlane()
        self.assertTrue(dp.learn_lan_host(2, LAN_IP, LAN_MAC))
        before = state(dp)
        for hop, code in ((64, 0), (255, 1), (64, 1)):
            pkt, eth, ip6, port = make_ndp(mac='02:00:00:aa:bb:cc')
            ip6.hop_limit = hop
            pkt.get_protocol(ICMP).code = code
            self.assertIsNone(dp.handle_ndp(pkt, eth, ip6, port))
            self.assertEqual(state(dp), before)

    def test_06_valid_transit_ns_unchanged(self):
        dp = DataPlane()
        dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        pkt, eth, ip6, port = make_ndp(target=CFG.LINK_LOCAL,
                                         port=1, src=TRANSIT_IP, mac=TRANSIT_MAC)
        self.assertIsInstance(dp.handle_ndp(pkt, eth, ip6, port), bytes)
        self.assertEqual((dp.transit_router_ipv6, dp.transit_router_mac), (TRANSIT_IP, TRANSIT_MAC))

    def test_07_bad_transit_ns_does_not_mutate(self):
        dp = DataPlane()
        dp.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        before = state(dp)
        for hop, code in ((64, 0), (255, 9)):
            pkt, eth, ip6, port = make_ndp(target=CFG.LINK_LOCAL,
                                             port=1, src=TRANSIT_IP, mac=TRANSIT_MAC)
            ip6.hop_limit = hop
            pkt.get_protocol(ICMP).code = code
            self.assertIsNone(dp.handle_ndp(pkt, eth, ip6, port))
            self.assertEqual(state(dp), before)

    def test_08_invalid_multicast_ns_no_packet_out_or_barrier(self):
        for hop, code in ((64, 0), (255, 1)):
            ctl = make_controller(ready=False)
            ctl.data_plane.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
            before = state(ctl.data_plane)
            packet_in(ctl, make_raw_ns(hl=hop, code=code), 2)
            self.assertEqual(ctl.datapath.sent, [])
            self.assertFalse(ctl.pending_ndp_barriers)
            self.assertEqual(state(ctl.data_plane), before)

    def test_09_invalid_unicast_ns_cannot_fallthrough_to_host_learning(self):
        ctl = make_controller(ready=False)
        ctl.data_plane.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        before = state(ctl.data_plane)
        # A unicast Ethernet NS could otherwise fall through into regular
        # IPv6 host learning after DataPlane.handle_ndp rejected it.
        packet_in(ctl, make_raw_ns(hl=64, code=0, eth_dst=CFG.ROUTER_MAC,
                                    dest='2001:db8:23::3'), 2)
        self.assertEqual(state(ctl.data_plane), before)
        self.assertEqual(ctl.datapath.sent, [])

    def test_10_valid_ns_in_packetin_keeps_barrier_order(self):
        ctl = make_controller(ready=False)
        ctl.data_plane.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
        packet_in(ctl, make_raw_ns(), 2)
        self.assertEqual([m.kind for m in ctl.datapath.sent].count('barrier'), 1)
        self.assertEqual([m.kind for m in ctl.datapath.sent].count('packet_out'), 0)
        self.assertEqual(ctl.data_plane.lan_hosts[LAN_IP], LAN_MAC)

    def test_11_non_ns_icmp_and_echo_not_changed(self):
        dp = DataPlane()
        pkt, eth, ip6, port = make_ndp(icmp_type=128)
        self.assertIsNone(dp.handle_ndp(pkt, eth, ip6, port))
        self.assertFalse(dp.lan_hosts)
        # Normal IPv6 packets keep their historical mock Hop Limit 64.
        frame = ns(src=LAN_IP, dst='2001:db8:23::3', proto=6)
        self.assertEqual(FRAMES[frame].get_protocol(IP6).hop_limit, 64)

    def test_12_randomized_bad_ns_no_state_changes(self):
        r = random.Random(20261025)
        for _ in range(650):
            hop = r.choice([0, 1, 64, 128, 254, 255])
            code = r.choice([0, 1, 2, 99, 255])
            dp = DataPlane()
            pkt, eth, ip6, port = make_ndp()
            ip6.hop_limit = hop
            pkt.get_protocol(ICMP).code = code
            if hop != 255 or code != 0:
                before = state(dp)
                self.assertIsNone(dp.handle_ndp(pkt, eth, ip6, port))
                self.assertEqual(state(dp), before)
            else:
                self.assertIsInstance(dp.handle_ndp(pkt, eth, ip6, port), bytes)

    @unittest.skipUnless(importlib.util.find_spec('ryu'), 'real Ryu required')
    def test_13_real_ryu_packet_ns_validation(self):
        from dataplane import DataPlane as RealDataPlane
        from ryu.lib.packet import ethernet, ether_types, ipv6, icmpv6, packet
        for hop, code, valid in ((255, 0, True), (64, 0, False), (255, 1, False)):
            with self.subTest(hop=hop, code=code):
                frame = packet.Packet()
                frame.add_protocol(ethernet.ethernet(
                    src=LAN_MAC, dst='33:33:ff:00:00:01',
                    ethertype=ether_types.ETH_TYPE_IPV6))
                frame.add_protocol(ipv6.ipv6(
                    src=LAN_IP, dst='ff02::1:ff00:1', nxt=58, hop_limit=hop))
                frame.add_protocol(icmpv6.icmpv6(
                    type_=icmpv6.ND_NEIGHBOR_SOLICIT, code=code,
                    data=icmpv6.nd_neighbor(dst=CFG.LAN_GATEWAY)))
                frame.serialize()
                parsed = packet.Packet(bytes(frame.data))
                ip6 = parsed.get_protocol(ipv6.ipv6)
                icmp = parsed.get_protocol(icmpv6.icmpv6)
                self.assertEqual((ip6.hop_limit, icmp.code), (hop, code))
                dp = RealDataPlane()
                response = dp.handle_ndp(parsed, parsed.get_protocol(ethernet.ethernet), ip6, 2)
                self.assertEqual(isinstance(response, bytes), valid)
                self.assertEqual(bool(dp.lan_hosts), valid)

    def test_14_two_ndp_diagnostics_are_no_longer_expected_failures(self):
        source = (ROOT / 'tests/diagnose_b5_3_known_issues.py').read_text()
        tree = ast.parse(source)
        methods = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        for name in ('test_ndp_hop_limit_must_be_255', 'test_ndp_icmp_code_must_be_zero'):
            self.assertFalse(methods[name].decorator_list)
        # W02d: both first-packet forwarding diagnostics are repaired too.
        for name in ('test_tcp_first_packet_should_be_forwarded_when_route_known',
                     'test_udp_first_packet_should_be_forwarded_when_route_known'):
            self.assertFalse(methods[name].decorator_list)

if __name__ == '__main__':
    unittest.main()
