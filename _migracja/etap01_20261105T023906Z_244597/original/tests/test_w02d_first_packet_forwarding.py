"""W02d: first TCP/UDP packet forwarding, exact OF1.3 actions and no regressions.

Production PacketIn is executed via the historical B5.3 AST harness and, on
Ubuntu, using the installed Ryu packet decoder without launching controller
threads. No router or switch is needed for these tests.
"""
import ast
import copy
import importlib.util
import ipaddress
import random
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from b5_3_harness import (CFG, LAN_IP, LAN_MAC, TRANSIT_IP, TRANSIT_MAC,
                          ROUTE, FRAMES, Pkt, IP6, make_controller, packet_in,
                          ns, incoming, Ether, ICMP, ND, OFP)
from _w02d_packetin_reference import ORIGINAL_PACKET_IN
from test_w02a_ndp_validation import make_raw_ns

ROOT = Path(__file__).resolve().parents[1]


def production_method():
    tree = ast.parse((ROOT / 'ryu_sdn.py').read_text(encoding='utf8'))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef)
               and n.name == 'OSPFv3Controller')
    return next(n for n in cls.body if isinstance(n, ast.FunctionDef)
                and n.name == 'packet_in_handler')


def prepare(proto, *, dst='2001:db8:23::3', src=LAN_IP,
            eth_dst=None, route=True, next_hop=True):
    ctl = make_controller(ready=False, route=route)
    if next_hop:
        ctl.data_plane.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
    frame = ns(src=src, dst=dst, proto=proto,
               eth_dst=eth_dst or CFG.ROUTER_MAC)
    return ctl, frame


def packetouts(ctl):
    return [x for x in ctl.datapath.sent if x.kind == 'packet_out']


class TestW02DFirstPacket(unittest.TestCase):
    def test_01_exact_moved_forwarding_branch_and_other_methods_unchanged(self):
        old_tree = ast.parse('class X:\n' + ORIGINAL_PACKET_IN)
        old = old_tree.body[0].body[0]
        new = production_method()
        self.assertEqual(ast.dump(old.args, include_attributes=False),
                         ast.dump(new.args, include_attributes=False))
        original_icmp = next(x for x in old.body if isinstance(x, ast.If)
                             and 'ipv6_pkt.nxt == 58' in ast.unparse(x.test))
        current_icmp = next(x for x in new.body if isinstance(x, ast.If)
                             and 'ipv6_pkt.nxt == 58' in ast.unparse(x.test))
        original_body = next(x for x in original_icmp.body if isinstance(x, ast.If)
                             and 'eth_pkt.dst == cfg.ROUTER_MAC' in ast.unparse(x.test))
        moved_body = next(x for x in new.body if isinstance(x, ast.If)
                          and 'eth_pkt.dst == cfg.ROUTER_MAC' in ast.unparse(x.test))
        self.assertEqual(ast.dump(ast.Module(original_body.body, []), include_attributes=False),
                         ast.dump(ast.Module(moved_body.body, []), include_attributes=False))
        self.assertIn('ipv6_pkt.nxt in (6, 17, 58)', ast.unparse(moved_body.test))
        self.assertEqual(len(old.body), len(new.body) - 1)

    def test_02_old_reference_cannot_forward_tcp_udp(self):
        self.assertIn('if ipv6_pkt and ipv6_pkt.nxt == 58:', ORIGINAL_PACKET_IN)
        self.assertIn('ipv6_pkt.nxt != 89', ORIGINAL_PACKET_IN)
        self.assertNotIn('ipv6_pkt.nxt in (6, 17, 58)', ORIGINAL_PACKET_IN)

    def test_03_first_tcp_packet_is_sent(self):
        ctl, frame = prepare(6)
        packet_in(ctl, frame)
        self.assertEqual(len(packetouts(ctl)), 1)
        self.assertEqual(ctl.data_plane.lan_hosts[LAN_IP], LAN_MAC)

    def test_04_first_udp_packet_is_sent(self):
        ctl, frame = prepare(17)
        packet_in(ctl, frame)
        self.assertEqual(len(packetouts(ctl)), 1)
        self.assertEqual(ctl.data_plane.lan_hosts[LAN_IP], LAN_MAC)

    def test_05_raw_first_packet_data_not_mutated(self):
        for proto in (6, 17, 58):
            with self.subTest(proto=proto):
                ctl, frame = prepare(proto)
                packet_in(ctl, frame)
                self.assertEqual(packetouts(ctl)[0].data, frame)
                self.assertEqual(packetouts(ctl)[0].buffer_id, OFP.OFP_NO_BUFFER)
                self.assertEqual(packetouts(ctl)[0].in_port, 2)

    def test_06_exact_openflow_action_order(self):
        for proto in (6, 17):
            ctl, frame = prepare(proto)
            packet_in(ctl, frame)
            actions = packetouts(ctl)[0].actions
            self.assertEqual([a.kind for a in actions],
                             ['dec_ttl', 'set_field', 'set_field', 'output'])
            self.assertEqual(actions[1].eth_src, CFG.ROUTER_MAC)
            self.assertEqual(actions[2].eth_dst, TRANSIT_MAC)
            self.assertEqual(actions[3].args[0], 1)

    def test_07_flowmods_precede_first_packet_packetout(self):
        for proto in (6, 17):
            ctl, frame = prepare(proto)
            packet_in(ctl, frame)
            sent = [m.kind for m in ctl.datapath.sent]
            self.assertEqual(sent[-1], 'packet_out')
            self.assertGreaterEqual(sent.count('flow'), 2)
            self.assertFalse(any(x.kind == 'barrier' for x in ctl.datapath.sent))

    def test_08_existing_flow_cache_still_emits_packetout(self):
        ctl, frame = prepare(6)
        packet_in(ctl, frame)
        ctl.datapath.sent.clear()
        packet_in(ctl, frame)
        self.assertEqual([m.kind for m in ctl.datapath.sent], ['packet_out'])

    def test_09_unknown_route_does_not_forward(self):
        for proto in (6, 17):
            ctl, frame = prepare(proto, route=False)
            packet_in(ctl, frame)
            self.assertFalse(packetouts(ctl))
            self.assertEqual(ctl.data_plane.lan_hosts[LAN_IP], LAN_MAC)

    def test_10_missing_transit_next_hop_does_not_forward(self):
        for proto in (6, 17):
            ctl, frame = prepare(proto, next_hop=False)
            packet_in(ctl, frame)
            self.assertFalse(packetouts(ctl))
            self.assertEqual(ctl.data_plane.lan_hosts[LAN_IP], LAN_MAC)

    def test_11_not_addressed_to_router_does_not_learn(self):
        for proto in (6, 17):
            ctl, frame = prepare(proto, eth_dst='02:00:00:00:00:ff')
            packet_in(ctl, frame)
            self.assertFalse(packetouts(ctl))
            self.assertFalse(ctl.data_plane.lan_hosts)

    def test_12_outside_lan_source_does_not_forward(self):
        for proto in (6, 17):
            ctl, frame = prepare(proto, src='2001:db8:bb::2')
            packet_in(ctl, frame)
            self.assertFalse(packetouts(ctl))
            self.assertFalse(ctl.data_plane.lan_hosts)

    def test_13_transit_input_port_cannot_spoof_lan_host(self):
        for proto in (6, 17):
            ctl, frame = prepare(proto)
            packet_in(ctl, frame, 1)
            self.assertFalse(packetouts(ctl))
            self.assertFalse(ctl.data_plane.lan_hosts)

    def test_14_longest_prefix_match_kept(self):
        for proto in (6, 17):
            ctl, frame = prepare(proto)
            other = dict(ROUTE, prefix='2001:db8::', prefix_length=32, next_hop='old')
            best = dict(ROUTE, prefix='2001:db8:23::', prefix_length=64, next_hop='chosen')
            ctl.ipv6_routing_table = {'x': other, 'y': best}
            with self.assertLogs('B5_3', level='INFO') as captured:
                packet_in(ctl, frame)
            self.assertTrue(any('via=chosen' in x for x in captured.output))
            self.assertEqual(len(packetouts(ctl)), 1)

    def test_15_non_ipv6_next_header_not_modified(self):
        for proto in (0, 59, 88, 90, 255):
            ctl, frame = prepare(proto)
            packet_in(ctl, frame)
            self.assertFalse(packetouts(ctl))
            self.assertFalse(ctl.data_plane.lan_hosts)

    def test_16_ospf_protocol_89_still_not_host_forwarded(self):
        ctl, frame = prepare(89)
        packet_in(ctl, frame)
        self.assertFalse(packetouts(ctl))
        self.assertFalse(ctl.data_plane.lan_hosts)

    def test_17_invalid_ns_still_cannot_learn_or_forward(self):
        for hop, code in ((64, 0), (255, 1), (0, 9)):
            ctl, _ = prepare(58)
            packet_in(ctl, make_raw_ns(hl=hop, code=code,
                                      eth_dst=CFG.ROUTER_MAC,
                                      dest='2001:db8:23::3'))
            self.assertFalse(packetouts(ctl))
            self.assertFalse(ctl.data_plane.lan_hosts)

    def test_18_valid_neighbor_solicitation_barrier_unchanged(self):
        ctl, _ = prepare(58)
        packet_in(ctl, make_raw_ns())
        self.assertEqual([x.kind for x in ctl.datapath.sent].count('barrier'), 1)
        self.assertEqual(len(packetouts(ctl)), 0)

    def test_19_icmpv6_generic_first_packet_still_forwarded(self):
        ctl, frame = prepare(58)
        packet_in(ctl, frame)
        self.assertEqual(len(packetouts(ctl)), 1)

    def test_20_randomized_tcp_udp_matrix(self):
        rng = random.Random(20261025)
        for _ in range(800):
            proto = rng.choice((6, 17))
            matched = rng.choice((True, False))
            next_hop = rng.choice((True, False))
            to_router = rng.choice((True, False))
            from_lan = rng.choice((True, False))
            ctl, frame = prepare(proto, route=matched, next_hop=next_hop,
                                 eth_dst=CFG.ROUTER_MAC if to_router
                                           else '02:00:00:00:00:ff',
                                 src=LAN_IP if from_lan else '2001:db8:99::1')
            packet_in(ctl, frame)
            expected = matched and next_hop and to_router and from_lan
            self.assertEqual(len(packetouts(ctl)), int(expected))
            self.assertEqual(LAN_IP in ctl.data_plane.lan_hosts,
                             to_router and from_lan)

    @unittest.skipUnless(importlib.util.find_spec('ryu'), 'real Ryu needed on Ubuntu')
    def test_21_real_ryu_packet_in_with_serialized_tcp_udp(self):
        from ryu.lib.packet import ethernet, ether_types, ipv6, packet, tcp, udp
        from ryu_sdn import OSPFv3Controller
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                pkt = packet.Packet()
                pkt.add_protocol(ethernet.ethernet(src=LAN_MAC, dst=CFG.ROUTER_MAC,
                                                   ethertype=ether_types.ETH_TYPE_IPV6))
                pkt.add_protocol(ipv6.ipv6(src=LAN_IP, dst='2001:db8:23::3',
                                           nxt=protocol, hop_limit=64))
                if protocol == 6:
                    pkt.add_protocol(tcp.tcp(src_port=11234, dst_port=443,
                                             bits=2, seq=100))
                else:
                    pkt.add_protocol(udp.udp(src_port=11234, dst_port=5353))
                pkt.serialize()
                raw = bytes(pkt.data)
                decoded = packet.Packet(raw)
                self.assertEqual(decoded.get_protocol(ipv6.ipv6).nxt, protocol)
                ctl = make_controller(ready=False)
                ctl.data_plane.learn_transit_router(1, TRANSIT_IP, TRANSIT_MAC)
                ev = SimpleNamespace(msg=SimpleNamespace(data=raw, match={'in_port': 2},
                                                        datapath=ctl.datapath))
                OSPFv3Controller.packet_in_handler(ctl, ev)
                self.assertEqual(len(packetouts(ctl)), 1)
                self.assertEqual(packetouts(ctl)[0].data, raw)
                self.assertEqual([a.kind for a in packetouts(ctl)[0].actions],
                                 ['dec_ttl', 'set_field', 'set_field', 'output'])

    def test_22_both_diagnostics_now_regular_tests(self):
        tree = ast.parse((ROOT / 'tests/diagnose_b5_3_known_issues.py').read_text())
        methods = {node.name: node for node in ast.walk(tree)
                   if isinstance(node, ast.FunctionDef)}
        for name in ('test_tcp_first_packet_should_be_forwarded_when_route_known',
                     'test_udp_first_packet_should_be_forwarded_when_route_known'):
            self.assertFalse(methods[name].decorator_list)
        from diagnose_b5_3_known_issues import TestKnownIssues
        for name in ('test_tcp_first_packet_should_be_forwarded_when_route_known',
                     'test_udp_first_packet_should_be_forwarded_when_route_known'):
            inst = TestKnownIssues(name)
            getattr(inst, name)()


if __name__ == '__main__':
    unittest.main()
