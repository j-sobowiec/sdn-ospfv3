"""Etap 01: NEW behavioural contract. Historical C01/M03/W02d stay untouched."""

import ast
from pathlib import Path
import unittest

import b5_3_harness as h


ROOT = Path(__file__).resolve().parents[1]


def active_flows(ctl, priority):
    return [
        msg for msg in h.flowmods(ctl.datapath)
        if getattr(msg, "command", None) is None and msg.priority == priority
    ]


def action_trace(flow):
    instruction = flow.instructions[0]
    return instruction.args[1]


class FlowContract(unittest.TestCase):
    def setUp(self):
        # The old SPF has zero remote routes on purpose. R1 owns forwarding.
        self.ctl = h.make_controller(route=False, ready=True)
        self.assertFalse(hasattr(self.ctl, "get_ospf_transit_routes"))
        self.assertTrue(self.ctl.install_ipv6_host_flows(h.LAN_IP, h.LAN_MAC))

    def test_exact_matches_priorities_and_output_ports(self):
        controller = active_flows(self.ctl, 200)
        local_lan = active_flows(self.ctl, 190)
        forward = active_flows(self.ctl, 110)
        reverse = active_flows(self.ctl, 100)
        self.assertEqual((len(controller), len(local_lan), len(forward), len(reverse)),
                         (1, 1, 8, 8))
        self.assertEqual(controller[0].match.ipv6_dst, h.CFG.LAN_GATEWAY)
        self.assertEqual(controller[0].match.in_port, 2)
        self.assertEqual(action_trace(controller[0])[0].args[0], h.OFP.OFPP_CONTROLLER)
        self.assertEqual(local_lan[0].match.ipv6_dst,
                         ("2001:db8:1::", "ffff:ffff:ffff:ffff::"))
        self.assertEqual(local_lan[0].match.eth_dst, h.CFG.ROUTER_MAC)
        self.assertEqual(action_trace(local_lan[0])[0].args[0],
                         h.OFP.OFPP_CONTROLLER)

        expected_keys = {(6, None), (17, None)} | {
            (58, n) for n in (1, 2, 3, 4, 128, 129)
        }
        self.assertEqual(
            {(m.match.ip_proto, getattr(m.match, "icmpv6_type", None)) for m in forward},
            expected_keys
        )
        self.assertEqual(
            {(m.match.ip_proto, getattr(m.match, "icmpv6_type", None)) for m in reverse},
            expected_keys
        )
        for flow in forward:
            match = flow.match
            self.assertEqual(match.in_port, 2)
            self.assertEqual(match.eth_type, 0x86dd)
            self.assertEqual(match.eth_dst, h.CFG.ROUTER_MAC)
            self.assertEqual(match.ipv6_src, h.LAN_IP)
            self.assertEqual(match.ipv6_dst, ("2000::", "e000::"))
            actions = action_trace(flow)
            self.assertEqual([a.kind for a in actions],
                             ["dec_ttl", "set_field", "set_field", "output"])
            self.assertEqual(actions[1].eth_src, h.CFG.ROUTER_MAC)
            self.assertEqual(actions[2].eth_dst, h.TRANSIT_MAC)
            self.assertEqual(actions[3].args[0], 1)

        for flow in reverse:
            match = flow.match
            self.assertEqual(match.in_port, 1)
            self.assertEqual(match.eth_type, 0x86dd)
            self.assertEqual(match.ipv6_dst, h.LAN_IP)
            actions = action_trace(flow)
            self.assertEqual([a.kind for a in actions],
                             ["dec_ttl", "set_field", "set_field", "output"])
            self.assertEqual(actions[1].eth_src, h.CFG.ROUTER_MAC)
            self.assertEqual(actions[2].eth_dst, h.LAN_MAC)
            self.assertEqual(actions[3].args[0], 2)

    def test_ospf_route_withdrawal_does_not_delete_dataplane_rule(self):
        self.ctl.datapath.sent.clear()
        self.ctl.ipv6_routing_table = {(h.ROUTE["prefix"], 64): dict(h.ROUTE)}
        self.assertFalse(self.ctl.install_ipv6_host_flows(h.LAN_IP, h.LAN_MAC))
        self.ctl.ipv6_routing_table.clear()
        self.assertFalse(self.ctl.install_ipv6_host_flows(h.LAN_IP, h.LAN_MAC))
        self.assertEqual(h.flowmods(self.ctl.datapath), [])

    def test_r1_failure_deletes_both_directions(self):
        self.ctl.datapath.sent.clear()
        self.ctl.withdraw_all_ipv6_host_flows()
        deletes = h.flowmods(self.ctl.datapath, h.OFP.OFPFC_DELETE_STRICT)
        self.assertEqual(len(deletes), 16)
        self.assertEqual(sum(f.priority == 110 for f in deletes), 8)
        self.assertEqual(sum(f.priority == 100 for f in deletes), 8)
        self.assertEqual(self.ctl.installed_ipv6_host_flows, {})
        self.ctl.datapath.sent.clear()
        self.ctl.withdraw_all_ipv6_host_flows()
        self.assertEqual(self.ctl.datapath.sent, [])

    def test_transit_mac_and_port_change_replace_not_accumulate(self):
        self.ctl.datapath.sent.clear()
        self.ctl.data_plane.learn_transit_router(3, "fe80::2", "02:aa:bb:cc:dd:ee")
        self.assertTrue(self.ctl.install_ipv6_host_flows(h.LAN_IP, h.LAN_MAC))
        self.assertEqual(len(h.flowmods(self.ctl.datapath, h.OFP.OFPFC_DELETE_STRICT)), 16)
        new_forward = active_flows(self.ctl, 110)
        self.assertEqual(len(new_forward), 8)
        self.assertTrue(all(action_trace(f)[-1].args[0] == 3 for f in new_forward))
        self.assertTrue(all(action_trace(f)[2].eth_dst == "02:aa:bb:cc:dd:ee"
                            for f in new_forward))

    def test_not_a_catchall_for_ndp_or_ospf(self):
        for msg in active_flows(self.ctl, 110) + active_flows(self.ctl, 100):
            proto = msg.match.ip_proto
            self.assertNotEqual(proto, 89)
            if proto == 58:
                self.assertNotIn(msg.match.icmpv6_type, (133, 134, 135, 136, 137))


class PacketInContract(unittest.TestCase):
    def setUp(self):
        self.ctl = h.make_controller(route=False, ready=True)

    def test_first_tcp_and_udp_packet_out_then_flowmods(self):
        for proto in (6, 17):
            with self.subTest(proto=proto):
                self.ctl = h.make_controller(route=False, ready=True)
                h.packet_in(self.ctl, h.ns(proto=proto))
                outs = [m for m in self.ctl.datapath.sent if m.kind == "packet_out"]
                self.assertEqual(len(outs), 1)
                self.assertEqual(outs[0].in_port, 2)
                self.assertEqual(
                    [a.kind for a in outs[0].actions],
                    ["dec_ttl", "set_field", "set_field", "output"]
                )
                self.assertEqual(outs[0].actions[-1].args[0], 1)
                self.assertTrue(active_flows(self.ctl, 110))
                # Subsequent packets are covered by OVS FlowMods, not by
                # software PacketOut; live OVS counters verify this separately.
                self.assertTrue(any(f.match.ip_proto == proto
                                    for f in active_flows(self.ctl, 110)))

    def test_first_echo_request_out_with_no_spf_route(self):
        h.packet_in(self.ctl, h.ns(proto=58, data=h.ICMP(type_=128)))
        outs = [m for m in self.ctl.datapath.sent if m.kind == "packet_out"]
        self.assertEqual(len(outs), 1)
        self.assertEqual(outs[0].actions[0].kind, "dec_ttl")

    def test_control_ndp_and_ospf_never_forwarded_to_r1(self):
        for proto, data in [(58, h.ICMP(type_=136)), (58, h.ICMP(type_=134)),
                            (89, None)]:
            with self.subTest(proto=proto, icmp_type=getattr(data, "type_", None)):
                self.ctl.datapath.sent.clear()
                h.packet_in(self.ctl, h.ns(proto=proto, data=data))
                self.assertFalse(any(
                    m.kind == "packet_out" and
                    any(a.kind == "dec_ttl" for a in m.actions)
                    for m in self.ctl.datapath.sent
                ))

    def test_valid_gateway_ns_stays_local_and_uses_barrier(self):
        packet = h.ns(dst="ff02::1:ff00:1",
                      proto=58,
                      data=h.ICMP(type_=135, data=h.ND(dst=h.CFG.LAN_GATEWAY)))
        h.packet_in(self.ctl, packet)
        self.assertTrue(any(m.kind == "barrier" for m in self.ctl.datapath.sent))
        self.assertFalse(any(
            m.kind == "packet_out" and any(a.kind == "dec_ttl" for a in m.actions)
            for m in self.ctl.datapath.sent
        ))

    def test_valid_gateway_echo_is_replied_locally(self):
        request = h.ns(dst=h.CFG.LAN_GATEWAY, proto=58,
                       data=h.ICMP(type_=128,
                                   data=h.Echo(id_=12, seq=1, data=b"test")))
        h.packet_in(self.ctl, request)
        outs = [m for m in self.ctl.datapath.sent if m.kind == "packet_out"]
        self.assertEqual(len(outs), 1)
        self.assertEqual([a.kind for a in outs[0].actions], ["output"])
        self.assertEqual(outs[0].actions[0].args[0], 2)

    def test_gateway_and_local_lan_excluded(self):
        for dst in (h.CFG.LAN_GATEWAY, "2001:db8:1::101", "fe80::2", "ff02::5"):
            with self.subTest(dst=dst):
                self.ctl.datapath.sent.clear()
                h.packet_in(self.ctl, h.ns(dst=dst, proto=6))
                self.assertFalse(any(m.kind == "packet_out"
                                     for m in self.ctl.datapath.sent))

    def test_missing_transit_never_emits_data_packet_out(self):
        self.ctl.data_plane.reset_transit()
        h.packet_in(self.ctl, h.ns(proto=6))
        self.assertFalse(any(m.kind == "packet_out"
                             for m in self.ctl.datapath.sent))


class LifecycleContract(unittest.TestCase):
    def test_neighbor_dead_withdrawal_before_transit_reset(self):
        path = ROOT / "ospfv3/controller_timers.py"
        tree = ast.parse(path.read_text(encoding="utf8"))
        functions = [n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef) and n.name == "neighbor_dead_loop"]
        self.assertEqual(len(functions), 1)
        calls = [n for n in ast.walk(functions[0])
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        withdraw = [n.lineno for n in calls
                    if n.func.attr == "withdraw_all_ipv6_host_flows"]
        reset = [n.lineno for n in calls if n.func.attr == "reset_transit"]
        self.assertEqual(len(withdraw), 1)
        self.assertEqual(len(reset), 1)
        self.assertLess(withdraw[0], reset[0])

    def test_spf_lsdb_and_neighbor_still_exist(self):
        source = (ROOT / "ryu_sdn.py").read_text(encoding="utf8")
        for token in ("LSDB(self.logger)", "Neighbor(self.logger)"):
            self.assertIn(token, source)
        self.assertNotIn("Routing(self.lsdb)", source)
        self.assertNotIn("build_ipv6_routing_table()", source)


if __name__ == "__main__":
    unittest.main()
