"""Stage08C: exact event-level regression for a shared OpenFlow rule definition.

The Stage08B controller is frozen, and old historical tests are left intact.
These tests compare complete OFPMatch, FlowMod, delete and PacketOut messages;
they do not consider fewer Python lines evidence of network equivalence.
"""

import hashlib
import logging
from pathlib import Path
import unittest

import b5_3_harness as h
from test_stage08b_openflow_cleanup import canonical, controller_class


ROOT = Path(__file__).resolve().parents[1]
CURRENT = ROOT / "controller_openflow.py"
REFERENCE = ROOT / "tests/_stage08c_openflow_reference.py"
OLD_08B_CONTRACT = ROOT / "tests/_stage08c_stage08b_contract_reference.py"
BEFORE = "09c2499e6a3edccb017c9c7006afd9cd80bb5a1bf7adc304585a205f43ed0d4c"
AFTER = "5a45925519d6544a2044a8df9f2bb481feeae1f91ce8c5101221dc2955400014"
OLD_CONTRACT = "c4e45dda919ec88b916aa4488b5b7921960e65cbe081dbd1d857a83cc31d4185"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_controller(path):
    klass = controller_class(path)
    ctl = klass.__new__(klass)
    ctl.logger = logging.getLogger("stage08c")
    ctl.datapath = h.Switch()
    ctl.data_plane = h.DataPlane()
    ctl.installed_ipv6_host_flows = {}
    return ctl


def install_pair(ctl):
    ctl.data_plane.learn_lan_host(2, h.LAN_IP, h.LAN_MAC)
    ctl.data_plane.learn_transit_router(1, h.TRANSIT_IP, h.TRANSIT_MAC)
    return ctl.try_install_ipv6_host_flows()


class Stage08COpenFlowContract(unittest.TestCase):
    def test_pinned_source_and_frozen_prior_contract(self):
        self.assertEqual(digest(CURRENT), AFTER)
        self.assertEqual(digest(REFERENCE), BEFORE)
        self.assertEqual(digest(OLD_08B_CONTRACT), OLD_CONTRACT)

    def test_guard_order_and_success_equivalent(self):
        current, frozen = make_controller(CURRENT), make_controller(REFERENCE)
        for ctl in (current, frozen):
            self.assertFalse(ctl.try_install_ipv6_host_flows())
            ctl.data_plane.learn_lan_host(2, h.LAN_IP, h.LAN_MAC)
            self.assertFalse(ctl.try_install_ipv6_host_flows())
            ctl.data_plane.learn_transit_router(1, h.TRANSIT_IP, h.TRANSIT_MAC)
            self.assertTrue(ctl.try_install_ipv6_host_flows())
            self.assertFalse(ctl.try_install_ipv6_host_flows())
        self.assertEqual(canonical(current.datapath.sent),
                         canonical(frozen.datapath.sent))

    def test_all_forward_and_reverse_match_action_events_equivalent(self):
        current, frozen = make_controller(CURRENT), make_controller(REFERENCE)
        for ctl in (current, frozen):
            self.assertTrue(install_pair(ctl))
            for index in range(1, 8):
                host = f"2001:db8:1::{100 + index}"
                mac = f"02:00:00:03:00:{index:02x}"
                self.assertTrue(ctl.data_plane.learn_lan_host(2, host, mac))
                self.assertTrue(ctl.try_install_ipv6_host_flows())
            self.assertFalse(ctl.try_install_ipv6_host_flows())
        self.assertEqual(canonical(current.datapath.sent),
                         canonical(frozen.datapath.sent))
        self.assertEqual(
            sum(m.priority == 110 for m in h.flowmods(current.datapath)), 64)
        self.assertEqual(
            sum(m.priority == 100 for m in h.flowmods(current.datapath)), 64)

    def test_transit_change_host_mac_change_and_strict_deletes_equivalent(self):
        current, frozen = make_controller(CURRENT), make_controller(REFERENCE)
        for ctl in (current, frozen):
            install_pair(ctl)
            ctl.data_plane.learn_transit_router(3, "fe80::3", "02:00:00:00:0a:03")
            self.assertTrue(ctl.try_install_ipv6_host_flows())
            self.assertTrue(ctl.data_plane.learn_lan_host(
                2, h.LAN_IP, "02:00:00:00:0b:01"))
            self.assertTrue(ctl.try_install_ipv6_host_flows())
            ctl.withdraw_all_ipv6_host_flows()
            self.assertFalse(ctl.installed_ipv6_host_flows)
        self.assertEqual(canonical(current.datapath.sent),
                         canonical(frozen.datapath.sent))
        strict = h.flowmods(current.datapath, h.OFP.OFPFC_DELETE_STRICT)
        self.assertEqual(len(strict), 48)

    def test_no_control_protocol_captured_by_data_rules(self):
        ctl = make_controller(CURRENT)
        self.assertTrue(install_pair(ctl))
        msgs = h.flowmods(ctl.datapath)
        self.assertEqual(len(msgs), 18)
        self.assertEqual([m.priority for m in msgs[:2]], [200, 190])
        for flow in msgs[2:]:
            match = vars(flow.match)
            self.assertIn(match["ip_proto"], (6, 17, 58))
            self.assertNotEqual(match["ip_proto"], 89)
            if match["ip_proto"] == 58:
                self.assertIn(match["icmpv6_type"], (1, 2, 3, 4, 128, 129))
                self.assertNotIn(match["icmpv6_type"], (133, 134, 135, 136, 137))
            self.assertEqual(len(flow.instructions[0].args[1]), 4)
        self.assertEqual(msgs[0].match.ipv6_dst, h.CFG.LAN_GATEWAY)
        self.assertEqual(msgs[1].match.ipv6_dst[0], "2001:db8:1::")

    def test_packetout_unchanged(self):
        current, frozen = make_controller(CURRENT), make_controller(REFERENCE)
        sent = []
        for ctl in (current, frozen):
            self.assertTrue(ctl.send_frame(b"ethernet-frame", 7))
            sent.append(canonical(ctl.datapath.sent))
            ctl.datapath = None
            self.assertFalse(ctl.send_frame(b"ethernet-frame", 7))
        self.assertEqual(*sent)


if __name__ == "__main__":
    unittest.main()
