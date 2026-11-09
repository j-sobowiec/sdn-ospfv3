"""Exercise the Ryu handlers with a tiny in-memory OpenFlow stand-in."""

import importlib
import logging
import sys
import types
import unittest
from unittest.mock import patch

import config as cfg


def fake_ryu_modules():
    def module(name, **fields):
        result = types.ModuleType(name)
        result.__dict__.update(fields)
        if name in ("ryu", "ryu.base", "ryu.controller", "ryu.lib",
                    "ryu.lib.packet", "ryu.ofproto"):
            result.__path__ = []
        return result

    class RyuApp:
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger("test-ryu")

    return {name: module(name, **attrs) for name, attrs in {
        "ryu": {}, "ryu.base": {}, "ryu.controller": {}, "ryu.lib": {},
        "ryu.lib.packet": {
            "ether_types": types.SimpleNamespace(ETH_TYPE_IPV6=0x86dd),
            "ethernet": object(), "icmpv6": object(), "ipv6": object(),
            "packet": object(),
        },
        "ryu.ofproto": {},
        "ryu.base.app_manager": {"RyuApp": RyuApp},
        "ryu.controller.ofp_event": {
            "EventOFPSwitchFeatures": object(), "EventOFPPacketIn": object(),
            "EventOFPStateChange": object(),
        },
        "ryu.controller.handler": {
            "CONFIG_DISPATCHER": "config", "MAIN_DISPATCHER": "main",
            "DEAD_DISPATCHER": "dead",
            "set_ev_cls": lambda *_args: lambda function: function,
        },
        "ryu.lib.hub": {"spawn": lambda _function: None},
        "ryu.ofproto.ofproto_v1_3": {"OFP_VERSION": 4},
    }.items()}


class FakeParser:
    def __getattr__(self, name):
        return lambda *args, **kwargs: (name, args, kwargs)


class FakeDatapath:
    def __init__(self, dpid):
        self.id = dpid
        self.messages = []
        self.ofproto_parser = FakeParser()
        self.ofproto = types.SimpleNamespace(
            OFPFC_DELETE=3, OFPP_ANY=0xffffffff, OFPG_ANY=0xffffffff,
            OFPIT_APPLY_ACTIONS=4, OFPP_CONTROLLER=0xfffffffd,
            OFPCML_NO_BUFFER=0xffff, OFP_NO_BUFFER=0xffffffff)

    def send_msg(self, message):
        self.messages.append(message)


def routes(datapath):
    return [msg[2] for msg in datapath.messages
            if msg[0] == "OFPFlowMod" and msg[2].get("priority") == 100]


def action_fields(flow):
    actions = flow["instructions"][0][1][1]
    return {key: value for action in actions if action[0] == "OFPActionSetField"
            for key, value in action[2].items()}


class ControllerIsolationTests(unittest.TestCase):
    def test_independent_flows_and_reconnection(self):
        with patch.dict(sys.modules, fake_ryu_modules()):
            sys.modules.pop("controller", None)
            try:
                controller_module = importlib.import_module("controller")
                app = controller_module.MinimalOSPFv3Controller()
                first, second = FakeDatapath(1), FakeDatapath(2)
                for dp in (first, second):
                    app.switch_ready(types.SimpleNamespace(
                        msg=types.SimpleNamespace(datapath=dp)))

                self.assertEqual(set(app.datapaths), {1, 2})
                self.assertIsNot(app.peers[1], app.peers[2])
                for dp in (first, second):
                    router = cfg.SWITCHES[dp.id]
                    self.assertEqual(app.peers[dp.id].router["router_id"],
                                     router["router_id"])
                    self.assertEqual(len(routes(dp)), 2)
                    matches = [flow["match"][2] for flow in routes(dp)]
                    self.assertTrue(any(m.get("ipv6_src") == router["lan_host"]
                                        for m in matches))
                    self.assertTrue(any(m.get("ipv6_dst") == router["lan_host"]
                                        for m in matches))
                    outbound, inbound = routes(dp)
                    self.assertEqual(action_fields(outbound), {
                        "eth_src": router["gateway_mac"],
                        "eth_dst": router["frr_mac"]})
                    self.assertEqual(action_fields(inbound), {
                        "eth_src": router["gateway_mac"],
                        "eth_dst": router["host_mac"]})
                    actions = [flow["instructions"][0][1][1]
                               for flow in routes(dp)]
                    self.assertTrue(all(any(a[0] == "OFPActionDecNwTtl"
                                            for a in route) for route in actions))
                    all_flows = [msg[2] for msg in dp.messages
                                 if msg[0] == "OFPFlowMod" and "priority" in msg[2]]
                    self.assertTrue(any(flow["priority"] == 300 and
                                        flow["match"][2].get("ip_proto") == 89
                                        for flow in all_flows))

                app.peers[1].stage = "synchronized"
                app.peers[2].stage = "synchronized"
                app.switch_disconnected(types.SimpleNamespace(datapath=first))
                self.assertNotIn(1, app.datapaths)
                self.assertIn(2, app.datapaths)
                replacement = FakeDatapath(1)
                app.switch_ready(types.SimpleNamespace(
                    msg=types.SimpleNamespace(datapath=replacement)))
                self.assertEqual(app.peers[1].stage, "down")
                self.assertEqual(app.peers[2].stage, "synchronized")
                self.assertEqual(len(routes(replacement)), 2)
                # A delayed disconnect for the previous connection is ignored.
                app.switch_disconnected(types.SimpleNamespace(datapath=first))
                self.assertIs(app.datapaths[1], replacement)
            finally:
                sys.modules.pop("controller", None)


if __name__ == "__main__":
    unittest.main()
