"""Small protocol checks; no network namespaces or FRRouting required."""

import ipaddress
import logging
import unittest
from unittest.mock import Mock

from scapy.contrib.ospf import (OSPFv3_Intra_Area_Prefix_LSA,
                                OSPFv3_Link_LSA, OSPFv3_Router_LSA)

import config as cfg
import packets
from peer import Peer


class MultiRouterProtocolTests(unittest.TestCase):
    def test_distinct_router_configuration(self):
        self.assertEqual(set(cfg.SWITCHES), {1, 2})
        self.assertEqual(cfg.SWITCHES[2]["router_id"], "11.11.11.11")
        self.assertEqual(cfg.SWITCHES[2]["lan_prefix"], "2001:db8:2::/64")
        self.assertEqual(cfg.SWITCHES[2]["lan_host"], "2001:db8:2::100")
        for field in ("router_id", "neighbor_id", "interface_id", "gateway_mac", "frr_mac",
                      "host_mac", "link_local", "lan_prefix", "transit_prefix",
                      "lan_gateway", "lan_host"):
            self.assertNotEqual(cfg.SWITCHES[1][field], cfg.SWITCHES[2][field])
        for router in cfg.SWITCHES.values():
            self.assertEqual((router["transit_port"], router["lan_port"]), (1, 2))
            self.assertIn(ipaddress.IPv6Address(router["lan_host"]),
                          ipaddress.IPv6Network(router["lan_prefix"]))

    def test_hello_and_lsas_have_per_dpid_identity(self):
        for router in cfg.SWITCHES.values():
            eth, ip, hdr, _ = packets.decode(packets.hello(router), router)
            self.assertEqual(hdr.src, router["router_id"])
            self.assertEqual(eth.src, router["gateway_mac"])
            self.assertEqual(ip.src, router["link_local"])
            self.assertEqual(hdr.payload.intid, router["interface_id"])

            lsas = packets.local_lsas(router, "1.1.1.1", 3)
            self.assertEqual(len(lsas), 3)
            self.assertTrue(all(key[2] == router["router_id"] for key in lsas))
            router_lsa = next(OSPFv3_Router_LSA(wire) for key, wire in lsas.items()
                              if key[0] == 0x2001)
            link_lsa = next(OSPFv3_Link_LSA(wire) for key, wire in lsas.items()
                            if key[0] == 0x0008)
            prefix_lsa = next(OSPFv3_Intra_Area_Prefix_LSA(wire)
                              for key, wire in lsas.items() if key[0] == 0x2009)
            self.assertEqual(router_lsa.linklist[0].intid, router["interface_id"])
            self.assertEqual(link_lsa.lladdr, router["link_local"])
            self.assertEqual(ipaddress.IPv6Network(prefix_lsa.prefixlist[0].prefix),
                ipaddress.IPv6Network(router["lan_prefix"]))

    def test_one_peers_reset_does_not_reset_the_other(self):
        peers = {}
        for dpid, router in cfg.SWITCHES.items():
            peers[dpid] = Peer(router, lambda _data: True,
                               logging.getLogger("test"))
            impostor = dict(router, router_id="9.9.9.9",
                            gateway_mac=router["frr_mac"], link_local="fe80::9")
            with self.assertLogs("test", level="WARNING"):
                peers[dpid].receive(packets.hello(impostor, [router["router_id"]]))
            self.assertEqual(peers[dpid].stage, "down")
            frr = dict(router, router_id=router["neighbor_id"],
                       gateway_mac=router["frr_mac"], link_local=f"fe80::{dpid}")
            peers[dpid].receive(packets.hello(frr, [router["router_id"]]))
            self.assertEqual(peers[dpid].stage, "two-way")
            self.assertEqual(len(peers[dpid].local), 3)

        peers[1].reset()
        self.assertEqual(peers[1].stage, "down")
        self.assertEqual(peers[2].stage, "two-way")
        self.assertEqual(peers[2].router_id, "2.2.2.2")

    def test_periodic_hello_is_silent_but_adjacency_is_info(self):
        router = cfg.SWITCHES[1]
        peer = Peer(router, lambda _data: True,
                    logging.getLogger("test-quiet-hello"), label="S1")
        frr = dict(router, router_id=router["neighbor_id"],
                   gateway_mac=router["frr_mac"], link_local="fe80::1")
        with self.assertLogs("test-quiet-hello", level="DEBUG") as messages:
            peer.tick()  # periodic Hello TX
            peer.receive(packets.hello(frr, [router["router_id"]]))
        info = [message for message in messages.output
                if message.startswith("INFO:")]
        self.assertEqual(len(info), 2)
        self.assertEqual(len(messages.output), 2)  # no packet-level DEBUG
        self.assertIn("[OSPF][S1] Hello: discovered neighbor 1.1.1.1", info[0])
        self.assertIn("[OSPF][S1] neighbor 1.1.1.1: Init -> 2-Way", info[1])

    def test_early_dbd_is_ignored_without_logging(self):
        router = cfg.SWITCHES[2]
        logger = Mock()
        peer = Peer(router, lambda _data: True, logger, label="S2")
        frr = dict(router, router_id=router["neighbor_id"],
                   gateway_mac=router["frr_mac"], link_local="fe80::2")
        peer.receive(packets.dbd(frr, 123, 7))
        self.assertEqual(peer.stage, "down")
        logger.debug.assert_not_called()
        logger.info.assert_not_called()
        logger.warning.assert_not_called()

    def test_lsa_advertisement_and_ack_are_logged_once(self):
        router = cfg.SWITCHES[2]
        peer = Peer(router, lambda _data: True,
                    logging.getLogger("test-ospf-milestones"), label="S2")
        peer.router_id = router["neighbor_id"]
        peer.interface_id = 123
        peer.address = "fe80::2"
        peer.mac = router["frr_mac"]
        peer.local = packets.local_lsas(router, peer.router_id, peer.interface_id)
        peer.stage = "loading"
        headers = b"".join(lsa[:20] for lsa in peer.local.values())

        with self.assertLogs("test-ospf-milestones", level="INFO") as messages:
            peer.finish_loading()
            peer.finish_loading()  # not a new state transition
            peer.on_lsack(headers)
            peer.on_lsack(headers)  # repeated ACK should not log INFO

        self.assertEqual(len(messages.output), 3)
        self.assertIn("advertised 3 local LSAs", messages.output[0])
        self.assertIn("LSDB synchronized", messages.output[1])
        self.assertIn("local LSAs acknowledged", messages.output[2])


if __name__ == "__main__":
    unittest.main()
