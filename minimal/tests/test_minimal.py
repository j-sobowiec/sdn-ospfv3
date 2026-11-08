"""Protocol unit tests; do not need network namespaces or raw sockets."""

import logging
import unittest

# Suppress Scapy's interface/route autodiscovery in restricted test runners.
# Real controller execution does not use this test-only setup.
import scapy.config
scapy.config.conf.route_autoload = False
scapy.config.conf.route6_autoload = False
scapy.config._set_conf_sockets = lambda: None

from scapy.contrib.ospf import (OSPFv3_DBDesc, OSPFv3_Hdr, OSPFv3_Hello,
                                OSPFv3_LSA_Hdr, OSPFv3_Router_LSA)
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from minimal import config as cfg, packets
from minimal.peer import Peer


PEER_ID = "1.1.1.1"
PEER_IP = "fe80::1"


def incoming(kind, body, destination=cfg.LINK_LOCAL, hop_limit=1):
    return bytes(Ether(src=cfg.FRR_MAC, dst=cfg.GATEWAY_MAC) /
                 IPv6(src=PEER_IP, dst=destination, nh=89, hlim=hop_limit) /
                 OSPFv3_Hdr(type=kind, src=PEER_ID, area=cfg.AREA_ID) / body)


def remote_router_lsa():
    return bytes(OSPFv3_Router_LSA(
        age=0, type=0x2001, id="0.0.0.0", adrouter=PEER_ID,
        seq=cfg.LSA_INITIAL_SEQ, flags=0, options=cfg.OPTIONS, linklist=[]))


class WireTests(unittest.TestCase):
    def test_wire_builders_match_previous_scapy_implementation(self):
        from ospfv3 import packet as previous

        lsas = packets.local_lsas(PEER_ID, 17)
        router = lsas[(0x2001, "0.0.0.0", cfg.ROUTER_ID)]
        requests = [{"ls_type": 0x2001, "link_state_id": "0.0.0.0",
                     "advertising_router": PEER_ID}]
        comparisons = [
            (packets.hello([PEER_ID]),
             previous.build_ospfv3_hello_frame([PEER_ID])),
            (packets.dbd(12, 7), previous.build_ospfv3_dbd_frame(12, 7)),
            (packets.lsr([(0x2001, "0.0.0.0", PEER_ID)], PEER_IP, cfg.FRR_MAC),
             previous.build_ospfv3_lsr_frame(requests, PEER_IP, cfg.FRR_MAC)),
            (packets.lsu(list(lsas.values()), PEER_IP, cfg.FRR_MAC),
             previous.build_ospfv3_lsu_frame(
                 previous.encode_ospfv3_lsu_body(lsas.values()),
                 PEER_IP, cfg.FRR_MAC)),
            (packets.lsack([router[:20]], PEER_IP, cfg.FRR_MAC),
             previous.build_ospfv3_lsack_frame(
                 [{"raw_header": router[:20]}], PEER_IP, cfg.FRR_MAC)),
        ]
        for newer, older in comparisons:
            self.assertEqual(newer, older)

    def test_scapy_local_lsas_have_valid_checksums_and_types(self):
        lsas = packets.local_lsas(PEER_ID, 17)
        self.assertEqual({k[0] for k in lsas}, {0x2001, 0x0008, 0x2009})
        decoded = packets.lsa_headers(
            len(lsas).to_bytes(4, "big") + b"".join(lsas.values()))
        self.assertEqual(len(decoded), 3)
        self.assertEqual(int.from_bytes(lsas[(0x2001, "0.0.0.0", cfg.ROUTER_ID)][32:36],
                                        "big"), 17)

    def test_decode_five_valid_packet_types(self):
        lsa = remote_router_lsa()
        frames = [
            incoming(1, OSPFv3_Hello(intid=2, hellointerval=10,
                                     deadinterval=40, neighbors=[cfg.ROUTER_ID])),
            incoming(2, OSPFv3_DBDesc(mtu=1500, ddseq=8)),
            incoming(3, packets.OSPFv3_LSReq(
                requests=[packets.OSPFv3_LSReq_Item(
                    type=0x2001, id="0.0.0.0", adrouter=cfg.ROUTER_ID)])),
            incoming(4, packets.OSPFv3_LSUpd(lsacount=1) / packets.Raw(lsa)),
            incoming(5, packets.OSPFv3_LSAck(
                lsaheaders=[OSPFv3_LSA_Hdr(lsa[:20])])),
        ]
        self.assertEqual([packets.decode(frame)[2].type for frame in frames],
                         [1, 2, 3, 4, 5])

    def test_lsack_unicast_hop_limit_64_is_valid_but_multicast_is_not(self):
        lsa = remote_router_lsa()
        ack = packets.OSPFv3_LSAck(lsaheaders=[OSPFv3_LSA_Hdr(lsa[:20])])
        self.assertEqual(packets.decode(incoming(5, ack, hop_limit=64))[2].type, 5)
        with self.assertRaisesRegex(ValueError, "Hop Limit"):
            packets.decode(incoming(5, ack, destination=packets.ALL_ROUTERS,
                                    hop_limit=64))

    def test_truncated_and_corrupted_packets_rejected(self):
        lsa = remote_router_lsa()
        frame = incoming(4, packets.OSPFv3_LSUpd(lsacount=1) / packets.Raw(lsa))
        bad = bytearray(frame)
        bad[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum"):
            packets.decode(bytes(bad))
        with self.assertRaises(ValueError):
            packets.decode(frame[:-1])
        invalid = bytearray(packets.lsu([lsa], cfg.LINK_LOCAL, cfg.FRR_MAC))
        invalid[-1] ^= 1
        # The OSPFv3 header checksum must be repaired before the LSA check is reached.
        with self.assertRaisesRegex(ValueError, "checksum"):
            packets.decode(bytes(invalid))


class PeerTests(unittest.TestCase):
    def setUp(self):
        self.now = [100]
        self.sent = []
        self.peer = Peer(lambda data: self.sent.append(data) or True,
                         logging.getLogger("test-minimal"),
                         clock=lambda: self.now[0])

    def hello(self, neighbors=(), interval=10):
        self.peer.receive(incoming(1, OSPFv3_Hello(
            intid=17, hellointerval=interval, deadinterval=40,
            neighbors=list(neighbors))))

    def negotiate(self, with_requests=True):
        self.hello()
        self.hello([cfg.ROUTER_ID])
        self.assertEqual(self.peer.interface_id, 17)
        self.peer.receive(incoming(2, OSPFv3_DBDesc(
            mtu=1500, dbdescr=7, ddseq=9)))
        seq = self.peer.sequence
        lsa = remote_router_lsa()
        headers = [OSPFv3_LSA_Hdr(lsa[:20])] if with_requests else []
        self.peer.receive(incoming(2, OSPFv3_DBDesc(
            mtu=1500, dbdescr=0, ddseq=seq, lsaheaders=headers)))
        self.peer.receive(incoming(2, OSPFv3_DBDesc(
            mtu=1500, dbdescr=0, ddseq=seq + 1)))
        return lsa

    def test_actual_exchange_requests_ack_and_local_lsa(self):
        lsa = self.negotiate()
        self.assertEqual(self.peer.stage, "loading")
        self.assertEqual(len(self.peer.requests), 1)
        self.peer.receive(incoming(4, packets.OSPFv3_LSUpd(lsacount=1)
                                   / packets.Raw(lsa)))
        self.assertEqual(self.peer.stage, "synchronized")
        self.assertEqual(len(self.peer.pending_acks), 3)
        self.assertEqual(Ether(self.sent[-1])[IPv6].payload.type, 4)
        self.peer.receive(incoming(5, packets.OSPFv3_LSAck(lsaheaders=[
            OSPFv3_LSA_Hdr(wire[:20]) for wire in self.peer.local.values()])))
        self.assertEqual(self.peer.pending_acks, {})

    def test_unicast_lsack_after_restart_clears_retransmit_queue(self):
        lsa = self.negotiate()
        self.peer.receive(incoming(4, packets.OSPFv3_LSUpd(lsacount=1)
                                   / packets.Raw(lsa)))
        self.assertEqual(len(self.peer.pending_acks), 3)
        self.peer.receive(incoming(5, packets.OSPFv3_LSAck(lsaheaders=[
            OSPFv3_LSA_Hdr(wire[:20]) for wire in self.peer.local.values()]),
            hop_limit=64))
        self.assertEqual(self.peer.pending_acks, {})
        before = len(self.sent)
        self.now[0] += cfg.RETRANSMIT_INTERVAL + 1
        self.peer.tick()
        self.assertEqual(len([frame for frame in self.sent[before:]
                              if Ether(frame)[IPv6].payload.type == 4]), 0)

    def test_restart_bumps_sequences_from_peer_dbd_summaries(self):
        self.hello()
        self.hello([cfg.ROUTER_ID])
        old = packets.local_lsas(PEER_ID, 17, cfg.LSA_INITIAL_SEQ + 2)
        self.peer.receive(incoming(2, OSPFv3_DBDesc(
            mtu=1500, dbdescr=7, ddseq=9)))
        seq = self.peer.sequence
        self.peer.receive(incoming(2, OSPFv3_DBDesc(
            mtu=1500, dbdescr=0, ddseq=seq,
            lsaheaders=[OSPFv3_LSA_Hdr(wire[:20]) for wire in old.values()])))
        self.peer.receive(incoming(2, OSPFv3_DBDesc(
            mtu=1500, dbdescr=0, ddseq=seq + 1)))
        self.assertEqual(self.peer.stage, "synchronized")
        self.assertEqual(self.peer.local_sequence, cfg.LSA_INITIAL_SEQ + 3)
        self.assertEqual({int(OSPFv3_LSA_Hdr(wire[:20]).seq)
                          for wire in self.peer.local.values()},
                         {cfg.LSA_INITIAL_SEQ + 3})

    def test_no_remote_lsa_still_announces_prefix(self):
        self.negotiate(with_requests=False)
        self.assertEqual(self.peer.stage, "synchronized")
        self.assertEqual(len(self.peer.local), 3)

    def test_hello_validation_dead_timeout_and_retransmission(self):
        self.hello(interval=8)
        self.assertEqual(self.peer.stage, "down")
        self.hello()
        self.hello([cfg.ROUTER_ID])
        self.peer.receive(incoming(2, OSPFv3_DBDesc(
            mtu=1500, dbdescr=7, ddseq=9)))
        before = len(self.sent)
        self.now[0] += cfg.RETRANSMIT_INTERVAL + 1
        self.peer.tick()
        self.assertGreater(len(self.sent), before)
        self.now[0] += cfg.DEAD_INTERVAL
        self.peer.tick()
        self.assertEqual(self.peer.stage, "down")


if __name__ == "__main__":
    unittest.main()
