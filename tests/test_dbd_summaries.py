"""Focused DBD summary and retransmission tests for both logical routers."""

import logging
import unittest
from unittest.mock import patch

from scapy.contrib.ospf import OSPFv3_DBDesc, OSPFv3_Hdr, OSPFv3_LSA_Hdr, OSPFv3_LSReq_Item
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

import config as cfg
import packets
from peer import Peer


class DBDSummaryTests(unittest.TestCase):
    def test_local_headers_and_lsr_exchange(self):
        for router in cfg.SWITCHES.values():
            with self.subTest(router=router["router_id"]):
                sent = []
                peer = Peer(router, lambda data: sent.append(data) or True,
                            logging.getLogger("test-dbd"))
                peer.router_id = router["neighbor_id"]
                peer.interface_id = 3
                peer.address = "fe80::1"
                peer.mac = router["frr_mac"]
                peer.stage = "two-way"
                peer.local = packets.local_lsas(
                    router, peer.router_id, peer.interface_id)

                def remote_dbd(flags, sequence, headers=()):
                    desc = OSPFv3_DBDesc(
                        mtu=cfg.MTU, options=cfg.OPTIONS,
                        dbdescr=flags, ddseq=sequence,
                        lsaheaders=list(headers))
                    peer.on_dbd(desc, bytes(desc))

                def outgoing_dbd():
                    _, _, hdr, body = packets.decode(sent[-1], router)
                    self.assertEqual(hdr.type, 2)
                    return hdr.payload, body

                with patch("peer.time.time", return_value=1000):
                    remote_dbd(7, 123)
                initial, body = outgoing_dbd()
                self.assertEqual(initial.dbdescr, 7)
                self.assertEqual(initial.ddseq, peer.sequence)
                self.assertEqual(len(body), 12)
                self.assertEqual(len(initial.lsaheaders), 0)
                peer._retransmit_due_packets(peer.dbd_sent_at + cfg.RETRANSMIT_INTERVAL)
                self.assertEqual(sent[-1], sent[-2])

                # A summary of a newer self-originated LSA must be reflected
                # in the headers sent next, and in the eventual LSU body.
                old_seq = peer.local_sequence
                newer = OSPFv3_LSA_Hdr(next(iter(peer.local.values()))[:20])
                newer.seq = old_seq + 2
                remote_dbd(2, peer.sequence, [newer])
                advertised, body = outgoing_dbd()
                self.assertEqual(advertised.dbdescr, 1)
                self.assertEqual(advertised.ddseq, (initial.ddseq + 1) & 0xffffffff)
                self.assertEqual(peer.local_sequence, old_seq + 3)
                self.assertEqual(len(body), 12 + 3 * 20)
                headers = [OSPFv3_LSA_Hdr(body[i:i + 20])
                           for i in range(12, len(body), 20)]
                self.assertEqual(set(map(packets.lsa_key, headers)),
                                 set(peer.local))
                self.assertEqual([int(h.seq) for h in headers],
                                 [peer.local_sequence] * 3)
                self.assertEqual([body[i:i + 20] for i in range(12, len(body), 20)],
                                 [wire[:20] for wire in peer.local.values()])

                # Duplicate slave DBD retransmits the identical master packet.
                last = sent[-1]
                peer._retransmit_due_packets(peer.dbd_sent_at + cfg.RETRANSMIT_INTERVAL)
                self.assertEqual(sent[-1], last)
                remote_dbd(2, initial.ddseq, [newer])
                self.assertEqual(sent[-1], last)
                self.assertEqual(peer.sequence, advertised.ddseq)

                # An additional, genuinely new master DBD must not re-announce
                # the three headers; only the original packet is retransmitted.
                remote_dbd(2, peer.sequence)
                continued, body = outgoing_dbd()
                self.assertEqual(continued.dbdescr, 1)
                self.assertEqual(continued.ddseq, (advertised.ddseq + 1) & 0xffffffff)
                self.assertEqual(len(body), 12)

                remote_dbd(0, peer.sequence)
                self.assertEqual(peer.stage, "synchronized")
                self.assertEqual(peer.last_dbd, None)

                # FRR can request every advertised LSA, receiving complete LSU.
                sent.clear()
                requests = b"".join(
                    bytes(OSPFv3_LSReq_Item(type=key[0], id=key[1], adrouter=key[2]))
                    for key in peer.local)
                peer.on_lsr(requests)
                self.assertEqual(len(sent), 1)
                wire = bytes(Ether(sent[0])[IPv6].payload)
                hdr, body = OSPFv3_Hdr(wire), wire[16:]
                self.assertEqual(hdr.type, 4)
                self.assertEqual([wire for _, wire in packets.lsa_headers(body)],
                                 list(peer.local.values()))


if __name__ == "__main__":
    unittest.main()
