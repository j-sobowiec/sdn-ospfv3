"""Minimal OSPFv3 Hello/DBD/LSR/LSU/LSAck transmission and retransmission."""

import struct
import time

from ospfv3.lsa import ospfv3_lsa_type_description
from ospfv3.packet import (build_ospfv3_hello_frame, build_ospfv3_dbd_frame,
                           build_ospfv3_lsr_frame, build_ospfv3_lsu_frame,
                           build_ospfv3_lsack_frame)


class OSPFTransmitMixin:
    def send_ospfv3_hello(self, neighbors=None):
        if self.neighbor.port is None:
            return
        if neighbors is None:
            neighbors = self.neighbor.router_ids
        frame = build_ospfv3_hello_frame(neighbors)
        if not self.send_frame(frame, self.neighbor.port):
            return
        self.logger.info("[OSPF][HELLO TX] port=%s neighbors=%s",
                         self.neighbor.port, neighbors)

    def _ospf_unicast_ready(self):
        return (self.neighbor.port is not None
                and self.neighbor.ipv6 is not None
                and self.neighbor.mac is not None)

    def _build_ospf_unicast_frame(self, builder, payload):
        return builder(payload, self.neighbor.ipv6, self.neighbor.mac)

    def _send_dbd_frame(self, flags):
        if self.neighbor.port is None:
            return False
        frame = build_ospfv3_dbd_frame(self.neighbor.dbd_sequence, flags=flags)
        return self.send_frame(frame, self.neighbor.port)

    def send_initial_dbd(self):
        if not self._send_dbd_frame(0x07):
            return
        self.logger.info("[OSPF][DBD TX] initial seq=0x%08x flags=I,M,MS",
                         self.neighbor.dbd_sequence)

    def send_exchange_dbd(self):
        if not self._send_dbd_frame(0x01):
            return
        self.logger.info("[OSPF][DBD TX] exchange seq=0x%08x flags=MS",
                         self.neighbor.dbd_sequence)

    def reset_dbd_state(self, reason):
        self.neighbor.reset_exchange()
        self.local_lsa_ack_pending = {}
        self.local_lsu_last_tx = None
        self.local_lsu_sent = False
        self.logger.warning("[OSPF][DBD] state reset reason=%s new-seq=0x%08x",
                            reason, self.neighbor.dbd_sequence)

    def send_link_state_request(self):
        if not self._ospf_unicast_ready():
            return
        if not self.neighbor.request_list:
            self.logger.info("[OSPF][LSR] no LSAs to request")
            return
        frame = self._build_ospf_unicast_frame(
            build_ospfv3_lsr_frame, self.neighbor.request_list)
        if not self.send_frame(frame, self.neighbor.port):
            return
        self.neighbor.lsr_sent = True
        self.logger.info("[OSPF][LSR TX] to=%s count=%d",
                         self.neighbor.ipv6, len(self.neighbor.request_list))
        for lsa in self.neighbor.request_list:
            self.logger.info("  -> %s adv=%s lsid=%s",
                             ospfv3_lsa_type_description(lsa["ls_type"]),
                             lsa["advertising_router"], lsa["link_state_id"])

    def send_ls_ack(self, lsa_headers):
        if not self._ospf_unicast_ready() or not lsa_headers:
            return
        frame = self._build_ospf_unicast_frame(
            build_ospfv3_lsack_frame, lsa_headers)
        if not self.send_frame(frame, self.neighbor.port):
            return
        self.logger.info("[OSPF][LSAck TX] to=%s count=%d",
                         self.neighbor.ipv6, len(lsa_headers))

    def send_local_ls_update(self):
        if not self._ospf_unicast_ready():
            return False
        body = self.local_lsa.build_update_body()
        if body is None:
            return False
        frame = self._build_ospf_unicast_frame(build_ospfv3_lsu_frame, body)
        self.local_lsa_ack_pending = {
            key: {"ls_sequence": lsa["ls_sequence"],
                  "ls_checksum": lsa["ls_checksum"]}
            for key, lsa in self.local_lsa.items()
        }
        if not self.send_frame(frame, self.neighbor.port):
            self.local_lsa_ack_pending = {}
            self.local_lsu_last_tx = None
            return False
        self.local_lsu_last_tx = time.monotonic()
        self.logger.info("[OSPF][LSU TX] to=%s lsas=%d "
                         "frame-length=%d pending-acks=%d",
                         self.neighbor.ipv6, len(self.local_lsa), len(frame),
                         len(self.local_lsa_ack_pending))
        return True

    def send_local_lsr_response(self, local_lsas):
        if not self._ospf_unicast_ready() or not local_lsas:
            return False
        body = struct.pack("!I", len(local_lsas)) + b"".join(
            lsa["raw_lsa"] for lsa in local_lsas)
        frame = self._build_ospf_unicast_frame(build_ospfv3_lsu_frame, body)
        if not self.send_frame(frame, self.neighbor.port):
            return False
        self.logger.info("[OSPF][LSR RESPONSE TX] to=%s lsas=%d frame-length=%d",
                         self.neighbor.ipv6, len(local_lsas), len(frame))
        for lsa in local_lsas:
            self.logger.info("  -> %s adv=%s lsid=%s "
                             "seq=0x%08x checksum=0x%04x",
                             ospfv3_lsa_type_description(lsa["ls_type"]),
                             lsa["advertising_router"], lsa["link_state_id"],
                             lsa["ls_sequence"], lsa["ls_checksum"])
        return True

    def send_local_lsa_retransmission(self):
        if not self._ospf_unicast_ready():
            return False
        result = self.local_lsa.build_pending_body(self.local_lsa_ack_pending)
        if result is None:
            return False
        body, count = result
        frame = self._build_ospf_unicast_frame(build_ospfv3_lsu_frame, body)
        if not self.send_frame(frame, self.neighbor.port):
            return False
        self.local_lsu_last_tx = time.monotonic()
        self.logger.info("[OSPF][LSU RETX] to=%s lsas=%d "
                         "frame-length=%d pending-acks=%d",
                         self.neighbor.ipv6, count, len(frame),
                         len(self.local_lsa_ack_pending))
        return True

    def reoriginate_local_lsas(self, reason):
        if self.local_lsa_ack_pending:
            self.logger.warning("[OSPF][REORIGINATE] postponed - "
                                "previous local LSAs are still awaiting acknowledgment")
            return False
        if not self.local_lsa.reoriginate(self.neighbor.router_id, reason):
            return False
        return self.send_local_ls_update()
