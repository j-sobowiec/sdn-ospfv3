"""Minimal receive-side OSPFv3 state machine for the single R1 neighbor.

Hello, DBD, LSR, LSU and LSAck remain fully handled. This component still
uses the existing Scapy-backed parser, LSDB and LocalLSA implementations;
route selection belongs to FRRouting, not to Ryu.
"""

import socket
import struct

from ospfv3 import config as cfg
from ospfv3.parser import parse_hello, parse_dbd, parse_lsr, parse_lsu, parse_lsack


class OSPFReceiveMixin:
    def _parse_or_log(self, parser, data, length, kind):
        try:
            return parser(data, length)
        except ValueError as exc:
            self.logger.warning(f"[OSPF][{kind}] %s", exc)
            return None

    def handle_ospf_hello(self, in_port, eth_pkt, ipv6_pkt, ospf_data,
                          pkt_len, router_id_text, area_id_text):
        hello = self._parse_or_log(parse_hello, ospf_data, pkt_len, "HELLO")
        if hello is None:
            return

        if hello["hello_interval"] != cfg.HELLO_INTERVAL:
            self.logger.warning("[OSPF][HELLO DROP] hello interval mismatch "
                                "received=%ds expected=%ds",
                                hello["hello_interval"], cfg.HELLO_INTERVAL)
            return
        if hello["dead_interval"] != cfg.DEAD_INTERVAL:
            self.logger.warning("[OSPF][HELLO DROP] dead interval mismatch "
                                "received=%ds expected=%ds",
                                hello["dead_interval"], cfg.DEAD_INTERVAL)
            return

        neighbor = self.neighbor
        neighbor.mark_hello_received()
        neighbor.port, neighbor.ipv6 = in_port, ipv6_pkt.src
        neighbor.mac, neighbor.router_id = eth_pkt.src, router_id_text
        self.log_hello(in_port, ipv6_pkt, pkt_len, router_id_text, area_id_text,
                       hello["interface_id"], hello["router_priority"],
                       hello["options"], hello["hello_interval"],
                       hello["dead_interval"], hello["neighbors"])

        if self.data_plane.learn_transit_router(
                in_port=neighbor.port, ipv6_address=neighbor.ipv6,
                mac_address=neighbor.mac):
            self.logger.info("[DATA][TRANSIT LEARN] "
                             "source=verified-ospf-hello ipv6=%s mac=%s port=%s",
                             neighbor.ipv6, neighbor.mac, neighbor.port)
            self.try_install_ipv6_host_flows()

        # A restarted controller may encounter an adjacency FRR still keeps
        # alive. A one-way Hello forces an actual database resynchronization.
        if self.ospf_resync_required:
            self.ospf_resync_required = False
            if cfg.ROUTER_ID in hello["neighbors"]:
                self.logger.info("[OSPF][RESYNC] peer retained adjacency; "
                                 "sending one-way Hello")
                self.send_ospfv3_hello(neighbors=[])
                return

        if router_id_text not in neighbor.router_ids:
            neighbor.router_ids.append(router_id_text)
            self.logger.info("[OSPF][NEIGHBOR] discovered router=%s src=%s",
                             router_id_text, ipv6_pkt.src)
            self.send_ospfv3_hello()

    def is_current_ospf_neighbor(self, in_port, ipv6_pkt, router_id_text):
        neighbor = self.neighbor
        return (neighbor.router_id is not None
                and router_id_text == neighbor.router_id
                and router_id_text in neighbor.router_ids
                and ipv6_pkt.src == neighbor.ipv6
                and in_port == neighbor.port)

    def _reject_noncurrent_ospf_neighbor(self, in_port, ipv6_pkt, router_id_text):
        if self.is_current_ospf_neighbor(in_port, ipv6_pkt, router_id_text):
            return False
        self.logger.warning("[OSPF][DROP] packet from unknown neighbor "
                            "router=%s src=%s port=%s",
                            router_id_text, ipv6_pkt.src, in_port)
        return True

    @staticmethod
    def _split_ospf_lsa_by_origin(lsas):
        return ([lsa for lsa in lsas if lsa["advertising_router"] == cfg.ROUTER_ID],
                [lsa for lsa in lsas if lsa["advertising_router"] != cfg.ROUTER_ID])

    def handle_ospf_dbd(self, in_port, ipv6_pkt, ospf_data, pkt_len,
                        router_id, router_id_text, area_id_text):
        if self._reject_noncurrent_ospf_neighbor(in_port, ipv6_pkt, router_id_text):
            return
        dbd = self._parse_or_log(parse_dbd, ospf_data, pkt_len, "DBD")
        if dbd is None:
            return

        mtu = dbd["interface_mtu"]
        if mtu == 0 or mtu > cfg.INTERFACE_MTU:
            self.logger.warning("[OSPF][DBD DROP] invalid MTU "
                                "received=%d local=%d", mtu, cfg.INTERFACE_MTU)
            return
        self.log_dbd(in_port, ipv6_pkt, router_id_text, area_id_text, mtu,
                     dbd["options"], dbd["i_bit"], dbd["m_bit"], dbd["ms_bit"],
                     dbd["dd_sequence"], dbd["lsa_headers"])

        neighbor = self.neighbor
        local_id = struct.unpack("!I", socket.inet_aton(cfg.ROUTER_ID))[0]
        master = local_id > router_id
        seq = dbd["dd_sequence"]

        if (dbd["i_bit"] and dbd["m_bit"] and dbd["ms_bit"]
                and pkt_len == 28 and master):
            if neighbor.dbd_negotiated or neighbor.dbd_exchange_complete:
                self.reset_dbd_state("neighbor restarted ExStart")
            self.logger.info("[OSPF][DBD] ExStart local=%s peer=%s role=Master",
                             cfg.ROUTER_ID, router_id_text)
            self.send_initial_dbd()
        elif (not neighbor.dbd_negotiated and not dbd["i_bit"]
              and not dbd["ms_bit"] and seq == neighbor.dbd_sequence and master):
            neighbor.dbd_negotiated = True
            self.logger.info("[OSPF][DBD] negotiation-complete "
                             "role=Master seq=0x%08x", seq)
            mine, remote = self._split_ospf_lsa_by_origin(dbd["lsa_headers"])
            changed, recovered = self.local_lsa.recover_sequences(
                mine, prepare_next=not bool(self.local_lsa))
            if changed and self.local_lsa:
                self.local_lsa_rebuild_required = True
            neighbor.request_list = remote
            self.logger.info("[OSPF][DBD] request-list=%d self-originated=%d",
                             len(remote), recovered)
            neighbor.dbd_sequence = (neighbor.dbd_sequence + 1) & 0xffffffff
            self.send_exchange_dbd()
        elif (neighbor.dbd_negotiated and not neighbor.dbd_exchange_complete
              and not dbd["i_bit"] and not dbd["m_bit"] and not dbd["ms_bit"]
              and seq == neighbor.dbd_sequence):
            neighbor.dbd_exchange_complete = True
            self.logger.info("[OSPF][DBD] exchange-complete "
                             "seq=0x%08x pending=%d", seq,
                             len(neighbor.request_list))
            if neighbor.request_list and not neighbor.lsr_sent:
                self.send_link_state_request()

    def handle_ospf_lsr(self, in_port, ipv6_pkt, ospf_data,
                        pkt_len, router_id_text, area_id_text):
        if self._reject_noncurrent_ospf_neighbor(in_port, ipv6_pkt, router_id_text):
            return
        requests = self._parse_or_log(parse_lsr, ospf_data, pkt_len, "LSR RX")
        if requests is None:
            return

        self.logger.info("[OSPF][LSR RX] router=%s src=%s count=%d",
                         router_id_text, ipv6_pkt.src, len(requests))
        local_lsas, seen = [], set()
        for request in requests:
            key = (request["ls_type"], request["link_state_id"],
                   request["advertising_router"])
            item = self.local_lsa.get(key)
            if item is not None and key not in seen:
                local_lsas.append(item)
                seen.add(key)
        if local_lsas:
            self.send_local_lsr_response(local_lsas)

    def handle_ospf_lsu(self, in_port, ipv6_pkt, ospf_data,
                        pkt_len, router_id_text, area_id_text):
        if self._reject_noncurrent_ospf_neighbor(in_port, ipv6_pkt, router_id_text):
            return
        received = self._parse_or_log(parse_lsu, ospf_data, pkt_len, "LSU")
        if received is None:
            return
        self.log_lsu(in_port, ipv6_pkt, pkt_len, router_id_text,
                     area_id_text, received)
        if not received:
            return

        self.neighbor.update_request_list(received)
        own, remote = self._split_ospf_lsa_by_origin(received)
        if own:
            changed, recovered = self.local_lsa.recover_sequences(
                own, prepare_next=not bool(self.local_lsa))
            self.logger.info("[OSPF][SELF LSA] "
                             "received=%d excluded-from-remote-lsdb", recovered)
            if changed and self.local_lsa:
                self.local_lsa_rebuild_required = True
        if remote:
            self.lsdb.update(remote)
        if not self.local_lsa:
            self.local_lsa.initialize(self.neighbor.router_id)
        self.send_ls_ack(received)

        if (self.local_lsa and self.neighbor.dbd_exchange_complete
                and not self.neighbor.request_list and not self.local_lsu_sent):
            if self.local_lsa_rebuild_required:
                if not self.local_lsa.reoriginate(
                        self.neighbor.router_id, "neighbor session restarted"):
                    self.logger.warning("[OSPF][REORIGINATE] "
                                        "failed after neighbor restart")
                    return
                self.local_lsa_rebuild_required = False
                self.logger.info("[OSPF][REORIGINATE] "
                                 "local LSAs rebuilt after neighbor restart")
            if self.send_local_ls_update():
                self.local_lsu_sent = True

    def handle_ospf_lsack(self, in_port, ipv6_pkt, ospf_data,
                          pkt_len, router_id_text, area_id_text):
        if self._reject_noncurrent_ospf_neighbor(in_port, ipv6_pkt, router_id_text):
            return
        headers = self._parse_or_log(parse_lsack, ospf_data, pkt_len, "LSAck RX")
        if headers is None:
            return

        self.logger.info("[OSPF][LSAck RX] router=%s src=%s count=%d",
                         router_id_text, ipv6_pkt.src, len(headers))
        accepted = 0
        for lsa in headers:
            key = (lsa["ls_type"], lsa["link_state_id"],
                   lsa["advertising_router"])
            pending = self.local_lsa_ack_pending.get(key)
            if (pending is not None
                    and pending["ls_sequence"] == lsa["ls_sequence"]
                    and pending["ls_checksum"] == lsa["ls_checksum"]):
                del self.local_lsa_ack_pending[key]
                accepted += 1
                self.logger.info("[OSPF][LSAck] acknowledged type=0x%04x "
                                 "adv=%s lsid=%s pending=%d",
                                 lsa["ls_type"], lsa["advertising_router"],
                                 lsa["link_state_id"],
                                 len(self.local_lsa_ack_pending))
        if accepted and not self.local_lsa_ack_pending:
            self.local_lsu_last_tx = None
            self.logger.info("[OSPF][LSAck] all local LSAs acknowledged")
