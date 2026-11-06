"""Receive-side handlers for OSPFv3 protocol packets.

This mixin processes Hello, DBD, LSR, LSU and LSAck messages,
checks adjacency and LSA state, and coordinates incoming updates.
The RyuApp owns the shared neighbor, LSDB and routing state;
handlers access other controller capabilities through ``self``.
"""

import socket
import struct

from ospfv3 import config as cfg
from ospfv3.parser import parse_hello, parse_dbd, parse_lsr, parse_lsu, parse_lsack
from ospfv3.lsa import ospfv3_lsa_type_description


class OSPFReceiveMixin:
    """Receive Hello/DBD/LSR/LSU/LSAck, neighbor eligibility and LSA split."""

    def handle_ospf_hello(
        self,
        in_port,
        eth_pkt,
        ipv6_pkt,
        ospf_data,
        pkt_len,
        router_id_text,
        area_id_text
    ):
        """
        Handles a received OSPFv3 Hello packet.
        """

        try:
            hello = parse_hello(
                ospf_data,
                pkt_len
            )
        except ValueError as exc:
            self.logger.warning(
                "[OSPF][HELLO] %s",
                exc
            )
            return

        interface_id = hello["interface_id"]
        router_priority = hello["router_priority"]
        options = hello["options"]
        hello_interval = hello["hello_interval"]
        dead_interval = hello["dead_interval"]
        neighbors = hello["neighbors"]

        if hello_interval != cfg.HELLO_INTERVAL:
            self.logger.warning(
                "[OSPF][HELLO DROP] hello interval mismatch "
                "received=%ds expected=%ds",
                hello_interval,
                cfg.HELLO_INTERVAL
            )
            return

        if dead_interval != cfg.DEAD_INTERVAL:
            self.logger.warning(
                "[OSPF][HELLO DROP] dead interval mismatch "
                "received=%ds expected=%ds",
                dead_interval,
                cfg.DEAD_INTERVAL
            )
            return

        self.neighbor.mark_hello_received()

        self.neighbor.port = in_port
        self.neighbor.ipv6 = ipv6_pkt.src
        self.neighbor.mac = eth_pkt.src
        self.neighbor.router_id = router_id_text

        self.log_hello(
            in_port,
            ipv6_pkt,
            pkt_len,
            router_id_text,
            area_id_text,
            interface_id,
            router_priority,
            options,
            hello_interval,
            dead_interval,
            neighbors
        )

        # Learn the transit-side L2 state only from a valid OSPF Hello.
        transit_changed = (
            self.data_plane.learn_transit_router(
                in_port=self.neighbor.port,
                ipv6_address=self.neighbor.ipv6,
                mac_address=self.neighbor.mac
            )
        )

        if transit_changed:
            self.logger.info(
                "[DATA][TRANSIT LEARN] "
                "source=verified-ospf-hello "
                "ipv6=%s mac=%s port=%s",
                self.neighbor.ipv6,
                self.neighbor.mac,
                self.neighbor.port
            )

            self.try_install_ipv6_host_flows()

        # After a controller/switch restart, FRR may still consider the
        # previous OSPF adjacency alive because DeadInterval has not expired.
        #
        # If the peer still lists our Router ID, send one Hello without
        # advertising the peer as a neighbor. This forces the old adjacency
        # to be resynchronized.
        if self.ospf_resync_required:
            self.ospf_resync_required = False

            if cfg.ROUTER_ID in neighbors:
                self.logger.info(
                    "[OSPF][RESYNC] "
                    "peer retained previous adjacency; "
                    "sending one-way Hello"
                )

                self.send_ospfv3_hello(
                    neighbors=[]
                )

                return

        if router_id_text not in self.neighbor.router_ids:
            self.neighbor.router_ids.append(
                router_id_text
            )

            self.logger.info(
                "[OSPF][NEIGHBOR] "
                "discovered router=%s src=%s",
                router_id_text,
                ipv6_pkt.src
            )

            self.send_ospfv3_hello()

    def is_current_ospf_neighbor(
        self,
        in_port,
        ipv6_pkt,
        router_id_text
    ):
        return (
            self.neighbor.router_id is not None
            and router_id_text == self.neighbor.router_id
            and router_id_text in self.neighbor.router_ids
            and ipv6_pkt.src == self.neighbor.ipv6
            and in_port == self.neighbor.port
        )

    def _reject_noncurrent_ospf_neighbor(self, in_port, ipv6_pkt, router_id_text):
        """Keep the original drop warning in one place for all RX handlers."""
        if self.is_current_ospf_neighbor(in_port, ipv6_pkt, router_id_text):
            return False
        self.logger.warning(
            "[OSPF][DROP] packet from unknown neighbor "
            "router=%s src=%s port=%s",
            router_id_text, ipv6_pkt.src, in_port
        )
        return True

    @staticmethod
    def _split_ospf_lsa_by_origin(lsas):
        """Preserve the original two-pass filtering and ordering of LSAs."""
        return (
            [lsa for lsa in lsas if lsa["advertising_router"] == cfg.ROUTER_ID],
            [lsa for lsa in lsas if lsa["advertising_router"] != cfg.ROUTER_ID],
        )

    def handle_ospf_dbd(
        self,
        in_port,
        ipv6_pkt,
        ospf_data,
        pkt_len,
        router_id,
        router_id_text,
        area_id_text
    ):
        """
        Handles a received OSPFv3 Database Description packet.
        """

        if self._reject_noncurrent_ospf_neighbor(
            in_port, ipv6_pkt, router_id_text
        ):
            return

        try:
            dbd = parse_dbd(
                ospf_data,
                pkt_len
            )
        except ValueError as exc:
            self.logger.warning(
                "[OSPF][DBD] %s",
                exc
            )
            return

        interface_mtu = dbd["interface_mtu"]
        options = dbd["options"]
        i_bit = dbd["i_bit"]
        m_bit = dbd["m_bit"]
        ms_bit = dbd["ms_bit"]
        dd_sequence = dbd["dd_sequence"]
        lsa_headers = dbd["lsa_headers"]

        if (
            interface_mtu == 0
            or interface_mtu > cfg.INTERFACE_MTU
        ):
            self.logger.warning(
                "[OSPF][DBD DROP] invalid MTU "
                "received=%d local=%d",
                interface_mtu,
                cfg.INTERFACE_MTU
            )
            return

        self.log_dbd(
            in_port,
            ipv6_pkt,
            router_id_text,
            area_id_text,
            interface_mtu,
            options,
            i_bit,
            m_bit,
            ms_bit,
            dd_sequence,
            lsa_headers
        )

        local_router_id = struct.unpack(
            "!I",
            socket.inet_aton(cfg.ROUTER_ID)
        )[0]

        is_initial_dbd = (
            i_bit
            and m_bit
            and ms_bit
            and pkt_len == 28
            and local_router_id > router_id
        )

        if is_initial_dbd:
            if (
                self.neighbor.dbd_negotiated
                or self.neighbor.dbd_exchange_complete
            ):
                self.reset_dbd_state(
                    "neighbor restarted ExStart"
                )

            self.logger.info(
                "[OSPF][DBD] ExStart "
                "local=%s peer=%s role=Master",
                cfg.ROUTER_ID,
                router_id_text
            )

            self.send_initial_dbd()

        elif (
            not self.neighbor.dbd_negotiated
            and not i_bit
            and not ms_bit
            and dd_sequence == self.neighbor.dbd_sequence
            and local_router_id > router_id
        ):
            self.logger.info(
                "[OSPF][DBD] negotiation-complete "
                "role=Master seq=0x%08x",
                dd_sequence
            )

            self.neighbor.dbd_negotiated = True

            self_originated_headers, remote_headers = (
                self._split_ospf_lsa_by_origin(lsa_headers)
            )

            sequence_changed, recovered_count = (
                self.local_lsa.recover_sequences(
                    self_originated_headers,
                    prepare_next=not bool(
                        self.local_lsa
                    )
                )
            )

            if (
                sequence_changed
                and self.local_lsa
            ):
                self.local_lsa_rebuild_required = True

            self.neighbor.request_list = remote_headers

            self.logger.info(
                "[OSPF][DBD] request-list=%d "
                "self-originated=%d",
                len(self.neighbor.request_list),
                recovered_count
            )

            self.neighbor.dbd_sequence = (
                self.neighbor.dbd_sequence + 1
            ) & 0xffffffff

            self.send_exchange_dbd()

        elif (
            self.neighbor.dbd_negotiated
            and not self.neighbor.dbd_exchange_complete
            and not i_bit
            and not m_bit
            and not ms_bit
            and dd_sequence == self.neighbor.dbd_sequence
        ):
            self.neighbor.dbd_exchange_complete = True

            self.logger.info(
                "[OSPF][DBD] exchange-complete "
                "seq=0x%08x pending=%d",
                dd_sequence,
                len(self.neighbor.request_list)
            )

            if (
                self.neighbor.request_list
                and not self.neighbor.lsr_sent
            ):
                self.send_link_state_request()

    def handle_ospf_lsr(
        self,
        in_port,
        ipv6_pkt,
        ospf_data,
        pkt_len,
        router_id_text,
        area_id_text
    ):
        """
        Handles a received OSPFv3 Link State Request packet.
        """
        if self._reject_noncurrent_ospf_neighbor(
            in_port, ipv6_pkt, router_id_text
        ):
            return

        try:
            requests = parse_lsr(
                ospf_data,
                pkt_len
            )
        except ValueError as exc:
            self.logger.warning(
                "[OSPF][LSR RX] %s",
                exc
            )
            return

        self.logger.info(
            "[OSPF][LSR RX] router=%s src=%s port=%s "
            "area=%s count=%d",
            router_id_text,
            ipv6_pkt.src,
            in_port,
            area_id_text,
            len(requests)
        )

        requested_local_lsas = []
        requested_keys = set()

        for request in requests:
            key = (
                request["ls_type"],
                request["link_state_id"],
                request["advertising_router"]
            )

            local_lsa = self.local_lsa.get(key)
            local_match = local_lsa is not None

            self.logger.info(
                "  -> %s adv=%s lsid=%s local-match=%s",
                ospfv3_lsa_type_description(
                    request["ls_type"]
                ),
                request["advertising_router"],
                request["link_state_id"],
                local_match
            )

            if (
                local_lsa is not None
                and key not in requested_keys
            ):
                requested_local_lsas.append(
                    local_lsa
                )

                requested_keys.add(key)

        if requested_local_lsas:
            self.send_local_lsr_response(
                requested_local_lsas
            )

    def handle_ospf_lsu(
        self,
        in_port,
        ipv6_pkt,
        ospf_data,
        pkt_len,
        router_id_text,
        area_id_text
    ):
        """
        Handles a received OSPFv3 Link State Update packet.
        """

        if self._reject_noncurrent_ospf_neighbor(
            in_port, ipv6_pkt, router_id_text
        ):
            return

        try:
            lsu_lsa_headers = parse_lsu(
                ospf_data,
                pkt_len
            )
        except ValueError as exc:
            self.logger.warning(
                "[OSPF][LSU] %s",
                exc
            )
            return

        self.log_lsu(
            in_port,
            ipv6_pkt,
            pkt_len,
            router_id_text,
            area_id_text,
            lsu_lsa_headers
        )

        if lsu_lsa_headers:
            self.neighbor.update_request_list(
                lsu_lsa_headers
            )

            self_originated_lsas, remote_lsas = (
                self._split_ospf_lsa_by_origin(lsu_lsa_headers)
            )

            if self_originated_lsas:
                sequence_changed, recovered_count = (
                    self.local_lsa.recover_sequences(
                        self_originated_lsas,
                        prepare_next=not bool(
                            self.local_lsa
                        )
                    )
                )

                self.logger.info(
                    "[OSPF][SELF LSA] "
                    "received=%d excluded-from-remote-lsdb",
                    recovered_count
                )

                if (
                    sequence_changed
                    and self.local_lsa
                ):
                    self.local_lsa_rebuild_required = True

            if remote_lsas:
                self.lsdb.update(
                    remote_lsas
                )

            if not self.local_lsa:
                self.local_lsa.initialize(self.neighbor.router_id)

            self.send_ls_ack(
                lsu_lsa_headers
            )

            if (
                self.local_lsa
                and self.neighbor.dbd_exchange_complete
                and not self.neighbor.request_list
                and not self.local_lsu_sent
            ):
                if self.local_lsa_rebuild_required:
                    if not self.local_lsa.reoriginate(
                        self.neighbor.router_id,
                        "neighbor session restarted"
                    ):
                        self.logger.warning(
                            "[OSPF][REORIGINATE] "
                            "failed after neighbor restart"
                        )
                        return

                    self.local_lsa_rebuild_required = False

                    self.logger.info(
                        "[OSPF][REORIGINATE] "
                        "local LSAs rebuilt after neighbor restart"
                    )

                if self.send_local_ls_update():
                    self.local_lsu_sent = True

    def handle_ospf_lsack(
        self,
        in_port,
        ipv6_pkt,
        ospf_data,
        pkt_len,
        router_id_text,
        area_id_text
    ):
        """
        Handles a received OSPFv3 Link State Acknowledgment packet.
        """

        if self._reject_noncurrent_ospf_neighbor(
            in_port, ipv6_pkt, router_id_text
        ):
            return

        try:
            lsa_headers = parse_lsack(
                ospf_data,
                pkt_len
            )
        except ValueError as exc:
            self.logger.warning(
                "[OSPF][LSAck RX] %s",
                exc
            )
            return

        self.logger.info(
            "[OSPF][LSAck RX] router=%s src=%s port=%s "
            "area=%s count=%d",
            router_id_text,
            ipv6_pkt.src,
            in_port,
            area_id_text,
            len(lsa_headers)
        )

        acknowledged_count = 0

        for lsa in lsa_headers:
            key = (
                lsa["ls_type"],
                lsa["link_state_id"],
                lsa["advertising_router"]
            )

            local_lsa = self.local_lsa.get(key)

            matched = (
                local_lsa is not None
                and local_lsa["ls_sequence"] == lsa["ls_sequence"]
                and local_lsa["ls_checksum"] == lsa["ls_checksum"]
            )

            self.logger.info(
                "  -> %s adv=%s lsid=%s "
                "seq=0x%08x checksum=0x%04x local-match=%s",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"],
                lsa["ls_checksum"],
                matched
            )

            pending_lsa = self.local_lsa_ack_pending.get(
                key
            )

            pending_match = (
                pending_lsa is not None
                and pending_lsa["ls_sequence"]
                == lsa["ls_sequence"]
                and pending_lsa["ls_checksum"]
                == lsa["ls_checksum"]
            )

            if pending_match:
                del self.local_lsa_ack_pending[key]
                acknowledged_count += 1

                self.logger.info(
                    "[OSPF][LSAck] acknowledged %s "
                    "adv=%s lsid=%s pending=%d",
                    ospfv3_lsa_type_description(
                        lsa["ls_type"]
                    ),
                    lsa["advertising_router"],
                    lsa["link_state_id"],
                    len(self.local_lsa_ack_pending)
                )

        if (
            acknowledged_count > 0
            and not self.local_lsa_ack_pending
        ):
            self.local_lsu_last_tx = None

            self.logger.info(
                "[OSPF][LSAck] all local LSAs acknowledged"
            )
