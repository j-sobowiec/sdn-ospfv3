"""Frozen M04 production methods before M05 separation. Never modify."""

class OriginalTX:
    def send_ospfv3_hello(self, neighbors=None):
        if self.neighbor.port is None:
            return

        if neighbors is None:
            neighbors = self.neighbor.router_ids

        frame = build_ospfv3_hello_frame(
            neighbors
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return

        self.logger.info(
            "[OSPF][HELLO TX] port=%s neighbors=%s",
            self.neighbor.port,
            neighbors
        )

    def _ospf_unicast_ready(self):
        return (
            self.neighbor.port is not None
            and self.neighbor.ipv6 is not None
            and self.neighbor.mac is not None
        )

    def _build_ospf_unicast_frame(self, builder, payload):
        return builder(payload, self.neighbor.ipv6, self.neighbor.mac)

    def _send_dbd_frame(self, flags):
        if self.neighbor.port is None:
            return False

        frame = build_ospfv3_dbd_frame(
            self.neighbor.dbd_sequence,
            flags=flags
        )
        return self.send_frame(frame, self.neighbor.port)

    def send_initial_dbd(self):
        if not self._send_dbd_frame(0x07):
            return

        self.logger.info(
            "[OSPF][DBD TX] initial "
            "seq=0x%08x flags=I,M,MS",
            self.neighbor.dbd_sequence
        )

    def send_exchange_dbd(self):
        if not self._send_dbd_frame(0x01):
            return

        self.logger.info(
            "[OSPF][DBD TX] exchange "
            "seq=0x%08x flags=MS",
            self.neighbor.dbd_sequence
        )

    def reset_dbd_state(self, reason):
        self.neighbor.reset_exchange()

        self.local_lsa_ack_pending = {}
        self.local_lsu_last_tx = None
        self.local_lsu_sent = False

        self.logger.warning(
            "[OSPF][DBD] state reset reason=%s "
            "new-seq=0x%08x",
            reason,
            self.neighbor.dbd_sequence
        )

    def send_link_state_request(self):
        if not self._ospf_unicast_ready():
            return

        if not self.neighbor.request_list:
            self.logger.info(
                "[OSPF][LSR] no LSAs to request"
            )
            return

        frame = self._build_ospf_unicast_frame(
            build_ospfv3_lsr_frame, self.neighbor.request_list
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return

        self.neighbor.lsr_sent = True

        self.logger.info(
            "[OSPF][LSR TX] to=%s count=%d",
            self.neighbor.ipv6,
            len(self.neighbor.request_list)
        )

        for lsa in self.neighbor.request_list:
            self.logger.info(
                "  -> %s adv=%s lsid=%s",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"]
            )

    def send_ls_ack(self, lsa_headers):
        if not self._ospf_unicast_ready():
            return

        if not lsa_headers:
            return

        frame = self._build_ospf_unicast_frame(
            build_ospfv3_lsack_frame, lsa_headers
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return

        self.logger.info(
            "[OSPF][LSAck TX] to=%s count=%d",
            self.neighbor.ipv6,
            len(lsa_headers)
        )

    def send_local_ls_update(self):
        """
        Sends all locally originated LSAs to the OSPF neighbor
        in a single Link State Update packet.
        """

        if not self._ospf_unicast_ready():
            return False

        lsu_body = self.local_lsa.build_update_body()

        if lsu_body is None:
            return False

        frame = self._build_ospf_unicast_frame(
            build_ospfv3_lsu_frame, lsu_body
        )

        self.local_lsa_ack_pending = {
            key: {
                "ls_sequence": lsa["ls_sequence"],
                "ls_checksum": lsa["ls_checksum"]
            }
            for key, lsa in self.local_lsa.items()
        }

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            self.local_lsa_ack_pending = {}
            self.local_lsu_last_tx = None
            return False

        self.local_lsu_last_tx = time.monotonic()

        self.logger.info(
            "[OSPF][LSU TX] to=%s lsas=%d "
            "frame-length=%d pending-acks=%d",
            self.neighbor.ipv6,
            len(self.local_lsa),
            len(frame),
            len(self.local_lsa_ack_pending)
        )

        return True

    def send_local_lsr_response(self, local_lsas):
        """
        Sends an LSU containing locally originated LSAs
        requested by the OSPF neighbor.
        """

        if not self._ospf_unicast_ready():
            return False

        if not local_lsas:
            return False

        lsu_body = (
            struct.pack(
                "!I",
                len(local_lsas)
            )
            + b"".join(
                lsa["raw_lsa"]
                for lsa in local_lsas
            )
        )

        frame = self._build_ospf_unicast_frame(
            build_ospfv3_lsu_frame, lsu_body
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return False

        self.logger.info(
            "[OSPF][LSR RESPONSE TX] to=%s "
            "lsas=%d frame-length=%d",
            self.neighbor.ipv6,
            len(local_lsas),
            len(frame)
        )

        for lsa in local_lsas:
            self.logger.info(
                "  -> %s adv=%s lsid=%s "
                "seq=0x%08x checksum=0x%04x",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"],
                lsa["ls_checksum"]
            )

        return True

    def send_local_lsa_retransmission(self):
        """
        Retransmits locally originated LSAs that have not yet
        been acknowledged by the OSPF neighbor.
        """

        if not self._ospf_unicast_ready():
            return False

        result = self.local_lsa.build_pending_body(self.local_lsa_ack_pending)

        if result is None:
            return False

        lsu_body, lsa_count = result

        frame = self._build_ospf_unicast_frame(
            build_ospfv3_lsu_frame, lsu_body
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return False

        self.local_lsu_last_tx = time.monotonic()

        self.logger.info(
            "[OSPF][LSU RETX] to=%s lsas=%d "
            "frame-length=%d pending-acks=%d",
            self.neighbor.ipv6,
            lsa_count,
            len(frame),
            len(self.local_lsa_ack_pending)
        )

        return True

    def reoriginate_local_lsas(self, reason):
        if self.local_lsa_ack_pending:
            self.logger.warning(
                "[OSPF][REORIGINATE] postponed - "
                "previous local LSAs are still awaiting acknowledgment"
            )
            return False

        if not self.local_lsa.reoriginate(
            self.neighbor.router_id,
            reason
        ):
            return False

        return self.send_local_ls_update()


class OriginalTimers:
    def hello_loop(self):
        while True:
            if self.datapath is not None and self.neighbor.port is not None:
                self.send_ospfv3_hello()

            hub.sleep(cfg.HELLO_INTERVAL)

    def neighbor_dead_loop(self):
        while True:
            if self.neighbor.dead_interval_expired(
                cfg.DEAD_INTERVAL
            ):
                dead_router_id = self.neighbor.router_id

                self.logger.warning(
                    "[OSPF][DEAD] neighbor=%s "
                    "no Hello received for %ds",
                    dead_router_id,
                    cfg.DEAD_INTERVAL
                )

                # Stop local LSA retransmission state associated
                # with the lost adjacency.
                self.local_lsa_ack_pending = {}
                self.local_lsu_last_tx = None
                self.local_lsu_sent = False

                # Remove topology learned through the lost
                # OSPF adjacency.
                self.lsdb.clear_remote(
                    cfg.ROUTER_ID
                )

                # Rebuild routing before clearing transit data.
                # This also removes stale route-derived
                # OpenFlow entries.
                self.recompute_routing_state()

                dead_transit_port = (
                    self.data_plane.transit_port
                )

                for host_ipv6 in list(
                    self.data_plane.lan_hosts
                ):
                    self.delete_ipv6_reverse_flow(
                        host_ipv6,
                        dead_transit_port
                    )

                # The OSPF next-hop is no longer valid.
                self.data_plane.reset_transit()

                # Clear the neighbor session but preserve the
                # OpenFlow port so Hello packets can continue.
                self.neighbor.reset_adjacency()

                self.logger.warning(
                    "[OSPF][NEIGHBOR] down router=%s",
                    dead_router_id
                )

            hub.sleep(1)

    def lsdb_aging_loop(self):
        self.logger.info("[OSPF][LSDB] aging loop started")

        while True:
            hub.sleep(5)
            if self.lsdb and self.lsdb.purge_expired():
                self.logger.info(
                    "[OSPF][ROUTING] LSDB expiration triggered SPF"
                )
                self.recompute_routing_state()

    def local_lsa_retransmission_loop(self):
        """
        Periodically retransmits unacknowledged local LSAs.
        """
        while True:
            hub.sleep(1)
            if not self.local_lsa_ack_pending:
                continue
            if self.local_lsu_last_tx is None:
                continue
            if (time.monotonic() - self.local_lsu_last_tx
                    < cfg.RETRANSMIT_INTERVAL):
                continue
            self.send_local_lsa_retransmission()

    def local_lsa_refresh_loop(self):
        """
        Periodically refreshes locally originated LSAs.

        When the oldest local LSA reaches LSRefreshTime,
        all locally originated LSAs are reoriginated
        with newer sequence numbers.
        """
        while True:
            hub.sleep(1)
            if (not self.local_lsa
                    or not self.neighbor.dbd_exchange_complete
                    or self.neighbor.request_list
                    or self.local_lsa_ack_pending):
                continue

            originated_times = [
                lsa.get("_originated_at")
                for lsa in self.local_lsa.values()
                if lsa.get("_originated_at") is not None
            ]
            if not originated_times:
                continue

            oldest_originated_at = min(originated_times)
            elapsed = time.monotonic() - oldest_originated_at
            if elapsed < cfg.LS_REFRESH_TIME:
                continue

            self.logger.info(
                "[OSPF][REFRESH] local LSAs reached "
                "refresh interval elapsed=%.1fs",
                elapsed
            )
            self.reoriginate_local_lsas("periodic refresh")
