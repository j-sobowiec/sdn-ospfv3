"""Frozen TX methods from controller after C03, before C04.

Used only by C04 differential tests. Do not edit during later refactoring.
"""

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


    def send_initial_dbd(self):
        if self.neighbor.port is None:
            return

        frame = build_ospfv3_dbd_frame(
            self.neighbor.dbd_sequence,
            flags=0x07
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return

        self.logger.info(
            "[OSPF][DBD TX] initial "
            "seq=0x%08x flags=I,M,MS",
            self.neighbor.dbd_sequence
        )


    def send_exchange_dbd(self):
        if self.neighbor.port is None:
            return

        frame = build_ospfv3_dbd_frame(
            self.neighbor.dbd_sequence,
            flags=0x01
        )

        if not self.send_frame(
            frame,
            self.neighbor.port
        ):
            return

        self.logger.info(
            "[OSPF][DBD TX] exchange "
            "seq=0x%08x flags=MS",
            self.neighbor.dbd_sequence
        )


    def send_link_state_request(self):
        if self.neighbor.port is None:
            return

        if self.neighbor.ipv6 is None:
            return

        if self.neighbor.mac is None:
            return

        if not self.neighbor.request_list:
            self.logger.info(
                "[OSPF][LSR] no LSAs to request"
            )
            return

        frame = build_ospfv3_lsr_frame(
            self.neighbor.request_list,
            self.neighbor.ipv6,
            self.neighbor.mac
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
        if self.neighbor.port is None:
            return

        if self.neighbor.ipv6 is None:
            return

        if self.neighbor.mac is None:
            return

        if not lsa_headers:
            return

        frame = build_ospfv3_lsack_frame(
            lsa_headers,
            self.neighbor.ipv6,
            self.neighbor.mac
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

        if self.neighbor.port is None:
            return False

        if self.neighbor.ipv6 is None:
            return False

        if self.neighbor.mac is None:
            return False

        lsu_body = self.local_lsa.build_update_body()

        if lsu_body is None:
            return False

        frame = build_ospfv3_lsu_frame(
            lsu_body,
            self.neighbor.ipv6,
            self.neighbor.mac
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

        if self.neighbor.port is None:
            return False

        if self.neighbor.ipv6 is None:
            return False

        if self.neighbor.mac is None:
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

        frame = build_ospfv3_lsu_frame(
            lsu_body,
            self.neighbor.ipv6,
            self.neighbor.mac
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

        if self.neighbor.port is None:
            return False

        if self.neighbor.ipv6 is None:
            return False

        if self.neighbor.mac is None:
            return False

        result = self.local_lsa.build_pending_body(self.local_lsa_ack_pending)

        if result is None:
            return False

        lsu_body, lsa_count = result

        frame = build_ospfv3_lsu_frame(
            lsu_body,
            self.neighbor.ipv6,
            self.neighbor.mac
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


