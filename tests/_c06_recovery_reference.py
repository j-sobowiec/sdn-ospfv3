"""Frozen C05 pre-C06 loops. Never edit after the C06 patch is applied."""

class OriginalRecovery:
    def lsdb_aging_loop(self):
        self.logger.info(
            "[OSPF][LSDB] aging loop started"
        )

        while True:
            hub.sleep(5)

            if not self.lsdb:
                continue

            routing_changed = self.lsdb.purge_expired()

            if routing_changed:
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

            elapsed = (
                time.monotonic()
                - self.local_lsu_last_tx
            )

            if elapsed < cfg.RETRANSMIT_INTERVAL:
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

            if not self.local_lsa:
                continue

            if not self.neighbor.dbd_exchange_complete:
                continue

            if self.neighbor.request_list:
                continue

            if self.local_lsa_ack_pending:
                continue

            originated_times = [
                lsa.get("_originated_at")
                for lsa in self.local_lsa.values()
                if lsa.get("_originated_at") is not None
            ]

            if not originated_times:
                continue

            oldest_originated_at = min(
                originated_times
            )

            elapsed = (
                time.monotonic()
                - oldest_originated_at
            )

            if elapsed < cfg.LS_REFRESH_TIME:
                continue

            self.logger.info(
                "[OSPF][REFRESH] local LSAs reached "
                "refresh interval elapsed=%.1fs",
                elapsed
            )

            self.reoriginate_local_lsas(
                "periodic refresh"
            )

