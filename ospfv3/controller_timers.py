"""Periodic OSPFv3 tasks and neighbor adjacency expiration.

Provides Hello, Dead, LSDB aging, LSA retransmission and refresh loops.
The RyuApp schedules these loops and owns shared state.
"""

import time
from ryu.lib import hub

from ospfv3 import config as cfg


class OSPFTimerMixin:
    """Periodic Hello, dead neighbor, LSDB aging, LSA RETX and refresh."""

    def hello_loop(self):
        while True:
            if self.datapath is not None and self.neighbor.port is not None:
                self.send_ospfv3_hello()

            hub.sleep(cfg.HELLO_INTERVAL)

    def neighbor_dead_loop(self):
        while True:
            if self.neighbor.dead_interval_expired(cfg.DEAD_INTERVAL):
                dead_router_id = self.neighbor.router_id
                self.logger.warning("[OSPF][DEAD] neighbor=%s "
                                    "no Hello received for %ds",
                                    dead_router_id, cfg.DEAD_INTERVAL)

                # Stop retransmission and revoke routes learned via R1.
                self.local_lsa_ack_pending = {}
                self.local_lsu_last_tx = None
                self.local_lsu_sent = False
                self.lsdb.clear_remote(cfg.ROUTER_ID)
                self.withdraw_all_ipv6_host_flows()
                self.data_plane.reset_transit()
                # Preserve the port so Hello can reestablish adjacency.
                self.neighbor.reset_adjacency()
                self.logger.warning("[OSPF][NEIGHBOR] down router=%s",
                                    dead_router_id)

            hub.sleep(1)

    def lsdb_aging_loop(self):
        self.logger.info("[OSPF][LSDB] aging loop started")

        while True:
            hub.sleep(5)
            if self.lsdb and self.lsdb.purge_expired():
                self.logger.info("[OSPF][LSDB] expired remote records removed")

    def local_lsa_retransmission_loop(self):
        """
        Periodically retransmits unacknowledged local LSAs.
        """
        while True:
            hub.sleep(1)
            if (not self.local_lsa_ack_pending
                    or self.local_lsu_last_tx is None):
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

            # A generator avoids building a temporary list on every tick.
            oldest_originated_at = min(
                (lsa["_originated_at"] for lsa in self.local_lsa.values()
                 if lsa.get("_originated_at") is not None), default=None)
            if oldest_originated_at is None:
                continue
            elapsed = time.monotonic() - oldest_originated_at
            if elapsed < cfg.LS_REFRESH_TIME:
                continue

            self.logger.info("[OSPF][REFRESH] local LSAs reached "
                             "refresh interval elapsed=%.1fs", elapsed)
            self.reoriginate_local_lsas("periodic refresh")
