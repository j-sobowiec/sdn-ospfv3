import time

from ospfv3.lsa import compare_lsa_instances


class Neighbor:
    def __init__(self, logger):
        self.logger = logger

        self.port = None
        self.router_id = None
        self.ipv6 = None
        self.mac = None

        self.router_ids = []
        self.last_hello_received = None

        self.dbd_sequence = self._new_dbd_sequence()
        self.dbd_negotiated = False
        self.dbd_exchange_complete = False

        self.request_list = []
        self.lsr_sent = False

    @staticmethod
    def _new_dbd_sequence():
        return int(time.time() * 1000) & 0xffffffff

    def mark_hello_received(self):
        self.last_hello_received = time.monotonic()

    def dead_interval_expired(self, dead_interval):
        return (
            self.last_hello_received is not None
            and time.monotonic() - self.last_hello_received >= dead_interval
        )

    def reset_exchange(self):
        old_sequence = self.dbd_sequence

        self.dbd_negotiated = False
        self.dbd_exchange_complete = False

        self.request_list = []
        self.lsr_sent = False

        self.dbd_sequence = self._new_dbd_sequence()

        if self.dbd_sequence == old_sequence:
            self.dbd_sequence = (old_sequence + 1) & 0xffffffff

    def update_request_list(self, received_lsas):
        if not self.request_list:
            return

        remaining = []

        for request in self.request_list:
            for received in received_lsas:
                # Compare instances only when their three-field LSA identity matches.
                if (
                    request["ls_type"] == received["ls_type"]
                    and request["link_state_id"] == received["link_state_id"]
                    and request["advertising_router"] == received["advertising_router"]
                    and compare_lsa_instances(received, request) >= 0
                ):
                    break
            else:
                remaining.append(request)

        old_count = len(self.request_list)
        new_count = len(remaining)
        self.request_list = remaining

        if new_count != old_count:
            self.logger.info(
                "[OSPF][LSR] received=%d pending=%d",
                old_count - new_count,
                new_count
            )

        if old_count and not new_count:
            self.logger.info(
                "[OSPF][LSR] request-list complete"
            )

    def reset_adjacency(self):
        self.router_id = None
        self.ipv6 = None
        self.mac = None
        self.router_ids = []

        self.last_hello_received = None

        self.reset_exchange()

    def reset(self):
        self.port = None

        self.reset_adjacency()