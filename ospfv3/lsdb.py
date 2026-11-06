"""Age-aware OSPFv3 LSDB; FRRouting, not this store, selects routes."""

import copy
import time

from ospfv3 import config as cfg
from ospfv3.lsa import compare_lsa_instances, ospfv3_lsa_type_description


class LSDB:
    def __init__(self, logger):
        self.entries = {}
        self.logger = logger

    def __bool__(self):
        return bool(self.entries)

    def __len__(self):
        return len(self.entries)

    def values(self):
        return self.entries.values()

    def items(self):
        return self.entries.items()

    def get(self, key):
        return self.entries.get(key)

    def _install(self, lsa):
        entry = copy.deepcopy(lsa)
        entry["_age_base"] = lsa["ls_age"]
        entry["_age_timestamp"] = time.monotonic()
        return entry

    def get_age(self, lsa):
        base_age = lsa.get("_age_base", lsa["ls_age"])
        timestamp = lsa.get("_age_timestamp")
        if timestamp is None:
            return base_age
        return min(cfg.MAX_AGE, base_age + int(time.monotonic() - timestamp))

    def update(self, received_lsas):
        """Install newer LSAs, honor MaxAge flush; report routing-relevant changes."""
        routing_changed = False
        for received in received_lsas:
            ls_type = received["ls_type"]
            key = (ls_type, received["link_state_id"], received["advertising_router"])
            current = self.entries.get(key)
            if current is not None:
                aged = dict(current)
                aged["ls_age"] = self.get_age(current)
            is_max_age = received["ls_age"] >= cfg.MAX_AGE
            if current is not None:
                comparison = compare_lsa_instances(received, aged)

            if is_max_age:
                if current is None or comparison < 0:
                    continue
                del self.entries[key]
                message = "[OSPF][LSDB] flushed %s adv=%s lsid=%s"
                extra = ()
            else:
                if current is not None and comparison <= 0:
                    continue
                if current is None:
                    message = "[OSPF][LSDB] installed %s adv=%s lsid=%s seq=0x%08x"
                    extra = (received["ls_sequence"],)
                else:
                    message = "[OSPF][LSDB] updated %s adv=%s lsid=%s seq=0x%08x -> 0x%08x"
                    extra = (current["ls_sequence"], received["ls_sequence"])
                self.entries[key] = self._install(received)

            routing_changed |= ls_type in (0x2001, 0x2009)
            self.logger.info(message, ospfv3_lsa_type_description(ls_type),
                             received["advertising_router"], received["link_state_id"], *extra)
        return routing_changed

    def purge_expired(self):
        """Remove LSAs at MaxAge, preserving logging and update semantics."""
        expired_keys = [key for key, lsa in self.entries.items()
                        if self.get_age(lsa) >= cfg.MAX_AGE]
        routing_changed = False
        for key in expired_keys:
            lsa = self.entries.pop(key)
            routing_changed |= lsa["ls_type"] in (0x2001, 0x2009)
            self.logger.info(
                "[OSPF][LSDB] removed expired %s adv=%s lsid=%s age=%ds",
                ospfv3_lsa_type_description(lsa["ls_type"]),
                lsa["advertising_router"], lsa["link_state_id"], cfg.MAX_AGE)
        return routing_changed

    def clear_remote(self, local_router_id):
        removed = 0
        for key, lsa in list(self.entries.items()):
            if lsa.get("advertising_router") != local_router_id:
                del self.entries[key]
                removed += 1
        if removed:
            self.logger.info("[OSPF][LSDB] cleared remote entries=%d", removed)
        return removed > 0
