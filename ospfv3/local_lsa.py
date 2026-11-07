"""Originate and retransmit the three local OSPFv3 LSAs advertised to FRR."""

import ipaddress
import socket
import struct
import time

from scapy.contrib.ospf import (
    OSPFv3_Intra_Area_Prefix_LSA, OSPFv3_Link, OSPFv3_Link_LSA,
    OSPFv3_LSA_Hdr, OSPFv3_Prefix_Item, OSPFv3_Router_LSA)
from ospfv3 import config as cfg
from ospfv3.packet import encode_ospfv3_lsu_body
from ospfv3.lsa import (next_ospfv3_lsa_sequence,
                        ospfv3_lsa_type_description, lsa_sequence_signed)


class LocalLSA:
    def __init__(self, lsdb, logger):
        self.lsdb, self.logger = lsdb, logger
        self.entries = {}
        self.router_sequence = cfg.INITIAL_SEQUENCE
        self.link_sequence = cfg.INITIAL_SEQUENCE
        self.prefix_sequence = cfg.INITIAL_SEQUENCE

    def __bool__(self):
        return bool(self.entries)

    def __len__(self):
        return len(self.entries)

    def get(self, key):
        return self.entries.get(key)

    def items(self):
        return self.entries.items()

    def values(self):
        return self.entries.values()

    def clear(self):
        self.entries.clear()

    def recover_sequences(self, lsa_headers, prepare_next):
        # A peer may retain newer self-originated LSAs after Ryu restarts.
        interface_lsid = str(ipaddress.IPv4Address(cfg.INTERFACE_ID))
        sequences = {
            (0x2001, "0.0.0.0"): "router_sequence",
            (0x0008, interface_lsid): "link_sequence",
            (0x2009, "0.0.0.0"): "prefix_sequence",
        }
        changed, recovered = False, 0
        for lsa in lsa_headers:
            if lsa["advertising_router"] != cfg.ROUTER_ID:
                continue
            attribute = sequences.get((lsa["ls_type"], lsa["link_state_id"]))
            if attribute is None:
                continue
            observed = lsa["ls_sequence"]
            try:
                candidate = (next_ospfv3_lsa_sequence(observed)
                             if prepare_next else observed)
            except ValueError as exc:
                self.logger.warning("[OSPF][SELF LSA] cannot recover sequence: %s", exc)
                continue
            if lsa_sequence_signed(candidate) > lsa_sequence_signed(
                    getattr(self, attribute)):
                setattr(self, attribute, candidate)
                changed = True
            recovered += 1
            self.logger.info("[OSPF][SELF LSA] recovered "
                             "type=0x%04x lsid=%s observed=0x%08x prepared=0x%08x",
                             lsa["ls_type"], lsa["link_state_id"], observed,
                             getattr(self, attribute))
        return changed, recovered

    def get_neighbor_interface_id(self, neighbor_router_id):
        if neighbor_router_id is None:
            return None
        local_id = str(ipaddress.IPv4Address(cfg.INTERFACE_ID))
        for lsa in self.lsdb.values():
            if (lsa["ls_type"] != 0x2001
                    or lsa["advertising_router"] != neighbor_router_id):
                continue
            router_lsa = lsa.get("router_lsa")
            if router_lsa is None:
                continue
            for link in router_lsa["links"]:
                if (link["type"] == 1
                        and link["neighbor_router_id"] == cfg.ROUTER_ID
                        and link["neighbor_interface_id"] == local_id):
                    return struct.unpack("!I", socket.inet_aton(link["interface_id"]))[0]
        return None

    @staticmethod
    def _prefix_item(prefix, length, metric):
        network = ipaddress.IPv6Network(f"{prefix}/{length}", strict=False)
        return OSPFv3_Prefix_Item(
            prefixlen=length, prefixoptions=0, metric=metric,
            prefix=f"{network.network_address}/{length}")

    def build_router(self, neighbor_router_id):
        if neighbor_router_id is None:
            self.logger.warning("[OSPF][LOCAL LSA] cannot build Router-LSA: "
                                "neighbor Router ID is unknown")
            return None
        neighbor_interface_id = self.get_neighbor_interface_id(neighbor_router_id)
        if neighbor_interface_id is None:
            self.logger.warning("[OSPF][LOCAL LSA] cannot build Router-LSA: "
                                "neighbor Interface ID is unknown")
            return None
        return bytes(OSPFv3_Router_LSA(
            age=0, type=0x2001, id="0.0.0.0", adrouter=cfg.ROUTER_ID,
            seq=self.router_sequence, flags=0, options=cfg.OPTIONS,
            linklist=[OSPFv3_Link(
                type=1, reserved=0, metric=cfg.INTERFACE_COST,
                intid=cfg.INTERFACE_ID, neighintid=neighbor_interface_id,
                neighbor=neighbor_router_id)]))

    def build_prefix(self):
        return bytes(OSPFv3_Intra_Area_Prefix_LSA(
            age=0, type=0x2009, id="0.0.0.0", adrouter=cfg.ROUTER_ID,
            seq=self.prefix_sequence, prefixes=1, reflstype=0x2001,
            reflsid="0.0.0.0", refadrouter=cfg.ROUTER_ID,
            prefixlist=[self._prefix_item(
                cfg.LAN_PREFIX, cfg.LAN_PREFIX_LEN, cfg.LAN_PREFIX_METRIC)]))

    def build_link(self):
        interface_lsid = str(ipaddress.IPv4Address(cfg.INTERFACE_ID))
        return bytes(OSPFv3_Link_LSA(
            age=0, type=0x0008, id=interface_lsid, adrouter=cfg.ROUTER_ID,
            seq=self.link_sequence, prio=cfg.ROUTER_PRIORITY,
            options=cfg.OPTIONS, lladdr=cfg.LINK_LOCAL, prefixes=1,
            prefixlist=[self._prefix_item(
                cfg.TRANSIT_PREFIX, cfg.TRANSIT_PREFIX_LEN, 0)]))

    def install(self, raw_lsa):
        if len(raw_lsa) < 20:
            raise ValueError("Local LSA is too short")
        # Preserve the original serialized LSA; only the fixed header is read.
        header = OSPFv3_LSA_Hdr(bytes(raw_lsa[:20]))
        key = (header.type, header.id, header.adrouter)
        self.entries[key] = {
            "ls_age": header.age, "ls_type": header.type,
            "link_state_id": header.id, "advertising_router": header.adrouter,
            "ls_sequence": header.seq, "ls_checksum": header.chksum,
            "ls_length": header.len, "raw_lsa": raw_lsa,
            "_originated_at": time.monotonic()}

    def initialize(self, neighbor_router_id):
        if self.entries:
            return True
        if self.get_neighbor_interface_id(neighbor_router_id) is None:
            return False
        router = self.build_router(neighbor_router_id)
        if router is None:
            return False
        self.install(router)
        self.install(self.build_link())
        self.install(self.build_prefix())
        self.logger.info("[OSPF][LOCAL LSDB] initialized entries=%d",
                         len(self.entries))
        for _, lsa in sorted(self.entries.items(), key=lambda item: item[0]):
            self.logger.info("  -> %s adv=%s lsid=%s "
                             "seq=0x%08x checksum=0x%04x length=%d",
                             ospfv3_lsa_type_description(lsa["ls_type"]),
                             lsa["advertising_router"], lsa["link_state_id"],
                             lsa["ls_sequence"], lsa["ls_checksum"],
                             lsa["ls_length"])
        return True

    def build_update_body(self):
        if not self.entries:
            return None
        lsas = [entry["raw_lsa"] for _, entry in sorted(
            self.entries.items(), key=lambda item: item[0])]
        return encode_ospfv3_lsu_body(lsas)

    def build_pending_body(self, pending):
        if not pending:
            return None
        lsas = []
        for key in sorted(pending):
            local = self.entries.get(key)
            if (local is not None
                    and local["ls_sequence"] == pending[key]["ls_sequence"]
                    and local["ls_checksum"] == pending[key]["ls_checksum"]):
                lsas.append(local["raw_lsa"])
        if not lsas:
            return None
        return encode_ospfv3_lsu_body(lsas), len(lsas)

    def reoriginate(self, neighbor_router_id, reason):
        if not self.entries:
            self.logger.warning("[OSPF][REORIGINATE] local LSDB is empty")
            return False
        if self.get_neighbor_interface_id(neighbor_router_id) is None:
            self.logger.warning("[OSPF][REORIGINATE] neighbor interface ID unavailable")
            return False
        self.router_sequence = next_ospfv3_lsa_sequence(self.router_sequence)
        self.link_sequence = next_ospfv3_lsa_sequence(self.link_sequence)
        self.prefix_sequence = next_ospfv3_lsa_sequence(self.prefix_sequence)
        router = self.build_router(neighbor_router_id)
        if router is None:
            return False
        link, prefix = self.build_link(), self.build_prefix()
        self.entries.clear()
        self.install(router)
        self.install(link)
        self.install(prefix)
        self.logger.info("[OSPF][REORIGINATE] reason=%s entries=%d",
                         reason, len(self.entries))
        for _, lsa in sorted(self.entries.items(), key=lambda item: item[0]):
            self.logger.info("  -> %s adv=%s lsid=%s seq=0x%08x checksum=0x%04x",
                             ospfv3_lsa_type_description(lsa["ls_type"]),
                             lsa["advertising_router"], lsa["link_state_id"],
                             lsa["ls_sequence"], lsa["ls_checksum"])
        return True
