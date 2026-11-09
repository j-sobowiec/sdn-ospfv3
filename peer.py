"""One point-to-point OSPFv3 neighbor; FRRouting still performs SPF."""

import ipaddress
import struct
import time

from scapy.contrib.ospf import OSPFv3_LSA_Hdr, OSPFv3_LSReq_Item
from scapy.error import Scapy_Exception

import config as cfg
import packets


def lsa_seq_rank(sequence):
    """Map encoded LSA sequence numbers to signed-order ranks."""
    return int(sequence) ^ 0x80000000


def lsa_is_newer(incoming, current):
    """Compare LSA instances according to RFC 2328 section 13.1."""
    incoming_seq = lsa_seq_rank(incoming.seq)
    current_seq = lsa_seq_rank(current.seq)
    if incoming_seq != current_seq:
        return incoming_seq > current_seq
    if int(incoming.chksum) != int(current.chksum):
        return int(incoming.chksum) > int(current.chksum)
    incoming_age, current_age = int(incoming.age), int(current.age)
    if (incoming_age == 3600) != (current_age == 3600):
        return incoming_age == 3600
    return (abs(incoming_age - current_age) > 900
            and incoming_age < current_age)


class Peer:
    def __init__(self, router, send, logger, clock=time.monotonic):
        self.router = router
        self.send = send
        self.log = logger
        self.clock = clock
        self.reset()

    def reset(self):
        self.router_id = None
        self.interface_id = None
        self.address = None
        self.mac = None
        self.last_hello = None
        self.next_hello = 0
        self.stage = "down"
        self.sequence = 0
        self.last_dbd = None
        self.last_peer_dbd = None
        self.peer_dbd_options = None
        self.dbd_sent_at = 0
        self.requests = {}
        self.lsr_sent_at = 0
        self.local = {}
        self.local_sequence = cfg.LSA_INITIAL_SEQ
        self.local_sent_at = 0
        self.local_refreshed_at = 0
        self.pending_acks = {}

    def transmit(self, data, label):
        if self.send(data):
            self.log.info("[OSPF][%s TX]", label)
            return True
        return False

    def send_hello(self):
        neighbors = [self.router_id] if self.router_id else []
        self.transmit(packets.hello(self.router, neighbors), "Hello")

    def tick(self):
        now = self.clock()
        if self.last_hello is not None and now - self.last_hello >= cfg.DEAD_INTERVAL:
            self.log.warning("[OSPF] neighbor %s dead; adjacency reset", self.router_id)
            self.reset()
        if now >= self.next_hello:
            self.send_hello()
            self.next_hello = now + cfg.HELLO_INTERVAL
        if (self.stage in ("exstart", "exchange") and self.last_dbd
                and now - self.dbd_sent_at >= cfg.RETRANSMIT_INTERVAL):
            self.transmit(self.last_dbd, "DBD retransmit")
            self.dbd_sent_at = now
        if (self.stage == "loading" and self.requests
                and now - self.lsr_sent_at >= cfg.RETRANSMIT_INTERVAL):
            self.send_requests()
        if (self.pending_acks and now - self.local_sent_at
                >= cfg.RETRANSMIT_INTERVAL):
            self.send_local_update(list(self.pending_acks))
        if (self.stage == "synchronized" and not self.pending_acks
                and now - self.local_refreshed_at >= cfg.LS_REFRESH_INTERVAL):
            self.local_sequence += 1
            self.local = packets.local_lsas(
                self.router, self.router_id, self.interface_id, self.local_sequence)
            self.send_local_update()
            self.local_refreshed_at = now
            self.log.info("[OSPF] refreshed local LSAs")

    def receive(self, data):
        try:
            eth, ip, hdr, body = packets.decode(data, self.router)
            if hdr.src == self.router["router_id"]:
                return
            if hdr.type == 1:
                self.on_hello(eth, ip, hdr, body)
                return
            if (hdr.src != self.router_id or ip.src != self.address
                    or eth.src != self.mac or self.stage in ("down", "init")):
                raise ValueError("packet from unknown or one-way neighbor")
            if hdr.type == 2:
                self.on_dbd(hdr.payload, body)
                return
            handlers = {3: self.on_lsr, 4: self.on_lsu, 5: self.on_lsack}
            if hdr.type in handlers:
                handlers[hdr.type](body)
        except (ValueError, IndexError, TypeError, struct.error,
                Scapy_Exception) as exc:
            self.log.warning("[OSPF][DROP] %s", exc)

    def on_hello(self, eth, ip, hdr, body):
        hello = hdr.payload
        if hdr.src != self.router["neighbor_id"]:
            raise ValueError("unexpected OSPFv3 neighbor Router ID")
        if (hello.hellointerval != cfg.HELLO_INTERVAL
                or hello.deadinterval != cfg.DEAD_INTERVAL
                or int(hello.intid) == 0):
            raise ValueError("incompatible Hello timers or interface ID")
        # Both ends of this fixed backbone-area link must agree on the
        # external-routing (E) bit. Other capabilities need not match.
        if (int(hello.options) ^ cfg.OPTIONS) & 0x02:
            raise ValueError("OSPFv3 Hello E-bit does not match area type")
        if self.router_id and (hdr.src != self.router_id or ip.src != self.address
                               or eth.src != self.mac):
            raise ValueError("only one OSPFv3 neighbor is supported")
        discovered = self.router_id is None
        self.router_id, self.address, self.mac = hdr.src, ip.src, eth.src
        self.interface_id = int(hello.intid)
        self.last_hello = self.clock()
        self.log.info("[OSPF][Hello RX] peer=%s ifid=%d", hdr.src, hello.intid)
        if discovered:
            self.stage = "init"
            self.send_hello()
        if self.router["router_id"] not in hello.neighbors:
            if self.stage not in ("down", "init"):
                # RFC 2328 10.3/10.5: 1-WayReceived takes every state from
                # 2-Way upwards back to Init, while preserving the neighbor.
                self.log.warning("[OSPF] neighbor no longer lists our Router ID")
                self.stage = "init"
                self.clear_exchange_state()
                self.local.clear()
            return
        if self.stage == "init":
            if int(ipaddress.IPv4Address(self.router["router_id"])) <= int(
                    ipaddress.IPv4Address(self.router_id)):
                raise ValueError("demo requires controller to be DBD master")
            self.stage = "two-way"
            self.local = packets.local_lsas(
                self.router, self.router_id, self.interface_id, self.local_sequence)
            self.log.info("[OSPF] neighbor %s: Init -> 2-Way", self.router_id)

    def send_dbd(self, flags):
        data = packets.dbd(self.router, self.sequence, flags)
        if self.transmit(data, "DBD"):
            self.last_dbd = data
            self.dbd_sent_at = self.clock()
            self.log.info("[OSPF][DBD] seq=0x%08x flags=%d", self.sequence, flags)

    def remember_summaries(self, body):
        newest_self = None
        for offset in range(12, len(body), 20):
            header = OSPFv3_LSA_Hdr(body[offset:offset + 20])
            key = packets.lsa_key(header)
            if key[2] == self.router["router_id"]:
                seq = int(header.seq)
                if newest_self is None or lsa_seq_rank(seq) > lsa_seq_rank(newest_self):
                    newest_self = seq
            else:
                self.requests[key] = header
        if (newest_self is not None and
                lsa_seq_rank(newest_self) >= lsa_seq_rank(self.local_sequence)):
            if newest_self == 0x7fffffff:
                raise ValueError("local LSA sequence number exhausted")
            self.local_sequence = newest_self + 1
            self.local = packets.local_lsas(
                self.router, self.router_id, self.interface_id, self.local_sequence)

    def on_dbd(self, desc, body):
        if self.stage not in ("two-way", "exstart", "exchange", "loading",
                              "synchronized"):
            return
        if not 0 < int(desc.mtu) <= cfg.MTU:
            raise ValueError("DBD MTU mismatch")
        flags, seq = int(desc.dbdescr), int(desc.ddseq)
        options = int(desc.options)
        identity = (flags, seq, options)
        self.log.info("[OSPF][DBD RX] seq=0x%08x flags=%d summaries=%d",
                      seq, flags, (len(body) - 12) // 20)
        if self.stage in ("loading", "synchronized"):
            # A master ignores an exact duplicate of the last accepted DBD.
            # Any different DBD after exchange is SeqNumberMismatch.
            if identity != self.last_peer_dbd:
                self.restart_exchange("SeqNumberMismatch: unexpected DBD after exchange")
            return
        if flags == 7 and len(body) == 12:
            if self.stage in ("two-way", "exstart"):
                if self.stage == "two-way":
                    self.sequence = int(time.time() * 1000) & 0xffffffff
                    self.stage = "exstart"
                self.send_dbd(7)
            else:
                self.restart_exchange("SeqNumberMismatch: unexpected initial DBD")
            return
        if flags & 5:
            if self.stage == "exchange":
                self.restart_exchange("SeqNumberMismatch: unexpected DBD flags")
            return
        if self.stage not in ("exstart", "exchange"):
            return
        if seq != self.sequence:
            if (seq == (self.sequence - 1) & 0xffffffff
                    and identity == self.last_peer_dbd and self.last_dbd):
                self.transmit(self.last_dbd, "DBD duplicate")
            elif self.stage == "exchange":
                self.restart_exchange("SeqNumberMismatch: unexpected DD sequence")
            return
        if self.peer_dbd_options is not None and options != self.peer_dbd_options:
            self.restart_exchange("SeqNumberMismatch: DBD Options changed")
            return
        self.peer_dbd_options = options
        self.last_peer_dbd = identity
        self.remember_summaries(body)
        if self.stage == "exstart" or flags & 2:
            self.stage = "exchange"
            self.sequence = (self.sequence + 1) & 0xffffffff
            self.send_dbd(1)
        else:
            self.last_dbd = None
            self.stage = "loading"
            self.log.info("[OSPF] DBD exchange complete; LSR=%d", len(self.requests))
            if self.requests:
                self.send_requests()
            else:
                self.finish_loading()

    def send_requests(self):
        if not self.requests or not self.address:
            return
        data = packets.lsr(self.router, self.requests, self.address, self.mac)
        if len(data) > cfg.MTU + 14:
            raise ValueError("demo LSR exceeds link MTU")
        if self.transmit(data, "LSR"):
            self.lsr_sent_at = self.clock()
            self.log.info("[OSPF] requesting %d remote LSAs", len(self.requests))

    def on_lsr(self, body):
        if self.stage not in ("exchange", "loading", "synchronized"):
            return
        keys = [packets.lsa_key(OSPFv3_LSReq_Item(body[i:i + 12]))
                for i in range(0, len(body), 12)]
        self.log.info("[OSPF][LSR RX] requests=%d", len(keys))
        if any(key not in self.local for key in keys):
            # RFC 2328 section 10.7: BadLSReq invalidates the current
            # exchange, even if some other requested LSAs are available.
            self.restart_exchange("BadLSReq: requested LSA is absent")
            return
        requested = [self.local[key] for key in keys]
        if requested:
            self.transmit(packets.lsu(self.router, requested, self.address,
                                      self.mac), "LSU reply")

    def restart_exchange(self, reason):
        """Re-negotiate a broken adjacency without forgetting the neighbor."""
        self.log.warning("[OSPF] %s; restarting database exchange", reason)
        self.stage = "exstart"
        self.sequence = (self.sequence + 1) & 0xffffffff
        self.clear_exchange_state()
        self.send_dbd(7)

    def clear_exchange_state(self):
        """Forget protocol exchange state, retaining the neighbor identity."""
        self.last_dbd = None
        self.last_peer_dbd = None
        self.peer_dbd_options = None
        self.dbd_sent_at = 0
        self.requests.clear()
        self.lsr_sent_at = 0
        self.pending_acks.clear()
        self.local_sent_at = 0

    def on_lsu(self, body):
        received = packets.lsa_headers(body)
        self.log.info("[OSPF][LSU RX] lsas=%d", len(received))
        if not received:
            return
        self.transmit(packets.lsack(self.router, [wire[:20] for _, wire in received],
                                    self.address, self.mac), "LSAck")
        newest_self = None
        for hdr, _ in received:
            key = packets.lsa_key(hdr)
            if key[2] == self.router["router_id"] and key in self.local:
                current = OSPFv3_LSA_Hdr(self.local[key][:20])
                if lsa_is_newer(hdr, current):
                    seq = int(hdr.seq)
                    if (newest_self is None
                            or lsa_seq_rank(seq) > lsa_seq_rank(newest_self)):
                        newest_self = seq
            expected = self.requests.get(key)
            if expected is None:
                continue
            if (lsa_seq_rank(hdr.seq) > lsa_seq_rank(expected.seq) or
                    (int(hdr.seq) == int(expected.seq)
                     and int(hdr.chksum) >= int(expected.chksum))):
                del self.requests[key]
        if newest_self is not None:
            if newest_self == 0x7fffffff:
                self.log.error("[OSPF] cannot fight back MaxSequenceNumber LSA")
            else:
                self.local_sequence = max(
                    lsa_seq_rank(self.local_sequence),
                    lsa_seq_rank(newest_self)) ^ 0x80000000
                self.local_sequence += 1
                self.local = packets.local_lsas(
                    self.router, self.router_id, self.interface_id, self.local_sequence)
                if self.stage == "synchronized":
                    self.send_local_update()
                    self.local_refreshed_at = self.clock()
                self.log.info("[OSPF] re-originated newer self-LSA at seq=0x%08x",
                              self.local_sequence)
        if self.stage == "loading" and not self.requests:
            self.finish_loading()

    def finish_loading(self):
        if self.stage != "loading":
            return
        self.stage = "synchronized"
        self.local_refreshed_at = self.clock()
        self.send_local_update()
        self.log.info("[OSPF] database exchange complete; check Full in FRR")

    def send_local_update(self, keys=None):
        if not self.local or not self.address:
            return
        if keys is None:
            keys = list(self.local)
        if not keys:
            return
        lsas = [self.local[key] for key in keys]
        if self.transmit(packets.lsu(self.router, lsas, self.address,
                                     self.mac), "local LSU"):
            for key in keys:
                self.pending_acks[key] = OSPFv3_LSA_Hdr(self.local[key][:20])
            self.local_sent_at = self.clock()
            self.log.info("[OSPF] advertised %d local LSAs", len(keys))

    def on_lsack(self, body):
        for offset in range(0, len(body), 20):
            hdr = OSPFv3_LSA_Hdr(body[offset:offset + 20])
            key = packets.lsa_key(hdr)
            pending = self.pending_acks.get(key)
            if (pending and int(pending.seq) == int(hdr.seq)
                    and int(pending.chksum) == int(hdr.chksum)):
                del self.pending_acks[key]
        self.log.info("[OSPF][LSAck RX] pending=%d", len(self.pending_acks))
