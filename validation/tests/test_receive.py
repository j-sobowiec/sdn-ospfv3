"""Independent Scapy peer produces on-wire packets for black-box receiving."""

import logging
import struct

import pytest
from scapy.contrib.ospf import (OSPFv3_DBDesc, OSPFv3_Hdr, OSPFv3_Hello,
                                OSPFv3_LSReq, OSPFv3_LSReq_Item, OSPFv3_LSUpd)
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

import config as cfg
import packets
from peer import Peer


def inbound(payload, kind, *, router="1.1.1.1", area="0.0.0.0", instance=0,
            source="fe80::1", dest=cfg.LINK_LOCAL, mac=cfg.FRR_MAC):
    return bytes(
        Ether(src=mac, dst=cfg.GATEWAY_MAC)
        / IPv6(src=source, dst=dest, nh=89, hlim=1)
        / OSPFv3_Hdr(type=kind, src=router, area=area, instance=instance)
        / payload
    )


def hello(*, neighbors=(), hello_interval=cfg.HELLO_INTERVAL,
          dead_interval=cfg.DEAD_INTERVAL, router="1.1.1.1", mac=cfg.FRR_MAC,
          options=cfg.OPTIONS):
    body = OSPFv3_Hello(
        intid=3, prio=1, options=options,
        hellointerval=hello_interval, deadinterval=dead_interval,
        router="0.0.0.0", backup="0.0.0.0", neighbors=list(neighbors),
    )
    return inbound(body, 1, router=router, mac=mac)


def dbd(sequence, flags, *, options=cfg.OPTIONS):
    return inbound(OSPFv3_DBDesc(
        mtu=cfg.MTU, options=options, dbdescr=flags,
        ddseq=sequence, lsaheaders=[]), 2)


class Clock:
    def __init__(self):
        self.time = 100.0

    def __call__(self):
        return self.time

    def advance(self, seconds):
        self.time += seconds


def fresh_peer():
    clock = Clock()
    sent = []

    def transmit(frame):
        sent.append(frame)
        return True

    return Peer(transmit, logging.getLogger("test-peer"), clock=clock), clock, sent


def kinds(sent):
    return [raw[55] for raw in sent]  # ethernet(14) + IPv6(40) + OSPF type byte


def synchronized_peer():
    peer, clock, sent = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    peer.receive(dbd(123, 7))
    peer.receive(dbd(peer.sequence, 2))
    peer.receive(dbd(peer.sequence, 0))
    assert peer.stage == "synchronized"
    return peer, clock, sent


def test_accepts_valid_inbound_hello():
    eth, ip, hdr, body = packets.decode(hello(neighbors=[cfg.ROUTER_ID]))
    assert hdr.version == 3 and hdr.type == 1 and hdr.src == "1.1.1.1"
    assert ip.src == "fe80::1"
    assert len(body) == 24


@pytest.mark.parametrize("wire", [
    lambda: inbound(OSPFv3_Hello(), 1, area="0.0.0.1"),
    lambda: inbound(OSPFv3_Hello(), 1, instance=1),
    lambda: inbound(OSPFv3_Hello(), 1, source="2001:db8:10::1"),
    lambda: inbound(Raw(b"\x00" * 21), 1),  # malformed neighbor list
    lambda: inbound(Raw(struct.pack("!I", 2)), 4),  # two absent LSAs
])
def test_invalid_envelope_or_length_rejected(wire):
    with pytest.raises(ValueError):
        packets.decode(wire())


def test_modified_packet_checksum_rejected():
    raw = bytearray(hello())
    raw[-1] ^= 0x01
    with pytest.raises(ValueError, match="checksum"):
        packets.decode(bytes(raw))


def test_lsu_with_invalid_lsa_fletcher_checksum_is_rejected():
    original = next(iter(packets.local_lsas("1.1.1.1", 3).values()))
    broken = bytearray(original)
    broken[26] ^= 1  # mutate a Router-LSA metric, preserving its old checksum
    # A fresh, valid OSPF checksum ensures the rejection is caused by the LSA.
    raw_lsu = struct.pack("!I", 1) + bytes(broken)
    with pytest.raises(ValueError, match="Fletcher"):
        packets.decode(inbound(Raw(raw_lsu), 4))


def test_hello_two_way_progression_and_local_lsa_origination():
    peer, _, sent = fresh_peer()
    peer.receive(hello())
    assert peer.stage == "init"
    assert peer.router_id == "1.1.1.1"
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    assert peer.stage == "two-way"
    assert {key[0] for key in peer.local} == {0x2001, 0x0008, 0x2009}
    assert 1 in kinds(sent)


def test_mismatched_hello_timers_do_not_form_adjacency():
    peer, _, sent = fresh_peer()
    peer.receive(hello(hello_interval=9))
    assert peer.stage == "down"
    assert not sent


def test_regular_area_e_bit_mismatch_must_not_form_adjacency():
    """RFC 5340 §4.2.1.1/A.2: E-bit of a normal area cannot mismatch."""
    peer, _, _ = fresh_peer()
    # An otherwise well-formed peer says E=0, as on a stub area.
    peer.receive(hello(neighbors=[cfg.ROUTER_ID], options=cfg.OPTIONS & ~0x02))
    assert peer.stage == "down", "E-bit mismatch was accepted as Two-Way"


def test_e_bit_mismatch_does_not_advance_an_existing_init_neighbor():
    peer, _, _ = fresh_peer()
    peer.receive(hello())
    assert peer.stage == "init"
    peer.receive(hello(neighbors=[cfg.ROUTER_ID], options=cfg.OPTIONS & ~0x02))
    assert peer.stage == "init"


def test_wrong_router_id_does_not_replace_existing_neighbor():
    peer, _, _ = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    peer.receive(hello(neighbors=[cfg.ROUTER_ID], router="2.2.2.2"))
    assert peer.router_id == "1.1.1.1"


def test_dbd_exchange_reaches_local_loading_and_retransmits_unacked_lsas():
    peer, clock, sent = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    assert peer.stage == "two-way"
    peer.receive(dbd(123, 7))
    assert peer.stage == "exstart" and kinds(sent)[-1] == 2
    first_seq = peer.sequence
    peer.receive(dbd(first_seq, 2))
    assert peer.stage == "exchange" and kinds(sent)[-1] == 2
    peer.receive(dbd(peer.sequence, 0))
    assert peer.stage == "synchronized"
    assert kinds(sent)[-1] == 4
    assert len(peer.pending_acks) == 3
    previous = len(sent)
    clock.advance(cfg.RETRANSMIT_INTERVAL)
    peer.tick()
    assert len(sent) > previous and 4 in kinds(sent)[previous:]

    # Negative acknowledgment comparison: a different sequence must not clear.
    good_headers = [raw[:20] for raw in peer.local.values()]
    wrong = bytearray(good_headers[0])
    wrong[15] ^= 1  # sequence number, not the key
    peer.on_lsack(bytes(wrong))
    assert len(peer.pending_acks) == 3
    peer.on_lsack(b"".join(good_headers))
    assert not peer.pending_acks
    previous = len(sent)
    clock.advance(cfg.RETRANSMIT_INTERVAL)
    peer.tick()
    assert 4 not in kinds(sent)[previous:]


def test_neighbor_dead_interval_clears_state_and_restarts_hello():
    peer, clock, sent = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    clock.advance(cfg.DEAD_INTERVAL)
    peer.tick()
    assert peer.stage == "down" and peer.router_id is None
    assert 1 in kinds(sent)


def test_unknown_link_state_request_signals_database_desynchronization():
    """RFC 2328 §10.7, inherited by RFC 5340: BadLSReq restarts exchange."""
    peer, clock, sent = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    peer.receive(dbd(123, 7))
    peer.receive(dbd(peer.sequence, 2))
    peer.receive(dbd(peer.sequence, 0))
    assert peer.stage == "synchronized"
    assert peer.pending_acks
    previous_seq = peer.sequence
    request = OSPFv3_LSReq(requests=[
        OSPFv3_LSReq_Item(type=0x2001, id="9.9.9.9", adrouter="9.9.9.9")
    ])
    peer.receive(inbound(request, 3))
    assert peer.stage == "exstart", "BadLSReq must transition to ExStart"
    assert peer.sequence == (previous_seq + 1) & 0xffffffff
    assert not peer.requests and not peer.pending_acks
    assert kinds(sent)[-1] == 2  # new initial DBD, not a partial LSU reply
    assert sent[-1][77] == 7  # I/M/MS bits of the DBD body
    clock.advance(cfg.RETRANSMIT_INTERVAL)
    previous = len(sent)
    peer.tick()
    assert 2 in kinds(sent)[previous:]  # initial DBD is retransmitted
    # A fresh master/slave negotiation can complete after BadLSReq.
    peer.receive(dbd(777, 7))
    peer.receive(dbd(peer.sequence, 2))
    peer.receive(dbd(peer.sequence, 0))
    assert peer.stage == "synchronized"
    assert len(peer.pending_acks) == 3


def test_known_lsr_still_receives_correct_local_lsa():
    peer, _, sent = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    peer.receive(dbd(123, 7))
    peer.receive(dbd(peer.sequence, 2))
    peer.receive(dbd(peer.sequence, 0))
    assert peer.stage == "synchronized"
    key = next(key for key in peer.local if key[0] == 0x2001)
    request = OSPFv3_LSReq(requests=[
        OSPFv3_LSReq_Item(type=key[0], id=key[1], adrouter=key[2])
    ])
    peer.receive(inbound(request, 3))
    assert peer.stage == "synchronized"
    assert kinds(sent)[-1] == 4  # Link State Update reply
    assert sent[-1].endswith(peer.local[key])


def test_lsr_during_two_way_is_ignored_before_database_exchange():
    peer, _, sent = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    assert peer.stage == "two-way"
    key = next(key for key in peer.local if key[0] == 0x2001)
    request = OSPFv3_LSReq(requests=[
        OSPFv3_LSReq_Item(type=key[0], id=key[1], adrouter=key[2])
    ])
    count_before = len(sent)
    peer.receive(inbound(request, 3))
    assert peer.stage == "two-way" and len(sent) == count_before


def test_one_way_hello_downgrades_adjacency_and_clears_exchange_state():
    """A Hello omitting our RID is a 1-WayReceived event, even from Full."""
    peer, _, _ = synchronized_peer()
    assert peer.local and peer.pending_acks
    peer.receive(hello(neighbors=[]))
    assert peer.stage == "init"
    assert peer.router_id == "1.1.1.1"  # still a known one-way neighbor
    assert not peer.requests and not peer.pending_acks
    assert not peer.local and peer.last_dbd is None


def test_adjacency_can_recover_after_one_way_hello():
    peer, _, _ = synchronized_peer()
    peer.local_sequence += 3  # emulate LSAs already refreshed on this link
    old_lsa_seq = peer.local_sequence
    peer.receive(hello(neighbors=[]))
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    assert peer.stage == "two-way"
    assert peer.local_sequence == old_lsa_seq
    assert {struct.unpack("!I", raw[12:16])[0] for raw in peer.local.values()} == {
        old_lsa_seq}
    peer.receive(dbd(123, 7))
    peer.receive(dbd(peer.sequence, 2))
    peer.receive(dbd(peer.sequence, 0))
    assert peer.stage == "synchronized"


def test_wrong_dbd_sequence_during_exchange_restarts_negotiation():
    peer, _, sent = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    peer.receive(dbd(123, 7))
    peer.receive(dbd(peer.sequence, 2))
    assert peer.stage == "exchange"
    old_sequence = peer.sequence
    peer.receive(dbd((old_sequence + 5) & 0xffffffff, 0))
    assert peer.stage == "exstart"
    assert peer.sequence == (old_sequence + 1) & 0xffffffff
    assert kinds(sent)[-1] == 2 and sent[-1][77] == 7


def test_dbd_without_master_negotiation_does_not_leave_two_way():
    peer, _, sent = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    assert peer.stage == "two-way"
    before = len(sent)
    peer.receive(dbd(0, 0))
    assert peer.stage == "two-way"
    assert len(sent) == before


def test_duplicate_dbd_during_exchange_keeps_the_exchange_alive():
    peer, _, sent = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    peer.receive(dbd(123, 7))
    peer.receive(dbd(peer.sequence, 2))
    assert peer.stage == "exchange"
    seq = peer.sequence
    last_sent = sent[-1]
    peer.receive(dbd((seq - 1) & 0xffffffff, 2))
    assert peer.stage == "exchange" and peer.sequence == seq
    assert sent[-1] == last_sent  # retransmit our previous DBD


def test_unexpected_slave_master_flag_during_exchange_restarts():
    peer, _, _ = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    peer.receive(dbd(123, 7))
    peer.receive(dbd(peer.sequence, 2))
    assert peer.stage == "exchange"
    peer.receive(dbd(peer.sequence, 4))  # slave falsely asserts MS=1
    assert peer.stage == "exstart"


def test_fresh_initial_dbd_after_full_restarts_negotiation():
    peer, _, sent = synchronized_peer()
    peer.receive(dbd(987, 7))
    assert peer.stage == "exstart"
    assert kinds(sent)[-1] == 2 and sent[-1][77] == 7


def test_changed_dbd_options_during_exchange_restarts_negotiation():
    peer, _, _ = fresh_peer()
    peer.receive(hello(neighbors=[cfg.ROUTER_ID]))
    peer.receive(dbd(123, 7))
    peer.receive(dbd(peer.sequence, 2))
    assert peer.stage == "exchange"
    peer.receive(dbd(peer.sequence, 0, options=cfg.OPTIONS ^ 0x01))
    assert peer.stage == "exstart"


def test_duplicate_final_dbd_after_full_is_ignored():
    peer, _, sent = synchronized_peer()
    old_sequence = peer.sequence
    sent_before = len(sent)
    peer.receive(dbd(old_sequence, 0))
    assert peer.stage == "synchronized"
    assert peer.sequence == old_sequence
    assert len(sent) == sent_before


def test_newer_self_originated_lsa_in_lsu_is_fought_back():
    peer, _, sent = synchronized_peer()
    old_sequence = peer.local_sequence
    newer = packets.local_lsas(peer.router_id, peer.interface_id,
                               sequence=old_sequence + 3)
    router_lsa = next(wire for key, wire in newer.items() if key[0] == 0x2001)
    before = len(sent)
    peer.receive(inbound(OSPFv3_LSUpd(lsacount=1) / Raw(router_lsa), 4))
    assert peer.stage == "synchronized"
    assert peer.local_sequence == old_sequence + 4
    assert kinds(sent)[before:] == [5, 4]  # LSAck, then newer local LSU
    assert {struct.unpack("!I", wire[12:16])[0] for wire in peer.local.values()} == {
        old_sequence + 4}
    assert len(peer.pending_acks) == 3
