"""Strict OSPFv3 packet parsers; Scapy handles the protocol fields."""

import ipaddress
from ipaddress import IPv4Address
import struct

from scapy.contrib.ospf import (
    OSPFv3_DBDesc, OSPFv3_Hdr, OSPFv3_Hello, OSPFv3_LSA_Hdr,
    OSPFv3_LSAck, OSPFv3_LSReq, OSPFv3_LSUpd,
)
from scapy.error import Scapy_Exception
from ospfv3 import config as cfg
from ospfv3.packet import calculate_ospfv3_checksum
from ospfv3.lsa import (
    parse_ospfv3_router_lsa, parse_ospfv3_link_lsa,
    parse_ospfv3_intra_area_prefix_lsa, ospfv3_lsa_checksum,
)

_LSA_BODY_PARSERS = {
    0x2001: ("router_lsa", "Router-LSA", parse_ospfv3_router_lsa),
    0x0008: ("link_lsa", "Link-LSA", parse_ospfv3_link_lsa),
    0x2009: ("intra_area_prefix_lsa", "Intra-Area-Prefix-LSA", parse_ospfv3_intra_area_prefix_lsa),
}


def _packet_bytes(ospf_data, pkt_len, minimum_length):
    if pkt_len < minimum_length:
        raise ValueError(f"packet is shorter than {minimum_length} bytes")
    if len(ospf_data) < pkt_len:
        raise ValueError(
            f"truncated OSPF packet: declared={pkt_len} available={len(ospf_data)}")
    if int.from_bytes(ospf_data[2:4], "big") != pkt_len:
        raise ValueError("OSPF header length differs from pkt_len")
    return bytes(ospf_data[:pkt_len])


def _decode_packet(raw_packet, packet_class):
    try:
        packet = OSPFv3_Hdr(raw_packet)
        if not isinstance(packet.payload, packet_class):
            raise ValueError(f"expected {packet_class.__name__} payload")
        return packet.payload
    except (Scapy_Exception, struct.error, IndexError, TypeError) as exc:
        raise ValueError(f"unable to decode OSPFv3 packet: {exc}") from exc


def _lsa_header_fields(header):
    return {
        "ls_age": int(header.age), "ls_type": int(header.type),
        "link_state_id": header.id, "advertising_router": header.adrouter,
        "ls_sequence": int(header.seq), "ls_checksum": int(header.chksum),
        "ls_length": int(header.len),
    }


def _parse_lsa_header(raw_header):
    if len(raw_header) != 20:
        raise ValueError("LSA header must contain exactly 20 bytes")
    try:
        header = OSPFv3_LSA_Hdr(bytes(raw_header))
    except (Scapy_Exception, struct.error, IndexError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid LSA header: {exc}") from exc
    return {**_lsa_header_fields(header), "raw_header": bytes(raw_header)}


def _items(ospf_data, pkt_len, base, size, packet_class, field,
           invalid, mismatch, required=False):
    """Validate byte alignment and Scapy's decoded item count together."""
    raw = _packet_bytes(ospf_data, pkt_len, base)
    length = pkt_len - base
    if (required and length <= 0) or length % size:
        raise ValueError(f"{invalid}={length}")
    packet = _decode_packet(raw, packet_class)
    elements = list(getattr(packet, field) or ())
    if len(elements) != length // size:
        raise ValueError(mismatch)
    return packet, elements


def parse_hello(ospf_data, pkt_len):
    hello, neighbors = _items(
        ospf_data, pkt_len, 36, 4, OSPFv3_Hello, "neighbors",
        "invalid neighbor-list length",
        "Hello neighbor count does not match payload length")
    return {
        "interface_id": int(hello.intid), "router_priority": int(hello.prio),
        "options": int(hello.options), "hello_interval": int(hello.hellointerval),
        "dead_interval": int(hello.deadinterval),
        "designated_router": int(IPv4Address(hello.router)),
        "backup_designated_router": int(IPv4Address(hello.backup)),
        "neighbors": neighbors,
    }


def parse_dbd(ospf_data, pkt_len):
    dbd, lsa_headers = _items(
        ospf_data, pkt_len, 28, 20, OSPFv3_DBDesc, "lsaheaders",
        "invalid LSA-summary length", "DBD summary count does not match payload length")
    flags = int(dbd.dbdescr)
    return {
        "interface_mtu": int(dbd.mtu), "options": int(dbd.options),
        "i_bit": bool(flags & 4), "m_bit": bool(flags & 2),
        "ms_bit": bool(flags & 1), "dd_sequence": int(dbd.ddseq),
        "lsa_headers": [_lsa_header_fields(header) for header in lsa_headers],
    }


def parse_lsr(ospf_data, pkt_len):
    _, requests = _items(
        ospf_data, pkt_len, 16, 12, OSPFv3_LSReq, "requests",
        "invalid payload length", "LSR item count does not match payload length", True)
    return [{
        "ls_type": int(item.type), "link_state_id": item.id,
        "advertising_router": item.adrouter,
    } for item in requests]


def parse_lsu(ospf_data, pkt_len):
    raw = _packet_bytes(ospf_data, pkt_len, 20)
    # Count is the fixed four-byte, network-order field after the OSPF header.
    number_of_lsas = int.from_bytes(raw[16:20], "big")

    parsed, offset = [], 20
    for number in range(1, number_of_lsas + 1):
        if offset + 20 > pkt_len:
            raise ValueError(f"insufficient data for LSA header #{number}")
        lsa = _parse_lsa_header(raw[offset:offset + 20])
        length = lsa["ls_length"]
        if length < 20:
            raise ValueError(f"invalid LSA length #{number}: {length}")
        if offset + length > pkt_len:
            raise ValueError(
                f"LSA #{number} exceeds packet boundary "
                f"(offset={offset} length={length} packet={pkt_len})")
        wire = raw[offset:offset + length]
        checksum = ospfv3_lsa_checksum(wire)
        if lsa["ls_checksum"] != checksum:
            raise ValueError(
                f"invalid LSA checksum #{number}: "
                f"received=0x{lsa['ls_checksum']:04x}, calculated=0x{checksum:04x}")
        body_parser = _LSA_BODY_PARSERS.get(lsa["ls_type"])
        if body_parser is not None:
            key, label, decode = body_parser
            try:
                lsa[key] = decode(wire)
            except ValueError as exc:
                raise ValueError(f"{label} parse error #{number}: {exc}") from exc
        parsed.append(lsa)
        offset += length
    if offset != pkt_len:
        raise ValueError(f"length mismatch parsed={offset} packet={pkt_len}")
    return parsed


def parse_lsack(ospf_data, pkt_len):
    _, headers = _items(
        ospf_data, pkt_len, 16, 20, OSPFv3_LSAck, "lsaheaders",
        "invalid payload length", "LSAck header count does not match payload length", True)
    return [_lsa_header_fields(header) for header in headers]


def validate_ospfv3_transport(pkt, ipv6_pkt, logger):
    """Validate the IPv6/OSPFv3 envelope before RX handles a message.

    Return the unchanged OSPF bytes and dispatch metadata, or None on drop.
    All wire checks and warning messages match the former Ryu PacketIn path.
    """
    try:
        ipv6_index = pkt.protocols.index(ipv6_pkt)
        ospf_payload = pkt.protocols[ipv6_index + 1]
    except (ValueError, IndexError):
        return None
    if not isinstance(ospf_payload, (bytes, bytearray)):
        return None
    ospf_data = bytes(ospf_payload)
    if len(ospf_data) < 16:
        return None
    try:
        ospf_header = OSPFv3_Hdr(ospf_data[:16])
        version = int(ospf_header.version)
        pkt_type = int(ospf_header.type)
        pkt_len = int(ospf_header.len)
        router_id_text = ospf_header.src
        area_id_text = ospf_header.area
        router_id = int(ipaddress.IPv4Address(router_id_text))
        checksum = int(ospf_header.chksum)
        instance_id = int(ospf_header.instance)
    except (Scapy_Exception, ValueError, TypeError, IndexError) as exc:
        logger.warning("[OSPF][DROP] invalid OSPFv3 header: %s", exc)
        return None
    if pkt_len < 16 or pkt_len > len(ospf_data):
        return None
    ospf_for_checksum = bytearray(ospf_data[:pkt_len])
    ospf_for_checksum[12:14] = b"\x00\x00"
    calculated_checksum = calculate_ospfv3_checksum(
        ipv6_pkt.src, ipv6_pkt.dst, bytes(ospf_for_checksum))
    if checksum != calculated_checksum:
        logger.warning(
            "[OSPF][WARN] invalid checksum "
            "received=0x%04x calculated=0x%04x",
            checksum, calculated_checksum)
        return None
    if area_id_text != cfg.AREA_ID:
        logger.warning("[OSPF][DROP] area mismatch "
                       "received=%s expected=%s", area_id_text, cfg.AREA_ID)
        return None
    if instance_id != cfg.INSTANCE_ID:
        logger.warning("[OSPF][DROP] instance mismatch "
                       "received=%d expected=%d", instance_id, cfg.INSTANCE_ID)
        return None
    try:
        ospf_source = ipaddress.IPv6Address(ipv6_pkt.src)
    except ValueError:
        return None
    if not ospf_source.is_link_local:
        logger.warning("[OSPF][DROP] non-link-local source=%s", ipv6_pkt.src)
        return None
    try:
        ospf_destination = ipaddress.IPv6Address(ipv6_pkt.dst)
    except ValueError:
        return None
    ospf_multicast = (ipaddress.IPv6Address("ff02::5"),
                      ipaddress.IPv6Address("ff02::6"))
    if ospf_destination in ospf_multicast and ipv6_pkt.hop_limit != 1:
        logger.warning(
            "[OSPF][DROP] invalid multicast hop-limit "
            "dst=%s received=%d expected=1",
            ipv6_pkt.dst, ipv6_pkt.hop_limit)
        return None
    if version != 3:
        return None
    return ospf_data, pkt_type, pkt_len, router_id_text, area_id_text, router_id
