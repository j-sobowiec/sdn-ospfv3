"""OSPFv3 wire encoding/validation; Scapy owns protocol serialization."""

import ipaddress
import struct

from scapy.contrib.ospf import (
    OSPFv3_DBDesc, OSPFv3_Hdr, OSPFv3_Hello, OSPFv3_Intra_Area_Prefix_LSA,
    OSPFv3_Link, OSPFv3_Link_LSA, OSPFv3_LSA_Hdr, OSPFv3_LSAck,
    OSPFv3_LSReq, OSPFv3_LSReq_Item, OSPFv3_LSUpd, OSPFv3_Prefix_Item,
    OSPFv3_Router_LSA, ospf_lsa_checksum,
)
from scapy.layers.inet6 import IPv6, in6_chksum
from scapy.layers.l2 import Ether
from scapy.packet import Raw

import config as cfg

ALL_ROUTERS = "ff02::5"
ALL_ROUTERS_MAC = "33:33:00:00:00:05"


def lsa_key(header):
    return int(header.type), header.id, header.adrouter


def lsa_headers(raw):
    """Decode only LSA headers and boundaries, preserving opaque bodies."""
    if len(raw) < 4:
        raise ValueError("short LSU")
    count = struct.unpack("!I", raw[:4])[0]
    offset, result = 4, []
    if count > (len(raw) - 4) // 20:
        raise ValueError("invalid LSU LSA count")
    for _ in range(count):
        if offset + 20 > len(raw):
            raise ValueError("truncated LSA header")
        head = OSPFv3_LSA_Hdr(raw[offset:offset + 20])
        size = int(head.len)
        if size < 20 or offset + size > len(raw):
            raise ValueError("invalid LSA length")
        wire = raw[offset:offset + size]
        if wire[16:18] != ospf_lsa_checksum(wire):
            raise ValueError("invalid LSA Fletcher checksum")
        result.append((head, wire))
        offset += size
    if offset != len(raw):
        raise ValueError("extra LSU bytes")
    return result


def decode(frame):
    """Validate the envelope and non-LSU payload layout before dispatch."""
    eth = Ether(frame)
    if not eth.haslayer(IPv6):
        raise ValueError("not IPv6")
    ip = eth[IPv6]
    if ip.nh != 89:
        raise ValueError("not OSPFv3")
    if ip.hlim < 1 or (ip.dst in (ALL_ROUTERS, "ff02::6") and ip.hlim != 1):
        raise ValueError("invalid OSPFv3 Hop Limit")
    if not ipaddress.IPv6Address(ip.src).is_link_local:
        raise ValueError("OSPFv3 source must be link-local")
    if ip.dst not in (ALL_ROUTERS, "ff02::6", cfg.LINK_LOCAL):
        raise ValueError("unexpected OSPFv3 destination")
    raw = bytes(ip.payload)
    if len(raw) < 16:
        raise ValueError("short OSPFv3 packet")
    hdr = OSPFv3_Hdr(raw)
    if (hdr.version != 3 or hdr.area != cfg.AREA_ID or
            hdr.instance != cfg.INSTANCE_ID or hdr.len != len(raw)):
        raise ValueError("OSPFv3 version, area, instance or length mismatch")
    check = bytearray(raw)
    check[12:14] = b"\x00\x00"
    calculated = in6_chksum(89, IPv6(src=ip.src, dst=ip.dst, nh=89), bytes(check))
    if hdr.chksum != calculated:
        raise ValueError("invalid OSPFv3 checksum")
    body = raw[16:]
    sizes = {1: (20, 4), 2: (12, 20), 3: (12, 12), 5: (20, 20)}
    if hdr.type in sizes:
        base, item = sizes[hdr.type]
        if len(body) < base or (len(body) - base) % item:
            raise ValueError("invalid OSPFv3 message length")
    return eth, ip, hdr, body


def frame(packet_type, payload, dst=ALL_ROUTERS, mac=ALL_ROUTERS_MAC):
    ip = IPv6(src=cfg.LINK_LOCAL, dst=dst, nh=89, hlim=1)
    ospf = OSPFv3_Hdr(type=packet_type, src=cfg.ROUTER_ID,
                      area=cfg.AREA_ID, instance=cfg.INSTANCE_ID)
    return bytes(Ether(src=cfg.GATEWAY_MAC, dst=mac) / ip / ospf / payload)


def hello(neighbors=()):
    body = OSPFv3_Hello(intid=cfg.INTERFACE_ID, prio=1, options=cfg.OPTIONS,
                        hellointerval=cfg.HELLO_INTERVAL,
                        deadinterval=cfg.DEAD_INTERVAL, router="0.0.0.0",
                        backup="0.0.0.0", neighbors=list(neighbors))
    return frame(1, body)


def dbd(sequence, flags):
    return frame(2, OSPFv3_DBDesc(mtu=cfg.MTU, options=cfg.OPTIONS,
                                   dbdescr=flags, ddseq=sequence, lsaheaders=[]))


def lsr(requests, dst, mac):
    items = [OSPFv3_LSReq_Item(type=k[0], id=k[1], adrouter=k[2])
             for k in requests]
    return frame(3, OSPFv3_LSReq(requests=items), dst, mac)


def lsu(lsas, dst, mac):
    # Opaque LSA bodies are preserved; Scapy builds the OSPFv3/IPv6 checksums.
    payload = OSPFv3_LSUpd(lsacount=len(lsas)) / Raw(b"".join(lsas))
    return frame(4, payload, dst, mac)


def lsack(headers, dst, mac):
    items = [OSPFv3_LSA_Hdr(bytes(h)[:20]) for h in headers]
    return frame(5, OSPFv3_LSAck(lsaheaders=items), dst, mac)


def local_lsas(peer_id, peer_interface_id, sequence=cfg.LSA_INITIAL_SEQ):
    """Point-to-point adjacency + transit link + stub SDN LAN."""
    prefix = OSPFv3_Prefix_Item(prefixlen=64, prefixoptions=0, metric=10,
                                prefix=cfg.LAN_PREFIX)
    transit = OSPFv3_Prefix_Item(prefixlen=64, prefixoptions=0, metric=0,
                                 prefix=cfg.TRANSIT_PREFIX)
    router = OSPFv3_Router_LSA(
        age=0, type=0x2001, id="0.0.0.0", adrouter=cfg.ROUTER_ID,
        seq=sequence, flags=0, options=cfg.OPTIONS,
        linklist=[OSPFv3_Link(type=1, reserved=0, metric=10,
                              intid=cfg.INTERFACE_ID,
                              neighintid=peer_interface_id, neighbor=peer_id)])
    link = OSPFv3_Link_LSA(
        age=0, type=0x0008, id=str(ipaddress.IPv4Address(cfg.INTERFACE_ID)),
        adrouter=cfg.ROUTER_ID, seq=sequence, prio=1, options=cfg.OPTIONS,
        lladdr=cfg.LINK_LOCAL, prefixes=1, prefixlist=[transit])
    intra = OSPFv3_Intra_Area_Prefix_LSA(
        age=0, type=0x2009, id="0.0.0.0", adrouter=cfg.ROUTER_ID,
        seq=sequence, prefixes=1, reflstype=0x2001,
        reflsid="0.0.0.0", refadrouter=cfg.ROUTER_ID, prefixlist=[prefix])
    lsas = (bytes(obj) for obj in (router, link, intra))
    return {lsa_key(OSPFv3_LSA_Hdr(wire[:20])): wire for wire in lsas}
