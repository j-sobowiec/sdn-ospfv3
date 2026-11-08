"""RFC 5340 wire-format checks; expected values use stdlib byte parsing."""

import ipaddress
import struct

import config as cfg
import packets


def wire_parts(wire):
    assert wire[12:14] == b"\x86\xdd"  # EtherType IPv6
    assert wire[14] >> 4 == 6
    assert wire[20] == 89  # IPv6 Next Header OSPF
    assert wire[21] == 1  # single-hop protocol traffic
    iplen = struct.unpack("!H", wire[18:20])[0]
    assert len(wire) == 14 + 40 + iplen
    assert iplen >= 16
    ospf = wire[54:]
    assert ospf[0] == 3
    assert struct.unpack("!H", ospf[2:4])[0] == len(ospf)
    return ospf


def checksum16(data):
    if len(data) & 1:
        data += b"\x00"
    accum = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while accum >> 16:
        accum = (accum & 0xFFFF) + (accum >> 16)
    return (~accum) & 0xFFFF


def assert_ipv6_ospf_checksum(wire):
    ospf = wire_parts(wire)
    src, dst = wire[22:38], wire[38:54]
    pseudo = src + dst + struct.pack("!I3xB", len(ospf), 89)
    # Checksum verification over the whole OSPF datagram gives zero.
    assert checksum16(pseudo + ospf) == 0


def assert_lsa_fletcher(lsa):
    # RFC 2328, Appendix B: Fletcher checksum excludes the first two LS-age
    # bytes, but includes the two checksum bytes themselves.
    sum1 = sum2 = 0
    for byte in lsa[2:]:
        sum1 = (sum1 + byte) % 255
        sum2 = (sum2 + sum1) % 255
    assert (sum1, sum2) == (0, 0)


def test_hello_header_and_ipv6_pseudoheader_checksum():
    wire = packets.hello()
    ospf = wire_parts(wire)
    assert ospf[1] == 1
    assert ipaddress.IPv4Address(ospf[4:8]) == ipaddress.IPv4Address(cfg.ROUTER_ID)
    assert ospf[8:12] == b"\x00" * 4  # backbone area 0
    assert ospf[14] == cfg.INSTANCE_ID
    assert_ipv6_ospf_checksum(wire)


def test_hello_intervals_and_neighbor_ids():
    ospf = wire_parts(packets.hello(["1.1.1.1", "2.2.2.2"]))
    body = ospf[16:]
    assert struct.unpack("!I", body[:4])[0] == cfg.INTERFACE_ID
    assert struct.unpack("!H", body[8:10])[0] == cfg.HELLO_INTERVAL
    assert struct.unpack("!H", body[10:12])[0] == cfg.DEAD_INTERVAL
    assert body[20:] == b"\x01\x01\x01\x01\x02\x02\x02\x02"


def test_dbd_master_flags_and_sequence_are_on_wire():
    ospf = wire_parts(packets.dbd(0x12345678, 7))
    assert ospf[1] == 2
    assert struct.unpack("!H", ospf[20:22])[0] == cfg.MTU
    assert ospf[23] == 7
    assert struct.unpack("!I", ospf[24:28])[0] == 0x12345678
    assert_ipv6_ospf_checksum(packets.dbd(0x12345678, 7))


def test_local_lsa_types_lengths_checksums_and_lan_prefix():
    result = packets.local_lsas("1.1.1.1", 3)
    assert {key[0] for key in result} == {0x2001, 0x0008, 0x2009}
    for key, raw in result.items():
        assert len(raw) >= 20
        assert struct.unpack("!H", raw[18:20])[0] == len(raw)
        assert struct.unpack("!H", raw[2:4])[0] == key[0]
        assert ipaddress.IPv4Address(raw[8:12]) == ipaddress.IPv4Address(cfg.ROUTER_ID)
        assert_lsa_fletcher(raw)

    router = next(raw for key, raw in result.items() if key[0] == 0x2001)
    assert router[24] == 1  # point-to-point link
    assert struct.unpack("!H", router[26:28])[0] == 10
    assert struct.unpack("!I", router[28:32])[0] == cfg.INTERFACE_ID
    assert struct.unpack("!I", router[32:36])[0] == 3
    assert ipaddress.IPv4Address(router[36:40]) == ipaddress.IPv4Address("1.1.1.1")

    intra = next(raw for key, raw in result.items() if key[0] == 0x2009)
    assert struct.unpack("!H", intra[20:22])[0] == 1  # one LAN prefix
    assert struct.unpack("!H", intra[22:24])[0] == 0x2001  # router-LSA ref
    assert intra[32] == 64
    subnet = ipaddress.IPv6Network((ipaddress.IPv6Address(intra[36:44] + b"\x00" * 8), 64))
    assert subnet == ipaddress.IPv6Network(cfg.LAN_PREFIX)


def test_lsu_lsa_count_and_integrity_on_wire():
    lsas = list(packets.local_lsas("1.1.1.1", 3).values())
    wire = packets.lsu(lsas, "fe80::1", "02:00:00:00:10:01")
    ospf = wire_parts(wire)
    assert ospf[1] == 4
    assert struct.unpack("!I", ospf[16:20])[0] == 3
    assert ospf[20:] == b"".join(lsas)
    assert_ipv6_ospf_checksum(wire)
