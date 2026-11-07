"""IPv6 LAN/transit state and local NDP/ICMPv6 responses for the SDN gateway.

Ryu owns the logical gateway; FRRouting owns paths beyond the transit link.
Only a verified OSPFv3 transit peer can resolve the link-local address.
"""

import ipaddress

from ryu.lib.packet import ethernet, ipv6, icmpv6, packet, ether_types
from ospfv3 import config as cfg


class DataPlane:
    def __init__(self):
        self.lan_port = None
        self.lan_hosts = {}
        self.transit_port = None
        self.transit_router_mac = None
        self.transit_router_ipv6 = None
        self.lan_network = ipaddress.IPv6Network(
            f"{cfg.LAN_PREFIX}/{cfg.LAN_PREFIX_LEN}", strict=False)

    def learn_transit_router(self, in_port, ipv6_address, mac_address):
        changed = (self.transit_port != in_port
                   or self.transit_router_mac != mac_address
                   or self.transit_router_ipv6 != ipv6_address)
        self.transit_port = in_port
        self.transit_router_mac = mac_address
        self.transit_router_ipv6 = ipv6_address
        return changed

    def reset(self):
        self.lan_port = None
        self.lan_hosts.clear()
        self.reset_transit()

    def reset_transit(self):
        self.transit_port = None
        self.transit_router_mac = None
        self.transit_router_ipv6 = None

    def learn_lan_host(self, in_port, ipv6_address, mac_address):
        try:
            source_ipv6 = ipaddress.IPv6Address(ipv6_address)
        except ValueError:
            return False
        if source_ipv6 not in self.lan_network:
            return False
        if self.transit_port is not None and in_port == self.transit_port:
            return False
        if self.lan_port is None:
            self.lan_port = in_port
        elif in_port != self.lan_port:
            return False
        self.lan_hosts[ipv6_address] = mac_address
        return True

    def handle_ndp(self, pkt, eth_pkt, ipv6_pkt, in_port):
        icmp_pkt = pkt.get_protocol(icmpv6.icmpv6)
        if icmp_pkt is None or icmp_pkt.type_ != icmpv6.ND_NEIGHBOR_SOLICIT:
            return None
        if not isinstance(icmp_pkt.data, icmpv6.nd_neighbor):
            return None
        # RFC 4861 §7.1.1: reject malformed NS before learning any state.
        if ipv6_pkt.hop_limit != 255 or icmp_pkt.code != 0:
            return None
        target = icmp_pkt.data.dst
        if target not in (cfg.LAN_GATEWAY, cfg.LINK_LOCAL):
            return None
        if ipv6_pkt.src == "::":
            return None
        # Preserve validation for both LAN and transit solicitations.
        ipaddress.IPv6Address(ipv6_pkt.src)

        if target == cfg.LAN_GATEWAY:
            if not self.learn_lan_host(in_port, ipv6_pkt.src, eth_pkt.src):
                return None
        elif target == cfg.LINK_LOCAL:
            if self.transit_port is None or in_port != self.transit_port:
                return None
            if self.transit_router_ipv6 is None or self.transit_router_mac is None:
                return None
            if ipv6_pkt.src != self.transit_router_ipv6:
                return None
            if eth_pkt.src != self.transit_router_mac:
                return None

        return self.build_neighbor_advertisement(
            destination_mac=eth_pkt.src, destination_ipv6=ipv6_pkt.src,
            target_ipv6=target)

    @staticmethod
    def _icmpv6_packet(destination_mac, source_ipv6, destination_ipv6, hop_limit):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            dst=destination_mac, src=cfg.ROUTER_MAC,
            ethertype=ether_types.ETH_TYPE_IPV6))
        pkt.add_protocol(ipv6.ipv6(
            src=source_ipv6, dst=destination_ipv6, nxt=58, hop_limit=hop_limit))
        return pkt

    @staticmethod
    def _serialize_icmpv6(pkt, type_, data):
        pkt.add_protocol(icmpv6.icmpv6(type_=type_, code=0, csum=0, data=data))
        pkt.serialize()
        return bytes(pkt.data)

    def build_neighbor_advertisement(self, destination_mac,
                                     destination_ipv6, target_ipv6):
        pkt = self._icmpv6_packet(destination_mac, target_ipv6,
                                  destination_ipv6, 255)
        option = icmpv6.nd_option_tla(hw_src=cfg.ROUTER_MAC)
        neighbor = icmpv6.nd_neighbor(res=0x7, dst=target_ipv6, option=option)
        return self._serialize_icmpv6(pkt, icmpv6.ND_NEIGHBOR_ADVERT, neighbor)

    def build_echo_reply(self, destination_mac, destination_ipv6, echo_data):
        pkt = self._icmpv6_packet(destination_mac, cfg.LAN_GATEWAY,
                                  destination_ipv6, 64)
        reply = icmpv6.echo(id_=echo_data.id, seq=echo_data.seq,
                            data=echo_data.data)
        return self._serialize_icmpv6(pkt, 129, reply)

    def handle_echo_request(self, pkt, eth_pkt, ipv6_pkt, in_port):
        icmp_pkt = pkt.get_protocol(icmpv6.icmpv6)
        if icmp_pkt is None or icmp_pkt.type_ != 128:
            return None
        if ipv6_pkt.dst != cfg.LAN_GATEWAY:
            return None
        if not isinstance(icmp_pkt.data, icmpv6.echo):
            return None
        if not self.learn_lan_host(in_port=in_port, ipv6_address=ipv6_pkt.src,
                                   mac_address=eth_pkt.src):
            return None
        return self.build_echo_reply(
            destination_mac=eth_pkt.src, destination_ipv6=ipv6_pkt.src,
            echo_data=icmp_pkt.data)
