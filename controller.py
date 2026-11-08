"""Ryu/OpenFlow 1.3 gateway for one fixed IPv6 LAN and one OSPFv3 peer."""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, icmpv6, ipv6, packet
from ryu.ofproto import ofproto_v1_3

import config as cfg
from peer import Peer


class MinimalOSPFv3Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapath = None
        self.peer = Peer(self.send_ospf, self.logger)
        self.timer_thread = hub.spawn(self.tick)

    def tick(self):
        while True:
            if self.datapath is not None:
                self.peer.tick()
            hub.sleep(1)

    def send_packet(self, data, port):
        dp = self.datapath
        if dp is None:
            return False
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(port)], data=data))
        return True

    def send_ospf(self, data):
        return self.send_packet(data, cfg.TRANSIT_PORT)

    def flow(self, priority, match, actions):
        dp = self.datapath
        p = dp.ofproto_parser
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, priority=priority, match=p.OFPMatch(**match),
            instructions=[p.OFPInstructionActions(
                dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_ready(self, event):
        dp = event.msg.datapath
        self.datapath = dp
        self.peer.reset()
        p, ofp = dp.ofproto_parser, dp.ofproto
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE, table_id=0,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            match=p.OFPMatch()))

        punt = [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.flow(0, {}, punt)
        if dp.id != cfg.SWITCH_DPID:
            self.logger.error("[OPENFLOW] unexpected DPID %d", dp.id)
            return
        self.flow(200, dict(in_port=cfg.LAN_PORT, eth_type=0x86dd,
                            ipv6_dst=("2001:db8:1::", "ffff:ffff:ffff:ffff::")), punt)

        def route_actions(mac, port):
            return [p.OFPActionDecNwTtl(),
                    p.OFPActionSetField(eth_src=cfg.GATEWAY_MAC),
                    p.OFPActionSetField(eth_dst=mac),
                    p.OFPActionOutput(port)]

        self.flow(100, dict(
            in_port=cfg.LAN_PORT, eth_type=ether_types.ETH_TYPE_IPV6,
            eth_dst=cfg.GATEWAY_MAC, ipv6_src=cfg.LAN_HOST,
            ipv6_dst=("2000::", "e000::")),
            route_actions(cfg.FRR_MAC, cfg.TRANSIT_PORT))
        self.flow(100, dict(
            in_port=cfg.TRANSIT_PORT, eth_type=ether_types.ETH_TYPE_IPV6,
            eth_dst=cfg.GATEWAY_MAC, ipv6_dst=cfg.LAN_HOST),
            route_actions(cfg.HOST_MAC, cfg.LAN_PORT))
        self.logger.info("[OPENFLOW] installed two IPv6 routes + LAN punt + table miss")

    def neighbor_advertisement(self, mac, address, target):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            dst=mac, src=cfg.GATEWAY_MAC, ethertype=ether_types.ETH_TYPE_IPV6))
        pkt.add_protocol(ipv6.ipv6(src=target, dst=address, nxt=58, hop_limit=255))
        pkt.add_protocol(icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_ADVERT, code=0, csum=0,
            data=icmpv6.nd_neighbor(
                res=0x7, dst=target,
                option=icmpv6.nd_option_tla(hw_src=cfg.GATEWAY_MAC))))
        pkt.serialize()
        return bytes(pkt.data)

    def echo_reply(self, mac, address, echo):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            dst=mac, src=cfg.GATEWAY_MAC, ethertype=ether_types.ETH_TYPE_IPV6))
        pkt.add_protocol(ipv6.ipv6(src=cfg.LAN_GATEWAY, dst=address,
                                   nxt=58, hop_limit=64))
        pkt.add_protocol(icmpv6.icmpv6(
            type_=129, code=0, csum=0,
            data=icmpv6.echo(id_=echo.id, seq=echo.seq, data=echo.data)))
        pkt.serialize()
        return bytes(pkt.data)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, event):
        msg = event.msg
        port = msg.match.get("in_port")
        if port == cfg.TRANSIT_PORT:
            pkt = packet.Packet(msg.data)
            ip = pkt.get_protocol(ipv6.ipv6)
            if ip is not None and ip.nxt == 89:
                self.peer.receive(msg.data)
                return
        elif port != cfg.LAN_PORT:
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv6.ipv6)
        icmp = pkt.get_protocol(icmpv6.icmpv6)
        if eth is None or ip is None or icmp is None or ip.nxt != 58:
            return
        if (icmp.type_ == icmpv6.ND_NEIGHBOR_SOLICIT
                and isinstance(icmp.data, icmpv6.nd_neighbor)
                and ip.hop_limit == 255 and icmp.code == 0 and ip.src != "::"):
            target = icmp.data.dst
            lan = (port == cfg.LAN_PORT and eth.src == cfg.HOST_MAC
                   and target == cfg.LAN_GATEWAY)
            transit = (port == cfg.TRANSIT_PORT and eth.src == cfg.FRR_MAC
                       and target == cfg.LINK_LOCAL)
            if lan or transit:
                self.send_packet(self.neighbor_advertisement(
                    eth.src, ip.src, target), port)
                self.logger.info("[NDP] advertised %s on port %d", target, port)
        elif (icmp.type_ == 128 and port == cfg.LAN_PORT
              and eth.src == cfg.HOST_MAC and ip.src == cfg.LAN_HOST
              and ip.dst == cfg.LAN_GATEWAY
              and isinstance(icmp.data, icmpv6.echo)):
            self.send_packet(self.echo_reply(eth.src, ip.src, icmp.data), port)
