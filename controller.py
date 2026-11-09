"""One Ryu controller for two fixed IPv6/OSPFv3 OVS routers."""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                    MAIN_DISPATCHER, set_ev_cls)
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, icmpv6, ipv6, packet
from ryu.ofproto import ofproto_v1_3

import config as cfg
from peer import Peer


class MinimalOSPFv3Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.peers = {}
        self.timer_thread = hub.spawn(self.tick)

    def tick(self):
        while True:
            for dpid in list(self.datapaths):
                self.peers[dpid].tick()
            hub.sleep(1)

    def send_packet(self, dpid, data, port):
        dp = self.datapaths.get(dpid)
        if dp is None:
            return False
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(port)], data=data))
        return True

    def send_ospf(self, dpid, data):
        return self.send_packet(dpid, data, cfg.SWITCHES[dpid]["transit_port"])

    def flow(self, dp, priority, match, actions):
        p = dp.ofproto_parser
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, priority=priority, match=p.OFPMatch(**match),
            instructions=[p.OFPInstructionActions(
                dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_ready(self, event):
        dp = event.msg.datapath
        router = cfg.SWITCHES.get(dp.id)
        if router is None:
            # Never clear flows or reset the neighbor on an unknown switch.
            self.logger.error("[OPENFLOW] unexpected DPID %d", dp.id)
            return
        self.datapaths[dp.id] = dp
        reconnected = dp.id in self.peers
        if not reconnected:
            self.peers[dp.id] = Peer(
                router, lambda data, dpid=dp.id: self.send_ospf(dpid, data),
                self.logger, label=f"S{dp.id}")
        else:
            self.peers[dp.id].reset()
        p, ofp = dp.ofproto_parser, dp.ofproto
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE, table_id=0,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            match=p.OFPMatch()))

        punt = [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.flow(dp, 0, {}, punt)
        # OSPFv3 and NDP are control-plane traffic, never data-plane routes.
        self.flow(dp, 300, dict(in_port=router["transit_port"],
                                eth_type=0x86dd, ip_proto=89), punt)
        for port in (router["transit_port"], router["lan_port"]):
            self.flow(dp, 250, dict(in_port=port, eth_type=0x86dd,
                                    ip_proto=58, icmpv6_type=135), punt)
        self.flow(dp, 200, dict(
            in_port=router["lan_port"], eth_type=0x86dd,
            ipv6_dst=(router["lan_prefix"].split("/")[0],
                      "ffff:ffff:ffff:ffff::")), punt)

        def route_actions(mac, port):
            return [p.OFPActionDecNwTtl(),
                    p.OFPActionSetField(eth_src=router["gateway_mac"]),
                    p.OFPActionSetField(eth_dst=mac),
                    p.OFPActionOutput(port)]

        self.flow(dp, 100, dict(
            in_port=router["lan_port"], eth_type=ether_types.ETH_TYPE_IPV6,
            eth_dst=router["gateway_mac"], ipv6_src=router["lan_host"],
            ipv6_dst=("2000::", "e000::")),
            route_actions(router["frr_mac"], router["transit_port"]))
        self.flow(dp, 100, dict(
            in_port=router["transit_port"], eth_type=ether_types.ETH_TYPE_IPV6,
            eth_dst=router["gateway_mac"], ipv6_dst=router["lan_host"]),
            route_actions(router["host_mac"], router["lan_port"]))
        self.logger.info("[OPENFLOW][S%d] %s; 2 IPv6 routes, OSPF/NDP punts",
                         dp.id, "reconnected" if reconnected else "connected")

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_disconnected(self, event):
        dp = event.datapath
        if self.datapaths.get(dp.id) is dp:
            del self.datapaths[dp.id]
            self.logger.warning("[OPENFLOW][S%d] disconnected", dp.id)

    def neighbor_advertisement(self, router, mac, address, target):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            dst=mac, src=router["gateway_mac"], ethertype=ether_types.ETH_TYPE_IPV6))
        pkt.add_protocol(ipv6.ipv6(src=target, dst=address, nxt=58, hop_limit=255))
        pkt.add_protocol(icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_ADVERT, code=0, csum=0,
            data=icmpv6.nd_neighbor(
                res=0x7, dst=target,
                option=icmpv6.nd_option_tla(hw_src=router["gateway_mac"]))))
        pkt.serialize()
        return bytes(pkt.data)

    def echo_reply(self, router, mac, address, echo):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            dst=mac, src=router["gateway_mac"], ethertype=ether_types.ETH_TYPE_IPV6))
        pkt.add_protocol(ipv6.ipv6(src=router["lan_gateway"], dst=address,
                                   nxt=58, hop_limit=64))
        pkt.add_protocol(icmpv6.icmpv6(
            type_=129, code=0, csum=0,
            data=icmpv6.echo(id_=echo.id, seq=echo.seq, data=echo.data)))
        pkt.serialize()
        return bytes(pkt.data)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, event):
        msg = event.msg
        dp = msg.datapath
        router = cfg.SWITCHES.get(dp.id)
        if router is None or self.datapaths.get(dp.id) is not dp:
            return
        port = msg.match.get("in_port")
        if port not in (router["transit_port"], router["lan_port"]):
            return

        pkt = packet.Packet(msg.data)
        ip = pkt.get_protocol(ipv6.ipv6)
        if port == router["transit_port"] and ip is not None and ip.nxt == 89:
            self.peers[dp.id].receive(msg.data)
            return
        eth = pkt.get_protocol(ethernet.ethernet)
        icmp = pkt.get_protocol(icmpv6.icmpv6)
        if eth is None or ip is None or icmp is None or ip.nxt != 58:
            return
        if (icmp.type_ == icmpv6.ND_NEIGHBOR_SOLICIT
                and isinstance(icmp.data, icmpv6.nd_neighbor)
                and ip.hop_limit == 255 and icmp.code == 0 and ip.src != "::"):
            target = icmp.data.dst
            lan = (port == router["lan_port"] and eth.src == router["host_mac"]
                   and target == router["lan_gateway"])
            transit = (port == router["transit_port"] and eth.src == router["frr_mac"]
                       and target == router["link_local"])
            if lan or transit:
                self.send_packet(dp.id, self.neighbor_advertisement(
                    router, eth.src, ip.src, target), port)
        elif (icmp.type_ == 128 and port == router["lan_port"]
              and eth.src == router["host_mac"] and ip.src == router["lan_host"]
              and ip.dst == router["lan_gateway"]
              and isinstance(icmp.data, icmpv6.echo)):
            self.send_packet(dp.id, self.echo_reply(
                router, eth.src, ip.src, icmp.data), port)
