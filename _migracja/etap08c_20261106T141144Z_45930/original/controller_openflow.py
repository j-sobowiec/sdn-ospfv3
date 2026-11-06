"""OpenFlow 1.3 flow programming and packet emission for Ryu.

Mixin installs/removes IPv6 forwarding rules and emits PacketOut frames.
It shares datapath, routing and host-learning state with the RyuApp,
and registers no event handlers or periodic controller tasks.
"""

import ipaddress

from ryu.lib.packet import ether_types

from ospfv3 import config as cfg


class OpenFlowMixin:
    """Program IPv6 host routes and send OpenFlow PacketOut/FlowMod."""

    # IPv6 global-unicast scope. OSPFv3 multicast/link-local and NDP
    # are intentionally outside the forwarding contract.
    _DATA_GLOBAL_PREFIX = ("2000::", "e000::")
    _DATA_ICMPV6_TYPES = (1, 2, 3, 4, 128, 129)

    def _send_action_flow(self, datapath, match, priority, actions):
        """Send a FlowMod with the existing APPLY_ACTIONS instruction."""
        parser = datapath.ofproto_parser
        instructions = [
            parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions
        )
        datapath.send_msg(flow_mod)


    def _send_strict_delete(self, datapath, match, priority):
        """Delete the matching priority/table-0 entry, not all routes."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            table_id=0,
            priority=priority,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(flow_mod)


    def try_install_ipv6_host_flows(self):
        self.logger.info(
            "[DATA][STATE] "
            "lan-port=%s hosts=%s "
            "transit-port=%s transit-mac=%s",
            self.data_plane.lan_port,
            self.data_plane.lan_hosts,
            self.data_plane.transit_port,
            self.data_plane.transit_router_mac
        )

        if self.datapath is None:
            self.logger.info(
                "[DATA][WAIT] datapath not ready"
            )
            return False

        if self.data_plane.lan_port is None:
            self.logger.info(
                "[DATA][WAIT] LAN port not learned"
            )
            return False

        if not self.data_plane.lan_hosts:
            self.logger.info(
                "[DATA][WAIT] no LAN hosts learned"
            )
            return False

        if self.data_plane.transit_port is None:
            self.logger.info(
                "[DATA][WAIT] transit port not learned"
            )
            return False

        if self.data_plane.transit_router_mac is None:
            self.logger.info(
                "[DATA][WAIT] transit router MAC not learned"
            )
            return False

        installed = False

        for host_ipv6, host_mac in (
            self.data_plane.lan_hosts.items()
        ):
            if self.install_ipv6_host_flows(
                host_ipv6,
                host_mac
            ):
                installed = True

        return installed


    def install_ipv6_host_flows(
        self,
        host_ipv6,
        host_mac
    ):
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        lan_port = self.data_plane.lan_port
        transit_port = self.data_plane.transit_port
        transit_mac = self.data_plane.transit_router_mac

        state = (
            host_mac,
            lan_port,
            transit_mac,
            transit_port
        )

        previous_state = (
            self.installed_ipv6_host_flows.get(
                host_ipv6
            )
        )

        if previous_state == state:
            return False

        if previous_state is not None:
            self._delete_host_protocol_flows(
                host_ipv6, previous_state
            )

        #
        # Local logical gateway:
        # packets addressed to 2001:db8:1::1
        # must still go to the controller.
        #
        match = parser.OFPMatch(
            in_port=lan_port,
            eth_type=0x86dd,
            ipv6_dst=cfg.LAN_GATEWAY
        )

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self._send_action_flow(datapath, match, 200, actions)

        # 2000::/3 also includes the local LAN! A more-specific punt
        # prevents the generic R1 rule from swallowing LAN-destined IP.
        lan_network = ipaddress.IPv6Network(
            f"{cfg.LAN_PREFIX}/{cfg.LAN_PREFIX_LEN}", strict=False
        )
        lan_match = parser.OFPMatch(
            in_port=lan_port,
            eth_type=ether_types.ETH_TYPE_IPV6,
            eth_dst=cfg.ROUTER_MAC,
            ipv6_dst=(
                str(lan_network.network_address),
                str(lan_network.netmask)
            )
        )
        self._send_action_flow(datapath, lan_match, 190, actions)

        forward_actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=cfg.ROUTER_MAC),
            parser.OFPActionSetField(eth_dst=transit_mac),
            parser.OFPActionOutput(transit_port)
        ]

        # No route-prefix dependency: R1/FRRouting performs the IPv6
        # destination lookup after OVS forwards the data-plane packet.
        forward_base = dict(
            in_port=lan_port,
            eth_type=ether_types.ETH_TYPE_IPV6,
            eth_dst=cfg.ROUTER_MAC,
            ipv6_src=host_ipv6,
            ipv6_dst=self._DATA_GLOBAL_PREFIX
        )
        for match in self._data_protocol_matches(parser, forward_base):
            self._send_action_flow(datapath, match, 110, forward_actions)

        #
        # R1 -> LAN host
        #
        reverse_actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(eth_src=cfg.ROUTER_MAC),
            parser.OFPActionSetField(eth_dst=host_mac),
            parser.OFPActionOutput(lan_port)
        ]
        reverse_base = dict(
            in_port=transit_port,
            eth_type=ether_types.ETH_TYPE_IPV6,
            ipv6_dst=host_ipv6
        )
        for match in self._data_protocol_matches(parser, reverse_base):
            self._send_action_flow(datapath, match, 100, reverse_actions)

        self.installed_ipv6_host_flows[
            host_ipv6
        ] = state

        self.logger.info(
            "[DATA][FLOW INSTALL] host=%s mac=%s "
            "lan-port=%s transit-port=%s next-hop-mac=%s",
            host_ipv6,
            host_mac,
            lan_port,
            transit_port,
            transit_mac
        )

        return True

    def _data_protocol_matches(self, parser, base):
        """Keep ND (ICMPv6 133-137) and OSPFv3 (89) off the fast path."""
        for protocol in (6, 17):
            yield parser.OFPMatch(**dict(base, ip_proto=protocol))
        for icmp_type in self._DATA_ICMPV6_TYPES:
            yield parser.OFPMatch(
                **dict(base, ip_proto=58, icmpv6_type=icmp_type)
            )

    def _delete_host_protocol_flows(self, host_ipv6, state):
        if self.datapath is None:
            return

        _host_mac, lan_port, _transit_mac, transit_port = state
        datapath = self.datapath
        parser = datapath.ofproto_parser
        forward_base = dict(
            in_port=lan_port,
            eth_type=ether_types.ETH_TYPE_IPV6,
            eth_dst=cfg.ROUTER_MAC,
            ipv6_src=host_ipv6,
            ipv6_dst=self._DATA_GLOBAL_PREFIX
        )
        reverse_base = dict(
            in_port=transit_port,
            eth_type=ether_types.ETH_TYPE_IPV6,
            ipv6_dst=host_ipv6
        )
        for match in self._data_protocol_matches(parser, forward_base):
            self._send_strict_delete(datapath, match, 110)
        for match in self._data_protocol_matches(parser, reverse_base):
            self._send_strict_delete(datapath, match, 100)

    def withdraw_all_ipv6_host_flows(self):
        """Fail closed after R1 adjacency loss, without touching OSPF/LSDB."""
        for host_ipv6, state in list(
            self.installed_ipv6_host_flows.items()
        ):
            self._delete_host_protocol_flows(host_ipv6, state)
        self.installed_ipv6_host_flows.clear()


    def send_frame(self, frame, out_port):
        """
        Sends a raw Ethernet frame through the specified OpenFlow port.
        """

        if self.datapath is None:
            return False

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=frame
        )

        datapath.send_msg(packet_out)

        return True
