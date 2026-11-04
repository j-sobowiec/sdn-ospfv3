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

        ospf_routes = self.get_ospf_transit_routes()

        route_signature = tuple(
            sorted(
                (
                    route["prefix"],
                    route["prefix_length"],
                    route["next_hop"]
                )
                for route in ospf_routes
            )
        )

        state = (
            host_mac,
            lan_port,
            transit_mac,
            transit_port,
            route_signature
        )

        previous_state = (
            self.installed_ipv6_host_flows.get(
                host_ipv6
            )
        )

        if previous_state == state:
            return False

        if previous_state is not None:
            previous_lan_port = previous_state[1]
            previous_route_signature = set(
                previous_state[4]
            )

            current_route_signature = set(
                route_signature
            )

            withdrawn_routes = (
                previous_route_signature
                - current_route_signature
            )

            for (
                prefix,
                prefix_length,
                next_hop
            ) in withdrawn_routes:
                self.delete_ipv6_route_flow(
                    host_ipv6=host_ipv6,
                    prefix=prefix,
                    prefix_length=prefix_length,
                    lan_port=previous_lan_port
                )

        if (
            self.installed_ipv6_host_flows.get(host_ipv6)
            == state
        ):
            return False

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

        for route in ospf_routes:
            network = ipaddress.IPv6Network(
                f'{route["prefix"]}/{route["prefix_length"]}',
                strict=False
            )

            match = parser.OFPMatch(
                in_port=lan_port,
                eth_type=ether_types.ETH_TYPE_IPV6,
                eth_dst=cfg.ROUTER_MAC,
                ipv6_src=host_ipv6,
                ipv6_dst=(
                    str(network.network_address),
                    str(network.netmask)
                )
            )

            actions = [
                parser.OFPActionDecNwTtl(),
                parser.OFPActionSetField(
                    eth_src=cfg.ROUTER_MAC
                ),
                parser.OFPActionSetField(
                    eth_dst=transit_mac
                ),
                parser.OFPActionOutput(
                    transit_port
                )
            ]

            self._send_action_flow(datapath, match, 110, actions)

            self.logger.info(
                "[DATA][ROUTE FLOW INSTALL] "
                "host=%s dst=%s/%d via=%s",
                host_ipv6,
                route["prefix"],
                route["prefix_length"],
                route["next_hop"]
            )

        #
        # R1 -> LAN host
        #
        match = parser.OFPMatch(
            in_port=transit_port,
            eth_type=0x86dd,
            ipv6_dst=host_ipv6
        )

        actions = [
            parser.OFPActionDecNwTtl(),
            parser.OFPActionSetField(
                eth_src=cfg.ROUTER_MAC
            ),
            parser.OFPActionSetField(
                eth_dst=host_mac
            ),
            parser.OFPActionOutput(
                lan_port
            )
        ]

        self._send_action_flow(datapath, match, 100, actions)

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


    def delete_ipv6_route_flow(
        self,
        host_ipv6,
        prefix,
        prefix_length,
        lan_port
    ):
        if self.datapath is None:
            return

        datapath = self.datapath
        parser = datapath.ofproto_parser

        network = ipaddress.IPv6Network(
            f"{prefix}/{prefix_length}",
            strict=False
        )

        match = parser.OFPMatch(
            in_port=lan_port,
            eth_type=ether_types.ETH_TYPE_IPV6,
            eth_dst=cfg.ROUTER_MAC,
            ipv6_src=host_ipv6,
            ipv6_dst=(
                str(network.network_address),
                str(network.netmask)
            )
        )

        self._send_strict_delete(datapath, match, 110)

        self.logger.info(
            "[DATA][ROUTE FLOW DELETE] "
            "host=%s dst=%s/%d",
            host_ipv6,
            prefix,
            prefix_length
        )


    def delete_ipv6_reverse_flow(
        self,
        host_ipv6,
        transit_port
    ):
        if (
            self.datapath is None
            or transit_port is None
        ):
            return

        datapath = self.datapath
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=transit_port,
            eth_type=ether_types.ETH_TYPE_IPV6,
            ipv6_dst=host_ipv6
        )

        self._send_strict_delete(datapath, match, 100)

        self.logger.info(
            "[DATA][REVERSE FLOW DELETE] host=%s",
            host_ipv6
        )


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
