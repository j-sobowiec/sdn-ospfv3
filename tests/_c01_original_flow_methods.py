"""Frozen original C01 FlowMod methods (only four affected methods).

Original method bodies copied verbatim from baseline ryu_sdn.py.
Base class is supplied by b5_3_harness during differential testing.
Not a production module.
"""
class OriginalFlowMethods:
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath

        self.data_plane.reset()
        self.installed_ipv6_host_flows.clear()
        self.pending_ndp_barriers.clear()

        self.neighbor.reset()
        self.ospf_resync_required = True

        remote_routing_changed = (
            self.lsdb.clear_remote(cfg.ROUTER_ID)
        )

        self.local_lsa_ack_pending.clear()
        self.local_lsu_sent = False
        self.local_lsu_last_tx = None

        self.local_lsa_rebuild_required = bool(
            self.local_lsa
        )

        if remote_routing_changed:
            self.recompute_routing_state()

        self.logger.info(
            "[DATA][RESET] dynamic data-plane state cleared"
        )

        self.logger.info(
            "[OSPF][RESET] neighbor session and remote LSDB cleared"
        )
                        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        delete_flows = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            table_id=0,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch()
        )

        datapath.send_msg(
            delete_flows
        )

        self.logger.info(
            "[OPENFLOW] cleared table=0 stale flows"
        )

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(flow_mod)

        self.logger.info(
            "[OPENFLOW] switch connected DPID=%016x "
            "table-miss installed",
            datapath.id
        )


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

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=200,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(flow_mod)

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

            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions
                )
            ]

            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=110,
                match=match,
                instructions=instructions
            )

            datapath.send_msg(flow_mod)

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

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(flow_mod)

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
        ofproto = datapath.ofproto
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

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            table_id=0,
            priority=110,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )

        datapath.send_msg(flow_mod)

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
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=transit_port,
            eth_type=ether_types.ETH_TYPE_IPV6,
            ipv6_dst=host_ipv6
        )

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            table_id=0,
            priority=100,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )

        datapath.send_msg(flow_mod)

        self.logger.info(
            "[DATA][REVERSE FLOW DELETE] host=%s",
            host_ipv6
        )


