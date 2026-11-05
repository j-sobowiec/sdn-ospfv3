"""Frozen PacketIn handler from C01: do not edit.

For C03 differential tests only.
"""
class OSPFv3Controller:
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match.get("in_port")

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)

        if ipv6_pkt and ipv6_pkt.nxt == 58:
            frame = self.data_plane.handle_ndp(
                pkt,
                eth_pkt,
                ipv6_pkt,
                in_port
            )

            if frame is not None:
                flows_installed = (
                    self.try_install_ipv6_host_flows()
                )

                if flows_installed:
                    datapath = self.datapath
                    parser = datapath.ofproto_parser

                    barrier = parser.OFPBarrierRequest(
                        datapath
                    )

                    datapath.set_xid(barrier)

                    self.pending_ndp_barriers[
                        barrier.xid
                    ] = {
                        "frame": frame,
                        "out_port": in_port,
                        "destination_ipv6": ipv6_pkt.src,
                        "destination_mac": eth_pkt.src
                    }

                    self.logger.info(
                        "[DATA][BARRIER WAIT] xid=%s",
                        barrier.xid
                    )

                    datapath.send_msg(barrier)

                else:
                    if self.send_frame(
                        frame,
                        in_port
                    ):
                        self.logger.info(
                            "[NDP][NA TX] "
                            "to=%s mac=%s port=%s",
                            ipv6_pkt.src,
                            eth_pkt.src,
                            in_port
                        )

                return

            frame = self.data_plane.handle_echo_request(
                pkt,
                eth_pkt,
                ipv6_pkt,
                in_port
            )

            if frame is not None:
                if self.send_frame(
                    frame,
                    in_port
                ):
                    self.logger.info(
                        "[ICMPv6][ECHO REPLY TX] "
                        "to=%s mac=%s port=%s",
                        ipv6_pkt.src,
                        eth_pkt.src,
                        in_port
                    )

                return
        
            if (
                ipv6_pkt is not None
                and eth_pkt is not None
                and eth_pkt.dst == cfg.ROUTER_MAC
                and ipv6_pkt.nxt != 89
            ):
                lan_host_valid = self.data_plane.learn_lan_host(
                    in_port=in_port,
                    ipv6_address=ipv6_pkt.src,
                    mac_address=eth_pkt.src
                )

                if lan_host_valid:
                    destination = ipaddress.IPv6Address(
                        ipv6_pkt.dst
                    )

                    matching_route = None
                    matching_prefix_length = -1

                    for route in self.get_ospf_transit_routes():
                        network = ipaddress.IPv6Network(
                            f'{route["prefix"]}/{route["prefix_length"]}',
                            strict=False
                        )

                        if (
                            destination in network
                            and route["prefix_length"]
                            > matching_prefix_length
                        ):
                            matching_route = route
                            matching_prefix_length = route["prefix_length"]

                    if (
                        matching_route is not None
                        and self.data_plane.transit_port is not None
                        and self.data_plane.transit_router_mac is not None
                    ):
                        self.try_install_ipv6_host_flows()

                        datapath = msg.datapath
                        ofproto = datapath.ofproto
                        parser = datapath.ofproto_parser

                        actions = [
                            parser.OFPActionDecNwTtl(),
                            parser.OFPActionSetField(
                                eth_src=cfg.ROUTER_MAC
                            ),
                            parser.OFPActionSetField(
                                eth_dst=(
                                    self.data_plane.transit_router_mac
                                )
                            ),
                            parser.OFPActionOutput(
                                self.data_plane.transit_port
                            )
                        ]

                        packet_out = parser.OFPPacketOut(
                            datapath=datapath,
                            buffer_id=ofproto.OFP_NO_BUFFER,
                            in_port=in_port,
                            actions=actions,
                            data=msg.data
                        )

                        datapath.send_msg(
                            packet_out
                        )

                        self.logger.info(
                            "[DATA][FIRST PACKET FORWARD] "
                            "host=%s dst=%s via=%s",
                            ipv6_pkt.src,
                            ipv6_pkt.dst,
                            matching_route["next_hop"]
                        )

                        return
                      
        if ipv6_pkt and ipv6_pkt.nxt == 89:
            try:
                ipv6_index = pkt.protocols.index(
                    ipv6_pkt
                )
                ospf_payload = pkt.protocols[
                    ipv6_index + 1
                ]
            except (ValueError, IndexError):
                return

            if not isinstance(
                ospf_payload,
                (bytes, bytearray)
            ):
                return

            ospf_data = bytes(
                ospf_payload
            )

            if len(ospf_data) >= 16:
                # Scapy decodes only the fixed 16-byte OSPFv3 header.
                # Keep the packet-length and IPv6 pseudo-header checksum
                # validation below unchanged.
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
                    self.logger.warning(
                        "[OSPF][DROP] invalid OSPFv3 header: %s", exc
                    )
                    return

                if pkt_len < 16 or pkt_len > len(ospf_data):
                    return

                ospf_for_checksum = bytearray(ospf_data[:pkt_len])
                ospf_for_checksum[12:14] = b"\x00\x00"

                calculated_checksum = calculate_ospfv3_checksum(
                    ipv6_pkt.src,
                    ipv6_pkt.dst,
                    bytes(ospf_for_checksum)
                )   

                if checksum != calculated_checksum:
                    self.logger.warning(
                        "[OSPF][WARN] invalid checksum "
                        "received=0x%04x calculated=0x%04x",
                        checksum,
                        calculated_checksum
                    )
                    return

                if area_id_text != cfg.AREA_ID:
                    self.logger.warning(
                        "[OSPF][DROP] area mismatch "
                        "received=%s expected=%s",
                        area_id_text,
                        cfg.AREA_ID
                    )
                    return

                if instance_id != cfg.INSTANCE_ID:
                    self.logger.warning(
                        "[OSPF][DROP] instance mismatch "
                        "received=%d expected=%d",
                        instance_id,
                        cfg.INSTANCE_ID
                    )
                    return

                try:
                    ospf_source = ipaddress.IPv6Address(
                        ipv6_pkt.src
                    )
                except ValueError:
                    return

                if not ospf_source.is_link_local:
                    self.logger.warning(
                        "[OSPF][DROP] non-link-local source=%s",
                        ipv6_pkt.src
                    )
                    return

                try:
                    ospf_destination = ipaddress.IPv6Address(
                        ipv6_pkt.dst
                    )
                except ValueError:
                    return

                ospf_multicast = (
                    ipaddress.IPv6Address("ff02::5"),
                    ipaddress.IPv6Address("ff02::6")
                )

                if (
                    ospf_destination in ospf_multicast
                    and ipv6_pkt.hop_limit != 1
                ):
                    self.logger.warning(
                        "[OSPF][DROP] invalid multicast hop-limit "
                        "dst=%s received=%d expected=1",
                        ipv6_pkt.dst,
                        ipv6_pkt.hop_limit
                    )
                    return
                
                if version == 3 and pkt_type == 1 and pkt_len >= 36:

                    self.handle_ospf_hello(
                        in_port,
                        eth_pkt,
                        ipv6_pkt,
                        ospf_data,
                        pkt_len,
                        router_id_text,
                        area_id_text
                    )

                elif version == 3 and pkt_type == 2 and pkt_len >= 28:

                    self.handle_ospf_dbd(
                        in_port,
                        ipv6_pkt,
                        ospf_data,
                        pkt_len,
                        router_id,
                        router_id_text,
                        area_id_text
                    )

                elif version == 3 and pkt_type == 3 and pkt_len >= 28:
                    
                    self.handle_ospf_lsr(
                        in_port,
                        ipv6_pkt,
                        ospf_data,
                        pkt_len,
                        router_id_text,
                        area_id_text
                    )

                elif version == 3 and pkt_type == 4 and pkt_len >= 20:
                    self.handle_ospf_lsu(
                        in_port,
                        ipv6_pkt,
                        ospf_data,
                        pkt_len,
                        router_id_text,
                        area_id_text
                    )

                elif version == 3 and pkt_type == 5 and pkt_len >= 36:
                    self.handle_ospf_lsack(
                        in_port,
                        ipv6_pkt,
                        ospf_data,
                        pkt_len,
                        router_id_text,
                        area_id_text
                    )
