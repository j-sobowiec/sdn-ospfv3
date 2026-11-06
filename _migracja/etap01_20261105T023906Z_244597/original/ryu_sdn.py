from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ipv6
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmpv6
from ryu.lib import hub
import ipaddress

from scapy.contrib.ospf import OSPFv3_Hdr
from scapy.error import Scapy_Exception

from dataplane import DataPlane

from ospfv3 import config as cfg
from ospfv3.routing import Routing
from ospfv3.lsdb import LSDB
from ospfv3.local_lsa import LocalLSA
from ospfv3.neighbor import Neighbor
from ospfv3.controller_diagnostics import OSPFDiagnosticsMixin
from ospfv3.controller_rx import OSPFReceiveMixin
from ospfv3.controller_tx import OSPFTransmitMixin
from ospfv3.controller_timers import OSPFTimerMixin
from controller_openflow import OpenFlowMixin
from ospfv3.packet import calculate_ospfv3_checksum

class OSPFv3Controller(OSPFDiagnosticsMixin, OSPFReceiveMixin, OSPFTransmitMixin, OSPFTimerMixin, OpenFlowMixin, app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OSPFv3Controller, self).__init__(*args, **kwargs)

        self.datapath = None
        self.data_plane = DataPlane()
        self.installed_ipv6_host_flows = {}
        self.pending_ndp_barriers = {}

        self.neighbor = Neighbor(self.logger)
        self.lsdb = LSDB(self.logger)
        self.routing = Routing(self.lsdb)
        self.ipv6_routing_table = {}
        self.local_lsa = LocalLSA(self.lsdb, self.logger)
        self.local_lsa_ack_pending = {}
        self.local_lsu_sent = False

        self.local_lsa_rebuild_required = False
        self.ospf_resync_required = True

        self.hello_thread = hub.spawn(self.hello_loop)

        self.neighbor_dead_thread = hub.spawn(
            self.neighbor_dead_loop
        )
        
        self.lsdb_aging_thread = hub.spawn(self.lsdb_aging_loop)

        self.local_lsu_last_tx = None

        self.local_lsa_retransmission_thread = hub.spawn(
            self.local_lsa_retransmission_loop
        )

        self.local_lsa_refresh_thread = hub.spawn(
            self.local_lsa_refresh_loop
        )



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
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

        self._send_action_flow(datapath, match, 0, actions)

        self.logger.info(
            "[OPENFLOW] switch connected DPID=%016x "
            "table-miss installed",
            datapath.id
        )

    @set_ev_cls(
        ofp_event.EventOFPBarrierReply,
        MAIN_DISPATCHER
    )
    def barrier_reply_handler(self, ev):
        xid = ev.msg.xid

        pending = self.pending_ndp_barriers.pop(
            xid,
            None
        )

        if pending is None:
            return

        frame = pending["frame"]
        out_port = pending["out_port"]
        destination_ipv6 = pending["destination_ipv6"]
        destination_mac = pending["destination_mac"]

        self.logger.info(
            "[DATA][BARRIER OK] xid=%s",
            xid
        )

        if self.send_frame(
            frame,
            out_port
        ):
            self.logger.info(
                "[NDP][NA TX] "
                "to=%s mac=%s port=%s",
                destination_ipv6,
                destination_mac,
                out_port
            )





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

            # A rejected Neighbor Solicitation must not fall through to
            # ordinary IPv6 host learning or first-packet forwarding.
            icmp_pkt = pkt.get_protocol(icmpv6.icmpv6)
            if icmp_pkt is not None and icmp_pkt.type_ == icmpv6.ND_NEIGHBOR_SOLICIT:
                return

        if (
            ipv6_pkt is not None
            and eth_pkt is not None
            and eth_pkt.dst == cfg.ROUTER_MAC
            and ipv6_pkt.nxt in (6, 17, 58)
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
                
                # Dispatch only a valid, sufficiently long OSPFv3 packet.
                # Keep the existing per-type handler argument order.
                if version == 3:
                    target = {
                        1: (36, "handle_ospf_hello"),
                        2: (28, "handle_ospf_dbd"),
                        3: (28, "handle_ospf_lsr"),
                        4: (20, "handle_ospf_lsu"),
                        5: (36, "handle_ospf_lsack"),
                    }.get(pkt_type)
                    if target is not None and pkt_len >= target[0]:
                        args = [in_port, ipv6_pkt, ospf_data, pkt_len,
                                router_id_text, area_id_text]
                        if pkt_type == 1:
                            args.insert(1, eth_pkt)
                        elif pkt_type == 2:
                            args.insert(4, router_id)
                        getattr(self, target[1])(*args)


    def recompute_routing_state(self):
        """
        Recalculates SPF and rebuilds the IPv6 routing table
        after a relevant LSDB change.
        """

        new_routes = self.routing.build_ipv6_routing_table()

        if new_routes == self.ipv6_routing_table:
            self.logger.info(
                "[OSPF][ROUTING] recalculated - no route changes"
            )
            return

        self.ipv6_routing_table = new_routes

        self.logger.info(
            "[OSPF][ROUTING] routing table changed"
        )

        self.log_spf_result()
        self.log_ipv6_routing_table()

        for route in self.get_ospf_transit_routes():
            self.logger.info(
                "[DATA][ROUTE CANDIDATE] %s/%s via=%s",
                route["prefix"],
                route["prefix_length"],
                route["next_hop"]
            )

        self.try_install_ipv6_host_flows()


    def get_ospf_transit_routes(self):
        routes = []

        for route in self.ipv6_routing_table.values():
            if route.get("source") != "ospf":
                continue

            if route.get("interface") != "transit":
                continue

            routes.append(route)

        return routes
