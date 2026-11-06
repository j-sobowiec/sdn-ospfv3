"""Human-readable OSPFv3 diagnostics for the Ryu controller.

Mixin formats protocol events and LSA updates.
It uses the controller's logger and shared protocol state,
without keeping independent state or registering Ryu events.
"""

from ospfv3 import config as cfg
from ospfv3.lsa import ospfv3_lsa_type_description


class OSPFDiagnosticsMixin:
    """Logging responsibility separated from protocol and OpenFlow logic."""

    def log_hello(
        self,
        in_port,
        ipv6_pkt,
        pkt_len,
        router_id_text,
        area_id_text,
        interface_id,
        priority,
        options,
        hello_interval,
        dead_interval,
        neighbors
    ):
        neighbors_text = ", ".join(neighbors) if neighbors else "-"

        self.logger.info(
            "\n[OSPF][HELLO RX] "
            "router=%s src=%s port=%s area=%s len=%d",
            router_id_text,
            ipv6_pkt.src,
            in_port,
            area_id_text,
            pkt_len
        )

        self.logger.info(
            "  ifid=%s priority=%d "
            "hello=%ds dead=%ds "
            "options=0x%06x neighbors=%s",
            interface_id,
            priority,
            hello_interval,
            dead_interval,
            options,
            neighbors_text
        )

    def log_dbd(
        self,
        in_port,
        ipv6_pkt,
        router_id_text,
        area_id_text,
        interface_mtu,
        options,
        i_bit,
        m_bit,
        ms_bit,
        dd_sequence,
        lsa_headers
    ):
        flags_text = ",".join(
            flag for flag, enabled in (
                ("I", i_bit), ("M", m_bit), ("MS", ms_bit)
            ) if enabled
        ) or "-"

        self.logger.info(
            "\n[OSPF][DBD RX] "
            "router=%s src=%s port=%s area=%s",
            router_id_text,
            ipv6_pkt.src,
            in_port,
            area_id_text
        )

        self.logger.info(
            "  mtu=%d seq=0x%08x "
            "flags=%s options=0x%06x summaries=%d",
            interface_mtu,
            dd_sequence,
            flags_text,
            options,
            len(lsa_headers)
        )

        for lsa in lsa_headers:
            self.logger.info(
                "    -> %s adv=%s lsid=%s seq=0x%08x",
                ospfv3_lsa_type_description(
                    lsa["ls_type"]
                ),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"]
            )

    def log_lsu(
        self,
        in_port,
        ipv6_pkt,
        pkt_len,
        router_id_text,
        area_id_text,
        lsa_headers
    ):
        self.logger.info(
            "\n[OSPF][LSU RX] "
            "router=%s src=%s port=%s area=%s "
            "lsas=%d len=%d",
            router_id_text,
            ipv6_pkt.src,
            in_port,
            area_id_text,
            len(lsa_headers),
            pkt_len
        )

        for index, lsa in enumerate(
            lsa_headers,
            start=1
        ):
            lsa_type = lsa["ls_type"]

            self.logger.info(
                "  #%d %s "
                "adv=%s "
                "lsid=%s "
                "seq=0x%08x "
                "age=%d",
                index,
                ospfv3_lsa_type_description(lsa_type),
                lsa["advertising_router"],
                lsa["link_state_id"],
                lsa["ls_sequence"],
                lsa["ls_age"]
            )

            # Router-LSA
            if lsa_type == 0x2001:
                router_lsa = lsa["router_lsa"]

                self.logger.info(
                    "     links=%d flags=0x%02x options=0x%06x",
                    len(router_lsa["links"]),
                    router_lsa["flags"],
                    router_lsa["options"]
                )

                for link in router_lsa["links"]:
                    self.logger.info(
                        "       -> router=%s "
                        "cost=%d "
                        "if=%s "
                        "neighbor_if=%s",
                        link["neighbor_router_id"],
                        link["metric"],
                        link["interface_id"],
                        link["neighbor_interface_id"]
                    )

            # Link-LSA
            elif lsa_type == 0x0008:
                link_lsa = lsa["link_lsa"]

                self.logger.info(
                    "     link_local=%s "
                    "priority=%d "
                    "prefixes=%d",
                    link_lsa["link_local_address"],
                    link_lsa["router_priority"],
                    link_lsa["number_of_prefixes"]
                )

                for prefix in link_lsa["prefixes"]:
                    self.logger.info(
                        "       -> %s/%d",
                        prefix["prefix"],
                        prefix["prefix_length"]
                    )

            # Intra-Area-Prefix-LSA
            elif lsa_type == 0x2009:
                prefix_lsa = lsa[
                    "intra_area_prefix_lsa"
                ]

                self.logger.info(
                    "     referenced=%s "
                    "router=%s "
                    "prefixes=%d",
                    ospfv3_lsa_type_description(
                        prefix_lsa["referenced_ls_type"]
                    ),
                    prefix_lsa[
                        "referenced_advertising_router"
                    ],
                    prefix_lsa["number_of_prefixes"]
                )

                for prefix in prefix_lsa["prefixes"]:
                    self.logger.info(
                        "       -> %s/%d cost=%d",
                        prefix["prefix"],
                        prefix["prefix_length"],
                        prefix["metric"]
                    )

