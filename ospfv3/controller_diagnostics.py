"""Concise OSPFv3 event diagnostics; no independent protocol state.

The OSPF handlers keep their exact call interface. Verbose per-field and
per-prefix dumps are unnecessary for the single Ryu--R1 adjacency, while
state transitions and rejection warnings remain logged at their call sites.
"""


class OSPFDiagnosticsMixin:
    def log_hello(self, in_port, ipv6_pkt, pkt_len, router_id_text,
                  area_id_text, interface_id, priority, options,
                  hello_interval, dead_interval, neighbors):
        self.logger.info(
            "[OSPF][HELLO RX] router=%s src=%s port=%s area=%s "
            "ifid=%s hello=%ds dead=%ds neighbors=%d",
            router_id_text, ipv6_pkt.src, in_port, area_id_text,
            interface_id, hello_interval, dead_interval, len(neighbors)
        )

    def log_dbd(self, in_port, ipv6_pkt, router_id_text, area_id_text,
                interface_mtu, options, i_bit, m_bit, ms_bit, dd_sequence,
                lsa_headers):
        self.logger.info(
            "[OSPF][DBD RX] router=%s src=%s port=%s area=%s "
            "mtu=%d seq=0x%08x flags=%d%d%d summaries=%d",
            router_id_text, ipv6_pkt.src, in_port, area_id_text,
            interface_mtu, dd_sequence,
            int(bool(i_bit)), int(bool(m_bit)), int(bool(ms_bit)),
            len(lsa_headers)
        )

    def log_lsu(self, in_port, ipv6_pkt, pkt_len, router_id_text,
                area_id_text, lsa_headers):
        self.logger.info(
            "[OSPF][LSU RX] router=%s src=%s port=%s area=%s "
            "lsas=%d len=%d types=%s",
            router_id_text, ipv6_pkt.src, in_port, area_id_text,
            len(lsa_headers), pkt_len,
            ",".join("0x%04x" % lsa["ls_type"] for lsa in lsa_headers)
        )
