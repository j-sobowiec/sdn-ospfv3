"""Frozen C06 implementations used only for differential logging tests."""
from types import SimpleNamespace
cfg = SimpleNamespace(ROUTER_ID="10.10.10.10")

def ospfv3_lsa_type_description(value):
    return f"lsa-type-{value}"

class LoggingReference:
    def log_dbd(self, in_port, ipv6_pkt, router_id_text, area_id_text, interface_mtu, options, i_bit, m_bit, ms_bit, dd_sequence, lsa_headers):
        flags = []
        if i_bit:
            flags.append('I')
        if m_bit:
            flags.append('M')
        if ms_bit:
            flags.append('MS')
        flags_text = ','.join(flags) if flags else '-'
        self.logger.info('\n[OSPF][DBD RX] router=%s src=%s port=%s area=%s', router_id_text, ipv6_pkt.src, in_port, area_id_text)
        self.logger.info('  mtu=%d seq=0x%08x flags=%s options=0x%06x summaries=%d', interface_mtu, dd_sequence, flags_text, options, len(lsa_headers))
        for lsa in lsa_headers:
            self.logger.info('    -> %s adv=%s lsid=%s seq=0x%08x', ospfv3_lsa_type_description(lsa['ls_type']), lsa['advertising_router'], lsa['link_state_id'], lsa['ls_sequence'])

    def log_spf_result(self):
        distances, previous = self.routing.run_spf()
        self.logger.info('\n[OSPF][SPF] root=%s', cfg.ROUTER_ID)
        router_ids = [cfg.ROUTER_ID]
        router_ids.extend(sorted((router_id for router_id in distances if router_id != cfg.ROUTER_ID)))
        for router_id in router_ids:
            cost = distances[router_id]
            predecessor = previous[router_id]
            next_hop = self.routing.get_spf_next_hop(router_id, previous)
            self.logger.info('  router=%s cost=%s predecessor=%s next-hop=%s', router_id, cost, predecessor, next_hop)

