"""W02c: reciprocal SPF links and OSPFv3 PrefixOptions NU-bit.

Offline tests compile the actual Routing classes from AST, preserving method bodies.
The real-integration test uses LSDB/Scapy from the deployed Ubuntu environment.
"""
import ast
import copy
import heapq
import logging
import random
import unittest
from pathlib import Path
from types import SimpleNamespace

from ospfv3 import config as cfg

ROOT_DIR = Path(__file__).resolve().parents[1]
NEW_PATH = ROOT_DIR / 'ospfv3' / 'routing.py'
OLD_PATH = Path(__file__).with_name('_w02c_routing_reference.py')
DIAG_PATH = Path(__file__).with_name('diagnose_b5_1_known_issues.py')

ROOT = cfg.ROUTER_ID
R1, R2, R3, R4 = '1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4'


def methods(path):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Routing')
    return {n.name: n for n in cls.body if isinstance(n, ast.FunctionDef)}


def load_routing(path, entries):
    cls = next(n for n in ast.parse(path.read_text(encoding='utf-8')).body
               if isinstance(n, ast.ClassDef) and n.name == 'Routing')
    namespace = {'heapq': heapq, 'cfg': cfg}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])),
                 str(path), 'exec'), namespace)
    return namespace['Routing'](SimpleNamespace(values=lambda: entries))


def link(peer, cost=10, typ=1, interface_id='0.0.0.1', neighbor_interface_id='0.0.0.2'):
    return {'type': typ, 'metric': cost, 'neighbor_router_id': peer,
            'interface_id': interface_id, 'neighbor_interface_id': neighbor_interface_id}


def router(router_id, *links, lsid='0.0.0.0'):
    return {'ls_type': 0x2001, 'advertising_router': router_id,
            'link_state_id': lsid, 'router_lsa': {'links': list(links)}}


def prefix(router_id, address, length=64, metric=10, options=0):
    return {'ls_type': 0x2009, 'advertising_router': router_id,
            'intra_area_prefix_lsa': {'prefixes': [
                {'prefix': address, 'prefix_length': length,
                 'prefix_options': options, 'metric': metric}
            ]}}


def base(*additional):
    return [router(R1, link(ROOT), link(R2)), router(R2, link(R1)), *additional]


class TestW02CSPF(unittest.TestCase):
    def new(self, entries):
        return load_routing(NEW_PATH, entries)

    def old(self, entries):
        return load_routing(OLD_PATH, entries)

    def test_01_only_two_routing_methods_changed(self):
        a, b = methods(OLD_PATH), methods(NEW_PATH)
        self.assertEqual(set(a), set(b))
        for name in a:
            if name not in {'build_router_graph', 'collect_prefix_advertisements'}:
                self.assertEqual(ast.dump(a[name], include_attributes=False),
                                 ast.dump(b[name], include_attributes=False), name)
        self.assertIn('router_links', ast.unparse(b['build_router_graph']))
        self.assertIn('prefix_options', ast.unparse(b['collect_prefix_advertisements']))

    def test_02_frozen_reference_retains_both_known_defects(self):
        old = OLD_PATH.read_text(encoding='utf-8')
        self.assertIn('do not silently "fix" unidirectional SPF', old)
        self.assertNotIn('prefix.get("prefix_options", 0) & 0x01', old)
        self.assertNotEqual(OLD_PATH.read_bytes(), NEW_PATH.read_bytes())

    def test_03_oneway_remote_edge_is_not_traversable(self):
        entries = [router(R1, link(ROOT), link(R2)), prefix(R2, '2001:db8:77::')]
        routes = self.new(entries).build_ipv6_routing_table()
        self.assertNotIn(('2001:db8:77::', 64), routes)
        self.assertEqual(self.new(entries).run_spf()[0][R2], float('inf'))
        self.assertIn(('2001:db8:77::', 64), self.old(entries).build_ipv6_routing_table())

    def test_04_reciprocal_remote_edge_is_restored(self):
        entries = base(prefix(R2, '2001:db8:77::'))
        route = self.new(entries).build_ipv6_routing_table()[('2001:db8:77::', 64)]
        self.assertEqual((route['total_cost'], route['next_hop']), (30, R1))

    def test_05_local_root_special_reverse_link_preserved(self):
        entries = [router(R1, link(ROOT, 14, interface_id='0.0.8.8',
                                   neighbor_interface_id='0.0.0.1'))]
        edges = self.new(entries).build_router_graph()[ROOT]
        self.assertEqual(edges, [{'neighbor': R1, 'cost': 14,
                                  'interface_id': '0.0.0.1',
                                  'neighbor_interface_id': '0.0.8.8'}])
        self.assertEqual(self.new(entries).run_spf()[0][R1], 14)

    def test_06_reverse_in_another_router_lsa_of_same_router(self):
        entries = [router(R1, link(ROOT), link(R2)), router(R2, lsid='0.0.0.1'),
                   router(R2, link(R1), lsid='0.0.0.2'),
                   prefix(R2, '2001:db8:aa::')]
        self.assertIn(('2001:db8:aa::', 64), self.new(entries).build_ipv6_routing_table())

    def test_07_reciprocal_lsa_processing_order_unimportant(self):
        entries = base(prefix(R2, '2001:db8:77::'))
        for permutation in [entries, list(reversed(entries)), entries[1:] + entries[:1]]:
            with self.subTest(permutation=permutation[0]['ls_type']):
                self.assertEqual(self.new(permutation).run_spf()[0][R2], 20)

    def test_08_non_p2p_reverse_is_not_confirmation(self):
        entries = [router(R1, link(ROOT), link(R2)), router(R2, link(R1, typ=2)),
                   prefix(R2, '2001:db8:77::')]
        self.assertNotIn(('2001:db8:77::', 64), self.new(entries).build_ipv6_routing_table())

    def test_09_only_one_remote_directed_link_in_chain(self):
        entries = [router(R1, link(ROOT), link(R2)), router(R2, link(R1), link(R3)),
                   router(R3), prefix(R3, '2001:db8:33::')]
        self.assertNotIn(('2001:db8:33::', 64), self.new(entries).build_ipv6_routing_table())
        entries[2]['router_lsa']['links'].append(link(R2))
        self.assertEqual(self.new(entries).build_ipv6_routing_table()[('2001:db8:33::', 64)]['total_cost'], 40)

    def test_10_nu_bit_excludes_prefix_even_on_reachable_router(self):
        entries = base(prefix(R2, '2001:db8:88::', options=1))
        self.assertNotIn(('2001:db8:88::', 64), self.new(entries).build_ipv6_routing_table())
        self.assertIn(('2001:db8:88::', 64), self.old(entries).build_ipv6_routing_table())

    def test_11_nu_with_other_option_bits_still_excluded(self):
        for flags in (1, 3, 5, 9, 0x11, 0x81, 0xff):
            with self.subTest(flags=flags):
                self.assertNotIn(('2001:db8:88::', 64),
                                 self.new(base(prefix(R2, '2001:db8:88::', options=flags)))
                                 .build_ipv6_routing_table())

    def test_12_other_prefix_options_do_not_block_unicast(self):
        for flags in (0, 2, 4, 8, 16, 0xfe):
            with self.subTest(flags=flags):
                self.assertIn(('2001:db8:88::', 64),
                              self.new(base(prefix(R2, '2001:db8:88::', options=flags)))
                              .build_ipv6_routing_table())

    def test_13_missing_prefix_options_preserves_existing_fixtures(self):
        entries = base(prefix(R2, '2001:db8:88::'))
        del entries[-1]['intra_area_prefix_lsa']['prefixes'][0]['prefix_options']
        self.assertIn(('2001:db8:88::', 64), self.new(entries).build_ipv6_routing_table())

    def test_14_nu_does_not_become_preferred_low_cost_candidate(self):
        entries = base(prefix(R2, '2001:db8:88::', metric=1, options=1),
                       prefix(R1, '2001:db8:88::', metric=100))
        route = self.new(entries).build_ipv6_routing_table()[('2001:db8:88::', 64)]
        self.assertEqual((route['advertising_router'], route['total_cost']), (R1, 110))

    def test_15_connected_prefix_keeps_priority(self):
        entries = base(prefix(R2, cfg.LAN_PREFIX, cfg.LAN_PREFIX_LEN, options=1),
                       prefix(R2, cfg.TRANSIT_PREFIX, cfg.TRANSIT_PREFIX_LEN))
        routes = self.new(entries).build_ipv6_routing_table()
        self.assertEqual(routes[(cfg.LAN_PREFIX, cfg.LAN_PREFIX_LEN)]['source'], 'connected')
        self.assertEqual(routes[(cfg.TRANSIT_PREFIX, cfg.TRANSIT_PREFIX_LEN)]['source'], 'connected')

    def test_16_same_lsa_mixed_nu_and_normal_prefixes(self):
        entries = base(prefix(R2, '2001:db8:88::', options=1))
        entries[-1]['intra_area_prefix_lsa']['prefixes'].append({
            'prefix': '2001:db8:89::', 'prefix_length': 64, 'metric': 5,
            'prefix_options': 0})
        advertised = self.new(entries).collect_prefix_advertisements()
        self.assertEqual([p['prefix'] for p in advertised], ['2001:db8:89::'])
        self.assertEqual(advertised[0]['metric'], 5)

    def test_17_valid_topologies_same_graph_distances_routes_and_next_hops(self):
        rng = random.Random(0xC0FFEE)
        for i in range(200):
            members = [R1, R2, R3, R4]
            nodes = {r: [] for r in members}
            nodes[R1].append(link(ROOT, rng.randint(1, 20)))
            for ix, u in enumerate(members):
                for v in members[ix+1:]:
                    if rng.random() < 0.5:
                        nodes[u].append(link(v, rng.randint(1, 20)))
                        nodes[v].append(link(u, rng.randint(1, 20)))
            entries = [router(r, *edges) for r, edges in nodes.items()]
            entries += [prefix(r, f'2001:db8:{j+100:x}::', metric=rng.randint(0, 40))
                        for j, r in enumerate(members)]
            old, new = self.old(entries), self.new(entries)
            with self.subTest(case=i):
                self.assertEqual(old.build_router_graph(), new.build_router_graph())
                self.assertEqual(old.run_spf(), new.run_spf())
                self.assertEqual(old.build_ipv6_routing_table(), new.build_ipv6_routing_table())

    def test_18_random_oneway_graph_against_independent_reference(self):
        rng = random.Random(0x1234)
        members = [R1, R2, R3, R4]
        for i in range(250):
            adj = {r: [] for r in members}
            adj[R1].append(link(ROOT, 10))
            for u in members:
                for v in members:
                    if v != u and rng.random() < .50:
                        adj[u].append(link(v, rng.randint(1, 35)))
            entries = [router(r, *links) for r, links in adj.items()]
            entries.append(prefix(R4, '2001:db8:44::'))
            got, _ = self.new(entries).run_spf()
            # Independent Bellman-Ford over only mutually confirmed links.
            expected = {r: float('inf') for r in members + [ROOT]}
            expected[ROOT] = 0
            directed = [(ROOT, R1, 10)]
            for u, links in adj.items():
                for edge in links:
                    v = edge['neighbor_router_id']
                    if v != ROOT and any(back['neighbor_router_id'] == u for back in adj[v]):
                        directed.append((u, v, edge['metric']))
            for _ in range(len(expected)-1):
                for a, b, cost in directed:
                    expected[b] = min(expected[b], expected[a]+cost)
            with self.subTest(case=i):
                self.assertEqual(got, expected)

    def test_19_diagnostics_converted_not_deleted(self):
        tree = ast.parse(DIAG_PATH.read_text(encoding='utf-8'))
        klass = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                     and n.name == 'TestObservedLimitations')
        defs = {n.name: n for n in klass.body if isinstance(n, ast.FunctionDef)}
        self.assertIn('test_unidirectional_router_edge_without_reverse_lsa_not_routable', defs)
        self.assertIn('test_nu_bit_prefix_not_installed_as_unicast_route', defs)
        for name in defs:
            self.assertFalse(any(isinstance(d, ast.Attribute) and d.attr == 'expectedFailure'
                                 for d in defs[name].decorator_list), name)
        self.assertEqual(len(defs), 4)  # setUp + three tests

    def test_20_no_runtime_ryu_or_scapy_added_to_routing(self):
        tree = ast.parse(NEW_PATH.read_text(encoding='utf-8'))
        imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertEqual([ast.unparse(n) for n in imports],
                         ['import heapq', 'from ospfv3 import config as cfg'])

    def test_21_real_scapy_lsdb_and_spf_integration(self):
        try:
            import scapy
            from ospfv3.lsdb import LSDB
            from ospfv3.routing import Routing
            from test_lsdb_spf_b5_1 import router_lsa, prefix_lsa, link
        except ImportError as exc:
            self.skipTest(f'Real Scapy/LSDB import unavailable: {exc}')
        self.assertEqual(scapy.__version__, '2.7.0')
        db = LSDB(logging.getLogger('ospfv3.w02c'))
        rt = Routing(db)
        db.update([router_lsa(R1, link(ROOT), link(R2)),
                   prefix_lsa(R2, ('2001:db8:77::', 64, 10)),
                   prefix_lsa(R1, ('2001:db8:88::', 64, 10))])
        pref = next(p for p in db.values() if p['ls_type'] == 0x2009
                    and p['advertising_router'] == R1)
        pref['intra_area_prefix_lsa']['prefixes'][0]['prefix_options'] = 0x01
        self.assertNotIn(('2001:db8:77::', 64), rt.build_ipv6_routing_table())
        self.assertNotIn(('2001:db8:88::', 64), rt.build_ipv6_routing_table())
        db.update([router_lsa(R2, link(R1))])
        self.assertEqual(rt.build_ipv6_routing_table()[('2001:db8:77::', 64)]['total_cost'], 30)
        self.assertEqual(rt.get_spf_next_hop(R2, rt.run_spf()[1]), R1)


if __name__ == '__main__':
    unittest.main()
