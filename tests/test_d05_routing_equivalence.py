"""D05: exact differential tests against the unmodified pre-D05 Routing.

The reference is a frozen copy of ospfv3/routing.py from the original project.
Both implementations operate on the same already-decoded LSA dictionaries.
No fixtures are hardcoded with a preferred result: the old implementation is
executed independently for every case. Existing B5.1 tests remain mandatory.
"""

import copy
import itertools
import random
import unittest
from unittest.mock import patch

from ospfv3 import config as cfg
from ospfv3.routing import Routing
from _d05_routing_reference import Routing as OldRouting


ROOT = cfg.ROUTER_ID
ROUTERS = (ROOT, "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5")


class FixtureDB:
    """LSDB.values() stand-in returning decoded LSA dictionaries."""

    def __init__(self, entries):
        self.entries = entries

    def values(self):
        return iter(self.entries)


def router_lsa(router, links=(), body=True):
    result = {"ls_type": 0x2001, "advertising_router": router}
    if body:
        result["router_lsa"] = {"links": list(links)}
    return result


def link(neighbor, cost=10, kind=1, interface_id="0.0.0.1",
         neighbor_interface_id="0.0.0.2"):
    return {
        "type": kind, "neighbor_router_id": neighbor, "metric": cost,
        "interface_id": interface_id,
        "neighbor_interface_id": neighbor_interface_id,
    }


def prefix_lsa(router, prefixes=(), body=True):
    result = {"ls_type": 0x2009, "advertising_router": router}
    if body:
        result["intra_area_prefix_lsa"] = {"prefixes": [
            {"prefix": address, "prefix_length": length, "metric": metric}
            for address, length, metric in prefixes
        ]}
    return result


def other_lsa(router, kind):
    return {"ls_type": kind, "advertising_router": router}


def reciprocal_reference_graph(entries, old_graph):
    """Keep old node/edge ordering, but reject remote non-reciprocal arcs.

    The old implementation is the independent oracle for unchanged routing
    rules. Only its *graph* is filtered according to the W02c contract;
    every original (including randomized and malformed) fixture is retained.
    """
    advertised = {}
    for lsa in entries:
        if lsa["ls_type"] != 0x2001 or lsa.get("router_lsa") is None:
            continue
        advertised.setdefault(lsa["advertising_router"], []).extend(
            edge["neighbor_router_id"] for edge in lsa["router_lsa"]["links"]
            if edge["type"] == 1
        )

    return {
        router: [
            edge for edge in edges
            if edge["neighbor"] == ROOT or router in advertised.get(edge["neighbor"], ())
        ]
        for router, edges in old_graph.items()
    }


class TestD05Differential(unittest.TestCase):
    def compare(self, entries):
        # Separate deep copies protect against accidental mutation of input.
        original = OldRouting(FixtureDB(copy.deepcopy(entries)))
        modified = Routing(FixtureDB(copy.deepcopy(entries)))

        graph_before = original.build_router_graph()
        # RFC 5340 semantics changed intentionally in W02c: unconfirmed
        # remote edges must be removed. Compare against the frozen old
        # implementation running on an independently filtered graph, not
        # against its previously incorrect unfiltered topology.
        expected_graph = reciprocal_reference_graph(entries, graph_before)
        graph_after = modified.build_router_graph()
        self.assertEqual(graph_after, expected_graph)
        original.build_router_graph = lambda: copy.deepcopy(expected_graph)
        self.assertEqual(list(graph_after), list(graph_before))

        dist_before, prev_before = original.run_spf()
        dist_after, prev_after = modified.run_spf()
        self.assertEqual(dist_after, dist_before)
        self.assertEqual(prev_after, prev_before)
        self.assertEqual(list(dist_after), list(dist_before))
        self.assertEqual(list(prev_after), list(prev_before))
        for router in (*ROUTERS, "99.99.99.99"):
            self.assertEqual(
                modified.get_spf_next_hop(router, prev_after),
                original.get_spf_next_hop(router, prev_before),
            )

        self.assertEqual(
            modified.collect_prefix_advertisements(),
            original.collect_prefix_advertisements(),
        )
        before = original.build_ipv6_routing_table()
        after = modified.build_ipv6_routing_table()
        self.assertEqual(after, before)
        self.assertEqual(list(after), list(before))
        return before

    def test_empty_db_and_connected_routes(self):
        table = self.compare([])
        self.assertEqual(len(table), 2)
        self.assertEqual({row["source"] for row in table.values()}, {"connected"})

    def test_non_router_lsas_do_not_create_nodes(self):
        self.compare([other_lsa("1.1.1.1", 0x0008),
                      other_lsa("1.1.1.1", 0x200b)])

    def test_missing_decoded_body_is_ignored(self):
        self.compare([router_lsa("1.1.1.1", body=False),
                      prefix_lsa("1.1.1.1", body=False)])

    def test_remote_advertises_root_synthetic_reverse_link(self):
        self.compare([router_lsa("1.1.1.1", [
            link(ROOT, 19, interface_id="0.0.0.7",
                 neighbor_interface_id="0.0.0.8")]),
            prefix_lsa("1.1.1.1", [("2001:db8:11::", 64, 3)])])

    def test_reverse_link_and_explicit_link_order(self):
        self.compare([router_lsa("1.1.1.1", [link(ROOT, 10)]),
                      router_lsa(ROOT, [link("1.1.1.1", 33)]),
                      router_lsa("2.2.2.2", [link(ROOT, 5)])])

    def test_multiple_parallel_links_kept(self):
        self.compare([router_lsa(ROOT, [link("1.1.1.1", 30),
                                        link("1.1.1.1", 10),
                                        link("1.1.1.1", 10)])])

    def test_non_p2p_types_are_ignored(self):
        self.compare([router_lsa(ROOT, [link("1.1.1.1", 10, kind=2),
                                        link("2.2.2.2", 11, kind=3),
                                        link("3.3.3.3", 12, kind=0)])])

    def test_self_links_are_not_deduplicated(self):
        self.compare([router_lsa(ROOT, [link(ROOT, 0), link(ROOT, 10)]),
                      router_lsa("1.1.1.1", [link("1.1.1.1", 2)])])

    def test_disconnected_prefix_is_not_installed(self):
        table = self.compare([router_lsa("1.1.1.1"),
                              prefix_lsa("1.1.1.1", [("2001:db8:ff::", 64, 2)])])
        self.assertNotIn(("2001:db8:ff::", 64), table)

    def test_connected_route_wins_regardless_of_cost(self):
        self.compare([router_lsa("1.1.1.1", [link(ROOT)]),
                      prefix_lsa("1.1.1.1", [
                          (cfg.LAN_PREFIX, cfg.LAN_PREFIX_LEN, -50),
                          (cfg.TRANSIT_PREFIX, cfg.TRANSIT_PREFIX_LEN, -20)])])

    def test_equal_cost_prefix_tie_break_in_all_orders(self):
        links = [router_lsa("1.1.1.1", [link(ROOT, 10)]),
                 router_lsa("2.2.2.2", [link(ROOT, 10)])]
        adv = [prefix_lsa("1.1.1.1", [("2001:db8:99::", 64, 5)]),
               prefix_lsa("2.2.2.2", [("2001:db8:99::", 64, 5)])]
        for ordered in itertools.permutations(adv):
            with self.subTest(order=[p["advertising_router"] for p in ordered]):
                self.compare(links + list(ordered))

    def test_overlapping_prefixes_and_duplicates(self):
        self.compare([router_lsa("1.1.1.1", [link(ROOT)]),
                      prefix_lsa("1.1.1.1", [
                          ("2001:db8:aa::", 48, 5),
                          ("2001:db8:aa::", 64, 3),
                          ("2001:db8:aa::", 64, 3),
                          ("2001:db8:aa::", 64, 7)])])

    def test_unidirectional_graph_behavior_is_corrected(self):
        # Preserve this original fixture, but require the safe W02c behavior.
        table = self.compare([router_lsa("1.1.1.1", [link(ROOT)]),
                              router_lsa("2.2.2.2", [link("1.1.1.1")]),
                              prefix_lsa("2.2.2.2", [("2001:db8:2::", 64, 1)])])
        self.assertNotIn(("2001:db8:2::", 64), table)

    def test_random_graphs_and_prefix_advertisements(self):
        rng = random.Random(20261019)
        for i in range(2600):
            selected = ROUTERS[:rng.randrange(1, len(ROUTERS) + 1)]
            entries = []
            for router in selected:
                links = []
                for peer in selected:
                    if rng.random() < .32:
                        links.append(link(
                            peer, rng.randrange(0, 80),
                            kind=rng.choice((1, 1, 1, 2, 3)),
                            interface_id=f"0.0.0.{rng.randrange(1, 255)}",
                            neighbor_interface_id=f"0.0.0.{rng.randrange(1, 255)}",
                        ))
                entries.append(router_lsa(router, links))
                if rng.random() < .83:
                    prefixes = [(
                        f"2001:db8:{rng.randrange(0, 12):x}::",
                        rng.choice((0, 32, 48, 64, 128)),
                        rng.randrange(0, 50),
                    ) for _ in range(rng.randrange(0, 4))]
                    entries.append(prefix_lsa(router, prefixes))
            rng.shuffle(entries)
            with self.subTest(case=i):
                self.compare(entries)

    def test_zero_cost_links_and_multiple_equal_cost_paths(self):
        self.compare([
            router_lsa(ROOT, [link("1.1.1.1", 0), link("2.2.2.2", 0)]),
            router_lsa("1.1.1.1", [link("3.3.3.3", 5)]),
            router_lsa("2.2.2.2", [link("3.3.3.3", 5)]),
            prefix_lsa("3.3.3.3", [("2001:db8:44::", 64, 0)]),
        ])

    def test_connected_networks_colliding_with_each_other(self):
        # The old code builds "transit" then "lan": the second one wins.
        with patch.object(cfg, "LAN_PREFIX", cfg.TRANSIT_PREFIX), \
                patch.object(cfg, "LAN_PREFIX_LEN", cfg.TRANSIT_PREFIX_LEN):
            self.compare([])

    def test_negative_costs_do_not_change_selection(self):
        # A strict regression test for code semantics, not an OSPF feature.
        self.compare([router_lsa(ROOT, [link("1.1.1.1", -3)]),
                      prefix_lsa("1.1.1.1", [("2001:db8:beef::", 64, -2)])])

    def test_next_hop_handles_unknown_and_unreachable(self):
        previous = {ROOT: None, "1.1.1.1": None,
                    "2.2.2.2": "1.1.1.1", "3.3.3.3": ROOT}
        old, new = OldRouting(FixtureDB([])), Routing(FixtureDB([]))
        for target in (ROOT, "1.1.1.1", "2.2.2.2", "3.3.3.3", "no-such-router"):
            with self.subTest(target=target):
                self.assertEqual(new.get_spf_next_hop(target, previous),
                                 old.get_spf_next_hop(target, previous))


if __name__ == "__main__":
    unittest.main()
