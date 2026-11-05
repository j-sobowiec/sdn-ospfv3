import heapq

from ospfv3 import config as cfg


class Routing:
    def __init__(self, lsdb):
        self.lsdb = lsdb

    def build_router_graph(self):
        """Build the directed point-to-point graph from Router-LSAs."""
        graph = {}
        for lsa in self.lsdb.values():
            if lsa["ls_type"] != 0x2001:
                continue
            router_lsa = lsa.get("router_lsa")
            if router_lsa is None:
                continue

            router_id = lsa["advertising_router"]
            links = graph.setdefault(router_id, [])
            for link in router_lsa["links"]:
                if link["type"] != 1:
                    continue

                neighbor = link["neighbor_router_id"]
                links.append({
                    "neighbor": neighbor,
                    "cost": link["metric"],
                    "interface_id": link["interface_id"],
                    "neighbor_interface_id": link["neighbor_interface_id"],
                })
                neighbor_links = graph.setdefault(neighbor, [])

                # A neighbor can be known even without its own Router-LSA.
                # Preserve the existing, local-root-only synthetic reverse link;
                # do not silently "fix" unidirectional SPF in this refactor.
                if neighbor == cfg.ROUTER_ID and not any(
                    edge["neighbor"] == router_id for edge in neighbor_links
                ):
                    neighbor_links.append({
                        "neighbor": router_id,
                        "cost": link["metric"],
                        "interface_id": link["neighbor_interface_id"],
                        "neighbor_interface_id": link["interface_id"],
                    })
        return graph

    def run_spf(self):
        """Run the existing heap-based Dijkstra, preserving tie-breaking."""
        graph = self.build_router_graph()
        root = cfg.ROUTER_ID
        graph.setdefault(root, [])
        distances = dict.fromkeys(graph, float("inf"))
        previous = dict.fromkeys(graph)
        distances[root] = 0
        queue = [(0, root)]

        while queue:
            current_cost, current_router = heapq.heappop(queue)
            if current_cost > distances[current_router]:
                continue
            for link in graph[current_router]:
                neighbor = link["neighbor"]
                new_cost = current_cost + link["cost"]
                if new_cost < distances[neighbor]:
                    distances[neighbor] = new_cost
                    previous[neighbor] = current_router
                    heapq.heappush(queue, (new_cost, neighbor))
        return distances, previous

    def get_spf_next_hop(self, destination, previous):
        """Return the first hop beyond the root, or None if unreachable."""
        root = cfg.ROUTER_ID
        if destination == root or previous.get(destination) is None:
            return None

        current = destination
        while previous[current] != root:
            current = previous[current]
            if current is None:
                return None
        return current

    def collect_prefix_advertisements(self):
        """Collect flat prefix records from parsed Intra-Area-Prefix-LSAs."""
        advertisements = []
        for lsa in self.lsdb.values():
            if lsa["ls_type"] != 0x2009:
                continue
            prefix_lsa = lsa.get("intra_area_prefix_lsa")
            if prefix_lsa is None:
                continue

            advertising_router = lsa["advertising_router"]
            for prefix in prefix_lsa["prefixes"]:
                advertisements.append({
                    "prefix": prefix["prefix"],
                    "prefix_length": prefix["prefix_length"],
                    "metric": prefix["metric"],
                    "advertising_router": advertising_router,
                })
        return advertisements

    def build_ipv6_routing_table(self):
        """Build connected and OSPF routes, retaining all precedence rules."""
        distances, previous = self.run_spf()
        advertisements = self.collect_prefix_advertisements()
        routes = {}

        for prefix, length, interface in (
            (cfg.TRANSIT_PREFIX, cfg.TRANSIT_PREFIX_LEN, "transit"),
            (cfg.LAN_PREFIX, cfg.LAN_PREFIX_LEN, "lan"),
        ):
            # Connected routes must keep precedence over advertised prefixes.
            routes[(prefix, length)] = {
                "prefix": prefix,
                "prefix_length": length,
                "source": "connected",
                "advertising_router": None,
                "router_cost": 0,
                "prefix_metric": 0,
                "total_cost": 0,
                "next_hop": None,
                "interface": interface,
            }

        for advertisement in advertisements:
            advertising_router = advertisement["advertising_router"]
            if advertising_router not in distances:
                continue
            router_cost = distances[advertising_router]
            if router_cost == float("inf"):
                continue

            prefix_metric = advertisement["metric"]
            total_cost = router_cost + prefix_metric
            next_hop = self.get_spf_next_hop(advertising_router, previous)
            prefix_key = (
                advertisement["prefix"], advertisement["prefix_length"]
            )
            candidate = {
                "prefix": advertisement["prefix"],
                "prefix_length": advertisement["prefix_length"],
                "source": "ospf",
                "advertising_router": advertising_router,
                "router_cost": router_cost,
                "prefix_metric": prefix_metric,
                "total_cost": total_cost,
                "next_hop": next_hop,
                "interface": "transit",
            }

            current = routes.get(prefix_key)
            if current is not None and current["source"] == "connected":
                continue
            # Only a lower OSPF cost, or a smaller router ID at equal cost,
            # replaces an existing advertisement. Strict comparisons matter.
            if current is None or (
                candidate["total_cost"] < current["total_cost"]
                or (
                    candidate["total_cost"] == current["total_cost"]
                    and candidate["advertising_router"]
                    < current["advertising_router"]
                )
            ):
                routes[prefix_key] = candidate
        return routes
