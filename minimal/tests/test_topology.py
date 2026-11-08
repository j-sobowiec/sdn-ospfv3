"""Check the physical layout without requiring Docker/Containernet."""

import importlib
import sys
import types
import unittest
from unittest.mock import patch


class Node:
    def __init__(self, name):
        self.name = name
        self.commands = []

    def cmd(self, command):
        self.commands.append(command)
        return ""


class Network:
    def __init__(self, **kwargs):
        self.nodes = {}
        self.links = []
        self.stopped = False

    def addController(self, *args, **kwargs):
        return None

    def addDocker(self, name, **kwargs):
        return self.addHost(name)

    def addHost(self, name, **kwargs):
        self.nodes[name] = Node(name)
        return self.nodes[name]

    def addSwitch(self, name, **kwargs):
        return self.addHost(name)

    def addLink(self, left, right, **kwargs):
        self.links.append((left.name, right.name, kwargs))

    def start(self):
        pass

    def waitConnected(self, timeout):
        return True

    def stop(self):
        self.stopped = True


class TopologyTests(unittest.TestCase):
    def test_original_triangle_and_additional_host(self):
        modules = {
            "mininet": types.ModuleType("mininet"),
            "mininet.cli": types.ModuleType("mininet.cli"),
            "mininet.log": types.ModuleType("mininet.log"),
            "mininet.net": types.ModuleType("mininet.net"),
            "mininet.node": types.ModuleType("mininet.node"),
        }
        modules["mininet.cli"].CLI = lambda net: None
        modules["mininet.log"].info = lambda *args: None
        modules["mininet.log"].setLogLevel = lambda level: None
        modules["mininet.net"].Containernet = Network
        modules["mininet.node"].OVSSwitch = object
        modules["mininet.node"].RemoteController = object
        with patch.dict(sys.modules, modules):
            topology = importlib.import_module("minimal.topology")
        network = None

        def create_network(**kwargs):
            nonlocal network
            network = Network(**kwargs)
            return network

        with patch.object(topology, "Containernet", create_network), \
                patch.object(topology, "start_frr"):
            topology.main()

        self.assertTrue(network.stopped)
        self.assertEqual(set(network.nodes), {"r1", "r2", "r3", "s1", "h1", "h2"})
        links = {(a, b, opts.get("intfName1"), opts.get("intfName2"))
                 for a, b, opts in network.links}
        self.assertIn(("r1", "r2", "r1-eth0", "r2-eth0"), links)
        self.assertIn(("r2", "r3", "r2-eth1", "r3-eth0"), links)
        self.assertIn(("r3", "r1", "r3-eth1", "r1-eth1"), links)
        self.assertIn(("r1", "s1", "r1-eth2", None), links)
        self.assertIn(("s1", "h1", None, None), links)
        self.assertIn(("r2", "h2", "r2-eth2", None), links)
        addresses = {
            "r1": {"r1-eth0": "2001:db8:12::1/64",
                   "r1-eth1": "2001:db8:31::1/64",
                   "r1-eth2": "2001:db8:10::1/64"},
            "r2": {"r2-eth0": "2001:db8:12::2/64",
                   "r2-eth1": "2001:db8:23::2/64",
                   "r2-eth2": "2001:db8:2::1/64"},
            "r3": {"r3-eth0": "2001:db8:23::3/64",
                   "r3-eth1": "2001:db8:31::3/64"},
        }
        for node, interfaces in addresses.items():
            for port, address in interfaces.items():
                self.assertIn(f"ip -6 address replace {address} dev {port}",
                              network.nodes[node].commands)
        self.assertTrue(any("r1-eth2 address 02:00:00:00:10:01" in command
                            for command in network.nodes["r1"].commands))


if __name__ == "__main__":
    unittest.main()
