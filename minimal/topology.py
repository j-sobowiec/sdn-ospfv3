#!/usr/bin/env python3
"""Original three-FRR-router triangle, SDN LAN, and a remote test host."""

import os
import shlex
import time

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Containernet
from mininet.node import OVSSwitch, RemoteController

from minimal import config as cfg

FRR_IMAGE = os.environ.get("FRR_IMAGE", "frrouting/frr:latest")
DAEMONS = ('zebra=yes\nospf6d=yes\nvtysh_enable=no\n'
           'zebra_options="-A 127.0.0.1 -s 90000000"\n'
           'ospf6d_options="-A ::1"\n')


def write_frr_file(router, path, content):
    router.cmd("mkdir -p /etc/frr /run/frr")
    router.cmd(f"printf '%s' {shlex.quote(content)} > {shlex.quote(path)}")


def configure_frr(router, router_id, addresses, active, passive=()):
    for setting in ("all.disable_ipv6=0", "default.disable_ipv6=0",
                    "all.forwarding=1"):
        router.cmd(f"sysctl -w net.ipv6.conf.{setting} >/dev/null")
    for iface, address in addresses.items():
        router.cmd(f"ip link set {iface} up")
        router.cmd(f"ip -4 address flush dev {iface}")
        router.cmd(f"ip -6 address replace {address} dev {iface}")
    lines = ["frr defaults traditional", f"hostname {router.name}",
             "service integrated-vtysh-config", "log stdout", "!",
             "router ospf6", f" ospf6 router-id {router_id}",
             " log-adjacency-changes", "exit", "!"]
    for iface in active + passive:
        lines.extend((f"interface {iface}", " ipv6 ospf6 area 0.0.0.0",
                      " ipv6 ospf6 network point-to-point" if iface in active
                      else " ipv6 ospf6 passive", "exit", "!"))
    write_frr_file(router, "/etc/frr/daemons", DAEMONS)
    write_frr_file(router, "/etc/frr/frr.conf", "\n".join(lines) + "\n")
    write_frr_file(router, "/etc/frr/vtysh.conf",
                   "service integrated-vtysh-config\n")
    router.cmd("chown -R frr:frr /etc/frr /run/frr")
    router.cmd("if getent group frrvty >/dev/null 2>&1; then "
               "chown frr:frrvty /etc/frr/vtysh.conf; fi")
    router.cmd("chmod 640 /etc/frr/daemons /etc/frr/frr.conf /etc/frr/vtysh.conf")


def start_frr(router):
    router.cmd("if [ -x /usr/lib/frr/frrinit.sh ]; then "
               "/usr/lib/frr/frrinit.sh start </dev/null >/tmp/frr-start.log 2>&1; "
               "else /etc/init.d/frr start </dev/null >/tmp/frr-start.log 2>&1; fi")
    output = router.cmd("cat /tmp/frr-start.log 2>/dev/null")
    if output.strip():
        info(f"{router.name}: {output.strip()}\n")
    time.sleep(2)
    if "ospf6d.vty" not in router.cmd("ls /run/frr/*.vty 2>/dev/null"):
        info(f"WARNING: no ospf6d socket in {router.name}\n")


def configure_host(host, mac, address, gateway):
    host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null")
    host.cmd(f"ip link set dev {host.name}-eth0 address {mac} up")
    host.cmd(f"ip -4 addr flush dev {host.name}-eth0")
    host.cmd(f"ip -6 addr replace {address} dev {host.name}-eth0")
    host.cmd(f"ip -6 route replace default via {gateway} dev {host.name}-eth0")


def main():
    net = Containernet(controller=None, switch=OVSSwitch)
    try:
        net.addController("c0", controller=RemoteController,
                          ip="127.0.0.1", port=6653)
        docker = dict(ip=None, dimage=FRR_IMAGE, dcmd="/bin/bash",
                      cap_add=["net_admin", "net_raw", "sys_admin"],
                      sysctls={"net.ipv6.conf.all.disable_ipv6": "0",
                               "net.ipv6.conf.default.disable_ipv6": "0",
                               "net.ipv6.conf.all.forwarding": "1",
                               "net.ipv6.conf.default.forwarding": "1"},
                      rm=True)
        r1 = net.addDocker("r1", **docker)
        r2 = net.addDocker("r2", **docker)
        r3 = net.addDocker("r3", **docker)
        s1 = net.addSwitch("s1", cls=OVSSwitch, protocols="OpenFlow13",
                           failMode="secure", dpid="0000000000000001")
        h1 = net.addHost("h1", ip=None)
        h2 = net.addHost("h2", ip=None)

        # Preserve all three original FRR links, interfaces and subnets.
        for left, right, left_port, right_port in (
            (r1, r2, "r1-eth0", "r2-eth0"),
            (r2, r3, "r2-eth1", "r3-eth0"),
            (r3, r1, "r3-eth1", "r1-eth1"),
        ):
            net.addLink(left, right, intfName1=left_port, intfName2=right_port)
        net.addLink(r1, s1, intfName1="r1-eth2")  # s1-eth1, transit
        net.addLink(s1, h1)                       # s1-eth2, LAN
        net.addLink(r2, h2, intfName1="r2-eth2")  # additional test LAN
        net.start()
        if not net.waitConnected(timeout=15):
            raise RuntimeError("OpenFlow switch did not connect")
        configure_frr(r1, "1.1.1.1", {
            "r1-eth0": "2001:db8:12::1/64",
            "r1-eth1": "2001:db8:31::1/64",
            "r1-eth2": "2001:db8:10::1/64"},
            ("r1-eth0", "r1-eth1", "r1-eth2"))
        configure_frr(r2, "2.2.2.2", {
            "r2-eth0": "2001:db8:12::2/64",
            "r2-eth1": "2001:db8:23::2/64",
            "r2-eth2": "2001:db8:2::1/64"},
            ("r2-eth0", "r2-eth1"), ("r2-eth2",))
        configure_frr(r3, "3.3.3.3", {
            "r3-eth0": "2001:db8:23::3/64",
            "r3-eth1": "2001:db8:31::3/64"},
            ("r3-eth0", "r3-eth1"))
        r1.cmd(f"ip link set dev r1-eth2 address {cfg.FRR_MAC}")
        configure_host(h1, cfg.HOST_MAC, f"{cfg.LAN_HOST}/64", cfg.LAN_GATEWAY)
        configure_host(h2, "02:00:00:00:02:00", "2001:db8:2::100/64",
                       "2001:db8:2::1")
        start_frr(r1)
        start_frr(r2)
        start_frr(r3)
        info("\nVerify: r1 vtysh -c 'show ipv6 ospf6 neighbor'\n")
        info("        r2 vtysh -c 'show ipv6 route ospf6'\n")
        info("        r3 vtysh -c 'show ipv6 route ospf6'\n")
        info("        h1 ping -6 -c 3 2001:db8:2::100\n")
        info("        h2 ping -6 -c 3 2001:db8:1::100\n")
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()
