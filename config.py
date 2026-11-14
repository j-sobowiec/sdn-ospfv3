"""Two fixed SDN routers, indexed by OpenFlow datapath ID."""

AREA_ID = "0.0.0.0"
INSTANCE_ID = 0
MTU = 1500
OPTIONS = 0x13
HELLO_INTERVAL = 10
DEAD_INTERVAL = 40
RETRANSMIT_INTERVAL = 5
LS_REFRESH_INTERVAL = 1800
LSA_INITIAL_SEQ = 0x80000001

# All values are specific to the physical ports in topology.py. There is
# intentionally no discovery or generic routing configuration mechanism.
SWITCHES = {
    1: dict(
        router_id="10.10.10.10", 
        neighbor_id="1.1.1.1", 
        interface_id=1,
        transit_port=1, 
        lan_port=2,
        transit_mac="02:00:00:00:00:01",
        lan_mac="02:00:00:00:01:01",
        frr_mac="02:00:00:00:10:01",
        host_mac="02:00:00:00:01:00", 
        link_local="fe80::10",
        transit_prefix="2001:db8:10::/64", 
        lan_prefix="2001:db8:1::/64",
        lan_gateway="2001:db8:1::1", 
        lan_host="2001:db8:1::100",
    ),
    2: dict(
        router_id="11.11.11.11", 
        neighbor_id="2.2.2.2", 
        interface_id=2,
        transit_port=1, 
        lan_port=2,
        transit_mac="02:00:00:00:00:02", 
        lan_mac="02:00:00:00:02:01",
        frr_mac="02:00:00:00:20:01",
        host_mac="02:00:00:00:02:00", 
        link_local="fe80::11",
        transit_prefix="2001:db8:20::/64",
        lan_prefix="2001:db8:2::/64",
        lan_gateway="2001:db8:2::1", 
        lan_host="2001:db8:2::100",
    ),
}
