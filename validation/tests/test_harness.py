"""Guard the harness against vacuous PASS from unrelated network state."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_integration import (forwarding_flows_have_packets, is_full,
                             integration_status, kernel_route_missing, ospf_route_present,
                             ping_success, strip_terminal_artifacts)


def test_neighbor_must_have_correct_id_and_full_on_same_line():
    assert is_full("10.10.10.10   Full/PointToPoint   00:00:30\n")
    assert not is_full("10.10.10.10   Init\n2.2.2.2   Full/PointToPoint\n")
    assert not is_full("110.10.10.100   Full/PointToPoint\n")


def test_route_must_be_in_protocol_rib_and_linux_fib():
    frr = "I 2001:db8:1::/64 cost 20 via fe80::10"
    kernel = "2001:db8:1::/64 via fe80::10 dev r2-eth0 proto ospf6 metric 20"
    assert ospf_route_present(frr, kernel)
    assert ospf_route_present("*N 2001:db8:1::/64 fe80::10 r2-eth0", kernel)
    assert not ospf_route_present("", kernel)
    assert not ospf_route_present("No OSPF route to 2001:db8:1::/64", kernel)
    assert not ospf_route_present(frr, "2001:db8:1::/64 dev eth0 proto static")


def test_ping_requires_nonzero_received_and_zero_loss():
    assert ping_success("5 packets transmitted, 5 received, 0% packet loss")
    assert ping_success("3 packets transmitted, 3 received, 0% packet loss",
                        expected_packets=3)
    assert not ping_success("1 packets transmitted, 1 received, 0% packet loss")
    assert not ping_success("5 packets transmitted, 0 received, 100% packet loss")
    assert not ping_success("5 packets transmitted, 4 received, 20% packet loss")


def test_both_forwarding_flows_must_have_traffic():
    line = ("cookie=0, table=0, n_packets={n}, n_bytes=100, "
            "priority=100,ipv6,in_port={p} "
            "actions=dec_ttl,set_field:02:00:00:00:00:01->eth_src,"
            "set_field:02:00:00:00:10:01->eth_dst,output:{out}")
    both = "\n".join((line.format(n=5, p=1, out=2), line.format(n=5, p=2, out=1)))
    assert forwarding_flows_have_packets(both)
    assert not forwarding_flows_have_packets(line.format(n=7, p=1, out=2))
    assert not forwarding_flows_have_packets("\n".join((
        line.format(n=0, p=1, out=2), line.format(n=2, p=2, out=1))))
    assert not forwarding_flows_have_packets("\n".join((
        "n_packets=2, priority=100,ipv6,in_port=1 actions=drop",
        "n_packets=2, priority=100,ipv6,in_port=2 actions=drop")))
    assert not forwarding_flows_have_packets("\n".join((
        line.format(n=5, p=1, out=1), line.format(n=5, p=2, out=2))))


def test_integration_requires_all_eleven_distinct_passes():
    records = [{"test": f"INT-{number:02d}", "status": "PASS"}
               for number in range(1, 12)]
    assert integration_status(records) == "PASS"
    assert integration_status(records, exception=True) == "BLOCKED"
    assert integration_status(records[:-1]) == "BLOCKED"
    blocked = [dict(item) for item in records]
    blocked[8]["status"] = "BLOCKED"
    assert integration_status(blocked) == "BLOCKED"
    failed = [dict(item) for item in records]
    failed[8]["status"] = "FAIL"
    assert integration_status(failed) == "FAIL"
    duplicate = [dict(item) for item in records]
    duplicate[8]["test"] = "INT-01"
    assert integration_status(duplicate) == "BLOCKED"


def test_bracketed_paste_sequences_do_not_create_phantom_interface_errors():
    # Actual bytes captured in the failed INT-10 result on Ubuntu.
    noise = "\x1b[?2004l\r\x1b[?2004h\n"
    assert strip_terminal_artifacts(noise) == ""
    assert kernel_route_missing(noise)
    assert kernel_route_missing("\n")


def test_real_interface_errors_and_routes_are_not_hidden():
    noise = "\x1b[?2004l\r\x1b[?2004h\n"
    error = "ifconfig: error: No such device\n"
    route = "2001:db8:1::/64 via fe80::1 dev r2-eth0 proto ospf\n"
    assert error in strip_terminal_artifacts(noise + error)
    assert strip_terminal_artifacts(noise + route).strip() == route.strip()
    assert not kernel_route_missing(noise + route)
    assert not kernel_route_missing(noise + error)
