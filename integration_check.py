#!/usr/bin/env python3
"""End-to-end OSPFv3/SDN check using the real existing Containernet topology.

Run on the Ubuntu lab host (Ryu venv + system Containernet):
    sudo python3 integration_check.py --ryu-python "$HOME/ryu-env/bin/python3"

Starts its own Ryu, delegates setup/teardown to topology.main(), never opens
an interactive Mininet CLI, and restores the S1 controller endpoint on errors.
Exit code 0 means all measured integration checks passed, nonzero means failure.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
CONTROL_PORT = 6653
S1_FAIL_PORT = 16653
NEIGHBORS = {"r1": "10.10.10.10", "r2": "11.11.11.11"}
PREFIX_ROUTES = {
    "r1": ("2001:db8:2::/64", "2001:db8:3::/64"),
    "r2": ("2001:db8:1::/64", "2001:db8:3::/64"),
    "r3": ("2001:db8:1::/64", "2001:db8:2::/64"),
}
PINGS = (
    ("h1", "2001:db8:2::100"), ("h2", "2001:db8:1::100"),
    ("h1", "2001:db8:3::100"), ("h3", "2001:db8:1::100"),
    ("h2", "2001:db8:3::100"), ("h3", "2001:db8:2::100"),
)


class CheckFailure(RuntimeError):
    pass


def report(label, details=""):
    print(f"[OK] {label}" + (f" | {details}" if details else ""), flush=True)


def require(condition, explanation):
    if not condition:
        raise CheckFailure(explanation)


def run_host(*command, timeout=20):
    result = subprocess.run(command, encoding="utf-8", errors="replace",
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout, check=False)
    if result.returncode:
        raise CheckFailure(f"command failed ({result.returncode}): "
                           f"{' '.join(command)}\n{result.stdout}")
    return result.stdout


def node_command(node, command):
    # Mininet Node.cmd returns output but not a reliable subprocess exit code.
    result = node.cmd(command + "; printf '\\n__OSPFCHECK_STATUS__=%s\\n' \"$?\"")
    match = re.search(r"__OSPFCHECK_STATUS__=(\d+)", result)
    require(match is not None, f"No shell status from {node.name}: {result}")
    return int(match.group(1)), result[:match.start()]


def neighbor_full(text, router_id):
    return any(router_id in line and re.search(r"\bFull(?:/|\b)", line, re.I)
               for line in text.splitlines())


def show_neighbor(node):
    status, output = node_command(node, "vtysh -c 'show ipv6 ospf6 neighbor'")
    require(status == 0, f"FRR neighbor query failed on {node.name}: {output}")
    return output


def wait_for(predicate, label, timeout=140, interval=2):
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        result = predicate()
        if isinstance(result, tuple):
            ok, last = result
        else:
            ok = result
        if ok:
            report(label)
            return
        time.sleep(interval)
    raise CheckFailure(f"TIMEOUT {label} ({timeout}s). Last output:\n{last}")


def assert_neighbors(net, timeout=140):
    def ready():
        outputs = {n: show_neighbor(net.get(n)) for n in NEIGHBORS}
        good = all(neighbor_full(outputs[n], router_id)
                   for n, router_id in NEIGHBORS.items())
        return good, "\n".join(f"{n}: {value}" for n, value in outputs.items())
    wait_for(ready, "R1-S1 and R2-S2 adjacency Full", timeout=timeout)


def assert_routes(net):
    for node_name, prefixes in PREFIX_ROUTES.items():
        node = net.get(node_name)
        status, output = node_command(node, "vtysh -c 'show ipv6 route ospf6'")
        require(status == 0, f"FRR OSPF route query failed on {node_name}: {output}")
        for prefix in prefixes:
            require(prefix in output,
                    f"Missing OSPF route {prefix} on {node_name}:\n{output}")
    report("Remote OSPFv3 routes on R1/R2/R3")


def assert_pings(net, label):
    for host_name, dest in PINGS:
        status, output = node_command(
            net.get(host_name), f"ping -6 -n -c 5 -W 2 {dest}")
        require(status == 0 and re.search(r"(?<!\d)0% packet loss", output),
                f"{label}: {host_name} -> {dest} failed:\n{output}")
    for host_name, gateway in (("h1", "2001:db8:1::1"),
                               ("h2", "2001:db8:2::1")):
        status, output = node_command(
            net.get(host_name), f"ping -6 -n -c 3 -W 2 {gateway}")
        require(status == 0 and re.search(r"(?<!\d)0% packet loss", output),
                f"NDP/gateway ping failed: {host_name} -> {gateway}:\n{output}")
    report(label, "6 end-to-end pings + 2 gateway pings, all 0% loss")


def flow_snapshot(switch):
    output = run_host("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch)
    routes = [line for line in output.splitlines() if "priority=100" in line]
    require(len(routes) == 2,
            f"Expected exactly two priority=100 rules on {switch}:\n{output}")
    require(all("dec_ttl" in line and "set_field" in line
                and "output:" in line for line in routes),
            f"Incomplete IPv6 forwarding actions on {switch}:\n{output}")
    counters = {}
    for line in routes:
        match = re.search(r"n_packets=(\d+)", line)
        require(match is not None, f"Missing flow packet counter: {line}")
        kind = "out" if "ipv6_src=" in line else "in"
        require(kind not in counters, f"Ambiguous {switch} flow rules:\n{output}")
        counters[kind] = int(match.group(1))
    require(set(counters) == {"in", "out"}, f"Incomplete {switch} flows: {output}")
    return counters


def assert_flow_counters(previous):
    for switch in ("s1", "s2"):
        current = flow_snapshot(switch)
        for key in ("in", "out"):
            require(current[key] > previous[switch][key],
                    f"{switch} {key}: OpenFlow counter not increasing "
                    f"({previous[switch][key]} -> {current[key]})")
    report("OpenFlow IPv6 flow counters increased in both directions")


def controller_endpoint(port):
    run_host("ovs-vsctl", "set-controller", "s1", f"tcp:127.0.0.1:{port}")


def assert_failure_isolation(net):
    require(not listener_active(S1_FAIL_PORT),
            f"Port {S1_FAIL_PORT} is occupied: fault test would be invalid")
    # Always restore the controller endpoint, including when an assertion fails.
    controller_endpoint(S1_FAIL_PORT)
    try:
        deadline = time.monotonic() + 57
        s1_down = False
        samples = 0
        while time.monotonic() < deadline:
            r2 = show_neighbor(net.get("r2"))
            require(neighbor_full(r2, NEIGHBORS["r2"]),
                    f"S2 adjacency lost during S1 failure:\n{r2}")
            r1 = show_neighbor(net.get("r1"))
            s1_down |= not neighbor_full(r1, NEIGHBORS["r1"])
            samples += 1
            time.sleep(2)
        require(s1_down, "S1 neighbor did not expire after >40s outage")
        report("S1 outage detected; S2 remained Full", f"{samples} samples")
    finally:
        controller_endpoint(CONTROL_PORT)
    assert_neighbors(net, timeout=150)
    assert_routes(net)
    report("S1 reconverged after reconnect without resetting S2")


def check_topology(net):
    require(all(net.get(name) for name in
                ("r1", "r2", "r3", "s1", "s2", "h1", "h2", "h3")),
            "Topology is missing required nodes")
    assert_neighbors(net)
    assert_routes(net)
    old = {s: flow_snapshot(s) for s in ("s1", "s2")}
    report("Expected OpenFlow IPv6 rules installed on both OVS")
    assert_pings(net, "IPv6 connectivity before fault")
    assert_flow_counters(old)
    assert_failure_isolation(net)
    assert_pings(net, "IPv6 connectivity after S1 recovery")
    report("ALL INTEGRATION CHECKS PASSED")


def listener_active(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ryu-python", default=os.environ.get(
        "RYU_PYTHON", str(Path("~/ryu-env/bin/python3").expanduser())),
        help="Python interpreter in the Ryu environment")
    parser.add_argument("--no-fault", action="store_true",
                        help="Skip the 57-second S1 disconnect/recovery scenario")
    args = parser.parse_args()

    require(os.geteuid() == 0, "Run with sudo (Mininet/Containernet requires root)")
    require(Path(args.ryu_python).is_file(),
            f"Ryu interpreter not found: {args.ryu_python}; use --ryu-python PATH")
    for cmd in ("ovs-ofctl", "ovs-vsctl", "docker"):
        require(shutil.which(cmd) is not None, f"Missing host executable: {cmd}")
    require(not listener_active(CONTROL_PORT),
            f"Port {CONTROL_PORT} already in use; stop any existing Ryu instance")
    try:
        import topology
    except ImportError as exc:
        raise CheckFailure(f"Mininet/Containernet unavailable in system Python: {exc}") from exc

    process = subprocess.Popen(
        [args.ryu_python, str(ROOT / "run_ryu.py"),
         "--ofp-tcp-listen-port", str(CONTROL_PORT), str(ROOT / "controller.py")],
        cwd=ROOT, stdout=sys.stdout, stderr=sys.stderr)
    try:
        def listening():
            require(process.poll() is None, "Ryu exited before listening on OpenFlow port")
            return listener_active(CONTROL_PORT)
        wait_for(listening, "Ryu OpenFlow listener ready", timeout=25, interval=0.5)
        if args.no_fault:
            def checks_without_fault(net):
                assert_neighbors(net)
                assert_routes(net)
                old = {s: flow_snapshot(s) for s in ("s1", "s2")}
                assert_pings(net, "IPv6 connectivity")
                assert_flow_counters(old)
                report("ALL INTEGRATION CHECKS PASSED (fault test skipped)")
            topology.CLI = checks_without_fault
        else:
            topology.CLI = check_topology
        topology.main()  # builds the real network, then always net.stop()
    finally:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    try:
        main()
    except (CheckFailure, subprocess.TimeoutExpired, OSError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
