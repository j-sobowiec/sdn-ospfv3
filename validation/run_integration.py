#!/usr/bin/env python3
"""Dedicated Ubuntu/Containernet integration validation (explicit --execute).

Runs the existing topology unmodified, replacing only its interactive CLI
callback with read-only network probes. The optional stop/restart of the
controller is deliberate and limited to the process started by this runner.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import traceback


PREFIX = "2001:db8:1::/64"
CONTROLLER_PORT = 6653


def check_command(cmd, *args):
    try:
        return subprocess.run([cmd, *args], capture_output=True, text=True,
                              timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def preflight(source, controller_python, check_live=True):
    issues = []
    if not (source / "topology.py").is_file() or not (source / "controller.py").is_file():
        issues.append("source checkout lacks topology.py/controller.py")
    for tool in ("docker", "ovs-vsctl", "ovs-ofctl", "ip"):
        if not shutil.which(tool):
            issues.append(f"missing command: {tool}")
    try:
        import mininet.net  # noqa: F401
        from mininet.net import Containernet  # noqa: F401
    except Exception as exc:
        issues.append(f"Python cannot import Containernet: {exc}")
    run = check_command(str(controller_python), "-c", "import ryu, scapy, eventlet")
    if run is None or run.returncode:
        issues.append("controller Python lacks working ryu/scapy/eventlet imports")
    docker = check_command("docker", "info", "--format", "{{.ServerVersion}}")
    if docker is None or docker.returncode:
        issues.append("Docker daemon unavailable")
    if check_live:
        if os.geteuid() != 0:
            issues.append("must run as root (Containernet changes network namespaces)")
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("127.0.0.1", CONTROLLER_PORT))
            probe.close()
        except OSError:
            issues.append(f"TCP port {CONTROLLER_PORT} is already in use")
        bridge = check_command("ovs-vsctl", "br-exists", "s1")
        if bridge is not None and bridge.returncode == 0:
            issues.append("OVS bridge s1 exists; refusing to overwrite it")
        containers = check_command("docker", "ps", "-a", "--format", "{{.Names}}")
        if containers is not None and containers.returncode == 0:
            existing = set(containers.stdout.splitlines()) & {"r1", "r2", "r3"}
            if existing:
                issues.append(f"FRR container names already exist: {sorted(existing)}")
    return issues


def git_commit(source):
    run = check_command("git", "-C", str(source), "rev-parse", "HEAD")
    return run.stdout.strip() if run and run.returncode == 0 else None


def git_status(source):
    run = check_command("git", "-C", str(source), "status", "--short")
    return run.stdout.strip() if run and run.returncode == 0 else None


def source_fingerprints(source):
    """Record exact file bytes, including uncommitted protocol fixes."""
    names = ("config.py", "controller.py", "packets.py", "peer.py",
             "run_ryu.py", "topology.py")
    hashes = {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
              for name in names}
    hashes["validation/run_integration.py"] = hashlib.sha256(
        Path(__file__).read_bytes()).hexdigest()
    return hashes


def is_full(text):
    # FRRouting plain-text neighbor output: ID and Full on the same line.
    return any("10.10.10.10" in line and re.search(r"\bFull\b", line, re.I)
               for line in text.splitlines())


def ospf_route_present(frr_table, kernel_table):
    # Both the FRR protocol RIB and the Linux FIB must agree. A kernel-only
    # static route, or an OSPF entry not installed in the FIB, is insufficient.
    frr_has = PREFIX in frr_table or "2001:db8:1::/64" in frr_table.lower()
    kernel_lines = [line.lower() for line in kernel_table.splitlines()
                    if "2001:db8:1::/64" in line.lower()]
    # iproute2 displays FRR protocol labels as ospf6, ospf, or numeric 188.
    kernel_has = any(re.search(r"\bproto\s+(ospf6?|188)\b", line)
                     for line in kernel_lines)
    return frr_has and kernel_has


def ping_success(output):
    loss = re.search(r"(?<!\d)(\d+(?:\.\d+)?)% packet loss\b", output)
    return (loss is not None and float(loss.group(1)) == 0 and
            re.search(r"\b([1-9]\d*) received\b", output) is not None)


def strip_terminal_artifacts(output):
    """Remove only Bash's bracketed-paste toggles from Mininet command output.

    These bytes can make a successful, silent `ifconfig up` look like an error.
    Preserve any actual diagnostic message for the caller to report.
    """
    cleaned = re.sub(r"\x1b\[\?2004[hl]", "", output)
    return cleaned if cleaned.strip() else ""


def kernel_route_missing(output):
    return not strip_terminal_artifacts(output).strip()


def forwarding_flows_have_packets(output):
    matched = set()
    for line in output.splitlines():
        if "priority=100" not in line or "actions=" not in line:
            continue
        count = re.search(r"\bn_packets=(\d+)\b", line)
        port = re.search(r"\bin_port=([12])\b", line)
        if count and int(count.group(1)) > 0 and port:
            matched.add(port.group(1))
    return matched == {"1", "2"}


def application_payload_probe(sender, receiver, address, transport, port):
    """Send non-ICMP IPv6 bytes between namespaces, without nc/iperf."""
    marker = "ospfv3-validation-payload"
    kind = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
    server_source = (
        "import socket\n"
        f"s=socket.socket(socket.AF_INET6,{kind})\n"
        "s.settimeout(12)\n"
        f"s.bind(('::',{port}))\n"
    )
    if transport == "tcp":
        server_source += (
            "s.listen(1)\n"
            "c,_=s.accept()\n"
            "data=c.recv(256)\n"
            f"assert data=={marker.encode()!r}\n"
            "c.sendall(b'ACK:'+data)\n"
            "c.close()\n"
        )
        client_source = (
            "import socket\n"
            "s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)\n"
            "s.settimeout(8)\n"
            f"s.connect(({address!r},{port}))\n"
            f"s.sendall({marker.encode()!r})\n"
            "data=s.recv(256)\n"
            f"assert data=={(b'ACK:' + marker.encode())!r},data\n"
            "print('CLIENT_OK')\n"
        )
    else:
        server_source += (
            "data,remote=s.recvfrom(256)\n"
            f"assert data=={marker.encode()!r}\n"
            "s.sendto(b'ACK:'+data,remote)\n"
        )
        client_source = (
            "import socket\n"
            "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)\n"
            "s.settimeout(8)\n"
            f"s.sendto({marker.encode()!r},({address!r},{port}))\n"
            "data,_=s.recvfrom(256)\n"
            f"assert data=={(b'ACK:' + marker.encode())!r},data\n"
            "print('CLIENT_OK')\n"
        )
    server_source += "print('SERVER_OK')\ns.close()\n"
    server = receiver.popen(["python3", "-u", "-c", server_source],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        time.sleep(0.6)
        client_text = sender.cmd("python3 -c " + shlex.quote(client_source))
        try:
            server_out, _ = server.communicate(timeout=14)
        except subprocess.TimeoutExpired:
            server_out = b"server timeout"
            server.terminate()
            server.wait(timeout=4)
        combined = (f"Client ({sender.name}):\n{client_text}\n"
                    f"Server ({receiver.name}):\n{server_out.decode(errors='replace')}\n")
        return ("CLIENT_OK" in client_text and b"SERVER_OK" in server_out
                and server.returncode == 0), combined
    finally:
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=4)


class Recorder:
    def __init__(self, directory):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=False)
        self.records = []
        self.counter = 0

    def observe(self, label, command, output):
        self.counter += 1
        name = f"{self.counter:03d}-{label}.txt"
        path = self.directory / name
        path.write_text(f"$ {command}\n\n{output}\n", encoding="utf-8")
        return name

    def check(self, test_id, expected, got, passed, evidence, status=None):
        result = {
            "test": test_id,
            "expected": expected,
            "observed": got,
            "status": status or ("PASS" if passed else "FAIL"),
            "evidence": evidence,
            "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        self.records.append(result)
        print(f"{test_id}: {result['status']} — {got}", flush=True)


class Harness:
    def __init__(self, source, output, controller_python):
        self.source = source
        self.output = output
        self.controller_python = controller_python
        self.controller = None
        self.controller_log = None
        self.rec = Recorder(output / "evidence")

    def launch_controller(self, tag):
        if self.controller is not None:
            raise RuntimeError("controller already launched")
        self.controller_log = (self.output / f"controller-{tag}.log").open("w")
        self.controller = subprocess.Popen(
            [str(self.controller_python), str(self.source / "run_ryu.py"),
             "--ofp-tcp-listen-port", str(CONTROLLER_PORT),
             str(self.source / "controller.py")],
            cwd=self.source, stdout=self.controller_log,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        until = time.monotonic() + 25
        while time.monotonic() < until:
            if self.controller.poll() is not None:
                raise RuntimeError(f"Ryu exited {self.controller.returncode}; see controller-{tag}.log")
            try:
                with socket.create_connection(("127.0.0.1", CONTROLLER_PORT), timeout=1):
                    return
            except OSError:
                time.sleep(0.4)
        raise RuntimeError(f"Ryu never opened TCP {CONTROLLER_PORT}")

    def stop_controller(self):
        if self.controller:
            if self.controller.poll() is None:
                self.controller.terminate()
                try:
                    self.controller.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    self.controller.kill()
                    self.controller.wait(timeout=5)
            self.controller = None
        if self.controller_log:
            self.controller_log.close()
            self.controller_log = None

    def query(self, node, label, command):
        value = node.cmd(command)
        log = self.rec.observe(label, f"{node.name}: {command}", value)
        return value, log

    def wait_for(self, node, label, command, predicate, seconds=110):
        limit = time.monotonic() + seconds
        last_value = ""
        last_log = None
        while True:
            last_value, last_log = self.query(node, label, command)
            if predicate(last_value):
                return True, last_value, last_log
            if time.monotonic() >= limit:
                return False, last_value, last_log
            time.sleep(4)

    def probes(self, net):
        r1, r2, r3 = net.get("r1"), net.get("r2"), net.get("r3")
        h1, h2 = net.get("h1"), net.get("h2")
        neigh_cmd = "vtysh -c 'show ipv6 ospf6 neighbor'"
        frr_cmd = "vtysh -c 'show ipv6 ospf6 route'"
        kernel_cmd = f"ip -6 route show exact {PREFIX}"

        version_commands = [
            ("docker-version", "docker", ["--version"]),
            ("ovs-version", "ovs-vsctl", ["--version"]),
        ]
        versions = {}
        for label, cmd, cmd_args in version_commands:
            version = check_command(cmd, *cmd_args)
            versions[label] = version.stdout.strip() if version else None
        versions["FRRouting"] = r1.cmd("vtysh --version")
        version_file = self.output / "component-versions.json"
        version_file.write_text(json.dumps(versions, indent=2) + "\n")

        reached, neighbors, nlog = self.wait_for(r1, "neighbor", neigh_cmd, is_full)
        self.rec.check("INT-01", "Controller 10.10.10.10 Full on FRR R1",
                       "Full" if reached else "Full not observed", reached, [nlog])

        route_ok = False
        flogs = []
        if reached:
            limit = time.monotonic() + 70
            while time.monotonic() < limit:
                frr_route, flog = self.query(r2, "r2-frr-route", frr_cmd)
                kernel_route, klog = self.query(r2, "r2-kernel-route", kernel_cmd)
                flogs = [flog, klog]
                if ospf_route_present(frr_route, kernel_route):
                    route_ok = True
                    break
                time.sleep(4)
        self.rec.check("INT-02", f"R2 OSPF6 RIB and Linux FIB learn {PREFIX}",
                       "both tables contain protocol route" if route_ok else "not confirmed",
                       route_ok, flogs)

        r3_ok, r3_frr, r3log = self.wait_for(
            r3, "r3-ospf-route", frr_cmd,
            lambda text: PREFIX in text, seconds=45)
        r3_kernel, r3klog = self.query(r3, "r3-kernel-route", kernel_cmd)
        r3_ok = r3_ok and ospf_route_present(r3_frr, r3_kernel)
        self.rec.check("INT-03", f"R3 independently learns SDN LAN by OSPF6",
                       "FRR + Linux route present" if r3_ok else "route not confirmed",
                       r3_ok, [r3log, r3klog])

        # Also record the full LSA database; its prefix claim needs protocol
        # routing evidence, not a grep of a controller diagnostic message.
        db, dlog = self.query(r1, "r1-lsdb", "vtysh -c 'show ipv6 ospf6 database detail'")
        lsdb_ok = "2001:db8:1::" in db.lower() and "10.10.10.10" in db
        self.rec.check("INT-04", f"R1 LSDB contains controller's LAN {PREFIX}",
                       "prefix and Router ID visible" if lsdb_ok else "prefix/Router ID not confirmed",
                       lsdb_ok, [dlog])

        for name, host, addr in (
            ("INT-05", h1, "2001:db8:2::100"),
            ("INT-06", h2, "2001:db8:1::100"),
        ):
            result, log = self.query(host, name.lower(), f"ping -6 -n -c 5 -W 2 {addr}")
            self.rec.check(name, f"5 ICMPv6 echo requests to {addr}, zero lost",
                           "ping success" if ping_success(result) else "ping failed",
                           ping_success(result), [log])

        for name, protocol, port in (("INT-07", "tcp", 49071),
                                     ("INT-08", "udp", 49081)):
            observations = []
            outcomes = []
            for sender, receiver, address in ((h1, h2, "2001:db8:2::100"),
                                              (h2, h1, "2001:db8:1::100")):
                try:
                    ok, output = application_payload_probe(
                        sender, receiver, address, protocol, port)
                except Exception as exc:
                    ok, output = False, f"probe exception: {type(exc).__name__}: {exc}"
                outcomes.append(ok)
                observations.append(self.rec.observe(
                    f"{name.lower()}-{sender.name}-to-{receiver.name}",
                    f"IPv6 {protocol} payload/ACK {sender.name}->{receiver.name}", output))
            self.rec.check(name, f"IPv6 {protocol.upper()} payload and ACK in BOTH directions",
                           f"direction passes={outcomes}", all(outcomes), observations)

        ovs = check_command("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1")
        if ovs:
            flow_log = self.rec.observe("ovs-flow-counters",
                                        "ovs-ofctl -O OpenFlow13 dump-flows s1",
                                        ovs.stdout + ovs.stderr)
            flows_ok = ovs.returncode == 0 and forwarding_flows_have_packets(ovs.stdout)
            self.rec.check("INT-09", "Both OpenFlow 1.3 forwarding directions have nonzero counters",
                           "forwarding flow counters nonzero" if flows_ok else "counters not confirmed",
                           flows_ok, [flow_log])
        else:
            self.rec.check("INT-09", "OVS flows available", "tool execution failed",
                           False, [], status="BLOCKED")

        # Causal test: a static/synthetic route alone must not survive loss of
        # the OSPF adjacency. This intentionally interrupts only our Ryu process.
        self.stop_controller()
        lost, nlast, nl = self.wait_for(
            r1, "withdraw-neighbor", neigh_cmd, lambda text: not is_full(text), 85)
        withdrawn, last, klog = self.wait_for(
            r2, "withdraw-r2-kernel", kernel_cmd,
            kernel_route_missing, 85)
        frr_after, flog = self.query(r2, "withdraw-r2-frr", frr_cmd)
        # Some FRR versions retain old LSA text briefly, so the protocol RIB
        # and kernel FIB must both no longer offer the SDN prefix.
        frr_withdrawn = PREFIX not in frr_after
        self.rec.check("INT-10", "After Ryu stops, neighbor drops and R2 route is withdrawn",
                       f"neighbor_down={lost}; FIB_withdrawn={withdrawn}; RIB_withdrawn={frr_withdrawn}",
                       lost and withdrawn and frr_withdrawn, [nl, klog, flog])

        self.launch_controller("restart")
        again, nvalue, nlog = self.wait_for(r1, "recovered-neighbor", neigh_cmd, is_full)
        recovered_route = False
        rlogs = [nlog]
        if again:
            limit = time.monotonic() + 60
            while time.monotonic() < limit:
                frr_route, flog = self.query(r2, "recovered-frr", frr_cmd)
                kernel_route, klog = self.query(r2, "recovered-kernel", kernel_cmd)
                rlogs += [flog, klog]
                if ospf_route_present(frr_route, kernel_route):
                    recovered_route = True
                    break
                time.sleep(4)
        recover_pings = []
        for host, addr in ((h1, "2001:db8:2::100"), (h2, "2001:db8:1::100")):
            raw, log = self.query(host, "recovered-ping", f"ping -6 -n -c 3 -W 2 {addr}")
            recover_pings.append(ping_success(raw))
            rlogs.append(log)
        self.rec.check("INT-11", "Full, protocol route and both IPv6 pings recover after Ryu restarts",
                       f"Full={again}; OSPF route={recovered_route}; pings={recover_pings}",
                       again and recovered_route and all(recover_pings), rlogs)


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=here.parent)
    parser.add_argument("--controller-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--results", type=Path)
    parser.add_argument("--execute", action="store_true",
                        help="actually create a network, Docker containers and Ryu")
    args = parser.parse_args()
    source = args.source.resolve()
    # Do not follow a venv's python symlink to /usr/bin/python3: it would
    # lose the controller's installed Ryu/Scapy/Eventlet packages.
    controller_python = args.controller_python.absolute()
    issues = preflight(source, controller_python, check_live=args.execute)
    if not args.execute:
        print("PREFLIGHT ONLY (no network changes); issues:")
        print("\n".join(" - " + issue for issue in issues) or " - none")
        print("To start on a DEDICATED Ubuntu host: sudo -E python3 run_integration.py --execute --source ... --controller-python ...")
        return 0 if not issues else 2
    if issues:
        print("BLOCKED — will not modify this host:\n" + "\n".join(issues), file=sys.stderr)
        return 2

    output = (args.results or here / "results" / dt.datetime.now(dt.timezone.utc).strftime(
        "integration-%Y%m%dT%H%M%SZ")).resolve()
    output.mkdir(parents=True, exist_ok=False)
    harness = Harness(source, output, controller_python)
    metadata = {
        "type": "real-containernet-frr-ryu-ovs",
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "commit": git_commit(source),
        "source_git_status": git_status(source),
        "source_file_sha256": source_fingerprints(source),
        "system": platform.platform(),
        "python": sys.version,
        "controller_python": str(controller_python),
        "user_confirmed_execute": True,
        "tests": [],
    }
    try:
        harness.launch_controller("initial")
        sys.path.insert(0, str(source))
        import topology
        from mininet.link import Intf

        # Mininet's Intf.isUp treats any text returned by `ifconfig up` as an
        # error. In some shells, terminal-only bracketed-paste sequences are
        # returned even on success. Filter just those from the Python-side
        # interface command result, without altering Containernet or hiding
        # real errors. Restore the original method after the test.
        original_ifconfig = Intf.ifconfig

        def clean_ifconfig(intf, *cmd_args):
            return strip_terminal_artifacts(original_ifconfig(intf, *cmd_args))

        Intf.ifconfig = clean_ifconfig
        topology.CLI = harness.probes
        try:
            topology.main()
        finally:
            Intf.ifconfig = original_ifconfig
    except Exception as exc:
        metadata["exception"] = repr(exc)
        (output / "exception.txt").write_text(traceback.format_exc())
        print("BLOCKED/ERROR during integration harness:", exc, file=sys.stderr)
    finally:
        harness.stop_controller()
        metadata["tests"] = harness.rec.records
        metadata["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        metadata["status"] = ("BLOCKED" if "exception" in metadata else
                              "FAIL" if any(test["status"] == "FAIL" for test in metadata["tests"])
                              else "PASS" if len(metadata["tests"]) == 11 else "BLOCKED")
        (output / "summary.json").write_text(json.dumps(metadata, indent=2) + "\n")
        print("Evidence:", output)
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[metadata["status"]]


if __name__ == "__main__":
    sys.exit(main())
