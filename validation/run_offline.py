#!/usr/bin/env python3
"""Run repeatable, non-root offline tests and retain evidence as files."""

import argparse
import datetime as dt
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET


def command_output(args, cwd):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else None


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=here.parent)
    parser.add_argument("--results", type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    if not (source / "packets.py").is_file():
        parser.error("--source must be the sdn-ospfv3 root")
    output = (args.results or here / "results" / dt.datetime.now(dt.timezone.utc).strftime(
        "offline-%Y%m%dT%H%M%SZ")).resolve()
    output.mkdir(parents=True, exist_ok=False)

    packages = {}
    for name in ("pytest", "scapy"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    if any(v is None for v in packages.values()):
        print("BLOCKED: install requirements-test.txt in a separate virtualenv", file=sys.stderr)
        return 2

    netlink = True
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
        s.close()
    except (PermissionError, AttributeError):
        netlink = False

    command = [sys.executable, "-m", "pytest", "-ra", "-q",
               f"--junitxml={output / 'junit.xml'}", str(here / "tests")]
    env = os.environ.copy()
    env["OSPFV3_SOURCE_DIR"] = str(source)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Avoid accidentally collecting local access tokens in test reports.
    metadata = {
        "type": "offline",
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_commit": command_output(["git", "rev-parse", "HEAD"], source),
        "source_status": command_output(["git", "status", "--short"], source),
        "python": sys.version,
        "system": platform.platform(),
        "dependencies": packages,
        "netlink_available": netlink,
        "scapy_interface_discovery_disabled_for_offline_tests": not netlink,
        "command": command,
        "source": str(source),
    }
    with (output / "run.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=source, env=env,
                                stdout=log, stderr=subprocess.STDOUT,
                                text=True, check=False)
    metadata["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    metadata["pytest_exit_code"] = result.returncode
    metadata["status"] = "PASS" if result.returncode == 0 else "FAIL"
    cases = []
    junit = output / "junit.xml"
    if junit.is_file():
        for case in ET.parse(junit).iter("testcase"):
            failure = case.find("failure")
            if failure is None:
                failure = case.find("error")
            failed = failure is not None
            skipped = case.find("skipped") is not None
            cases.append({
                "test": case.attrib.get("name"),
                "class": case.attrib.get("classname"),
                "status": "NOT TESTED" if skipped else "FAIL" if failed else "PASS",
                "duration_seconds": float(case.attrib.get("time", 0)),
                "diagnostic": failure.attrib.get("message", "") if failed else "",
            })
    (output / "test-results.json").write_text(json.dumps(cases, indent=2) + "\n")
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print((output / "run.log").read_text())
    print("Evidence:", output)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
