"""Offline test setup: load the checked-out source without editing it."""

import os
from pathlib import Path
import socket
import sys


HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
SOURCE = Path(os.environ.get("OSPFV3_SOURCE_DIR", ROOT.parent)).resolve()
if not (SOURCE / "packets.py").exists():
    # Also work when this validation directory sits beside a read-only clone.
    SOURCE = ROOT.parent / "audit-source"
if not (SOURCE / "packets.py").is_file():
    raise RuntimeError("Set OSPFV3_SOURCE_DIR to the repository checkout")
sys.path.insert(0, str(SOURCE))


def _netlink_available():
    if not hasattr(socket, "AF_NETLINK"):
        return True
    try:
        probe = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    except PermissionError:
        return False
    else:
        probe.close()
        return True


# Some restricted CI sandboxes forbid Linux NETLINK, which Scapy probes on
# import even for packet-only use. In that case ONLY, disable its discovery.
# Production packets / protocol code and checksum functions remain unpatched.
if not _netlink_available():
    import scapy.interfaces
    from scapy.config import conf

    scapy.interfaces.NetworkInterfaceDict._reload_provs = lambda self: None
    conf.route_autoload = False
    conf.route6_autoload = False
