"""SentinelWiFi — DHCP server audit (rogue-DHCP detection).

For auditing networks you own or are authorized to test.

Purely local: we parse the DHCP client lease files your own machine already
wrote (/var/lib/NetworkManager, /var/lib/dhcp, ...). If the server that
handed out your network settings is not your gateway, someone else may be
answering DHCP requests on your LAN — a classic way to redirect all your
traffic. We never send DHCP packets ourselves.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

LEASE_DIRS = ("/var/lib/NetworkManager", "/var/lib/dhcp", "/var/lib/dhclient",
              "/var/db/dhclient.leases")
_LEASE_RE = re.compile(r"dhcp-server-identifier\s+(\d{1,3}(?:\.\d{1,3}){3})")


@dataclass
class DhcpInfo:
    servers: list[str] = field(default_factory=list)
    gateway: str = ""
    rogue: bool = False
    detail: str = ""


def parse_leases_text(text: str) -> set[str]:
    """Extract dhcp-server-identifier values from lease file text."""
    return set(_LEASE_RE.findall(text))


def dhcp_servers() -> set[str]:
    servers: set[str] = set()
    for base in LEASE_DIRS:
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            for fn in files:
                if fn.endswith((".lease", ".leases")) or fn == "dhclient.leases":
                    try:
                        with open(os.path.join(root, fn), errors="replace") as f:
                            servers |= parse_leases_text(f.read())
                    except OSError:
                        continue
    return servers


def audit_dhcp(gateway: str) -> DhcpInfo:
    """Compare DHCP server(s) from local leases against the gateway."""
    servers = sorted(dhcp_servers())
    info = DhcpInfo(servers=servers, gateway=gateway)
    if not servers:
        info.detail = ("No DHCP lease file found on this machine — cannot "
                       "verify which server assigned your settings.")
        return info
    unexpected = [s for s in servers if s != gateway]
    if unexpected:
        info.rogue = True
        info.detail = (f"DHCP was served by {', '.join(servers)}, but your "
                       f"gateway is {gateway or 'unknown'}. A server you don't "
                       "recognize is handing out network settings — it could "
                       "be redirecting your traffic (rogue DHCP).")
    else:
        info.detail = f"DHCP server matches your gateway ({servers[0]}). OK."
    return info
