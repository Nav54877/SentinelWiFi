"""SentinelWiFi — LAN device inventory (ARP scan of YOUR subnet only).

For auditing networks you own or are authorized to test.

We ARP-scan only the /24 the machine is currently on. ARP requests are
normal L2 broadcast traffic that any host generates; no packets leave the
local subnet and nothing is sent to any external address. Device history is
stored locally in ~/.sentinelwifi/known_devices.json (never uploaded).
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field

from .vendors import lookup_vendor

DATA_DIR = os.path.expanduser("~/.sentinelwifi")
KNOWN_DEVICES_FILE = os.path.join(DATA_DIR, "known_devices.json")


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str
    is_gateway: bool = False
    is_self: bool = False
    is_new: bool = False
    hostname: str = ""
    first_seen: float = field(default_factory=time.time)


def local_network_info() -> tuple[str, str, str]:
    """Return (local_ip, gateway_ip, interface_name)."""
    local_ip = ""
    gateway = ""
    iface = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("192.0.2.1", 80))  # TEST-NET-1: no traffic is actually sent
        local_ip = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    if local_ip:
        iface = _iface_for_ip(local_ip)
        gateway = _default_gateway()
    return local_ip, gateway, iface


def _iface_for_ip(ip: str) -> str:
    try:
        out = subprocess.run(["ip", "route", "get", "8.8.8.8"],
                             capture_output=True, text=True, timeout=5)
        parts = out.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return ""


def _default_gateway() -> str:
    try:
        with open("/proc/net/route") as f:
            next(f)  # header
            for line in f:
                fields = line.split()
                if fields[1] == "00000000":  # destination 0.0.0.0
                    return socket.inet_ntoa(bytes.fromhex(fields[2])[::-1])
    except OSError:
        pass
    return ""


def self_mac() -> str:
    try:
        iface = _iface_for_ip(local_network_info()[0]) or "eth0"
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().upper()
    except OSError:
        return ""


def arp_scan(subnet: str, timeout: int = 4) -> list[Device]:
    """ARP-scan the given CIDR subnet and return responding devices.

    Prefers scapy's ARP (no extra tools needed). Degrades to `ip neigh`
    fallback if scapy is missing. Only ever targets addresses inside
    `subnet`.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    devices: dict[str, Device] = {}
    local_ip, gateway, _ = local_network_info()
    my_mac = self_mac()

    try:
        from scapy.all import ARP, Ether, srp
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = srp(pkt, timeout=timeout, verbose=False)
        for _, rcv in answered:
            ip = rcv.psrc
            mac = str(rcv.hwsrc).upper()
            devices[ip] = Device(ip=ip, mac=mac, vendor=lookup_vendor(mac))
    except ImportError:
        # Fallback: read the kernel neighbour table (passive, no new traffic)
        try:
            out = subprocess.run(["ip", "neigh", "show"], capture_output=True,
                                 text=True, timeout=10)
            for line in out.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[2] == "lladdr":
                    ip, mac = parts[0], parts[4].upper()
                    if ipaddress.ip_address(ip) in network:
                        devices[ip] = Device(ip=ip, mac=mac, vendor=lookup_vendor(mac))
        except Exception:
            pass

    for dev in devices.values():
        dev.is_gateway = (dev.ip == gateway)
        dev.is_self = (dev.ip == local_ip) or (my_mac and dev.mac == my_mac)
        try:
            dev.hostname = socket.gethostbyaddr(dev.ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            dev.hostname = ""
    return sorted(devices.values(), key=lambda d: ipaddress.ip_address(d.ip))


def mark_new_devices(devices: list[Device]) -> None:
    """Compare against ~/.sentinelwifi/known_devices.json; flag newcomers."""
    known = _load_known()
    macs_seen = {d.mac for d in devices}
    for d in devices:
        d.is_new = d.mac not in known
    known.update(macs_seen)
    _save_known(known)


def _load_known() -> set[str]:
    try:
        with open(KNOWN_DEVICES_FILE) as f:
            data = json.load(f)
        return set(data.get("macs", []))
    except (OSError, json.JSONDecodeError, ValueError):
        return set()


def _save_known(macs: set[str]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = KNOWN_DEVICES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"macs": sorted(macs)}, f, indent=2)
    os.replace(tmp, KNOWN_DEVICES_FILE)  # atomic update


def announce_new_devices(previous: set[str], devices: list[Device]) -> list[Device]:
    """Return devices whose MAC was not in `previous` (for watch mode)."""
    return [d for d in devices if d.mac not in previous]


def check_gateway_admin(gateway_ip: str, timeout: float = 3.0) -> str:
    """Check how the router admin page answers: 'https', 'http', or
    'unreachable'.

    We open a single TCP connection to the gateway on standard web ports
    and read at most one response — the same thing your browser does. This
    is a reachability check, not an attack.
    """
    if not gateway_ip:
        return "unreachable"
    for port, proto in ((443, "https"), (80, "http")):
        try:
            with socket.create_connection((gateway_ip, port), timeout=timeout):
                return proto
        except OSError:
            continue
    return "unreachable"
