"""SentinelWiFi — network adapter detection and monitor-mode handling.

For auditing networks you own or are authorized to test.

Everything here is local and passive: we query interface state with stdlib
tools (ioctl via fcntl on Linux, /sys/class/net, and optionally the `iw`
command). No packets are ever transmitted and no frames leave the adapter.
"""

from __future__ import annotations

import fcntl
import os
import shutil
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass, field

SIOCGIFADDR = 0x8915      # get IPv4 address of an interface
SIOCGIFHWADDR = 0x8927    # get MAC address of an interface
SIOCGIFFLAGS = 0x8913     # get interface flags


@dataclass
class AdapterInfo:
    name: str
    mac: str = "unknown"
    ip: str = ""
    mode: str = "managed"      # "managed" | "monitor" | "unknown"
    monitor_capable: bool = False  # driver says it can do monitor mode
    monitor_notes: list[str] = field(default_factory=list)
    wireless: bool = False


def _ioctl_bytes(ifname: str, request: int, length: int = 40) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("256s", ifname.encode()[:15])
        return fcntl.ioctl(sock.fileno(), request, ifreq)[:length]
    finally:
        sock.close()


def get_ipv4(ifname: str) -> str:
    try:
        data = _ioctl_bytes(ifname, SIOCGIFADDR, 40)
        return socket.inet_ntoa(data[20:24])
    except OSError:
        return ""


def get_mac(ifname: str) -> str:
    try:
        data = _ioctl_bytes(ifname, SIOCGIFHWADDR, 24)
        return ":".join(f"{b:02x}" for b in data[18:24])
    except OSError:
        return "unknown"


def get_flags(ifname: str) -> int:
    data = _ioctl_bytes(ifname, SIOCGIFFLAGS, 40)
    return struct.unpack("H", data[16:18])[0]


def is_wireless(ifname: str) -> bool:
    """Best-effort: check sysfs for wireless extensions, then `iw`."""
    if os.path.exists(f"/sys/class/net/{ifname}/wireless"):
        return True
    if shutil.which("iw"):
        try:
            out = subprocess.run(
                ["iw", "dev", ifname, "info"],
                capture_output=True, text=True, timeout=5,
            )
            return out.returncode == 0 and "type" in out.stdout
        except Exception:
            return False
    return False


def detect_adapters() -> list[AdapterInfo]:
    """Enumerate network interfaces (skips loopback and virtual bridges)."""
    adapters: list[AdapterInfo] = []
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return adapters
    for name in names:
        if name == "lo" or name.startswith(("docker", "br-", "virbr", "veth", "tun", "tap", "wg")):
            continue
        try:
            flags = get_flags(name)
        except OSError:
            continue
        up = bool(flags & 0x1)
        adapters.append(AdapterInfo(
            name=name,
            mac=get_mac(name),
            ip=get_ipv4(name) if up else "",
            wireless=is_wireless(name),
        ))
    return adapters


def pick_default_adapter() -> AdapterInfo | None:
    """Choose the adapter to audit: first wireless with an IP, else any
    adapter with an IP, else the first non-loopback adapter."""
    adapters = detect_adapters()
    for a in adapters:
        if a.wireless and a.ip:
            return a
    for a in adapters:
        if a.ip:
            return a
    return adapters[0] if adapters else None


def check_monitor_capability(ifname: str) -> AdapterInfo:
    """Fill in monitor-mode capability info for the given adapter.

    Uses `iw list` (if present) to see whether the driver exposes monitor
    mode. This only *queries* capability — it does not change interface
    state unless try_enable_monitor is called, and even then it falls back
    gracefully on failure.
    """
    adapters = detect_adapters()
    info = next((a for a in adapters if a.name == ifname), None)
    if info is None:
        info = AdapterInfo(name=ifname)

    if shutil.which("iw"):
        try:
            out = subprocess.run(["iw", "list"], capture_output=True,
                                 text=True, timeout=10)
            if out.returncode == 0 and "monitor" in out.stdout:
                info.monitor_capable = True
            elif out.returncode != 0:
                info.monitor_notes.append("`iw list` failed; monitor-mode "
                                          "status unknown.")
        except Exception as exc:
            info.monitor_notes.append(f"could not query monitor capability: {exc}")
    else:
        info.monitor_notes.append("`iw` not installed — cannot determine "
                                  "monitor-mode support; assuming managed-mode only.")

    # Also check current mode via `iw dev <if> info`
    if shutil.which("iw"):
        try:
            out = subprocess.run(["iw", "dev", ifname, "info"],
                                 capture_output=True, text=True, timeout=5)
            for line in out.stdout.splitlines():
                if "type" in line:
                    if "monitor" in line:
                        info.mode = "monitor"
                    elif "managed" in line:
                        info.mode = "managed"
                    break
        except Exception:
            pass
    return info


def try_enable_monitor(ifname: str) -> bool:
    """Attempt to switch the adapter to monitor mode (read-only sniffing).

    Uses `iw dev <if> set type monitor`. No frames are sent — this only
    changes the interface's receive mode. Returns False on any failure so
    the caller can degrade to managed-mode scanning instead of crashing.
    """
    if not shutil.which("iw"):
        return False
    try:
        subprocess.run(["ip", "link", "set", ifname, "down"], timeout=10)
        r = subprocess.run(["iw", "dev", ifname, "set", "type", "monitor"],
                           capture_output=True, timeout=10)
        if r.returncode != 0:
            subprocess.run(["ip", "link", "set", ifname, "up"], timeout=10)
            return False
        subprocess.run(["ip", "link", "set", ifname, "up"], timeout=10)
        return True
    except Exception:
        return False


def restore_managed(ifname: str) -> None:
    """Best-effort restore of managed mode. Called at exit if we changed it."""
    if not shutil.which("iw"):
        return
    try:
        subprocess.run(["ip", "link", "set", ifname, "down"], timeout=10)
        subprocess.run(["iw", "dev", ifname, "set", "type", "managed"],
                       capture_output=True, timeout=10)
        subprocess.run(["ip", "link", "set", ifname, "up"], timeout=10)
    except Exception:
        pass


def platform_notes() -> list[str]:
    """Return platform-specific limitation notes for the report."""
    notes = []
    if sys.platform.startswith("win"):
        notes.append("Windows: monitor mode is not supported — AP scanning is "
                     "limited to netsh-visible networks. Vendor lookup and "
                     "ARP inventory work normally.")
    if not shutil.which("iw"):
        notes.append("`iw` (wireless tools) not found — full channel scanning "
                     "requires it. Try: sudo apt install iw")
    if os.geteuid() != 0 if hasattr(os, "geteuid") else False:
        notes.append("Not running as root: sniffing and ARP scanning may be "
                     "limited. Re-run with sudo for complete results.")
    return notes
