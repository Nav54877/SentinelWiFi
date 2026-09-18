"""SentinelWiFi — exposed-service scan of devices on YOUR subnet.

For auditing networks you own or are authorized to test.

TCP connect-scan of a small, curated port list against IPs inside the local
/24 only. Connect-scanning your own devices is the same thing a browser or
SSH client does — it never authenticates, never exploits, and stops at
"port open / banner read". It answers the real question: "what services are
my devices exposing to anyone on my WiFi?"
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

# Curated, security-relevant port list (not a 65k sweep).
PORTS: dict[int, str] = {
    21: "FTP (cleartext login)", 22: "SSH", 23: "Telnet (cleartext login)",
    53: "DNS", 80: "HTTP", 111: "rpcbind", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB file sharing", 515: "Printer (LPD)",
    631: "Printer (IPP)", 1900: "UPnP discovery", 3000: "Dev server (e.g. Grafana/Rails)",
    3306: "MySQL", 3389: "RDP (remote desktop)", 5000: "UPnP/HTTP alt",
    5357: "WS-Discovery", 5432: "PostgreSQL", 5900: "VNC (remote desktop)",
    7547: "TR-069 router mgmt", 8080: "Alt HTTP / proxy", 8443: "Alt HTTPS",
    8888: "Alt admin panel", 9100: "Printer (raw)", 27017: "MongoDB",
}

BANNER_PORTS = {21, 22, 80, 8080, 8888, 5900}
MAX_WORKERS = 64


@dataclass
class OpenPort:
    port: int
    service: str
    banner: str = ""


def grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
            data = s.recv(80)
            return data.decode("utf-8", errors="replace").strip().splitlines()[0][:60]
    except OSError:
        return ""


def _probe(task) -> tuple[str, OpenPort] | None:
    ip, port, service, timeout = task
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
    except OSError:
        return None
    banner = grab_banner(ip, port, timeout) if port in BANNER_PORTS else ""
    return ip, OpenPort(port=port, service=service, banner=banner)


def scan_services(ips: list[str], timeout: float = 0.5,
                  ports: dict[int, str] | None = None) -> dict[str, list[OpenPort]]:
    """Scan curated ports on the given (local-subnet) IPs. ip -> open ports."""
    ports = ports or PORTS
    tasks = [(ip, p, svc, timeout) for ip in ips for p, svc in ports.items()]
    results: dict[str, list[OpenPort]] = {}
    if not tasks:
        return results
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for res in ex.map(_probe, tasks):
            if res:
                ip, op = res
                results.setdefault(ip, []).append(op)
    for ip in results:
        results[ip].sort(key=lambda o: o.port)
    return results


def risk_summary(services: dict[str, list[OpenPort]]) -> list[str]:
    """One-line risk notes for the worst offenders, sorted by severity."""
    SEV = {23: 3, 7547: 3, 21: 3, 3389: 2, 5900: 2, 445: 1, 139: 1,
           111: 1, 3306: 1, 5432: 1, 27017: 1, 1900: 1, 5357: 1, 5000: 1}
    notes = []
    for ip, ops in services.items():
        for op in ops:
            if op.port in SEV:
                notes.append((SEV[op.port], f"{ip} exposes {op.service} on port {op.port}"))
    return [n for _s, n in sorted(notes, key=lambda t: -t[0])]
