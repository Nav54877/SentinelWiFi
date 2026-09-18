#!/usr/bin/env python3
"""SentinelWiFi — CLI entry point (v2).

For auditing networks you own or are authorized to test.

Commands:
    scan      audit your WiFi + surroundings (+ grade)
    devices   ARP inventory of your subnet, flag newcomers
    ports     exposed-service scan of devices on your subnet
    watch     loop inventory, announce new devices (rogue-device alarm)
    report    full combined audit, optional HTML export
    selftest  verify the install/environment and show what's missing
    demo      render a report from synthetic data (no network needed)

Global flags: --json, --iface, --html FILE, --no-ports, --notify, --window,
--timeout, --interval. Persistent config lives in ~/.sentinelwifi/config.json.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import time

from sentinelwifi import __version__, ap_scan, history, lan_scan, ports
from sentinelwifi.config import load_config
from sentinelwifi.dhcp import audit_dhcp
from sentinelwifi.iface import (check_monitor_capability, pick_default_adapter,
                                platform_notes, restore_managed, try_enable_monitor)
from sentinelwifi.notify import notify
from sentinelwifi.report import ReportData, report_to_console, report_to_json
from sentinelwifi.report import write_html_report
from sentinelwifi.scoring import (check_congestion, check_dhcp, check_evil_twin,
                                  check_exposed_services, check_http_admin,
                                  check_new_aps, check_ssid_leak,
                                  check_unknown_devices, check_wifi_encryption,
                                  compute_grade)


def _subnet24(local_ip: str) -> str:
    return str(ipaddress.ip_network(local_ip + "/24", strict=False))


def _adapter_and_notes(args, cfg):
    adapter = pick_default_adapter(prefer=getattr(args, "iface", "") or
                                   cfg.get("preferred_iface", ""))
    limitations = platform_notes()
    if adapter is None:
        limitations.append("No usable network adapter found.")
        return None, limitations
    adapter = check_monitor_capability(adapter.name)
    if not adapter.wireless:
        limitations.append(f"{adapter.name} is not a WiFi adapter — wireless "
                           "audits limited to Ethernet-side checks.")
    return adapter, limitations


def _gather_wireless(adapter, window: int, cfg):
    """Returns (current, aps, rogue, limitations)."""
    limitations = []
    current = ap_scan.get_current_connection(adapter)
    aps, used_monitor = [], False
    if adapter.mode == "monitor":
        try:
            aps = ap_scan.sniff_aps_monitor(adapter.name, window)
            used_monitor = True
        except RuntimeError as exc:
            limitations.append(str(exc))
    if not aps and not used_monitor and adapter.monitor_capable:
        limitations.append("Monitor mode available but not active; attempting "
                           "to enable it for a passive sniffing window…")
        if try_enable_monitor(adapter.name):
            try:
                aps = ap_scan.sniff_aps_monitor(adapter.name, window)
                used_monitor = True
            except RuntimeError as exc:
                limitations.append(str(exc))
            finally:
                restore_managed(adapter.name)
        else:
            limitations.append("Could not enable monitor mode "
                               "(driver/permissions). Falling back to "
                               "managed-mode scan.")
    if not aps and adapter.wireless:
        aps = ap_scan.managed_mode_scan()
        if aps:
            limitations.append("Managed-mode scan only (no monitor mode): "
                               "results are snapshots, not a live channel "
                               "capture. A monitor-capable adapter + root "
                               "gives the full passive window.")
    trusted = frozenset(b.upper() for b in cfg.get("trusted_bssids", []))
    rogue = ap_scan.analyze_environment(aps, current, trusted) if aps else []
    return current, aps, rogue, limitations


def _build_findings(current, aps, rogue, devices, admin_proto, gateway,
                    dhcp_info, services, hist, cfg):
    findings = []
    for f in (check_wifi_encryption(current.get("encryption", "")),
              check_http_admin(admin_proto, gateway),
              check_ssid_leak(current.get("ssid", "")),
              check_dhcp(dhcp_info)):
        if f:
            findings.append(f)
    etwin = next((r for r in rogue if r.kind == "evil_twin"), None)
    if etwin:
        findings.append(check_evil_twin(etwin.message))
    cong = next((r for r in rogue if r.kind == "congestion"), None)
    if cong:
        on_ch = len([a for a in aps if a.channel == current.get("channel")])
        findings.append(check_congestion(cong.message, on_ch))
    new_count = len([d for d in devices if d.is_new and not d.is_self])
    f = check_unknown_devices(new_count)
    if f:
        findings.append(f)
    f = check_exposed_services(ports.risk_summary(services))
    if f:
        findings.append(f)
    if hist:
        f = check_new_aps(hist.new_aps, current.get("ssid", ""))
        if f:
            findings.append(f)
    return compute_grade(findings)


def _render(data: ReportData, args) -> None:
    if getattr(args, "json", False):
        print(report_to_json(data))
    else:
        print(report_to_console(data))
    out = getattr(args, "html", "")
    if out:
        path = write_html_report(data, out)
        print(f"\nHTML report written to: {path}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_scan(args, cfg) -> int:
    adapter, limitations = _adapter_and_notes(args, cfg)
    if adapter is None:
        print("ERROR: no network adapter found.", file=sys.stderr)
        return 1
    current, aps, rogue, lim2 = _gather_wireless(adapter, args.window, cfg)
    limitations += lim2
    local_ip, gateway, _ = lan_scan.local_network_info()
    admin_proto = lan_scan.check_gateway_admin(gateway)
    findings = []
    for f in (check_wifi_encryption(current.get("encryption", "")),
              check_http_admin(admin_proto, gateway),
              check_ssid_leak(current.get("ssid", ""))):
        if f:
            findings.append(f)
    etwin = next((r for r in rogue if r.kind == "evil_twin"), None)
    if etwin:
        findings.append(check_evil_twin(etwin.message))
    cong = next((r for r in rogue if r.kind == "congestion"), None)
    if cong:
        on_ch = len([a for a in aps if a.channel == current.get("channel")])
        findings.append(check_congestion(cong.message, on_ch))
    data = ReportData(current=current, aps=aps, rogue=rogue,
                      score=compute_grade(findings),
                      admin_proto=admin_proto, limitations=limitations)
    _render(data, args)
    return 0


def cmd_devices(args, cfg) -> int:
    local_ip, gateway, _ = lan_scan.local_network_info()
    if not local_ip:
        print("ERROR: no IPv4 address on this machine.", file=sys.stderr)
        return 1
    subnet = _subnet24(local_ip)
    devices = lan_scan.arp_scan(subnet, timeout=args.timeout)
    lan_scan.mark_new_devices(devices)
    services = {}
    if getattr(args, "ports", False):
        services = ports.scan_services([d.ip for d in devices],
                                       timeout=cfg["port_scan_timeout"])
    findings = []
    f = check_unknown_devices(len([d for d in devices if d.is_new and not d.is_self]))
    if f:
        findings.append(f)
    f = check_exposed_services(ports.risk_summary(services))
    if f:
        findings.append(f)
    admin_proto = lan_scan.check_gateway_admin(gateway)
    _render(ReportData(devices=devices, services=services,
                       score=compute_grade(findings), admin_proto=admin_proto,
                       limitations=[f"Subnet scanned: {subnet}"]), args)
    return 0


def cmd_ports(args, cfg) -> int:
    local_ip, _, _ = lan_scan.local_network_info()
    if not local_ip:
        print("ERROR: no IPv4 address on this machine.", file=sys.stderr)
        return 1
    subnet = _subnet24(local_ip)
    devices = lan_scan.arp_scan(subnet, timeout=args.timeout)
    ips = [d.ip for d in devices] if not args.include_self else \
        [d.ip for d in devices] + ([local_ip] if all(d.ip != local_ip for d in devices) else [])
    services = ports.scan_services(ips, timeout=cfg["port_scan_timeout"])
    if getattr(args, "json", False):
        import json as _json
        print(_json.dumps({ip: [{"port": o.port, "service": o.service,
                                 "banner": o.banner} for o in ops]
                           for ip, ops in services.items()}, indent=2))
    else:
        print(f"Scanning {len(ips)} host(s) on {subnet}, "
              f"{len(ports.PORTS)} ports each…")
        if not services:
            print("No curated ports open. (That's good.)")
        for ip, ops in sorted(services.items()):
            print(f"\n{ip}")
            for o in ops:
                b = f"  — {o.banner}" if o.banner else ""
                print(f"  :{o.port:<5} {o.service}{b}")
    return 0


def cmd_watch(args, cfg) -> int:
    local_ip, gateway, _ = lan_scan.local_network_info()
    if not local_ip:
        print("ERROR: no IPv4 address on this machine.", file=sys.stderr)
        return 1
    subnet = _subnet24(local_ip)
    known = lan_scan._load_known()
    do_notify = args.notify or cfg.get("notify", False)
    print(f"Watching {subnet} every {args.interval}s — new devices will be "
          f"announced. Ctrl-C to stop.")
    try:
        while True:
            devices = lan_scan.arp_scan(subnet, timeout=args.timeout)
            fresh = lan_scan.announce_new_devices(known, devices)
            known |= {d.mac for d in devices}
            for d in fresh:
                if d.is_self:
                    continue
                line = (f"★ NEW DEVICE: {d.ip:<15} {d.mac}  {d.vendor}  "
                        f"({time.strftime('%H:%M:%S')})")
                print("\a" + line)
                if do_notify:
                    notify("SentinelWiFi: new device",
                           f"{d.vendor} at {d.ip} joined your network")
                if getattr(args, "json", False):
                    import json as _json
                    print(_json.dumps({"ip": d.ip, "mac": d.mac,
                                       "vendor": d.vendor}))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_report(args, cfg) -> int:
    local_ip, gateway, _ = lan_scan.local_network_info()
    if not local_ip:
        print("ERROR: no IPv4 address on this machine.", file=sys.stderr)
        return 1
    adapter, limitations = _adapter_and_notes(args, cfg)
    current, aps, rogue, lim2 = ({}, [], [], [])
    if adapter is not None and adapter.wireless:
        current, aps, rogue, lim2 = _gather_wireless(adapter, args.window, cfg)
    limitations += lim2

    subnet = _subnet24(local_ip)
    devices = lan_scan.arp_scan(subnet, timeout=8)
    lan_scan.mark_new_devices(devices)
    services = {}
    if not args.no_ports and cfg.get("port_scan_enabled", True):
        services = ports.scan_services([d.ip for d in devices],
                                       timeout=cfg["port_scan_timeout"])
    admin_proto = lan_scan.check_gateway_admin(gateway)
    dhcp_info = audit_dhcp(gateway)
    hist = history.update(aps, devices)
    score = _build_findings(current, aps, rogue, devices, admin_proto,
                            gateway, dhcp_info, services, hist, cfg)
    _render(ReportData(current=current, aps=aps, rogue=rogue, devices=devices,
                       services=services, dhcp=dhcp_info, history=hist,
                       score=score, admin_proto=admin_proto,
                       limitations=limitations), args)
    return 0


def cmd_selftest(args, cfg) -> int:
    checks = []
    checks.append(("Python >= 3.10",
                   sys.version_info >= (3, 10), sys.version.split()[0]))
    try:
        import scapy  # noqa
        checks.append(("scapy installed", True, scapy.__version__))
    except ImportError:
        checks.append(("scapy installed", False, "pip install scapy "
                       "(needed for sniffing/ARP; fallbacks exist)"))
    try:
        import importlib.metadata
        checks.append(("rich installed (optional)", True,
                       importlib.metadata.version("rich")))
    except Exception:
        checks.append(("rich installed (optional)", False,
                       "console will be plain text"))
    import shutil
    iw = shutil.which("iw")
    checks.append(("`iw` present (Linux)", bool(iw), iw or "apt install iw"))
    adapter = pick_default_adapter(prefer=cfg.get("preferred_iface", ""))
    checks.append(("network adapter detected", adapter is not None,
                   adapter.name if adapter else "none found"))
    if adapter:
        checks.append(("wireless adapter", adapter.wireless,
                       adapter.name if adapter.wireless else
                       f"{adapter.name} is Ethernet-only (WiFi audits limited)"))
    root = (hasattr(os, "geteuid") and os.geteuid() == 0)
    checks.append(("root/Administrator", root,
                   "ok" if root else "re-run with sudo for full sniffing/ARP"))
    try:
        os.makedirs(lan_scan.DATA_DIR, exist_ok=True)
        probe = os.path.join(lan_scan.DATA_DIR, ".probe")
        with open(probe, "w"):
            pass
        os.unlink(probe)
        checks.append(("data dir writable", True, lan_scan.DATA_DIR))
    except OSError as exc:
        checks.append(("data dir writable", False, str(exc)))
    ok = True
    print("SentinelWiFi self-test")
    for name, passed, detail in checks:
        status = "PASS" if passed else "WARN/FAIL"
        if not passed:
            ok = False
        print(f"  [{status:<8}] {name}: {detail}")
    print("\nEnvironment looks good." if ok else
          "\nSome checks failed — see details above (usually fixable: "
          "pip install scapy / sudo / apt install iw).")
    return 0 if ok else 1


def _demo_data() -> ReportData:
    """Synthetic but realistic data — renders without any network access."""
    from sentinelwifi.ap_scan import AccessPoint, RogueFinding
    from sentinelwifi.dhcp import DhcpInfo
    from sentinelwifi.history import HistoryDiff
    from sentinelwifi.lan_scan import Device
    from sentinelwifi.ports import OpenPort
    from sentinelwifi.scoring import Finding

    current = {"ssid": "dlink-Home-2.4", "bssid": "C4:AD:34:12:9B:F0",
               "signal": -52, "channel": 6, "encryption": "WPA2", "band": "2.4"}
    aps = [
        AccessPoint("dlink-Home-2.4", "C4:AD:34:12:9B:F0", 6, -52, "WPA2", "2.4"),
        AccessPoint("dlink-Home-2.4", "F0:9F:C2:77:AA:01", 11, -71, "WPA2", "2.4"),
        AccessPoint("PrettyFlyForAWiFi", "8C:15:C7:3D:22:10", 6, -78, "WPA2", "2.4"),
        AccessPoint("xfinitywifi", "0A:11:22:33:44:55", 1, -83, "Open", "2.4"),
        AccessPoint("HomeNet-5G", "C4:AD:34:12:9B:F1", 44, -55, "WPA3", "5"),
    ]
    rogue = ap_scan.analyze_environment(aps, current)
    devices = [
        Device("192.168.1.1", "C4:AD:34:12:9B:F0", "D-Link", is_gateway=True),
        Device("192.168.1.2", "B8:27:EB:44:10:9A", "Raspberry Pi Foundation",
               is_self=True),
        Device("192.168.1.23", "F0:9F:C2:77:AA:01", "Espressif (ESP32/ESP8266)",
               is_new=True),
        Device("192.168.1.42", "AC:BC:32:9E:11:02", "Samsung"),
    ]
    services = {
        "192.168.1.1": [OpenPort(80, "HTTP", "HTTP/1.0 200 OK"),
                        OpenPort(7547, "TR-069 router mgmt"),
                        OpenPort(23, "Telnet (cleartext login)")],
        "192.168.1.42": [OpenPort(445, "SMB file sharing")],
    }
    dhcp = DhcpInfo(servers=["192.168.1.1"], gateway="192.168.1.1",
                    rogue=False, detail="DHCP server matches your gateway (192.168.1.1). OK.")
    hist = HistoryDiff(runs=12,
                       new_aps=[aps[1]],
                       new_devices=[devices[2]],
                       gone_devices=["DE:AD:BE:EF:00:01"])
    findings = []
    for f in (check_wifi_encryption(current["encryption"]),
              check_http_admin("http", "192.168.1.1"),
              check_ssid_leak(current["ssid"]),
              check_dhcp(dhcp),
              check_exposed_services(ports.risk_summary(services)),
              check_new_aps(hist.new_aps, current["ssid"])):
        if f:
            findings.append(f)
    etwin = next((r for r in rogue if r.kind == "evil_twin"), None)
    if etwin:
        findings.append(check_evil_twin(etwin.message))
    cong = next((r for r in rogue if r.kind == "congestion"), None)
    if cong:
        findings.append(check_congestion(cong.message, 3))
    findings.append(Finding(id="demo-new-device", severity="warning",
                            title="1 new device(s) on your network",
                            explanation="A device you have not seen before is "
                                        "connected to your WiFi.",
                            fix="Check the device list in your router's app.",
                            penalty=10))
    return ReportData(current=current, aps=aps, rogue=rogue, devices=devices,
                      services=services, dhcp=dhcp, history=hist,
                      score=compute_grade(findings), admin_proto="http",
                      limitations=["Demo mode: synthetic data, no network "
                                   "access performed."])


def cmd_demo(args, cfg) -> int:
    data = _demo_data()
    if getattr(args, "json", False):
        print(report_to_json(data))
    else:
        print(report_to_console(data))
    out = getattr(args, "html", "")
    if out:
        print(f"\nHTML report written to: {write_html_report(data, out)}")
    return 0


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    cfg = load_config()
    p = argparse.ArgumentParser(
        prog="sentinel.py",
        description="SentinelWiFi — personal network security auditor "
                    "(passive/defensive only). For auditing networks you own "
                    "or are authorized to test.")
    p.add_argument("--version", action="version",
                   version=f"SentinelWiFi {__version__}")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    p.add_argument("--iface", default="", help="force a network interface")
    p.add_argument("--html", metavar="FILE", default="",
                   help="also write an HTML report to FILE")
    sub = p.add_subparsers(dest="command", required=True)

    # Shared flags so `sentinel.py --json scan` AND `sentinel.py scan --json`
    # both work (subparser values override the top-level ones).
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--json", action="store_true",
                        help=argparse.SUPPRESS)
    parent.add_argument("--html", metavar="FILE", default=None,
                        help=argparse.SUPPRESS)
    parent.add_argument("--iface", default=None, help=argparse.SUPPRESS)

    def common(sp):
        sp.add_argument("--window", type=int,
                        default=ap_scan.SCAN_WINDOW_SECONDS,
                        help="sniffing window in seconds (default 30)")
        return sp

    common(sub.add_parser("scan", parents=[parent], help="audit your WiFi + surroundings")). \
        set_defaults(func=cmd_scan)
    dp = sub.add_parser("devices", parents=[parent], help="list devices on your subnet")
    dp.add_argument("--timeout", type=int, default=4)
    dp.add_argument("--ports", action="store_true",
                    help="also connect-scan curated ports on found devices")
    dp.set_defaults(func=cmd_devices)
    pp = sub.add_parser("ports", parents=[parent], help="exposed-service scan of your subnet")
    pp.add_argument("--timeout", type=int, default=4)
    pp.add_argument("--include-self", action="store_true",
                    help="include this machine in the scan")
    pp.set_defaults(func=cmd_ports)
    wp = sub.add_parser("watch", parents=[parent],
                        help="loop inventory, announce new devices")
    wp.add_argument("--interval", type=int,
                    default=cfg.get("watch_interval", 60))
    wp.add_argument("--timeout", type=int, default=4)
    wp.add_argument("--notify", action="store_true",
                    help="desktop notifications (or set notify=true in config)")
    wp.set_defaults(func=cmd_watch)
    rp = common(sub.add_parser("report", parents=[parent],
                               help="full combined report"))
    rp.add_argument("--timeout", type=int, default=8)
    rp.add_argument("--no-ports", action="store_true",
                    help="skip the exposed-services scan")
    rp.set_defaults(func=cmd_report)
    sub.add_parser("selftest", parents=[parent], help="verify install & environment"). \
        set_defaults(func=cmd_selftest)
    sub.add_parser("demo", parents=[parent], help="render a report from synthetic data"). \
        set_defaults(func=cmd_demo)

    args = p.parse_args(argv)
    return args.func(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
