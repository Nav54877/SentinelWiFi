#!/usr/bin/env python3
"""SentinelWiFi — CLI entry point.

For auditing networks you own or are authorized to test.

Usage:
    python sentinel.py scan      audit your WiFi + surroundings (+ grade)
    python sentinel.py devices   ARP inventory of your subnet, flag newcomers
    python sentinel.py watch     loop inventory every 60s, announce new devices
    python sentinel.py report    full combined audit report
    --json anywhere for machine-readable output.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time

from sentinelwifi import ap_scan, lan_scan
from sentinelwifi.iface import (check_monitor_capability, pick_default_adapter,
                                platform_notes, restore_managed, try_enable_monitor)
from sentinelwifi.report import report_to_console, report_to_json
from sentinelwifi.scoring import (check_congestion, check_evil_twin,
                                  check_http_admin, check_ssid_leak,
                                  check_unknown_devices, check_wifi_encryption,
                                  compute_grade)

WATCH_INTERVAL = 60


def _subnet24(local_ip: str) -> str:
    return str(ipaddress.ip_network(local_ip + "/24", strict=False))


def _adapter_and_notes():
    adapter = pick_default_adapter()
    limitations = platform_notes()
    if adapter is None:
        limitations.append("No usable network adapter found.")
        return None, limitations
    adapter = check_monitor_capability(adapter.name)
    if not adapter.wireless:
        limitations.append(f"{adapter.name} is not a WiFi adapter — wireless "
                           "audits limited to Ethernet-side checks.")
    return adapter, limitations


def _gather_wireless(adapter, window: int):
    """Returns (aps, rogue_findings, used_monitor, limitations)."""
    limitations = []
    aps, rogue = [], []
    if not adapter.wireless:
        return aps, rogue, False, limitations
    current = ap_scan.get_current_connection(adapter)
    used_monitor = False
    if adapter.mode == "monitor":
        try:
            aps = ap_scan.sniff_aps_monitor(adapter.name, window)
            used_monitor = True
        except RuntimeError as exc:
            limitations.append(str(exc))
    if not aps and not used_monitor:
        if adapter.monitor_capable:
            limitations.append(
                "Monitor mode available but not active; attempting to "
                "enable it for a passive sniffing window…")
            if try_enable_monitor(adapter.name):
                try:
                    aps = ap_scan.sniff_aps_monitor(adapter.name, window)
                    used_monitor = True
                except RuntimeError as exc:
                    limitations.append(str(exc))
                finally:
                    restore_managed(adapter.name)
            else:
                limitations.append(
                    "Could not enable monitor mode (driver/permissions). "
                    "Falling back to managed-mode scan.")
        if not aps:
            aps = ap_scan.managed_mode_scan()
            if aps:
                limitations.append(
                    "Managed-mode scan only (no monitor mode): results are "
                    "snapshots from the kernel's client scan, not a live "
                    "channel capture. Run with a monitor-capable adapter + "
                    "root for the full 30s passive window.")
    rogue = ap_scan.analyze_environment(aps, current) if aps else []
    return aps, rogue, used_monitor, limitations


def cmd_scan(args) -> int:
    adapter, limitations = _adapter_and_notes()
    if adapter is None:
        print("ERROR: no network adapter found.", file=sys.stderr)
        return 1
    current = ap_scan.get_current_connection(adapter) if adapter.wireless else {}
    aps, rogue, _, lim2 = _gather_wireless(adapter, args.window)
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
    score = compute_grade(findings)

    if args.json:
        print(report_to_json(current, aps, rogue, [], score, admin_proto, limitations))
    else:
        print(report_to_console(current, aps, rogue, [], score, admin_proto, limitations))
    return 0


def cmd_devices(args) -> int:
    local_ip, gateway, _ = lan_scan.local_network_info()
    if not local_ip:
        print("ERROR: no IPv4 address on this machine.", file=sys.stderr)
        return 1
    subnet = _subnet24(local_ip)
    devices = lan_scan.arp_scan(subnet, timeout=args.timeout)
    lan_scan.mark_new_devices(devices)
    findings = []
    new_count = len([d for d in devices if d.is_new and not d.is_self])
    f = check_unknown_devices(new_count)
    if f:
        findings.append(f)
    score = compute_grade(findings)
    admin_proto = lan_scan.check_gateway_admin(gateway)
    if args.json:
        print(report_to_json({}, [], [], devices, score, admin_proto,
                             [f"Subnet scanned: {subnet}"]))
    else:
        print(report_to_console({}, [], [], devices, score, admin_proto,
                                [f"Subnet scanned: {subnet}"]))
    return 0


def cmd_watch(args) -> int:
    local_ip, gateway, _ = lan_scan.local_network_info()
    if not local_ip:
        print("ERROR: no IPv4 address on this machine.", file=sys.stderr)
        return 1
    subnet = _subnet24(local_ip)
    known = lan_scan._load_known()
    print(f"Watching {subnet} every {args.interval}s — new devices will be "
          f"announced. Ctrl-C to stop.")
    try:
        while True:
            devices = lan_scan.arp_scan(subnet, timeout=args.timeout)
            fresh = lan_scan.announce_new_devices(known, devices)
            known |= {d.mac for d in devices}
            for d in fresh:
                if not d.is_self:
                    print(f"\a  ★ NEW DEVICE: {d.ip:<15} {d.mac}  "
                          f"{d.vendor}  ({time.strftime('%H:%M:%S')})")
            if args.json and fresh:
                import json as _json
                print(_json.dumps([{"ip": d.ip, "mac": d.mac, "vendor": d.vendor}
                                   for d in fresh]))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_report(args) -> int:
    """Full audit: wireless environment + devices, one combined report."""
    local_ip, gateway, _ = lan_scan.local_network_info()
    if not local_ip:
        print("ERROR: no IPv4 address on this machine.", file=sys.stderr)
        return 1
    adapter, limitations = _adapter_and_notes()
    current = ap_scan.get_current_connection(adapter) if adapter and adapter.wireless else {}
    aps, rogue, _, lim2 = _gather_wireless(adapter, args.window) if adapter else ([], [], False, [])
    limitations += lim2

    subnet = _subnet24(local_ip)
    devices = lan_scan.arp_scan(subnet, timeout=8)
    lan_scan.mark_new_devices(devices)
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
    new_count = len([d for d in devices if d.is_new and not d.is_self])
    f = check_unknown_devices(new_count)
    if f:
        findings.append(f)
    score = compute_grade(findings)

    if args.json:
        print(report_to_json(current, aps, rogue, devices, score, admin_proto, limitations))
    else:
        print(report_to_console(current, aps, rogue, devices, score, admin_proto, limitations))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="sentinel.py",
        description="SentinelWiFi — personal network security auditor "
                    "(passive/defensive only). For auditing networks you own "
                    "or are authorized to test.")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="audit your WiFi + surroundings")
    sp.add_argument("--window", type=int, default=ap_scan.SCAN_WINDOW_SECONDS,
                    help="sniffing window in seconds (default 30)")
    sp.set_defaults(func=cmd_scan)

    dp = sub.add_parser("devices", help="list devices on your subnet")
    dp.add_argument("--timeout", type=int, default=4)
    dp.set_defaults(func=cmd_devices)

    wp = sub.add_parser("watch", help="loop device inventory, announce new devices")
    wp.add_argument("--interval", type=int, default=WATCH_INTERVAL)
    wp.add_argument("--timeout", type=int, default=4)
    wp.set_defaults(func=cmd_watch)

    rp = sub.add_parser("report", help="full combined report")
    rp.add_argument("--window", type=int, default=ap_scan.SCAN_WINDOW_SECONDS)
    rp.set_defaults(func=cmd_report)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
