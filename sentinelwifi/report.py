"""SentinelWiFi — console report (rich) and machine-readable JSON output.

For auditing networks you own or are authorized to test.

`rich` is optional: if it is not installed we fall back to plain ANSI-free
text so the tool always works on a minimal system.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .ap_scan import AccessPoint, RogueFinding
from .lan_scan import Device
from .scoring import ScoreResult

_SEVERITY_STYLE = {"critical": "bold red", "warning": "yellow", "info": "cyan"}


def report_to_json(current: dict, aps: list[AccessPoint],
                   rogue_findings: list[RogueFinding],
                   devices: list[Device],
                   score: ScoreResult,
                   admin_proto: str,
                   limitations: list[str]) -> str:
    """Machine-readable report (used by --json)."""
    payload = {
        "current_connection": current,
        "admin_page_protocol": admin_proto,
        "access_points": [asdict(a) for a in aps],
        "rogue_findings": [asdict(r) for r in rogue_findings],
        "devices": [asdict(d) for d in devices],
        "score": {
            "grade": score.grade,
            "score": score.score,
            "findings": [asdict(f) for f in score.findings],
        },
        "limitations": limitations,
    }
    return json.dumps(payload, indent=2, default=str)


def report_to_console(current: dict, aps: list[AccessPoint],
                      rogue_findings: list[RogueFinding],
                      devices: list[Device],
                      score: ScoreResult,
                      admin_proto: str,
                      limitations: list[str]) -> str:
    """Return the full report as a string (rich-rendered if available)."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        rich_ok = True
    except ImportError:
        rich_ok = False

    lines: list[str] = []

    def emit(s: str = "") -> None:
        lines.append(s)

    # ---- Header ----
    grade_color = {"A": "green", "B": "green", "C": "yellow",
                   "D": "red", "F": "bold red"}.get(score.grade, "white")
    emit("═" * 64)
    emit("  SentinelWiFi — Personal Network Security Report")
    emit("  (auditing networks you own or are authorized to test)")
    emit("═" * 64)

    # ---- Score card ----
    emit("")
    if rich_ok:
        emit(f"  Overall grade: [{grade_color}]{score.grade}[/{grade_color}]"
             f"  ({score.score}/100)")
    else:
        emit(f"  Overall grade: {score.grade}  ({score.score}/100)")
    emit("")

    # ---- Current connection ----
    emit("  ▶ YOUR CONNECTION")
    if current.get("ssid"):
        enc = current.get("encryption", "unknown")
        enc_flag = ""
        if enc.upper() in ("OPEN", "WEP"):
            enc_flag = "  ⚠ INSECURE"
        emit(f"    SSID        : {current['ssid']}")
        emit(f"    BSSID       : {current.get('bssid', '?')}")
        emit(f"    Channel     : {current.get('channel', '?')}"
             f"  (band: {current.get('band') or '?'} GHz)")
        sig = current.get("signal", 0)
        emit(f"    Signal      : {sig} dBm" if sig else "    Signal      : ?")
        emit(f"    Encryption  : {enc}{enc_flag}")
    else:
        emit("    Not connected to a WiFi network (or adapter is Ethernet-only).")
    emit(f"    Router admin: {admin_proto.upper()}"
         + ("  ⚠ passwords sent in cleartext" if admin_proto == "http" else ""))
    emit("")

    # ---- AP environment ----
    emit("  ▶ WI-FI ENVIRONMENT")
    if aps:
        emit(f"    {len(aps)} network(s) visible:")
        for ap in sorted(aps, key=lambda a: a.signal, reverse=True)[:15]:
            enc = ap.encryption.upper()
            mark = " ⚠" if enc in ("OPEN", "WEP") else ""
            emit(f"      {ap.ssid[:28]:<28} ch {ap.channel or '?':<3} "
                 f"{ap.signal or '?':>4} dBm  {enc}{mark}")
        if len(aps) > 15:
            emit(f"      … and {len(aps) - 15} more")
    else:
        emit("    No access points detected (monitor mode unavailable?).")
    emit("")

    for r in rogue_findings:
        tag = "⚠ WARNING" if r.severity == "high" else "ℹ info"
        emit(f"    [{tag}] {r.message}")
    if not rogue_findings:
        emit("    No rogue-AP or congestion issues detected.")
    emit("")

    # ---- Devices ----
    emit("  ▶ DEVICES ON YOUR NETWORK")
    if devices:
        emit(f"    {'IP':<16} {'MAC':<18} {'VENDOR':<26} NOTES")
        for d in devices:
            notes = []
            if d.is_gateway:
                notes.append("GATEWAY")
            if d.is_self:
                notes.append("this machine")
            if d.is_new:
                notes.append("★ NEW — first time seen")
            if d.hostname:
                notes.append(d.hostname)
            emit(f"    {d.ip:<16} {d.mac:<18} {d.vendor[:26]:<26} "
                 f"{'; '.join(notes)}")
    else:
        emit("    No devices found (ARP scan may need root/Administrator).")
    emit("")

    # ---- Findings & fixes ----
    emit("  ▶ FINDINGS & FIXES")
    if score.findings:
        for f in score.findings:
            sev = f.severity.upper()
            emit(f"    [{sev:<8}] {f.title}")
            emit(f"               Why it matters: {f.explanation}")
            emit(f"               Fix: {f.fix}")
            emit("")
    else:
        emit("    Nothing to fix — your setup looks good.")
        emit("")

    # ---- Limitations ----
    if limitations:
        emit("  ▶ PLATFORM NOTES / LIMITATIONS")
        for note in limitations:
            emit(f"    - {note}")
        emit("")

    emit("  Report generated locally. No data left this machine.")
    emit("═" * 64)
    return "\n".join(lines)
