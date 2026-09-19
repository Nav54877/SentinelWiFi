"""SentinelWiFi — report rendering: rich console, JSON, HTML.

For auditing networks you own or are authorized to test.

`rich` is optional: if it is not installed we fall back to plain text so the
tool always works on a minimal system. HTML reports are written locally with
inline CSS only — no assets, no network, safe to open offline or share.
"""

from __future__ import annotations

import html as _html
import json
from dataclasses import asdict, dataclass, field

from .ap_scan import AccessPoint, RogueFinding
from .history import HistoryDiff
from .lan_scan import Device
from .ports import OpenPort
from .scoring import ScoreResult

_SEV_STYLE = {"critical": "bold red", "warning": "yellow", "info": "cyan"}


@dataclass
class ReportData:
    """Everything one report needs. Build once, render many ways."""
    current: dict = field(default_factory=dict)
    aps: list[AccessPoint] = field(default_factory=list)
    rogue: list[RogueFinding] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)
    services: dict[str, list[OpenPort]] = field(default_factory=dict)
    dhcp: object | None = None
    history: HistoryDiff | None = None
    score: ScoreResult | None = None
    admin_proto: str = "unreachable"
    limitations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def report_to_json(data: ReportData) -> str:
    payload = {
        "current_connection": data.current,
        "admin_page_protocol": data.admin_proto,
        "access_points": [asdict(a) for a in data.aps],
        "rogue_findings": [asdict(r) for r in data.rogue],
        "dhcp": asdict(data.dhcp) if data.dhcp else None,
        "devices": [asdict(d) for d in data.devices],
        "services": {ip: [asdict(o) for o in ops]
                     for ip, ops in data.services.items()},
        "history": asdict(data.history) if data.history else None,
        "score": ({"grade": data.score.grade, "score": data.score.score,
                   "findings": [asdict(f) for f in data.score.findings]}
                  if data.score else None),
        "limitations": data.limitations,
    }
    return json.dumps(payload, indent=2, default=str)


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

def report_to_console(data: ReportData) -> str:
    score = data.score
    lines: list[str] = []

    def emit(s: str = "") -> None:
        lines.append(s)

    grade = score.grade if score else "?"
    num = score.score if score else 0
    emit("═" * 64)
    emit("  SentinelWiFi — Personal Network Security Report")
    emit("  (auditing networks you own or are authorized to test)")
    emit("═" * 64)
    emit("")
    emit(f"  Overall grade: {grade}  ({num}/100)")
    emit("")

    # -- Your connection ------------------------------------------------
    emit("  ▶ YOUR CONNECTION")
    if data.current.get("ssid"):
        enc = data.current.get("encryption", "unknown")
        flag = "  ⚠ INSECURE" if enc.upper() in ("OPEN", "WEP") else ""
        emit(f"    SSID        : {data.current['ssid']}")
        emit(f"    BSSID       : {data.current.get('bssid', '?')}")
        emit(f"    Channel     : {data.current.get('channel', '?')}"
             f"  (band: {data.current.get('band') or '?'} GHz)")
        sig = data.current.get("signal", 0)
        emit(f"    Signal      : {sig} dBm" if sig else "    Signal      : ?")
        emit(f"    Encryption  : {enc}{flag}")
        if data.current.get("wps"):
            emit("    WPS         : ENABLED  ⚠ brute-forceable PIN")
        if data.current.get("pmf") == "none":
            emit("    Deauth-safe : NO (PMF/802.11w off)")
        elif data.current.get("pmf") == "capable":
            emit("    Deauth-safe : partially (PMF optional)")
        elif data.current.get("pmf") == "required":
            emit("    Deauth-safe : YES (PMF required)")
        if data.current.get("phy"):
            emit(f"    Generation  : {data.current['phy']}")
    else:
        emit("    Not connected to a WiFi network (or Ethernet-only adapter).")
    emit(f"    Router admin: {data.admin_proto.upper()}"
         + ("  ⚠ passwords sent in cleartext" if data.admin_proto == "http" else ""))
    emit("")

    # -- DHCP -----------------------------------------------------------
    if data.dhcp is not None and getattr(data.dhcp, "servers", None):
        emit("  ▶ DHCP (who gave you your network settings)")
        emit(f"    Servers: {', '.join(data.dhcp.servers)}"
             + ("   ⚠ ROGUE SERVER!" if data.dhcp.rogue else "   OK"))
        emit(f"    {data.dhcp.detail}")
        emit("")

    # -- WiFi environment ----------------------------------------------
    emit("  ▶ WI-FI ENVIRONMENT")
    if data.aps:
        emit(f"    {len(data.aps)} network(s) visible:")
        for ap in sorted(data.aps, key=lambda a: a.signal, reverse=True)[:15]:
            enc = ap.encryption.upper()
            mark = " ⚠" if enc in ("OPEN", "WEP") else ""
            if ap.wps:
                mark += " [WPS]"
            gen = f" {ap.phy}" if ap.phy else ""
            emit(f"      {ap.ssid[:28]:<28} ch {ap.channel or '?':<3} "
                 f"{ap.signal or '?':>4} dBm  {enc}{gen}{mark}")
        if len(data.aps) > 15:
            emit(f"      … and {len(data.aps) - 15} more")
    else:
        emit("    No access points detected (monitor mode unavailable?).")
    emit("")
    for r in data.rogue:
        tag = "⚠ WARNING" if r.severity == "high" else "ℹ info"
        emit(f"    [{tag}] {r.message}")
    if not data.rogue:
        emit("    No rogue-AP or congestion issues detected.")
    emit("")

    # -- Devices + services ---------------------------------------------
    emit("  ▶ DEVICES ON YOUR NETWORK")
    if data.devices:
        emit(f"    {'IP':<16} {'MAC':<18} {'VENDOR':<26} NOTES")
        for d in data.devices:
            notes = []
            if d.is_gateway:
                notes.append("GATEWAY")
            if d.is_self:
                notes.append("this machine")
            if d.is_new:
                notes.append("★ NEW — first time seen")
            if d.hostname:
                notes.append(d.hostname)
            svc = data.services.get(d.ip)
            if svc:
                risky = [o for o in svc if o.port in
                         (21, 23, 3389, 5900, 7547)]
                if risky:
                    notes.append("⚠ " + ", ".join(f":{o.port}" for o in risky))
            emit(f"    {d.ip:<16} {d.mac:<18} {d.vendor[:26]:<26} "
                 f"{'; '.join(notes)}")
        if data.services:
            emit("")
            emit("    Exposed services (scan of your own devices):")
            for ip, ops in sorted(data.services.items()):
                for o in ops:
                    b = f"  — {o.banner}" if o.banner else ""
                    emit(f"      {ip:<16} :{o.port:<5} {o.service}{b}")
    else:
        emit("    No devices found (ARP scan may need root/Administrator).")
    emit("")

    # -- History ----------------------------------------------------------
    if data.history is not None and data.history.runs > 1:
        h = data.history
        emit("  ▶ SINCE LAST RUN")
        emit(f"    Run #{h.runs}")
        if h.new_aps:
            emit(f"    + {len(h.new_aps)} new AP(s): "
                 + ", ".join(sorted({a.ssid for a in h.new_aps})[:6]))
        if h.new_devices:
            emit(f"    + {len(h.new_devices)} new device(s): "
                 + ", ".join(d.ip for d in h.new_devices[:6]))
        if h.gone_devices:
            emit(f"    − {len(h.gone_devices)} device(s) gone: "
                 + ", ".join(h.gone_devices[:6]))
        if not (h.new_aps or h.new_devices or h.gone_devices):
            emit("    No changes detected.")
        emit("")

    # -- Findings & fixes --------------------------------------------------
    emit("  ▶ FINDINGS & FIXES")
    if score and score.findings:
        for f in score.findings:
            emit(f"    [{f.severity.upper():<8}] {f.title}"
                 + ("" if f.penalty == 0 else f"  (−{f.penalty})"))
            emit(f"               Why: {f.explanation}")
            emit(f"               Fix: {f.fix}")
            emit("")
    elif score:
        emit("    Nothing to fix — your setup looks good.")
        emit("")

    # -- Limitations ---------------------------------------------------------
    if data.limitations:
        emit("  ▶ PLATFORM NOTES / LIMITATIONS")
        for note in data.limitations:
            emit(f"    - {note}")
        emit("")

    emit("  Report generated locally. No data left this machine.")
    emit("═" * 64)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
max-width:880px;margin:2rem auto;padding:0 1rem;color:#1a1a2e;background:#fafafa}
h1{font-size:1.4rem;border-bottom:3px solid #4361ee;padding-bottom:.4rem}
h2{font-size:1.05rem;color:#4361ee;margin-top:1.6rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.9rem}
td,th{border:1px solid #ddd;padding:.35rem .6rem;text-align:left}
th{background:#eef1fb}
.grade{display:inline-block;font-size:2.2rem;font-weight:800;padding:.2rem 1rem;
border-radius:.6rem;color:#fff}
.A,.B{background:#2a9d8f}.C{background:#e9c46a}.D{background:#f4a261}
.F{background:#e63946}.unknown{background:#888}
.sev{display:inline-block;padding:.05rem .5rem;border-radius:.4rem;color:#fff;
font-size:.75rem;font-weight:700}
.sev.critical{background:#e63946}.sev.warning{background:#f4a261}.sev.info{background:#457b9d}
.fix{color:#2a6f2a}.muted{color:#666;font-size:.85rem}
.warn{color:#c1121f;font-weight:700}.new{color:#b5179e;font-weight:700}
"""


def _esc(s) -> str:
    return _html.escape(str(s))


def write_html_report(data: ReportData, path: str) -> str:
    """Render ReportData to a self-contained HTML file; return the path."""
    score = data.score
    grade = score.grade if score else "?"
    out = [f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
           f"<title>SentinelWiFi Report</title><style>{_CSS}</style></head><body>",
           "<h1>SentinelWiFi — Network Security Report</h1>",
           "<p class='muted'>Auditing networks you own or are authorized to test. "
           "Generated locally; no data left this machine.</p>",
           f"<p><span class='grade {grade}'>{grade}</span> "
           f"<b>{score.score if score else '?'}/100</b></p>"]

    if data.current.get("ssid"):
        c = data.current
        flag = (" <span class='warn'>INSECURE</span>"
                if c.get("encryption", "").upper() in ("OPEN", "WEP") else "")
        out.append("<h2>Your connection</h2><table>"
                   f"<tr><th>SSID</th><td>{_esc(c.get('ssid',''))}</td></tr>"
                   f"<tr><th>BSSID</th><td>{_esc(c.get('bssid','?'))}</td></tr>"
                   f"<tr><th>Channel</th><td>{_esc(c.get('channel','?'))} "
                   f"({_esc(c.get('band','?'))} GHz)</td></tr>"
                   f"<tr><th>Signal</th><td>{_esc(c.get('signal','?'))} dBm</td></tr>"
                   f"<tr><th>Encryption</th><td>{_esc(c.get('encryption','?'))}{flag}</td></tr>"
                   f"<tr><th>Router admin</th><td>{_esc(data.admin_proto.upper())}"
                   + (" <span class='warn'>cleartext passwords</span>"
                      if data.admin_proto == "http" else "") +
                   "</td></tr></table>")

    if data.dhcp is not None and getattr(data.dhcp, "servers", None):
        rogue = " <span class='warn'>ROGUE SERVER</span>" if data.dhcp.rogue else ""
        out.append(f"<h2>DHCP</h2><p>Servers: {_esc(', '.join(data.dhcp.servers))}{rogue}<br>"
                   f"<span class='muted'>{_esc(data.dhcp.detail)}</span></p>")

    if data.aps:
        rows = "".join(
            f"<tr><td>{_esc(a.ssid)}</td><td>{_esc(a.bssid)}</td>"
            f"<td>{a.channel or '?'}</td><td>{a.signal or '?'}</td>"
            f"<td>{_esc(a.encryption.upper())}</td></tr>"
            for a in sorted(data.aps, key=lambda x: x.signal, reverse=True))
        out.append("<h2>Wi-Fi environment</h2>"
                   f"<table><tr><th>SSID</th><th>BSSID</th><th>Ch</th>"
                   f"<th>dBm</th><th>Encryption</th></tr>{rows}</table>")
    for r in data.rogue:
        cls = "warn" if r.severity == "high" else "muted"
        out.append(f"<p class='{cls}'>⚠ {_esc(r.message)}</p>")

    if data.devices:
        rows = []
        for d in data.devices:
            notes = []
            if d.is_gateway:
                notes.append("GATEWAY")
            if d.is_self:
                notes.append("this machine")
            if d.is_new:
                notes.append("<span class='new'>★ NEW</span>")
            rows.append(f"<tr><td>{_esc(d.ip)}</td><td>{_esc(d.mac)}</td>"
                        f"<td>{_esc(d.vendor)}</td><td>{' '.join(notes)}</td></tr>")
        out.append("<h2>Devices on your network</h2>"
                   f"<table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Notes</th>"
                   f"</tr>{''.join(rows)}</table>")
    if data.services:
        rows = "".join(
            f"<tr><td>{_esc(ip)}</td><td>:{o.port}</td>"
            f"<td>{_esc(o.service)}</td><td class='muted'>{_esc(o.banner)}</td></tr>"
            for ip, ops in sorted(data.services.items()) for o in ops)
        out.append("<h2>Exposed services (your devices)</h2>"
                   f"<table><tr><th>IP</th><th>Port</th><th>Service</th>"
                   f"<th>Banner</th></tr>{rows}</table>")

    if score and score.findings:
        items = []
        for f in score.findings:
            items.append(
                f"<p><span class='sev {_esc(f.severity)}'>{_esc(f.severity.upper())}</span> "
                f"<b>{_esc(f.title)}</b>"
                + (f" <span class='muted'>(−{f.penalty})</span>" if f.penalty else "")
                + f"<br>{_esc(f.explanation)}<br>"
                f"<span class='fix'><b>Fix:</b> {_esc(f.fix)}</span></p>")
        out.append("<h2>Findings &amp; fixes</h2>" + "".join(items))

    if data.limitations:
        out.append("<h2>Platform notes</h2><ul>"
                   + "".join(f"<li>{_esc(n)}</li>" for n in data.limitations)
                   + "</ul>")
    out.append("</body></html>")
    with open(path, "w") as fh:
        fh.write("\n".join(out))
    return path
