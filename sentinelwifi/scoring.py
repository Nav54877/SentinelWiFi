"""SentinelWiFi — transparent A-F grading rules.

For auditing networks you own or are authorized to test.

The grade is computed by starting at 100 and subtracting weighted penalties.
Every rule is listed here explicitly so the score is explainable — there is
no hidden ML or magic. Each penalty produces a human-readable finding with
a one-line explanation and a concrete fix.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    id: str
    severity: str          # "critical" | "warning" | "info"
    title: str
    explanation: str       # plain language, non-technical
    fix: str               # concrete action
    penalty: int           # points deducted from 100


@dataclass
class ScoreResult:
    grade: str             # A-F
    score: int
    findings: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Individual checks (each returns a Finding or None)
# ---------------------------------------------------------------------------

def check_wifi_encryption(encryption: str) -> Finding | None:
    enc = (encryption or "").upper()
    if enc in ("OPEN", ""):
        return Finding(
            id="wifi-open",
            severity="critical",
            title="Your WiFi has no password",
            explanation=("Anyone within range can join your network and see "
                         "everything you do on it, and their traffic looks "
                         "like it comes from you."),
            fix="Set WPA2 or WPA3 security with a strong password in your "
                "router settings.",
            penalty=45)
    if enc == "WEP":
        return Finding(
            id="wifi-wep",
            severity="critical",
            title="Your WiFi uses WEP — broken since 2007",
            explanation=("WEP passwords can be recovered in minutes with free "
                         "tools. It is not security, only an illusion of it."),
            fix="Switch to WPA2 (or WPA3) in your router settings immediately.",
            penalty=45)
    if "WPA2" in enc:
        return Finding(
            id="wifi-wpa2",
            severity="info",
            title="WiFi uses WPA2",
            explanation=("WPA2 is solid, but WPA3 is stronger against "
                         "password-guessing attacks."),
            fix="If your router supports it, upgrade to WPA3.",
            penalty=5)
    return None  # WPA3 — no penalty


def check_http_admin(admin_proto: str, gateway: str) -> Finding | None:
    if admin_proto == "http":
        return Finding(
            id="admin-http",
            severity="warning",
            title="Router admin page uses HTTP (not HTTPS)",
            explanation=("When you log into your router at http://" +
                         (gateway or "its IP") + ", your admin password "
                         "travels in plain text — anyone on your WiFi who is "
                         "listening can read it."),
            fix="If the router offers HTTPS admin access, enable it; "
                "otherwise avoid managing the router from untrusted devices "
                "on the network.",
            penalty=15)
    if admin_proto == "unreachable":
        return Finding(
            id="admin-unreachable",
            severity="info",
            title="Router admin page not detected",
            explanation=("We could not confirm how the router's admin page "
                         "answers. It may use a non-standard port."),
            fix="No action needed; check your router manual if unsure.",
            penalty=0)
    return None


def check_ssid_leak(ssid: str) -> Finding | None:
    """SSID names often reveal the router brand/model, which tells an
    attacker exactly which default-password list to try."""
    if not ssid:
        return None
    weak_hints = ("dlink", "linksys", "netgear", "tplink", "tp-link", "admin",
                  "default", "asus", "vodafone", "verizon", "att", "bt-", "sky",
                  "virgin", "fritz", "sagem", "technicolor", "zyxel", "tenda",
                  "huawei", "xfinity", "spectrum")
    low = ssid.lower()
    hit = next((h for h in weak_hints if h in low), None)
    if hit:
        return Finding(
            id="ssid-leak",
            severity="warning",
            title="Network name reveals your router model",
            explanation=(f"'{ssid}' hints at the router brand/model. Attackers "
                         "use that to look up known default passwords and "
                         "known weaknesses for that exact device."),
            fix="Rename your network to something neutral in the router "
                "settings (no brand, no family name, no address).",
            penalty=10)
    return None


def check_unknown_devices(new_devices: int) -> Finding | None:
    if new_devices <= 0:
        return None
    return Finding(
        id="unknown-devices",
        severity="warning" if new_devices < 3 else "critical",
        title=f"{new_devices} new device(s) on your network",
        explanation=("A device you have not seen before is connected to your "
                     "WiFi. If you don't recognize it, someone may be using "
                     "your network without permission."),
        fix="Check the device list in your router's app; if unrecognized, "
            "change the WiFi password — every device will need to re-join.",
        penalty=10 if new_devices < 3 else 25)


def check_congestion(finding_msg: str | None, ap_count_on_channel: int) -> Finding | None:
    if finding_msg is None:
        return None
    sev = "warning" if "Total co-channel" in finding_msg else "info"
    return Finding(
        id="congestion",
        severity="warning" if ap_count_on_channel >= 6 else "info",
        title="WiFi channel is crowded",
        explanation=("Many neighbouring networks share your WiFi channel (or "
                     "overlapping ones), which slows your connection and can "
                     "cause dropouts."),
        fix="In the router settings, try channels 1, 6 or 11 (2.4GHz) or let "
            "the router pick automatically.",
        penalty=5)


def check_evil_twin(rogue_msg: str | None) -> Finding | None:
    if rogue_msg is None:
        return None
    return Finding(
        id="evil-twin",
        severity="critical",
        title="Possible fake WiFi network (evil twin)",
        explanation=rogue_msg,
        fix="Before entering any password, check your device's saved network "
            "details and compare the router's MAC (BSSID) with the sticker "
            "on the physical router. When in doubt, use mobile data.",
        penalty=20)


# ---------------------------------------------------------------------------
# Grade computation
# ---------------------------------------------------------------------------

def compute_grade(findings: list[Finding]) -> ScoreResult:
    """Start at 100, subtract penalties, map to A-F.

    Grade bands: A >= 90, B >= 75, C >= 60, D >= 40, F < 40.
    """
    score = 100
    for f in findings:
        score -= f.penalty
    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return ScoreResult(grade=grade, score=score,
                       findings=sorted(findings,
                                       key=lambda f: {"critical": 0, "warning": 1, "info": 2}[f.severity]))


# ---------------------------------------------------------------------------
# v2 checks: DHCP, exposed services, new APs
# ---------------------------------------------------------------------------

def check_dhcp(dhcp_info) -> "Finding | None":
    """Rogue-DHCP: a server other than the gateway handed out network config."""
    if dhcp_info is None or not getattr(dhcp_info, "servers", None):
        return None
    if not dhcp_info.rogue:
        return Finding(
            id="dhcp-ok", severity="info", title="DHCP server looks normal",
            explanation=dhcp_info.detail, fix="No action needed.", penalty=0)
    return Finding(
        id="dhcp-rogue", severity="critical",
        title="Unknown DHCP server on your network",
        explanation=dhcp_info.detail,
        fix="Disconnect and check what device is plugged into your router; "
            "reboot the router, then re-run this scan. If it persists, "
            "someone may be on your network — change the WiFi password.",
        penalty=20)


def check_exposed_services(risk_notes: list[str]) -> "Finding | None":
    """Devices exposing dangerous services to anyone on the LAN."""
    if not risk_notes:
        return None
    top = "; ".join(risk_notes[:4])
    extra = f" (and {len(risk_notes) - 4} more)" if len(risk_notes) > 4 else ""
    return Finding(
        id="exposed-services", severity="warning",
        title=f"{len(risk_notes)} risky service(s) exposed on your devices",
        explanation=("Some of your devices offer services like Telnet, FTP or "
                     "remote desktop to anyone connected to your WiFi. On an "
                     "open or compromised network these are easy entry points: "
                     f"{top}{extra}."),
        fix="Disable unused services in each device's settings (router: turn "
            "off Telnet/TR-069/remote admin; PCs: disable SMBv1, close RDP "
            "unless you use it). Re-scan to confirm.",
        penalty=10)


def check_new_aps(new_aps: list, current_ssid: str) -> "Finding | None":
    """APs visible now that weren't visible last run (from local history)."""
    if not new_aps:
        return None
    names = ", ".join(sorted({a.ssid for a in new_aps})[:5])
    near_yours = any(a.ssid == current_ssid for a in new_aps)
    sev = "warning" if near_yours else "info"
    return Finding(
        id="new-aps", severity=sev,
        title=f"{len(new_aps)} new access point(s) visible since last scan",
        explanation=(f"These networks appeared near you since the last run: "
                     f"{names}. A new network copying your own SSID can be an "
                     "evil twin." if near_yours else
                     f"These networks appeared near you since the last run: "
                     f"{names}. Usually just neighbours, but worth a glance."),
        fix="If one copies your network's name, verify the BSSID against your "
            "router's sticker before joining anything.",
        penalty=10 if near_yours else 3)


def check_wps(wps_enabled: bool) -> "Finding | None":
    """WPS (WiFi Protected Setup) is a known weak point: the PIN mechanism
    can be brute-forced regardless of password strength."""
    if not wps_enabled:
        return None
    return Finding(
        id="wps-enabled", severity="warning", title="WPS is enabled",
        explanation=("WiFi Protected Setup makes connecting easier, but its "
                     "8-digit PIN can be brute-forced even if your WiFi "
                     "password is strong — and then the password is revealed "
                     "anyway."),
        fix="Disable WPS in the router settings (look under WiFi Advanced). "
            "Everything that uses WPS also works with the normal password.",
        penalty=10)


def check_pmf(pmf: str) -> "Finding | None":
    """PMF (802.11w / management frame protection): without it, an attacker
    on your network can kick devices off WiFi at will (a forced-disconnect attack). Detected
    from the RSN capabilities flag — no attack is ever performed."""
    if pmf == "none":
        return Finding(
            id="pmf-none", severity="info",
            title="Management frame protection is off",
            explanation=("Your network does not protect management frames, so "
                         "a device on your WiFi could force other devices to "
                         "disconnect at will (a 'forced-disconnect attack'). It cannot "
                         "steal passwords by itself, but it's a common first "
                         "step for evil-twin tricks."),
            fix="If your router supports 'PMF' or '802.11w', set it to "
                "required or capable. Most modern WPA3-capable routers have it.",
            penalty=5)
    if pmf == "capable":
        return Finding(
            id="pmf-capable", severity="info",
            title="Management frame protection is optional",
            explanation=("Your router supports PMF (802.11w) but doesn't "
                         "require it, so clients can still skip it."),
            fix="Set PMF to 'required' in the router settings if all your "
                "devices connect fine afterwards.",
            penalty=0)
    return None
