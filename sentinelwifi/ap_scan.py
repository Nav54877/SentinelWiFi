"""SentinelWiFi — passive AP environment scanning + rogue/evil-twin detection.

For auditing networks you own or are authorized to test.

Strictly passive: with monitor mode we use scapy's sniff() to receive beacon
frames only (no frames are ever sent). Without monitor mode we degrade to a
managed-mode scan (kernel-driven, standard `nmcli`/`iw` results). We never
transmit frames and never attempt to associate with anything.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

from .iface import AdapterInfo

SCAN_WINDOW_SECONDS = 30


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    channel: int = 0
    signal: int = 0          # dBm, negative
    encryption: str = "unknown"   # WPA3 / WPA2 / WEP / Open
    band: str = ""           # "2.4" / "5" / ""
    wps: bool = False        # WiFi Protected Setup enabled (weak point)
    pmf: str = ""            # "required" | "capable" | "none" | "" (802.11w)
    phy: str = ""            # "WiFi 4" | "WiFi 5" | "WiFi 6" | "WiFi 7" | ""


@dataclass
class RogueFinding:
    kind: str                # "evil_twin" | "unexpected_channel" | "congestion"
    severity: str            # "high" | "info"
    message: str


# ---------------------------------------------------------------------------
# Current connection details
# ---------------------------------------------------------------------------

def get_current_connection(adapter: AdapterInfo) -> dict:
    """Best-effort details of the network this machine is joined to."""
    info: dict = {"ssid": "", "bssid": "", "signal": 0, "channel": 0,
                  "encryption": "unknown", "band": ""}
    if not adapter.wireless:
        return info

    # Windows: netsh gives everything we need
    import sys as _sys
    if _sys.platform.startswith("win") and shutil.which("netsh"):
        try:
            out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                 capture_output=True, text=True, timeout=15)
            for line in out.stdout.splitlines():
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key, val = parts[0].strip(), parts[1].strip()
                if key == "SSID" and val:
                    info["ssid"] = val
                elif key == "BSSID":
                    info["bssid"] = val.upper()
                elif key == "Signal":
                    pct = int(val.rstrip(" %"))
                    info["signal"] = min(-30, -30 - (100 - pct) // 2)
                elif key == "Channel":
                    info["channel"] = int(val.split()[0])
                    info["band"] = _band_for_channel(info["channel"])
                elif key == "Authentication":
                    info["encryption"] = _normalize_security(val)
            if info["ssid"]:
                return info
        except Exception:
            pass

    # Try nmcli first (distro-agnostic-ish, very reliable output)
    if shutil.which("nmcli"):
        try:
            out = subprocess.run(
                ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SIGNAL,SECURITY,CHAN_BW",
                 "dev", "wifi", "list"],
                capture_output=True, text=True, timeout=15)
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    if not line.startswith("yes:"):
                        continue
                    parts = line.split(":")
                    # ACTIVE:SSID:BSSID:CHAN:SIGNAL:SECURITY (SSID may contain ':')
                    rest = line[len("yes:"):]
                    # SSID is everything before the last 4 colon fields
                    m = re.match(r"(?P<ssid>.*):(?P<bssid>[0-9A-Fa-f:]{17}):(?P<chan>\d+):(?P<sig>\d+):(?P<sec>.*)$", rest)
                    if m:
                        info["ssid"] = m.group("ssid")
                        info["bssid"] = m.group("bssid").upper()
                        info["channel"] = int(m.group("chan"))
                        # nmcli SIGNAL is 0-100 percentage; convert roughly to dBm
                        pct = int(m.group("sig"))
                        info["signal"] = min(-30, -30 - (100 - pct) // 2)
                        info["encryption"] = _normalize_security(m.group("sec"))
                        info["band"] = _band_for_channel(info["channel"])
                        return info
        except Exception:
            pass

    # Fallback: iw dev <if> link (SSID/BSSID/signal/freq)
    if shutil.which("iw"):
        try:
            out = subprocess.run(["iw", "dev", adapter.name, "link"],
                                 capture_output=True, text=True, timeout=10)
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("SSID:"):
                    info["ssid"] = line.split(":", 1)[1].strip()
                elif line.startswith("Connected to"):
                    info["bssid"] = line.split()[2].upper()
                elif line.startswith("signal:"):
                    info["signal"] = int(float(line.split()[1]))
                elif line.startswith("freq:"):
                    info["channel"] = _FREQ_TO_CHAN.get(int(float(line[5:].strip())), 0)
                    info["band"] = _band_for_channel(info["channel"])
        except Exception:
            pass

    # Channel from interface info if still missing
    if not info["channel"] and shutil.which("iw"):
        try:
            out = subprocess.run(["iw", "dev", adapter.name, "info"],
                                 capture_output=True, text=True, timeout=5)
            for line in out.stdout.splitlines():
                if "channel" in line:
                    info["channel"] = int(line.split("channel")[1].split()[0])
                    info["band"] = _band_for_channel(info["channel"])
                    break
        except Exception:
            pass

    # Encryption + channel via a one-off `iw scan` matched to our BSSID
    if info["encryption"] == "unknown" and info.get("bssid") and shutil.which("iw"):
        try:
            out = subprocess.run(["iw", "dev", adapter.name, "scan"],
                                 capture_output=True, text=True, timeout=25)
            for ap in _parse_iw_scan(out.stdout):
                if ap.bssid == info["bssid"]:
                    info["encryption"] = ap.encryption
                    if not info["channel"] and ap.channel:
                        info["channel"] = ap.channel
                        info["band"] = ap.band
                    info["wps"] = ap.wps
                    info["pmf"] = ap.pmf
                    info["phy"] = ap.phy
                    break
        except Exception:
            pass
    return info


_FREQ_TO_CHAN: dict[int, int] = {
    2412: 1, 2417: 2, 2422: 3, 2427: 4, 2432: 5, 2437: 6, 2442: 7,
    2447: 8, 2452: 9, 2457: 10, 2462: 11, 2467: 12, 2472: 13, 2484: 14,
    5180: 36, 5200: 40, 5220: 44, 5240: 48, 5260: 52, 5300: 56, 5320: 60,
    5500: 100, 5520: 104, 5540: 108, 5560: 112, 5580: 116, 5600: 120,
    5620: 124, 5640: 128, 5660: 132, 5680: 136, 5700: 140, 5720: 144,
    5745: 149, 5765: 153, 5785: 157, 5805: 161, 5825: 165,
}


def _parse_iw_scan(text: str) -> list[AccessPoint]:
    """Parse `iw dev <if> scan` output into AccessPoints (stdlib only)."""
    aps: list[dict] = []
    cur: dict | None = None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"BSS ([0-9A-Fa-f:]{17})", s)
        if m:
            if cur:
                aps.append(cur)
            # NB: "BSS Load:"/"BSS Color:" IE lines must NOT start a block
            cur = {"bssid": m.group(1), "ssid": "", "freq": 0, "signal": 0,
                   "privacy": False, "rsn": False, "wpa": False, "sae": False,
                   "wps": False, "ht": False, "vht": False, "he": False,
                   "eht": False, "rsncap": None}
        elif cur is None:
            continue
        elif s.startswith("SSID:"):
            cur["ssid"] = s[5:].strip()
        elif s.startswith("freq:"):
            try:
                cur["freq"] = int(float(s[5:].strip()))
            except ValueError:
                pass
        elif s.startswith("signal:"):
            try:
                cur["signal"] = int(float(s[7:].strip().split()[0]))
            except ValueError:
                pass
        elif s.startswith("capability:"):
            cur["privacy"] = "Privacy" in s
        elif s.startswith("RSN:"):
            cur["rsn"] = True
        elif s.startswith("WPS:"):
            cur["wps"] = True
        elif s.startswith("* Capability:"):
            try:
                cur["rsncap"] = int(s.split(":", 1)[1].strip(), 16)
            except ValueError:
                pass
        elif s.startswith("EHT capabilities") or s.startswith("EHT operation") \
                or s.startswith("EHT Operation"):
            cur["eht"] = True
        elif s.startswith("HE capabilities") or s.startswith("HE operation") \
                or s.startswith("HE Operation"):
            cur["he"] = True
        elif s.startswith("VHT capabilities") or s.startswith("VHT operation") \
                or s.startswith("VHT Operation"):
            cur["vht"] = True
        elif s.startswith("HT capabilities") or s.startswith("HT operation") \
                or s.startswith("HT Operation"):
            cur["ht"] = True
        elif s.startswith("WPA:"):
            cur["wpa"] = True
        elif "00-0f-ac-8" in s.lower() or "SAE" in s:
            cur["sae"] = True
    if cur:
        aps.append(cur)
    out: list[AccessPoint] = []
    for c in aps:
        if c["rsn"]:
            enc = "WPA3" if c["sae"] else "WPA2"
        elif c["wpa"]:
            enc = "WPA2"
        elif c["privacy"]:
            enc = "WEP"
        else:
            enc = "Open"
        chan = _FREQ_TO_CHAN.get(c["freq"], 0)
        if c["eht"]:
            phy = "WiFi 7"
        elif c["he"]:
            phy = "WiFi 6"
        elif c["vht"]:
            phy = "WiFi 5"
        elif c["ht"]:
            phy = "WiFi 4"
        else:
            phy = ""
        pmf = ""
        if c["rsncap"] is not None:
            pmf = ("required" if c["rsncap"] & 0x0040
                   else "capable" if c["rsncap"] & 0x0080 else "none")
        out.append(AccessPoint(ssid=c["ssid"] or "(hidden)",
                               bssid=c["bssid"].upper(), channel=chan,
                               signal=c["signal"], encryption=enc,
                               band=_band_for_channel(chan),
                               wps=c["wps"], pmf=pmf, phy=phy))
    return out


def _normalize_security(sec: str) -> str:
    s = sec.strip().lower()
    if not s or s in ("--", ""):
        return "Open"
    if "wpa3" in s:
        return "WPA3"
    if "wpa2" in s or "wpa1" in s or "wpa" in s:
        return "WPA2"
    if "wep" in s:
        return "WEP"
    return sec.strip()


def _band_for_channel(chan: int) -> str:
    if 1 <= chan <= 14:
        return "2.4"
    if 32 <= chan <= 177:
        return "5"
    return ""


# ---------------------------------------------------------------------------
# AP environment scanning (passive)
# ---------------------------------------------------------------------------

def sniff_aps_monitor(ifname: str, seconds: int = SCAN_WINDOW_SECONDS) -> list[AccessPoint]:
    """Passive beacon sniffing with scapy in monitor mode.

    We only RECEIVE. Returns list of unique APs seen in the window.
    Raises RuntimeError if scapy is unavailable so the caller can degrade.
    """
    try:
        from scapy.all import sniff, Dot11Beacon, Dot11Elt, RadioTap  # noqa: F401
        from scapy.layers.dot11 import Dot11
    except ImportError as exc:
        raise RuntimeError(
            "scapy is not importable. If you installed it with "
            "`pip install --user`, either run SentinelWiFi WITHOUT sudo or "
            "install system-wide (`sudo pip install scapy`).") from exc

    aps: dict[str, AccessPoint] = {}

    def _handle(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None or dot11.addr3 in (None, "ff:ff:ff:ff:ff:ff"):
            return
        bssid = str(dot11.addr3).upper()
        ssid = ""
        channel = 0
        encryption = "Open"
        wps = False
        rsncap = None
        phy_bits = {"ht": False, "vht": False, "he": False}
        if pkt.haslayer(Dot11Elt):
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace")
                    except Exception:
                        ssid = ""
                elif elt.ID == 3 and elt.len >= 1:
                    channel = int(elt.info[0])
                elif elt.ID == 48:      # RSN element
                    encryption = "WPA3" if b"WPA3" in bytes(elt.info) or b"\x00\x0f\xac\x08" in bytes(elt.info) else "WPA2"
                elif elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x01"):
                    if encryption == "Open":
                        encryption = "WPA2"
                elif elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x02"):
                    if encryption == "Open":
                        encryption = "WEP"
                elif elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x04"):
                    wps = True  # WiFi Protected Setup IE
                elif elt.ID == 45:      # HT capabilities -> WiFi 4
                    phy_bits["ht"] = True
                elif elt.ID == 192:     # VHT capabilities -> WiFi 5
                    phy_bits["vht"] = True
                elif elt.ID == 255 and elt.info[:1] == b"#":  # ext 35 HE -> WiFi 6
                    phy_bits["he"] = True
                elif elt.ID == 48:
                    rsncap = int.from_bytes(bytes(elt.info)[-2:], "little")
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload.haslayer(Dot11Elt) else None
        # Privacy bit in capability field => at least WEP-era encryption
        cap = pkt[Dot11Beacon].cap
        if not (cap & 0x0010) and encryption == "unknown":
            encryption = "Open"
        if (cap & 0x0010) and encryption == "Open":
            encryption = "WEP"  # privacy bit set but no WPA/RSN IEs
        signal = int(pkt.dBm_AntNoise) if hasattr(pkt, "dBm_AntNoise") else 0
        pmf = ""
        if rsncap is not None:
            pmf = ("required" if rsncap & 0x0040
                   else "capable" if rsncap & 0x0080 else "none")
        phy = ("WiFi 6" if phy_bits["he"] else "WiFi 5" if phy_bits["vht"]
               else "WiFi 4" if phy_bits["ht"] else "")
        aps[bssid] = AccessPoint(
            ssid=ssid or "(hidden)",
            bssid=bssid,
            channel=channel,
            signal=signal,
            encryption=encryption,
            band=_band_for_channel(channel),
            wps=wps, pmf=pmf, phy=phy,
        )

    sniff(iface=ifname, timeout=seconds, prn=_handle, store=False)
    return list(aps.values())


def managed_mode_scan(iface: str = "") -> list[AccessPoint]:
    """Managed-mode fallback scan (no monitor mode needed).

    Prefers nmcli; falls back to `iw dev <if> scan` when nmcli is absent
    (minimal systems, servers). Both are standard client scans — we listen
    to what APs broadcast and send nothing ourselves.
    """
    aps: list[AccessPoint] = []
    if shutil.which("nmcli"):
        try:
            out = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev",
                 "wifi", "list", "--rescan", "yes"],
                capture_output=True, text=True, timeout=30)
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    m = re.match(
                        r"(?P<ssid>.*):(?P<bssid>[0-9A-Fa-f:]{17}):(?P<chan>\d+):(?P<sig>\d+):(?P<sec>.*)$",
                        line)
                    if not m:
                        continue
                    chan = int(m.group("chan"))
                    pct = int(m.group("sig"))
                    aps.append(AccessPoint(
                        ssid=m.group("ssid") or "(hidden)",
                        bssid=m.group("bssid").upper(),
                        channel=chan,
                        signal=min(-30, -30 - (100 - pct) // 2),
                        encryption=_normalize_security(m.group("sec")),
                        band=_band_for_channel(chan),
                    ))
                if aps:
                    return aps
        except Exception:
            pass
    if not aps and iface and shutil.which("iw"):
        try:
            out = subprocess.run(["iw", "dev", iface, "scan"],
                                 capture_output=True, text=True, timeout=25)
            if out.returncode == 0:
                return _parse_iw_scan(out.stdout)
        except Exception:
            pass
    return aps


# ---------------------------------------------------------------------------
# Analysis: rogue detection + congestion
# ---------------------------------------------------------------------------

def _channel_overlap_24(chan: int) -> list[int]:
    """Channels that overlap a 2.4GHz channel (±4, in 1-13)."""
    return [c for c in range(max(1, chan - 4), min(13, chan + 4) + 1) if c != chan]


def analyze_environment(aps: list[AccessPoint], current: dict,
                        trusted: frozenset | None = None) -> list[RogueFinding]:
    """Evil-twin, unexpected-channel and congestion findings."""
    findings: list[RogueFinding] = []

    by_ssid: dict[str, list[AccessPoint]] = {}
    for ap in aps:
        by_ssid.setdefault(ap.ssid, []).append(ap)

    my_ssid = current.get("ssid", "")
    trusted = trusted or frozenset()

    # Evil twin: same SSID, 2+ distinct BSSIDs (minus ones you told us you own)
    my_chan = current.get("channel", 0)
    for ssid, group in by_ssid.items():
        if ssid in ("", "(hidden)"):
            continue  # hidden SSIDs can't be meaningfully twin-checked
        bssids = {a.bssid for a in group} - set(trusted)
        if len(bssids) >= 2:
            tag = "YOUR network" if ssid == my_ssid else f"SSID '{ssid}'"
            findings.append(RogueFinding(
                kind="evil_twin",
                severity="high",
                message=(f"SSID '{ssid}' is being broadcast by {len(bssids)} different "
                         f"access points ({', '.join(sorted(bssids)[:4])}). If this is "
                         f"{tag}, one of them may be an evil twin — verify which "
                         f"BSSID is your real router (check the sticker on it).")))

    # Same SSID on unexpected channels
    if my_ssid and my_ssid in by_ssid:
        for ap in by_ssid[my_ssid]:
            if my_chan and ap.channel and ap.channel != my_chan and ap.bssid != current.get("bssid"):
                findings.append(RogueFinding(
                    kind="unexpected_channel",
                    severity="info",
                    message=(f"Your SSID '{my_ssid}' also appears on channel "
                             f"{ap.channel} (you are on {my_chan}). Could be a "
                             f"dual-band router (normal) or a copycat AP.")))

    # Congestion on current channel (with 2.4GHz overlap math)
    if my_chan and aps:
        on_channel = [a for a in aps if a.channel == my_chan]
        if current.get("band") == "2.4":
            overlapping = [a for a in aps
                           if a.band == "2.4" and a.channel in _channel_overlap_24(my_chan)]
            total = len(on_channel) + len(overlapping)
            msg = (f"Your channel {my_chan} is shared by {len(on_channel)} AP(s), and "
                   f"{len(overlapping)} more AP(s) sit on overlapping 2.4GHz channels "
                   f"({', '.join(str(c) for c in sorted({a.channel for a in overlapping}))}). "
                   f"Total co-channel + adjacent-channel load: {total} APs.")
            if total >= 6:
                findings.append(RogueFinding(kind="congestion", severity="high", message=msg))
            elif total >= 3:
                findings.append(RogueFinding(kind="congestion", severity="info", message=msg))
        else:
            if len(on_channel) >= 4:
                findings.append(RogueFinding(
                    kind="congestion", severity="info",
                    message=(f"Your channel {my_chan} is shared by {len(on_channel)} APs.")))
    return findings
