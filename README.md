# SentinelWiFi — personal network security auditor

**SentinelWiFi is a strictly passive, defensive tool.** It observes the
WiFi environment around you and the devices on your own LAN, then produces
a plain-language security report with concrete fixes. It sends nothing to
any network beyond normal local ARP/scan traffic on your own subnet, makes
no cloud calls, contains no telemetry, and stores everything locally in
`~/.sentinelwifi/`.

> ## Only audit networks you own or are authorized to test
> Pointing this (or any scanner) at networks you don't control or have
> written permission to test may be illegal where you live (in the US,
> the CFAA; in the EU, national computer-misuse laws). SentinelWiFi is
> built for your home network: your router, your WiFi, your devices.

## What it does

1. **Network audit** — shows your SSID, BSSID, signal, channel, and
   encryption (WPA3/WPA2/WEP/Open), with red warnings for WEP/Open; checks
   gateway reachability and whether the router admin page answers on HTTP
   (cleartext credentials) vs HTTPS.
2. **AP environment scan** — a 30-second passive sniffing window (monitor
   mode) enumerates all visible APs, detects possible evil twins (same
   SSID, 2+ BSSIDs), and reports channel congestion including 2.4GHz
   overlap math.
3. **LAN device inventory** — ARP-scans your /24, resolves vendors from a
   bundled OUI map, marks gateway/self/unknown devices, and remembers
   devices across runs in `~/.sentinelwifi/known_devices.json` so **new
   devices are highlighted — the "who's on my WiFi" feature**.
4. **Report card** — an A–F grade computed from transparent rules (see
   `scoring.py`), each finding with severity, plain-language explanation,
   and the fix. `--json` gives machine-readable output; `watch` mode loops
   the inventory every 60s and announces new devices.

## Passive-only scope

- No deauth, no packet injection, no handshake capture, no password
  cracking, no WPS attacks, no association attempts. Verified with:
  `grep -ri "deauth\|inject\|handshake\|crack" sentinelwifi/` → nothing.
- All scanning is receive-only sniffing or standard client scans
  (nmcli/iw) plus ARP on your own subnet.
- If a feature needs monitor mode and your adapter/driver can't do it,
  the tool **degrades to a managed-mode scan and tells you** — it never
  crashes or silently skips.

## Install & run

```bash
pip install -r requirements.txt
sudo python sentinel.py scan      # sudo recommended for sniffing/ARP
python sentinel.py devices
sudo python sentinel.py watch     # rogue-device alarm
python sentinel.py report
python sentinel.py scan --json
```

## Platform notes (honest limitations)

- **Linux (Ubuntu/Kali)**: full feature set. Monitor mode needs a
  monitor-capable USB adapter (e.g., an Atheros/Realtek chipset with
  in-kernel driver) and `iw` installed; the built-in adapter of most
  laptops is managed-mode-only, which is handled gracefully.
- **Windows**: monitor mode is not supported — AP scanning falls back to
  what standard APIs expose, and results are sparser. Vendor lookup, ARP
  inventory, watch mode, and grading all work.
- **macOS**: untested; sniffing requires root and adapter support.
- Without `scapy`, ARP scanning degrades to reading the kernel neighbour
  table (sparser) and monitor sniffing is unavailable.
- Without `rich`, reports render as plain text (no colors/tables).

## Grading rubric (transparent — see `scoring.py`)

Start at 100, subtract penalties, bands A≥90 B≥75 C≥60 D≥40 F<40.

| Finding | Penalty |
|---|---|
| Open or WEP WiFi | 45 (critical) |
| Possible evil twin (same SSID, 2+ BSSIDs) | 20 (critical) |
| 3+ unknown/new devices | 25 (critical) |
| Router admin page on HTTP (cleartext password) | 15 (warning) |
| 1–2 unknown/new devices | 10 (warning) |
| SSID leaks router brand/model | 10 (warning) |
| Crowded channel (co + adjacent ≥ 6 APs) | 5 |
| WPA2 when WPA3 is available | 5 (info) |

## Sample report

```
════════════════════════════════════════════════════════════════
  SentinelWiFi — Personal Network Security Report
  (auditing networks you own or are authorized to test)
════════════════════════════════════════════════════════════════

  Overall grade: C  (60/100)

  ▶ YOUR CONNECTION
    SSID        : dlink-Home-2.4
    BSSID       : C4:AD:34:12:9B:F0
    Channel     : 6  (band: 2.4 GHz)
    Signal      : -52 dBm
    Encryption  : WPA2
    Router admin: HTTP  ⚠ passwords sent in cleartext

  ▶ WI-FI ENVIRONMENT
    9 network(s) visible:
      dlink-Home-2.4            ch 6   -52 dBm  WPA2
      dlink-Home-2.4            ch 11  -71 dBm  WPA2   ⚠
      ...

  ▶ FINDINGS & FIXES
    [WARNING  ] Network name reveals your router model
    [WARNING  ] Router admin page uses HTTP (not HTTPS)
    [WARNING  ] WiFi channel is crowded
    [INFO     ] WiFi uses WPA2

  Report generated locally. No data left this machine.
════════════════════════════════════════════════════════════════
```

## Project layout

```
sentinelwifi/
  sentinel.py        # CLI entry (argparse: scan, devices, watch, report)
  sentinelwifi/
    __init__.py
    iface.py         # adapter detection, monitor-mode attempt + fallback
    ap_scan.py       # passive AP enumeration + rogue detection
    lan_scan.py      # ARP inventory + known-device tracking
    scoring.py       # A–F grading rules (transparent & commented)
    report.py        # rich console report + --json
    vendors.py       # small bundled OUI prefix map
  requirements.txt
  README.md
```

## Legal / ethical scope

Every source file carries the header: *"For auditing networks you own or
are authorized to test."* This tool exists to help you secure your own
home network. Do not use it to observe, enumerate, or test networks,
devices, or traffic you do not own or lack explicit written authorization
to assess.
