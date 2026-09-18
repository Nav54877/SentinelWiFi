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

![CI](https://github.com/Nav54877/SentinelWiFi/actions/workflows/ci.yml/badge.svg)

## Features

1. **Network audit** — SSID, BSSID, signal, channel, encryption
   (WPA3/WPA2/WEP/Open) with red warnings for WEP/Open; checks whether the
   router admin page answers on HTTP (cleartext credentials) vs HTTPS.
2. **AP environment scan** — 30-second passive sniffing window (monitor
   mode) enumerates all visible APs; **evil-twin detection** (same SSID,
   2+ BSSIDs — suppress known dual-band BSSIDs via `trusted_bssids` in the
   config); channel-congestion report with 2.4GHz overlap math; "new APs
   since last run" from local history.
3. **LAN device inventory** — ARP-scans your /24, resolves vendors from a
   bundled OUI map, marks gateway/self/**new** devices, persists across
   runs in `~/.sentinelwifi/known_devices.json` — the "who's on my WiFi"
   feature. `watch` mode sweeps every 60s and announces newcomers, with
   optional desktop notifications.
4. **Rogue-DHCP detection** — parses your own DHCP lease files; if the
   server that handed you network settings isn't your gateway, that's a
   critical finding.
5. **Exposed-service scan** — threaded TCP connect-scan of 26 curated,
   security-relevant ports (Telnet, TR-069, VNC, RDP, SMB…) on **your own
   devices**, with banner grabbing. Answers "what could an attacker who
   got on my WiFi touch first?"
6. **Report card** — transparent A–F grading (see `scoring.py`), every
   finding with severity, plain-language explanation, and the fix.
   Output: rich console, `--json`, or self-contained `--html` (offline,
   shareable).

## Commands

```bash
sudo python sentinel.py scan       # your WiFi + surroundings (+ grade)
python sentinel.py devices         # device inventory, newcomers flagged
python sentinel.py devices --ports # …+ exposed-service scan of found devices
python sentinel.py ports           # dedicated service scan of your subnet
sudo python sentinel.py watch      # rogue-device alarm (60s loop, --notify, --interval N)
python sentinel.py report          # everything, one report (+ --html out.html)
python sentinel.py selftest        # environment checklist (what's missing/failing)
python sentinel.py demo            # full report from synthetic data — no network needed
python sentinel.py --version       # v2.0.0
```

Global flags work before or after the subcommand: `--json`, `--html FILE`,
`--iface NAME`. Config lives in `~/.sentinelwifi/config.json`
(`watch_interval`, `port_scan_timeout`, `notify`, `trusted_bssids`, …).

## Passive-only scope

- No deauth, no packet injection, no handshake capture, no password
  cracking, no WPS attacks, no association attempts — enforced in CI:
  `grep -ri "deauth\|inject\|handshake\|crack" sentinelwifi/` must return
  nothing on every push.
- Scanning is receive-only sniffing, standard client scans (nmcli/iw/
  netsh), DHCP-lease parsing, and ARP/TCP-connect to your own subnet.
- If a feature needs monitor mode and your adapter can't do it, the tool
  degrades to managed-mode scanning **and tells you** — never crashes,
  never silently skips.

## Grading rubric (transparent — see `scoring.py`)

Start at 100, subtract penalties, bands A≥90 B≥75 C≥60 D≥40 F<40.

| Finding | Penalty |
|---|---|
| Open or WEP WiFi | 45 (critical) |
| Unknown DHCP server (rogue DHCP) | 20 (critical) |
| Possible evil twin (same SSID, 2+ BSSIDs) | 20 (critical) |
| 3+ unknown/new devices | 25 (critical) |
| Router admin on HTTP (cleartext password) | 15 (warning) |
| Risky services exposed (Telnet/FTP/VNC/RDP/TR-069…) | 10 (warning) |
| 1–2 unknown devices / SSID leaks router brand | 10 each (warning) |
| New APs visible that copy your SSID | 10 |
| New APs visible (other) / crowded channel | 3 / 5 |
| WPA2 when WPA3 is available | 5 (info) |

## Install

```bash
git clone https://github.com/Nav54877/SentinelWiFi.git
cd SentinelWiFi
pip install -r requirements.txt
python sentinel.py selftest   # see what your machine needs
```

## Platform notes (honest limitations)

- **Linux (Ubuntu/Kali)**: full feature set. Monitor mode needs a
  monitor-capable adapter (Atheros/Realtek USB) + `iw`; laptop built-ins
  are usually managed-mode-only — handled gracefully.
- **Windows**: monitor mode unsupported — `netsh`-based current-connection
  and gateway detection work; inventory, ports, watch, grading, HTML all work.
- **macOS**: untested; sniffing needs root + adapter support.
- Without `scapy`: ARP falls back to the kernel neighbour table; without
  `rich`: plain-text console. Everything still runs.

## Development

```bash
python -m unittest discover -s tests   # 29 tests, no network needed
python sentinel.py demo                # eyeball the report rendering
```

CI (GitHub Actions, Python 3.10–3.12) runs the test suite, the
passive-only grep, the header check, and demo-mode smoke tests on every
push.

## License

MIT — see `LICENSE`. This tool is for auditing networks you own or are
authorized to test; the authors accept no liability for misuse.
