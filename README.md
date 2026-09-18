# SentinelWiFi

A small command-line tool that audits the security of your own home
network: WiFi encryption, the router's admin page, rogue DHCP servers,
evil-twin access points, and whatever is sitting on your LAN. It hands you
a plain-language report with an A–F grade and tells you how to fix what it
finds.

Everything it does is passive and stays on your machine. It listens; it
doesn't transmit anything beyond ordinary LAN traffic, writes its data to
`~/.sentinelwifi/`, and has no telemetry, no cloud calls, no auto-update.

> **Scope:** run this on networks you own or are explicitly authorized to
> test. Scanning or monitoring other people's networks is illegal in most
> jurisdictions (CFAA in the US, computer-misuse laws in the EU, and
> equivalents elsewhere).

## Quick start

```bash
git clone https://github.com/Nav54877/SentinelWiFi.git
cd SentinelWiFi
pip install -r requirements.txt

python sentinel.py selftest   # check your environment first
sudo python sentinel.py report  # the full audit
```

No adapter handy, or just curious what the output looks like?

```bash
python sentinel.py demo                      # sample data, no network access
python sentinel.py demo --html report.html   # same, as a standalone HTML file
```

The HTML version of the sample report is checked in at
[docs/sample-report.html](docs/sample-report.html).

## What it checks

- **Your connection** — SSID, BSSID, channel, signal, and encryption type.
  Open and WEP networks get flagged as what they are: no real protection.
- **Router admin exposure** — whether the admin page answers on HTTP
  (your admin password crosses the LAN in cleartext) or HTTPS.
- **Rogue DHCP** — parses your own DHCP lease files. If the server that
  handed out your network settings isn't your gateway, someone else may be
  redirecting your traffic.
- **AP environment** — a 30-second passive sniff (monitor mode) or a
  managed-mode scan lists the networks around you, with evil-twin
  detection (your SSID broadcast by more than one MAC) and channel
  congestion including 2.4 GHz overlap math.
- **Devices on your LAN** — an ARP scan of your /24 with vendor lookup.
  Devices are remembered between runs, so anything new shows up marked
  ★ NEW. `watch` mode sweeps every 60 seconds and alerts on joiners,
  optionally with a desktop notification.
- **Exposed services** — a fast TCP connect-scan of a small, curated port
  list (Telnet, TR-069, VNC, RDP, SMB…) against your own devices, with
  banner grabbing. Answers "what could an attacker who got onto my WiFi
  touch first?"

## Commands

```
scan      your WiFi + surroundings (+ grade)
devices   device inventory, newcomers flagged
ports     exposed-service scan of your subnet
watch     loop the inventory, announce new devices
report    everything, one report (optionally as HTML)
selftest  environment checklist
demo      report from synthetic data
```

Global flags work before or after the subcommand: `--json`, `--html FILE`,
`--iface NAME`, plus per-command options (`--window`, `--interval`,
`--timeout`, `--no-ports`, `--notify`).

## Sample output (demo data)

```
  Overall grade: D  (55/100)

  ▶ YOUR CONNECTION
    SSID        : dlink-Home-2.4
    BSSID       : C4:AD:34:12:9B:F0
    Channel     : 6  (band: 2.4 GHz)
    Signal      : -52 dBm
    Encryption  : WPA2
    Router admin: HTTP  ⚠ passwords sent in cleartext

  ▶ FINDINGS & FIXES
    [CRITICAL] Possible fake WiFi network (evil twin)  (−20)
    [WARNING ] Network name reveals your router model  (−10)
    [WARNING ] 5 new access point(s) visible since last scan  (−10)
```

Full text version: [docs/sample-report.txt](docs/sample-report.txt)

## Configuration

On first run a config file appears at `~/.sentinelwifi/config.json`:

```json
{
  "watch_interval": 60,
  "port_scan_timeout": 0.5,
  "port_scan_enabled": true,
  "notify": false,
  "trusted_bssids": [],
  "preferred_iface": ""
}
```

`trusted_bssids` is worth setting on dual-band setups: put your own
APs' BSSIDs there and the evil-twin check stops flagging your second
radio. Find them in any report under *Your connection* and *Wi-Fi
environment*.

## How the grade works

The score starts at 100 and loses points per finding — Open/WEP WiFi
(−45), rogue DHCP (−20), a possible evil twin (−20), unknown devices
(−10/−25), HTTP admin page (−15), exposed risky services (−10), a
brand-revealing SSID (−10), congestion (−5), WPA2 instead of WPA3 (−5).
Bands: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below that. Every rule is in
`scoring.py`, commented, in plain sight.

## Platform notes

- **Linux** is the primary target and gets the full feature set. Passive
  sniffing wants a monitor-capable adapter (most laptop built-ins are
  managed-mode-only; the tool detects this and falls back to a managed
  scan instead of failing). Install `iw` for wireless tools.
- **Windows** works for everything except monitor mode (`netsh` provides
  the connection details; inventory, ports, watch, reports all run).
- **macOS** is untested; sniffing needs root.
- Missing `scapy`? ARP falls back to reading the kernel neighbour table
  (after priming it with a quick connect sweep) and sniffing is skipped
  with a note. Missing `rich`? You get plain text instead of colors.

If you installed scapy with `pip install --user`, run without `sudo` or
install it system-wide — root's Python can't see user packages.

## Development

```bash
python -m unittest discover -s tests   # 34 tests, no network required
```

CI runs the tests on Python 3.10–3.12 plus two guards that keep the tool
honest: a grep proving no offensive capability exists in the package, and
a check that every source file carries the authorized-use header.

## License

MIT, see [LICENSE](LICENSE). Use it on your own networks.
