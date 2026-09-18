# Changelog

## v2.1.0

Professionalization pass:

- PyPI-ready packaging: `pipx install git+https://github.com/Nav54877/SentinelWiFi.git`
  gives you a `sentinelwifi` command.
- `doctor` alias for `selftest`.
- `--csv` on `devices` (ip, mac, vendor, flags, hostname) and `--quiet`
  global flag for cron/dashboard use.
- SECURITY.md, CONTRIBUTING.md, issue/PR templates, ROADMAP.md.
- README: support matrix up top, explicit "does not do" section, cron
  example.

## v2.0.3

Fixes from real-world runs:

- `iw scan` parser no longer treats `BSS Load:` / `BSS Color:` IE lines
  as access points (they produced phantom "hidden" networks and a false
  evil-twin critical).
- Evil-twin check skips hidden SSIDs — there is nothing meaningful to
  compare.
- `ip neigh` fallback parsing fixed; device inventory now works without
  scapy (a quick connect sweep primes the kernel ARP table first).
- First run with real data is a history baseline, not a diff — no more
  "everything is new" penalties.
- Clearer error when scapy is installed per-user but the tool is run
  under sudo.
- Latent crash when the connected SSID isn't among the visible APs.

## v2.0.2

- Replaced a real-user SSID that had slipped into a test fixture with a
  generic one.

## v2.0.1

Fixes from a live audit on a minimal Linux box:

- Managed-mode scan falls back to `iw dev <iface> scan` when nmcli is
  absent; stdlib parser for its output (SSID/BSSID/freq/signal/RSN/WPA).
- Channel and encryption resolved via `iw link` freq, interface info, and
  a one-off scan matched to the connected BSSID.
- scapy-less ARP fallback for Windows (`arp -a`) and an ARP-priming
  connect sweep on Linux.

## v2.0.0

- Rogue-DHCP detection from local lease files.
- Exposed-service scan (26 curated ports, banner grabbing) on your own
  devices.
- Cross-run history: new/gone APs and devices since the last run.
- HTML report export (`--html`), self-contained and offline-safe.
- Desktop notifications in watch mode (`--notify`).
- Config file at `~/.sentinelwifi/config.json` (intervals, trusted
  BSSIDs, toggles).
- Windows support for connection details and gateway detection.
- `demo` and `selftest` commands.
- 30+ unit tests and GitHub Actions CI.

## v1.0.0

Initial release: connection audit, passive AP scan with evil-twin
detection and congestion analysis, ARP device inventory with newcomer
tracking, A–F grading, rich/JSON reports, watch mode.
