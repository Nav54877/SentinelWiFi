# Roadmap

Things that would make this better, roughly in priority order. If you
want to pick one up, open an issue first so we can agree on the shape.

## Near term

- **PyPI release** — packaging is ready (`pipx install
  git+https://github.com/Nav54877/SentinelWiFi.git` works today);
  a proper `pip install sentinelwifi` needs an account on PyPI.
- **Demo recording** — an asciinema cast or GIF of a real `report` run
  for the README. Generate it on your own network and strip anything
  identifying.
- **Richer evil-twin heuristics** — weigh signal strength and channel
  when the same SSID appears twice, and surface which BSSID is more
  likely the impostor.
- **macOS verification** — someone with a Mac run `selftest` and a full
  `report`, then fix whatever breaks (or document it as unsupported).

## Medium term

- **Plugin interface for checks** — a `checks.d`-style directory where
  users can drop their own passive checks without touching core code.
- **TOML config** alongside the JSON one, if people actually want it.
- **Scheduled scans** — ship example systemd timer and cron units with
  alerting via local notification only.
- **CSV export for every command** (devices already has it).

## Explicitly out of scope

- Anything active or offensive. If a check would require transmitting
  frames that aren't ordinary client traffic, or testing credentials,
  it does not belong in this tool. Fork it if you disagree — the MIT
  license allows that.
