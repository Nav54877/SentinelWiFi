"""SentinelWiFi — user configuration (~/.sentinelwifi/config.json).

For auditing networks you own or are authorized to test.

All settings are local. Sensible defaults ship with the tool; users override
by editing the JSON file or passing CLI flags.
"""

from __future__ import annotations

import json
import os

from .lan_scan import DATA_DIR

CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

DEFAULTS: dict = {
    "watch_interval": 60,        # seconds between watch-mode sweeps
    "port_scan_timeout": 0.5,    # TCP connect timeout for service scan
    "port_scan_enabled": True,   # set False to skip the services section
    "notify": False,             # desktop notifications in watch mode
    "trusted_bssids": [],        # your own APs' BSSIDs (lowers evil-twin noise)
    "preferred_iface": "",       # force an interface name
}


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE) as f:
            user = json.load(f)
        if isinstance(user, dict):
            cfg.update({k: v for k, v in user.items() if k in DEFAULTS})
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    # env override for CI/headless
    if os.environ.get("SENTINELWIFI_NO_NOTIFY"):
        cfg["notify"] = False
    return cfg


def save_config(cfg: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in cfg.items() if k in DEFAULTS})
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(merged, f, indent=2)
    os.replace(tmp, CONFIG_FILE)
