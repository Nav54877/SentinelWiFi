"""SentinelWiFi — cross-run history: "what changed since last time?"

For auditing networks you own or are authorized to test.

Snapshots of visible APs and LAN devices are stored locally in
~/.sentinelwifi/history.json. Each run diffs against the previous snapshot
so the report can say "2 new APs appeared", "a device disappeared", and so
newcomers are highlighted even across reboots.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from .ap_scan import AccessPoint
from .lan_scan import DATA_DIR, Device

HISTORY_FILE = os.path.join(DATA_DIR, "history.json")


@dataclass
class HistoryDiff:
    runs: int = 0
    new_aps: list[AccessPoint] = field(default_factory=list)
    new_devices: list[Device] = field(default_factory=list)
    gone_devices: list[str] = field(default_factory=list)  # MACs


def _load() -> dict:
    try:
        with open(HISTORY_FILE) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return {"runs": 0, "aps": {}, "devices": {}}


def _save(data: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = HISTORY_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, HISTORY_FILE)


def update(aps: list[AccessPoint], devices: list[Device]) -> HistoryDiff:
    """Record this run's snapshot; return what changed vs the previous one."""
    data = _load()
    old_aps: dict = data.get("aps", {})
    old_devs: dict = data.get("devices", {})

    diff = HistoryDiff(runs=int(data.get("runs", 0)) + 1)
    diff.new_aps = [a for a in aps if a.bssid not in old_aps]
    diff.new_devices = [d for d in devices if d.mac not in old_devs]
    diff.gone_devices = [mac for mac in old_devs
                         if mac not in {d.mac for d in devices}]

    data["runs"] = diff.runs
    data["last_run"] = time.time()
    data["aps"] = {a.bssid: a.ssid for a in aps}
    data["devices"] = {d.mac: d.ip for d in devices}
    _save(data)
    return diff
