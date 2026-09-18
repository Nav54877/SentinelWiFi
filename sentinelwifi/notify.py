"""SentinelWiFi — local desktop notifications (watch mode).

For auditing networks you own or are authorized to test.

Uses notify-send (Linux), osascript (macOS). On Windows or when no notifier
is available it falls back to a console line. Nothing is sent anywhere —
these are local desktop notifications only.
"""

from __future__ import annotations

import shutil
import subprocess
import sys


def notify(title: str, message: str) -> bool:
    try:
        if sys.platform.startswith("linux") and shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "-a", "SentinelWiFi", title, message],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        if sys.platform == "darwin":
            script = f'display notification "{message}" with title "{title}"'
            subprocess.Popen(["osascript", "-e", script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
    except Exception:
        pass
    print(f"[notify] {title}: {message}")
    return False
