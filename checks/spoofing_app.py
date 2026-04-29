#!/usr/bin/env python3
"""
Check : Spoofing App Installed
Weight: 15
Identifies known GPS spoofing applications in the installed package list.
"""

import datetime
from checks.base_check import BaseCheck


def _epoch_ms_str(ts_ms: int) -> str:
    try:
        dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"(ts={ts_ms})"


class SpoofingAppCheck(BaseCheck):
    NAME   = "Spoofing App Installed"
    WEIGHT = 15

    def run(self) -> dict:
        apps     = self.data.get('spoofing_apps', [])
        evidence = []
        flagged  = bool(apps)

        for app in apps:
            entry = f"Package: {app['package']}  |  Name: {app['name']}"
            if app.get('install_ts'):
                entry += f"  |  Installed: {_epoch_ms_str(app['install_ts'])}"
            evidence.append(entry)

        if flagged:
            summary = (
                f"FLAGGED — {len(apps)} known spoofing application(s) found: "
                + ", ".join(a['package'] for a in apps)
            )
            confidence = 'high' if len(apps) >= 2 else 'medium'
        else:
            summary = "No known GPS spoofing applications detected in package list."
            confidence = 'none'

        return self._result(flagged, summary, evidence, confidence)
