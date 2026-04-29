#!/usr/bin/env python3
"""
Check  : App Behavioral Attribution (Phase 3)
Weight : 15
Correlates foreground app usage with spoofing events.
Identifies which app likely triggered GPS spoofing by analyzing
usage_stats data, accessibility logs, and automation tool presence.
"""

import datetime
from checks.base_check import BaseCheck


KNOWN_AUTOMATION_PACKAGES = {
    "net.dinglisch.android.taskerm"   : "Tasker (automation)",
    "com.arlosoft.macrodroid"         : "MacroDroid (automation)",
    "com.llamalab.automate"           : "Automate (automation)",
    "com.x0.strai"                    : "Automagic (automation)",
    "ch.gridvision.ppam.androidauto"  : "Auto Input (automation)",
}


def _epoch_ms_str(ts_ms: int) -> str:
    try:
        dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"(ts={ts_ms})"


class BehaviorCheck(BaseCheck):
    NAME   = "App Behavioral Attribution"
    WEIGHT = 15

    def run(self) -> dict:
        evidence = []
        flagged  = False

        spoofing_apps = self.data.get('spoofing_apps', [])
        app_usage     = self.data.get('app_usage', [])
        all_packages  = self.data.get('all_packages', [])
        usage_stats   = self.data.get('usage_stats', [])

        # --- Check 1: Automation tool presence ---
        automation_found = []
        for pkg in all_packages:
            if pkg in KNOWN_AUTOMATION_PACKAGES:
                automation_found.append({
                    'package': pkg,
                    'name':    KNOWN_AUTOMATION_PACKAGES[pkg],
                })

        if automation_found:
            flagged = True
            for auto in automation_found:
                evidence.append(
                    f"Automation tool detected: {auto['name']} ({auto['package']}) — "
                    f"could be used to trigger spoofing programmatically."
                )

        # --- Check 2: Spoofing app foreground activity correlation ---
        if usage_stats and spoofing_apps:
            spoof_pkgs = {a['package'] for a in spoofing_apps}
            for stat in usage_stats:
                if stat.get('package') in spoof_pkgs and stat.get('event') == 'FOREGROUND':
                    flagged = True
                    evidence.append(
                        f"Spoofing app foreground activity: {stat['package']} "
                        f"was in foreground at {_epoch_ms_str(stat.get('ts_ms', 0))}"
                    )

        # --- Check 3: Temporal clustering of spoofing app install + mock location ---
        if spoofing_apps:
            mock_ts = self.data.get('mock_location_set_ts')
            for app in spoofing_apps:
                install_ts = app.get('install_ts')
                if install_ts and mock_ts:
                    gap_s = abs(mock_ts - install_ts) / 1000.0
                    if gap_s < 600:  # within 10 minutes
                        flagged = True
                        evidence.append(
                            f"Behavioral pattern: '{app['package']}' installed within "
                            f"{gap_s:.0f}s of mock location setting activation — "
                            f"strong install-then-spoof correlation."
                        )

        # --- Check 4: Accessibility service abuse ---
        accessibility_apps = self.data.get('accessibility_apps', [])
        if accessibility_apps:
            for acc in accessibility_apps:
                if acc.get('package') in {a['package'] for a in spoofing_apps}:
                    flagged = True
                    evidence.append(
                        f"Spoofing app has accessibility privileges: {acc['package']} — "
                        f"can interact with other apps without user intervention."
                    )

        if not flagged and not spoofing_apps:
            return self._result(
                False,
                "No spoofing app behavioral attribution data available.",
                evidence
            )

        if flagged:
            summary = (
                f"FLAGGED — {len(evidence)} behavioral attribution indicator(s) found. "
                f"Spoofing app activity correlates with detected GPS anomalies."
            )
            confidence = 'high' if len(evidence) >= 3 else 'medium'
        else:
            summary = "No suspicious app behavioral patterns detected."
            confidence = 'none'

        return self._result(flagged, summary, evidence, confidence)
