#!/usr/bin/env python3
"""
Check : Root / Hooking Indicators
Weight: 10
Detects root management and hooking framework apps.
"""

from checks.base_check import BaseCheck


class RootIndicatorsCheck(BaseCheck):
    NAME   = "Root / Hooking Indicators"
    WEIGHT = 10

    def run(self) -> dict:
        indicators = self.data.get('root_indicators', [])
        evidence   = []
        flagged    = bool(indicators)

        for ind in indicators:
            evidence.append(f"Root/hooking app: {ind['name']} ({ind['package']})")

        if flagged:
            summary = (
                f"FLAGGED — {len(indicators)} root/hooking indicator(s) found: "
                + ", ".join(i['package'].split('.')[-1] for i in indicators)
            )
            confidence = 'medium'
        else:
            summary = "No root or hooking framework indicators detected."
            confidence = 'none'

        return self._result(flagged, summary, evidence, confidence)
