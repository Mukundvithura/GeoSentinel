#!/usr/bin/env python3
"""
Check : Logcat Mock Events
Weight: 20
Scans logcat for mock location provider system events.
"""

from checks.base_check import BaseCheck


class LogcatMockCheck(BaseCheck):
    NAME   = "Logcat Mock Events"
    WEIGHT = 20

    def run(self) -> dict:
        events   = self.data.get('logcat_mock_events', [])
        evidence = []
        flagged  = bool(events)

        for event in events:
            evidence.append(f"[{event['ts_str']}] {event['line']}")

        if flagged:
            summary = (
                f"FLAGGED — {len(events)} mock location provider event(s) found in logcat. "
                f"System-level evidence of active GPS spoofing."
            )
            confidence = 'high'
        else:
            summary = "No mock location events found in logcat dump."
            confidence = 'none'

        return self._result(flagged, summary, evidence, confidence)
