#!/usr/bin/env python3
"""
Check : Mock Location Setting
Weight: 15
Detects Developer Options enablement and mock location app designation.
"""

import datetime
from checks.base_check import BaseCheck


def _epoch_ms_str(ts_ms: int) -> str:
    try:
        dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"(ts={ts_ms})"


class MockLocationCheck(BaseCheck):
    NAME   = "Mock Location Setting"
    WEIGHT = 15

    def run(self) -> dict:
        evidence = []
        flagged  = False

        if self.data.get('mock_location_enabled'):
            flagged = True
            evidence.append("Developer Options were enabled on this device.")

        dev_ts = self.data.get('developer_options_ts')
        if dev_ts:
            evidence.append(
                f"Developer Options enablement timestamp: {_epoch_ms_str(dev_ts)}"
            )

        mock_pkg = self.data.get('mock_location_package')
        if mock_pkg:
            flagged = True
            evidence.append(f"Mock Location App designated: '{mock_pkg}'")

        mock_ts = self.data.get('mock_location_set_ts')
        if mock_ts:
            evidence.append(
                f"Mock location setting modification timestamp: {_epoch_ms_str(mock_ts)}"
            )

        if not flagged:
            summary = "No mock location setting detected."
            confidence = 'none'
        elif mock_pkg:
            summary = f"FLAGGED — Mock location app '{mock_pkg}' was active."
            confidence = 'high'
        else:
            summary = "FLAGGED — Developer Options enabled (mock location may have been used)."
            confidence = 'medium'

        return self._result(flagged, summary, evidence, confidence)
