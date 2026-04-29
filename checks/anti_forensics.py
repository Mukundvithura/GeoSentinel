#!/usr/bin/env python3
"""
Check : Anti-Forensics Signals
Weight: 10
Detects out-of-order timestamps, recording gaps, and duplicate records.
"""

from checks.base_check import BaseCheck


class AntiForensicsCheck(BaseCheck):
    NAME   = "Anti-Forensics Signals"
    WEIGHT = 10

    def run(self) -> dict:
        inconsistencies = self.data.get('data_inconsistencies', [])
        evidence = []
        flagged  = False

        ooo   = [i for i in inconsistencies if i['type'] == 'OUT_OF_ORDER_TIMESTAMP']
        gaps  = [i for i in inconsistencies if i['type'] == 'RECORDING_GAP']
        dupes = [i for i in inconsistencies if i['type'] == 'DUPLICATE_RECORD']

        if ooo:
            flagged = True
            evidence.append(f"{len(ooo)} out-of-order timestamp(s) detected in location data.")
            for item in ooo[:3]:
                evidence.append(f"  -> {item['description']}")

        if gaps:
            flagged = True
            evidence.append(f"{len(gaps)} suspicious recording gap(s) detected.")
            for item in gaps[:3]:
                evidence.append(f"  -> {item['description']}")

        if dupes:
            evidence.append(f"{len(dupes)} duplicate record(s) found.")
            for item in dupes[:2]:
                evidence.append(f"  -> {item['description']}")

        if flagged:
            summary = (
                f"FLAGGED — {len(inconsistencies)} data anomalies suggest "
                f"possible anti-forensic tampering."
            )
            confidence = 'medium' if len(inconsistencies) >= 3 else 'low'
        else:
            summary = "No anti-forensic signals detected in location data."
            confidence = 'none'

        return self._result(flagged, summary, evidence, confidence)
