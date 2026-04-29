#!/usr/bin/env python3
"""
Check  : GNSS Hardware Simulation Detection (Phase 6)
Weight : 35
Detects SDR/HackRF-based GNSS signal simulation attacks by analyzing
satellite signal quality, constellation metadata, and RF anomalies.

Indicators:
  - Sudden SNR (Signal-to-Noise Ratio) jumps across all satellites
  - Unrealistic satellite IDs or missing constellation diversity
  - Identical SNR values across multiple satellites (SDR artifact)
  - Abrupt constellation changes (all sats appear/disappear simultaneously)
"""

import datetime
from checks.base_check import BaseCheck


def _epoch_ms_str(ts_ms: int) -> str:
    try:
        dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"(ts={ts_ms})"


class GNSSCheck(BaseCheck):
    NAME   = "GNSS Signal Analysis"
    WEIGHT = 35

    # Expected constellation types for real multi-GNSS receivers
    EXPECTED_CONSTELLATIONS = {'GPS', 'GLONASS', 'GALILEO', 'BEIDOU', 'QZSS', 'SBAS'}

    def run(self) -> dict:
        gnss_records = self.data.get('gnss_records', [])
        evidence     = []
        flagged      = False

        if not gnss_records:
            return self._unavailable(
                "No GNSS satellite data available. "
                "Raw GNSS measurements require Android 7.0+ and may need "
                "GnssLogger or bugreport data."
            )

        # --- Check 1: SNR uniformity anomaly ---
        # Real signals have varying SNR. SDR simulators often output
        # identical or near-identical SNR for all satellites.
        for epoch in gnss_records:
            sats = epoch.get('satellites', [])
            if len(sats) < 4:
                continue

            snr_values = [s.get('snr', 0) for s in sats if s.get('snr', 0) > 0]
            if len(snr_values) < 4:
                continue

            mean_snr = sum(snr_values) / len(snr_values)
            variance = sum((v - mean_snr) ** 2 for v in snr_values) / len(snr_values)

            # SDR artifact: variance < 2.0 dB-Hz across 4+ sats is suspicious
            if variance < 2.0:
                flagged = True
                evidence.append(
                    f"SNR UNIFORMITY ANOMALY at {_epoch_ms_str(epoch.get('ts_ms', 0))}: "
                    f"{len(snr_values)} satellites with near-identical SNR "
                    f"(variance={variance:.2f} dB-Hz, mean={mean_snr:.1f} dB-Hz). "
                    f"Real GNSS signals exhibit significant SNR variation."
                )

        # --- Check 2: Constellation diversity ---
        # Real receivers see GPS + GLONASS + Galileo. Cheap SDR
        # simulators often only emit GPS L1.
        all_constellations = set()
        for epoch in gnss_records:
            for sat in epoch.get('satellites', []):
                ctype = sat.get('constellation', 'UNKNOWN')
                all_constellations.add(ctype.upper())

        if gnss_records and len(all_constellations) == 1:
            flagged = True
            evidence.append(
                f"CONSTELLATION MISMATCH: Only '{list(all_constellations)[0]}' constellation "
                f"observed across all epochs. Modern receivers typically see 3+ constellations "
                f"(GPS, GLONASS, Galileo). Single-constellation data suggests SDR simulation."
            )

        # --- Check 3: Sudden satellite appearance/disappearance ---
        # Real GNSS transitions are gradual. SDR power-on/off causes
        # all satellites to appear/disappear simultaneously.
        if len(gnss_records) >= 2:
            for i in range(1, len(gnss_records)):
                prev_sats = set(s.get('svid', 0) for s in gnss_records[i-1].get('satellites', []))
                curr_sats = set(s.get('svid', 0) for s in gnss_records[i].get('satellites', []))

                appeared    = curr_sats - prev_sats
                disappeared = prev_sats - curr_sats

                # 6+ satellites appearing/disappearing simultaneously is suspicious
                if len(appeared) >= 6 and len(prev_sats) < 2:
                    flagged = True
                    evidence.append(
                        f"ABRUPT SAT APPEARANCE at {_epoch_ms_str(gnss_records[i].get('ts_ms', 0))}: "
                        f"{len(appeared)} satellites appeared simultaneously (from {len(prev_sats)} -> "
                        f"{len(curr_sats)}). Suggests SDR simulator power-on."
                    )

                if len(disappeared) >= 6 and len(curr_sats) < 2:
                    flagged = True
                    evidence.append(
                        f"ABRUPT SAT LOSS at {_epoch_ms_str(gnss_records[i].get('ts_ms', 0))}: "
                        f"{len(disappeared)} satellites disappeared simultaneously "
                        f"({len(prev_sats)} -> {len(curr_sats)}). Suggests SDR simulator power-off."
                    )

        # --- Check 4: Unrealistic satellite IDs ---
        invalid_svids = []
        for epoch in gnss_records:
            for sat in epoch.get('satellites', []):
                svid = sat.get('svid', 0)
                ctype = sat.get('constellation', 'GPS').upper()

                # GPS SVIDs: 1-32, GLONASS: 65-96, Galileo: 1-36
                if ctype == 'GPS' and (svid < 1 or svid > 32):
                    invalid_svids.append(svid)
                elif ctype == 'GLONASS' and (svid < 65 or svid > 96):
                    invalid_svids.append(svid)

        if invalid_svids:
            flagged = True
            evidence.append(
                f"INVALID SATELLITE IDs: {len(invalid_svids)} satellite(s) with "
                f"out-of-range SVIDs detected: {invalid_svids[:5]}. "
                f"Suggests fabricated constellation data."
            )

        if flagged:
            summary = (
                f"FLAGGED — {len(evidence)} GNSS signal anomaly(ies) detected. "
                f"Satellite metadata suggests possible hardware-level GNSS simulation."
            )
            confidence = 'high' if len(evidence) >= 2 else 'medium'
        else:
            summary = "GNSS satellite data appears consistent with genuine signals."
            confidence = 'none'

        return self._result(flagged, summary, evidence, confidence)
