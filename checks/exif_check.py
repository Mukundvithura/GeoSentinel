#!/usr/bin/env python3
"""
Check  : EXIF & Media Correlation (Phase 4)
Weight : 20
Cross-references image EXIF metadata GPS coordinates with the device
GPS timeline to detect contradictions between photo locations and
reported device position.
"""

import math
import datetime
from checks.base_check import BaseCheck


def haversine_km(lat1, lng1, lat2, lng2):
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi   = math.radians(lat2 - lat1)
    d_lambda = math.radians(lng2 - lng1)
    a = (math.sin(d_phi / 2) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _epoch_ms_str(ts_ms: int) -> str:
    try:
        dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"(ts={ts_ms})"


class ExifCheck(BaseCheck):
    NAME   = "EXIF Media Correlation"
    WEIGHT = 20

    # Maximum acceptable distance between EXIF GPS and device GPS
    MAX_MISMATCH_KM = 50.0

    def run(self) -> dict:
        exif_records = self.data.get('exif_records', [])
        gps_records  = self.data.get('gps_records', [])
        evidence     = []
        flagged      = False

        if not exif_records:
            return self._unavailable(
                "No EXIF media metadata available. "
                "Media access may be restricted or no geotagged photos found on device."
            )

        if not gps_records:
            return self._result(
                False,
                "No GPS records available for EXIF cross-correlation.",
                []
            )

        mismatches = 0
        matches    = 0

        for exif in exif_records:
            exif_lat = exif.get('lat')
            exif_lng = exif.get('lng')
            exif_ts  = exif.get('ts_ms')

            if exif_lat is None or exif_lng is None or exif_ts is None:
                continue

            # Find closest GPS record by timestamp
            closest_gps = min(
                gps_records,
                key=lambda g: abs(g['ts_ms'] - exif_ts)
            )
            time_gap_s = abs(closest_gps['ts_ms'] - exif_ts) / 1000.0

            # Only compare if within a 10-minute window
            if time_gap_s > 600:
                continue

            dist_km = haversine_km(
                exif_lat, exif_lng,
                closest_gps['lat'], closest_gps['lng']
            )

            if dist_km > self.MAX_MISMATCH_KM:
                mismatches += 1
                flagged = True
                evidence.append(
                    f"EXIF MISMATCH at {_epoch_ms_str(exif_ts)}: "
                    f"Photo GPS ({exif_lat:.4f},{exif_lng:.4f}) vs "
                    f"Device GPS ({closest_gps['lat']:.4f},{closest_gps['lng']:.4f})  |  "
                    f"Separation: {dist_km:.1f} km  |  "
                    f"Source: {exif.get('source', 'unknown')}  |  "
                    f"Time gap: {time_gap_s:.0f}s"
                )
            else:
                matches += 1

        if flagged:
            summary = (
                f"FLAGGED — {mismatches} EXIF/GPS mismatch(es) detected. "
                f"Photo metadata contradicts reported device location."
            )
            confidence = 'high' if mismatches >= 2 else 'medium'
        else:
            summary = (
                f"EXIF coordinates consistent with GPS timeline "
                f"({matches} photos cross-referenced)."
            )
            confidence = 'none'

        return self._result(flagged, summary, evidence, confidence)
