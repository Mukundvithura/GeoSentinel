#!/usr/bin/env python3
"""
Check : Cell Tower Contradiction
Weight: 25
Cross-references GPS coordinates with simultaneously active cell tower locations.
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


_SEED_CELL_DATA = {
    28741: ("Chennai", 13.0827, 80.2707),
    28742: ("Chennai", 13.0900, 80.2750),
    28743: ("Chennai", 13.0750, 80.2650),
    28744: ("Chennai", 13.0800, 80.2800),
    41001: ("Bengaluru", 12.9716, 77.5946),
    41002: ("Bengaluru", 12.9780, 77.6000),
    41003: ("Bengaluru", 12.9650, 77.5900),
}


def resolve_cell_region(cid: int) -> tuple:
    return _SEED_CELL_DATA.get(cid, ("Unknown", None, None))


def _epoch_ms_str(ts_ms: int) -> str:
    try:
        dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"(ts={ts_ms})"


class CellTowerCheck(BaseCheck):
    NAME   = "Cell Tower Contradiction"
    WEIGHT = 25

    def run(self) -> dict:
        MAX_HONEST_DIST_KM = 50.0
        gps_records  = self.data.get('gps_records',  [])
        cell_records = self.data.get('cell_records', [])
        evidence     = []
        flagged      = False

        if not gps_records or not cell_records:
            return self._result(
                False,
                "Insufficient data for cell/GPS cross-correlation.",
                []
            )

        for gps in gps_records:
            gps_ts = gps['ts_ms']
            closest_cell = min(cell_records, key=lambda c: abs(c['ts_ms'] - gps_ts))
            time_gap_s = abs(closest_cell['ts_ms'] - gps_ts) / 1000.0
            if time_gap_s > 300:
                continue

            cell_region, cell_lat, cell_lng = resolve_cell_region(closest_cell['cid'])
            if cell_lat is None:
                continue

            dist_km = haversine_km(gps['lat'], gps['lng'], cell_lat, cell_lng)

            self._dbg(
                f"GPS ({gps['lat']:.4f},{gps['lng']:.4f}) vs "
                f"Cell CID {closest_cell['cid']} ({cell_region}) "
                f"dist={dist_km:.1f} km  gap={time_gap_s:.1f}s"
            )

            if dist_km > MAX_HONEST_DIST_KM:
                flagged = True
                evidence.append(
                    f"CONTRADICTION at {_epoch_ms_str(gps_ts)}: "
                    f"GPS reports ({gps['lat']:.4f},{gps['lng']:.4f})  |  "
                    f"Cell tower CID={closest_cell['cid']} resolves to '{cell_region}' "
                    f"({cell_lat:.4f},{cell_lng:.4f})  |  "
                    f"Separation: {dist_km:.1f} km  |  "
                    f"Time gap between records: {time_gap_s:.1f} s"
                )

        if flagged:
            summary = (
                f"FLAGGED — {len(evidence)} GPS/cell tower geographic contradictions detected. "
                f"Device GPS reports locations inconsistent with simultaneously active cell towers."
            )
            confidence = 'high' if len(evidence) >= 3 else 'medium'
        else:
            summary = "GPS coordinates are consistent with cell tower geographic regions."
            confidence = 'none'

        return self._result(flagged, summary, evidence, confidence)
