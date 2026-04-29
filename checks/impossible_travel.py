#!/usr/bin/env python3
"""
Check : Impossible Travel Speed
Weight: 30
Detects physically impossible GPS coordinate jumps using Haversine distance.
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


class ImpossibleTravelCheck(BaseCheck):
    NAME   = "Impossible Travel Speed"
    WEIGHT = 30

    def run(self) -> dict:
        threshold = self.kwargs.get('speed_threshold_kmh', 900.0)
        records   = self.data.get('gps_records', [])
        evidence  = []
        flagged   = False
        worst_speed = 0.0
        worst_pair  = None

        if len(records) < 2:
            return self._result(
                False,
                "Insufficient GPS records for travel speed analysis.",
                []
            )

        for i in range(len(records) - 1):
            r1, r2 = records[i], records[i + 1]
            ts_delta_ms = r2['ts_ms'] - r1['ts_ms']
            if ts_delta_ms <= 0:
                continue
            ts_delta_hrs = ts_delta_ms / 1000.0 / 3600.0
            dist_km = haversine_km(r1['lat'], r1['lng'], r2['lat'], r2['lng'])
            speed_kmh = dist_km / ts_delta_hrs if ts_delta_hrs > 0 else 0.0

            self._dbg(
                f"GPS pair {i}->{i+1}: dist={dist_km:.1f}km  "
                f"time={ts_delta_ms/1000:.1f}s  speed={speed_kmh:.0f} km/h"
            )

            if speed_kmh > threshold:
                flagged = True
                if speed_kmh > worst_speed:
                    worst_speed = speed_kmh
                    worst_pair = (r1, r2, dist_km, ts_delta_ms / 1000.0, speed_kmh)

                evidence.append(
                    f"GPS jump detected: "
                    f"({r1['lat']:.4f},{r1['lng']:.4f}) -> ({r2['lat']:.4f},{r2['lng']:.4f})  |  "
                    f"Distance: {dist_km:.1f} km  |  "
                    f"Time delta: {ts_delta_ms/1000:.1f} s  |  "
                    f"Implied speed: {speed_kmh:,.0f} km/h  |  "
                    f"Threshold: {threshold:.0f} km/h  |  "
                    f"At: {_epoch_ms_str(r2['ts_ms'])}"
                )

        if flagged and worst_pair:
            _, _, dist, dt, speed = worst_pair
            summary = (
                f"FLAGGED — Maximum implied speed: {speed:,.0f} km/h "
                f"({dist:.1f} km in {dt:.1f} s). "
                f"Threshold: {threshold:.0f} km/h. Physically impossible."
            )
            # >10x threshold = high, >2x = medium, else low
            if speed > threshold * 10:
                confidence = 'high'
            elif speed > threshold * 2:
                confidence = 'medium'
            else:
                confidence = 'low'
        else:
            summary = (
                f"No impossible travel detected. All GPS transitions within "
                f"{threshold:.0f} km/h threshold."
            )
            confidence = 'none'

        return self._result(flagged, summary, evidence, confidence)
