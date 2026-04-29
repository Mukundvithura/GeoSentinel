#!/usr/bin/env python3
"""
Check  : Sensor Contradiction Detection (Phase 5)
Weight : 40
Cross-references GPS velocity with physical sensor state (accelerometer,
step counter, activity recognition) to detect stationary-device-moving-GPS
contradictions.

Data Sources (fallbacks for historical sensor data):
  - Android bugreport sensor dumps
  - Google Fit / Samsung Health activity databases
  - Activity Recognition transition logs
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


class SensorCheck(BaseCheck):
    NAME   = "Sensor Contradiction"
    WEIGHT = 40

    def run(self) -> dict:
        sensor_records    = self.data.get('sensor_records', [])
        activity_records  = self.data.get('activity_records', [])
        step_records      = self.data.get('step_records', [])
        gps_records       = self.data.get('gps_records', [])
        evidence          = []
        flagged           = False

        has_sensor_data = bool(sensor_records or activity_records or step_records)

        if not has_sensor_data:
            return self._unavailable(
                "No sensor/activity data available. "
                "Historical sensor logs require root access, bugreport dumps, "
                "or health framework data (Google Fit / Samsung Health)."
            )

        if not gps_records or len(gps_records) < 2:
            return self._result(
                False,
                "Insufficient GPS records for sensor cross-correlation.",
                []
            )

        # --- Check 1: Activity Recognition vs GPS velocity ---
        if activity_records:
            for i in range(len(gps_records) - 1):
                r1, r2 = gps_records[i], gps_records[i + 1]
                ts_delta_s = (r2['ts_ms'] - r1['ts_ms']) / 1000.0
                if ts_delta_s <= 0:
                    continue

                dist_km = haversine_km(r1['lat'], r1['lng'], r2['lat'], r2['lng'])
                speed_kmh = (dist_km / (ts_delta_s / 3600.0)) if ts_delta_s > 0 else 0

                # Find activity records in this time window
                window_activities = [
                    a for a in activity_records
                    if r1['ts_ms'] <= a['ts_ms'] <= r2['ts_ms']
                ]

                for act in window_activities:
                    activity_type = act.get('activity', '').upper()

                    # GPS says moving fast, but activity says STILL or ON_FOOT
                    if speed_kmh > 100 and activity_type in ('STILL', 'TILTING'):
                        flagged = True
                        evidence.append(
                            f"SENSOR CONTRADICTION at {_epoch_ms_str(act['ts_ms'])}: "
                            f"GPS implies {speed_kmh:.0f} km/h travel, "
                            f"but Activity Recognition reports '{activity_type}'. "
                            f"Device was physically stationary while GPS moved {dist_km:.1f} km."
                        )

                    # GPS says moving fast, but activity says walking
                    elif speed_kmh > 200 and activity_type == 'ON_FOOT':
                        flagged = True
                        evidence.append(
                            f"SENSOR CONTRADICTION at {_epoch_ms_str(act['ts_ms'])}: "
                            f"GPS implies {speed_kmh:.0f} km/h, "
                            f"but Activity Recognition reports 'ON_FOOT' (~5 km/h). "
                            f"Impossible velocity for pedestrian movement."
                        )

        # --- Check 2: Step counter vs GPS distance ---
        if step_records and len(step_records) >= 2:
            # Compare total steps during GPS travel window
            first_step = step_records[0]
            last_step  = step_records[-1]
            total_steps = last_step.get('steps', 0) - first_step.get('steps', 0)

            # Estimate distance from steps (avg stride ~0.75m)
            step_distance_km = (total_steps * 0.75) / 1000.0

            # Compare with GPS total distance
            gps_total_km = 0.0
            for i in range(len(gps_records) - 1):
                gps_total_km += haversine_km(
                    gps_records[i]['lat'], gps_records[i]['lng'],
                    gps_records[i+1]['lat'], gps_records[i+1]['lng']
                )

            if gps_total_km > 50 and step_distance_km < 1:
                flagged = True
                evidence.append(
                    f"STEP COUNTER CONTRADICTION: GPS shows {gps_total_km:.1f} km travel, "
                    f"but step counter recorded only {total_steps} steps "
                    f"(~{step_distance_km:.1f} km). Device was physically stationary."
                )

        # --- Check 3: Accelerometer variance (if raw data available) ---
        if sensor_records:
            for i in range(len(gps_records) - 1):
                r1, r2 = gps_records[i], gps_records[i + 1]
                ts_delta_s = (r2['ts_ms'] - r1['ts_ms']) / 1000.0
                if ts_delta_s <= 0:
                    continue
                dist_km = haversine_km(r1['lat'], r1['lng'], r2['lat'], r2['lng'])
                speed_kmh = (dist_km / (ts_delta_s / 3600.0)) if ts_delta_s > 0 else 0

                # Find sensor readings in this window
                window_sensors = [
                    s for s in sensor_records
                    if r1['ts_ms'] <= s['ts_ms'] <= r2['ts_ms']
                ]

                if window_sensors and speed_kmh > 100:
                    # Calculate accelerometer variance
                    accel_vals = [s.get('magnitude', 9.81) for s in window_sensors]
                    if len(accel_vals) >= 2:
                        mean_accel = sum(accel_vals) / len(accel_vals)
                        variance = sum((v - mean_accel) ** 2 for v in accel_vals) / len(accel_vals)

                        # Stationary device: variance < 0.1 m/s² near gravity (~9.81)
                        if variance < 0.1 and abs(mean_accel - 9.81) < 0.5:
                            flagged = True
                            evidence.append(
                                f"ACCELEROMETER CONTRADICTION at {_epoch_ms_str(r1['ts_ms'])}: "
                                f"GPS implies {speed_kmh:.0f} km/h, but accelerometer shows "
                                f"stationary (variance={variance:.3f}, mean={mean_accel:.2f} m/s²). "
                                f"Phone was sitting still while GPS 'moved' {dist_km:.1f} km."
                            )

        if flagged:
            summary = (
                f"FLAGGED — {len(evidence)} sensor/GPS contradiction(s) detected. "
                f"Physical sensor data contradicts reported GPS movement."
            )
            confidence = 'high' if len(evidence) >= 2 else 'medium'
        else:
            summary = "Sensor data consistent with GPS movement patterns."
            confidence = 'none'

        return self._result(flagged, summary, evidence, confidence)
