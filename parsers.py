#!/usr/bin/env python3
"""
=============================================================================
Module : parsers.py
Purpose: Parse all acquired Android forensic artefacts into structured
         Python data suitable for the detection and timeline engines.
=============================================================================

Parsed artefact types:
  1. settings_secure.xml    → mock_location_enabled, developer_options state
  2. package_list.txt       → installed app inventory, spoofing app detection
  3. herrevad.db            → GPS location records (latitude, longitude, time)
  4. netconn.db             → Cell tower records (MCC, MNC, LAC, CID, time)
  5. location_cache.db      → Fused Location Provider cache
  6. da_destination_history.db → Google Maps navigation destinations
  7. logcat_dump.txt        → Mock location provider log entries
  8. dumpsys_location.txt   → Current location service state
"""

import os
import sqlite3
import xml.etree.ElementTree as ET
import datetime
import re


# ─────────────────────────────────────────────────────────────────────────────
# KNOWN GPS SPOOFING APP PACKAGE NAMES
# This list covers the most common consumer-grade spoofing applications
# available on Google Play Store and via sideload.
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_SPOOFING_PACKAGES = {
    "com.lexa.fakegps"                        : "Fake GPS Location by Lexa",
    "com.theappninjas.gpsjoy"                 : "GPS JoyStick by The App Ninjas",
    "com.incorporateapps.fakegps.fre"         : "Fake GPS Run! (Free)",
    "com.blogspot.newapphorizons.fakegpslocations": "Fake GPS Location Changer Free",
    "com.rosteam.gpsemulator"                 : "Fake GPS Location — GPS JoyStick",
    "com.fly.mock.location"                   : "Fake GPS — Mock Location",
    "com.fakegps.mock"                        : "Fake GPS Mock",
    "ru.gavrikov.mocklocations"               : "Mock Locations (fake GPS path)",
    "com.ssrlab.fakeLocation"                 : "Fake Location — GPS Spoofer",
    "com.evezzon.fakegps"                     : "Fake GPS Location Spoofer Pro",
}

# ─────────────────────────────────────────────────────────────────────────────
# KNOWN ROOT / HOOKING INDICATOR PACKAGES
# Presence of these apps indicates the device may have elevated privileges,
# enabling low-level GPS manipulation beyond mock-location APIs.
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_ROOT_PACKAGES = {
    "com.topjohnwu.magisk"                    : "Magisk Manager (root)",
    "eu.chainfire.supersu"                    : "SuperSU (root)",
    "com.koushikdutta.superuser"              : "Superuser (root)",
    "com.noshufou.android.su"                 : "Superuser (legacy root)",
    "com.kingroot.kinguser"                   : "KingRoot (root)",
    "de.robv.android.xposed.installer"        : "Xposed Installer (hooking)",
    "org.lsposed.manager"                     : "LSPosed Manager (hooking)",
    "com.saurik.substrate"                    : "Cydia Substrate (hooking)",
    "com.formyhm.hideroot"                    : "Hide My Root (anti-forensics)",
    "com.devadvance.rootcloak"                : "RootCloak (anti-forensics)",
}


# ─────────────────────────────────────────────────────────────────────────────
# ARTEFACT PARSER CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ArtifactParser:
    """
    Reads all acquired forensic artefacts and returns a unified parsed_data
    dictionary consumed by the detection and timeline engines.

    Args:
        artefact_root : Root directory containing acquired files
                        (mirrors Android directory structure)
        verbose       : Print debug info when True
    """

    def __init__(self, artefact_root: str, verbose: bool = False):
        self.root    = artefact_root
        self.verbose = verbose

    # ── Resolve a device path to a local path ─────────────────────────────────

    def _local(self, *path_parts) -> str:
        """
        Build a local filesystem path by joining artefact_root with
        the relative version of an Android device path.

        Example:
            _local("data/system/users/0/settings_secure.xml")
            → "/path/to/acquisition/data/system/users/0/settings_secure.xml"
        """
        return os.path.join(self.root, *path_parts)

    def _dbg(self, msg: str):
        """Print debug message if verbose mode is on."""
        if self.verbose:
            print(f"    [DBG] {msg}")

    # ─────────────────────────────────────────────────────────────────────────
    # MASTER PARSE FUNCTION
    # ─────────────────────────────────────────────────────────────────────────

    def parse_all(self) -> dict:
        """
        Run all parsers and return a unified dictionary:

        {
          'mock_location_enabled'  : bool,
          'developer_options_ts'   : int (epoch ms) or None,
          'mock_location_package'  : str or None,
          'mock_location_set_ts'   : int (epoch ms) or None,
          'spoofing_apps'          : [ {'package': ..., 'name': ..., 'install_ts': ...} ],
          'root_indicators'        : [ {'package': ..., 'name': ...} ],
          'gps_records'            : [ {'lat', 'lng', 'accuracy', 'provider', 'ts_ms'} ],
          'cell_records'           : [ {'mcc', 'mnc', 'lac', 'cid', 'signal', 'ts_ms'} ],
          'fused_records'          : [ {'lat', 'lng', 'accuracy', 'provider', 'ts_ms'} ],
          'map_destinations'       : [ {'lat', 'lng', 'name', 'ts_ms'} ],
          'gmaps_trace_records'    : [ {'lat', 'lng', 'ts_ms'} ],
          'app_usage'              : [ {'package', 'event', 'ts_ms'} ],
          'logcat_mock_events'     : [ {'line', 'ts_str'} ],
          'all_packages'           : [ str ],
          'data_inconsistencies'   : [ {'type', 'description', 'ts_ms'} ],
          'exif_records'           : [ {'lat', 'lng', 'ts_ms', 'source'} ],
          'sensor_records'         : [ {'ts_ms', 'magnitude'} ],
          'activity_records'       : [ {'ts_ms', 'activity'} ],
          'step_records'           : [ {'ts_ms', 'steps'} ],
          'gnss_records'           : [ {'ts_ms', 'satellites': [...]} ],
          'usage_stats'            : [ {'package', 'event', 'ts_ms'} ],
          'accessibility_apps'     : [ {'package'} ],
        }
        """
        parsed = {}

        # Settings: mock_location and developer options
        parsed.update(self._parse_settings_secure())

        # Package list: installed apps + spoofing app detection + root traces
        parsed.update(self._parse_package_list())

        # GPS records from GMS herrevad.db
        parsed['gps_records'] = self._parse_location_db(
            path    = self._local("data/data/com.google.android.gms/databases/herrevad.db"),
            table   = "locations",
            lat_col = "latitude",
            lng_col = "longitude",
            ts_col  = "timestamp",
            extra_cols=["accuracy", "provider"]
        )

        # Cell tower records from netconn.db
        parsed['cell_records'] = self._parse_cell_db()

        # Fused location cache
        parsed['fused_records'] = self._parse_location_db(
            path    = self._local("data/data/com.google.android.gms/databases/location_cache.db"),
            table   = "fused_locations",
            lat_col = "latitude",
            lng_col = "longitude",
            ts_col  = "timestamp",
            extra_cols=["accuracy", "provider"]
        )

        # Google Maps destination history
        parsed['map_destinations'] = self._parse_map_destinations()

        # Google Maps Timeline JSON export (if available)
        parsed['gmaps_trace_records'] = self._parse_gmaps_timeline_json()

        # Logcat mock location events
        parsed['logcat_mock_events'] = self._parse_logcat()

        # App usage (package list install times as a proxy)
        parsed['app_usage'] = self._parse_app_usage(parsed.get('spoofing_apps', []))

        # Data inconsistency analysis (out-of-order timestamps, gaps)
        parsed['data_inconsistencies'] = self._scan_data_inconsistencies(parsed)

        # ── New Phase 3–6 data sources ────────────────────────────────────

        # EXIF media metadata (Phase 4)
        parsed['exif_records'] = self._parse_exif_records()

        # Sensor / activity / step data (Phase 5)
        parsed['sensor_records']   = self._parse_sensor_data()
        parsed['activity_records'] = self._parse_activity_data()
        parsed['step_records']     = self._parse_step_data()

        # GNSS satellite data (Phase 6)
        parsed['gnss_records'] = self._parse_gnss_data()

        # Usage stats and accessibility (Phase 3)
        parsed['usage_stats']      = self._parse_usage_stats()
        parsed['accessibility_apps'] = self._parse_accessibility_apps()

        return parsed

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: settings_secure.xml
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_settings_secure(self) -> dict:
        """
        Parse settings_secure.xml and settings_global.xml to extract:
          - Whether Developer Options are/were enabled
          - Whether a mock location app was designated
          - Timestamps of those settings changes
        """
        result = {
            'mock_location_enabled'  : False,
            'developer_options_ts'   : None,
            'mock_location_package'  : None,
            'mock_location_set_ts'   : None,
        }

        for xml_filename in ["settings_secure.xml", "settings_global.xml"]:
            xml_path = self._local("data/system/users/0", xml_filename)

            if not os.path.isfile(xml_path):
                self._dbg(f"{xml_filename} not found at {xml_path}")
                continue

            try:
                tree = ET.parse(xml_path)
                root = tree.getroot()

                for setting in root.findall("setting"):
                    name     = setting.get("name", "")
                    value    = setting.get("value", "")
                    modified = setting.get("modified")

                    # Developer Options enablement
                    if name == "development_settings_enabled" and value == "1":
                        result['mock_location_enabled'] = True
                        if modified:
                            result['developer_options_ts'] = int(modified)
                        self._dbg(f"Developer Options enabled, modified={modified}")

                    # Mock location app designation (Android 6+)
                    elif name == "mock_location" and value:
                        result['mock_location_package'] = value
                        result['mock_location_enabled'] = True
                        if modified:
                            result['mock_location_set_ts'] = int(modified)
                        self._dbg(f"Mock location package: {value}, modified={modified}")

            except ET.ParseError as e:
                self._dbg(f"XML parse error in {xml_filename}: {e}")

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: package_list.txt
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_package_list(self) -> dict:
        """
        Parse the ADB package list dump to:
          - Build a complete list of all installed packages
          - Identify any known GPS spoofing applications
          - Identify root / hooking indicator applications
          - Extract install timestamps where available
        """
        result = {
            'all_packages'    : [],
            'spoofing_apps'   : [],
            'root_indicators' : [],
        }

        pkg_path = os.path.join(self.root, "package_list.txt")
        if not os.path.isfile(pkg_path):
            self._dbg("package_list.txt not found")
            return result

        with open(pkg_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Extract package name from lines like:
            # package:/data/app/com.lexa.fakegps-1/base.apk=com.lexa.fakegps
            pkg_match = re.search(r'=([a-zA-Z][a-zA-Z0-9._]+)', line)
            if not pkg_match:
                continue

            package_name = pkg_match.group(1)
            result['all_packages'].append(package_name)

            # Check against known spoofing app list
            if package_name in KNOWN_SPOOFING_PACKAGES:
                ts_match = re.search(r'firstInstallTime=(\d+)', line)
                install_ts = int(ts_match.group(1)) * 1000 if ts_match else None

                entry = {
                    'package'    : package_name,
                    'name'       : KNOWN_SPOOFING_PACKAGES[package_name],
                    'install_ts' : install_ts,
                }
                result['spoofing_apps'].append(entry)
                self._dbg(f"Spoofing app detected: {package_name}")

            # Check against known root / hooking indicator list
            if package_name in KNOWN_ROOT_PACKAGES:
                result['root_indicators'].append({
                    'package' : package_name,
                    'name'    : KNOWN_ROOT_PACKAGES[package_name],
                })
                self._dbg(f"Root/hooking indicator detected: {package_name}")

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: Generic SQLite location database
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_location_db(
        self,
        path: str,
        table: str,
        lat_col: str,
        lng_col: str,
        ts_col: str,
        extra_cols: list = None
    ) -> list:
        """
        Generic parser for SQLite databases containing location records.
        Returns a list of dicts with keys: lat, lng, ts_ms, plus extras.

        Timestamps are expected in Unix epoch milliseconds.
        """
        records = []

        if not os.path.isfile(path):
            self._dbg(f"DB not found: {path}")
            return records

        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur  = conn.cursor()

            # Build SELECT with any extra columns requested
            cols = [lat_col, lng_col, ts_col]
            if extra_cols:
                cols += extra_cols
            query = f"SELECT {', '.join(cols)} FROM {table} ORDER BY {ts_col} ASC"

            cur.execute(query)
            rows = cur.fetchall()
            conn.close()

            for row in rows:
                record = {
                    'lat'   : row[lat_col],
                    'lng'   : row[lng_col],
                    'ts_ms' : row[ts_col],
                }
                if extra_cols:
                    for col in extra_cols:
                        record[col] = row[col]
                records.append(record)

            self._dbg(f"Parsed {len(records)} records from {os.path.basename(path)}/{table}")

        except sqlite3.Error as e:
            self._dbg(f"SQLite error reading {path}: {e}")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: netconn.db — Cell Tower Records
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_cell_db(self) -> list:
        """
        Parse netconn.db for cell tower scan records.
        Cell towers are geographically bound — cannot be spoofed by app-level mock location.
        """
        records = []
        db_path = self._local("data/data/com.google.android.gms/databases/netconn.db")

        if not os.path.isfile(db_path):
            self._dbg("netconn.db not found")
            return records

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur  = conn.cursor()

            cur.execute("""
                SELECT mcc, mnc, lac, cid, signal, timestamp
                FROM   cell_scan_results
                ORDER  BY timestamp ASC
            """)

            for row in cur.fetchall():
                records.append({
                    'mcc'    : row['mcc'],
                    'mnc'    : row['mnc'],
                    'lac'    : row['lac'],
                    'cid'    : row['cid'],
                    'signal' : row['signal'],
                    'ts_ms'  : row['timestamp'],
                })

            conn.close()
            self._dbg(f"Parsed {len(records)} cell tower records")

        except sqlite3.Error as e:
            self._dbg(f"SQLite error reading netconn.db: {e}")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: da_destination_history.db — Google Maps Destinations
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_map_destinations(self) -> list:
        """
        Parse Google Maps navigation destination history.
        A destination in a distant city is significant if the device GPS
        simultaneously claims to be in that city.
        """
        records = []
        db_path = self._local(
            "data/data/com.google.android.apps.maps/databases/da_destination_history.db"
        )

        if not os.path.isfile(db_path):
            self._dbg("da_destination_history.db not found")
            return records

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur  = conn.cursor()

            cur.execute("""
                SELECT dest_lat, dest_lng, dest_name, timestamp
                FROM   destination_history
                ORDER  BY timestamp ASC
            """)

            for row in cur.fetchall():
                records.append({
                    'lat'   : row['dest_lat'],
                    'lng'   : row['dest_lng'],
                    'name'  : row['dest_name'],
                    'ts_ms' : row['timestamp'],
                })

            conn.close()
            self._dbg(f"Parsed {len(records)} map destination records")

        except sqlite3.Error as e:
            self._dbg(f"SQLite error reading destination history: {e}")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: logcat_dump.txt — Mock Location Log Events
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_logcat(self) -> list:
        """
        Scan logcat dump for lines containing mock location provider events.
        Key strings: 'MockLocationProvider', 'setTestProviderLocation',
                     'Mock provider enabled', 'Mock provider disabled'.
        """
        events  = []
        log_path = os.path.join(self.root, "logcat_dump.txt")

        if not os.path.isfile(log_path):
            self._dbg("logcat_dump.txt not found")
            return events

        mock_keywords = [
            "MockLocationProvider",
            "setTestProviderLocation",
            "Mock provider enabled",
            "Mock provider disabled",
            "mockLocation",
            "fakegps",
        ]

        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_lower = line.lower()
                if any(kw.lower() in line_lower for kw in mock_keywords):
                    # Extract timestamp prefix from logcat format MM-DD HH:MM:SS.mmm
                    ts_match = re.match(r'^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', line)
                    ts_str   = ts_match.group(1) if ts_match else "unknown"
                    events.append({
                        'line'   : line.strip(),
                        'ts_str' : ts_str,
                    })
                    self._dbg(f"Logcat mock event: {ts_str}")

        return events

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: App Usage (derived from install timestamps)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_app_usage(self, spoofing_apps: list) -> list:
        """
        Build an app usage event list from:
          - Spoofing app install timestamps (from package_list)
          - Mock location setting timestamps (from settings_secure.xml)
          - Logcat events

        In a real investigation, /data/system/usagestats/ would provide
        richer usage data. This implementation uses available proxies.
        """
        usage_events = []

        for app in spoofing_apps:
            if app.get('install_ts'):
                usage_events.append({
                    'package'  : app['package'],
                    'event'    : 'INSTALL',
                    'ts_ms'    : app['install_ts'],
                })

        return usage_events

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: Google Maps Timeline JSON export
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_gmaps_timeline_json(self) -> list:
        """
        Parse a Google Maps Timeline export (Records.json / LocationHistory.json)
        if present in the artefact root. These exports contain high-fidelity
        timestamped GPS traces from Google's location history service.

        Searches for common export filenames in the artefact root directory.
        """
        import json

        records = []
        candidate_names = [
            "Records.json",
            "LocationHistory.json",
            "location_history.json",
            "timeline_export.json",
        ]

        json_path = None
        for name in candidate_names:
            candidate = os.path.join(self.root, name)
            if os.path.isfile(candidate):
                json_path = candidate
                break

        if json_path is None:
            self._dbg("No Google Maps Timeline JSON export found")
            return records

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Google Takeout format: {"locations": [...]}
            locations = data if isinstance(data, list) else data.get("locations", [])

            for loc in locations:
                lat = loc.get("latitudeE7") or loc.get("lat")
                lng = loc.get("longitudeE7") or loc.get("lng")
                ts  = loc.get("timestampMs") or loc.get("timestamp") or loc.get("ts_ms")

                if lat is None or lng is None or ts is None:
                    continue

                # Google Takeout uses E7 format (integer × 1e-7 = degrees)
                if isinstance(lat, int) and abs(lat) > 1000:
                    lat = lat / 1e7
                    lng = lng / 1e7

                ts_ms = int(ts)

                records.append({
                    'lat'   : float(lat),
                    'lng'   : float(lng),
                    'ts_ms' : ts_ms,
                })

            self._dbg(f"Parsed {len(records)} records from Google Maps Timeline export")

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            self._dbg(f"Error parsing Google Maps Timeline JSON: {e}")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # SCANNER: Data Inconsistency Detection
    # ─────────────────────────────────────────────────────────────────────────

    def _scan_data_inconsistencies(self, parsed: dict) -> list:
        """
        Scan parsed artefact data for anomalies that may indicate
        anti-forensic tampering or data manipulation:
          - Out-of-order timestamps within a single data source
          - Large gaps in otherwise regular recording intervals
          - Duplicate records at identical timestamps

        These anomalies contribute to the Anti-Forensics risk score.
        """
        inconsistencies = []

        # ── Check GPS records for out-of-order timestamps ────────────────
        gps = parsed.get('gps_records', [])
        for i in range(1, len(gps)):
            if gps[i]['ts_ms'] < gps[i - 1]['ts_ms']:
                inconsistencies.append({
                    'type'        : 'OUT_OF_ORDER_TIMESTAMP',
                    'description' : (
                        f"GPS record {i} timestamp ({gps[i]['ts_ms']}) "
                        f"precedes record {i-1} ({gps[i-1]['ts_ms']})"
                    ),
                    'ts_ms'       : gps[i]['ts_ms'],
                })

        # ── Check for large gaps in GPS recording ────────────────────────
        if len(gps) >= 3:
            deltas = []
            for i in range(1, len(gps)):
                d = gps[i]['ts_ms'] - gps[i - 1]['ts_ms']
                if d > 0:
                    deltas.append(d)
            if deltas:
                avg_delta = sum(deltas) / len(deltas)
                for i in range(1, len(gps)):
                    gap = gps[i]['ts_ms'] - gps[i - 1]['ts_ms']
                    # Flag gaps that are > 10× the average interval
                    if gap > 0 and avg_delta > 0 and gap > avg_delta * 10:
                        inconsistencies.append({
                            'type'        : 'RECORDING_GAP',
                            'description' : (
                                f"GPS recording gap of {gap/1000:.0f}s between "
                                f"records {i-1} and {i} (avg interval: {avg_delta/1000:.0f}s)"
                            ),
                            'ts_ms'       : gps[i - 1]['ts_ms'],
                        })

        # ── Check cell records for out-of-order timestamps ───────────────
        cells = parsed.get('cell_records', [])
        for i in range(1, len(cells)):
            if cells[i]['ts_ms'] < cells[i - 1]['ts_ms']:
                inconsistencies.append({
                    'type'        : 'OUT_OF_ORDER_TIMESTAMP',
                    'description' : (
                        f"Cell record {i} timestamp ({cells[i]['ts_ms']}) "
                        f"precedes record {i-1} ({cells[i-1]['ts_ms']})"
                    ),
                    'ts_ms'       : cells[i]['ts_ms'],
                })

        # ── Check for duplicate GPS records ──────────────────────────────
        seen_gps = set()
        for i, rec in enumerate(gps):
            key = (rec['ts_ms'], round(rec['lat'], 6), round(rec['lng'], 6))
            if key in seen_gps:
                inconsistencies.append({
                    'type'        : 'DUPLICATE_RECORD',
                    'description' : (
                        f"Duplicate GPS record at index {i}: "
                        f"({rec['lat']:.4f}, {rec['lng']:.4f}) ts={rec['ts_ms']}"
                    ),
                    'ts_ms'       : rec['ts_ms'],
                })
            seen_gps.add(key)

        self._dbg(f"Data inconsistency scan: {len(inconsistencies)} anomalies found")
        return inconsistencies

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: EXIF Media Metadata (Phase 4)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_exif_records(self) -> list:
        """
        Parse EXIF GPS metadata from media files (DCIM, WhatsApp, screenshots).
        Looks for a pre-extracted exif_data.json or scans image files directly.

        Falls back gracefully if no media access is available.
        """
        import json

        records = []

        # Method 1: Pre-extracted EXIF JSON (from bugreport or custom tool)
        exif_json = os.path.join(self.root, "exif_data.json")
        if os.path.isfile(exif_json):
            try:
                with open(exif_json, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else data.get("photos", [])
                for item in items:
                    lat = item.get("lat") or item.get("latitude")
                    lng = item.get("lng") or item.get("longitude")
                    ts  = item.get("ts_ms") or item.get("timestamp")
                    src = item.get("source") or item.get("filename", "unknown")

                    if lat is not None and lng is not None and ts is not None:
                        records.append({
                            'lat'    : float(lat),
                            'lng'    : float(lng),
                            'ts_ms'  : int(ts),
                            'source' : src,
                        })

                self._dbg(f"Parsed {len(records)} EXIF records from exif_data.json")
            except (json.JSONDecodeError, KeyError) as e:
                self._dbg(f"Error parsing exif_data.json: {e}")
        else:
            self._dbg("No exif_data.json found — EXIF correlation unavailable")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: Sensor Data (Phase 5)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_sensor_data(self) -> list:
        """
        Parse accelerometer/sensor data from:
          - sensor_data.json (pre-extracted)
          - bugreport sensor dumps
          - Google Fit activity databases
        """
        import json

        records = []
        sensor_json = os.path.join(self.root, "sensor_data.json")
        if os.path.isfile(sensor_json):
            try:
                with open(sensor_json, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else data.get("readings", [])
                for item in items:
                    ts = item.get("ts_ms") or item.get("timestamp")
                    mag = item.get("magnitude") or item.get("accel_magnitude")
                    if ts is not None and mag is not None:
                        records.append({
                            'ts_ms'     : int(ts),
                            'magnitude' : float(mag),
                        })

                self._dbg(f"Parsed {len(records)} sensor records")
            except (json.JSONDecodeError, KeyError) as e:
                self._dbg(f"Error parsing sensor_data.json: {e}")
        else:
            self._dbg("No sensor_data.json found — sensor contradiction check unavailable")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: Activity Recognition Data (Phase 5)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_activity_data(self) -> list:
        """
        Parse activity recognition transitions from:
          - activity_data.json (pre-extracted)
          - Google Fit activity segments
        """
        import json

        records = []
        activity_json = os.path.join(self.root, "activity_data.json")
        if os.path.isfile(activity_json):
            try:
                with open(activity_json, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else data.get("activities", [])
                for item in items:
                    ts = item.get("ts_ms") or item.get("timestamp")
                    act = item.get("activity") or item.get("type")
                    if ts is not None and act is not None:
                        records.append({
                            'ts_ms'    : int(ts),
                            'activity' : str(act).upper(),
                        })

                self._dbg(f"Parsed {len(records)} activity records")
            except (json.JSONDecodeError, KeyError) as e:
                self._dbg(f"Error parsing activity_data.json: {e}")
        else:
            self._dbg("No activity_data.json found")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: Step Counter Data (Phase 5)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_step_data(self) -> list:
        """
        Parse step counter data from:
          - step_data.json (pre-extracted)
          - Google Fit / Samsung Health step databases
        """
        import json

        records = []
        step_json = os.path.join(self.root, "step_data.json")
        if os.path.isfile(step_json):
            try:
                with open(step_json, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else data.get("steps", [])
                for item in items:
                    ts = item.get("ts_ms") or item.get("timestamp")
                    steps = item.get("steps") or item.get("count")
                    if ts is not None and steps is not None:
                        records.append({
                            'ts_ms' : int(ts),
                            'steps' : int(steps),
                        })

                self._dbg(f"Parsed {len(records)} step records")
            except (json.JSONDecodeError, KeyError) as e:
                self._dbg(f"Error parsing step_data.json: {e}")
        else:
            self._dbg("No step_data.json found")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: GNSS Satellite Data (Phase 6)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_gnss_data(self) -> list:
        """
        Parse raw GNSS measurement data from:
          - gnss_data.json (pre-extracted from GnssLogger or bugreport)
          - Android raw GNSS measurement logs
        """
        import json

        records = []
        gnss_json = os.path.join(self.root, "gnss_data.json")
        if os.path.isfile(gnss_json):
            try:
                with open(gnss_json, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else data.get("epochs", [])
                for item in items:
                    ts = item.get("ts_ms") or item.get("timestamp")
                    sats = item.get("satellites", [])
                    if ts is not None:
                        records.append({
                            'ts_ms'      : int(ts),
                            'satellites' : sats,
                        })

                self._dbg(f"Parsed {len(records)} GNSS satellite epochs")
            except (json.JSONDecodeError, KeyError) as e:
                self._dbg(f"Error parsing gnss_data.json: {e}")
        else:
            self._dbg("No gnss_data.json found — GNSS signal analysis unavailable")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: Usage Stats (Phase 3)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_usage_stats(self) -> list:
        """
        Parse Android UsageStatsManager data from:
          - usage_stats.json (pre-extracted)
          - /data/system/usagestats/ XML dumps
        """
        import json

        records = []
        usage_json = os.path.join(self.root, "usage_stats.json")
        if os.path.isfile(usage_json):
            try:
                with open(usage_json, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else data.get("events", [])
                for item in items:
                    pkg   = item.get("package")
                    event = item.get("event")
                    ts    = item.get("ts_ms") or item.get("timestamp")
                    if pkg and event and ts:
                        records.append({
                            'package' : pkg,
                            'event'   : event,
                            'ts_ms'   : int(ts),
                        })

                self._dbg(f"Parsed {len(records)} usage stats events")
            except (json.JSONDecodeError, KeyError) as e:
                self._dbg(f"Error parsing usage_stats.json: {e}")
        else:
            self._dbg("No usage_stats.json found")

        return records

    # ─────────────────────────────────────────────────────────────────────────
    # PARSER: Accessibility Services (Phase 3)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_accessibility_apps(self) -> list:
        """
        Parse which apps have accessibility service privileges from:
          - accessibility_apps.json (pre-extracted)
          - settings_secure.xml 'enabled_accessibility_services' key
        """
        import json

        records = []

        # Method 1: JSON file
        acc_json = os.path.join(self.root, "accessibility_apps.json")
        if os.path.isfile(acc_json):
            try:
                with open(acc_json, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else data.get("apps", [])
                for item in items:
                    pkg = item.get("package")
                    if pkg:
                        records.append({'package': pkg})

                self._dbg(f"Parsed {len(records)} accessibility apps")
            except (json.JSONDecodeError, KeyError) as e:
                self._dbg(f"Error parsing accessibility_apps.json: {e}")

        # Method 2: Parse from settings_secure.xml
        if not records:
            xml_path = self._local("data/system/users/0", "settings_secure.xml")
            if os.path.isfile(xml_path):
                try:
                    import xml.etree.ElementTree as ET2
                    tree = ET2.parse(xml_path)
                    root = tree.getroot()
                    for setting in root.findall("setting"):
                        name  = setting.get("name", "")
                        value = setting.get("value", "")
                        if name == "enabled_accessibility_services" and value:
                            # Format: com.package/com.package.Service:com.other/...
                            for svc in value.split(":"):
                                pkg = svc.split("/")[0].strip()
                                if pkg:
                                    records.append({'package': pkg})
                except Exception as e:
                    self._dbg(f"Error parsing accessibility from settings: {e}")

        return records


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY: Convert Unix epoch milliseconds to UTC datetime string
# ─────────────────────────────────────────────────────────────────────────────

def epoch_ms_to_utc(ts_ms: int) -> str:
    """Convert Unix timestamp in milliseconds to a human-readable UTC string."""
    try:
        dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        return f"INVALID_TS({ts_ms})"

