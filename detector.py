#!/usr/bin/env python3
"""
=============================================================================
Module : detector.py
Purpose: Orchestrator for the plugin-based detection engine.
         Loads all check plugins from the checks/ package and runs them
         against parsed artefact data. Produces a unified result set with
         confidence scoring.
=============================================================================

Architecture:
  Each check in checks/ inherits from BaseCheck and implements run().
  This module simply iterates over ALL_CHECKS, instantiates each with
  the parsed_data, and collects results.

Evidence Scoring Matrix:
  Each check has a WEIGHT (0–100). The composite risk score is the
  sum of weights for all flagged checks. Verdict thresholds:
    0        → No Evidence
    1–30     → Low Confidence
    31–60    → Medium Confidence
    61–100   → High Confidence
    100+     → Critical — Conclusive Evidence
"""

import math
import datetime
import sqlite3
import os
import urllib.request
import json

from checks import ALL_CHECKS


# ─────────────────────────────────────────────────────────────────────────────
# HAVERSINE DISTANCE CALCULATOR (shared utility)
# ─────────────────────────────────────────────────────────────────────────────

def haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """
    Calculate the great-circle distance between two GPS coordinates
    using the Haversine formula. Returns distance in kilometres.
    """
    R = 6371.0
    phi1    = math.radians(lat1)
    phi2    = math.radians(lat2)
    d_phi   = math.radians(lat2 - lat1)
    d_lambda= math.radians(lng2 - lng1)

    a = (math.sin(d_phi   / 2) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2)

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


# ─────────────────────────────────────────────────────────────────────────────
# HYBRID CELL TOWER RESOLVER (SQLite Cache → OpenCelliD API Fallback)
# ─────────────────────────────────────────────────────────────────────────────

# Seed data used when no cache DB exists yet
_SEED_CELL_DATA = {
    28741: ("Chennai", 13.0827, 80.2707),
    28742: ("Chennai", 13.0900, 80.2750),
    28743: ("Chennai", 13.0750, 80.2650),
    28744: ("Chennai", 13.0800, 80.2800),
    41001: ("Bengaluru", 12.9716, 77.5946),
    41002: ("Bengaluru", 12.9780, 77.6000),
    41003: ("Bengaluru", 12.9650, 77.5900),
}


class CellResolver:
    """
    Hybrid cell tower resolver: checks a local SQLite cache first,
    then falls back to the OpenCelliD API if configured.

    Args:
        cache_dir  : Directory to store cell_cache.sqlite
        api_key    : OpenCelliD API key (optional; None = offline only)
        verbose    : Print debug output
    """

    def __init__(self, cache_dir: str = ".", api_key: str = None, verbose: bool = False):
        self.api_key = api_key
        self.verbose = verbose
        self._db_path = os.path.join(cache_dir, "cell_cache.sqlite")
        self._conn = None
        self._init_db()

    def _init_db(self):
        """Create or open the SQLite cache and seed it if empty."""
        self._conn = sqlite3.connect(self._db_path)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS cell_towers (
                mcc     INTEGER,
                mnc     INTEGER,
                lac     INTEGER,
                cid     INTEGER,
                region  TEXT,
                lat     REAL,
                lng     REAL,
                PRIMARY KEY (mcc, mnc, lac, cid)
            )
        """)
        # Seed with known towers if table is empty
        cur = self._conn.execute("SELECT COUNT(*) FROM cell_towers")
        if cur.fetchone()[0] == 0:
            for cid, (region, lat, lng) in _SEED_CELL_DATA.items():
                self._conn.execute(
                    "INSERT OR IGNORE INTO cell_towers (mcc,mnc,lac,cid,region,lat,lng) "
                    "VALUES (404,20,8001,?,?,?,?)", (cid, region, lat, lng)
                )
            self._conn.commit()

    def resolve(self, mcc: int, mnc: int, lac: int, cid: int) -> tuple:
        """
        Resolve a cell tower to (region, lat, lng).
        Returns ('Unknown', None, None) if unresolvable.
        """
        # 1. Check local cache
        cur = self._conn.execute(
            "SELECT region, lat, lng FROM cell_towers "
            "WHERE mcc=? AND mnc=? AND lac=? AND cid=?",
            (mcc, mnc, lac, cid)
        )
        row = cur.fetchone()
        if row:
            return row

        # 2. Fallback: try CID-only lookup (partial match)
        cur = self._conn.execute(
            "SELECT region, lat, lng FROM cell_towers WHERE cid=? LIMIT 1",
            (cid,)
        )
        row = cur.fetchone()
        if row:
            return row

        # 3. API fallback (if key configured)
        if self.api_key:
            result = self._query_opencellid(mcc, mnc, lac, cid)
            if result:
                return result

        return ("Unknown", None, None)

    def _query_opencellid(self, mcc, mnc, lac, cid) -> tuple:
        """Query the OpenCelliD API and cache the result."""
        try:
            url = (
                f"https://opencellid.org/cell/get?"
                f"key={self.api_key}&mcc={mcc}&mnc={mnc}&lac={lac}&cellid={cid}"
                f"&format=json"
            )
            req = urllib.request.Request(url, headers={"User-Agent": "GeoSentinel/2.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                if data.get("lat") and data.get("lon"):
                    lat = float(data["lat"])
                    lng = float(data["lon"])
                    region = f"CID-{cid}"
                    # Cache for future use
                    self._conn.execute(
                        "INSERT OR REPLACE INTO cell_towers VALUES (?,?,?,?,?,?,?)",
                        (mcc, mnc, lac, cid, region, lat, lng)
                    )
                    self._conn.commit()
                    return (region, lat, lng)
        except Exception as e:
            if self.verbose:
                print(f"    [DBG] OpenCelliD query failed: {e}")
        return None

    def close(self):
        if self._conn:
            self._conn.close()


# Legacy compatibility wrapper
def resolve_cell_region(cid: int) -> tuple:
    """Legacy resolver — uses seed data only."""
    return _SEED_CELL_DATA.get(cid, ("Unknown", None, None))


# ─────────────────────────────────────────────────────────────────────────────
# SPOOFING DETECTOR CLASS — Plugin Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class SpoofingDetector:
    """
    Orchestrates all spoofing detection checks via the plugin architecture.
    Each check in checks/ is instantiated and executed independently.

    Args:
        parsed_data        : Dictionary returned by ArtifactParser.parse_all()
        speed_threshold_kmh: Travel speed above which GPS jump is flagged
        verbose            : Print debug info when True
    """

    def __init__(
        self,
        parsed_data: dict,
        speed_threshold_kmh: float = 900.0,
        verbose: bool = False
    ):
        self.data      = parsed_data
        self.threshold = speed_threshold_kmh
        self.verbose   = verbose

    def _dbg(self, msg: str):
        if self.verbose:
            print(f"    [DBG:DETECT] {msg}")

    # ─────────────────────────────────────────────────────────────────────────
    # MASTER: Run all checks via plugin architecture
    # ─────────────────────────────────────────────────────────────────────────

    def run_all_checks(self) -> dict:
        """
        Execute all registered detection checks from the checks/ package.

        Returns a dictionary: { check_name → result_dict }

        Each result_dict contains:
          name       : str    — Check name
          flagged    : bool   — True if indicator detected
          weight     : int    — Evidence score (0–100)
          confidence : str    — 'none' | 'low' | 'medium' | 'high'
          summary    : str    — One-line human-readable result
          evidence   : list   — List of evidence strings
          available  : bool   — False if data was unavailable
        """
        results = {}

        for CheckClass in ALL_CHECKS:
            check = CheckClass(
                parsed_data=self.data,
                verbose=self.verbose,
                speed_threshold_kmh=self.threshold,
            )
            result = check.run()
            results[result['name']] = result
            self._dbg(
                f"{result['name']}: "
                f"{'FLAGGED' if result['flagged'] else 'CLEAR'} "
                f"(weight={result['weight']}, confidence={result['confidence']})"
            )

        return results

    # ─────────────────────────────────────────────────────────────────────────
    # EVIDENCE SCORING — Weighted Confidence Verdict
    # ─────────────────────────────────────────────────────────────────────────

    def get_overall_verdict(self, results: dict) -> str:
        """
        Produce an overall spoofing verdict using the evidence scoring matrix.

        Each check has a weight (0–100). The composite risk score is the
        sum of weights for all flagged checks.

        Thresholds:
          0        → No Evidence of Spoofing
          1–30     → Low Confidence — Possible Innocent Explanation
          31–60    → Medium Confidence — Investigation Warranted
          61–100   → High Confidence — Strong Spoofing Indicators
          100+     → Critical — Conclusive Evidence of GPS Spoofing
        """
        risk_score = sum(
            r.get('weight', 0)
            for r in results.values()
            if r['flagged']
        )
        flag_count = sum(1 for r in results.values() if r['flagged'])
        available_count = sum(1 for r in results.values() if r.get('available', True))
        unavailable = [
            r['name'] for r in results.values()
            if not r.get('available', True)
        ]

        unavail_note = ""
        if unavailable:
            unavail_note = f" ({len(unavailable)} check(s) had no data)"

        if risk_score == 0:
            return f"NO EVIDENCE OF GPS SPOOFING DETECTED (Score: 0/225){unavail_note}"
        elif risk_score <= 30:
            return (
                f"LOW CONFIDENCE -- {flag_count} indicator(s), "
                f"Risk Score: {risk_score}/225{unavail_note}"
            )
        elif risk_score <= 60:
            return (
                f"MEDIUM CONFIDENCE -- {flag_count} indicators, "
                f"Risk Score: {risk_score}/225{unavail_note}"
            )
        elif risk_score <= 100:
            return (
                f"HIGH CONFIDENCE -- {flag_count} indicators, "
                f"Risk Score: {risk_score}/225{unavail_note}"
            )
        else:
            return (
                f"CRITICAL -- CONCLUSIVE EVIDENCE OF GPS SPOOFING "
                f"({flag_count}/{len(results)} indicators, "
                f"Risk Score: {risk_score}/225){unavail_note}"
            )

    def get_risk_score(self, results: dict) -> int:
        """Return the raw numeric risk score (sum of flagged weights)."""
        return sum(
            r.get('weight', 0)
            for r in results.values()
            if r['flagged']
        )

    def get_confidence_level(self, results: dict) -> str:
        """Return the confidence level string."""
        score = self.get_risk_score(results)
        if score == 0:
            return "none"
        elif score <= 30:
            return "low"
        elif score <= 60:
            return "medium"
        elif score <= 100:
            return "high"
        else:
            return "critical"


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY
# ─────────────────────────────────────────────────────────────────────────────

def _epoch_ms_str(ts_ms: int) -> str:
    """Convert Unix epoch milliseconds to UTC string."""
    try:
        dt = datetime.datetime.utcfromtimestamp(ts_ms / 1000.0)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"(ts={ts_ms})"
