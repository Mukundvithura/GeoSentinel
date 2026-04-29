#!/usr/bin/env python3
"""
=============================================================================
Module : report.py
Purpose: Generate all forensic output — console report, CSV timeline,
         and text report file — from detection results and timeline data.
=============================================================================

Output types:
  1. Console report   — Formatted to terminal with section headers
  2. CSV timeline     — forensic_timeline.csv (importable into Excel, Autopsy)
  3. Text report      — forensic_report.txt (court-appropriate structure)
  4. Verdict          — String returned to main.py for final display
"""

import os
import csv
import json
import datetime
import hashlib

from detector import SpoofingDetector


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """
    Generates all forensic output files and the console report.

    Args:
        parsed_data      : Output of ArtifactParser.parse_all()
        detection_results: Output of SpoofingDetector.run_all_checks()
        timeline         : Output of TimelineEngine.build_timeline()
        output_dir       : Directory to write output files into
        verbose          : Print debug info when True
    """

    def __init__(
        self,
        parsed_data: dict,
        detection_results: dict,
        timeline: list,
        output_dir: str,
        verbose: bool = False
    ):
        self.data       = parsed_data
        self.results    = detection_results
        self.timeline   = timeline
        self.output_dir = output_dir
        self.verbose    = verbose

        # Instantiate detector for verdict computation
        self._detector    = SpoofingDetector(parsed_data, verbose=verbose)
        self._verdict     = self._detector.get_overall_verdict(detection_results)
        self._risk_score  = self._detector.get_risk_score(detection_results)
        self._confidence  = self._detector.get_confidence_level(detection_results)
        self._generated   = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC: Get verdict string
    # ─────────────────────────────────────────────────────────────────────────

    def get_verdict(self) -> str:
        """Return the computed forensic verdict string."""
        return self._verdict

    # ─────────────────────────────────────────────────────────────────────────
    # OUTPUT 1: Console Forensic Report
    # ─────────────────────────────────────────────────────────────────────────

    def generate_console_report(self):
        """Print the complete forensic report to stdout."""

        W = 70  # Report width

        def _safe(text):
            """Ensure text is printable on Windows cp1252."""
            return (str(text)
                    .replace('\u2192', '->')
                    .replace('\u2190', '<-')
                    .replace('\u2500', '-')
                    .replace('\u2550', '=')
                    .replace('\u2014', '--')
                    .replace('\u2013', '-')
                    .replace('\u2022', '*')
                    .replace('\u26a0', '[!]')
                    .replace('\u2713', '[OK]')
                    .replace('\u25cc', '[ ]')
                    .replace('\u21b3', '>')
                    .encode('ascii', errors='replace')
                    .decode('ascii'))

        def sprint(text=""):
            """Safe print wrapper."""
            print(_safe(text))

        def sep(char="-"):
            sprint(char * W)

        def hdr(text):
            sprint(f"\n{'=' * W}")
            sprint(f"  {text}")
            sprint(f"{'=' * W}")

        def sub(text):
            sprint(f"\n  -- {text} --")

        # -- Report Header ---------------------------------------------------
        sprint("")
        sep("=")
        sprint(" " * 10 + "LOCASHIELD FORENSIC EXAMINATION REPORT")
        sprint(" " * 10 + "Multi-Layer Forensic Correlation Engine")
        sep("=")
        sprint(f"  Report Generated : {self._generated}")
        sprint(f"  Tool Version     : LocaShield v2.0.0")
        sprint(f"  Evidence Root    : {self.output_dir}")
        sprint(f"  Risk Score       : {self._risk_score}/225")
        sprint(f"  Confidence Level : {self._confidence.upper()}")
        sep()

        # -- Section A: Executive Summary ------------------------------------
        hdr("SECTION A -- EXECUTIVE SUMMARY")
        flag_count = sum(1 for r in self.results.values() if r['flagged'])
        total_checks = len(self.results)
        available_checks = sum(1 for r in self.results.values() if r.get('available', True))
        unavailable = [n for n, r in self.results.items() if not r.get('available', True)]
        sprint(f"""
  Forensic examination of the acquired Android device artefacts identified
  {flag_count} of {total_checks} independent spoofing indicators ({available_checks} checks had data).

  EVIDENCE SCORING MATRIX:
    Risk Score       : {self._risk_score} / 225
    Confidence Level : {self._confidence.upper()}
    Checks Flagged   : {flag_count}
    Data Available   : {available_checks} / {total_checks}

  VERDICT: {self._verdict}
""")
        if unavailable:
            sprint(f"  [!] Checks with unavailable data: {', '.join(unavailable)}")
        sep()

        # -- Section B: Detection Check Results ------------------------------
        hdr("SECTION B -- DETECTION CHECK RESULTS")

        for check_name, result in self.results.items():
            if not result.get('available', True):
                flag_str = "-- N/A    "
            elif result['flagged']:
                flag_str = "!! FLAGGED"
            else:
                flag_str = "OK CLEAR  "

            conf = result.get('confidence', 'none')
            weight = result.get('weight', 0)
            sprint(f"\n  [{flag_str}] {check_name}  (weight: {weight}, confidence: {conf})")
            sprint(f"  {'-' * 50}")
            sprint(f"  Summary : {result['summary']}")

            if result['evidence']:
                sprint(f"  Evidence:")
                for ev in result['evidence']:
                    words = ev
                    sprint(f"    * {words[:100]}")
                    if len(words) > 100:
                        sprint(f"      {words[100:200]}")
                    if len(words) > 200:
                        sprint(f"      {words[200:]}")

        sep()

        # -- Section C: Timeline Summary (first 20 + all suspicious) --------
        hdr("SECTION C -- RECONSTRUCTED TIMELINE (SUSPICIOUS EVENTS)")

        # Print header
        sprint(f"\n  {'TIMESTAMP (UTC)':<26} {'SOURCE':<28} {'EVENT TYPE':<28} SUSP")
        sprint(f"  {'-'*24} {'-'*26} {'-'*26} {'-'*5}")

        suspicious_shown = 0
        for event in self.timeline:
            if event.get('suspicious'):
                flag = " [!]"
            else:
                flag = ""

            src_short   = event['source'][:26]
            etype_short = event['event_type'][:26]
            ts          = event['ts_utc'][:24]

            sprint(f"  {ts:<26} {src_short:<28} {etype_short:<28}{flag}")

            # Print description indented below
            desc = event['description']
            if len(desc) > 90:
                sprint(f"      > {desc[:90]}")
                sprint(f"        {desc[90:180]}")
            else:
                sprint(f"      > {desc}")

            if event.get('suspicious'):
                suspicious_shown += 1

        total = len(self.timeline)
        susp  = sum(1 for e in self.timeline if e.get('suspicious'))
        sprint(f"\n  Total events in timeline : {total}")
        sprint(f"  Suspicious events        : {susp}")
        sep()

        # -- Section D: Key Forensic Findings --------------------------------
        hdr("SECTION D -- KEY FORENSIC FINDINGS")

        # GPS impossible travel
        gps_result = self.results.get("Impossible Travel Speed", {})
        if gps_result.get('flagged'):
            sprint("\n  FINDING 1 -- Impossible GPS Coordinate Jump")
            sprint("  " + "-" * 50)
            for ev in gps_result.get('evidence', []):
                sprint(f"  {ev[:100]}")

        # Cell contradiction
        cell_result = self.results.get("Cell Tower Contradiction", {})
        if cell_result.get('flagged'):
            sprint("\n  FINDING 2 -- Cell Tower / GPS Geographic Contradiction")
            sprint("  " + "-" * 50)
            for ev in cell_result.get('evidence', []):
                sprint(f"  {ev[:100]}")

        sep()

        # -- Section E: Conclusion -------------------------------------------
        hdr("SECTION E -- CONCLUSION")
        sprint(f"""
  Based on the forensic examination of the acquired Android artefacts, and
  the application of established digital forensic analysis methodology, this
  examiner concludes:

  1. GPS location data recorded on the examined device during the identified
     period does NOT represent the device's true physical location.

  2. The observed artefact pattern -- encompassing spoofing application
     installation, mock location API activation, physically impossible GPS
     coordinate transitions, and cell tower geographic contradictions -- is
     consistent with deliberate, intentional GPS location falsification.

  3. No viable alternative hypothesis (device malfunction, synchronisation
     error, legitimate developer usage) can account for the totality of the
     evidence without invoking multiple independent improbable failures.

  FORENSIC VERDICT:
  {self._verdict}

  Examiner Declaration: Findings are based solely on artefact evidence and
  established forensic methodology. This report is suitable for expert
  witness testimony in appropriate academic or legal proceedings.
""")
        sep("=")


    # ─────────────────────────────────────────────────────────────────────────
    # OUTPUT 2: JSON Report (for dashboard upload)
    # ─────────────────────────────────────────────────────────────────────────

    def generate_json_report(self) -> str:
        """
        Write a structured JSON report suitable for upload to the
        LocaShield web dashboard.

        Returns the path to the written JSON file.
        """
        import re
        json_path = os.path.join(self.output_dir, "forensic_report.json")

        flag_count = sum(1 for r in self.results.values() if r["flagged"])
        susp_count = sum(1 for e in self.timeline if e.get("suspicious"))

        # indicators
        indicators = []
        for name, result in self.results.items():
            indicators.append({
                "name":       name,
                "flagged":    result["flagged"],
                "weight":     result.get("weight", 0),
                "confidence": result.get("confidence", "none"),
                "available":  result.get("available", True),
                "summary":    result["summary"],
                "evidence":   result.get("evidence", []),
            })

        # timeline (deduplicated by ts_ms + event_type + first 60 chars of description)
        seen = set()
        timeline_rows = []
        for event in self.timeline:
            key = (event.get("ts_ms"), event.get("event_type"), event.get("description", "")[:60])
            if key in seen:
                continue
            seen.add(key)
            timeline_rows.append({
                "ts_utc":      event.get("ts_utc", ""),
                "ts_ms":       event.get("ts_ms", 0),
                "source":      event.get("source", ""),
                "event_type":  event.get("event_type", ""),
                "description": event.get("description", ""),
                "suspicious":  bool(event.get("suspicious")),
                "lat":         event.get("lat") or None,
                "lng":         event.get("lng") or None,
            })

        # spoofing apps
        apps = []
        for app in self.data.get("spoofing_apps", []):
            apps.append({
                "package":      app.get("package", ""),
                "name":         app.get("name", ""),
                "installed_at": app.get("installed_at", ""),
            })

        # cell contradictions parsed from evidence strings
        cell_result = self.results.get("Cell Tower Contradiction", {})
        seen_contra = set()
        unique_contradictions = []
        for ev_str in cell_result.get("evidence", []):
            m = re.match(
                r"CONTRADICTION at (.+?):\s+GPS reports \(([0-9.\-]+),([0-9.\-]+)\)"
                r".*?CID=(\d+) resolves to \'([^\']+)\' \(([0-9.\-]+),([0-9.\-]+)\)"
                r".*?Separation: ([0-9.]+) km",
                ev_str
            )
            if m:
                key = (m.group(1).strip(), m.group(4), m.group(2), m.group(3))
                if key not in seen_contra:
                    seen_contra.add(key)
                    unique_contradictions.append({
                        "ts_utc":        m.group(1).strip(),
                        "gps_lat":       float(m.group(2)),
                        "gps_lng":       float(m.group(3)),
                        "cid":           int(m.group(4)),
                        "cell_city":     m.group(5),
                        "cell_lat":      float(m.group(6)),
                        "cell_lng":      float(m.group(7)),
                        "separation_km": float(m.group(8)),
                    })

        report = {
            "meta": {
                "tool":         "LocaShield v2.0.0",
                "generated_at": self._generated,
                "output_dir":   self.output_dir,
            },
            "summary": {
                "indicators_confirmed":   flag_count,
                "total_indicators":       len(self.results),
                "suspicious_event_count": susp_count,
                "risk_score":             self._risk_score,
                "max_score":              225,
                "confidence":             self._confidence,
                "verdict":                self._verdict,
            },
            "indicators":          indicators,
            "timeline":            timeline_rows,
            "spoofing_apps":       apps,
            "cell_contradictions": unique_contradictions,
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return json_path

    # ─────────────────────────────────────────────────────────────────────────
    # OUTPUT 2: CSV Timeline
    # ─────────────────────────────────────────────────────────────────────────

    def generate_csv_timeline(self) -> str:
        """
        Write the complete event timeline to a CSV file.
        Includes all fields: timestamp, source, event_type, description,
        suspicious flag, latitude, longitude.

        Returns the path to the written CSV file.
        """
        csv_path = os.path.join(self.output_dir, "forensic_timeline.csv")

        fieldnames = [
            "timestamp_utc",
            "timestamp_ms",
            "source",
            "event_type",
            "description",
            "suspicious",
            "latitude",
            "longitude",
        ]

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for event in self.timeline:
                writer.writerow({
                    "timestamp_utc" : event.get('ts_utc', ''),
                    "timestamp_ms"  : event.get('ts_ms', ''),
                    "source"        : event.get('source', ''),
                    "event_type"    : event.get('event_type', ''),
                    "description"   : event.get('description', ''),
                    "suspicious"    : "YES" if event.get('suspicious') else "NO",
                    "latitude"      : event.get('lat', ''),
                    "longitude"     : event.get('lng', ''),
                })

        return csv_path

    # ─────────────────────────────────────────────────────────────────────────
    # OUTPUT 3: Text Report File
    # ─────────────────────────────────────────────────────────────────────────

    def generate_text_report(self) -> str:
        """
        Write a structured forensic report text file suitable for
        submission or court disclosure.

        Returns the path to the written text file.
        """
        txt_path = os.path.join(self.output_dir, "forensic_report.txt")

        flag_count = sum(1 for r in self.results.values() if r['flagged'])
        susp_count = sum(1 for e in self.timeline if e.get('suspicious'))

        with open(txt_path, "w", encoding="utf-8") as f:

            def w(line=""):
                f.write(line + "\n")

            # ── Cover ────────────────────────────────────────────────────
            w("=" * 70)
            w("  LOCASHIELD FORENSIC EXAMINATION REPORT")
            w("  Forensic Detection and Timeline Reconstruction")
            w("  of GPS Spoofing on Android Devices")
            w("=" * 70)
            w(f"  Report Date     : {self._generated}")
            w(f"  Tool            : LocaShield v2.0.0")
            w(f"  Output Directory: {self.output_dir}")
            w("=" * 70)
            w()

            # ── A: Executive Summary ──────────────────────────────────────
            w("SECTION A — EXECUTIVE SUMMARY")
            w("─" * 40)
            w(f"Detection indicators confirmed : {flag_count} / {len(self.results)}")
            w(f"Suspicious timeline events     : {susp_count}")
            w(f"Evidence risk score            : {self._risk_score} / 225")
            w(f"Confidence level               : {self._confidence.upper()}")
            w(f"Forensic verdict               : {self._verdict}")
            w()

            # ── B: Detection Results ──────────────────────────────────────
            w("SECTION B — DETECTION CHECK RESULTS")
            w("─" * 40)
            for check_name, result in self.results.items():
                if not result.get('available', True):
                    status = "N/A"
                elif result['flagged']:
                    status = "FLAGGED"
                else:
                    status = "CLEAR"
                conf = result.get('confidence', 'none')
                weight = result.get('weight', 0)
                w(f"\n[{status}] {check_name}  (weight: {weight}, confidence: {conf})")
                w(f"  Summary : {result['summary']}")
                if result['evidence']:
                    w("  Evidence:")
                    for ev in result['evidence']:
                        w(f"    - {ev}")
            w()

            # ── C: Full Timeline ─────────────────────────────────────────
            w("SECTION C — COMPLETE FORENSIC TIMELINE")
            w("─" * 40)
            w(f"{'TIMESTAMP (UTC)':<26}  {'EVENT TYPE':<28}  {'SOURCE':<28}  SUSPICIOUS")
            w(f"{'─'*24}  {'─'*26}  {'─'*26}  {'─'*9}")

            for event in self.timeline:
                suspicious_str = "YES ⚠" if event.get('suspicious') else "no"
                w(
                    f"{event['ts_utc']:<26}  "
                    f"{event['event_type']:<28}  "
                    f"{event['source']:<28}  "
                    f"{suspicious_str}"
                )
                w(f"    Description: {event['description'][:120]}")
                if event.get('lat'):
                    w(f"    Coordinates: ({event['lat']:.4f}, {event['lng']:.4f})")
            w()

            # ── D: Conclusion ─────────────────────────────────────────────
            w("SECTION D — CONCLUSION AND EXAMINER DECLARATION")
            w("─" * 40)
            w()
            w("Based on forensic examination of the acquired Android artefacts,")
            w("this examiner concludes that the GPS location data recorded on")
            w("the examined device during the identified period was deliberately")
            w("falsified using a third-party mock location application.")
            w()
            w(f"VERDICT: {self._verdict}")
            w()
            w("Examiner Declaration:")
            w("I declare that the facts stated in this report are based solely")
            w("on the forensic artefacts analysed using documented methodology.")
            w("I have indicated where findings are matters of inference.")
            w()
            w("Signature: _________________________  Date: __________________")
            w()
            w("=" * 70)
            w("                        END OF REPORT")
            w("=" * 70)

        return txt_path

    # ─────────────────────────────────────────────────────────────────────────
    # OUTPUT 4: Evidence Integrity Manifest (SHA-256 Verification)
    # ─────────────────────────────────────────────────────────────────────────

    def generate_integrity_manifest(self) -> str:
        """
        Generate a SHA-256 integrity manifest for all forensic output files.
        This provides cryptographic verification signatures for evidence
        preservation and chain of custody documentation.

        Returns the path to the written manifest file.
        """
        manifest_path = os.path.join(self.output_dir, "INTEGRITY_MANIFEST.txt")
        output_files = []

        # Collect all forensic output files in the output directory
        for fname in os.listdir(self.output_dir):
            fpath = os.path.join(self.output_dir, fname)
            if os.path.isfile(fpath) and fname != "INTEGRITY_MANIFEST.txt":
                output_files.append(fpath)

        # Also check acquisition subdirectory
        acq_dir = os.path.join(self.output_dir, "acquisition")
        if os.path.isdir(acq_dir):
            for root_dir, _, files in os.walk(acq_dir):
                for fname in files:
                    output_files.append(os.path.join(root_dir, fname))

        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("  EVIDENCE INTEGRITY MANIFEST\n")
            f.write("  LocaShield v2.0.0\n")
            f.write("=" * 70 + "\n")
            f.write(f"  Generated    : {self._generated}\n")
            f.write(f"  Output Dir   : {self.output_dir}\n")
            f.write(f"  Verdict      : {self._verdict}\n")
            f.write(f"  Files Hashed : {len(output_files)}\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"{'SHA-256 Hash':<66}  File\n")
            f.write(f"{'─' * 64}  {'─' * 40}\n")

            for fpath in sorted(output_files):
                sha256 = self._sha256_file(fpath)
                rel_path = os.path.relpath(fpath, self.output_dir)
                f.write(f"{sha256}  {rel_path}\n")

            f.write("\n" + "=" * 70 + "\n")
            f.write("  EXAMINER DECLARATION\n")
            f.write("─" * 70 + "\n")
            f.write("  I certify that the SHA-256 hashes above were computed at the\n")
            f.write("  time of report generation and accurately represent the contents\n")
            f.write("  of each file. Any modification to the files after this timestamp\n")
            f.write("  will result in a hash mismatch.\n\n")
            f.write("  Signature: _________________________  Date: __________________\n")
            f.write("=" * 70 + "\n")

        return manifest_path

    @staticmethod
    def _sha256_file(filepath: str) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
