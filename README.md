# GeoSentinel — Advanced GPS Spoofing Forensic Detection Engine

> A modular Android forensic platform that detects GPS spoofing attacks using
> **multi-artifact correlation** across system logs, app behaviour, EXIF metadata,
> sensor telemetry, GNSS anomalies, and evidence integrity verification.

---

## Why This Exists

GPS spoofing is actively weaponised in:

- **Ride-sharing fraud** — drivers faking routes and locations
- **Fake attendance systems** — employees clocking in remotely
- **Delivery & insurance fraud** — falsified location trails
- **False legal alibis** — fabricated digital-evidence chains
- **Location-based app abuse** — games, banking, compliance bypasses

Traditional tools rely on mock-location flags and fail against advanced attackers using rooted devices, automation frameworks (Tasker, Frida), and GNSS hardware simulators.

**GeoSentinel solves this by correlating 11 independent forensic signals** — so even when individual indicators are suppressed, the composite evidence picture survives.

---

## Architecture

```
ADB Acquisition / Offline Forensic Dump
              │
              ▼
      ┌───────────────┐
      │  adb_acquire  │  Live device pull  OR  offline dump ingest
      └──────┬────────┘
             │
             ▼
      ┌───────────────┐
      │   parsers.py  │  Artifact extraction: logcat, GNSS, EXIF,
      └──────┬────────┘  sensor telemetry, SQLite DBs, XML settings
             │
             ▼
      ┌────────────────────────────────────────────────────────┐
      │                   Detection Engine                      │
      │  checks/  — 11 weighted, independent forensic modules  │
      └──────────────────────┬─────────────────────────────────┘
                             │
             ┌───────────────┼───────────────┐
             ▼               ▼               ▼
     Composite Score   Timeline Recon   Integrity Manifest
             │               │               │
             └───────────────▼───────────────┘
                      ┌─────────────┐
                      │  report.py  │  Console / JSON / TXT / CSV
                      └──────┬──────┘
                             │
                             ▼
                    dashboard.html
               (offline, browser-native)
```

---

## Detection Modules

| Module | Weight | Detection Vector |
|---|:---:|---|
| Mock Location Setting | 15 | Developer Options & mock app designation |
| Spoofing App Installed | 15 | 10+ known spoofing packages (FakeGPS, Lexa, etc.) |
| Impossible Travel Speed | 30 | Haversine distance — physically unreachable velocity |
| Cell Tower Contradiction | 25 | GPS coordinates vs cell tower geolocation mismatch |
| Logcat Mock Events | 20 | System-level `MockProvider` log injection |
| Anti-Forensics Signals | 10 | Out-of-order timestamps, recording gaps |
| Root / Hooking Indicators | 10 | Magisk, SuperSU, Xposed, Frida presence |
| App Behavioral Attribution | 15 | Foreground app correlation with spoofing events |
| EXIF Media Correlation | 20 | Photo GPS metadata vs device GPS timeline |
| Sensor Contradiction | **40** | Accelerometer / step counter vs GPS velocity |
| GNSS Signal Analysis | **35** | SNR uniformity, constellation diversity, SDR artifacts |
| **Maximum Score** | **235** | |

### Verdict Thresholds

| Score | Verdict |
|---|---|
| 0 | No Evidence |
| 1 – 30 | Low Confidence |
| 31 – 60 | Medium Confidence |
| 61 – 100 | High Confidence |
| **100+** | **Critical — Conclusive Evidence** |

---

## Quick Start

**Demo mode** (no device required — dynamically generates a synthetic dataset):
```bash
python main.py --mode demo --output ./out
```

**Live device** (ADB connected):
```bash
python main.py --mode live --output ./evidence
```

**Offline forensic dump** (pre-acquired directory):
```bash
python main.py --mode offline --dump-path ./dump --output ./evidence
```

**Dashboard:**
1. Run the tool → generates `forensic_report.json`
2. Open `dashboard.html` in any browser
3. Upload the JSON file — renders instantly, **fully offline**

---

## Sample Output

```
======================================================================
  LOCASHIELD FORENSIC EXAMINATION REPORT
  Multi-Layer Forensic Correlation Engine
======================================================================
  Report Date     : 2026-04-29 09:31:24 UTC
  Tool Version     : LocaShield v2.0.0
  Evidence Root    : ./out
  Risk Score       : 185/225
  Confidence Level : CRITICAL
======================================================================

SECTION A -- EXECUTIVE SUMMARY
======================================================================

  Forensic examination of the acquired Android device artefacts identified
  8 of 11 independent spoofing indicators (11 checks had data).

  EVIDENCE SCORING MATRIX:
    Risk Score       : 185 / 225
    Confidence Level : CRITICAL
    Checks Flagged   : 8
    Data Available   : 11 / 11

  VERDICT: CRITICAL -- CONCLUSIVE EVIDENCE OF GPS SPOOFING (8/11 indicators, Risk Score: 185/225)
```

---

## Output Files

| File | Format | Purpose |
|---|---|---|
| `forensic_report.json` | JSON | Dashboard data + programmatic consumption |
| `forensic_report.txt` | TXT | Court-appropriate narrative report |
| `forensic_timeline.csv` | CSV | Importable into Excel, Autopsy, Cellebrite |
| `INTEGRITY_MANIFEST.txt` | TXT | SHA-256 hashes for all generated forensic output files |
| `acquisition/CHAIN_OF_CUSTODY_HASHES.txt` | TXT | Acquisition-phase integrity log |

---

## Repo Structure

```
GeoSentinel/
├── checks/
│   ├── __init__.py            # Check registry (ALL_CHECKS)
│   ├── base_check.py          # Abstract base — all modules extend this
│   ├── mock_location.py
│   ├── spoofing_app.py
│   ├── impossible_travel.py   # Haversine velocity analysis
│   ├── cell_tower.py
│   ├── logcat_mock.py
│   ├── anti_forensics.py
│   ├── root_indicators.py
│   ├── behavior_check.py
│   ├── exif_check.py
│   ├── sensor_check.py        # Accelerometer + step counter correlation
│   └── gnss_check.py          # SDR / hardware simulator detection
├── main.py                    # Entry point & pipeline orchestrator
├── detector.py                # Plugin orchestrator & verdict engine
├── parsers.py                 # Artifact extraction (logcat, SQLite, XML, JSON)
├── report.py                  # Report generation (Console / JSON / CSV / TXT)
├── timeline.py                # Forensic timeline reconstruction
├── adb_acquire.py             # Live ADB acquisition & demo generator
└── dashboard.html             # Interactive forensic dashboard (offline)
```

---
## Research Extensions

GeoSentinel is designed as a foundation for further academic and applied research into:

- **Sensor replay attacks** — pre-recorded IMU data replayed alongside spoofed GNSS
- **GNSS hardware simulators** — SDR-based signal injection (HackRF, USRP)
- **Root framework evasion** — Magisk DenyList, Zygisk, LSPosed bypass detection
- **Anti-forensics correlation** — detecting deliberate timestamp manipulation
- **Multi-device corroboration** — cross-referencing location claims across devices in a case

This project is extensible toward publication-ready investigation of advanced location fraud scenarios.

---

## Requirements

- Python 3.8+
- No external dependencies (standard library only)
- ADB (for live device mode only)

---

## Suggested GitHub Topics

`cybersecurity` · `digital-forensics` · `android-security` · `python` · `gps-spoofing` · `gnss` · `mobile-forensics` · `incident-response`
