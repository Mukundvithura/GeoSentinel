#!/usr/bin/env python3
"""
=============================================================================
Package : checks
Purpose : Plugin-based detection check architecture.
          Each check module exposes a class that inherits from BaseCheck
          and implements the `run()` method.
=============================================================================
"""

from checks.base_check import BaseCheck

# All check plugins — import order determines display order in reports
from checks.mock_location    import MockLocationCheck
from checks.spoofing_app     import SpoofingAppCheck
from checks.impossible_travel import ImpossibleTravelCheck
from checks.cell_tower       import CellTowerCheck
from checks.logcat_mock      import LogcatMockCheck
from checks.anti_forensics   import AntiForensicsCheck
from checks.root_indicators  import RootIndicatorsCheck
from checks.behavior_check   import BehaviorCheck
from checks.exif_check       import ExifCheck
from checks.sensor_check     import SensorCheck
from checks.gnss_check       import GNSSCheck


# Registry: ordered list of all check classes for the orchestrator
ALL_CHECKS = [
    MockLocationCheck,
    SpoofingAppCheck,
    ImpossibleTravelCheck,
    CellTowerCheck,
    LogcatMockCheck,
    AntiForensicsCheck,
    RootIndicatorsCheck,
    BehaviorCheck,
    ExifCheck,
    SensorCheck,
    GNSSCheck,
]
