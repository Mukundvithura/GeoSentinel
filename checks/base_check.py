#!/usr/bin/env python3
"""
=============================================================================
Module  : checks/base_check.py
Purpose : Abstract base class for all detection check plugins.
          Every check returns a standardised result dict with:
            - name       : str   — Human-readable check name
            - flagged    : bool  — True if indicator detected
            - weight     : int   — Evidence scoring weight (0–100 scale)
            - confidence : str   — 'low' | 'medium' | 'high'
            - summary    : str   — One-line human-readable result
            - evidence   : list  — List of evidence strings
            - available  : bool  — False if data was unavailable (device restrictions)
=============================================================================
"""

from abc import ABC, abstractmethod


class BaseCheck(ABC):
    """Abstract base class for all forensic detection checks."""

    # Subclasses MUST override these
    NAME   = "Unnamed Check"
    WEIGHT = 0   # Evidence score contribution (0–100)

    def __init__(self, parsed_data: dict, verbose: bool = False, **kwargs):
        self.data    = parsed_data
        self.verbose = verbose
        self.kwargs  = kwargs

    def _dbg(self, msg: str):
        """Print debug message if verbose mode is on."""
        if self.verbose:
            print(f"    [DBG:{self.NAME}] {msg}")

    @abstractmethod
    def run(self) -> dict:
        """
        Execute the check and return a standardised result dict.

        Returns:
            {
                'name'       : str,
                'flagged'    : bool,
                'weight'     : int,
                'confidence' : 'low' | 'medium' | 'high' | 'none',
                'summary'    : str,
                'evidence'   : [str, ...],
                'available'  : bool,
            }
        """
        ...

    def _result(
        self,
        flagged: bool,
        summary: str,
        evidence: list,
        confidence: str = 'none',
        available: bool = True,
    ) -> dict:
        """Build a standardised result dictionary."""
        return {
            'name'       : self.NAME,
            'flagged'    : flagged,
            'weight'     : self.WEIGHT if flagged else 0,
            'confidence' : confidence if flagged else 'none',
            'summary'    : summary,
            'evidence'   : evidence,
            'available'  : available,
        }

    def _unavailable(self, reason: str) -> dict:
        """Return a result indicating data was unavailable."""
        return self._result(
            flagged    = False,
            summary    = f"Evidence unavailable: {reason}",
            evidence   = [f"Evidence unavailable due to device restrictions: {reason}"],
            confidence = 'none',
            available  = False,
        )
