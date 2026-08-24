"""Public re-exports for the access_log analyzer package.

The legacy flat module `src/alma_audit/analyzers/access_log.py` exposed:
    AccessRecord, AccessAggregator, parse_line, analyze_access_logs
plus the constants SUSPICIOUS_PATH_PATTERNS, SAFE_METHODS, DEFAULT_RULES.

This package preserves the exact same import surface so existing
callers (`runner.py` and the test suite under `tests/`) need no
changes. The 1000-line ceiling in `docs/GAPS.md` §7 forced the split
into parser / aggregator / settings / suppression / rules / analyzer.

Layout:
    parser.py       — line → AccessRecord (or None)
    aggregator.py   — streaming state machine + probe patterns + safe methods
    settings.py     — DEFAULT_RULES thresholds + compressed-suffix list
    suppression.py  — never-raises wrapper around the §6.1 crawler chain
    rules.py        — D1/D4/D2/D5 detection rules → list[Finding]
    analyzer.py     — orchestrator: `analyze_access_logs` public entry

Read `docs/GAPS.md` §7.3 for why this split.
"""

from __future__ import annotations

from .aggregator import SAFE_METHODS, SUSPICIOUS_PATH_PATTERNS, AccessAggregator
from .analyzer import analyze_access_logs
from .parser import AccessRecord, parse_line
from .settings import DEFAULT_RULES

__all__ = [
    # Public entry point
    "analyze_access_logs",
    # Parser surface
    "AccessRecord",
    "parse_line",
    # Aggregator surface
    "AccessAggregator",
    "SUSPICIOUS_PATH_PATTERNS",
    "SAFE_METHODS",
    # Settings (re-exported for tests / config that used to grab them)
    "DEFAULT_RULES",
]