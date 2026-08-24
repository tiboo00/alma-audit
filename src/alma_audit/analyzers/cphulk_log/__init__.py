"""Public re-exports for the cphulk_log analyzer package.

Parses `/var/log/cphulkd.log*` (cPanel's cPHulk brute-force detector).
Detects:

  - **Brute-force bursts from a single source IP** (per-IP counter).
    WARN/CRITICAL based on `brute_force_warn` / `brute_force_crit`
    thresholds (per-IP within the scan window).
  - **Brute-force bursts against a single account** (per-user counter).
    WARN/CRITICAL based on the same thresholds applied to the
    username axis.
  - **Account-level blocks** recorded by cPHulk. Each block event is
    surfaced as INFO so operators can correlate with syslog.

cPHulk is the canonical cPanel anti-brute-force daemon. Its log format
is syslog-style with bracketed `[warn]` / `[critical]` / `[info]`
prefixes and the service tag `[cphulkd]` on every line. The parser is
lenient about whitespace and timestamp shape — cPanel's log rotation
breaks timestamps across a few variants (microseconds optional, year
sometimes missing).

Layout (per GAPS §7.3 standard pattern):
    parser.py      — line → CphulkRecord
    aggregator.py  — streaming per-IP + per-user counters
    rules.py       — burst rules + block summary
    settings.py    — DEFAULT_RULES thresholds + glob
    analyzer.py    — public `analyze_cphulk_logs` orchestrator

Tests live in `tests/test_cphulk_log.py`.
"""

from __future__ import annotations

from .analyzer import analyze_cphulk_logs
from .aggregator import CphulkAggregator
from .parser import CphulkLevel, CphulkRecord, parse_line
from .settings import DEFAULT_RULES, CPHULK_LOG_GLOB

__all__ = [
    "analyze_cphulk_logs",
    "CphulkAggregator",
    "CphulkLevel",
    "CphulkRecord",
    "parse_line",
    "DEFAULT_RULES",
    "CPHULK_LOG_GLOB",
]