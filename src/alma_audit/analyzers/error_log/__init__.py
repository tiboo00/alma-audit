"""Public re-exports for the ``error_log`` analyzer package (AISO-211).

Parses Apache's ``/var/log/apache2/error_log*`` (the per-line module
+ PID + client IP log) and surfaces:

  - **Per-client error counts** — top 10 clients by error count, in
    the summary finding.
  - **Top error message templates** — ``<module>:<level>: <truncated
    body>`` keys, so the operator can see which kinds of failures
    are accumulating.
  - **Per-(client, template) bursts** — a single host repeating the
    same message >= ``message_burst_crit`` (default 100) fires a
    CRITICAL finding. This is the AISO-211 §3 contract signature for
    mpm_prefork OOM loops, repeated SSL handshake failures, or
    scripted 404-spam probes.

The analyzer is OPT-IN via ``modules.error_log.enabled: true``. The
default is OFF to preserve the audit's scope for hosts that don't
have an ``error_log`` (or operators who haven't explicitly opted in).
The analyzer never emits an INFO "module is disabled" finding —
absence is silent.

Layout (per GAPS §7.3 standard pattern):

    parser.py      — line → ErrorLogRecord (or None)
    aggregator.py  — per-client / per-template streaming counters
    rules.py       — summary + per-burst detection rules
    settings.py    — DEFAULT_RULES thresholds + compressed-suffix list
    analyzer.py    — public ``analyze_error_log`` orchestrator

All five modules stay well under the 1000-line ceiling.
"""

from __future__ import annotations

from .aggregator import ErrorAggregator
from .analyzer import analyze_error_log
from .parser import ErrorLogRecord, parse_error_line
from .settings import DEFAULT_RULES

__all__ = [
    # Public entry point
    "analyze_error_log",
    # Parser surface
    "ErrorLogRecord",
    "parse_error_line",
    # Aggregator surface
    "ErrorAggregator",
    # Settings (re-exported for tests / config that used to grab them)
    "DEFAULT_RULES",
]