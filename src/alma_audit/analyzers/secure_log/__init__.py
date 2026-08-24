"""Public re-exports for the secure_log analyzer package.

Parses `/var/log/secure*` (RHEL family) and `/var/log/auth.log*`
(Debian family). Detects:

  - **Failed SSH authentications** (Failed password for ... / Failed
    none / Authentication failed for ...). Bursts of >= `ssh_fail_warn`
    from a single source within the scan window escalate to WARN/CRITICAL.
  - **`useradd` / `groupadd` events** creating new accounts mid-run
    (CRITICAL if the new UID/GID is 0 — i.e. root-level).
  - **sudo authentication failures** (`pam_unix(sudo:auth):
    authentication failure`); bursts of >= `sudo_fail_warn` from a
    single user escalate to WARN.

The analyzer emits INFO findings for every well-formed line that was
classified (scan summary), plus structured WARN/CRITICAL findings for
the threshold breaches. It does NOT shell out; it uses the injected
`FileSystem` so the read-only contract holds. An unreadable / missing
log root produces an INFO finding rather than an exception.

Layout (per GAPS §7.3 standard pattern):
    parser.py      — line → SecureRecord
    aggregator.py  — streaming counters + per-key burst tracking
    rules.py       — detection rules → list[Finding]
    settings.py    — DEFAULT_RULES thresholds + glob list
    analyzer.py    — public `analyze_secure_logs` orchestrator

All five modules stay well under the 1000-line ceiling; the largest is
the orchestrator (~80 LOC). Tests live in `tests/test_secure_log.py`.
"""

from __future__ import annotations

from .analyzer import analyze_secure_logs
from .aggregator import SecureAggregator
from .parser import SecureRecord, parse_line
from .settings import DEFAULT_RULES, SECURE_LOG_GLOBS

__all__ = [
    "analyze_secure_logs",
    "SecureRecord",
    "SecureAggregator",
    "parse_line",
    "DEFAULT_RULES",
    "SECURE_LOG_GLOBS",
]