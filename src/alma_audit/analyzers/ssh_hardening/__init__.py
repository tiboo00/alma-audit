"""Public re-exports for the ssh_hardening analyzer package.

Reads ``/etc/ssh/sshd_config`` (and the ``sshd_config.d/*.conf``
drop-ins concatenated in alphabetical order, matching OpenSSH
``Include`` semantics) and emits findings for weak settings:

  - **CRITICAL**: ``PermitRootLogin yes``, ``PermitEmptyPasswords yes``,
    ``Protocol 1`` or ``Protocol 1,2`` (SSH-1 enabled).
  - **WARN**: ``PasswordAuthentication yes`` (no PubkeyAuthentication
    forced), ``Port 22`` (default port), ``MaxAuthTries > 6``,
    ``ClientAliveInterval 0`` (no idle timeout),
    ``LoginGraceTime > 120``, missing ``AllowUsers`` / ``AllowGroups``,
    weak ``Ciphers`` / ``MACs``.
  - **INFO**: ``X11Forwarding yes``, ``PermitRootLogin
    prohibit-password`` (key-only root), ``Protocol 2,1``, no
    ``Banner``.

Unlike the log-driven analyzers, ssh_hardening inspects the
**system configuration** that determines whether those logs are
worth auditing at all. A cPanel host with ``PermitRootLogin yes``
+ ``PasswordAuthentication yes`` is fundamentally broken,
regardless of what ``/var/log/secure`` shows.

Layout (per GAPS §7.3 standard pattern):
    parser.py      — line → SshdDirective, with ``Match`` blocks skipped
    aggregator.py  — last-wins snapshot (drop-ins override main)
    rules.py       — one rule per directive, severity per AISO-209 §3
    settings.py    — DEFAULT_RULES thresholds + known-directive set
    analyzer.py    — public ``analyze_ssh_config`` orchestrator

Tests live in ``tests/test_ssh_hardening.py``.
"""

from __future__ import annotations

from .aggregator import SshdConfigSnapshot, aggregate, finalize
from .analyzer import (
    DEFAULT_SSHD_CONFIG_PATH,
    DEFAULT_SSHD_DROP_IN_DIR,
    analyze_ssh_config,
)
from .parser import SshdDirective, parse_multiple, parse_sshd_config
from .settings import DEFAULT_RULES, WEAK_CIPHERS, WEAK_MACS

__all__ = [
    "analyze_ssh_config",
    "SshdConfigSnapshot",
    "aggregate",
    "finalize",
    "SshdDirective",
    "parse_multiple",
    "parse_sshd_config",
    "DEFAULT_RULES",
    "DEFAULT_SSHD_CONFIG_PATH",
    "DEFAULT_SSHD_DROP_IN_DIR",
    "WEAK_CIPHERS",
    "WEAK_MACS",
]
