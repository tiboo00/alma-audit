"""Defaults for the secure_log analyzer — thresholds and glob patterns.

Operators override these via the YAML config (`modules.secure_log.*`).
The single source of truth lives here so a `grep default_settings` finds
every threshold in one place.
"""

from __future__ import annotations

from typing import Any


# Default rule thresholds. Operators can override per-config.
DEFAULT_RULES: dict[str, Any] = {
    # SSH brute-force burst from a single source.
    "ssh_fail_warn": 5,        # >= 5 failed passwords in window → WARN
    "ssh_fail_crit": 20,       # >= 20 → CRITICAL
    # AISO-203: separate threshold pair for username enumeration
    # (`Invalid user X from <ip>`). Operators with a known scanner
    # landscape (masscan / research / a friendly bot) raise this bar
    # so the per-IP brute-force rule doesn't page on a normal
    # username-enumeration pass. Defaults mirror the ssh_fail pair.
    "ssh_invalid_user_warn": 5,
    "ssh_invalid_user_crit": 20,
    # sudo authentication failure burst from a single user.
    "sudo_fail_warn": 3,
    "sudo_fail_crit": 10,
    # A useradd / groupadd that creates a UID=0 account is always CRITICAL.
    # This rule has no warn/crit; the rule itself decides severity by the
    # UID value.
    "new_root_account_enabled": True,
    # How many files at most to scan (defensive against huge logs).
    "max_files": 20,
    # Per-file line cap. 0 = no cap. Default: 200,000.
    "max_lines_per_file": 200_000,
}


# Default glob patterns for the secure log. RHEL uses `/var/log/secure*`
# (rotated copies become `secure.1`, `secure-20260801`, etc.), Debian
# uses `/var/log/auth.log*`. We default to both roots because alma-audit
# is meant to run on either family. Operators can override either glob
# via the YAML config (`paths.secure_log_glob`, `paths.auth_log_glob`).
SECURE_LOG_GLOBS: dict[str, list[str]] = {
    "secure": ["secure", "secure.*", "secure-*"],
    "auth": ["auth.log", "auth.log.*", "auth.log-*"],
}


# Rotated copies may include compressed archives (`.gz`, `.bz2`, `.xz`,
# `.zst`). The runners layer already filters those out for the read-only
# contract — this list is consulted at analyzer level too, so a test
# scenario that bypasses the layer still behaves the same way.
_COMPRESSED_SUFFIXES = (".gz", ".bz2", ".xz", ".zst", ".lz4")


def is_compressed(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in _COMPRESSED_SUFFIXES)