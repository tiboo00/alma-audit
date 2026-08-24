"""Defaults for the cphulk_log analyzer — thresholds and glob patterns.

Operators override these via the YAML config (`modules.cphulk_log.*`).
The single source of truth lives here so a `grep default_settings` finds
every threshold in one place.
"""

from __future__ import annotations

from typing import Any


# Default rule thresholds. Operators can override per-config.
DEFAULT_RULES: dict[str, Any] = {
    # Brute-force bursts from a single IP.
    "brute_force_warn": 5,
    "brute_force_crit": 20,
    # Brute-force bursts against a single username.
    "brute_force_user_warn": 5,
    "brute_force_user_crit": 20,
    # Files matched per scan (defensive against huge logs).
    "max_files": 10,
    # Per-file line cap. 0 = no cap. Default: 200,000.
    "max_lines_per_file": 200_000,
}


# Default glob pattern for the cPHulk log. The cPanel default path is
# `/var/log/cphulkd.log`; rotations append `.1`, `.2`, etc.
CPHULK_LOG_GLOB: list[str] = ["cphulkd.log", "cphulkd.log.*", "cphulkd.log-*"]


# Rotated copies may include compressed archives (`.gz`, `.bz2`, `.xz`,
# `.zst`). The runners layer already filters those out for the read-only
# contract — this list is consulted at analyzer level too, so a test
# scenario that bypasses the layer still behaves the same way.
_COMPRESSED_SUFFIXES = (".gz", ".bz2", ".xz", ".zst", ".lz4")


def is_compressed(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in _COMPRESSED_SUFFIXES)