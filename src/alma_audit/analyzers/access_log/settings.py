"""Defaults for the access_log analyzer — thresholds and file-shape rules.

Operators override these via the YAML config (`modules.access_log.*`).
The single source of truth lives here so a `grep default_settings` finds
every threshold in one place.
"""

from __future__ import annotations

from typing import Any


# Default rule thresholds. Operators can override per-config.
DEFAULT_RULES: dict[str, Any] = {
    "top_host_share_warn": 0.30,        # >30% of traffic from one IP → WARN
    "top_host_share_crit": 0.70,        # >70% → CRITICAL
    "error_rate_warn": 0.05,            # >5% 4xx/5xx → WARN
    "error_rate_crit": 0.20,            # >20% → CRITICAL
    "probe_count_warn": 10,             # ≥10 probe hits → WARN
    "probe_count_crit": 100,            # ≥100 → CRITICAL
    "weird_method_count_warn": 5,
    "max_files_scanned": 50,
    "max_lines_per_file": 200_000,
}


# Rotated access logs may include compressed copies of older bytes
# (`.gz`, `.bz2`, `.xz`, `.zst`). The runners layer already filters
# those out for the read-only contract — this list is consulted at
# analyzer level too, so a test scenario that bypasses the layer
# still behaves the same way.
_COMPRESSED_SUFFIXES = (".gz", ".bz2", ".xz", ".zst", ".lz4")


def is_compressed(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in _COMPRESSED_SUFFIXES)