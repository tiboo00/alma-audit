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
    # AISO-204: bandwidth anomaly detection (top bandwidth hog).
    # On a tiny log a single host is mechanically dominant — so the rule
    # applies only when the access_log holds at least this many lines.
    "bandwidth_hog_min_lines": 1000,
    "bandwidth_hog_warn": 0.50,         # ≥50% of total bytes → WARN
    "bandwidth_hog_crit": 0.80,         # ≥80% → CRITICAL
    "max_files_scanned": 50,
    "max_lines_per_file": 200_000,
    # AISO-208 (review fix #2): cap on the per-IP distinct UA list
    # that drives the `top_attackers` rollup. This is purely a UI
    # bound on the operator-eye summary; the per-(path, ip) forensic
    # detail in `probe_by_path_ip` is uncapped (the operator wants
    # the full distribution of UA hits against each probe path). The
    # cap is here to stop the rollup from ballooning into an O(n²)
    # membership scan on UA-diverse per-IP traffic. A value of 0 or
    # negative disables the cap (the operator opts into unbounded
    # cost). Default 5 mirrors the historic post-AISO-197 window.
    "ip_user_agent_cap": 5,
    # AISO-211: filter the host's own IPs out of the access_log
    # per-IP rollups (`top_attackers`, `host_errors_top`, `top_hosts`)
    # so a cPanel server's self-admin-panel noise doesn't drown the
    # real external traffic. The forensic JSON still records the
    # self-IP events for audit. Default ON; flip to False for
    # diagnostic mode (operators investigating self-noise).
    "exclude_self_ips": True,
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