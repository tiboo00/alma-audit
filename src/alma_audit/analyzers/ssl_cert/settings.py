"""Defaults for the ssl_cert analyzer — thresholds and glob roots.

Operators override these via the YAML config (`modules.ssl_cert.*`).
The single source of truth lives here so a `grep default_settings` finds
every threshold in one place.
"""

from __future__ import annotations

from typing import Any


# Default rule thresholds. Operators can override per-config.
DEFAULT_RULES: dict[str, Any] = {
    # Certificates expiring within this many days → WARN.
    "expiry_warn_days": 14,
    # Within this many days → CRITICAL.
    "expiry_crit_days": 3,
    # Files matched per scan (defensive against huge cert dirs).
    "max_files": 200,
}


# Default glob roots for the ssl_cert analyzer. The first root that
# exists on the host wins; if NONE of them exist, the analyzer emits a
# single INFO "no certificate directory found" finding (which is the
# expected outcome on a non-cPanel / non-TLS host).
#
# Operators can override via `paths.ssl_cert_glob` in the YAML config —
# they append to or replace this list.
SSL_CERT_GLOB_ROOTS: list[str] = [
    "/var/cpanel/ssl",
    "/etc/pki/tls/certs",
    "/etc/ssl/certs",
]