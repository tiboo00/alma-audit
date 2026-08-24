"""Public re-exports for the ssl_cert analyzer package.

Parses PEM-encoded X.509 certificates under the configured glob roots
(`/var/cpanel/ssl/*`, `/etc/pki/tls/certs/*`, etc.) and flags:

  - **Expired certificates** (CRITICAL).
  - **Certificates expiring within `expiry_warn_days`** (WARN).
  - **Certificates expiring within `expiry_crit_days`** (CRITICAL).
  - **Unreadable / malformed certificates** (WARN — operator
    forensics; we never raise).

The analyzer NEVER shells out — it uses the stdlib + the optional
`cryptography` dependency. If `cryptography` is not importable, the
analyzer emits a single WARN finding naming the dependency. Operators
who need it install it via the `ssl` extra (`pip install alma-audit[ssl]`).
The dependency is optional because most cPanel hosts don't run alma-audit
on every box; the cert check is opt-in.

Layout (per GAPS §7.3 standard pattern):
    parser.py      — file → CertInfo (optional decode helper)
    aggregator.py  — currently no-op; CertAggregator kept for future
                     growth (certs-by-CN rollups, etc.)
    rules.py       — expiry + read-error rules
    settings.py    — DEFAULT_RULES thresholds + glob roots
    analyzer.py    — public `analyze_ssl_certs` orchestrator

Tests live in `tests/test_ssl_cert.py`. The `tests/test_readonly.py`
contract test still passes — the analyzer only reads.
"""

from __future__ import annotations

from .aggregator import CertAggregator
from .analyzer import analyze_ssl_certs, cryptography_available
from .parser import CertInfo, parse_pem_cert
from .settings import DEFAULT_RULES, SSL_CERT_GLOB_ROOTS

__all__ = [
    "analyze_ssl_certs",
    "cryptography_available",
    "CertAggregator",
    "CertInfo",
    "parse_pem_cert",
    "DEFAULT_RULES",
    "SSL_CERT_GLOB_ROOTS",
]