"""PEM certificate parser.

Wraps `cryptography.x509.load_pem_x509_certificate` with a clean
failure mode (returns None instead of raising) so the analyzer can
record a WARN finding rather than crashing the scan.

The parser is a thin shim. The reason it lives in its own file is to
keep the §7 "one concern per file" rule satisfied: anything that
needs to evolve when cPanel changes its cert format (combined PEM
chains, header-only files, DER-encoded bytes) lives here, not in the
aggregator or the analyzer.

A `CertInfo` carries everything the rules layer needs without exposing
the underlying `cryptography` object — keeps the dependency surface
narrow and makes the rules layer easy to unit-test.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass


@dataclass(frozen=True)
class CertInfo:
    """Parsed certificate metadata.

    `not_before` / `not_after` are timezone-aware `datetime` objects
    in UTC. `subject_cn` is the commonName attribute when present;
    `subject` is the full X.500 name as a short string. `issuer_cn`
    is the issuer commonName; `is_ca` flags self-signed certificates
    (issuer == subject) which cPanel uses as both a leaf and a CA.
    """

    path: str
    subject_cn: str
    subject: str
    issuer_cn: str
    serial: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    is_ca: bool

    def days_until_expiry(self, now: datetime.datetime | None = None) -> int:
        """Whole days until `not_after`. Negative if already expired."""
        ref = now or datetime.datetime.now(tz=datetime.timezone.utc)
        if self.not_after.tzinfo is None:
            # Defensive: cryptography emits aware datetimes in modern
            # releases, but treat naive values as UTC for the math.
            na = self.not_after.replace(tzinfo=datetime.timezone.utc)
        else:
            na = self.not_after
        delta = na - ref
        return delta.days


def parse_pem_cert(path: str, content: bytes) -> CertInfo | None:
    """Parse a PEM certificate from in-memory `content`.

    Returns None if `cryptography` is not importable, or if the file
    is not a recognisable PEM certificate. The analyzer records a
    WARN finding for None returns so the operator sees the failure.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None

    # Cryptography's PEM loader accepts bytes or str; we accept bytes
    # so the FileSystem can stay text-mode and we don't need to decode
    # twice.
    try:
        cert = x509.load_pem_x509_certificate(content)
    except Exception:
        # Not PEM, malformed bytes, unsupported algorithm — treat as
        # "not a certificate" and let the rules layer record the file.
        return None

    def _cn(name) -> str:
        try:
            cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        except Exception:
            return ""
        return cns[0].value if cns else ""

    subject_cn = _cn(cert.subject)
    issuer_cn = _cn(cert.issuer)
    serial = format(cert.serial_number, "x")

    # The `not_after` / `not_before` fields are timezone-aware in
    # cryptography >= 3.0; we don't downgrade them.
    return CertInfo(
        path=path,
        subject_cn=subject_cn,
        subject=cert.subject.rfc4514_string(),
        issuer_cn=issuer_cn,
        serial=serial,
        not_before=cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_before,
        not_after=cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_after,
        is_ca=(cert.subject == cert.issuer),
    )