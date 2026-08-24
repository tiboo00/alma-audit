"""Tests for the ssl_cert analyzer."""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from alma_audit.analyzers.ssl_cert import (
    CertAggregator,
    CertInfo,
    analyze_ssl_certs,
    cryptography_available,
    parse_pem_cert,
)
from alma_audit.models import Severity
from alma_audit.runners import FakeFileSystem


# --- helpers --------------------------------------------------------------


def _make_cert_pem(
    *,
    cn: str = "example.com",
    issuer_cn: str = "Test CA",
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    self_signed: bool = False,
) -> bytes:
    """Build a self-contained PEM cert via the cryptography library.

    Used by every test that needs a real X.509 blob. We intentionally
    build the cert from scratch (no openssl invocation) so the tests
    stay hermetic.
    """
    if not_before is None:
        not_before = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=30)
    if not_after is None:
        not_after = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=90)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn if not self_signed else issuer_cn),
    ])
    if self_signed:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=self_signed, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _fs_with_bytes(files: dict[str, bytes]) -> FakeFileSystem:
    fs = FakeFileSystem()
    for path, content in files.items():
        fs.add_bytes(path, content)
    return fs


# --- module helpers -------------------------------------------------------


def test_cryptography_available_returns_true_when_installed():
    assert cryptography_available() is True


def test_parse_pem_cert_returns_cert_info_for_valid_cert():
    pem = _make_cert_pem(cn="example.com")
    info = parse_pem_cert("/etc/ssl/certs/example.pem", pem)
    assert info is not None
    assert info.subject_cn == "example.com"
    assert isinstance(info.not_after, datetime.datetime)
    assert info.days_until_expiry() > 0


def test_parse_pem_cert_returns_none_for_garbage():
    assert parse_pem_cert("/x.pem", b"not a cert") is None


def test_parse_pem_cert_returns_none_for_truncated_pem():
    """A PEM file that's been chopped mid-base64 must parse-fail cleanly."""
    pem = _make_cert_pem()
    truncated = pem[: len(pem) // 2]
    assert parse_pem_cert("/x.pem", truncated) is None


# --- aggregator -----------------------------------------------------------


def test_aggregator_counts_certs_and_malformed():
    agg = CertAggregator()
    pem_ok = _make_cert_pem()
    cert = parse_pem_cert("/a.pem", pem_ok)
    assert cert is not None
    agg.add(cert)
    agg.note_malformed()
    agg.note_non_pem()
    summary = agg.finalize()
    assert summary["parsed_files"] == 1
    assert summary["malformed_files"] == 1
    assert summary["skipped_non_pem"] == 1
    assert summary["cert_count"] == 1


# --- analyzer -------------------------------------------------------------


def test_analyzer_missing_cryptography_dependency(tmp_path):
    """If `cryptography` is not importable, emit a single WARN."""
    from unittest.mock import patch

    fs = FakeFileSystem()
    with patch(
        "alma_audit.analyzers.ssl_cert.analyzer.cryptography_available",
        return_value=False,
    ):
        findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARN
    assert "cryptography" in findings[0].title.lower()


def test_analyzer_no_cert_root_returns_info():
    fs = FakeFileSystem()
    findings = analyze_ssl_certs(["/does/not/exist"], fs)
    assert all(f.severity == Severity.INFO for f in findings)
    assert any("No certificate directory found" in f.title for f in findings)


def test_analyzer_emits_warn_for_expiring_soon():
    pem = _make_cert_pem(
        not_after=datetime.datetime.now(tz=datetime.timezone.utc)
        + datetime.timedelta(days=10),
    )
    fs = _fs_with_bytes({"/var/cpanel/ssl/example.pem": pem})
    findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    warn = [f for f in findings if f.severity == Severity.WARN]
    # `days_until_expiry` truncates; expect ~9-10.
    assert any("expires in" in f.title and "example.com" in f.title for f in warn), (
        f"Expected WARN for ~10-day expiry; got: {[f.title for f in findings]}"
    )


def test_analyzer_emits_critical_for_crit_window():
    pem = _make_cert_pem(
        not_after=datetime.datetime.now(tz=datetime.timezone.utc)
        + datetime.timedelta(days=2),
    )
    fs = _fs_with_bytes({"/var/cpanel/ssl/example.pem": pem})
    findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("expires in" in f.title and "example.com" in f.title for f in crit)


def test_analyzer_emits_critical_for_already_expired():
    pem = _make_cert_pem(
        not_before=datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=60),
        not_after=datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=1),
    )
    fs = _fs_with_bytes({"/var/cpanel/ssl/old.pem": pem})
    findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("expired" in f.title.lower() for f in crit)


def test_analyzer_emits_no_finding_for_healthy_cert():
    pem = _make_cert_pem(
        not_after=datetime.datetime.now(tz=datetime.timezone.utc)
        + datetime.timedelta(days=120),
    )
    fs = _fs_with_bytes({"/var/cpanel/ssl/example.pem": pem})
    findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    # No expiry WARN/CRITICAL.
    expiry = [
        f for f in findings
        if "expire" in f.title.lower() or "expired" in f.title.lower()
    ]
    assert expiry == []


def test_analyzer_warn_for_unreadable_cert():
    fs = FakeFileSystem()
    fs.add_bytes("/var/cpanel/ssl/broken.pem", b"not a cert")
    findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    warn = [f for f in findings if f.severity == Severity.WARN]
    assert any("could not be parsed" in f.title for f in warn)


def test_analyzer_unreadable_root_emits_warn():
    """A readable directory that lists to [] is fine; one that can't
    list at all (PermissionError simulation) emits a WARN."""
    fs = FakeFileSystem()
    fs.add_file("/var/cpanel/ssl/.placeholder", "")
    # Force is_readable_dir → False to simulate chmod-000.
    monkey = pytest.MonkeyPatch()
    monkey.setattr(fs, "is_readable_dir", lambda p: False)
    findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    monkey.undo()
    warn = [f for f in findings if f.severity == Severity.WARN]
    assert any("not readable" in f.title.lower() for f in warn)


def test_analyzer_skips_files_outside_glob():
    """Files not matching the configured glob are silently skipped."""
    pem = _make_cert_pem()
    fs = _fs_with_bytes({
        "/var/cpanel/ssl/cert.pem": pem,
        "/var/cpanel/ssl/README.txt": b"not a cert",
    })
    findings = analyze_ssl_certs(
        ["/var/cpanel/ssl"], fs,
        glob_patterns=["*.pem"],
    )
    # No WARN about the README; only the cert is scanned.
    parsed = [f for f in findings if "could not be parsed" in f.title]
    assert parsed == []


def test_analyzer_boundary_thresholds(tmp_path):
    """Days_until_expiry boundary cases.

      days == expiry_warn_days → WARN
      days <= expiry_crit_days → CRITICAL
      days == expiry_crit_days (exact) → CRITICAL (not WARN)
    """
    # 14 days from now (== default expiry_warn_days, truncated to ~13).
    pem_warn = _make_cert_pem(
        not_after=datetime.datetime.now(tz=datetime.timezone.utc)
        + datetime.timedelta(days=14),
    )
    fs = _fs_with_bytes({"/var/cpanel/ssl/warn.pem": pem_warn})
    findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    warn = [f for f in findings if f.severity == Severity.WARN]
    assert any("expires in" in f.title and "warn" not in f.title.lower() and "warn.pem" in f.details.get("path", "") for f in warn), (
        f"Expected WARN for the 14-day cert; got: {[f.title for f in findings]}"
    )

    # 3 days from now (== default expiry_crit_days, truncated to ~2).
    pem_crit = _make_cert_pem(
        not_after=datetime.datetime.now(tz=datetime.timezone.utc)
        + datetime.timedelta(days=3),
    )
    fs = _fs_with_bytes({"/var/cpanel/ssl/crit.pem": pem_crit})
    findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("expires in" in f.title and "crit.pem" in f.details.get("path", "") for f in crit)


def test_analyzer_no_double_finding_for_single_cert():
    """One cert must produce at most one expiry finding (not both warn and crit)."""
    pem = _make_cert_pem(
        not_after=datetime.datetime.now(tz=datetime.timezone.utc)
        + datetime.timedelta(days=2),
    )
    fs = _fs_with_bytes({"/var/cpanel/ssl/x.pem": pem})
    findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    expiry = [
        f for f in findings
        if "expire" in f.title.lower() or "expired" in f.title.lower()
    ]
    assert len(expiry) == 1


def test_analyzer_uses_max_files_cap():
    pem = _make_cert_pem()
    files = {f"/var/cpanel/ssl/cert-{i}.pem": pem for i in range(5)}
    fs = _fs_with_bytes(files)
    findings = analyze_ssl_certs(
        ["/var/cpanel/ssl"], fs,
        rules={"max_files": 2},
    )
    summary = next(f for f in findings if "Scanned" in f.title)
    assert summary.details["files_scanned"] == 2


def test_cert_info_days_until_expiry_handles_timezones():
    now = datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    info = CertInfo(
        path="/x", subject_cn="x", subject="x", issuer_cn="x", serial="1",
        not_before=now,
        not_after=now + datetime.timedelta(days=10),
        is_ca=False,
    )
    assert info.days_until_expiry(now=now) == 10
    # Naive datetime (no tzinfo) still works — defensive fallback.
    naive = info.not_after.replace(tzinfo=None)
    info_naive = CertInfo(
        path="/x", subject_cn="x", subject="x", issuer_cn="x", serial="1",
        not_before=now,
        not_after=naive,
        is_ca=False,
    )
    assert info_naive.days_until_expiry(now=now) == 10