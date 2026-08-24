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
    SSL_CERT_GLOB_ROOTS,
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


def test_default_glob_roots_excludes_os_trust_stores():
    """Anti-regression: `SSL_CERT_GLOB_ROOTS` only carries host cert dirs.

    OS-level CA trust stores (`/etc/pki/tls/certs`, `/etc/ssl/certs`)
    are deliberately excluded — see `ssl_cert/settings.py` for the
    rationale. This test fails fast if a future refactor re-adds them.
    """
    assert SSL_CERT_GLOB_ROOTS == ["/var/cpanel/ssl"]
    assert "/etc/pki/tls/certs" not in SSL_CERT_GLOB_ROOTS
    assert "/etc/ssl/certs" not in SSL_CERT_GLOB_ROOTS


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


def test_analyzer_missing_cryptography_dependency_is_silent_without_roots(tmp_path):
    """If `cryptography` is missing AND no cert roots match on disk,
    the analyzer emits nothing — a default `pip install alma-audit`
    (without `[ssl]`) on a non-cPanel host must be cron-clean.
    """
    from unittest.mock import patch

    fs = FakeFileSystem()
    # No cert roots registered. `_discover_any_root_has_matches`
    # returns False, so the dependency-WARN is suppressed.
    with patch(
        "alma_audit.analyzers.ssl_cert.analyzer.cryptography_available",
        return_value=False,
    ):
        findings = analyze_ssl_certs(["/var/cpanel/ssl"], fs)
    assert findings == []


def test_analyzer_missing_cryptography_dependency_warns_when_certs_exist(tmp_path):
    """If `cryptography` is missing AND a cert root has matching
    files on disk, the analyzer emits a single WARN naming the
    missing dependency — operators see why the module produced
    zero findings.
    """
    from unittest.mock import patch

    # Register a PEM cert under the only cert root.
    pem = _make_cert_pem()
    fs = FakeFileSystem()
    fs.add_bytes("/var/cpanel/ssl/example.pem", pem)

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


# ---------------------------------------------------------------------------
# AISO-197: per-IP forensic detail in access_log + secure_log analyzers
# ---------------------------------------------------------------------------


def _make_record(host: str, path: str, status: int, ua: str = "test") -> dict:
    """Build an AccessRecord-shaped dict the aggregator can consume."""
    from alma_audit.analyzers.access_log.parser import AccessRecord

    return AccessRecord(
        host=host,
        timestamp="10/Oct/2025:13:55:36 -0700",
        method="GET",
        path=path,
        status=status,
        size=1024,
        user_agent=ua,
    )


def test_probe_paths_by_ip_captures_per_ip_count_and_timestamps():
    """Each probe-path hit must record the source IP, count, and timestamps."""
    from alma_audit.analyzers.access_log.aggregator import AccessAggregator

    agg = AccessAggregator()
    agg.add(_make_record("1.2.3.4", "/.env", 404))
    agg.add(_make_record("1.2.3.4", "/.env", 404))
    agg.add(_make_record("5.6.7.8", "/wp-login.php", 403))
    summary = agg.finalize()

    # probe_paths_by_ip should have BOTH paths listed.
    assert "/.env" in summary["probe_paths_by_ip"]
    assert "/wp-login.php" in summary["probe_paths_by_ip"]
    # /.env has 1 IP, 2 hits.
    env_rows = summary["probe_paths_by_ip"]["/.env"]
    assert len(env_rows) == 1
    assert env_rows[0]["ip"] == "1.2.3.4"
    assert env_rows[0]["count"] == 2
    # wp-login has 1 IP, 1 hit.
    wp_rows = summary["probe_paths_by_ip"]["/wp-login.php"]
    assert len(wp_rows) == 1
    assert wp_rows[0]["ip"] == "5.6.7.8"
    # top_attackers should aggregate both IPs.
    ips = [row["ip"] for row in summary["top_attackers"]]
    assert "1.2.3.4" in ips
    assert "5.6.7.8" in ips


def test_top_attackers_aggregates_across_paths():
    """An IP hitting multiple probe paths is rolled up into one attacker row."""
    from alma_audit.analyzers.access_log.aggregator import AccessAggregator

    agg = AccessAggregator()
    # 1.2.3.4 hits /.env twice and /wp-login.php once.
    agg.add(_make_record("1.2.3.4", "/.env", 404))
    agg.add(_make_record("1.2.3.4", "/.env", 404))
    agg.add(_make_record("1.2.3.4", "/wp-login.php", 403))
    # 5.6.7.8 hits only /admin.php.
    agg.add(_make_record("5.6.7.8", "/admin.php", 403))
    summary = agg.finalize()

    attacker_124 = next(r for r in summary["top_attackers"] if r["ip"] == "1.2.3.4")
    assert attacker_124["total_probe_requests"] == 3
    assert attacker_124["probe_paths"]["/.env"] == 2
    assert attacker_124["probe_paths"]["/wp-login.php"] == 1
    # 1.2.3.4 should be ranked first (3 > 1).
    assert summary["top_attackers"][0]["ip"] == "1.2.3.4"


def test_ssh_fail_details_per_ip_user_with_timestamps():
    """SecureAggregator records SSH failures with (ip, user, count, timestamps)."""
    from alma_audit.analyzers.secure_log.aggregator import SecureAggregator
    from alma_audit.analyzers.secure_log.parser import SecureRecord

    agg = SecureAggregator()
    # Same IP, same user, 3 fails.
    for i in range(3):
        agg.add(SecureRecord(
            event="ssh_fail", service="sshd",
            source_ip="212.32.226.231", user="root",
            username=None, uid=None, gid=None, pid=1234,
            raw=f"Aug 17 04:12:34 host sshd[1234]: Failed password for root from 212.32.226.231 port {12345 + i} ssh2",
            raw_timestamp=f"Aug 17 04:12:3{i}",
        ))
    summary = agg.finalize()
    # One (ip, user) row.
    assert len(summary["ssh_fail_details"]) == 1
    row = summary["ssh_fail_details"][0]
    assert row["ip"] == "212.32.226.231"
    assert row["user"] == "root"
    assert row["count"] == 3
    # First/last seen timestamps tracked.
    assert row["first_seen"] == "Aug 17 04:12:30"
    assert row["last_seen"] == "Aug 17 04:12:32"


def test_ssh_fail_details_groups_unknown_users_separately():
    """Failed logins without a parsed user (rare syslog shapes) get a None user bucket."""
    from alma_audit.analyzers.secure_log.aggregator import SecureAggregator
    from alma_audit.analyzers.secure_log.parser import SecureRecord

    agg = SecureAggregator()
    agg.add(SecureRecord(
        event="ssh_fail", service="sshd",
        source_ip="9.9.9.9", user=None,
        username=None, uid=None, gid=None, pid=1,
        raw="<unknown shape>",
        raw_timestamp="Aug 17 04:12:34",
    ))
    summary = agg.finalize()
    assert len(summary["ssh_fail_details"]) == 1
    assert summary["ssh_fail_details"][0]["user"] is None