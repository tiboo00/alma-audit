"""Tests for the analyzer orchestration layer."""

from __future__ import annotations

from alma_audit.config import Config
from alma_audit.runner import run_analyzers
from alma_audit.runners import FakeFileSystem


def test_run_analyzers_collects_findings_from_all_three():
    fs = FakeFileSystem(files={
        "/var/log/apache2/access_log":
            "1.2.3.4 - - [17/Aug/2026:04:12:34 +0000] \"GET /wp-login.php HTTP/1.1\" 404 - \"-\" \"ua\"\n"
            * 50,
        "/var/log/apache2/domlogs/example.com": "",
        "/var/log/apache2/domlogs/hostdzi" + "a" * 100: "",  # overlong
        "/var/log/apache2/error_log":
            "[Sun Aug 17 04:12:34.123456 2026] [core:error] [pid 12345] AH00037: 503 Service Unavailable\n",
        "/var/log/apache2/modsec_audit.log": "",
    })
    cfg = Config()
    findings = run_analyzers(cfg, fs)
    modules_seen = {f.module for f in findings}
    assert "access_log" in modules_seen
    assert "domlog_inventory" in modules_seen
    assert "modsec_log" in modules_seen


def test_run_analyzers_handles_missing_root_gracefully():
    fs = FakeFileSystem()  # nothing
    cfg = Config()
    findings = run_analyzers(cfg, fs)
    # Every analyzer should at least emit an INFO finding about missing input
    assert all(f.severity.value == "INFO" for f in findings)


def test_run_analyzers_respects_module_overrides():
    """A module's rule overrides should be passed through."""
    fs = FakeFileSystem(files={
        "/var/log/apache2/access_log":
            "1.2.3.4 - - [17/Aug/2026:04:12:34 +0000] \"GET /wp-login.php HTTP/1.1\" 404 - \"-\" \"ua\"\n"
            * 50,
    })
    cfg = Config()
    cfg.modules["access_log"] = {"probe_count_warn": 1000}
    findings = run_analyzers(cfg, fs)
    # With a high threshold, no probe finding should fire
    probe_findings = [f for f in findings if "probe" in f.title.lower()]
    assert probe_findings == []


def test_run_analyzers_silent_when_cryptography_missing_and_no_cert_roots():
    """Regression: a default install without `[ssl]` must NOT emit a
    WARN when no cert roots exist on disk. Without this guard, every
    cron run on a non-cPanel host would exit 1 — defeating the
    INFO-only / cron-clean contract.
    """
    from unittest.mock import patch

    fs = FakeFileSystem()  # nothing — no cert roots, no log files
    cfg = Config()
    with patch(
        "alma_audit.analyzers.ssl_cert.analyzer.cryptography_available",
        return_value=False,
    ):
        findings = run_analyzers(cfg, fs)
    # The only finding should be the "no cert directory" INFO.
    # No WARN about cryptography-missing.
    cryptography_warns = [
        f for f in findings
        if f.module == "ssl_cert" and "cryptography" in f.title.lower()
    ]
    assert cryptography_warns == []
    # And no CRITICAL / non-INFO findings overall.
    from alma_audit.models import Severity
    assert all(f.severity == Severity.INFO for f in findings)
