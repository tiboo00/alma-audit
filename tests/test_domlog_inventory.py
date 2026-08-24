"""Tests for the domlog inventory anomaly detector."""

from __future__ import annotations

from alma_audit.analyzers.domlog_inventory import (
    _is_anomalous_filename,
    analyze_domlog_inventory,
)
from alma_audit.models import Severity

DOMLOG_ROOT = "/var/log/apache2/domlogs"


def _fs_with(files: dict[str, str]):
    from alma_audit.runners import FakeFileSystem

    return FakeFileSystem(files=files)


def test_clean_inventory_yields_info_only():
    files = {
        f"{DOMLOG_ROOT}/hostdzire.com": "log",
        f"{DOMLOG_ROOT}/hostdzire.com-ssl_log": "log",
        f"{DOMLOG_ROOT}/hostdzire.com-bytes_log": "log",
        f"{DOMLOG_ROOT}/bfiber.in": "log",
        f"{DOMLOG_ROOT}/bfiber.in-ssl_log": "log",
    }
    fs = _fs_with(files)
    findings = analyze_domlog_inventory(DOMLOG_ROOT, fs)
    # No WARN/CRITICAL — only INFO summary
    sevs = {f.severity for f in findings}
    assert sevs == {Severity.INFO}


def test_too_long_filename_is_critical():
    long_name = "a" * 130  # > LENGTH_CRIT
    fs = _fs_with({f"{DOMLOG_ROOT}/{long_name}": "log"})
    findings = analyze_domlog_inventory(DOMLOG_ROOT, fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit
    assert any(a["reason"] == "filename_too_long" for a in crit[0].details["anomalies"])


def test_unusually_long_but_under_crit_is_warn():
    long_name = "b" * 75  # 60 ≤ len < 120 → WARN
    fs = _fs_with({f"{DOMLOG_ROOT}/{long_name}": "log"})
    findings = analyze_domlog_inventory(DOMLOG_ROOT, fs)
    warn = [f for f in findings if f.severity == Severity.WARN]
    assert warn
    assert any(a["reason"] == "filename_unusually_long" for a in warn[0].details["anomalies"])


def test_repeated_character_fuzzing_is_flagged():
    # 25 'A's — over the REPEAT_MIN_LEN, well over the repeat ratio
    name = "A" * 25
    fs = _fs_with({f"{DOMLOG_ROOT}/{name}": "log"})
    findings = analyze_domlog_inventory(DOMLOG_ROOT, fs)
    flagged = [
        f for f in findings
        if any(a.get("reason") == "repeated_character_pattern" for a in f.details.get("anomalies", []))
    ]
    assert flagged


def test_shell_metacharacter_is_critical():
    fs = _fs_with({f"{DOMLOG_ROOT}/host;rm": "log"})
    findings = analyze_domlog_inventory(DOMLOG_ROOT, fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit
    assert any(a["reason"] == "shell_metacharacters" for a in crit[0].details["anomalies"])


def test_subdirectory_is_flagged():
    # FakeFileSystem has implicit dirs — adding a file under a sub-dir
    # creates that sub-dir.
    fs = _fs_with({
        f"{DOMLOG_ROOT}/zmrk2md30edvm/hostdzire.com": "log",
        f"{DOMLOG_ROOT}/hostdzire.com": "log",
    })
    findings = analyze_domlog_inventory(DOMLOG_ROOT, fs)
    # Either a sub-dir finding OR an anomaly finding is fine — what we
    # care about is that the layout doesn't pass silently.
    assert any(f.severity in (Severity.WARN, Severity.CRITICAL) for f in findings)


def test_missing_domlog_dir_is_info():
    fs = _fs_with({})  # nothing registered
    findings = analyze_domlog_inventory(DOMLOG_ROOT, fs)
    assert findings[0].severity == Severity.INFO
    assert "not present" in findings[0].title


def test_filename_helper_returns_none_for_normal():
    assert _is_anomalous_filename("hostdzire.com") is None
    assert _is_anomalous_filename("hostdzire.com-ssl_log") is None
    assert _is_anomalous_filename("bfiber.in-bytes_log") is None


def test_filename_helper_flags_injection_chars():
    assert _is_anomalous_filename("hostdzire.com;rm") is not None
    assert _is_anomalous_filename("a$b.com") is not None
