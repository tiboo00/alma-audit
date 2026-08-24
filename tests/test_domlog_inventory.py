"""Tests for the domlog inventory anomaly detector + multi-root discovery."""

from __future__ import annotations

from alma_audit.analyzers.domlog_inventory import (
    _is_anomalous_filename,
    analyze_domlog_inventory,
)
from alma_audit.analyzers.domlog_roots import (
    DEFAULT_DOMLOG_ROOTS,
    DOMLOG_EXCLUDE_SUFFIXES,
    should_skip_filename,
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
        f"{DOMLOG_ROOT}/hostdzire.com-bytes_log": "log",  # must be skipped, not flagged
        f"{DOMLOG_ROOT}/bfiber.in": "log",
        f"{DOMLOG_ROOT}/bfiber.in-ssl_log": "log",
    }
    fs = _fs_with(files)
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    # No WARN/CRITICAL — only INFO summary. -bytes_log is intentionally
    # excluded, so it doesn't produce a false-positive "unexpected_filename_shape".
    sevs = {f.severity for f in findings}
    assert sevs == {Severity.INFO}


def test_too_long_filename_is_critical():
    long_name = "a" * 130  # > LENGTH_CRIT
    fs = _fs_with({f"{DOMLOG_ROOT}/{long_name}": "log"})
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit
    assert any(a["reason"] == "filename_too_long" for a in crit[0].details["anomalies"])


def test_unusually_long_but_under_crit_is_warn():
    long_name = "b" * 75  # 60 ≤ len < 120 → WARN
    fs = _fs_with({f"{DOMLOG_ROOT}/{long_name}": "log"})
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    warn = [f for f in findings if f.severity == Severity.WARN]
    assert warn
    assert any(a["reason"] == "filename_unusually_long" for a in warn[0].details["anomalies"])


def test_repeated_character_fuzzing_is_flagged():
    # 25 'A's — over the REPEAT_MIN_LEN, well over the repeat ratio
    name = "A" * 25
    fs = _fs_with({f"{DOMLOG_ROOT}/{name}": "log"})
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    flagged = [
        f for f in findings
        if any(a.get("reason") == "repeated_character_pattern" for a in f.details.get("anomalies", []))
    ]
    assert flagged


def test_shell_metacharacter_is_critical():
    fs = _fs_with({f"{DOMLOG_ROOT}/host;rm": "log"})
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit
    assert any(a["reason"] == "shell_metacharacters" for a in crit[0].details["anomalies"])


def test_subdirectory_is_flagged():
    """Non-account-shaped sub-directories ARE flagged (anomaly).

    AISO-198: cPanel account-ID-shaped sub-directories (random 8-char
    alphanumeric names) are normal layout, so they emit INFO only.
    Genuinely suspicious layouts (e.g. a `nested/year/` structure)
    still emit WARN/CRITICAL.
    """
    fs = _fs_with({
        f"{DOMLOG_ROOT}/zmrk2md30edvm/hostdzire.com": "log",
        f"{DOMLOG_ROOT}/hostdzire.com": "log",
    })
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    # Account-ID-shaped subdir → INFO scope-info finding.
    info_subs = [
        f for f in findings
        if "sub-director" in f.title.lower()
    ]
    assert info_subs, "Expected an INFO scope-info finding for the account subdir"
    assert all(f.severity == Severity.INFO for f in info_subs)


def test_non_account_subdirectory_is_anomaly():
    """Sub-directories that don't match the cPanel account-ID shape are flagged.

    A directory like `nested_2024/` (contains a digit pattern outside
    the account-ID convention) is treated as a structural anomaly.
    """
    fs = _fs_with({
        f"{DOMLOG_ROOT}/nested_2024_q1/hostdzire.com": "log",
        f"{DOMLOG_ROOT}/hostdzire.com": "log",
    })
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    subdir_findings = [
        f for f in findings
        if "sub-directory" in f.title.lower()
        or "sub-director" in f.title.lower()
    ]
    assert subdir_findings
    assert any(f.severity in (Severity.WARN, Severity.CRITICAL) for f in subdir_findings), (
        f"Expected a WARN/CRITICAL for a non-account-shaped subdir; got: "
        f"{[(f.severity, f.title) for f in subdir_findings]}"
    )


# ---------------------------------------------------------------------------
# AISO-194: multi-root domlog discovery
# ---------------------------------------------------------------------------


def test_default_domlog_roots_include_cloudlinux_layout():
    """The default root list must include both cPanel and CloudLinux paths.

    `hostdzire.com` was the canonical example from a CloudLinux + cPanel
    server fingerprint. A single-root default would have missed
    `/usr/local/apache/domlogs`, where the actual files live.
    """
    assert "/var/log/apache2/domlogs" in DEFAULT_DOMLOG_ROOTS
    assert "/usr/local/apache/domlogs" in DEFAULT_DOMLOG_ROOTS


def test_should_skip_filename_excludes_bytes_log_and_offset():
    """`-bytes_log`, `-bytes_log.bkup`, `.offset` are NOT access logs."""
    assert should_skip_filename("hostdzire.com-bytes_log") is True
    assert should_skip_filename("hostdzire.com-bytes_log.bkup") is True
    assert should_skip_filename("hostdzire.com-bytes_log.bkup.offset") is True
    assert should_skip_filename("hostdzire.com.offset") is True
    # Real access logs are NOT excluded.
    assert should_skip_filename("hostdzire.com") is False
    assert should_skip_filename("hostdzire.com-ssl_log") is False
    assert should_skip_filename("bfiber.in-ssl_log") is False
    # Mid-name hits do NOT match (suffix-only).
    assert should_skip_filename("bytes_log-bkup-file.com") is False


def test_domlog_exclude_suffixes_are_stable():
    """Anti-regression: the exclusion tuple is the single source of truth.

    A future refactor must not silently drop a suffix (that would
    re-introduce the false-positive WARN on `bytes_log` files).
    """
    assert "-bytes_log" in DOMLOG_EXCLUDE_SUFFIXES
    assert "-bytes_log.bkup" in DOMLOG_EXCLUDE_SUFFIXES
    assert ".offset" in DOMLOG_EXCLUDE_SUFFIXES


def test_ssl_log_is_well_formed():
    """`<domain>-ssl_log` is a real Apache combined-format log.

    The D7 detector must accept it as well-formed (the domlog filename
    regex permits `<domain>(-ssl_log|-bytes_log)?`). It must NOT be
    classified as anomalous, and it must NOT be skipped.
    """
    fs = _fs_with({
        f"{DOMLOG_ROOT}/hostdzire.com-ssl_log": "log",
        f"{DOMLOG_ROOT}/another.com-ssl_log": "log",
    })
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    # Both files are well-formed → only the INFO summary finding.
    info = [f for f in findings if f.severity == Severity.INFO]
    summary = next(f for f in info if "well-formed" in f.title.lower())
    assert summary.details["count"] == 2


def test_bytes_log_is_skipped_silently():
    """`-bytes_log` files are skipped at the discovery layer.

    They must NOT appear in anomalies (would produce false-positive
    WARN "unexpected_filename_shape") and must NOT be counted as
    well-formed either.
    """
    fs = _fs_with({
        f"{DOMLOG_ROOT}/hostdzire.com": "log",
        f"{DOMLOG_ROOT}/hostdzire.com-bytes_log": "log",
        f"{DOMLOG_ROOT}/hostdzire.com-bytes_log.bkup": "log",
        f"{DOMLOG_ROOT}/hostdzire.com.offset": "log",
    })
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    # No anomalies — the 3 non-access-log files were skipped.
    anomalies_findings = [f for f in findings if f.severity != Severity.INFO]
    assert anomalies_findings == []
    # Only the single well-formed domain is counted.
    info = next(f for f in findings if "well-formed" in f.title.lower())
    assert info.details["count"] == 1


def test_multi_root_scans_both_paths():
    """Two populated roots merge into one aggregated summary.

    The well-formed count is the SUM across all roots (no dedup —
    the filesystem abstraction here is the bare path, not a realpath;
    see `analyze_domlog_inventory` for the rationale). The report
    surfaces this as a single INFO finding, listing all scanned roots.
    """
    root_a = "/var/log/apache2/domlogs"
    root_b = "/usr/local/apache/domlogs"
    fs = _fs_with({
        f"{root_a}/hosta1.com": "log",
        f"{root_a}/hosta2.com": "log",
        f"{root_b}/hostb1.com": "log",
        f"{root_b}/hostb2.com": "log",
    })
    findings = analyze_domlog_inventory([root_a, root_b], fs)
    info_titles = [f.title for f in findings if f.severity == Severity.INFO]
    assert any("well-formed" in t.lower() for t in info_titles), (
        f"Expected a well-formed summary finding; got titles: {info_titles}"
    )
    summary = next(f for f in findings if "well-formed" in f.title.lower())
    # 4 unique files, summed across both roots.
    assert summary.details["count"] == 4
    assert set(summary.details["roots_scanned"]) == {root_a, root_b}


def test_multi_root_scans_one_root_when_other_is_empty():
    """A configured root that doesn't exist is silently skipped.

    CloudLinux hosts may have `/var/log/apache2/domlogs` empty or
    absent while `/usr/local/apache/domlogs` is the live one — the
    inventory should scan the populated root and not emit a
    "directory not present" finding for the absent one.
    """
    fs = _fs_with({
        "/usr/local/apache/domlogs/hostdzire.com": "log",
        "/usr/local/apache/domlogs/hostdzire.com-ssl_log": "log",
    })
    findings = analyze_domlog_inventory(
        ["/var/log/apache2/domlogs", "/usr/local/apache/domlogs"], fs,
    )
    # No "directory not present" finding — at least one root existed.
    assert not any("not present" in f.title.lower() for f in findings)
    # The populated root was scanned.
    summary = next(f for f in findings if "well-formed" in f.title.lower())
    assert summary.details["count"] == 2


def test_multi_root_with_missing_second_root():
    """A configured root that doesn't exist is silently skipped.

    CloudLinux hosts may have `/var/log/apache2/domlogs` empty or
    absent while `/usr/local/apache/domlogs` is the live one — the
    inventory should scan the populated root and not emit a
    "directory not present" finding for the absent one.
    """
    fs = _fs_with({
        "/usr/local/apache/domlogs/hostdzire.com": "log",
        "/usr/local/apache/domlogs/hostdzire.com-ssl_log": "log",
    })
    findings = analyze_domlog_inventory(
        ["/var/log/apache2/domlogs", "/usr/local/apache/domlogs"], fs,
    )
    # No "directory not present" finding — at least one root existed.
    assert not any("not present" in f.title.lower() for f in findings)
    # The populated root was scanned.
    summary = next(f for f in findings if "well-formed" in f.title.lower())
    assert summary.details["count"] == 2


def test_multi_root_aggregates_anomalies_across_roots():
    """Anomalies from multiple roots are merged into one finding.

    If root A has one anomalous filename and root B has another,
    the report shows a single "2 anomalous domlog filename(s)"
    finding, not two separate ones.
    """
    root_a = "/var/log/apache2/domlogs"
    root_b = "/usr/local/apache/domlogs"
    # 25 pure-A / pure-B strings — over the REPEAT_MIN_LEN (20) and
    # well over the REPEAT_RATIO (0.8), so the detector flags them
    # as `repeated_character_pattern`. (Same threshold as the
    # existing test_repeated_character_fuzzing_is_flagged test.)
    fs = _fs_with({
        f"{root_a}/{'A' * 25}": "log",
        f"{root_b}/{'B' * 25}": "log",
    })
    findings = analyze_domlog_inventory([root_a, root_b], fs)
    anomaly_findings = [
        f for f in findings
        if "anomalous domlog filename" in f.title.lower()
    ]
    # Exactly one aggregated anomaly finding — not two.
    assert len(anomaly_findings) == 1, (
        f"Expected one aggregated anomaly finding; got {len(anomaly_findings)}: "
        f"{[(f.severity, f.title) for f in anomaly_findings]}"
    )
    assert len(anomaly_findings[0].details["anomalies"]) == 2


def test_domlog_root_none_falls_back_to_default():
    """Passing `None` to `analyze_domlog_inventory` triggers the default
    CloudLinux + cPanel layout (AISO-194). On a host with NONE of the
    default roots present, the analyzer must emit a single INFO listing
    all roots — not crash.
    """
    fs = _fs_with({})  # no domlogs anywhere
    findings = analyze_domlog_inventory(None, fs)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "not present" in findings[0].title.lower()
    # The reported roots are exactly the defaults.
    assert findings[0].details["roots_checked"] == DEFAULT_DOMLOG_ROOTS
