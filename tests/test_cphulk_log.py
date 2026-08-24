"""Tests for the cphulk_log analyzer."""

from __future__ import annotations

import pytest

from alma_audit.analyzers.cphulk_log import (
    CphulkAggregator,
    analyze_cphulk_logs,
    parse_line,
)
from alma_audit.models import Severity
from alma_audit.runners import FakeFileSystem


# Sample cPHulk log lines. The header is the canonical cPanel format.
SAMPLE_CPHULK = """\
[2026-08-17 04:12:34 -0500] info [cphulkd] Loaded 10000 netblocks
[2026-08-17 04:12:35 -0500] info [cphulkd] Processing band...
[2026-08-17 04:12:36 -0500] warn [cphulkd] Brute force attempt detected for user "root" from IP 1.2.3.4 - too many authentication failures
[2026-08-17 04:12:37 -0500] warn [cphulkd] Brute force attempt detected for user "root" from IP 1.2.3.4 - too many authentication failures
[2026-08-17 04:12:38 -0500] warn [cphulkd] Brute force attempt detected for user "admin" from IP 5.6.7.8 - too many authentication failures
[2026-08-17 04:12:39 -0500] critical [cphulkd] Account "root" blocked
[2026-08-17 04:12:40 -0500] info [cphulkd] Processing band...
[2026-08-17 04:12:41 -0500] info [cphulkd] Account "root" unblocked
"""


# --- parser ---------------------------------------------------------------


def test_parse_line_brute_force():
    rec = parse_line(
        '[2026-08-17 04:12:36 -0500] warn [cphulkd] '
        'Brute force attempt detected for user "root" from IP 1.2.3.4'
    )
    assert rec is not None
    assert rec.event == "brute_force"
    assert rec.source_ip == "1.2.3.4"
    assert rec.username == "root"
    assert rec.level.value == "warn"


def test_parse_line_brute_force_without_quotes():
    """Some cPHulk versions emit the username without surrounding quotes."""
    rec = parse_line(
        "[2026-08-17 04:12:36 -0500] warn [cphulkd] "
        "Brute force attempt detected for user root from IP 1.2.3.4"
    )
    assert rec is not None
    assert rec.event == "brute_force"
    assert rec.source_ip == "1.2.3.4"
    assert rec.username == "root"


def test_parse_line_account_blocked():
    rec = parse_line(
        '[2026-08-17 04:12:39 -0500] critical [cphulkd] Account "root" blocked'
    )
    assert rec is not None
    assert rec.event == "account_blocked"
    assert rec.username == "root"


def test_parse_line_account_unblocked():
    rec = parse_line(
        '[2026-08-17 04:12:41 -0500] info [cphulkd] Account "root" unblocked'
    )
    assert rec is not None
    assert rec.event == "account_unblocked"


def test_parse_line_ip_blocked():
    rec = parse_line(
        "[2026-08-17 04:12:42 -0500] warn [cphulkd] IP 9.10.11.12 blocked"
    )
    assert rec is not None
    assert rec.event == "ip_blocked"
    assert rec.source_ip == "9.10.11.12"


def test_parse_line_unrelated_returns_none():
    rec = parse_line(
        "[2026-08-17 04:12:34 -0500] info [cphulkd] Loaded 10000 netblocks"
    )
    assert rec is None


def test_parse_line_other_service_returns_none():
    """Lines from non-cphulkd services must be ignored."""
    rec = parse_line(
        "[2026-08-17 04:12:34 -0500] info [otherd] Account \"x\" blocked"
    )
    assert rec is None


def test_parse_line_malformed_returns_none():
    assert parse_line("not a log line") is None
    assert parse_line("") is None


# --- aggregator -----------------------------------------------------------


def test_aggregator_counts_classified_lines():
    agg = CphulkAggregator()
    for line in SAMPLE_CPHULK.splitlines():
        rec = parse_line(line)
        if rec is not None:
            agg.add(rec)
    summary = agg.finalize()
    assert summary["classified_lines"] == 5
    assert summary["brute_force_by_ip"]["1.2.3.4"] == 2
    assert summary["brute_force_by_user"]["root"] == 2
    assert summary["block_event_count"] == 1
    assert summary["unblock_event_count"] == 1


# --- analyzer -------------------------------------------------------------


def test_analyzer_emits_brute_force_per_ip():
    fs = FakeFileSystem(files={"/var/log/cphulkd.log": SAMPLE_CPHULK})
    findings = analyze_cphulk_logs(["/var/log/cphulkd.log"], fs)
    per_ip = [f for f in findings if "1.2.3.4" in f.title]
    # Default warn threshold is 5; we only have 2 BF events. Override:
    findings_warn = analyze_cphulk_logs(
        ["/var/log/cphulkd.log"], fs,
        rules={"brute_force_warn": 2},
    )
    per_ip_warn = [f for f in findings_warn if "1.2.3.4" in f.title and "brute-force" in f.title.lower()]
    assert len(per_ip_warn) == 1
    assert per_ip_warn[0].severity == Severity.WARN


def test_analyzer_emits_brute_force_per_user():
    log = "\n".join([
        '[2026-08-17 04:12:36 -0500] warn [cphulkd] '
        f'Brute force attempt detected for user "admin" from IP 1.2.3.{i}'
        for i in range(6)
    ])
    fs = FakeFileSystem(files={"/var/log/cphulkd.log": log})
    findings = analyze_cphulk_logs(
        ["/var/log/cphulkd.log"], fs,
        rules={"brute_force_user_warn": 5},
    )
    per_user = [f for f in findings if "admin" in f.title and "against" in f.title.lower()]
    assert len(per_user) == 1
    assert per_user[0].severity == Severity.WARN


def test_analyzer_emits_critical_for_large_burst():
    log = "\n".join([
        f'[2026-08-17 04:12:36 -0500] warn [cphulkd] '
        f'Brute force attempt detected for user "admin" from IP 1.2.3.{i}'
        for i in range(25)
    ])
    fs = FakeFileSystem(files={"/var/log/cphulkd.log": log})
    findings = analyze_cphulk_logs(
        ["/var/log/cphulkd.log"], fs,
        rules={"brute_force_warn": 5, "brute_force_crit": 20},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL and "brute-force" in f.title.lower()]
    assert crit, f"Expected CRITICAL; got: {[f.title for f in findings]}"


def test_analyzer_emits_block_summary():
    fs = FakeFileSystem(files={"/var/log/cphulkd.log": SAMPLE_CPHULK})
    findings = analyze_cphulk_logs(["/var/log/cphulkd.log"], fs)
    summary = next(f for f in findings if "block event" in f.title.lower())
    assert summary.severity == Severity.INFO
    # SAMPLE_CPHULK has 1 account_blocked + 1 account_unblocked.
    assert len(summary.details["blocked"]) == 1
    assert len(summary.details["unblocked"]) == 1


def test_analyzer_missing_log_root_emits_info():
    fs = FakeFileSystem()
    findings = analyze_cphulk_logs(["/var/log/cphulkd.log"], fs)
    assert all(f.severity == Severity.INFO for f in findings)
    assert any("No cPHulk" in f.title for f in findings)


def test_analyzer_skips_compressed_files_silently():
    fs = FakeFileSystem(files={
        "/var/log/cphulkd.log.1.gz": SAMPLE_CPHULK,
        "/var/log/cphulkd.log": SAMPLE_CPHULK,
    })
    findings = analyze_cphulk_logs(
        ["/var/log/cphulkd.log.1.gz", "/var/log/cphulkd.log"], fs,
    )
    summary = next(f for f in findings if "Scanned" in f.title)
    assert "/var/log/cphulkd.log.1.gz" in summary.details["skipped_compressed"]


def test_analyzer_records_malformed_lines():
    log = "\n".join([
        '[2026-08-17 04:12:36 -0500] warn [cphulkd] Brute force attempt detected for user "root" from IP 1.2.3.4',
        "garbage line",
        "another garbage",
    ])
    fs = FakeFileSystem(files={"/var/log/cphulkd.log": log})
    findings = analyze_cphulk_logs(["/var/log/cphulkd.log"], fs)
    summary = next(f for f in findings if "Scanned" in f.title)
    assert summary.details["classified_lines"] == 1
    assert summary.details["malformed_lines"] == 2


def test_analyzer_duplicate_suppression_per_ip():
    """One IP burst must produce exactly one brute-force finding per analyzer pass."""
    fs = FakeFileSystem(files={"/var/log/cphulkd.log": SAMPLE_CPHULK})
    findings = analyze_cphulk_logs(
        ["/var/log/cphulkd.log"], fs,
        rules={"brute_force_warn": 1},
    )
    per_ip = [f for f in findings if "1.2.3.4" in f.title and "brute-force" in f.title.lower()]
    assert len(per_ip) == 1


def test_analyzer_respects_max_files_cap():
    fs = FakeFileSystem(files={
        f"/var/log/cphulkd.log.{i}": SAMPLE_CPHULK for i in range(5)
    })
    findings = analyze_cphulk_logs(
        [f"/var/log/cphulkd.log.{i}" for i in range(5)],
        fs,
        rules={"max_files": 2},
    )
    summary = next(f for f in findings if "Scanned" in f.title)
    assert summary.details["files_scanned"] <= 2


def test_analyzer_boundary_threshold():
    """At exactly brute_force_warn=5, the 5th attempt fires WARN; the 4th does not."""
    def _log_with_n(n: int) -> str:
        return "\n".join([
            f'[2026-08-17 04:12:{i:02d} -0500] warn [cphulkd] '
            f'Brute force attempt detected for user "root" from IP 1.2.3.4'
            for i in range(n)
        ])

    fs = FakeFileSystem(files={"/var/log/cphulkd.log": _log_with_n(4)})
    findings = analyze_cphulk_logs(
        ["/var/log/cphulkd.log"], fs,
        rules={"brute_force_warn": 5},
    )
    per_ip = [f for f in findings if "1.2.3.4" in f.title and "brute-force" in f.title.lower()]
    assert per_ip == []

    fs = FakeFileSystem(files={"/var/log/cphulkd.log": _log_with_n(5)})
    findings = analyze_cphulk_logs(
        ["/var/log/cphulkd.log"], fs,
        rules={"brute_force_warn": 5},
    )
    per_ip = [f for f in findings if "1.2.3.4" in f.title and "brute-force" in f.title.lower()]
    assert len(per_ip) == 1
    assert per_ip[0].severity == Severity.WARN