"""Regression tests for AISO-211 — new ``error_log`` analyzer.

The Apache ``error_log`` is a separate, per-line log with module +
PID + client IP context. It's where inter-module failures
(mpm_prefork OOM, ssl handshake errors) show up. Previously the
``modsec_log`` analyzer only scanned the file's *presence* — the
contents were dropped. This analyzer surfaces the per-IP error
breakdown so the operator can act on bursts.

The analyzer is OPT-IN via ``modules.error_log.enabled: true`` to
keep the audit scope unchanged for hosts that don't have it.

These tests are the regression lock — flipping the ``enabled`` flag
default, or stripping the per-IP rollup, must turn at least one of
these red.
"""

from __future__ import annotations

from alma_audit.analyzers.error_log import (
    ErrorAggregator,
    ErrorLogRecord,
    analyze_error_log,
    parse_error_line,
)
from alma_audit.models import Severity


# ---------------------------------------------------------------------------
# Parser surface
# ---------------------------------------------------------------------------


def test_parser_handles_combined_error_line():
    """Apache 2.4 combined error_log format → parsed record."""
    line = (
        "[Sun Aug 24 04:12:34.123456 2026] [core:error] [pid 12345] "
        "[client 1.2.3.4:5678] File does not exist: /var/www/foo"
    )
    rec = parse_error_line(line)
    assert rec is not None
    assert rec.client_ip == "1.2.3.4"
    assert rec.module == "core"
    assert rec.level == "error"
    assert rec.pid == 12345
    assert rec.message == "File does not exist: /var/www/foo"
    assert rec.timestamp.startswith("Sun Aug 24")


def test_parser_handles_warn_level():
    """Apache error_log has warn / error / crit / info / debug."""
    line = (
        "[Mon Aug 25 10:00:00.000 2026] [mpm_prefork:notice] [pid 99] "
        "[client 9.9.9.9:1234] AH00163: mpm_prefork slots configured"
    )
    rec = parse_error_line(line)
    assert rec is not None
    assert rec.level == "notice"
    assert rec.module == "mpm_prefork"


def test_parser_no_client_ip_still_parses():
    """Some error_log lines have no client — return record with empty ip."""
    line = (
        "[Tue Aug 26 12:00:00.000 2026] [ssl:warn] [pid 7] "
        "AH02013: no SSL handshake possible"
    )
    rec = parse_error_line(line)
    assert rec is not None
    assert rec.client_ip == ""
    assert rec.module == "ssl"
    assert rec.level == "warn"


def test_parser_returns_none_for_garbage():
    """Non-error_log lines → None (caller bumps malformed counter)."""
    assert parse_error_line("not an error log line") is None
    assert parse_error_line("") is None
    # Apache access-log style with status code → not an error_log line.
    assert parse_error_line(
        '127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] '
        '"GET / HTTP/1.1" 200 100 "-" "ua"'
    ) is None


# ---------------------------------------------------------------------------
# Aggregator surface
# ---------------------------------------------------------------------------


def test_aggregator_counts_per_client_ip():
    """Per-IP error counts surface in the finalized summary."""
    agg = ErrorAggregator()
    # 3 errors from 1.2.3.4, 2 from 5.6.7.8.
    for _ in range(3):
        agg.add(ErrorLogRecord(
            timestamp="Sun Aug 24 04:12:34", module="core", level="error",
            pid=1, client_ip="1.2.3.4", message="File does not exist: /a",
        ))
    for _ in range(2):
        agg.add(ErrorLogRecord(
            timestamp="Sun Aug 24 04:13:00", module="core", level="error",
            pid=1, client_ip="5.6.7.8", message="File does not exist: /b",
        ))
    summary = agg.finalize()
    counts = {row["ip"]: row["count"] for row in summary["top_clients"]}
    assert counts["1.2.3.4"] == 3
    assert counts["5.6.7.8"] == 2


def test_aggregator_message_template_aggregation():
    """Same message template across IPs rolls up into top_messages."""
    agg = ErrorAggregator()
    for _ in range(5):
        agg.add(ErrorLogRecord(
            timestamp="Sun Aug 24 04:12:34", module="core", level="error",
            pid=1, client_ip="1.2.3.4",
            message="File does not exist: /var/www/foo",
        ))
    summary = agg.finalize()
    # The summary should include a top_messages list; the file-not-found
    # template appears with count >= 5.
    msgs = {row["template"]: row["count"] for row in summary["top_messages"]}
    assert any("File does not exist" in tpl for tpl in msgs)
    assert sum(row["count"] for row in summary["top_messages"]) >= 5


# ---------------------------------------------------------------------------
# Analyzer-level surface (the orchestrator)
# ---------------------------------------------------------------------------


def test_analyzer_emits_top_clients_finding(make_fs):
    """The analyzer emits a finding with details.top_clients populated."""
    log = (
        "[Sun Aug 24 04:12:34.000 2026] [core:error] [pid 1] "
        "[client 1.2.3.4:5678] File does not exist: /var/www/foo\n"
    )
    fs = make_fs({"/var/log/apache2/error_log": log})
    findings = analyze_error_log(
        ["/var/log/apache2/error_log"],
        fs,
        rules={"enabled": True},
    )
    # The top_clients rollup is in the summary finding; downstream
    # rules consume it.
    summary_findings = [
        f for f in findings
        if f.module == "error_log" and "error log" in f.title.lower()
    ]
    assert summary_findings, "expected a summary finding"
    summary = summary_findings[0].details
    assert summary["top_clients"]
    assert summary["top_clients"][0]["ip"] == "1.2.3.4"
    assert summary["top_clients"][0]["count"] == 1


def test_analyzer_disabled_by_default(make_fs):
    """AISO-211: enabled=false → no findings emitted.

    Hosts without ``/var/log/apache2/error_log`` (or operators who
    haven't opted in) get a quiet run. The analyzer does not surface
    an INFO finding either — the operator hasn't enabled the
    analyzer, so its absence is silent.
    """
    log = (
        "[Sun Aug 24 04:12:34.000 2026] [core:error] [pid 1] "
        "[client 1.2.3.4:5678] File does not exist: /var/www/foo\n"
    )
    fs = make_fs({"/var/log/apache2/error_log": log})
    # enabled is omitted (defaults to False).
    findings = analyze_error_log(
        ["/var/log/apache2/error_log"],
        fs,
    )
    assert findings == []


def test_analyzer_message_template_burst_fires_critical(make_fs):
    """Same message × 100+ on a single host → CRITICAL finding."""
    log_lines = [
        "[Sun Aug 24 04:12:00.000 2026] [core:error] [pid 1] "
        "[client 1.2.3.4:5678] File does not exist: /var/www/foo"
    ] * 120
    fs = make_fs({"/var/log/apache2/error_log": "\n".join(log_lines) + "\n"})
    findings = analyze_error_log(
        ["/var/log/apache2/error_log"],
        fs,
        rules={"enabled": True},
    )
    crit_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit_findings, "expected a CRITICAL finding for 120× same template"
    assert any(
        "1.2.3.4" in str(f.details.get("top_messages", ""))
        or "File does not exist" in str(f.details.get("top_messages", ""))
        for f in crit_findings
    )


def test_analyzer_skips_compressed(make_fs):
    """Rotated .gz copies are skipped (read-only contract).

    Same as the access_log analyzer: a compressed rotation is listed
    in ``skipped_compressed`` for forensics but not scanned.
    """
    fs = make_fs({})  # FakeFS doesn't allow registering .gz paths.
    # Just confirm the helper is_compressed recognises the suffix.
    from alma_audit.analyzers.error_log.settings import is_compressed
    assert is_compressed("/var/log/apache2/error_log.1.gz") is True
    assert is_compressed("/var/log/apache2/error_log") is False