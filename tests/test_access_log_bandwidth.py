"""Regression tests for AISO-204 — bandwidth anomaly detection (top bandwidth hog).

The rule fires when a single source IP accounts for an unusual share of the
total bytes served in the access log. Default thresholds (configurable via
`modules.access_log.bandwidth_hog_warn` / `bandwidth_hog_crit`):

    share >= 0.80  → CRITICAL
    share >= 0.50  → WARN

The rule is skipped entirely when fewer than 1000 lines were parsed; on a
tiny sample one host is mechanically dominant and the signal is meaningless.

These tests are the regression lock — flipping the share / line thresholds
or dropping the rule from the analyzer must turn at least one of these red.
"""

from __future__ import annotations

from alma_audit.analyzers.access_log import (
    AccessAggregator,
    analyze_access_logs,
    parse_line,
)
from alma_audit.models import Severity


def _build_log(host_bytes: dict[str, int], lines_per_host: int) -> str:
    """Synthesize an Apache combined-log blob.

    Each host gets `lines_per_host` GET requests; each request advertises
    the byte size that contributes `host_bytes[host]` to `bytes_by_host`.
    Counts allocate evenly across the host's lines so a 90%-share target
    falls out of (one host bytes / total bytes).
    """
    rows: list[str] = []
    second = 0
    for host, total_bytes in host_bytes.items():
        per_line = max(1, total_bytes // lines_per_host)
        for _ in range(lines_per_host):
            second = (second + 1) % 60
            rows.append(
                f'{host} - - [17/Aug/2026:04:12:{second:02d} +0000] '
                f'"GET /p HTTP/1.1" 200 {per_line} "-" "ua"'
            )
    return "\n".join(rows) + "\n"


def _find(findings, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


def test_analyzer_emits_critical_bandwidth_hog(make_fs):
    # 2000 lines total, 1000 lines per host so a host with 900 KB out of
    # 1 MB total is exactly 90% — comfortably above the 0.80 CRITICAL threshold.
    log = _build_log(
        host_bytes={"10.0.0.1": 900_000, "10.0.0.2": 100_000},
        lines_per_host=1000,
    )
    fs = make_fs({"/var/log/apache2/access_log": log})
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs,
        rules={"max_lines_per_file": 0},  # disable cap so all 2000 lines parse
    )

    crit = _find(findings, title_contains="bandwidth")
    assert crit, "expected a bandwidth finding for a 90%-share IP"
    assert crit[0].severity == Severity.CRITICAL
    details = crit[0].details
    # Acceptance criterion: details expose {host, bytes, share, total}.
    assert details["host"] == "10.0.0.1"
    assert details["bytes"] == 900_000
    assert details["total"] == 1_000_000
    assert details["share"] == 0.9
    assert "10.0.0.1" in crit[0].title


def test_analyzer_no_bandwidth_finding_on_even_split(make_fs):
    # Five hosts split evenly (20% each) — below both thresholds.
    log = _build_log(
        host_bytes={f"10.0.0.{i}": 100_000 for i in range(1, 6)},
        lines_per_host=400,  # 5 × 400 = 2000 lines
    )
    fs = make_fs({"/var/log/apache2/access_log": log})
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs,
        rules={"max_lines_per_file": 0},
    )
    assert _find(findings, title_contains="bandwidth") == []


def test_analyzer_bandwidth_warn_band(make_fs):
    # Single host at 60% share — between WARN (0.50) and CRITICAL (0.80).
    log = _build_log(
        host_bytes={"10.0.0.1": 600_000, "10.0.0.2": 400_000},
        lines_per_host=1000,  # 2000 lines
    )
    fs = make_fs({"/var/log/apache2/access_log": log})
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs,
        rules={"max_lines_per_file": 0},
    )
    bw = _find(findings, title_contains="bandwidth")
    assert bw, "expected a bandwidth WARN finding"
    assert bw[0].severity == Severity.WARN
    assert bw[0].details["host"] == "10.0.0.1"
    assert bw[0].details["share"] == 0.6


def test_analyzer_bandwidth_rule_skipped_on_tiny_sample(make_fs):
    # 50 lines per host × 2 = 100 lines — below the 1000-line gate.
    log = _build_log(
        host_bytes={"10.0.0.1": 90_000, "10.0.0.2": 10_000},
        lines_per_host=50,
    )
    fs = make_fs({"/var/log/apache2/access_log": log})
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs,
        rules={"max_lines_per_file": 0},
    )
    assert _find(findings, title_contains="bandwidth") == [], (
        "bandwidth rule must not fire on logs with < 1000 lines"
    )


def test_analyzer_bandwidth_threshold_override_suppresses_critical(make_fs):
    # 90%-share host, but thresholds raised so neither fires.
    log = _build_log(
        host_bytes={"10.0.0.1": 900_000, "10.0.0.2": 100_000},
        lines_per_host=1000,
    )
    fs = make_fs({"/var/log/apache2/access_log": log})
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs,
        rules={
            "max_lines_per_file": 0,
            "bandwidth_hog_warn": 0.99,
            "bandwidth_hog_crit": 0.999,
        },
    )
    assert _find(findings, title_contains="bandwidth") == []


def test_aggregator_bytes_by_host_contract_holds():
    """Direct aggregator test: bytes_by_host + bytes_total must reflect inputs.

    Locks the data contract the rule depends on so a refactor of `add()`
    cannot silently break `rule_bandwidth_hog` without flipping this test.
    """
    agg = AccessAggregator()
    for host, payload in (("10.0.0.1", 500_000), ("10.0.0.2", 500_000)):
        line = (
            f'{host} - - [17/Aug/2026:04:12:00 +0000] '
            f'"GET /p HTTP/1.1" 200 {payload} "-" "ua"'
        )
        rec = parse_line(line)
        assert rec is not None
        agg.add(rec)
    assert agg.bytes_total == 1_000_000
    assert agg.bytes_by_host["10.0.0.1"] == 500_000
    assert agg.bytes_by_host["10.0.0.2"] == 500_000
    assert agg.total_lines == 2
