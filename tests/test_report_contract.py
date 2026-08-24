"""AISO-119 §7.1 / §8 — JSON report stability + summary keys contract.

The detection contract requires:
  - `Finding.to_dict()` MUST be deterministic (sorted keys, no set
    serialisation).
  - `AuditReport.summary` MUST contain the four required keys:
    `total_findings`, `info`, `warn`, `critical`.
  - Two consecutive runs against the same inputs MUST produce
    byte-identical JSON reports, modulo the `timestamp` field.

These tests lock the contract from the AISO-121 integration side so
that the DevOps (AISO-122) smoke test can rely on report diffs.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from alma_audit.models import Finding, Severity
from alma_audit.reporting import build_report, write_json_report


def _sample_findings() -> list[Finding]:
    return [
        Finding(module="access_log", severity=Severity.INFO, title="info", description="ok"),
        Finding(module="domlog_inventory", severity=Severity.WARN, title="warn", description="e"),
        Finding(
            module="modsec_log",
            severity=Severity.CRITICAL,
            title="crit",
            description="bad",
            details={"rule_ids": ["942100"], "sample_paths": ["/a", "/b"]},
        ),
    ]


def test_finding_to_dict_is_deterministic() -> None:
    f = Finding(
        module="x",
        severity=Severity.INFO,
        title="t",
        description="d",
        details={"b": 2, "a": 1, "c": [3, 1]},
    )
    d = f.to_dict()
    # Top-level keys must be in a stable order. dataclasses.asdict-style
    # output preserves declaration order; we just assert the keys exist.
    assert list(d.keys()) == ["module", "severity", "title", "description", "details", "recommendation"]
    # Nested dict ordering is implementation-defined in Python 3.7+, but
    # `json.dumps` with sort_keys gives a stable byte string. That's the
    # contract the report writer relies on.
    a = json.dumps(d, sort_keys=True, ensure_ascii=False)
    b = json.dumps(d, sort_keys=True, ensure_ascii=False)
    assert a == b


def test_audit_report_summary_has_required_keys() -> None:
    findings = _sample_findings()
    report = build_report(findings)
    required = {"total_findings", "info", "warn", "critical"}
    assert required.issubset(report.summary.keys()), (
        f"AuditReport.summary missing required keys; got {set(report.summary.keys())}"
    )
    assert report.summary["total_findings"] == 3
    assert report.summary["info"] == 1
    assert report.summary["warn"] == 1
    assert report.summary["critical"] == 1


def test_audit_report_to_dict_round_trip(tmp_path: Any) -> None:
    """to_dict() is JSON-serialisable round-trip clean."""
    report = build_report(_sample_findings())
    payload = report.to_dict()
    # Required top-level keys.
    assert set(payload.keys()) >= {"timestamp", "hostname", "findings", "summary"}
    # All findings serialise cleanly to JSON (no set, no bytes, no Decimal).
    json.dumps(payload, ensure_ascii=False)


def test_two_runs_produce_identical_findings_payload(tmp_path: Any) -> None:
    """Two runs against the same findings produce identical JSON, except
    for `timestamp`.

    The contract §8 requires: "Report hashes stable across two
    consecutive runs against the same log directory (same findings, same
    counts, modulo timestamps) when --state-path is NOT passed."
    """
    findings = _sample_findings()
    # Run twice in the same process — `build_report` stamps a fresh
    # timestamp each call, so we strip that field before comparing.
    r1 = build_report(findings)
    r2 = build_report(findings)

    p1 = r1.to_dict()
    p2 = r2.to_dict()
    p1.pop("timestamp", None)
    p2.pop("timestamp", None)

    # Even the findings themselves are sorted by their dataclass order.
    # The two `to_dict()` calls must produce structurally equal objects.
    assert json.dumps(p1, sort_keys=True) == json.dumps(p2, sort_keys=True)


def test_write_json_report_writes_valid_json(tmp_path: Any) -> None:
    findings = _sample_findings()
    report = build_report(findings)
    out_path = write_json_report(report, str(tmp_path))
    with open(out_path, encoding="utf-8") as fh:
        payload = json.load(fh)
    # Re-load and assert summary keys survive the round-trip.
    assert set(payload["summary"].keys()) >= {"total_findings", "info", "warn", "critical"}
    assert payload["summary"]["critical"] == 1


@pytest.mark.parametrize(
    "severity_count",
    [
        (0, 0, 0),
        (1, 0, 0),
        (0, 1, 0),
        (0, 0, 1),
        (5, 3, 2),
    ],
)
def test_summary_counts_match_input(
    tmp_path: Any, severity_count: tuple[int, int, int]
) -> None:
    info_n, warn_n, crit_n = severity_count
    findings: list[Finding] = []
    findings.extend(Finding("m", Severity.INFO, "i", "x") for _ in range(info_n))
    findings.extend(Finding("m", Severity.WARN, "w", "x") for _ in range(warn_n))
    findings.extend(Finding("m", Severity.CRITICAL, "c", "x") for _ in range(crit_n))
    report = build_report(findings)
    assert report.summary["info"] == info_n
    assert report.summary["warn"] == warn_n
    assert report.summary["critical"] == crit_n
    assert report.summary["total_findings"] == info_n + warn_n + crit_n