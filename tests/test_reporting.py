"""Tests for the reporting layer."""

from __future__ import annotations

import json
import os

from alma_audit.models import Finding, Severity
from alma_audit.reporting import (
    build_report,
    write_json_report,
    write_markdown_report,
)


def _findings():
    return [
        Finding(
            module="access_log",
            severity=Severity.INFO,
            title="Scanned 1 file",
            description="ok",
        ),
        Finding(
            module="modsec_log",
            severity=Severity.CRITICAL,
            title="Critical rule fired",
            description="bad",
            details={"rule_ids": ["942100"]},
            recommendation="block the IP",
        ),
    ]


def test_build_report_counts_severities(tmp_path):
    findings = _findings()
    report = build_report(findings)
    assert report.summary["info"] == 1
    assert report.summary["critical"] == 1
    assert report.summary["warn"] == 0
    assert report.summary["total_findings"] == 2
    assert report.findings == findings


def test_write_json_report(tmp_path):
    report = build_report(_findings())
    path = write_json_report(report, str(tmp_path))
    assert os.path.isfile(path)
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    assert payload["summary"]["critical"] == 1
    assert payload["findings"][1]["module"] == "modsec_log"
    assert payload["findings"][1]["details"]["rule_ids"] == ["942100"]


def test_write_markdown_report(tmp_path):
    report = build_report(_findings())
    path = write_markdown_report(report, str(tmp_path))
    assert os.path.isfile(path)
    text = open(path, encoding="utf-8").read()
    assert "# AlmaAudit Report" in text
    assert "CRITICAL" in text
    assert "block the IP" in text
    assert "```json" in text  # details rendered as JSON


def test_write_reports_overwrites(tmp_path):
    """Second run overwrites the first — no history (operators handle that)."""
    report1 = build_report([Finding("m", Severity.INFO, "first", "x")])
    report2 = build_report([Finding("m", Severity.WARN, "second", "y")])
    json1 = write_json_report(report1, str(tmp_path))
    json2 = write_json_report(report2, str(tmp_path))
    assert json1 == json2
    payload = json.load(open(json2, encoding="utf-8"))
    assert payload["summary"]["warn"] == 1
