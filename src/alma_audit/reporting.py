"""Reporting layer: JSON + Markdown writers.

The CLI hands a list of Finding objects to the writers. We do not try to
be clever — these are simple templates. Severity emojis come from the
existing audit toolkit conventions so reports feel familiar.
"""

from __future__ import annotations

import datetime
import json
import os
import socket
from typing import Iterable

from .models import AuditReport, Finding, Severity

SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.INFO: "✅",
    Severity.WARN: "⚠️",
    Severity.CRITICAL: "🚨",
}


def build_report(findings: Iterable[Finding], hostname: str | None = None) -> AuditReport:
    """Assemble an AuditReport from a list of findings."""
    items = list(findings)
    info = sum(1 for f in items if f.severity == Severity.INFO)
    warn = sum(1 for f in items if f.severity == Severity.WARN)
    crit = sum(1 for f in items if f.severity == Severity.CRITICAL)
    return AuditReport(
        timestamp=datetime.datetime.now().isoformat(timespec="seconds"),
        hostname=hostname or socket.gethostname(),
        findings=items,
        summary={
            "total_findings": len(items),
            "info": info,
            "warn": warn,
            "critical": crit,
        },
    )


def write_json_report(report: AuditReport, output_dir: str) -> str:
    """Write the JSON report to <output_dir>/alma-audit-latest.json."""
    path = os.path.join(output_dir, "alma-audit-latest.json")
    os.makedirs(output_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False)
    return path


def write_markdown_report(report: AuditReport, output_dir: str) -> str:
    """Write a Markdown report to <output_dir>/alma-audit-latest.md."""
    path = os.path.join(output_dir, "alma-audit-latest.md")
    os.makedirs(output_dir, exist_ok=True)
    lines: list[str] = []
    lines.append(f"# AlmaAudit Report — {report.hostname}")
    lines.append("")
    lines.append(f"- **Timestamp:** {report.timestamp}")
    lines.append(f"- **Hostname:** {report.hostname}")
    lines.append(f"- **Total findings:** {report.summary['total_findings']}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in (Severity.INFO, Severity.WARN, Severity.CRITICAL):
        lines.append(f"| {sev.value} | {report.summary[sev.value.lower()]} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not report.findings:
        lines.append("_No findings._")
    for f in report.findings:
        emoji = SEVERITY_EMOJI[f.severity]
        lines.append(f"### {emoji} [{f.severity.value}] {f.title}")
        lines.append("")
        lines.append(f"- **Module:** `{f.module}`")
        lines.append(f"- **Description:** {f.description}")
        if f.recommendation:
            lines.append(f"- **Recommendation:** {f.recommendation}")
        if f.details:
            lines.append("- **Details:**")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(f.details, indent=2, ensure_ascii=False))
            lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path
