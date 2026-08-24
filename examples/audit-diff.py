#!/usr/bin/env python3
"""alma-audit trend sidecar.

Diffs two `alma-audit-latest.json` reports and emits a structured
"what changed" summary in three formats: JSON (machine-readable),
Markdown (operator-friendly), and plain text (for log/cron output).

Contract:

  - **Read-only.** The script never modifies the input reports; it
    only reads them and writes the diff to a separate output file
    (or stdout).
  - **Deterministic.** Output is sorted by severity then title so two
    runs over the same inputs produce byte-identical output. No
    timestamps leak into the diff content (they are stored once at
    the top of the report).
  - **Three formats, one schema.** JSON / Markdown / text all carry
    the same diff rows (added, removed, severity_changed, count_changed)
    so operators can switch between them without learning a new shape.

Usage:

    audit-diff.py PREVIOUS CURRENT [--format json|markdown|text] [--output PATH]

Examples:

    # Diff yesterday's report against today's, print JSON to stdout.
    audit-diff.py alma-audit-prev.json alma-audit-latest.json --format json

    # Write a Markdown report to /var/log/alma-audit/diff.md.
    audit-diff.py alma-audit-prev.json alma-audit-latest.json \\
        --format markdown --output /var/log/alma-audit/diff.md

    # Cron line (rotate yesterday's report before alma-audit runs):
    #   15 4 * * * cp /var/log/alma-audit/alma-audit-latest.json \\
    #                   /var/log/alma-audit/alma-audit-prev.json
    #   16 4 * * * /usr/local/bin/alma-audit --output /var/log/alma-audit \\
    #                   && /usr/local/bin/audit-diff.py \\
    #                       /var/log/alma-audit/alma-audit-prev.json \\
    #                       /var/log/alma-audit/alma-audit-latest.json \\
    #                       --output /var/log/alma-audit/diff.md

The diff is *content-addressable*: a finding is identified by
`(module, title)` — the same finding emitted across runs hashes to
the same key regardless of whether the description text drifts
(`details["source_ip"]` changes per run for the same finding shape).

This script is a sidecar — it lives in `examples/`, not in the
package proper. Operators who don't run it pay no runtime cost.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Any


# Diff row types. The JSON schema uses these strings verbatim so
# downstream pipelines can branch on them.
DIFF_ADDED = "added"
DIFF_REMOVED = "removed"
DIFF_SEVERITY_CHANGED = "severity_changed"
DIFF_COUNT_CHANGED = "count_changed"


@dataclass(frozen=True)
class DiffRow:
    """One change between two reports.

    `kind` is one of `added`, `removed`, `severity_changed`,
    `count_changed`. `key` is the canonical `(module, title)` tuple
    used to identify the finding across runs. The `before` and
    `after` fields carry the severity + a representative detail
    (e.g. count) for the two runs — they are Optional because
    `added` rows have no `before` and `removed` rows have no `after`.
    """

    kind: str
    module: str
    title: str
    before_severity: str | None
    after_severity: str | None
    before_count: int | None = None
    after_count: int | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.module, self.title)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "module": self.module,
            "title": self.title,
            "before_severity": self.before_severity,
            "after_severity": self.after_severity,
            "before_count": self.before_count,
            "after_count": self.after_count,
        }


@dataclass(frozen=True)
class TrendReport:
    """Top-level container for the diff.

    `rows` is sorted by (kind severity rank, module, title) so the
    output is deterministic across runs.
    """

    previous_timestamp: str | None
    current_timestamp: str | None
    previous_summary: dict[str, int]
    current_summary: dict[str, int]
    rows: list[DiffRow] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "previous_timestamp": self.previous_timestamp,
            "current_timestamp": self.current_timestamp,
            "previous_summary": self.previous_summary,
            "current_summary": self.current_summary,
            "summary_delta": _summary_delta(self.previous_summary, self.current_summary),
            "rows": [r.to_dict() for r in self.rows],
        }


# Severity rank used for sorting. Higher rank = more severe. Sorts
# `severity_changed` rows so escalations float to the top (a finding
# that just turned CRITICAL is more interesting than one that just
# turned INFO).
SEVERITY_RANK = {"INFO": 0, "WARN": 1, "CRITICAL": 2}


def _summary_delta(prev: dict[str, int], curr: dict[str, int]) -> dict[str, int]:
    return {
        "info": curr.get("info", 0) - prev.get("info", 0),
        "warn": curr.get("warn", 0) - prev.get("warn", 0),
        "critical": curr.get("critical", 0) - prev.get("critical", 0),
        "total": curr.get("total_findings", 0) - prev.get("total_findings", 0),
    }


def _load_report(path: str) -> dict[str, Any]:
    """Load a JSON report and assert the shape.

    Raises `SystemExit` with a clear message on any parse / shape
    error — the script's callers are cron entries, and a silent
    crash is worse than a visible failure.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"audit-diff: input file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as exc:
        print(f"audit-diff: malformed JSON in {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(data, dict):
        print(f"audit-diff: {path} is not a JSON object at the root", file=sys.stderr)
        sys.exit(2)
    if "findings" not in data or not isinstance(data["findings"], list):
        print(f"audit-diff: {path} missing 'findings' list", file=sys.stderr)
        sys.exit(2)
    return data


def _index_findings(report: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """Build a (module, title) → finding dict for one report.

    When the same (module, title) appears more than once in a single
    report (a known possibility when a brute-force burst produces
    multiple findings from different IPs), we keep the FIRST one and
    count how many times it appeared under `__count`. This makes
    the diff robust against the duplicate-suppression contract in
    the analyzer layer (we compare what the operator sees, not what
    the rules emitted internally).
    """
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for f in report["findings"]:
        if not isinstance(f, dict):
            continue
        module = f.get("module")
        title = f.get("title")
        severity = f.get("severity")
        if not (isinstance(module, str) and isinstance(title, str) and isinstance(severity, str)):
            continue
        key = (module, title)
        if key not in index:
            index[key] = dict(f)
            index[key]["__count"] = 1
        else:
            index[key]["__count"] += 1
    return index


def _diff_reports(prev: dict[str, Any], curr: dict[str, Any]) -> TrendReport:
    """Compute the diff between two loaded reports."""
    prev_index = _index_findings(prev)
    curr_index = _index_findings(curr)
    rows: list[DiffRow] = []

    # Added in current run.
    for key, finding in curr_index.items():
        if key not in prev_index:
            rows.append(DiffRow(
                kind=DIFF_ADDED,
                module=key[0],
                title=key[1],
                before_severity=None,
                after_severity=finding.get("severity"),
                before_count=None,
                after_count=finding.get("__count"),
            ))

    # Removed in current run.
    for key, finding in prev_index.items():
        if key not in curr_index:
            rows.append(DiffRow(
                kind=DIFF_REMOVED,
                module=key[0],
                title=key[1],
                before_severity=finding.get("severity"),
                after_severity=None,
                before_count=finding.get("__count"),
                after_count=None,
            ))

    # Changed (severity + count).
    for key in prev_index.keys() & curr_index.keys():
        prev_f = prev_index[key]
        curr_f = curr_index[key]
        prev_sev = prev_f.get("severity")
        curr_sev = curr_f.get("severity")
        prev_count = prev_f.get("__count", 1)
        curr_count = curr_f.get("__count", 1)
        if prev_sev != curr_sev:
            rows.append(DiffRow(
                kind=DIFF_SEVERITY_CHANGED,
                module=key[0],
                title=key[1],
                before_severity=prev_sev,
                after_severity=curr_sev,
                before_count=prev_count,
                after_count=curr_count,
            ))
        elif prev_count != curr_count:
            rows.append(DiffRow(
                kind=DIFF_COUNT_CHANGED,
                module=key[0],
                title=key[1],
                before_severity=prev_sev,
                after_severity=curr_sev,
                before_count=prev_count,
                after_count=curr_count,
            ))

    rows.sort(key=lambda r: (
        # Severity rank for the "after" side; for `removed` rows fall
        # back to the "before" side so they sort near the changed rows
        # they used to belong to.
        -SEVERITY_RANK.get(r.after_severity or r.before_severity or "INFO", 0),
        r.kind,
        r.module,
        r.title,
    ))
    return TrendReport(
        previous_timestamp=prev.get("timestamp"),
        current_timestamp=curr.get("timestamp"),
        previous_summary=dict(prev.get("summary", {})),
        current_summary=dict(curr.get("summary", {})),
        rows=rows,
    )


# --- formatters -----------------------------------------------------------


def render_json(report: TrendReport) -> str:
    """JSON formatter. Stable key order; UTF-8; indent=2."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_markdown(report: TrendReport) -> str:
    """Markdown formatter. Designed for paste-into-issue-tracker."""
    lines: list[str] = []
    lines.append("# AlmaAudit Trend Diff")
    lines.append("")
    lines.append(f"- **Previous run:** {report.previous_timestamp or 'unknown'}")
    lines.append(f"- **Current run:**  {report.current_timestamp or 'unknown'}")
    lines.append("")
    delta = _summary_delta(report.previous_summary, report.current_summary)
    lines.append("## Summary delta")
    lines.append("")
    lines.append("| Severity | Previous | Current | Δ |")
    lines.append("|----------|---------:|--------:|--:|")
    for sev in ("info", "warn", "critical", "total"):
        if sev == "total":
            prev = report.previous_summary.get("total_findings", 0)
            curr = report.current_summary.get("total_findings", 0)
        else:
            prev = report.previous_summary.get(sev, 0)
            curr = report.current_summary.get(sev, 0)
        d = delta.get(sev, 0)
        sign = "+" if d > 0 else ""
        lines.append(f"| {sev.upper() if sev != 'total' else 'Total'} | {prev} | {curr} | {sign}{d} |")
    lines.append("")
    if not report.rows:
        lines.append("_No changes between runs._")
        return "\n".join(lines)
    lines.append(f"## Changes ({len(report.rows)})")
    lines.append("")
    for kind in (DIFF_SEVERITY_CHANGED, DIFF_COUNT_CHANGED, DIFF_ADDED, DIFF_REMOVED):
        subset = [r for r in report.rows if r.kind == kind]
        if not subset:
            continue
        lines.append(f"### {kind.replace('_', ' ').title()} ({len(subset)})")
        lines.append("")
        for r in subset:
            if r.kind == DIFF_ADDED:
                lines.append(
                    f"- **+ [{r.after_severity}] `{r.module}` — {r.title}"
                    + (f" (×{r.after_count})" if r.after_count and r.after_count > 1 else "")
                )
            elif r.kind == DIFF_REMOVED:
                lines.append(
                    f"- **- [{r.before_severity}] `{r.module}` — {r.title}"
                    + (f" (was ×{r.before_count})" if r.before_count and r.before_count > 1 else "")
                )
            elif r.kind == DIFF_SEVERITY_CHANGED:
                lines.append(
                    f"- **~ `{r.module}`** — {r.title}: "
                    f"{r.before_severity} → {r.after_severity}"
                )
            elif r.kind == DIFF_COUNT_CHANGED:
                lines.append(
                    f"- **~ `{r.module}`** — {r.title}: "
                    f"{r.before_count} → {r.after_count}"
                )
        lines.append("")
    return "\n".join(lines)


def render_text(report: TrendReport) -> str:
    """Plain-text formatter. One line per change, easy to grep / pipe."""
    lines: list[str] = []
    lines.append(f"alma-audit trend diff: {report.previous_timestamp or '?'} → {report.current_timestamp or '?'}")
    delta = _summary_delta(report.previous_summary, report.current_summary)
    lines.append(
        f"  INFO: {report.previous_summary.get('info', 0)} → {report.current_summary.get('info', 0)} "
        f"({'+' if delta['info'] >= 0 else ''}{delta['info']})"
    )
    lines.append(
        f"  WARN: {report.previous_summary.get('warn', 0)} → {report.current_summary.get('warn', 0)} "
        f"({'+' if delta['warn'] >= 0 else ''}{delta['warn']})"
    )
    lines.append(
        f"  CRITICAL: {report.previous_summary.get('critical', 0)} → {report.current_summary.get('critical', 0)} "
        f"({'+' if delta['critical'] >= 0 else ''}{delta['critical']})"
    )
    if not report.rows:
        lines.append("  (no changes)")
        return "\n".join(lines)
    for r in report.rows:
        if r.kind == DIFF_ADDED:
            tag = "+"
            sev = r.after_severity or "?"
            lines.append(f"  {tag} [{sev}] {r.module}: {r.title}")
        elif r.kind == DIFF_REMOVED:
            tag = "-"
            sev = r.before_severity or "?"
            lines.append(f"  {tag} [{sev}] {r.module}: {r.title}")
        elif r.kind == DIFF_SEVERITY_CHANGED:
            lines.append(
                f"  ~ {r.module}: {r.title} "
                f"({r.before_severity} → {r.after_severity})"
            )
        elif r.kind == DIFF_COUNT_CHANGED:
            lines.append(
                f"  ~ {r.module}: {r.title} "
                f"(count {r.before_count} → {r.after_count})"
            )
    return "\n".join(lines)


# --- CLI ------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit-diff",
        description=(
            "Diff two alma-audit JSON reports and emit a structured "
            "what-changed summary. Read-only; never mutates the "
            "input reports."
        ),
    )
    parser.add_argument("previous", help="Path to the previous alma-audit JSON report.")
    parser.add_argument("current", help="Path to the current alma-audit JSON report.")
    parser.add_argument(
        "--format", "-f",
        choices=["json", "markdown", "text"],
        default="text",
        help="Output format. Default: text (good for cron logs).",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write to this path instead of stdout.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    prev = _load_report(args.previous)
    curr = _load_report(args.current)
    report = _diff_reports(prev, curr)
    if args.format == "json":
        out = render_json(report)
    elif args.format == "markdown":
        out = render_markdown(report)
    else:
        out = render_text(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
            if not out.endswith("\n"):
                fh.write("\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())