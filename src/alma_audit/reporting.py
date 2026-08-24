"""Reporting layer: JSON + Markdown writers + forensic export.

AISO-199: the per-IP forensic detail is split out of the main
report into `alma-audit-forensic.json`. The Markdown summary stays
short (counts + top-10 + recommendation), and the operator opens the
forensic JSON for the full per-IP breakdown — or pipes it into the
Cloudflare firewall-rule builder for mass-blocking.
"""

from __future__ import annotations

import datetime
import json
import os
import socket
from typing import Iterable

from .forensic_export import build_forensic_export
from .models import AuditReport, Finding, Severity

SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.INFO: "✅",
    Severity.WARN: "⚠️",
    Severity.CRITICAL: "🚨",
}

# Findings whose `details` dict carries per-IP forensic detail. The
# Markdown summary pulls only the top 10 entries; the full list lives
# in `alma-audit-forensic.json`.
#
# AISO-200: `probe_paths_by_ip` is intentionally excluded — it's the
# same IPs as `top_attackers`, just sliced by path instead of by IP.
# Showing both would duplicate the operator-eye view. The
# path-by-path breakdown lives in `alma-audit-forensic.json` for
# forensic consumers.
_FORENSIC_FIELDS: tuple[str, ...] = (
    "top_attackers",
    "host_errors_top",
    "ssh_fail_details",
    "sudo_fail_details",
)


def _strip_forensic(findings: list[Finding], keep_top: int = 10) -> list[Finding]:
    """Return a copy of `findings` with forensic fields truncated or removed.

    Behaviour per `_FORENSIC_FIELDS` whitelist:

    - `top_attackers`, `host_errors_top`, `ssh_fail_details`,
      `sudo_fail_details`: kept inline (top N) so the operator sees
      the most actionable IPs at a glance.
    - `probe_paths_by_ip` (AISO-200): REMOVED entirely. It's the same
      data as `top_attackers`, just sliced by path instead of by IP;
      the full breakdown lives in `alma-audit-forensic.json`.

    The original `details` dict is preserved in full on the main JSON
    report (so machine consumers still see everything); only the
    Markdown rendering strips the long lists.
    """
    _REMOVED_FIELDS = frozenset({"probe_paths_by_ip"})

    out: list[Finding] = []
    for f in findings:
        new_details = dict(f.details or {})
        # AISO-200: drop fields the Markdown considers redundant with
        # other top-N fields (probe_paths_by_ip == top_attackers by IP).
        for field in _REMOVED_FIELDS:
            new_details.pop(field, None)
        for field in _FORENSIC_FIELDS:
            value = new_details.get(field)
            if isinstance(value, list) and len(value) > keep_top:
                # Sort by count desc when the entries carry a numeric
                # `count` or `total_probe_requests` field.
                def _key(r: object) -> int:
                    if not isinstance(r, dict):
                        return 0
                    return (
                        r.get("count", 0)
                        or r.get("error_count", 0)
                        or r.get("total_probe_requests", 0)
                    )
                truncated = sorted(value, key=_key, reverse=True)[:keep_top]
                new_details[field] = truncated
                new_details[f"_{field}_total"] = len(value)
        # Build a new Finding with the trimmed details. Finding is a
        # frozen dataclass, so we replace it via `dataclasses.replace`.
        from dataclasses import replace
        out.append(replace(f, details=new_details))
    return out


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
    """Write the JSON report to <output_dir>/alma-audit-latest.json.

    The JSON carries the full un-trimmed per-IP forensic detail so
    machine consumers see everything.
    """
    path = os.path.join(output_dir, "alma-audit-latest.json")
    os.makedirs(output_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False)
    return path


def write_forensic_report(report: AuditReport, output_dir: str) -> str:
    """Write the per-IP forensic JSON to <output_dir>/alma-audit-forensic.json.

    Bundles the scanner IPs, brute-force IPs, error-burst IPs, sudo-fail
    users, ssh_fail_details, and probe_paths_by_ip into one machine-
    readable file. Also embeds the Cloudflare firewall-rule payloads
    and a copy-paste-ready curl script so the operator can mass-block
    offenders without re-running the audit.
    """
    forensic = build_forensic_export(
        report.findings,
        hostname=report.hostname,
        timestamp=report.timestamp,
    )
    path = os.path.join(output_dir, "alma-audit-forensic.json")
    os.makedirs(output_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(forensic, fh, indent=2, ensure_ascii=False)
    return path


def write_cloudflare_block_script(report: AuditReport, output_dir: str) -> str:
    """Write the bash script that POSTs each rule to Cloudflare.

    The script is generated from the same forensic JSON the audit
    produces, so it's always in sync with the report. The operator
    reviews the script, sets CF_ZONE_ID + CF_API_TOKEN, and runs it.
    """
    forensic = build_forensic_export(
        report.findings,
        hostname=report.hostname,
        timestamp=report.timestamp,
    )
    path = os.path.join(output_dir, "cloudflare-block.sh")
    os.makedirs(output_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(forensic["cloudflare"]["curl_script"])
    os.chmod(path, 0o755)
    return path


def write_markdown_report(report: AuditReport, output_dir: str) -> str:
    """Write a CONCISE Markdown report.

    Per-IP forensic detail is intentionally omitted — full breakdown
    lives in `alma-audit-forensic.json`. The Markdown keeps the top 10
    entries per forensic field so the operator can skim the report
    without scrolling through tens of thousands of lines.
    """
    path = os.path.join(output_dir, "alma-audit-latest.md")
    os.makedirs(output_dir, exist_ok=True)

    # Markdown gets a forensic-trimmed view; JSON gets full detail.
    markdown_finding_list = _strip_forensic(report.findings, keep_top=10)

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
    if not markdown_finding_list:
        lines.append("_No findings._")
    for f in markdown_finding_list:
        emoji = SEVERITY_EMOJI[f.severity]
        lines.append(f"### {emoji} [{f.severity.value}] {f.title}")
        lines.append("")
        lines.append(f"- **Module:** `{f.module}`")
        lines.append(f"- **Description:** {f.description}")
        if f.recommendation:
            lines.append(f"- **Recommendation:** {f.recommendation}")
        if f.details:
            _render_details_summary(lines, f.details)
        lines.append("")
        lines.append("---")
        lines.append("")
    _render_cloudflare_appendix(lines, report)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def _render_details_summary(lines: list[str], details: dict) -> None:
    """Render the details block as compact Markdown (no embedded JSON dump).

    Forensic fields are summarised inline (top-10 lists with `...`
    suffix when truncated); the rest of the details go in a compact
    JSON block whose line count is bounded by `_MAX_DETAIL_LINES`.
    """
    _MAX_DETAIL_LINES = 40
    forensic_keys = set(_FORENSIC_FIELDS)

    # Render forensic fields inline as a Markdown bullet list, then
    # note that the full list lives in the forensic JSON file.
    forensic_subsections: list[str] = []
    other_items: list[tuple[str, object]] = []
    for k, v in details.items():
        if k.startswith("_") and k.endswith("_total"):
            # Truncation hint rendered alongside the forensic section.
            continue
        if k in forensic_keys:
            forensic_subsections.append(f"- **{k}** (top 10 — full list in `alma-audit-forensic.json`):")
            total_field = f"_{k}_total"
            if total_field in details:
                forensic_subsections.append(
                    f"  - _Showing 10 of {details[total_field]} entries._"
                )
            if isinstance(v, list) and v:
                for row in v[:10]:
                    if isinstance(row, dict):
                        # Render the most informative fields.
                        ip = row.get("ip") or row.get("user") or row.get("path", "?")
                        count = (
                            row.get("count")
                            or row.get("error_count")
                            or row.get("total_probe_requests")
                            or 0
                        )
                        ts = row.get("last_seen") or row.get("first_seen") or ""
                        suffix = f" — last seen: `{ts}`" if ts else ""
                        forensic_subsections.append(f"  - `{ip}` × {count}{suffix}")
                    else:
                        forensic_subsections.append(f"  - `{row}`")
        else:
            other_items.append((k, v))

    if forensic_subsections:
        lines.append("- **Forensic summary (top 10 per category):**")
        lines.append("")
        lines.extend(forensic_subsections)
        lines.append("")

    if other_items:
        # Render the rest of the details as compact JSON, truncated
        # to `_MAX_DETAIL_LINES` lines. Beyond that, a pointer to the
        # full forensic JSON.
        rendered = {k: v for k, v in other_items}
        dumped = json.dumps(rendered, indent=2, ensure_ascii=False)
        dumped_lines = dumped.splitlines()
        if len(dumped_lines) <= _MAX_DETAIL_LINES:
            lines.append("- **Other details:**")
            lines.append("")
            lines.append("```json")
            lines.append(dumped)
            lines.append("```")
        else:
            head = "\n".join(dumped_lines[:_MAX_DETAIL_LINES])
            lines.append(
                f"- **Other details (truncated; see `alma-audit-forensic.json` "
                f"for full payload, ~{len(dumped_lines) - _MAX_DETAIL_LINES} "
                f"more lines):**"
            )
            lines.append("")
            lines.append("```json")
            lines.append(head)
            lines.append("... (truncated)")
            lines.append("```")


def _render_cloudflare_appendix(lines: list[str], report: AuditReport) -> None:
    """Append a Cloudflare block-rule summary at the bottom of the MD report."""
    from .forensic_export import build_cloudflare_block_payloads

    payloads = build_cloudflare_block_payloads(report.findings)
    if not payloads:
        return

    # AISO-200: surface the local-IP filter so the operator can see
    # what was excluded (otherwise 127.0.0.1 / 10.x entries vanish
    # silently from the block list).
    filtered = payloads[0].get("_filtered_local_ips", [])

    lines.append("## Cloudflare block rules (apply manually)")
    lines.append("")
    lines.append(
        "The audit generated the following Cloudflare firewall rule "
        "payloads based on the forensic detail. Apply them via the\n"
        "`cloudflare-block.sh` script in this directory, or POST the\n"
        "JSON payloads below to\n"
        "`https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/firewall/rules`."
    )
    lines.append("")
    if filtered:
        lines.append(
            f"**AISO-200 local-IP filter:** {len(filtered)} loopback / private "
            f"/ link-local / reserved IP(s) excluded from these payloads "
            f"(see `alma-audit-forensic.json` for the full unfiltered list):"
        )
        lines.append("")
        # Show up to 20 filtered IPs inline; the rest goes in forensic JSON.
        for ip in filtered[:20]:
            lines.append(f"  - `{ip}`")
        if len(filtered) > 20:
            lines.append(f"  - _... and {len(filtered) - 20} more_")
        lines.append("")
    # AISO-202: when a category produces multiple chunks (a rule with
    # > 500 IPs), group the per-chunk sub-headings under a single
    # category heading so the operator can see at a glance that the
    # 4-rule list "scanner IPs (probe paths)" is really one logical
    # blocklist split for Cloudflare's 4 KiB ceiling, not 4 unrelated
    # blocks. Each chunk still gets its own JSON dump + rule number.
    last_category: str | None = None
    for i, p in enumerate(payloads, start=1):
        cat = p.get("_category", f"rule {i}")
        cnt = p.get("_count", 0)
        chunk = p.get("_chunk", 1)
        chunk_total = p.get("_chunk_total", 1)
        # Emit a category heading the first time we see this category,
        # and a smaller "Rule N: chunk N/M" sub-heading for each chunk.
        if cat != last_category:
            if chunk_total > 1:
                lines.append(f"### {cat} (split into {chunk_total} chunks)")
            else:
                lines.append(f"### {cat}")
            lines.append("")
            last_category = cat
        if not p.get("expression"):
            # No-op payload (everything was local). Skip the JSON
            # dump — the "local IP filter" section above already covers
            # it.
            lines.append(
                "_No external IPs to block — every suspicious source "
                "was filtered out as local / private / loopback "
                "(see list above)._"
            )
            lines.append("")
            continue
        body = json.dumps(
            {k: v for k, v in p.items() if not k.startswith("_")},
            indent=2, ensure_ascii=False,
        )
        if chunk_total > 1:
            lines.append(
                f"**Rule {i} — chunk {chunk}/{chunk_total} ({cnt} entries):**"
            )
        else:
            lines.append(f"**Rule {i} ({cnt} entries):**")
        lines.append("")
        lines.append("```json")
        lines.append(body)
        lines.append("```")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "_Full per-IP forensic detail (no truncation):_ `alma-audit-forensic.json`"
    )
