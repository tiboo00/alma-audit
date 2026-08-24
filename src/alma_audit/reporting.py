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

from .fix_suggestions import (
    RISK_ORDER,
    SCOPE_ORDER,
    SCOPE_LOCAL_CONFIG,
    SCOPE_WAF,
    SCOPE_APP_CONFIG,
    SCOPE_DNS_BLOCK,
    SCOPE_KERNEL_PARAM,
    all_fixes_from_findings,
    sort_fixes,
)
from .forensic_export import build_forensic_export
from .models import AuditReport, Finding, Severity

# AISO-210: CLI `--fix-format` value sentinels.
_FIX_FORMAT_TEXT = "text"        # current behaviour + "Recommended fixes" section
_FIX_FORMAT_JSON = "json"        # only carry fixes_recommended; no MD section
_FIX_FORMAT_NONE = "none"        # suppress fix rendering entirely
_FIX_FORMATS: tuple = (
    _FIX_FORMAT_TEXT,
    _FIX_FORMAT_JSON,
    _FIX_FORMAT_NONE,
)

# Display labels for the scope — keep stable so operator reports
# don't drift across versions.
_SCOPE_LABELS: dict = {
    SCOPE_LOCAL_CONFIG: "local_config (.htaccess, sudoers, sshd_config)",
    SCOPE_WAF: "waf (Cloudflare / ModSecurity)",
    SCOPE_APP_CONFIG: "app_config (Apache httpd.conf, logrotate, fail2ban)",
    SCOPE_DNS_BLOCK: "dns_block (hosts.deny, csf.deny, Cloudflare IP rule)",
    SCOPE_KERNEL_PARAM: "kernel_param (sysctl / sshd_config Protocol)",
}

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
#
# AISO-208: `top_path_ip_ua` is included (path × IP × UA combinations).
# Rendering for this field is handled by a custom branch in
# `_render_details_summary` because the row shape is `{path, ip,
# user_agent, count}` — different from the default `{ip, count}`.
_FORENSIC_FIELDS: tuple[str, ...] = (
    "top_attackers",
    "top_path_ip_ua",
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


def write_forensic_report(
    report: AuditReport,
    output_dir: str,
    *,
    fix_format: str = "text",
) -> str:
    """Write the per-IP forensic JSON to <output_dir>/alma-audit-forensic.json.

    Bundles the scanner IPs, brute-force IPs, error-burst IPs, sudo-fail
    users, ssh_fail_details, and probe_paths_by_ip into one machine-
    readable file. Also embeds the Cloudflare firewall-rule payloads
    and a copy-paste-ready curl script so the operator can mass-block
    offenders without re-running the audit.

    AISO-210 (fix_format): ``text`` and ``json`` both carry the
    ``fixes_recommended`` array under the forensic JSON — downstream
    SIEM / automation consumers always see the structured remediation
    data. ``none`` omits the field (and the Markdown section) so
    pre-AISO-210 consumers stay byte-identical.
    """
    forensic = build_forensic_export(
        report.findings,
        hostname=report.hostname,
        timestamp=report.timestamp,
    )
    if fix_format == _FIX_FORMAT_NONE:
        forensic.pop("fixes_recommended", None)
        forensic.pop("fix_scope_order", None)
    # Both `text` and `json` keep `fixes_recommended` in the forensic
    # JSON. `text` additionally renders the Markdown section in
    # write_markdown_report; `json` only ships the JSON.
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


def write_markdown_report(
    report: AuditReport,
    output_dir: str,
    *,
    fix_format: str = "text",
) -> str:
    """Write a CONCISE Markdown report.

    Per-IP forensic detail is intentionally omitted — full breakdown
    lives in `alma-audit-forensic.json`. The Markdown keeps the top 10
    entries per forensic field so the operator can skim the report
    without scrolling through tens of thousands of lines.

    AISO-210 (fix_format): ``text`` (default) appends a
    `## Recommended fixes` section grouped by scope. ``json`` omits
    the section; the fixes live in `alma-audit-forensic.json` under
    ``fixes_recommended``. ``none`` suppresses both the MD section
    and the JSON key — pre-fix behaviour. Anything else raises
    ValueError so a CLI typo fails closed.
    """
    if fix_format not in _FIX_FORMATS:
        raise ValueError(
            f"unknown fix_format {fix_format!r}; expected one of {_FIX_FORMATS}"
        )
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
    # AISO-210: only emit the section when ``fix_format == 'text'``.
    # The JSON / none branches leave the MD output untouched so
    # existing operator dashboards / Slack webhooks don't drift.
    if fix_format == _FIX_FORMAT_TEXT:
        _render_recommended_fixes(lines, report.findings)
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

    # AISO-203: the secure_log summary finding carries two dict-typed
    # per-IP counters that describe distinct SSH attack patterns
    # (`ssh_fail_by_ip` = single-account credential stuffing,
    # `ssh_invalid_user_by_ip` = rotating-username enumeration).
    # When both are non-empty we render them as separate top-N
    # bullet sections so the operator can tell the two attack classes
    # apart at a glance — even when both came from the same IP.
    ssh_fail_by_ip = details.get("ssh_fail_by_ip") or {}
    ssh_invalid_by_ip = details.get("ssh_invalid_user_by_ip") or {}

    # Render forensic fields inline as a Markdown bullet list, then
    # note that the full list lives in the forensic JSON file.
    forensic_subsections: list[str] = []
    other_items: list[tuple[str, object]] = []
    for k, v in details.items():
        if k.startswith("_") and k.endswith("_total"):
            # Truncation hint rendered alongside the forensic section.
            continue
        # AISO-203: the two SSH attack-pattern counters are handled
        # separately below (one combined "SSH attack-pattern split"
        # section, shown when they differ OR when at least one is
        # non-empty). Suppress them from the generic forensic-key
        # loop and the JSON dump so they don't render twice.
        if k in ("ssh_fail_by_ip", "ssh_invalid_user_by_ip"):
            continue
        if k in forensic_keys:
            # AISO-208: `top_path_ip_ua` rows carry `{path, ip,
            # user_agent, count}`. The default forensic-keys loop
            # renders rows as `ip × count — last_seen`, which loses
            # the path and UA — the two pieces the operator needs to
            # distinguish "scanner using python-requests on /.env"
            # from "credential stuffing on /wp-login.php via curl".
            # Render these rows specially below; suppress the default
            # rendering so we don't print them twice.
            if k == "top_path_ip_ua":
                continue
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

    # AISO-203: emit the SSH attack-pattern split section when at
    # least one of the two counters is non-empty. AC#3 says "if the
    # counts differ" — we honour the spec while still emitting a
    # section when only one is populated (the operator sees the
    # active attack pattern; the other branch shows "no events").
    if ssh_fail_by_ip or ssh_invalid_by_ip:
        forensic_subsections.append(
            "- **SSH attack-pattern split (top 10 per pattern — "
            "credential stuffing vs rotating-username enumeration):**"
        )
        # Credential stuffing first — the more common / well-known
        # attack class. If empty, emit an explicit "(none)" so the
        # operator can see "this IP is enumerating only".
        if ssh_fail_by_ip:
            forensic_subsections.append(
                "  - `ssh_fail_by_ip` (single-account credential stuffing):"
            )
            for ip, count in list(ssh_fail_by_ip.items())[:10]:
                forensic_subsections.append(f"    - `{ip}` × {count}")
        else:
            forensic_subsections.append(
                "  - `ssh_fail_by_ip` (single-account credential stuffing): _none_"
            )
        # Rotating-username enumeration.
        if ssh_invalid_by_ip:
            forensic_subsections.append(
                "  - `ssh_invalid_user_by_ip` (rotating-username enumeration):"
            )
            for ip, count in list(ssh_invalid_by_ip.items())[:10]:
                forensic_subsections.append(f"    - `{ip}` × {count}")
        else:
            forensic_subsections.append(
                "  - `ssh_invalid_user_by_ip` (rotating-username enumeration): _none_"
            )
        # AISO-203 hint: surface the per-IP totals so the operator can
        # see at a glance which IP carries both patterns vs only one.
        combined_ips = set(ssh_fail_by_ip) | set(ssh_invalid_by_ip)
        overlapping = set(ssh_fail_by_ip) & set(ssh_invalid_by_ip)
        if overlapping:
            forensic_subsections.append(
                f"  - _IPs seen in BOTH patterns: "
                f"{', '.join(f'`{ip}`' for ip in sorted(overlapping))}_"
            )
        elif combined_ips:
            forensic_subsections.append(
                f"  - _The two patterns came from disjoint IP sets "
                f"({len(combined_ips)} IP(s) total)._"
            )

    # AISO-208: emit the path × IP × UA section. Same rendering
    # budget (top 10) as the other forensic fields, but the row
    # format is richer — the operator needs to see all three
    # dimensions (path, IP, UA) inline to tell apart different
    # threat classes (e.g. python-requests on /.env vs curl on
    # /wp-login.php). We render the rows as
    # `/path` from `1.2.3.4` using `python-requests/2.28.0` × N —
    # matching the example in the AISO-208 acceptance criteria.
    top_path_ip_ua = details.get("top_path_ip_ua") or []
    if isinstance(top_path_ip_ua, list) and top_path_ip_ua:
        forensic_subsections.append(
            "- **top_path_ip_ua** (top 10 — full list in "
            "`alma-audit-forensic.json`): path × IP × user-agent "
            "combinations:"
        )
        total_field = "_top_path_ip_ua_total"
        if total_field in details:
            forensic_subsections.append(
                f"  - _Showing 10 of {details[total_field]} combinations._"
            )
        for row in top_path_ip_ua[:10]:
            if not isinstance(row, dict):
                continue
            path = row.get("path", "?")
            ip = row.get("ip", "?")
            ua = row.get("user_agent", "<unknown>")
            count = row.get("count", 0)
            forensic_subsections.append(
                f"  - `{path}` from `{ip}` using `{ua}` × {count}"
            )

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


def _render_recommended_fixes(lines: list[str], findings) -> None:
    """Append the ``## Recommended fixes`` section to the Markdown report.

    AISO-210: groups fixes by scope (cheap → network-wide) and within
    each scope by risk (low → medium → high). The output is the same
    set of fixes that lands in ``alma-audit-forensic.json`` under
    ``fixes_recommended`` — a single dedup pass happens in
    ``fix_suggestions.all_fixes_from_findings`` so the MD and the
    forensic JSON never disagree.

    Empty fixes → empty section: we still emit the header so the
    operator sees a deterministic shape (`yes, the audit considered
    fixes; nothing to do here`) instead of a missing section.
    """
    fixes_deduped = all_fixes_from_findings(findings)
    if not fixes_deduped:
        # Always render the section so the operator knows the audit
        # was aware of fixes — never silently skip the header when
        # nothing actionable is attached (an empty report happens when
        # an audit was clean).
        lines.append("## Recommended fixes")
        lines.append("")
        lines.append("_No structured fixes attached to any finding._")
        lines.append("")
        return

    sorted_fixes = sort_fixes(fixes_deduped)

    lines.append("## Recommended fixes")
    lines.append("")
    lines.append(
        "Concrete remediation steps grouped by scope — the cheapest, "
        "lowest-blast-radius fix is shown first so the operator can stop "
        "at the first one that matches the host's posture. Each fix ships "
        "with the matching rollback note."
    )
    lines.append("")

    # Group by scope in the canonical order. Unknown scopes go at the
    # bottom (alphabetical fallback) so the layout stays deterministic.
    by_scope: dict = {}
    for fix in sorted_fixes:
        by_scope.setdefault(fix.scope, []).append(fix)

    scope_index = {s: i for i, s in enumerate(SCOPE_ORDER)}
    unknown_scopes = [s for s in by_scope if s not in scope_index]
    scopes_in_order: list = sorted(
        by_scope.keys(),
        key=lambda s: (
            scope_index.get(s, len(scope_index)),
            s,
        ),
    )

    for scope in scopes_in_order:
        label = _SCOPE_LABELS.get(scope, scope)
        lines.append(f"### {label}")
        lines.append("")
        bucket = sorted(
            by_scope[scope],
            key=lambda f: (
                RISK_ORDER.get(f.risk, 99),
                f.what,
            ),
        )
        for fix in bucket:
            risk_marker = f" ({fix.risk} risk)" if fix.risk else ""
            lines.append(f"**{fix.what}**{risk_marker}")
            lines.append("")
            lines.append(f"- **Why:** {fix.why}")
            lines.append(f"- **Scope:** `{fix.scope}`")
            if fix.commands:
                lines.append("- **Apply:**")
                lines.append("")
                lines.append("```bash")
                for cmd in fix.commands:
                    lines.append(cmd)
                lines.append("```")
            if fix.rollback:
                lines.append(f"- **Rollback:** {fix.rollback}")
            lines.append("")

    # Authoritative pointer to the structured JSON consumer.
    lines.append(
        "_Full deduplicated fix list (machine-readable, sorted by scope "
        "+ risk):_ `alma-audit-forensic.json` → `fixes_recommended`."
    )
    lines.append("")


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
