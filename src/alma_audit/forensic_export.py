"""Cloudflare firewall-rule builder for alma-audit forensic output.

AISO-199: the per-IP forensic data can be turned into a Cloudflare
firewall-rules list so the operator can mass-block brute-force and
scanner IPs from the CDN edge. This module is **read-only** — it builds
the JSON payload and curl command, but never calls the Cloudflare API
itself. The operator runs the curl manually (the audit has no
credentials and the production host may not have network access to
api.cloudflare.com anyway).

Output shape (per the Cloudflare API v4 firewall rules schema):

  {
    "description": "alma-audit: <category> blocklist",
    "mode": "block",
    "expression": "(ip.src in {1.2.3.4 5.6.7.8 ...})",
    "action": "block"
  }

For more granular blocklists (e.g. "scanner-only" vs "brute-force"),
the helper emits one payload per category.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any


# AISO-200: local / private / loopback / link-local IP ranges must NEVER
# land in a Cloudflare block rule. The operator would lock themselves
# out (127.0.0.1 = the audit host itself; 10/8 / 172.16/12 / 192.168/16 =
# RFC1918 private networks behind the CDN; ::1 = IPv6 loopback; fe80::/10 =
# IPv6 link-local; 169.254/16 = IPv4 link-local).
_LOCAL_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # Cloudflare's own internal range (per the CF API docs) — these IPs
    # are the CDN edge network and never originate from real clients.
    ipaddress.ip_network("173.245.48.0/20"),
    # Documentation / reserved blocks we never want to block.
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]


def _is_local_ip(ip: str) -> bool:
    """True if the IP belongs to a loopback / private / reserved range.

    Used by `build_cloudflare_block_payloads` to drop IPs that the
    operator must NEVER block on Cloudflare.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Unparseable — treat as external so we don't accidentally
        # swallow a real attacker IP that has a typo.
        return False
    return any(addr in net for net in _LOCAL_NETWORKS)


def build_cloudflare_block_payloads(
    findings: list[Any],
    *,
    description_prefix: str = "alma-audit",
) -> list[dict[str, Any]]:
    """Build Cloudflare firewall-rule payloads from per-IP forensic findings.

    Categorises IPs by the finding that surfaced them (scanner IPs from
    access_log probe paths, brute-force IPs from secure_log, etc.) and
    emits one block payload per category. Categories with fewer than
    `min_ips` IPs are dropped — single-IP rules don't justify a
    firewall rule and can go in the operator's manual allow/deny list.

    Local / private / loopback / link-local IPs are filtered out
    automatically (AISO-200). The full un-filtered list still lands
    in `alma-audit-forensic.json` for diagnostic purposes — only the
    Cloudflare payloads are scrubbed.

    Returns a list of ready-to-POST JSON payloads.
    """
    min_ips = 3  # below this, the operator can block manually

    # AISO-202: Cloudflare firewall rules have a hard ~4 KiB ceiling on
    # the `expression` field. Empirically, 500 IPs already push ~7 KiB
    # of text (Cloudflare uses space-separated IPs inside `{...}`),
    # which gets rejected at apply time. 500 is a safe upper bound
    # that keeps each chunk comfortably under the limit even when
    # IPv6 addresses land in the list.
    _CHUNK_SIZE = 500

    scanner_ips: dict[str, dict[str, Any]] = defaultdict(dict)
    brute_force_ips: dict[str, dict[str, Any]] = defaultdict(dict)
    error_burst_ips: dict[str, dict[str, Any]] = defaultdict(dict)
    sudo_fail_ips: dict[str, dict[str, Any]] = defaultdict(dict)

    local_ip_filtered: set[str] = set()

    def _absorb(row_ip: str, target: dict[str, dict[str, Any]], field: str) -> None:
        if _is_local_ip(row_ip):
            local_ip_filtered.add(row_ip)
            return
        if row_ip:
            target.setdefault(row_ip, {"count": 0})
            target[row_ip]["count"] += row.get(field, 0)

    for f in findings:
        details = getattr(f, "details", None) or {}

        # access_log probe_paths / top_attackers
        top_attackers = details.get("top_attackers")
        if isinstance(top_attackers, list) and top_attackers:
            for row in top_attackers:
                ip = row.get("ip", "")
                if not ip:
                    continue
                if row.get("total_probe_requests", 0) > 0:
                    if _is_local_ip(ip):
                        local_ip_filtered.add(ip)
                        continue
                    scanner_ips.setdefault(ip, {"probe_count": 0, "ua": []})
                    scanner_ips[ip]["probe_count"] += row["total_probe_requests"]
                    ua = row.get("user_agents", [])
                    if isinstance(ua, list):
                        scanner_ips[ip]["ua"].extend(ua[:2])

        # access_log host_errors_top — IPs generating 4xx/5xx burst.
        host_errors_top = details.get("host_errors_top")
        if isinstance(host_errors_top, list) and host_errors_top:
            for row in host_errors_top:
                ip = row.get("ip", "")
                if not ip:
                    continue
                if row.get("error_count", 0) > 0:
                    if _is_local_ip(ip):
                        local_ip_filtered.add(ip)
                        continue
                    error_burst_ips.setdefault(ip, {"error_count": 0})
                    error_burst_ips[ip]["error_count"] += row["error_count"]

        # secure_log ssh_fail_details
        ssh_fail_details = details.get("ssh_fail_details")
        if isinstance(ssh_fail_details, list) and ssh_fail_details:
            for row in ssh_fail_details:
                ip = row.get("ip", "")
                if not ip:
                    continue
                if row.get("count", 0) > 0:
                    if _is_local_ip(ip):
                        local_ip_filtered.add(ip)
                        continue
                    brute_force_ips.setdefault(ip, {"count": 0})
                    brute_force_ips[ip]["count"] += row["count"]

        # secure_log sudo_fail_details (no IP per the parser, just user;
        # we still emit a per-user payload below if applicable).
        sudo_fail_details = details.get("sudo_fail_details")
        if isinstance(sudo_fail_details, list) and sudo_fail_details:
            for row in sudo_fail_details:
                user = row.get("user", "")
                if not user or user == "<unknown_user>":
                    continue
                if row.get("count", 0) > 0:
                    sudo_fail_ips.setdefault(user, {"count": 0})
                    sudo_fail_ips[user]["count"] += row["count"]

    payloads: list[dict[str, Any]] = []

    def _emit_chunked(
        category: str,
        ips_or_users: dict[str, dict[str, Any]],
        field: str,
    ) -> None:
        if not ips_or_users or len(ips_or_users) < min_ips:
            return
        # Sort by count desc, then alphabetical for stability.
        sorted_keys = sorted(
            ips_or_users.items(),
            key=lambda kv: (-kv[1].get(field, 0), kv[0]),
        )
        all_keys = [k for k, _ in sorted_keys]

        # AISO-202: split into chunks of at most _CHUNK_SIZE entries so
        # each rule's `expression` stays well under Cloudflare's hard
        # ~4 KiB ceiling. One curl per chunk is mechanically identical
        # to one curl per rule — the operator just runs more lines.
        chunk_total = (len(all_keys) + _CHUNK_SIZE - 1) // _CHUNK_SIZE
        for chunk_index in range(chunk_total):
            start = chunk_index * _CHUNK_SIZE
            chunk_keys = all_keys[start:start + _CHUNK_SIZE]
            # Cloudflare's expression syntax uses space-separated IPs.
            expression = "(ip.src in {" + " ".join(chunk_keys) + "})"
            base_desc = (
                f"{description_prefix}: {category} "
                f"({len(chunk_keys)} {field.replace('count', 'entries')})"
            )
            # Only suffix with "(chunk N/M)" when there's more than one
            # chunk — a single-chunk rule stays as-is so existing
            # dashboards / grep filters don't have to special-case it.
            if chunk_total > 1:
                description = f"{base_desc} (chunk {chunk_index + 1}/{chunk_total})"
            else:
                description = base_desc
            payloads.append({
                "description": description,
                "mode": "block",
                "expression": expression,
                "action": "block",
                "_category": category,        # internal: stripped before output
                "_count": len(chunk_keys),
                "_chunk": chunk_index + 1,
                "_chunk_total": chunk_total,
            })

    _emit_chunked("scanner IPs (probe paths)", scanner_ips, "probe_count")
    _emit_chunked("brute-force IPs (SSH)", brute_force_ips, "count")
    _emit_chunked("error-burst IPs (4xx/5xx)", error_burst_ips, "error_count")
    _emit_chunked("sudo-fail users", sudo_fail_ips, "count")

    # Attach a list of filtered local IPs to the first payload so the
    # operator can see what was excluded.
    if local_ip_filtered and payloads:
        payloads[0]["_filtered_local_ips"] = sorted(local_ip_filtered)
    elif local_ip_filtered:
        # No payloads emitted (everything was local). Surface the
        # filtered set so the operator doesn't think the script is broken.
        payloads.append({
            "description": f"{description_prefix}: no-op (all suspicious IPs were local)",
            "mode": "block",
            "expression": "",
            "action": "block",
            "_category": "no-op",
            "_count": 0,
            "_chunk": 1,
            "_chunk_total": 1,
            "_filtered_local_ips": sorted(local_ip_filtered),
        })

    return payloads


def build_cloudflare_curl_script(
    payloads: list[dict[str, Any]],
    *,
    zone_id_var: str = "CF_ZONE_ID",
    api_token_var: str = "CF_API_TOKEN",
) -> str:
    """Build a copy-paste-ready bash script for applying the payloads.

    The script reads `CF_ZONE_ID` and `CF_API_TOKEN` from the
    environment, then POSTs each payload to the Cloudflare firewall
    rules endpoint. Output is a single bash script that the operator
    can review before running.
    """
    lines = [
        "#!/usr/bin/env bash",
        "# Generated by alma-audit (AISO-199).",
        "# Review each rule, then run this script to apply it.",
        "# Required env: $CF_ZONE_ID and $CF_API_TOKEN.",
        "set -euo pipefail",
        "",
        ": \"${CF_ZONE_ID:?Set CF_ZONE_ID in your environment}\"",
        ": \"${CF_API_TOKEN:?Set CF_API_TOKEN in your environment}\"",
        "",
        "API=\"https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/firewall/rules\"",
        "",
    ]
    for i, p in enumerate(payloads, start=1):
        cat = p.pop("_category", "rule")
        cnt = p.pop("_count", 0)
        chunk = p.pop("_chunk", 1)
        chunk_total = p.pop("_chunk_total", 1)
        body = json.dumps(p, separators=(",", ":"), ensure_ascii=False)
        # AISO-202: when a rule is chunked, surface the chunk label in
        # both the comment and the echo so the operator can see at a
        # glance which sub-rule they're about to apply.
        chunk_label = (
            f" [chunk {chunk}/{chunk_total}]" if chunk_total > 1 else ""
        )
        lines.append(f"# Rule {i}: {cat}{chunk_label} ({cnt} entries)")
        lines.append(f'echo "Applying rule {i}: {cat}{chunk_label} ({cnt} entries)"')
        lines.append("curl -fsS -X POST \"${API}\" \\")
        lines.append('  -H "Authorization: Bearer ***" \\')
        lines.append('  -H "Content-Type: application/json" \\')
        lines.append(f"  --data '{body}'")
        lines.append("")
    return "\n".join(lines)


import json  # noqa: E402  (kept near the helper that needs it)


from .fix_suggestions import SCOPE_ORDER, all_fixes_from_findings, sort_fixes  # noqa: E402


def build_forensic_export(
    findings: list[Any],
    *,
    hostname: str,
    timestamp: str,
) -> dict[str, Any]:
    """Bundle the per-IP forensic detail + Cloudflare payloads into one JSON.

    The main `alma-audit-latest.json` already carries the same `details`
    blocks, but pulling them into a dedicated `alma-audit-forensic.json`
    gives the operator a single, machine-readable file to pipe into
    downstream tooling (blocklists, threat intel, etc.).
    """
    scanner_ips: list[dict[str, Any]] = []
    brute_force_ips: list[dict[str, Any]] = []
    error_burst_ips: list[dict[str, Any]] = []
    sudo_fail_users: list[dict[str, Any]] = []
    ssh_fail_by_ip: list[dict[str, Any]] = []
    probe_paths_by_ip: dict[str, list[dict[str, Any]]] = {}

    # AISO-208 (review-fix): the operator-facing Markdown report
    # surfaces a top-N slice of the per-(path, IP, UA) breakdown as
    # `top_path_ip_ua` and points the operator to
    # `alma-audit-forensic.json` for "the full list". Before this fix,
    # the forensic export carried only `probe_paths_by_ip` — the top-N
    # slice was nowhere in the forensic JSON, so the MD's "full list
    # in alma-audit-forensic.json" claim was false. We now collect the
    # same slice into the forensic export so consumers (SIEM ingestion,
    # incident response scripts) see exactly the rows the operator saw.
    # The list is *appended* across all findings of the same kind;
    # multiple findings (e.g. two probe detectors) are merged in
    # finding order, which the orchestrator keeps deterministic.
    top_path_ip_ua: list[dict[str, Any]] = []

    # AISO-206: the domlog inventory finding carries its full
    # `details.anomalies` payload already sorted by `_SORT_WEIGHTS`
    # (most-dangerous first, then filename ascending). We expose it
    # verbatim under an explicit `domlog_anomalies` key on the
    # forensic export so the operator sees the weighted ordering in
    # `alma-audit-forensic.json`, not only in `alma-audit-latest.json`.
    # AC #4 — the forensic JSON preserves the sort.
    domlog_anomalies: list[dict[str, Any]] = []

    # Also expose raw rule lists for direct ingestion.
    cloudflare_payloads: list[dict[str, Any]] = []
    cloudflare_curl_script: str = ""

    for f in findings:
        details = getattr(f, "details", None) or {}
        if details.get("probe_paths_by_ip"):
            probe_paths_by_ip.update(details["probe_paths_by_ip"])
        # AISO-208 (review-fix): carry the operator-facing top-N
        # slice into the forensic JSON. Defensive copy via ``list(...)``
        # so a downstream consumer can't mutate the Finding's payload.
        for row in details.get("top_path_ip_ua", []) or []:
            top_path_ip_ua.append(dict(row))
        for row in details.get("top_attackers", []) or []:
            scanner_ips.append({
                "ip": row.get("ip"),
                "total_probe_requests": row.get("total_probe_requests"),
                "total_requests": row.get("total_requests"),
                "probe_paths": row.get("probe_paths"),
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
                "user_agents": row.get("user_agents"),
            })
        for row in details.get("host_errors_top", []) or []:
            error_burst_ips.append({
                "ip": row.get("ip"),
                "error_count": row.get("error_count"),
                "total_requests": row.get("total_requests"),
                "error_share": row.get("error_share"),
                "status_buckets": row.get("status_buckets"),
            })
        for row in details.get("ssh_fail_details", []) or []:
            ssh_fail_by_ip.append({
                "ip": row.get("ip"),
                "user": row.get("user"),
                "count": row.get("count"),
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
            })
            if row.get("count", 0) > 0:
                brute_force_ips.append({
                    "ip": row.get("ip"),
                    "user": row.get("user"),
                    "count": row.get("count"),
                })
        for row in details.get("sudo_fail_details", []) or []:
            sudo_fail_users.append({
                "user": row.get("user"),
                "count": row.get("count"),
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
            })
        # AISO-206: collect the domlog `details.anomalies` payload
        # verbatim. The analyzer (`domlog_inventory.analyze_domlog_inventory`)
        # is the single source of truth for the sorted ordering —
        # `_SORT_WEIGHTS` (most-dangerous first, filename ascending
        # within the same weight). We don't re-sort here; we only carry
        # the already-sorted list into the forensic export. Multiple
        # findings with anomalies (e.g. two domlog roots) are merged in
        # the order their findings are passed in, which is deterministic
        # because the orchestrator (`runner.run_analyzers`) walks the
        # domlog roots in a stable order. Defensive copy via `list(...)`
        # so a downstream consumer can't mutate the Finding's payload.
        if isinstance(details.get("anomalies"), list):
            domlog_anomalies.extend(list(details["anomalies"]))

    # Build Cloudflare payloads + curl script (after collection).
    cloudflare_payloads = build_cloudflare_block_payloads(findings)
    cloudflare_curl_script = build_cloudflare_curl_script(
        [_p for _p in cloudflare_payloads],
    )

    # AISO-210: collect deduplicated, sorted fix recommendations across
    # every finding. Two consumers read it:
    #   1. forensic JSON consumers (SIEM ingestion, downstream automation).
    #   2. the Markdown `## Recommended fixes` section (via reporting.py).
    # The DEDUP happens inside `all_fixes_from_findings` (see
    # fix_suggestions.py), so the same fix appearing on multiple
    # findings collapses into a single row here.
    fixes_deduped = all_fixes_from_findings(findings)
    fixes_sorted = sort_fixes(fixes_deduped)
    fixes_recommended: list[dict[str, Any]] = [
        f.to_dict() for f in fixes_sorted
    ]

    return {
        "hostname": hostname,
        "timestamp": timestamp,
        "summary": {
            "unique_scanner_ips": len({r["ip"] for r in scanner_ips if r.get("ip")}),
            "unique_brute_force_ips": len({r["ip"] for r in brute_force_ips if r.get("ip")}),
            "unique_error_burst_ips": len({r["ip"] for r in error_burst_ips if r.get("ip")}),
            "scanner_probe_count_total": sum(
                r.get("total_probe_requests", 0) or 0 for r in scanner_ips
            ),
            "ssh_fail_count_total": sum(r.get("count", 0) or 0 for r in ssh_fail_by_ip),
            "domlog_anomalies_total": len(domlog_anomalies),
        },
        "scanner_ips": scanner_ips,
        "brute_force_ips": brute_force_ips,
        "error_burst_ips": error_burst_ips,
        "sudo_fail_users": sudo_fail_users,
        "ssh_fail_by_ip": ssh_fail_by_ip,
        "probe_paths_by_ip": probe_paths_by_ip,
        # AISO-208 (review-fix): explicit top-N (path, IP, UA) slice.
        # The Markdown report renders the first 10 of this list inline
        # and points the operator at ``alma-audit-forensic.json`` for
        # "the full list". The full *per-(path, ip)* breakdown lives
        # under ``probe_paths_by_ip`` above; ``top_path_ip_ua`` is the
        # same operator-facing slice the MD saw, kept for forensic
        # consumers (SIEM, incident-response scripts) that don't
        # re-parse the MD. Empty list is the correct sentinel when no
        # probe finding surfaced.
        "top_path_ip_ua": top_path_ip_ua,
        # AISO-206: explicit, full, already-sorted domlog anomalies.
        # The forensic JSON (`alma-audit-forensic.json`) keeps this
        # list intact so the operator can see the weighted ordering
        # here too, not only in `alma-audit-latest.json`. Empty list
        # is the correct sentinel when no domlog finding surfaced.
        "domlog_anomalies": domlog_anomalies,
        # AISO-210: structured fix library (already-deduplicated,
        # already sorted by (scope, risk, what)). Operators / SIEM
        # consumers render their own remediation UI from this list.
        # Scope constants are SCOPE_LOCAL_CONFIG / WAF / APP_CONFIG /
        # DNS_BLOCK / KERNEL_PARAM — see fix_suggestions.py.
        "fixes_recommended": fixes_recommended,
        "fix_scope_order": list(SCOPE_ORDER),
        "cloudflare": {
            "payloads": cloudflare_payloads,
            "curl_script": cloudflare_curl_script,
            "apply_instructions": (
                "1. Set $CF_ZONE_ID and $CF_API_TOKEN in your shell.\n"
                "2. Review each payload in `payloads` — verify the IPs are not "
                "legitimate users (e.g. office IPs, monitoring agents).\n"
                "3. Apply via the curl script, or POST the payloads manually "
                "to https://api.cloudflare.com/client/v4/zones/$ZONE_ID/firewall/rules"
            ),
        },
    }


def json_dumps_for_script(obj: Any) -> str:
    """Compact JSON suitable for embedding in a bash single-quoted string."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


# Late-binding patch: the function `build_cloudflare_curl_script` uses
# `json.dumps_for_script`, which we just defined below it. This is
# duck-typed by Python at call time (late binding), so it's safe.
