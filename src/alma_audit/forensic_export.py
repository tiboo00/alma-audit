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

from collections import defaultdict
from typing import Any


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

    Returns a list of ready-to-POST JSON payloads.
    """
    min_ips = 3  # below this, the operator can block manually

    scanner_ips: dict[str, dict[str, Any]] = defaultdict(dict)
    brute_force_ips: dict[str, dict[str, Any]] = defaultdict(dict)
    error_burst_ips: dict[str, dict[str, Any]] = defaultdict(dict)
    sudo_fail_ips: dict[str, dict[str, Any]] = defaultdict(dict)

    for f in findings:
        details = getattr(f, "details", None) or {}

        # access_log probe_paths / top_attackers
        top_attackers = details.get("top_attackers")
        if isinstance(top_attackers, list) and top_attackers:
            for row in top_attackers:
                ip = row.get("ip", "")
                if not ip:
                    continue
                # Per-IP count > 0 means the IP actively probed us.
                if row.get("total_probe_requests", 0) > 0:
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

    def _emit(
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
        keys = [k for k, _ in sorted_keys]
        # Cloudflare's expression syntax uses space-separated IPs.
        expression = "(ip.src in {" + " ".join(keys) + "})"
        payloads.append({
            "description": f"{description_prefix}: {category} ({len(keys)} {field.replace('count', 'entries')})",
            "mode": "block",
            "expression": expression,
            "action": "block",
            "_category": category,  # internal: stripped before output
            "_count": len(keys),
        })

    _emit("scanner IPs (probe paths)", scanner_ips, "probe_count")
    _emit("brute-force IPs (SSH)", brute_force_ips, "count")
    _emit("error-burst IPs (4xx/5xx)", error_burst_ips, "error_count")
    _emit("sudo-fail users", sudo_fail_ips, "count")

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
        body = json.dumps(p, separators=(",", ":"), ensure_ascii=False)
        lines.append(f"# Rule {i}: {cat} ({cnt} entries)")
        lines.append(f'echo "Applying rule {i}: {cat} ({cnt} entries)"')
        lines.append("curl -fsS -X POST \"${API}\" \\")
        lines.append('  -H "Authorization: Bearer ${CF_API_TOKEN}" \\')
        lines.append('  -H "Content-Type: application/json" \\')
        lines.append(f"  --data '{body}'")
        lines.append("")
    return "\n".join(lines)


import json  # noqa: E402  (kept near the helper that needs it)


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

    # Also expose raw rule lists for direct ingestion.
    cloudflare_payloads: list[dict[str, Any]] = []
    cloudflare_curl_script: str = ""

    for f in findings:
        details = getattr(f, "details", None) or {}
        if details.get("probe_paths_by_ip"):
            probe_paths_by_ip.update(details["probe_paths_by_ip"])
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

    # Build Cloudflare payloads + curl script (after collection).
    cloudflare_payloads = build_cloudflare_block_payloads(findings)
    cloudflare_curl_script = build_cloudflare_curl_script(
        [_p for _p in cloudflare_payloads],
    )

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
        },
        "scanner_ips": scanner_ips,
        "brute_force_ips": brute_force_ips,
        "error_burst_ips": error_burst_ips,
        "sudo_fail_users": sudo_fail_users,
        "ssh_fail_by_ip": ssh_fail_by_ip,
        "probe_paths_by_ip": probe_paths_by_ip,
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
