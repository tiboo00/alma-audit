"""AISO-199 tests: forensic export + Cloudflare block-rule builder."""

from __future__ import annotations

import json

from alma_audit.forensic_export import (
    build_cloudflare_block_payloads,
    build_cloudflare_curl_script,
    build_forensic_export,
)
from alma_audit.models import Finding, Severity


def _finding_with_details(details: dict, *, title: str = "test") -> Finding:
    return Finding(
        module="access_log",
        severity=Severity.CRITICAL,
        title=title,
        description="",
        details=details,
    )


def test_forensic_export_bundles_scanner_ips():
    findings = [_finding_with_details({
        "top_attackers": [
            {"ip": "1.2.3.4", "total_probe_requests": 5, "total_requests": 10,
             "probe_paths": {"/.env": 5}, "first_seen": "ts1", "last_seen": "ts2",
             "user_agents": ["curl/7.68.0"]},
            {"ip": "5.6.7.8", "total_probe_requests": 3, "total_requests": 7,
             "probe_paths": {"/wp-login.php": 3}, "first_seen": "ts1", "last_seen": "ts2",
             "user_agents": ["Mozilla/5.0"]},
        ],
    })]
    forensic = build_forensic_export(findings, hostname="host1", timestamp="2026-01-01T00:00:00")
    assert forensic["summary"]["unique_scanner_ips"] == 2
    assert forensic["summary"]["scanner_probe_count_total"] == 8
    assert len(forensic["scanner_ips"]) == 2


def test_forensic_export_includes_ssh_fail_details():
    findings = [_finding_with_details({
        "ssh_fail_details": [
            {"ip": "212.32.226.231", "user": "root", "count": 3,
             "first_seen": "t1", "last_seen": "t2"},
        ],
    }, title="ssh brute")]
    forensic = build_forensic_export(findings, hostname="host1", timestamp="now")
    assert forensic["summary"]["ssh_fail_count_total"] == 3
    assert len(forensic["ssh_fail_by_ip"]) == 1
    assert forensic["ssh_fail_by_ip"][0]["ip"] == "212.32.226.231"


def test_cloudflare_payloads_group_scanner_ips():
    findings = [_finding_with_details({
        "top_attackers": [
            {"ip": f"1.2.3.{i}", "total_probe_requests": i + 1, "total_requests": 10,
             "probe_paths": {"/.env": i + 1}, "first_seen": "", "last_seen": "",
             "user_agents": []}
            for i in range(5)
        ],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    # 5 scanner IPs >= min_ips (3) → scanner payload.
    scanner_payloads = [p for p in payloads if "scanner" in p.get("_category", "")]
    assert len(scanner_payloads) == 1
    p = scanner_payloads[0]
    # IPs are sorted by count desc; "1.2.3.4" has count 5, "1.2.3.3" has 4, ...
    assert "1.2.3.4" in p["expression"]
    assert "1.2.3.0" in p["expression"]
    # Verified Cloudflare API shape.
    assert p["mode"] == "block"
    assert p["action"] == "block"
    assert p["expression"].startswith("(ip.src in {")
    assert p["expression"].endswith("})")


def test_cloudflare_payloads_skip_below_min_ips():
    """Categories with < 3 IPs are skipped — single-IP blocks are noise."""
    findings = [_finding_with_details({
        "top_attackers": [
            {"ip": "1.2.3.4", "total_probe_requests": 5, "total_requests": 10,
             "probe_paths": {"/.env": 5}, "first_seen": "", "last_seen": "",
             "user_agents": []},
        ],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    assert payloads == []  # 1 IP < min_ips=3 → no payload


def test_cloudflare_curl_script_emits_one_curl_per_payload():
    findings = [_finding_with_details({
        "top_attackers": [
            {"ip": f"1.2.3.{i}", "total_probe_requests": i + 1, "total_requests": 10,
             "probe_paths": {"/.env": i + 1}, "first_seen": "", "last_seen": "",
             "user_agents": []}
            for i in range(5)
        ],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    script = build_cloudflare_curl_script(payloads)
    assert "CF_ZONE_ID" in script
    assert "CF_API_TOKEN" in script
    assert script.count("curl -fsS -X POST") == len(payloads)
    assert "firewall/rules" in script


def test_markdown_report_does_not_include_full_per_ip_lists():
    """The Markdown must stay concise — full per-IP lists go to forensic.json."""
    from dataclasses import asdict
    from alma_audit.reporting import _strip_forensic

    big_top_attackers = [
        {"ip": f"1.2.3.{i}", "total_probe_requests": 1, "total_requests": 1,
         "probe_paths": {"/.env": 1}, "first_seen": "t1", "last_seen": "t2",
         "user_agents": ["curl"]}
        for i in range(20)
    ]
    f = _finding_with_details({"top_attackers": big_top_attackers, "host_errors_top": []})
    trimmed = _strip_forensic([f], keep_top=10)
    assert len(trimmed[0].details["top_attackers"]) == 10
    assert trimmed[0].details["_top_attackers_total"] == 20
