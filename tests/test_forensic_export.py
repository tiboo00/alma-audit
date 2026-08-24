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


def test_markdown_report_omits_probe_paths_by_ip():
    """AISO-200: probe_paths_by_ip is duplicated content with top_attackers.

    The Markdown shows top_attackers (rolled up by IP) and skips
    probe_paths_by_ip (rolled up by path). The forensic JSON still
    carries both for downstream consumers.
    """
    from alma_audit.reporting import _strip_forensic

    f = _finding_with_details({
        "top_attackers": [
            {"ip": "1.2.3.4", "total_probe_requests": 10, "total_requests": 10,
             "probe_paths": {"/.env": 5, "/wp-login.php": 5},
             "first_seen": "t1", "last_seen": "t2", "user_agents": []},
        ],
        "probe_paths_by_ip": {
            "/.env": [{"ip": "1.2.3.4", "count": 5}],
            "/wp-login.php": [{"ip": "1.2.3.4", "count": 5}],
        },
    })
    trimmed = _strip_forensic([f], keep_top=10)
    # top_attackers preserved.
    assert "top_attackers" in trimmed[0].details
    # probe_paths_by_ip stripped (the forensic fields whitelist excludes it).
    assert "probe_paths_by_ip" not in trimmed[0].details
    # Other forensic fields still in scope.
    assert "host_errors_top" not in trimmed[0].details  # not present
    # The dict doesn't contain the stripped field even with a sentinel.
    for k in trimmed[0].details:
        assert not k.startswith("probe_paths_by_ip")


def test_cloudflare_payloads_filter_loopback_ip():
    """AISO-200: 127.0.0.1 must NEVER appear in Cloudflare block payloads."""
    from alma_audit.forensic_export import build_cloudflare_block_payloads

    row_template = {
        "total_probe_requests": 1, "total_requests": 10,
        "probe_paths": {"/.env": 1}, "first_seen": "", "last_seen": "",
        "user_agents": [],
    }
    top_attackers = [{"ip": "127.0.0.1", "total_probe_requests": 100,
                      "total_requests": 100,
                      "probe_paths": {"/.env": 100},
                      "first_seen": "", "last_seen": "", "user_agents": []}]
    for i in range(5):
        top_attackers.append({"ip": f"1.2.3.{i}", **row_template})
    findings = [_finding_with_details({"top_attackers": top_attackers})]
    payloads = build_cloudflare_block_payloads(findings)
    # 5 external IPs survive the filter, 1 localhost dropped.
    assert payloads[0]["_count"] == 5
    assert "127.0.0.1" not in payloads[0]["expression"]
    assert "127.0.0.1" in payloads[0]["_filtered_local_ips"]


def test_cloudflare_payloads_filter_rfc1918_private_networks():
    """RFC1918 private ranges (10/8, 172.16/12, 192.168/16) must never block."""
    from alma_audit.forensic_export import build_cloudflare_block_payloads

    row_template = {
        "total_probe_requests": 5, "total_requests": 5,
        "probe_paths": {"/.env": 5}, "first_seen": "", "last_seen": "",
        "user_agents": [],
    }
    top_attackers = [
        {"ip": ip, **row_template}
        for ip in ["10.0.0.5", "172.16.5.5", "192.168.1.5", "8.8.8.8"]
    ]
    findings = [_finding_with_details({"top_attackers": top_attackers})]
    payloads = build_cloudflare_block_payloads(findings)
    # Only 8.8.8.8 survives the filter, but min_ips=3 drops it because
    # 1 < 3. So no payload — but the no-op sentinel carries the
    # filtered set so the test can verify what was excluded.
    no_op = [p for p in payloads if p["_category"] == "no-op"]
    assert no_op, f"Expected a no-op payload, got: {payloads}"
    filtered = no_op[0]["_filtered_local_ips"]
    for ip in ["10.0.0.5", "172.16.5.5", "192.168.1.5"]:
        assert ip in filtered
        assert "8.8.8.8" not in filtered


def test_cloudflare_payloads_min_ips_threshold_emits_only_external():
    """Below min_ips, external IPs (not local) still get filtered out.

    RFC1918 IPs are scrubbed regardless of the min_ips threshold; the
    operator never sees a private-IP block list.
    """
    from alma_audit.forensic_export import build_cloudflare_block_payloads

    row_template = {
        "total_probe_requests": 5, "total_requests": 5,
        "probe_paths": {"/.env": 5}, "first_seen": "", "last_seen": "",
        "user_agents": [],
    }
    top_attackers = [{"ip": f"8.8.4.{i}", **row_template} for i in range(5)]
    top_attackers += [{"ip": "10.0.0.1", **row_template}]
    findings = [_finding_with_details({"top_attackers": top_attackers})]
    payloads = build_cloudflare_block_payloads(findings)
    # 5 external IPs survive (>= min_ips=3); 10.0.0.1 dropped.
    assert len(payloads) == 1
    assert payloads[0]["_count"] == 5
    assert "10.0.0.1" not in payloads[0]["expression"]
    assert "10.0.0.1" in payloads[0]["_filtered_local_ips"]


def test_cloudflare_payloads_handle_all_local_gracefully():
    """If every suspicious IP is local, emit a no-op payload, not an empty one."""
    from alma_audit.forensic_export import build_cloudflare_block_payloads

    findings = [_finding_with_details({
        "top_attackers": [
            {"ip": "127.0.0.1", "total_probe_requests": 5, "total_requests": 5,
             "probe_paths": {"/.env": 5}, "first_seen": "", "last_seen": "",
             "user_agents": []},
            {"ip": "10.0.0.1", "total_probe_requests": 5, "total_requests": 5,
             "probe_paths": {"/.env": 5}, "first_seen": "", "last_seen": "",
             "user_agents": []},
        ],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    # min_ips=3 means we'd otherwise drop everything; the no-op
    # payload still surfaces the filtered list so the operator sees
    # that the audit ran but couldn't find any external offenders.
    assert len(payloads) == 1
    assert payloads[0]["_category"] == "no-op"
    assert payloads[0]["expression"] == ""
    assert "127.0.0.1" in payloads[0]["_filtered_local_ips"]


def test_forensic_export_keeps_local_ips_in_json():
    """Local IPs ARE filtered from Cloudflare but KEPT in the forensic JSON.

    The forensic bundle is for diagnosis; the Cloudflare payloads are
    for blocking. The two audiences need different views.
    """
    import re
    from alma_audit.forensic_export import build_forensic_export

    row_template = {
        "total_probe_requests": 5, "total_requests": 5,
        "probe_paths": {"/.env": 5}, "first_seen": "", "last_seen": "",
        "user_agents": [],
    }
    top_attackers = [
        {"ip": "127.0.0.1", "total_probe_requests": 50, **row_template},
        *[{"ip": f"8.8.4.{i}", **row_template} for i in range(5)],
    ]
    findings = [_finding_with_details({"top_attackers": top_attackers})]
    forensic = build_forensic_export(findings, hostname="h", timestamp="t")
    # All scanner IPs appear in the forensic JSON (unfiltered, for diagnosis).
    ips = {r["ip"] for r in forensic["scanner_ips"]}
    assert ips == {"127.0.0.1", "8.8.4.0", "8.8.4.1", "8.8.4.2", "8.8.4.3", "8.8.4.4"}
    # Cloudflare payloads filter out the loopback but keep the 5 externals.
    cf_ips: set[str] = set()
    for payload in forensic["cloudflare"]["payloads"]:
        if payload.get("expression"):
            # Extract IPs from "(ip.src in {1.2.3.4 5.6.7.8 ...})".
            match = re.search(r"\{([^}]*)\}", payload["expression"])
            if match:
                cf_ips.update(match.group(1).split())
    assert "127.0.0.1" not in cf_ips
    for i in range(5):
        assert f"8.8.4.{i}" in cf_ips
