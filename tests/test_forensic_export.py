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


def test_cloudflare_payloads_chunk_above_threshold():
    """AISO-202: Cloudflare's ~4 KiB expression ceiling forces chunking.

    Feed 1100 unique scanner IPs and expect exactly 3 payloads (one per
    chunk), with sizes 500 / 500 / 100. Every payload must:
      - carry `_chunk` (1-indexed) and `_chunk_total` keys,
      - keep `_category` shared across the three,
      - render `(chunk N/M)` in the description,
      - emit at most _CHUNK_SIZE entries in its `expression`.
    """
    findings = [_finding_with_details({
        "top_attackers": [
            {"ip": f"203.0.113.{i}", "total_probe_requests": 1100 - i,
             "total_requests": 1100 - i,
             "probe_paths": {"/.env": 1100 - i}, "first_seen": "", "last_seen": "",
             "user_agents": []}
            for i in range(1100)
        ],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    # 1100 >= min_ips=3, so we get the scanner category chunked.
    scanner_payloads = [p for p in payloads if p.get("_category", "").startswith("scanner")]
    assert len(scanner_payloads) == 3, f"Expected 3 chunked payloads, got {len(scanner_payloads)}"

    sizes = [p["_count"] for p in scanner_payloads]
    assert sizes == [500, 500, 100], f"Expected 500/500/100 split, got {sizes}"

    # Each chunk must carry _chunk / _chunk_total and stay under the cap.
    for p in scanner_payloads:
        assert p["_chunk_total"] == 3
        assert p["_chunk"] in (1, 2, 3)
        assert p["_count"] <= 500
        # Cloudflare expression must be well-formed.
        assert p["expression"].startswith("(ip.src in {")
        assert p["expression"].endswith("})")
        # Description must carry the chunk suffix when M > 1.
        m = p["_chunk"]
        assert f"(chunk {m}/3)" in p["description"], (
            f"Missing '(chunk {m}/3)' in description: {p['description']!r}"
        )

    # No overlap between chunks — every IP must appear exactly once
    # across the three expressions (sorted-count tie-break: highest
    # counts land in chunk 1).
    seen_ips: set[str] = set()
    for p in scanner_payloads:
        chunk_ips = set(p["expression"][len("(ip.src in {"):-2].split())
        assert chunk_ips.isdisjoint(seen_ips), "Chunk IPs overlap"
        seen_ips.update(chunk_ips)
    assert len(seen_ips) == 1100


def test_cloudflare_payloads_no_chunk_suffix_when_single_chunk():
    """AISO-202: a single-chunk rule stays as-is (no '(chunk 1/1)').

    The suffix is only meaningful when M > 1. Dashboards and existing
    grep filters that key off the description must not have to
    special-case '(chunk 1/1)'.
    """
    findings = [_finding_with_details({
        "top_attackers": [
            {"ip": f"1.2.3.{i}", "total_probe_requests": i + 1, "total_requests": 10,
             "probe_paths": {"/.env": i + 1}, "first_seen": "", "last_seen": "",
             "user_agents": []}
            for i in range(5)
        ],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    scanner = [p for p in payloads if p.get("_category", "").startswith("scanner")]
    assert len(scanner) == 1
    assert "chunk" not in scanner[0]["description"].lower()
    assert scanner[0]["_chunk"] == 1
    assert scanner[0]["_chunk_total"] == 1


def test_cloudflare_curl_script_emits_one_curl_per_chunk():
    """AISO-202: chunking must produce one curl per chunk in order."""
    findings = [_finding_with_details({
        "top_attackers": [
            {"ip": f"203.0.113.{i}", "total_probe_requests": 1100 - i,
             "total_requests": 1,
             "probe_paths": {"/.env": 1}, "first_seen": "", "last_seen": "",
             "user_agents": []}
            for i in range(1100)
        ],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    script = build_cloudflare_curl_script(payloads)
    # Exactly 3 curl POSTs (one per chunk of the scanner category).
    assert script.count("curl -fsS -X POST") == 3
    # Each chunk label must appear in both the comment and the echo.
    for n in (1, 2, 3):
        assert f"chunk {n}/3" in script, f"chunk {n}/3 not in script"


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


# ---------------------------------------------------------------------------
# AISO-202 — Cloudflare payload chunking (max 500 entries / rule)
# ---------------------------------------------------------------------------


def _row(ip: str, count: int = 1) -> dict:
    """Compact top_attackers row used by the chunking tests."""
    return {
        "ip": ip,
        "total_probe_requests": count,
        "total_requests": count,
        "probe_paths": {"/.env": count},
        "first_seen": "",
        "last_seen": "",
        "user_agents": [],
    }


def _ips_in_expression(expr: str) -> list[str]:
    """Extract the space-separated IPs from a CF expression.

    Strips the literal `(ip.src in {` prefix and trailing `})` so callers
    get back a clean list. Used to assert no-drops / no-dupes across
    chunks.
    """
    assert expr.startswith("(ip.src in {") and expr.endswith("})"), expr
    body = expr[len("(ip.src in {"):-len("})")]
    return body.split()


def _external_ips(count: int) -> list[str]:
    """Generate `count` distinct non-local IPs.

    Uses the public 8.0.0.0/8 block (8.0.0.0–8.255.255.255 = 16M+ IPs)
    which is NOT in the `_LOCAL_NETWORKS` filter, so every IP survives
    `build_cloudflare_block_payloads` and lands in the chunks.
    """
    import ipaddress
    from alma_audit.forensic_export import _is_local_ip
    ips: list[str] = []
    net = ipaddress.ip_network("8.0.0.0/8")
    for ip in net:
        if len(ips) >= count:
            break
        if not _is_local_ip(str(ip)):
            ips.append(str(ip))
    assert len(ips) == count, f"only generated {len(ips)}/{count}"
    return ips


def test_cloudflare_chunking_empty_findings_emits_no_payloads():
    """Empty findings → no payloads, no no-op sentinel, no crash.

    Edge case for the chunking path: with no categories populated,
    every `_emit_chunked` returns early. The function must return `[]`
    so the curl script / forensic JSON cleanly says "nothing to block".
    """
    payloads = build_cloudflare_block_payloads([])
    assert payloads == []


def test_cloudflare_chunking_below_min_ips_emits_no_payload():
    """1 IP for a category (below min_ips=3) → no payload, no chunks.

    Edge case: the chunking loop must never run when there aren't
    enough IPs to warrant a rule in the first place.
    """
    findings = [_finding_with_details({"top_attackers": [_row("1.2.3.4")]}),
                _finding_with_details({"ssh_fail_details": [
                    {"ip": "5.6.7.8", "user": "root", "count": 5,
                     "first_seen": "", "last_seen": ""},
                ]})]
    payloads = build_cloudflare_block_payloads(findings)
    assert payloads == []


def test_cloudflare_chunking_small_input_single_chunk_no_suffix():
    """'Small but valid' input (3 IPs, well below 500) → 1 chunk, no suffix.

    A single-chunk rule must NOT carry the `(chunk 1/1)` suffix so
    existing dashboards / grep filters don't have to special-case it.
    """
    findings = [_finding_with_details({
        "top_attackers": [_row(f"1.2.3.{i}", count=i + 1) for i in range(3)],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    # Exactly one scanner payload.
    scanner_payloads = [p for p in payloads if "scanner" in p.get("_category", "")]
    assert len(scanner_payloads) == 1
    p = scanner_payloads[0]
    assert p["_chunk"] == 1
    assert p["_chunk_total"] == 1
    assert "(chunk" not in p["description"]
    assert _ips_in_expression(p["expression"]) == [
        "1.2.3.2", "1.2.3.1", "1.2.3.0",  # count desc: 3, 2, 1
    ]


def test_cloudflare_chunking_exactly_chunk_boundary_single_payload():
    """Exactly 500 IPs → 1 payload, no chunk suffix, all 500 present.

    Boundary case: 500 must NOT split. The chunking loop's `start:start+500`
    slice yields the whole list as a single chunk, with no `(chunk 1/1)`
    noise in the description.
    """
    # 500 distinct external IPs in 8.0.0.0/8 — survives the local-IP
    # filter (`_is_local_ip` doesn't reject 8/8) and gives every IP a
    # unique value so no count-desc tie-breaks pollute the assertion.
    ips = _external_ips(500)
    findings = [_finding_with_details({
        "top_attackers": [_row(ip, count=1) for ip in ips],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    scanner_payloads = [p for p in payloads if "scanner" in p.get("_category", "")]
    assert len(scanner_payloads) == 1
    p = scanner_payloads[0]
    assert p["_chunk"] == 1
    assert p["_chunk_total"] == 1
    assert p["_count"] == 500
    assert "(chunk" not in p["description"]
    emitted = _ips_in_expression(p["expression"])
    assert len(emitted) == 500
    assert emitted == sorted(emitted)  # 500 IPs with equal count → alpha
    assert set(emitted) == set(ips)  # no drops, no dupes


def test_cloudflare_chunking_just_over_chunk_boundary_splits_into_two():
    """501 IPs → 2 chunks: first has 500, second has 1.

    Boundary case: the 501st IP must trigger a new chunk, not silently
    overflow the first. This is the off-by-one boundary — the chunking
    loop's `start + _CHUNK_SIZE` slice must produce exactly 500+1.
    """
    ips = _external_ips(501)
    findings = [_finding_with_details({
        "top_attackers": [_row(ip, count=1) for ip in ips],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    scanner_payloads = sorted(
        [p for p in payloads if "scanner" in p.get("_category", "")],
        key=lambda p: p["_chunk"],
    )
    assert len(scanner_payloads) == 2
    first, second = scanner_payloads
    # First chunk is the boundary case: exactly 500 entries.
    assert first["_count"] == 500
    assert first["_chunk"] == 1
    assert first["_chunk_total"] == 2
    assert "(chunk 1/2)" in first["description"]
    # Second chunk carries the overflow: just 1 entry.
    assert second["_count"] == 1
    assert second["_chunk"] == 2
    assert second["_chunk_total"] == 2
    assert "(chunk 2/2)" in second["description"]
    # Union of chunks == original list (no drops, no dupes).
    union = _ips_in_expression(first["expression"]) + _ips_in_expression(second["expression"])
    assert len(union) == 501
    assert set(union) == set(ips)
    # Chunks must be disjoint.
    assert not (set(_ips_in_expression(first["expression"]))
                & set(_ips_in_expression(second["expression"])))


def test_cloudflare_chunking_multi_chunk_preserves_global_order():
    """1,250 IPs → 3 chunks (500/500/250), preserving the global sort order.

    Across chunks, the top-N sorting (count desc, then alpha) must be
    respected — the union of chunk expressions must equal the
    globally-sorted original list with no gaps and no overlap.
    """
    ips = _external_ips(1250)
    findings = [_finding_with_details({
        "top_attackers": [_row(ip, count=1) for ip in ips],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    scanner_payloads = sorted(
        [p for p in payloads if "scanner" in p.get("_category", "")],
        key=lambda p: p["_chunk"],
    )
    assert len(scanner_payloads) == 3
    sizes = [p["_count"] for p in scanner_payloads]
    assert sizes == [500, 500, 250]
    for idx, p in enumerate(scanner_payloads, start=1):
        assert p["_chunk"] == idx
        assert p["_chunk_total"] == 3
        assert f"(chunk {idx}/3)" in p["description"]
    # Reassemble and verify ordering matches the global sort.
    reassembled: list[str] = []
    for p in scanner_payloads:
        reassembled.extend(_ips_in_expression(p["expression"]))
    expected_sorted = sorted(ips)  # all count=1 → pure alpha sort
    assert reassembled == expected_sorted
    # No drops, no dupes.
    assert len(reassembled) == len(set(reassembled)) == 1250


def test_cloudflare_chunking_across_categories_no_bleeding():
    """scanner + brute-force chunking operate independently.

    The scanner and SSH brute-force categories must NOT share chunks
    or bleed into each other's payloads. Both can chunk independently.
    """
    scanner_ips = _external_ips(600)  # 2 chunks (500 + 100)
    # Pull SSH IPs from a disjoint slice of the same external pool —
    # avoids depending on a fixed prefix scheme.
    ssh_ips = _external_ips(700)[600:650]  # 50 IPs, disjoint from scanner_ips

    def _ssh_row(ip: str) -> dict:
        return {"ip": ip, "user": "root", "count": 1,
                "first_seen": "", "last_seen": ""}

    findings = [_finding_with_details({
        "top_attackers": [_row(ip) for ip in scanner_ips],
        "ssh_fail_details": [_ssh_row(ip) for ip in ssh_ips],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    by_cat: dict[str, list[dict]] = {}
    for p in payloads:
        by_cat.setdefault(p["_category"], []).append(p)
    # Scanner: 2 chunks (600 IPs / 500).
    scanner_payloads = sorted(by_cat.get("scanner IPs (probe paths)", []),
                              key=lambda p: p["_chunk"])
    assert len(scanner_payloads) == 2
    assert scanner_payloads[0]["_count"] == 500
    assert scanner_payloads[1]["_count"] == 100
    assert scanner_payloads[0]["_chunk_total"] == 2
    # SSH: 1 chunk (50 IPs, below 500).
    ssh_payloads = by_cat.get("brute-force IPs (SSH)", [])
    assert len(ssh_payloads) == 1
    assert ssh_payloads[0]["_count"] == 50
    assert ssh_payloads[0]["_chunk_total"] == 1
    assert "(chunk" not in ssh_payloads[0]["description"]
    # Scanner chunks must contain only scanner IPs, not SSH IPs.
    scanner_set = set(scanner_ips)
    ssh_set = set(ssh_ips)
    for p in scanner_payloads:
        ips_in = _ips_in_expression(p["expression"])
        # Scanner chunk must be a subset of the scanner IP set.
        assert set(ips_in) <= scanner_set
        # SSH IPs must not appear in scanner chunks.
        assert ssh_set.isdisjoint(ips_in)
    # And the SSH chunk must not contain scanner IPs.
    ssh_in = _ips_in_expression(ssh_payloads[0]["expression"])
    assert set(ssh_in) <= ssh_set
    assert scanner_set.isdisjoint(ssh_in)


def test_cloudflare_chunking_no_drops_no_duplicates_across_chunks():
    """Property: union of chunk IPs == original IP set, |union| == |original|.

    A direct property-style check: generate a larger random set of
    IPs, verify the chunking preserves cardinality and uniqueness.
    """
    import random
    rng = random.Random(42)  # deterministic
    # 1234 distinct external IPs — large enough to span 3 chunks.
    ips = _external_ips(1234)
    findings = [_finding_with_details({
        "top_attackers": [_row(ip, count=rng.randint(1, 100)) for ip in ips],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    scanner_payloads = sorted(
        [p for p in payloads if "scanner" in p.get("_category", "")],
        key=lambda p: p["_chunk"],
    )
    # 1234 / 500 = 3 chunks (500, 500, 234).
    assert len(scanner_payloads) == 3
    union: list[str] = []
    for p in scanner_payloads:
        union.extend(_ips_in_expression(p["expression"]))
    # No drops: every original IP appears in exactly one chunk.
    # NOTE: set comparison — `ips` is in numeric (network) order from
    # `_external_ips`'s `ipaddress.ip_network` iteration, but the chunk
    # assembly emits in count-desc-then-alpha order, so position-wise
    # equality of sorted lists is not a useful invariant. The
    # cardinality check below is the real property.
    assert set(union) == set(ips)
    # No duplicates: chunk cardinality == original cardinality.
    assert len(union) == len(ips)


def test_cloudflare_chunking_curl_script_emits_one_curl_per_chunk():
    """build_cloudflare_curl_script emits one curl line per chunk.

    The script-level wiring: each chunk payload produces one POST
    in the generated script. The operator's workflow is unchanged —
    they run `bash cloudflare-block.sh` and it iterates the chunks
    transparently.
    """
    ips = _external_ips(1250)
    findings = [_finding_with_details({
        "top_attackers": [_row(ip) for ip in ips],
    })]
    payloads = build_cloudflare_block_payloads(findings)
    script = build_cloudflare_curl_script(payloads)
    # One curl per payload (chunk), regardless of how many chunks.
    assert script.count("curl -fsS -X POST") == len(payloads)
    # The chunk-N/M metadata lands in the script's comment lines.
    assert "(chunk 1/3)" in script
    assert "(chunk 2/3)" in script
    assert "(chunk 3/3)" in script
