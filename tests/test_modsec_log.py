"""Tests for the ModSecurity + error_log analyzer."""

from __future__ import annotations

from alma_audit.analyzers.modsec_log import (
    ModSecAggregator,
    _iter_modsec_requests,
    _parse_modsec_request,
    analyze_modsec_and_errors,
)
from alma_audit.models import Severity

SAMPLE_ERR = """\
[Sun Aug 17 04:12:34.123456 2026] [core:error] [pid 12345] [client 1.2.3.4] AH00112: failure
[Sun Aug 17 04:12:35.123456 2026] [mpm_prefork:notice] [pid 12345] AH00163: started
[Sun Aug 17 04:12:36.123456 2026] [core:error] [pid 12345] AH00037: 503 Service Unavailable
[Sun Aug 17 04:12:37.123456 2026] [proxy:error] [pid 12345] AH01114: 502 Bad Gateway
[Sun Aug 17 04:12:38.123456 2026] [core:warn] [pid 12345] AH00037: warning
"""

# ModSecurity v2 audit format — one request per block, sections delimited by --X--Y-- lines.
SAMPLE_MODSEC = """\
--abcdef12-A--
[17/Aug/2026:04:12:34 +0000] 1234567890 abcdef12.example.com 1.2.3.4 54321
--abcdef12-B--
GET /.env HTTP/1.1
Host: example.com
User-Agent: masscan
--abcdef12-F--
HTTP/1.1 403 Forbidden
Content-Length: 0
--abcdef12-E--
Message: Access denied with code 403 (phase 1). Pattern match "\\\\b(?:select\\\\b)" at REQUEST_URI.
[file "/etc/modsecurity/owasp/crs/REQUEST-942-100.sql-injection.conf"]
[line "12"] [id "942100"] [rev "1"] [msg "SQL Injection Attack Detected via libinjection"] [data "select 1"]
[severity "CRITICAL"] [ver "OWASP_CRS/3.3.5"] [tag "application-multi"] [tag "language-multi"]
Action: Intercepted (phase 1)
--abcdef12-Z--
Stop: 1
--deadbeef-A--
[17/Aug/2026:04:12:35 +0000] 1234567891 deadbeef.example.com 5.6.7.8 54322
--deadbeef-B--
GET /robots.txt HTTP/1.1
--deadbeef-F--
HTTP/1.1 200 OK
--deadbeef-Z--
Stop: 0
"""


def test_parse_modsec_request_extracts_action_and_ids():
    blocks = list(_iter_modsec_requests(SAMPLE_MODSEC.splitlines()))
    assert len(blocks) == 2
    action, ids, sev, uri = _parse_modsec_request(blocks[0])
    assert action == "intercepted"
    assert "942100" in ids
    assert sev == 2  # CRITICAL → 2
    assert uri == "/.env"  # AISO-205: B-section request line is captured


def test_parse_modsec_request_multi_field_line():
    """Regression: a single line may carry multiple `[key "value"]` fields.

    The Supervisor caught this: the old single-pair regex swallowed only
    the first field per line, so `[id "942100"] [severity "CRITICAL"]`
    on one line left severity=0 in the aggregator.
    """
    lines = [
        '[line "12"] [id "942100"] [rev "1"] [msg "SQL Injection Attack"] [severity "CRITICAL"]',
    ]
    action, ids, sev, uri = _parse_modsec_request(lines)
    assert "942100" in ids
    assert ids.count("942100") == 1, f"id 942100 must not be duplicated, got {ids}"
    assert sev == 2  # CRITICAL extracted from the multi-field line
    # No B-section in this fixture → URI stays empty.
    assert uri == ""


def test_parse_modsec_request_action_overrides_message():
    """Regression: an explicit `Action:` line must beat the `Message:` heuristic."""
    lines = [
        'Message: Access denied with code 403 (phase 1).',
        'Action: Intercepted (phase 1)',
    ]
    action, _, _, _ = _parse_modsec_request(lines)
    assert action == "intercepted"


def test_parse_modsec_request_clean_request():
    blocks = list(_iter_modsec_requests(SAMPLE_MODSEC.splitlines()))
    action, ids, sev, uri = _parse_modsec_request(blocks[1])
    assert action == ""  # no deny
    assert ids == []
    assert sev == 0
    # The second sample block hits /robots.txt with no action — even so,
    # the B-section URI should still surface (the parser captures it
    # regardless of action / severity).
    assert uri == "/robots.txt"


def _fs_with(files):
    from alma_audit.runners import FakeFileSystem

    return FakeFileSystem(files=files)


def test_analyzer_emits_error_count_finding():
    fs = _fs_with({
        "/var/log/apache2/error_log": SAMPLE_ERR,
        "/var/log/apache2/modsec_audit.log": SAMPLE_MODSEC,
    })
    findings = analyze_modsec_and_errors(
        error_paths=["/var/log/apache2/error_log"],
        modsec_paths=["/var/log/apache2/modsec_audit.log"],
        fs=fs,
    )
    # We expect: 1 INFO "Scanned error_log", 1 INFO "Scanned modsec",
    # 1 WARN/CRITICAL "5xx messages", 1 INFO about modsec scan, and
    # 1 CRITICAL about modsec CRITICAL severity rule.
    sevs = [f.severity for f in findings]
    assert Severity.CRITICAL in sevs
    assert any("denied" in f.title.lower() or "5xx" in f.title.lower() for f in findings)


def test_analyzer_missing_logs_yields_info_only():
    fs = _fs_with({})
    findings = analyze_modsec_and_errors(
        error_paths=["/var/log/apache2/error_log"],
        modsec_paths=["/var/log/apache2/modsec_audit.log"],
        fs=fs,
    )
    # Both files missing → 2 INFO findings.
    assert all(f.severity == Severity.INFO for f in findings)
    assert len(findings) == 2


def test_analyzer_deny_threshold_tuning():
    # A log with only one deny shouldn't escalate by default (threshold=1 → WARN).
    fs = _fs_with({"/var/log/apache2/modsec_audit.log": SAMPLE_MODSEC})
    findings = analyze_modsec_and_errors(
        error_paths=[],
        modsec_paths=["/var/log/apache2/modsec_audit.log"],
        fs=fs,
        rules={"modsec_deny_warn": 1000},  # bump threshold above what we see
    )
    # Should have INFO summary + CRITICAL from "severity=CRITICAL rule fired",
    # but NOT a WARN about denies.
    titles = [f.title for f in findings]
    assert not any("ModSecurity denied" in t for t in titles)


# ---------------------------------------------------------------------------
# AISO-205: ModSecurity rule IDs detailed report.
#
# The existing finalize() already exposes `top_rule_ids: [(rule_id, count)]`,
# but the issue asks for a richer `modsec_rule_breakdown` payload that also
# surfaces the top request URI per rule (so the operator can tell *which*
# payload triggered 942100 — /.env? /wp-login.php?). The tests below pin the
# new contract down before the implementation lands.
# ---------------------------------------------------------------------------


def test_aggregator_modsec_rule_breakdown_units_by_count_then_rule_id():
    """AISO-205 AC #2 + AC #5: aggregator exposes rule → count → top_uri,
    sorted by count desc with rule_id asc as the deterministic tie-breaker.
    """
    agg = ModSecAggregator()
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="/a")
    agg.add_request(action="deny", ids=["942100", "941100"], max_sev=2, uri="/b")
    agg.add_request(action="deny", ids=["941100"], max_sev=1, uri="/c")

    result = agg.finalize()

    assert "modsec_rule_breakdown" in result
    breakdown = result["modsec_rule_breakdown"]
    # 942100 appears twice (with /a on the first hit), 941100 appears twice
    # (with /b on its first hit). Equal counts — tie-break on rule_id asc.
    assert breakdown == [
        ("941100", 2, "/b"),
        ("942100", 2, "/a"),
    ]
    # top_rule_ids is the existing 2-tuple shape (AC #3 wiring).
    assert result["top_rule_ids"] == [("941100", 2), ("942100", 2)]


def test_aggregator_modsec_rule_breakdown_top_uri_picks_most_frequent():
    """AISO-205 follow-up: top_uri is the URI that fired a rule the MOST
    often, NOT the first URI seen.

    The previous "first-URI-wins" implementation was flagged by the
    Supervisor as semantically wrong: feeding `/rare-first` × 1 then
    `/common` × 3 used to surface `/rare-first` even though `/common`
    fired 3× as often. This test pins the corrected behaviour: the
    most-frequent URI wins.
    """
    agg = ModSecAggregator()
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="/rare-first")
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="/common")
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="/common")
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="/common")

    result = agg.finalize()

    # Rule 942100 fired 4 times — 1× /rare-first, 3× /common. /common
    # is the top_uri, not the first-seen /rare-first.
    assert result["modsec_rule_breakdown"] == [("942100", 4, "/common")]


def test_aggregator_modsec_rule_breakdown_top_uri_lex_tie_break():
    """When two URIs tie on count for the same rule, the lex-smallest URI
    wins so the operator dashboard sees a deterministic value across runs.

    ``Counter.most_common()`` is NOT stable for ties — it preserves
    insertion order, which depends on parse order. We sort explicitly
    by ``(-count, uri)`` to keep the result reproducible.
    """
    agg = ModSecAggregator()
    # Insert /zzz first so insertion order would prefer it under
    # ``Counter.most_common()`` — the tie-break must still prefer /aaa.
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="/zzz")
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="/aaa")
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="/zzz")
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="/aaa")

    result = agg.finalize()

    # /aaa and /zzz both fired 2×; lex tie-break prefers /aaa.
    assert result["modsec_rule_breakdown"] == [("942100", 4, "/aaa")]


def test_aggregator_modsec_rule_breakdown_empty_uri_when_parser_cannot_extract():
    """If the parser never supplied a URI for a rule (malformed
    B-section), top_uri falls back to an empty string rather than
    surfacing a phantom bucket.
    """
    agg = ModSecAggregator()
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="")
    agg.add_request(action="deny", ids=["942100"], max_sev=2, uri="")

    result = agg.finalize()

    assert result["modsec_rule_breakdown"] == [("942100", 2, "")]


def test_aggregator_modsec_rule_breakdown_caps_at_top_10():
    """The breakdown is bounded at 10 rules so the JSON + MD don't blow up
    on a long-tail CRS install.
    """
    agg = ModSecAggregator()
    # 15 distinct rule IDs with descending counts.
    for i in range(15):
        rule_id = f"9{4100 + i:04d}"
        # Each rule gets (15 - i) hits — first one is loudest.
        for _ in range(15 - i):
            agg.add_request(action="deny", ids=[rule_id], max_sev=2, uri=f"/u{i}")

    result = agg.finalize()

    assert len(result["modsec_rule_breakdown"]) == 10
    # Loudest rule is the one with 15 hits.
    assert result["modsec_rule_breakdown"][0][0] == "94100"
    assert result["modsec_rule_breakdown"][0][1] == 15


def test_parse_modsec_request_captures_request_uri_from_b_section():
    """AISO-205: the URI sits on the first line of the B-section
    (`GET /.env HTTP/1.1`). The parser must surface it so the aggregator
    can attribute each rule to its triggering URI.
    """
    lines = [
        "--deadbeef-A--",
        "[17/Aug/2026:04:12:34 +0000] 1234567890 x.example 1.2.3.4 54321",
        "--deadbeef-B--",
        "GET /.env HTTP/1.1",
        "Host: example.com",
        "--deadbeef-E--",
        '[line "12"] [id "942100"] [severity "CRITICAL"]',
        "Action: Intercepted (phase 1)",
    ]
    action, ids, sev, uri = _parse_modsec_request(lines)
    assert action == "intercepted"
    assert ids == ["942100"]
    assert sev == 2
    assert uri == "/.env"


def test_analyzer_top_rule_ids_matches_acceptance_criterion_5():
    """AISO-205 AC #5: synthesize a log with two [id "942100"] and one
    [id "941100"] entries — the 'ModSecurity denied' finding's `details`
    block must list them with the loudest rule first.
    """
    block = """\
--feedf00d-A--
[17/Aug/2026:04:12:34 +0000] 1234567890 a.example 1.2.3.4 54321
--feedf00d-B--
GET /login.php HTTP/1.1
--feedf00d-E--
[line "12"] [id "942100"] [severity "CRITICAL"]
Action: Intercepted (phase 1)
--feedf00d-Z--
--cafebabe-A--
[17/Aug/2026:04:12:35 +0000] 1234567891 b.example 1.2.3.5 54322
--cafebabe-B--
GET /wp-admin HTTP/1.1
--cafebabe-E--
[line "12"] [id "942100"] [severity "CRITICAL"]
Action: Intercepted (phase 1)
--cafebabe-Z--
--deadc0de-A--
[17/Aug/2026:04:12:36 +0000] 1234567892 c.example 1.2.3.6 54323
--deadc0de-B--
GET /xmlrpc.php HTTP/1.1
--deadc0de-E--
[line "12"] [id "941100"] [severity "WARNING"]
Action: Intercepted (phase 1)
--deadc0de-Z--
"""
    fs = _fs_with({"/var/log/apache2/modsec_audit.log": block})
    findings = analyze_modsec_and_errors(
        error_paths=[],
        modsec_paths=["/var/log/apache2/modsec_audit.log"],
        fs=fs,
    )

    denied = [f for f in findings if "ModSecurity denied" in f.title]
    assert denied, "expected a 'ModSecurity denied' finding"
    details = denied[0].details
    assert details["top_rule_ids"] == [("942100", 2), ("941100", 1)]


def test_no_modsec_finding_unchanged_when_no_audit_logs_present():
    """AISO-205 AC #4: when no modsec audit log is found, the existing
    'No ModSecurity audit log files matched' INFO finding stays exactly
    as it was before the new feature landed.
    """
    fs = _fs_with({})
    findings = analyze_modsec_and_errors(
        error_paths=[],
        modsec_paths=["/var/log/apache2/modsec_audit.log"],
        fs=fs,
    )
    titles = [f.title for f in findings]
    assert "No ModSecurity audit log files matched" in titles
    # No deny / no rule-breakdown finding when no data.
    assert not any("ModSecurity denied" in t for t in titles)
