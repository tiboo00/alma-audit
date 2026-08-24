"""Tests for the ModSecurity + error_log analyzer."""

from __future__ import annotations

from alma_audit.analyzers.modsec_log import (
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
    action, ids, sev = _parse_modsec_request(blocks[0])
    assert action == "intercepted"
    assert "942100" in ids
    assert sev == 2  # CRITICAL → 2


def test_parse_modsec_request_multi_field_line():
    """Regression: a single line may carry multiple `[key "value"]` fields.

    The Supervisor caught this: the old single-pair regex swallowed only
    the first field per line, so `[id "942100"] [severity "CRITICAL"]`
    on one line left severity=0 in the aggregator.
    """
    lines = [
        '[line "12"] [id "942100"] [rev "1"] [msg "SQL Injection Attack"] [severity "CRITICAL"]',
    ]
    action, ids, sev = _parse_modsec_request(lines)
    assert "942100" in ids
    assert ids.count("942100") == 1, f"id 942100 must not be duplicated, got {ids}"
    assert sev == 2  # CRITICAL extracted from the multi-field line


def test_parse_modsec_request_action_overrides_message():
    """Regression: an explicit `Action:` line must beat the `Message:` heuristic."""
    lines = [
        'Message: Access denied with code 403 (phase 1).',
        'Action: Intercepted (phase 1)',
    ]
    action, _, _ = _parse_modsec_request(lines)
    assert action == "intercepted"


def test_parse_modsec_request_clean_request():
    blocks = list(_iter_modsec_requests(SAMPLE_MODSEC.splitlines()))
    action, ids, sev = _parse_modsec_request(blocks[1])
    assert action == ""  # no deny
    assert ids == []
    assert sev == 0


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
