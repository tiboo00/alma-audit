"""Tests for the Apache access-log parser + aggregator."""

from __future__ import annotations

from alma_audit.analyzers.access_log import (
    AccessAggregator,
    analyze_access_logs,
    parse_line,
)
from alma_audit.models import Severity

# A real-flavored combined log: cPanel/Apache host with mixed traffic
# (some Googlebot, some Sogou spider, some masscan, plus the IPs the
# user explicitly called out). We include many probe hits to make the
# WARN finding deterministic.
SAMPLE_LOG = """\
211.248.230.233 - - [17/Aug/2026:04:12:34 +0000] "GET /administrator/ HTTP/1.1" 301 795 "-" "Mozilla/5.0"
38.253.224.2 - - [17/Aug/2026:04:12:35 +0000] "GET /wp-login.php HTTP/1.1" 200 1234 "-" "Googlebot/2.1"
2a06:98c0:3600::103 - - [17/Aug/2026:04:12:36 +0000] "GET /.env HTTP/1.1" 404 - "-" "Sogou Pic Spider/3.0"
134.199.208.10 - - [17/Aug/2026:04:12:37 +0000] "PROPFIND / HTTP/1.1" 405 235 "-" "masscan"
38.253.224.2 - - [17/Aug/2026:04:12:38 +0000] "GET /index.html HTTP/1.1" 200 5432 "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:39 +0000] "GET /favicon.ico HTTP/1.1" 200 318 "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:40 +0000] "GET /robots.txt HTTP/1.1" 200 200 "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:41 +0000] "GET /wp-admin/ HTTP/1.1" 404 - "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:42 +0000] "GET /admin.php HTTP/1.1" 404 - "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:43 +0000] "GET /admin/ HTTP/1.1" 404 - "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:44 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:45 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:46 +0000] "GET /xmlrpc.php HTTP/1.1" 404 - "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:47 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:48 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:49 +0000] "GET /wp-admin/ HTTP/1.1" 404 - "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:50 +0000] "GET /.env HTTP/1.1" 404 - "-" "Sogou Pic Spider/3.0"
38.253.224.2 - - [17/Aug/2026:04:12:51 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "Googlebot/2.1"
38.253.224.2 - - [17/Aug/2026:04:12:52 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "Googlebot/2.1"
malformed line that is definitely not an access log entry
"""

# A log dominated by a single IP (top-host-share > 70%)
DOMINATED_LOG = (
    "\n".join(
        f'10.0.0.1 - - [17/Aug/2026:04:12:{i:02d} +0000] "GET /page{i} HTTP/1.1" 200 100 "-" "ua{i}"'
        for i in range(80)
    )
    + "\n10.0.0.2 - - [17/Aug/2026:04:13:00 +0000] \"GET /x HTTP/1.1\" 200 100 \"-\" \"ua\"\n"
)


def test_parse_line_combined_format():
    rec = parse_line(
        '1.2.3.4 - - [17/Aug/2026:04:12:34 +0000] "GET /a/b HTTP/1.1" 301 795 "-" "ua"'
    )
    assert rec is not None
    assert rec.host == "1.2.3.4"
    assert rec.method == "GET"
    assert rec.path == "/a/b"
    assert rec.status == 301
    assert rec.size == 795
    assert rec.timestamp == "17/Aug/2026:04:12:34 +0000"


def test_parse_line_handles_dash_size():
    rec = parse_line(
        '1.2.3.4 - - [17/Aug/2026:04:12:34 +0000] "GET / HTTP/1.1" 404 - "-" "ua"'
    )
    assert rec is not None
    assert rec.size == 0


def test_parse_line_returns_none_for_garbage():
    assert parse_line("not a log line") is None
    assert parse_line("") is None
    assert parse_line('1.2.3.4 - - badts "GET / HTTP/1.1" 200 100') is None


def test_aggregator_counts_probes():
    agg = AccessAggregator()
    malformed = 0
    for line in SAMPLE_LOG.strip().split("\n"):
        rec = parse_line(line)
        if rec is None:
            malformed += 1
        else:
            agg.add(rec)
    summary = agg.finalize()
    assert summary["total_lines"] == 19  # 19 valid + 1 malformed
    assert malformed == 1
    # The probe hits should include the wp-login / wp-admin / administrator / admin paths
    probe_patterns = {p for p, _ in summary["probe_hits"]}
    assert "/administrator/" in probe_patterns
    assert "/wp-login.php" in probe_patterns
    assert "/.env" in probe_patterns


def test_analyzer_emits_probe_finding(make_fs):
    fs = make_fs({"/var/log/apache2/access_log": SAMPLE_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    probe_findings = [f for f in findings if "probe" in f.title.lower()]
    assert probe_findings, "expected a probe-path finding"
    assert probe_findings[0].severity == Severity.WARN


def test_analyzer_emits_weird_method_finding(make_fs):
    # 6 PROPFIND lines — at threshold (warn=5) this fires deterministically.
    log = SAMPLE_LOG + "\n".join(
        f'134.199.208.10 - - [17/Aug/2026:04:13:{i:02d} +0000] "PROPFIND / HTTP/1.1" 405 235 "-" "masscan"'
        for i in range(6)
    )
    fs = make_fs({"/var/log/apache2/access_log": log})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    weird_findings = [f for f in findings if "unusual" in f.title.lower()]
    assert weird_findings, "expected an unusual-method finding (PROPFIND)"
    assert "PROPFIND" in weird_findings[0].details["weird_methods"]


def test_analyzer_emits_critical_top_host(make_fs):
    fs = make_fs({"/var/log/apache2/access_log": DOMINATED_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit, "expected a CRITICAL finding for a single-IP-dominated log"
    assert "10.0.0.1" in crit[0].title


def test_analyzer_handles_missing_log(make_fs):
    fs = make_fs({})  # no files
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "no" in findings[0].title.lower()


def test_analyzer_threshold_override_suppresses_warning(make_fs):
    # Set thresholds so high that no findings fire.
    fs = make_fs({"/var/log/apache2/access_log": SAMPLE_LOG})
    rules = {"probe_count_warn": 1000, "weird_method_count_warn": 1000}
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs, rules=rules)
    probe_findings = [f for f in findings if "probe" in f.title.lower()]
    weird_findings = [f for f in findings if "unusual" in f.title.lower()]
    assert probe_findings == []
    assert weird_findings == []
