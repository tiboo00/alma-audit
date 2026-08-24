"""Regression tests for AISO-208 — path-level user-agent breakdown.

Background
==========

`AccessAggregator.top_attackers` carries a top-5 user-agent list per
IP, but the operator can't see **which user-agent hits which probe
path**. A scanner using `python-requests/2.28.0` on `/.env` is a
different threat from the same UA on `/wp-login.php` (form-fill
credential stuffing).

These tests lock the per-(path, ip, UA) breakdown in three places:

1. **Aggregator contract** — `_PerIPProbeStat.user_agents` is stored
   per (path, ip), NOT aggregated across paths. Same IP hitting two
   different paths with two different UAs must produce two separate
   UA lists in the forensic output.
2. **Forensic JSON** — `alma-audit-forensic.json` carries the full
   `probe_paths_by_ip` block with `{path: [{ip, count, first_seen,
   last_seen, user_agents}, ...]}`.
3. **Markdown summary** — the operator sees the top path × top IP ×
   UA combination (e.g. "/wp-login.php from 1.2.3.4 using
   python-requests/2.28.0 × 27 requests") inline in the MD report.

These tests are the regression lock — a refactor of `add()` or
`_serialise_probe_paths_by_ip` that re-introduces cross-path UA
aggregation would flip AC#1 / AC#2 red.
"""

from __future__ import annotations

from alma_audit.analyzers.access_log import (
    AccessAggregator,
    analyze_access_logs,
    parse_line,
)
from alma_audit.forensic_export import build_forensic_export
from alma_audit.models import Severity
from alma_audit.reporting import write_markdown_report


# Same IP, two different probe paths, two different user-agents. The
# acceptance criterion's exact scenario: a single source IP that uses
# one UA on /.env and a different UA on /wp-login.php. The forensic
# JSON MUST distinguish the two (path, ip, UA) combinations — they are
# different threats, even though the IP and the "is it probing?"
# answer are the same.
# Counts exceed the default `probe_count_warn` (10) so the probe-path
# finding deterministically fires for the Markdown test below.
TWO_PATH_TWO_UA_LOG = "\n".join(
    [
        # /.env with python-requests (15 hits) — exceeds the WARN threshold.
        '198.51.100.10 - - [17/Aug/2026:04:12:34 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:35 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:36 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:37 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:38 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:39 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:40 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:41 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:42 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:43 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:44 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:45 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:46 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:47 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        '198.51.100.10 - - [17/Aug/2026:04:12:48 +0000] "GET /.env HTTP/1.1" 404 - "-" "python-requests/2.28.0"',
        # /wp-login.php with curl/8.4.0 (15 hits) — second threat vector.
        '198.51.100.10 - - [17/Aug/2026:04:13:00 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:01 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:02 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:03 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:04 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:05 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:06 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:07 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:08 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:09 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:10 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:11 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:12 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:13 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
        '198.51.100.10 - - [17/Aug/2026:04:13:14 +0000] "GET /wp-login.php HTTP/1.1" 404 - "-" "curl/8.4.0"',
    ]
)


def _feed(log: str) -> AccessAggregator:
    """Helper: parse + feed every line into a fresh aggregator."""
    agg = AccessAggregator()
    for line in log.strip().splitlines():
        rec = parse_line(line)
        assert rec is not None, f"failed to parse: {line!r}"
        agg.add(rec)
    return agg


# ---------------------------------------------------------------------------
# AC#1: aggregator stores UAs per (path, ip), NOT aggregated across paths.
# ---------------------------------------------------------------------------


def test_aggregator_per_path_ip_user_agents_not_aggregated():
    """AC#1: same IP, two paths, two UAs — UAs must be tracked per (path, ip).

    The 198.51.100.10 IP hits /.env with python-requests/2.28.0 and
    /wp-login.php with curl/8.4.0. The forensic JSON must distinguish
    them — the (/.env, 198.51.100.10) bucket only sees python-requests,
    the (/wp-login.php, 198.51.100.10) bucket only sees curl.
    """
    agg = _feed(TWO_PATH_TWO_UA_LOG)
    summary = agg.finalize()
    pp = summary["probe_paths_by_ip"]

    assert "/.env" in pp, "expected /.env bucket in probe_paths_by_ip"
    assert "/wp-login.php" in pp, "expected /wp-login.php bucket in probe_paths_by_ip"

    env_rows = pp["/.env"]
    wp_rows = pp["/wp-login.php"]
    assert len(env_rows) == 1
    assert len(wp_rows) == 1

    env_ip_row = env_rows[0]
    wp_ip_row = wp_rows[0]
    assert env_ip_row["ip"] == "198.51.100.10"
    assert wp_ip_row["ip"] == "198.51.100.10"

    # AC#1 lock: the two buckets MUST carry different UA lists.
    # Cross-path aggregation would put both UAs in both buckets
    # (or merge them under a per-IP rollup), which would fail this test.
    assert env_ip_row["user_agents"] == ["python-requests/2.28.0"]
    assert wp_ip_row["user_agents"] == ["curl/8.4.0"]

    # Counts are still per (path, ip).
    assert env_ip_row["count"] == 15
    assert wp_ip_row["count"] == 15


def test_aggregator_same_ip_same_path_distinct_uas_tracked():
    """Same IP + same path but two different UAs — both should appear.

    This proves the UA list within a (path, ip) bucket keeps distinct
    UAs (not just the last-seen one). Together with the test above,
    it locks the bidirectional distinction AC#1 + AC#5 require.
    """
    log = "\n".join([
        '198.51.100.20 - - [17/Aug/2026:04:12:34 +0000] "GET /.env HTTP/1.1" 404 - "-" "ua-A"',
        '198.51.100.20 - - [17/Aug/2026:04:12:35 +0000] "GET /.env HTTP/1.1" 404 - "-" "ua-B"',
        '198.51.100.20 - - [17/Aug/2026:04:12:36 +0000] "GET /.env HTTP/1.1" 404 - "-" "ua-A"',
    ])
    agg = _feed(log)
    pp = agg.finalize()["probe_paths_by_ip"]
    rows = pp["/.env"]
    assert len(rows) == 1
    assert rows[0]["ip"] == "198.51.100.20"
    # Encounter-order; ua-A came first.
    assert rows[0]["user_agents"] == ["ua-A", "ua-B"]
    assert rows[0]["count"] == 3


# ---------------------------------------------------------------------------
# AC#4 + AC#5: forensic JSON keeps the full per-(path, ip, UA) breakdown.
# ---------------------------------------------------------------------------


def test_forensic_json_distinguishes_same_ip_different_paths(make_fs):
    """AC#5: forensic JSON distinguishes two records, same IP, different
    paths and UAs.

    The audit is the regression lock for AC#5 — feeding the canonical
    `TWO_PATH_TWO_UA_LOG` (single IP, two paths, two UAs) and asserting
    the resulting `alma-audit-forensic.json` carries the per-bucket UA
    distinction is the canonical AC#5 test. If a future change
    re-aggregates the UAs at the analyzer or forensic layer, this test
    must turn red.
    """
    fs = make_fs({"/var/log/apache2/access_log": TWO_PATH_TWO_UA_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    # 6 probe hits — must trip the WARN threshold (default 5).
    assert any(f.severity in (Severity.WARN, Severity.CRITICAL) for f in findings), (
        "expected at least one WARN/CRIT finding on 6 probe hits"
    )

    # Build the forensic export exactly as reporting.write_forensic_report
    # would: feed the un-trimmed findings into build_forensic_export.
    forensic = build_forensic_export(
        findings, hostname="test-host", timestamp="2026-08-24T00:00:00",
    )
    pp = forensic["probe_paths_by_ip"]
    assert "/.env" in pp
    assert "/wp-login.php" in pp

    env_row = pp["/.env"][0]
    wp_row = pp["/wp-login.php"][0]
    # AC#4 + AC#5: the forensic JSON keeps the full per-(path, ip, UA)
    # distinction. The two buckets carry their own UA list — they are
    # NOT merged at the IP level.
    assert env_row["ip"] == "198.51.100.10"
    assert wp_row["ip"] == "198.51.100.10"
    assert env_row["user_agents"] == ["python-requests/2.28.0"]
    assert wp_row["user_agents"] == ["curl/8.4.0"]
    # Count + first/last_seen are also per (path, ip).
    assert env_row["count"] == 15
    assert wp_row["count"] == 15
    assert env_row["first_seen"] == "17/Aug/2026:04:12:34 +0000"
    assert env_row["last_seen"] == "17/Aug/2026:04:12:48 +0000"
    assert wp_row["first_seen"] == "17/Aug/2026:04:13:00 +0000"
    assert wp_row["last_seen"] == "17/Aug/2026:04:13:14 +0000"


# ---------------------------------------------------------------------------
# AC#3: Markdown summary surfaces the top path × top IP × UA combination.
# ---------------------------------------------------------------------------


def test_markdown_summary_surfaces_path_ip_ua_combo(tmp_path, make_fs):
    """AC#3: the Markdown report includes the path × IP × UA combo.

    The MD is trimmed of long forensic lists (AISO-200 contract) but
    the per-(path, ip, UA) insight must remain visible — the operator
    needs to see at a glance that "1.2.3.4 used python-requests/2.28.0
    on /wp-login.php" without opening the JSON. We assert the MD
    contains the path, the IP, the UA, and the count for at least
    one top combination.
    """
    fs = make_fs({"/var/log/apache2/access_log": TWO_PATH_TWO_UA_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    probe = [f for f in findings if "probe" in f.title.lower()]
    assert probe, "expected a probe-path finding"
    probe_finding = probe[0]

    from alma_audit.models import AuditReport
    from alma_audit.reporting import build_report
    report = build_report([probe_finding], hostname="test-host")

    out_dir = tmp_path / "alma-audit-out"
    md_path = write_markdown_report(report, str(out_dir))
    md_text = open(md_path, encoding="utf-8").read()

    # AC#3: the MD summary surfaces the path × IP × UA combination.
    # We accept any rendering that makes the three pieces discoverable
    # in close proximity (e.g. a "Top path × IP × UA" section, or the
    # UA list inline within a per-path row).
    assert "/wp-login.php" in md_text or "/.env" in md_text, (
        "MD must mention at least one probe path"
    )
    assert "198.51.100.10" in md_text, "MD must mention the source IP"
    # UA string(s) must be visible — at least one of the two UAs.
    assert ("python-requests/2.28.0" in md_text) or ("curl/8.4.0" in md_text), (
        "MD must surface the per-(path, ip) user-agent for at least one bucket"
    )
    # Count context: at least one of the bucket counts (15) is shown
    # alongside the IP / UA so the operator can judge severity.
    # The per-path bucket count is the minimum granularity — at least
    # one `× 15` style marker must appear next to the IP / UA.
    assert "× 15" in md_text, (
        "MD must show the per-(path, ip) hit count alongside the UA so "
        "the operator can judge severity without opening the JSON"
    )