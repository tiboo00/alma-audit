"""Regression tests for AISO-211 — self-IP filtering in access_log.

The audit host's own daemon (cpsrvd / monitoring / cPanel service)
generates a substantial fraction of access_log + error_log traffic.
The AISO-201 pattern (secure_log / brute-force counters already filter
self-IPs from the SSH rule) is extended here:

  - ``AccessAggregator.add()`` accepts ``self_ips: set[str]``.
  - Self-IP records are STILL counted in the overall counters
    (``total_lines``, ``bytes_total``, ``status_buckets``,
    ``method_buckets``) so the operator's-eye rollup is honest.
  - Self-IP records are NOT counted in ``top_attackers``,
    ``host_errors_top`` or the ``top_hosts`` aggregator slice.
  - The forensic JSON keeps ``self_ip_event_count`` /
    ``self_ip_examples`` so the operator can audit self-noise.
  - ``rule_error_rate`` emits BOTH ``error_rate_total`` (preserved
    for backwards compatibility) AND ``error_rate_external``
    (the localhost-excluded ratio). Severity is decided by
    ``error_rate_external`` only.

These tests are the regression lock — flipping the aggregator to
count self-IPs in ``top_attackers`` again, or emitting only
``error_rate`` from the rule, must turn at least one of these red.
"""

from __future__ import annotations

from alma_audit.analyzers.access_log import (
    AccessAggregator,
    analyze_access_logs,
    parse_line,
)
from alma_audit.models import Severity
from alma_audit.analyzers.crawler_verify import Resolver


class FakeResolver:
    """Resolver stub that always returns ``(None, [])`` — i.e. no
    crawler verification path applies. Mirrors the test helper in
    ``test_crawler_integration.py``; defined here to avoid a test-import
    dependency.
    """

    def ptr(self, ip: str) -> str | None:  # type: ignore[no-untyped-def]
        return None

    def forward(self, hostname: str) -> list[str]:  # type: ignore[no-untyped-def]
        return []


def _resolver() -> Resolver:
    return FakeResolver()  # type: ignore[return-value]


def _build_records(rows: list[tuple[str, int, str]]) -> list:
    """Build AccessRecord list from (host, status, path) tuples.

    The status is a 4xx/5xx class so we can drive the error-rate rule.
    A path doesn't matter for self-IP filtering; the tests below focus
    on per-IP rollups.
    """
    out = []
    for i, (host, status, path) in enumerate(rows):
        line = (
            f'{host} - - [17/Aug/2026:04:12:{i % 60:02d} +0000] '
            f'"GET {path} HTTP/1.1" {status} 100 "-" "ua"'
        )
        rec = parse_line(line)
        assert rec is not None
        out.append(rec)
    return out


# ---------------------------------------------------------------------------
# AccessAggregator surface
# ---------------------------------------------------------------------------


def test_aggregator_strips_self_ip_from_top_attackers():
    """AISO-211: 10 self-IP + 5 external. Only the 5 external show up.

    The top_attackers iterator MUST NOT contain any self-IP entry —
    even though the host is part of `hosts` and is counted in
    `total_lines` + `bytes_total`. The forensic JSON keeps the
    self-IP event count + a sample so the operator can audit it.
    """
    rows = (
        [(f"10.0.0.{i % 5 + 1}", 404, "/.env") for i in range(10)]  # 10 self-IP hits
        + [("198.51.100.7", 404, "/.env") for _ in range(5)]        # 5 external hits
    )
    agg = AccessAggregator(self_ips={"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"})
    for rec in _build_records(rows):
        agg.add(rec)
    summary = agg.finalize()

    # The 5 external IPs all appear in top_attackers (probe_total_by_ip).
    attacker_ips = {row["ip"] for row in summary["top_attackers"]}
    assert attacker_ips == {"198.51.100.7"}
    assert summary["top_attackers"][0]["total_probe_requests"] == 5
    # No self-IP entry should appear in the iterator.
    assert not any(ip.startswith("10.0.0.") for ip in attacker_ips)

    # Self-IP events still counted for forensic dump.
    assert summary["self_ip_event_count"] == 10
    assert len(summary["self_ip_examples"]) <= 5
    assert summary["self_ip_examples"]

    # Overall counters stay accurate (self-IP still in `hosts`).
    assert summary["total_lines"] == 15
    assert summary["bytes_total"] == 15 * 100


def test_aggregator_strips_self_ip_from_host_errors_top():
    """AISO-211: self-IP errors excluded from `host_errors_top`.

    The burst host rollup is the one the operator uses to identify
    which client IPs are generating the most 4xx/5xx responses. A
    localhost self-burst would otherwise dominate the top-N view.
    """
    rows = (
        # 8 localhost 404s (self-noise from cpsrvd admin panel probing).
        [("127.0.0.1", 404, "/__notfound__") for _ in range(8)]
        # 4 external 500s (real attacker / misconfigured upstream).
        + [("198.51.100.7", 500, "/wp-login.php") for _ in range(4)]
    )
    agg = AccessAggregator(self_ips={"127.0.0.1"})
    for rec in _build_records(rows):
        agg.add(rec)
    summary = agg.finalize()

    err_ips = {row["ip"] for row in summary["host_errors_top"]}
    assert err_ips == {"198.51.100.7"}
    assert summary["host_errors_top"][0]["error_count"] == 4

    # The error_rate_total field still reflects the unfiltered ratio
    # (so the operator can see localhost IS contributing errors), but
    # `host_errors_top` only surfaces the external source.
    # Note: ratio fields are emitted from the rule, not finalize().
    # We just sanity-check the underlying per-host error count.


def test_aggregator_empty_self_ips_back_compat():
    """AISO-211: default empty set keeps the original behaviour.

    No self-IPs configured → every IP is treated as external. The
    `self_ip_event_count` stays at 0.
    """
    rows = [(f"10.0.0.{i}", 200, "/.env") for i in range(3)]
    agg = AccessAggregator()
    for rec in _build_records(rows):
        agg.add(rec)
    summary = agg.finalize()
    assert summary["self_ip_event_count"] == 0
    assert summary["self_ip_examples"] == []
    # All 3 IPs show up in top_attackers.
    attacker_ips = {row["ip"] for row in summary["top_attackers"]}
    assert attacker_ips == {"10.0.0.0", "10.0.0.1", "10.0.0.2"}


def test_aggregator_self_ip_only_no_external():
    """AISO-211: all-self-IP sample → empty top_attackers / host_errors_top.

    When every record comes from the host's own IPs, the operator-eye
    rollups should be empty (the self-IP events are recorded in the
    forensic JSON, not surfaced as a top-N).
    """
    rows = [("10.0.0.1", 404, "/.env") for _ in range(20)]
    agg = AccessAggregator(self_ips={"10.0.0.1"})
    for rec in _build_records(rows):
        agg.add(rec)
    summary = agg.finalize()
    assert summary["top_attackers"] == []
    assert summary["host_errors_top"] == []
    # All 20 lines still tallied as scanned + bytes.
    assert summary["total_lines"] == 20
    # Forensic dump records them.
    assert summary["self_ip_event_count"] == 20


# ---------------------------------------------------------------------------
# rule_error_rate surface (the public rule call)
# ---------------------------------------------------------------------------


def _run_error_rate_rule(rows, self_ips=None):
    """Run rule_error_rate on a synthetic aggregator.

    Mirrors the orchestrator's call shape — pass the aggregator, the
    total_hits count, the burst host (None to disable the crawler
    suppression branch), the FakeResolver, settings, and the
    aggregator's finalize() summary.
    """
    from alma_audit.analyzers.access_log.rules import rule_error_rate
    agg = AccessAggregator(self_ips=self_ips or set())
    for rec in _build_records(rows):
        agg.add(rec)
    summary = agg.finalize()
    findings = rule_error_rate(
        agg=agg,
        total_hits=summary["total_lines"],
        burst_host=None,
        resolver=_resolver(),
        settings={
            "error_rate_warn": 0.05,
            "error_rate_crit": 0.20,
        },
        summary=summary,
    )
    return findings, summary


def test_error_rate_rule_external_50pct_still_critical():
    """AISO-211: external rate 50% → CRITICAL.

    80 internal errors + 10 external errors + 10 external successes.
    Unfiltered rate is 0.90 (>= crit) but more importantly the
    external rate is 10/20 = 0.50 (>= crit too). The rule fires
    CRITICAL on the external rate.
    """
    rows = (
        # 80 localhost errors → 80% of the 100-row sample.
        [("127.0.0.1", 404, "/") for _ in range(80)]
        # 10 external errors + 10 external successes → external rate = 0.50.
        + [("198.51.100.7", 404, "/") for _ in range(10)]
        + [("198.51.100.7", 200, "/") for _ in range(10)]
    )
    findings, summary = _run_error_rate_rule(
        rows,
        self_ips={"127.0.0.1"},
    )
    assert len(findings) == 1
    details = findings[0].details
    # 90 errors / 100 total = 0.90.
    assert abs(details["error_rate_total"] - 0.90) < 1e-6
    # External rate = external errors / external total = 10 / 20 = 0.50.
    assert abs(details["error_rate_external"] - 0.50) < 1e-6
    # External rate 0.50 >= 0.20 crit → CRITICAL.
    assert findings[0].severity == Severity.CRITICAL


def test_error_rate_rule_external_drives_severity():
    """AISO-211: localhost-spammed sample with low external rate.

    80 internal errors + 10 external errors + 90 external successes.
    Unfiltered error rate is 90/180 = 0.50 (>= warn, < crit on the
    old contract would have fired WARN — but with 50% unfiltered
    we'd want CRIT on the localhost-spam sample).
    """
    rows = (
        # 80 localhost errors → 80% of the 100-row sample.
        [("127.0.0.1", 404, "/") for _ in range(80)]
        # 10 external errors + 90 external successes → external rate
        # 10 / 100 = 0.10 (< warn threshold).
        + [("198.51.100.7", 404, "/") for _ in range(10)]
        + [("198.51.100.7", 200, "/") for _ in range(90)]
    )
    findings, summary = _run_error_rate_rule(
        rows,
        self_ips={"127.0.0.1"},
    )
    assert len(findings) == 1
    details = findings[0].details
    # 90 errors / 180 total = 0.50.
    assert abs(details["error_rate_total"] - 0.50) < 1e-6
    assert abs(details["error_rate_external"] - 0.10) < 1e-6
    # External rate 0.10 >= 0.05 warn → WARN, not CRITICAL.
    assert findings[0].severity == Severity.WARN


def test_error_rate_rule_no_self_ip_external_is_none():
    """AISO-211: sample with no self-IP traffic → error_rate_external None.

    When there's no localhost traffic to filter, the external rate IS
    the total rate. We emit `None` (not the same number twice) so
    downstream consumers can detect "no localhost to strip" without
    floating-point comparison.
    """
    rows = [(f"198.51.100.{i}", 404, "/") for i in range(5)] + \
           [(f"198.51.100.{i}", 200, "/") for i in range(95)]
    findings, _ = _run_error_rate_rule(rows)  # no self_ips
    assert len(findings) == 1
    details = findings[0].details
    assert details["error_rate_external"] is None
    assert abs(details["error_rate_total"] - 0.05) < 1e-6
    # 5% >= warn → WARN.
    assert findings[0].severity == Severity.WARN


def test_error_rate_rule_details_split_internal_external_top():
    """AISO-211: detail carries split lists for forensic consumers.

    host_errors_external_top and host_errors_internal_top are the
    operator-eye view with localhost explicitly partitioned, so the
    report can highlight the split instead of pretending one bucket
    is the "right" answer.
    """
    rows = (
        [("127.0.0.1", 404, "/") for _ in range(30)]
        + [("198.51.100.7", 500, "/") for _ in range(10)]
    )
    findings, _ = _run_error_rate_rule(rows, self_ips={"127.0.0.1"})
    assert len(findings) == 1
    details = findings[0].details
    assert "host_errors_external_top" in details
    assert "host_errors_internal_top" in details
    assert {row["ip"] for row in details["host_errors_external_top"]} == {"198.51.100.7"}
    assert {row["ip"] for row in details["host_errors_internal_top"]} == {"127.0.0.1"}


# ---------------------------------------------------------------------------
# End-to-end: analyze_access_logs honors the new flag
# ---------------------------------------------------------------------------


def test_analyzer_with_self_ips_excludes_localhost_from_d1(make_fs):
    """AISO-211: analyze_access_logs() with self_ips skips localhost in D1.

    Self-IP hits on probe paths are still recorded in the diagnostic
    dump (`self_ip_event_count`/`self_ip_examples`) but they do NOT
    surface as a D2 probe-path finding or in the `top_attackers`
    rollup. The 5 external wp-login.php hits are below the probe
    threshold (default 10), so this test asserts the localhost
    isolation contract via the diagnostic counters alone.
    """
    log = (
        "127.0.0.1 - - [17/Aug/2026:04:12:00 +0000] "
        '"GET /.env HTTP/1.1" 404 0 "-" "ua"\n'
    ) * 30 + (
        "198.51.100.7 - - [17/Aug/2026:04:12:30 +0000] "
        '"GET /index.html HTTP/1.1" 200 100 "-" "ua"\n'
    ) * 5
    fs = make_fs({"/var/log/apache2/access_log": log})
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"],
        fs,
        rules={"exclude_self_ips": True},
        self_ips={"127.0.0.1"},  # type: ignore[call-arg]
    )
    # The 30 localhost /.env hits should NOT trigger a probe-path
    # finding (they're self-noise), and they MUST NOT show up in the
    # `top_attackers` rollup.
    probe_findings = [f for f in findings if "probe" in f.title.lower()]
    assert not probe_findings, (
        "self-IP hits on probe paths should not fire D2"
    )
    # The summary finding carries the aggregator's diagnostic counter.
    summary_findings = [
        f for f in findings
        if f.module == "access_log" and "Scanned" in f.title
    ]
    assert summary_findings
    details = summary_findings[0].details
    assert details["self_ip_event_count"] == 30
    # The diagnostic samples are bounded (don't flood the JSON).
    assert len(details["self_ip_examples"]) <= 5
    # The top_hosts rollup strips self-IP.
    assert all(ip != "127.0.0.1" for ip, _ in details["top_hosts"])


# ---------------------------------------------------------------------------
# AISO-211 review regression tests (post-merge correctness bugs)
# ---------------------------------------------------------------------------


def test_rule_top_host_concentration_strips_self_ip():
    """AISO-211 review fix: D1 must not fire on self-IP as the top host.

    Repro from the Supervisor's review: 30× localhost + 5× external.
    Pre-fix, ``rule_top_host_concentration`` read
    ``agg.hosts.most_common(1)`` directly and surfaced ``127.0.0.1
    (85.7%)`` as a CRITICAL even though the operator-eye
    ``top_hosts`` summary correctly stripped the localhost. Post-fix,
    the rule consumes the same self-IP-filtered view the aggregator
    uses in ``finalize()`` — D1 fires on the external IP, not on
    the host's own daemon.
    """
    rows = (
        # 30 localhost 200s — cPanel self-admin-panel noise.
        [("127.0.0.1", 200, "/") for _ in range(30)]
        # 5 external 200s — the only external traffic in the sample.
        + [("198.51.100.7", 200, "/") for _ in range(5)]
    )
    findings, _ = _run_error_rate_rule(
        rows,
        self_ips={"127.0.0.1"},
    )
    # No error-rate finding because the sample has no 4xx/5xx.
    err_findings = [f for f in findings if "error rate" in f.title.lower()]
    assert not err_findings, (
        "no error-rate finding expected for an all-2xx sample"
    )

    # Drive the D1 rule directly to lock the regression.
    from alma_audit.analyzers.access_log.rules import rule_top_host_concentration
    agg = AccessAggregator(self_ips={"127.0.0.1"})
    for rec in _build_records(rows):
        agg.add(rec)
    total_hits = sum(agg.hosts.values())
    d1_findings = rule_top_host_concentration(
        agg=agg,
        total_hits=total_hits,
        resolver=_resolver(),
        settings={
            "top_host_share_warn": 0.20,
            "top_host_share_crit": 0.50,
        },
    )
    # Pre-fix: CRITICAL 127.0.0.1 (85.7%). Post-fix: 198.51.100.7 at
    # 5/35 = 14.3% — below the warn threshold, no finding at all.
    assert d1_findings == [], (
        f"D1 should be silent for a self-IP-dominated sample; "
        f"got {d1_findings!r}"
    )


def test_rule_top_host_concentration_self_ip_only_no_finding():
    """AISO-211 review fix: every record from self-IPs → no D1 finding.

    Even with the warn threshold set low enough to trip on the
    unfiltered rate, the self-IP-filtered view has no top host to
    flag. The rule's ``filtered_hosts`` empty check returns an empty
    list — the forensic JSON keeps the ``self_ip_event_count`` /
    ``self_ip_examples`` diagnostic dump for the operator's audit
    trail.
    """
    from alma_audit.analyzers.access_log.rules import rule_top_host_concentration
    rows = [("127.0.0.1", 200, "/") for _ in range(50)]
    agg = AccessAggregator(self_ips={"127.0.0.1"})
    for rec in _build_records(rows):
        agg.add(rec)
    total_hits = sum(agg.hosts.values())
    d1_findings = rule_top_host_concentration(
        agg=agg,
        total_hits=total_hits,
        resolver=_resolver(),
        settings={
            "top_host_share_warn": 0.10,
            "top_host_share_crit": 0.50,
        },
    )
    assert d1_findings == []
    # The aggregator's diagnostic dump is preserved for forensics.
    summary = agg.finalize()
    assert summary["self_ip_event_count"] == 50


def test_rule_error_rate_external_when_self_ip_only_successful():
    """AISO-211 review fix: external rate is correct even when self-IP traffic is all 2xx.

    Repro from the Supervisor's review: 900× localhost 200 +
    10× external 500 + 90× external 200. The correct external rate
    is 10/100 = 10%. Pre-fix, the rule computed the external total
    from the ``host_errors_internal_top`` list — which only
    contains hosts that have produced errors and is capped at 20.
    Because every self-IP request was a 200, no self-IP row
    appeared in ``host_errors_internal_top``, so the pre-fix code
    emitted ``error_rate_external=None`` for this sample. Post-fix,
    the rule reads ``agg.status_by_host`` (uncapped) and computes
    the right number.
    """
    rows = (
        # 900 localhost successes — cPanel self-admin-panel hits
        # that resolved cleanly. No self-IP errors.
        [("127.0.0.1", 200, "/") for _ in range(900)]
        # 10 external 500s.
        + [("198.51.100.7", 500, "/") for _ in range(10)]
        # 90 external successes.
        + [("198.51.100.7", 200, "/") for _ in range(90)]
    )
    findings, summary = _run_error_rate_rule(
        rows,
        self_ips={"127.0.0.1"},
    )
    assert len(findings) == 1
    details = findings[0].details
    # 10 errors / 1000 total = 1% overall.
    assert abs(details["error_rate_total"] - 0.01) < 1e-6
    # External rate is 10 errors / 100 external requests = 10%.
    assert details["error_rate_external"] is not None
    assert abs(details["error_rate_external"] - 0.10) < 1e-6
    # Self-IP total = 900, self-IP errors = 0 (every request was 200).
    assert details["self_total_requests"] == 900
    assert details["self_error_count"] == 0
    assert details["external_total_requests"] == 100
    assert details["external_error_count"] == 10
    # External rate 10% >= warn → WARN, not CRITICAL.
    assert findings[0].severity == Severity.WARN


def test_rule_error_rate_external_from_uncapped_per_host_aggregate():
    """AISO-211 review fix: the external rate is computed from the uncapped per-host aggregate.

    Pre-fix regression: ``host_errors_internal_top`` is capped at 20
    entries AND only contains hosts with errors. A self-IP with only
    successes has no entry, so the pre-fix code computed
    ``external_total = total_hits - 0 = total_hits`` and silently
    returned ``error_rate_external=None``. The post-fix code reads
    ``agg.status_by_host`` (uncapped per-host status map) and
    produces the right answer.

    This test also locks the new ``self_total_requests`` /
    ``self_error_count`` forensic detail fields, which downstream
    consumers can use to audit the self-IP noise partition.
    """
    rows = (
        # Self-IP traffic split: 50 errors + 950 successes.
        [("127.0.0.1", 404, "/") for _ in range(50)]
        + [("127.0.0.1", 200, "/") for _ in range(950)]
        # External traffic: 30 errors + 70 successes.
        + [("198.51.100.7", 404, "/") for _ in range(30)]
        + [("198.51.100.7", 200, "/") for _ in range(70)]
    )
    findings, _ = _run_error_rate_rule(
        rows,
        self_ips={"127.0.0.1"},
    )
    assert len(findings) == 1
    details = findings[0].details
    # Total: 80 errors / 1100 = 7.27%.
    assert abs(details["error_rate_total"] - 80 / 1100) < 1e-6
    # External: 30 errors / 100 external = 30%.
    assert details["error_rate_external"] is not None
    assert abs(details["error_rate_external"] - 0.30) < 1e-6
    # Self-IP totals: 1000 requests, 50 errors.
    assert details["self_total_requests"] == 1000
    assert details["self_error_count"] == 50
    # External totals: 100 requests, 30 errors.
    assert details["external_total_requests"] == 100
    assert details["external_error_count"] == 30
    # 30% >= 20% crit → CRITICAL on the external rate.
    assert findings[0].severity == Severity.CRITICAL


def test_analyzer_burst_host_excludes_self_ip(make_fs):
    """AISO-211 review fix: ``analyze_access_logs`` passes a self-IP-filtered burst_host.

    The crawler-suppression branch in ``rule_error_rate`` is only
    meaningful for external traffic. Pre-fix, the analyzer used
    ``agg.hosts.most_common(1)`` directly and surfaced the
    localhost as the burst host. Post-fix, the call site filters
    self-IPs before assigning ``top_host``.

    Verifies the contract via the summary finding's details —
    ``burst_host`` (surfaced in ``rule_error_rate`` details) should
    NOT be a self-IP.
    """
    log = (
        # 30× localhost 200s + 5× external 500s.
        "127.0.0.1 - - [17/Aug/2026:04:12:00 +0000] "
        '"GET /index.html HTTP/1.1" 200 100 "-" "ua"\n'
    ) * 30 + (
        "198.51.100.7 - - [17/Aug/2026:04:12:30 +0000] "
        '"GET /wp-login.php HTTP/1.1" 500 0 "-" "ua"\n'
    ) * 5
    fs = make_fs({"/var/log/apache2/access_log": log})
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"],
        fs,
        rules={"exclude_self_ips": True},
        self_ips={"127.0.0.1"},  # type: ignore[call-arg]
    )
    err_findings = [
        f for f in findings
        if f.module == "access_log" and "error rate" in f.title.lower()
    ]
    assert err_findings, "expected an error-rate finding"
    burst_host = err_findings[0].details.get("burst_host")
    assert burst_host != "127.0.0.1", (
        f"burst_host must not be a self-IP; got {burst_host!r}"
    )