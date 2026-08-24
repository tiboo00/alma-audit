"""Detection rules for the access_log analyzer.

Five rules, each emitting zero or more `Finding` records:

  D1 — top-host concentration (crawler-suppressible)
  D4 — 4xx + 5xx burst rate (crawler-suppressible on the burst host)
  D2 — known probe paths (NEVER crawler-suppressible)
  D5 — unusual HTTP methods (NEVER crawler-suppressible)
  D6 — top bandwidth hog (AISO-204; single IP -> unusual share of bytes)

The crawler-suppressibility distinction is the §6.1 contract:
D2/D5 are never suppressed because a Googlebot asking for `/.env` is
still an event — it is downgraded but not erased.

AISO-197: every security-relevant rule attaches a `top_attackers`
and (where applicable) a per-path / per-IP / per-host breakdown so the
operator can identify the source of the activity, not just the
aggregate count. The full forensic view is in the JSON `details`;
the Markdown rendering slices it for readability.

AISO-204: a single IP carrying an unusual share of the access_log's
byte volume is a stronger exfiltration signal than a 4xx count alone
(404-spam can disguise outbound dataflow). The rule skips samples
smaller than `bandwidth_hog_min_lines`, where one host is mechanically
dominant and the signal is meaningless.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ...fix_suggestions import attach_fixes, lookup_fixes
from ...models import Finding, Severity
from ...self_ip import is_self_ip
from ..crawler_verify import CrawlerSuppression, Resolver
from .aggregator import AccessAggregator, SAFE_METHODS
from .suppression import resolve_suppression


def _is_self_ip(ip: str, self_ips: set[str]) -> bool:
    """Self-IP check wrapper — rules.py uses the same predicate the
    aggregator applies so D1/D4 stay aligned with the operator-eye
    ``top_hosts`` summary.
    """
    return is_self_ip(ip, self_ips)


def rule_top_host_concentration(
    agg: AccessAggregator,
    total_hits: int,
    resolver: Resolver,
    settings: dict[str, Any],
) -> list[Finding]:
    """D1 — single source dominates traffic.

    Suppressed (downgraded to INFO) only if the top-host's UA verifies
    as a legitimate crawler via the §6.1 chain.
    """
    if total_hits <= 0:
        return []
    # AISO-211 review fix: the previous implementation read
    # ``agg.hosts.most_common(1)[0]`` directly — i.e. the unfiltered
    # per-IP counter that includes self-IP traffic. On a cPanel host
    # with 30× localhost + 5× external that surfaces ``127.0.0.1
    # (85.7%)`` as a D1 CRITICAL even though the operator-eye
    # ``top_hosts`` summary correctly strips the localhost. The
    # aggregator's ``self_ips`` set is the source of truth for the
    # filter — apply it here too, mirroring the defense-in-depth
    # pattern already used in ``AccessAggregator.finalize()``.
    filtered_hosts = [
        (ip, count)
        for ip, count in agg.hosts.most_common()
        if not _is_self_ip(ip, agg.self_ips)
    ]
    if not filtered_hosts:
        # Every request came from a self-IP. There is no external
        # top-host to flag — the forensic JSON keeps the
        # self-IP diagnostic dump so the operator can still audit
        # the noise, but D1 does not fire on self-traffic alone.
        return []
    top_host, top_hits = filtered_hosts[0]
    share = top_hits / total_hits
    ua_for_top = agg.last_ua_by_host.get(top_host, "")
    suppression = resolve_suppression(resolver, top_host, ua_for_top)
    d1_details: dict[str, Any] = {"host": top_host, "hits": top_hits, "share": share}
    d1_details["crawler_suppression"] = suppression.to_dict()

    if suppression.applied:
        return [Finding(
            module="access_log",
            severity=Severity.INFO,
            title=f"Top-host concentration suppressed: {top_host} ({share:.0%}) — verified crawler",
            description=(
                f"Host {top_host!r} would normally fire a top-host "
                f"D1 finding, but the UA verified as a legitimate "
                f"crawler via PTR + forward-confirmation + suffix match."
            ),
            details=d1_details,
            recommendation="No action required — claim was bidirectionally verified.",
        )]

    if share >= settings["top_host_share_crit"]:
        return [Finding(
            module="access_log",
            severity=Severity.CRITICAL,
            title=f"Single source dominates traffic: {top_host} ({share:.0%})",
            description=(
                f"Host {top_host!r} accounts for {top_hits}/{total_hits} "
                f"requests ({share:.1%}). This is consistent with a "
                f"scanner / single-client abuse pattern."
            ),
            details=d1_details,
            recommendation="Investigate the IP; consider fail2ban / rate-limit.",
        )]
    if share >= settings["top_host_share_warn"]:
        return [Finding(
            module="access_log",
            severity=Severity.WARN,
            title=f"Traffic concentrated on one host: {top_host} ({share:.0%})",
            description=f"Host {top_host!r} is {share:.1%} of traffic; review whether expected.",
            details=d1_details,
        )]
    return []


def rule_error_rate(
    agg: AccessAggregator,
    total_hits: int,
    burst_host: str | None,
    resolver: Resolver,
    settings: dict[str, Any],
    summary: dict[str, Any],
) -> list[Finding]:
    """D4 — 4xx + 5xx burst rate.

    AISO-211: emits TWO error-rate fields so the operator sees both
    the unfiltered ratio (preserved for backwards compat) AND the
    localhost-excluded ratio. The severity decision is driven by
    the external rate only — a cPanel server's self-admin-panel
    noise would otherwise trip CRITICAL on every audit run.

    Without per-host status counts we fall back to top_host. The
    suppression decision is still gated so the contract's "crawler
    claim must come from the burst host" is honored.
    """
    if total_hits <= 0:
        return []
    err_count = sum(
        c for code, c in agg.status_buckets.items() if 400 <= code < 600
    )
    err_rate = err_count / total_hits
    # AISO-211 review fix: the previous implementation computed the
    # external error rate from the ``host_errors_internal_top`` list
    # in the summary — but that list is capped at 20 entries AND only
    # contains hosts that have produced errors. When every self-IP
    # request was a 200 (e.g. cPanel self-admin-panel hits that
    # resolved cleanly), no self-IP row appeared in
    # ``host_errors_internal_top``, so ``internal_rows`` was empty
    # and ``external_total`` collapsed back to ``total_hits``,
    # giving ``error_rate_external=None`` for a sample where the
    # external traffic was 10% errors but every self-IP request was
    # a success. The fix: compute the per-IP rollup from
    # ``agg.status_by_host`` directly — the uncapped per-host status
    # map that the aggregator maintains. That gives us the real
    # self-IP request total regardless of whether any self-IP
    # request was an error.
    self_total = 0
    self_errors = 0
    for ip, status_counter in agg.status_by_host.items():
        if not _is_self_ip(ip, agg.self_ips):
            continue
        ip_total = sum(status_counter.values())
        ip_errors = sum(c for code, c in status_counter.items() if 400 <= code < 600)
        self_total += ip_total
        self_errors += ip_errors
    external_total = total_hits - self_total
    external_err = err_count - self_errors
    if external_total > 0 and self_total > 0:
        error_rate_external: float | None = external_err / external_total
    else:
        # No self-IP traffic at all (external_total == total_hits),
        # or every request was self-IP (external_total == 0).
        # Emit ``None`` for the external field so downstream consumers
        # can distinguish "the filter had nothing to do" from "filter
        # applied, ratio == total".
        error_rate_external = None
    burst_ua = agg.last_ua_by_host.get(burst_host, "") if burst_host else ""
    d4_suppression = resolve_suppression(resolver, burst_host or "", burst_ua)
    d4_details: dict[str, Any] = {
        # AISO-211: both fields emitted. ``error_rate`` (the old
        # name) is preserved for backwards compat with consumers
        # that were already reading it; new code should read
        # ``error_rate_total`` / ``error_rate_external``.
        "error_rate": err_rate,
        "error_rate_total": err_rate,
        "error_rate_external": error_rate_external,
        "error_count": err_count,
        "external_error_count": external_err,
        "external_total_requests": external_total,
        "self_total_requests": self_total,
        "self_error_count": self_errors,
        "total": total_hits,
        "status_buckets": summary["status_buckets"],
        "burst_host": burst_host,
        "crawler_suppression": d4_suppression.to_dict(),
        # AISO-197: per-host error breakdown — top 20 hosts by error count.
        # AISO-211: `host_errors_top` is preserved as the operator-eye
        # rollup (external-only). The `host_errors_external_top` +
        # `host_errors_internal_top` keys are the explicit split for
        # forensic consumers that want to see the localhost traffic
        # partition alongside the external one.
        "host_errors_top": summary.get("host_errors_top", []),
        "host_errors_external_top": summary.get("host_errors_top", []),
        "host_errors_internal_top": summary.get("host_errors_internal_top", []),
        "host_errors_total": summary.get("host_errors_total", 0),
    }
    # AISO-211: the severity decision is driven by the external rate
    # only — that's the operator's "what's the external burst?"
    # question. The total rate stays in the details for transparency.
    decision_rate = (
        error_rate_external if error_rate_external is not None else err_rate
    )
    if decision_rate >= settings["error_rate_crit"]:
        sev: Severity | None = Severity.CRITICAL
    elif decision_rate >= settings["error_rate_warn"]:
        sev = Severity.WARN
    else:
        sev = None
    if sev is None:
        return []
    if d4_suppression.applied:
        # Downgrade to INFO since the verified claim explains the burst.
        return [Finding(
            module="access_log",
            severity=Severity.INFO,
            title=f"Error burst suppressed on {burst_host} — verified crawler",
            description=(
                f"4xx/5xx burst on host {burst_host!r} was attributed "
                "to a verified-crawler UA, so the D4 finding is "
                "downgraded to informational."
            ),
            details=d4_details,
            recommendation="No action required — claim was bidirectionally verified.",
        )]
    return [Finding(
        module="access_log",
        severity=sev,
        # AISO-211: the title shows the EXTERNAL rate (the rate that
        # actually drove the severity decision). When the external
        # rate is None (no self-IP traffic), fall back to the total
        # rate for the operator's headline number.
        title=(
            f"Error rate {decision_rate:.1%} "
            f"({external_err}/{external_total} external)"
            if error_rate_external is not None
            else f"Error rate {err_rate:.1%} ({err_count}/{total_hits})"
        ),
        description=(
            "More than expected 4xx/5xx responses on external "
            "traffic. Either an external source is probing, or an "
            "upstream service is failing. The unfiltered rate is "
            f"{err_rate:.1%} — cPanel self-admin-panel noise "
            "explains the gap when localhost traffic is heavy."
        ),
        details=d4_details,
        recommendation="Correlate with error_log to identify the cause.",
    )]


def rule_probe_paths(
    agg: AccessAggregator,
    settings: dict[str, Any],
) -> list[Finding]:
    """D2 — known probe paths. NEVER crawler-suppressible (§6.1 contract)."""
    probe_total = sum(agg.probe_hits.values())
    if probe_total >= settings["probe_count_crit"]:
        sev = Severity.CRITICAL
    elif probe_total >= settings["probe_count_warn"]:
        sev = Severity.WARN
    else:
        sev = None
    if sev is None:
        return []
    base = Finding(
        module="access_log",
        severity=sev,
        title=f"{probe_total} request(s) to known probe paths",
        description=(
            "Endpoints like /.env, /wp-login.php, /administrator/, "
            "/phpmyadmin, /xmlrpc.php were accessed. These are common "
            "scanner / brute-force targets."
        ),
        details={
            "probe_hits": dict(agg.probe_hits),
            # AISO-197: forensic detail — every (path, ip) pair with
            # count / first_seen / last_seen / user_agents. No cap on
            # list size per the operator's "show me everything" rule.
            "probe_paths_by_ip": agg.probe_by_path_ip
            and _serialise_probe_paths_by_ip(agg.probe_by_path_ip)
            or {},
            # AISO-197: top attacker rollup across all probe paths.
            "top_attackers": _serialise_top_attackers(agg),
            # AISO-208: top path × IP × user-agent combinations.
            # Same IP hitting /.env with python-requests vs /wp-login.php
            # with curl are different threat vectors — a per-IP rollup
            # loses that distinction. The full per-(path, ip) UA map
            # stays in `probe_paths_by_ip` for forensic consumers; this
            # field is the operator-eye flat list, ranked by count desc,
            # capped at the same `_TOP_PATH_IP_UA_LIMIT` budget so the
            # MD summary stays bounded.
            "top_path_ip_ua": _serialise_top_path_ip_ua(agg),
            # D2/D5: these are NEVER suppressed by crawler verification,
            # so the field is the `n/a` sentinel.
            "crawler_suppression": CrawlerSuppression.not_applicable().to_dict(),
        },
        recommendation=(
            "Inspect source IPs and ensure those endpoints are blocked at the WAF. "
            "Top offenders are listed in `top_attackers`; full per-path detail in "
            "`probe_paths_by_ip`."
        ),
    )
    # AISO-210: structured fix library — .htaccess / Cloudflare WAF /
    # fail2ban. The render layer groups by scope; the operator walks
    # the cheapest fix first.
    return [attach_fixes(base, lookup_fixes("D2:probe_hits"))]


# AISO-208: cap on the path × IP × UA combination list. The forensic
# JSON keeps the full per-(path, ip) breakdown; this cap is just the
# top-N slice surfaced inline in the Markdown summary. 50 entries
# comfortably covers any realistic single-IP scanner pattern while
# keeping the MD report scannable.
_TOP_PATH_IP_UA_LIMIT = 50


def _serialise_top_path_ip_ua(agg: AccessAggregator) -> list[dict[str, Any]]:
    """Flatten every (path, ip) bucket into per-UA rows, ranked by count.

    AISO-208 review fix: the previous implementation divided the bucket
    total evenly across the UAs in ``stat.user_agents`` and assigned
    the remainder to the last UA — a *fabricated* breakdown that
    produced e.g. ``5/5`` for a real ``9× ua-A + 1× ua-B`` input.
    The operator relied on those numbers and the report was provably
    wrong.

    The aggregator now tracks exact per-UA counts in
    ``_PerIPProbeStat.ua_counts`` (an unbounded ``Counter[str]``).
    We read those counts directly here — no arithmetic, no
    approximation. The full per-(path, ip, UA) breakdown is preserved
    in ``probe_paths_by_ip`` for the forensic JSON consumers; this
    list is the trimmed operator-eye view rendered in the MD summary.
    """
    rows: list[dict[str, Any]] = []
    for path, ip_map in agg.probe_by_path_ip.items():
        for ip, stat in ip_map.items():
            # Emit one row per distinct UA with its REAL count.
            # ``ua_counts`` is a Counter[str]; iteration order matches
            # insertion order on Python 3.7+, so the operator sees the
            # first-seen UA first within each bucket.
            for ua, ua_count in stat.ua_counts.items():
                rows.append({
                    "path": path,
                    "ip": ip,
                    "user_agent": ua,
                    "count": ua_count,
                })
    rows.sort(key=lambda r: r["count"], reverse=True)
    return rows[:_TOP_PATH_IP_UA_LIMIT]


def _serialise_probe_paths_by_ip(
    probe_by_path_ip: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Convert the aggregator's internal `_PerIPProbeStat` map to JSON-safe rows.

    AISO-208 review fix: each row now carries ``user_agent_counts``
    (the exact per-UA hit counts from the aggregator's ``Counter[str]``)
    alongside the existing ``user_agents`` list. Consumers that only
    care about which UAs were seen keep reading ``user_agents``;
    consumers that need the precise breakdown read
    ``user_agent_counts``.
    """
    out: dict[str, list[dict[str, Any]]] = {}
    for path, ip_map in probe_by_path_ip.items():
        rows = [
            {
                "ip": ip,
                "count": stat.count,
                "first_seen": stat.first_seen,
                "last_seen": stat.last_seen,
                "user_agents": list(stat.user_agents),
                "user_agent_counts": dict(stat.ua_counts),
            }
            for ip, stat in ip_map.items()
        ]
        rows.sort(key=lambda r: r["count"], reverse=True)
        out[path] = rows
    return out


def _serialise_top_attackers(agg: AccessAggregator) -> list[dict[str, Any]]:
    """Per-IP rollup across all probe paths. Sorted by probe count desc."""
    rows: list[dict[str, Any]] = []
    for ip, probe_count in agg.probe_total_by_ip.items():
        paths: dict[str, int] = {}
        for path, ip_map in agg.probe_by_path_ip.items():
            if ip in ip_map:
                paths[path] = ip_map[ip].count
        rows.append({
            "ip": ip,
            "total_probe_requests": probe_count,
            "total_requests": agg.hosts.get(ip, 0),
            "probe_paths": dict(sorted(paths.items(), key=lambda kv: kv[1], reverse=True)),
            "first_seen": agg.ip_first_seen.get(ip, ""),
            "last_seen": agg.ip_last_seen.get(ip, ""),
            "user_agents": list(agg.ip_user_agents.get(ip, [])),
        })
    rows.sort(key=lambda r: r["total_probe_requests"], reverse=True)
    return rows


def rule_weird_methods(
    agg: AccessAggregator,
    settings: dict[str, Any],
) -> list[Finding]:
    """D5 — unusual HTTP methods. NEVER crawler-suppressible (§6.1 contract)."""
    weird_methods: dict[str, int] = defaultdict(int)  # type: ignore[assignment]
    for method, count in agg.methods.items():
        if method not in SAFE_METHODS:
            weird_methods[method] += count
    if sum(weird_methods.values()) < settings["weird_method_count_warn"]:
        return []
    base = Finding(
        module="access_log",
        severity=Severity.WARN,
        title="Unusual HTTP methods observed",
        description=(
            "Methods outside the safe set (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS) "
            "appeared. PROPFIND / TRACE / CONNECT are common WebDAV / recon tools."
        ),
        details={
            "weird_methods": dict(weird_methods),
            "crawler_suppression": CrawlerSuppression.not_applicable().to_dict(),
        },
        recommendation="Inspect source IPs; consider blocking WebDAV methods if not used.",
    )
    # AISO-210: four-scope fix set — Apache TraceEnable, .htaccess
    # LimitExcept, Cloudflare WAF method block, ModSecurity rule.
    # Each scope carries its own risk rating so the operator can pick
    # the cheapest first.
    return [attach_fixes(base, lookup_fixes("D5:weird_methods"))]


def rule_bandwidth_hog(
    agg: AccessAggregator,
    settings: dict[str, Any],
) -> list[Finding]:
    """D6 — AISO-204 top bandwidth hog.

    A single source IP responsible for an unusual share of the total
    bytes served is a stronger exfiltration signal than a 4xx count
    (404-spam can disguise outbound dataflow).

    The rule is intentionally skipped when the sample is too small to
    be meaningful (`bandwidth_hog_min_lines`, default 1000). At that
    scale one host is mechanically dominant and any threshold trips.

    Thresholds default to WARN at >=50% and CRITICAL at >=80% of total
    bytes; both are overridable via `modules.access_log.bandwidth_hog_*`
    config keys (AISO-207 will tighten the plumbing).
    """
    total_lines = settings.get("bandwidth_hog_min_lines", 1000)
    if agg.total_lines < total_lines:
        return []
    bytes_total = agg.bytes_total
    if bytes_total <= 0 or not agg.bytes_by_host:
        return []
    # `most_common` returns (host, bytes) ordered desc; we only need the
    # top hog — multi-host findings are out of scope for AISO-204.
    hog_host, hog_bytes = agg.bytes_by_host.most_common(1)[0]
    share = hog_bytes / bytes_total
    warn_threshold = settings["bandwidth_hog_warn"]
    crit_threshold = settings["bandwidth_hog_crit"]
    if share >= crit_threshold:
        sev: Severity | None = Severity.CRITICAL
    elif share >= warn_threshold:
        sev = Severity.WARN
    else:
        return []
    details: dict[str, Any] = {
        "host": hog_host,
        "bytes": hog_bytes,
        "share": share,
        "total": bytes_total,
        "thresholds": {
            "warn": warn_threshold,
            "crit": crit_threshold,
            "min_lines": total_lines,
        },
        # AISO-197-style forensic detail: the per-host byte ranks so the
        # operator can see whether one IP truly dwarfs the rest or whether
        # there is a near-tie that pushed it over the threshold.
        "bytes_by_host_top": agg.bytes_by_host.most_common(10),
        "crawler_suppression": CrawlerSuppression.not_applicable().to_dict(),
    }
    return [Finding(
        module="access_log",
        severity=sev,
        title=(
            f"{'CRITICAL' if sev is Severity.CRITICAL else 'WARN'} "
            f"bandwidth hog: {hog_host} served {share:.0%} of bytes "
            f"({hog_bytes:,} / {bytes_total:,})"
        ),
        description=(
            f"Source IP {hog_host!r} carried {hog_bytes:,} of "
            f"{bytes_total:,} bytes ({share:.1%}) in the scanned access log. "
            "On a busy host an IP dominating byte volume can indicate "
            "data exfiltration disguised as legitimate traffic; correlate "
            "with secure_log / domlog_inventory and consider egress rules."
        ),
        details=details,
        recommendation=(
            "Investigate the host's traffic; correlate with domlog_inventory "
            "and consider a per-IP byte rate-limit in the WAF."
        ),
    )]