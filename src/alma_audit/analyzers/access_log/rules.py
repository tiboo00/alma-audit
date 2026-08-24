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

from ...models import Finding, Severity
from ..crawler_verify import CrawlerSuppression, Resolver
from .aggregator import AccessAggregator, SAFE_METHODS
from .suppression import resolve_suppression


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
    top_host, top_hits = agg.hosts.most_common(1)[0]
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
    burst_ua = agg.last_ua_by_host.get(burst_host, "") if burst_host else ""
    d4_suppression = resolve_suppression(resolver, burst_host or "", burst_ua)
    d4_details: dict[str, Any] = {
        "error_rate": err_rate,
        "error_count": err_count,
        "total": total_hits,
        "status_buckets": summary["status_buckets"],
        "burst_host": burst_host,
        "crawler_suppression": d4_suppression.to_dict(),
        # AISO-197: per-host error breakdown — top 20 hosts by error count.
        "host_errors_top": summary.get("host_errors_top", []),
        "host_errors_total": summary.get("host_errors_total", 0),
    }
    if err_rate >= settings["error_rate_crit"]:
        sev: Severity | None = Severity.CRITICAL
    elif err_rate >= settings["error_rate_warn"]:
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
        title=f"Error rate {err_rate:.1%} ({err_count}/{total_hits})",
        description=(
            "More than expected 4xx/5xx responses. Either the host is "
            "being probed, or an upstream service is failing."
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
    return [Finding(
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
    )]


# AISO-208: cap on the path × IP × UA combination list. The forensic
# JSON keeps the full per-(path, ip) breakdown; this cap is just the
# top-N slice surfaced inline in the Markdown summary. 50 entries
# comfortably covers any realistic single-IP scanner pattern while
# keeping the MD report scannable.
_TOP_PATH_IP_UA_LIMIT = 50


def _serialise_top_path_ip_ua(agg: AccessAggregator) -> list[dict[str, Any]]:
    """Flatten every (path, ip) bucket into per-UA rows, ranked by count.

    The aggregator tracks user-agents per (path, ip) pair — each bucket
    may hold up to 5 distinct UAs. We expand those into one row per
    (path, ip, ua) triple, sorted by count desc, so the operator sees
    the highest-volume UA-on-which-path combination first. The per-(path,
    ip) total count is split evenly across the bucket's UAs only when
    the bucket actually held multiple UAs; for the common single-UA
    case the row carries the full bucket count, which is what the
    operator expects ("× 27 requests using python-requests/2.28.0").

    The full per-(path, ip, UA) breakdown is preserved in
    `probe_paths_by_ip` for the forensic JSON consumers; this list is
    the trimmed operator-eye view rendered in the MD summary.
    """
    rows: list[dict[str, Any]] = []
    for path, ip_map in agg.probe_by_path_ip.items():
        for ip, stat in ip_map.items():
            bucket_count = stat.count
            uas = list(stat.user_agents)
            if not uas:
                # No UA tracked — emit a single "<unknown>" row so the
                # bucket still appears in the operator's view.
                rows.append({
                    "path": path,
                    "ip": ip,
                    "user_agent": "<unknown>",
                    "count": bucket_count,
                })
                continue
            if len(uas) == 1:
                rows.append({
                    "path": path,
                    "ip": ip,
                    "user_agent": uas[0],
                    "count": bucket_count,
                })
                continue
            # Multiple UAs in one bucket — distribute the bucket count
            # across the UAs that were seen. This is an approximation
            # (we don't track per-UA counts inside the bucket today)
            # but it preserves the invariant "sum of UA counts in a
            # bucket = bucket total count", which the operator can
            # rely on. The forensic JSON carries the exact per-(path,
            # ip) totals, so the operator can always drill in.
            per_ua, remainder = divmod(bucket_count, len(uas))
            for idx, ua in enumerate(uas):
                rows.append({
                    "path": path,
                    "ip": ip,
                    "user_agent": ua,
                    # Last UA absorbs the remainder so the rows sum
                    # back to `bucket_count`.
                    "count": per_ua + (remainder if idx == len(uas) - 1 else 0),
                })
    rows.sort(key=lambda r: r["count"], reverse=True)
    return rows[:_TOP_PATH_IP_UA_LIMIT]


def _serialise_probe_paths_by_ip(
    probe_by_path_ip: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Convert the aggregator's internal `_PerIPProbeStat` map to JSON-safe rows."""
    out: dict[str, list[dict[str, Any]]] = {}
    for path, ip_map in probe_by_path_ip.items():
        rows = [
            {
                "ip": ip,
                "count": stat.count,
                "first_seen": stat.first_seen,
                "last_seen": stat.last_seen,
                "user_agents": list(stat.user_agents),
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
    return [Finding(
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
    )]


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