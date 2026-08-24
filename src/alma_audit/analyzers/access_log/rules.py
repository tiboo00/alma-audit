"""Detection rules for the access_log analyzer.

Four rules, each emitting zero or more `Finding` records:

  D1 — top-host concentration (crawler-suppressible)
  D4 — 4xx + 5xx burst rate (crawler-suppressible on the burst host)
  D2 — known probe paths (NEVER crawler-suppressible)
  D5 — unusual HTTP methods (NEVER crawler-suppressible)

The crawler-suppressibility distinction is the §6.1 contract:
D2/D5 are never suppressed because a Googlebot asking for `/.env` is
still an event — it is downgraded but not erased.
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
                f"to a verified-crawler UA, so the D4 finding is "
                f"downgraded to informational."
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
            # D2/D5: these are NEVER suppressed by crawler verification,
            # so the field is the `n/a` sentinel.
            "crawler_suppression": CrawlerSuppression.not_applicable().to_dict(),
        },
        recommendation="Inspect source IPs and ensure those endpoints are blocked at the WAF.",
    )]


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