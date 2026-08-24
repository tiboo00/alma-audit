"""Detection rules for the cphulk_log analyzer.

Three rules:

  D14 — Brute-force burst per source IP. WARN/CRITICAL based on
        `brute_force_warn` / `brute_force_crit`. Mirrors the access_log
        D8 shape but on cPHulk-recorded events; operators see this
        alongside the sshd-side brute-force finding from secure_log.
  D15 — Brute-force burst per username. WARN/CRITICAL based on
        `brute_force_user_warn` / `brute_force_user_crit`. A single
        account being hammered is the classic credential-stuffing
        pattern against cPanel.
  D16 — Account / IP block summary. INFO finding listing the unique
        accounts and IPs blocked during the scan window.

The crawler-suppressibility distinction does NOT apply — these are
non-HTTP findings.
"""

from __future__ import annotations

from typing import Any

from ...models import Finding, Severity
from ..crawler_verify import CrawlerSuppression
from .aggregator import CphulkAggregator


def rule_brute_force_by_ip(
    agg: CphulkAggregator,
    settings: dict[str, Any],
) -> list[Finding]:
    """D14 — brute-force burst per source IP."""
    n_a = CrawlerSuppression.not_applicable().to_dict()
    findings: list[Finding] = []
    if not agg.brute_force_by_ip:
        return findings
    for ip, count in agg.brute_force_by_ip.most_common():
        if count >= settings["brute_force_crit"]:
            sev = Severity.CRITICAL
        elif count >= settings["brute_force_warn"]:
            sev = Severity.WARN
        else:
            continue
        findings.append(Finding(
            module="cphulk_log",
            severity=sev,
            title=f"cPHulk brute-force from {ip}: {count} attempt(s)",
            description=(
                f"cPHulk recorded {count} brute-force attempt(s) from "
                f"{ip!r} in the scan window. This is the cPanel-side "
                "view of the same activity the SSH daemon sees in "
                "secure.log — corroborating evidence."
            ),
            details={
                "source_ip": ip,
                "brute_force_count": count,
                "crawler_suppression": n_a,
            },
            recommendation=(
                "If the IP is not on a known allowlist, the cPHulk block "
                "should already be in effect. Verify by inspecting the "
                "block_events list for this IP."
            ),
        ))
    return findings


def rule_brute_force_by_user(
    agg: CphulkAggregator,
    settings: dict[str, Any],
) -> list[Finding]:
    """D15 — brute-force burst per username."""
    n_a = CrawlerSuppression.not_applicable().to_dict()
    findings: list[Finding] = []
    if not agg.brute_force_by_user:
        return findings
    for user, count in agg.brute_force_by_user.most_common():
        if count >= settings["brute_force_user_crit"]:
            sev = Severity.CRITICAL
        elif count >= settings["brute_force_user_warn"]:
            sev = Severity.WARN
        else:
            continue
        findings.append(Finding(
            module="cphulk_log",
            severity=sev,
            title=f"cPHulk brute-force against {user}: {count} attempt(s)",
            description=(
                f"cPHulk recorded {count} brute-force attempt(s) "
                f"against account {user!r} in the scan window. "
                "Targeted attacks against cPanel admin / mail / FTP "
                "accounts frequently look like this."
            ),
            details={
                "username": user,
                "brute_force_count": count,
                "crawler_suppression": n_a,
            },
            recommendation=(
                "Audit the password strength for this account; review "
                "the originating IPs via the access_log analyzer."
            ),
        ))
    return findings


def rule_block_summary(
    agg: CphulkAggregator,
) -> list[Finding]:
    """D16 — list of accounts / IPs that cPHulk blocked in the window."""
    n_a = CrawlerSuppression.not_applicable().to_dict()
    if not agg.block_events and not agg.unblock_events:
        return []
    blocked = sorted({
        (e["event"], e["source_ip"], e["username"])
        for e in agg.block_events
    })
    unblocked = sorted({
        (e["event"], e["source_ip"], e["username"])
        for e in agg.unblock_events
    })
    return [Finding(
        module="cphulk_log",
        severity=Severity.INFO,
        title=(
            f"{len(blocked)} unique block event(s), "
            f"{len(unblocked)} unique unblock event(s)"
        ),
        description=(
            "cPHulk recorded block / unblock actions during the scan "
            "window. Use this list to verify expected blocks (a known "
            "fail2ban jump host) vs unexpected ones (a customer IP "
            "locked out by mistake)."
        ),
        details={
            "blocked": [
                {"event": e, "source_ip": ip, "username": user}
                for (e, ip, user) in blocked
            ],
            "unblocked": [
                {"event": e, "source_ip": ip, "username": user}
                for (e, ip, user) in unblocked
            ],
            "crawler_suppression": n_a,
        },
    )]