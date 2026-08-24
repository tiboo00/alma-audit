"""Detection rules for the secure_log analyzer.

Four rules, each emitting zero or more `Finding` records:

  D8 — SSH brute-force burst (per source IP). WARN/CRITICAL based on
       the combined number of `ssh_fail` AND `ssh_invalid_user` lines
       for that IP across the scan window. NEVER crawler-suppressible
       (no crawler layer here).
  D9 — sudo authentication failure burst (per user). WARN/CRITICAL
       based on the number of `pam_unix(sudo:auth): authentication
       failure` lines for that user.
  D10 — New root account creation. Always CRITICAL when a useradd
        event creates a UID=0 (root-equivalent) account mid-scan.
  D11 — Any new user / new group creation. WARN whenever a useradd
        or groupadd event fires, even for non-root accounts — a fresh
        account in a single-host audit window is unusual.

The crawler-suppressibility distinction does NOT apply to secure_log —
the §6.1 chain is access_log-scoped. Operators reading the report
still get the `crawler_suppression: n/a` sentinel for shape parity.

AISO-203: D8 combines the per-IP `ssh_fail_by_ip` (single-account
credential stuffing) and `ssh_invalid_user_by_ip` (rotating-username
enumeration) counters into a single brute-force total per IP, so an
attacker that only rotates usernames still trips D8. The two
underlying counters stay separate in the aggregator / forensic JSON
so the operator can tell which attack pattern they are seeing.
"""

from __future__ import annotations

from typing import Any

from ...models import Finding, Severity
from ..crawler_verify import CrawlerSuppression
from .aggregator import SecureAggregator


def rule_ssh_brute_force(
    agg: SecureAggregator,
    settings: dict[str, Any],
) -> list[Finding]:
    """D8 — SSH failed-password burst per source IP.

    AISO-203: combine `ssh_fail_by_ip` (single-account credential
    stuffing) with `ssh_invalid_user_by_ip` (rotating-username
    enumeration) into a per-IP brute-force total. An attacker that
    ONLY rotates usernames (and never hits a known account) still
    trips the rule. The aggregator keeps the two counters separate
    so the operator can tell which attack pattern they are seeing
    in the report's `details`.
    """
    n_a = CrawlerSuppression.not_applicable().to_dict()
    findings: list[Finding] = []
    # AISO-203: union of all IPs across both attack-pattern counters.
    all_ips = set(agg.ssh_fail_by_ip) | set(agg.ssh_invalid_user_by_ip)
    if not all_ips:
        return findings
    # Pre-compute the per-IP totals and sort by combined count desc.
    combined: list[tuple[str, int, int]] = []
    for ip in all_ips:
        fail_count = agg.ssh_fail_by_ip.get(ip, 0)
        invalid_count = agg.ssh_invalid_user_by_ip.get(ip, 0)
        combined.append((ip, fail_count, invalid_count))
    combined.sort(key=lambda t: (t[1] + t[2]), reverse=True)
    for ip, fail_count, invalid_count in combined:
        total = fail_count + invalid_count
        if total >= settings["ssh_fail_crit"]:
            sev = Severity.CRITICAL
        elif total >= settings["ssh_fail_warn"]:
            sev = Severity.WARN
        else:
            continue
        findings.append(Finding(
            module="secure_log",
            severity=sev,
            title=f"SSH brute-force from {ip}: {total} failed attempt(s)",
            description=(
                f"Source IP {ip!r} produced {total} failed SSH "
                "authentication(s) in the scan window. "
                f"Breakdown: {fail_count} known-account "
                f"credential-stuffing attempt(s) and "
                f"{invalid_count} rotating-username "
                f"enumeration attempt(s). "
                "Consistent with a brute-force campaign against the host."
            ),
            details={
                "source_ip": ip,
                "fail_count": total,
                # AISO-203: surface the per-pattern split so the
                # operator can distinguish credential stuffing from
                # username enumeration at a glance.
                "ssh_fail_count": fail_count,
                "ssh_invalid_user_count": invalid_count,
                "crawler_suppression": n_a,
            },
            recommendation=(
                "Investigate the IP in auth logs; consider fail2ban / "
                "firewalld rate-limit. If the IP is a known legitimate "
                "scanner (monitoring agent, ops jump host), add it to "
                "the operator allowlist outside this package."
            ),
        ))
    return findings


def rule_sudo_failures(
    agg: SecureAggregator,
    settings: dict[str, Any],
) -> list[Finding]:
    """D9 — sudo authentication failure burst per user."""
    n_a = CrawlerSuppression.not_applicable().to_dict()
    findings: list[Finding] = []
    if not agg.sudo_fail_by_user:
        return findings
    for user, count in agg.sudo_fail_by_user.most_common():
        if count >= settings["sudo_fail_crit"]:
            sev = Severity.CRITICAL
        elif count >= settings["sudo_fail_warn"]:
            sev = Severity.WARN
        else:
            continue
        findings.append(Finding(
            module="secure_log",
            severity=sev,
            title=f"sudo authentication failures for {user}: {count}",
            description=(
                f"User {user!r} had {count} sudo authentication "
                "failure(s) in the scan window. Could be a misconfigured "
                "sudoers rule, or an attacker probing for password reuse."
            ),
            details={
                "user": user,
                "fail_count": count,
                "crawler_suppression": n_a,
            },
            recommendation=(
                "Check the sudoers rule for this user; review the "
                "session log for the originating tty / remote host."
            ),
        ))
    return findings


def rule_new_root_account(
    agg: SecureAggregator,
    settings: dict[str, Any],
) -> list[Finding]:
    """D10 — a useradd event that creates a UID=0 account is always CRITICAL.

    A non-root useradd (UID > 0) is reported via `rule_any_user_change`.
    This rule ONLY fires for UID=0 (root-equivalent). It has no
    threshold knob because any root-level account creation mid-run is
    by definition anomalous on a hardened host.
    """
    n_a = CrawlerSuppression.not_applicable().to_dict()
    findings: list[Finding] = []
    if not settings.get("new_root_account_enabled", True):
        return findings
    for entry in agg.useradds:
        uid = entry.get("uid")
        if uid != 0:
            continue
        findings.append(Finding(
            module="secure_log",
            severity=Severity.CRITICAL,
            title=f"Root-level account created: {entry.get('name')!r} (UID=0)",
            description=(
                f"useradd created a new account named "
                f"{entry.get('name')!r} with UID=0 (root equivalent). "
                "On a hardened host this is almost always a compromise "
                "indicator — a root shell hidden behind a known account."
            ),
            details={
                "username": entry.get("name"),
                "uid": 0,
                "gid": entry.get("gid"),
                "pid": entry.get("pid"),
                "crawler_suppression": n_a,
            },
            recommendation=(
                "Investigate immediately: which session triggered the "
                "useradd, from which tty / SSH source IP. Lock the "
                "account with `passwd -l <name>` until reviewed."
            ),
        ))
    return findings


def rule_any_user_change(
    agg: SecureAggregator,
) -> list[Finding]:
    """D11 — any useradd / groupadd / passwd-change event in the window.

    Emits one INFO finding per unique account name across useradd +
    groupadd + passwd-change events. Operators can grep the report for
    `account_change` to see what mutated mid-window.
    """
    n_a = CrawlerSuppression.not_applicable().to_dict()
    findings: list[Finding] = []
    changed: dict[str, list[str]] = {}
    for entry in agg.useradds:
        name = entry.get("name")
        if name is None:
            continue
        changed.setdefault(name, []).append(f"useradd(uid={entry.get('uid')})")
    for entry in agg.groupadds:
        name = entry.get("name")
        if name is None:
            continue
        changed.setdefault(name, []).append(f"groupadd(gid={entry.get('gid')})")
    for name in agg.passwd_changes:
        changed.setdefault(name, []).append("passwd-change")
    if not changed:
        return findings
    items = [
        {"username": name, "events": evs}
        for name, evs in sorted(changed.items())
    ]
    findings.append(Finding(
        module="secure_log",
        severity=Severity.INFO,
        title=f"{len(items)} account mutation(s) observed",
        description=(
            "useradd / groupadd / passwd-change events seen in the "
            "scan window. Operators should verify these match an "
            "expected provisioning window."
        ),
        details={
            "changes": items,
            "crawler_suppression": n_a,
        },
    ))
    return findings