"""Detection rules for the ssh_hardening analyzer.

One rule per sshd directive the audit flags. The severity mapping
follows acceptance criterion #3 from AISO-209:

  - **CRITICAL**: ``PermitRootLogin yes``, ``PermitEmptyPasswords yes``,
    ``Protocol 1`` or ``Protocol 1,2`` (SSH-1 enabled).
  - **WARN**: ``PasswordAuthentication yes``, ``Port 22`` (default
    port), ``MaxAuthTries > max_auth_tries_warn``,
    ``ClientAliveInterval 0`` (no idle timeout),
    ``LoginGraceTime > login_grace_time_warn``, missing
    ``AllowUsers`` / ``AllowGroups`` (no explicit allowlist), weak
    ``Ciphers`` / ``MACs`` (3des-cbc, arcfour, md5*, hmac-md5*).
  - **INFO**: ``X11Forwarding yes``, ``PermitRootLogin prohibit-password``
    (key-only root, acceptable but worth noting),
    ``Protocol 2,1`` (same as 1,2), no ``Banner``.

Each rule reads the first-obtained-wins snapshot from the
aggregator (matching ``sshd_config(5)`` semantics — the first
obtained value of every keyword is used, not the last) and emits
one ``Finding`` per detected posture. The ``details`` dict carries
the actual line that triggered the rule (per acceptance criterion
#4).
"""

from __future__ import annotations

from typing import Any

from ...models import Finding, Severity
from ..crawler_verify import CrawlerSuppression
from .aggregator import SshdConfigSnapshot
from .settings import WEAK_CIPHERS, WEAK_MACS

_NA = CrawlerSuppression.not_applicable().to_dict()


def _directive(snap: SshdConfigSnapshot, name: str) -> Any:
    """Return the last-wins directive for ``name`` (case-INsensitive) or None."""
    return snap.directives.get(name.lower())


def _values(snap: SshdConfigSnapshot, name: str) -> list[str]:
    d = _directive(snap, name)
    if d is None:
        return []
    return list(d.values)


def rule_permit_root_login(snap: SshdConfigSnapshot) -> list[Finding]:
    d = _directive(snap, "PermitRootLogin")
    if d is None or not d.values:
        return []
    val = d.values[0].lower()
    if val == "yes":
        severity = Severity.CRITICAL
        title = "PermitRootLogin yes — root SSH login allowed"
        description = (
            "sshd_config sets `PermitRootLogin yes`. Direct root SSH "
            "logins are enabled — any actor with the root password "
            "(or a successful brute-force) gets full system access "
            "with no audit trail tying the session to an individual "
            "account."
        )
        recommendation = (
            "Set `PermitRootLogin no` (preferred) or at minimum "
            "`PermitRootLogin prohibit-password` to force key-only "
            "root. Combined with `PasswordAuthentication no` this "
            "removes the credential-stuffing path entirely."
        )
    elif val == "prohibit-password":
        severity = Severity.INFO
        title = "PermitRootLogin prohibit-password — root via key only"
        description = (
            "Root SSH is allowed but only via public key (no password "
            "or keyboard-interactive). This is the CIS Benchmark "
            "minimum posture; a stronger choice is "
            "`PermitRootLogin no` plus a sudo-enabled admin account."
        )
        recommendation = (
            "Acceptable. If a sudo-enabled admin account exists, "
            "tighten to `PermitRootLogin no` and log admin elevation "
            "via sudo instead."
        )
    elif val == "without-password":
        # ``without-password`` is the legacy spelling of
        # ``prohibit-password`` (OpenSSH < 7.0). Same semantics.
        severity = Severity.INFO
        title = "PermitRootLogin without-password — root via key only (legacy spelling)"
        description = (
            "Root SSH is allowed only via public key. The "
            "`without-password` spelling is the legacy alias of "
            "`prohibit-password` (OpenSSH < 7.0); both are "
            "equivalent."
        )
        recommendation = (
            "Acceptable. Modernise to `prohibit-password` for "
            "clarity, but functionally identical."
        )
    elif val == "no":
        return []
    else:
        return []
    return [Finding(
        module="ssh_hardening",
        severity=severity,
        title=title,
        description=description,
        details={
            "directive": d.keyword,
            "value": d.values[0],
            "source_path": d.source_path,
            "source_line": d.source_line,
            "crawler_suppression": _NA,
        },
        recommendation=recommendation,
    )]


def rule_permit_empty_passwords(snap: SshdConfigSnapshot) -> list[Finding]:
    d = _directive(snap, "PermitEmptyPasswords")
    if d is None or not d.values:
        return []
    if d.values[0].lower() != "yes":
        return []
    return [Finding(
        module="ssh_hardening",
        severity=Severity.CRITICAL,
        title="PermitEmptyPasswords yes — empty-password login allowed",
        description=(
            "sshd_config allows login to accounts with empty "
            "password strings. This is the textbook SSH backdoor — "
            "any account with a blank ``passwd`` field (often "
            "service accounts created during bulk provisioning) is "
            "remotely reachable."
        ),
        details={
            "directive": d.keyword,
            "value": d.values[0],
            "source_path": d.source_path,
            "source_line": d.source_line,
            "crawler_suppression": _NA,
        },
        recommendation=(
            "Set `PermitEmptyPasswords no` (the OpenSSH default). "
            "Audit ``/etc/shadow`` for accounts with an empty "
            "password field and lock or set a password on each one."
        ),
    )]


def rule_protocol(snap: SshdConfigSnapshot) -> list[Finding]:
    d = _directive(snap, "Protocol")
    if d is None or not d.values:
        return []
    # ``Protocol`` accepts a comma-separated list — any ``1`` in
    # the list enables SSH-1 (a fundamentally broken protocol,
    # disabled at compile time in modern OpenSSH but still
    # supported as a config token for legacy reasons).
    raw = d.values[0]
    parts = {p.strip() for p in raw.split(",")}
    findings: list[Finding] = []
    if "1" in parts and "2" in parts:
        # ``1,2`` or ``2,1`` — SSH-1 enabled but SSH-2 is
        # preferred. CIS Benchmark is CRITICAL.
        findings.append(Finding(
            module="ssh_hardening",
            severity=Severity.CRITICAL,
            title="Protocol 1 enabled (SSH-1 is broken)",
            description=(
                f"sshd_config sets `Protocol {raw}` — SSH-1 is "
                "enabled. SSH-1 has been broken (man-in-the-middle, "
                "session hijack) since 1998 and is removed from "
                "modern OpenSSH builds. Even as a fallback it has "
                "no security value."
            ),
            details={
                "directive": d.keyword,
                "value": raw,
                "source_path": d.source_path,
                "source_line": d.source_line,
                "crawler_suppression": _NA,
            },
            recommendation=(
                "Set `Protocol 2` (the OpenSSH default since "
                "OpenSSH 5.x; the only legal value in modern "
                "builds). The `Protocol` directive itself is a "
                "no-op on OpenSSH >= 7.4 — you can remove it "
                "entirely."
            ),
        ))
    elif parts == {"2"}:
        return []
    elif parts == {"1"}:
        findings.append(Finding(
            module="ssh_hardening",
            severity=Severity.CRITICAL,
            title="Protocol 1 (SSH-1 only)",
            description=(
                "sshd_config sets `Protocol 1` — only SSH-1 is "
                "served. This is a downgrade-only posture; the "
                "host will refuse all SSH-2 clients."
            ),
            details={
                "directive": d.keyword,
                "value": raw,
                "source_path": d.source_path,
                "source_line": d.source_line,
                "crawler_suppression": _NA,
            },
            recommendation=(
                "Set `Protocol 2`. Modern OpenSSH builds will not "
                "honour `Protocol 1` (compile-time disabled), so "
                "this line is silently ignored — but it remains a "
                "red flag in the audit."
            ),
        ))
    return findings


def rule_password_authentication(snap: SshdConfigSnapshot) -> list[Finding]:
    d = _directive(snap, "PasswordAuthentication")
    if d is None or not d.values:
        return []
    if d.values[0].lower() != "yes":
        return []
    # Check whether PubkeyAuthentication is also set to yes — if
    # both are yes, the WARN still fires (the credential-stuffing
    # path is still open) but the recommendation mentions key-only.
    pk = _directive(snap, "PubkeyAuthentication")
    pk_yes = pk is not None and bool(pk.values) and pk.values[0].lower() == "yes"
    rec = (
        "Set `PasswordAuthentication no` and require public-key "
        "auth. Pair with `PermitRootLogin prohibit-password` (or "
        "`no`) and an SSH key enrolled for the admin account."
    )
    if pk_yes:
        rec += (
            "\n\n`PubkeyAuthentication yes` is also set — the host "
            "accepts both password and key auth, which leaves the "
            "credential-stuffing surface open. Either move all "
            "users to key-only (preferred) or set "
            "`PasswordAuthentication no` once you have verified "
            "every admin has a working key."
        )
    return [Finding(
        module="ssh_hardening",
        severity=Severity.WARN,
        title="PasswordAuthentication yes — password login enabled",
        description=(
            "sshd_config allows password-based authentication. "
            "Every account with a guessable / reused password is a "
            "credential-stuffing target; the SSH brute-force "
            "findings from the secure_log analyzer are downstream "
            "of this single setting."
        ),
        details={
            "directive": d.keyword,
            "value": d.values[0],
            "pubkey_authentication": pk.values[0] if pk is not None and pk.values else None,
            "source_path": d.source_path,
            "source_line": d.source_line,
            "crawler_suppression": _NA,
        },
        recommendation=rec,
    )]


def rule_default_port(snap: SshdConfigSnapshot) -> list[Finding]:
    d = _directive(snap, "Port")
    if d is None or not d.values:
        return []
    raw = d.values[0]
    try:
        port = int(raw)
    except ValueError:
        return []
    if port != 22:
        return []
    return [Finding(
        module="ssh_hardening",
        severity=Severity.WARN,
        title="SSH on default port 22",
        description=(
            "sshd_config listens on port 22 (the IANA-registered "
            "SSH port). Internet-wide scanners target port 22 by "
            "default; moving to a non-standard high port cuts the "
            "credential-stuffing background noise by 1-2 orders of "
            "magnitude."
        ),
        details={
            "directive": d.keyword,
            "value": raw,
            "source_path": d.source_path,
            "source_line": d.source_line,
            "crawler_suppression": _NA,
        },
        recommendation=(
            "Pick a high unprivileged port (e.g. 5022, 2222, or "
            "22000+) and update `Port <new>`. Remember to open the "
            "firewall (``csf -p`` / ``firewall-cmd`` / cloud "
            "security group) and update any monitoring that "
            "expects port 22. Port-knock / fail2ban are NOT "
            "substitutes — they only kick in AFTER the scan "
            "reaches the daemon."
        ),
    )]


def rule_max_auth_tries(snap: SshdConfigSnapshot, settings: dict[str, Any]) -> list[Finding]:
    d = _directive(snap, "MaxAuthTries")
    if d is None or not d.values:
        return []
    raw = d.values[0]
    try:
        n = int(raw)
    except ValueError:
        return []
    if n <= settings["max_auth_tries_warn"]:
        return []
    return [Finding(
        module="ssh_hardening",
        severity=Severity.WARN,
        title=f"MaxAuthTries {n} (> {settings['max_auth_tries_warn']})",
        description=(
            f"sshd_config allows {n} authentication attempts per "
            f"connection — above the {settings['max_auth_tries_warn']} "
            "threshold. Each attempt lets the brute-forcer try "
            "another password without reconnecting; combined with "
            "the default `LoginGraceTime` (120s) the practical "
            "surface is `n` guesses per connection."
        ),
        details={
            "directive": d.keyword,
            "value": raw,
            "threshold": settings["max_auth_tries_warn"],
            "source_path": d.source_path,
            "source_line": d.source_line,
            "crawler_suppression": _NA,
        },
        recommendation=(
            f"Lower `MaxAuthTries` to at most "
            f"{settings['max_auth_tries_warn']} (CIS Benchmark "
            "upper bound). Pair with `PasswordAuthentication no` "
            "for the strongest posture."
        ),
    )]


def rule_client_alive_interval(snap: SshdConfigSnapshot) -> list[Finding]:
    d = _directive(snap, "ClientAliveInterval")
    if d is None or not d.values:
        return []
    raw = d.values[0]
    try:
        n = int(raw)
    except ValueError:
        return []
    if n != 0:
        return []
    # ``ClientAliveInterval 0`` disables the keep-alive timeout
    # entirely — idle sessions stay open until the kernel TCP
    # timeout (often days).
    cam = _directive(snap, "ClientAliveCountMax")
    cam_raw = cam.values[0] if cam is not None and cam.values else None
    return [Finding(
        module="ssh_hardening",
        severity=Severity.WARN,
        title="ClientAliveInterval 0 — no idle timeout",
        description=(
            "sshd_config sets `ClientAliveInterval 0` — the "
            "daemon never closes idle sessions based on silence. "
            "An unattended SSH session (laptop closed, VPN "
            "reconnect, ...) stays open until the kernel TCP "
            "timeout."
        ),
        details={
            "directive": d.keyword,
            "value": raw,
            "client_alive_count_max": cam_raw,
            "source_path": d.source_path,
            "source_line": d.source_line,
            "crawler_suppression": _NA,
        },
        recommendation=(
            "Set `ClientAliveInterval 300` (5 minutes) and "
            "`ClientAliveCountMax 2` so an idle session is closed "
            "after ~10 minutes of silence. Adjust to your "
            "monitoring / interactive workload."
        ),
    )]


def rule_login_grace_time(snap: SshdConfigSnapshot, settings: dict[str, Any]) -> list[Finding]:
    d = _directive(snap, "LoginGraceTime")
    if d is None or not d.values:
        return []
    raw = d.values[0]
    # sshd accepts ``120``, ``2m``, ``90s`` — parse to seconds.
    seconds = _parse_grace_time(raw)
    if seconds is None or seconds <= settings["login_grace_time_warn"]:
        return []
    return [Finding(
        module="ssh_hardening",
        severity=Severity.WARN,
        title=f"LoginGraceTime {raw} (> {settings['login_grace_time_warn']}s)",
        description=(
            f"sshd_config sets `LoginGraceTime {raw}` — "
            f"{seconds}s window for the client to authenticate. "
            "An attacker can hold the daemon slot open for the "
            "entire grace window with a single TCP connection, "
            "denying service to legitimate users (slow-loris "
            "variant)."
        ),
        details={
            "directive": d.keyword,
            "value": raw,
            "seconds": seconds,
            "threshold": settings["login_grace_time_warn"],
            "source_path": d.source_path,
            "source_line": d.source_line,
            "crawler_suppression": _NA,
        },
        recommendation=(
            f"Lower `LoginGraceTime` to at most "
            f"{settings['login_grace_time_warn']}s "
            "(CIS Benchmark upper bound). 30-60s is typical."
        ),
    )]


def _parse_grace_time(raw: str) -> int | None:
    """Parse ``120`` / ``2m`` / ``90s`` / ``1h`` → seconds."""
    s = raw.strip().lower()
    if not s:
        return None
    if s.endswith("s"):
        try:
            return int(s[:-1])
        except ValueError:
            return None
    if s.endswith("m"):
        try:
            return int(s[:-1]) * 60
        except ValueError:
            return None
    if s.endswith("h"):
        try:
            return int(s[:-1]) * 3600
        except ValueError:
            return None
    try:
        return int(s)
    except ValueError:
        return None


def rule_missing_allowlist(snap: SshdConfigSnapshot) -> list[Finding]:
    """WARN if neither ``AllowUsers`` nor ``AllowGroups`` is set."""
    has_users = _directive(snap, "AllowUsers") is not None
    has_groups = _directive(snap, "AllowGroups") is not None
    if has_users or has_groups:
        return []
    return [Finding(
        module="ssh_hardening",
        severity=Severity.WARN,
        title="No AllowUsers / AllowGroups allowlist",
        description=(
            "sshd_config has neither `AllowUsers` nor `AllowGroups` "
            "— every local account on the host is reachable over "
            "SSH (subject to the PasswordAuthentication / "
            "PermitRootLogin posture). On a cPanel host that's "
            "hundreds of cPanel accounts; the blast radius of a "
            "compromised password is the entire account roster."
        ),
        details={
            "directive": "AllowUsers",
            "value": None,
            "source_path": "(absent)",
            "source_line": "(no AllowUsers / AllowGroups directive)",
            "crawler_suppression": _NA,
        },
        recommendation=(
            "Set `AllowGroups ssh-admins` (or similar) and put "
            "every SSH-eligible user in that group. Alternatively "
            "set `AllowUsers admin1 admin2` for a small roster. "
            "`DenyUsers` / `DenyGroups` are also accepted but the "
            "allowlist form is the CIS Benchmark recommendation."
        ),
    )]


def rule_x11_forwarding(snap: SshdConfigSnapshot) -> list[Finding]:
    d = _directive(snap, "X11Forwarding")
    if d is None or not d.values:
        return []
    if d.values[0].lower() != "yes":
        return []
    return [Finding(
        module="ssh_hardening",
        severity=Severity.INFO,
        title="X11Forwarding yes",
        description=(
            "sshd_config enables X11 forwarding. Most server "
            "workloads (cPanel included) have no X11 client; the "
            "feature only widens the daemon's attack surface."
        ),
        details={
            "directive": d.keyword,
            "value": d.values[0],
            "source_path": d.source_path,
            "source_line": d.source_line,
            "crawler_suppression": _NA,
        },
        recommendation=(
            "Set `X11Forwarding no` unless an X11 client is a "
            "documented requirement."
        ),
    )]


def rule_no_banner(snap: SshdConfigSnapshot) -> list[Finding]:
    d = _directive(snap, "Banner")
    if d is not None:
        return []
    return [Finding(
        module="ssh_hardening",
        severity=Severity.INFO,
        title="No SSH Banner configured",
        description=(
            "sshd_config has no `Banner` directive. Many "
            "compliance regimes (PCI-DSS, CIS Benchmark) require "
            "a legal-warning banner on every interactive login."
        ),
        details={
            "directive": "Banner",
            "value": None,
            "source_path": "(absent)",
            "source_line": "(no Banner directive)",
            "crawler_suppression": _NA,
        },
        recommendation=(
            "Drop a banner file (e.g. `/etc/ssh/banner`) and add "
            "`Banner /etc/ssh/banner` to sshd_config. The banner "
            "is shown BEFORE authentication — it must NOT contain "
            "system version info."
        ),
    )]


def rule_weak_algorithms(
    snap: SshdConfigSnapshot,
    *,
    keyword: str,
    weak_set: set[str],
) -> list[Finding]:
    """Single finding listing every weak algorithm in the list."""
    d = _directive(snap, keyword)
    if d is None or not d.values:
        return []
    # ``Ciphers`` / ``MACs`` take a comma-separated list as the
    # FIRST token (``Ciphers aes128-ctr,aes192-ctr,...``) or split
    # across multiple tokens (``Ciphers aes128-ctr aes192-ctr``).
    # sshd normalises to comma-separated at parse time; we accept
    # either shape.
    raw = d.values[0]
    raw_extras = ",".join(d.values[1:]) if len(d.values) > 1 else ""
    combined = raw + "," + raw_extras if raw_extras else raw
    listed = {p.strip() for p in combined.split(",") if p.strip()}
    weak_hits = sorted(listed & weak_set)
    if not weak_hits:
        return []
    return [Finding(
        module="ssh_hardening",
        severity=Severity.WARN,
        title=f"Weak {keyword}: {', '.join(weak_hits)}",
        description=(
            f"sshd_config lists {len(weak_hits)} weak {keyword} "
            "algorithm(s). Each is on a known-weak list (3DES / "
            "RC4 / MD5 family) and is reachable for any client "
            "that offers it during kex."
        ),
        details={
            "directive": d.keyword,
            "value": raw,
            "weak_algorithms": weak_hits,
            "source_path": d.source_path,
            "source_line": d.source_line,
            "crawler_suppression": _NA,
        },
        recommendation=(
            f"Remove the weak {keyword} from the list. The "
            "modern defaults (``Ciphers`` = chacha20-poly1305@openssh.com, "
            "aes128-ctr, aes192-ctr, aes256-ctr, "
            "aes128-gcm@openssh.com, aes256-gcm@openssh.com; "
            "``MACs`` = hmac-sha2-512-etm@openssh.com, "
            "hmac-sha2-256-etm@openssh.com, "
            "umac-128-etm@openssh.com, "
            "hmac-sha2-512, hmac-sha2-256) cover every modern "
            "client. Run ``ssh -Q cipher`` / ``ssh -Q mac`` to "
            "see what your OpenSSH build supports."
        ),
    )]


def rule_weak_ciphers(snap: SshdConfigSnapshot) -> list[Finding]:
    return rule_weak_algorithms(snap, keyword="Ciphers", weak_set=WEAK_CIPHERS)


def rule_weak_macs(snap: SshdConfigSnapshot) -> list[Finding]:
    return rule_weak_algorithms(snap, keyword="MACs", weak_set=WEAK_MACS)


def all_findings(
    snap: SshdConfigSnapshot,
    settings: dict[str, Any],
) -> list[Finding]:
    """Run every rule and return the combined findings list."""
    findings: list[Finding] = []
    findings.extend(rule_permit_root_login(snap))
    findings.extend(rule_permit_empty_passwords(snap))
    findings.extend(rule_protocol(snap))
    findings.extend(rule_password_authentication(snap))
    findings.extend(rule_default_port(snap))
    findings.extend(rule_max_auth_tries(snap, settings))
    findings.extend(rule_client_alive_interval(snap))
    findings.extend(rule_login_grace_time(snap, settings))
    findings.extend(rule_missing_allowlist(snap))
    findings.extend(rule_x11_forwarding(snap))
    findings.extend(rule_no_banner(snap))
    findings.extend(rule_weak_ciphers(snap))
    findings.extend(rule_weak_macs(snap))
    return findings
