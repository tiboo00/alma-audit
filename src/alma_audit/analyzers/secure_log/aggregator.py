"""Streaming aggregator for the secure_log analyzer.

Holds O(unique-sources + unique-users + new-account-count) state, not
per-line data. The detection rules in `rules.py` read this state to
emit findings.

Counts tracked:
  - SSH failed-password bursts per source IP (`ssh_fail_by_ip`)
  - SSH invalid-user (rotating-username) bursts per source IP
    (`ssh_invalid_user_by_ip`) — kept SEPARATE because these two
    patterns describe distinct attack classes:
      * `ssh_fail` (`Failed password for known_user from IP`) is
        single-user credential stuffing against a valid account.
      * `ssh_invalid_user` (`Invalid user ghost from IP`) is
        rotating-username enumeration — the scanner rotates names
        because it doesn't know which accounts exist.
    The rule layer combines both for the brute-force *finding*; the
    aggregator tracks them in distinct counters so the operator can
    tell which pattern they are seeing.
  - sudo authentication failure bursts per user
  - new-user creations (useradd) with their UID/GID for the rules
    layer to escalate UID=0 to CRITICAL
  - well-formed lines (any event we classified) vs malformed lines
    (anything else that did not parse)

AISO-197: per-(ip, user) forensic detail for SSH failures and sudo
failures, with first_seen/last_seen timestamps. No cap on list size
per the operator's "show me everything" rule — the per-file line cap
in settings.py is the only budget control.

AISO-201: the host's own IPs (auto-detected + operator allowlist) are
filtered out of the SSH brute-force counters and the forensic detail
SKIPPED paths. A cPanel server is going to log hundreds of self-login
attempts from cron jobs, monitoring, internal services — treating
those as brute-force would drown the operator in noise. The forensic
JSON still records every self-IP event so the operator can audit it,
but the per-IP counters and the SSH brute-force finding skip them.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from ...self_ip import is_self_ip
from .parser import SecureRecord


class _PerIPUserStat:
    """Tracks (count, first_seen, last_seen) for one (event_type, ip, user) tuple."""

    __slots__ = ("count", "first_seen", "last_seen")

    def __init__(self, timestamp: str) -> None:
        self.count = 1
        self.first_seen = timestamp
        self.last_seen = timestamp

    def update(self, timestamp: str) -> None:
        self.count += 1
        if timestamp < self.first_seen:
            self.first_seen = timestamp
        if timestamp > self.last_seen:
            self.last_seen = timestamp


class SecureAggregator:
    """Streaming aggregator. Call `add(record)` per parsed line, then `finalize()`."""

    def __init__(
        self,
        self_ips: set[str] | None = None,
    ) -> None:
        # AISO-201: the host's own IPs (auto-detected + operator allowlist).
        # SSH / sudo events from these IPs are still recorded in the
        # forensic JSON, but the brute-force counters skip them so a
        # cPanel self-login cron doesn't trip a CRITICAL finding.
        self.self_ips: set[str] = self_ips or set()
        # SSH brute-force tracking. AISO-203: ssh_invalid_user is a
        # distinct attack class from ssh_fail (rotating-username
        # enumeration vs single-account credential stuffing) — keep
        # them in SEPARATE counters so the operator can tell which
        # pattern they are seeing in the report. The rule layer
        # combines both for the brute-force finding (see rules.py).
        self.ssh_fail_by_ip: Counter[str] = Counter()
        self.ssh_invalid_user_by_ip: Counter[str] = Counter()
        self.ssh_invalid_users: list[str] = []
        self.ssh_accept_by_ip: Counter[str] = Counter()
        # sudo failure tracking.
        self.sudo_fail_by_user: Counter[str] = Counter()
        self.sudo_success_count: int = 0
        # Account-creation tracking. The rules layer decides whether
        # the UID=0 case becomes a CRITICAL finding.
        self.useradds: list[dict[str, Any]] = []
        self.groupadds: list[dict[str, Any]] = []
        self.passwd_changes: list[str] = []
        # Diagnostic counters.
        self.total_lines: int = 0
        self.classified_lines: int = 0
        self.malformed_lines: int = 0
        # AISO-201: track self-IP events for the forensic dump even
        # when we skip them in the brute-force counters.
        self.self_ip_event_count: int = 0
        self.self_ip_examples: list[str] = []
        # AISO-197 forensic detail: ssh_fail_by_ip_user and
        # sudo_fail_by_user_full track (ip, user) pairs with timestamps.
        # Stored as dict-of-dicts for O(1) updates.
        self.ssh_fail_by_ip_user: dict[str, dict[str, _PerIPUserStat]] = {}
        self.sudo_fail_by_user_full: dict[str, _PerIPUserStat] = {}

    def _bump_ssh(self, ip: str, user: str | None, ts: str) -> None:
        ip_map = self.ssh_fail_by_ip_user.setdefault(ip, {})
        # Key by user if we have it, else a single-row "unknown_user"
        # bucket so the operator can see "this IP tried without a user".
        key = user or "<unknown_user>"
        stat = ip_map.get(key)
        if stat is None:
            ip_map[key] = _PerIPUserStat(ts)
        else:
            stat.update(ts)

    def add(self, record: SecureRecord) -> None:
        self.total_lines += 1
        self.classified_lines += 1
        ts = getattr(record, "raw_timestamp", "") or ""
        if record.event == "ssh_fail" and record.source_ip:
            # AISO-201: skip self-IP in brute-force counter. Forensic
            # JSON still records the event so the operator can audit
            # their own cron / monitoring noise.
            #
            # AISO-203: ONLY `ssh_fail` events bump `ssh_fail_by_ip`.
            # `ssh_invalid_user` events bump the SEPARATE
            # `ssh_invalid_user_by_ip` counter so the operator can
            # distinguish single-account credential stuffing from
            # rotating-username enumeration.
            if is_self_ip(record.source_ip, self.self_ips):
                self.self_ip_event_count += 1
                if len(self.self_ip_examples) < 5:
                    self.self_ip_examples.append(
                        f"ssh_fail from {record.source_ip} (self-IP)"
                    )
            else:
                self.ssh_fail_by_ip[record.source_ip] += 1
                if record.user:
                    self.ssh_invalid_users.append(record.user)
                self._bump_ssh(record.source_ip, record.user, ts)
        elif record.event == "ssh_invalid_user" and record.source_ip:
            # AISO-203: `Invalid user X from Y` is a SEPARATE attack
            # class from `Failed password for known_user from Y`. It
            # bumps `ssh_invalid_user_by_ip` only — NOT
            # `ssh_fail_by_ip`. The rule layer combines both counters
            # per (ip) for the brute-force finding, so an attacker
            # that only rotates usernames still trips D8.
            #
            # AISO-201: still skip self-IPs (cron / monitoring noise).
            if is_self_ip(record.source_ip, self.self_ips):
                self.self_ip_event_count += 1
                if len(self.self_ip_examples) < 5:
                    self.self_ip_examples.append(
                        f"ssh_invalid_user from {record.source_ip} (self-IP)"
                    )
            else:
                self.ssh_invalid_user_by_ip[record.source_ip] += 1
                if record.user:
                    self.ssh_invalid_users.append(record.user)
                self._bump_ssh(record.source_ip, record.user, ts)
        elif record.event == "ssh_accept" and record.source_ip:
            self.ssh_accept_by_ip[record.source_ip] += 1
        elif record.event == "sudo_fail" and record.user:
            # Sudo fails aren't per-IP in our parser, but we still
            # protect against the local-sudo noise (e.g. a cron job
            # running `sudo -n <command>` from a service account).
            self.sudo_fail_by_user[record.user] += 1
            stat = self.sudo_fail_by_user_full.get(record.user)
            if stat is None:
                self.sudo_fail_by_user_full[record.user] = _PerIPUserStat(ts)
            else:
                stat.update(ts)
        elif record.event == "sudo_success":
            self.sudo_success_count += 1
        elif record.event == "useradd":
            self.useradds.append({
                "name": record.username,
                "uid": record.uid,
                "gid": record.gid,
                "pid": record.pid,
            })
        elif record.event == "groupadd":
            self.groupadds.append({
                "name": record.username,  # parser stores the group name here
                "gid": record.gid,
                "pid": record.pid,
            })
        elif record.event == "passwd_change":
            if record.username:
                self.passwd_changes.append(record.username)

    def note_malformed(self) -> None:
        """Increment the malformed-line counter for an un-classified syslog line."""
        self.total_lines += 1
        self.malformed_lines += 1

    def extend(self, records: Iterable[SecureRecord]) -> None:
        for r in records:
            self.add(r)

    def finalize(self) -> dict[str, Any]:
        # AISO-197: serialise per-(ip, user) SSH detail into JSON-safe rows.
        ssh_details: list[dict[str, Any]] = []
        for ip, user_map in self.ssh_fail_by_ip_user.items():
            for user, stat in user_map.items():
                ssh_details.append({
                    "ip": ip,
                    "user": user if user != "<unknown_user>" else None,
                    "count": stat.count,
                    "first_seen": stat.first_seen,
                    "last_seen": stat.last_seen,
                })
        # Sort by count desc — operator's-eye view of top offenders.
        ssh_details.sort(key=lambda r: r["count"], reverse=True)

        sudo_details: list[dict[str, Any]] = []
        for user, stat in self.sudo_fail_by_user_full.items():
            sudo_details.append({
                "user": user,
                "count": stat.count,
                "first_seen": stat.first_seen,
                "last_seen": stat.last_seen,
            })
        sudo_details.sort(key=lambda r: r["count"], reverse=True)

        return {
            "total_lines": self.total_lines,
            "classified_lines": self.classified_lines,
            "malformed_lines": self.malformed_lines,
            "ssh_fail_by_ip": dict(self.ssh_fail_by_ip.most_common(10)),
            # AISO-203: separate counter for `ssh_invalid_user` (rotating-
            # username enumeration). Empty when the scanner never
            # tried non-existent accounts; populated alongside
            # `ssh_fail_by_ip` when both attack patterns were observed
            # from the same IP.
            "ssh_invalid_user_by_ip": dict(self.ssh_invalid_user_by_ip.most_common(10)),
            "ssh_invalid_users_top": Counter(self.ssh_invalid_users).most_common(10),
            "ssh_accept_by_ip": dict(self.ssh_accept_by_ip.most_common(10)),
            "sudo_fail_by_user": dict(self.sudo_fail_by_user.most_common(10)),
            "sudo_success_count": self.sudo_success_count,
            "useradds": list(self.useradds),
            "groupadds": list(self.groupadds),
            "passwd_changes": list(self.passwd_changes),
            # AISO-197 forensic detail.
            "ssh_fail_details": ssh_details,
            "sudo_fail_details": sudo_details,
            # AISO-201: self-IP events (cron / monitoring noise from
            # the host itself). Recorded for diagnostic purposes; not
            # surfaced as a finding.
            "self_ip_event_count": self.self_ip_event_count,
            "self_ip_examples": list(self.self_ip_examples),
        }