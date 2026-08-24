"""Streaming aggregator for the secure_log analyzer.

Holds O(unique-sources + unique-users + new-account-count) state, not
per-line data. The detection rules in `rules.py` read this state to
emit findings.

Counts tracked:
  - SSH failed-password bursts per source IP
  - sudo authentication failure bursts per user
  - new-user creations (useradd) with their UID/GID for the rules
    layer to escalate UID=0 to CRITICAL
  - well-formed lines (any event we classified) vs malformed lines
    (anything else that did not parse)
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from .parser import SecureRecord


class SecureAggregator:
    """Streaming aggregator. Call `add(record)` per parsed line, then `finalize()`."""

    def __init__(self) -> None:
        # SSH brute-force tracking.
        self.ssh_fail_by_ip: Counter[str] = Counter()
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

    def add(self, record: SecureRecord) -> None:
        self.total_lines += 1
        self.classified_lines += 1
        if record.event == "ssh_fail" and record.source_ip:
            self.ssh_fail_by_ip[record.source_ip] += 1
            if record.user:
                self.ssh_invalid_users.append(record.user)
        elif record.event == "ssh_invalid_user" and record.source_ip:
            # Treat `Invalid user X from Y` the same as a fail for the
            # burst counter — the scanner has already tried to log in
            # with a non-existent account. Without this distinction an
            # attacker that rotates usernames wouldn't trip the rule.
            self.ssh_fail_by_ip[record.source_ip] += 1
            if record.user:
                self.ssh_invalid_users.append(record.user)
        elif record.event == "ssh_accept" and record.source_ip:
            self.ssh_accept_by_ip[record.source_ip] += 1
        elif record.event == "sudo_fail" and record.user:
            self.sudo_fail_by_user[record.user] += 1
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
        return {
            "total_lines": self.total_lines,
            "classified_lines": self.classified_lines,
            "malformed_lines": self.malformed_lines,
            "ssh_fail_by_ip": dict(self.ssh_fail_by_ip.most_common(10)),
            "ssh_invalid_users_top": Counter(self.ssh_invalid_users).most_common(10),
            "ssh_accept_by_ip": dict(self.ssh_accept_by_ip.most_common(10)),
            "sudo_fail_by_user": dict(self.sudo_fail_by_user.most_common(10)),
            "sudo_success_count": self.sudo_success_count,
            "useradds": list(self.useradds),
            "groupadds": list(self.groupadds),
            "passwd_changes": list(self.passwd_changes),
        }