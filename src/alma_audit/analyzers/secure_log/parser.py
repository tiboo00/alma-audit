"""Secure / auth.log line parser.

Pure parser: one line → one `SecureRecord` (or `None` if the line is
not a security-relevant event we know about). The aggregator lives in
`aggregator.py`; detection rules live in `rules.py`.

Recognised syslog line shapes (RHEL `secure` / Debian `auth.log`):

  Aug 17 04:12:34 host sshd[1234]: Failed password for invalid user \
      admin from 1.2.3.4 port 12345 ssh2
  Aug 17 04:12:34 host sshd[1234]: Failed password for root from \
      1.2.3.4 port 12345 ssh2
  Aug 17 04:12:34 host sshd[1234]: Accepted password for admin from \
      1.2.3.4 port 12345 ssh2   # SUCCESS — recorded but not flagged
  Aug 17 04:12:34 host sshd[1234]: Invalid user evil from 1.2.3.4
  Aug 17 04:12:34 host sudo: pam_unix(sudo:auth): authentication \
      failure; user=root tty=pts/0 ruser=root rhost= user=admin
  Aug 17 04:12:34 host sudo:    root : TTY=pts/0 ; PWD=/root ; \
      USER=admin ; COMMAND=/bin/bash
  Aug 17 04:12:34 host useradd[1234]: new user: name=evil, UID=0, \
      GID=0, home=/home/evil, shell=/bin/bash
  Aug 17 04:12:34 host groupadd[1234]: new group: name=evil, GID=0
  Aug 17 04:12:34 host passwd[1234]: password changed for user evil

Lines that don't match any of the recognised event shapes return None
(incremented as `malformed` by the analyzer — these are usually
informational syslog noise like cron lines).

The parser is intentionally case-sensitive on the service name
(`sshd`, `sudo`, `useradd`) because the upstream daemons emit those
lowercased; we don't want `SSHD[...]` from a noisy aggregator to be
classified as a real ssh event. The verb tokens (`Failed password`,
`Accepted password`, `authentication failure`, `new user`, etc.) ARE
matched case-insensitively to tolerate the rare capitalised variants.
"""

from __future__ import annotations

import re
from typing import NamedTuple, Optional


class SecureRecord(NamedTuple):
    """One classified syslog line.

    `event` is one of: `ssh_fail`, `ssh_accept`, `ssh_invalid_user`,
    `sudo_fail`, `sudo_success`, `useradd`, `groupadd`, `passwd_change`.
    Any other syslog line returns `None` from `parse_line`.

    For `ssh_fail` / `ssh_invalid_user` the `source_ip` is set; for
    `sudo_fail` the `user` (account attempting to run sudo) is set;
    for `useradd` / `groupadd` the `username` + `uid`/`gid` are set
    so the rules layer can escalate root-level creations.
    """

    event: str
    service: str  # "sshd", "sudo", "useradd", etc.
    source_ip: Optional[str]
    user: Optional[str]
    username: Optional[str]
    uid: Optional[int]
    gid: Optional[int]
    pid: Optional[int]
    raw: str
    raw_timestamp: str = ""


# Syslog timestamp header: "Aug 17 04:12:34.123456 2026" or the older
# "Aug 17 04:12:34". What we want is to anchor past the second
# occurrence of whitespace + non-space token (the hostname). We don't
# extract a full date — the analyzer runs over a single scan window so
# the timestamp is just diagnostic.
_TS_RE = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+"
    r"\S+\s+",
)

# "sshd[1234]:" service tag. Captures pid (may be None for `sudo:`).
_SERVICE_RE = re.compile(r"^(?P<svc>[a-zA-Z][\w-]*)(?:\[(?P<pid>\d+)\])?:\s*")

# "Failed password for invalid user admin from 1.2.3.4 port 12345 ssh2"
_SSH_FAIL_INVALID_RE = re.compile(
    r"Failed password for invalid user (?P<user>\S+)"
    r" from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|\S+) port \d+"
)

# "Failed password for root from 1.2.3.4 port 12345 ssh2"
_SSH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+)"
    r" from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|\S+) port \d+"
)

# "Accepted password for admin from 1.2.3.4 port 12345 ssh2"
_SSH_ACCEPT_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+)"
    r" from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|\S+) port \d+"
)

# "Invalid user evil from 1.2.3.4"
_SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|\S+)"
)

# sudo auth: "pam_unix(sudo:auth): authentication failure; user=root
# tty=pts/0 ruser=root rhost= user=admin"
# Some distros put `user=` mid-line; we tolerate either ordering.
_SUDO_FAIL_RE = re.compile(
    r"pam_unix\(sudo:auth\):\s+authentication failure;"
    r"(?:\s+\w+=[^\s;]+)*"
    r"\s+user=(?P<user>\S+)"
    r"(?:\s+\w+=[^\s;]+)*"
)

# useradd: "new user: name=evil, UID=0, GID=0, home=/home/evil, shell=/bin/bash"
_USERADD_RE = re.compile(
    r"new user:\s+name=(?P<name>[^,\s]+),"
    r"\s+UID=(?P<uid>\d+),\s+GID=(?P<gid>\d+)"
)

# groupadd: "new group: name=evil, GID=0"
_GROUPADD_RE = re.compile(
    r"new group:\s+name=(?P<name>[^,\s]+),\s+GID=(?P<gid>\d+)"
)

# passwd: "password changed for user evil"
_PASSWD_CHANGE_RE = re.compile(r"password changed for user (?P<name>\S+)")


def parse_line(line: str) -> SecureRecord | None:
    """Parse a single syslog line; return None for unclassified lines.

    The parser is forgiving about the timestamp prefix — it strips
    everything up to (and including) the service tag `sshd[NNN]:` and
    then matches the rest. Lines without a service tag (e.g. cron noise)
    return None.
    """
    # Drop the optional timestamp prefix to simplify the rest of the match.
    ts_match = _TS_RE.match(line)
    raw_ts = ts_match.group(0).strip() if ts_match else ""
    body = _TS_RE.sub("", line, count=1)
    svc_match = _SERVICE_RE.match(body)
    if not svc_match:
        return None
    service = svc_match.group("svc").lower()
    pid_str = svc_match.group("pid")
    pid = int(pid_str) if pid_str else None
    rest = body[svc_match.end():]

    # Strip the optional `pam_unix(...)` wrapper suffix lines that some
    # services add: `sudo: pam_unix(sudo:auth): ...`. We've already
    # captured `sudo` as the service; the wrapper just adds noise.

    if service == "sshd":
        m = _SSH_FAIL_INVALID_RE.search(rest)
        if m:
            return SecureRecord(
                event="ssh_fail",
                service="sshd",
                source_ip=m.group("ip"),
                user=m.group("user"),
                username=None,
                uid=None,
                gid=None,
                pid=pid,
                raw=line,
                raw_timestamp=raw_ts,
            )
        m = _SSH_FAIL_RE.search(rest)
        if m:
            return SecureRecord(
                event="ssh_fail",
                service="sshd",
                source_ip=m.group("ip"),
                user=m.group("user"),
                username=None,
                uid=None,
                gid=None,
                pid=pid,
                raw=line,
                raw_timestamp=raw_ts,
            )
        m = _SSH_ACCEPT_RE.search(rest)
        if m:
            return SecureRecord(
                event="ssh_accept",
                service="sshd",
                source_ip=m.group("ip"),
                user=m.group("user"),
                username=None,
                uid=None,
                gid=None,
                pid=pid,
                raw=line,
                raw_timestamp=raw_ts,
            )
        m = _SSH_INVALID_USER_RE.search(rest)
        if m:
            return SecureRecord(
                event="ssh_invalid_user",
                service="sshd",
                source_ip=m.group("ip"),
                user=m.group("user"),
                username=None,
                uid=None,
                gid=None,
                pid=pid,
                raw=line,
                raw_timestamp=raw_ts,
            )
        return None

    if service == "sudo":
        m = _SUDO_FAIL_RE.search(rest)
        if m:
            return SecureRecord(
                event="sudo_fail",
                service="sudo",
                source_ip=None,
                user=m.group("user"),
                username=None,
                uid=None,
                gid=None,
                pid=pid,
                raw=line,
                raw_timestamp=raw_ts,
            )
        # "COMMAND=..." in a sudo session line. Not flagged by itself.
        if "COMMAND=" in rest and "authentication failure" not in rest:
            return SecureRecord(
                event="sudo_success",
                service="sudo",
                source_ip=None,
                user=None,
                username=None,
                uid=None,
                gid=None,
                pid=pid,
                raw=line,
                raw_timestamp=raw_ts,
            )
        return None

    if service == "useradd":
        m = _USERADD_RE.search(rest)
        if m:
            return SecureRecord(
                event="useradd",
                service="useradd",
                source_ip=None,
                user=None,
                username=m.group("name"),
                uid=int(m.group("uid")),
                gid=int(m.group("gid")),
                pid=pid,
                raw=line,
                raw_timestamp=raw_ts,
            )
        return None

    if service == "groupadd":
        m = _GROUPADD_RE.search(rest)
        if m:
            return SecureRecord(
                event="groupadd",
                service="groupadd",
                source_ip=None,
                user=None,
                username=m.group("name"),
                uid=None,
                gid=int(m.group("gid")),
                pid=pid,
                raw=line,
                raw_timestamp=raw_ts,
            )
        return None

    if service == "passwd":
        m = _PASSWD_CHANGE_RE.search(rest)
        if m:
            return SecureRecord(
                event="passwd_change",
                service="passwd",
                source_ip=None,
                user=None,
                username=m.group("name"),
                uid=None,
                gid=None,
                pid=pid,
                raw=line,
                raw_timestamp=raw_ts,
            )
        return None

    return None