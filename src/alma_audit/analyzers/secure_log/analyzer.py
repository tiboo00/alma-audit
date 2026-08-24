"""Public entry point for the secure_log analyzer.

Orchestrates the parser, aggregator, and rules. Reads files via the
injected `FileSystem` (read-only contract enforced upstream), respects
`max_files` and `max_lines_per_file` caps, and dispatches the four
rules in D8/D9/D10/D11 order. Returns a flat list of `Finding`.

External callers import `analyze_secure_logs` from this module; the
package re-exports the public API in `__init__.py`.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from ...models import Finding, Severity
from ...runners import FileSystem
from .aggregator import SecureAggregator
from .parser import parse_line
from .rules import (
    rule_any_user_change,
    rule_new_root_account,
    rule_ssh_brute_force,
    rule_sudo_failures,
)
from .settings import DEFAULT_RULES, is_compressed

_LOG = logging.getLogger("alma_audit")


def analyze_secure_logs(
    paths: Iterable[str],
    fs: FileSystem,
    rules: dict[str, Any] | None = None,
    *,
    self_ips: set[str] | None = None,
) -> list[Finding]:
    """Run the secure/auth.log analyzer across `paths` and emit findings.

    `self_ips` is the host's own IP set (AISO-201). SSH fail events from
    these IPs are skipped in the brute-force counters — a cPanel
    server's cron / monitoring / internal-service self-logins would
    otherwise flood the report. The forensic JSON still records the
    event so the operator can audit it.
    """
    settings = {**DEFAULT_RULES, **(rules or {})}
    cap = settings["max_lines_per_file"] or None
    agg = SecureAggregator(self_ips=self_ips or set())
    files_scanned = 0
    skipped_compressed: list[str] = []
    unreadable: list[tuple[str, str]] = []  # (path, error str)

    for path in paths:
        if is_compressed(path):
            skipped_compressed.append(path)
            continue
        if not fs.is_file(path):
            continue
        # Honour the cap BEFORE reading the file. The pre-increment
        # check guarantees `files_scanned` is the actual number of
        # files opened, not "files attempted" (which would include
        # the one we skipped).
        if files_scanned >= settings["max_files"]:
            break
        files_scanned += 1
        # Use the strict `read_text` (vs. permissive `open_text`) so
        # permission denied / I/O error surfaces here, not silently
        # as "0 lines". A swallowed-OSError read_text returns `[]` for
        # compressed rotations (treated as out-of-scope, not as
        # "unreadable"), so we still record the file as scanned.
        try:
            raw_lines = fs.read_text(path, max_lines=cap)
        except FileNotFoundError:
            files_scanned -= 1
            continue
        except OSError as exc:
            unreadable.append((path, str(exc)))
            files_scanned -= 1
            continue
        for line in raw_lines:
            record = parse_line(line)
            if record is None:
                # Don't count a line as malformed until we've actually
                # failed to classify a service-tag line; pure noise
                # like `cron: ...` shouldn't pollute the counter.
                # parse_line returns None for both noise and unknown
                # service-tagged lines. We treat any non-empty line
                # with a service tag as a candidate; the parser
                # already returns None for both. The contract is that
                # the parser is exact: the counter is bumped only when
                # a line was attempted and rejected, which is what
                # `agg.note_malformed` records. To keep that contract
                # honest we count ALL non-empty lines that failed to
                # classify — the operator sees the ratio in the
                # summary finding.
                line_clean = line.strip()
                if line_clean:
                    agg.note_malformed()
                continue
            agg.add(record)

    findings: list[Finding] = []
    if files_scanned == 0 and not skipped_compressed and not unreadable:
        # No files at all, no unreadable ones — pure "missing log
        # file" case (e.g. syslog isn't writing here). Quiet INFO.
        findings.append(Finding(
            module="secure_log",
            severity=Severity.INFO,
            title="No secure/auth log files matched",
            description=(
                "No `/var/log/secure*` or `/var/log/auth.log*` files "
                "were found. Either syslog is configured to log "
                "elsewhere, or the audit user cannot see these files."
            ),
            details={"scanned_paths": list(paths)},
        ))
        return findings

    summary = agg.finalize()
    findings.append(Finding(
        module="secure_log",
        severity=Severity.INFO,
        title=(
            f"Scanned {files_scanned} secure/auth log file(s), "
            f"{summary['classified_lines']} classified line(s)"
        ),
        description="Secure/auth log scan complete.",
        details={
            "files_scanned": files_scanned,
            "skipped_compressed": skipped_compressed,
            "unreadable": [{"path": p, "error": e} for p, e in unreadable],
            **summary,
        },
    ))

    # Order: brute-force first (most common), then sudo, then the
    # always-CRITICAL root-account rule, then the catch-all
    # account-change summary.
    findings.extend(rule_ssh_brute_force(agg, settings))
    findings.extend(rule_sudo_failures(agg, settings))
    findings.extend(rule_new_root_account(agg, settings))
    findings.extend(rule_any_user_change(agg))

    # Surface unreadable files as a structured WARN. The summary
    # finding above already lists them in `details` for grep-ability;
    # the WARN is the cron-friendly signal so operators don't miss
    # "the file existed but couldn't be read" because of a silent INFO.
    if unreadable:
        findings.append(Finding(
            module="secure_log",
            severity=Severity.WARN,
            title=f"{len(unreadable)} secure/auth log file(s) could not be read",
            description=(
                "One or more `/var/log/secure*` or `/var/log/auth.log*` "
                "files were present but the audit user could not read "
                "them (typically a permission problem). The scan "
                "continued with the readable files; coverage for the "
                "unreadable range is incomplete."
            ),
            details={
                "unreadable": [{"path": p, "error": e} for p, e in unreadable],
            },
            recommendation=(
                "Grant the audit service account targeted read access "
                "on the affected log paths. The recommended pattern "
                "is a dedicated `alma-audit` group that owns nothing "
                "else, then POSIX ACLs scoped to that group only:\n"
                "\n"
                "    groupadd alma-audit\n"
                "    usermod -aG alma-audit alma-audit-user\n"
                "    setfacl -m g:alma-audit:r /var/log/secure\n"
                "    setfacl -m g:alma-audit:r /var/log/auth.log\n"
                "\n"
                "**Rotations**: do NOT apply a default ACL on `/var/log` "
                "(e.g. `setfacl -d -m g:alma-audit:r /var/log`) — that "
                "would inherit `alma-audit:r` to every new file created "
                "under `/var/log`, leaking future log access. Instead, "
                "modify the **existing** `logrotate` stanza that already "
                "owns the path (RHEL/rsyslog ships `/var/log/secure` and "
                "`/var/log/auth.log` under `/etc/logrotate.d/syslog`), "
                "preserve its retention / compression / service-reopen "
                "directives, and re-apply the ACL inside its existing "
                "`postrotate`/`lastaction` branch on both the live file "
                "and the `*.1`, `*.2.gz`, ... copies. Do **not** add a "
                "second stanza for the same path — `logrotate` rejects "
                "duplicate entries with `error: duplicate log entry` "
                "and exit 1, and a second block would override the "
                "service's own rotation policy and reopen hooks (so "
                "`rsyslog` would keep writing to a rotated inode). "
                "After editing, validate with `logrotate -d` to confirm "
                "there is no duplicate entry.\n"
                "\n"
                "Avoid blanket `chmod a+r` and broad system groups "
                "(`adm`, `wheel`) — `/var/log/secure*` and "
                "`/var/log/auth.log*` carry credential and session "
                "data that should not be readable by every local "
                "user account."
            ),
        ))

    return findings