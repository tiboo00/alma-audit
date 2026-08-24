"""Public entry point for the cphulk_log analyzer.

Orchestrates the parser, aggregator, and rules. Reads files via the
injected `FileSystem` (read-only contract enforced upstream), respects
`max_files` and `max_lines_per_file` caps, and dispatches the three
rules in D14/D15/D16 order. Returns a flat list of `Finding`.

External callers import `analyze_cphulk_logs` from this module; the
package re-exports the public API in `__init__.py`.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from ...models import Finding, Severity
from ...runners import FileSystem
from .aggregator import CphulkAggregator
from .parser import parse_line
from .rules import (
    rule_block_summary,
    rule_brute_force_by_ip,
    rule_brute_force_by_user,
)
from .settings import DEFAULT_RULES, is_compressed

_LOG = logging.getLogger("alma_audit")


def analyze_cphulk_logs(
    paths: Iterable[str],
    fs: FileSystem,
    rules: dict[str, Any] | None = None,
) -> list[Finding]:
    """Run the cphulk_log analyzer across `paths` and emit findings."""
    settings = {**DEFAULT_RULES, **(rules or {})}
    cap = settings["max_lines_per_file"] or None
    agg = CphulkAggregator()
    files_scanned = 0
    skipped_compressed: list[str] = []
    unreadable: list[tuple[str, str]] = []  # (path, error str)

    for path in paths:
        if is_compressed(path):
            skipped_compressed.append(path)
            continue
        if not fs.is_file(path):
            continue
        # Honour the cap BEFORE reading the file.
        if files_scanned >= settings["max_files"]:
            break
        files_scanned += 1
        # Use `read_text` (strict) so permission denied / I/O error
        # surfaces here, not silently as "0 lines". Compressed
        # rotations raise FileNotFoundError (treated as out-of-scope,
        # not as "unreadable") — see `runners.read_text`.
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
                line_clean = line.strip()
                if line_clean:
                    agg.note_malformed()
                continue
            agg.add(record)

    findings: list[Finding] = []
    if files_scanned == 0 and not skipped_compressed and not unreadable:
        # No files at all, no unreadable ones — pure "missing log
        # file" case. Quiet INFO.
        findings.append(Finding(
            module="cphulk_log",
            severity=Severity.INFO,
            title="No cPHulk log files matched",
            description=(
                "No `/var/log/cphulkd.log*` files were found. "
                "Either cPHulk is disabled on this host, or the "
                "audit user cannot see the log."
            ),
            details={"scanned_paths": list(paths)},
        ))
        return findings

    summary = agg.finalize()
    findings.append(Finding(
        module="cphulk_log",
        severity=Severity.INFO,
        title=(
            f"Scanned {files_scanned} cphulkd.log file(s), "
            f"{summary['classified_lines']} classified line(s)"
        ),
        description="cPHulk log scan complete.",
        details={
            "files_scanned": files_scanned,
            "skipped_compressed": skipped_compressed,
            "unreadable": [{"path": p, "error": e} for p, e in unreadable],
            **summary,
        },
    ))

    findings.extend(rule_brute_force_by_ip(agg, settings))
    findings.extend(rule_brute_force_by_user(agg, settings))
    findings.extend(rule_block_summary(agg))

    # Surface unreadable files as a structured WARN — same contract
    # as the secure_log analyzer. Cron-friendly signal that the file
    # existed but couldn't be read.
    if unreadable:
        findings.append(Finding(
            module="cphulk_log",
            severity=Severity.WARN,
            title=f"{len(unreadable)} cphulkd.log file(s) could not be read",
            description=(
                "One or more `/var/log/cphulkd.log*` files were present "
                "but the audit user could not read them (typically a "
                "permission problem). The scan continued with the "
                "readable files; brute-force coverage for the "
                "unreadable range is incomplete."
            ),
            details={
                "unreadable": [{"path": p, "error": e} for p, e in unreadable],
            },
            recommendation=(
                "Grant the audit service account targeted read access "
                "on the affected cphulkd log. The recommended pattern "
                "is a dedicated `alma-audit` group that owns nothing "
                "else, then POSIX ACLs scoped to that group only:\n"
                "\n"
                "    groupadd alma-audit\n"
                "    usermod -aG alma-audit alma-audit-user\n"
                "    setfacl -m g:alma-audit:r /var/log/cphulkd.log\n"
                "\n"
                "**Rotations**: do NOT apply a default ACL on `/var/log` "
                "(e.g. `setfacl -d -m g:alma-audit:r /var/log`) — that "
                "would inherit `alma-audit:r` to every new file created "
                "under `/var/log`, leaking future log access. Instead, "
                "wire a `logrotate` directive so each rotated copy is "
                "tagged explicitly. cPHulk's own logrotate entry on "
                "RHEL/cPanel is `/etc/logrotate.d/cphulkd`; append a "
                "matching `alma-audit` block (or your own):\n"
                "\n"
                "    # /etc/logrotate.d/alma-audit\n"
                "    /var/log/cphulkd.log {\n"
                "        daily\n"
                "        create 0640 root alma-audit\n"
                "        sharedscripts\n"
                "        postrotate\n"
                "            /usr/bin/setfacl -m g:alma-audit:r "
                "/var/log/cphulkd.log /var/log/cphulkd.log.* "
                "2>/dev/null || true\n"
                "        endscript\n"
                "    }\n"
                "\n"
                "The `create 0640 root alma-audit` line makes new files "
                "group-readable by the `alma-audit` group from the "
                "moment of creation; the `postrotate` re-applies the "
                "ACL to `*.1`, `*.2.gz`, etc. where `create` does not "
                "run.\n"
                "\n"
                "Avoid membership in `cpanel` or `wheel` — those "
                "groups grant write access to the log file (and "
                "in `wheel`'s case, full sudo). cphulkd.log carries "
                "credential-stuffing source IPs that should not be "
                "readable by every member of those groups."
            ),
        ))

    return findings