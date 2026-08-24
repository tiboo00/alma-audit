"""Public entry point for the ``error_log`` analyzer (AISO-211).

Orchestrates the parser, aggregator, and rules. Reads files via the
injected ``FileSystem`` (read-only contract enforced upstream),
respects ``max_files`` and ``max_lines_per_file`` caps, and dispatches
the summary + per-(client, template) burst rules.

The analyzer is OPT-IN: ``modules.error_log.enabled`` must be True
for ``analyze_error_log`` to emit any findings. When disabled (the
default) the function returns ``[]`` silently so the audit scope
stays unchanged for hosts that don't have an ``error_log`` file or
operators who haven't explicitly opted in.

External callers import ``analyze_error_log`` from this module; the
package re-exports the public API in ``__init__.py``.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from ...models import Finding, Severity
from ...runners import FileSystem
from .aggregator import ErrorAggregator
from .parser import parse_error_line
from .rules import all_findings
from .settings import DEFAULT_RULES, is_compressed

_LOG = logging.getLogger("alma_audit")


def analyze_error_log(
    paths: Iterable[str],
    fs: FileSystem,
    rules: dict[str, Any] | None = None,
) -> list[Finding]:
    """Run the Apache ``error_log`` analyzer across ``paths``.

    Returns an empty list when ``modules.error_log.enabled`` is False
    (the default) — the analyzer is opt-in to preserve the audit's
    scope for hosts without ``error_log``. When enabled, emits:

    - INFO summary finding (with top 10 clients + top 10 message
      templates)
    - One CRITICAL finding per (client, template) burst exceeding
      ``message_burst_crit`` (default 100)

    ``paths`` is an iterable of file paths. Files whose names end in
    ``.gz`` / ``.bz2`` / ``.xz`` / ``.zst`` / ``.lz4`` are skipped
    silently (the read-only contract forbids shelling out to
    decompressors); the skipped paths are recorded in the summary's
    ``skipped_compressed`` detail.
    """
    settings = {**DEFAULT_RULES, **(rules or {})}
    # AISO-211: opt-in gate. The analyzer is disabled by default to
    # keep the audit's scope unchanged for hosts that don't have an
    # error_log file. When disabled, return [] silently — the
    # operator hasn't enabled the analyzer, so its absence is quiet.
    if not settings.get("enabled", False):
        return []
    cap = settings["max_lines_per_file"] or None
    agg = ErrorAggregator()
    files_scanned = 0
    skipped_compressed: list[str] = []
    unreadable: list[tuple[str, str]] = []  # (path, error str)

    for path in paths:
        if is_compressed(path):
            skipped_compressed.append(path)
            continue
        if not fs.is_file(path):
            continue
        # Honour the file cap BEFORE opening — same contract as
        # secure_log (AISO-186).
        if files_scanned >= settings["max_files"]:
            break
        files_scanned += 1
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
            line_clean = line.strip()
            if not line_clean:
                continue
            record = parse_error_line(line_clean)
            if record is None:
                agg.note_malformed()
                continue
            agg.add(record)

    findings: list[Finding] = []
    if files_scanned == 0 and not skipped_compressed and not unreadable:
        # No files matched, no unreadable ones, no compressed
        # rotations — pure "missing log file" case. Quiet INFO so
        # the operator sees the analyzer ran but found nothing to
        # scan. This mirrors the secure_log analyzer's empty-input
        # branch.
        return [Finding(
            module="error_log",
            severity=Severity.INFO,
            title="No error_log files matched",
            description=(
                "No `/var/log/apache2/error_log*` files were found. "
                "Either Apache is logging to a non-standard location "
                "or the audit user cannot see these files."
            ),
            details={"scanned_paths": list(paths)},
        )]

    findings.extend(all_findings(
        agg,
        files_scanned,
        settings,
        skipped_compressed=skipped_compressed,
        unreadable=unreadable,
    ))

    # Surface unreadable files as a structured WARN. The summary
    # finding already lists them in `details` for grep-ability; the
    # WARN is the cron-friendly signal so operators don't miss
    # "the file existed but couldn't be read".
    if unreadable:
        findings.append(Finding(
            module="error_log",
            severity=Severity.WARN,
            title=f"{len(unreadable)} error_log file(s) could not be read",
            description=(
                "One or more `/var/log/apache2/error_log*` files "
                "were present but the audit user could not read them "
                "(typically a permission problem). The scan continued "
                "with the readable files; coverage for the unreadable "
                "range is incomplete."
            ),
            details={
                "unreadable": [{"path": p, "error": e} for p, e in unreadable],
            },
            recommendation=(
                "Grant the audit service account targeted read access "
                "on the affected log paths (POSIX ACLs scoped to a "
                "dedicated `alma-audit` group is the recommended "
                "pattern — see the secure_log analyzer's WARN "
                "recommendation for the full rotation-safe recipe)."
            ),
        ))

    return findings


__all__ = ["analyze_error_log"]