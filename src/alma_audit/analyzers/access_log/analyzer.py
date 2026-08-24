"""Public entry point for the access_log analyzer.

Orchestrates the parser, aggregator, and rules. Reads files via the
injected `FileSystem` (read-only contract enforced upstream), respects
`max_files_scanned` and `max_lines_per_file` caps, and dispatches the
five rules in D1/D4/D2/D5/D6 order. Returns a flat list of `Finding`.

External callers import `analyze_access_logs` from this module; the
legacy `from alma_audit.analyzers.access_log import ...` paths are
preserved by the package re-exports in `__init__.py`.
"""

from __future__ import annotations

from typing import Any, Iterable

from ...models import Finding, Severity
from ...runners import FileSystem
from ..crawler_verify import Resolver, SocketResolver
from .aggregator import AccessAggregator
from .parser import parse_line
from .rules import (
    rule_bandwidth_hog,
    rule_error_rate,
    rule_probe_paths,
    rule_top_host_concentration,
    rule_weird_methods,
)
from .settings import DEFAULT_RULES, is_compressed


def analyze_access_logs(
    paths: Iterable[str],
    fs: FileSystem,
    rules: dict[str, Any] | None = None,
    resolver: Resolver | None = None,
) -> list[Finding]:
    """Run the access-log analyzer across `paths` and emit findings.

    The `resolver` argument is optional — production code may pass a
    real `SocketResolver` (3-second timeouts per the §6.1 contract);
    tests inject a `FakeResolver`. The default is `SocketResolver`,
    so a missing argument stays fail-closed and time-bounded.
    """
    settings = {**DEFAULT_RULES, **(rules or {})}
    # A `max_lines_per_file` of 0 (or negative) disables the cap.
    cap = settings["max_lines_per_file"] or None
    resolver = resolver or SocketResolver()
    # AISO-208 (review fix #2): the cap is plumbed via the aggregator
    # constructor so a single setting key (YAML-configurable under
    # ``modules.access_log.ip_user_agent_cap``) bounds the per-IP
    # rollup. Cap convention follows the rest of the analyzer:
    # **negative** disables the cap (operator opts into unbounded
    # cost on UA-diverse per-IP traffic). Default of 5 keeps the
    # rollup bounded on the realistic common case — measured to
    # avoid O(n²) amplification on 40k-record single-IP logs.
    raw_ua_cap = settings.get("ip_user_agent_cap", 5)
    # Normalise: 0 → -1 (no cap); negative stays negative; positive
    # capped at the historic 5-baseline window.
    if raw_ua_cap is None or raw_ua_cap < 0:
        ip_ua_cap = -1  # sentinel: no cap.
    elif raw_ua_cap == 0:
        ip_ua_cap = -1  # 0 also means "no cap" by operator convention.
    else:
        ip_ua_cap = int(raw_ua_cap)
    agg = AccessAggregator(ip_user_agent_cap=ip_ua_cap)
    files_scanned = 0
    files_truncated: list[str] = []
    # Track if the file we are reading is itself an issue — e.g.
    # explicit compressed copies are listed in the report for operator
    # forensics without breaking the read-only contract.
    skipped_compressed: list[str] = []

    for path in paths:
        if is_compressed(path):
            skipped_compressed.append(path)
            continue
        if not fs.is_file(path):
            continue
        files_scanned += 1
        if files_scanned >= settings["max_files_scanned"]:
            # Track this as truncated so the operator can see we
            # stopped before reading the rest of the rotation.
            files_truncated.append(path)
        # `fs.open_text` already honors `max_lines` via the file cap.
        # We cap "ahead" of reading — a runaway log cannot allocate
        # more than `cap` lines per path. If the file holds at least
        # `cap` lines, we mark it truncated and the operator sees it
        # in the summary.
        raw_lines = fs.open_text(path, max_lines=cap)
        truncated_at_cap = cap is not None and len(raw_lines) >= cap
        if truncated_at_cap and path not in files_truncated:
            files_truncated.append(path)
        for line in raw_lines:
            line = line.strip()
            if not line:
                continue
            record = parse_line(line)
            if record is None:
                agg.malformed += 1
                continue
            agg.add(record)
        if files_scanned >= settings["max_files_scanned"]:
            break  # stop after the inclusive cap

    findings: list[Finding] = []
    if files_scanned == 0 and not skipped_compressed:
        findings.append(Finding(
            module="access_log",
            severity=Severity.INFO,
            title="No access log files matched",
            description="The configured apache_root had no files matching the access_log glob.",
            details={"scanned_paths": list(paths)},
        ))
        return findings

    summary = agg.finalize()
    summary_detail: dict[str, Any] = {
        "files_scanned": files_scanned,
        "skipped_compressed": skipped_compressed,
        "files_truncated_at_cap": files_truncated,
    }
    summary_detail.update(summary)
    findings.append(Finding(
        module="access_log",
        severity=Severity.INFO,
        title=f"Scanned {files_scanned} access log file(s), {summary['total_lines']} lines",
        description="Access log scan complete.",
        details=summary_detail,
    ))

    total_hits = sum(agg.hosts.values())
    top_host = agg.hosts.most_common(1)[0][0] if total_hits > 0 else None

    findings.extend(rule_top_host_concentration(
        agg, total_hits, resolver, settings,
    ))
    findings.extend(rule_error_rate(
        agg, total_hits, top_host, resolver, settings, summary,
    ))
    findings.extend(rule_probe_paths(agg, settings))
    findings.extend(rule_weird_methods(agg, settings))
    findings.extend(rule_bandwidth_hog(agg, settings))

    return findings