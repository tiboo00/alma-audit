"""CSF (ConfigServer Firewall) state analyzer.

Reads `/etc/csf/csf.deny` and `/etc/csf/csf.allow` and emits findings
about the block-list size and any sudden growth. CSF is the de-facto
host firewall on most cPanel servers; alma-audit deliberately does
NOT shell out to `csf -l` (read-only contract).

Detection contract:

  - **Denylist size** — the number of non-comment, non-empty lines in
    `csf.deny`. WARN if > `deny_count_warn`, CRITICAL if >
    `deny_count_crit`. A small denylist (< 50 entries) is normal; a
    several-thousand-entry denylist often means the host has been
    under sustained attack OR the operator forgot to expire old
    entries (CSF's `LF_TEMP` config).
  - **Sudden growth** — operators can pass a baseline count via the
    YAML config (`modules.csf_state.deny_baseline`). If the current
    denylist is `> baseline + deny_growth_warn`, WARN; if `>
    baseline + deny_growth_crit`, CRITICAL. This is the "trend" hook
    per GAPS §4 — a lightweight version of the trend sidecar that
    fits inside the analyzer package.
  - **Denylist / allowlist mismatch** — INFO summary listing the
    counts so operators can spot a denylist that's been emptied by
    accident (suddenly 0 entries, baseline 200).

This is a single-purpose module — no parser/aggregator/rules split
because the logic is < 80 LOC. If a second CSF file (e.g. `csf.temp`
or `csf.allow` rule analysis) grows the module past 100 lines, split
per GAPS §7.3.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..models import Finding, Severity
from ..runners import FileSystem

_LOG = logging.getLogger("alma_audit")

# A "real" CSF entry is either an IPv4 dotted quad, an IPv6 literal,
# or a CIDR (one of the above with `/N` suffix). Comments start with
# `#` and empty lines are skipped. We accept any non-empty,
# non-comment line for permissive counting — CSF can also carry a
# few human-friendly notations like `Include /etc/csf/csf.blocklist`.
_CIDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}|\S+:\S+)(/\d+)?(\s|$)")
_COMMENT_RE = re.compile(r"^\s*#")
_INCLUDE_RE = re.compile(r"^\s*Include\s+", re.IGNORECASE)


def _count_entries(lines: list[str]) -> tuple[int, list[str]]:
    """Return (entry_count, malformed_sample).

    A "valid" entry is a non-empty, non-comment line that begins with
    what looks like an IP / CIDR. Lines that don't fit either pattern
    are added to `malformed_sample` (capped at 5) so the analyzer can
    surface a soft WARN when the format drifts.
    """
    count = 0
    malformed: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if _COMMENT_RE.match(line):
            continue
        if _INCLUDE_RE.match(line):
            # CSF supports `Include /etc/csf/csf.blocklist` to chain
            # extra blocklists. We don't recurse — that's a script,
            # not a parser. Count it as one entry.
            count += 1
            continue
        if _CIDR_RE.match(line):
            count += 1
            continue
        malformed.append(line)
        if len(malformed) >= 5:
            break
    return count, malformed


def analyze_csf_state(
    deny_paths: list[str],
    allow_paths: list[str],
    fs: FileSystem,
    rules: dict[str, Any] | None = None,
) -> list[Finding]:
    """Read CSF state files and emit findings.

    `deny_paths` should normally be `["/etc/csf/csf.deny"]`; we accept
    a list so an operator with split CSF configs (multi-host clusters)
    can point the analyzer at multiple files. `allow_paths` follows
    the same convention.
    """
    settings = {
        "deny_count_warn": 200,
        "deny_count_crit": 2000,
        "deny_growth_warn": 100,
        "deny_growth_crit": 500,
        "deny_baseline": None,
        **(rules or {}),
    }
    findings: list[Finding] = []

    deny_total = 0
    deny_files_scanned = 0
    deny_malformed: list[str] = []
    for path in deny_paths:
        if not fs.is_file(path):
            continue
        deny_files_scanned += 1
        try:
            lines = fs.open_text(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            _LOG.warning("csf_state: open_text(%s) failed: %s", path, exc)
            continue
        count, malformed = _count_entries(lines)
        deny_total += count
        deny_malformed.extend(malformed)

    allow_total = 0
    allow_files_scanned = 0
    for path in allow_paths:
        if not fs.is_file(path):
            continue
        allow_files_scanned += 1
        try:
            lines = fs.open_text(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            _LOG.warning("csf_state: open_text(%s) failed: %s", path, exc)
            continue
        count, _ = _count_entries(lines)
        allow_total += count

    if deny_files_scanned == 0 and allow_files_scanned == 0:
        findings.append(Finding(
            module="csf_state",
            severity=Severity.INFO,
            title="No CSF state files found",
            description=(
                "Neither /etc/csf/csf.deny nor /etc/csf/csf.allow were "
                "found on this host. Either CSF is not installed, or "
                "the audit user cannot see the directory."
            ),
            details={"deny_paths": list(deny_paths), "allow_paths": list(allow_paths)},
        ))
        return findings

    # ---- INFO summary ----
    findings.append(Finding(
        module="csf_state",
        severity=Severity.INFO,
        title=(
            f"CSF state: deny={deny_total}, allow={allow_total} "
            f"({deny_files_scanned} deny file(s), "
            f"{allow_files_scanned} allow file(s))"
        ),
        description="CSF denylist + allowlist counts captured.",
        details={
            "deny_files_scanned": deny_files_scanned,
            "allow_files_scanned": allow_files_scanned,
            "deny_count": deny_total,
            "allow_count": allow_total,
            "baseline": settings.get("deny_baseline"),
        },
    ))

    # ---- D17 — denylist size ----
    if deny_files_scanned > 0:
        if deny_total >= settings["deny_count_crit"]:
            sev = Severity.CRITICAL
        elif deny_total >= settings["deny_count_warn"]:
            sev = Severity.WARN
        else:
            sev = None
        if sev is not None:
            findings.append(Finding(
                module="csf_state",
                severity=sev,
                title=f"CSF denylist size is {deny_total}",
                description=(
                    f"csf.deny contains {deny_total} active entries "
                    "(above the operator-configured threshold). On a "
                    "well-managed host this is usually < 200; a "
                    "several-thousand entry denylist often means the "
                    "host has been under sustained attack OR the "
                    "operator forgot to expire old entries "
                    "(CSF LF_TEMP)."
                ),
                details={
                    "deny_count": deny_total,
                    "threshold_warn": settings["deny_count_warn"],
                    "threshold_crit": settings["deny_count_crit"],
                },
                recommendation=(
                    "Audit the denylist with `csf -l` (the toolkit "
                    "won't do this — it would break the read-only "
                    "contract). Consider lowering LF_TEMP to expire "
                    "stale entries automatically."
                ),
            ))

    # ---- D18 — sudden growth vs baseline ----
    baseline = settings.get("deny_baseline")
    if isinstance(baseline, (int, float)) and baseline >= 0 and deny_files_scanned > 0:
        delta = deny_total - baseline
        if delta >= settings["deny_growth_crit"]:
            sev = Severity.CRITICAL
        elif delta >= settings["deny_growth_warn"]:
            sev = Severity.WARN
        else:
            sev = None
        if sev is not None:
            findings.append(Finding(
                module="csf_state",
                severity=sev,
                title=f"CSF denylist grew by {delta} since baseline ({baseline} → {deny_total})",
                description=(
                    f"Denylist grew from baseline {baseline} to current "
                    f"{deny_total} (delta +{delta}). On a hardened "
                    "host, sustained growth of more than a few "
                    "hundred entries per scan window is unusual."
                ),
                details={
                    "baseline": baseline,
                    "current": deny_total,
                    "delta": delta,
                    "threshold_warn": settings["deny_growth_warn"],
                    "threshold_crit": settings["deny_growth_crit"],
                },
                recommendation=(
                    "Correlate the spike with the access_log / "
                    "modsec_log / cphulk_log findings from the same "
                    "window; an expected spike after a known "
                    "credential-stuffing campaign is normal."
                ),
            ))
        elif delta < 0:
            # Sudden shrinkage — operator probably ran `csf -f` or
            # rotated. INFO so the operator can confirm it was
            # expected.
            findings.append(Finding(
                module="csf_state",
                severity=Severity.INFO,
                title=f"CSF denylist shrank by {abs(delta)} since baseline ({baseline} → {deny_total})",
                description=(
                    f"Denylist shrank from baseline {baseline} to "
                    f"current {deny_total} (delta {delta}). Could be "
                    "an operator `csf -f` flush, a CSF rotation, or "
                    "an accidental wipe."
                ),
                details={"baseline": baseline, "current": deny_total, "delta": delta},
            ))

    # ---- D19 — malformed entries ----
    if deny_malformed:
        findings.append(Finding(
            module="csf_state",
            severity=Severity.WARN,
            title=f"{len(deny_malformed)} CSF denylist line(s) had unexpected format",
            description=(
                "One or more lines in `csf.deny` did not parse as an "
                "IP / CIDR / Include. CSF is tolerant of arbitrary "
                "text in the file but operators should know when the "
                "format drifts."
            ),
            details={"malformed_sample": deny_malformed},
            recommendation=(
                "Inspect csf.deny for typos or pasted comments. The "
                "Include directive is supported — the parser counts "
                "it but does not recurse into the linked file."
            ),
        ))

    return findings