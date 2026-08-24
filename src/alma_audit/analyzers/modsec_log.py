"""Apache error_log + ModSecurity audit scanner.

ModSecurity audit logs are a sequence of "sections" delimited by lines
that look like:

    ---(.*?)---A--[timestamp]

where the letters between dashes describe the section type (request
headers A, response headers B, etc.). The most useful single line in
each request is the "H" message line:

    Message: Access denied with code 403 ...
    [file "/etc/modsecurity/owasp/crs/REQUEST-942-...sql-injection.conf"]
    [line "12"] [id "942100"] [rev ...] [msg "SQL Injection Attack"]
    [data "..."] [severity "CRITICAL"] [ver ...] ...

We parse:

  - Apache error_log: timestamps + severity + pid + message.
  - ModSecurity audit:  per-request action (deny/drop), the matched
    rule ID(s), and the highest severity seen.

Rules of thumb:
  - 5xx in error_log > threshold → WARN/CRITICAL (server-side issues).
  - ModSecurity `deny` or `drop` ≥ threshold → WARN/CRITICAL.
  - Any rule with severity=CRITICAL is escalated.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Iterable

from ..models import Finding, Severity
from ..runners import FileSystem

# Apache error_log default format:
#   [Sun Aug 17 04:12:34.123456 2026] [core:error] [pid 12345] ...
_ERR_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+"
    r"\[(?P<module>[^:\]]+):(?P<level>\w+)\]\s+"
    r"(?:\[pid\s+(?P<pid>\d+)\]\s+)?"
    r"(?P<msg>.*)$"
)

# ModSecurity section header. Real ModSecurity emits hex IDs with a
# single '-' separator: --ABCDEFGH-A--. Some downstream rotators
# lowercase the IDs; accept both. The captured group is the section
# letter so the iterator can decide whether to flush.
_MODSEC_HEADER_RE = re.compile(r"^--[A-Fa-f0-9]+-([A-Z])--$")

# A single ModSecurity "field" — `[key "value"]` (the common quoted form).
# Real audit logs pack many of these onto one line:
#   [line "12"] [id "942100"] [rev "1"] [msg "SQL Injection"] [severity "CRITICAL"]
# We extract them ALL, not just the first.
_FIELD_RE = re.compile(r"\[(?P<key>[^\]\s]+)\s+\"(?P<value>[^\"]*)\"\]")
# Fallback for unquoted values (rare; e.g. `[line 12]` in some setups).
_FIELD_UNQUOTED_RE = re.compile(r"\[(?P<key>[^\]\s]+)\s+(?P<value>\S+?)\]")

# "Message: ..." line — used to detect an implicit deny when no Action: present.
_MSG_RE = re.compile(r"^Message:\s*(?P<msg>.*)$")

# Action line — ModSecurity prints "Action: Intercepted (phase 1)".
_ACTION_RE = re.compile(r"^Action:\s*(?P<a>\w+)")

# B-section request line: `GET /.env HTTP/1.1`, `POST /wp-login.php HTTP/1.1`,
# etc. Captures the request URI only (no method, no protocol). AISO-205 uses
# this to attribute each ModSecurity rule hit back to the request that fired
# it, so the operator can see "942100 fired 80% of the time on /login.php".
# The URI may contain query strings, percent-encoded bytes, and is truncated
# at whitespace — we never decode it here (audit-side normalization is the
# reporting layer's job, not the parser's).
_B_REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/[\d.]+$")

# AISO-205: the breakdown payload is bounded so the report JSON + MD stay
# scannable on a long-tail CRS install. Ten is enough for the operator's
# "what rule is firing" eye-view without flooding the page.
_BREAKDOWN_TOP_N = 10


class ModSecAggregator:
    """Streaming aggregator for a single ModSecurity audit file."""

    def __init__(self) -> None:
        self.requests = 0
        self.actions: Counter[str] = Counter()
        self.rule_ids: Counter[str] = Counter()
        # AISO-205: per-rule "first URI seen" map. Only the first hit
        # sticks — later repeat-scanner hits for the same rule do not
        # overwrite it. Keeps the operator-facing top-URI stable.
        self._first_uri_by_rule: dict[str, str] = {}
        self.max_severity: int = 0  # 0=none, 2=CRITICAL, 1=WARN, else notice
        self.critical_hits: list[dict[str, Any]] = []

    def add_request(
        self,
        action: str,
        ids: Iterable[str],
        max_sev: int,
        uri: str = "",
    ) -> None:
        self.requests += 1
        if action:
            self.actions[action] += 1
        for rid in ids:
            self.rule_ids[rid] += 1
            if uri and rid not in self._first_uri_by_rule:
                self._first_uri_by_rule[rid] = uri
        if max_sev > self.max_severity:
            self.max_severity = max_sev
        if max_sev >= 2:
            self.critical_hits.append({
                "action": action,
                "ids": list(ids),
                "severity": max_sev,
            })

    def finalize(self) -> dict[str, Any]:
        # AISO-205: rule → count → top_uri, sorted by count desc, with
        # rule_id asc as the deterministic tie-breaker (matches how the
        # access_log / secure_log aggregators break ties elsewhere — see
        # GAPS §7.4 "ordering invariants"). `top_rule_ids` and
        # `modsec_rule_breakdown` must agree on ordering — otherwise the
        # operator dashboard sees two different "top" lists for the
        # same data and has to reconcile them by hand.
        ranked = sorted(
            self.rule_ids.items(),
            key=lambda kv: (-kv[1], kv[0]),
        )
        top_rule_ids = [(rule_id, count) for rule_id, count in ranked[:_BREAKDOWN_TOP_N]]
        breakdown: list[tuple[str, int, str]] = [
            (rule_id, count, self._first_uri_by_rule.get(rule_id, ""))
            for rule_id, count in ranked[:_BREAKDOWN_TOP_N]
        ]
        return {
            "requests_total": self.requests,
            "actions": dict(self.actions),
            "top_rule_ids": top_rule_ids,
            "modsec_rule_breakdown": breakdown,
            "max_severity_seen": self.max_severity,
            "critical_hit_count": len(self.critical_hits),
        }


def _parse_modsec_request(lines: list[str]) -> tuple[str, list[str], int, str]:
    """Parse a single ModSecurity request block.

    Returns ``(action, rule_ids, max_severity, request_uri)``.

    `action` is the most-severe action emitted by the rule set
    (intercepted / deny / drop / block). Lower-case normalized so the
    aggregator can compare against its thresholds. `request_uri` is the
    path + query string of the B-section request line (e.g. `/.env`,
    `/wp-login.php?foo=bar`) — empty string when the B-section is
    malformed or absent (AISO-205 surfaces this so the operator's
    `modsec_rule_breakdown` can pin each rule to its triggering URI).
    """
    action = ""
    action_severity = {"intercepted": 3, "deny": 3, "drop": 3, "block": 3, "pass": 1}
    rule_ids: list[str] = []
    max_sev = 0
    request_uri = ""
    in_b_section = False  # AISO-205: only the first B-section request line counts
    for line in lines:
        # Section boundary tracking — the B-section request line is the
        # only place where the request URI lives. We scan for the first
        # `METHOD /uri HTTP/x.y` line that arrives after a `--X-B--`
        # header; everything else in the B-section (Host / Cookie / UA
        # headers) is ignored.
        header_match = _MODSEC_HEADER_RE.match(line)
        if header_match:
            in_b_section = header_match.group(1) == "B"
            # Any section header resets the URI — only the B-section that
            # belongs to THIS request block counts.
            if not in_b_section and header_match.group(1) != "B":
                # Don't reset request_uri on non-B headers — the URI was
                # captured the moment the B-section's request line arrived
                # and should stay sticky through the rest of the block.
                pass
            continue
        if in_b_section and not request_uri:
            # First line inside B-section — almost always the request
            # line (`GET /uri HTTP/1.1`). Skip leading whitespace just in
            # case a rotator snuck in a blank line.
            m = _B_REQUEST_RE.match(line.strip())
            if m:
                request_uri = m.group("uri")
        # Action line is authoritative when present: "Action: Intercepted (phase 1)"
        # overrides any earlier "Message: Access denied" heuristic at the same
        # severity level.
        m = _ACTION_RE.match(line)
        if m:
            candidate = m.group("a").lower()
            if action_severity.get(candidate, 0) >= action_severity.get(action, 0):
                action = candidate
        # A "Message: Access denied..." line is also a signal even when
        # no explicit Action: line is present.
        m = _MSG_RE.match(line)
        if m and "denied" in m.group("msg").lower() and not action:
            action = "deny"
        # ModSecurity packs multiple `[key "value"]` fields onto one line:
        #   [line "12"] [id "942100"] [rev "1"] [msg "SQL Injection"] [severity "CRITICAL"]
        # Try the quoted form first (the common one), then the unquoted
        # fallback for setups that omit quotes.
        for tok in _FIELD_RE.finditer(line):
            key = tok.group("key").strip()
            value = tok.group("value").strip()
            if key == "id":
                rule_ids.append(value)
            elif key == "severity":
                v = value.upper()
                if v == "CRITICAL":
                    max_sev = max(max_sev, 2)
                elif v == "WARNING":
                    max_sev = max(max_sev, 1)
                elif v == "NOTICE":
                    max_sev = max(max_sev, 0)
        for tok in _FIELD_UNQUOTED_RE.finditer(line):
            # Skip if this match is fully covered by the quoted regex above.
            if _FIELD_RE.fullmatch(tok.group(0)):
                continue
            key = tok.group("key").strip()
            value = tok.group("value").strip()
            if key == "id":
                rule_ids.append(value)
            elif key == "severity":
                v = value.upper()
                if v == "CRITICAL":
                    max_sev = max(max_sev, 2)
                elif v == "WARNING":
                    max_sev = max(max_sev, 1)
                elif v == "NOTICE":
                    max_sev = max(max_sev, 0)
    return action, rule_ids, max_sev, request_uri


def _iter_modsec_requests(lines: Iterable[str]) -> Iterable[list[str]]:
    """Yield each ModSecurity request block as a list of lines.

    A "request" is everything between two A-section headers (--X-A--).
    The B/E/F/H/Z sections of the SAME request stay in the same block;
    only an A-section header demarcates a new request. The first
    request starts at the very first A header; the last ends at the
    next A header (or EOF).
    """
    buf: list[str] = []
    started = False  # whether we've seen the first A header
    for line in lines:
        line = line.rstrip("\n")
        m = _MODSEC_HEADER_RE.match(line)
        if m and m.group(1) == "A":
            # An A-section starts a new request. Flush the previous.
            if started and buf:
                yield buf
            buf = [line]
            started = True
        elif m:
            # B/E/F/H/Z sections: stay attached to the current block.
            buf.append(line)
        else:
            buf.append(line)
    if started and buf:
        yield buf


def analyze_modsec_and_errors(
    error_paths: Iterable[str],
    modsec_paths: Iterable[str],
    fs: FileSystem,
    rules: dict[str, Any] | None = None,
) -> list[Finding]:
    """Scan error_log(s) and ModSecurity audit log(s)."""
    settings = {
        "error_5xx_warn": 5,
        "error_5xx_crit": 50,
        "modsec_deny_warn": 1,    # any deny in a windowed sample is a signal
        "modsec_deny_crit": 50,
        "max_files": 20,
        "max_lines_per_file": 200_000,
        **(rules or {}),
    }
    findings: list[Finding] = []

    # ---- error_log ----
    err_levels: Counter[str] = Counter()
    err_5xx = 0
    err_files = 0
    for path in error_paths:
        if not fs.is_file(path):
            continue
        err_files += 1
        if err_files > settings["max_files"]:
            break
        line_count = 0
        for line in fs.open_text(path):
            line_count += 1
            if line_count > settings["max_lines_per_file"]:
                break
            m = _ERR_RE.match(line.strip())
            if not m:
                continue
            err_levels[m.group("level")] += 1
            if m.group("level") == "error":
                # Apache doesn't put status codes in error_log by default
                # — but modules sometimes do. Cheap heuristic: a status
                # code in the message counts toward the 5xx bucket.
                msg = m.group("msg")
                sc = re.search(r"\b(5\d{2})\b", msg)
                if sc:
                    err_5xx += 1

    if err_files == 0:
        findings.append(Finding(
            module="modsec_log",
            severity=Severity.INFO,
            title="No error_log files matched",
            description="error_log was not present under the configured root.",
        ))
    else:
        findings.append(Finding(
            module="modsec_log",
            severity=Severity.INFO,
            title=f"Scanned {err_files} error_log file(s)",
            description="error_log scan complete.",
            details={"level_counts": dict(err_levels), "files": list(error_paths)},
        ))
        if err_5xx >= settings["error_5xx_crit"]:
            sev = Severity.CRITICAL
        elif err_5xx >= settings["error_5xx_warn"]:
            sev = Severity.WARN
        else:
            sev = None
        if sev is not None:
            findings.append(Finding(
                module="modsec_log",
                severity=sev,
                title=f"{err_5xx} error_log 5xx message(s)",
                description=(
                    "Apache error_log contained a notable number of 5xx "
                    "status messages. Could be upstream failures, or a sign "
                    "that a probe triggered server-side errors."
                ),
                details={"count": err_5xx, "levels": dict(err_levels)},
                recommendation="Cross-reference timestamps with access_log 5xx bursts.",
            ))

    # ---- ModSecurity ----
    agg = ModSecAggregator()
    modsec_files = 0
    for path in modsec_paths:
        if not fs.is_file(path):
            continue
        modsec_files += 1
        if modsec_files > settings["max_files"]:
            break
        # Pull the whole file into a list; modsec_audit lines are small
        # and the per-file line cap keeps memory bounded.
        line_count = 0
        raw_lines: list[str] = []
        for line in fs.open_text(path):
            line_count += 1
            if line_count > settings["max_lines_per_file"]:
                break
            raw_lines.append(line)
        for block in _iter_modsec_requests(raw_lines):
            action, ids, sev, uri = _parse_modsec_request(block)
            agg.add_request(action, ids, sev, uri=uri)

    if modsec_files == 0:
        findings.append(Finding(
            module="modsec_log",
            severity=Severity.INFO,
            title="No ModSecurity audit log files matched",
            description=(
                "ModSecurity audit logs were not present under the configured "
                "root. Either ModSecurity is not installed, or it logs to "
                "another path."
            ),
            details={"paths": list(modsec_paths)},
            recommendation="If ModSecurity is installed but no audit log is present, check SecAuditLog directive.",
        ))
        return findings

    deny_count = sum(
        agg.actions.get(action, 0)
        for action in ("deny", "drop", "block", "intercepted")
    )
    findings.append(Finding(
        module="modsec_log",
        severity=Severity.INFO,
        title=f"Scanned {modsec_files} ModSecurity audit log(s)",
        description="ModSecurity scan complete.",
        details=agg.finalize(),
    ))
    if deny_count >= settings["modsec_deny_crit"]:
        sev = Severity.CRITICAL
    elif deny_count >= settings["modsec_deny_warn"]:
        sev = Severity.WARN
    else:
        sev = None
    if sev is not None:
        findings.append(Finding(
            module="modsec_log",
            severity=sev,
            title=f"ModSecurity denied {deny_count} request(s)",
            description=(
                "ModSecurity recorded deny/drop actions on this host. "
                "Review the rule IDs and source IPs."
            ),
            details={
                "actions": dict(agg.actions),
                "top_rule_ids": agg.rule_ids.most_common(10),
            },
            recommendation="Cross-reference with access_log IPs; consider fail2ban.",
        ))
    if agg.max_severity >= 2:
        findings.append(Finding(
            module="modsec_log",
            severity=Severity.CRITICAL,
            title="ModSecurity CRITICAL severity rule fired",
            description=(
                "At least one matched rule reported severity=CRITICAL. This "
                "indicates an active exploit attempt, not just probing."
            ),
            details={"critical_hits": agg.critical_hits[:10]},
            recommendation="Investigate the source IP and rule ID immediately.",
        ))
    return findings
