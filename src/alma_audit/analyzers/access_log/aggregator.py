"""Streaming aggregator for parsed access log records.

Holds O(unique-IPs + unique-paths + unique-methods) state. The detection
rules in `rules.py` read this state to emit findings.

AISO-197 adds per-probe-path / per-IP detail so the operator can see
exactly which source IPs hit which scanner endpoints (and not just the
per-path totals). No cap on the per-IP list size — the operator
explicitly asked for the full forensic view; the `max_lines_per_file`
and `max_files` caps in `settings.py` are the budget controls.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .parser import AccessRecord


# Path prefixes / suffixes that almost always mean a probe.
SUSPICIOUS_PATH_PATTERNS: tuple[str, ...] = (
    "/.env",
    "/.git",
    "/.git/",
    "/.htaccess",
    "/wp-login.php",
    "/wp-admin/",
    "/administrator/",
    "/administrator/index.php",
    "/admin.php",
    "/admin/",
    "/phpmyadmin",
    "/pma/",
    "/phpinfo.php",
    "/xmlrpc.php",
    "/cgi-bin/",
    "/cgi-bin/phf",
    "/server-status",
    "/server-info",
    "/.aws/credentials",
    "/.ssh/id_rsa",
)


SAFE_METHODS: frozenset[str] = frozenset({
    "GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS",
})


class _PerIPProbeStat:
    """Tracks per-(path, ip) probe totals + an unbounded UA counter.

    AISO-208 review fix: the bucket previously kept an *ordered, 5-UA-capped*
    list of distinct user-agents, with no per-UA counts. The downstream
    serializer then divided the bucket total by ``len(user_agents)`` and
    assigned the quotient to each UA — a fabricated breakdown that
    produced e.g. ``5/5`` for a real ``9× ua-A + 1× ua-B`` input. The
    operator relied on those numbers and the report was provably wrong.

    We now keep a ``Counter[str]`` of per-UA hit counts inside the
    bucket. There is **no** cap on the number of distinct UAs (a
    rotating scanner may surface dozens of UAs against one path; we
    want the real distribution, not a 5-UA window).

    Invariants this class guarantees:

    * ``count`` is the total number of probe records seen on this
      ``(path, ip)`` — equal to ``sum(ua_counts.values())`` for the
      case where every record carried a UA. If some records lacked a
      UA string, the bucket keeps an explicit ``"<unknown>"`` key so
      the invariant still holds exactly.
    * ``user_agents`` is the **insertion-ordered** list of distinct
      UA strings seen — kept for human-readable display and for
      backward compatibility with consumers that read
      ``probe_paths_by_ip`` and expect a list of UAs.
    * The first-seen / last-seen timestamps are tracked as
      ``str`` min/max — Apache log lines have ISO-style timestamps
      that compare lexicographically.
    """

    __slots__ = ("count", "first_seen", "last_seen", "user_agents", "ua_counts")

    def __init__(self, timestamp: str, user_agent: str) -> None:
        self.count = 1
        self.first_seen = timestamp
        self.last_seen = timestamp
        # Ordered list of distinct UA strings (encounter order). No cap.
        self.user_agents: list[str] = []
        # Per-UA hit counts — the source of truth for the
        # path × IP × UA breakdown. The previous 5-UA list cap was
        # the root cause of the AISO-208 review bug.
        self.ua_counts: Counter[str] = Counter()
        if user_agent:
            if user_agent not in self.user_agents:
                self.user_agents.append(user_agent)
            self.ua_counts[user_agent] += 1
        else:
            # Track an explicit "<unknown>" bucket so the count
            # invariant ``count == sum(ua_counts.values())`` holds
            # even when records lack a UA string.
            if "<unknown>" not in self.user_agents:
                self.user_agents.append("<unknown>")
            self.ua_counts["<unknown>"] += 1

    def update(self, timestamp: str, user_agent: str) -> None:
        self.count += 1
        # Timestamps may not be strictly monotonic across log lines
        # (rotation, clock skew); keep min/max.
        if timestamp < self.first_seen:
            self.first_seen = timestamp
        if timestamp > self.last_seen:
            self.last_seen = timestamp
        if user_agent:
            if user_agent not in self.user_agents:
                self.user_agents.append(user_agent)
            self.ua_counts[user_agent] += 1
        else:
            if "<unknown>" not in self.user_agents:
                self.user_agents.append("<unknown>")
            self.ua_counts["<unknown>"] += 1


class AccessAggregator:
    """Streaming aggregator. Call `add(record)` per parsed line, then `finalize()`."""

    def __init__(self) -> None:
        self.hosts: Counter[str] = Counter()
        self.paths: Counter[str] = Counter()
        self.methods: Counter[str] = Counter()
        self.status_buckets: Counter[int] = Counter()
        self.bytes_total = 0
        self.bytes_by_host: Counter[str] = Counter()
        self.malformed = 0
        self.probe_hits: Counter[str] = Counter()  # pattern -> count
        self.total_lines = 0
        # Per-host representative User-Agent. Used by the analyzer to
        # run the crawler verification chain (top-host, error-burst).
        self.last_ua_by_host: dict[str, str] = {}
        # AISO-197 forensic detail: probe_path -> ip -> stat.
        # Stored as a dict-of-dicts for O(1) updates and clean finalization.
        self.probe_by_path_ip: dict[str, dict[str, _PerIPProbeStat]] = defaultdict(dict)
        # Per-IP rollup across ALL probe paths (drives `top_attackers`).
        self.probe_total_by_ip: Counter[str] = Counter()
        self.ip_first_seen: dict[str, str] = {}
        self.ip_last_seen: dict[str, str] = {}
        self.ip_user_agents: dict[str, list[str]] = defaultdict(list)
        # Status-by-host for per-host error breakdown (used by D4 details).
        self.status_by_host: dict[str, Counter[int]] = defaultdict(Counter)

    def add(self, record: AccessRecord) -> None:
        self.total_lines += 1
        self.hosts[record.host] += 1
        self.paths[record.path] += 1
        self.methods[record.method] += 1
        self.status_buckets[record.status] += 1
        self.status_by_host[record.host][record.status] += 1
        self.bytes_total += record.size
        self.bytes_by_host[record.host] += record.size
        if record.user_agent:
            self.last_ua_by_host[record.host] = record.user_agent
            # AISO-208 review fix: was previously capped at 5 distinct
            # UAs per IP — that cap truncated the real distribution
            # and made the per-IP rollup under-report scanner
            # diversity. No cap now; the operator wants the full list.
            if record.user_agent not in self.ip_user_agents[record.host]:
                self.ip_user_agents[record.host].append(record.user_agent)

        # First/last seen per host (string comparison works for ISO-style
        # Apache timestamps like "10/Oct/2025:13:55:36 -0700").
        ip = record.host
        ts = record.timestamp
        if ip not in self.ip_first_seen or (ts and ts < self.ip_first_seen[ip]):
            self.ip_first_seen[ip] = ts
        if ip not in self.ip_last_seen or (ts and ts > self.ip_last_seen[ip]):
            self.ip_last_seen[ip] = ts

        for pattern in SUSPICIOUS_PATH_PATTERNS:
            if pattern in record.path:
                self.probe_hits[pattern] += 1
                # AISO-197: per-(path, ip) detail.
                per_ip = self.probe_by_path_ip[pattern].get(ip)
                if per_ip is None:
                    self.probe_by_path_ip[pattern][ip] = _PerIPProbeStat(
                        record.timestamp, record.user_agent,
                    )
                else:
                    per_ip.update(record.timestamp, record.user_agent)
                self.probe_total_by_ip[ip] += 1
                break  # one pattern per record is enough

    def finalize(self) -> dict[str, Any]:
        # probe_paths_by_ip: { path -> [ {ip, count, first_seen, last_seen,
        #                                 user_agents, user_agent_counts}, ... ] }
        # `user_agents` is the insertion-ordered distinct-UA list
        # (kept for backward compatibility with consumers that just
        # want the names); `user_agent_counts` is the per-UA hit
        # counts — the source of truth for any "path × IP × UA"
        # breakdown (AISO-208 review fix). Sorted by count desc so the
        # operator's-eye view is "top offenders first".
        probe_paths_by_ip: dict[str, list[dict[str, Any]]] = {}
        for path, ip_map in self.probe_by_path_ip.items():
            rows = [
                {
                    "ip": ip,
                    "count": stat.count,
                    "first_seen": stat.first_seen,
                    "last_seen": stat.last_seen,
                    "user_agents": list(stat.user_agents),
                    # Per-UA counts — the AISO-208 review fix added
                    # this field so the forensic JSON carries the
                    # exact breakdown instead of a fabricated even
                    # split. ``stat.ua_counts`` is a Counter[str];
                    # ``dict(...)`` produces a JSON-safe plain dict.
                    "user_agent_counts": dict(stat.ua_counts),
                }
                for ip, stat in ip_map.items()
            ]
            rows.sort(key=lambda r: r["count"], reverse=True)
            probe_paths_by_ip[path] = rows

        # top_attackers: [ {ip, total_probe_count, probe_paths, first_seen, last_seen, user_agents}, ... ]
        attacker_rows: list[dict[str, Any]] = []
        for ip, probe_count in self.probe_total_by_ip.items():
            # Per-attacker path breakdown (paths -> counts).
            paths: dict[str, int] = {}
            for path, ip_map in self.probe_by_path_ip.items():
                if ip in ip_map:
                    paths[path] = ip_map[ip].count
            attacker_rows.append({
                "ip": ip,
                "total_probe_requests": probe_count,
                "probe_paths": dict(sorted(paths.items(), key=lambda kv: kv[1], reverse=True)),
                "first_seen": self.ip_first_seen.get(ip, ""),
                "last_seen": self.ip_last_seen.get(ip, ""),
                "user_agents": list(self.ip_user_agents.get(ip, [])),
                "total_requests": self.hosts.get(ip, 0),
            })
        # Sort by total_probe_requests desc — operator cares about scanner IPs first.
        attacker_rows.sort(key=lambda r: r["total_probe_requests"], reverse=True)

        # Per-host error breakdown — top 4xx/5xx contributors.
        # Sorted by error count desc, capped at top 20 hosts to keep the
        # report scannable (per the user's preference for lean output).
        host_error_rows: list[dict[str, Any]] = []
        for host, status_counter in self.status_by_host.items():
            err_count = sum(c for code, c in status_counter.items() if 400 <= code < 600)
            if err_count == 0:
                continue
            host_error_rows.append({
                "ip": host,
                "error_count": err_count,
                "total_requests": self.hosts.get(host, 0),
                "error_share": err_count / max(self.hosts.get(host, 1), 1),
                "status_buckets": {
                    str(code): count for code, count in sorted(status_counter.items())
                },
            })
        host_error_rows.sort(key=lambda r: r["error_count"], reverse=True)
        # Cap at 20 to keep report size sane; the operator can grep the
        # raw JSON for the rest if they want a full list.
        host_errors_top = host_error_rows[:20]
        host_errors_total = len(host_error_rows)

        return {
            "total_lines": self.total_lines,
            "malformed_lines": self.malformed,
            "unique_hosts": len(self.hosts),
            "unique_paths": len(self.paths),
            "bytes_total": self.bytes_total,
            "status_buckets": {
                str(code): count
                for code, count in sorted(self.status_buckets.items())
            },
            "method_buckets": dict(self.methods),
            "top_hosts": self.hosts.most_common(10),
            "top_paths": self.paths.most_common(10),
            "probe_hits": self.probe_hits.most_common(),
            # AISO-197 forensic detail (full, no cap):
            "probe_paths_by_ip": probe_paths_by_ip,
            "top_attackers": attacker_rows,
            "host_errors_top": host_errors_top,
            "host_errors_total": host_errors_total,
        }
