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

from ...self_ip import is_self_ip
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

    AISO-208 review fix #2 (perf): the previous implementation did a
    linear ``ua not in self.user_agents`` membership check on every
    ``update()`` call. On a busy log that's a per-record O(distinct UAs)
    scan, which adds up to O(n²) per (path, ip) bucket. We now drive the
    "is this a new UA?" decision from the Counter's O(1) ``get`` —
    ``append`` only runs the (rare) first-time path. Hot-path lookups
    for repeat UAs skip the list entirely, so the bucket mutates in
    constant time per record regardless of UA diversity.

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
        # The list is appended to only when ``ua_counts`` sees a UA
        # for the first time, so append cost is paid at most
        # O(distinct-UAs) over the bucket's lifetime — never per record.
        self.user_agents: list[str] = []
        # Per-UA hit counts — the source of truth for the
        # path × IP × UA breakdown AND the source for the
        # "is this UA new?" O(1) membership check.
        self.ua_counts: Counter[str] = Counter()
        # Sentinel for empty UA strings (parser coerces ``None`` → ``""``).
        _ua = user_agent if user_agent else "<unknown>"
        self.ua_counts[_ua] += 1
        self.user_agents.append(_ua)

    def update(self, timestamp: str, user_agent: str) -> None:
        self.count += 1
        # Timestamps may not be strictly monotonic across log lines
        # (rotation, clock skew); keep min/max.
        if timestamp < self.first_seen:
            self.first_seen = timestamp
        if timestamp > self.last_seen:
            self.last_seen = timestamp
        _ua = user_agent if user_agent else "<unknown>"
        # O(1) Counter membership via ``get`` — drives both the count
        # bump and the new-UA branch. The previous list-based
        # ``not in self.user_agents`` scan was O(distinct UAs) per
        # record and made the bucket O(n²) on UA-heavy paths.
        if self.ua_counts.get(_ua, 0) == 0:
            self.user_agents.append(_ua)
        self.ua_counts[_ua] += 1


class AccessAggregator:
    """Streaming aggregator. Call `add(record)` per parsed line, then `finalize()`.

    AISO-208 review fix #2 (perf): ``ip_user_agent_cap`` bounds the
    per-IP rollup of distinct user-agents (the ``ip_user_agents`` field
    that feeds ``top_attackers``). The previous PR removed this cap as
    a side-effect of the per-probe change — that made the per-IP
    rollup unbounded and turned the rollup into O(n²) per host on
    UA-diverse traffic (measured on a real host: 10k records / 0.6s,
    20k / 1.8s, 40k / 7.4s — quadratic amplification). The cap is
    restored here, plumbed via the constructor so an operator can
    lift or tighten it from the YAML config (AISO-207 contract).
    """

    def __init__(
        self,
        ip_user_agent_cap: int = 5,
        self_ips: set[str] | None = None,
    ) -> None:
        # 0/5/10/N all bound the per-IP rollup at N distinct UAs.
        # A negative value disables the cap (operator opts into the
        # unbounded, O(n²)-on-UA-diverse-traffic behaviour — measured
        # at 7.4s for 40k records / single IP).
        self.ip_user_agent_cap = ip_user_agent_cap
        # AISO-211: the host's own IPs (auto-detected + operator
        # allowlist). Self-IP records are STILL counted in
        # ``hosts``, ``bytes_total``, ``status_buckets``,
        # ``method_buckets`` (the overall counters stay accurate),
        # but they are NOT counted in ``top_attackers``,
        # ``host_errors_top`` or the ``top_hosts`` aggregator slice.
        # Forensic dump records them in ``self_ip_event_count`` /
        # ``self_ip_examples`` so the operator can audit self-noise.
        # A cPanel server is going to log hundreds of self-login /
        # admin-panel fetches from the host's own daemon — surfacing
        # them in the top-N would drown the operator in noise.
        self.self_ips: set[str] = self_ips or set()
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
        # Per-IP distinct UA list (operator-eye rollup, NOT the
        # per-path × per-IP forensic detail — that lives in
        # ``probe_by_path_ip`` and is uncapped). AISO-208 review
        # fix #2: the cap is restored at 5 to keep the rollup
        # bounded; lift to a larger N (or disable via a negative
        # value) in the YAML config if the operator really wants
        # the full list.
        self.ip_user_agents: dict[str, list[str]] = defaultdict(list)
        # Status-by-host for per-host error breakdown (used by D4 details).
        self.status_by_host: dict[str, Counter[int]] = defaultdict(Counter)
        # AISO-211: self-IP diagnostic counters. Surfaced in the
        # forensic JSON dump so the operator can audit self-noise.
        self.self_ip_event_count: int = 0
        self.self_ip_examples: list[str] = []

    def add(self, record: AccessRecord) -> None:
        self.total_lines += 1
        ip = record.host
        is_self = is_self_ip(ip, self.self_ips)
        if is_self:
            # AISO-211: record the event for forensic dump (capped at
            # 5 samples so the JSON stays bounded), but skip the
            # per-IP / per-(path, ip) rollups that drive the
            # operator-eye top-N views.
            self.self_ip_event_count += 1
            if len(self.self_ip_examples) < 5:
                self.self_ip_examples.append(
                    f"{record.method} {record.path} from {ip} (self-IP)"
                )
        # Overall counters: ALWAYS include self-IP traffic so the
        # operator's "how many lines did the audit scan?" / "how many
        # bytes came through?" views stay honest.
        self.hosts[ip] += 1
        self.paths[record.path] += 1
        self.methods[record.method] += 1
        self.status_buckets[record.status] += 1
        self.status_by_host[ip][record.status] += 1
        self.bytes_total += record.size
        self.bytes_by_host[ip] += record.size
        if record.user_agent:
            # AISO-211: skip UA tracking for self-IPs. A cPanel
            # admin-panel request from 127.0.0.1 has no UA worth
            # keeping in the per-IP rollup — it would just inflate
            # the forensic view of the host's own daemon.
            if not is_self:
                self.last_ua_by_host[ip] = record.user_agent
                ua_list = self.ip_user_agents[ip]
                new_ua = record.user_agent not in ua_list
                if new_ua and (self.ip_user_agent_cap < 0 or len(ua_list) < self.ip_user_agent_cap):
                    ua_list.append(record.user_agent)

        # First/last seen per host (string comparison works for ISO-style
        # Apache timestamps like "10/Oct/2025:13:55:36 -0700"). Self-IPs
        # keep their own timestamps so the diagnostic dump is honest.
        ts = record.timestamp
        if ip not in self.ip_first_seen or (ts and ts < self.ip_first_seen[ip]):
            self.ip_first_seen[ip] = ts
        if ip not in self.ip_last_seen or (ts and ts > self.ip_last_seen[ip]):
            self.ip_last_seen[ip] = ts

        if is_self:
            # AISO-211: stop here for self-IP records. They are NOT
            # counted in the probe-path rollups (`probe_hits`,
            # `probe_by_path_ip`, `probe_total_by_ip`) — a localhost
            # hit on `/.env` is a self-admin-panel fetch, not a
            # scanner event. The diagnostic counter above keeps the
            # event visible for forensics.
            return

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
        # AISO-211: self-IP set (may be empty). Used to filter the
        # per-IP rollups below so the operator-eye top-N views don't
        # get drowned by cPanel self-admin-panel noise.
        self_ips = self.self_ips

        def _is_self(ip: str) -> bool:
            return is_self_ip(ip, self_ips)

        # probe_paths_by_ip: { path -> [ {ip, count, first_seen, last_seen,
        #                                 user_agents, user_agent_counts}, ... ] }
        # `user_agents` is the insertion-ordered distinct-UA list
        # (kept for backward compatibility with consumers that just
        # want the names); `user_agent_counts` is the per-UA hit
        # counts — the source of truth for any "path × IP × UA"
        # breakdown (AISO-208 review fix). Sorted by count desc so the
        # operator's-eye view is "top offenders first". AISO-211:
        # self-IP rows are excluded — the aggregator's `add()` already
        # skips them, so this is a defense-in-depth check.
        probe_paths_by_ip: dict[str, list[dict[str, Any]]] = {}
        for path, ip_map in self.probe_by_path_ip.items():
            rows = [
                {
                    "ip": ip,
                    "count": stat.count,
                    "first_seen": stat.first_seen,
                    "last_seen": stat.last_seen,
                    "user_agents": list(stat.user_agents),
                    "user_agent_counts": dict(stat.ua_counts),
                }
                for ip, stat in ip_map.items()
                if not _is_self(ip)
            ]
            if not rows:
                continue
            rows.sort(key=lambda r: r["count"], reverse=True)
            probe_paths_by_ip[path] = rows

        # top_attackers: [ {ip, total_probe_count, probe_paths, first_seen, last_seen, user_agents}, ... ]
        # AISO-211: skip self-IP entries (the aggregator's add() already
        # excludes them from probe_total_by_ip, so this is also a
        # defense-in-depth check on the iteration path).
        attacker_rows: list[dict[str, Any]] = []
        for ip, probe_count in self.probe_total_by_ip.items():
            if _is_self(ip):
                continue
            # Per-attacker path breakdown (paths -> counts).
            paths: dict[str, int] = {}
            for path, ip_map in self.probe_by_path_ip.items():
                if ip in ip_map and not _is_self(ip):
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
        # AISO-211: exclude self-IPs from the operator-eye rollup.
        # The forensic JSON keeps the unfiltered status_by_host map;
        # the rules layer can split internal vs external from there.
        host_error_rows: list[dict[str, Any]] = []
        host_error_rows_internal: list[dict[str, Any]] = []
        for host, status_counter in self.status_by_host.items():
            err_count = sum(c for code, c in status_counter.items() if 400 <= code < 600)
            if err_count == 0:
                continue
            row = {
                "ip": host,
                "error_count": err_count,
                "total_requests": self.hosts.get(host, 0),
                "error_share": err_count / max(self.hosts.get(host, 1), 1),
                "status_buckets": {
                    str(code): count for code, count in sorted(status_counter.items())
                },
            }
            if _is_self(host):
                host_error_rows_internal.append(row)
            else:
                host_error_rows.append(row)
        host_error_rows.sort(key=lambda r: r["error_count"], reverse=True)
        host_error_rows_internal.sort(key=lambda r: r["error_count"], reverse=True)
        # Cap at 20 to keep report size sane; the operator can grep the
        # raw JSON for the rest if they want a full list. AISO-211:
        # the internal split is also capped at 20 for symmetry.
        host_errors_top = host_error_rows[:20]
        host_errors_internal_top = host_error_rows_internal[:20]
        host_errors_total = len(host_error_rows) + len(host_error_rows_internal)

        # AISO-211: top_hosts rollup also strips self-IP. The
        # operator's "who generated the most traffic?" view would
        # otherwise surface 127.0.0.1 × 52041 as the #1 host on every
        # cPanel server, drowning the real external traffic.
        top_hosts_filtered = [
            (ip, count)
            for ip, count in self.hosts.most_common()
            if not _is_self(ip)
        ][:10]

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
            "top_hosts": top_hosts_filtered,
            "top_paths": self.paths.most_common(10),
            "probe_hits": self.probe_hits.most_common(),
            # AISO-197 forensic detail (full, no cap):
            "probe_paths_by_ip": probe_paths_by_ip,
            "top_attackers": attacker_rows,
            "host_errors_top": host_errors_top,
            # AISO-211: self-IP rollup for forensic consumers.
            "host_errors_internal_top": host_errors_internal_top,
            "host_errors_total": host_errors_total,
            # AISO-211: self-IP diagnostic dump. Recorded for forensic
            # consumers, not surfaced as a finding.
            "self_ip_event_count": self.self_ip_event_count,
            "self_ip_examples": list(self.self_ip_examples),
        }
