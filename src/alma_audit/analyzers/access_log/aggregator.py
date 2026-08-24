"""Streaming aggregator for parsed access log records.

Holds O(unique-IPs + unique-paths + unique-methods) state, not per-line
data. The detection rules in `rules.py` read this state to emit findings.

Probe pattern lists and the safe-method set are also defined here —
they are aggregator inputs (probe_hits counter, methods Counter), so
keeping them next to the state avoids cross-module cycles.
"""

from __future__ import annotations

from collections import Counter
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
        # The most recent non-empty UA wins; that's enough to give the
        # resolver a representative claim.
        self.last_ua_by_host: dict[str, str] = {}

    def add(self, record: AccessRecord) -> None:
        self.total_lines += 1
        self.hosts[record.host] += 1
        self.paths[record.path] += 1
        self.methods[record.method] += 1
        self.status_buckets[record.status] += 1
        self.bytes_total += record.size
        self.bytes_by_host[record.host] += record.size
        if record.user_agent:
            self.last_ua_by_host[record.host] = record.user_agent
        for pattern in SUSPICIOUS_PATH_PATTERNS:
            if pattern in record.path:
                self.probe_hits[pattern] += 1
                break  # one pattern per record is enough

    def finalize(self) -> dict[str, Any]:
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
        }