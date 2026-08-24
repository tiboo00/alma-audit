"""Streaming aggregator for the cphulk_log analyzer.

Holds O(unique-IPs + unique-users + unique-block-events) state, not
per-line data. The detection rules in `rules.py` read this state to
emit findings.

The two cardinal counters are:

  - `brute_force_by_ip` — per-IP count of brute-force-attempt events
  - `brute_force_by_user` — per-user count of the same event

A separate `block_events` list captures account_blocked / ip_blocked
events verbatim so the rules layer can summarise them in an INFO
finding (correlates with syslog).
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from .parser import CphulkRecord


class CphulkAggregator:
    """Streaming aggregator. Call `add(record)` per parsed line, then `finalize()`."""

    def __init__(self) -> None:
        self.brute_force_by_ip: Counter[str] = Counter()
        self.brute_force_by_user: Counter[str] = Counter()
        self.block_events: list[dict[str, Any]] = []
        self.unblock_events: list[dict[str, Any]] = []
        self.total_lines: int = 0
        self.classified_lines: int = 0
        self.malformed_lines: int = 0

    def add(self, record: CphulkRecord) -> None:
        self.total_lines += 1
        self.classified_lines += 1
        if record.event == "brute_force":
            if record.source_ip:
                self.brute_force_by_ip[record.source_ip] += 1
            if record.username:
                self.brute_force_by_user[record.username] += 1
        elif record.event in ("account_blocked", "ip_blocked"):
            self.block_events.append({
                "event": record.event,
                "source_ip": record.source_ip,
                "username": record.username,
                "level": record.level.value,
            })
        elif record.event in ("account_unblocked", "ip_unblocked"):
            self.unblock_events.append({
                "event": record.event,
                "source_ip": record.source_ip,
                "username": record.username,
                "level": record.level.value,
            })

    def note_malformed(self) -> None:
        self.total_lines += 1
        self.malformed_lines += 1

    def extend(self, records: Iterable[CphulkRecord]) -> None:
        for r in records:
            self.add(r)

    def finalize(self) -> dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "classified_lines": self.classified_lines,
            "malformed_lines": self.malformed_lines,
            "brute_force_by_ip": dict(self.brute_force_by_ip.most_common(10)),
            "brute_force_by_user": dict(self.brute_force_by_user.most_common(10)),
            "block_event_count": len(self.block_events),
            "unblock_event_count": len(self.unblock_events),
        }