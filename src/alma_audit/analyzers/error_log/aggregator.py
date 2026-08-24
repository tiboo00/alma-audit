"""Streaming aggregator for the ``error_log`` analyzer.

Holds O(unique-clients + unique-message-templates) state. The
detection rules in ``rules.py`` read this state to emit findings.

Counts tracked:

  - Per-client-IP error count (``clients: Counter[str]``). The
    summary finding surfaces the top 10 by count; the full list is
    in the forensic JSON.
  - Per-message-template count (``messages: Counter[str]``). The
    template is ``<module>:<level>: <truncated_message_body>`` so
    identical ``File does not exist: /var/www/foo`` messages across
    IPs roll up into one row. The detection rule looks for any
    template whose count exceeds ``message_burst_crit``.
  - Per-(client, template) count (``bursts: dict[(ip, template), count]``).
    This is the row that drives the CRITICAL finding — a single
    host repeating the same message 100+ times is the AISO-211
    signature (e.g. mpm_prefork OOM, repeated SSL handshake
    failures on a single client).
  - Diagnostic counters (``total_lines``, ``malformed_lines``,
    ``classified_lines``).
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from .parser import ErrorLogRecord


# Cap on the truncated message body that goes into the message
# template. The full body is preserved verbatim in the per-IP
# ``top_messages`` forensic detail; the template is just for
# grouping identical messages across IPs. 80 chars covers
# Apache's canonical ``File does not exist: ...``, ``AH02013: ...``,
# ``AH00163: ...`` message heads without losing uniqueness.
_TEMPLATE_BODY_LIMIT = 80


def _template_key(record: ErrorLogRecord) -> str:
    """Build the dedup key for ``record``.

    ``module:level: <truncated body>`` — three components so two
    different modules emitting the same literal message string
    don't collide. Body is truncated to ``_TEMPLATE_BODY_LIMIT``
    chars; the operator can grep the forensic JSON for the full
    message if the template looks interesting.
    """
    body = record.message[:_TEMPLATE_BODY_LIMIT].rstrip()
    return f"{record.module}:{record.level}: {body}"


class ErrorAggregator:
    """Streaming aggregator. Call ``add(record)`` per parsed line, then ``finalize()``."""

    def __init__(self) -> None:
        # Per-client error counts.
        self.clients: Counter[str] = Counter()
        # Per-template total counts (across all clients).
        self.messages: Counter[str] = Counter()
        # Per-(client, template) counts — drives the CRITICAL finding.
        # ``bursts`` is the source of truth for the message-burst
        # detection rule (AISO-211 §3: ``CRITICAL if same message ×
        # 100+ on a single host``).
        self.bursts: dict[tuple[str, str], int] = {}
        # Per-(client, template) example messages (capped at 1 each,
        # so the forensic JSON can show what the burst looks like).
        self.burst_examples: dict[tuple[str, str], str] = {}
        # Diagnostic counters.
        self.total_lines: int = 0
        self.classified_lines: int = 0
        self.malformed_lines: int = 0

    def add(self, record: ErrorLogRecord) -> None:
        self.total_lines += 1
        self.classified_lines += 1
        # Lines without a client IP (e.g. SSL handshake errors on
        # the parent process) are still classified; they just don't
        # contribute to the per-client rollup. The template row
        # captures them under an empty client key.
        client = record.client_ip or "<no_client>"
        self.clients[client] += 1
        template = _template_key(record)
        self.messages[template] += 1
        burst_key = (client, template)
        self.bursts[burst_key] = self.bursts.get(burst_key, 0) + 1
        if burst_key not in self.burst_examples:
            self.burst_examples[burst_key] = record.message

    def note_malformed(self) -> None:
        """Bump the malformed-line counter for an un-classified line."""
        self.total_lines += 1
        self.malformed_lines += 1

    def extend(self, records: Iterable[ErrorLogRecord]) -> None:
        for r in records:
            self.add(r)

    def finalize(self) -> dict[str, Any]:
        # Sort by count desc so the operator-eye view is "top
        # offenders first". Cap at the configured limit (default 10)
        # for the summary finding; the forensic JSON carries the
        # full list (no cap).
        top_clients = self.clients.most_common()
        top_messages = self.messages.most_common()
        # The forensic view keeps every (client, template) burst so
        # the operator can grep for "which client repeated which
        # message how many times". The summary rolls up by template
        # so the operator sees the message-level counts first.
        bursts_serialised = [
            {
                "client_ip": client if client != "<no_client>" else "",
                "template": template,
                "count": count,
                "example_message": self.burst_examples.get((client, template), ""),
            }
            for (client, template), count in sorted(
                self.bursts.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )
        ]
        return {
            "total_lines": self.total_lines,
            "classified_lines": self.classified_lines,
            "malformed_lines": self.malformed_lines,
            # JSON-safe: Counter → list of (key, count) pairs.
            "top_clients": [
                {"ip": ip if ip != "<no_client>" else "", "count": count}
                for ip, count in top_clients
            ],
            "top_messages": [
                {"template": tpl, "count": count}
                for tpl, count in top_messages
            ],
            # Forensic detail: every (client, template) burst.
            "bursts": bursts_serialised,
        }