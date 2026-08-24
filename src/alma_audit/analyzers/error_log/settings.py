"""Defaults for the ``error_log`` analyzer — thresholds and file-shape rules.

Operators override these via the YAML config (``modules.error_log.*``).
The single source of truth lives here so a ``grep DEFAULT_RULES`` finds
every threshold in one place.

The analyzer is OPT-IN: ``modules.error_log.enabled`` must be True
for the analyzer to emit findings. The default is False so the audit
scope stays unchanged for hosts that don't have an ``error_log``
file (or operators who haven't explicitly opted in).
"""

from __future__ import annotations

from typing import Any


# Default rule thresholds. Operators can override per-config.
DEFAULT_RULES: dict[str, Any] = {
    # AISO-211: opt-in gate. Hosts without ``/var/log/apache2/error_log``
    # (or operators who haven't explicitly opted in) see a quiet run.
    "enabled": False,
    # Top-N clients by error count — surfaced in the summary finding.
    # The forensic JSON carries the full list (no cap).
    "top_clients_limit": 10,
    # Top-N error message templates. Templates are the ``[module:level]``
    # prefix + first 80 chars of the message body; identical messages
    # across IPs roll up into one row.
    "top_messages_limit": 10,
    # A single (client, message_template) pair producing >= this many
    # hits fires a CRITICAL finding (data-exfiltration / OOM-loop
    # signature on a single host). Default 100 matches the AISO-211
    # issue text; operators with noisy ``error_log`` files can lift it.
    "message_burst_crit": 100,
    # How many files at most to scan (defensive against huge logs).
    "max_files": 20,
    # Per-file line cap. 0 = no cap. Default: 200,000.
    "max_lines_per_file": 200_000,
}


# Rotated copies may include compressed archives (``.gz``, ``.bz2``,
# ``.xz``, ``.zst``). The runners layer already filters those out for
# the read-only contract — this list is consulted at analyzer level
# too, so a test scenario that bypasses the layer still behaves the
# same way.
_COMPRESSED_SUFFIXES = (".gz", ".bz2", ".xz", ".zst", ".lz4")


def is_compressed(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in _COMPRESSED_SUFFIXES)