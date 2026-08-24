"""Apache ``error_log`` line parser (AISO-211).

Pure parser: one line → one ``ErrorLogRecord``, or ``None`` if the
line doesn't look like an Apache error_log entry. No state, no
aggregator, no detection rules. The aggregator lives in
``aggregator.py``; detection lives in ``rules.py``.

Apache 2.4 combined ``error_log`` format::

    [Sun Aug 24 04:12:34.123456 2026] [core:error] [pid 12345] \\
        [client 1.2.3.4:5678] File does not exist: /var/www/foo

Variants the parser handles:

  - ``[module:level]`` may be ``[mpm_prefork:notice]``, ``[ssl:warn]``,
    ``[core:error]`` — any token ending in ``:level`` where level is
    one of ``error``, ``warn``, ``notice``, ``info``, ``debug``,
    ``crit``, ``emerg``, ``alert``.
  - ``[pid N]`` is optional (some lines lack it, e.g. SSL handshake
    failures on the parent process).
  - ``[client IP:port]`` is optional — lines like ``[ssl:warn] [pid 7]
    AH02013: ...`` carry no client context.
  - The timestamp may or may not carry sub-second decimals. The
    parser captures the raw timestamp string verbatim — the analyzer
    is single-shot so a parsed timestamp is just diagnostic.

Returns ``None`` for lines that don't match the canonical
``[ts] [module:level]`` prefix. The aggregator's malformed counter
records those for forensic visibility.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class ErrorLogRecord(NamedTuple):
    """One parsed ``error_log`` line.

    Fields:

    - ``timestamp``: the raw timestamp string (``Sun Aug 24 04:12:34.123456 2026``).
      Carried verbatim — the audit is a single-shot run so we don't
      normalise it.
    - ``module``: the Apache module token (``core``, ``ssl``,
      ``mpm_prefork``, ``proxy``).
    - ``level``: the log level (``error``, ``warn``, ``notice``, ...).
    - ``pid``: the process ID, or ``None`` when the line has no ``[pid]`` field.
    - ``client_ip``: the client IP (``1.2.3.4``) WITHOUT the port. Empty
      string when the line carries no client context.
    - ``message``: the trailing message body verbatim.
    """

    timestamp: str
    module: str
    level: str
    pid: int | None
    client_ip: str
    message: str


# Apache 2.4 error_log line. The regex is intentionally tolerant:
# - timestamp may carry sub-second decimals (.123456) or not
# - pid is optional
# - [client IP:port] is optional
# - message body is the rest of the line (matches greedily up to EOL)
#
# Anchored at the start so a malformed half-line can't sneak through.
_LOG_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+"
    r"\[(?P<module>[a-zA-Z][\w-]*):(?P<level>[a-z]+)\]\s+"
    r"(?:\[pid\s+(?P<pid>\d+)\]\s+)?"
    r"(?:\[client\s+(?P<client>[\d:a-fA-F\.]+)(?::\d+)?\]\s+)?"
    r"(?P<msg>.*)$"
)


def parse_error_line(line: str) -> ErrorLogRecord | None:
    """Parse a single ``error_log`` line.

    Returns ``None`` for lines that don't carry the canonical
    ``[ts] [module:level]`` prefix (caller bumps a malformed counter).
    The parser is case-sensitive on the module + level tokens because
    Apache itself emits those lowercased — we don't want
    ``[Core:Error]`` from a noisy aggregator to be classified as a
    real Apache module.
    """
    match = _LOG_RE.match(line)
    if not match:
        return None
    pid_raw = match.group("pid")
    client_raw = match.group("client")
    # Strip the optional ``:port`` tail from the client capture
    # (``[client 1.2.3.4:5678]`` → ``1.2.3.4``). The regex's client
    # capture group is non-greedy enough that the trailing ``:NNNN``
    # never lands inside the capture, so a literal ``rstrip`` against
    # the trailing ``:digits`` is enough.
    client_ip = ""
    if client_raw:
        client_ip = client_raw.split(":", 1)[0]
    return ErrorLogRecord(
        timestamp=match.group("ts"),
        module=match.group("module"),
        level=match.group("level"),
        pid=int(pid_raw) if pid_raw else None,
        client_ip=client_ip,
        message=match.group("msg") or "",
    )