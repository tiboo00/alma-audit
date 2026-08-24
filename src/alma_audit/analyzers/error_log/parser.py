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

from ...ip_normalise import normalise_ip


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
#
# AISO-211 review fix: the inner client capture group now accepts
# ``[`` and ``]`` so Apache's bracketed IPv6 form
# ``[2001:db8::1]:5678`` survives the regex pass intact. The
# previous pattern ``[\d:a-fA-F\.]+`` only captured the hex-digit
# run BEFORE the first colon, so ``2001:db8::1:5678`` came out as
# ``"2001"`` (a single hex chunk with no IP semantics). The whole
# ``[client ...]`` block remains optional so lines like
# ``[ssl:warn] [pid 7] AH02013: ...`` (no client context) still
# parse. The actual IP canonicalisation happens in
# ``_canonicalise_client`` via ``ip_normalise.normalise_ip``, which
# handles all four input forms (IPv4 / IPv4+port / IPv6 / IPv6+port)
# and strips the optional ``:NNNN`` port suffix.
_LOG_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+"
    r"\[(?P<module>[a-zA-Z][\w-]*):(?P<level>[a-z]+)\]\s+"
    r"(?:\[pid\s+(?P<pid>\d+)\]\s+)?"
    r"(?:\[client\s+(?P<client>.+?)\]\s+)?"
    r"(?P<msg>.*)$"
)


def _canonicalise_client(raw: str) -> str:
    """Return the canonical IP literal for an Apache ``[client X]`` capture.

    Accepts an IPv4 literal (``1.2.3.4:5678`` or ``1.2.3.4``), an
    IPv6 literal (``[2001:db8::1]:5678``, ``2001:db8::1:5678``, or
    ``2001:db8::1``), and a bare token with no port suffix. Returns
    the canonical form via ``ip_normalise.normalise_ip`` (e.g.
    ``2001:db8::1`` for the bracketed / unbracketed forms), or the
    empty string when the capture is missing or cannot be parsed as
    an IP literal.

    The Apache ``error_log`` convention for the IPv6 case is
    bracketed ``[2001:db8::1]:5678``; some downstream log forwarders
    strip the brackets and emit ``2001:db8::1:5678`` instead. We
    detect both forms: a bracketed IPv6 (strip the brackets, parse
    the IP, return the canonical form); an unbracketed IPv6 with a
    trailing ``:NNNN`` (strip the trailing port, parse the rest);
    an IPv4 with a trailing ``:NNNN`` (strip the trailing port);
    and a bare literal (parse directly).
    """
    if not raw:
        return ""
    token = raw.strip()
    # Bracketed IPv6 form: ``[2001:db8::1]:5678`` or ``[::1]``.
    if token.startswith("["):
        end = token.find("]")
        if end == -1:
            return ""
        bracket_inner = token[1:end]
        try:
            return normalise_ip(bracket_inner)[0]
        except ValueError:
            return ""
    # No brackets. Apache's default ErrorLogFormat emits the IPv6
    # without a port suffix, but custom formats (and downstream log
    # forwarders) often append ``:NNNN``. We can't tell the two
    # cases apart purely from the literal — ``2001:db8::1:5678`` is
    # a valid 8-group IPv6 to inet_pton, AND it is also the
    # canonical IPv6 ``2001:db8::1`` with a port suffix.
    #
    # Heuristic: if the trailing ``:NNNN`` looks like a TCP port
    # (1..65535) AND the prefix is itself a valid IPv6, treat the
    # suffix as a port and return the canonical form of the prefix.
    # The IPv4 case (``1.2.3.4:5678``) is caught the same way
    # because ``normalise_ip`` rejects the colon form for IPv4.
    if ":" in token:
        head, _, tail = token.rpartition(":")
        if tail.isdigit() and 1 <= int(tail) <= 65535 and head:
            try:
                return normalise_ip(head)[0]
            except ValueError:
                # The prefix isn't an IP literal after stripping
                # the port — fall through to the as-is parse, which
                # handles a bare IP without any port suffix.
                pass
    # As-is parse — bare IPv4 (``1.2.3.4``) or bare IPv6
    # (``2001:db8::1``). If the literal is genuinely an 8-group
    # IPv6 like ``2001:db8:0:0:0:0:0:5678``, the user has no port
    # to strip and we return the canonical form verbatim.
    try:
        return normalise_ip(token)[0]
    except ValueError:
        pass
    # Last resort: malformed IP — return empty so the aggregator
    # doesn't aggregate under a bogus key.
    return ""


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
    # AISO-211 review fix: hand the raw client capture to
    # ``_canonicalise_client`` so IPv6 literals (``2001:db8::1``,
    # ``[::1]``, etc.) survive the parse. The previous
    # ``client_raw.split(":", 1)[0]`` truncated an IPv6 address at
    # the first colon — ``2001:db8::1:5678`` came out as ``"2001"``
    # (a single hex chunk, no IP semantics). The new path uses the
    # project's standard ``ip_normalise.normalise_ip`` helper for
    # both IPv4 and IPv6, so the aggregator's per-IP rollup gets a
    # canonical IP literal.
    client_ip = _canonicalise_client(client_raw) if client_raw else ""
    return ErrorLogRecord(
        timestamp=match.group("ts"),
        module=match.group("module"),
        level=match.group("level"),
        pid=int(pid_raw) if pid_raw else None,
        client_ip=client_ip,
        message=match.group("msg") or "",
    )