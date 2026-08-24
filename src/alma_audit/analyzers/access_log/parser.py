"""Apache combined / common access log line parser.

Pure parser: one line → one `AccessRecord`, or `None` if malformed.
No state, no aggregator, no detection rules. The aggregator lives in
`aggregator.py`; detection lives in `rules.py`.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class AccessRecord(NamedTuple):
    host: str
    timestamp: str
    method: str
    path: str
    status: int
    size: int
    user_agent: str


# Combined log format:
#   host ident authuser timestamp request status bytes referer useragent
# We use a regex tolerant to missing fields (Apache emits "-" for empty).
# Order: we DON'T try to be Apache-2.4-perfect — we want to parse the
# real shapes the user described (`301 795`, `200 0`, `404 -`).
#
# The trailing two quoted fields are optional — many real-world feeds
# (e.g. the bytes_log mirror) write only the first 7 fields. When the
# regex's quoted-UA tail does not match, the parser returns None and
# the caller increments a `malformed` counter.
_LOG_RE = re.compile(
    r"^(?P<host>\S+)\s+"
    r"\S+\s+\S+\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\d+|-)"
    r"(?:\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?"
)


def parse_line(line: str) -> AccessRecord | None:
    """Parse a single combined-format access log line.

    Returns None for malformed lines (caller increments a counter). The
    parser is intentionally strict about the timestamp + status + size
    slots and lenient about the request field (only splits method/path/
    protocol on whitespace).
    """
    match = _LOG_RE.match(line)
    if not match:
        return None
    request = match.group("request")
    parts = request.split(" ", 2)
    if len(parts) < 2:
        return None
    method = parts[0].upper()
    path = parts[1]
    try:
        status = int(match.group("status"))
    except ValueError:
        return None
    size_raw = match.group("size")
    size = 0 if size_raw == "-" else int(size_raw)
    return AccessRecord(
        host=match.group("host"),
        timestamp=match.group("ts"),
        method=method,
        path=path,
        status=status,
        size=size,
        user_agent=match.group("ua") or "",
    )