"""cPHulk log line parser.

Pure parser: one line → one `CphulkRecord` (or `None` if the line is
not a security-relevant event we know about). The aggregator lives in
`aggregator.py`; detection rules live in `rules.py`.

cPHulk log format (cPanel default):

  [2026-08-17 04:12:34 -0500] info [cphulkd] message...
  [2026-08-17 04:12:35 -0500] warn [cphulkd] Brute force attempt \
      detected for user "root" from IP 1.2.3.4 - too many authentication failures
  [2026-08-17 04:12:36 -0500] critical [cphulkd] Account "evil" blocked
  [2026-08-17 04:12:37 -0500] info [cphulkd] Loaded 10000 netblocks

The parser is forgiving:
  - The timestamp bracket is captured verbatim; we don't try to parse
    it. The scan window is the file's content, so the timestamp is
    diagnostic only.
  - The level is one of `info`, `warn`, `critical` (case-insensitive).
  - The service tag must be `[cphulkd]`; other services share the
    file via syslog forwarding (rare in practice) and we ignore them.
  - The message body is matched against known event shapes.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import NamedTuple, Optional


class CphulkLevel(str, Enum):
    INFO = "info"
    WARN = "warn"
    CRITICAL = "critical"


class CphulkRecord(NamedTuple):
    """One classified cPHulk log line.

    `event` is one of: `brute_force`, `account_blocked`,
    `account_unblocked`, `ip_blocked`, `ip_unblocked`, `band_event`.
    `level` is the bracket tag from the source line.
    """

    event: str
    level: CphulkLevel
    source_ip: Optional[str]
    username: Optional[str]
    raw: str


# Header: "[2026-08-17 04:12:34 -0500] info [cphulkd] ". The timestamp
# itself is captured verbatim — we don't need it for detection.
_HEADER_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+"
    r"(?P<level>info|warn|critical)\s+"
    r"\[cphulkd\]\s+",
    re.IGNORECASE,
)

# "Brute force attempt detected for user "root" from IP 1.2.3.4 - ..."
_BRUTE_FORCE_RE = re.compile(
    r"Brute force attempt detected for user\s+"
    r'"?(?P<user>[^"\s]+)"?\s+from IP\s+'
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|\S+)",
    re.IGNORECASE,
)

# "Account "evil" blocked"
_ACCOUNT_BLOCK_RE = re.compile(
    r'Account\s+"?'
    r'(?P<user>[^"\s]+)"?\s+(?P<action>blocked|unblocked)',
    re.IGNORECASE,
)

# "IP 1.2.3.4 blocked"
_IP_BLOCK_RE = re.compile(
    r"IP\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|\S+)\s+(?P<action>blocked|unblocked)",
    re.IGNORECASE,
)


def parse_line(line: str) -> CphulkRecord | None:
    """Parse a single cPHulk log line; return None for unclassified lines."""
    m = _HEADER_RE.match(line)
    if not m:
        return None
    level = CphulkLevel(m.group("level").lower())
    rest = line[m.end():]

    bf = _BRUTE_FORCE_RE.search(rest)
    if bf:
        return CphulkRecord(
            event="brute_force",
            level=level,
            source_ip=bf.group("ip"),
            username=bf.group("user"),
            raw=line,
        )
    ab = _ACCOUNT_BLOCK_RE.search(rest)
    if ab:
        action = ab.group("action").lower()
        return CphulkRecord(
            event="account_" + action,
            level=level,
            source_ip=None,
            username=ab.group("user"),
            raw=line,
        )
    ib = _IP_BLOCK_RE.search(rest)
    if ib:
        action = ib.group("action").lower()
        return CphulkRecord(
            event="ip_" + action,
            level=level,
            source_ip=ib.group("ip"),
            username=None,
            raw=line,
        )
    # Anything else is informational noise (Loaded X netblocks,
    # Processing band, ...). Return None so the aggregator only
    # counts events we know about.
    return None