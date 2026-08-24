"""AISO-119 §5.1 — IPv4/IPv6 normalisation.

Per the detection contract:
  - IPv4: pass-through after `socket.inet_aton`.
  - IPv6: lowercase, strip `zone_id` (`%eth0`), expand `::` to canonical
    form via `socket.inet_ntop(socket.AF_INET6, socket.inet_pton(AF_INET6, addr))`.
  - Loopback / private / link-local / ULA / 0.0.0.0 are tagged with a
    `scope` label and excluded from D3/D4 thresholds (only listed in the
    report).

This module is the canonical implementation. The access_log analyzer
will use it once Stage 2 wires it into the aggregator; for now it is
shipped as a stand-alone helper so its contract can be locked under
unit tests before downstream changes.
"""

from __future__ import annotations

import socket
from typing import Literal

Scope = Literal["public", "loopback", "private", "linklocal", "ula", "unspecified"]


def _scope_for_v4(packed: bytes) -> Scope:
    """Return the RFC-defined scope of an IPv4 address (4-byte packed)."""
    a = packed[0]
    if a == 0:
        return "unspecified"
    if a == 127:
        return "loopback"
    if a == 10:
        return "private"
    if a == 169 and packed[1] == 254:
        return "linklocal"
    if a == 172 and 16 <= packed[1] <= 31:
        return "private"
    if a == 192 and packed[1] == 168:
        return "private"
    if a == 100 and 64 <= packed[1] <= 127:  # CGNAT — informational
        return "private"
    if a == 192 and packed[2] == 0 and packed[3] in (0, 2):  # TEST-NET
        return "private"
    return "public"


def _scope_for_v6(packed: bytes) -> Scope:
    """Return the RFC-defined scope of an IPv6 address (16-byte packed)."""
    if packed == b"\x00" * 15 + b"\x01":
        return "loopback"
    if packed == b"\x00" * 16:
        return "unspecified"
    # fe80::/10 — link-local
    if packed[0] == 0xFE and (packed[1] & 0xC0) == 0x80:
        return "linklocal"
    # fc00::/7 — ULA
    if (packed[0] & 0xFE) == 0xFC:
        return "ula"
    # ::ffff:a.b.c.d — IPv4-mapped
    if packed[:12] == b"\x00" * 10 + b"\xff\xff":
        return _scope_for_v4(packed[12:])
    return "public"


def normalise_ip(addr: str) -> tuple[str, Scope]:
    """Return (canonical_ip, scope) for a valid IPv4/IPv6 literal.

    The input may be a bare IPv6 (`2a06:98c0:3600::103`), a
    bracket-and-port form (`[2a06:98c0:3600::103]:443`), or with a
    zone-id suffix (`fe80::1%eth0`).

    Raises `ValueError` on any malformed input.
    """
    if not addr:
        raise ValueError("empty IP literal")

    # Strip a trailing port from bracketed-IPv6, e.g. "[...]:443".
    if addr.startswith("[") and "]" in addr:
        addr = addr[1 : addr.index("]")]

    # Strip a zone-id (RFC 6874 / RFC 4007). `socket.inet_pton` itself
    # does NOT accept zone-ids, so we must remove the suffix before
    # parsing.
    if "%" in addr:
        addr = addr.split("%", 1)[0]

    # Try IPv4 first (the contract §3.1 says IPv4 is tried first;
    # this also avoids `::` being misclassified in the colon case).
    try:
        packed = socket.inet_pton(socket.AF_INET, addr)
        return socket.inet_ntop(socket.AF_INET, packed), _scope_for_v4(packed)
    except OSError:
        pass

    # Fall back to IPv6.
    try:
        packed = socket.inet_pton(socket.AF_INET6, addr)
    except OSError as exc:
        raise ValueError(f"not a valid IPv4 or IPv6 address: {addr!r}") from exc

    return socket.inet_ntop(socket.AF_INET6, packed), _scope_for_v6(packed)


def is_internal_scope(scope: Scope) -> bool:
    """Return True if the scope is non-public (must be excluded from D3/D4)."""
    return scope != "public"