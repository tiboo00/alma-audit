"""Parser for the listening_ports analyzer.

Two inputs, picked by the orchestrator (``analyzer.py``):

*   ``parse_layer_a_json`` — reads the JSON the ``tools/port_audit.sh``
    sidecar wrote. Returns ``(listeners, mysql_bind_address, source)``.
*   ``parse_proc_net`` — read-only fallback. Reads
    ``/proc/net/tcp{,6}`` and ``/proc/net/udp{,6}`` line by line. The
    address:port fields are hex-encoded little-endian for IPv4 and
    hex-native for IPv6. We decode port with ``int(hex, 16)`` and the
    address with a manual byte-swap (IPv4) / grouped hex (IPv6).

Both return a normalised ``Listener`` shape so the aggregator never
has to care which source the data came from.

The parser is pure — no I/O outside the injected ``FileSystem`` (or,
for Layer A's JSON, the file the operator pre-staged at the output
path). The orchestrator handles ``FileNotFoundError`` /
``json.JSONDecodeError`` so the parser only sees good input.
"""
from __future__ import annotations

import json
import logging
import socket
import struct
from dataclasses import dataclass

from ...runners import FileSystem

_LOG = logging.getLogger("alma_audit")


@dataclass(frozen=True)
class Listener:
    """One TCP/UDP listener entry, source-agnostic.

    ``address`` is a printable IP (no brackets for IPv6 — we strip the
    surrounding ``[``/``]`` here so the rest of the pipeline doesn't
    have to). ``port`` is an integer.

    ``process`` / ``pid`` come from Layer A's snapshot only (Layer B's
    /proc/net/* doesn't carry the PID; the analyzer treats them as
    None when missing). The aggregator records them but the rule
    layer doesn't use them — the rule layer is purely port-driven.
    """

    proto: str           # "tcp" / "udp" / "tcp6" / "udp6"
    address: str         # printable IP, brackets stripped
    port: int
    state: str           # "LISTEN" / "UNCONN"
    process: str | None = None
    pid: int | None = None


@dataclass(frozen=True)
class LayerAParseResult:
    """The full Layer A payload parsed into the shapes the analyzer wants."""

    listeners: list[Listener]
    mysql_bind_address: str | None
    # Source identifier for the INFO finding so the operator knows which
    # path produced it (e.g. ``"layer_a"`` or ``"layer_b:/proc/net/tcp"``).
    source: str


# ---------------------------------------------------------------------------
# Layer A parser
# ---------------------------------------------------------------------------

# Layer A JSON schema version we accept. Mismatched versions trigger a
# warning + [] return — the analyzer's Layer B fallback picks up the
# rest.
_LAYER_A_SUPPORTED_VERSIONS: frozenset[int] = frozenset({1})


def parse_layer_a_json(text: str) -> LayerAParseResult:
    """Parse the sidecar JSON text into a ``LayerAParseResult``.

    Tolerant of missing fields: a sidecar that only had the listeners
    array still parses (mysql_bind_address becomes None).
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        _LOG.warning("listening_ports: layer A JSON decode error: %s", exc)
        return LayerAParseResult(listeners=[], mysql_bind_address=None, source="layer_a")

    if not isinstance(data, dict):
        _LOG.warning("listening_ports: layer A JSON root is not a dict")
        return LayerAParseResult(listeners=[], mysql_bind_address=None, source="layer_a")

    schema_version = data.get("schema_version")
    if schema_version not in _LAYER_A_SUPPORTED_VERSIONS:
        _LOG.warning(
            "listening_ports: unsupported layer A schema_version=%r "
            "(supported: %s) — falling back to Layer B",
            schema_version, sorted(_LAYER_A_SUPPORTED_VERSIONS),
        )
        return LayerAParseResult(listeners=[], mysql_bind_address=None, source="layer_a")

    listeners: list[Listener] = []
    raw_listeners = data.get("listeners") or []
    if not isinstance(raw_listeners, list):
        _LOG.warning("listening_ports: layer A listeners is not a list")
        raw_listeners = []
    for entry in raw_listeners:
        if not isinstance(entry, dict):
            continue
        proto = entry.get("proto")
        address = entry.get("address")
        port = entry.get("port")
        state = entry.get("state") or ("LISTEN" if proto in ("tcp", "tcp6") else "UNCONN")
        if proto not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        if not isinstance(address, str):
            continue
        if not isinstance(port, int) or not (0 <= port <= 65535):
            continue
        # Layer A may emit `null` for process/pid when the audit user
        # can't see the process table.
        proc = entry.get("process")
        pid = entry.get("pid")
        listeners.append(Listener(
            proto=proto,
            address=address,
            port=port,
            state=state,
            process=proc if isinstance(proc, str) else None,
            pid=pid if isinstance(pid, int) else None,
        ))

    bind = data.get("mysql_bind_address")
    return LayerAParseResult(
        listeners=listeners,
        mysql_bind_address=bind if isinstance(bind, str) else None,
        source="layer_a",
    )


# ---------------------------------------------------------------------------
# Layer B parser — /proc/net/tcp{,6} + /proc/net/udp{,6}
# ---------------------------------------------------------------------------

# The first column of every /proc/net/* row is the row index (sl).
# The header line carries ``sl  local_address rem_address   st tx_queue
# rx_queue tr tm->when retrnsmt   uid  timeout inode``. We only use
# columns 0 (sl) and 1 (local_address) and 3 (state for tcp only).
# Format reference: ``man 5 proc`` / kernel Documentation/filesystems/proc.txt.


def _hex_to_ip_v4(hex_ip: str) -> str:
    """Convert a ``/proc/net/tcp``-style IPv4 hex literal to a printable IP.

    The kernel writes the IPv4 bytes in little-endian order, so
    ``0100007F`` (4-byte hex) decodes to ``127.0.0.1``. We use
    ``struct`` for portability — same result as ``socket.inet_ntoa``
    on the byte-swapped input but doesn't depend on byte order.
    """
    raw = bytes.fromhex(hex_ip)
    # Reverse the 4 bytes — kernel writes little-endian, we want big.
    return socket.inet_ntoa(raw[::-1])


def _hex_to_ip_v6(hex_ip: str) -> str:
    """Convert a 32-char /proc/net/tcp6 hex literal to a printable IPv6.

    IPv6 addresses in /proc/net/tcp6 are written in the kernel's native
    byte order — they're already network byte order for IPv6, so no
    reverse is needed. We split into 4 groups of 4 hex chars (8 groups
    of 2 bytes / 16-bit words) and emit ``:``-joined ``"%x"`` strings.
    """
    # Split the 32 hex chars into 8 groups of 4 chars (each group = 16 bits).
    words = [int(hex_ip[i:i + 4], 16) for i in range(0, 32, 4)]
    # Trim leading zeros for readability.
    parts = [(f"{w:x}") for w in words]
    # ``socket.inet_ntop(socket.AF_INET6, ...)`` is the canonical call —
    # it canonicalises (compresses) the address. We don't strictly need
    # that here, but using it makes the output identical to what an
    # operator would type into ``ip -6 addr show``.
    raw = b"".join(struct.pack(">H", w) for w in words)
    return socket.inet_ntop(socket.AF_INET6, raw)


def _parse_proc_line(
    line: str, proto: str, v6: bool,
) -> Listener | None:
    """Parse a single /proc/net/{tcp,udp}{,6} data row.

    ``proto`` is the explicit proto name (``"tcp"``, ``"udp"``,
    ``"tcp6"``, ``"udp6"``) — the caller passes it because the state
    column can't distinguish TCP from UDP (both have non-empty
    state values). Returns ``None`` for unparseable rows or
    non-LISTEN TCP rows. UDP rows always pass (no LISTEN state).
    """
    parts = line.split()
    if len(parts) < 4:
        return None
    local_field = parts[1]
    state_field = parts[3]
    # ``local_field`` is ``HEX_IP:HEX_PORT``.
    try:
        hex_ip, hex_port = local_field.split(":")
    except ValueError:
        return None
    try:
        port = int(hex_port, 16)
    except ValueError:
        return None
    try:
        address = _hex_to_ip_v6(hex_ip) if v6 else _hex_to_ip_v4(hex_ip)
    except (ValueError, OSError):
        return None
    if proto in ("tcp", "tcp6"):
        # In /proc/net/tcp{,6} the listener state is "0A" (10).
        if state_field != "0A":
            return None
        state = "LISTEN"
    else:
        # UDP has no LISTEN state — every UDP socket appears as
        # state ``07`` (UNCONN). Keep all UDP rows.
        state = "UNCONN"
    return Listener(
        proto=proto,
        address=address,
        port=port,
        state=state,
        process=None,
        pid=None,
    )


def parse_proc_net(fs: FileSystem, proc_root: str = "/proc") -> LayerAParseResult:
    """Read /proc/net/tcp{,6} + /proc/net/udp{,6} and return all listeners.

    Tolerant: a missing file returns ``[]`` (the analyzer emits an INFO
    ``"no listeners found"`` finding). The caller decides whether
    that's WARN-worthy (it usually is — Layer B failing to read
    ``/proc`` strongly suggests the audit is in a chroot or container
    with reduced visibility).
    """
    listeners: list[Listener] = []
    files: list[tuple[str, str]] = [
        (f"{proc_root}/net/tcp", "tcp"),
        (f"{proc_root}/net/tcp6", "tcp6"),
        (f"{proc_root}/net/udp", "udp"),
        (f"{proc_root}/net/udp6", "udp6"),
    ]
    sources: list[str] = []
    for path, proto in files:
        if not fs.is_file(path):
            continue
        try:
            lines = fs.read_text(path)
        except (OSError, FileNotFoundError):
            continue
        sources.append(path)
        v6 = proto.endswith("6")
        for line in lines:
            # First line is the header — drop it.
            if line.startswith("  sl"):
                continue
            parsed = _parse_proc_line(line, proto=proto, v6=v6)
            if parsed is not None:
                listeners.append(parsed)
    return LayerAParseResult(
        listeners=listeners,
        mysql_bind_address=None,
        source="layer_b:" + ",".join(sources) if sources else "layer_b:none",
    )