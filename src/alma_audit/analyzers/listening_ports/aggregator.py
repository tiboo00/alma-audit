"""Aggregator for the listening_ports analyzer.

Holds the per-port listener inventory the rules layer reads. The
shape is intentionally compact — one row per (proto, address, port)
— so a single 0.0.0.0:3306 + [::]:3306 dual-stack pair is two rows
the rule layer can correlate via D23.

Streaming shape (``new_snapshot()`` / ``add_listener()`` /
``finalize()``) matches the convention used by ``secure_log`` and
``ssh_hardening``. The orchestrator calls them in order; tests call
``finalize(new_snapshot())`` to get an empty default.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from .parser import Listener


@dataclass
class ListenerSnapshot:
    """In-memory inventory of every TCP/UDP listener the audit collected.

    ``listeners`` is the canonical list, in arrival order. The rule
    layer iterates this directly; we keep it as a list (not a dict) so
    dual-stack pairs (0.0.0.0 + ::) preserve their original ordering
    and the operator can match by index in ``details``.

    ``sources`` records which data source produced the snapshot
    (Layer A JSON path, or ``layer_b:/proc/net/tcp,/proc/net/udp,...``)
    so the INFO summary finding can name it.

    ``mysql_bind_address`` is carried through to D22 — it's a separate
    config-file signal, not a listener, but we put it on the snapshot
    so the rule layer has a single source of truth.
    """

    listeners: list[Listener] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    mysql_bind_address: str | None = None

    def add(self, listener: Listener) -> None:
        self.listeners.append(listener)

    def __len__(self) -> int:
        return len(self.listeners)


def new_snapshot() -> ListenerSnapshot:
    """Allocate an empty snapshot."""
    return ListenerSnapshot()


def add_listener(snap: ListenerSnapshot, listener: Listener) -> None:
    """Fold one parsed ``Listener`` into the snapshot.

    The aggregator keeps every listener — duplicates are deduplicated
    in ``finalize`` (Layer A's snapshot can repeat listeners across
    both v4 and v6 paths).
    """
    snap.add(listener)


def finalize(snap: ListenerSnapshot) -> dict[str, Any]:
    """Render the snapshot to a JSON-serialisable summary.

    The rule layer never reads this directly (it iterates
    ``snap.listeners``), but the orchestrator's INFO finding embeds
    ``details`` from this dict so the operator can see what was found.
    """
    # Public-bind breakdown — the operator-eye metric.
    by_proto: Counter[str] = Counter()
    by_public: Counter[str] = Counter()
    for L in snap.listeners:
        by_proto[L.proto] += 1
        # ``is_public_bind`` matches the same logic the rule layer uses
        # (``PUBLIC_BIND_VALUES``). We import here to avoid a circular
        # import — settings is a leaf.
        from .settings import PUBLIC_BIND_VALUES  # noqa: PLC0415

        if L.address in PUBLIC_BIND_VALUES:
            by_public[L.proto] += 1
    return {
        "listener_count": len(snap.listeners),
        "by_proto": dict(by_proto),
        "public_bind_count": dict(by_public),
        "sources": list(snap.sources),
        "mysql_bind_address": snap.mysql_bind_address,
    }


def dedupe_listeners(
    listeners: Iterable[Listener],
) -> list[Listener]:
    """Collapse identical (proto, address, port, state) rows.

    Layer A's sidecar emits one row per (proto, address, port) pair;
    Layer B's /proc/net reads emit the same. When the orchestrator
    runs Layer A and Layer B together (it doesn't, today — Layer A
    is exclusive — but kept for safety), the dedupe keeps the rule
    layer's counts honest.
    """
    seen: set[tuple[str, str, int, str]] = set()
    out: list[Listener] = []
    for L in listeners:
        key = (L.proto, L.address, L.port, L.state)
        if key in seen:
            continue
        seen.add(key)
        out.append(L)
    return out