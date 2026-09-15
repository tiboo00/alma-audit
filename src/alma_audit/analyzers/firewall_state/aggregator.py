"""Aggregator for the firewall_state analyzer.

Holds the per-engine installed/running matrix the rules layer reads.
Same streaming pattern as ``listening_ports``: ``new_snapshot()`` /
``add_engine()`` / ``finalize()``.

The snapshot also carries the iptables / nftables ruleset counts
separately from the per-engine block so D28 can read them without
walking the engine list twice.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .parser import EngineState


@dataclass
class FirewallSnapshot:
    """In-memory state of every firewall engine the audit collected."""

    engines: list[EngineState] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    iptables_filter_count: int = 0
    nftables_ruleset_lines: int = 0

    def add(self, engine: EngineState) -> None:
        self.engines.append(engine)


def new_snapshot() -> FirewallSnapshot:
    """Allocate an empty snapshot."""
    return FirewallSnapshot()


def add_engine(snap: FirewallSnapshot, engine: EngineState) -> None:
    """Fold one parsed ``EngineState`` into the snapshot."""
    snap.add(engine)


def _replace_engine(snap: FirewallSnapshot, engine: EngineState) -> None:
    """Replace an existing engine's state (Layer A wins over Layer B)."""
    for i, e in enumerate(snap.engines):
        if e.name == engine.name:
            snap.engines[i] = engine
            return
    snap.add(engine)


def finalize(snap: FirewallSnapshot) -> dict[str, Any]:
    """Render the snapshot to a JSON-serialisable summary."""
    by_engine: dict[str, dict[str, Any]] = {}
    for e in snap.engines:
        by_engine[e.name] = {
            "installed": e.installed,
            "running": e.running,
            "version": e.version,
            "binary": e.binary,
            "denylist_count": e.denylist_count,
            "filter_count": e.filter_count,
            "nat_count": e.nat_count,
            "ruleset_lines": e.ruleset_lines,
        }
    return {
        "engines": by_engine,
        "sources": list(snap.sources),
        "iptables_filter_count": snap.iptables_filter_count,
        "nftables_ruleset_lines": snap.nftables_ruleset_lines,
    }


def merge_layer_a_into_b(
    snap: FirewallSnapshot,
    layer_a_engines: list[EngineState],
    iptables_filter_count: int,
    nftables_ruleset_lines: int,
) -> None:
    """Fold Layer A's engine data on top of Layer B's snapshot.

    Layer A wins for every field it can resolve. The count fields
    (``iptables_filter_count``, ``nftables_ruleset_lines``) come from
    Layer A because Layer B never sees actual rule content.
    """
    for eng in layer_a_engines:
        _replace_engine(snap, eng)
    if iptables_filter_count:
        snap.iptables_filter_count = iptables_filter_count
    if nftables_ruleset_lines:
        snap.nftables_ruleset_lines = nftables_ruleset_lines