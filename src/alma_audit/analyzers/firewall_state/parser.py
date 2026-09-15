"""Parser for the firewall_state analyzer.

Two inputs:

*   ``parse_layer_a_json`` — reads the JSON the ``tools/port_audit.sh``
    sidecar wrote; extracts the ``firewall_engines`` + ``firewall_rules_summary``
    blocks.
*   ``parse_filesystem_probes`` — pure read-only fallback. Walks the
    ``DEFAULT_PROBES`` list and reports which engines are installed
    (config dir + binary present). Doesn't try to detect "running"
    state — that requires ``systemctl`` or a PID file, both of which
    the read-only contract forbids — so Layer B reports installed=YES
    and running="unknown"; the rule layer downgrades D26/D27 from
    CRITICAL to WARN when running is unknown.

The parser is pure — no I/O outside the injected ``FileSystem`` and
the JSON string. The orchestrator handles FileNotFoundError /
JSONDecodeError so the parser only sees good input.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from ...runners import FileSystem
from .settings import DEFAULT_PROBES, EngineProbe

_LOG = logging.getLogger("alma_audit")


@dataclass(frozen=True)
class EngineState:
    """One firewall engine's installed/running state.

    ``installed`` is True when the engine's config files or binary
    exist on the host. ``running`` is True/False when Layer A's
    sidecar can detect a daemon; ``None`` when neither source can tell
    (e.g. Layer B without systemctl access).

    ``version`` is a string or None — best-effort, surfaced in INFO
    findings for the operator.

    ``binary`` is the resolved path to the engine's main binary (when
    Layer A could resolve it). ``None`` when only the config dir is
    present (e.g. a container with config files but no binaries).
    """

    name: str
    installed: bool
    running: bool | None
    version: str | None = None
    binary: str | None = None
    # Engine-specific extras:
    #   * csf.denylist_count: integer or None
    #   * iptables.filter_count, iptables.nat_count: integer
    #   * nftables.ruleset_lines: integer
    denylist_count: int | None = None
    filter_count: int | None = None
    nat_count: int | None = None
    ruleset_lines: int | None = None


@dataclass(frozen=True)
class LayerAParseResult:
    """The full Layer A payload parsed into the shapes the analyzer wants."""

    engines: list[EngineState]
    # iptables_filter_count + nftables_ruleset_lines — kept on the
    # top-level so D28 doesn't have to walk the engine list.
    iptables_filter_count: int
    nftables_ruleset_lines: int
    source: str


# ---------------------------------------------------------------------------
# Layer A parser
# ---------------------------------------------------------------------------

_LAYER_A_SUPPORTED_VERSIONS: frozenset[int] = frozenset({1})


def _eng_from_layer_a(name: str, block: dict) -> EngineState:
    """Translate one ``firewall_engines.<name>`` block to ``EngineState``."""
    return EngineState(
        name=name,
        installed=bool(block.get("installed", False)),
        running=block.get("running") if isinstance(block.get("running"), bool) else None,
        version=block.get("version") if isinstance(block.get("version"), str) else None,
        binary=block.get("binary") if isinstance(block.get("binary"), str) else None,
        denylist_count=(
            block.get("denylist_count")
            if isinstance(block.get("denylist_count"), int) else None
        ),
    )


def parse_layer_a_json(text: str) -> LayerAParseResult:
    """Parse the sidecar JSON text into a ``LayerAParseResult``."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        _LOG.warning("firewall_state: layer A JSON decode error: %s", exc)
        return LayerAParseResult(
            engines=[], iptables_filter_count=0,
            nftables_ruleset_lines=0, source="layer_a",
        )
    if not isinstance(data, dict):
        return LayerAParseResult(
            engines=[], iptables_filter_count=0,
            nftables_ruleset_lines=0, source="layer_a",
        )
    schema_version = data.get("schema_version")
    if schema_version not in _LAYER_A_SUPPORTED_VERSIONS:
        _LOG.warning(
            "firewall_state: unsupported layer A schema_version=%r",
            schema_version,
        )
        return LayerAParseResult(
            engines=[], iptables_filter_count=0,
            nftables_ruleset_lines=0, source="layer_a",
        )

    engines_block = data.get("firewall_engines") or {}
    engines: list[EngineState] = []
    if isinstance(engines_block, dict):
        for name in ("csf", "firewalld", "iptables", "nftables"):
            block = engines_block.get(name)
            if not isinstance(block, dict):
                continue
            engines.append(_eng_from_layer_a(name, block))

    rules = data.get("firewall_rules_summary") or {}
    iptables_filter_count = (
        rules.get("iptables_filter_count")
        if isinstance(rules.get("iptables_filter_count"), int) else 0
    )
    nftables_ruleset_lines = (
        rules.get("nftables_ruleset_lines")
        if isinstance(rules.get("nftables_ruleset_lines"), int) else 0
    )

    # Pyright: the ``rules.get(...) if isinstance(...) else 0`` chains
    # widen to ``int | None`` in its type inference. Coerce to int to
    # match the dataclass field type exactly.
    iptables_filter_count = int(iptables_filter_count or 0)
    nftables_ruleset_lines = int(nftables_ruleset_lines or 0)

    return LayerAParseResult(
        engines=engines,
        iptables_filter_count=iptables_filter_count,
        nftables_ruleset_lines=nftables_ruleset_lines,
        source="layer_a",
    )


# ---------------------------------------------------------------------------
# Layer B parser — filesystem probes
# ---------------------------------------------------------------------------


def _probe_engine(
    probe: EngineProbe, fs: FileSystem,
) -> EngineState:
    """Run one engine's filesystem probes.

    Detection rule: an engine is "installed" when at least one of its
    config dirs OR binaries exists. We don't try to detect running
    state from the filesystem — that needs ``systemctl`` or a PID
    file, both forbidden by the read-only contract.
    """
    config_hit = any(
        fs.is_dir(p) for p in probe.config_dirs
    )
    binary_hit: str | None = None
    for path in probe.binaries:
        if fs.is_file(path):
            binary_hit = path
            break
    installed = bool(config_hit or binary_hit)
    return EngineState(
        name=probe.name,
        installed=installed,
        running=None,           # unknown without Layer A
        version=None,
        binary=binary_hit,
    )


def parse_filesystem_probes(
    fs: FileSystem,
    probes: tuple[EngineProbe, ...] = DEFAULT_PROBES,
) -> LayerAParseResult:
    """Walk the probes list and report which engines are installed.

    Always returns four ``EngineState`` rows (one per engine) — even
    if the engine isn't installed — so the rule layer can iterate a
    fixed shape. The ``installed`` flag carries the actual answer.

    The iptables/nftables rule counts are 0 in Layer B (the rule layer
    only escalates them to WARN at the D28 threshold, and 0 always
    trips that threshold by design — D28 is precisely the "no rules
    detected" alarm).
    """
    engines = [_probe_engine(p, fs) for p in probes]
    return LayerAParseResult(
        engines=engines,
        iptables_filter_count=0,
        nftables_ruleset_lines=0,
        source="layer_b:fs",
    )