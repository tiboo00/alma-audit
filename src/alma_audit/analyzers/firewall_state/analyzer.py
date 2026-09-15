"""Orchestrator for the firewall_state analyzer (AISO-220).

Picks Layer A (sidecar JSON) when available, falls back to Layer B
(f filesystem probes) otherwise. The ``rules`` dict carries the
operator's YAML config; the orchestrator plumbs the right paths
through.

Public entry point: ``analyze_firewall_state``.

The orchestrator's behavior mirrors ``listening_ports``: Layer A is
preferred when present (richer data — running state + rule counts),
Layer B fires only when Layer A is absent OR produces zero engines.

Layer A vs Layer B data fusion:

*   When Layer A returns a populated engine list, we use it. Layer B
    is skipped.
*   When Layer A returns [] (the sidecar couldn't read any daemon
    state), Layer B's filesystem probes fill in the installed-vs-not
    matrix. The orchestrator logs this fallback so the operator sees
    it in the report.

An empty-state INFO finding always surfaces so the operator knows
whether the analyzer ran or not.
"""
from __future__ import annotations

import logging
from typing import Any

from ...models import Finding, Severity
from ...runners import FileSystem
from .aggregator import (
    FirewallSnapshot,
    add_engine,
    finalize,
    merge_layer_a_into_b,
    new_snapshot,
)
from .parser import (
    LayerAParseResult,
    parse_filesystem_probes,
    parse_layer_a_json,
)
from .rules import all_findings
from .settings import DEFAULT_LAYER_A_JSON_NAME, DEFAULT_RULES

_LOG = logging.getLogger("alma_audit")


def _try_layer_a(
    fs: FileSystem, layer_a_json_path: str | None,
) -> LayerAParseResult | None:
    """Read the sidecar JSON via the injected ``FileSystem``."""
    if not layer_a_json_path:
        return None
    if not fs.is_file(layer_a_json_path):
        return None
    try:
        lines = fs.read_text(layer_a_json_path)
    except (OSError, FileNotFoundError) as exc:
        _LOG.warning(
            "firewall_state: layer A read failed (%s): %s",
            layer_a_json_path, exc,
        )
        return None
    text = "\n".join(lines)
    try:
        return parse_layer_a_json(text)
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("firewall_state: layer A parse error: %s", exc)
        return None


def analyze_firewall_state(
    fs: FileSystem,
    *,
    rules: dict[str, Any] | None = None,
) -> list[Finding]:
    """Run the firewall_state analyzer."""
    settings = {**DEFAULT_RULES, **(rules or {})}
    findings: list[Finding] = []

    layer_a_path = settings.get("layer_a_json_path")
    layer_a_result = _try_layer_a(fs, layer_a_path)
    layer_b_result: LayerAParseResult | None = None

    if layer_a_result is None or not layer_a_result.engines:
        if settings.get("fallback_to_fs", True):
            layer_b_result = parse_filesystem_probes(fs)
        else:
            layer_b_result = None

    snap = new_snapshot()
    snap.sources = []
    if layer_a_result is not None and layer_a_result.engines:
        snap.sources.append("layer_a:" + (layer_a_path or "unset"))
        merge_layer_a_into_b(
            snap,
            layer_a_result.engines,
            layer_a_result.iptables_filter_count,
            layer_a_result.nftables_ruleset_lines,
        )
    if layer_b_result is not None:
        snap.sources.append(layer_b_result.source)
        for engine in layer_b_result.engines:
            add_engine(snap, engine)
        # Layer B never sees rule counts (read-only contract) — leave
        # the Layer A values intact if any, else 0.

    if not snap.engines:
        # Empty snapshot — degenerate; shouldn't happen because the
        # parser always emits 4 engine rows even when nothing is
        # installed. Defensive only.
        findings.append(Finding(
            module="firewall_state",
            severity=Severity.INFO,
            title="No firewall engine data collected",
            description=(
                "The analyzer could not collect any firewall state. "
                "Either Layer A's JSON was unreadable and Layer B's "
                "filesystem probes saw no /etc/csf, /etc/firewalld, "
                "iptables, or nftables configs."
            ),
            details={"sources": snap.sources},
        ))
        return findings

    summary = finalize(snap)
    installed_names = [
        e.name for e in snap.engines if e.installed
    ]
    running_names = [
        e.name for e in snap.engines if e.running is True
    ]
    findings.append(Finding(
        module="firewall_state",
        severity=Severity.INFO,
        title=(
            f"Firewall engines: installed={installed_names or 'none'}, "
            f"running={running_names or 'unknown'}"
        ),
        description=(
            f"Firewall-state check complete from "
            f"{', '.join(snap.sources)}. "
            f"{len(installed_names)} engine(s) installed, "
            f"{len(running_names)} confirmed running."
        ),
        details=summary,
    ))
    findings.extend(all_findings(snap, settings))
    return findings


__all__ = ["analyze_firewall_state", "DEFAULT_LAYER_A_JSON_NAME"]