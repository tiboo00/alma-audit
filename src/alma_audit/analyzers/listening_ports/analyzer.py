"""Orchestrator for the listening_ports analyzer (AISO-220).

Picks Layer A (sidecar JSON) when available, falls back to Layer B
(``/proc/net/tcp{,6}`` + ``/proc/net/udp{,6}``) otherwise. The
``rules`` dict carries the operator's YAML config; the orchestrator
plumbs the right paths through.

Public entry point: ``analyze_listening_ports``.

Layer A / Layer B cooperation:

*   If ``rules.layer_a_json_path`` is set (or the orchestrator's
    ``paths.port_audit_json`` default points to an existing file), we
    use that JSON.
*   On missing file OR unreadable file OR JSON-decode error, the
    orchestrator logs the failure and falls back to Layer B when
    ``rules.fallback_to_proc`` is True (the default).
*   Layer B never fails the audit — a missing ``/proc`` is an INFO
    finding so the operator knows the analyzer ran in degraded mode.

The orchestrator writes a single INFO summary finding regardless of
the data path so the operator always sees a snapshot summary
(listener count, source path, public-bind breakdown).
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from ...models import Finding, Severity
from ...runners import FileSystem
from .aggregator import (
    ListenerSnapshot,
    add_listener,
    dedupe_listeners,
    finalize,
    new_snapshot,
)
from .parser import LayerAParseResult, parse_layer_a_json, parse_proc_net
from .rules import all_findings
from .settings import DEFAULT_LAYER_A_JSON_NAME, DEFAULT_RULES

_LOG = logging.getLogger("alma_audit")


def _try_layer_a(
    fs: FileSystem, layer_a_json_path: str | None,
) -> LayerAParseResult | None:
    """Read the sidecar JSON via the injected ``FileSystem``.

    Returns ``None`` when the path is unset OR the file is missing OR
    the JSON cannot be decoded. The orchestrator decides what to do
    with ``None`` (typically: fall back to Layer B).
    """
    if not layer_a_json_path:
        return None
    if not fs.is_file(layer_a_json_path):
        return None
    try:
        lines = fs.read_text(layer_a_json_path)
    except (OSError, FileNotFoundError) as exc:
        _LOG.warning(
            "listening_ports: layer A read failed (%s): %s",
            layer_a_json_path, exc,
        )
        return None
    text = "\n".join(lines)
    try:
        result = parse_layer_a_json(text)
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("listening_ports: layer A parse error: %s", exc)
        return None
    # ``parse_layer_a_json`` is tolerant — only returns None when it
    # detects a missing listeners array. We trust its decision and
    # fall through to Layer B only when the result has zero listeners.
    return result


def _resolve_layer_a_path(
    rules: dict[str, Any],
    fs: FileSystem,
) -> str | None:
    """Pick the JSON path to read — explicit YAML override wins.

    The orchestrator passes ``paths.port_audit_json`` (set by
    ``runner.py`` from the CLI ``--output`` flag) as the
    ``rules.layer_a_json_path`` default when the YAML config didn't
    specify it. This helper applies that convention.
    """
    return rules.get("layer_a_json_path")


def analyze_listening_ports(
    fs: FileSystem,
    *,
    rules: dict[str, Any] | None = None,
) -> list[Finding]:
    """Run the listening_ports analyzer.

    Returns a flat list of findings. Always emits at least one INFO
    summary finding — even when both Layer A and Layer B returned zero
    listeners (the analyzer ran; the host has no listening ports, or
    the audit user can't see them).
    """
    settings = {**DEFAULT_RULES, **(rules or {})}
    findings: list[Finding] = []

    layer_a_path = _resolve_layer_a_path(settings, fs)
    layer_a_result = _try_layer_a(fs, layer_a_path)
    layer_b_result: LayerAParseResult | None = None

    if layer_a_result is None or not layer_a_result.listeners:
        if settings.get("fallback_to_proc", True):
            layer_b_result = parse_proc_net(fs, settings["proc_root"])
        else:
            layer_b_result = None

    snap = new_snapshot()
    snap.sources = []
    if layer_a_result is not None and layer_a_result.listeners:
        snap.sources.append("layer_a:" + (layer_a_path or "unset"))
        snap.mysql_bind_address = layer_a_result.mysql_bind_address
        for L in layer_a_result.listeners:
            add_listener(snap, L)
    if layer_b_result is not None:
        snap.sources.append(layer_b_result.source)
        # Layer A wins for mysql_bind_address — Layer B doesn't carry it.
        for L in layer_b_result.listeners:
            add_listener(snap, L)

    # Dedupe across Layer A + Layer B (Layer A alone already
    # idempotent; Layer B reads /proc four times).
    snap.listeners = dedupe_listeners(snap.listeners)

    if not snap.listeners:
        # Both layers empty — emit an INFO summary so the operator
        # knows the analyzer ran. Whether it's an "everything is
        # perfect" or "we can't see anything" signal is ambiguous;
        # the source line in details disambiguates.
        findings.append(Finding(
            module="listening_ports",
            severity=Severity.INFO,
            title="No listening ports found",
            description=(
                "Neither the sidecar JSON nor /proc/net/{tcp,udp}{,6} "
                "yielded any listeners. On a healthy host this is "
                "impossible (every Linux box has at least one "
                "listener) — the audit user likely lacks permission to "
                "read /proc/net or the sidecar script didn't run."
            ),
            details={
                "layer_a_path": layer_a_path,
                "layer_a_attempted": layer_a_path is not None,
                "layer_b_attempted": layer_b_result is not None,
                "sources": snap.sources,
            },
            recommendation=(
                "If the sidecar script wasn't run, invoke "
                "``tools/port_audit.sh <output-dir>`` before the next "
                "audit. If /proc/net isn't readable, grant the audit "
                "user ``CAP_SYS_PTRACE`` or run the audit as root."
            ),
        ))
        return findings

    summary = finalize(snap)
    findings.append(Finding(
        module="listening_ports",
        severity=Severity.INFO,
        title=(
            f"{summary['listener_count']} listener(s) "
            f"(public: {sum(summary['public_bind_count'].values())})"
        ),
        description=(
            f"Listener snapshot complete from {', '.join(snap.sources)}. "
            f"Public-bind breakdown by protocol: "
            f"{summary['public_bind_count']}."
        ),
        details=summary,
    ))
    findings.extend(all_findings(snap, settings))
    return findings


__all__ = ["analyze_listening_ports", "DEFAULT_LAYER_A_JSON_NAME"]