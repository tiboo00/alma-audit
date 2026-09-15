"""Public API for the firewall_state analyzer.

Detects which firewall engines (CSF, firewalld, iptables, nftables)
are installed on the host and which are running. Emits findings when
no firewall is present at all, when an installed engine is not
running, and when the active ruleset is effectively empty.

Two data sources, picked automatically:

*   **Layer A** — ``tools/port_audit.sh`` writes the
    ``firewall_engines`` and ``firewall_rules_summary`` blocks of the
    JSON. The analyzer reads this when present.
*   **Layer B** — pure read-only fallback. The analyzer probes the
    filesystem directly (config files in ``/etc/csf``, ``/etc/firewalld``,
    ``/etc/sysconfig/iptables*``, ``/etc/nftables.conf``) plus the
    ``/usr/sbin/{firewalld,iptables*,nft}`` binary presence via
    ``fs.is_file``. No subprocess.

Public entry point: ``analyze_firewall_state``.

Detection rules (per AISO-220 plan §5.2):

*   **D25** CRITICAL — no firewall engine installed/running.
*   **D26** CRITICAL — engine installed but not running.
*   **D27** CRITICAL — CSF installed but ``lfd`` daemon dead (cPanel
    reality: ``lfd`` is the actual blocker; a non-running lfd leaves
    the host's CSF config unenforced).
*   **D28** WARN     — installed + running but the ruleset is
    effectively empty (iptables_filter_count == 0 AND
    nftables_ruleset_lines < 5). A "running but empty" firewall is
    indistinguishable from no firewall at all.

Tests live at ``tests/test_firewall_state.py``.
"""
from __future__ import annotations

from .analyzer import analyze_firewall_state
from .aggregator import (
    EngineState,
    FirewallSnapshot,
    add_engine,
    finalize,
    new_snapshot,
)
from .parser import parse_layer_a_json, parse_filesystem_probes
from .settings import (
    DEFAULT_LAYER_A_JSON_NAME,
    DEFAULT_PROBES,
    DEFAULT_RULES,
    ENGINE_NAMES,
)

__all__ = [
    "analyze_firewall_state",
    "EngineState",
    "FirewallSnapshot",
    "add_engine",
    "finalize",
    "new_snapshot",
    "parse_layer_a_json",
    "parse_filesystem_probes",
    "DEFAULT_PROBES",
    "DEFAULT_RULES",
    "ENGINE_NAMES",
]