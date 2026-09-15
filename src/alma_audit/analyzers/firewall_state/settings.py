"""Settings for the firewall_state analyzer.

Single source of truth for which engines to detect, where to look
for their config files, and the ruleset-empty thresholds. All
YAML-overridable via ``modules.firewall_state.*``.

The four supported engines are the de-facto EL8/EL9 firewall stack:

  * **CSF** — ConfigServer Firewall, the standard cPanel firewall.
    Detected by ``/etc/csf/csf.conf`` (or ``/etc/csf/`` dir).
  * **firewalld** — RHEL / AlmaLinux / CloudLinux default since EL7.
    Detected by ``/etc/firewalld/`` dir OR the ``firewall-cmd``
    binary.
  * **iptables** — legacy EL7 firewall. Still in use on hosts where
    CSF was installed but not yet converted to nftables, and on
    hosts that explicitly opt out of firewalld. Detected by the
    ``iptables`` binary (``/usr/sbin/iptables`` or
    ``/usr/sbin/iptables-legacy``).
  * **nftables** — nft successor to iptables. Some AlmaLinux 9 hosts
    run it by default; cPanel/WHMCS hosts typically use iptables-
    nft-multi compatibility shim. Detected by the ``nft`` binary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# The engine names we surface. Used as keys in the snapshot + JSON.
ENGINE_NAMES: tuple[str, ...] = ("csf", "firewalld", "iptables", "nftables")


# Default filename for the sidecar JSON. The orchestrator resolves
# the full path from ``paths.output_dir`` (set by ``runner.py`` from
# the CLI ``--output`` flag) + this filename.
DEFAULT_LAYER_A_JSON_NAME: str = "port-audit.json"


@dataclass(frozen=True)
class EngineProbe:
    """Where to look for an engine's config files + binary.

    The orchestrator's Layer B parser iterates these probes against the
    injected ``FileSystem`` to detect installed engines without
    subprocess.
    """

    name: str
    # Config-dir probe — a directory whose presence + readable child
    # counts as "installed". ``[]`` means the engine is detected by
    # binary alone (e.g. nftables — no canonical config dir).
    config_dirs: tuple[str, ...]
    # Binary path(s) to check. First match wins.
    binaries: tuple[str, ...]


# Filesystem probes used by Layer B. The orchestrator uses these when
# Layer A's JSON is missing.
DEFAULT_PROBES: tuple[EngineProbe, ...] = (
    EngineProbe(
        name="csf",
        config_dirs=("/etc/csf",),
        binaries=("/usr/sbin/csf", "/usr/bin/csf"),
    ),
    EngineProbe(
        name="firewalld",
        config_dirs=("/etc/firewalld",),
        binaries=(
            "/usr/bin/firewall-cmd",
            "/usr/sbin/firewall-cmd",
        ),
    ),
    EngineProbe(
        name="iptables",
        config_dirs=("/etc/sysconfig",),  # iptables-config + iptables rules live here
        binaries=(
            "/usr/sbin/iptables",
            "/usr/sbin/iptables-legacy",
            "/usr/sbin/xtables-nft-multi",
        ),
    ),
    EngineProbe(
        name="nftables",
        config_dirs=("/etc/nftables.d",),  # /etc/nftables.conf is a file, not dir
        binaries=("/usr/sbin/nft", "/usr/bin/nft"),
    ),
)


# Rule thresholds. Operators tune via YAML.
DEFAULT_RULES: dict[str, Any] = {
    # Path to the sidecar JSON. ``None`` → orchestrator auto-discovers
    # ``<output>/port-audit.json``.
    "layer_a_json_path": None,
    # When True, fall back to filesystem probes when Layer A's JSON is
    # missing or unreadable.
    "fallback_to_fs": True,
    # Ruleset "effectively empty" threshold for D28. iptables_filter
    # rules below this AND nftables ruleset lines below this ⇒ WARN.
    # Numbers picked from a typical AlmaLinux 8 baseline (a host
    # with default iptables rules has ~30 lines; a host with explicit
    # CSF integration has 80+).
    "iptables_filter_min_lines": 5,
    "nftables_min_lines": 5,
    # When True, missing ``lfd`` daemon on a CSF-installed host
    # triggers D27. Disable for hosts that run CSF's own process
    # management under a non-standard service name.
    "csf_check_lfd": True,
}