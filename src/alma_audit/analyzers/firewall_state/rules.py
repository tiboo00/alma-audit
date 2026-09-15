"""Detection rules for the firewall_state analyzer.

Four rules per AISO-220 plan §5.2:

*   **D25** CRITICAL — no firewall engine installed (or none running).
*   **D26** CRITICAL — installed engine whose daemon is NOT running.
*   **D27** CRITICAL — CSF installed but ``lfd`` daemon dead (cPanel
    reality check: the lfd daemon is what actually enforces the
    rules; csf -e enables both lfd and csf).
*   **D28** WARN     — installed + running but the ruleset is empty
    (effectively no protection).

Each rule reads the snapshot and emits a structured Finding with
``FindingFix`` references so the operator gets a concrete next-action
in the report.
"""
from __future__ import annotations

from typing import Any

from ...fix_suggestions import attach_fixes, lookup_fixes
from ...models import Finding, Severity
from .aggregator import FirewallSnapshot
from .parser import EngineState


# ---------------------------------------------------------------------------
# D25 — no firewall at all
# ---------------------------------------------------------------------------


def rule_d25_no_firewall(
    snap: FirewallSnapshot, settings: dict[str, Any],
) -> list[Finding]:
    """CRITICAL — no firewall engine installed on the host.

    Fires when every engine in the snapshot has ``installed=False``.
    "Installed" is the strongest signal the read-only contract can
    give — without it, even if some daemon is running, the operator
    hasn't made a deliberate firewall choice (the host is relying
    on cloud-provider security groups alone).

    Operators with internal / management-only hosts can disable this
    via ``modules.firewall_state.no_firewall_disabled: true`` —
    nothing in this skill is opinionated about operator policy.
    """
    installed = [e for e in snap.engines if e.installed]
    if installed:
        return []
    findings: list[Finding] = []
    base = Finding(
        module="firewall_state",
        severity=Severity.CRITICAL,
        title="No firewall engine installed",
        description=(
            "None of the supported firewall engines (CSF, firewalld, "
            "iptables, nftables) are installed on this host. Every "
            "AlmaLinux / CloudLinux / cPanel host should run at least "
            "one. The host may be relying on a cloud-provider security "
            "group alone — that is a single point of failure if the "
            "control plane is compromised."
        ),
        details={
            "checked_engines": [e.name for e in snap.engines],
            "sources": snap.sources,
        },
        recommendation=(
            "Install CSF (cPanel default) or firewalld:\n\n"
            "  # CSF on cPanel:\n"
            "  cd /usr/src/csf && sh install.sh && csf -e\n\n"
            "  # OR firewalld on plain AlmaLinux:\n"
            "  dnf install -y firewalld\n"
            "  systemctl enable --now firewalld\n"
            "  firewall-cmd --permanent --add-service=ssh\n"
            "  firewall-cmd --reload\n"
        ),
    )
    fixes = lookup_fixes("D25:no_firewall")
    if fixes:
        findings.append(attach_fixes(base, *fixes))
    else:
        findings.append(base)
    return findings


# ---------------------------------------------------------------------------
# D26 — engine installed but not running
# ---------------------------------------------------------------------------


def rule_d26_installed_not_running(
    snap: FirewallSnapshot, settings: dict[str, Any],
) -> list[Finding]:
    """CRITICAL — an installed engine's daemon is not running.

    Fires per-engine when ``installed=True`` and ``running=False``.
    Layer B (filesystem-only) reports `running=None` — we treat that
    as "unknown", not "not running", so this rule stays silent on
    pure-Layer-B runs; the operator who wants definitive daemon
    detection should run the sidecar script.
    """
    findings: list[Finding] = []
    for e in snap.engines:
        if not e.installed:
            continue
        if e.running is None:
            # Unknown — can't tell if the daemon is up.
            continue
        if e.running:
            continue
        base = Finding(
            module="firewall_state",
            severity=Severity.CRITICAL,
            title=f"{e.name} is installed but the daemon is not running",
            description=(
                f"{e.name} is installed (config files present, "
                f"{'binary: ' + e.binary if e.binary else 'binary unknown'}) "
                f"but its daemon is not active. The host has firewall "
                f"configuration files but no enforcement — same as having "
                f"no firewall."
            ),
            details={
                "engine": e.name,
                "binary": e.binary,
                "version": e.version,
                "source": snap.sources,
            },
            recommendation=_enable_engine_recommendation(e),
        )
        key = f"D26:{e.name}_not_running"
        fixes = lookup_fixes(key) or lookup_fixes("D26:generic")
        if fixes:
            findings.append(attach_fixes(base, *fixes))
        else:
            findings.append(base)
    return findings


def _enable_engine_recommendation(e: EngineState) -> str:
    if e.name == "csf":
        return (
            "Enable CSF: ``csf -e`` (one-shot) and "
            "``systemctl enable lfd`` (persist across reboots). "
            "Then ``csf -r`` to reload rules."
        )
    if e.name == "firewalld":
        return (
            "Enable firewalld: ``systemctl enable --now firewalld``. "
            "Open the SSH port before disconnecting: "
            "``firewall-cmd --permanent --add-service=ssh && "
            "firewall-cmd --reload``."
        )
    if e.name == "iptables":
        return (
            "iptables has no daemon — it's a userspace CLI. "
            "Install a service unit (``iptables-restore`` from "
            "``/etc/sysconfig/iptables``) and ``systemctl enable "
            "--now iptables``. On EL9 the equivalent is "
            "``nftables.service``."
        )
    if e.name == "nftables":
        return (
            "Enable nftables: ``systemctl enable --now nftables``. "
            "Restore rules from ``/etc/nftables.conf`` via "
            "``nft -f /etc/nftables.conf``."
        )
    return "Enable the daemon via your distro's service management."


# ---------------------------------------------------------------------------
# D27 — CSF installed but lfd daemon dead
# ---------------------------------------------------------------------------


def rule_d27_csf_lfd_dead(
    snap: FirewallSnapshot, settings: dict[str, Any],
) -> list[Finding]:
    """CRITICAL — CSF installed but the lfd daemon is dead.

    cPanel reality: CSF ships two daemons, ``csf`` (the rules engine,
    triggered by config changes) and ``lfd`` (the per-event blocker
    that watches logs for brute-force attempts). ``csf -e`` enables
    BOTH. If only ``csf`` is running (or neither), the host has the
    CSF config files but no live enforcement — every CSF integration
    in cPanel expects lfd to be up.

    This rule ONLY fires when Layer A's snapshot says ``csf.installed``
    AND ``csf.running == False`` (Layer A is the only source that
    distinguishes lfd from csf). On pure-Layer-B runs we don't have
    the running state, so we stay silent — D26 already covers
    "installed but unknown running state".
    """
    if not settings.get("csf_check_lfd", True):
        return []
    csf_state = next((e for e in snap.engines if e.name == "csf"), None)
    if csf_state is None:
        return []
    if not csf_state.installed:
        return []
    if csf_state.running is None:
        # Unknown — can't tell.
        return []
    if csf_state.running:
        return []
    base = Finding(
        module="firewall_state",
        severity=Severity.CRITICAL,
        title="CSF installed but lfd daemon is not running",
        description=(
            "CSF (ConfigServer Firewall) is installed and the config "
            "files are present, but the lfd (Login Failure Daemon) is "
            "not active. cPanel's cPHulk and every CSF-aware integration "
            "(csf -e, csf --profile, CSF UI in WHM) assume lfd is "
            "running — without it, brute-force detection is silent."
        ),
        details={
            "binary": csf_state.binary,
            "version": csf_state.version,
            "denylist_count": csf_state.denylist_count,
            "source": snap.sources,
        },
        recommendation=(
            "Run ``csf -e`` to enable both CSF and lfd, then "
            "``systemctl enable lfd`` to persist across reboots. "
            "Verify with ``systemctl status lfd``."
        ),
    )
    fixes = lookup_fixes("D27:csf_lfd_dead")
    if fixes:
        return [attach_fixes(base, *fixes)]
    return [base]


# ---------------------------------------------------------------------------
# D28 — installed + running but ruleset effectively empty
# ---------------------------------------------------------------------------


def rule_d28_no_rules(
    snap: FirewallSnapshot, settings: dict[str, Any],
) -> list[Finding]:
    """WARN — running firewall but no rules detected.

    Fires when at least one engine is installed AND running, but the
    combined iptables + nftables ruleset count is below the
    configured threshold. A running firewall with no rules offers
    zero protection — every packet is accepted (default policy).

    Skips silently when no engine is running — D25/D26 already
    cover that case.
    """
    iptables_min = int(settings.get("iptables_filter_min_lines", 5))
    nftables_min = int(settings.get("nftables_min_lines", 5))
    # "Running" for iptables / nftables means the binary resolved
    # something non-zero; that's the Layer A path. On Layer B, we
    # cannot tell — stay silent.
    iptables_state = next((e for e in snap.engines if e.name == "iptables"), None)
    nftables_state = next((e for e in snap.engines if e.name == "nftables"), None)
    has_running_engine = any(
        e.running is True for e in snap.engines
    )
    if not has_running_engine:
        return []
    # Check each engine's ruleset count separately.
    findings: list[Finding] = []
    if (
        iptables_state is not None
        and iptables_state.running is True
        and snap.iptables_filter_count < iptables_min
    ):
        findings.append(_emit_d28_engine(
            engine_name="iptables",
            count=snap.iptables_filter_count,
            threshold=iptables_min,
            source=snap.sources,
        ))
    if (
        nftables_state is not None
        and nftables_state.running is True
        and snap.nftables_ruleset_lines < nftables_min
    ):
        findings.append(_emit_d28_engine(
            engine_name="nftables",
            count=snap.nftables_ruleset_lines,
            threshold=nftables_min,
            source=snap.sources,
        ))
    return findings


def _emit_d28_engine(
    engine_name: str, count: int, threshold: int, source: list[str],
) -> Finding:
    base = Finding(
        module="firewall_state",
        severity=Severity.WARN,
        title=f"{engine_name} is running but the ruleset is empty",
        description=(
            f"{engine_name} is active but only {count} rule line(s) "
            f"were detected (threshold: {threshold}). A running "
            f"firewall with no rules is indistinguishable from no "
            f"firewall — every packet is accepted by the default "
            f"policy."
        ),
        details={
            "engine": engine_name,
            "rule_count": count,
            "threshold": threshold,
            "source": source,
        },
        recommendation=_populate_ruleset_recommendation(engine_name),
    )
    fixes = lookup_fixes(f"D28:{engine_name}_no_rules") or lookup_fixes("D28:generic_no_rules")
    if fixes:
        return attach_fixes(base, *fixes)
    return base


def _populate_ruleset_recommendation(engine_name: str) -> str:
    if engine_name == "iptables":
        return (
            "Restore a baseline ruleset from ``/etc/sysconfig/iptables`` "
            "(or your distro's equivalent), then ``iptables-restore`` "
            "(or ``systemctl reload iptables``). cPanel hosts with CSF: "
            "``csf -r`` to reload CSF's rules."
        )
    if engine_name == "nftables":
        return (
            "Restore the ruleset from ``/etc/nftables.conf``: "
            "``nft -f /etc/nftables.conf``. If you don't have a baseline "
            "config, the AlmaLinux 9 default ships one in the package."
        )
    return (
        "Verify the engine's config file is loaded and reload rules."
    )


# ---------------------------------------------------------------------------
# all_findings — orchestrator entry point
# ---------------------------------------------------------------------------


def all_findings(
    snap: FirewallSnapshot, settings: dict[str, Any],
) -> list[Finding]:
    """Run every rule and return the combined findings list."""
    findings: list[Finding] = []
    findings.extend(rule_d25_no_firewall(snap, settings))
    findings.extend(rule_d26_installed_not_running(snap, settings))
    findings.extend(rule_d27_csf_lfd_dead(snap, settings))
    findings.extend(rule_d28_no_rules(snap, settings))
    return findings