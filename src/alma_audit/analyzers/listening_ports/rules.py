"""Detection rules for the listening_ports analyzer.

Four rules per AISO-220 plan §5.1:

*   **D21** CRITICAL — critical service bound to a public interface.
*   **D22** INFO    — MySQL bind-address secondary signal (config-file
    pointer; suppressed when D21 already fired CRITICAL).
*   **D23** WARN    — IPv6 dual-stack on a critical port.
*   **D24** INFO    — unknown high port public bind (catch-all).

Each rule reads the snapshot from the aggregator and emits one
``Finding`` per detected exposure. The fixes come from the
``FIX_LIBRARY`` keys in ``fix_suggestions.py``.
"""
from __future__ import annotations

from typing import Any

from ...fix_suggestions import attach_fixes, lookup_fixes
from ...models import Finding, Severity
from .aggregator import ListenerSnapshot
from .parser import Listener
from .settings import CRITICAL_PORTS, PORT_SERVICE_MAP, PUBLIC_BIND_VALUES


def _is_public_bind(listener: Listener) -> bool:
    """True if ``listener`` binds a public interface (not loopback / RFC1918)."""
    return listener.address in PUBLIC_BIND_VALUES


def _service_name(port: int) -> tuple[str, str] | None:
    """Return ``(service_name, default_severity)`` from ``PORT_SERVICE_MAP``.

    ``None`` for unknown ports — the rule layer falls back to "unknown".
    """
    return PORT_SERVICE_MAP.get(port)


def _dual_stack_pair(
    listeners: list[Listener], port: int, critical: bool,
) -> tuple[Listener | None, Listener | None]:
    """Return ``(v4_listener, v6_listener)`` if both exist for ``port``.

    Only considered when the port is in the operator's ``critical_ports``
    list — D23 is a critical-port-specific warning. The orchestrator
    passes ``critical=True`` for ports flagged by D21 so we don't
    duplicate-work between D21 and D23.
    """
    if not critical:
        return None, None
    v4 = next(
        (L for L in listeners
         if L.port == port and L.proto in ("tcp", "udp")
         and _is_public_bind(L)),
        None,
    )
    v6 = next(
        (L for L in listeners
         if L.port == port and L.proto in ("tcp6", "udp6")
         and _is_public_bind(L)),
        None,
    )
    if v4 is None or v6 is None:
        return None, None
    return v4, v6


# ---------------------------------------------------------------------------
# D21 — critical service public bind
# ---------------------------------------------------------------------------


def rule_d21_critical_public_bind(
    snap: ListenerSnapshot, settings: dict[str, Any],
) -> list[Finding]:
    """CRITICAL — a critical service is bound to a public interface.

    The rule scans every listener and emits one finding per
    (proto, port) public-bind pair whose port is in the operator's
    ``critical_ports`` list. Layer A's snapshot usually has only one
    row per public bind (no IPv6 counterpart) so the count is small.
    """
    findings: list[Finding] = []
    operator_critical = set(settings.get("critical_ports") or list(CRITICAL_PORTS))
    seen: set[tuple[str, int]] = set()
    for L in snap.listeners:
        if not _is_public_bind(L):
            continue
        if L.port not in operator_critical:
            continue
        key = (L.proto, L.port)
        if key in seen:
            continue
        seen.add(key)
        svc = _service_name(L.port) or ("unknown", "critical")
        svc_name = svc[0]
        findings.append(_emit_d21(L, svc_name))
    return findings


def _emit_d21(listener: Listener, service_name: str) -> Finding:
    """Compose a D21 finding for one public critical listener."""
    base = Finding(
        module="listening_ports",
        severity=Severity.CRITICAL,
        title=(
            f"{service_name} bound to {listener.address}:{listener.port} "
            f"({listener.proto})"
        ),
        description=(
            f"A service that should never be reachable from the public "
            f"internet is listening on {listener.address}:{listener.port}. "
            f"On a cPanel / AlmaLinux host this is almost always a "
            f"misconfiguration — the bind address should be 127.0.0.1, "
            f"::1, or a private interface, and a host firewall (CSF or "
            f"firewalld) should restrict the public exposure."
        ),
        details={
            "proto": listener.proto,
            "address": listener.address,
            "port": listener.port,
            "state": listener.state,
            "process": listener.process,
            "pid": listener.pid,
        },
        recommendation=(
            f"Edit the {service_name} config to bind to 127.0.0.1 / ::1 "
            f"(or a private interface). If remote access is required, "
            f"restrict it via CSF/firewalld to the operator's IP range. "
            f"Do NOT rely on the bind alone — a firewall rule is a "
            f"defence-in-depth must."
        ),
    )
    # AISO-210: attach the per-service FIX_LIBRARY entries. We pick the
    # fix library key that matches the service name; the fallthrough
    # is the generic local_config one.
    key = _fix_library_key_for_service(service_name)
    fixes = lookup_fixes(key) if key else ()
    if fixes:
        return attach_fixes(base, *fixes)
    return base


def _fix_library_key_for_service(service_name: str) -> str:
    """Map a service name to a ``FIX_LIBRARY`` finding key.

    The library keys are ``"D21:<service>"`` — see ``fix_suggestions.py``
    for the exact entries. Unknown services fall through to
    ``"D21:critical_generic"`` so the operator still gets a generic
    fix (pointing at ``bind-address`` edits + firewall rule).
    """
    known = {
        "mysql": "D21:mysql_public_bind",
        "postgresql": "D21:postgres_public_bind",
        "redis": "D21:redis_public_bind",
        "memcached": "D21:memcached_public_bind",
        "mongodb": "D21:mongodb_public_bind",
        "telnet": "D21:telnet_public_bind",
        "rdp": "D21:rdp_public_bind",
        "pop3": "D21:pop3_imap_plaintext",
        "imap": "D21:pop3_imap_plaintext",
    }
    return known.get(service_name, "D21:critical_generic")


# ---------------------------------------------------------------------------
# D22 — MySQL bind-address secondary signal
# ---------------------------------------------------------------------------


def rule_d22_mysql_bind_address(
    snap: ListenerSnapshot, settings: dict[str, Any],
) -> list[Finding]:
    """INFO — config-file evidence of MySQL public exposure.

    Fires when ``mysql_bind_address`` in the Layer A JSON (parsed from
    ``/etc/my.cnf`` by the sidecar) is ``0.0.0.0`` or ``::``. This is
    the config-side complement of D21 — if D21 already fired CRITICAL
    for the same port, D22 is suppressed to avoid double-reporting the
    same root cause.
    """
    bind = snap.mysql_bind_address
    if bind is None:
        return []
    # Acceptable values: 127.0.0.1, ::1, a private IP, or "skip-networking".
    acceptable = {
        "127.0.0.1", "::1", "localhost",
        "skip-networking", "skip-networking-mysqld",
    }
    if bind in acceptable:
        return []
    # If D21 already fired for MySQL port 3306, suppress D22.
    for L in snap.listeners:
        if L.port == 3306 and _is_public_bind(L):
            return []
    findings: list[Finding] = []
    base = Finding(
        module="listening_ports",
        severity=Severity.INFO,
        title=f"mysql bind-address = {bind} (config file)",
        description=(
            "The MySQL config file (my.cnf or my.cnf.d/server.cnf, "
            "resolved by the sidecar) sets `bind-address = " + bind + "`, "
            "which makes MySQL listen on every interface. The runtime "
            "listener check (D21) is the canonical signal; this finding "
            "is the config-file pointer for the fix path."
        ),
        details={"bind_address": bind, "source": "my.cnf"},
        recommendation=(
            "Edit ``[mysqld] bind-address = 127.0.0.1`` in "
            "``/etc/my.cnf`` (or ``/etc/my.cnf.d/server.cnf`` on cPanel) "
            "and ``systemctl restart mysql``. If remote MySQL access "
            "is required (monitoring, off-host backups), restrict via "
            "CSF/firewalld to the source IP range."
        ),
    )
    fixes = lookup_fixes("D22:mysql_bind_address")
    if fixes:
        findings.append(attach_fixes(base, *fixes))
    else:
        findings.append(base)
    return findings


# ---------------------------------------------------------------------------
# D23 — IPv6 dual-stack on a critical port
# ---------------------------------------------------------------------------


def rule_d23_ipv6_dual_stack(
    snap: ListenerSnapshot, settings: dict[str, Any],
) -> list[Finding]:
    """WARN — IPv6 dual-stack listener on a critical port.

    Common operator mistake: ``bind-address = 127.0.0.1`` is set
    (kills the IPv4 listener), but the IPv6 listener on ``::`` keeps
    serving the public. D23 catches this.
    """
    findings: list[Finding] = []
    operator_critical = set(settings.get("critical_ports") or list(CRITICAL_PORTS))
    seen_ports: set[int] = set()
    for port in operator_critical:
        v4, v6 = _dual_stack_pair(snap.listeners, port, critical=True)
        if v4 is None or v6 is None:
            continue
        if port in seen_ports:
            continue
        seen_ports.add(port)
        svc = _service_name(port) or ("unknown", "critical")
        base = Finding(
            module="listening_ports",
            severity=Severity.WARN,
            title=(
                f"{svc[0]} dual-stack on {port} "
                f"({v4.address} + {v6.address})"
            ),
            description=(
                f"{svc[0]} is listening on BOTH IPv4 ({v4.address}:{port}) "
                f"and IPv6 ({v6.address}:{port}). Operators commonly close "
                f"the IPv4 path but forget the IPv6 one — the IPv6 "
                f"listener keeps the service reachable from IPv6-capable "
                f"networks."
            ),
            details={
                "port": port,
                "v4": {"proto": v4.proto, "address": v4.address},
                "v6": {"proto": v6.proto, "address": v6.address},
            },
            recommendation=(
                f"Set BOTH ``bind-address`` to IPv4 (127.0.0.1) AND the "
                f"IPv6 equivalent (typically ``::1`` or a private ULA) — "
                f"then restart the service. Verify with ``ss -tuln`` "
                f"after the restart that neither ``0.0.0.0:{port}`` nor "
                f"``::{port}`` remain bound."
            ),
        )
        fixes = lookup_fixes("D23:ipv6_dual_stack")
        if fixes:
            findings.append(attach_fixes(base, *fixes))
        else:
            findings.append(base)
    return findings


# ---------------------------------------------------------------------------
# D24 — unknown high port public bind
# ---------------------------------------------------------------------------


def rule_d24_unknown_high_port(
    snap: ListenerSnapshot, settings: dict[str, Any],
) -> list[Finding]:
    """INFO — public-bind listener for an unknown high port.

    Catch-all for ports the audit doesn't recognise (>1024, not in
    PORT_SERVICE_MAP). Operators sometimes run custom services on
    public ports — this rule names them so the operator can decide
    whether the public exposure is intentional.
    """
    if not settings.get("warn_unknown_high_port", True):
        return []
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for L in snap.listeners:
        if not _is_public_bind(L):
            continue
        if L.port <= 1024:
            continue
        if L.port in PORT_SERVICE_MAP:
            continue
        key = (L.proto, L.port)
        if key in seen:
            continue
        seen.add(key)
        proc = L.process or "(unknown)"
        base = Finding(
            module="listening_ports",
            severity=Severity.INFO,
            title=(
                f"Unknown high port public bind: {L.address}:{L.port} "
                f"({proc})"
            ),
            description=(
                f"A service on port {L.port} ({proc}) is bound to a "
                f"public interface. The port is not in the audit's "
                f"service map; this is likely a custom application or "
                f"a non-standard daemon. Verify the public exposure is "
                f"intentional and that a firewall rule (CSF / firewalld) "
                f"restricts it to the operator's IP range."
            ),
            details={
                "proto": L.proto,
                "address": L.address,
                "port": L.port,
                "process": L.process,
                "pid": L.pid,
            },
            recommendation=(
                "Verify with the application owner / operator docs that "
                "the public bind is intended. If not, bind to 127.0.0.1 "
                "/ ::1 / a private interface. If remote access is "
                "required, restrict via CSF/firewalld."
            ),
        )
        findings.append(base)
    return findings


# ---------------------------------------------------------------------------
# all_findings — orchestrator entry point
# ---------------------------------------------------------------------------


def all_findings(
    snap: ListenerSnapshot, settings: dict[str, Any],
) -> list[Finding]:
    """Run every rule and return the combined findings list."""
    findings: list[Finding] = []
    findings.extend(rule_d21_critical_public_bind(snap, settings))
    findings.extend(rule_d22_mysql_bind_address(snap, settings))
    findings.extend(rule_d23_ipv6_dual_stack(snap, settings))
    findings.extend(rule_d24_unknown_high_port(snap, settings))
    return findings