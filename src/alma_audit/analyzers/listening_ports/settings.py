"""Settings for the listening_ports analyzer.

Single source of truth for the port → service map, the public-bind
classifier, and the rule thresholds. All YAML-overridable via
``modules.listening_ports.*``.

The port service map covers the ports that actually show up on
AlmaLinux 8/9 + CloudLinux + cPanel + WHMCS hosts. Adding a new port
is intentional — operators who run a non-default stack add to their
own config; the upstream library stays conservative.

Per-port severity overrides (when binding to 0.0.0.0 / ::):

  CRITICAL: services that should never be reachable from the public
            internet (databases, memcached, RDP, telnet, deprecated
            plaintext mail).
  WARN    : services with documented risk (SSH on default port,
            cPanel / WHM admin ports) — not CRITICAL because legitimate
            public exposure exists, but operators should know.
  INFO    : services that ARE meant to be public (HTTP/HTTPS/SMTP
            submission / IMAPS).
"""
from __future__ import annotations

from typing import Any

# Layer A JSON default — the runner.py resolves this to <output>/port-audit.json
# if the operator didn't override it. ``None`` means "auto-discover from
# ``paths.output_dir`` / port_audit.json".
DEFAULT_LAYER_A_JSON_NAME = "port-audit.json"

# Layer B /proc fallback root. Override for chroot / container / test
# environments where ``/proc`` is not the live socket table.
DEFAULT_PROC_ROOT = "/proc"

# Addresses that count as "public bind" — i.e. the port is reachable
# from outside the host. ``*`` (ss) and ``::`` / ``0.0.0.0`` are the
# canonical "all interfaces" sentinels. RFC1918 / loopback / link-local
# are NOT in this set — they don't trigger D21.
PUBLIC_BIND_VALUES: frozenset[str] = frozenset({
    "0.0.0.0",
    "*",
    "::",
    "[::]",
})

# Port service map: port -> (service_name, severity_when_public).
# Severity follows the conventions in the module docstring.
PORT_SERVICE_MAP: dict[int, tuple[str, str]] = {
    # Admin / shell
    22: ("sshd", "warn"),                # default SSH port
    23: ("telnet", "critical"),          # deprecated plaintext
    3389: ("rdp", "critical"),           # Windows RDP — never on a Linux host

    # Mail
    25: ("smtp-exim", "warn"),           # cPanel exim outbound
    110: ("pop3", "critical"),           # deprecated plaintext
    143: ("imap", "critical"),           # deprecated plaintext
    465: ("smtps-exim-submission", "info"),
    587: ("smtp-submission", "info"),
    993: ("imaps", "info"),
    995: ("pop3s", "info"),

    # Web
    80: ("httpd", "info"),
    443: ("httpsd", "info"),
    8080: ("httpd-alt", "info"),
    8443: ("httpsd-alt", "info"),

    # cPanel / WHM (critical ports for cPanel/WHM operators)
    2082: ("cpanel", "warn"),
    2083: ("cpanel-ssl", "warn"),
    2086: ("whm", "warn"),
    2087: ("whm-ssl", "warn"),
    2095: ("cpanel-webmail", "info"),
    2096: ("cpanel-webmail-ssl", "info"),

    # Databases — must never be public
    3306: ("mysql", "critical"),
    5432: ("postgresql", "critical"),
    6379: ("redis", "critical"),
    11211: ("memcached", "critical"),
    27017: ("mongodb", "critical"),
    1433: ("mssql", "critical"),
    9200: ("elasticsearch", "critical"),
    9300: ("elasticsearch-transport", "critical"),
    5984: ("couchdb", "critical"),

    # DNS / NTP / monitoring
    53: ("dns", "warn"),                 # BIND / named
    123: ("ntp", "info"),
    161: ("snmp", "warn"),               # often misconfigured on public nets
    514: ("syslog", "warn"),

    # WebSocket / admin tools
    8081: ("admin-alt", "info"),
}

# CRITICAL ports are the union of "must never be public" + ports that
# trigger D22 (MySQL bind-address). Operators override via YAML
# (``modules.listening_ports.critical_ports``).
CRITICAL_PORTS: tuple[int, ...] = tuple(
    port for port, (_, sev) in PORT_SERVICE_MAP.items() if sev == "critical"
)

# D21/D23 thresholds — operators tune via YAML. Defaults match
# common cPanel reality: a 0.0.0.0 critical bind is always CRITICAL;
# IPv6 dual-stack is always WARN; unknown high ports is INFO unless the
# ``unknown_high_port_critical`` flag is on.
DEFAULT_RULES: dict[str, Any] = {
    # ``layer_a_json_path`` is resolved by runner.py to <output>/port-audit.json
    # if the operator didn't override it. ``None`` means "auto-discover from
    # ``paths.output_dir`` / port_audit.json".
    "layer_a_json_path": None,
    "proc_root": DEFAULT_PROC_ROOT,
    # ``critical_ports`` is an explicit override list — operators add
    # custom ports here. The DEFAULT_RULES also implicitly include the
    # builtin PORT_SERVICE_MAP entries with severity == critical.
    "critical_ports": list(CRITICAL_PORTS),
    # When True (default), the analyzer always falls back to Layer B
    # (``/proc/net/*``) if Layer A's JSON is missing or unreadable.
    # Set False in a sandboxed container where /proc is not available.
    "fallback_to_proc": True,
    # When True, a single public-bind listener for an UNKNOWN high
    # port (port > 1024, no service in PORT_SERVICE_MAP) emits D24
    # as INFO. Disable to suppress this catch-all.
    "warn_unknown_high_port": True,
}