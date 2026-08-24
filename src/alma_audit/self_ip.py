"""Detect the host's own IP addresses for forensic filtering (AISO-201).

SSH brute-force findings (and other per-IP security findings) should
NOT flag the host's own IPs as suspicious — a cPanel server is going
to log hundreds of self-login attempts from cron jobs, monitoring,
internal services, etc. Treating those as brute-force would drown the
operator in noise.

The detector gathers the host's IP set from two sources, in order:

  1. Explicit allowlist from `modules.secure_log.trusted_ips`
     (operator-supplied, takes precedence over auto-detection).
  2. Socket hostname → DNS A/AAAA lookup — the host's primary
     public IP per its DNS records. This is the IP the rest of the
     internet sees when our SSH port is hit, so brute-force events
     logged FROM that IP are almost always our own services hitting
     themselves.

Why no `subprocess` and no `ip route`-style parsing?

  The alma-audit read-only contract (enforced by `tests/test_readonly.py`)
  forbids `subprocess` / `os.system` / `shell=True` in any module under
  `src/alma_audit/`. We deliberately do NOT shell out to `hostname -I`
  or `ip route get 1.1.1.1` — even though both are read-only on paper,
  a future reviewer auditing the contract would have to verify the
  binary's behaviour. Sticking to stdlib socket calls keeps the
  contract trivially auditable.

  The trade-off: behind a NAT (cloud VMs often have a private
  internal IP and a different public IP), `socket.gethostbyname`
  resolves the host's *configured* hostname, which may not be the
  public IP. Operators who need to whitelist additional addresses
  in that case set `modules.secure_log.trusted_ips` in their config
  YAML — the explicit allowlist is merged into the auto-detected
  set, never used to replace it.

The user memory notes: "User prefers lean Swift source/tests:
comments only for non-obvious rationale, security/protocol
invariants" — the rationale above is the "security invariant"
that justifies why this module has no subprocess import despite
hostnamectl / ip route being obvious choices.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable


def _hostname_ip() -> set[str]:
    """Resolve the host's primary A/AAAA record via the OS resolver.

    Uses socket.getaddrinfo which is a pure-Python DNS lookup; no
    subprocess, no shell, no file IO. Returns an empty set on
    resolution failure (e.g. no DNS configured) — callers must
    handle the empty case gracefully.
    """
    out: set[str] = set()
    try:
        hostname = socket.gethostname()
    except OSError:
        return out
    if not hostname:
        return out
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, OSError):
        return out
    for family, _, _, _, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6) and sockaddr:
            ip = sockaddr[0]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            out.add(ip)
    return out


def detect_self_ips(
    config_overrides: Iterable[str] | None = None,
) -> set[str]:
    """Return every IP address the host can plausibly call itself.

    `config_overrides` is the operator-supplied allowlist from
    `modules.secure_log.trusted_ips`. Explicit entries are merged
    INTO the auto-detected set, never used to replace it, because the
    operator may forget to include loopback / private networks and
    we don't want to silently drop the local-IP filter.
    """
    result: set[str] = set()
    result |= _hostname_ip()
    if config_overrides:
        result |= {ip for ip in config_overrides if ip}
    return result


def is_self_ip(ip: str, self_ips: set[str]) -> bool:
    """True if `ip` is one of the host's own IPs (string-exact or CIDR-net).

    The exact-match path covers the common case (operator's own
    public IP, internal NIC IP). The CIDR containment check covers
    the rare case where the host has a /64 IPv6 prefix and the
    forensic data only records one address from it — without the
    CIDR check, an internal-only IPv6 neighbour would still trigger.
    """
    if not ip or not self_ips:
        return False
    if ip in self_ips:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for candidate in self_ips:
        try:
            net = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        if addr.version != net.version:
            continue
        if addr in net:
            return True
    return False
