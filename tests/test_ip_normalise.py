"""AISO-119 §5.1 + §8 acceptance — IPv4/IPv6 normalisation tests.

Per the detection contract §8 the implementation MUST be unit-tested
against:

  1. `2a06:98c0:3600::103` (bare canonical)
  2. `2A06:98C0:3600:0:0:0:0:103` (uppercase non-canonical → canonicalised)
  3. `[2a06:98c0:3600::103]:443` (bracketed-with-port)
  4. `fe80::1%eth0` (zone-id)
  5. A malformed string → ValueError
"""

from __future__ import annotations

import pytest

from alma_audit.ip_normalise import is_internal_scope, normalise_ip


def test_ipv6_bare_canonical() -> None:
    canonical, scope = normalise_ip("2a06:98c0:3600::103")
    assert canonical == "2a06:98c0:3600::103"
    assert scope == "public"


def test_ipv6_uppercase_expands_to_canonical() -> None:
    canonical, scope = normalise_ip("2A06:98C0:3600:0:0:0:0:103")
    assert canonical == "2a06:98c0:3600::103"
    assert scope == "public"


def test_ipv6_bracketed_with_port() -> None:
    canonical, scope = normalise_ip("[2a06:98c0:3600::103]:443")
    assert canonical == "2a06:98c0:3600::103"
    assert scope == "public"


def test_ipv6_zone_id_is_stripped() -> None:
    canonical, scope = normalise_ip("fe80::1%eth0")
    assert canonical == "fe80::1"
    assert scope == "linklocal"


def test_malformed_string_raises() -> None:
    with pytest.raises(ValueError):
        normalise_ip("not.an.ip.at.all")
    with pytest.raises(ValueError):
        normalise_ip("999.999.999.999")
    with pytest.raises(ValueError):
        normalise_ip("gggg::1")


def test_ipv4_canonical() -> None:
    canonical, scope = normalise_ip("211.248.230.233")
    assert canonical == "211.248.230.233"
    assert scope == "public"


def test_ipv4_loopback_scope() -> None:
    canonical, scope = normalise_ip("127.0.0.1")
    assert canonical == "127.0.0.1"
    assert scope == "loopback"
    assert is_internal_scope(scope)


def test_ipv4_private_scope() -> None:
    canonical, scope = normalise_ip("10.0.0.1")
    assert canonical == "10.0.0.1"
    assert scope == "private"
    assert is_internal_scope(scope)


def test_ipv4_unspecified_scope() -> None:
    canonical, scope = normalise_ip("0.0.0.0")
    assert canonical == "0.0.0.0"
    assert scope == "unspecified"
    assert is_internal_scope(scope)


def test_ipv6_ula_scope() -> None:
    canonical, scope = normalise_ip("fc00::1")
    assert canonical == "fc00::1"
    assert scope == "ula"
    assert is_internal_scope(scope)


def test_ipv4_linklocal_scope() -> None:
    canonical, scope = normalise_ip("169.254.1.1")
    assert canonical == "169.254.1.1"
    assert scope == "linklocal"
    assert is_internal_scope(scope)