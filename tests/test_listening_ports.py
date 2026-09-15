"""Tests for the listening_ports analyzer (AISO-220).

Covers:
*   Layer A JSON parsing — happy path, missing fields, schema mismatch.
*   Layer B /proc/net/* parsing — happy path, IPv4 little-endian hex,
    IPv6 native hex, UDP UNCONN state.
*   Analyzer behavior — D21 critical port, D22 MySQL bind-address,
    D23 IPv6 dual-stack, D24 unknown high port.
*   Layer A vs Layer B fallback.
*   Public-bind classifier — RFC1918/loopback excluded, 0.0.0.0/*/::
    included.
"""
from __future__ import annotations

import json
from textwrap import dedent

from alma_audit.analyzers.listening_ports import (
    CRITICAL_PORTS,
    DEFAULT_RULES,
    PUBLIC_BIND_VALUES,
    ListenerSnapshot,
    analyze_listening_ports,
    parse_layer_a_json,
    parse_proc_net,
)
from alma_audit.models import Severity
from alma_audit.runners import FakeFileSystem


# ---------------------------------------------------------------------------
# parser.parse_layer_a_json
# ---------------------------------------------------------------------------


def test_parse_layer_a_json_happy_path():
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "0.0.0.0", "port": 3306,
             "process": "mysqld", "pid": 1234, "state": "LISTEN"},
            {"proto": "tcp6", "address": "::", "port": 3306,
             "process": "mysqld", "pid": 1234, "state": "LISTEN"},
            {"proto": "udp", "address": "127.0.0.1", "port": 53,
             "process": None, "pid": None, "state": "UNCONN"},
        ],
        "mysql_bind_address": "0.0.0.0",
    })
    result = parse_layer_a_json(text)
    assert result.source == "layer_a"
    assert len(result.listeners) == 3
    # Multiple listeners may share the same port (IPv4 + IPv6 dual-stack).
    by_proto = {(L.proto, L.port): L for L in result.listeners}
    assert by_proto[("tcp", 3306)].address == "0.0.0.0"
    assert by_proto[("tcp", 3306)].process == "mysqld"
    assert by_proto[("tcp", 3306)].pid == 1234
    assert by_proto[("tcp", 3306)].state == "LISTEN"
    assert by_proto[("tcp6", 3306)].address == "::"
    assert result.mysql_bind_address == "0.0.0.0"


def test_parse_layer_a_json_missing_fields_returns_empty():
    """A sidecar with only the top-level schema_version + listeners
    (no firewall state, no mysql_bind_address) still parses — the
    listener block carries the canonical signal anyway.
    """
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "0.0.0.0", "port": 3306,
             "process": None, "pid": None, "state": "LISTEN"},
        ],
    })
    result = parse_layer_a_json(text)
    assert len(result.listeners) == 1
    assert result.mysql_bind_address is None


def test_parse_layer_a_json_schema_mismatch_returns_empty():
    """A sidecar written with a future schema version (e.g. the
    sidecar was upgraded to v2 with breaking changes) yields []
    so the analyzer falls back to Layer B.
    """
    text = json.dumps({
        "schema_version": 999,
        "listeners": [{"proto": "tcp", "address": "0.0.0.0",
                        "port": 3306, "process": "x", "pid": 1,
                        "state": "LISTEN"}],
    })
    result = parse_layer_a_json(text)
    assert result.listeners == []
    assert result.source == "layer_a"


def test_parse_layer_a_json_malformed_returns_empty():
    """Truncated / non-JSON input never crashes the analyzer."""
    result = parse_layer_a_json("this is not json")
    assert result.listeners == []
    assert result.source == "layer_a"


def test_parse_layer_a_json_drops_unknown_proto():
    """A sidecar that accidentally emits a non-IP proto gets dropped
    before it reaches the rule layer.
    """
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "sctp", "address": "0.0.0.0", "port": 9999,
             "process": "x", "pid": 1, "state": "LISTEN"},
            {"proto": "tcp", "address": "0.0.0.0", "port": 80,
             "process": "httpd", "pid": 1, "state": "LISTEN"},
        ],
    })
    result = parse_layer_a_json(text)
    assert len(result.listeners) == 1
    assert result.listeners[0].proto == "tcp"


# ---------------------------------------------------------------------------
# parser.parse_proc_net — Layer B /proc/net/* parsing
# ---------------------------------------------------------------------------


def test_parse_proc_net_v4_hex_decoding():
    """``/proc/net/tcp`` encodes the local IPv4 in little-endian hex
    (e.g. ``0100007F:1538`` = 127.0.0.1:5432). The parser must
    correctly reverse the byte order.
    """
    # Format: each line is "  sl  local_address:port  rem_address  st ..."
    # ``0100007F:1538`` = 127.0.0.1:5432, state ``0A`` = LISTEN.
    fs = FakeFileSystem({
        "/proc/net/tcp": "  sl  local_address rem_address   st\n"
                         "   1: 0100007F:1538 00000000:0000 0A\n",
    })
    result = parse_proc_net(fs, proc_root="/proc")
    assert len(result.listeners) == 1
    L = result.listeners[0]
    assert L.address == "127.0.0.1"
    assert L.port == 5432
    assert L.proto == "tcp"
    assert L.state == "LISTEN"


def test_parse_proc_net_v6_hex_decoding():
    """IPv6 in /proc/net/tcp6 is 32-hex-char + port; the address is
    already in network byte order (no reversal needed).
    """
    # ``::1`` is 32 hex chars: 15 zero groups + 0x0001. The hex is
    # ``00000000000000000000000000000001`` = 16 bytes, 8 groups of
    # 16 bits. Split into 4-char chunks: 0000 0000 0000 0000 0000
    # 0000 0000 0001.
    fs = FakeFileSystem({
        "/proc/net/tcp6": "  sl  local_address rem_address   st\n"
                          "   1: 00000000000000000000000000000001:1538 "
                          "00000000000000000000000000000000:0000 0A\n",
    })
    result = parse_proc_net(fs, proc_root="/proc")
    assert len(result.listeners) == 1
    L = result.listeners[0]
    assert L.address == "::1", f"expected ::1, got {L.address!r}"
    assert L.port == 5432
    assert L.proto == "tcp6"


def test_parse_proc_net_drops_non_listen_tcp():
    """TCP rows with state != 0A (LISTEN) are dropped — the analyzer
    only cares about listeners, not established sessions.
    """
    fs = FakeFileSystem({
        "/proc/net/tcp": "  sl  local_address rem_address   st\n"
                         "   1: 0100007F:1538 0100007F:9A0A 01\n",  # ESTABLISHED
    })
    result = parse_proc_net(fs, proc_root="/proc")
    assert result.listeners == []


def test_parse_proc_net_keeps_udp_rows():
    """UDP has no LISTEN state — every UDP socket appears as state ``07``
    (UNCONN). The parser keeps all UDP rows.

    The /proc/net/udp line format is the same as tcp EXCEPT the
    state column carries the UDP socket state (``07`` = UNCONN, which
    is what every UDP socket has — UDP has no LISTEN state). The
    parser distinguishes by file path (udp vs tcp), not by state value.
    """
    fs = FakeFileSystem({
        "/proc/net/udp": "  sl  local_address rem_address   st\n"
                         "   1: 0100007F:0035 00000000:0000 07\n",  # 127.0.0.1:53
    })
    result = parse_proc_net(fs, proc_root="/proc")
    assert len(result.listeners) == 1, f"got {result.listeners}"
    L = result.listeners[0]
    assert L.address == "127.0.0.1"
    assert L.port == 53
    assert L.proto == "udp"


def test_parse_proc_net_handles_missing_files():
    """A chroot without /proc returns [] — Layer B gracefully degrades."""
    fs = FakeFileSystem({})  # no files at all
    result = parse_proc_net(fs, proc_root="/proc")
    assert result.listeners == []
    assert result.source == "layer_b:none"


# ---------------------------------------------------------------------------
# PUBLIC_BIND_VALUES
# ---------------------------------------------------------------------------


def test_public_bind_values_set():
    """The set of public bind values is exactly the public interfaces
    we treat as 'exposed to the internet' — nothing else (loopback,
    RFC1918 are NOT in this set).
    """
    assert "0.0.0.0" in PUBLIC_BIND_VALUES
    assert "*" in PUBLIC_BIND_VALUES
    assert "::" in PUBLIC_BIND_VALUES
    assert "127.0.0.1" not in PUBLIC_BIND_VALUES
    assert "192.168.1.1" not in PUBLIC_BIND_VALUES
    assert "10.0.0.5" not in PUBLIC_BIND_VALUES


# ---------------------------------------------------------------------------
# Analyzer — D21 critical port public bind
# ---------------------------------------------------------------------------


def test_analyze_d21_critical_port_public():
    """Layer A JSON: MySQL on 0.0.0.0:3306 → CRITICAL D21."""
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "0.0.0.0", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
        ],
        "mysql_bind_address": "0.0.0.0",
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_listening_ports(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) >= 1
    title = crit[0].title
    assert "mysql" in title
    assert "3306" in title


def test_analyze_loopback_critical_port_no_d21():
    """MySQL on 127.0.0.1:3306 → no D21 (loopback is not public)."""
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "127.0.0.1", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
        ],
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_listening_ports(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert all("3306" not in f.title for f in crit)


# ---------------------------------------------------------------------------
# Analyzer — D22 MySQL bind-address secondary signal
# ---------------------------------------------------------------------------


def test_analyze_d22_mysql_bind_address_info():
    """Layer A JSON: mysql_bind_address=0.0.0.0 but no listener on
    0.0.0.0:3306 (loopback listener only) → D22 fires once.
    """
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            # Loopback MySQL listener — D21 does NOT fire on this.
            {"proto": "tcp", "address": "127.0.0.1", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
        ],
        "mysql_bind_address": "0.0.0.0",
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_listening_ports(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    info = [f for f in findings if f.severity == Severity.INFO]
    assert any("bind-address" in f.title for f in info)


def test_analyze_d22_suppressed_when_d21_fired():
    """Layer A JSON: mysql_bind_address=0.0.0.0 AND listener on
    0.0.0.0:3306 → D22 suppressed (D21 already covers the root cause).
    """
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "0.0.0.0", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
        ],
        "mysql_bind_address": "0.0.0.0",
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_listening_ports(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    info = [f for f in findings if f.severity == Severity.INFO]
    # The INFO summary is fine — but no D22 bind-address info.
    assert not any(
        "bind-address" in f.title and "config file" in f.title for f in info
    )


def test_analyze_d22_acceptable_bind_no_finding():
    """Layer A JSON: mysql_bind_address=127.0.0.1 → no D22 (already locked)."""
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "127.0.0.1", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
        ],
        "mysql_bind_address": "127.0.0.1",
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_listening_ports(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    assert not any("bind-address" in f.title for f in findings)


# ---------------------------------------------------------------------------
# Analyzer — D23 IPv6 dual-stack
# ---------------------------------------------------------------------------


def test_analyze_d23_ipv6_dual_stack():
    """Layer A JSON: 0.0.0.0:3306 + ::3306 → WARN D23."""
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "0.0.0.0", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
            {"proto": "tcp6", "address": "::", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
        ],
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_listening_ports(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    warn = [f for f in findings if f.severity == Severity.WARN]
    assert any("dual-stack" in f.title for f in warn)


def test_analyze_d23_only_v4_no_warning():
    """Layer A JSON: 0.0.0.0:3306 only (no IPv6) → no D23."""
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "0.0.0.0", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
        ],
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_listening_ports(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    warn = [f for f in findings if f.severity == Severity.WARN]
    assert not any("dual-stack" in f.title for f in warn)


# ---------------------------------------------------------------------------
# Analyzer — D24 unknown high port
# ---------------------------------------------------------------------------


def test_analyze_d24_unknown_high_port_info():
    """Layer A JSON: 0.0.0.0:55000 (unknown high port) → D24 INFO."""
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "0.0.0.0", "port": 55000,
             "process": "myapp", "pid": 1, "state": "LISTEN"},
        ],
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_listening_ports(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    info = [f for f in findings if f.severity == Severity.INFO]
    assert any("55000" in f.title for f in info)


def test_analyze_d24_suppressed_when_disabled():
    """Operator sets ``warn_unknown_high_port: false`` → no D24."""
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "0.0.0.0", "port": 55000,
             "process": "myapp", "pid": 1, "state": "LISTEN"},
        ],
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_listening_ports(
        fs,
        rules={
            "layer_a_json_path": "/tmp/out/port-audit.json",
            "warn_unknown_high_port": False,
        },
    )
    info = [f for f in findings if f.severity == Severity.INFO]
    assert not any("55000" in f.title for f in info)


# ---------------------------------------------------------------------------
# Layer B fallback
# ---------------------------------------------------------------------------


def test_layer_b_fallback_when_layer_a_missing():
    """No Layer A JSON, no /proc → empty INFO finding (operator sees
    the analyzer ran but found nothing — clearly the audit user
    can't see /proc).
    """
    fs = FakeFileSystem({})  # nothing on disk
    findings = analyze_listening_ports(
        fs,
        rules={"layer_a_json_path": None, "fallback_to_proc": True},
    )
    # Either an "empty" INFO (when /proc is unreadable) or the
    # analyzer ran with the data it had. Either way: at least one
    # finding is returned so the audit chain stays intact.
    assert len(findings) >= 1
    info = [f for f in findings if f.severity == Severity.INFO]
    assert any("No listening ports" in f.title or
               "listener(s)" in f.title for f in info)


def test_layer_b_fallback_uses_proc():
    """No Layer A JSON but /proc/net/tcp has data → CRITICAL D21."""
    fs = FakeFileSystem({
        "/proc/net/tcp": "  sl  local_address rem_address   st\n"
                         "   1: 00000000:0CEA 00000000:0000 0A\n",  # 0.0.0.0:3306
    })
    findings = analyze_listening_ports(
        fs,
        rules={"layer_a_json_path": None, "fallback_to_proc": True},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("3306" in f.title for f in crit)


def test_layer_b_fallback_disabled():
    """Operator sets ``fallback_to_proc: false`` → empty INFO when
    Layer A is missing. The analyzer does NOT crash.
    """
    fs = FakeFileSystem({})  # nothing on disk
    findings = analyze_listening_ports(
        fs,
        rules={"layer_a_json_path": None, "fallback_to_proc": False},
    )
    # Should produce an INFO "no listeners" finding (degraded mode).
    assert len(findings) >= 1
    info = [f for f in findings if f.severity == Severity.INFO]
    assert any("No listening ports" in f.title for f in info)


# ---------------------------------------------------------------------------
# CRITICAL_PORTS default set
# ---------------------------------------------------------------------------


def test_critical_ports_includes_default_db_and_mail():
    """The default critical-ports set includes MySQL/Postgres/Redis
    and the deprecated plaintext mail protocols. Operators extend
    via YAML (``modules.listening_ports.critical_ports``).
    """
    assert 3306 in CRITICAL_PORTS  # MySQL
    assert 5432 in CRITICAL_PORTS  # Postgres
    assert 6379 in CRITICAL_PORTS  # Redis
    assert 11211 in CRITICAL_PORTS  # Memcached
    assert 27017 in CRITICAL_PORTS  # MongoDB
    assert 110 in CRITICAL_PORTS   # POP3
    assert 143 in CRITICAL_PORTS   # IMAP
    assert 23 in CRITICAL_PORTS    # telnet
    assert 3389 in CRITICAL_PORTS  # RDP


def test_default_rules_has_required_keys():
    """The DEFAULT_RULES dict carries every key the analyzer reads.
    Operators can override any subset via YAML.
    """
    assert "layer_a_json_path" in DEFAULT_RULES
    assert "proc_root" in DEFAULT_RULES
    assert "critical_ports" in DEFAULT_RULES
    assert "fallback_to_proc" in DEFAULT_RULES
    assert "warn_unknown_high_port" in DEFAULT_RULES


# ---------------------------------------------------------------------------
# Dedupe (Layer A + Layer B both run when Layer A is empty)
# ---------------------------------------------------------------------------


def test_layer_a_preferred_over_layer_b():
    """Layer A populated → Layer B is skipped (richer data wins)."""
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "127.0.0.1", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
        ],
    })
    # /proc/net/tcp has a STALE entry — should not appear because
    # Layer A wins.
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
        "/proc/net/tcp": "  sl  local_address rem_address   st\n"
                         "   1: 00000000:0CEA 00000000:0000 0A\n",  # 0.0.0.0:3306
    })
    findings = analyze_listening_ports(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    # Layer A's loopback-only MySQL is not exposed → no CRITICAL.
    assert not any("3306" in f.title for f in crit)


def test_no_findings_when_only_layer_a_passes():
    """Both layers empty (no listeners visible) → INFO 'No listening
    ports found'. The analyzer never silently swallows a missing
    data source.
    """
    fs = FakeFileSystem({})
    findings = analyze_listening_ports(
        fs,
        rules={"layer_a_json_path": None, "fallback_to_proc": True},
    )
    info = [f for f in findings if f.severity == Severity.INFO]
    assert any("No listening ports" in f.title for f in info)
    # The finding carries the source list so the operator can tell
    # Layer B failed (no /proc).
    empty_findings = [f for f in info if "No listening ports" in f.title]
    assert "layer_b_attempted" in empty_findings[0].details


# ---------------------------------------------------------------------------
# Fix suggestions attached to critical findings
# ---------------------------------------------------------------------------


def test_d21_critical_finding_carries_fix_suggestion():
    """D21 CRITICAL findings carry at least one ``FindingFix``
    (AISO-210 contract).
    """
    text = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "0.0.0.0", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
        ],
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_listening_ports(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit
    assert crit[0].fixes
    fix = crit[0].fixes[0]
    assert fix.scope == "local_config"
    assert "bind-address" in fix.what.lower() or "127.0.0.1" in fix.what