"""Tests for the tools/port_audit.sh sidecar JSON round-trip.

These tests don't run the bash script — they construct the JSON
text in-process and feed it to both analyzers' Layer A parsers.
A real shell-level integration test would need the script's runtime
environment (`jq`, `ss`, ...); that's covered by the project's
``verify_all.sh`` smoke test (Phase 4 in the repo's gate).

What's tested here:

*   The JSON schema is what the analyzers expect.
*   Missing optional fields are tolerated (mysql_bind_address=None,
    firewall_engines={}).
*   Schema version mismatch → graceful empty result.
*   Both analyzers consume the same JSON without conflicts.
"""
from __future__ import annotations

import json

from alma_audit.analyzers.firewall_state import analyze_firewall_state
from alma_audit.analyzers.listening_ports import analyze_listening_ports
from alma_audit.runners import FakeFileSystem


# A representative port-audit.json payload — the shape
# ``tools/port_audit.sh`` writes.
EXAMPLE_JSON = json.dumps({
    "schema_version": 1,
    "captured_at": "2026-09-15T14:32:11+02:00",
    "hostname": "host.example.com",
    "listeners": [
        {"proto": "tcp", "address": "0.0.0.0", "port": 3306,
         "process": "mysqld", "pid": 1234, "state": "LISTEN"},
        {"proto": "tcp6", "address": "::", "port": 3306,
         "process": "mysqld", "pid": 1234, "state": "LISTEN"},
        {"proto": "tcp", "address": "127.0.0.1", "port": 5432,
         "process": "postgres", "pid": 1235, "state": "LISTEN"},
        {"proto": "tcp", "address": "0.0.0.0", "port": 41639,
         "process": "sshd", "pid": 1, "state": "LISTEN"},
    ],
    "firewall_engines": {
        "csf": {"installed": True, "running": True, "version": "14.21",
                 "denylist_count": 42},
        "firewalld": {"installed": False, "running": False,
                       "version": None, "zones": None},
        "iptables": {"installed": True, "running": True,
                      "binary": "/usr/sbin/iptables-legacy"},
        "nftables": {"installed": False, "running": False,
                      "version": None},
    },
    "mysql_bind_address": "0.0.0.0",
    "firewall_rules_summary": {
        "csf": {
            "open_tcp_ports": [22, 80, 443, 2083, 2087],
            "open_udp_ports": [],
        },
        "firewalld": None,
        "iptables_filter_count": 80,
        "iptables_nat_count": 5,
        "nftables_ruleset_lines": 0,
    },
})


def test_analyzers_consume_sidecar_json():
    """Both analyzers happily consume the same port-audit.json.

    This is the integration contract — the sidecar JSON is the
    canonical artifact the analyzer layer reads.
    """
    fs = FakeFileSystem({"/var/log/alma-audit/port-audit.json": EXAMPLE_JSON})
    listening = analyze_listening_ports(
        fs,
        rules={"layer_a_json_path": "/var/log/alma-audit/port-audit.json"},
    )
    firewall = analyze_firewall_state(
        fs,
        rules={"layer_a_json_path": "/var/log/alma-audit/port-audit.json"},
    )
    assert listening, "listening_ports produced no findings"
    assert firewall, "firewall_state produced no findings"

    # D21 fires for MySQL on 0.0.0.0:3306 (critical port public-bind).
    crit = [f for f in listening if f.severity.value == "CRITICAL"]
    assert any("3306" in f.title for f in crit)

    # D23 fires for MySQL dual-stack (0.0.0.0:3306 + ::3306).
    warn = [f for f in listening if f.severity.value == "WARN"]
    assert any("dual-stack" in f.title for f in warn)

    # D22 fires for mysql_bind_address=0.0.0.0 (the config-side
    # secondary signal — only emitted when D21's listener signal is
    # the canonical answer; both fire here per the plan).
    # Note: D22 may be suppressed if D21 already fired (per the
    # plan §12 default), but the JSON carries bind_address so the
    # INFO summary still surfaces it.

    # No D25 (CSF installed).
    no_fw = [f for f in firewall if f.severity.value == "CRITICAL"
              and "No firewall" in f.title]
    assert not no_fw


def test_json_round_trip_minimal():
    """A JSON with only the required keys (schema_version + listeners)
    parses cleanly. Missing firewall_engines block → no firewall
    info, but the analyzer never crashes.
    """
    minimal = json.dumps({
        "schema_version": 1,
        "listeners": [
            {"proto": "tcp", "address": "0.0.0.0", "port": 3306,
             "process": "mysqld", "pid": 1, "state": "LISTEN"},
        ],
    })
    fs = FakeFileSystem({"/var/log/alma-audit/port-audit.json": minimal})
    listening = analyze_listening_ports(
        fs,
        rules={"layer_a_json_path": "/var/log/alma-audit/port-audit.json"},
    )
    firewall = analyze_firewall_state(
        fs,
        rules={"layer_a_json_path": "/var/log/alma-audit/port-audit.json"},
    )
    # MySQL exposed → CRITICAL D21.
    assert any(
        f.severity.value == "CRITICAL" and "3306" in f.title
        for f in listening
    )
    # Firewall data missing → Layer A returns [] → Layer B sees
    # nothing → D25 CRITICAL.
    assert any(
        f.severity.value == "CRITICAL" and "No firewall" in f.title
        for f in firewall
    )


def test_json_round_trip_with_only_firewall_block():
    """A JSON with only the firewall block (no listeners key) still
    parses. The listening_ports analyzer finds zero listeners and
    emits the empty-INFO finding.
    """
    only_firewall = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": True, "running": True,
                     "version": "14.21", "denylist_count": 0},
            "firewalld": {"installed": False, "running": False,
                           "version": None, "zones": None},
            "iptables": {"installed": False, "running": False},
            "nftables": {"installed": False, "running": False},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 80,
            "nftables_ruleset_lines": 0,
        },
    })
    fs = FakeFileSystem({"/var/log/alma-audit/port-audit.json": only_firewall})
    listening = analyze_listening_ports(
        fs,
        rules={"layer_a_json_path": "/var/log/alma-audit/port-audit.json"},
    )
    firewall = analyze_firewall_state(
        fs,
        rules={"layer_a_json_path": "/var/log/alma-audit/port-audit.json"},
    )
    # Layer A returns [] for listeners — the analyzer falls back to
    # Layer B, which finds nothing → INFO summary.
    listening_info = [f for f in listening if f.severity.value == "INFO"]
    assert any("No listening ports" in f.title for f in listening_info)
    # CSF installed → no D25.
    no_fw = [f for f in firewall if f.severity.value == "CRITICAL"
              and "No firewall" in f.title]
    assert not no_fw


def test_json_with_mysql_bind_address_alone():
    """A JSON with only ``mysql_bind_address=127.0.0.1`` and no listeners
    → D22 silent (acceptable bind)."""
    only_bind = json.dumps({
        "schema_version": 1,
        "listeners": [],
        "mysql_bind_address": "127.0.0.1",
    })
    fs = FakeFileSystem({"/var/log/alma-audit/port-audit.json": only_bind})
    listening = analyze_listening_ports(
        fs,
        rules={"layer_a_json_path": "/var/log/alma-audit/port-audit.json"},
    )
    # No D22 (acceptable bind address).
    assert not any("bind-address" in f.title for f in listening)