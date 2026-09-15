"""Tests for the firewall_state analyzer (AISO-220).

Covers:
*   Layer A JSON parsing — happy path, missing fields, schema mismatch.
*   Layer B filesystem probes — installed detection across CSF,
    firewalld, iptables, nftables.
*   Analyzer behavior — D25 no firewall, D26 engine installed but
    not running, D27 CSF lfd dead, D28 running with empty ruleset.
*   Layer A vs Layer B fallback.
"""
from __future__ import annotations

import json

from alma_audit.analyzers.firewall_state import (
    DEFAULT_PROBES,
    DEFAULT_RULES,
    EngineState,
    analyze_firewall_state,
    parse_filesystem_probes,
    parse_layer_a_json,
)
from alma_audit.models import Severity
from alma_audit.runners import FakeFileSystem


# ---------------------------------------------------------------------------
# parser.parse_layer_a_json
# ---------------------------------------------------------------------------


def test_parse_layer_a_json_happy_path():
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": True, "running": True, "version": "14.21",
                     "denylist_count": 42},
            "firewalld": {"installed": False, "running": False,
                           "version": None, "zones": None},
            "iptables": {"installed": True, "running": True,
                          "binary": "/usr/sbin/iptables"},
            "nftables": {"installed": False, "running": False,
                          "version": None},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 80,
            "nftables_ruleset_lines": 0,
        },
    })
    result = parse_layer_a_json(text)
    assert len(result.engines) == 4
    by_name = {e.name: e for e in result.engines}
    assert by_name["csf"].installed is True
    assert by_name["csf"].running is True
    assert by_name["csf"].denylist_count == 42
    assert by_name["firewalld"].installed is False
    assert by_name["iptables"].binary == "/usr/sbin/iptables"
    assert result.iptables_filter_count == 80


def test_parse_layer_a_json_schema_mismatch_returns_empty():
    text = json.dumps({
        "schema_version": 999,
        "firewall_engines": {"csf": {"installed": True, "running": True}},
    })
    result = parse_layer_a_json(text)
    assert result.engines == []


def test_parse_layer_a_json_malformed_returns_empty():
    result = parse_layer_a_json("not json")
    assert result.engines == []


def test_parse_layer_a_json_missing_fields_yields_zero_counts():
    """Layer A JSON without ``firewall_rules_summary`` → counts default
    to 0 (D28 stays silent — 0 rules isn't a finding on its own when
    the rule layer can't tell which engine's rules it represents).
    """
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": True, "running": True},
        },
    })
    result = parse_layer_a_json(text)
    assert len(result.engines) == 1
    assert result.iptables_filter_count == 0


# ---------------------------------------------------------------------------
# parser.parse_filesystem_probes — Layer B
# ---------------------------------------------------------------------------


def test_parse_filesystem_probes_csf_installed():
    """``/etc/csf`` directory present → csf detected as installed.

    The FakeFileSystem uses implicit-directory semantics — registering
    a child file (``/etc/csf/csf.conf``) makes the parent (``/etc/csf``)
    appear as a directory via ``is_dir``.
    """
    fs = FakeFileSystem({
        "/etc/csf/csf.conf": "# CSF config\n",
    })
    result = parse_filesystem_probes(fs)
    by_name = {e.name: e for e in result.engines}
    assert by_name["csf"].installed is True
    assert by_name["csf"].running is None  # Layer B can't tell
    assert by_name["firewalld"].installed is False
    assert by_name["iptables"].installed is False


def test_parse_filesystem_probes_binary_only_detection():
    """An engine with only the binary (no config dir) is still
    detected — e.g. nftables ships with /usr/sbin/nft and a
    /etc/nftables.conf file (not a directory).
    """
    fs = FakeFileSystem({
        "/usr/sbin/nft": "#!/bin/sh\necho nft\n",
    })
    result = parse_filesystem_probes(fs)
    by_name = {e.name: e for e in result.engines}
    assert by_name["nftables"].installed is True
    assert by_name["nftables"].binary == "/usr/sbin/nft"


def test_parse_filesystem_probes_returns_all_engines():
    """The parser always returns 4 engine rows (one per supported
    engine) so the rule layer can iterate a fixed shape.
    """
    result = parse_filesystem_probes(FakeFileSystem({}))
    assert len(result.engines) == 4
    names = {e.name for e in result.engines}
    assert names == {"csf", "firewalld", "iptables", "nftables"}


def test_parse_filesystem_probes_firewalld_installed():
    """firewalld installs /etc/firewalld/ — the parser sees that."""
    fs = FakeFileSystem({
        "/etc/firewalld/firewalld.conf": "# firewalld config\n",
    })
    result = parse_filesystem_probes(fs)
    by_name = {e.name: e for e in result.engines}
    assert by_name["firewalld"].installed is True


# ---------------------------------------------------------------------------
# Analyzer — D25 no firewall
# ---------------------------------------------------------------------------


def test_analyze_d25_no_firewall():
    """Empty Layer A + Layer B sees no config → D25 CRITICAL."""
    fs = FakeFileSystem({})
    findings = analyze_firewall_state(
        fs,
        rules={"layer_a_json_path": None, "fallback_to_fs": True},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("No firewall" in f.title for f in crit)


def test_analyze_d25_no_firewall_with_csffix():
    """Layer A populated with csf.installed=True → no D25."""
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": True, "running": True, "version": "14.21",
                     "denylist_count": 0},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 80,
            "nftables_ruleset_lines": 0,
        },
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_firewall_state(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert not any("No firewall" in f.title for f in crit)


# ---------------------------------------------------------------------------
# Analyzer — D26 installed but not running
# ---------------------------------------------------------------------------


def test_analyze_d26_installed_not_running():
    """Layer A: csf.installed=True, csf.running=False → D26 CRITICAL."""
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": True, "running": False, "version": "14.21",
                     "denylist_count": 0},
            "firewalld": {"installed": False, "running": False},
            "iptables": {"installed": False, "running": False},
            "nftables": {"installed": False, "running": False},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 0,
            "nftables_ruleset_lines": 0,
        },
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_firewall_state(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    # D25 + D26 + D27 may all fire (CSF not running = lfd not running)
    titles = " | ".join(f.title for f in crit)
    assert "csf" in titles
    assert "not running" in titles or "lfd" in titles


def test_analyze_d26_suppressed_when_running_unknown():
    """Layer B reports running=None (unknown). The analyzer treats
    this as "can't tell" and stays silent on D26/D27.
    """
    # Layer B sees no config files → no installed engine → no D26
    # anyway. Use a scenario where one engine is installed (Layer B
    # detects it) but running is unknown.
    fs = FakeFileSystem({
        "/etc/csf/csf.conf": "# CSF config\n",
    })
    findings = analyze_firewall_state(
        fs,
        rules={"layer_a_json_path": None, "fallback_to_fs": True},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    # csf installed but running=None → D25 may not fire (CSF IS
    # installed) but D26 stays silent.
    assert not any("not running" in f.title for f in crit)


# ---------------------------------------------------------------------------
# Analyzer — D27 CSF lfd dead
# ---------------------------------------------------------------------------


def test_analyze_d27_csf_lfd_dead():
    """Layer A: csf.installed=True, csf.running=False → D27 fires."""
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": True, "running": False, "version": "14.21",
                     "denylist_count": 0},
            "firewalld": {"installed": False, "running": False},
            "iptables": {"installed": False, "running": False},
            "nftables": {"installed": False, "running": False},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 0,
            "nftables_ruleset_lines": 0,
        },
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_firewall_state(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("lfd" in f.title for f in crit)


def test_analyze_d27_suppressed_when_lfd_running():
    """Layer A: csf.installed=True, csf.running=True → D27 silent."""
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": True, "running": True, "version": "14.21",
                     "denylist_count": 5},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 80,
            "nftables_ruleset_lines": 0,
        },
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_firewall_state(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert not any("lfd" in f.title for f in crit)


def test_analyze_d27_disabled_by_setting():
    """``csf_check_lfd: false`` → D27 suppressed even when conditions
    match (operator explicitly opts out).
    """
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": True, "running": False, "version": "14.21",
                     "denylist_count": 0},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 0,
            "nftables_ruleset_lines": 0,
        },
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_firewall_state(
        fs,
        rules={
            "layer_a_json_path": "/tmp/out/port-audit.json",
            "csf_check_lfd": False,
        },
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert not any("lfd" in f.title for f in crit)


# ---------------------------------------------------------------------------
# Analyzer — D28 running but empty ruleset
# ---------------------------------------------------------------------------


def test_analyze_d28_iptables_empty_ruleset():
    """Layer A: iptables.running=True, iptables_filter_count=2 (below
    the 5-line threshold) → D28 WARN.
    """
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": False, "running": False},
            "firewalld": {"installed": False, "running": False},
            "iptables": {"installed": True, "running": True,
                          "binary": "/usr/sbin/iptables"},
            "nftables": {"installed": False, "running": False},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 2,
            "nftables_ruleset_lines": 0,
        },
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_firewall_state(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    warn = [f for f in findings if f.severity == Severity.WARN]
    assert any("iptables" in f.title and "empty" in f.title for f in warn)


def test_analyze_d28_suppressed_when_above_threshold():
    """iptables_filter_count=80 (well above threshold 5) → no D28."""
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": False, "running": False},
            "firewalld": {"installed": False, "running": False},
            "iptables": {"installed": True, "running": True,
                          "binary": "/usr/sbin/iptables"},
            "nftables": {"installed": False, "running": False},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 80,
            "nftables_ruleset_lines": 0,
        },
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_firewall_state(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    warn = [f for f in findings if f.severity == Severity.WARN]
    assert not any("empty" in f.title for f in warn)


# ---------------------------------------------------------------------------
# Analyzer — Layer A wins over Layer B
# ---------------------------------------------------------------------------


def test_layer_a_preferred_over_layer_b():
    """Layer A populated → Layer B's filesystem probes are skipped.
    If Layer B sees /etc/csf BUT Layer A says csf is installed and
    running, the Layer A data wins (no D25/D26 fired).
    """
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": True, "running": True, "version": "14.21",
                     "denylist_count": 5},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 80,
            "nftables_ruleset_lines": 0,
        },
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
        "/etc/csf/csf.conf": "# CSF config (already known to Layer A)\n",
    })
    findings = analyze_firewall_state(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    # CSF installed + running → no D25 (no firewall) and no D26 (not running).
    crit = [f for f in findings if f.severity.value == "CRITICAL"]
    assert not any("No firewall" in f.title for f in crit)
    assert not any("not running" in f.title for f in crit)
    assert not any("lfd" in f.title for f in crit)


# ---------------------------------------------------------------------------
# Fix suggestions
# ---------------------------------------------------------------------------


def test_d25_critical_finding_carries_fix():
    """D25 CRITICAL carries a ``FindingFix``."""
    fs = FakeFileSystem({})
    findings = analyze_firewall_state(
        fs,
        rules={"layer_a_json_path": None, "fallback_to_fs": True},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit
    assert crit[0].fixes
    fix = crit[0].fixes[0]
    assert "csf" in fix.what.lower() or "firewalld" in fix.what.lower()


def test_d26_critical_finding_carries_fix():
    """D26 CRITICAL carries a ``FindingFix``."""
    text = json.dumps({
        "schema_version": 1,
        "firewall_engines": {
            "csf": {"installed": True, "running": False, "version": "14.21"},
        },
        "firewall_rules_summary": {
            "iptables_filter_count": 0,
            "nftables_ruleset_lines": 0,
        },
    })
    fs = FakeFileSystem({
        "/tmp/out/port-audit.json": text,
    })
    findings = analyze_firewall_state(
        fs, rules={"layer_a_json_path": "/tmp/out/port-audit.json"},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    # D25 may not fire (CSF installed), D26 + D27 will.
    csffix_findings = [f for f in crit if "csf" in f.title.lower()]
    assert csffix_findings
    assert csffix_findings[0].fixes
    fix = csffix_findings[0].fixes[0]
    assert "csf -e" in "\n".join(fix.commands).lower() or "lfd" in fix.what.lower()


# ---------------------------------------------------------------------------
# Default probes + DEFAULT_RULES shape
# ---------------------------------------------------------------------------


def test_default_probes_covers_all_engines():
    """The DEFAULT_PROBES list has one entry per supported engine."""
    names = {p.name for p in DEFAULT_PROBES}
    assert names == {"csf", "firewalld", "iptables", "nftables"}


def test_default_rules_has_required_keys():
    """``DEFAULT_RULES`` carries every key the analyzer reads."""
    assert "layer_a_json_path" in DEFAULT_RULES
    assert "fallback_to_fs" in DEFAULT_RULES
    assert "iptables_filter_min_lines" in DEFAULT_RULES
    assert "nftables_min_lines" in DEFAULT_RULES
    assert "csf_check_lfd" in DEFAULT_RULES


def test_engine_state_dataclass():
    """``EngineState`` carries every field the rule layer reads."""
    e = EngineState(
        name="csf", installed=True, running=True,
        version="14.21", binary="/usr/sbin/csf",
        denylist_count=42,
    )
    assert e.name == "csf"
    assert e.denylist_count == 42
    assert e.running is True