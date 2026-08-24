"""Tests for the ssh_hardening analyzer (AISO-209).

Coverage matrix against acceptance criteria #3 / #5 / #6:

  #3 — every CRITICAL / WARN / INFO directive triggers
       exactly one finding with the expected severity.
  #4 — every finding's ``details`` carries ``source_line`` with
       the actual line from the config.
  #5 — the weak fixture fires exactly the expected findings.
  #6 — the strong fixture fires zero CRITICAL, zero WARN.

The fixtures themselves live under ``tests/fixtures/``:

  sshd_config_weak.conf   — every weak posture
  sshd_config_strong.conf — CIS Benchmark minimum
"""

from __future__ import annotations

import pathlib

import pytest

from alma_audit.analyzers.ssh_hardening import (
    DEFAULT_SSHD_CONFIG_PATH,
    DEFAULT_SSHD_DROP_IN_DIR,
    analyze_ssh_config,
    parse_sshd_config,
)
from alma_audit.models import Severity
from alma_audit.runners import FakeFileSystem


FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
WEAK_CONF = (FIXTURES / "sshd_config_weak.conf").read_text(encoding="utf-8")
STRONG_CONF = (FIXTURES / "sshd_config_strong.conf").read_text(encoding="utf-8")


def _by_title(findings, contains: str) -> list:
    """Return findings whose title contains `contains` (case-sensitive substring)."""
    return [f for f in findings if contains in f.title]


def _by_severity(findings, sev: Severity) -> list:
    return [f for f in findings if f.severity == sev]


# --------------------------------------------------------------------
# parser / aggregator unit tests
# --------------------------------------------------------------------


def test_parser_classifies_known_directives():
    text = (
        "PermitRootLogin yes\n"
        "Protocol 2\n"
        "Port 5022\n"
        "MaxAuthTries 3\n"
    )
    directives, malformed = parse_sshd_config(
        text.splitlines(), source_path="/etc/ssh/sshd_config",
    )
    assert malformed == 0
    assert {d.keyword for d in directives} >= {
        "PermitRootLogin", "Protocol", "Port", "MaxAuthTries",
    }


def test_parser_strips_comments():
    text = (
        "# this is a comment\n"
        "PermitRootLogin yes # trailing comment\n"
        "  # indented comment\n"
        "Protocol 2\n"
    )
    directives, _ = parse_sshd_config(
        text.splitlines(), source_path="/etc/ssh/sshd_config",
    )
    keywords = [d.keyword for d in directives]
    assert "PermitRootLogin" in keywords
    assert "Protocol" in keywords
    # Trailing-comment value should be ``yes`` only — the parser
    # strips ``# trailing comment`` BEFORE splitting on whitespace,
    # so the values tuple is `("yes",)`.
    prl = next(d for d in directives if d.keyword == "PermitRootLogin")
    assert prl.values == ("yes",)


def test_parser_skips_match_blocks():
    text = (
        "Protocol 2\n"
        "Match User root\n"
        "    PermitRootLogin yes\n"
        "    PasswordAuthentication yes\n"
        "Match Group admins\n"
        "    PermitRootLogin no\n"
    )
    directives, _ = parse_sshd_config(
        text.splitlines(), source_path="/etc/ssh/sshd_config",
    )
    # Only Protocol survives — every ``Match`` block is skipped
    # entirely. The analyzer's contract is the top-level posture.
    assert [d.keyword for d in directives] == ["Protocol"]


def test_parser_accepts_equals_form():
    text = "PermitRootLogin=yes\nProtocol=2\n"
    directives, _ = parse_sshd_config(
        text.splitlines(), source_path="/etc/ssh/sshd_config",
    )
    assert {d.keyword for d in directives} == {"PermitRootLogin", "Protocol"}


def test_parser_keyword_case_insensitive_but_values_preserved():
    text = "permitrootlogin YES\n"
    directives, _ = parse_sshd_config(
        text.splitlines(), source_path="/etc/ssh/sshd_config",
    )
    assert len(directives) == 1
    d = directives[0]
    # Keyword is preserved verbatim.
    assert d.keyword == "permitrootlogin"
    # Values are preserved verbatim too — the aggregator case-folds
    # for the last-wins dict.
    assert d.values == ("YES",)


# --------------------------------------------------------------------
# Weak fixture: every expected finding fires
# --------------------------------------------------------------------


def test_weak_fixture_fires_every_expected_finding():
    fs = FakeFileSystem(files={
        DEFAULT_SSHD_CONFIG_PATH: WEAK_CONF,
    })
    findings = analyze_ssh_config(fs)

    # CRITICAL findings.
    assert _by_title(findings, "PermitRootLogin yes")[0].severity == Severity.CRITICAL
    assert _by_title(findings, "PermitEmptyPasswords yes")[0].severity == Severity.CRITICAL
    assert _by_title(findings, "Protocol 1 enabled")[0].severity == Severity.CRITICAL

    # WARN findings.
    assert _by_title(findings, "PasswordAuthentication yes")[0].severity == Severity.WARN
    assert _by_title(findings, "default port 22")[0].severity == Severity.WARN
    assert _by_title(findings, "MaxAuthTries 10")[0].severity == Severity.WARN
    assert _by_title(findings, "ClientAliveInterval 0")[0].severity == Severity.WARN
    assert _by_title(findings, "LoginGraceTime 300")[0].severity == Severity.WARN
    assert _by_title(findings, "No AllowUsers / AllowGroups")[0].severity == Severity.WARN
    assert _by_title(findings, "Weak Ciphers")[0].severity == Severity.WARN
    assert _by_title(findings, "Weak MACs")[0].severity == Severity.WARN

    # INFO findings.
    assert _by_title(findings, "X11Forwarding yes")[0].severity == Severity.INFO
    assert _by_title(findings, "No SSH Banner")[0].severity == Severity.INFO


def test_weak_fixture_count_summary():
    """Sanity: the weak fixture fires a known count of each severity.

    The summary INFO (``Scanned ... post-Include directive(s)``)
    plus the listed findings gives a stable count. If a new rule
    is added without updating this test, the test fails loud —
    which is the desired behaviour.
    """
    fs = FakeFileSystem(files={DEFAULT_SSHD_CONFIG_PATH: WEAK_CONF})
    findings = analyze_ssh_config(fs)
    assert len(_by_severity(findings, Severity.CRITICAL)) == 3
    assert len(_by_severity(findings, Severity.WARN)) == 8
    # 1 scan-summary INFO + 2 directive-driven INFOs.
    assert len(_by_severity(findings, Severity.INFO)) == 3


# --------------------------------------------------------------------
# Acceptance criterion #4: source_line is preserved
# --------------------------------------------------------------------


def test_every_finding_carries_source_line():
    """Per acceptance criterion #4: ``details.source_line`` is the
    actual config line that triggered the rule."""
    fs = FakeFileSystem(files={DEFAULT_SSHD_CONFIG_PATH: WEAK_CONF})
    findings = analyze_ssh_config(fs)
    # Skip the scan-summary INFO finding (it has no ``source_line``).
    for f in findings:
        if "Scanned" in f.title:
            continue
        assert "source_line" in f.details, (
            f"Finding {f.title!r} missing source_line in details"
        )
        # The source_line must actually contain the directive's
        # keyword (modulo leading whitespace).
        keyword = f.details.get("directive")
        if keyword is not None:
            assert keyword in f.details["source_line"], (
                f"Finding {f.title!r} source_line does not contain {keyword!r}: "
                f"{f.details['source_line']!r}"
            )


def test_every_finding_carries_source_path():
    fs = FakeFileSystem(files={DEFAULT_SSHD_CONFIG_PATH: WEAK_CONF})
    findings = analyze_ssh_config(fs)
    for f in findings:
        if "Scanned" in f.title:
            continue
        assert "source_path" in f.details, (
            f"Finding {f.title!r} missing source_path"
        )
        # Either a real path OR the ``(absent)`` sentinel for the
        # AllowUsers / Banner rules (which fire when the directive
        # is missing entirely).
        assert f.details["source_path"] in (
            DEFAULT_SSHD_CONFIG_PATH, "(absent)",
        ), f"Unexpected source_path: {f.details['source_path']!r}"


# --------------------------------------------------------------------
# Acceptance criterion #6: strong fixture fires zero CRITICAL, zero WARN
# --------------------------------------------------------------------


def test_strong_fixture_fires_zero_critical_zero_warn():
    """Acceptance criterion #6 — strong config has no CRITICAL/WARN."""
    fs = FakeFileSystem(files={DEFAULT_SSHD_CONFIG_PATH: STRONG_CONF})
    findings = analyze_ssh_config(fs)
    assert _by_severity(findings, Severity.CRITICAL) == [], (
        f"Unexpected CRITICAL findings: {[f.title for f in _by_severity(findings, Severity.CRITICAL)]}"
    )
    assert _by_severity(findings, Severity.WARN) == [], (
        f"Unexpected WARN findings: {[f.title for f in _by_severity(findings, Severity.WARN)]}"
    )


def test_strong_fixture_infos_are_expected():
    """The strong fixture fires three known INFOs:
    ``PermitRootLogin prohibit-password``, ``X11Forwarding yes``,
    and ``No SSH Banner``. All three are by design."""
    fs = FakeFileSystem(files={DEFAULT_SSHD_CONFIG_PATH: STRONG_CONF})
    findings = analyze_ssh_config(fs)
    infos = _by_severity(findings, Severity.INFO)
    titles = [f.title for f in infos]
    assert any("prohibit-password" in t for t in titles)
    assert any("X11Forwarding" in t for t in titles)
    assert any("No SSH Banner" in t for t in titles)


# --------------------------------------------------------------------
# Drop-in handling — last-wins, alphabetical order
# --------------------------------------------------------------------


def test_drop_in_overrides_main_config():
    """A drop-in that says ``PermitRootLogin no`` after the main
    file's ``PermitRootLogin yes`` must suppress the CRITICAL
    finding (last-wins semantics, matching OpenSSH)."""
    fs = FakeFileSystem(files={
        DEFAULT_SSHD_CONFIG_PATH: "PermitRootLogin yes\nProtocol 2\n",
        f"{DEFAULT_SSHD_DROP_IN_DIR}/90-hardening.conf": "PermitRootLogin no\n",
    })
    findings = analyze_ssh_config(fs)
    assert _by_title(findings, "root SSH login allowed") == [], (
        "PermitRootLogin yes CRITICAL should be suppressed by the "
        "drop-in override"
    )


def test_drop_ins_are_concatenated_alphabetically():
    """Drop-ins must be parsed in alphabetical order to match
    OpenSSH ``Include /etc/ssh/sshd_config.d/*.conf`` semantics."""
    fs = FakeFileSystem(files={
        DEFAULT_SSHD_CONFIG_PATH: "Protocol 2\n",
        # Intentionally out of alphabetical order on disk; the
        # analyzer must sort before reading.
        f"{DEFAULT_SSHD_DROP_IN_DIR}/zz-late.conf": "PermitRootLogin no\n",
        f"{DEFAULT_SSHD_DROP_IN_DIR}/aa-early.conf": "PermitRootLogin yes\n",
    })
    findings = analyze_ssh_config(fs)
    # Last-wins: ``zz-late.conf`` overrides ``aa-early.conf`` —
    # PermitRootLogin no survives → no CRITICAL.
    assert _by_title(findings, "root SSH login allowed") == []


def test_non_conf_files_in_drop_in_dir_are_ignored():
    """Only ``*.conf`` files in the drop-in dir are read."""
    fs = FakeFileSystem(files={
        DEFAULT_SSHD_CONFIG_PATH: "PermitRootLogin yes\nProtocol 2\n",
        f"{DEFAULT_SSHD_DROP_IN_DIR}/readme.txt": "PermitRootLogin no\n",
        f"{DEFAULT_SSHD_DROP_IN_DIR}/not-a-config": "PermitRootLogin no\n",
    })
    findings = analyze_ssh_config(fs)
    # The non-``.conf`` files do NOT override — CRITICAL fires.
    assert len(_by_title(findings, "root SSH login allowed")) == 1


# --------------------------------------------------------------------
# Rule-by-rule coverage (acceptance criterion #3)
# --------------------------------------------------------------------


@pytest.mark.parametrize("directive, value, expected_sev, expected_substr", [
    ("PermitRootLogin", "yes", Severity.CRITICAL, "PermitRootLogin yes — root SSH login allowed"),
    ("PermitRootLogin", "no", None, ""),
    ("PermitRootLogin", "prohibit-password", Severity.INFO, "prohibit-password — root via key only"),
    ("PermitRootLogin", "without-password", Severity.INFO, "without-password — root via key only"),
    ("PermitEmptyPasswords", "yes", Severity.CRITICAL, "PermitEmptyPasswords yes"),
    ("PermitEmptyPasswords", "no", None, ""),
    ("Protocol", "1", Severity.CRITICAL, "Protocol 1 (SSH-1 only)"),
    ("Protocol", "2", None, ""),
    ("Protocol", "1,2", Severity.CRITICAL, "Protocol 1 enabled"),
    ("Protocol", "2,1", Severity.CRITICAL, "Protocol 1 enabled"),
    ("PasswordAuthentication", "yes", Severity.WARN, "PasswordAuthentication yes"),
    ("PasswordAuthentication", "no", None, ""),
    ("Port", "22", Severity.WARN, "default port 22"),
    ("Port", "5022", None, ""),
    ("MaxAuthTries", "10", Severity.WARN, "MaxAuthTries 10"),
    ("MaxAuthTries", "3", None, ""),
    ("MaxAuthTries", "6", None, ""),  # exactly the threshold = no WARN
    ("ClientAliveInterval", "0", Severity.WARN, "ClientAliveInterval 0"),
    ("ClientAliveInterval", "300", None, ""),
    ("LoginGraceTime", "300", Severity.WARN, "LoginGraceTime 300"),
    ("LoginGraceTime", "120", None, ""),  # exactly the threshold = no WARN
    ("LoginGraceTime", "60", None, ""),
    ("LoginGraceTime", "2m", None, ""),  # 2m == 120s == threshold
    ("LoginGraceTime", "3m", Severity.WARN, "LoginGraceTime 3m"),  # 180s
    ("X11Forwarding", "yes", Severity.INFO, "X11Forwarding yes"),
    ("X11Forwarding", "no", None, ""),
])
def test_rule_per_directive(directive, value, expected_sev, expected_substr):
    """One parametrized case per (directive, value) pair, asserting
    that the rule fires (or not) with the right severity."""
    from alma_audit.analyzers.ssh_hardening.aggregator import aggregate
    from alma_audit.analyzers.ssh_hardening.parser import SshdDirective

    snap = aggregate([SshdDirective(
        keyword=directive,
        values=(value,),
        source_path="/etc/ssh/sshd_config",
        source_line=f"{directive} {value}",
    )])
    settings = {"max_auth_tries_warn": 6, "login_grace_time_warn": 120}

    from alma_audit.analyzers.ssh_hardening.rules import all_findings
    findings = all_findings(snap, settings)

    if expected_sev is None:
        # Assert that NO finding's title starts with the directive
        # name — i.e. the rule did NOT fire. Other findings (the
        # AllowUsers/Banner WARN+INFO) are unrelated to the directive
        # under test and may legitimately appear.
        if expected_substr:
            assert not any(
                f.title.startswith(expected_substr) for f in findings
            ), (
                f"{directive} {value} should NOT fire; got: "
                f"{[f.title for f in findings]}"
            )
    else:
        matching = [f for f in findings if expected_substr in f.title]
        assert matching, (
            f"{directive} {value} expected to fire ({expected_sev}); "
            f"got: {[f.title for f in findings]}"
        )
        assert matching[0].severity == expected_sev


# --------------------------------------------------------------------
# Weak-algorithms rule
# --------------------------------------------------------------------


def test_weak_ciphers_lists_offenders():
    from alma_audit.analyzers.ssh_hardening.aggregator import aggregate
    from alma_audit.analyzers.ssh_hardening.parser import SshdDirective

    snap = aggregate([SshdDirective(
        keyword="Ciphers",
        values=("aes128-ctr,3des-cbc,arcfour,aes256-ctr",),
        source_path="/etc/ssh/sshd_config",
        source_line="Ciphers aes128-ctr,3des-cbc,arcfour,aes256-ctr",
    )])
    from alma_audit.analyzers.ssh_hardening.rules import all_findings
    findings = all_findings(snap, {"max_auth_tries_warn": 6, "login_grace_time_warn": 120})
    weak = _by_title(findings, "Weak Ciphers")
    assert len(weak) == 1
    assert set(weak[0].details["weak_algorithms"]) == {"3des-cbc", "arcfour"}


def test_weak_macs_lists_offenders():
    from alma_audit.analyzers.ssh_hardening.aggregator import aggregate
    from alma_audit.analyzers.ssh_hardening.parser import SshdDirective

    snap = aggregate([SshdDirective(
        keyword="MACs",
        values=("hmac-sha2-512,hmac-md5",),
        source_path="/etc/ssh/sshd_config",
        source_line="MACs hmac-sha2-512,hmac-md5",
    )])
    from alma_audit.analyzers.ssh_hardening.rules import all_findings
    findings = all_findings(snap, {"max_auth_tries_warn": 6, "login_grace_time_warn": 120})
    weak = _by_title(findings, "Weak MACs")
    assert len(weak) == 1
    assert weak[0].details["weak_algorithms"] == ["hmac-md5"]


def test_no_weak_algorithms_when_modern_list():
    from alma_audit.analyzers.ssh_hardening.aggregator import aggregate
    from alma_audit.analyzers.ssh_hardening.parser import SshdDirective

    snap = aggregate([
        SshdDirective(
            keyword="Ciphers",
            values=("chacha20-poly1305@openssh.com,aes128-ctr",),
            source_path="/etc/ssh/sshd_config",
            source_line="Ciphers chacha20-poly1305@openssh.com,aes128-ctr",
        ),
        SshdDirective(
            keyword="MACs",
            values=("hmac-sha2-512,hmac-sha2-256",),
            source_path="/etc/ssh/sshd_config",
            source_line="MACs hmac-sha2-512,hmac-sha2-256",
        ),
    ])
    from alma_audit.analyzers.ssh_hardening.rules import all_findings
    findings = all_findings(snap, {"max_auth_tries_warn": 6, "login_grace_time_warn": 120})
    assert _by_title(findings, "Weak Ciphers") == []
    assert _by_title(findings, "Weak MACs") == []


# --------------------------------------------------------------------
# Allowlist rule
# --------------------------------------------------------------------


def test_no_allowlist_fires_warn():
    fs = FakeFileSystem(files={DEFAULT_SSHD_CONFIG_PATH: "Protocol 2\n"})
    findings = analyze_ssh_config(fs)
    assert any(
        f.severity == Severity.WARN and "AllowUsers" in f.title
        for f in findings
    )


def test_allow_groups_suppresses_warn():
    fs = FakeFileSystem(files={
        DEFAULT_SSHD_CONFIG_PATH: "Protocol 2\nAllowGroups ssh-admins\n",
    })
    findings = analyze_ssh_config(fs)
    assert not any("AllowUsers" in f.title for f in findings)


def test_allow_users_suppresses_warn():
    fs = FakeFileSystem(files={
        DEFAULT_SSHD_CONFIG_PATH: "Protocol 2\nAllowUsers admin\n",
    })
    findings = analyze_ssh_config(fs)
    assert not any("AllowUsers" in f.title for f in findings)


# --------------------------------------------------------------------
# Missing config + drop-in dir
# --------------------------------------------------------------------


def test_missing_main_config_emits_info():
    """No main config and no drop-ins → quiet INFO finding."""
    fs = FakeFileSystem()  # no files at all
    findings = analyze_ssh_config(fs)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "No sshd_config" in findings[0].title


def test_missing_main_but_dropin_present_works():
    """Missing main config + present drop-in: the drop-in still
    drives the analysis."""
    fs = FakeFileSystem(files={
        f"{DEFAULT_SSHD_DROP_IN_DIR}/10-weak.conf": "PermitRootLogin yes\n",
    })
    findings = analyze_ssh_config(fs)
    assert any(
        f.severity == Severity.CRITICAL and "root SSH login" in f.title
        for f in findings
    )


# --------------------------------------------------------------------
# YAML threshold override (acceptance criterion #2 — modules.ssh_hardening)
# --------------------------------------------------------------------


def test_yaml_threshold_override_relaxes_max_auth_tries():
    fs = FakeFileSystem(files={
        DEFAULT_SSHD_CONFIG_PATH: "MaxAuthTries 10\n",
    })
    # Default threshold (6) would fire. Relax to 20 → no WARN.
    findings = analyze_ssh_config(fs, rules={"max_auth_tries_warn": 20})
    assert _by_title(findings, "MaxAuthTries 10") == []


def test_yaml_threshold_override_tightens_max_auth_tries():
    fs = FakeFileSystem(files={
        DEFAULT_SSHD_CONFIG_PATH: "MaxAuthTries 4\n",
    })
    # Default threshold (6) would NOT fire (4 < 6). Tighten to 3 → WARN.
    findings = analyze_ssh_config(fs, rules={"max_auth_tries_warn": 3})
    assert len(_by_title(findings, "MaxAuthTries 4")) == 1


def test_yaml_threshold_override_relaxes_login_grace_time():
    fs = FakeFileSystem(files={
        DEFAULT_SSHD_CONFIG_PATH: "LoginGraceTime 300\n",
    })
    findings = analyze_ssh_config(fs, rules={"login_grace_time_warn": 600})
    assert _by_title(findings, "LoginGraceTime 300") == []


# --------------------------------------------------------------------
# Public API surface (re-export contract)
# --------------------------------------------------------------------


def test_package_reexports_expected_symbols():
    """The package's __init__ must re-export the symbols used by the
    runner + the tests."""
    from alma_audit.analyzers import ssh_hardening

    expected = {
        "analyze_ssh_config",
        "SshdConfigSnapshot",
        "aggregate",
        "finalize",
        "SshdDirective",
        "parse_multiple",
        "parse_sshd_config",
        "DEFAULT_RULES",
        "DEFAULT_SSHD_CONFIG_PATH",
        "DEFAULT_SSHD_DROP_IN_DIR",
        "WEAK_CIPHERS",
        "WEAK_MACS",
    }
    for name in expected:
        assert hasattr(ssh_hardening, name), (
            f"ssh_hardening package missing re-export: {name}"
        )


# --------------------------------------------------------------------
# Read-only contract — no subprocess, no writes
# --------------------------------------------------------------------


def test_no_subprocess_calls_in_ssh_hardening():
    """The package must not shell out (read-only contract)."""
    import ast
    import pathlib

    pkg_dir = (
        pathlib.Path(__file__).resolve().parents[1]
        / "src" / "alma_audit" / "analyzers" / "ssh_hardening"
    )
    for py in pkg_dir.glob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {
                    "system", "popen", "run", "call",
                    "check_call", "check_output", "exec",
                }, f"{py.name} calls {node.func.id}() — forbidden"


def test_ssh_hardening_does_not_open_files_directly():
    """Analyzers must use FileSystem — not raw open()."""
    import ast
    import pathlib

    pkg_dir = (
        pathlib.Path(__file__).resolve().parents[1]
        / "src" / "alma_audit" / "analyzers" / "ssh_hardening"
    )
    for py in pkg_dir.glob("*.py"):
        if py.name == "__init__.py":
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "open", (
                    f"{py.name} calls open() directly — "
                    "use the FileSystem protocol"
                )
