"""Tests for the analyzer orchestration layer."""

from __future__ import annotations

from alma_audit.config import Config
from alma_audit.runner import run_analyzers
from alma_audit.runners import FakeFileSystem


def test_run_analyzers_collects_findings_from_all_three():
    fs = FakeFileSystem(files={
        "/var/log/apache2/access_log":
            "1.2.3.4 - - [17/Aug/2026:04:12:34 +0000] \"GET /wp-login.php HTTP/1.1\" 404 - \"-\" \"ua\"\n"
            * 50,
        "/var/log/apache2/domlogs/example.com": "",
        "/var/log/apache2/domlogs/hostdzi" + "a" * 100: "",  # overlong
        "/var/log/apache2/error_log":
            "[Sun Aug 17 04:12:34.123456 2026] [core:error] [pid 12345] AH00037: 503 Service Unavailable\n",
        "/var/log/apache2/modsec_audit.log": "",
    })
    cfg = Config()
    findings = run_analyzers(cfg, fs)
    modules_seen = {f.module for f in findings}
    assert "access_log" in modules_seen
    assert "domlog_inventory" in modules_seen
    assert "modsec_log" in modules_seen


def test_run_analyzers_handles_missing_root_gracefully():
    fs = FakeFileSystem()  # nothing
    cfg = Config()
    findings = run_analyzers(cfg, fs)
    # Every analyzer should at least emit an INFO finding about missing input
    assert all(f.severity.value == "INFO" for f in findings)


def test_run_analyzers_respects_module_overrides():
    """A module's rule overrides should be passed through."""
    fs = FakeFileSystem(files={
        "/var/log/apache2/access_log":
            "1.2.3.4 - - [17/Aug/2026:04:12:34 +0000] \"GET /wp-login.php HTTP/1.1\" 404 - \"-\" \"ua\"\n"
            * 50,
    })
    cfg = Config()
    cfg.modules["access_log"] = {"probe_count_warn": 1000}
    findings = run_analyzers(cfg, fs)
    # With a high threshold, no probe finding should fire
    probe_findings = [f for f in findings if "probe" in f.title.lower()]
    assert probe_findings == []


def test_run_analyzers_silent_when_cryptography_missing_and_no_cert_roots():
    """Regression: a default install without `[ssl]` must NOT emit a
    WARN when no cert roots exist on disk. Without this guard, every
    cron run on a non-cPanel host would exit 1 — defeating the
    INFO-only / cron-clean contract.
    """
    from unittest.mock import patch

    fs = FakeFileSystem()  # nothing — no cert roots, no log files
    cfg = Config()
    with patch(
        "alma_audit.analyzers.ssl_cert.analyzer.cryptography_available",
        return_value=False,
    ):
        findings = run_analyzers(cfg, fs)
    # The only finding should be the "no cert directory" INFO.
    # No WARN about cryptography-missing.
    cryptography_warns = [
        f for f in findings
        if f.module == "ssl_cert" and "cryptography" in f.title.lower()
    ]
    assert cryptography_warns == []
    # And no CRITICAL / non-INFO findings overall.
    from alma_audit.models import Severity
    assert all(f.severity == Severity.INFO for f in findings)


# --------------------------------------------------------------------
# AISO-209 review fix: ``modules.ssh_hardening.config_path`` YAML key
# --------------------------------------------------------------------


def _ssh_hardening_findings(findings):
    """Return only the ssh_hardening-scan INFO finding (the one whose
    title starts with ``Scanned ...``)."""
    return [
        f for f in findings
        if f.module == "ssh_hardening"
        and f.title.startswith("Scanned ")
    ]


def test_modules_ssh_hardening_config_path_overrides_default():
    """The issue-spec key ``modules.ssh_hardening.config_path``
    must take effect when set. We register the SSH file ONLY at the
    alternate path; if the runner reads the default ``paths.*`` key
    instead, the analyzer sees an empty filesystem and emits the
    "No sshd_config files found" INFO rather than the
    "Scanned ... " finding with the file content."""
    from alma_audit.analyzers.ssh_hardening import (
        DEFAULT_SSHD_CONFIG_PATH,
        DEFAULT_SSHD_DROP_IN_DIR,
    )

    alt = "/opt/ssh/etc/sshd_config"
    fs = FakeFileSystem(files={
        alt: "Protocol 2\nPermitRootLogin yes\n",
    })
    cfg = Config()
    cfg.modules["ssh_hardening"] = {"config_path": alt}
    findings = run_analyzers(cfg, fs)

    scanned = _ssh_hardening_findings(findings)
    assert scanned, (
        "modules.ssh_hardening.config_path did NOT take effect — "
        "the analyzer didn't pick up the alternate sshd_config"
    )
    detail = scanned[0].details
    assert detail["config_path"] == alt
    assert alt in detail["files_scanned"]
    assert DEFAULT_SSHD_CONFIG_PATH not in detail["files_scanned"]


def test_paths_ssh_config_path_still_works_for_backcompat():
    """``paths.ssh_config_path`` (the original PR #12 key) remains a
    valid override for operators who haven't migrated to the module-
    level key."""
    alt = "/etc/ssh/sshd_config.test"
    fs = FakeFileSystem(files={
        alt: "Protocol 2\nPermitRootLogin yes\n",
    })
    cfg = Config()
    cfg.paths.ssh_config_path = alt
    cfg.paths.ssh_drop_in_dir = "/nonexistent"
    findings = run_analyzers(cfg, fs)

    scanned = _ssh_hardening_findings(findings)
    assert scanned
    assert scanned[0].details["config_path"] == alt


def test_modules_key_wins_over_paths_key():
    """When BOTH ``paths.ssh_config_path`` and
    ``modules.ssh_hardening.config_path`` are set, the module key
    wins (the issue-spec path is the more specific contract)."""
    paths_key = "/etc/ssh/paths-key.conf"
    modules_key = "/etc/ssh/modules-key.conf"
    fs = FakeFileSystem(files={
        paths_key: "Protocol 2\nPermitRootLogin yes\n",
        modules_key: "Protocol 2\nPermitRootLogin no\n",
    })
    cfg = Config()
    cfg.paths.ssh_config_path = paths_key
    cfg.paths.ssh_drop_in_dir = "/nonexistent"
    cfg.modules["ssh_hardening"] = {"config_path": modules_key}
    findings = run_analyzers(cfg, fs)

    scanned = _ssh_hardening_findings(findings)
    assert scanned
    assert scanned[0].details["config_path"] == modules_key
    # The PermitRootLogin no from the modules-key file MUST be in
    # effect (no CRITICAL).
    crit = [
        f for f in findings
        if f.module == "ssh_hardening" and "root SSH login" in f.title
    ]
    assert crit == []


def test_modules_ssh_hardening_drop_in_dir_is_honoured():
    """``modules.ssh_hardening.drop_in_dir`` (an optional sibling
    of ``config_path``) is honoured too — sets the drop-in
    directory independently of ``config_path``'s parent dir."""
    from alma_audit.analyzers.ssh_hardening import DEFAULT_SSHD_CONFIG_PATH

    fs = FakeFileSystem(files={
        DEFAULT_SSHD_CONFIG_PATH: (
            "Include /opt/ssh/drop-ins/*.conf\n"
            "Protocol 2\n"
        ),
        "/opt/ssh/drop-ins/10-weak.conf": "PermitRootLogin yes\n",
    })
    cfg = Config()
    cfg.modules["ssh_hardening"] = {
        "drop_in_dir": "/opt/ssh/drop-ins",
    }
    findings = run_analyzers(cfg, fs)
    # Default config_path is used (no override) but the drop-in
    # directory comes from the module key — and the main file's
    # ``Include`` directive picks it up.
    crit = [
        f for f in findings
        if f.module == "ssh_hardening" and "root SSH login" in f.title
    ]
    assert len(crit) == 1
    assert crit[0].details["source_path"] == "/opt/ssh/drop-ins/10-weak.conf"


def test_modules_ssh_hardening_config_path_invalid_type_is_ignored():
    """A non-string ``config_path`` (typo / bool / int / None) is
    ignored — the analyzer falls back to ``paths.ssh_config_path``.
    This protects operators from a config typo killing the audit."""
    fs = FakeFileSystem(files={
        "/etc/ssh/sshd_config": "Protocol 2\n",
    })
    cfg = Config()
    cfg.modules["ssh_hardening"] = {"config_path": 12345}  # bogus
    findings = run_analyzers(cfg, fs)
    scanned = _ssh_hardening_findings(findings)
    assert scanned
    assert scanned[0].details["config_path"] == "/etc/ssh/sshd_config"
