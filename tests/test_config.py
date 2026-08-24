"""Tests for the YAML config loader."""

from __future__ import annotations

import pytest

from alma_audit.config import Config, load_config


def test_load_returns_defaults_when_path_missing():
    cfg = load_config(None)
    assert isinstance(cfg, Config)
    assert cfg.paths.apache_root == "/var/log/apache2"
    assert cfg.paths.domlog_root == "/var/log/apache2/domlogs"


def test_load_returns_defaults_when_file_absent(tmp_path):
    cfg = load_config(str(tmp_path / "missing.yaml"))
    assert cfg.modules == {}


def test_load_overrides_paths(tmp_path):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text(
        "paths:\n"
        "  apache_root: /var/log/custom\n"
        "  domlog_root: /var/log/custom/domlogs\n",
        encoding="utf-8",
    )
    cfg = load_config(str(cfg_file))
    assert cfg.paths.apache_root == "/var/log/custom"
    assert cfg.paths.domlog_root == "/var/log/custom/domlogs"


def test_load_overrides_module_rules(tmp_path):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text(
        "modules:\n"
        "  access_log:\n"
        "    probe_count_warn: 42\n",
        encoding="utf-8",
    )
    cfg = load_config(str(cfg_file))
    assert cfg.modules["access_log"]["probe_count_warn"] == 42


def test_load_rejects_non_mapping_root(tmp_path):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("- not a mapping\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        load_config(str(cfg_file))


def test_load_rejects_malformed_yaml(tmp_path):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("paths:\n  apache_root: [unclosed\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        load_config(str(cfg_file))


def test_load_accepts_unknown_keys(tmp_path):
    """Forward-compat: extra keys are ignored silently."""
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text(
        "future_setting:\n  whatever: true\n",
        encoding="utf-8",
    )
    cfg = load_config(str(cfg_file))
    assert cfg.modules == {}


def test_default_ssl_cert_roots_excludes_os_trust_stores():
    """The default `ssl_cert_roots` only includes the host cert directory.

    OS-level CA trust stores (`/etc/pki/tls/certs`, `/etc/ssl/certs`)
    must be excluded from the default — those directories contain
    package-managed root CAs, not host-issued certs the operator
    renews. Scanning them produces false-positive WARN findings on
    AlmaLinux 8 / RHEL 8 hosts (the `ca-bundle.trust.crt` file is not
    single-PEM and trips `cryptography`'s loader). Operators who need
    to scan a custom path can override via `paths.ssl_cert_roots` in
    YAML.

    This test guards against accidental re-inclusion of those paths
    in a future refactor.
    """
    cfg = load_config(None)
    assert cfg.paths.ssl_cert_roots == ["/var/cpanel/ssl"]
    assert "/etc/pki/tls/certs" not in cfg.paths.ssl_cert_roots
    assert "/etc/ssl/certs" not in cfg.paths.ssl_cert_roots
