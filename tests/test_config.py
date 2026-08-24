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
