"""Tests for the CLI."""

from __future__ import annotations

import os

from alma_audit.cli import main


def test_list_analyzers_prints_three_names(capsys):
    rc = main(["--list-analyzers"])
    assert rc == 0
    captured = capsys.readouterr().out.strip().splitlines()
    assert "access_log" in captured
    assert "domlog_inventory" in captured
    assert "modsec_log" in captured
    # crawler_verify is a v1.2 helper that the access_log analyzer
    # invokes. It is exposed so operators can grep for it.
    assert "crawler_verify" in captured


def test_cli_creates_output_dir(tmp_path):
    out = tmp_path / "out"
    assert not out.exists()
    rc = main(["--output", str(out), "--apache-root", "/nonexistent", "--domlog-root", "/nonexistent"])
    assert rc == 0  # all INFO findings
    assert out.is_dir()
    assert (out / "alma-audit-latest.json").is_file()
    assert (out / "alma-audit-latest.md").is_file()


def test_cli_exits_1_on_warn_or_critical(tmp_path, monkeypatch):
    """Smoke check that the exit code reflects severity."""
    # Inject a fake filesystem so we can produce a CRITICAL without
    # needing real apache logs.
    from alma_audit import cli
    from alma_audit.runners import FakeFileSystem

    def fake_fs():
        return FakeFileSystem(files={
            "/var/log/apache2/access_log":
                "1.2.3.4 - - [17/Aug/2026:04:12:34 +0000] "
                '"GET /wp-login.php HTTP/1.1" 404 - "-" "ua"\n'
                * 200,  # enough to trigger probe finding
            "/var/log/apache2/domlogs": "fake",
        })

    # The simplest hack: monkeypatch the runner.
    from alma_audit import runner as runner_mod
    from alma_audit.models import Finding, Severity

    def fake_run(cfg, fs):
        return [Finding(module="test", severity=Severity.WARN, title="t", description="d")]

    monkeypatch.setattr(runner_mod, "run_analyzers", fake_run)
    monkeypatch.setattr(cli, "run_analyzers", fake_run)
    rc = main(["--output", str(tmp_path / "out")])
    assert rc == 1
