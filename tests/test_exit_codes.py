"""AISO-119 §7.3 / §8 — cron-friendly exit codes.

The detection contract requires:
  - 0 — INFO-only run (or no findings)
  - 1 — at least one WARN/CRITICAL finding
  - 2 — configuration / I/O error

These tests cover the three documented exit codes so the DevOps
(AISO-122) smoke test can rely on them. The contract also documents
codes 3 (I/O partial) and 4 (internal bug) — those are future work
and not yet exercised by the toolkit.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

from alma_audit.cli import main
from alma_audit.models import Finding, Severity


def test_exit_0_when_only_info_findings(tmp_path, monkeypatch) -> None:
    """All-INFO findings → exit 0 (clean run)."""
    from alma_audit import cli
    from alma_audit import runner as runner_mod

    def fake_run(cfg, fs):
        return [
            Finding(module="x", severity=Severity.INFO, title="ok", description="d"),
            Finding(module="y", severity=Severity.INFO, title="ok2", description="d"),
        ]

    monkeypatch.setattr(runner_mod, "run_analyzers", fake_run)
    monkeypatch.setattr(cli, "run_analyzers", fake_run)

    rc = main(["--output", str(tmp_path / "out")])
    assert rc == 0


def test_exit_1_on_warn_finding(tmp_path, monkeypatch) -> None:
    """WARN finding → exit 1 (cron fail-loud)."""
    from alma_audit import cli
    from alma_audit import runner as runner_mod

    def fake_run(cfg, fs):
        return [Finding(module="x", severity=Severity.WARN, title="w", description="d")]

    monkeypatch.setattr(runner_mod, "run_analyzers", fake_run)
    monkeypatch.setattr(cli, "run_analyzers", fake_run)

    rc = main(["--output", str(tmp_path / "out")])
    assert rc == 1


def test_exit_1_on_critical_finding(tmp_path, monkeypatch) -> None:
    """CRITICAL finding → exit 1."""
    from alma_audit import cli
    from alma_audit import runner as runner_mod

    def fake_run(cfg, fs):
        return [Finding(module="x", severity=Severity.CRITICAL, title="c", description="d")]

    monkeypatch.setattr(runner_mod, "run_analyzers", fake_run)
    monkeypatch.setattr(cli, "run_analyzers", fake_run)

    rc = main(["--output", str(tmp_path / "out")])
    assert rc == 1


def test_exit_2_on_malformed_config(tmp_path) -> None:
    """Malformed YAML config → exit 2 (config error)."""
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("paths:\n  apache_root: [unclosed\n", encoding="utf-8")
    rc = main(["--config", str(cfg), "--output", str(tmp_path / "out")])
    assert rc == 2


def test_exit_2_on_unparseable_yaml_root(tmp_path) -> None:
    """YAML that parses but is not a mapping → exit 2."""
    cfg = tmp_path / "bad2.yaml"
    cfg.write_text("- not a mapping\n", encoding="utf-8")
    rc = main(["--config", str(cfg), "--output", str(tmp_path / "out")])
    assert rc == 2


def test_exit_0_for_list_analyzers() -> None:
    """--list-analyzers is a pure introspection — exit 0 always."""
    rc = main(["--list-analyzers"])
    assert rc == 0


def test_default_exit_code_with_real_filesystem_no_apache(tmp_path) -> None:
    """Default run against a non-existent apache root emits INFO findings
    and exits 0 — this is the cron-friendliness smoke check.
    """
    rc = main([
        "--output", str(tmp_path / "out"),
        "--apache-root", "/nonexistent",
        "--domlog-root", "/nonexistent",
        # AISO-209: point the ssh_hardening analyzer at a
        # non-existent path too, so the run is purely INFO. On a
        # real host the default sshd_config + drop-ins would
        # otherwise fire WARN findings (missing AllowUsers etc.),
        # which is the correct production behaviour but
        # unrelated to what this cron-smoke test checks.
        "--ssh-config", "/nonexistent",
    ])
    assert rc == 0


# ---------------------------------------------------------------------------
# AISO-124 — chmod-000 directory must produce a valid report and a
# deterministic exit code per the documented 0/1/2 contract.
#
# We exercise this with a real on-disk chmod-000 directory and a
# subprocess that drops privileges to `nobody`. The test only runs when
# both `nobody` exists on the system and the test process has the
# privilege to setuid into it; otherwise it skips with an explanatory
# reason — but the analyzer-level tests above still lock the contract.
# ---------------------------------------------------------------------------


def _have_runuser_nobody() -> bool:
    if not shutil.which("runuser"):
        return False
    try:
        import pwd
        pwd.getpwnam("nobody")
        return True
    except KeyError:
        return False


@pytest.mark.skipif(
    not _have_runuser_nobody(),
    reason="`runuser` or `nobody` user not available on this host",
)
def test_cli_exit_1_on_unreadable_apache_root_via_runuser() -> None:
    """End-to-end smoke: a real chmod-000 apache_root, run by the
    `nobody` user via runuser, must NOT crash. The CLI must exit 1
    (WARN finding emitted) and write a valid JSON report.

    Note: tmp_path is owned by the test runner (root, mode 0o700), so
    `nobody` can't traverse into it. We use /tmp directly — world
    writable and traversable by everyone.
    """
    apache_root = "/tmp/alma-audit-test-apache2"
    if os.path.exists(apache_root):
        # Clean up leftover from a previous failed run.
        import shutil as _shutil
        _shutil.rmtree(apache_root, ignore_errors=True)
    os.makedirs(apache_root)
    # chmod 000 — directory is unreadable to non-root users.
    os.chmod(apache_root, 0o000)
    # Output dir must be writable by `nobody`. /tmp is world-writable.
    output_dir = "/tmp/alma-audit-test-out"
    os.makedirs(output_dir, exist_ok=True)
    os.chmod(output_dir, 0o777)
    try:
        project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        venv_python = os.path.join(project_root, ".venv", "bin", "python")
        if not os.path.exists(venv_python):
            venv_python = sys.executable

        result = subprocess.run(
            [
                "runuser", "-u", "nobody", "--",
                venv_python, "-m", "alma_audit.cli",
                "--apache-root", apache_root,
                "--domlog-root", apache_root,
                "--output", output_dir,
            ],
            capture_output=True,
            text=True,
            cwd=project_root,
            env={**os.environ, "PYTHONPATH": os.path.join(project_root, "src")},
        )
        # CRITICAL contract: NO traceback in stderr.
        assert "Traceback (most recent call last):" not in result.stderr, (
            f"CLI crashed with traceback:\nstderr={result.stderr!r}"
        )
        assert "PermissionError" not in result.stderr, (
            f"PermissionError leaked to stderr:\nstderr={result.stderr!r}"
        )
        # Documented exit-code contract: at least one WARN finding
        # → exit 1 (cron fail-loud).
        assert result.returncode == 1, (
            f"Expected exit 1 (WARN finding), got {result.returncode}. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        # Valid JSON + Markdown reports written.
        json_path = os.path.join(output_dir, "alma-audit-latest.json")
        md_path = os.path.join(output_dir, "alma-audit-latest.md")
        assert os.path.exists(json_path), f"JSON report missing at {json_path}"
        assert os.path.exists(md_path), f"Markdown report missing at {md_path}"
        import json as json_mod
        report = json_mod.loads(open(json_path, encoding="utf-8").read())
        # The report must be valid + reference the unreadable path.
        assert report["summary"]["total_findings"] >= 1
        assert report["summary"]["warn"] >= 1
        joined = json_mod.dumps(report["findings"])
        assert apache_root in joined, (
            f"Report findings must reference the unreadable path. "
            f"Findings: {report['findings']}"
        )
    finally:
        # Always restore so leftover chmod-000 dirs don't accumulate.
        os.chmod(apache_root, 0o755)
        import shutil as _shutil
        _shutil.rmtree(apache_root, ignore_errors=True)