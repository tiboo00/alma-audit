"""AISO-125 — chmod-000 directory end-to-end regression.

The runner-layer (AISO-124) tests cover the unit boundary:
``RealFileSystem.listdir`` swallows ``PermissionError`` and the
analyzer emits a structured ``WARN`` finding. This module locks the
end-to-end behavior:

  * The CLI exits 1 (cron fail-loud) when a configured log root is
    unreadable by the audit user, not 0 (silently passing).
  * The JSON + Markdown reports are still written.
  * The report contains the WARN finding naming the unreadable root.
  * A real chmod-000 directory on disk, accessed as a non-root user
    via ``runuser -u nobody``, does not raise — this is the test the
    Stage 2 AlmaLinux smoke ran and failed.

The chmod-000 subprocess smoke test is skipped automatically when
``runuser`` is unavailable (e.g. on macOS dev hosts); the rest of
the module always runs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

from alma_audit.cli import main


# ---------------------------------------------------------------------------
# CLI exit-code contract: unreadable root → exit 1, not 0.
# ---------------------------------------------------------------------------

def test_unreadable_root_exits_1_not_0(monkeypatch, tmp_path) -> None:
    """When the apache_root / domlog_root is unreadable, the CLI must
    exit 1 so cron catches it.

    We simulate "unreadable" by patching ``os.listdir`` to raise
    ``PermissionError`` — same effect as chmod 000 + non-root.
    """
    from alma_audit import cli as cli_mod
    from alma_audit.config import Config
    import alma_audit.runners as runners_mod

    apache_root = tmp_path / "apache2"
    apache_root.mkdir()

    def _deny(_path: str) -> list[str]:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(runners_mod.os, "listdir", _deny)

    cfg = Config()
    cfg.paths.apache_root = str(apache_root)
    cfg.paths.domlog_root = str(apache_root)
    # cli.py imports `load_config` at module top; patch the binding in
    # the cli module's namespace so ``main`` sees the override.
    monkeypatch.setattr(cli_mod, "load_config", lambda _p: cfg)

    rc = main(["--output", str(tmp_path / "out")])
    assert rc == 1, (
        f"Expected cron fail-loud exit 1 for unreadable log root; got {rc}"
    )


def test_unreadable_root_still_writes_json_and_markdown(
    monkeypatch, tmp_path,
) -> None:
    """The report files must still be written so the operator has
    something to look at after the cron alert."""
    from alma_audit import cli as cli_mod
    from alma_audit.config import Config
    import alma_audit.runners as runners_mod

    apache_root = tmp_path / "apache2"
    apache_root.mkdir()

    def _deny(_path: str) -> list[str]:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(runners_mod.os, "listdir", _deny)

    cfg = Config()
    cfg.paths.apache_root = str(apache_root)
    cfg.paths.domlog_root = str(apache_root)
    monkeypatch.setattr(cli_mod, "load_config", lambda _p: cfg)

    out = tmp_path / "out"
    rc = main(["--output", str(out)])
    assert rc == 1
    assert (out / "alma-audit-latest.json").is_file()
    assert (out / "alma-audit-latest.md").is_file()


def test_unreadable_root_json_contains_warn_finding(
    monkeypatch, tmp_path,
) -> None:
    """The JSON report must include the WARN finding naming the
    unreadable root so downstream alerting can match on it."""
    from alma_audit import cli as cli_mod
    from alma_audit.config import Config
    import alma_audit.runners as runners_mod

    apache_root = tmp_path / "apache2"
    apache_root.mkdir()

    def _deny(_path: str) -> list[str]:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(runners_mod.os, "listdir", _deny)

    cfg = Config()
    cfg.paths.apache_root = str(apache_root)
    cfg.paths.domlog_root = str(apache_root)
    monkeypatch.setattr(cli_mod, "load_config", lambda _p: cfg)

    out = tmp_path / "out"
    rc = main(["--output", str(out)])
    assert rc == 1
    payload = json.loads((out / "alma-audit-latest.json").read_text())
    warn = [
        f for f in payload["findings"]
        if f["severity"] == "WARN"
        and (
            "unreadable" in f["title"].lower()
            or "permission" in f["title"].lower()
        )
    ]
    assert warn, (
        f"JSON must carry a WARN for unreadable root. "
        f"Got: {[(f['severity'], f['title']) for f in payload['findings']]}"
    )
    # The path must appear in details or description so the operator
    # can fix it (chmod, audit user group, etc.).
    found = warn[0]
    blob = (found.get("description", "") + " " + json.dumps(found.get("details", {})))
    assert str(apache_root) in blob


# ---------------------------------------------------------------------------
# chmod-000 subprocess smoke (AlmaLinux Stage 2 reproduction).
# ---------------------------------------------------------------------------

def _has_runuser() -> bool:
    return shutil.which("runuser") is not None


def _has_nobody_user() -> bool:
    try:
        subprocess.run(
            ["id", "nobody"],
            check=True,
            capture_output=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


@pytest.mark.skipif(
    not (_has_runuser() and _has_nobody_user()),
    reason="requires runuser + nobody user (Linux only)",
)
def test_chmod_000_domlog_root_as_nobody_does_not_traceback(tmp_path) -> None:
    """Stage 2 smoke (AlmaLinux 8 + Python 3.11): chmod 000 the
    domlog_root, run as ``nobody``, audit must NOT traceback.

    Pre-fix this raises:

        PermissionError: [Errno 13] Permission denied:
            '/tmp/.../domlogs_blocked'

    Post-fix the audit exits 1 with a structured WARN finding.
    """
    # Use a self-owned workspace under /tmp so ``nobody`` can write
    # the report. pytest's tmp_path is owned by root with mode 700,
    # so ``nobody`` cannot create files anywhere underneath. We use
    # an explicit ``/tmp/alma-smoke-XXX`` path so we don't land under
    # pytest's private tmp dir (also mode 700, root-owned).
    workspace = tempfile.mkdtemp(prefix="alma-smoke-", dir="/tmp")
    # mkdtemp gives us root-owned 0o700. ``nobody`` needs to traverse
    # this dir AND create ``out`` inside, so make it world-writable.
    os.chmod(workspace, 0o1777)
    try:
        apache_root = os.path.join(workspace, "apache2")
        os.makedirs(apache_root)
        with open(os.path.join(apache_root, "access_log"), "w") as f:
            f.write(
                '127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] '
                '"GET / HTTP/1.1" 200 1234 "-" "curl/7.68.0"\n'
            )
        domlogs = os.path.join(apache_root, "domlogs")
        os.makedirs(domlogs)
        with open(os.path.join(domlogs, "hostdzire.com"), "w") as f:
            f.write("")  # would be picked up if readable
        # apache_root needs to be traversable by ``nobody`` (the audit
        # user) so it can stat() the domlogs child.
        os.chmod(apache_root, 0o755)
        os.chmod(domlogs, 0)

        out = os.path.join(workspace, "out")

        # Run the audit as nobody. We pass `cwd=` so the subprocess
        # inherits the project root (needed so `python -m alma_audit.cli`
        # can find the package on sys.path). The venv is activated in
        # the parent; subprocess inherits sys.executable.
        proc = subprocess.run(
            [
                "runuser", "-u", "nobody", "--",
                sys.executable, "-m", "alma_audit.cli",
                "--apache-root", apache_root,
                "--domlog-root", domlogs,
                "--output", out,
            ],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            timeout=30,
        )

        # No traceback — stderr must NOT contain a Python traceback header.
        assert "Traceback (most recent call last)" not in proc.stderr, (
            f"Audit crashed with traceback:\n{proc.stderr}"
        )
        # The PermissionError string must not leak either.
        assert "PermissionError" not in proc.stderr, proc.stderr

        # Exit 1 — cron fail-loud.
        assert proc.returncode == 1, (
            f"Expected exit 1, got {proc.returncode}\n"
            f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
        )

        # Reports must be written and contain the WARN finding.
        json_path = os.path.join(out, "alma-audit-latest.json")
        assert os.path.isfile(json_path), (
            f"Expected JSON report at {json_path}; "
            f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
        )
        assert os.path.isfile(os.path.join(out, "alma-audit-latest.md"))
        payload = json.loads(open(json_path).read())
        warn = [
            f for f in payload["findings"]
            if f["severity"] == "WARN"
            and (
                "unreadable" in f["title"].lower()
                or "permission" in f["title"].lower()
            )
        ]
        assert warn, (
            f"Expected WARN for unreadable domlog_root in JSON. "
            f"Findings: {[(f['severity'], f['title']) for f in payload['findings']]}"
        )
    finally:
        # Restore perms so cleanup can remove the workspace.
        try:
            os.chmod(domlogs, 0o700)
        except FileNotFoundError:
            pass
        shutil.rmtree(workspace, ignore_errors=True)