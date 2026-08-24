"""Tests for the FakeFileSystem and RealFileSystem runners."""

from __future__ import annotations

import pytest

from alma_audit.runners import FakeFileSystem, RealFileSystem


def test_file_and_dir_detection():
    fs = FakeFileSystem()
    fs.add_file("/a/b/file.txt", "hello\nworld")
    assert fs.exists("/a/b/file.txt")
    assert fs.is_file("/a/b/file.txt")
    assert not fs.is_dir("/a/b/file.txt")
    assert fs.is_dir("/a")
    assert fs.is_dir("/a/b")
    assert not fs.exists("/missing")


def test_listdir_returns_immediate_children():
    fs = FakeFileSystem()
    fs.add_file("/a/x.txt", "x")
    fs.add_file("/a/y.txt", "y")
    fs.add_file("/a/b/z.txt", "z")
    assert sorted(fs.listdir("/a")) == ["b", "x.txt", "y.txt"]
    assert fs.listdir("/a/b") == ["z.txt"]


def test_open_text_returns_lines():
    fs = FakeFileSystem()
    fs.add_file("/a/b.txt", "line1\nline2\nline3")
    out = fs.open_text("/a/b.txt")
    assert out == ["line1", "line2", "line3"]
    # Re-readable (returned as list, not iterator)
    assert fs.open_text("/a/b.txt") == ["line1", "line2", "line3"]


def test_open_text_raises_for_missing():
    fs = FakeFileSystem()
    with pytest.raises(FileNotFoundError):
        fs.open_text("/nope")


def test_glob_matches_basename_pattern():
    fs = FakeFileSystem()
    fs.add_file("/a/hostdzire.com-ssl_log", "")
    fs.add_file("/a/hostdzire.com", "")
    fs.add_file("/a/hostdzire.com-bytes_log", "")
    fs.add_file("/a/other.txt", "")
    matches = fs.glob("/a", "hostdzire.com*")
    assert len(matches) == 3
    assert all(m.startswith("/a/hostdzire.com") for m in matches)


def test_glob_returns_empty_for_missing_root():
    fs = FakeFileSystem()
    assert fs.glob("/missing", "anything") == []


def test_trailing_slashes_are_normalized():
    fs = FakeFileSystem()
    fs.add_file("/a/b.txt", "")
    assert fs.exists("/a/b.txt")
    assert fs.exists("/a/b.txt/")
    assert fs.is_file("/a/b.txt/")


# ---------------------------------------------------------------------------
# AISO-124 — RealFileSystem.listdir permission-error resilience.
#
# Cron runs the audit as a non-root service account. If apache_root /
# domlog_root happens to be mode 000 (e.g. a cPanel account whose logs
# were rotated with restrictive perms), the audit MUST NOT crash with a
# traceback — it must surface a structured WARN finding and continue.
#
# These tests are deterministic: they monkey-patch os.listdir (the only
# thing RealFileSystem.listdir actually does) so they don't rely on the
# pytest process running as non-root. A separate subprocess-based smoke
# test (test_log_handling_smoke_chmod_000_does_not_traceback, in
# tests/test_log_handling.py) covers the chmod-000-on-disk case via
# runuser -u nobody.
# ---------------------------------------------------------------------------

def test_real_listdir_returns_empty_on_oserror(monkeypatch) -> None:
    """OSError from os.listdir must be swallowed by RealFileSystem.listdir.

    A cron run as a non-root audit user hitting an `apache_root` of mode
    000 used to propagate PermissionError out of os.listdir and crash
    the entire audit. The contract is: listdir returns [] and never
    raises for any OSError — the caller surfaces a WARN finding.
    """
    import alma_audit.runners as runners_mod

    def _boom(_path: str) -> list[str]:
        raise PermissionError(13, "Permission denied: /var/log/apache2")

    monkeypatch.setattr(runners_mod.os, "listdir", _boom)
    fs = RealFileSystem()
    assert fs.listdir("/var/log/apache2") == []


def test_real_listdir_swallows_permissionerror_for_apache_root(
    monkeypatch, tmp_path,
) -> None:
    """Regression for the documented AISO-118 Stage 2 bug: a chmod-000
    `apache_root` must not propagate PermissionError from listdir.

    The runner contract (AISO-121) says the analyzer layer will translate
    an empty listdir into a structured WARN finding; the runner itself
    only needs to NOT raise.
    """
    apache_root = tmp_path / "apache2"
    apache_root.mkdir()
    # The actual chmod-000 won't deny root on the test runner, so the
    # monkey-patch of os.listdir simulates the non-root audit-user view.
    import alma_audit.runners as runners_mod

    def _deny(_path: str) -> list[str]:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(runners_mod.os, "listdir", _deny)
    fs = RealFileSystem()
    # is_dir should still work (it uses os.path.isdir → stat, not listdir)
    assert fs.is_dir(str(apache_root)) is True
    # listdir must NOT raise
    result = fs.listdir(str(apache_root))
    assert result == []


def test_real_glob_still_returns_empty_on_permissionerror(
    monkeypatch, tmp_path,
) -> None:
    """Regression lock for the existing glob() behavior: the glob path
    already swallows PermissionError. We re-test here to ensure the
    listdir fix doesn't regress glob's resilience.
    """
    apache_root = tmp_path / "apache2"
    apache_root.mkdir()
    import alma_audit.runners as runners_mod

    def _deny(_path: str) -> list[str]:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(runners_mod.os, "listdir", _deny)
    fs = RealFileSystem()
    assert fs.glob(str(apache_root), "access_log*") == []


def test_real_listdir_raises_filenotfound_for_missing_dir(tmp_path) -> None:
    """Documented exception path: listdir on a non-existent directory
    raises FileNotFoundError. This is NOT a regression target — the
    contract only swallows OSError subclasses for permission problems;
    a missing directory is still a programming error.
    """
    fs = RealFileSystem()
    with pytest.raises(FileNotFoundError):
        fs.listdir(str(tmp_path / "nope"))
