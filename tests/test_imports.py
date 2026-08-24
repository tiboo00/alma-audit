"""Smoke test: the package imports cleanly and the version is set."""

from alma_audit import __version__


def test_version_is_string():
    assert isinstance(__version__, str)
    assert __version__  # non-empty
