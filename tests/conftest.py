"""Shared pytest fixtures for alma-audit."""

from __future__ import annotations

import pytest

from alma_audit.runners import FakeFileSystem


@pytest.fixture
def make_fs():
    """Factory: build a FakeFileSystem from a dict of path -> content."""

    def _make(files: dict[str, str] | None = None) -> FakeFileSystem:
        return FakeFileSystem(files=files)

    return _make
