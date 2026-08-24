"""File-listing + read abstraction.

The analyzers never call `open()` directly. They go through this runner
so tests can substitute an in-memory filesystem without monkey-patching
builtins. The runner only exposes read operations; the read-only contract
of the toolkit is enforced here, not by convention.
"""

from __future__ import annotations

import fnmatch
import os
from typing import Protocol


class FileSystem(Protocol):
    def exists(self, path: str) -> bool: ...
    def is_file(self, path: str) -> bool: ...
    def is_dir(self, path: str) -> bool: ...
    def listdir(self, path: str) -> list[str]: ...
    def is_readable_dir(self, path: str) -> bool: ...
    def open_text(self, path: str, max_lines: int | None = None) -> list[str]: ...
    def read_bytes(self, path: str, max_bytes: int | None = None) -> bytes: ...
    def glob(self, root: str, pattern: str) -> list[str]: ...


class RealFileSystem:
    """Production filesystem adapter. Read-only."""

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def is_file(self, path: str) -> bool:
        return os.path.isfile(path)

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(path)

    def listdir(self, path: str) -> list[str]:
        """List the immediate children of `path`.

        Permission / unreadable errors (OSError, including PermissionError)
        are swallowed and return [] — the analyzer layer translates an
        empty listdir into a structured WARN finding naming the path.
        Cron-friendly: a chmod-000 apache_root must NOT crash the audit
        (AISO-124). A missing directory is still a programming error and
        raises FileNotFoundError so callers can distinguish "not there"
        from "not readable".
        """
        try:
            return os.listdir(path)
        except PermissionError:
            # Caller already gated on fs.is_dir() / os.path.isdir(), which
            # uses stat() (works even on mode-000 dirs as long as the path
            # resolves). The dir exists; we just can't enumerate it.
            return []
        except OSError:
            # FileNotFoundError (path missing) and other OSError subclasses
            # — re-raise so the analyzer can still distinguish the
            # "directory disappeared" case from "directory is unreadable".
            raise

    def open_text(self, path: str, max_lines: int | None = None) -> list[str]:
        """Read the file and return its lines as a list.

        `max_lines` caps how many lines we read (defensive against
        runaway logs). Returns [] if the file is empty.

        The list-returning contract is deliberate: analyzers iterate
        twice in some cases (e.g. modsec_log reads into a buffer, then
        re-iterates to parse). A generator would force them to copy.

        Compressed extensions (`.gz`, `.bz2`, `.xz`, `.zst`) are
        skipped silently — opening them in text mode would error and
        the contract is read-only, so we can't shell out to `gunzip`.
        """
        # Skip compressed rotations — readable text-mode requires an
        # out-of-process decompressor (forbidden by the read-only
        # contract). The caller treats this as "0 lines from this file"
        # and continues with the next rotated log.
        lower = path.lower()
        for ext in (".gz", ".bz2", ".xz", ".zst", ".lz4"):
            if lower.endswith(ext):
                return []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                if max_lines is None:
                    return fh.read().splitlines()
                # Take exactly max_lines, ignoring any trailing newline
                # mangling from the file. We deliberately use a count
                # loop rather than islice so a runaway log cannot blow
                # up memory.
                lines: list[str] = []
                for _ in range(max_lines):
                    try:
                        lines.append(next(fh))
                    except StopIteration:
                        break
                return lines
        except FileNotFoundError:
            raise
        except OSError:
            # Permission denied, IsADirectory, bad encoding, etc.
            # — treat as "no lines" so the analyzer doesn't blow up.
            return []

    def read_bytes(self, path: str, max_bytes: int | None = None) -> bytes:
        """Read the file as bytes. Returns b'' if unreadable.

        Used by the ssl_cert analyzer to load PEM certificates
        without forcing the whole file through the text decoder.
        `max_bytes` caps the read (defensive against multi-megabyte
        blob files masquerading as certs); a runaway file cannot
        allocate more than the cap.

        Per the read-only contract this method opens files in binary
        read mode only — `test_readonly.py` enforces that.
        """
        try:
            with open(path, "rb") as fh:
                if max_bytes is None:
                    return fh.read()
                return fh.read(max_bytes)
        except FileNotFoundError:
            raise
        except OSError:
            return b""

    def glob(self, root: str, pattern: str) -> list[str]:
        if not self.exists(root):
            return []
        try:
            entries = os.listdir(root)
        except PermissionError:
            return []
        matches = [name for name in entries if fnmatch.fnmatchcase(name, pattern)]
        return sorted(os.path.join(root, name) for name in matches)

    def is_readable_dir(self, path: str) -> bool:
        """True iff `path` is a directory the current process can list.

        Used by analyzers to distinguish "directory is empty" from
        "directory exists but is unreadable" (AISO-125). Cheap probe:
        one ``os.listdir`` call, no recursion.
        """
        if not os.path.isdir(path):
            return False
        try:
            os.listdir(path)
        except OSError:
            return False
        return True


class FakeFileSystem:
    """In-memory filesystem for tests.

    Files are stored as `path -> list[str]` (one entry per line) for
    text content, or `path -> bytes` for binary content. `add_file`
    accepts strings (text mode); `add_bytes` accepts bytes (binary
    mode). Adding a file also implicitly creates its parent directory.
    """

    def __init__(self, files: dict[str, str] | None = None) -> None:
        self._files: dict[str, list[str]] = {}
        self._bytes: dict[str, bytes] = {}
        if files:
            for path, content in files.items():
                self.add_file(path, content)

    def add_file(self, path: str, content: str) -> None:
        key = self._norm(path)
        self._files[key] = content.splitlines() if content else []

    def add_bytes(self, path: str, content: bytes) -> None:
        """Register a binary file (e.g. PEM cert blob).

        The fake stores it in `_bytes`; `read_bytes` reads it back,
        `open_text` falls back to UTF-8-decoding the bytes for tests
        that want to exercise both paths from the same fixture.
        """
        key = self._norm(path)
        self._bytes[key] = content

    def _norm(self, path: str) -> str:
        return path.rstrip("/")

    def _is_under(self, child: str, parent: str) -> bool:
        c = self._norm(child)
        p = self._norm(parent)
        return c == p or c.startswith(p + "/")

    def exists(self, path: str) -> bool:
        path = self._norm(path)
        if path in self._files or path in self._bytes:
            return True
        # implicit directory: any registered file under this prefix
        return any(self._is_under(p, path) for p in self._files) or any(
            self._is_under(p, path) for p in self._bytes
        )

    def is_file(self, path: str) -> bool:
        path = self._norm(path)
        return path in self._files or path in self._bytes

    def is_dir(self, path: str) -> bool:
        path = self._norm(path)
        if path in self._files or path in self._bytes:
            return False
        return any(self._is_under(p, path) for p in self._files) or any(
            self._is_under(p, path) for p in self._bytes
        )

    def listdir(self, path: str) -> list[str]:
        path = self._norm(path)
        if not self.is_dir(path):
            return []
        prefix = path + "/"
        names: set[str] = set()
        for source in (self._files, self._bytes):
            for p in source:
                if p.startswith(prefix):
                    rest = p[len(prefix):]
                    if "/" in rest:
                        names.add(rest.split("/", 1)[0])
                    else:
                        names.add(rest)
        return sorted(names)

    def is_readable_dir(self, path: str) -> bool:
        """Test fake — a registered directory is always readable.

        Tests that need to simulate unreadable dirs override this on
        the instance (``monkeypatch.setattr(fs, "is_readable_dir",
        lambda p: False)``) rather than registering files.
        """
        return self.is_dir(path)

    def open_text(self, path: str, max_lines: int | None = None) -> list[str]:
        """Return the list of lines (already in memory).

        `max_lines` is accepted for API parity with RealFileSystem but
        is irrelevant here — the entire file is in memory already.

        If the file was registered with `add_bytes` (binary mode),
        we decode it as UTF-8 for tests that want to exercise both
        paths from a single fixture.
        """
        key = self._norm(path)
        if key in self._bytes:
            text = self._bytes[key].decode("utf-8", errors="replace")
            lines = text.splitlines()
        else:
            lines = self._files.get(key)
        if lines is None:
            raise FileNotFoundError(path)
        if max_lines is None:
            return list(lines)
        return list(lines)[:max_lines]

    def read_bytes(self, path: str, max_bytes: int | None = None) -> bytes:
        """Return the raw bytes of the file.

        If the file was registered with `add_file` (text mode), we
        encode the stored lines as UTF-8 so tests can mix-and-match.
        """
        key = self._norm(path)
        if key in self._bytes:
            data = self._bytes[key]
        elif key in self._files:
            data = ("\n".join(self._files[key])).encode("utf-8")
        else:
            raise FileNotFoundError(path)
        if max_bytes is None:
            return data
        return data[:max_bytes]

    def glob(self, root: str, pattern: str) -> list[str]:
        try:
            entries = self.listdir(root)
        except (KeyError, FileNotFoundError):
            return []
        names = [name for name in entries if fnmatch.fnmatchcase(name, pattern)]
        return sorted(os.path.join(root, name) for name in names)
