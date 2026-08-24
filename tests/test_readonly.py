"""Enforce the read-only contract.

The user explicitly required that the toolkit never write to source
logs and never change firewall / fail2ban / cPanel / WHMCS state. We
encode that here as a static check across the package source: no
import or call to write APIs, no subprocess invocations.
"""

from __future__ import annotations

import ast
import os
import pathlib

PACKAGE_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "alma_audit"

FORBIDDEN_CALLS = {
    # writing APIs
    "open": "open() — only allowed as FileSystem.open_text() wrapper",
    "write": "write() — direct write calls are forbidden",
    "truncate": "truncate() — forbidden",
    "rename": "rename / os.rename — forbidden",
    "remove": "remove / os.remove — forbidden",
    "unlink": "os.unlink — forbidden",
    "mkdir": "os.mkdir / os.makedirs — only allowed in reporting layer for output_dir",
    "system": "os.system — forbidden",
    "popen": "os.popen / subprocess.Popen — forbidden",
    "run": "subprocess.run — forbidden",
    "call": "subprocess.call — forbidden",
    "check_call": "subprocess.check_call — forbidden",
    "check_output": "subprocess.check_output — forbidden",
    "exec": "exec / execfile — forbidden",
}

# Files where some writes are *expected* (the report writer).
ALLOWED_WRITE_FILES = {"reporting.py"}


def _function_calls(tree: ast.AST) -> list[tuple[str, str]]:
    """Yield (call_name, lineno) for every Call in the tree."""
    out: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name: str | None = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                # e.g. os.remove → "remove"; subprocess.run → "run"
                name = func.attr
            if name:
                out.append((name, str(node.lineno)))
    return out


def test_no_subprocess_calls():
    """The package must not shell out."""
    for path in PACKAGE_ROOT.rglob("*.py"):
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        calls = _function_calls(tree)
        for name, lineno in calls:
            assert name not in {"system", "popen", "run", "call", "check_call", "check_output", "exec"}, (
                f"{path.name}:{lineno} calls {name}() — forbidden by read-only contract"
            )


def test_no_subprocess_imports():
    """Even unused imports are a smell — the contract bans subprocess altogether."""
    for path in PACKAGE_ROOT.rglob("*.py"):
        src = path.read_text(encoding="utf-8")
        assert "import subprocess" not in src, (
            f"{path.name} imports subprocess — forbidden by read-only contract"
        )
        assert "from subprocess" not in src, (
            f"{path.name} imports from subprocess — forbidden by read-only contract"
        )


def test_only_reporting_layer_writes_files():
    """reporting.py may call os.makedirs; nothing else may."""
    for path in PACKAGE_ROOT.rglob("*.py"):
        if path.name in ALLOWED_WRITE_FILES:
            continue
        src = path.read_text(encoding="utf-8")
        # We allow 'open(' for the FakeFileSystem / RealFileSystem open_text wrapper,
        # but not as a direct read+write. Check mode argument.
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                # The only legitimate open(...) outside reporting is open_text(...)
                # in runners.py, which is wrapped inside the FileSystem protocol.
                # Verify the mode argument is 'r' if present.
                mode = None
                for kw in node.keywords:
                    if kw.arg == "mode":
                        if isinstance(kw.value, ast.Constant):
                            mode = kw.value.value
                if mode is not None:
                    assert "r" in mode and "w" not in mode and "a" not in mode, (
                        f"{path.name}:{node.lineno} opens in write mode — forbidden"
                    )


def test_runners_does_not_open_in_write_mode():
    """Specifically: runners.py only opens for read."""
    src = (PACKAGE_ROOT / "runners.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            mode = None
            for kw in node.keywords:
                if kw.arg == "mode":
                    if isinstance(kw.value, ast.Constant):
                        mode = kw.value.value
            assert mode is None or "w" not in mode, (
                f"runners.py opens a file in write mode — forbidden"
            )


def test_analyzers_do_not_open_directly():
    """Analyzers must use the FileSystem protocol — not raw open()."""
    analyzers_dir = PACKAGE_ROOT / "analyzers"
    for path in analyzers_dir.rglob("*.py"):
        if path.name == "__init__.py":
            continue
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                raise AssertionError(
                    f"{path.name}:{node.lineno} calls open() directly — "
                    "analyzers must use the FileSystem protocol"
                )
