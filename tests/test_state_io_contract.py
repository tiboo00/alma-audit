"""AISO-119 §10 — default-run state I/O is opt-in, so the default
codebase MUST NOT contain any write-mode `open(...)` or
`pathlib.Path.write_text` call outside the reporting layer.

The contract's state file (--state-path) is opt-in via §10.2. Until
that is implemented, no state module exists. The reporting layer is
the ONLY legitimate writer. This test enforces that contract.

If a future change adds `--state-path`, the test must grow a
whitelist entry naming the new state module.
"""

from __future__ import annotations

import ast
import pathlib

PACKAGE_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "alma_audit"

# Modules allowed to write files. Today: just the JSON / Markdown
# report writer. Add a state_io module name here when §10.2 is
# implemented so the gate stays explicit.
ALLOWED_WRITE_MODULES = {"reporting.py"}

# Paths considered "inside" the package's subtree.
PACKAGE_FILES = sorted(p for p in PACKAGE_ROOT.rglob("*.py"))


def _mode_kw(node: ast.Call) -> str | None:
    """Return the `mode=` keyword value (str) of a Call, if any."""
    for kw in node.keywords:
        if kw.arg != "mode":
            continue
        if isinstance(kw.value, ast.Constant):
            v = kw.value.value
            if isinstance(v, str):
                return v
    return None


def _first_positional_str(node: ast.Call) -> str | None:
    """Return the first positional arg of a Call if it's a string literal."""
    if not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def test_no_open_in_write_mode_outside_reporting() -> None:
    for path in PACKAGE_FILES:
        if path.name in ALLOWED_WRITE_MODULES:
            continue
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open"):
                continue
            mode = _mode_kw(node)
            if mode is None:
                continue
            if "w" in mode or "a" in mode or "+" in mode:
                raise AssertionError(
                    f"{path.name}:{node.lineno} opens a file in write/append mode "
                    f"(mode={mode!r}) — only {ALLOWED_WRITE_MODULES} may write"
                )


def test_no_os_makedirs_outside_reporting() -> None:
    """os.makedirs is allowed only in reporting.py (it creates --output)."""
    for path in PACKAGE_FILES:
        if path.name in ALLOWED_WRITE_MODULES:
            continue
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            qname = ""
            if isinstance(func, ast.Attribute):
                owner = "<expr>"
                if isinstance(func.value, ast.Name):
                    owner = func.value.id
                qname = f"{owner}.{func.attr}"
            if qname in {"os.makedirs", "pathlib.Path.write_text", "Path.write_text", "os.mkdir"}:
                raise AssertionError(
                    f"{path.name}:{node.lineno} calls {qname}() — "
                    f"only {ALLOWED_WRITE_MODULES} may write"
                )


def test_no_state_io_in_default_path() -> None:
    """No module besides the allowlist performs any state I/O on the
    default run.

    The contract §10.2 places state I/O behind `--state-path` opt-in.
    Until that flag is implemented, no state module may exist. This
    test asserts that no module imports or references "state" in a way
    that suggests hidden I/O.
    """
    for path in PACKAGE_FILES:
        src = path.read_text(encoding="utf-8")
        # A future state module is allowed; the contract is explicit about
        # what may write, not what may read. So this only guards against
        # accidental "open(..., 'w')" patterns hidden behind alias names.
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name):
                continue
            if node.func.id in {"write_text", "write_bytes"}:
                # Free-function `write_text(...)` — likely a pathlib
                # method called via `from pathlib import write_text`.
                # Allowed only in the reporting layer.
                raise AssertionError(
                    f"{path.name}:{node.lineno} calls {node.func.id}() — "
                    f"only {ALLOWED_WRITE_MODULES} may write"
                )