"""AISO-119 v1.2 §4.5.1 / §8 acceptance: AST-level guard for the D7
input-normalisation path.

The v1.2 contract closes the case-folding contradiction by removing
§4.5.1 step 5 (the partial ASCII-lowercase fold of the case-1 prefix).
To prevent a future change from re-introducing case folding, the
`domlog_inventory` module's D7 path MUST NOT contain:

  - `.lower()` calls
  - `.casefold()` calls
  - `str.translate(...)` tables that fold A-Z → a-z

This test scans the AST of `domlog_inventory.py` for these patterns
and fails if any are present in code that runs before the regex match.
"""

from __future__ import annotations

import ast
import pathlib

# The single file that owns the D7 normalisation pipeline.
DOMLOG_INVENTORY = (
    pathlib.Path(__file__).resolve().parents[1]
    / "src" / "alma_audit" / "analyzers" / "domlog_inventory.py"
)


def _collect_call_names(tree: ast.AST) -> list[tuple[str, int]]:
    """Yield (qualified_call_name, lineno) for every Call in the tree.

    Qualified name is e.g. `str.lower`, `name.lower`, `str.translate`.
    """
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            out.append((f"<local>.{func.id}", node.lineno))
        elif isinstance(func, ast.Attribute):
            # Build "<owner>.<attr>" for chainable detection.
            owner = "<expr>"
            if isinstance(func.value, ast.Name):
                owner = func.value.id
            elif isinstance(func.value, ast.Call):
                owner = "<call>"
            out.append((f"{owner}.{func.attr}", node.lineno))
    return out


def test_d7_path_has_no_lower_call() -> None:
    """`.lower()` MUST NOT appear anywhere in the D7 normalisation path."""
    src = DOMLOG_INVENTORY.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for qname, lineno in _collect_call_names(tree):
        assert not qname.endswith(".lower"), (
            f"{DOMLOG_INVENTORY.name}:{lineno} calls .lower() — "
            "the D7 §4.5.1 pipeline must NOT case-fold (AISO-119 v1.2)"
        )


def test_d7_path_has_no_casefold_call() -> None:
    """`.casefold()` MUST NOT appear anywhere in the D7 normalisation path."""
    src = DOMLOG_INVENTORY.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for qname, lineno in _collect_call_names(tree):
        assert not qname.endswith(".casefold"), (
            f"{DOMLOG_INVENTORY.name}:{lineno} calls .casefold() — "
            "the D7 §4.5.1 pipeline must NOT case-fold (AISO-119 v1.2)"
        )


def test_d7_path_has_no_az_folding_translate() -> None:
    """`str.translate(...)` tables must NOT fold A-Z → a-z.

    The control-character table in `_normalise_for_d7` step 4 is allowed
    (it replaces whitespace/control chars with `?`). But it MUST NOT
    contain any key/value pair that maps an uppercase letter to its
    lowercase counterpart — that would reintroduce case folding.
    """
    src = DOMLOG_INVENTORY.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "translate"):
            continue
        # Only `str.translate(...)` is suspect. Attribute calls on
        # strings (`s.translate(...)`) are also caught by the audit.
        # The translation table is the first positional argument.
        if not node.args:
            continue
        table_arg = node.args[0]
        if not isinstance(table_arg, ast.Call):
            continue
        # `str.maketrans({...})` — look for a dict literal with A→a pairs.
        if not (
            isinstance(table_arg.func, ast.Attribute)
            and table_arg.func.attr == "maketrans"
        ):
            continue
        if not table_arg.args:
            continue
        first = table_arg.args[0]
        if not isinstance(first, ast.Dict):
            continue
        for k_node, v_node in zip(first.keys, first.values):
            if not (isinstance(k_node, ast.Constant) and isinstance(v_node, ast.Constant)):
                continue
            k = k_node.value
            v = v_node.value
            if (
                isinstance(k, str) and len(k) == 1 and k.isupper()
                and isinstance(v, str) and len(v) == 1 and v.islower()
                and k.lower() == v
            ):
                raise AssertionError(
                    f"{DOMLOG_INVENTORY.name}:{table_arg.lineno} "
                    f"str.maketrans contains A-Z → a-z folding ({k!r} → {v!r}) — "
                    "the D7 §4.5.1 pipeline must NOT case-fold (AISO-119 v1.2)"
                )