"""AISO-121 — regression tests for v1.2 contract deltas.

This file complements `test_report_contract.py`,
`test_readonly.py`, `test_exit_codes.py`, and
`test_state_io_contract.py` with assertions that lock the v1.2
shape specifically:

  - `Finding.to_dict()` carries `crawler_suppression` only when the
    finding is D1/D4-shaped; D2/D5 carry the `n/a` sentinel; INFO
    summary findings carry NO field. The shape must be stable across
    runs so the DevOps (AISO-122) JSON-schema validator can rely on it.

  - The CLI exit-code mapping (0/1/2) covers each branch even with
    the new injectable resolver so the cron-friendly contract
    survives the crawler wiring.

  - The static AST guard is extended to verify the new crawler_verify
    and access_log modules never use write-mode APIs and never
    shell out — preserving the read-only contract through the
    integration.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

from alma_audit.analyzers.access_log import analyze_access_logs
from alma_audit.analyzers.crawler_verify import CrawlerSuppression
from alma_audit.cli import main
from alma_audit.models import Finding, Severity


PACKAGE_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "alma_audit"


# ---------------------------------------------------------------------------
# Finding.to_dict() regression — D1/D4 vs D2/D5 vs INFO shape stability.
# ---------------------------------------------------------------------------


def test_finding_to_dict_shape_with_suppression_detail(make_fs) -> None:
    """A logged D1 finding with crawler suppression has a stable shape:
    the `crawler_suppression` dict always has exactly the 5 keys, in
    this order.
    """
    googlebot_ip = "66.249.66.1"
    host = "crawl-66-249-66-1.googlebot.com"
    lines = []
    for i in range(9):
        lines.append(
            f'{googlebot_ip} - - [17/Aug/2026:04:12:{i:02d} +0000] '
            f'"GET /page{i} HTTP/1.1" 200 100 "-" '
            f'"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"'
        )
    lines.append(
        '10.0.0.1 - - [17/Aug/2026:04:13:00 +0000] '
        '"GET /x HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
    )
    fs = make_fs({"/var/log/apache2/access_log": "\n".join(lines)})

    class R:
        def ptr(self, ip):  # noqa: ARG002
            return host

        def forward(self, hostname):  # noqa: ARG002
            return [googlebot_ip]

    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs, resolver=R(),
    )
    suppressed = next(
        f for f in findings if "suppressed" in f.title.lower()
    )

    d = suppressed.to_dict()
    assert list(d.keys()) == ["module", "severity", "title", "description", "details", "recommendation"]
    assert "crawler_suppression" in d["details"]
    cs = d["details"]["crawler_suppression"]
    # Exactly 5 keys, in declared order:
    assert list(cs.keys()) == ["applied", "reason", "claimed", "hostname", "suffix"]
    assert cs["applied"] is True
    assert cs["reason"] == "n/a"
    assert cs["claimed"] == "googlebot"
    assert cs["hostname"] == host
    # Two `to_dict()` calls produce identical JSON.
    again = suppressed.to_dict()
    assert json.dumps(d, sort_keys=True) == json.dumps(again, sort_keys=True)


def test_finding_to_dict_for_probe_path_carries_na_sentinel(make_fs) -> None:
    """D2 (probe path) carries the `n/a` sentinel — never `applied=True`."""
    googlebot_ip = "66.249.66.1"
    host = "crawl-66-249-66-1.googlebot.com"
    lines = []
    for i in range(25):
        lines.append(
            f'{googlebot_ip} - - [17/Aug/2026:04:12:{i:02d} +0000] '
            '"GET /.env HTTP/1.1" 404 - "-" '
            '"Mozilla/5.0 (compatible; Googlebot/2.1)"'
        )
    fs = make_fs({"/var/log/apache2/access_log": "\n".join(lines)})

    class R:
        def ptr(self, ip):  # noqa: ARG002
            return host

        def forward(self, hostname):  # noqa: ARG002
            return [googlebot_ip]

    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs, resolver=R(),
    )
    probe = next(f for f in findings if "probe" in f.title.lower())
    cs = probe.to_dict()["details"]["crawler_suppression"]
    assert cs["applied"] is False
    assert cs["reason"] == "n/a"
    # No `claimed` / `hostname` / `suffix` for `n/a` findings.
    assert cs["claimed"] is None
    assert cs["hostname"] is None
    assert cs["suffix"] is None


def test_info_summary_finding_has_no_suppression_field(make_fs) -> None:
    """The scan-summary INFO finding does NOT carry a
    `crawler_suppression` field — it's not a D1/D4 decision.
    """
    fs = make_fs({"/var/log/apache2/access_log": ""})
    findings = analyze_access_logs(
        ["/var/log/apache2/access_log"], fs,
    )
    scan = next(f for f in findings if "scanned" in f.title.lower())
    assert "crawler_suppression" not in scan.details


def test_crawler_suppression_to_dict_keys_are_stable() -> None:
    """The dataclass shape itself must not change without a v1.3 bump."""
    cases = [
        CrawlerSuppression(False, "no_claim", None, None, None),
        CrawlerSuppression(False, "ptr_error", "googlebot", None, None),
        CrawlerSuppression(False, "forward_mismatch", "googlebot", "crawl.example.com", None),
        CrawlerSuppression(False, "suffix_mismatch", "googlebot", "crawl.example.com", None),
        CrawlerSuppression(True, "n/a", "googlebot", "crawl.googlebot.com", "googlebot.com"),
        CrawlerSuppression.not_applicable(),
    ]
    for cs in cases:
        d = cs.to_dict()
        assert list(d.keys()) == ["applied", "reason", "claimed", "hostname", "suffix"]
        # JSON-serialisable.
        json.dumps(d)


# ---------------------------------------------------------------------------
# CLI exit codes — full coverage of 0/1/2 with the v1.2 analyzer.
# ---------------------------------------------------------------------------


def test_cli_exit_0_when_only_info_findings_v12(tmp_path, monkeypatch) -> None:
    """All-INFO findings (including suppressed-crawler INFO findings) → exit 0."""
    from alma_audit import cli
    from alma_audit import runner as runner_mod

    def fake_run(cfg, fs):  # noqa: ARG001 — test stub
        return [
            Finding(
                module="access_log",
                severity=Severity.INFO,
                title="Top-host concentration suppressed: 66.249.66.1 (90%) — verified crawler",
                description="Suppressed",
                details={
                    "host": "66.249.66.1",
                    "crawler_suppression": {"applied": True, "reason": "n/a"},
                },
            ),
        ]

    monkeypatch.setattr(runner_mod, "run_analyzers", fake_run)
    monkeypatch.setattr(cli, "run_analyzers", fake_run)
    rc = main(["--output", str(tmp_path / "out")])
    assert rc == 0


def test_cli_exit_1_on_probe_finding_v12(tmp_path, monkeypatch) -> None:
    """Even with crawler verification wired in, a D2 probe finding
    is NEVER suppressed — cron must fail-loud.
    """
    from alma_audit import cli
    from alma_audit import runner as runner_mod

    def fake_run(cfg, fs):  # noqa: ARG001 — test stub
        return [
            Finding(
                module="access_log",
                severity=Severity.WARN,
                title="50 request(s) to known probe paths",
                description="D2",
                details={
                    "probe_hits": {"/.env": 50},
                    "crawler_suppression": {"applied": False, "reason": "n/a"},
                },
            ),
        ]

    monkeypatch.setattr(runner_mod, "run_analyzers", fake_run)
    monkeypatch.setattr(cli, "run_analyzers", fake_run)
    rc = main(["--output", str(tmp_path / "out")])
    assert rc == 1


def test_cli_exit_2_on_yaml_error_v12(tmp_path) -> None:
    """Malformed YAML config → exit 2 (regression: not affected by v1.2)."""
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("paths:\n  apache_root: [unclosed\n", encoding="utf-8")
    rc = main(["--config", str(cfg), "--output", str(tmp_path / "out")])
    assert rc == 2


# ---------------------------------------------------------------------------
# AST guard — the v1.2 modules must not introduce write APIs.
# ---------------------------------------------------------------------------


def _ast_calls(src: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            out.append((func.id, node.lineno))
        elif isinstance(func, ast.Attribute):
            owner = "<expr>"
            if isinstance(func.value, ast.Name):
                owner = func.value.id
            out.append((f"{owner}.{func.attr}", node.lineno))
    return out


@pytest.mark.parametrize(
    "module_name,kind",
    [
        # `access_log` is now a package (`analyzers/access_log/`) per
        # docs/GAPS.md §7 (file-size discipline). The split into
        # parser/aggregator/settings/suppression/rules/analyzer means
        # every .py under that directory is part of the v1.2 surface and
        # must obey the read-only contract. `crawler_verify.py` stays a
        # single flat file.
        ("access_log", "package"),
        ("crawler_verify.py", "file"),
    ],
)
def test_v12_modules_have_no_subprocess_calls(module_name: str, kind: str) -> None:
    """The two modules added/changed for v1.2 must not shell out."""
    for src, label in _iter_v12_sources(module_name, kind):
        forbidden = {"system", "popen", "run", "call", "check_call", "check_output", "exec"}
        for name, lineno in _ast_calls(src):
            bare = name.rsplit(".", 1)[-1]
            assert bare not in forbidden, (
                f"{label}:{lineno} calls {bare}() — "
                "forbidden by read-only contract (v1.2)"
            )


@pytest.mark.parametrize(
    "module_name,kind",
    [
        ("access_log", "package"),
        ("crawler_verify.py", "file"),
    ],
)
def test_v12_modules_do_not_open_in_write_mode(module_name: str, kind: str) -> None:
    """No `open(..., 'w')` etc. anywhere in the v1.2 modules."""
    for src, label in _iter_v12_sources(module_name, kind):
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "open"):
                continue
            for kw in node.keywords:
                if kw.arg != "mode":
                    continue
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    mode = kw.value.value
                    assert "w" not in mode and "a" not in mode and "+" not in mode, (
                        f"{label}:{node.lineno} opens in write mode"
                    )


def _iter_v12_sources(name: str, kind: str):
    """Yield (source_text, label) for each v1.2 module under test.

    `kind == "file"` reads a single flat .py. `kind == "package"`
    walks every .py inside the directory (skipping __init__.py, which
    is re-exports only and carries no logic to audit) and labels each
    one `analyzers/<dir>/<file>.py:<lineno>` so failures stay traceable.
    """
    base = PACKAGE_ROOT / "analyzers"
    if kind == "file":
        path = base / name
        yield path.read_text(encoding="utf-8"), f"analyzers/{name}"
        return
    pkg = base / name
    assert pkg.is_dir(), f"expected package directory: {pkg}"
    for sub in sorted(pkg.glob("*.py")):
        if sub.name == "__init__.py":
            continue
        yield sub.read_text(encoding="utf-8"), f"analyzers/{name}/{sub.name}"


def test_v12_modules_do_not_import_subprocess() -> None:
    """Even unused imports are a smell — banned outright."""
    for name, kind in [("access_log", "package"), ("crawler_verify.py", "file")]:
        for src, label in _iter_v12_sources(name, kind):
            assert "import subprocess" not in src, label
            assert "from subprocess" not in src, label


def test_v12_modules_do_not_call_os_writes() -> None:
    """`os.makedirs`, `os.mkdir`, `pathlib.Path.write_text` — banned."""
    forbidden = {"os.makedirs", "os.mkdir", "os.write", "os.rename", "os.remove",
                 "os.unlink", "pathlib.Path.write_text", "Path.write_text",
                 "Path.write_bytes", "truncate"}
    for name, kind in [("access_log", "package"), ("crawler_verify.py", "file")]:
        for src, label in _iter_v12_sources(name, kind):
            for qname, lineno in _ast_calls(src):
                if qname in forbidden:
                    raise AssertionError(
                        f"{label}:{lineno} calls {qname}() "
                        "— reporting.py is the only writer"
                    )
