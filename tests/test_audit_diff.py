"""Tests for the audit-diff trend sidecar.

The sidecar is a pure-Python script under `examples/`; the tests
import it directly (via sys.path manipulation) so we don't need a
package wrapper. Every test asserts a property of the diff output
that an operator would notice in cron logs.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "examples" / "audit-diff.py"


@pytest.fixture(scope="module")
def audit_diff():
    """Import `examples/audit-diff.py` as a Python module.

    The script is a sidecar (not a package member), so we use
    importlib to load it without polluting sys.path for other tests.
    """
    spec = importlib.util.spec_from_file_location(
        "audit_diff_module", str(SCRIPT_PATH),
    )
    module = importlib.util.module_from_spec(spec)
    # `dataclasses` introspects `sys.modules[__module__]` for the
    # owning module — failing that, dataclass errors out with a
    # confusing "NoneType has no attribute __dict__" message. We
    # register the module in sys.modules BEFORE exec_module runs so
    # the dataclass decorator finds the namespace.
    sys.modules["audit_diff_module"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


# --- helpers --------------------------------------------------------------


def _finding(module: str, title: str, severity: str = "WARN") -> dict:
    return {
        "module": module,
        "severity": severity,
        "title": title,
        "description": "test",
        "details": {},
        "recommendation": "",
    }


def _report(
    findings: list[dict],
    *,
    timestamp: str = "2026-08-17T04:15:00",
    summary: dict | None = None,
) -> dict:
    summary = summary or {
        "total_findings": len(findings),
        "info": sum(1 for f in findings if f["severity"] == "INFO"),
        "warn": sum(1 for f in findings if f["severity"] == "WARN"),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
    }
    return {
        "timestamp": timestamp,
        "hostname": "test-host",
        "findings": findings,
        "summary": summary,
    }


# --- _index_findings -------------------------------------------------------


def test_index_findings_dedupes_by_module_title(audit_diff):
    """Same (module, title) appearing twice counts once with __count=2."""
    report = _report([
        _finding("access_log", "Probe path hit"),
        _finding("access_log", "Probe path hit"),
    ])
    idx = audit_diff._index_findings(report)
    assert ("access_log", "Probe path hit") in idx
    assert idx[("access_log", "Probe path hit")]["__count"] == 2


def test_index_findings_skips_malformed(audit_diff):
    """Findings missing required fields are skipped, not crashing the diff."""
    report = {
        "findings": [
            {"module": "x", "title": "y", "severity": "WARN"},
            {"module": "x"},  # missing title + severity
            {"title": "y", "severity": "WARN"},  # missing module
            "not a dict",
        ],
        "summary": {},
        "timestamp": "t",
    }
    idx = audit_diff._index_findings(report)
    assert ("x", "y") in idx
    assert len(idx) == 1


# --- _diff_reports ---------------------------------------------------------


def test_diff_reports_detects_added(audit_diff):
    prev = _report([])
    curr = _report([_finding("access_log", "new finding", "WARN")])
    diff = audit_diff._diff_reports(prev, curr)
    assert len(diff.rows) == 1
    row = diff.rows[0]
    assert row.kind == audit_diff.DIFF_ADDED
    assert row.module == "access_log"
    assert row.title == "new finding"


def test_diff_reports_detects_removed(audit_diff):
    prev = _report([_finding("access_log", "gone finding", "WARN")])
    curr = _report([])
    diff = audit_diff._diff_reports(prev, curr)
    assert len(diff.rows) == 1
    assert diff.rows[0].kind == audit_diff.DIFF_REMOVED


def test_diff_reports_detects_severity_change(audit_diff):
    prev = _report([_finding("ssl_cert", "expires soon", "WARN")])
    curr = _report([_finding("ssl_cert", "expires soon", "CRITICAL")])
    diff = audit_diff._diff_reports(prev, curr)
    assert len(diff.rows) == 1
    assert diff.rows[0].kind == audit_diff.DIFF_SEVERITY_CHANGED
    assert diff.rows[0].before_severity == "WARN"
    assert diff.rows[0].after_severity == "CRITICAL"


def test_diff_reports_detects_count_change(audit_diff):
    prev = _report([
        _finding("secure_log", "brute-force"),
        _finding("secure_log", "brute-force"),
    ])
    curr = _report([
        _finding("secure_log", "brute-force"),
    ])
    diff = audit_diff._diff_reports(prev, curr)
    assert len(diff.rows) == 1
    assert diff.rows[0].kind == audit_diff.DIFF_COUNT_CHANGED
    assert diff.rows[0].before_count == 2
    assert diff.rows[0].after_count == 1


def test_diff_reports_no_changes_returns_empty_rows(audit_diff):
    prev = _report([_finding("x", "y", "WARN")])
    curr = _report([_finding("x", "y", "WARN")])
    diff = audit_diff._diff_reports(prev, curr)
    assert diff.rows == []


def test_diff_reports_rows_are_sorted_deterministically(audit_diff):
    """Same input → same row order (determinism contract)."""
    prev = _report([])
    curr = _report([
        _finding("a", "title1", "INFO"),
        _finding("b", "title2", "CRITICAL"),
        _finding("a", "title3", "WARN"),
    ])
    diff1 = audit_diff._diff_reports(prev, curr)
    diff2 = audit_diff._diff_reports(prev, curr)
    keys1 = [(r.kind, r.module, r.title) for r in diff1.rows]
    keys2 = [(r.kind, r.module, r.title) for r in diff2.rows]
    assert keys1 == keys2
    # CRITICAL first (severity rank 2), then WARN (1), then INFO (0).
    assert keys1[0][2] == "title2"


# --- renderers ------------------------------------------------------------


def test_render_json_is_valid_json(audit_diff):
    diff = audit_diff.TrendReport(
        previous_timestamp="t1",
        current_timestamp="t2",
        previous_summary={"info": 0, "warn": 1, "critical": 0, "total_findings": 1},
        current_summary={"info": 0, "warn": 0, "critical": 1, "total_findings": 1},
        rows=[
            audit_diff.DiffRow(
                kind=audit_diff.DIFF_SEVERITY_CHANGED,
                module="x", title="y",
                before_severity="WARN", after_severity="CRITICAL",
                before_count=1, after_count=1,
            ),
        ],
    )
    out = audit_diff.render_json(diff)
    parsed = json.loads(out)
    assert parsed["previous_timestamp"] == "t1"
    assert parsed["current_timestamp"] == "t2"
    assert parsed["summary_delta"]["warn"] == -1
    assert parsed["summary_delta"]["critical"] == 1
    assert len(parsed["rows"]) == 1
    assert parsed["rows"][0]["kind"] == "severity_changed"


def test_render_json_is_deterministic(audit_diff):
    """Two runs over the same TrendReport produce identical output."""
    diff = audit_diff.TrendReport(
        previous_timestamp=None, current_timestamp=None,
        previous_summary={}, current_summary={},
        rows=[
                audit_diff.DiffRow(
                    kind=audit_diff.DIFF_ADDED, module="x", title="z",
                    before_severity=None, after_severity="INFO",
                ),
        ],
    )
    assert audit_diff.render_json(diff) == audit_diff.render_json(diff)


def test_render_markdown_contains_summary_table(audit_diff):
    diff = audit_diff.TrendReport(
        previous_timestamp="t1", current_timestamp="t2",
        previous_summary={"info": 1, "warn": 0, "critical": 0, "total_findings": 1},
        current_summary={"info": 2, "warn": 1, "critical": 0, "total_findings": 3},
        rows=[],
    )
    out = audit_diff.render_markdown(diff)
    assert "# AlmaAudit Trend Diff" in out
    assert "Previous run" in out
    assert "Current run" in out
    assert "| INFO |" in out
    assert "No changes between runs." in out


def test_render_markdown_groups_rows_by_kind(audit_diff):
    diff = audit_diff.TrendReport(
        previous_timestamp="t1", current_timestamp="t2",
        previous_summary={}, current_summary={},
        rows=[
            audit_diff.DiffRow(audit_diff.DIFF_ADDED, "a", "t1", None, "INFO"),
            audit_diff.DiffRow(audit_diff.DIFF_ADDED, "a", "t2", None, "WARN"),
            audit_diff.DiffRow(audit_diff.DIFF_REMOVED, "b", "t3", "WARN", None),
        ],
    )
    out = audit_diff.render_markdown(diff)
    assert "### Added (2)" in out
    assert "### Removed (1)" in out


def test_render_text_one_line_per_change(audit_diff):
    diff = audit_diff.TrendReport(
        previous_timestamp="t1", current_timestamp="t2",
        previous_summary={"info": 0, "warn": 1, "critical": 0},
        current_summary={"info": 0, "warn": 0, "critical": 1},
        rows=[
            audit_diff.DiffRow(audit_diff.DIFF_SEVERITY_CHANGED, "x", "y",
                              "WARN", "CRITICAL"),
        ],
    )
    out = audit_diff.render_text(diff)
    assert "WARN → CRITICAL" in out


def test_render_text_handles_empty_diff(audit_diff):
    diff = audit_diff.TrendReport(
        previous_timestamp=None, current_timestamp=None,
        previous_summary={}, current_summary={},
        rows=[],
    )
    out = audit_diff.render_text(diff)
    assert "(no changes)" in out


# --- CLI -----------------------------------------------------------------


def _write_report(tmp_path, name: str, report: dict) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(report), encoding="utf-8")
    return str(path)


def test_cli_json_format_stdout(audit_diff, tmp_path, capsys):
    prev_path = _write_report(tmp_path, "prev.json", _report([]))
    curr_path = _write_report(tmp_path, "curr.json", _report([
        _finding("access_log", "added finding"),
    ]))
    rc = audit_diff.main([prev_path, curr_path, "--format", "json"])
    captured = capsys.readouterr()
    assert rc == 0
    parsed = json.loads(captured.out)
    assert len(parsed["rows"]) == 1
    assert parsed["rows"][0]["kind"] == "added"


def test_cli_markdown_format_to_file(audit_diff, tmp_path):
    prev_path = _write_report(tmp_path, "prev.json", _report([]))
    curr_path = _write_report(tmp_path, "curr.json", _report([
        _finding("access_log", "new finding"),
    ]))
    out_path = tmp_path / "diff.md"
    rc = audit_diff.main([prev_path, curr_path, "--format", "markdown", "--output", str(out_path)])
    assert rc == 0
    content = out_path.read_text(encoding="utf-8")
    assert "# AlmaAudit Trend Diff" in content


def test_cli_text_format_default(audit_diff, tmp_path, capsys):
    prev_path = _write_report(tmp_path, "prev.json", _report([]))
    curr_path = _write_report(tmp_path, "curr.json", _report([
        _finding("x", "y", "WARN"),
    ]))
    rc = audit_diff.main([prev_path, curr_path])
    captured = capsys.readouterr()
    assert rc == 0
    assert "WARN: 0 → 1" in captured.out


def test_cli_does_not_mutate_inputs(audit_diff, tmp_path):
    """The sidecar must never write to the input files."""
    prev_report = _report([])
    curr_report = _report([_finding("x", "y")])
    prev_path = _write_report(tmp_path, "prev.json", prev_report)
    curr_path = _write_report(tmp_path, "curr.json", curr_report)
    before_prev = pathlib.Path(prev_path).read_text(encoding="utf-8")
    before_curr = pathlib.Path(curr_path).read_text(encoding="utf-8")
    audit_diff.main([prev_path, curr_path, "--format", "json"])
    after_prev = pathlib.Path(prev_path).read_text(encoding="utf-8")
    after_curr = pathlib.Path(curr_path).read_text(encoding="utf-8")
    assert before_prev == after_prev
    assert before_curr == after_curr


def test_cli_missing_input_file_exits_2(audit_diff, tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        audit_diff.main([
            str(tmp_path / "missing.json"),
            str(tmp_path / "also_missing.json"),
            "--format", "json",
        ])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "not found" in captured.err


def test_cli_malformed_json_exits_2(audit_diff, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("not valid json", encoding="utf-8")
    other = _write_report(tmp_path, "ok.json", _report([]))
    with pytest.raises(SystemExit) as exc:
        audit_diff.main([str(bad), other])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "malformed JSON" in captured.err


def test_cli_top_level_not_object_exits_2(audit_diff, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")  # JSON array, not object
    other = _write_report(tmp_path, "ok.json", _report([]))
    with pytest.raises(SystemExit) as exc:
        audit_diff.main([str(bad), other])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "not a JSON object" in captured.err


def test_cli_missing_findings_key_exits_2(audit_diff, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"timestamp": "t", "summary": {}}', encoding="utf-8")
    other = _write_report(tmp_path, "ok.json", _report([]))
    with pytest.raises(SystemExit) as exc:
        audit_diff.main([str(bad), other])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "missing 'findings'" in captured.err


# --- end-to-end via subprocess --------------------------------------------


def test_subprocess_smoke(tmp_path):
    """Run the script as a real subprocess — checks the shebang and CLI plumbing."""
    prev_path = _write_report(tmp_path, "prev.json", _report([]))
    curr_path = _write_report(tmp_path, "curr.json", _report([
        _finding("a", "b", "WARN"),
    ]))
    import subprocess
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), prev_path, curr_path, "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    parsed = json.loads(result.stdout)
    assert len(parsed["rows"]) == 1
    assert parsed["rows"][0]["kind"] == "added"