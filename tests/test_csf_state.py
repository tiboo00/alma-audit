"""Tests for the csf_state analyzer."""

from __future__ import annotations

import pytest

from alma_audit.analyzers.csf_state import (
    _count_entries,
    analyze_csf_state,
)
from alma_audit.models import Severity
from alma_audit.runners import FakeFileSystem


# --- helpers ---------------------------------------------------------------


def _deny_text(n: int, with_comments: bool = True) -> str:
    lines = []
    if with_comments:
        lines.append("# CSF deny file — auto-managed, do not edit by hand")
        lines.append("")
    for i in range(n):
        lines.append(f"1.2.3.{i % 250}")
    lines.append("10.0.0.0/8")
    lines.append("192.168.0.0/16  # RFC1918 — operator wants it blocked here")
    return "\n".join(lines)


def _allow_text(n: int) -> str:
    lines = ["# CSF allow file"]
    for i in range(n):
        lines.append(f"5.6.7.{i}")
    return "\n".join(lines)


# --- _count_entries unit tests --------------------------------------------


def test_count_entries_skips_comments_and_blanks():
    n, malformed = _count_entries([
        "# comment",
        "",
        "  ",
        "1.2.3.4",
        "10.0.0.0/8",
        "192.168.0.0/16  # inline comment",
    ])
    assert n == 3
    assert malformed == []


def test_count_entries_include_directive():
    """CSF `Include /etc/csf/csf.blocklist` counts as one entry."""
    n, malformed = _count_entries([
        "Include /etc/csf/csf.blocklist",
        "1.2.3.4",
    ])
    assert n == 2
    assert malformed == []


def test_count_entries_collects_malformed_sample():
    n, malformed = _count_entries([
        "1.2.3.4",
        "this is not an IP",
        "neither is this",
        "or this",
    ])
    assert n == 1
    assert len(malformed) == 3
    assert "this is not an IP" in malformed


def test_count_entries_handles_ipv6():
    n, _ = _count_entries([
        "2a06:98c0:3600::103",
        "fe80::1",
    ])
    assert n == 2


# --- analyzer tests --------------------------------------------------------


def test_analyzer_no_csf_files_returns_info():
    fs = FakeFileSystem()
    findings = analyze_csf_state(["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs)
    assert all(f.severity == Severity.INFO for f in findings)
    assert any("No CSF state files found" in f.title for f in findings)


def test_analyzer_emits_info_summary_with_counts():
    fs = FakeFileSystem(files={
        "/etc/csf/csf.deny": _deny_text(10),
        "/etc/csf/csf.allow": _allow_text(5),
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
    )
    summary = next(f for f in findings if "CSF state" in f.title)
    assert summary.severity == Severity.INFO
    assert summary.details["deny_count"] == 12  # 10 IPs + 2 CIDRs
    assert summary.details["allow_count"] == 5


def test_analyzer_emits_warn_for_large_denylist():
    fs = FakeFileSystem(files={
        "/etc/csf/csf.deny": _deny_text(250),
        "/etc/csf/csf.allow": _allow_text(0),
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
        rules={"deny_count_warn": 200, "deny_count_crit": 1000},
    )
    warn = [f for f in findings if f.severity == Severity.WARN and "denylist size" in f.title.lower()]
    assert len(warn) == 1
    assert warn[0].details["deny_count"] == 252  # 250 + 2 CIDRs


def test_analyzer_emits_critical_for_huge_denylist():
    fs = FakeFileSystem(files={
        "/etc/csf/csf.deny": _deny_text(2500),
        "/etc/csf/csf.allow": _allow_text(0),
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
        rules={"deny_count_warn": 200, "deny_count_crit": 1000},
    )
    crit = [f for f in findings if f.severity == Severity.CRITICAL and "denylist size" in f.title.lower()]
    assert len(crit) == 1


def test_analyzer_emits_growth_warn():
    fs = FakeFileSystem(files={
        "/etc/csf/csf.deny": _deny_text(150),  # grew from baseline=10 to 152
        "/etc/csf/csf.allow": _allow_text(0),
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
        rules={
            "deny_baseline": 10,
            "deny_growth_warn": 100,
            "deny_growth_crit": 500,
        },
    )
    growth = [f for f in findings if "grew" in f.title.lower()]
    assert len(growth) == 1
    assert growth[0].severity == Severity.WARN
    assert growth[0].details["delta"] == 142  # 152 - 10


def test_analyzer_emits_growth_critical():
    fs = FakeFileSystem(files={
        "/etc/csf/csf.deny": _deny_text(600),
        "/etc/csf/csf.allow": _allow_text(0),
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
        rules={
            "deny_baseline": 10,
            "deny_growth_warn": 100,
            "deny_growth_crit": 500,
        },
    )
    crit = [f for f in findings if "grew" in f.title.lower() and f.severity == Severity.CRITICAL]
    assert len(crit) == 1


def test_analyzer_emits_shrinkage_info():
    """A sudden drop in denylist count is INFO — operators want to know."""
    fs = FakeFileSystem(files={
        "/etc/csf/csf.deny": _deny_text(2),  # baseline was 500, now only 4
        "/etc/csf/csf.allow": _allow_text(0),
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
        rules={"deny_baseline": 500},
    )
    shrink = [f for f in findings if "shrank" in f.title.lower()]
    assert len(shrink) == 1
    assert shrink[0].severity == Severity.INFO


def test_analyzer_baseline_with_no_deny_file_no_growth_finding():
    """If the denylist file is missing, no growth finding fires (even with a baseline)."""
    fs = FakeFileSystem(files={
        "/etc/csf/csf.allow": _allow_text(0),
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
        rules={"deny_baseline": 500, "deny_growth_warn": 100},
    )
    growth = [f for f in findings if "grew" in f.title.lower() or "shrank" in f.title.lower()]
    assert growth == []


def test_analyzer_emits_warn_for_malformed_entries():
    fs = FakeFileSystem(files={
        "/etc/csf/csf.deny": "1.2.3.4\nthis is not an IP\nneither is this",
        "/etc/csf/csf.allow": "",
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
    )
    warn = [f for f in findings if f.severity == Severity.WARN and "unexpected format" in f.title.lower()]
    assert len(warn) == 1
    assert "this is not an IP" in warn[0].details["malformed_sample"]


def test_analyzer_boundary_threshold():
    """Boundary: 199 IPs (+ 2 CIDRs = 201 total) exceeds 200 → WARN.
    195 IPs (+ 2 CIDRs = 197 total) < 200 → no WARN.
    """
    # 199 + 2 CIDRs = 201 → over threshold (200) → WARN fires.
    fs = FakeFileSystem(files={
        "/etc/csf/csf.deny": _deny_text(199),
        "/etc/csf/csf.allow": "",
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
        rules={"deny_count_warn": 200, "deny_count_crit": 1000},
    )
    denylist_size = [f for f in findings if "denylist size" in f.title.lower()]
    assert len(denylist_size) == 1
    assert denylist_size[0].severity == Severity.WARN

    # 195 + 2 CIDRs = 197 → under threshold (200) → no WARN.
    fs = FakeFileSystem(files={
        "/etc/csf/csf.deny": _deny_text(195),
        "/etc/csf/csf.allow": "",
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
        rules={"deny_count_warn": 200, "deny_count_crit": 1000},
    )
    denylist_size = [f for f in findings if "denylist size" in f.title.lower()]
    assert denylist_size == []


def test_analyzer_readonly_enforcement():
    """The analyzer only opens files via the injected FileSystem."""
    fs = FakeFileSystem()
    fs.add_bytes("/etc/csf/csf.deny", b"not text")
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
    )
    # Even with binary content, FakeFileSystem.open_text decodes via
    # errors='replace'. The analyzer must NOT raise.
    assert all(f.severity in (Severity.INFO, Severity.WARN) for f in findings)


def test_analyzer_only_allow_no_deny():
    """Edge case: csf.allow exists but csf.deny doesn't (rare)."""
    fs = FakeFileSystem(files={
        "/etc/csf/csf.allow": _allow_text(3),
    })
    findings = analyze_csf_state(
        ["/etc/csf/csf.deny"], ["/etc/csf/csf.allow"], fs,
    )
    summary = next(f for f in findings if "CSF state" in f.title)
    assert summary.details["deny_files_scanned"] == 0
    assert summary.details["allow_count"] == 3
    # No denylist-size finding fires (no deny file scanned).
    assert not any("denylist size" in f.title.lower() for f in findings)