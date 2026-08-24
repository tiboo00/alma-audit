"""AISO-210: structured fix-suggestion layer acceptance tests.

Four scenarios per the AISO-210 ticket acceptance criteria:

  1. `test_fix_suggestion_attached_to_weird_methods` — verifies the
     4 fixes (Apache, .htaccess, Cloudflare WAF, mod_security) appear
     on a D5 finding when triggered by a real access log.
  2. `test_fix_suggestion_deduplicated` — calling ``merge_fixes`` with
     a duplicate (same scope + what) collapses to a single entry.
  3. `test_fix_suggestion_grouped_by_scope_in_markdown` — the rendered
     Markdown report carries the ``## Recommended fixes`` section
     header.
  4. `test_fix_format_flag_none_suppresses_section` — passing
     ``--fix-format=none`` removes the section AND removes the
     ``fixes_recommended`` key from the forensic JSON.

Plus a handful of supporting tests around the catalogue shape, the
``attach_fixes`` helper, and ``sort_fixes`` ordering.
"""

from __future__ import annotations

import json
import os

import pytest

from alma_audit.analyzers.access_log import analyze_access_logs
from alma_audit.fix_suggestions import (
    FIX_LIBRARY,
    RISK_ORDER,
    SCOPE_APP_CONFIG,
    SCOPE_DNS_BLOCK,
    SCOPE_KERNEL_PARAM,
    SCOPE_LOCAL_CONFIG,
    SCOPE_ORDER,
    SCOPE_WAF,
    FindingFix,
    all_fixes_from_findings,
    attach_fixes,
    lookup_fixes,
    merge_fixes,
    sort_fixes,
)
from alma_audit.models import Finding, Severity
from alma_audit.reporting import (
    build_report,
    write_forensic_report,
    write_markdown_report,
)


# ----------------------------------------------------------------------
# Cataloue shape — tests 1-2 of AISO-210 §4: catalogue populated, all
# five rules (D2, D5, D7, D8, D9) carry at least one fix.
# ----------------------------------------------------------------------


def test_fix_library_populated_for_required_rules():
    """Every rule named in the AISO-210 AC#4 (D2/D5/D7/D8/D9) has a catalogue entry."""
    expected_keys = {
        "D2:probe_hits",
        "D5:weird_methods",
        "D7:domlog_anomalies",
        "D8:ssh_brute_force",
        "D9:sudo_failures",
    }
    assert expected_keys <= set(FIX_LIBRARY), (
        f"missing catalogue entries: {expected_keys - set(FIX_LIBRARY)}"
    )
    for key in expected_keys:
        fixes = FIX_LIBRARY[key]
        assert fixes, f"{key} catalogue entry is empty"
        for fix in fixes:
            assert isinstance(fix, FindingFix)
            assert fix.scope in SCOPE_ORDER, (
                f"{key}/{fix.what} has unknown scope {fix.scope!r}"
            )
            assert fix.risk in RISK_ORDER, (
                f"{key}/{fix.what} has unknown risk {fix.risk!r}"
            )


def test_d5_weird_methods_carries_four_fixes():
    """D5 carrier count per AC#4 — 4 fixes: Apache, .htaccess, CF WAF, ModSec."""
    fixes = FIX_LIBRARY["D5:weird_methods"]
    assert len(fixes) == 4, (
        f"D5 expected 4 fixes (Apache, .htaccess, Cloudflare WAF, "
        f"ModSecurity), got {len(fixes)}"
    )
    scopes = sorted(f.scope for f in fixes)
    # Two WAF fixes — one Cloudflare, one ModSecurity — and two local
    # configs (Apache + .htaccess). All four are independent scopes; the
    # renderer orders them via SCOPE_ORDER + RISK_ORDER.
    assert SCOPE_APP_CONFIG in scopes
    assert SCOPE_LOCAL_CONFIG in scopes
    assert scopes.count(SCOPE_WAF) == 2
    # Sanity: each fix has commands + rollback + why.
    for fix in fixes:
        assert fix.commands, f"D5/{fix.what} has empty commands"
        assert fix.rollback, f"D5/{fix.what} has empty rollback"
        assert fix.why, f"D5/{fix.what} has empty why"


def test_d2_probe_hits_carries_three_fixes():
    """D2 carrier count per AC#4 — 3 fixes: .htaccess, CF WAF, fail2ban."""
    fixes = FIX_LIBRARY["D2:probe_hits"]
    assert len(fixes) == 3, (
        f"D2 expected 3 fixes (.htaccess, Cloudflare WAF, fail2ban), got {len(fixes)}"
    )
    scopes = sorted(f.scope for f in fixes)
    assert SCOPE_LOCAL_CONFIG in scopes
    assert SCOPE_WAF in scopes
    assert SCOPE_APP_CONFIG in scopes


# ----------------------------------------------------------------------
# attach_fixes / merge_fixes — dupe handling, ordering.
# ----------------------------------------------------------------------


def test_attach_fixes_replaces_no_existing_fixes():
    """Attaching on a finding with no fixes just sets the tuple."""
    finding = Finding(
        module="access_log",
        severity=Severity.WARN,
        title="t",
        description="d",
    )
    patched = attach_fixes(finding, lookup_fixes("D2:probe_hits"))
    # D2 has 3 fixes — verify they all landed.
    assert len(patched.fixes) == 3
    for fix in patched.fixes:
        assert isinstance(fix, FindingFix)


def test_merge_fixes_deduplicates_by_scope_and_what():
    """Two FindingFix with the same (scope, what) collapse to one — AC#2."""
    a = FindingFix(
        what="Block via .htaccess",
        why="Cheap, no Apache restart.",
        scope=SCOPE_LOCAL_CONFIG,
        risk="low",
        commands=["RewriteRule..."],
    )
    b = FindingFix(
        what="Block via .htaccess",
        why="Same rewrite but with extra context for the operator.",
        scope=SCOPE_LOCAL_CONFIG,
        risk="low",
        # The richer commands list wins; both records have the same
        # number of commands here so ``why`` length is the tiebreaker.
        commands=["RewriteRule..."],
    )
    merged = merge_fixes([a], [b])
    assert len(merged) == 1, "dupe (scope, what) should collapse to one"


def test_merge_fixes_keeps_richer_record():
    """When two fixes collide on (scope, what), the longer commands list wins."""
    a = FindingFix(
        what="Block via .htaccess",
        why="Short",
        scope=SCOPE_LOCAL_CONFIG,
        risk="low",
        commands=["step1"],
    )
    b = FindingFix(
        what="Block via .htaccess",
        why="Longer but fewer commands.",
        scope=SCOPE_LOCAL_CONFIG,
        risk="low",
        commands=["step1", "step2", "step3"],
    )
    merged = merge_fixes([a], [b])
    assert len(merged) == 1
    assert merged[0].commands == ["step1", "step2", "step3"], (
        "the richer commands list (b) should have won the dedup"
    )


def test_attach_fixes_dedupes_with_existing():
    """Finding already carries a fix that matches by (scope, what) — attach is idempotent."""
    base_fix = FindingFix(
        what="same action",
        why="A",
        scope=SCOPE_APP_CONFIG,
        risk="low",
        commands=["original"],
    )
    finding = Finding(
        module="access_log",
        severity=Severity.WARN,
        title="t",
        description="d",
        fixes=(base_fix,),
    )
    new_fix = FindingFix(
        what="same action",
        why="B — with richer context",
        scope=SCOPE_APP_CONFIG,
        risk="low",
        commands=["original", "with", "more", "detail"],
    )
    patched = attach_fixes(finding, [new_fix])
    assert len(patched.fixes) == 1
    assert patched.fixes[0].commands == [
        "original",
        "with",
        "more",
        "detail",
    ], "longer commands list should have won"


def test_sort_fixes_orders_by_scope_then_risk():
    """Sort key is (scope-order, risk-order, what) — deterministic across CPython builds."""
    fixes = [
        FindingFix(what="z", why="x", scope=SCOPE_KERNEL_PARAM, risk="high"),
        FindingFix(what="a", why="x", scope=SCOPE_LOCAL_CONFIG, risk="high"),
        FindingFix(what="b", why="x", scope=SCOPE_LOCAL_CONFIG, risk="low"),
        FindingFix(what="y", why="x", scope=SCOPE_APP_CONFIG, risk="medium"),
    ]
    sorted_fixes = sort_fixes(fixes)
    whats = [f.what for f in sorted_fixes]
    assert whats == ["b", "a", "y", "z"], (
        f"expected [local-low, local-high, app-medium, kernel-high], got {whats}"
    )


# ----------------------------------------------------------------------
# End-to-end: D5 finding actually carries the four fixes through the
# analyzer pipeline (acceptance criterion #1).
# ----------------------------------------------------------------------

WEIRD_METHODS_LOG = """\
134.199.208.10 - - [17/Aug/2026:04:13:00 +0000] "PROPFIND / HTTP/1.1" 405 235 "-" "masscan"
134.199.208.10 - - [17/Aug/2026:04:13:01 +0000] "TRACE / HTTP/1.1" 405 235 "-" "masscan"
134.199.208.10 - - [17/Aug/2026:04:13:02 +0000] "PROPFIND /a HTTP/1.1" 405 235 "-" "masscan"
134.199.208.10 - - [17/Aug/2026:04:13:03 +0000] "DEBUG / HTTP/1.1" 405 235 "-" "masscan"
134.199.208.10 - - [17/Aug/2026:04:13:04 +0000] "CONNECT / HTTP/1.1" 405 235 "-" "masscan"
134.199.208.10 - - [17/Aug/2026:04:13:05 +0000] "PROPFIND /b HTTP/1.1" 405 235 "-" "masscan"
"""


def test_fix_suggestion_attached_to_weird_methods(make_fs):
    """AC#1: D5 finding carries the 4 fixes (Apache, .htaccess, CF WAF, mod_security)."""
    fs = make_fs({"/var/log/apache2/access_log": WEIRD_METHODS_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    weird = [f for f in findings if "unusual" in f.title.lower()]
    assert weird, "expected an unusual-method finding"
    f = weird[0]
    assert len(f.fixes) == 4, (
        f"D5 finding expected to carry 4 fixes, got {len(f.fixes)}"
    )
    whats = {fix.what for fix in f.fixes}
    # The 4 D5 fixes from the catalogue must all land on the finding.
    catalogue_whats = {fix.what for fix in FIX_LIBRARY["D5:weird_methods"]}
    assert whats == catalogue_whats, (
        f"D5 finding carries {whats!r}, expected {catalogue_whats!r}"
    )


def test_attach_fixes_preserves_existing_unrelated_fix(make_fs):
    """A finding with an unrelated pre-existing fix keeps BOTH after attach."""
    fs = make_fs({"/var/log/apache2/access_log": WEIRD_METHODS_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    weird = [f for f in findings if "unusual" in f.title.lower()][0]
    pre_existing = FindingFix(
        what="Manual note: also patch in JIRA",
        why="Ticket 1234 owner action.",
        scope=SCOPE_APP_CONFIG,
        risk="low",
    )
    enriched = attach_fixes(weird, [pre_existing])
    whats = {fix.what for fix in enriched.fixes}
    assert "Manual note: also patch in JIRA" in whats
    # plus the 4 catalogue fixes
    assert len(enriched.fixes) == 5


# ----------------------------------------------------------------------
# Markdown rendering — AC#3.
# ----------------------------------------------------------------------


def test_fix_suggestion_grouped_by_scope_in_markdown(tmp_path):
    """AC#3: rendered Markdown carries the `## Recommended fixes` section header."""
    fs = make_fs({"/var/log/apache2/access_log": WEIRD_METHODS_LOG}) if False else None
    # Use the FakeFileSystem via the import below — keeping the test
    # self-contained without needing the make_fs fixture.
    from alma_audit.runners import FakeFileSystem

    fs = FakeFileSystem({"/var/log/apache2/access_log": WEIRD_METHODS_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    report = build_report(findings, hostname="test-host")
    path = write_markdown_report(report, str(tmp_path), fix_format="text")
    text = open(path, encoding="utf-8").read()
    assert "## Recommended fixes" in text, (
        f"expected `## Recommended fixes` section header in {path}"
    )
    # local_config scope section is one of the four D5 subsections.
    assert "local_config" in text
    # All four D5 whats should land in the report at least once.
    for fix in FIX_LIBRARY["D5:weird_methods"]:
        # Some whats have shell-meta characters; just check a stable substring.
        suffix = fix.what[:30]
        assert suffix in text, f"missing {suffix!r} from MD report"


def test_fix_format_flag_none_suppresses_section(tmp_path):
    """AC#4: `--fix-format=none` removes the section from MD AND the JSON key."""
    from alma_audit.runners import FakeFileSystem

    fs = FakeFileSystem({"/var/log/apache2/access_log": WEIRD_METHODS_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    report = build_report(findings, hostname="test-host")
    out = str(tmp_path)
    md_path = write_markdown_report(report, out, fix_format="none")
    forensic_path = write_forensic_report(report, out, fix_format="none")
    md_text = open(md_path, encoding="utf-8").read()
    forensic = json.load(open(forensic_path, encoding="utf-8"))
    assert "## Recommended fixes" not in md_text, (
        "fix_format=none must suppress the MD section header"
    )
    assert "fixes_recommended" not in forensic, (
        "fix_format=none must drop fixes_recommended from the forensic JSON"
    )


def test_fix_format_text_adds_section_and_keeps_json_key(tmp_path):
    """``--fix-format=text`` (default): MD has section, JSON has fixes_recommended."""
    from alma_audit.runners import FakeFileSystem

    fs = FakeFileSystem({"/var/log/apache2/access_log": WEIRD_METHODS_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    report = build_report(findings, hostname="test-host")
    out = str(tmp_path)
    md_path = write_markdown_report(report, out, fix_format="text")
    forensic_path = write_forensic_report(report, out, fix_format="text")
    md_text = open(md_path, encoding="utf-8").read()
    forensic = json.load(open(forensic_path, encoding="utf-8"))
    assert "## Recommended fixes" in md_text
    assert "fixes_recommended" in forensic
    # The fixes_recommended array should hold the 4 D5 fixes.
    assert len(forensic["fixes_recommended"]) == 4


def test_fix_format_json_keeps_json_key_no_md_section(tmp_path):
    """``--fix-format=json``: forensic JSON keeps the key, MD has no section."""
    from alma_audit.runners import FakeFileSystem

    fs = FakeFileSystem({"/var/log/apache2/access_log": WEIRD_METHODS_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    report = build_report(findings, hostname="test-host")
    out = str(tmp_path)
    md_path = write_markdown_report(report, out, fix_format="json")
    forensic_path = write_forensic_report(report, out, fix_format="json")
    md_text = open(md_path, encoding="utf-8").read()
    forensic = json.load(open(forensic_path, encoding="utf-8"))
    assert "## Recommended fixes" not in md_text
    assert "fixes_recommended" in forensic


# ----------------------------------------------------------------------
# all_fixes_from_findings — dedup across multiple findings.
# ----------------------------------------------------------------------


def test_all_fixes_from_findings_dedups_across_findings():
    """Two findings carrying the same fix collapse to one row in fixes_recommended."""
    same_fix = FindingFix(
        what="Block via .htaccess",
        why="Cheap, no Apache restart.",
        scope=SCOPE_LOCAL_CONFIG,
        risk="low",
        commands=["RewriteRule..."],
    )
    f1 = Finding(
        module="access_log",
        severity=Severity.WARN,
        title="probe",
        description="d",
        fixes=(same_fix,),
    )
    f2 = Finding(
        module="secure_log",
        severity=Severity.WARN,
        title="brute",
        description="d",
        fixes=(same_fix,),
    )
    merged = all_fixes_from_findings([f1, f2])
    assert len(merged) == 1, "same fix on two findings should dedup to one"


# ----------------------------------------------------------------------
# Backwards-compat: Finding constructors without `fixes` still work (AC#9).
# ----------------------------------------------------------------------


def test_finding_constructor_without_fixes_still_works():
    """AC#9: existing tests / call-sites that omit `fixes` keep working."""
    f = Finding(
        module="domlog_inventory",
        severity=Severity.INFO,
        title="ok",
        description="nothing to report",
    )
    assert f.fixes == ()  # default empty tuple
    # to_dict() should NOT carry a `fixes` key when none were attached.
    payload = f.to_dict()
    assert "fixes" not in payload


def test_finding_recommendation_field_preserved():
    """AC#9: the legacy `recommendation` string still renders into to_dict."""
    f = Finding(
        module="domlog_inventory",
        severity=Severity.WARN,
        title="t",
        description="d",
        recommendation="legacy suggestion text",
    )
    assert f.to_dict()["recommendation"] == "legacy suggestion text"


# ----------------------------------------------------------------------
# Unknown fix_format → ValueError (closed-failure).
# ----------------------------------------------------------------------


def test_unknown_fix_format_raises(tmp_path):
    """An unknown --fix-format value must fail closed, not silently degrade."""
    from alma_audit.runners import FakeFileSystem

    fs = FakeFileSystem({"/var/log/apache2/access_log": ""})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    report = build_report(findings)
    with pytest.raises(ValueError, match="unknown fix_format"):
        write_markdown_report(report, str(tmp_path), fix_format="lol")
