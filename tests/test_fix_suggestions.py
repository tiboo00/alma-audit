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
    finding_keys,
    lookup_fix,
    lookup_fixes,
    merge_fixes,
    sort_fixes,
)
from alma_audit.models import Finding, Severity
from alma_audit.reporting import (
    build_report,
    write_forensic_report,
    write_json_report,
    write_markdown_report,
)


# ----------------------------------------------------------------------
# Cataloue shape — tests 1-2 of AISO-210 §4: catalogue populated, all
# five rules (D2, D5, D7, D8, D9) carry at least one fix.
# ----------------------------------------------------------------------


def test_fix_library_populated_for_required_rules():
    """Every rule named in the AISO-210 AC#4 (D2/D5/D7/D8/D9) has catalogue entries.

    AISO-215 follow-up: ``FIX_LIBRARY`` is now a flat
    ``dict[str, FindingFix]`` keyed by ``f"{finding_key}|{scope}"`` —
    we use the ``finding_keys()`` helper + ``lookup_fixes(key)`` to
    assert each rule still carries its catalogue without hard-coding
    the compound-key shape.
    """
    expected_keys = {
        "D2:probe_hits",
        "D5:weird_methods",
        "D7:domlog_anomalies",
        "D8:ssh_brute_force",
        "D9:sudo_failures",
    }
    assert expected_keys <= set(finding_keys()), (
        f"missing catalogue entries: {expected_keys - set(finding_keys())}"
    )
    for key in expected_keys:
        fixes = lookup_fixes(key)
        assert fixes, f"{key} catalogue entry is empty"
        for fix in fixes:
            assert isinstance(fix, FindingFix)
            # AISO-215: a fix's scope may be a primary scope
            # (``local_config``, ``waf``, ...) OR a ``waf`` sub-scope
            # (``waf:cflare``, ``waf:modsec``) — the latter is the
            # new AISO-215 contract that splits the two D5/WAF fixes
            # into distinct library rows. We accept any scope that
            # either matches SCOPE_ORDER verbatim OR starts with
            # ``waf:`` (a documented WAF sub-scope).
            scope_ok = fix.scope in SCOPE_ORDER or fix.scope.startswith("waf:")
            assert scope_ok, (
                f"{key}/{fix.what} has unknown scope {fix.scope!r}"
            )
            assert fix.risk in RISK_ORDER, (
                f"{key}/{fix.what} has unknown risk {fix.risk!r}"
            )


def test_d5_weird_methods_carries_four_fixes():
    """D5 carrier count per AC#4 — 4 fixes: Apache, .htaccess, CF WAF, ModSec.

    AISO-215 follow-up: the two WAF-scoped fixes (Cloudflare,
    ModSecurity) now each live at their own library key. This test
    asserts both the count AND that the two distinct WAF scopes are
    present via ``lookup_fix`` so the unambiguous keying is exercised
    end-to-end (the AC#1 requirement of AISO-215).
    """
    fixes = lookup_fixes("D5:weird_methods")
    assert len(fixes) == 4, (
        f"D5 expected 4 fixes (Apache, .htaccess, Cloudflare WAF, "
        f"ModSecurity), got {len(fixes)}"
    )
    # AISO-215 shape regression: the two WAF-scoped D5 fixes must be
    # retrievable individually. Pre-fix the library stored them as
    # anonymous list entries and only ``FIX_LIBRARY["D5:weird_methods"]``
    # could reach them — neither fix was addressable by scope.
    cflare = lookup_fix("D5:weird_methods", "waf:cflare")
    modsec = lookup_fix("D5:weird_methods", "waf:modsec")
    assert cflare.scope == "waf:cflare"
    assert "Cloudflare" in cflare.what
    assert modsec.scope == "waf:modsec"
    assert "ModSecurity" in modsec.what
    scopes = sorted(f.scope for f in fixes)
    # Apache + .htaccess + the two distinct WAF scopes (Cloudflare +
    # ModSecurity). ``local_config`` is one row, ``waf`` is split into
    # ``waf:cflare`` + ``waf:modsec``.
    assert SCOPE_APP_CONFIG in scopes
    assert SCOPE_LOCAL_CONFIG in scopes
    assert "waf:cflare" in scopes
    assert "waf:modsec" in scopes
    # Sanity: each fix has commands + rollback + why.
    for fix in fixes:
        assert fix.commands, f"D5/{fix.what} has empty commands"
        assert fix.rollback, f"D5/{fix.what} has empty rollback"
        assert fix.why, f"D5/{fix.what} has empty why"


def test_fix_library_shape_is_dict_str_to_finding_fix():
    """AISO-215 AC#1 shape regression: every value is a single FindingFix.

    Pre-fix the library was ``dict[str, list[FindingFix]]`` and the
    finding-key was the only key — the two D5/WAF fixes collided in a
    list and could not be looked up by scope. This test locks the new
    shape: ``FIX_LIBRARY`` MUST be a flat ``dict`` of strings to
    ``FindingFix``, with no nested lists anywhere.
    """
    assert isinstance(FIX_LIBRARY, dict)
    for key, value in FIX_LIBRARY.items():
        assert isinstance(key, str), f"library key {key!r} is not a string"
        assert isinstance(value, FindingFix), (
            f"library value for {key!r} is {type(value).__name__}, "
            f"expected FindingFix (AISO-215 AC#1 contract)"
        )
        assert "|" in key, (
            f"library key {key!r} missing the '{{finding_key}}|{{scope}}' "
            f"separator (AISO-215 AC#1 contract)"
        )


def test_d2_probe_hits_carries_three_fixes():
    """D2 carrier count per AC#4 — 3 fixes: .htaccess, CF WAF, fail2ban."""
    fixes = lookup_fixes("D2:probe_hits")
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
    catalogue_whats = {fix.what for fix in lookup_fixes("D5:weird_methods")}
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
    for fix in lookup_fixes("D5:weird_methods"):
        # Some whats have shell-meta characters; just check a stable substring.
        suffix = fix.what[:30]
        assert suffix in text, f"missing {suffix!r} from MD report"


def test_fix_format_flag_none_suppresses_section(tmp_path):
    """AC#4: `--fix-format=none` removes the section from MD AND the JSON key.

    AISO-215 follow-up: the suppression must reach the per-finding
    ``fixes`` array in the main JSON too — pre-fix the suppression
    only applied to the Markdown section and the forensic
    ``fixes_recommended``, so the main JSON still leaked the
    per-finding ``fixes`` array while the operator had explicitly
    asked for ``none``.
    """
    from alma_audit.runners import FakeFileSystem

    fs = FakeFileSystem({"/var/log/apache2/access_log": WEIRD_METHODS_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    report = build_report(findings, hostname="test-host")
    out = str(tmp_path)
    json_path = write_json_report(report, out, fix_format="none")
    md_path = write_markdown_report(report, out, fix_format="none")
    forensic_path = write_forensic_report(report, out, fix_format="none")
    md_text = open(md_path, encoding="utf-8").read()
    main_json = json.load(open(json_path, encoding="utf-8"))
    forensic = json.load(open(forensic_path, encoding="utf-8"))
    # 1. Markdown: no section.
    assert "## Recommended fixes" not in md_text, (
        "fix_format=none must suppress the MD section header"
    )
    # 2. Forensic JSON: no fixes_recommended / fix_scope_order keys.
    assert "fixes_recommended" not in forensic, (
        "fix_format=none must drop fixes_recommended from the forensic JSON"
    )
    assert "fix_scope_order" not in forensic, (
        "fix_format=none must drop fix_scope_order from the forensic JSON"
    )
    # 3. Main JSON: per-finding `fixes` array absent (the AC#2 fix).
    weird_findings = [
        f for f in main_json["findings"] if "unusual" in f["title"].lower()
    ]
    assert weird_findings, "expected an unusual-method finding in main JSON"
    for finding in weird_findings:
        assert "fixes" not in finding, (
            f"fix_format=none must strip per-finding 'fixes' from main JSON; "
            f"finding still carries fixes={finding.get('fixes')!r}"
        )


# ----------------------------------------------------------------------
# AISO-215 AC#2: --fix-format threading across all THREE artifacts.
#
# The follow-up review found that pre-fix ``--fix-format=none`` only
# suppressed the Markdown section + the forensic JSON's
# ``fixes_recommended``. The main JSON (`alma-audit-latest.json`)
# still leaked the per-finding ``fixes`` array, so the operator
# could not actually opt out of fix rendering.
#
# The fix threads ``fix_format`` into ``write_json_report`` and
# threads ``include_fixes`` through ``Finding.to_dict``. The tests
# below lock the new contract across all 3 modes × all 3 artifacts.
# ----------------------------------------------------------------------


def _write_all_artifacts(report, out, fix_format):
    """Run the full writer trio for a given fix_format; return parsed payloads."""
    json_path = write_json_report(report, out, fix_format=fix_format)
    md_path = write_markdown_report(report, out, fix_format=fix_format)
    forensic_path = write_forensic_report(report, out, fix_format=fix_format)
    return {
        "main_json": json.load(open(json_path, encoding="utf-8")),
        "md": open(md_path, encoding="utf-8").read(),
        "forensic": json.load(open(forensic_path, encoding="utf-8")),
    }


@pytest.mark.parametrize(
    "fix_format, expectations",
    [
        # ``text`` (default): every artifact carries fixes — section
        # in MD, per-finding fixes in main JSON, top-level
        # fixes_recommended in forensic JSON.
        (
            "text",
            {
                "md_has_section": True,
                "main_json_per_finding_fixes": True,
                "forensic_has_fixes_recommended": True,
            },
        ),
        # ``json``: forensic JSON carries the key, main JSON keeps
        # the per-finding fixes (consumers may want both), MD has no
        # section.
        (
            "json",
            {
                "md_has_section": False,
                "main_json_per_finding_fixes": True,
                "forensic_has_fixes_recommended": True,
            },
        ),
        # ``none``: every artifact strips fixes. Pre-fix this was
        # broken — the main JSON still leaked the per-finding
        # ``fixes`` array.
        (
            "none",
            {
                "md_has_section": False,
                "main_json_per_finding_fixes": False,
                "forensic_has_fixes_recommended": False,
            },
        ),
    ],
)
def test_fix_format_threading_across_all_artifacts(tmp_path, fix_format, expectations):
    """AISO-215 AC#2: ``--fix-format`` is honoured on every artifact.

    Parametrised across all three modes (``text`` / ``json`` /
    ``none``). Each artifact is asserted against the expectation for
    that mode. This is the lock the AISO-215 review requested.
    """
    from alma_audit.runners import FakeFileSystem

    fs = FakeFileSystem({"/var/log/apache2/access_log": WEIRD_METHODS_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    report = build_report(findings, hostname="test-host")

    artifacts = _write_all_artifacts(report, str(tmp_path), fix_format)

    # Markdown: section header present iff expected.
    has_section = "## Recommended fixes" in artifacts["md"]
    assert has_section == expectations["md_has_section"], (
        f"fix_format={fix_format!r}: expected MD section="
        f"{expectations['md_has_section']}, got {has_section}"
    )

    # Main JSON: per-finding ``fixes`` array present iff expected.
    weird_findings = [
        f
        for f in artifacts["main_json"]["findings"]
        if "unusual" in f["title"].lower()
    ]
    assert weird_findings, (
        f"fix_format={fix_format!r}: expected an unusual-method finding in main JSON"
    )
    for finding in weird_findings:
        present = "fixes" in finding
        assert present == expectations["main_json_per_finding_fixes"], (
            f"fix_format={fix_format!r}: expected per-finding fixes="
            f"{expectations['main_json_per_finding_fixes']}, got {present} "
            f"(finding={finding!r})"
        )

    # Forensic JSON: top-level ``fixes_recommended`` present iff expected.
    forensic_has_key = "fixes_recommended" in artifacts["forensic"]
    assert forensic_has_key == expectations["forensic_has_fixes_recommended"], (
        f"fix_format={fix_format!r}: expected forensic fixes_recommended="
        f"{expectations['forensic_has_fixes_recommended']}, got {forensic_has_key}"
    )


def test_fix_format_none_main_json_byte_matches_legacy_shape(tmp_path):
    """AISO-215 AC#2 regression: ``--fix-format=none`` main JSON shape
    is byte-equivalent to the legacy (pre-AISO-210) output: no
    ``fixes`` field on any finding, no empty ``fixes: []`` either.

    Pre-fix the main JSON carried ``"fixes": [...]`` even when the
    operator ran ``--fix-format=none``. This test asserts the byte
    shape: the field is completely absent (not present-but-empty).
    """
    from alma_audit.runners import FakeFileSystem

    fs = FakeFileSystem({"/var/log/apache2/access_log": WEIRD_METHODS_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    report = build_report(findings, hostname="test-host")

    json_path = write_json_report(report, str(tmp_path), fix_format="none")
    payload = json.load(open(json_path, encoding="utf-8"))

    for finding in payload["findings"]:
        # The field is gone entirely — not present-but-null, not
        # present-but-empty-list. AISO-215 AC#2 explicitly rejects
        # both stale shapes.
        assert "fixes" not in finding, (
            f"fix_format=none must not emit a 'fixes' key on any finding; "
            f"got {finding.get('fixes')!r} on {finding.get('title')!r}"
        )


def test_unknown_fix_format_raises_in_json_writer(tmp_path):
    """AISO-215: the unknown-mode guard is centralised in every writer.

    ``write_json_report`` was added to the range-check in AISO-215
    (pre-fix only ``write_markdown_report`` raised). A CLI typo on
    ``--fix-format`` now fails closed across every artifact path.
    """
    from alma_audit.runners import FakeFileSystem

    fs = FakeFileSystem({"/var/log/apache2/access_log": WEIRD_METHODS_LOG})
    findings = analyze_access_logs(["/var/log/apache2/access_log"], fs)
    report = build_report(findings, hostname="test-host")

    with pytest.raises(ValueError, match="unknown fix_format"):
        write_json_report(report, str(tmp_path), fix_format="lol")
    with pytest.raises(ValueError, match="unknown fix_format"):
        write_forensic_report(report, str(tmp_path), fix_format="lol")
    with pytest.raises(ValueError, match="unknown fix_format"):
        write_markdown_report(report, str(tmp_path), fix_format="lol")


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
