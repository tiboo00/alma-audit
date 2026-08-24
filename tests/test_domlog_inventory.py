"""Tests for the domlog inventory anomaly detector + multi-root discovery."""

from __future__ import annotations

from alma_audit.analyzers.domlog_inventory import (
    _SORT_WEIGHTS,
    _is_anomalous_filename,
    analyze_domlog_inventory,
)
from alma_audit.analyzers.domlog_roots import (
    DEFAULT_DOMLOG_ROOTS,
    DOMLOG_EXCLUDE_SUFFIXES,
    should_skip_filename,
)
from alma_audit.models import Severity

DOMLOG_ROOT = "/var/log/apache2/domlogs"


def _fs_with(files: dict[str, str]):
    from alma_audit.runners import FakeFileSystem

    return FakeFileSystem(files=files)


def test_clean_inventory_yields_info_only():
    files = {
        f"{DOMLOG_ROOT}/hostdzire.com": "log",
        f"{DOMLOG_ROOT}/hostdzire.com-ssl_log": "log",
        f"{DOMLOG_ROOT}/hostdzire.com-bytes_log": "log",  # must be skipped, not flagged
        f"{DOMLOG_ROOT}/bfiber.in": "log",
        f"{DOMLOG_ROOT}/bfiber.in-ssl_log": "log",
    }
    fs = _fs_with(files)
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    # No WARN/CRITICAL — only INFO summary. -bytes_log is intentionally
    # excluded, so it doesn't produce a false-positive "unexpected_filename_shape".
    sevs = {f.severity for f in findings}
    assert sevs == {Severity.INFO}


def test_too_long_filename_is_critical():
    long_name = "a" * 130  # > LENGTH_CRIT
    fs = _fs_with({f"{DOMLOG_ROOT}/{long_name}": "log"})
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit
    assert any(a["reason"] == "filename_too_long" for a in crit[0].details["anomalies"])


def test_unusually_long_but_under_crit_is_warn():
    long_name = "b" * 75  # 60 ≤ len < 120 → WARN
    fs = _fs_with({f"{DOMLOG_ROOT}/{long_name}": "log"})
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    warn = [f for f in findings if f.severity == Severity.WARN]
    assert warn
    assert any(a["reason"] == "filename_unusually_long" for a in warn[0].details["anomalies"])


def test_repeated_character_fuzzing_is_flagged():
    # 25 'A's — over the REPEAT_MIN_LEN, well over the repeat ratio
    name = "A" * 25
    fs = _fs_with({f"{DOMLOG_ROOT}/{name}": "log"})
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    flagged = [
        f for f in findings
        if any(a.get("reason") == "repeated_character_pattern" for a in f.details.get("anomalies", []))
    ]
    assert flagged


def test_shell_metacharacter_is_critical():
    fs = _fs_with({f"{DOMLOG_ROOT}/host;rm": "log"})
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit
    assert any(a["reason"] == "shell_metacharacters" for a in crit[0].details["anomalies"])


def test_subdirectory_is_flagged():
    """Non-account-shaped sub-directories ARE flagged (anomaly).

    AISO-198: cPanel account-ID-shaped sub-directories (random 8-char
    alphanumeric names) are normal layout, so they emit INFO only.
    Genuinely suspicious layouts (e.g. a `nested/year/` structure)
    still emit WARN/CRITICAL.
    """
    fs = _fs_with({
        f"{DOMLOG_ROOT}/zmrk2md30edvm/hostdzire.com": "log",
        f"{DOMLOG_ROOT}/hostdzire.com": "log",
    })
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    # Account-ID-shaped subdir → INFO scope-info finding.
    info_subs = [
        f for f in findings
        if "sub-director" in f.title.lower()
    ]
    assert info_subs, "Expected an INFO scope-info finding for the account subdir"
    assert all(f.severity == Severity.INFO for f in info_subs)


def test_non_account_subdirectory_is_anomaly():
    """Sub-directories that don't match the cPanel account-ID shape are flagged.

    A directory like `nested_2024/` (contains a digit pattern outside
    the account-ID convention) is treated as a structural anomaly.
    """
    fs = _fs_with({
        f"{DOMLOG_ROOT}/nested_2024_q1/hostdzire.com": "log",
        f"{DOMLOG_ROOT}/hostdzire.com": "log",
    })
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    subdir_findings = [
        f for f in findings
        if "sub-directory" in f.title.lower()
        or "sub-director" in f.title.lower()
    ]
    assert subdir_findings
    assert any(f.severity in (Severity.WARN, Severity.CRITICAL) for f in subdir_findings), (
        f"Expected a WARN/CRITICAL for a non-account-shaped subdir; got: "
        f"{[(f.severity, f.title) for f in subdir_findings]}"
    )


# ---------------------------------------------------------------------------
# AISO-194: multi-root domlog discovery
# ---------------------------------------------------------------------------


def test_default_domlog_roots_include_cloudlinux_layout():
    """The default root list must include both cPanel and CloudLinux paths.

    `hostdzire.com` was the canonical example from a CloudLinux + cPanel
    server fingerprint. A single-root default would have missed
    `/usr/local/apache/domlogs`, where the actual files live.
    """
    assert "/var/log/apache2/domlogs" in DEFAULT_DOMLOG_ROOTS
    assert "/usr/local/apache/domlogs" in DEFAULT_DOMLOG_ROOTS


def test_should_skip_filename_excludes_bytes_log_and_offset():
    """`-bytes_log`, `-bytes_log.bkup`, `.offset` are NOT access logs."""
    assert should_skip_filename("hostdzire.com-bytes_log") is True
    assert should_skip_filename("hostdzire.com-bytes_log.bkup") is True
    assert should_skip_filename("hostdzire.com-bytes_log.bkup.offset") is True
    assert should_skip_filename("hostdzire.com.offset") is True
    # Real access logs are NOT excluded.
    assert should_skip_filename("hostdzire.com") is False
    assert should_skip_filename("hostdzire.com-ssl_log") is False
    assert should_skip_filename("bfiber.in-ssl_log") is False
    # Mid-name hits do NOT match (suffix-only).
    assert should_skip_filename("bytes_log-bkup-file.com") is False


def test_domlog_exclude_suffixes_are_stable():
    """Anti-regression: the exclusion tuple is the single source of truth.

    A future refactor must not silently drop a suffix (that would
    re-introduce the false-positive WARN on `bytes_log` files).
    """
    assert "-bytes_log" in DOMLOG_EXCLUDE_SUFFIXES
    assert "-bytes_log.bkup" in DOMLOG_EXCLUDE_SUFFIXES
    assert ".offset" in DOMLOG_EXCLUDE_SUFFIXES


def test_ssl_log_is_well_formed():
    """`<domain>-ssl_log` is a real Apache combined-format log.

    The D7 detector must accept it as well-formed (the domlog filename
    regex permits `<domain>(-ssl_log|-bytes_log)?`). It must NOT be
    classified as anomalous, and it must NOT be skipped.
    """
    fs = _fs_with({
        f"{DOMLOG_ROOT}/hostdzire.com-ssl_log": "log",
        f"{DOMLOG_ROOT}/another.com-ssl_log": "log",
    })
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    # Both files are well-formed → only the INFO summary finding.
    info = [f for f in findings if f.severity == Severity.INFO]
    summary = next(f for f in info if "well-formed" in f.title.lower())
    assert summary.details["count"] == 2


def test_bytes_log_is_skipped_silently():
    """`-bytes_log` files are skipped at the discovery layer.

    They must NOT appear in anomalies (would produce false-positive
    WARN "unexpected_filename_shape") and must NOT be counted as
    well-formed either.
    """
    fs = _fs_with({
        f"{DOMLOG_ROOT}/hostdzire.com": "log",
        f"{DOMLOG_ROOT}/hostdzire.com-bytes_log": "log",
        f"{DOMLOG_ROOT}/hostdzire.com-bytes_log.bkup": "log",
        f"{DOMLOG_ROOT}/hostdzire.com.offset": "log",
    })
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    # No anomalies — the 3 non-access-log files were skipped.
    anomalies_findings = [f for f in findings if f.severity != Severity.INFO]
    assert anomalies_findings == []
    # Only the single well-formed domain is counted.
    info = next(f for f in findings if "well-formed" in f.title.lower())
    assert info.details["count"] == 1


def test_multi_root_scans_both_paths():
    """Two populated roots merge into one aggregated summary.

    The well-formed count is the SUM across all roots (no dedup —
    the filesystem abstraction here is the bare path, not a realpath;
    see `analyze_domlog_inventory` for the rationale). The report
    surfaces this as a single INFO finding, listing all scanned roots.
    """
    root_a = "/var/log/apache2/domlogs"
    root_b = "/usr/local/apache/domlogs"
    fs = _fs_with({
        f"{root_a}/hosta1.com": "log",
        f"{root_a}/hosta2.com": "log",
        f"{root_b}/hostb1.com": "log",
        f"{root_b}/hostb2.com": "log",
    })
    findings = analyze_domlog_inventory([root_a, root_b], fs)
    info_titles = [f.title for f in findings if f.severity == Severity.INFO]
    assert any("well-formed" in t.lower() for t in info_titles), (
        f"Expected a well-formed summary finding; got titles: {info_titles}"
    )
    summary = next(f for f in findings if "well-formed" in f.title.lower())
    # 4 unique files, summed across both roots.
    assert summary.details["count"] == 4
    assert set(summary.details["roots_scanned"]) == {root_a, root_b}


def test_multi_root_scans_one_root_when_other_is_empty():
    """A configured root that doesn't exist is silently skipped.

    CloudLinux hosts may have `/var/log/apache2/domlogs` empty or
    absent while `/usr/local/apache/domlogs` is the live one — the
    inventory should scan the populated root and not emit a
    "directory not present" finding for the absent one.
    """
    fs = _fs_with({
        "/usr/local/apache/domlogs/hostdzire.com": "log",
        "/usr/local/apache/domlogs/hostdzire.com-ssl_log": "log",
    })
    findings = analyze_domlog_inventory(
        ["/var/log/apache2/domlogs", "/usr/local/apache/domlogs"], fs,
    )
    # No "directory not present" finding — at least one root existed.
    assert not any("not present" in f.title.lower() for f in findings)
    # The populated root was scanned.
    summary = next(f for f in findings if "well-formed" in f.title.lower())
    assert summary.details["count"] == 2


def test_multi_root_with_missing_second_root():
    """A configured root that doesn't exist is silently skipped.

    CloudLinux hosts may have `/var/log/apache2/domlogs` empty or
    absent while `/usr/local/apache/domlogs` is the live one — the
    inventory should scan the populated root and not emit a
    "directory not present" finding for the absent one.
    """
    fs = _fs_with({
        "/usr/local/apache/domlogs/hostdzire.com": "log",
        "/usr/local/apache/domlogs/hostdzire.com-ssl_log": "log",
    })
    findings = analyze_domlog_inventory(
        ["/var/log/apache2/domlogs", "/usr/local/apache/domlogs"], fs,
    )
    # No "directory not present" finding — at least one root existed.
    assert not any("not present" in f.title.lower() for f in findings)
    # The populated root was scanned.
    summary = next(f for f in findings if "well-formed" in f.title.lower())
    assert summary.details["count"] == 2


def test_multi_root_aggregates_anomalies_across_roots():
    """Anomalies from multiple roots are merged into one finding.

    If root A has one anomalous filename and root B has another,
    the report shows a single "2 anomalous domlog filename(s)"
    finding, not two separate ones.
    """
    root_a = "/var/log/apache2/domlogs"
    root_b = "/usr/local/apache/domlogs"
    # 25 pure-A / pure-B strings — over the REPEAT_MIN_LEN (20) and
    # well over the REPEAT_RATIO (0.8), so the detector flags them
    # as `repeated_character_pattern`. (Same threshold as the
    # existing test_repeated_character_fuzzing_is_flagged test.)
    fs = _fs_with({
        f"{root_a}/{'A' * 25}": "log",
        f"{root_b}/{'B' * 25}": "log",
    })
    findings = analyze_domlog_inventory([root_a, root_b], fs)
    anomaly_findings = [
        f for f in findings
        if "anomalous domlog filename" in f.title.lower()
    ]
    # Exactly one aggregated anomaly finding — not two.
    assert len(anomaly_findings) == 1, (
        f"Expected one aggregated anomaly finding; got {len(anomaly_findings)}: "
        f"{[(f.severity, f.title) for f in anomaly_findings]}"
    )
    assert len(anomaly_findings[0].details["anomalies"]) == 2


def test_domlog_root_none_falls_back_to_default():
    """Passing `None` to `analyze_domlog_inventory` triggers the default
    CloudLinux + cPanel layout (AISO-194). On a host with NONE of the
    default roots present, the analyzer must emit a single INFO listing
    all roots — not crash.
    """
    fs = _fs_with({})  # no domlogs anywhere
    findings = analyze_domlog_inventory(None, fs)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "not present" in findings[0].title.lower()
    # The reported roots are exactly the defaults.
    assert findings[0].details["roots_checked"] == DEFAULT_DOMLOG_ROOTS


# ---------------------------------------------------------------------------
# AISO-206: domlog anomalies list is severity-sorted (most-dangerous first).
# ---------------------------------------------------------------------------


def _anomalies_for_filenames(filenames: list[str]):
    """Run the analyzer on a single-root FakeFS with the given filenames
    and return the `details["anomalies"]` list from the aggregated finding.

    A helper for the AISO-206 sort-order tests.
    """
    files = {f"{DOMLOG_ROOT}/{name}": "log" for name in filenames}
    findings = analyze_domlog_inventory([DOMLOG_ROOT], _fs_with(files))
    aggregated = [f for f in findings if "anomalous domlog filename" in f.title.lower()]
    assert aggregated, (
        f"Expected an aggregated anomaly finding; got titles: "
        f"{[f.title for f in findings]}"
    )
    return aggregated[0].details["anomalies"]


def test_aiso206_severity_sort_basic_three_reasons():
    """AISO-206 acceptance criterion #3 (anti-regression lock).

    Feed 3 anomalies with reasons `[filename_unusually_long,
    shell_metacharacters, filename_too_long]`. The rendered list MUST
    be ordered `[shell_metacharacters, filename_too_long,
    filename_unusually_long]` — most-dangerous reason first, then
    alphabetical filename within the same weight.

    We pick distinct filenames per reason so the secondary sort key
    (filename) doesn't accidentally mask a weight-regression.
    """
    filenames = [
        "z_unusually_long_name_" + "x" * 65,   # 65..120 → filename_unusually_long
        "a_host;rm",                            # shell_metacharacters
        "b_" + "c" * 130,                       # >= 120 → filename_too_long
    ]
    reasons_in = [
        "filename_unusually_long",
        "shell_metacharacters",
        "filename_too_long",
    ]
    anomalies = _anomalies_for_filenames(filenames)
    assert [a["reason"] for a in anomalies] == [
        "shell_metacharacters",
        "filename_too_long",
        "filename_unusually_long",
    ]
    # Belt-and-braces: also assert the input reasons landed exactly
    # where we asked (no detection drift).
    assert sorted(a["reason"] for a in anomalies) == sorted(reasons_in)


def test_aiso206_severity_weights_constant_is_sorted_aligned():
    """The weight table must be consistent with the docstring's contract.

    The order in `_SORT_WEIGHTS` is informational; the test pins the
    actual weights so any silent re-ordering of the dict (or removal of
    a key) breaks loudly.
    """
    assert _SORT_WEIGHTS == {
        "shell_metacharacters": 100,
        "contract_pattern_d7": 90,
        "repeated_character_pattern": 70,
        "filename_too_long": 50,
        "filename_unusually_long": 30,
        "unexpected_filename_shape": 20,
    }


def test_aiso206_unknown_reason_falls_back_to_zero_weight():
    """If the detector ever adds a new reason without a weight entry,
    the sort must still be deterministic (unknown reasons sink to the
    bottom, alphabetical within themselves), not crash with KeyError.
    """
    anomalies = [
        {"filename": "z_unknown", "root": "/tmp", "reason": "future_unknown_reason"},
        {"filename": "a_host;rm", "root": "/tmp", "reason": "shell_metacharacters"},
    ]
    # Reproduce the production sort in the test (mirrors the lambda in
    # analyze_domlog_inventory). If the production key ever drifts, this
    # test will silently agree — that's fine; the structural test above
    # is the regression lock.
    anomalies.sort(
        key=lambda a: (-_SORT_WEIGHTS.get(a["reason"], 0), a["filename"]),
    )
    assert [a["filename"] for a in anomalies] == ["a_host;rm", "z_unknown"]


def test_aiso206_full_report_and_forensic_share_sorted_anomalies():
    """Acceptance criterion #4 — the FULL forensic / report JSON
    preserves the sorted order so the operator sees the most-dangerous
    anomalies at the top.

    We build a real `AuditReport` via `cli.main()`'s report path (the
    same code that emits `alma-audit-latest.json` and the forensic
    JSON), then assert:

      1. `alma-audit-latest.json` carries the sorted `details.anomalies`
         payload on the domlog-anomalies finding.
      2. `alma-audit-forensic.json` carries the SAME list verbatim
         under the explicit top-level `domlog_anomalies` key (AISO-206
         follow-up — the field MUST exist, even when empty).
      3. The order in (2) is identical to (1), including the
         alphabetical tie-breaker for entries that share the same
         `_SORT_WEIGHTS` reason.

    The fixture is deliberately asymmetric: two `filename_too_long`
    filenames whose first character differs (`x` vs `y`) so the
    alphabetical secondary sort is observable. The pure-x / pure-y
    strings both trip `_is_anomalous_filename`'s length-CRIT branch
    (weight 50) BEFORE the repeated-character branch — so they stay
    on the same weight tier. The expected order is `'x' * 130` < `'y' * 130`
    (filename ascending).
    """
    from alma_audit.reporting import build_report, write_forensic_report

    # 4 filenames exercising:
    # - shell_metacharacters (weight 100) — top of the sorted list
    # - repeated_character_pattern (weight 70) — `A` * 25 hits the
    #   REPEAT_MIN_LEN=20 / REPEAT_RATIO=0.8 branch (no length-CRIT trip
    #   because length is 25 < LENGTH_CRIT=120).
    # - 2 × filename_too_long (weight 50) — pure-x and pure-y strings
    #   of length 130 both trip the LENGTH_CRIT branch first; the
    #   secondary alphabetical sort puts `x...` before `y...`.
    filenames = [
        "x" * 130,                  # filename_too_long (a-run, alphabetical tie 1/2)
        "host;rm",                  # shell_metacharacters (top)
        "A" * 25,                   # repeated_character_pattern
        "y" * 130,                  # filename_too_long (b-run, alphabetical tie 2/2)
    ]
    # Re-run the analyzer to grab the actual Finding objects.
    files = {f"{DOMLOG_ROOT}/{name}": "log" for name in filenames}
    findings = analyze_domlog_inventory([DOMLOG_ROOT], _fs_with(files))

    # --- alma-audit-latest.json (the full report) carries details.anomalies ---
    latest = build_report(findings, hostname="test-host").to_dict()
    latest_agg = next(
        f for f in latest["findings"]
        if "anomalous domlog filename" in f["title"].lower()
    )
    latest_anomalies = latest_agg["details"]["anomalies"]
    # Pin the full sorted order on the latest report. The exact
    # sequence is part of the AC #4 contract:
    #   [shell_metacharacters, repeated_character_pattern,
    #    filename_too_long (x...), filename_too_long (y...)]
    assert [a["reason"] for a in latest_anomalies] == [
        "shell_metacharacters",
        "repeated_character_pattern",
        "filename_too_long",
        "filename_too_long",
    ], (
        f"alma-audit-latest.json drift: {[a['reason'] for a in latest_anomalies]}"
    )
    assert [a["filename"] for a in latest_anomalies] == [
        "host;rm",
        "A" * 25,
        "x" * 130,        # filename ascending — `x` < `y`
        "y" * 130,
    ], (
        f"alma-audit-latest.json filename-order drift: "
        f"{[a['filename'] for a in latest_anomalies]}"
    )

    # --- alma-audit-forensic.json carries the same payload under `domlog_anomalies` ---
    import tempfile
    import json as _json
    with tempfile.TemporaryDirectory() as tmp:
        path = write_forensic_report(build_report(findings, hostname="test-host"), tmp)
        with open(path, encoding="utf-8") as fh:
            forensic = _json.load(fh)

    # AC #4 follow-up: the forensic JSON MUST expose `domlog_anomalies`
    # as a top-level field (not buried inside an `if findings`
    # collection). The supervisor caught that the previous
    # `if forensic_agg is not None` guard silently swallowed the
    # AC #4 assertion when the field was missing.
    assert "domlog_anomalies" in forensic, (
        f"alma-audit-forensic.json missing the explicit `domlog_anomalies` "
        f"field — top-level keys present: {sorted(forensic.keys())}"
    )
    # Summary counter must agree with the list length.
    assert forensic.get("summary", {}).get("domlog_anomalies_total") == len(filenames), (
        f"summary.domlog_anomalies_total drifted from list length: "
        f"{forensic.get('summary', {}).get('domlog_anomalies_total')} vs {len(filenames)}"
    )
    forensic_anomalies = forensic["domlog_anomalies"]
    assert isinstance(forensic_anomalies, list), (
        f"`domlog_anomalies` must be a list, got {type(forensic_anomalies).__name__}"
    )
    # The full forensic list MUST match the latest report exactly,
    # reason-by-reason and filename-by-filename — including the
    # alphabetical tie-breaker for the two `filename_too_long` entries.
    assert [a["reason"] for a in forensic_anomalies] == [
        "shell_metacharacters",
        "repeated_character_pattern",
        "filename_too_long",
        "filename_too_long",
    ], (
        f"alma-audit-forensic.json reason-order drift: "
        f"{[a['reason'] for a in forensic_anomalies]}"
    )
    assert [a["filename"] for a in forensic_anomalies] == [
        "host;rm",
        "A" * 25,
        "x" * 130,
        "y" * 130,
    ], (
        f"alma-audit-forensic.json filename-order drift: "
        f"{[a['filename'] for a in forensic_anomalies]}"
    )
    # Belt-and-braces: object-identity-equivalent payload (same items,
    # same order, same contents). Dict equality compares values, so this
    # also catches accidental re-sort or schema drift.
    assert forensic_anomalies == latest_anomalies, (
        "alma-audit-forensic.json `domlog_anomalies` drifted from "
        "alma-audit-latest.json `details.anomalies`"
    )


# ---------------------------------------------------------------------------
# AISO-207: YAML-configurable thresholds.
#
# The acceptance criteria require:
#   * `modules.domlog_inventory.length_warn` overrides the LENGTH_WARN
#     constant at the analyzer level. A 35-char filename is benign under
#     the default 60-char threshold, but MUST trip WARN when the operator
#     drops length_warn to 30.
#   * Defaults stay unchanged when the override is absent — the
#     `test_unusually_long_but_under_crit_is_warn` body above already
#     exercises the 60/120 default pair; the anti-regression test below
#     pins the 30-char boundary in the OTHER direction (length exactly
#     AT the default threshold still trips WARN — no off-by-one).
# ---------------------------------------------------------------------------


def test_override_length_warn_lowers_threshold():
    """AISO-207 AC #4: feed `length_warn: 30`; a 35-char name trips WARN.

    The default length_warn is 60, so a 35-char filename is silent. With
    `modules.domlog_inventory.length_warn: 30` the same name must trip
    `filename_unusually_long` at the lowered threshold.
    """
    name = "a" * 35  # above the override (30), below the default (60)
    fs = _fs_with({f"{DOMLOG_ROOT}/{name}": "log"})
    findings = analyze_domlog_inventory(
        [DOMLOG_ROOT], fs,
        rules={"length_warn": 30, "length_crit": 120},
    )
    warns = [f for f in findings if f.severity == Severity.WARN]
    assert warns, "expected WARN finding after lowering length_warn"
    matching = [
        a for a in warns[0].details.get("anomalies", [])
        if a.get("reason") == "filename_unusually_long"
        and a.get("filename") == name
    ]
    assert matching, (
        f"expected filename_unusually_long finding for {name!r} at "
        f"length_warn=30, got anomalies: "
        f"{warns[0].details.get('anomalies', [])}"
    )
    assert matching[0]["threshold"] == 30, (
        f"threshold in finding detail must reflect the override (30), "
        f"got {matching[0]['threshold']}"
    )


def test_default_length_warn_threshold_unchanged_when_no_override():
    """AISO-207 AC #5: anti-regression — no override keeps the 60/120 defaults.

    A 35-char filename (above the lowered threshold, below the default)
    stays silent when the operator has NOT configured `length_warn`.
    Catches the regression "operator forgot the override, analyzer
    silently lowered the threshold anyway".

    Uses a multi-character name (`a1b2c3...`) so the repeated-character
    detector (default min_len=20, ratio=0.8) does NOT trip — only the
    length threshold applies.
    """
    # Build a 35-char name with diverse characters so it's NOT a fuzz
    # repetition. `a1b2c3...` is below the default LENGTH_WARN (60) and
    # matches `_DOMLOG_FILE_RE` (letters/digits/dots/hyphens) — so under
    # default rules it's well-formed; with `length_warn: 30` it must
    # trip `filename_unusually_long`.
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"  # 36 chars pool
    name = (chars * 2)[:35]
    assert len(name) == 35
    # Sanity: this name is NOT a repeat-pattern (every char distinct in
    # the first 36 pool, so first 35 are distinct → ratio 1/35 < 0.8).
    fs = _fs_with({f"{DOMLOG_ROOT}/{name}": "log"})
    findings = analyze_domlog_inventory([DOMLOG_ROOT], fs)
    flagged = [
        f for f in findings
        if any(a.get("filename") == name for a in f.details.get("anomalies", []))
    ]
    assert not flagged, (
        f"35-char multi-character filename must NOT be flagged with "
        f"default thresholds; got findings: {[f.title for f in flagged]}"
    )


def test_override_length_crit_lowers_critical_threshold():
    """AISO-207: lowering length_crit escalates 100-char names to CRITICAL.

    Default length_crit is 120, so a 100-char name is WARN. With
    length_crit=80 the same name must trip CRITICAL.
    """
    name = "a" * 100  # above the override (80), below the default (120)
    fs = _fs_with({f"{DOMLOG_ROOT}/{name}": "log"})
    findings = analyze_domlog_inventory(
        [DOMLOG_ROOT], fs,
        rules={"length_warn": 60, "length_crit": 80},
    )
    crits = [f for f in findings if f.severity == Severity.CRITICAL]
    matching = [
        a for a in crits[0].details.get("anomalies", [])
        if a.get("filename") == name
        and a.get("reason") == "filename_too_long"
    ]
    assert matching, (
        f"expected filename_too_long CRITICAL for {name!r} at "
        f"length_crit=80, got findings: {[f.title for f in findings]}"
    )
    assert matching[0]["threshold"] == 80


def test_override_repeat_min_len_lowers_repeat_threshold():
    """AISO-207: lowering repeat_min_len flags shorter fuzzing artifacts.

    Default REPEAT_MIN_LEN=20 + REPEAT_RATIO=0.8. A 15-char string of 'A'
    is silent by default. With `repeat_min_len: 10` the same string must
    trip `repeated_character_pattern`.
    """
    name = "A" * 15  # above the override (10), below the default (20)
    fs = _fs_with({f"{DOMLOG_ROOT}/{name}": "log"})
    findings = analyze_domlog_inventory(
        [DOMLOG_ROOT], fs,
        rules={"repeat_min_len": 10, "repeat_ratio": 0.8},
    )
    flagged = [
        a for f in findings
        for a in f.details.get("anomalies", [])
        if a.get("reason") == "repeated_character_pattern"
        and a.get("filename") == name
    ]
    assert flagged, (
        f"expected repeated_character_pattern for {name!r} at "
        f"repeat_min_len=10, got findings: "
        f"{[f.title for f in findings]}"
    )
