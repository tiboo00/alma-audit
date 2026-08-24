"""Per-domain domlog inventory anomaly detector.

cPanel / WHMCS hosts place per-domain Apache access logs under
`/var/log/apache2/domlogs`. The directory layout itself is a security
signal — the user described entries like:

    bfiber
    bfiberco
    bfiber.co.in
    bfiber.co.in-ssl_log
    bfiber.in
    bfiber.in-bytes_log
    bfiber.in-ssl_log
    hostdzire.com
    hostdzire.com-bytes_log
    hostdzire.com-ssl_log
    ...számos szokatlanul hosszú `hostdzi...` / `hostdziAAAA...` nevű
    bejegyzést.

So a domlog entry is *expected* to be a short domain-shaped name or
`<domain>(-ssl_log|-bytes_log)`. Anything that diverges — overly long,
contains shell metacharacters, or matches no expected suffix — is a
finding.

We also check for unexpected sub-directories (the user mentioned
`domlogs/zmrk2md30edvm/`, which is a cPanel account id, not a real
domain; that's worth flagging).

D7 detector — the binding pattern comes from the AISO-119 detection
contract §4.5. The detector runs the §4.5.1 4-step normalisation
(strip cPanel suffixes, trailing dot+port, percent-decode, control
chars) and then matches the §4.5.2 case-sensitive regex. The regex
deliberately has NO `re.IGNORECASE` flag — case-folding was removed
in v1.2 to close the `Foo-Bar-BBBBBBB` false-positive hole. The
contract §4.5.4 corpus is the regression lock: a 31-case parametrize
test asserts the raw input → final result contract.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import Finding, Severity
from ..runners import FileSystem
from .domlog_roots import DEFAULT_DOMLOG_ROOTS, should_skip_filename

# A "normal" domlog name: a domain, optionally followed by -ssl_log
# or -bytes_log. Domain itself: letters/digits/dots/hyphens only.
_DOMLOG_FILE_RE = re.compile(r"^(?P<domain>[A-Za-z0-9.\-]+)(?:-(?P<suffix>ssl_log|bytes_log))?$")

# Shell metacharacters that should NEVER appear in a domlog filename.
SHELL_METACHARS = set(";|&$`<>(){}[]!?\"'\\")

# Default rule thresholds (AISO-207). Operators override these via the
# YAML config (`modules.domlog_inventory.*`). The single source of
# truth lives here so a `grep DEFAULT_RULES` finds every threshold in
# one place.
DEFAULT_RULES: dict[str, Any] = {
    # Filename length heuristics. The §4.5 corpus long names are at most
    # ~70 chars; anything past 60 is unusual on a real cPanel host.
    "length_warn": 60,
    "length_crit": 120,
    # Repeated-character fuzzing artifact: a single char >=80% of the
    # name AND name length >=20. Lowering either threshold catches
    # shorter fuzz names.
    "repeat_min_len": 20,
    "repeat_ratio": 0.8,
    # Discovery-layer caps (AISO-198). See analyze_domlog_inventory
    # below for the rationale.
    "max_entries": 1000,
    # Walk one level deep so we descend into cPanel account-ID
    # sub-directories (`<root>/<account>/<domain>`). Override via YAML
    # if your layout nests deeper.
    "max_subdir_depth": 1,
    "max_files": 10000,  # cap across the whole walk to bound the scan
}


# Backwards-compat aliases — existing callers (and downstream tooling
# that imports these as named constants) keep working. The analyzer
# itself now reads from `DEFAULT_RULES`; the constants below are
# derived so a `grep LENGTH_WARN` still surfaces them.
LENGTH_WARN = DEFAULT_RULES["length_warn"]
LENGTH_CRIT = DEFAULT_RULES["length_crit"]
REPEAT_MIN_LEN = DEFAULT_RULES["repeat_min_len"]
REPEAT_RATIO = DEFAULT_RULES["repeat_ratio"]


# A filename made entirely of repeated single characters ("AAAAAAA...")
# is a classic fuzzing artifact. We flag names where one character is
# >= 80% of the length AND the length is at least 20. The actual
# threshold pair is read from `settings` at analyze time (AISO-207).


# ---------------------------------------------------------------------------
# AISO-206: severity weights for the `anomalies` list ordering.
#
# The aggregator emits findings in filesystem iteration order, which
# buries the most-dangerous anomalies (shell-metachar injection
# attempts, exact D7 corpus hits) in the middle of a long tail of
# "filename too long" reports. We sort the list by `_SORT_WEIGHTS`
# (most-dangerous first) before rendering, so the operator sees the
# attack-style anomalies at the top of the JSON / forensic export.
#
# The weight is a per-reason integer; the sort key is
# `(weight, filename)` with `reverse=True`, so ties on weight are
# broken alphabetically by filename (descending → Z..A within the
# same weight).
# ---------------------------------------------------------------------------
_SORT_WEIGHTS: dict[str, int] = {
    "shell_metacharacters": 100,            # RCE / injection attempt
    "contract_pattern_d7": 90,              # corpus-exact, fuzzing pattern
    "repeated_character_pattern": 70,       # fuzzing artifact
    "filename_too_long": 50,                # D7 trigger
    "filename_unusually_long": 30,          # D7 soft trigger
    "unexpected_filename_shape": 20,        # mild anomaly
}


# ---------------------------------------------------------------------------
# D7 §4.5.2 — binding detector regex (AISO-119 v1.2 contract).
#
# IMPORTANT: This regex is the authoritative "hostdziAAAA..." detector per
# the detection contract. It is case-SENSITIVE on purpose:
#   - v1.0 used re.IGNORECASE which made case-1's [A-Z]{6,} match [a-z]{6,}
#     too, producing FPs like "abcdefghijklmnopqrst(.com)".
#   - v1.2 removed the global flag and inlined per-branch case discipline;
#     case-1 now requires a transition from lowercase → UPPERCASE.
#   - v1.2 §4.5.4 31-case corpus is the regression lock; flipping any of
#     cases #11–#13 (the FP cases) to True, or cases #29–#31 (all-uppercase
#     hostdzi-style) to True without a v1.3 spec, is a regression.
# ---------------------------------------------------------------------------
DOMLOG_BAD_NAME = re.compile(
    r"""^
    (?:
        # Case 1: lowercase alpha/digit/dash prefix (>= 4 chars, starting
        # with [a-z]) immediately followed by a UPPERCASE/digit run
        # (>= 6 chars) with NO lowercase reversion. Matches the
        # 'hostdziAAAAAA...' pattern. Inputs are matched verbatim — no
        # case-folding is applied before this point.
        [a-z][a-z0-9-]{3,14}[A-Z][A-Z0-9]{5,}\Z

        | # Case 2: long mixed-case alphanumeric (>= 20 chars) with at
          # least one lowercase AND one uppercase. Catches
          # 'AaBbCcDdEeFfGgHhIiJj1234567890'.
        (?=[A-Za-z0-9]{20,}\Z)
        (?=[A-Za-z0-9]*[a-z])
        (?=[A-Za-z0-9]*[A-Z])
        [A-Za-z0-9]+\Z

        | # Case 3: short punycode prefix + valid TLD.
        xn--[a-z0-9]{0,3}\.[a-z]{2,}\Z

        | # Case 4: pure-numeric hostname (DNS rebinding / squat).
        [0-9]+\.[a-z]+\Z

        | # Case 5: long string containing 'xn--' anywhere.
        (?=.{30,}).*xn--

        | # Case 6: known-abused TLD.
        .*\.(zip|mov|tk|ml|ga|cf|gq)\Z
    )
    """,
    re.VERBOSE,
    # NO re.IGNORECASE — see docstring and AISO-119 v1.2 §4.5.2.
)


# Cached §4.5.1 step-1 suffix patterns. Order matters: longest first so
# `-bytes_log` is stripped before `-ssl_log` doesn't false-match `-ssl`.
_CPANEL_SUFFIXES = (
    "-bytes_log",
    "-ssl_log",
    ".gz",
    ".bz2",
)
_CPANEL_ROTATION_RE = re.compile(r"\.(?:\d+|\d{8}|\d{4}_\d{2}_\d{2})\Z")
_TRAILING_DOT_PORT_RE = re.compile(r"[\.:]\d+\Z")


def _normalise_for_d7(name: str) -> str:
    """Apply the §4.5.1 4-step pre-normalisation pipeline (case-preserving).

    Step 1: Strip cPanel suffix tokens (`-ssl_log`, `-bytes_log`, `.gz`,
            rotation suffixes).
    Step 2: Strip trailing dot + port (e.g. `host:443`).
    Step 3: Percent-decode (e.g. `%2E` → `.`).
    Step 4: Replace control characters / null bytes with literal `?`.

    NO case-folding is performed (v1.2 contract; the regex itself handles
    case discipline). Inputs are matched verbatim after these 4 steps.
    """
    # Step 1: cPanel suffixes. Strip in order, repeatedly, so e.g.
    # `host-ssl_log.1.gz` → `host-ssl_log` → `host`.
    s = name
    changed = True
    while changed:
        changed = False
        for suf in _CPANEL_SUFFIXES:
            if s.endswith(suf):
                s = s[: -len(suf)]
                changed = True
                break
        if _CPANEL_ROTATION_RE.search(s):
            s = _CPANEL_ROTATION_RE.sub("", s)
            changed = True
    # Step 2: trailing dot + port.
    s = _TRAILING_DOT_PORT_RE.sub("", s)
    # Step 3: percent-decode (best-effort, no exception on malformed %).
    try:
        # urllib would split the whole string on `+` as form-decoding; we
        # only want percent-decode, so use stdlib's unquote only for %XX
        # sequences, ignoring `+` as data.
        from urllib.parse import unquote
        if "%" in s:
            s = unquote(s)
    except Exception:
        # Bad percent encoding is left as-is; the regex will simply not
        # match it (and §4.5.4 corpus doesn't exercise malformed %).
        pass
    # Step 4: control characters → "?". Use a translator table rather than
    # any case-folding.
    import string

    _ctrl_table = str.maketrans(
        {c: "?" for c in (string.whitespace + "".join(chr(c) for c in range(32)) + "\x7f") if c and c not in ("-", "_", ".")}
    )
    s = s.translate(_ctrl_table)
    return s


def _matches_contract_pattern(name: str) -> bool:
    """True if the domlog name (raw input) matches the §4.5.2 regex.

    This is the v1.2 contract's binding D7 detector. Inputs go through
    the §4.5.1 normalisation pipeline verbatim — no case-folding.
    """
    return bool(DOMLOG_BAD_NAME.match(_normalise_for_d7(name)))


def _is_anomalous_filename(
    name: str,
    *,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return a reason dict if the domlog filename is anomalous, else None.

    Combines length/metachar/repeat heuristics with the §4.5.2 regex.
    All four numeric thresholds come from `settings` (AISO-207) —
    callers that pass `None` get the module-level defaults via
    `DEFAULT_RULES`.
    """
    cfg = settings if settings is not None else DEFAULT_RULES
    length_warn = int(cfg["length_warn"])
    length_crit = int(cfg["length_crit"])
    repeat_min_len = int(cfg["repeat_min_len"])
    repeat_ratio = float(cfg["repeat_ratio"])

    if len(name) >= length_crit:
        return {"reason": "filename_too_long", "length": len(name), "threshold": length_crit}
    if len(name) >= length_warn:
        return {"reason": "filename_unusually_long", "length": len(name), "threshold": length_warn}

    bad_chars = sorted({c for c in name if c in SHELL_METACHARS})
    if bad_chars:
        return {"reason": "shell_metacharacters", "chars": bad_chars}

    # repeated-character fuzzing pattern
    if len(name) >= repeat_min_len:
        from collections import Counter
        most_common_char, char_count = Counter(name).most_common(1)[0]
        if char_count / len(name) >= repeat_ratio:
            return {
                "reason": "repeated_character_pattern",
                "char": most_common_char,
                "ratio": char_count / len(name),
            }

    # D7 contract §4.5.2 binding regex match.
    if _matches_contract_pattern(name):
        return {"reason": "contract_pattern_d7", "matched_pattern": DOMLOG_BAD_NAME.pattern[:60] + "..."}

    # If it doesn't match the domlog shape at all, that's worth a softer note
    # (it could be a stray temp file).
    if not _DOMLOG_FILE_RE.match(name):
        return {"reason": "unexpected_filename_shape"}
    return None


def _walk_and_classify(
    *,
    root: str,
    entries: list[str],
    fs: FileSystem,
    seen_paths: set[str],
    all_anomalies: list[dict[str, Any]],
    all_subdirs: list[dict[str, str]],
    total_well_formed_ref: int,
    settings: dict[str, Any],
    max_depth: int,
    files_visited_ref: int,
    max_files_total: int,
) -> tuple[int, int]:
    """Recursive walk of a domlog directory, classifying each entry.

    Returns (well_formed_count, files_visited) updated totals. Mutates
    `all_anomalies`, `all_subdirs`, `seen_paths` in place.
    """
    well_formed = total_well_formed_ref
    files_visited = files_visited_ref

    def _walk(current_root: str, current_entries: list[str], depth: int) -> None:
        nonlocal well_formed, files_visited
        for name in current_entries:
            if should_skip_filename(name):
                continue
            full = f"{current_root.rstrip('/')}/{name}"
            if full in seen_paths:
                continue
            seen_paths.add(full)

            if fs.is_dir(full):
                # AISO-198: cPanel account-ID sub-directories are
                # normal layout, not an anomaly. We record them in
                # `all_subdirs` for the scope-info finding but do NOT
                # flag them as CRITICAL/WARN — only filenames INSIDE
                # the sub-directory are checked for anomalies.
                all_subdirs.append({"subdir": name, "root": current_root})
                if depth < max_depth:
                    try:
                        sub_entries = fs.listdir(full)
                    except OSError:
                        # Sub-directory unreadable — skip silently.
                        # The top-level WARN finding already covered
                        # the broad case; per-subdir unreadability is
                        # a separate operator concern.
                        continue
                    _walk(full, sub_entries, depth + 1)
                continue

            # Leaf entry — feed to the anomaly detector.
            if files_visited >= max_files_total:
                return
            files_visited += 1
            reason = _is_anomalous_filename(name, settings=settings)
            if reason is not None:
                all_anomalies.append({
                    "filename": name,
                    "root": current_root,
                    **reason,
                })
            else:
                well_formed += 1

    _walk(root, entries, depth=0)
    return well_formed, files_visited


def analyze_domlog_inventory(
    domlog_roots: list[str] | None,
    fs: FileSystem,
    rules: dict[str, Any] | None = None,
) -> list[Finding]:
    """Scan one or more domlog directories (recursively) and emit findings.

    `domlog_roots` is a list of directories to walk. Pass `None` to use
    the default CloudLinux / cPanel layout
    (`DEFAULT_DOMLOG_ROOTS` from `domlog_roots.py`). Each existing
    root is scanned independently; findings from all roots are merged.

    Filenames ending in `-bytes_log`, `-bytes_log.bkup`, or `.offset`
    are skipped at the discovery layer — see `domlog_roots.py` for the
    rationale (mod_log_config byte-counters and cPanel offset backups
    are not Apache combined-format logs).

    AISO-198: sub-directories are walked one level deep (default
    `max_subdir_depth = 1`). On a CloudLinux / cPanel host the canonical
    layout is `/var/log/apache2/domlogs/<cpanel-account-id>/<domain>` —
    the `<cpanel-account-id>` sub-directory is the **normal** layout,
    not an anomaly. The 8-char random account ID is what cPanel writes
    when the account is created. Operators with a deeper nesting
    (e.g. `<user>/<year>/<domain>`) can override `max_subdir_depth`
    via `modules.domlog_inventory.max_subdir_depth` in YAML.
    """
    settings = {
        **DEFAULT_RULES,
        **(rules or {}),
    }
    max_depth = max(0, int(settings.get("max_subdir_depth", 1)))
    max_files_total = int(settings.get("max_files", 10000))
    roots = list(domlog_roots) if domlog_roots is not None else list(DEFAULT_DOMLOG_ROOTS)

    findings: list[Finding] = []

    # Aggregated across all roots. A file appearing under both roots
    # (e.g. when /var/log/apache2/domlogs is a symlink tree of
    # /usr/local/apache/domlogs) WILL be counted twice — the
    # filesystem abstraction here is the bare path, not a realpath.
    # Operators who want single-count semantics can dedupe at the
    # reporting layer (examples/audit-diff.py works on the report,
    # not the inventory). The upside is correctness: every root the
    # operator explicitly listed is honored, and a cPanel host with
    # two genuinely distinct file populations (e.g. addons outside
    # the symlink tree) gets a complete inventory.
    total_well_formed = 0
    all_anomalies: list[dict[str, Any]] = []
    all_subdirs: list[dict[str, str]] = []
    any_root_existed = False
    any_root_unreadable = False
    seen_paths: set[str] = set()
    files_visited = 0

    for root in roots:
        if not fs.is_dir(root):
            continue
        any_root_existed = True

        # Defense in depth: wrap listdir so an ``fs`` substitute that
        # raises PermissionError (e.g. AISO-124 tests) still produces
        # a WARN, not a traceback. RealFileSystem.listdir already
        # swallows PermissionError at the runner layer; this
        # try/except is for non-Production runners that re-raise.
        try:
            top_level_entries = fs.listdir(root)
        except OSError as exc:
            any_root_unreadable = True
            findings.append(Finding(
                module="domlog_inventory",
                severity=Severity.WARN,
                title="domlog directory is unreadable",
                description=(
                    f"Could not list {root!r}: {exc}. "
                    "This is usually a permission problem — the audit user "
                    "needs at least read+execute on the directory."
                ),
                details={"path": root, "error": str(exc), "errno": getattr(exc, "errno", None)},
                recommendation=(
                    "Fix the directory permissions (e.g. `chmod a+rx` for "
                    "the audit user or grant the user group membership)."
                ),
            ))
            continue

        # Distinguish "directory is empty" from "directory exists but is
        # unreadable" so the operator gets an actionable signal.
        if not top_level_entries and not fs.is_readable_dir(root):
            any_root_unreadable = True
            findings.append(Finding(
                module="domlog_inventory",
                severity=Severity.WARN,
                title="domlog directory is unreadable",
                description=(
                    f"{root!r} is a directory but could not be listed "
                    "(permission denied). The audit cannot enumerate domlog "
                    "filenames."
                ),
                details={"path": root},
                recommendation=(
                    "Grant the audit user read+execute on the domlog root."
                ),
            ))
            continue

        if len(top_level_entries) > settings["max_entries"]:
            findings.append(Finding(
                module="domlog_inventory",
                severity=Severity.WARN,
                title="Domlog directory is unexpectedly large",
                description=(
                    f"Found {len(top_level_entries)} top-level entries under {root!r} "
                    f"(threshold {settings['max_entries']}). Either the host "
                    "is multi-tenant at very large scale, or the directory is "
                    "being polluted."
                ),
                details={"count": len(top_level_entries), "path": root},
            ))

        # AISO-198: walk recursively up to `max_depth` levels. We classify
        # top-level entries by `fs.is_dir` and recurse into them; leaf
        # entries go through the anomaly detector. The `seen_paths`
        # set still keys on absolute path so symlinked or duplicated
        # entries (across multi-root) are deduped.
        total_well_formed, files_visited = _walk_and_classify(
            root=root,
            entries=top_level_entries,
            fs=fs,
            seen_paths=seen_paths,
            all_anomalies=all_anomalies,
            all_subdirs=all_subdirs,
            total_well_formed_ref=total_well_formed,
            settings=settings,
            max_depth=max_depth,
            files_visited_ref=files_visited,
            max_files_total=max_files_total,
        )

    if not any_root_existed:
        # None of the configured roots exist. Emit a single INFO
        # listing all of them so the operator can see why no scan ran.
        findings.append(Finding(
            module="domlog_inventory",
            severity=Severity.INFO,
            title="domlog directory not present",
            description=(
                "None of the configured domlog roots exist on this host. "
                "On a CloudLinux / cPanel box, check both "
                "/var/log/apache2/domlogs and /usr/local/apache/domlogs."
            ),
            details={"roots_checked": roots},
        ))
        return findings

    if any_root_unreadable:
        # Findings for unreadable roots are already appended inside the
        # loop; we don't add a second aggregated one to avoid duplication.
        pass

    if all_subdirs:
        # AISO-198: cPanel account-ID sub-directories (8-12 chars,
        # alphanumeric with optional `_`/`-`) are normal layout:
        # `/var/log/apache2/domlogs/<account>/<domain>`. Only flag
        # CRITICAL/WARN when the layout is genuinely suspicious, e.g.
        # `nested_2024_q1/` or `user/year/month/` structures that
        # bypass the standard analyzer.
        # Detection: a sub-directory is "account-id shaped" if its
        # name is alphanumeric (`_`/`-` allowed), length 4..16, and
        # contains no underscores (cPanel account IDs are pure
        # alphanumeric or with single hyphens).
        import re as _re
        _ACCT_SHAPE = _re.compile(r"^[A-Za-z][A-Za-z0-9-]{3,15}$")
        non_account_subdirs = [
            s for s in all_subdirs
            if not _ACCT_SHAPE.match(s["subdir"])
        ]
        if non_account_subdirs:
            # Genuinely suspicious layout — original CRITICAL/WARN.
            sev = Severity.CRITICAL if len(non_account_subdirs) > 1 else Severity.WARN
            findings.append(Finding(
                module="domlog_inventory",
                severity=sev,
                title=f"Unexpected sub-directory layout: {len(non_account_subdirs)}",
                description=(
                    "Domlog files are expected to be flat per-domain "
                    "entries, or under cPanel account-ID sub-directories "
                    "(`<root>/<account>/<domain>`). Non-account-shaped "
                    "sub-directories usually indicate a misconfigured "
                    "addon domain or a custom logrotate layout."
                ),
                details={"subdirectories": non_account_subdirs},
                recommendation="Inspect the subdirectory layout.",
            ))
        else:
            # AISO-198: account-ID sub-directories are normal scope-info.
            findings.append(Finding(
                module="domlog_inventory",
                severity=Severity.INFO,
                title=f"{len(all_subdirs)} cPanel account sub-director{'y' if len(all_subdirs) == 1 else 'ies'} scanned",
                description=(
                    f"Walked {len(all_subdirs)} cPanel account "
                    f"sub-direct{'y' if len(all_subdirs) == 1 else 'ies'} "
                    f"(recursive scan up to depth {max_depth}). Domain "
                    "files inside each sub-directory are included in the "
                    "inventory totals."
                ),
                details={"subdirectories": all_subdirs},
            ))

    # AISO-206: sort anomalies by reason-weight (most-dangerous first), then
    # alphabetically by filename (ascending). Without this, the list is in
    # filesystem iteration order, which buries attack-style anomalies
    # (shell-metachar injection attempts, exact D7 corpus hits) inside a
    # long tail of "filename too long" reports. Both `alma-audit-latest.json`
    # (the full report) and `alma-audit-forensic.json` (AISO-199) carry the
    # same `details.anomalies` payload via `report.findings`, so a single
    # sort here propagates to both artifacts.
    if all_anomalies:
        all_anomalies.sort(
            key=lambda a: (-_SORT_WEIGHTS.get(a["reason"], 0), a["filename"]),
        )
        crit = sum(1 for a in all_anomalies if a["reason"] in {"filename_too_long", "shell_metacharacters"})
        sev = Severity.CRITICAL if crit else Severity.WARN
        findings.append(Finding(
            module="domlog_inventory",
            severity=sev,
            title=f"{len(all_anomalies)} anomalous domlog filename(s)",
            description=(
                "One or more entries in the domlog directory do not match the "
                "expected per-domain layout (e.g. 'hostdzire.com', "
                "'hostdzire.com-ssl_log'). Examples include overlong names "
                "(fuzzing), shell metacharacters (injection attempt), or "
                "single-character repetitions."
            ),
            details={"anomalies": all_anomalies, "well_formed_count": total_well_formed},
            recommendation=(
                "Quarantine and review these filenames; they are almost never "
                "generated by a legitimate cPanel account."
            ),
        ))
    else:
        findings.append(Finding(
            module="domlog_inventory",
            severity=Severity.INFO,
            title=f"{total_well_formed} well-formed domlog file(s)",
            description=(
                f"All domlog entries across {len(roots)} root(s) match the "
                "expected layout. -bytes_log and offset backups are "
                "intentionally skipped."
            ),
            details={"roots_scanned": [r for r in roots if fs.is_dir(r)], "count": total_well_formed},
        ))

    return findings
