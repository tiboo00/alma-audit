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

# Filenames longer than this are suspicious. Real domains (e.g. very long
# TLD chains) rarely exceed 60 chars; anything past 80 is almost always
# junk.
LENGTH_WARN = 60
LENGTH_CRIT = 120

# A filename made entirely of repeated single characters ("AAAAAAA...")
# is a classic fuzzing artifact. We flag names where one character is
# >= 80% of the length AND the length is at least 20.
REPEAT_MIN_LEN = 20
REPEAT_RATIO = 0.8


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


def _is_anomalous_filename(name: str) -> dict[str, Any] | None:
    """Return a reason dict if the domlog filename is anomalous, else None.

    Combines length/metachar/repeat heuristics with the §4.5.2 regex.
    """
    if len(name) >= LENGTH_CRIT:
        return {"reason": "filename_too_long", "length": len(name), "threshold": LENGTH_CRIT}
    if len(name) >= LENGTH_WARN:
        return {"reason": "filename_unusually_long", "length": len(name), "threshold": LENGTH_WARN}

    bad_chars = sorted({c for c in name if c in SHELL_METACHARS})
    if bad_chars:
        return {"reason": "shell_metacharacters", "chars": bad_chars}

    # repeated-character fuzzing pattern
    if len(name) >= REPEAT_MIN_LEN:
        from collections import Counter
        most_common_char, char_count = Counter(name).most_common(1)[0]
        if char_count / len(name) >= REPEAT_RATIO:
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


def analyze_domlog_inventory(
    domlog_roots: list[str] | None,
    fs: FileSystem,
    rules: dict[str, Any] | None = None,
) -> list[Finding]:
    """Scan one or more domlog directories and emit findings for anomalies.

    `domlog_roots` is a list of directories to walk. Pass `None` to use
    the default CloudLinux / cPanel layout
    (`DEFAULT_DOMLOG_ROOTS` from `domlog_roots.py`). Each existing
    root is scanned independently; findings from all roots are merged.

    Filenames ending in `-bytes_log`, `-bytes_log.bkup`, or `.offset`
    are skipped at the discovery layer — see `domlog_roots.py` for the
    rationale (mod_log_config byte-counters and cPanel offset backups
    are not Apache combined-format logs).
    """
    settings = {
        "max_entries": 1000,
        "max_subdir_depth": 0,  # domlogs should be flat — subdirs are suspect
        **(rules or {}),
    }
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
            names = fs.listdir(root)
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
        if not names and not fs.is_readable_dir(root):
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

        if len(names) > settings["max_entries"]:
            findings.append(Finding(
                module="domlog_inventory",
                severity=Severity.WARN,
                title="Domlog directory is unexpectedly large",
                description=(
                    f"Found {len(names)} entries under {root!r} "
                    f"(threshold {settings['max_entries']}). Either the host "
                    "is multi-tenant at very large scale, or the directory is "
                    "being polluted."
                ),
                details={"count": len(names), "path": root},
            ))

        for name in names:
            # Skip mod_log_config byte counters and cPanel offset
            # backups at the discovery layer so they don't trip the
            # filename-shape detector. Real access logs (`<domain>`,
            # `<domain>-ssl_log`) are not affected.
            if should_skip_filename(name):
                continue

            full = f"{root.rstrip('/')}/{name}"

            if fs.is_dir(full):
                all_subdirs.append({"subdir": name, "root": root})
                continue
            reason = _is_anomalous_filename(name)
            if reason is not None:
                all_anomalies.append({"filename": name, "root": root, **reason})
            else:
                total_well_formed += 1

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
        # Subdirectories under domlogs are a structural anomaly. cPanel
        # writes a flat list of per-domain files there. A subdir like
        # `domlogs/zmrk2md30edvm/hostdzire.com` indicates that an account
        # ID was used as a directory name — almost always an error or a
        # misconfigured addon domain.
        sev = Severity.CRITICAL if len(all_subdirs) > 1 else Severity.WARN
        findings.append(Finding(
            module="domlog_inventory",
            severity=sev,
            title=f"Unexpected sub-directory under domlogs: {len(all_subdirs)}",
            description=(
                "Domlog files are expected to be flat per-domain entries. "
                "Sub-directories usually indicate an account-id layout (e.g. "
                "/domlogs/<cpanel-user>/) that bypasses standard log parsing."
            ),
            details={"subdirectories": all_subdirs},
            recommendation="Inspect the subdirectory layout; cPanel addons often misbehave here.",
        ))

    if all_anomalies:
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
