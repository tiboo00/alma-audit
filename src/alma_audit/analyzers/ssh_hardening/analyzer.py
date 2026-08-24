"""Public entry point for the ssh_hardening analyzer.

Orchestrates the parser, aggregator, and rules. Walks the main
``sshd_config`` + ``Include`` graph inline (lex-sorted glob
expansion at each ``Include`` directive's position, per
``sshd_config(5)`` semantics) and applies the first-obtained-wins
rule for every scalar directive via the aggregator.

External callers import ``analyze_ssh_config`` from this module; the
package re-exports the public API in ``__init__.py``.

The analyzer does NOT shell out to ``sshd -T`` — the read-only
contract forbids subprocess. The OpenSSH source-of-truth parser is
re-implemented in ``parser.py``; the operator can run ``sshd -T -f
/etc/ssh/sshd_config`` manually if they need exact OpenSSH
semantics (e.g. ``Match`` blocks).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ...models import Finding, Severity
from ...runners import FileSystem
from .aggregator import (
    SshdConfigSnapshot,
    apply_directive,
    finalize,
    new_snapshot,
)
from .parser import parse_sshd_config
from .rules import all_findings
from .settings import (
    DEFAULT_RULES,
    DEFAULT_SSHD_CONFIG_PATH,
    DEFAULT_SSHD_DROP_IN_DIR,
)

_LOG = logging.getLogger("alma_audit")


# Directives we never feed into the aggregator as data — they are
# control directives that the analyzer expands inline. ``Include`` is
# the only one we recognise in this position.
_INCLUDE_KEY = "include"


def _expand_include(
    pattern: str,
    *,
    include_from: str,
    fs: FileSystem,
) -> list[str]:
    """Resolve an ``Include`` pattern to a lex-sorted list of paths.

    Per ``sshd_config(5)``:
      * "Multiple pathnames may be specified and each pathname may
        contain glob(7) wildcards that will be expanded and processed
        in lexical order."
      * "Files without absolute paths are assumed to be in
        /etc/ssh."
      * "An Include directive may appear inside a Match block to
        perform conditional inclusion." — we skip ``Match`` blocks
        entirely (posture audit, not per-user), so this clause is
        intentionally NOT implemented.

    Parameters
    ----------
    pattern:
        A single token from the ``Include`` directive's value list.
    include_from:
        The path of the file that contained the ``Include`` line.
        Used to derive the parent directory for relative patterns.
    fs:
        The injected ``FileSystem`` (read-only contract). Glob
        expansion is delegated to ``fs.listdir`` + ``fnmatch`` so
        the analyzer works on a ``FakeFileSystem`` in tests AND on
        the host filesystem in production — never via ``os.listdir``
        or ``glob.glob`` (the read-only contract forbids any direct
        host FS access in analyzer code).
    """
    import fnmatch

    # Resolve the pattern's directory + basename per OpenSSH rules:
    #   * ``Include /abs/pattern``         — absolute, no rewrite
    #   * ``Include pattern/with/slashes`` — relative to includer's dir
    #   * ``Include bare-or-wildcard``     — under /etc/ssh
    if not pattern.startswith("/"):
        if "/" in pattern:
            base = os.path.dirname(include_from) or "/"
            search_dir = os.path.join(base, os.path.dirname(pattern))
            basename = os.path.basename(pattern)
        else:
            search_dir = "/etc/ssh"
            basename = pattern
    else:
        search_dir = os.path.dirname(pattern) or "/"
        basename = os.path.basename(pattern)

    # Delegate directory enumeration to the FileSystem so a
    # FakeFileSystem in tests sees only its registered files
    # (host-FS glob would see the actual /etc/ssh tree and ignore
    # the virtual files).
    try:
        entries = fs.listdir(search_dir)
    except (OSError, FileNotFoundError):
        return []

    # Match basenames against the pattern via fnmatch. Patterns may
    # contain ``*`` and ``?`` per ``glob(7)``; ``fnmatch`` covers
    # exactly that subset. Lex-sort the result to match OpenSSH.
    matches = sorted(
        os.path.join(search_dir, name)
        for name in entries
        if fnmatch.fnmatchcase(name, basename)
    )
    # Keep only files (skip directories whose name happens to match
    # the pattern) and dedupe.
    seen: set[str] = set()
    result: list[str] = []
    for m in matches:
        if fs.is_file(m) and m not in seen:
            seen.add(m)
            result.append(m)
    return result


def _stream_process(
    *,
    config_path: str,
    drop_in_dir: str,
    fs: FileSystem,
) -> tuple[SshdConfigSnapshot, list[str], list[str]]:
    """Apply directives in true OpenSSH stream order.

    The output preserves the position of every ``Include``:
    included lines are spliced in at the Include directive's
    position, lex-sorted, just like ``sshd -T`` would resolve them.

    When the main file is present we trust ITS ``Include``
    directives verbatim — no implicit drop-in walk. When the main
    file is missing, the drop-in directory is walked lex-sorted as
    a fallback so a heavily customised host (custom main path,
    drop-ins only) still gets a full audit.

    Returns
    -------
    (snapshot, files_actually_read, attempted_paths)
    """
    snap = new_snapshot()
    files_read: list[str] = []
    attempted: list[str] = []
    seen: set[str] = set()

    def _consume_file(path: str) -> None:
        if not fs.is_file(path):
            return
        norm = path.rstrip("/")
        if norm in seen:
            _LOG.warning("ssh_hardening: include cycle detected at %s", path)
            return
        seen.add(norm)
        try:
            lines = fs.read_text(path)
        except (OSError, FileNotFoundError) as exc:
            _LOG.warning("ssh_hardening: cannot read %s: %s", path, exc)
            return
        files_read.append(path)
        attempted.append(path)
        directives, malformed = parse_sshd_config(
            lines, source_path=path,
        )
        snap.malformed_count += malformed
        for directive in directives:
            if directive.keyword.lower() == _INCLUDE_KEY:
                # Expand each Include token (the directive value may
                # list multiple patterns, separated by whitespace).
                for token in directive.values:
                    for expanded in _expand_include(
                        token, include_from=path, fs=fs,
                    ):
                        _consume_file(expanded)
                continue
            apply_directive(snap, directive)

    # Step 1: consume the main file. Any ``Include`` directives in
    # it are expanded inline at their declared position (lex-sorted),
    # honouring OpenSSH first-obtained-wins.
    main_consumed = fs.is_file(config_path)
    _consume_file(config_path)

    # Step 2: when the main file is missing, fall back to walking
    # the drop-in directory lex-sorted. This matches the operator
    # expectation that a drop-in alone is enough for a posture audit
    # on a heavily customised host. With the main file missing, the
    # first obtained value for every directive IS the earliest
    # drop-in (lex-sorted).
    if not main_consumed and fs.is_dir(drop_in_dir):
        try:
            entries = fs.listdir(drop_in_dir)
        except OSError:
            entries = []
        for name in sorted(entries):
            if not name.endswith(".conf"):
                continue
            full = os.path.join(drop_in_dir, name)
            _consume_file(full)

    snap.sources = sorted(set(files_read))
    return snap, files_read, attempted


def analyze_ssh_config(
    fs: FileSystem,
    *,
    config_path: str = DEFAULT_SSHD_CONFIG_PATH,
    drop_in_dir: str = DEFAULT_SSHD_DROP_IN_DIR,
    rules: dict[str, Any] | None = None,
) -> list[Finding]:
    """Run the ssh_hardening analyzer and return a list of findings.

    Parameters
    ----------
    fs:
        The injected ``FileSystem`` (read-only contract). Tests pass
        a ``FakeFileSystem``; production passes ``RealFileSystem()``.
    config_path:
        Path to the main sshd_config. Override for non-standard
        layouts (e.g. ``sshd -f /test/sshd_config``).
    drop_in_dir:
        Directory of ``*.conf`` drop-ins. The OpenSSH convention is
        that the main file carries ``Include
        /etc/ssh/sshd_config.d/*.conf`` at the top — that directive
        is honored verbatim by the inline walker. If the main file
        is missing entirely, the drop-ins are still scanned lex-
        sorted so a host with a custom layout still gets a full
        audit.
    rules:
        YAML overrides for the thresholds in
        ``settings.DEFAULT_RULES``. Missing keys fall back to
        defaults.
    """
    settings = {**DEFAULT_RULES, **(rules or {})}

    snap, files_read, attempted = _stream_process(
        config_path=config_path,
        drop_in_dir=drop_in_dir,
        fs=fs,
    )

    if not files_read:
        # Nothing to scan (missing main config AND no drop-ins).
        # Emit a quiet INFO so the operator knows we didn't read
        # anything; same contract as the cphulk_log analyzer on a
        # missing /var/log/cphulkd.log.
        return [Finding(
            module="ssh_hardening",
            severity=Severity.INFO,
            title="No sshd_config files found",
            description=(
                f"Neither {config_path!r} nor any drop-in under "
                f"{drop_in_dir!r} exists on this host. The audit "
                "could not evaluate the SSH daemon's posture."
            ),
            details={
                "config_path": config_path,
                "drop_in_dir": drop_in_dir,
            },
        )]

    findings: list[Finding] = []
    summary = finalize(snap)
    findings.append(Finding(
        module="ssh_hardening",
        severity=Severity.INFO,
        title=(
            f"Scanned {len(files_read)} sshd_config file(s), "
            f"{snap.total_directives} effective directive(s)"
        ),
        description=(
            "sshd_config scan complete. Each finding below carries "
            "the originating config line in `details.source_line` "
            "so the operator can grep the original file. "
            "Directives are resolved in stream order — for each "
            "keyword the *first obtained value wins* per OpenSSH "
            "`sshd_config(5)`."
        ),
        details={
            "files_scanned": files_read,
            "config_path": config_path,
            "drop_in_dir": drop_in_dir,
            **summary,
        },
    ))

    findings.extend(all_findings(snap, settings))
    return findings


# Re-export aggregator symbol so the package API is symmetric with
# cphulk_log / secure_log.
__all__ = [
    "analyze_ssh_config",
    "SshdConfigSnapshot",
    "DEFAULT_RULES",
    "DEFAULT_SSHD_CONFIG_PATH",
    "DEFAULT_SSHD_DROP_IN_DIR",
]
