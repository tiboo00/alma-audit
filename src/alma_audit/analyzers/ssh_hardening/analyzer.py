"""Public entry point for the ssh_hardening analyzer.

Orchestrates the parser, aggregator, and rules. Reads the main
``sshd_config`` + ``sshd_config.d/*.conf`` drop-ins via the injected
``FileSystem`` (read-only contract enforced upstream), aggregates
last-wins, dispatches every rule in the D21..D27 range, and returns
a flat list of ``Finding``.

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
from typing import Any, Iterable

from ...models import Finding, Severity
from ...runners import FileSystem
from .aggregator import SshdConfigSnapshot, aggregate, finalize
from .parser import parse_multiple
from .rules import all_findings
from .settings import (
    DEFAULT_RULES,
    DEFAULT_SSHD_CONFIG_PATH,
    DEFAULT_SSHD_DROP_IN_DIR,
)

_LOG = logging.getLogger("alma_audit")


def _resolve_config_files(
    config_path: str,
    drop_in_dir: str,
    fs: FileSystem,
) -> list[tuple[str, list[str]]]:
    """Build the ordered list of ``(path, lines)`` to feed the parser.

    The main config file is first; ``drop_in_dir/*.conf`` follow in
    alphabetical order — matching OpenSSH ``Include /etc/ssh/sshd_config.d/*.conf``
    semantics (alphabetical, ``.conf`` extension).
    """
    files: list[tuple[str, list[str]]] = []

    if fs.is_file(config_path):
        try:
            lines = fs.read_text(config_path)
        except (OSError, FileNotFoundError) as exc:
            _LOG.warning("ssh_hardening: cannot read %s: %s", config_path, exc)
            return files
        files.append((config_path, lines))
    else:
        # Missing main config — record and continue with drop-ins
        # (which may still exist on a heavily customised host).
        _LOG.info("ssh_hardening: main config %s not found", config_path)

    if fs.is_dir(drop_in_dir):
        # ``fs.listdir`` is permission-safe (returns [] on PermissionError);
        # we filter to *.conf alphabetically to match OpenSSH behaviour.
        try:
            entries = fs.listdir(drop_in_dir)
        except OSError:
            entries = []
        for name in sorted(entries):
            if not name.endswith(".conf"):
                continue
            full = os.path.join(drop_in_dir, name)
            if not fs.is_file(full):
                continue
            try:
                lines = fs.read_text(full)
            except (OSError, FileNotFoundError) as exc:
                _LOG.warning("ssh_hardening: cannot read drop-in %s: %s", full, exc)
                continue
            files.append((full, lines))

    return files


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
        Directory of ``*.conf`` drop-ins concatenated in
        alphabetical order.
    rules:
        YAML overrides for the thresholds in
        ``settings.DEFAULT_RULES``. Missing keys fall back to
        defaults.
    """
    settings = {**DEFAULT_RULES, **(rules or {})}

    files = _resolve_config_files(config_path, drop_in_dir, fs)
    if not files:
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

    directives, _malformed = parse_multiple(files)
    snap = aggregate(directives)

    findings: list[Finding] = []
    summary = finalize(snap)
    findings.append(Finding(
        module="ssh_hardening",
        severity=Severity.INFO,
        title=(
            f"Scanned {len(files)} sshd_config file(s), "
            f"{snap.total_directives} post-Include directive(s)"
        ),
        description=(
            "sshd_config scan complete. Each finding below carries "
            "the originating config line in `details.source_line` "
            "so the operator can grep the original file."
        ),
        details={
            "files_scanned": [path for path, _ in files],
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
