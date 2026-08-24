"""Public entry point for the ssl_cert analyzer.

Orchestrates the parser, aggregator, and rules. Reads files via the
injected `FileSystem.read_bytes` (read-only contract enforced upstream),
respects the `max_files` cap, and dispatches the two rules in
D12/D13 order. Returns a flat list of `Finding`.

External callers import `analyze_ssl_certs` from this module; the
package re-exports the public API in `__init__.py`.
"""

from __future__ import annotations

import fnmatch
import logging
from typing import Any, Iterable

from ...models import Finding, Severity
from ...runners import FileSystem
from .aggregator import CertAggregator
from .parser import parse_pem_cert
from .rules import rule_certificate_expiry, rule_read_errors
from .settings import DEFAULT_RULES, SSL_CERT_GLOB_ROOTS

_LOG = logging.getLogger("alma_audit")

# A cert file is small (a few KB). The cap is defensive against an
# attacker dropping a multi-megabyte blob into the cert directory.
_MAX_BYTES_PER_CERT = 256 * 1024


def cryptography_available() -> bool:
    """True iff the optional `cryptography` dependency is importable.

    Lets callers (CLI --list-analyzers, config validator) surface a
    helpful message instead of a stack trace when the dependency is
    missing. Production installs use `pip install alma-audit[ssl]`.
    """
    try:
        import importlib.util
        if importlib.util.find_spec("cryptography") is None:
            return False
        return True
    except Exception:
        return False


def _discover_any_root_has_matches(
    roots: Iterable[str],
    patterns: list[str],
    fs: FileSystem,
) -> bool:
    """True iff at least one root contains a glob-matched file.

    Cheap probe used to decide whether the missing-cryptography
    WARN is worth emitting: if no cert roots match on disk, a
    default `pip install alma-audit` on a non-cPanel host would
    otherwise produce a cron-fail-loud WARN even when there is
    nothing for the module to do.

    The probe respects the same per-root checks as the main loop
    (`is_dir` + `is_readable_dir` + `is_file`) so we never report a
    match for a path the analyzer wouldn't actually try to read.
    """
    for root in roots:
        if not fs.is_dir(root):
            continue
        if not fs.is_readable_dir(root):
            continue
        try:
            entries = fs.listdir(root)
        except OSError:
            continue
        for name in entries:
            if not any(fnmatch.fnmatchcase(name, pat) for pat in patterns):
                continue
            full = f"{root.rstrip('/')}/{name}"
            if fs.is_file(full):
                return True
    return False


def analyze_ssl_certs(
    roots: Iterable[str] | None,
    fs: FileSystem,
    rules: dict[str, Any] | None = None,
    glob_patterns: Iterable[str] | None = None,
) -> list[Finding]:
    """Run the ssl_cert analyzer across the configured roots and emit findings.

    Each root is listed (via `fs.listdir`); children matching any of
    the glob patterns are loaded via `fs.read_bytes` and parsed as
    PEM X.509 certificates. Compressed / non-PEM files are recorded
    as malformed; the analyzer never raises.

    `roots=None` defaults to `SSL_CERT_GLOB_ROOTS`. `glob_patterns=None`
    matches everything (`*`). Operators usually want to filter for
    `*.pem`, `*.crt`, `*.cert` to avoid scanning every file in
    `/etc/pki/tls/certs/` (which mixes symlinks, openssl configs, etc.).

    Dependency opt-in: the optional `cryptography` package is required
    to actually parse PEM bytes. If it is missing AND we discover at
    least one glob-matched cert file we would otherwise try to parse,
    we emit a single WARN so operators know why this module produced
    zero findings. If no cert roots match on disk, the analyzer
    silently emits an INFO "no certificate directory found" finding
    — the absence of `cryptography` is irrelevant when there's
    nothing to parse, which keeps a default `pip install alma-audit`
    (without `[ssl]`) cron-clean on a non-cPanel host.
    """
    settings = {**DEFAULT_RULES, **(rules or {})}
    actual_roots = list(roots) if roots is not None else list(SSL_CERT_GLOB_ROOTS)
    actual_patterns = list(glob_patterns) if glob_patterns is not None else ["*"]
    findings: list[Finding] = []

    if not cryptography_available():
        # Discovery pass: only emit the dependency-WARN if there is
        # actually a cert root on disk we'd otherwise scan. Otherwise
        # a default `pip install alma-audit` (without `[ssl]`) on a
        # non-cPanel host would always produce a cron-fail-loud WARN,
        # even when there is nothing for the module to do.
        if _discover_any_root_has_matches(
            actual_roots, actual_patterns, fs,
        ):
            findings.append(Finding(
                module="ssl_cert",
                severity=Severity.WARN,
                title="cryptography dependency is not installed",
                description=(
                    "The optional `cryptography` package is required for "
                    "X.509 parsing. Install it with "
                    "`pip install 'alma-audit[ssl]'` (or "
                    "`pip install cryptography`). The analyzer discovered "
                    "cert files on this host but could not parse them."
                ),
                recommendation=(
                    "Run `pip install cryptography` (or the `[ssl]` extra) "
                    "and re-run alma-audit to enable cert expiry detection."
                ),
            ))
        return findings

    agg = CertAggregator()
    malformed_paths: list[str] = []
    scanned_paths: list[str] = []
    files_scanned = 0
    roots_checked = 0

    for root in actual_roots:
        if not fs.is_dir(root):
            continue
        roots_checked += 1
        if not fs.is_readable_dir(root):
            findings.append(Finding(
                module="ssl_cert",
                severity=Severity.WARN,
                title=f"cert root {root!r} is not readable",
                description=(
                    f"Directory {root!r} exists but cannot be listed. "
                    "Certificates under this root will not be scanned."
                ),
                details={"path": root},
                recommendation=(
                    "Grant the audit user read+execute on the cert root."
                ),
            ))
            continue
        try:
            entries = fs.listdir(root)
        except OSError as exc:
            findings.append(Finding(
                module="ssl_cert",
                severity=Severity.WARN,
                title=f"cert root {root!r} listdir failed",
                description=f"Could not list {root!r}: {exc}.",
                details={"path": root, "error": str(exc)},
            ))
            continue
        for name in entries:
            if not any(fnmatch.fnmatchcase(name, pat) for pat in actual_patterns):
                continue
            full = f"{root.rstrip('/')}/{name}"
            if not fs.is_file(full):
                continue
            # Honour the cap BEFORE opening the file.
            if files_scanned >= settings["max_files"]:
                break
            files_scanned += 1
            scanned_paths.append(full)
            try:
                content = fs.read_bytes(full, max_bytes=_MAX_BYTES_PER_CERT)
            except FileNotFoundError:
                continue
            except OSError as exc:
                malformed_paths.append(full)
                _LOG.warning("ssl_cert: read_bytes(%s) failed: %s", full, exc)
                continue
            if not content:
                malformed_paths.append(full)
                continue
            cert = parse_pem_cert(full, content)
            if cert is None:
                malformed_paths.append(full)
                agg.note_malformed()
                continue
            agg.add(cert)
        if files_scanned > settings["max_files"]:
            break

    if roots_checked == 0:
        findings.append(Finding(
            module="ssl_cert",
            severity=Severity.INFO,
            title="No certificate directory found",
            description=(
                "None of the configured cert roots exist on this host. "
                "This is expected on non-TLS / non-cPanel installations."
            ),
            details={"roots_checked": list(actual_roots)},
        ))
        return findings

    if not scanned_paths:
        findings.append(Finding(
            module="ssl_cert",
            severity=Severity.INFO,
            title="No certificate files matched the glob",
            description=(
                f"Found {roots_checked} cert root(s) but no files "
                f"matched the glob(s) {list(actual_patterns)}."
            ),
            details={"roots": list(actual_roots), "globs": list(actual_patterns)},
        ))
        return findings

    summary = agg.finalize()
    findings.append(Finding(
        module="ssl_cert",
        severity=Severity.INFO,
        title=(
            f"Scanned {summary['parsed_files']} certificate file(s) "
            f"across {roots_checked} root(s)"
        ),
        description="SSL certificate scan complete.",
        details={
            "roots": [r for r in actual_roots if fs.is_dir(r)],
            "files_scanned": summary["parsed_files"],
            "malformed_files": summary["malformed_files"],
            **summary,
        },
    ))

    findings.extend(rule_certificate_expiry(agg, settings))
    findings.extend(rule_read_errors(agg, malformed_paths))

    return findings