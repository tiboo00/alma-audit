"""Analyzer orchestration.

The CLI calls `run_analyzers(config, fs)` and gets a flat list of
findings. This keeps the CLI thin — it's just argparse + reporting.
"""

from __future__ import annotations

import logging
import os
from typing import Iterable

from .analyzers.access_log import analyze_access_logs
from .analyzers.cphulk_log import analyze_cphulk_logs
from .analyzers.csf_state import analyze_csf_state
from .analyzers.domlog_inventory import analyze_domlog_inventory
from .analyzers.error_log import analyze_error_log
from .analyzers.modsec_log import analyze_modsec_and_errors
from .analyzers.secure_log import analyze_secure_logs
from .analyzers.ssh_hardening import analyze_ssh_config
from .analyzers.ssl_cert import analyze_ssl_certs
from .config import Config
from .models import Finding, Severity
from .runners import FileSystem
from .self_ip import detect_self_ips  # noqa: F401  (used in run_analyzers)

_LOG = logging.getLogger("alma_audit")


def _expand_paths(patterns: Iterable[str], fs: FileSystem) -> list[str]:
    """Resolve a list of glob patterns into actual file paths.

    Each pattern is interpreted as `<apache_root>/<glob_pattern>` if it
    contains no slash, otherwise as a full pattern under the apache root.
    We use a literal `<root>/<pattern>` first; if that's a file, use it.
    Otherwise, expand the basename as a glob against the directory.
    """
    expanded: list[str] = []
    for pattern in patterns:
        directory = os.path.dirname(pattern)
        basename = os.path.basename(pattern)
        if not directory:
            # Caller passed a bare basename; we leave it for the analyzers
            # to handle (they know the apache root).
            expanded.append(pattern)
            continue
        if fs.is_file(pattern):
            expanded.append(pattern)
            continue
        if fs.is_dir(directory):
            expanded.extend(fs.glob(directory, basename))
    return expanded


def _effective_access_paths(cfg: Config, fs: FileSystem) -> list[str]:
    root = cfg.paths.apache_root
    if not fs.is_dir(root):
        return []
    out: list[str] = []
    for pattern in cfg.paths.access_log_glob:
        out.extend(fs.glob(root, pattern))
    return out


def _effective_error_paths(cfg: Config, fs: FileSystem) -> list[str]:
    root = cfg.paths.apache_root
    if not fs.is_dir(root):
        return []
    out: list[str] = []
    for pattern in cfg.paths.error_log_glob:
        out.extend(fs.glob(root, pattern))
    return out


def _effective_modsec_paths(cfg: Config, fs: FileSystem) -> list[str]:
    root = cfg.paths.apache_root
    if not fs.is_dir(root):
        return []
    out: list[str] = []
    for pattern in cfg.paths.modsec_log_glob:
        out.extend(fs.glob(root, pattern))
    return out


def _effective_secure_paths(cfg: Config, fs: FileSystem) -> list[str]:
    """Resolve secure/auth.log glob patterns into actual file paths.

    Globs are evaluated against the configured `secure_log_root`. The
    analyzer is forgiving: a missing root returns [] (the analyzer
    emits its own INFO "no files matched" finding).
    """
    root = cfg.paths.secure_log_root
    if not fs.is_dir(root):
        return []
    out: list[str] = []
    for pattern in cfg.paths.secure_log_glob + cfg.paths.auth_log_glob:
        out.extend(fs.glob(root, pattern))
    return out


def _effective_cphulk_paths(cfg: Config, fs: FileSystem) -> list[str]:
    root = cfg.paths.cphulk_log_root
    if not fs.is_dir(root):
        return []
    out: list[str] = []
    for pattern in cfg.paths.cphulk_log_glob:
        out.extend(fs.glob(root, pattern))
    return out


def _is_readable_dir(fs: FileSystem, path: str) -> bool:
    """True if `path` is a directory we can enumerate.

    `fs.is_dir(path)` only stats the inode, so it returns True even for
    a chmod-000 directory (the inode is still visible to the calling
    user). `fs.listdir(path)` is what actually tries to read the
    directory entries; for a chmod-000 root it returns [] (AISO-124
    runner contract). Combine the two: a "readable" directory is one
    that lists to at least one entry OR is known to be empty by
    design. Here we use the simplest signal — listdir returns [] on
    a chmod-000 root, so we rely on the OSError-vs-empty distinction
    being made inside the filesystem layer.

    For our purpose the helper below just checks `listdir` doesn't
    raise; the analyzer layer then decides whether an empty listing is
    "nothing to scan" (INFO) or "couldn't read" (WARN). The latter is
    detected by attempting listdir after is_dir has succeeded AND the
    apache_root actually exists on disk.
    """
    if not fs.is_dir(path):
        return False
    try:
        # listdir is permission-safe on RealFileSystem (returns [] on
        # PermissionError, AISO-124). For FakeFileSystem it raises
        # FileNotFoundError only on missing paths.
        fs.listdir(path)
        return True
    except OSError:
        return False


def _probe_root_readable(
    root: str, fs: FileSystem, module: str,
) -> Finding | None:
    """Emit a WARN finding if `root` exists but the audit user can't list it.

    Analyzers see ``fs.listdir`` returning [] (or raising) for an
    unreadable directory. Without this probe, the access_log /
    modsec_log analyzers would silently report "0 files scanned"
    and the operator would not know why the audit looked empty.
    Returns the WARN finding (caller appends), or None if the root is
    absent / readable.
    """
    if not fs.is_dir(root):
        return None
    if fs.is_readable_dir(root):
        return None
    return Finding(
        module=module,
        severity=Severity.WARN,
        title=f"{module} root directory is unreadable",
        description=(
            f"{root!r} is a directory but the audit user cannot list it "
            "(permission denied). Logs under this root will not be scanned."
        ),
        details={"path": root},
        recommendation=(
            "Grant the audit user read+execute on the apache root."
        ),
    )


def run_analyzers(cfg: Config, fs: FileSystem) -> list[Finding]:
    """Run all analyzers with the given config and filesystem."""
    findings: list[Finding] = []

    # Upfront probe — translate an unreadable apache_root into a WARN
    # finding so the access_log / modsec_log "0 files scanned" path
    # is not silently INFO (AISO-125).
    apache_warn = _probe_root_readable(cfg.paths.apache_root, fs, "access_log")
    if apache_warn is not None:
        findings.append(apache_warn)

    # AISO-201: detect the host's own IPs so self-logins (cron /
    # monitoring / internal services) don't trip brute-force findings.
    # The operator can extend the set via `modules.secure_log.trusted_ips`.
    # AISO-211: the same set is now also passed into the access_log
    # analyzer so cPanel self-admin-panel noise doesn't drown the
    # per-IP rollups. Detection runs early so both consumers see the
    # same set without a second DNS round-trip.
    operator_trusted = list(cfg.modules.get("secure_log", {}).get("trusted_ips", []) or [])
    self_ips = detect_self_ips(operator_trusted)
    _LOG.debug("self-IP set for self-login filter: %s", sorted(self_ips))

    access_paths = _effective_access_paths(cfg, fs)
    _LOG.info("access_log candidate paths: %s", access_paths)
    # AISO-211: pass the host's own IPs into the access_log analyzer
    # so cPanel self-admin-panel noise doesn't drown the per-IP
    # rollups (`top_attackers`, `host_errors_top`, `top_hosts`).
    # The orchestrator gates this on `modules.access_log.exclude_self_ips`
    # (default True); flip to False for diagnostic mode.
    findings.extend(analyze_access_logs(
        access_paths,
        fs,
        rules=cfg.modules.get("access_log", {}),
        self_ips=self_ips,
    ))

    findings.extend(analyze_domlog_inventory(
        cfg.paths.domlog_roots or [cfg.paths.domlog_root],
        fs,
        rules=cfg.modules.get("domlog_inventory", {}),
    ))

    error_paths = _effective_error_paths(cfg, fs)
    modsec_paths = _effective_modsec_paths(cfg, fs)
    _LOG.info("error_log paths: %s; modsec paths: %s", error_paths, modsec_paths)
    findings.extend(analyze_modsec_and_errors(
        error_paths,
        modsec_paths,
        fs,
        rules=cfg.modules.get("modsec_log", {}),
    ))

    # AISO-211: the new Apache ``error_log`` analyzer. Reads the
    # same paths the modsec analyzer already used for the error_log
    # *file presence* check (the INFO finding in
    # ``analyze_modsec_and_errors`` lists the file but drops the
    # contents). The new analyzer is OPT-IN via
    # ``modules.error_log.enabled`` — default OFF so the audit scope
    # stays unchanged for hosts that don't have the file or
    # operators who haven't opted in.
    if cfg.modules.get("error_log", {}).get("enabled", False):
        findings.extend(analyze_error_log(
            error_paths,
            fs,
            rules=cfg.modules.get("error_log", {}),
        ))

    # Quick-win analyzers (GAPS §4). Each is bounded: the analyzer
    # emits its own INFO finding when no files match. We do NOT
    # gate on root readability at the runner layer — the analyzer
    # layer handles that uniformly.
    secure_paths = _effective_secure_paths(cfg, fs)
    _LOG.info("secure_log candidate paths: %s", secure_paths)
    findings.extend(analyze_secure_logs(
        secure_paths,
        fs,
        rules=cfg.modules.get("secure_log", {}),
        self_ips=self_ips,
    ))

    cphulk_paths = _effective_cphulk_paths(cfg, fs)
    _LOG.info("cphulk_log candidate paths: %s", cphulk_paths)
    findings.extend(analyze_cphulk_logs(
        cphulk_paths,
        fs,
        rules=cfg.modules.get("cphulk_log", {}),
    ))

    findings.extend(analyze_ssl_certs(
        cfg.paths.ssl_cert_roots,
        fs,
        rules=cfg.modules.get("ssl_cert", {}),
        glob_patterns=cfg.paths.ssl_cert_glob,
    ))

    findings.extend(analyze_csf_state(
        cfg.paths.csf_deny_paths,
        cfg.paths.csf_allow_paths,
        fs,
        rules=cfg.modules.get("csf_state", {}),
    ))

    # AISO-209: SSH daemon hardening audit. Inspects sshd_config +
    # sshd_config.d/*.conf drop-ins for weak settings (root login,
    # password auth, default port, weak algorithms, ...). Reads via
    # the injected FileSystem; emits its own INFO finding when the
    # config / drop-ins are missing.
    #
    # AISO-209 also accepted the spec'd YAML override
    # ``modules.ssh_hardening.config_path`` (the issue text). The
    # ``paths.ssh_config_path`` key shipped in the original PR stays
    # valid for backward compatibility — ``paths.*`` is read first,
    # then the module-level key wins if present. Operators that don't
    # care about module-level organisation can keep their YAML flat.
    ssh_hardening_rules = dict(cfg.modules.get("ssh_hardening", {}) or {})
    module_config_path = ssh_hardening_rules.pop("config_path", None)
    ssh_config_path = (
        module_config_path
        if isinstance(module_config_path, str) and module_config_path
        else cfg.paths.ssh_config_path
    )
    module_drop_in_dir = ssh_hardening_rules.pop("drop_in_dir", None)
    ssh_drop_in_dir = (
        module_drop_in_dir
        if isinstance(module_drop_in_dir, str) and module_drop_in_dir
        else cfg.paths.ssh_drop_in_dir
    )
    findings.extend(analyze_ssh_config(
        fs,
        config_path=ssh_config_path,
        drop_in_dir=ssh_drop_in_dir,
        rules=ssh_hardening_rules,
    ))

    return findings
