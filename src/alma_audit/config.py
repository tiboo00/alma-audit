"""Configuration loader.

The CLI may be invoked with no config at all (built-in defaults are
sane) or with a YAML file. Unknown keys are tolerated (forward-compat
for adding rules); type errors are fatal. Module-specific config lives
under `modules.<name>` — see `examples/config.yaml`.

Default paths are first-class: `/var/log/apache2` and
`/var/log/apache2/domlogs`. Operators can override either via the
config file or the CLI flags (`--apache-root`, `--domlog-root`,
`--output`).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any

import yaml

DEFAULT_APACHE_ROOT = "/var/log/apache2"
DEFAULT_DOMLOG_ROOT = "/var/log/apache2/domlogs"
DEFAULT_ERROR_LOG = "error_log"
DEFAULT_MODSEC_LOG = "modsec_audit.log"
DEFAULT_ACCESS_LOG = "access_log"

# These are the file names a cPanel-style host rotates through inside the
# apache root; the analyzers glob them.
DEFAULT_ACCESS_LOG_GLOB = ["access_log", "access_log.*"]
DEFAULT_ERROR_LOG_GLOB = ["error_log", "error_log.*"]
DEFAULT_MODSEC_LOG_GLOB = ["modsec_audit*"]

# Roots used by the new quick-win analyzers (GAPS §4). The secure_log
# analyzer uses `secure_log_glob` (RHEL) and `auth_log_glob` (Debian);
# cphulk_log uses `cphulk_log_glob`; ssl_cert uses `ssl_cert_glob`;
# csf_state uses absolute paths hard-wired into the analyzer (CSF
# has a single canonical location).
DEFAULT_SECURE_LOG_GLOB = ["secure", "secure.*", "secure-*"]
DEFAULT_AUTH_LOG_GLOB = ["auth.log", "auth.log.*", "auth.log-*"]
DEFAULT_CPHULK_LOG_GLOB = ["cphulkd.log", "cphulkd.log.*", "cphulkd.log-*"]
DEFAULT_SSL_CERT_GLOB = ["*.pem", "*.crt", "*.cert"]
DEFAULT_CSF_DENY_PATH = "/etc/csf/csf.deny"
DEFAULT_CSF_ALLOW_PATH = "/etc/csf/csf.allow"


@dataclass
class Paths:
    apache_root: str = DEFAULT_APACHE_ROOT
    domlog_root: str = DEFAULT_DOMLOG_ROOT
    output_dir: str = ""
    access_log_glob: list[str] = field(default_factory=lambda: list(DEFAULT_ACCESS_LOG_GLOB))
    error_log_glob: list[str] = field(default_factory=lambda: list(DEFAULT_ERROR_LOG_GLOB))
    modsec_log_glob: list[str] = field(default_factory=lambda: list(DEFAULT_MODSEC_LOG_GLOB))
    # Quick-win roots (GAPS §4). Each is a glob pattern; the analyzers
    # use it together with the corresponding root directory.
    secure_log_root: str = "/var/log"
    secure_log_glob: list[str] = field(default_factory=lambda: list(DEFAULT_SECURE_LOG_GLOB))
    auth_log_glob: list[str] = field(default_factory=lambda: list(DEFAULT_AUTH_LOG_GLOB))
    cphulk_log_root: str = "/var/log"
    cphulk_log_glob: list[str] = field(default_factory=lambda: list(DEFAULT_CPHULK_LOG_GLOB))
    ssl_cert_roots: list[str] = field(default_factory=lambda: [
        "/var/cpanel/ssl",
        "/etc/pki/tls/certs",
        "/etc/ssl/certs",
    ])
    ssl_cert_glob: list[str] = field(default_factory=lambda: list(DEFAULT_SSL_CERT_GLOB))
    csf_deny_paths: list[str] = field(default_factory=lambda: [DEFAULT_CSF_DENY_PATH])
    csf_allow_paths: list[str] = field(default_factory=lambda: [DEFAULT_CSF_ALLOW_PATH])

    def access_log_paths(self) -> list[str]:
        return _expand(self.apache_root, self.access_log_glob)

    def error_log_paths(self) -> list[str]:
        return _expand(self.apache_root, self.error_log_glob)

    def modsec_log_paths(self) -> list[str]:
        return _expand(self.apache_root, self.modsec_log_glob)

    def secure_log_paths(self) -> list[str]:
        return _expand(self.secure_log_root, self.secure_log_glob) + _expand(
            self.secure_log_root, self.auth_log_glob,
        )

    def cphulk_log_paths(self) -> list[str]:
        return _expand(self.cphulk_log_root, self.cphulk_log_glob)


@dataclass
class Config:
    paths: Paths = field(default_factory=Paths)
    modules: dict[str, dict[str, Any]] = field(default_factory=dict)


def load_config(path: str | None) -> Config:
    """Load YAML from `path` and return a populated Config.

    `None` or non-existent path → return defaults. Type errors are fatal.
    Unknown top-level keys are ignored (forward-compat).
    """
    if not path or not os.path.isfile(path):
        return Config()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        print(f"alma-audit: config parse error in {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    if raw is None:
        return Config()
    if not isinstance(raw, dict):
        print(f"alma-audit: config root must be a mapping, got {type(raw).__name__}", file=sys.stderr)
        sys.exit(2)

    cfg = Config()
    paths_block = raw.get("paths")
    if paths_block is not None:
        if not isinstance(paths_block, dict):
            _fatal("paths must be a mapping")
        for key, val in paths_block.items():
            if not hasattr(cfg.paths, key):
                # Tolerate unknown keys but only if their value is the
                # expected scalar type; this protects against typos.
                continue
            # Lists of strings: globs AND list-of-paths fields share the
            # same type contract.
            if key.endswith("_glob") or key.endswith("_paths") or key.endswith("_roots"):
                if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                    _fatal(f"paths.{key} must be a list of strings")
            else:
                if not isinstance(val, str):
                    _fatal(f"paths.{key} must be a string")
            setattr(cfg.paths, key, val)

    modules_block = raw.get("modules")
    if modules_block is not None:
        if not isinstance(modules_block, dict):
            _fatal("modules must be a mapping (module-name -> settings)")
        for name, settings in modules_block.items():
            if not isinstance(settings, dict):
                _fatal(f"modules.{name} must be a mapping")
            cfg.modules[name] = settings
    return cfg


def _fatal(message: str) -> None:
    print(f"alma-audit: config error: {message}", file=sys.stderr)
    sys.exit(2)


def _expand(root: str, patterns: list[str]) -> list[str]:
    """Build absolute path candidates: <root>/<pattern>.

    We don't glob at config-load time — analyzers do that lazily, so a
    missing root doesn't kill the CLI before the user sees the report.
    """
    return [os.path.join(root, p) for p in patterns]
