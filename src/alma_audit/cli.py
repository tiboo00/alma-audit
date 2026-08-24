"""AlmaAudit command-line entry point.

Usage:
    alma-audit [--config CONFIG] [--apache-root DIR] [--domlog-root DIR]
               [--output DIR] [--list-analyzers]

Exit codes:
    0 — INFO-only (or no findings)
    1 — at least one WARN/CRITICAL finding (cron fail-loud)
    2 — config / IO error
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from . import __version__
from .config import (
    DEFAULT_APACHE_ROOT,
    DEFAULT_DOMLOG_ROOT,
    Config,
    load_config,
)
from .reporting import (
    build_report,
    write_cloudflare_block_script,
    write_forensic_report,
    write_json_report,
    write_markdown_report,
)
from .runner import run_analyzers
from .runners import RealFileSystem

_LOG = logging.getLogger("alma_audit")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alma-audit",
        description=(
            "Read-only audit toolkit for AlmaLinux WHMCS/cPanel hosts. "
            "Parses Apache access logs, domlogs, error_log, and ModSecurity "
            "audit logs; never writes back to source data."
        ),
    )
    parser.add_argument("--version", "-V", action="version", version=f"alma-audit {__version__}")
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="YAML config file. Optional — built-in defaults are sane.",
    )
    parser.add_argument(
        "--apache-root",
        default=None,
        help=f"Apache log root (default: {DEFAULT_APACHE_ROOT}).",
    )
    parser.add_argument(
        "--domlog-root",
        default=None,
        help=f"domlog directory (default: {DEFAULT_DOMLOG_ROOT}). "
             "Deprecated for multi-root layouts — prefer --domlog-roots (repeatable).",
    )
    parser.add_argument(
        "--domlog-roots",
        action="append",
        metavar="PATH",
        default=None,
        help="Add an additional domlog root to scan. Repeat the flag for "
             "multiple paths (e.g. --domlog-roots /var/log/apache2/domlogs "
             "--domlog-roots /usr/local/apache/domlogs). On CloudLinux + "
             "cPanel hosts both /var/log/apache2/domlogs and "
             "/usr/local/apache/domlogs are typically populated; this flag "
             "lets the inventory analyzer scan both without symlinking.",
    )
    parser.add_argument(
        "--output", "-o",
        default="./alma-audit-out",
        help="Output directory for JSON + Markdown reports "
             "(default: ./alma-audit-out).",
    )
    parser.add_argument(
        "--ssh-config",
        default=None,
        help="Path to the sshd_config file to audit "
             "(default: /etc/ssh/sshd_config). Drop-ins under "
             "/etc/ssh/sshd_config.d/*.conf are auto-included in "
             "alphabetical order. AISO-209.",
    )
    parser.add_argument(
        "--ssh-drop-in-dir",
        default=None,
        help="Directory of sshd_config drop-in files (*.conf). "
             "Concatenated in alphabetical order, matching OpenSSH "
             "``Include`` semantics. Defaults to "
             "``<parent of --ssh-config>/sshd_config.d`` when "
             "--ssh-config is set, otherwise "
             "``/etc/ssh/sshd_config.d``. AISO-209.",
    )
    parser.add_argument(
        "--list-analyzers",
        action="store_true",
        help="Print the analyzer names this build provides and exit.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser


def _apply_cli_overrides(cfg: Config, args: argparse.Namespace) -> Config:
    if args.apache_root is not None:
        cfg.paths.apache_root = args.apache_root
    if args.domlog_root is not None:
        # `--domlog-root PATH` sets the single-root path. Kept for
        # backward compatibility — pre-AISO-194 operators had only
        # this flag. New code should prefer `--domlog-roots` (repeated
        # for multiple paths).
        cfg.paths.domlog_root = args.domlog_root
    if getattr(args, "domlog_roots", None):
        # `--domlog-roots PATH` (repeatable) sets the multi-root list.
        # When set, this overrides `domlog_root` at the analyzer layer
        # (the runner prefers a non-empty `domlog_roots`).
        cfg.paths.domlog_roots = list(args.domlog_roots)
    if getattr(args, "ssh_config", None):
        # AISO-209: override the sshd_config path used by the
        # ssh_hardening analyzer. When the operator points
        # ``--ssh-config`` at a custom location but does NOT also
        # pass ``--ssh-drop-in-dir``, derive the drop-in directory
        # as ``<parent of --ssh-config>/sshd_config.d`` to keep
        # the default-OpenSSH layout (e.g. /test/cfg/sshd_config
        # → /test/cfg/sshd_config.d). Operators can override with
        # an explicit ``--ssh-drop-in-dir``.
        cfg.paths.ssh_config_path = args.ssh_config
        if getattr(args, "ssh_drop_in_dir", None) is None:
            cfg.paths.ssh_drop_in_dir = (
                os.path.join(os.path.dirname(args.ssh_config) or "/", "sshd_config.d")
            )
    if getattr(args, "ssh_drop_in_dir", None):
        cfg.paths.ssh_drop_in_dir = args.ssh_drop_in_dir
    return cfg


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.list_analyzers:
        # `crawler_verify` is not a stand-alone analyzer (no findings
        # of its own); it is a verification chain invoked by the
        # access_log analyzer. We expose its name for introspection so
        # operators can grep for it in reports / cron output. The
        # quick-win analyzers (AISO-186 / GAPS §4) are listed in
        # feature-add order. ``ssh_hardening`` (AISO-209) is the
        # latest addition; it audits the SSH daemon's own config
        # rather than its log output. ``error_log`` (AISO-211) is
        # the Apache error_log analyzer — opt-in via
        # ``modules.error_log.enabled``, listed for introspection.
        for name in (
            "access_log", "domlog_inventory", "modsec_log", "crawler_verify",
            "secure_log", "ssl_cert", "cphulk_log", "csf_state",
            "ssh_hardening", "error_log",
        ):
            print(name)
        return 0

    try:
        cfg = load_config(args.config)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    cfg = _apply_cli_overrides(cfg, args)

    fs = RealFileSystem()
    findings = run_analyzers(cfg, fs)

    report = build_report(findings)
    json_path = write_json_report(report, args.output)
    md_path = write_markdown_report(report, args.output)
    forensic_path = write_forensic_report(report, args.output)
    cf_script_path = write_cloudflare_block_script(report, args.output)
    print(f"alma-audit: {report.summary['total_findings']} findings "
          f"(INFO={report.summary['info']}, WARN={report.summary['warn']}, "
          f"CRITICAL={report.summary['critical']})")
    print(f"  JSON:      {json_path}")
    print(f"  Markdown:  {md_path}")
    print(f"  Forensic:  {forensic_path}  (per-IP detail + Cloudflare payloads)")
    print(f"  CF script: {cf_script_path}  (set CF_ZONE_ID + CF_API_TOKEN, then run)")

    if report.summary["critical"] > 0 or report.summary["warn"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
