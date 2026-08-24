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
import sys

from . import __version__
from .config import (
    DEFAULT_APACHE_ROOT,
    DEFAULT_DOMLOG_ROOT,
    Config,
    load_config,
)
from .reporting import build_report, write_json_report, write_markdown_report
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
        help=f"domlog directory (default: {DEFAULT_DOMLOG_ROOT}).",
    )
    parser.add_argument(
        "--output", "-o",
        default="./alma-audit-out",
        help="Output directory for JSON + Markdown reports "
             "(default: ./alma-audit-out).",
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
        cfg.paths.domlog_root = args.domlog_root
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
        # feature-add order.
        for name in (
            "access_log", "domlog_inventory", "modsec_log", "crawler_verify",
            "secure_log", "ssl_cert", "cphulk_log", "csf_state",
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
    _LOG.info("Reports written: %s, %s", json_path, md_path)
    print(f"alma-audit: {report.summary['total_findings']} findings "
          f"(INFO={report.summary['info']}, WARN={report.summary['warn']}, "
          f"CRITICAL={report.summary['critical']})")
    print(f"  JSON:      {json_path}")
    print(f"  Markdown:  {md_path}")

    if report.summary["critical"] > 0 or report.summary["warn"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
