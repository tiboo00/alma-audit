"""Multi-root domlog discovery for cPanel / CloudLinux layouts.

cPanel places per-domain Apache access logs in two canonical locations,
and CloudLinux adds a third:

  /var/log/apache2/domlogs     — cPanel "managed" copy (often a symlink)
  /usr/local/apache/domlogs    — cPanel + CloudLinux canonical location
  /var/log/apache2             — fallback for hosts where domlogs is a
                                 sub-tree of the main apache root

The original `domlog_root` config field accepted a single string. On a
CloudLinux + cPanel host that meant operators had to symlink or shell
glue the two together — or run alma-audit twice and merge the reports.
This module introduces a list-based default so the inventory analyzer
walks both roots in one pass and dedupes findings by absolute path.

Filename exclusions
-------------------
Several cPanel-managed files in the domlog directory are not Apache
combined-format access logs:

  -bytes_log          : `mod_log_config` byte counter (not Apache format)
  -bytes_log.bkup     : cPanel rotation offset backup (binary)
  .offset             : cPanel per-domain offset tracker

These were previously picked up by the inventory scan and produced
false-positive WARN findings ("unexpected_filename_shape"). They are
now excluded at the discovery layer so only true access-log candidates
flow into the anomaly detector. The exclusion is by suffix, not by
exact match, so `hostdzire.com-bytes_log`, `hostdzire.com-bytes_log.1`,
and `hostdzire.com-bytes_log.bkup.offset` are all skipped.

The `-ssl_log` suffix is NOT excluded — that one IS a real combined-
format access log written by cPanel when an account runs SSL.
"""

from __future__ import annotations


# Default domlog roots. The first existing root wins for the
# "domlog directory not present" INFO finding; both roots are walked
# when they coexist so a CloudLinux host with two populated locations
# gets a complete inventory.
DEFAULT_DOMLOG_ROOTS: list[str] = [
    "/var/log/apache2/domlogs",
    "/usr/local/apache/domlogs",
    "/var/log/apache2",
]

# Suffixes that mark a domlog entry as NOT-an-access-log. Match is
# case-sensitive and exact-suffix (e.g. `.offset` only matches files
# ending in `.offset`, not files containing `.offset` mid-name).
DOMLOG_EXCLUDE_SUFFIXES: tuple[str, ...] = (
    "-bytes_log",
    "-bytes_log.bkup",
    ".offset",
)


def should_skip_filename(name: str) -> bool:
    """True if `name` matches one of the non-access-log exclude suffixes.

    Used by `domlog_inventory.analyze_domlog_inventory` to filter
    `mod_log_config` byte-counters and cPanel offset backups out of
    the inventory scan. Domain filenames (`hostdzire.com`) and SSL
    logs (`hostdzire.com-ssl_log`) pass through.
    """
    return any(name.endswith(suf) for suf in DOMLOG_EXCLUDE_SUFFIXES)
