# alma-audit

Modular, **read-only** Python audit toolkit for AlmaLinux WHMCS/cPanel hosts.

It parses Apache access logs, domlogs (per-domain access logs), the Apache
error log, ModSecurity audit logs, the system `secure`/`auth.log`,
cPHulk's `cphulkd.log`, CSF's `csf.deny` / `csf.allow` state files,
and X.509 certificate PEMs; detects inventory anomalies (suspiciously
long filenames, unexpected layout), aggregates traffic, scores the
result against a built-in rule set, and emits structured JSON plus a
human-readable Markdown report.

The tool never writes back to source logs and never changes firewall,
fail2ban, cPanel or WHMCS state. The only files it writes are the two
report artifacts (JSON + Markdown).

## Layout

```
almalinux-whmcs-cpanel-security-audit/
├── pyproject.toml              # package metadata + deps
├── src/alma_audit/
│   ├── cli.py                  # argparse entry point
│   ├── config.py               # YAML loader + default paths
│   ├── models.py               # dataclasses: Finding, Severity, Report
│   ├── reporting.py            # JSON + Markdown writers
│   ├── runners.py              # file-glob runner (testable seam)
│   └── analyzers/
│       ├── access_log/         # combined-format parser + aggregator
│       ├── domlog_inventory.py # per-domain file inventory anomaly scan
│       ├── modsec_log.py       # Apache error + ModSecurity audit scanner
│       ├── secure_log/         # /var/log/secure + /var/log/auth.log
│       ├── ssl_cert/           # X.509 cert expiry (opt-in `[ssl]` extra)
│       ├── cphulk_log/         # cPHulk brute-force / block events
│       ├── ssh_hardening/      # sshd_config + drop-ins audit (AISO-209)
│       └── csf_state.py        # /etc/csf/csf.deny + csf.allow state
├── examples/
│   ├── config.yaml             # sample config (read-only)
│   ├── alma-audit.service      # systemd unit
│   ├── alma-audit.timer        # systemd timer (cron equivalent)
│   └── audit-diff.py           # trend sidecar (AISO-186 §4.5)
├── deploy/
│   └── README-deploy.md        # install + cron notes
└── tests/
    ├── conftest.py             # shared fixtures
    ├── test_access_log.py
    ├── test_domlog_inventory.py
    ├── test_modsec_log.py
    ├── test_secure_log.py
    ├── test_ssl_cert.py
    ├── test_cphulk_log.py
    ├── test_csf_state.py
    └── test_audit_diff.py
```

## Quick start

```bash
# install (editable, dev deps)
pip install -e '.[dev]'

# Optional: enable SSL cert expiry checks
pip install -e '.[ssl]'      # installs the `cryptography` package

# run with built-in defaults (looks at /var/log/apache2 + /var/log/apache2/domlogs)
alma-audit --output /var/log/alma-audit

# run with custom config
alma-audit --config examples/config.yaml --output ./out

# list built-in analyzer names
alma-audit --list-analyzers
```

The CLI exits 0 on INFO-only findings, 1 if any WARN/CRITICAL was emitted
(useful in cron to fail-loud).

## Detection contract

| Severity  | Meaning                                                   |
|-----------|-----------------------------------------------------------|
| INFO      | Inventory / status summary, no action required.           |
| WARN      | Unusual but explainable; review recommended.              |
| CRITICAL  | Active probe / known exploit / inventory drift; respond.  |

Built-in rules (see `src/alma_audit/analyzers/*.py` for thresholds):

- **access_log** — top talkers, 4xx/5xx bursts, suspicious path probes
  (`/.env`, `/wp-login.php`, `/administrator/`, `/.git/`, `/phpinfo`,
  `/phpmyadmin`, `/cgi-bin/`), unusual methods (PROPFIND, OPTIONS floods).
- **domlog_inventory** — filenames that are unusually long, that
  repeat a single character, or that contain shell-metacharacters;
  unexpected sub-directories; files owned by a different account than
  expected.
- **modsec_log** — Apache error_log 5xx rate; ModSecurity actions
  (`deny`, `drop`, `block`) with non-empty `msg`/`tag`; severity 1/2 hits.
- **secure_log** (AISO-186) — SSH brute-force burst per source IP,
  sudo authentication failure burst per user, useradd / groupadd /
  passwd-change mutations, root-level (UID=0) account creation
  (always CRITICAL).
- **cphulk_log** (AISO-186) — cPHulk brute-force burst per source IP
  + per username; account / IP block + unblock summary.
- **ssl_cert** (AISO-186, optional) — X.509 certificate expiry
  windows: CRITICAL if expired or within `expiry_crit_days`, WARN
  within `expiry_warn_days`. Requires the `cryptography` package.
- **csf_state** (AISO-186) — `/etc/csf/csf.deny` + `csf.allow` counts;
  WARN/CRITICAL on denylist size above `deny_count_warn` /
  `deny_count_crit`; optional growth/shrinkage deltas against an
  operator-provided baseline.
- **ssh_hardening** (AISO-209) — `/etc/ssh/sshd_config` (plus
  `sshd_config.d/*.conf` drop-ins, concatenated in alphabetical
  order to match OpenSSH `Include` semantics) audit. CRITICAL on
  `PermitRootLogin yes`, `PermitEmptyPasswords yes`, or `Protocol
  1` enabled; WARN on `PasswordAuthentication yes`, default port
  22, `MaxAuthTries > 6`, `ClientAliveInterval 0`,
  `LoginGraceTime > 120`, missing `AllowUsers` / `AllowGroups`,
  and weak `Ciphers` / `MACs`; INFO on `X11Forwarding yes`,
  `PermitRootLogin prohibit-password`, and missing `Banner`.
  Override the path via `--ssh-config PATH` /
  `--ssh-drop-in-dir DIR` (CLI) or
  `paths.ssh_config_path` / `paths.ssh_drop_in_dir` (YAML).

## Trend sidecar

`examples/audit-diff.py` diffs two `alma-audit-latest.json` reports
and emits a structured "what changed" summary in three formats
(JSON / Markdown / text). It is a sidecar — no package change, no
extra runtime cost for operators who don't run it.

```bash
# Diff yesterday's report against today's, write Markdown to a file.
audit-diff.py alma-audit-prev.json alma-audit-latest.json \
    --format markdown --output /var/log/alma-audit/diff.md

# Pipe JSON straight into a downstream pipeline.
audit-diff.py alma-audit-prev.json alma-audit-latest.json \
    --format json | jq '.rows[] | select(.kind == "added")'
```

The script is **read-only** — it never mutates the input reports.
Its output is deterministic (rows are sorted by severity, kind,
module, then title).

## Read-only contract

The toolkit uses an injected file-runner (`runners.py`) that only opens
files for read (`open(..., "r")` or `open(..., "rb")`). No module in
this package calls `subprocess.run`, `os.system`, or any write API.
This is enforced by the test suite (`tests/test_readonly.py`).

## Cron

See `examples/alma-audit.timer` + `examples/alma-audit.service`.
Equivalent crontab entry:

```cron
15 4 * * * root /usr/local/bin/alma-audit --output /var/log/alma-audit
```

For a daily trend diff, rotate yesterday's report before alma-audit
runs:

```cron
14 4 * * * root cp /var/log/alma-audit/alma-audit-latest.json \
                    /var/log/alma-audit/alma-audit-prev.json
15 4 * * * root /usr/local/bin/alma-audit --output /var/log/alma-audit
16 4 * * * root /usr/local/bin/audit-diff.py \
                    /var/log/alma-audit/alma-audit-prev.json \
                    /var/log/alma-audit/alma-audit-latest.json \
                    --format markdown --output /var/log/alma-audit/diff.md
```
