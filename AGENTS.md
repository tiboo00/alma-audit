# AGENTS.md

> **Single source of agent context** for `alma-audit`. Symlinked from
> `CLAUDE.md`, `.cursorrules`, and `.github/copilot-instructions.md` —
> edit here, the others follow.

## Project Overview

`alma-audit` is a **read-only** Python 3.10+ security audit toolkit for
**AlmaLinux WHMCS/cPanel hosts**. It parses Apache access logs, domlogs
(per-domain access logs), Apache error logs, ModSecurity audit logs,
`/var/log/secure` + `/var/log/auth.log`, `/var/log/cphulkd.log`,
CSF state files (`/etc/csf/csf.{deny,allow}`), and X.509 PEM
certificates; aggregates traffic, scores against a built-in rule
set, and emits four artifacts (JSON + Markdown + per-IP forensic
JSON + a copy-paste Cloudflare block script).

**Hard contract:** the toolkit **never** writes back to source logs,
**never** changes firewall / fail2ban / cPanel / WHMCS state, and
**never** spawns subprocesses. The only files it writes are the four
report artifacts in `--output`. This is enforced by AST in
`tests/test_readonly.py` (blocks PRs that violate it).

**Scope:** single host, runs as root from a systemd timer (or cron).
Single-file artifact, no fleet baseline, no remote coordination.
Two new AISO ticket batches land here as features: **AISO-119/124/125/186/189/194/197/198/199/200/201/202** are already in the tree;
**AISO-202..209** is the current rollup (see `verify_all.sh`).

## Layout (40 source files, ~6700 LOC + 6613 LOC tests)

```
alma-audit/
├── pyproject.toml                  # setuptools, name="alma-audit", v0.1.0
├── README.md                       # operator-facing quick start
├── verify_all.sh                   # CI-style end-to-end wiring check
├── AGENTS.md / CLAUDE.md / .cursorrules
├── src/alma_audit/
│   ├── cli.py                      # argparse, main(), exit 0/1/2
│   ├── config.py                   # YAML loader + Paths/Config dataclasses
│   ├── models.py                   # Severity enum + Finding/AuditReport dataclasses
│   ├── runners.py                  # FileSystem Protocol + RealFileSystem + FakeFileSystem
│   ├── runner.py                   # orchestration: run_analyzers(cfg, fs) -> list[Finding]
│   ├── ip_normalise.py             # canonical IP literal -> (canonical, scope)
│   ├── self_ip.py                  # AISO-201: host's own IPs (DNS only, no subprocess)
│   ├── reporting.py                # JSON + Markdown + forensic writers
│   ├── forensic_export.py          # Cloudflare firewall-rule payloads + curl script
│   └── analyzers/
│       ├── access_log/             # 5-file split: __init__, parser, aggregator, rules, settings
│       ├── secure_log/             # same 5-file split (AISO-186)
│       ├── ssl_cert/               # same 5-file split (AISO-186, optional [ssl] extra)
│       ├── cphulk_log/             # same 5-file split (AISO-186)
│       ├── ssh_hardening/          # same 5-file split (AISO-209 — sshd_config audit)
│       ├── csf_state.py            # flat — single-purpose CSF denylist reader (AISO-186)
│       ├── domlog_inventory.py     # flat (541 LOC — the largest src file; AISO-198)
│       ├── domlog_roots.py         # AISO-194 multi-root defaults
│       ├── modsec_log.py           # flat (351 LOC — could split per GAPS §7.3)
│       └── crawler_verify.py       # Googlebot PTR+forward+suffix verification chain
├── tests/                          # 30 test_*.py + conftest.py + 2 Dockerfiles
├── examples/
│   ├── config.yaml                 # sample config (read-only reference)
│   ├── alma-audit.service          # systemd unit (ReadOnlyPaths, ProtectSystem=strict)
│   ├── alma-audit.timer            # systemd timer (cron equivalent)
│   └── audit-diff.py               # trend sidecar — diffs two reports (read-only)
├── deploy/
│   ├── Dockerfile.dev              # alma-audit-dev:latest — AlmaLinux 8.10 + py3.11
│   ├── run-dev-tests.sh            # container entrypoint: copy /src, editable install, pytest
│   └── README-deploy.md            # install + cron notes for operators
├── docs/
│   └── GAPS.md                     # coverage matrix, gaps, file-size discipline (§7)
└── .venv/                          # local venv (git-ignored); uv.lock is also git-ignored
```

## Build, Test & Development

### Local install

```bash
# Editable install with dev extras (pytest, pytest-cov)
pip install -e '.[dev]'

# Optional: enable the ssl_cert analyzer (X.509 cert expiry)
pip install -e '.[ssl]'              # installs `cryptography`

# Run the CLI (built-in defaults — /var/log/apache2 + domlogs)
alma-audit --output /var/log/alma-audit

# Run with sample config
alma-audit --config examples/config.yaml --output ./out

# List analyzer names this build provides (for grep / sanity)
alma-audit --list-analyzers
```

### Pytest (host or dev container)

`pyproject.toml` declares the suite — no `conftest.py` config knobs.

```bash
pytest -q                                  # full suite (~290 tests, 6k LOC of test code)
pytest tests/test_readonly.py              # AST check: no write APIs / no subprocess
pytest tests/test_domlog_d7_corpus.py      # 31-case regression lock (AISO-119 v1.2)
pytest tests/test_self_ip.py               # self-IP filter (AISO-201)
pytest tests/test_secure_log.py            # sshd/sudo brute-force + UID=0 (AISO-186/201)
pytest tests/test_unreadable_log_root.py   # chmod-000 log root handling (AISO-124/125)
pytest tests/test_forensic_export.py       # CF payload + chunking (AISO-199/200/202)
pytest tests/test_exit_codes.py            # cron fail-loud exit 1 on WARN/CRIT
```

### End-to-end verifier (`verify_all.sh`)

The script is the **CI-style rollup gate**. It greps source files for
specific symbols (file presence + key strings), runs the full pytest
suite, checks that `alma-audit --list-analyzers` emits every analyzer
name (incl. the new `ssh_hardening`), and (if docker is available)
builds the dev image and runs a smoke scan.

```bash
./verify_all.sh
# Exit 0 = all AISO features wired in + tests green
# Exit 1 = read the printed report to find which AISO is missing
```

**AISO features it currently checks:** AISO-202 (chunking),
AISO-203 (SSH invalid_user / ssh_fail split counter), AISO-204
(bandwidth hog), AISO-205 (modsec rule IDs), AISO-206 (domlog
severity sort), AISO-207 (YAML-configurable thresholds), AISO-208
(path-level user-agent breakdown), AISO-209 (ssh_hardening analyzer).

### CLI exit codes (intentional cron fail-loud)

- `0` — INFO-only or no findings
- `1` — at least one WARN/CRITICAL (wrap cron with `|| mail ...`)
- `2` — config parse error / IO error

### CLI flags (full list)

```
alma-audit [--config CONFIG] [--apache-root DIR] [--domlog-root DIR]
           [--domlog-roots PATH (repeatable)] [--output DIR]
           [--list-analyzers] [--verbose] [--version]
```

- `--config` / `-c` — YAML config (omit for built-in defaults)
- `--apache-root` — Apache log root (default `/var/log/apache2`)
- `--domlog-root` — single domlog root (deprecated; use `--domlog-roots`)
- `--domlog-roots PATH` — repeatable; multi-root for CloudLinux + cPanel
  (both `/var/log/apache2/domlogs` and `/usr/local/apache/domlogs` are
  typically populated). When set, overrides `--domlog-root`.
- `--output` / `-o` — output dir (default `./alma-audit-out`)
- `--list-analyzers` — print names + exit 0
- `--verbose` / `-v` — DEBUG-level logging
- `--version` / `-V` — print `alma-audit 0.1.0`

### Reports written to `<output>`

| File | Purpose | Truncated? |
|---|---|---|
| `alma-audit-latest.json` | Full machine-readable | No (everything in `details`) |
| `alma-audit-latest.md` | Operator-friendly summary | Yes (top-10 per forensic category) |
| `alma-audit-forensic.json` | Per-IP detail bundle | No |
| `cloudflare-block.sh` | Generated `curl` script (chmod 755) | One curl per chunk |

## Docker (the AISO-202..209 dev container is the live test rig)

The dev container **is** the way the AISO rollup is verified locally
and in CI. The `verify_all.sh` script's Phase 4 builds and runs it.

### `deploy/Dockerfile.dev` — `alma-audit-dev:latest`

- **Base:** `almalinux:8.10` (matches prod hosts — same os-release, same
  Python 3.11 from appstream, same `cryptography` version family).
- **Why system-wide pip install (not a venv):** the `runuser -u nobody`
  test bodies in `tests/test_exit_codes.py` and
  `tests/test_unreadable_log_root.py` need the unprivileged `nobody`
  user to import the package + every runtime dep from the standard
  Python path. A venv under `/root` is invisible to `nobody`.
- **Why a bridge layer at build time:** EL8's `pip install` lands under
  `/usr/local/{lib,lib64}/python3.11/site-packages`, but the Python 3.11
  interpreter resolves `sys.path` for unprivileged users from
  `/usr/lib/python3.11/site-packages`. The Dockerfile symlinks every
  pip-installed package from `/usr/local` into `/usr/lib/python3.11/...`
  so `nobody` finds them.
- **Why editable install happens at run time:** the repo is bind-mounted
  at `/src` at run time. `git pull && docker run ...` re-runs the suite
  against the new code without rebuilding the image.
- **Re-build the image only when the Dockerfile itself changes** (rare).
  Day-to-day: mount the repo and re-run the existing image — the
  entrypoint reinstalls the editable package every run.

### `deploy/run-dev-tests.sh` — container entrypoint

1. Copies `/src` into `/tmp/alma_audit_work` (writable, the bind mount
   is owned by the host user and pip's editable install needs to write
   `src/alma_audit.egg-info`).
2. Runs `python3.11 -m pip install --quiet --editable /tmp/alma_audit_work`.
3. `chmod -R a+rX` so the inner `runuser -u nobody` subprocesses can
   stat + read package source + test fixtures.
4. **Pytest runs as root**, not as `nobody`. The container is
   ephemeral (`--rm`) so privilege separation at the test layer buys
   nothing; conversely, dropping to `nobody` at the outer layer breaks
   the inner `runuser -u nobody` calls (Linux forbids `runuser` from
   a non-root user). The test suite does its own privilege drop inside
   the cases that need it.
5. Exit code is the pytest exit code.

### Local docker commands

```bash
# Build the dev image (matches prod AlmaLinux 8.10 + py3.11)
docker build -f deploy/Dockerfile.dev -t alma-audit-dev:latest .

# Run the full pytest suite inside the dev container
docker run --rm -v "$PWD":/src:ro alma-audit-dev:latest

# Smoke pass for the AISO-125 nobody/chmod-000 contract
docker build -t alma-audit-smoke:al8-py311 -f tests/Dockerfile.smoke .
docker run --rm --network=none alma-audit-smoke:al8-py311

# Verify the host's docker daemon before relying on verify_all.sh
docker version
docker images | grep alma            # expect alma-audit-dev:latest, alma-audit-smoke:*
```

### `tests/Dockerfile.smoke` — AISO-125 smoke

- **Base:** `almalinux:8` (no `.10` pin).
- Installs `python3.11` + `pip` + `devel`, then `pip install -e .`
  editable into the system Python.
- Copies `tests/smoke_entrypoint.sh` as ENTRYPOINT.
- The entrypoint stages a chmod-000 domlog_root, runs `alma-audit` as
  `nobody` via `runuser -u nobody`, and asserts:
  1. Exit code = 1 (cron fail-loud)
  2. JSON report exists
  3. JSON contains a WARN finding naming the unreadable path
- No network (`--network=none`) — the smoke must succeed offline.

### Image inventory on this host (as of 2026-08-24)

| Image | Size | Notes |
|---|---|---|
| `almalinux:8` | 289 MB | upstream base |
| `alma-audit-dev:latest` | 676 MB | built via `deploy/Dockerfile.dev` |
| `alma-audit-smoke:al8-py311` | 449 MB | built via `tests/Dockerfile.smoke` |
| `alma-audit-smoke:al8-py311-AISO125` | 580 MB | AISO-125 rollback variant |
| `alma-audit-smoke:al8-py311-AISO125-split` | 580 MB | AISO-125 split-process variant |

## Stack & Key Dependencies

- **Python 3.10+**, setuptools (`pyproject.toml`), `src/alma_audit/`
  layout, license MIT.
- **Runtime:** `PyYAML>=5.1` only. Everything else is stdlib (`re`,
  `socket`, `ipaddress`, `logging`, `dataclasses`, `argparse`,
  `fnmatch`, `ast`, `urllib.parse`).
- **`[ssl]` extra:** `cryptography>=42` for X.509 parsing — the only
  optional runtime dep. Without it the `ssl_cert` analyzer emits a
  single WARN naming the missing dependency.
- **`[dev]` extra:** `pytest>=7`, `pytest-cov>=4`.
- **No HTTP client.** The audit builds Cloudflare firewall-rule JSON
  payloads + a `curl` script — it **never** calls the CF API itself.
- **CLI script:** `alma-audit = "alma_audit.cli:main"` in
  `pyproject.toml [project.scripts]`.

## Conventions

- **Python style:** `from __future__ import annotations` at the top
  of every module; type hints everywhere (`list[Finding]`,
  `dict[str, Any]`, `Severity | None`); dataclasses + Enums in
  `models.py`; docstrings describe **contract**, not implementation;
  `# noqa: F401` only when a re-export would otherwise trigger lint;
  `from dataclasses import replace` for immutable updates.
- **Naming:** `snake_case` modules and functions, `PascalCase` classes
  (`Finding`, `Severity`, `AccessAggregator`, `Resolver`),
  `UPPER_SNAKE` module constants (`DEFAULT_RULES`, `_CIDR_RE`,
  `LENGTH_WARN`, `_CHUNK_SIZE`).
- **File layout — analyzer split (GAPS §7.3):**
  `analyzers/<name>/{__init__.py, parser.py, aggregator.py, rules.py, settings.py}`.
  `__init__.py` is **re-exports only**, never logic. `settings.py`
  holds the default threshold dict at the top (grep `DEFAULT_RULES`).
  Single-purpose flat modules (`csf_state.py`, `modsec_log.py`,
  `domlog_inventory.py`, `crawler_verify.py`) are kept under one file
  only when the logic is < ~300 LOC; otherwise split.
- **Imports:** relative inside the package (`from ..models import
  Finding`); `from __future__ import annotations` lets us omit the
  forward-reference cost in type hints. Public analyzers re-export
  their entry point from `__init__.py` so `runner.py` only sees one
  import per analyzer.
- **Error handling — read vs. write split:**
  - Analyzers never call `open()` directly — they go through the
    injected `FileSystem` (`runners.py`).
  - `fs.read_text(path)` is **strict** (raises `OSError`); use it
    when the analyzer needs to emit a "permission denied" WARN.
  - `fs.open_text(path)` is **permissive** (swallows `OSError`,
    returns `[]`); use it for "scan as many lines as you can, skip
    the broken ones".
  - The `tests/test_readonly.py` AST check rejects any `open()` call
    in `analyzers/`, and any `open(..., "w"/"a")` outside
    `reporting.py`.
- **Compression:** `.gz`/`.bz2`/`.xz`/`.zst`/`.lz4` rotations are
  skipped silently (text-mode opening would error; the read-only
  contract forbids shelling out to `gunzip`). Skipped paths are
  listed in the report's `skipped_compressed` detail so the operator
  can see the audit was incomplete.
- **Comments only for non-obvious rationale**, security / protocol
  invariants, or the public contract. The GAPS §7 split is enforced
  at PR review; PR descriptions reference the AISO ticket id
  (e.g. "AISO-202: chunk CF payloads at 500 IPs").

## Architecture

```
src/alma_audit/
├── cli.py             # argparse entry — builds report, exits 0/1/2
├── config.py          # YAML loader + Paths/Config dataclasses
├── models.py          # Severity enum, Finding/AuditReport dataclasses
├── runners.py         # FileSystem Protocol + RealFileSystem + FakeFileSystem
├── runner.py          # orchestration: run_analyzers(cfg, fs) → list[Finding]
├── ip_normalise.py    # canonical IP literal → (canonical, scope)
├── self_ip.py         # AISO-201: host's own IPs (DNS only, no subprocess)
├── reporting.py       # JSON + Markdown + forensic writers
├── forensic_export.py # Cloudflare firewall-rule payloads + curl script
└── analyzers/
    ├── access_log/        # parser + aggregator + rules + settings (5 files)
    ├── secure_log/        # same 5-file split
    ├── ssl_cert/          # same 5-file split
    ├── cphulk_log/        # same 5-file split
    ├── csf_state.py       # flat — single-purpose CSF denylist reader
    ├── domlog_inventory.py # flat (541 LOC — the largest src file)
    ├── domlog_roots.py    # AISO-194 multi-root defaults
    ├── modsec_log.py      # flat (351 LOC — could split per GAPS §7.3)
    └── crawler_verify.py  # Googlebot PTR+forward+suffix verification chain
```

**Data flow:**
1. `cli.main(argv)` parses args → `load_config()` → `RealFileSystem()` →
   `run_analyzers(cfg, fs)` → flat `list[Finding]`.
2. Each analyzer exports `analyze_<name>(..., fs, rules) -> list[Finding]`.
   It only reads through `fs`, never writes.
3. `runner.run_analyzers` wires them together in order:
   - `apache_root` → `access_log` (D1/D4/D2/D5: top-host,
     4xx/5xx burst, probe paths, weird methods)
   - `domlog_roots` or `domlog_root` → `domlog_inventory` (D7:
     filename anomalies + subdir ownership)
   - `error_log` + `modsec_audit*` → `modsec_log_and_errors`
     (D5/D6: 5xx rate, modsec deny/drop/block, severity 1/2)
   - `secure_log_glob` + `auth_log_glob` → `secure_log`
     (D8/D9/D10/D11: SSH/sudo burst, UID=0 useradd; **filtered
     by `self_ips`**)
   - `cphulk_log_glob` → `cphulk_log` (D14/D15/D16: brute-force
     burst, block/unblock summary)
   - `ssl_cert_roots` + `ssl_cert_glob` → `ssl_cert`
     (D12/D13: PEM X.509 expiry windows; needs `[ssl]` extra)
   - `csf_deny_paths` + `csf_allow_paths` → `csf_state`
     (D17/D18/D19/D20: denylist size, growth vs baseline, malformed,
     unreadable)
4. `reporting.build_report(findings)` → `AuditReport`.
5. `write_json_report`, `write_markdown_report`, `write_forensic_report`,
   `write_cloudflare_block_script` write the four artifacts.

**Deployment paths:**
- **systemd timer:** `examples/alma-audit.timer` + `alma-audit.service`
  (`User=root`, `ProtectSystem=strict`, `ReadOnlyPaths=/var/log/apache2 /var/log/apache2/domlogs`,
  `ReadWritePaths=/var/log/alma-audit`, `NoNewPrivileges=true`,
  `LockPersonality=true`, `RestrictNamespaces=true`).
- **Plain cron:** equivalent crontab in `deploy/README-deploy.md`
  (rotate yesterday's report at 04:14, run audit at 04:15, run
  `audit-diff.py` at 04:16).
- **Trend sidecar:** `examples/audit-diff.py` — diffs two
  `alma-audit-latest.json` reports (read-only), emits JSON / Markdown /
  text. Deterministic (sorted by severity, kind, module, title).
  Lives in `examples/`, not in the package — operators who don't
  run it pay no runtime cost.

## AISO Ticket Map (what each batch added)

| Ticket | What it does | Where |
|---|---|---|
| **AISO-119** | `DOMLOG_BAD_NAME` v1.2 contract — case-SENSITIVE regex, 31-case regression corpus. Detects `hostdziAAAA...`-style filenames. | `analyzers/domlog_inventory.py` + `tests/test_domlog_d7_corpus.py` |
| **AISO-124** | Permission-safe `listdir` — chmod-000 dirs return `[]`, not traceback. | `runners.py:RealFileSystem.listdir` |
| **AISO-125** | `nobody` user can run the audit on AlmaLinux 8; chmod-000 emits WARN. | `tests/Dockerfile.smoke` + `tests/test_unreadable_log_root.py` |
| **AISO-186** | Quick-win analyzers: secure_log, ssl_cert, cphulk_log, csf_state. | 4 new analyzer packages + `test_secure_log.py`, `test_csf_state.py`, etc. |
| **AISO-189** | Quick-win analyzers: re-exports + `runners.read_bytes` + reporting tweaks. | `runners.py`, `reporting.py` |
| **AISO-194** | Multi-root domlog discovery (`--domlog-roots` repeatable). | `analyzers/domlog_roots.py`, `cli.py`, `config.py` |
| **AISO-197** | Per-(path,ip) probe forensic + `top_attackers` rollup across access_log / secure_log. | `analyzers/access_log/aggregator.py`, `analyzers/secure_log/aggregator.py` |
| **AISO-198** | Recursive domlog scan; account-ID subdirs are scope-info (not anomaly). | `analyzers/domlog_inventory.py` |
| **AISO-199** | `alma-audit-forensic.json` split from main report; concise MD top-10. | `reporting.py:_strip_forensic`, `write_forensic_report` |
| **AISO-200** | Local-IP filter before CF rule emission (private/loopback/ULA/CGNAT/CF-internal ranges). | `forensic_export.py:_LOCAL_NETWORKS` |
| **AISO-201** | Host self-IP detector (`socket.getaddrinfo`, no subprocess) → filter SSH/sudo brute-force events from self. | `self_ip.py`, `analyzers/secure_log/aggregator.py` |
| **AISO-202** | CF rule payloads chunk at 500 IPs (4 KiB ceiling). | `forensic_export.py:_CHUNK_SIZE` |
| **AISO-203..209** | Current rollup (see `verify_all.sh`). AISO-209 is the SSH hardening analyzer: `analyzers/ssh_hardening/` (5-file split) reads `/etc/ssh/sshd_config` + `/etc/ssh/sshd_config.d/*.conf` (alphabetical order, matching OpenSSH `Include`); flags PermitRootLogin yes / PermitEmptyPasswords yes / Protocol 1 as CRITICAL, weak Ciphers/MACs / default port / missing allowlist as WARN, X11Forwarding / prohibit-password / no Banner as INFO. | `analyzers/ssh_hardening/` |

## Gotchas / Boundaries

- **Never write `subprocess.run`, `os.system`, `shell=True`, or
  `open(..., "w"/"a")` outside `reporting.py`.** The AST check in
  `tests/test_readonly.py` blocks the PR. Use the injected
  `FileSystem` for any file access. Note the `FORBIDDEN_CALLS` set
  in `test_readonly.py` — `open` IS allowed when `mode` is unset or
  contains `r` without `w`/`a`, so wrapping an `open(..., "r")`
  inside a helper is fine.
- **Never fabricate `daemon_id` / filesystem paths in tests** — read
  from `socket.gethostname()` or accept them as arguments; the
  `FakeFileSystem` covers in-memory needs.
- **`tests/fixtures/`** holds static test inputs. Currently:
  `sshd_config_weak.conf` and `sshd_config_strong.conf` for the
  ssh_hardening analyzer (AISO-209). Add new fixtures here when an
  analyzer needs a multi-line input file that doesn't fit inline
  in the test body.
- **`uv.lock` is git-ignored on purpose** (`.gitignore` line 45).
  `pyproject.toml` uses **setuptools**, not uv; the lockfile is a
  local artifact left behind by someone's dev shell. Don't ship it.
- **Cloudflare rule payloads chunk at 500 IPs** (`_CHUNK_SIZE` in
  `forensic_export.py`, AISO-202). Single-chunk rules keep their
  original `description` — the `(chunk N/M)` suffix only appears
  when there's more than one chunk, so existing operator dashboards
  don't break.
- **Local / private / loopback / link-local / Cloudflare-internal
  / CGNAT / documentation / reserved ranges are stripped before CF
  rule emission** (AISO-200, `_LOCAL_NETWORKS` in `forensic_export.py`).
  The forensic JSON keeps the unfiltered list; only the CF payload
  drops them.
- **`DOMLOG_BAD_NAME` regex is case-SENSITIVE.** v1.0 used
  `re.IGNORECASE` and produced FPs (`abcdefghijklmnopqrst`). v1.2
  removed the flag; the 31-case `tests/test_domlog_d7_corpus.py` is
  the regression lock — flipping any case flips a detector contract.
- **A chmod-000 domlog root must NOT crash the audit** — it emits a
  WARN finding naming the unreadable path. `tests/test_unreadable_log_root.py`
  + `tests/smoke_entrypoint.sh` lock this behavior. `RealFileSystem.listdir`
  swallows `PermissionError` and returns `[]`; the runner's
  `_probe_root_readable` translates this into the WARN.
- **Self-IP detection** (`self_ip.py`) uses only `socket.getaddrinfo`,
  not `ip route` / `hostname -I` — a deliberate trade-off so the
  read-only contract stays trivially auditable. NAT'd hosts may need
  explicit entries via `modules.secure_log.trusted_ips` in YAML.
  The set merges explicit overrides INTO the auto-detected set,
  never replaces it.
- **Max 1000 LOC per `src/alma_audit/` file** (hard rule,
  `docs/GAPS.md` §7). Plan the split up-front — `domlog_inventory.py`
  is currently 541 LOC and the next growth push should split per
  §7.3 (`parser.py` + `aggregator.py` + `rules.py` + `settings.py`).
  PRs that push a single file past 1000 lines are rejected at review.
- **Analyzer exit code signal:** any WARN/CRITICAL → CLI exits 1 →
  cron `|| mail` fires. INFO-only or zero findings → exit 0.
  Config parse error → exit 2.
- **`alma-audit-out/` and `multica-delegation-*.md` are git-ignored
  by name** (`.gitignore` lines 39-40) — these are local scratch /
  delegation artifacts, never shipped.
- **`tests/` directory** has **no `__init__.py`** — pytest uses the
  rootdir + `conftest.py` pattern; adding `__init__.py` would
  shadow the package. Do not add it.

## Security Constraints

- **Read-only by contract** — enforced by AST in `tests/test_readonly.py`.
  The toolkit reads Apache / domlog / ModSecurity / secure / auth /
  cPHulk / CSF state files and **only writes** the four report
  artifacts in `<output>`. It never touches source logs, never calls
  `csf -l` or `csf -f`, never modifies `fail2ban` / cPHulk / cPanel
  state.
- **No network egress.** The audit builds CF rule payloads but
  never calls the Cloudflare API; the operator runs the generated
  `cloudflare-block.sh` script manually after setting `CF_ZONE_ID`
  + `CF_API_TOKEN`. The smoke container runs with `--network=none`
  for the same reason.
- **DNS lookups stay inside stdlib** — `socket.getaddrinfo` for
  self-IP detection, `socket.gethostbyname_ex` for crawler
  verification (`crawler_verify.py`). No `dig`, no `host`, no shell.
  The read-only contract forbids `subprocess` outright.
- **Inputs are untrusted text** — log lines, YAML config, PEM blobs.
  The parser layer (`access_log/parser.py`, `secure_log/parser.py`)
  returns `None` on malformed lines; the aggregator counts them
  under `malformed` and the analyzer surfaces a soft WARN. The
  `domlog_inventory._normalise_for_d7` 4-step pipeline (strip
  cPanel suffixes, strip trailing dot+port, percent-decode,
  replace control chars) runs on the raw input verbatim — no
  case-folding.
- **Service-account recommendation** (from `csf_state.py` finding
  text): grant a dedicated `alma-audit` group POSIX ACL read access
  on `/etc/csf/csf.{deny,allow}`. Avoid `wheel` membership or
  blanket `chmod a+r` — csf.deny reveals the operator's blocklist.
- **Crawler self-claim verification** (D1/D4 in `access_log/rules.py`):
  a UA claiming Googlebot MUST verify via PTR + forward-confirmation
  + suffix match before its top-host activity is downgraded to INFO.
  The verification chain has 3s/IP timeout (`SocketResolver`).
  D2/D5 (probe paths, weird methods) are NEVER crawler-suppressible
  even with a verified claim — a Googlebot asking for `/.env` is an
  event worth logging.
