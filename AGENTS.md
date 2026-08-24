# AGENTS.md

## Project Overview

`alma-audit` is a **read-only** Python 3.10+ security audit toolkit for
AlmaLinux WHMCS/cPanel hosts. It parses Apache access logs, domlogs,
error logs, ModSecurity audit logs, `/var/log/secure` + `auth.log`,
cPHulk logs, CSF state files, and X.509 certs; emits structured
JSON + Markdown reports plus a per-IP forensic JSON and a copy-paste
Cloudflare block script. The toolkit **never** writes back to source
logs, never changes firewall / fail2ban / cPanel / WHMCS state, and
never spawns subprocesses. Single-host scope, runs as root from a
systemd timer or cron.

## Build, Test & Development

```bash
# Editable install with dev extras (pytest, pytest-cov)
pip install -e '.[dev]'

# Optional: enable the ssl_cert analyzer (X.509 cert expiry)
pip install -e '.[ssl]'

# Run the CLI (built-in defaults — /var/log/apache2 + domlogs)
alma-audit --output /var/log/alma-audit

# Run with sample config
alma-audit --config examples/config.yaml --output ./out

# List analyzer names this build provides
alma-audit --list-analyzers

# Test suite — pytest is configured in pyproject.toml
pytest -q                                  # full suite
pytest tests/test_readonly.py              # AST check: no write APIs / no subprocess
pytest tests/test_domlog_d7_corpus.py      # 31-case regression lock (AISO-119 v1.2)
pytest tests/test_self_ip.py               # self-IP filter (AISO-201)

# End-to-end verifier (CI-style wiring check + full pytest + docker build)
./verify_all.sh                            # checks all AISO features are wired in
```

**CLI exit codes (intentional cron fail-loud):**
- `0` — INFO-only or no findings
- `1` — at least one WARN/CRITICAL (wrap cron with `|| mail ...`)
- `2` — config parse error / IO error

**Reports written to `<output>`:**
- `alma-audit-latest.json` — full machine-readable
- `alma-audit-latest.md` — concise, top-10 per category
- `alma-audit-forensic.json` — per-IP detail (no truncation)
- `cloudflare-block.sh` — generated `curl` script, chmod 755

## Stack & Key Dependencies

- **Python 3.10+**, setuptools (`pyproject.toml`), `src/alma_audit/` layout.
- **Runtime:** `PyYAML` only. Everything else is stdlib (`re`, `socket`,
  `ipaddress`, `logging`, `dataclasses`, `argparse`, `fnmatch`, `ast`).
- **`[ssl]` extra:** `cryptography>=42` for X.509 parsing — the only
  optional runtime dep; without it `ssl_cert` analyzer emits a single
  WARN naming the missing dependency.
- **`[dev]` extra:** `pytest>=7`, `pytest-cov>=4`.
- **No HTTP client.** The audit builds Cloudflare firewall-rule
  payloads + a `curl` script — it never calls the CF API itself.
- **Container image:** `deploy/Dockerfile.dev` (AlmaLinux 8.10 +
  Python 3.11) and `tests/Dockerfile.smoke` for the AISO-125
  nobody/chmod-000 smoke.

## Conventions

- **Python style:** `from __future__ import annotations` at the top
  of every module; type hints everywhere (`list[Finding]`, `dict[str, Any]`,
  `Severity | None`); dataclasses + Enums in `models.py`; docstrings
  describe contract, not implementation; `# noqa: F401` only when a
  re-export would otherwise trigger lint.
- **Naming:** `snake_case` modules and functions, `PascalCase` classes
  (`Finding`, `Severity`, `AccessAggregator`, `Resolver`), `UPPER_SNAKE`
  module constants (`DEFAULT_RULES`, `_CIDR_RE`, `LENGTH_WARN`,
  `_CHUNK_SIZE`).
- **File layout — analyzer split (GAPS §7.3):**
  `analyzers/<name>/{__init__.py, parser.py, aggregator.py, rules.py, settings.py}`.
  `__init__.py` is **re-exports only**, never logic. `settings.py`
  holds the default threshold dict at the top (grep `DEFAULT_RULES`).
  Single-purpose flat modules (`csf_state.py`, `modsec_log.py`,
  `domlog_inventory.py`) are kept under one file only when the logic
  is < ~300 LOC; otherwise split.
- **Imports:** relative inside the package (`from ..models import
  Finding`); `from __future__ import annotations` lets us omit the
  forward-reference cost in type hints.
- **Error handling:** analyzers never call `open()` directly — they
  go through the injected `FileSystem` (`runners.py`). `read_text`
  is **strict** (raises `OSError`); `open_text` is **permissive**
  (swallows `OSError`, returns `[]`). Use `read_text` when the
  analyzer needs to emit a "permission denied" WARN — that's the
  `csf_state` / `secure_log` pattern.
- **Compression:** `.gz`/`.bz2`/`.xz`/`.zst`/`.lz4` rotations are
  skipped silently (text-mode opening would error; the read-only
  contract forbids shelling out to `gunzip`).
- **Comments only for non-obvious rationale**, security / protocol
  invariants, or the public contract. The GAPS §7 split is enforced
  at PR review; PR descriptions reference the AISO ticket id.

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
3. `runner.run_analyzers` wires them together: apache_root → access_log,
   domlog → domlog_inventory, error/modsec → modsec_log_and_errors,
   secure/auth.log → secure_log (filtered by `self_ips`), cphulkd →
   cphulk_log, /var/cpanel/ssl → ssl_cert, /etc/csf/* → csf_state.
4. `reporting.build_report(findings)` → `AuditReport`.
5. `write_json_report`, `write_markdown_report`, `write_forensic_report`,
   `write_cloudflare_block_script` write the four artifacts.

**Cron path:** `examples/alma-audit.timer` + `alma-audit.service`
(`User=root`, `ProtectSystem=strict`, `ReadOnlyPaths=/var/log/apache2 /var/log/apache2/domlogs`,
`ReadWritePaths=/var/log/alma-audit`). Plain cron alternative in
`deploy/README-deploy.md`.

## Gotchas / Boundaries

- **Never write a `subprocess.run`, `os.system`, `shell=True`, or
  `open(..., "w"/"a")` outside `reporting.py`.** The AST-level check
  in `tests/test_readonly.py` blocks the PR. Use the injected
  `FileSystem` for any file access.
- **Never fabricate `daemon_id` / filesystem paths in tests** — read
  from `socket.gethostname()` or accept them as arguments; the
  `FakeFileSystem` covers in-memory needs.
- **No `tests/fixtures/` directory exists yet.** `verify_all.sh`
  expects `tests/fixtures/sshd_config_weak.conf` and `sshd_config_strong.conf`
  for the AISO-209 ssh_hardening analyzer; the analyzer module
  itself is referenced by `runner.py` but the fixtures are pending.
- **`uv.lock` is git-ignored on purpose** (`.gitignore` line 45).
  `pyproject.toml` uses **setuptools**, not uv; the lockfile is a
  local artifact left behind by someone's dev shell. Don't ship it.
- **Cloudflare rule payloads chunk at 500 IPs** (`_CHUNK_SIZE` in
  `forensic_export.py`, AISO-202). Single-chunk rules keep their
  original `description` — the `(chunk N/M)` suffix only appears
  when there's more than one chunk, so existing operator dashboards
  don't break.
- **Local / private / loopback / link-local / Cloudflare-internal
  ranges are stripped before CF rule emission** (AISO-200). The
  forensic JSON keeps the unfiltered list; only the CF payload drops
  them.
- **`DOMLOG_BAD_NAME` regex is case-SENSITIVE.** v1.0 used
  `re.IGNORECASE` and produced FPs (`abcdefghijklmnopqrst`). v1.2
  removed the flag; the 31-case `tests/test_domlog_d7_corpus.py` is
  the regression lock — flipping any case flips a detector contract.
- **A chmod-000 domlog root must NOT crash the audit** — it emits a
  WARN finding naming the unreadable path. `tests/test_unreadable_log_root.py`
  + `tests/smoke_entrypoint.sh` lock this behavior.
- **Self-IP detection** (`self_ip.py`) uses only `socket.getaddrinfo`,
  not `ip route` / `hostname -I` — a deliberate trade-off so the
  read-only contract stays trivially auditable. NAT'd hosts may need
  explicit entries via `modules.secure_log.trusted_ips` in YAML.
- **Max 1000 LOC per `src/alma_audit/` file** (hard rule, `docs/GAPS.md`
  §7). Plan the split up-front — `domlog_inventory.py` is currently
  541 LOC and the next growth push should split per §7.3.
- **Analyzer exit code signal:** any WARN/CRITICAL → CLI exits 1 →
  cron `|| mail` fires. INFO-only or zero findings → exit 0.

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
  + `CF_API_TOKEN`.
- **DNS lookups stay inside stdlib** — `socket.getaddrinfo` for
  self-IP detection, `socket.gethostbyname_ex` for crawler
  verification (`crawler_verify.py`). No `dig`, no `host`, no shell.
- **Inputs are untrusted text** — log lines, YAML config, PEM blobs.
  The parser layer (`access_log/parser.py`, `secure_log/parser.py`)
  returns `None` on malformed lines; the aggregator counts them
  under `malformed` and the analyzer surfaces a soft WARN.
- **`alma-audit-out/` and `multica-delegation-*.md` are git-ignored**
  by name — these are local scratch / delegation artifacts, never
  shipped.
- **Service-account recommendation** (from `csf_state.py` finding
  text): grant a dedicated `alma-audit` group POSIX ACL read access
  on `/etc/csf/csf.{deny,allow}`. Avoid `wheel` membership or
  blanket `chmod a+r` — csf.deny reveals the operator's blocklist.
