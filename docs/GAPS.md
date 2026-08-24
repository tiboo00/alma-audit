# Gaps in `alma-audit` — what it does NOT cover

**Status:** living document. Last revised against `src/alma_audit/` at the
current tree state. Adds §7 (file-size discipline rule, 2026-08-22).
Updates §7.2 after splitting `analyzers/access_log.py` into the
`analyzers/access_log/` package (2026-08-22).

`alma-audit` is a **layer-7 Apache / domlog / ModSecurity read-only
detector**. It is not a system audit, not a compliance scanner, and not a
replacement for a hardened host baseline. This file lists the security
surfaces the toolkit deliberately does **not** touch, why each gap exists
in the current design, and what would be needed to close it.

---

## 1. At a glance — coverage matrix

| Layer | Surface | Covered by `alma-audit`? | Notes |
|---|---|---|---|
| Layer-7 | Apache access_log | ✅ partial | top talker, 4xx/5xx, probe paths, weird method |
| Layer-7 | domlog inventory | ✅ partial | filename anomalies, layout, ownership |
| Layer-7 | ModSecurity audit | ✅ partial | deny/drop/block, severity, 5xx rate |
| Layer-7 | Crawler self-claim verification | ✅ yes | fail-closed PTR+forward+suffix, 3s/IP timeout |
| Layer-7 | Operator suppression list | ✅ yes | trusted-IP / UA whitelist to suppress findings |
| Auth | `/var/log/secure` / `journald` (sshd, sudo) | ✅ partial | failed-SSH burst, sudo fail burst, useradd UID=0 (AISO-186) |
| Auth | `last`, `lastb`, failed login correlation | ❌ no | out of scope |
| cPanel | `/var/cpanel` config drift | ❌ no | out of scope |
| cPanel | Account quota / license / EasyApache profile | ❌ no | out of scope |
| cPanel | MySQL grant audit / mail queue poisoning | ❌ no | out of scope |
| cPanel | cPHulk brute-force log | ✅ partial | per-IP + per-user burst, block/unblock summary (AISO-186) |
| cPanel | SSL/TLS cert expiry | ✅ partial | PEM X.509 expiry windows, optional `[ssl]` extra (AISO-186) |
| cPanel | CSF / csf.deny state | ✅ partial | denylist size + growth vs baseline (AISO-186) |
| WHMCS | `configuration.php` perms / license | ❌ no | out of scope |
| WHMCS | Fraud / order log / gateway webhook abuse | ❌ no | out of scope |
| WHMCS | Admin audit log / module audit | ❌ no | out of scope |
| Webshell | Content-level webshell scan | ❌ no | only filename-level via domlog |
| Compliance | PCI-DSS / CIS Benchmark / NIST | ❌ no | out of scope |
| Trend | Cross-run baseline / regression detection | ✅ partial | sidecar `examples/audit-diff.py` + csf_state baseline (AISO-186) |

**Short version:** if you ran only `alma-audit` and walked away, you would
have **layer-7 visibility and nothing else**.

---

## 2. Why these gaps exist (design intent)

The toolkit is intentionally narrow for three reasons:

1. **Read-only contract.** No module under `src/alma_audit/` calls
   `subprocess`, `os.system`, `os.popen`, `shell=True`, or any write API.
   The only `open(..., "w")` calls are in `reporting.py` for the two
   report artifacts. `tests/test_readonly.py` enforces this by AST/grep.
   Closing most system-layer gaps (package audit, SUID scan, sysctl) would
   require invoking external tools — which would either break the contract
   or require sandboxing the audit under a privileged wrapper.
2. **Cron-friendly failure mode.** Exit 0 = clean, exit 1 = any WARN/CRIT.
   This is only useful if the runtime stays bounded. Pulling in
   vulnerability databases, network scans, or DNS-heavy work for every
   host would break that budget.
3. **Single-host scope.** No remote coordination, no fleet baseline, no
   central store. The report is two files on local disk. Fleet-level
   coverage lives in a different product.

These are **trade-offs**, not oversights — the README and `deploy/`
docs position the tool as a complementary layer, not as a full audit.

---

## 3. What's needed to close each gap

The table below groups gaps by the kind of work required. Most cluster
into four buckets: **separate tool** (don't bolt onto alma-audit),
**out-of-band scanner** (Lynis / OpenSCAP / Wazuh / AIDE), **read-only
log expansion** (could be added inside the package without breaking the
read-only contract), or **stateful layer** (needs new infrastructure).

### 3.1 OS / kernel hardening

| Gap | Where it lives | Tool / approach | Fits in alma-audit? |
|---|---|---|---|
| CIS / NIST hardening | host | **Lynis** (`lynis audit system`), **OpenSCAP** (`oscap xccdf eval`) | ❌ separate tool |
| SUID / SGID / world-writable | filesystem | `find / -perm -4000`, wrapper script | ⚠️ possible but breaks read-only if it shells out |
| File integrity | filesystem | **AIDE**, **mtree**, **OSSEC** | ❌ stateful, needs baseline |
| Package CVE | `rpm` DB | `rpm -Va`, **Vuls**, **dnf-plugin-security** | ❌ network/DB |
| Kernel module load | `dmesg`, kmsg | custom parser | ⚠️ read-only log parser — could fit |
| SELinux AVC | `/var/log/audit/audit.log` | `ausearch -m avc`, **Wazuh** | ⚠️ read-only parser — could fit |

**Recommended path:** run Lynis nightly, ship its report alongside
`alma-audit-latest.md`. Do not bolt it into the package.

### 3.2 SSH / auth

| Gap | Where it lives | Tool / approach | Fits in alma-audit? |
|---|---|---|---|
| SSH config drift | `/etc/ssh/sshd_config` | file parser + CIS ruleset | ⚠️ read-only file — could fit as a small module |
| Failed SSH login | `/var/log/secure` (RHEL), `auth.log` (Debian) | regex parser | ✅ **implemented** (AISO-186 — `secure_log` analyzer) |
| `sudo` anomália | `/var/log/secure` | parser | ✅ **implemented** (AISO-186 — `secure_log` analyzer) |
| `last` / `lastb` | `wtmp`, `btmp` | `last -f` reader | ❌ command needed — breaks read-only unless wrapped |

**Recommended path:** the `secure_log` analyzer (implemented in
AISO-186) covers the two regex-parsable auth gaps. The `wtmp` /
`btmp` paths remain out of scope because reading them requires a
binary parser that would need to shell out or replicate `last`'s
internal table layout — both are higher-cost than the value
delivered.

### 3.3 cPanel-specific

| Gap | Where it lives | Tool / approach | Fits in alma-audit? |
|---|---|---|---|
| cPanel config drift | `/var/cpanel` | YAML/diff parser | ⚠️ read-only file — could fit |
| cPHulk brute-force log | `/var/log/cphulkd.log` | parser | ✅ **implemented** (AISO-186 — `cphulk_log` analyzer) |
| CSF state | `/etc/csf/csf.deny`, `/var/log/csf.log` | parser | ✅ **implemented** (AISO-186 — `csf_state` analyzer) |
| SSL cert expiry | `/var/cpanel/ssl/*` | `cryptography` lib, no shelling out | ✅ **implemented** (AISO-186 — `ssl_cert` analyzer; opt-in `[ssl]` extra) |
| MySQL grant audit | MySQL client | requires DB connection | ❌ breaks read-only |
| Mail queue poisoning | `/var/spool/exim/` | requires read of live queue | ⚠️ possible with care |
| EasyApache profile | `/etc/cpanel/ea4` | YAML parser | ⚠️ read-only — could fit |

**Recommended path:** the three cPanel regex-parsable gaps
(`cphulkd.log`, `csf.deny`, `cpanel/ssl/*.pem`) all landed in the
package as separate analyzer modules under
`src/alma_audit/analyzers/` (AISO-186). DB-bound checks
(MySQL grants, cPanel account quotas, license state) belong in a
**WHMCS-side plugin** that talks to the application directly.

### 3.4 WHMCS-specific

| Gap | Where it lives | Tool / approach | Fits in alma-audit? |
|---|---|---|---|
| `configuration.php` perms | `/var/www/whmcs/configuration.php` | `os.stat` + threshold | ⚠️ read-only — could fit |
| License key rotáció | DB | requires DB connection | ❌ breaks read-only |
| Fraud order log | DB | requires DB connection | ❌ breaks read-only |
| Gateway webhook abuse | access_log (WHMCS URL path) | already covered by `access_log` probe rules | ✅ already covered, may need whitelist |
| Admin audit log | DB | requires DB connection | ❌ breaks read-only |

**Recommended path:** DB-bound checks belong in a **WHMCS-side plugin**
that talks to the application directly. Do not try to drive SQL from
`alma-audit`.

### 3.5 Webshell / content-level

| Gap | Where it lives | Tool / approach | Fits in alma-audit? |
|---|---|---|---|
| Webshell signature scan | `/home/*/public_html` | **LMD** (Linux Malware Detect), **ClamAV**, **YARA** | ❌ separate tool |
| PHP backdoor heuristics | same | PHP parser + heuristics | ❌ out of scope by design |
| `.htaccess` injection | same | file parser | ⚠️ read-only — could fit |

**Recommended path:** install LMD or ClamAV; alma-audit only flags
filename-level anomalies in domlog.

### 3.6 Network / listening services

| Gap | Where it lives | Tool / approach | Fits in alma-audit? |
|---|---|---|---|
| Open ports / services | kernel netlink | `ss -tulnp`, `netstat` | ❌ requires command — breaks read-only |
| Unexpected bind | same | parser | ❌ |
| Reverse shell indicator | `ss` + `/proc/*/fd` | custom parser | ❌ requires live system |
| Outbound C2 | netflow / conntrack | separate pipeline | ❌ |

**Recommended path:** `ss -tulnp` snapshot at audit time, wrapped in a
sandboxed helper. Not a fit for the current package; better as a sidecar
script that writes its own report.

### 3.7 Compliance frameworks

| Gap | Tool / approach | Fits in alma-audit? |
|---|---|---|
| CIS AlmaLinux 8 Benchmark | **OpenSCAP** with `ssg-alma8` content | ❌ |
| PCI-DSS 4.0 | manual + scanner combo | ❌ |
| NIST 800-53 | OpenSCAP profiles | ❌ |

**Recommended path:** compliance evidence is a separate deliverable. Do
not overload `alma-audit` with it.

### 3.8 Trend / stateful detection

| Gap | Why missing | What's needed |
|---|---|---|
| Baseline diff between runs | No on-host store, no fleet aggregator | ✅ **implemented** as a sidecar: `examples/audit-diff.py` (AISO-186) takes two `alma-audit-latest.json` reports and emits a structured `added` / `removed` / `severity_changed` / `count_changed` diff in JSON, Markdown, or plain-text format. The csf_state analyzer also surfaces growth/shrinkage deltas when an operator-supplied `deny_baseline` is configured. |
| Fleet baseline | No central sink | A separate collector (the dashboards at `multica.aisolve.me` / `aisolve-dashboard` already exist for other products) — design choice, not in scope of this repo. |

---

## 4. Quick wins — gaps that fit cleanly inside the package

All five quick wins below are **implemented** as of AISO-186
(2026-08-24):

1. **`secure_log` analyzer** (`src/alma_audit/analyzers/secure_log/`)
   — parses `/var/log/secure*` and `/var/log/auth.log*` for failed
   SSH, sudo authentication failures, new user / group creation,
   and passwd-change events. Pure Python, ~330 LOC across the
   parser / aggregator / rules / settings / analyzer split
   (per GAPS §7.3). Adds INFO/WARN/CRITICAL findings and one
   always-CRITICAL rule for UID=0 account creation.
2. **`ssl_cert` analyzer** (`src/alma_audit/analyzers/ssl_cert/`)
   — globs `/var/cpanel/ssl/*`, `/etc/pki/tls/certs/*`, and
   `/etc/ssl/certs/*` (configurable), uses
   `cryptography.x509.load_pem_x509_certificate` to flag certs
   expiring within `expiry_warn_days` (WARN, default 14) and
   `expiry_crit_days` (CRITICAL, default 3). Pure Python. The
   `cryptography` dependency is **optional** — install with
   `pip install 'alma-audit[ssl]'`. Without it the analyzer emits
   a single WARN naming the missing dependency.
3. **`cphulk_log` analyzer** (`src/alma_audit/analyzers/cphulk_log/`)
   — parses `/var/log/cphulkd.log*` for `Brute force attempt`
   events (per-IP + per-user burst counts) and the `Account/IP
   blocked` events. Pure Python, ~250 LOC.
4. **`csf_state` analyzer** (`src/alma_audit/analyzers/csf_state.py`)
   — reads `/etc/csf/csf.deny` and `/etc/csf/csf.allow`, counts
   active entries (excluding comments and the `Include` directive
   recursion), warns on denylist size > `deny_count_warn` (200) /
   `deny_count_crit` (2000), and surfaces growth / shrinkage deltas
   when an operator-supplied `deny_baseline` is present. Flat
   module (one file, ~270 LOC) because the logic is single-purpose.
5. **Trend sidecar** (`examples/audit-diff.py`) — diffs two
   `alma-audit-latest.json` reports and emits a structured
   "what changed" summary in JSON, Markdown, or plain-text format.
   Read-only (it never mutates the input reports), deterministic
   output (rows are sorted by severity, kind, module, then title),
   and shipped with a 23-test unit suite covering the three
   formats, the four diff kinds, and the CLI plumbing.

The five quick wins above reuse the existing `Runner` interface,
emit the same `Finding` dataclass, and land in the same JSON +
   Markdown report with no breaking change to existing analyzers.
None call `subprocess` or write back to source data.

---

## 5. Out-of-scope by deliberate decision

These are **not** gaps to close — they are design choices the user
already approved:

- **No remote coordination.** Single-host, two output files. Federation
  is a different product.
- **No baseline / DB.** No SQLite, no JSONL history. Trend is a
  post-process, not a feature.
- **No webhook / alerting.** A WARN finding is text in a file. Paging
  is the operator's job.
- **No fix automation.** The toolkit reports; humans act. The README is
  explicit about this.
- **No write back to source.** No module calls `open(..., "w")` outside
  `reporting.py`. `tests/test_readonly.py` enforces it.

These are listed so future contributors do not re-propose them.

---

## 6. How to use this file

- **If you are scoping a future sprint:** jump to §4 (quick wins) and
  §3 (everything else, with effort estimates).
- **If you are answering "is this tool enough for compliance audit?":**
  jump to §1 (coverage matrix) and §3.7. Short answer: no.
- **If you are reviewing a PR that adds a new analyzer:** verify the
  gap it closes is listed here and the chosen approach matches the
  "fits in alma-audit?" column. Also check §7 for the file-size
  discipline rule before approving.
- **If you are auditing the audit:** confirm the out-of-scope items in
  §5 are still intentional and not bit-rotted assumptions.
- **If you are about to add code to `src/alma_audit/`:** read §7 first.
  The 1000-line ceiling is enforced at review; planning the split
  up-front is cheaper than re-doing the PR after rejection.

---

**Maintained by:** whoever touches `src/alma_audit/`. When a new
analyzer lands, update §1, remove the closed row from §3, and add a
short note to §4 only if it changed scope.

---

## 7. File-size discipline — one function per module

**Hard rule (project-wide):** **no source file in `src/alma_audit/` may
exceed 1000 lines.** When a file approaches the limit, it must be split
along its natural responsibility seams (one function / one analyzer / one
parser per file) before it crosses the line.

### 7.1 Why this rule exists

`alma-audit` is intentionally **breadth-first**: many narrow analyzers
over a wide-but-shallow layer-7 surface, plus the option to grow sideways
into secure_log, ssl_cert, cphulk, csf_state, trend (see §4). A wide
breadth means **many files**, each focused on one thing. A single file
that absorbs three responsibilities (parse + aggregate + emit) becomes
unreadable at ~600 lines, unmaintainable at ~1000, and un-reviewable
above that. The cost of review grows faster than the cost of writing the
code.

This is a **hard preference**, not a soft guideline. When proposing a
change, the question is never "should I add this to the existing file"
but always "what new file does this belong in".

### 7.2 Current state vs. the 1000-line ceiling

| File | Lines | Status | Notes |
|---|---:|---|---|
| `analyzers/access_log/aggregator.py` | 224 | 🟢 ok | AISO-197 — per-(path,ip) probe forensic + top_attackers rollup |
| `analyzers/access_log/parser.py` | 75 | 🟢 ok | Apache combined-format access log line parser |
| `analyzers/access_log/aggregator.py` | 224 | 🟢 ok | per-(path,ip) forensic detail, top_attackers, host_errors_top (AISO-197) |
| `analyzers/access_log/rules.py` | 268 | 🟢 ok | D1/D4/D2/D5; D2 details include probe_paths_by_ip + top_attackers (AISO-197) |
| `analyzers/access_log/analyzer.py` | 125 | 🟢 ok | orchestrator: `analyze_access_logs()` public entry |
| `analyzers/access_log/__init__.py` | 41 | 🟢 ok | re-exports only, no logic |
| `analyzers/domlog_roots.py` | 68 | 🟢 ok | AISO-194 — multi-root + bytes_log exclusion defaults |
| `analyzers/domlog_inventory.py` | 541 | 🟢 ok | AISO-198 — recursive scan, account-ID subdirs are scope-info (not anomaly) |
| `analyzers/modsec_log.py` | 351 | 🟢 ok | could split: `modsec_parser.py` + `modsec_analyze.py` |
| `analyzers/crawler_verify.py` | 317 | 🟢 ok | tightly scoped (one verification chain); keep as-is |
| `analyzers/secure_log/parser.py` | 293 | 🟢 ok | AISO-186/197 — syslog + sudo + useradd regexes; carries raw_timestamp |
| `analyzers/secure_log/aggregator.py` | 178 | 🟢 ok | AISO-197 — per-(ip,user) SSH/sudo forensic detail with timestamps |
| `analyzers/secure_log/rules.py` | 197 | 🟢 ok | D8/D9/D10/D11 rules |
| `analyzers/secure_log/settings.py` | 51 | 🟢 ok | thresholds + globs |
| `analyzers/secure_log/analyzer.py` | 199 | 🟢 ok | orchestrator |
| `analyzers/secure_log/__init__.py` | 45 | 🟢 ok | re-exports |
| `analyzers/ssl_cert/parser.py` | 101 | 🟢 ok | X.509 PEM parser, optional `[ssl]` extra |
| `analyzers/ssl_cert/aggregator.py` | 47 | 🟢 ok | thin aggregator |
| `analyzers/ssl_cert/rules.py` | 122 | 🟢 ok | D12/D13 expiry + read-error rules |
| `analyzers/ssl_cert/settings.py` | 34 | 🟢 ok | thresholds + cert roots |
| `analyzers/ssl_cert/analyzer.py` | 255 | 🟢 ok | orchestrator |
| `analyzers/ssl_cert/__init__.py` | 45 | 🟢 ok | re-exports |
| `analyzers/cphulk_log/parser.py` | 123 | 🟢 ok | cPHulk syslog parser |
| `analyzers/cphulk_log/aggregator.py` | 76 | 🟢 ok | per-IP + per-user counters |
| `analyzers/cphulk_log/rules.py` | 146 | 🟢 ok | D14/D15/D16 rules |
| `analyzers/cphulk_log/settings.py` | 41 | 🟢 ok | thresholds + globs |
| `analyzers/cphulk_log/analyzer.py` | 168 | 🟢 ok | orchestrator |
| `analyzers/cphulk_log/__init__.py` | 46 | 🟢 ok | re-exports |
| `analyzers/csf_state.py` | 376 | 🟢 ok | single-purpose flat module (AISO-186) |
| `runners.py` | 349 | 🟢 ok | single responsibility (file-glob runner + injected FS + read_bytes); grew from 284 after AISO-189 quick-win wiring — still well under the 1000-line ceiling |
| `runner.py` | 239 | 🟢 ok | orchestration only; no detection logic |
| `cli.py` | 133 | 🟢 ok | argparse + entry; nothing to split |
| `config.py` | 158 | 🟢 ok | YAML loader + defaults + new quick-win root paths |
| `ip_normalise.py` | 105 | 🟢 ok | pure utility; do not grow |
| `reporting.py` | 94 | 🟢 ok | two writers; could split `json_writer.py` / `md_writer.py` if it grows |
| `models.py` | 55 | 🟢 ok | dataclasses only |
| `__init__.py` | 3 | 🟢 ok | — |

**No file currently exceeds 1000 lines**, and the largest single
file is `domlog_inventory.py` at 367 lines. The five new
quick-win analyzers (AISO-186) all follow the §7.3 standard
split — even the smallest (`ssl_cert`) is a five-file package.

### 7.3 How to split (the standard pattern)

When a file approaches the limit, follow this split:

```
src/alma_audit/analyzers/<name>/
├── __init__.py              # re-exports analyze_<name>()
├── parser.py                # line → record parsing, no rules
├── aggregator.py            # in-memory state, no findings emission
├── rules.py                 # detection rules → Finding[]
└── settings.py              # threshold defaults (WARN/CRIT)
```

The package keeps the existing `analyze_<name>() -> list[Finding]`
public entry point so `runner.py` and `runners.py` need no changes.

**Rules of thumb:**

- **One parser per file.** If a module parses two log formats (e.g.
  Apache combined + Apache error), split into `parser_access.py` and
  `parser_error.py`.
- **One detection rule per file** when a rule is non-trivial (>50 LOC).
  Tiny one-line rules (`title="...", severity="..."`) stay grouped.
- **Settings always live in `settings.py`** with the default threshold
  dict at the top, so operators can grep `default_settings` and find the
  one source of truth.
- **`__init__.py` is a re-export only**, never logic.

### 7.4 Reviewer check (add to PR review checklist)

A PR that touches `src/alma_audit/` should be rejected at review if any
of these are true:

1. A single file is being pushed past 1000 lines without a split.
2. A new analyzer is being added to an existing module instead of as a
   new file under `analyzers/<name>/`.
3. A new detection rule is being inlined into a parser or aggregator
   instead of put in a `rules.py` / `rules_<name>.py`.
4. Two unrelated concerns (e.g. log parsing + JSON writing) share a
   file.

### 7.5 What this rule is NOT

- **Not a line-count fetish.** A 200-line file with one tightly-scoped
  responsibility is fine. A 600-line file with three responsibilities is
  not.
- **Not "everything must be its own file."** Tightly-coupled helpers
  (e.g. `parser.py` + `parser_helpers.py` for a 30-line utility) stay
  together if separating them costs more readability than it adds.
- **Not retroactive.** Do not split stable, well-tested code just to hit
  the count. Split when the file is being **touched and grown**, or when
  a second responsibility is being added.
- **Not applied to tests or docs.** Test files routinely exceed 1000
  lines by design (long fixtures, parametrized matrices). `docs/*.md`
  can be long if the topic warrants it. The 1000-line ceiling applies
  only to `src/`.