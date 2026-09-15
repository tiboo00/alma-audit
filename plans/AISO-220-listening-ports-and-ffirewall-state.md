# Plan — AISO-220: listening ports + firewall state coverage

> **Status:** draft — waiting for Tiboo's go-ahead before any code lands.
> **Scope:** close the GAPS §3.6 "Network / listening services" gap and
> the "is there ANY firewall at all?" gap with a two-layer design:
> sidecar (rich, subprocess-based) + analyzer (read-only fallback).
> Every output ends up in the existing `Finding` shape — no new report
> formats.

---

## 0. Why this plan

`alma-audit` currently has **9 analyzers**: `access_log`, `domlog_inventory`,
`error_log` (opt-in), `modsec_log`, `secure_log`, `cphulk_log`,
`ssl_cert`, `ssh_hardening`, `csf_state`.

What it **does not** check (Tiboo's complaint, 2026-09-15):

1. **"Is there ANY firewall at all?"** — `csf_state` only fires if CSF is
   installed. Hosts with `firewalld` only, `nftables` only, or no
   firewall at all get either an empty INFO row or nothing at all.
2. **"What ports are listening on the system?"** — no listener snapshot,
   no service-exposure analysis.
3. **"Is MySQL exposed externally?"** — neither `/etc/my.cnf`'s
   `bind-address`, nor the actual `LISTEN` state of `:3306`, nor any
   CSF/firewalld rule covering `:3306` is audited.

GAPS.md §3.6 documents this as deliberate (read-only contract — `ss`,
`netstat`, `csf -l` would shell out). The fix is a **two-layer design**
that keeps the read-only contract intact for the analyzer package and
moves the live-snapshot work into a sidecar script that writes a JSON
the analyzer can consume.

---

## 1. Design — two layers

```
┌──────────────────────────────────────────────────────────────────┐
│  LAYER A: sidecar script (rich, can shell out)                   │
│  ─────────────────────────────────────────────────────────────   │
│  tools/port_audit.sh                                             │
│    - ss -tulnp                       (TCP/UDP listeners)         │
│    - ss -tulnp6                      (IPv6 listeners)            │
│    - netstat -tulnp                  (fallback if ss missing)    │
│    - ps -ef | grep -E 'csf|firewalld|iptables|nft'               │
│    - csf -l 2>/dev/null              (CSF blocklist summary)     │
│    - firewall-cmd --list-all-zones   (firewalld state)           │
│    - iptables -S -t filter           (iptables legacy)           │
│    - iptables -S -t nat                                          │
│    - nft list ruleset               (nftables)                  │
│    - /sbin/my_print_defaults --socket mysqld | grep bind-address │
│    Output: <output>/port-audit.json (schema in §3)               │
└──────────────────────────────────────────────────────────────────┘
                              │ JSON
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  LAYER B: in-package analyzers (read-only, no subprocess)        │
│  ─────────────────────────────────────────────────────────────   │
│  src/alma_audit/analyzers/listening_ports/                       │
│    - Reads port-audit.json when present (Layer A path)           │
│    - Falls back to /proc/net/tcp, /proc/net/tcp6, udp{,6}        │
│      (read-only, always works)                                   │
│    - Maps ports → service names via port_service_map             │
│    - Emits Finding per public-bind critical port                 │
│                                                                  │
│  src/alma_audit/analyzers/firewall_state/                        │
│    - Reads port-audit.json when present (full data)              │
│    - Falls back to filesystem probe (read-only):                 │
│      /etc/csf/csf.conf, /etc/firewalld/,                         │
│      /etc/sysconfig/iptables*, /etc/nftables.conf                │
│    - Detects which firewall engines are INSTALLED vs RUNNING     │
│    - Emits "no firewall" + "firewall X not running" findings     │
└──────────────────────────────────────────────────────────────────┘
```

**Key property:** if the sidecar didn't run (operator forgot, sandbox
blocks subprocess, container has no `ss`), the analyzers still work —
just with less rich data. The Markdown report never silently degrades
to nothing; it always says something.

---

## 2. Files to add

### 2.1 Sidecar (Layer A)

```
tools/
└── port_audit.sh               # ~200 LOC, bash, no Python deps
```

The script writes one JSON file. Schema in §3.

### 2.2 Analyzer package — `listening_ports`

```
src/alma_audit/analyzers/listening_ports/
├── __init__.py                 # re-export analyze_listening_ports
├── parser.py                   # parses port-audit.json (Layer A) OR /proc/net/* (Layer B)
├── aggregator.py               # service-name mapping, public-bind classifier, exposure matrix
├── rules.py                    # 4 rules: critical-port public, mysqld bind-address, ipv6 dual-stack, unknown-port-public
├── settings.py                 # port_service_map (~60 well-known ports), thresholds, critical_ports list
└── analyzer.py                 # orchestrator: layer A → layer B fallback, emit findings
```

Total: ~560 LOC. Under the §7.3 1000-line ceiling.

### 2.3 Analyzer package — `firewall_state`

```
src/alma_audit/analyzers/firewall_state/
├── __init__.py
├── parser.py                   # Layer A JSON + filesystem config probes
├── aggregator.py               # which-engines-installed + which-running matrix
├── rules.py                    # 4 rules: no-firewall, csf-not-running, firewalld-not-running, iptables-disabled-and-no-replacement
├── settings.py                 # engine presence paths + running detection patterns
└── analyzer.py
```

Total: ~480 LOC. Under the 1000-line ceiling.

### 2.4 Wiring

```
src/alma_audit/runner.py        # +2 lines per analyzer: import + invoke in run_analyzers()
src/alma_audit/config.py        # +paths.port_audit_json (default: <output>/port-audit.json) + modules.listening_ports, modules.firewall_state
examples/config.yaml            # +modules.listening_ports.* + modules.firewall_state.* (defaults)
src/alma_audit/fix_suggestions.py # +FIX_LIBRARY entries for "service exposure" + "no firewall"
src/alma_audit/reporting.py     # no changes (the new findings flow through the existing pipeline)
```

### 2.5 Tests

```
tests/test_listening_ports.py   # ~150 LOC
tests/test_firewall_state.py    # ~150 LOC
tests/test_port_audit_json.py   # ~80 LOC — sidecar JSON round-trip
```

All three follow the existing `analyze_<name>(paths, fs, rules=...)`
pattern. Existing `tests/test_readonly.py` is **not changed** — neither
analyzer imports `subprocess`.

---

## 3. JSON schema — `port-audit.json`

Sidecar output. Each top-level key is optional (Layer B's
`/proc/net/*` fallback handles missing fields gracefully).

```json
{
  "schema_version": 1,
  "captured_at": "2026-09-15T14:32:11+02:00",
  "hostname": "host.example.com",

  "listeners": [
    {
      "proto": "tcp",            // "tcp" | "tcp6" | "udp" | "udp6"
      "address": "0.0.0.0",      // bind address (text)
      "port": 3306,
      "process": "mysqld",
      "pid": 1234,
      "state": "LISTEN"          // tcp only; udp has no state
    }
  ],

  "firewall_engines": {
    "csf":        { "installed": true, "running": true,  "version": "14.21", "denylist_count": 42 },
    "firewalld":  { "installed": true, "running": false, "version": "0.9.10" },
    "iptables":   { "installed": true, "running": true,  "binary": "/usr/sbin/iptables-legacy" },
    "nftables":   { "installed": false,"running": false }
  },

  "mysql_bind_address": "0.0.0.0",   // null if not parseable

  "firewall_rules_summary": {
    "csf":         { "open_tcp_ports": [80, 443, 22, 2083, 2087], "open_udp_ports": [] },
    "firewalld":   null,             // null if not running
    "iptables_filter_count": 0,
    "iptables_nat_count": 0,
    "nftables_ruleset_lines": 0
  }
}
```

The schema is forgiving: any field can be missing. The analyzers
treat missing fields as "unknown" and emit INFO findings, never crash.

---

## 4. Service mapping (`port_service_map`)

Default `settings.py` for `listening_ports`. ~60 entries covering the
ports that show up on cPanel / AlmaLinux / WHMCS hosts:

| Port  | Service                | Default severity if 0.0.0.0 bind |
|-------|------------------------|----------------------------------|
| 22    | sshd                   | WARN (consider non-default port) |
| 25    | smtp (exim)            | WARN (cPanel default; relay audit elsewhere) |
| 53    | named (DNS)            | WARN |
| 80    | httpd                  | INFO |
| 110   | pop3                   | CRITICAL (deprecated plaintext)  |
| 143   | imap                   | CRITICAL (deprecated plaintext)  |
| 443   | https                  | INFO |
| 465   | smtps (exim submission)| INFO |
| 587   | smtp submission        | INFO |
| 993   | imaps                  | INFO |
| 995   | pop3s                  | INFO |
| 2083  | cPanel ssl             | INFO |
| 2087  | WHM ssl                | CRITICAL (WHMCS / WHM should be IP-restricted) |
| 2096  | cPanel webmail         | INFO |
| 3306  | mysql                  | CRITICAL (should be 127.0.0.1 or socket) |
| 5432  | postgresql             | CRITICAL |
| 6379  | redis                  | CRITICAL |
| 11211 | memcached              | CRITICAL |
| 27017 | mongodb                | CRITICAL |
| 23    | telnet                 | CRITICAL |
| 3389  | rdp                    | CRITICAL (likely accidental on a Linux box) |

A `wildcard` mapping catches anything >1024 bind to 0.0.0.0 with no
process attribution → INFO "high port, external bind — verify".

---

## 5. Detection rules (per analyzer)

### 5.1 `listening_ports` rules (4)

| ID | Rule | Severity | Trigger |
|----|------|----------|---------|
| **D21** | Critical port public-bind | CRITICAL | `bind ∈ {0.0.0.0, ::}` AND `port ∈ critical_ports` |
| **D22** | MySQL external exposure | CRITICAL | (port 3306 in listeners) AND (`mysql_bind_address` is null OR "0.0.0.0" OR "::") AND NOT loopback |
| **D23** | IPv6 dual-stack on critical port | WARN | listener on `0.0.0.0:3306` AND listener on `[::]:3306` (often "I closed IPv4, forgot IPv6") |
| **D24** | Unknown high port public-bind | INFO | `port > 1024` AND `bind ∈ {0.0.0.0, ::}` AND not in `port_service_map` |

### 5.2 `firewall_state` rules (4)

| ID | Rule | Severity | Trigger |
|----|------|----------|---------|
| **D25** | No firewall at all | CRITICAL | `firewall_engines[*].installed` all false AND no `iptables`-shaped `nftables.conf` |
| **D26** | Installed but not running | CRITICAL | e.g. `firewalld.installed AND NOT firewalld.running` |
| **D27** | CSF installed but lfd daemon dead | CRITICAL | `csf.installed AND NOT csf.running` (cPanel reality: `lfd` is the actual blocker) |
| **D28** | Insecure default — only loopback rules | WARN | `iptables_filter_count + nftables_ruleset_lines ≈ 0` (effectively no rules) |

All findings carry `FindingFix` recommendations per the AISO-210
contract (see §6).

---

## 6. Fix suggestions (added to `fix_suggestions.py`)

Every CRITICAL/WARN finding in the two new analyzers carries concrete
fixes:

```python
# example: D21 (critical port public-bind, e.g. MySQL on 0.0.0.0:3306)
FIX_LIBRARY["listening_ports_critical_public_bind"] = FixBucket(
    local_config=FindingFix(
        what="MySQL bind-address → loopback only",
        why="Database ports must never be reachable from the public internet. "
            "cPanel and most hosting stacks only need local socket access.",
        scope="app_config",
        risk="low",
        commands=(
            "# Edit /etc/my.cnf (or /etc/my.cnf.d/server.cnf on cPanel):",
            "[mysqld]",
            "bind-address = 127.0.0.1",
            "systemctl restart mysql",
        ),
        rollback=(
            "sed -i 's|^bind-address = 127.0.0.1|#bind-address = 127.0.0.1|' /etc/my.cnf",
            "systemctl restart mysql",
        ),
    ),
    waf=None,  # WAF cannot help here — the port is open on the host
    app_config=None,
)
```

Per-scope examples:

| Finding | local_config | waf | app_config |
|---------|--------------|------|-----------|
| **D21 MySQL public** | `bind-address = 127.0.0.1` | n/a | restart `mysql` |
| **D21 Postgres public** | `listen_addresses = 'localhost'` in `postgresql.conf` | n/a | `pg_ctl reload` |
| **D21 Redis public** | `bind 127.0.0.1` in `redis.conf` + `protected-mode yes` | n/a | `systemctl restart redis` |
| **D21 Memcached public** | `-l 127.0.0.1` in `/etc/sysconfig/memcached` | n/a | `systemctl restart memcached` |
| **D22 MySQL via bind-address 0.0.0.0** | same as D21 | n/a | same |
| **D23 IPv6 dual-stack** | `bind-address = 127.0.0.1` (kills IPv4 only — still need IPv6) | n/a | `::1`-only bind in cnf |
| **D25 No firewall** | install CSF (`csf -i` enables it after first-run prompt) **or** `dnf install firewalld && systemctl enable --now firewalld` | Cloudflare WAF rules (separate concern) | n/a |
| **D26 Installed but not running** | `systemctl enable --now firewalld` / `csf -e` | n/a | n/a |
| **D27 CSF lfd dead** | `csf -e` (enable + start) + `systemctl enable lfd` | n/a | n/a |
| **D28 Effectively no rules** | `csf -r` (reload defaults) **or** populate `/etc/csf/csf.allow` | n/a | n/a |

---

## 7. CLI changes

No new flags. The existing `--config` covers the new YAML keys:

```yaml
modules:
  listening_ports:
    enabled: true                # default true
    critical_ports_warn: [110, 143, 23, 3389]   # override the default severity list
    layer_a_json_path: <output>/port-audit.json  # default: same as --output/port-audit.json
    fallback_to_proc: true       # default true; Layer B if sidecar JSON missing
  firewall_state:
    enabled: true
    layer_a_json_path: <output>/port-audit.json
    fallback_to_proc: true
```

---

## 8. Read-only contract impact — analysis

The contract is `tests/test_readonly.py`:

```python
# No subprocess imports
# No os.system / shell=True
# No urllib / requests / httpx
```

| Where | Subprocess? | Read-only? | OK? |
|-------|-------------|------------|-----|
| `tools/port_audit.sh` | yes (it's a bash script) | yes (only reads) | **not in src/alma_audit/** — out of scope |
| `analyzers/listening_ports/parser.py` | no (reads `/proc/net/tcp`) | yes | ✅ |
| `analyzers/listening_ports/aggregator.py` | no | yes (only in-memory dicts) | ✅ |
| `analyzers/firewall_state/parser.py` | no (reads config files + JSON) | yes | ✅ |
| `analyzers/firewall_state/aggregator.py` | no | yes | ✅ |

**`tests/test_readonly.py` is not modified.** The contract stays intact
because nothing in `src/alma_audit/` spawns a subprocess — the
subprocess lives in `tools/`, which the AST check does not scan.

`tools/port_audit.sh` is **not** automatically run by `alma-audit`. It
must be invoked by the operator (or the systemd timer wrapping
alma-audit) before the audit, with its output JSON dropped in the
`--output` directory. The audit picks it up if present; if not, it
falls back to `/proc/net/tcp` reads (still works in any container that
mounts `/proc`).

---

## 9. Migration / rollout

The two analyzers are **additive**. They emit findings on top of the
existing 9 analyzers. Operators who don't run `port_audit.sh` get the
read-only Layer B results; operators who do run it get the richer
Layer A results.

No DB migrations. No schema changes to existing output formats. The
JSON/Markdown/Forensic/CF files all gain new findings of the same
shape as before.

---

## 10. Test plan

`tests/test_listening_ports.py` (~150 LOC):
- `test_empty_no_findings` — empty Layer A JSON + no /proc → INFO only
- `test_layer_a_critical_port_public` — JSON with mysql on 0.0.0.0:3306 → CRITICAL D21
- `test_layer_b_fallback` — Layer A JSON absent + `FakeFileSystem` providing `/proc/net/tcp` → finds 0.0.0.0:3306 → CRITICAL
- `test_ipv6_dual_stack` — both IPv4 and IPv6 on port 3306 → WARN D23
- `test_settings_override_critical_ports` — operator removes 3306 from list → no D21
- `test_my_cnf_bind_address_override` — `mysql_bind_address = 127.0.0.1` in JSON → D21 still CRITICAL (port still public), D22 INFO

`tests/test_firewall_state.py` (~150 LOC):
- `test_no_firewall_critical` — empty engines → CRITICAL D25
- `test_csf_installed_not_running` — `csf.installed=true, running=false` → CRITICAL D26/D27
- `test_firewalld_only_running` — `firewalld.running=true`, others null → no D25
- `test_layer_b_fallback_filesystem` — Layer A JSON absent, FakeFileSystem has `/etc/csf/csf.conf` and `/etc/firewalld/firewalld.conf` → installed detected, running INFO

`tests/test_port_audit_json.py` (~80 LOC):
- `test_json_roundtrip` — JSON written by Layer A parses back into the aggregator identically
- `test_missing_fields_tolerated` — JSON with only `listeners`, no `firewall_engines` → no crash
- `test_schema_version_mismatch` — `schema_version=2` → analyzer logs warning, returns [] (graceful)

Plus the existing `verify_all.sh` grows:
- New symbol grep for `listening_ports` and `firewall_state` analyzer names
- `alma-audit --list-analyzers` must include both
- Smoke test: synthesize a port-audit.json with a critical MySQL exposure, run audit, assert finding appears

---

## 11. Branch + PR plan

Per the project's AGENTS.md and `hermes-feature-branch-workflow`:

```
Branch:   feature/AISO-220-listening-ports-and-firewall-state
Base:     hermes
Files:    src/alma_audit/analyzers/listening_ports/  (new package)
          src/alma_audit/analyzers/firewall_state/   (new package)
          tools/port_audit.sh                        (new sidecar)
          src/alma_audit/runner.py                   (+5 lines: imports + invokes)
          src/alma_audit/config.py                   (+~30 lines: new paths + modules keys)
          examples/config.yaml                       (+~50 lines: defaults + comments)
          src/alma_audit/fix_suggestions.py          (+~200 lines: FIX_LIBRARY entries)
          tests/test_listening_ports.py              (new)
          tests/test_firewall_state.py               (new)
          tests/test_port_audit_json.py              (new)
          docs/GAPS.md                               (update §3.6 → ✅ implemented)
          verify_all.sh                              (+grep symbols for both analyzers)

Worktree: a fresh git worktree under /tmp/aaso-220-audit
PR body:  references AISO-220 + the Tiboo chat (2026-09-15)
Reviewer: Tiboo
Merge:    gh pr merge --squash --delete-branch (the feature branch only)
```

---

## 12. Defaults chosen for this plan

These three questions came up; to avoid over-asking I'll set the
defaults here and adjust in implementation if Tiboo wants different.

1. **D21 vs D22 — MySQL exposure.**
   - **D21** fires when the kernel says `0.0.0.0:3306` (or `:::3306`)
     is in the listener table. This is definitive — the kernel will
     actually accept packets on that socket.
   - **D22** is added as a **secondary confirmation**: if
     `port-audit.json` carries `mysql_bind_address`, and it's
     `0.0.0.0` / `::`, we emit D22 with a *different* recommendation
     that points at `/etc/my.cnf` directly (the fix lives in the
     config file, not the firewall). D22 is INFO severity unless
     D21 already fired CRITICAL — in which case D22 is suppressed
     to avoid double-reporting the same root cause.
   - Net effect: operators get the listener-level signal (CRITICAL)
     and a config-file-level pointer to the fix path.

2. **Ports 2083 / 2087 (cPanel / WHM SSL).**
   - Default: **WARN** if `0.0.0.0` / `::` bind.
   - Escalates to **CRITICAL** ONLY when neither CSF nor firewalld is
     running (so there's no IP allowlist to constrain the surface) AND
     the audit's `self_ip.py` confirms the host's public interface is
     reachable. This way a properly-CSF'd host with an allowlist sees
     a WARN ("you have 2087 open, but CSF is your gate"), and an
     unprotected host sees CRITICAL.
   - The `WARN` finding's recommendation always points at the
     CSF/firewalld allowlist path so operators know how to harden.

3. **`port_audit.sh` invocation.**
   - The script ships in `tools/` and is **wired into the systemd
     timer** as an `ExecStartPre` step
     (`examples/alma-audit.timer` + `examples/alma-audit.service`).
   - The timer unit runs `tools/port_audit.sh <output-dir>` first,
     then `alma-audit --output <output-dir>`. If the sidecar fails
     (binary missing, permission denied), the timer logs the failure
     and **still runs `alma-audit`** — Layer B's `/proc` fallback
     keeps the audit functional.
   - Operators who want pure-Layer-B (no sidecar at all) can disable
     the `ExecStartPre` by editing the unit, or run the audit
     manually without the timer.

---

**End of plan.** Awaiting Tiboo's review.