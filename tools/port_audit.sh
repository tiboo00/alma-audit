#!/usr/bin/env bash
#
# tools/port_audit.sh — Layer A sidecar for alma-audit (AISO-220).
#
# Snapshots the host's listening TCP/UDP ports, the firewall engines
# that are installed/running, and key service config files (MySQL
# bind-address, etc.). Output is a single JSON file that the
# `listening_ports` and `firewall_state` analyzers consume when
# present; in its absence the analyzers fall back to /proc/net/tcp
# reads (Layer B).
#
# Read-only by design — this script does not start, stop, reload or
# restart any service. It only reads /proc, config files, and
# queries daemons that expose their own state (ss, csf -l,
# firewall-cmd).
#
# Usage:
#   tools/port_audit.sh <output-dir>
#
# Writes <output-dir>/port-audit.json. Exit 0 = success (partial
# snapshots OK), exit non-zero = a hard error the operator must
# look at (missing output dir, no jq available, ...).
#
# The alma-audit systemd timer (examples/alma-audit.service) runs
# this as an ExecStartPre step before the audit proper. If this
# script fails, the timer logs the failure via systemctl status
# and still runs alma-audit — Layer B keeps the audit functional.

set -uo pipefail

OUT_DIR="${1:-/var/log/alma-audit}"
OUT_FILE="${OUT_DIR}/port-audit.json"

if [ ! -d "$OUT_DIR" ]; then
    echo "port_audit.sh: output dir does not exist: $OUT_DIR" >&2
    exit 1
fi

# jq is the only hard dependency. alma-audit's host spec already
# requires python3.11 + PyYAML + (optionally) cryptography — none
# of those emit JSON without an explicit encoder. jq is the
# smallest tool that does.
if ! command -v jq >/dev/null 2>&1; then
    echo "port_audit.sh: 'jq' not found on PATH" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Helpers — every helper goes through a single point of failure so a
# missing binary does not kill the whole snapshot. Partial snapshots
# are fine: the JSON's "unknown" placeholders signal to the analyzer
# layer that it should fall back to Layer B.
# ---------------------------------------------------------------------------

# Try a command; print its stdout on success, "null" on failure.
# Stderr is captured for the audit log but never aborts.
try_cmd() {
    local label="$1"; shift
    local out
    out="$("$@" 2>/dev/null)"
    local rc=$?
    if [ $rc -ne 0 ] || [ -z "$out" ]; then
        printf '%s' "null"
    else
        printf '%s' "$out"
    fi
}

# Probe a single binary's presence (just -v / --version).
binary_present() {
    command -v "$1" >/dev/null 2>&1
}

# systemctl is-active returns "active"/"inactive"/"unknown"; wrap
# the active check.
is_active() {
    systemctl is-active "$1" 2>/dev/null | grep -q '^active$'
}

# Version probe — pick the first line of <bin> --version.
binary_version() {
    "$1" --version 2>/dev/null | head -n1 | sed 's/[[:cntrl:]]*$//'
}

# ---------------------------------------------------------------------------
# Listeners — one-shot snapshot via `ss -tulnp`. We accept ss's
# raw output verbatim; the analyzer layer (Layer B) only needs
# proto/address/port/process/pid, and `ss -tulnp` ships that in
# a stable column layout.
#
# Why ss (not netstat): AlmaLinux 8/9 / CloudLinux 8/9 ship ss by
# default. netstat is deprecated in EL8+ ("in the net-tools
# package, not preinstalled"). On the few minimal images where ss
# is missing, the script logs a "null" listener list — Layer B's
# /proc/net/tcp reads cover the same ground.
# ---------------------------------------------------------------------------

listeners_json="[]"
if binary_present ss; then
    # `ss -tulnp` columns (after the header line is dropped):
    #   Netid  State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
    # Field positions: $1=Netid $2=State $5=Local $7+=Process
    # Process column shows `users:(("name",pid=N,fd=N))` when the calling user can see it,
    # and is hidden entirely when the audit user lacks privileges. We emit "null" fields
    # when the user can't see the PID.
    listeners_json="$(ss -tulnp 2>/dev/null | python3 -c '
import json, re, sys

def hex_to_ip(s, v6):
    """Convert /proc-style hex IP to printable. IPv4 little-endian, IPv6 native."""
    if not v6:
        parts = [s[i:i+2] for i in range(0, len(s), 2)]
        parts = list(reversed(parts))
        return ".".join(str(int(p, 16)) for p in parts)
    parts = [s[i:i+4] for i in range(0, len(s), 4)]
    parts = [str(int(p, 16)) for p in parts]
    return ":".join(parts)

def parse_addr_port(s):
    """Parse ADDR:PORT or [v6addr]:PORT. Returns (addr, port)."""
    if s.startswith("["):
        end = s.index("]")
        return s[1:end], int(s[end+2:])
    idx = s.rfind(":")
    return s[:idx], int(s[idx+1:])

def strip_brackets(s):
    if s.startswith("[") and s.endswith("]"):
        return s[1:-1]
    return s

out = []
for line in sys.stdin:
    parts = line.split()
    if not parts or parts[0] == "Netid":
        continue
    netid = parts[0]
    state = parts[1] if len(parts) > 1 else ""
    local_field = parts[4] if len(parts) > 4 else ""
    process = " ".join(parts[6:]) if len(parts) > 6 else ""

    if netid not in ("tcp", "udp", "tcp6", "udp6"):
        continue
    if netid in ("tcp", "tcp6") and state != "LISTEN":
        continue

    try:
        addr, port = parse_addr_port(local_field)
    except (ValueError, IndexError):
        continue
    addr = strip_brackets(addr)

    proc_name = None
    proc_pid = None
    m = re.search(r"\(\"([^\"]+)\"", process)
    if m:
        proc_name = m.group(1)
    m = re.search(r"pid=(\d+)", process)
    if m:
        proc_pid = int(m.group(1))

    out.append({
        "proto": netid,
        "address": addr,
        "port": port,
        "process": proc_name,
        "pid": proc_pid,
        "state": state,
    })

print(json.dumps(out))
' 2>/dev/null || echo "[]")"
fi

# ---------------------------------------------------------------------------
# Firewall engines — presence + running + version.
#
# Detection order per engine:
#   1. Filesystem probe (config file present?). Fast, no permission
#      needed beyond read access to /etc.
#   2. Running check (systemctl is-active). Requires systemd; we
#      fall back to PID file presence when systemd is missing.
#   3. Version probe (`binary --version`). Optional; "unknown" if the
#      binary is gone but the config dirs exist.
# ---------------------------------------------------------------------------

csf_installed="false"
csf_running="false"
csf_version="null"
csf_denylist_count="null"
if [ -d /etc/csf ] && [ -f /etc/csf/csf.conf ]; then
    csf_installed="true"
    # csf has its own daemon (lfd) and a CLI (csf). lfd is the
    # actual blocker; csf -e enables both. `csf -l` lists the
    # blocklist. On a minimal container csf may be missing
    # despite the config files (the script ships csf without
    # perl); capture that with binary_present.
    if binary_present csf; then
        csf_version=$(binary_version csf | sed 's/^null$/"unknown"/')
        # `csf -l` reads /etc/csf/csf.deny; non-interactive only
        csf_denylist_count=$(try_cmd "csf -l" csf -l < /dev/null | grep -cE '^[0-9]+\.' 2>/dev/null || echo "null")
        csf_version_jq=$(printf '%s' "$csf_version" | jq -R . 2>/dev/null || echo '"unknown"')
        csf_running_raw=$(try_cmd "csf running" bash -c 'systemctl is-active lfd 2>/dev/null || systemctl is-active csf 2>/dev/null || echo inactive')
        if [ "$csf_running_raw" = "active" ]; then
            csf_running="true"
        fi
    fi
fi

firewalld_installed="false"
firewalld_running="false"
firewalld_version="null"
firewalld_zones="null"
if [ -d /etc/firewalld ] || binary_present firewall-cmd; then
    firewalld_installed="true"
    if is_active firewalld; then
        firewalld_running="true"
        if binary_present firewall-cmd; then
            firewalld_version=$(binary_version firewall-cmd | sed 's/^null$/"unknown"/')
            firewalld_zones=$(try_cmd "firewall-cmd --get-active-zones" firewall-cmd --get-active-zones | jq -Rs '.' 2>/dev/null || echo "null")
        fi
    fi
fi

iptables_installed="false"
iptables_running="false"
iptables_binary="null"
if binary_present iptables; then
    iptables_installed="true"
    iptables_binary=$(readlink -f "$(command -v iptables)" 2>/dev/null || echo "null")
    # An active iptables ruleset has non-zero filter chain counters
    # even if the policy is permissive. We treat "any non-error
    # output from `iptables -S`" as "running".
    iptables_ruleset=$(try_cmd "iptables -S" iptables -S 2>/dev/null)
    if [ "$iptables_ruleset" != "null" ] && [ -n "$iptables_ruleset" ]; then
        iptables_running="true"
    fi
fi

nftables_installed="false"
nftables_running="false"
nftables_version="null"
if binary_present nft; then
    nftables_installed="true"
    nftables_version=$(binary_version nft | sed 's/^null$/"unknown"/')
    nftables_ruleset=$(try_cmd "nft list ruleset" nft list ruleset 2>/dev/null)
    if [ "$nftables_ruleset" != "null" ] && [ -n "$nftables_ruleset" ]; then
        nftables_running="true"
    fi
fi

# ---------------------------------------------------------------------------
# MySQL bind-address — parsed from /etc/my.cnf. This is the
# config-side signal that supplements the listener-side signal
# (the analyzer compares both to emit a richer finding).
#
# cPanel hosts sometimes have /etc/my.cnf.d/server.cnf as the
# active file; we probe both.
# ---------------------------------------------------------------------------

mysql_bind_address="null"
for cnf in /etc/my.cnf /etc/my.cnf.d/server.cnf /etc/mysql/my.cnf; do
    if [ -r "$cnf" ]; then
        # Strip comments + groups, then look for bind-address under
        # [mysqld]. awk is portable enough for this.
        found=$(awk '
            /^\s*#/ /[^\]]*$/ { next }
            /^\s*\[/ {
                in_section = ($0 ~ /^\s*\[mysqld\]/)
                next
            }
            in_section && /^\s*bind-address\s*=/ {
                sub(/^\s*bind-address\s*=\s*/, "")
                sub(/\s*#.*$/, "")
                print
                exit
            }
        ' "$cnf" 2>/dev/null)
        if [ -n "$found" ]; then
            mysql_bind_address="$found"
            break
        fi
    fi
done

# ---------------------------------------------------------------------------
# Firewall rules summary — best-effort, for the analyzer to flag
# "firewall installed but no rules" patterns. csf and firewalld
# expose their allow-list explicitly; iptables/nftables count
# chain lines.
# ---------------------------------------------------------------------------

csf_open_tcp="null"
csf_open_udp="null"
if [ "$csf_installed" = "true" ] && binary_present csf; then
    # csf -p prints "tcp|in|udp|direction|dport" — extract TCP/UDP inbound ports
    p_out=$(try_cmd "csf -p" csf -p < /dev/null)
    if [ "$p_out" != "null" ]; then
        csf_open_tcp=$(echo "$p_out" | awk -F'|' '$1=="tcp" && $2=="in" {print $5}' | sort -un | jq -c '[.]' 2>/dev/null || echo "[]")
        csf_open_udp=$(echo "$p_out" | awk -F'|' '$1=="udp" && $2=="in" {print $5}' | sort -un | jq -c '[.]' 2>/dev/null || echo "[]")
    fi
fi

iptables_filter_count="0"
iptables_nat_count="0"
if [ "$iptables_installed" = "true" ]; then
    if binary_present iptables; then
        iptables_filter_count=$(try_cmd "iptables -S" iptables -S 2>/dev/null | wc -l)
        iptables_nat_count=$(try_cmd "iptables -S -t nat" iptables -S -t nat 2>/dev/null | wc -l)
    fi
fi

nftables_ruleset_lines="0"
if [ "$nftables_running" = "true" ]; then
    nftables_ruleset_lines=$(echo "$nftables_ruleset" | wc -l)
fi

# ---------------------------------------------------------------------------
# Hostname + capture timestamp (ISO 8601, local TZ).
# ---------------------------------------------------------------------------

hostname_short=$(hostname 2>/dev/null || echo "unknown")
captured_at=$(date -Iseconds 2>/dev/null || date)

# ---------------------------------------------------------------------------
# Emit JSON. We use jq to assemble, never heredoc into a file —
# jq guarantees the output parses (single source of truth for
# JSON correctness; the audit's read path rejects malformed JSON
# in its analyzer layer).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Emit JSON. Every optional value goes through a small helper that
# converts the textual "null" sentinel into the JSON `null` keyword;
# without this the jq call below would emit literal "null" strings
# (jq cannot tell apart the bash-variable-text "null" from the
# JSON-null keyword just by passing them as arguments).
# ---------------------------------------------------------------------------

# $1 is the bash value; $2 is the jq variable name. Emits jq option
# fragments — three space-separated strings per option so the
# downstream loop can read() them into one ARRAY ELEMENT each
# (one element per token). Without this split, a single printf
# "--argjson name value" would land as one element and jq would
# reject it (jq parses one token per argument).
emit_arg() {
    local val="$1"; local name="$2"
    case "$val" in
        true|false)
            printf -- '--argjson\n%s\n%s\n' "$name" "$val"
            ;;
        null)
            printf -- '--argjson\n%s\nnull\n' "$name"
            ;;
        *)
            printf -- '--arg\n%s\n%s\n' "$name" "$val"
            ;;
    esac
}

JQ_ARGS=()
JQ_ARGS+=(--arg schema "1")
JQ_ARGS+=(--arg captured_at "$captured_at")
JQ_ARGS+=(--arg hostname "$hostname_short")
JQ_ARGS+=(--argjson listeners "$listeners_json")
# Engines — installed/running are bool, version is string-or-null.
while IFS= read -r line; do JQ_ARGS+=("$line"); done < <(
    emit_arg "$csf_installed" csf_installed
    emit_arg "$csf_running" csf_running
    emit_arg "$csf_version" csf_version
    emit_arg "$csf_denylist_count" csf_denylist_count
    emit_arg "$firewalld_installed" firewalld_installed
    emit_arg "$firewalld_running" firewalld_running
    emit_arg "$firewalld_version" firewalld_version
    emit_arg "$firewalld_zones" firewalld_zones
    emit_arg "$iptables_installed" iptables_installed
    emit_arg "$iptables_running" iptables_running
    emit_arg "$iptables_binary" iptables_binary
    emit_arg "$nftables_installed" nftables_installed
    emit_arg "$nftables_running" nftables_running
    emit_arg "$nftables_version" nftables_version
    emit_arg "$mysql_bind_address" mysql_bind_address
    emit_arg "$csf_open_tcp" csf_open_tcp
    emit_arg "$csf_open_udp" csf_open_udp
    emit_arg "$iptables_filter_count" iptables_filter_count
    emit_arg "$iptables_nat_count" iptables_nat_count
    emit_arg "$nftables_ruleset_lines" nftables_ruleset_lines
)

jq -n "${JQ_ARGS[@]}" \
    '{
        schema_version: ($schema | tonumber),
        captured_at: $captured_at,
        hostname: $hostname,
        listeners: $listeners,
        firewall_engines: {
            csf: {
                installed: $csf_installed,
                running: $csf_running,
                version: $csf_version,
                denylist_count: $csf_denylist_count
            },
            firewalld: {
                installed: $firewalld_installed,
                running: $firewalld_running,
                version: $firewalld_version,
                zones: $firewalld_zones
            },
            iptables: {
                installed: $iptables_installed,
                running: $iptables_running,
                binary: $iptables_binary
            },
            nftables: {
                installed: $nftables_installed,
                running: $nftables_running,
                version: $nftables_version
            }
        },
        mysql_bind_address: $mysql_bind_address,
        firewall_rules_summary: {
            csf: {
                open_tcp_ports: $csf_open_tcp,
                open_udp_ports: $csf_open_udp
            },
            firewalld: $firewalld_zones,
            iptables_filter_count: ($iptables_filter_count | tonumber),
            iptables_nat_count: ($iptables_nat_count | tonumber),
            nftables_ruleset_lines: ($nftables_ruleset_lines | tonumber)
        }
    }' > "$OUT_FILE" 2>"$OUT_DIR/port-audit.json.err"

rc=$?
if [ $rc -ne 0 ] || [ ! -s "$OUT_FILE" ]; then
    echo "port_audit.sh: failed to write $OUT_FILE (jq rc=$rc)" >&2
    exit 3
fi

echo "port_audit.sh: wrote $OUT_FILE ($(wc -c < "$OUT_FILE") bytes)"
exit 0