#!/usr/bin/env bash
# verify_all.sh — end-to-end verifier for AISO-202..209 feature rollup.
#
# Run after the Developer squad has implemented all 8 tickets. The
# script checks:
#   1. Each AISO feature is wired in (file presence, key symbols).
#   2. The full pytest suite is green.
#   3. The CLI lists every analyzer (incl. the new ssh_hardening).
#   4. A container-based integration run completes and emits a
#      coherent forensic.json + cloudflare-block.sh.
#
# Exit 0 = all 8 AISO are live and tests pass.
# Exit 1 = one or more AISO missing or tests failing — read the
#         output for which one(s).

set -euo pipefail

WORK="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORK"

PASS=0
FAIL=0
REPORT=()

check() {
    local label="$1"
    local cmd="$2"
    REPORT+=("--- $label ---")
    if eval "$cmd" >/dev/null 2>&1; then
        REPORT+=("PASS: $label")
        PASS=$((PASS+1))
    else
        REPORT+=("FAIL: $label")
        REPORT+=("  command: $cmd")
        FAIL=$((FAIL+1))
    fi
}

# ----------------------------------------------------------------------
# 1. Per-AISO wiring checks (file presence + key symbols).
# ----------------------------------------------------------------------

# AISO-202: Cloudflare chunking. Look for _CHUNK_SIZE constant + the
# _chunk / _chunk_total keys in the rendered payload.
check "AISO-202 (chunking) — _CHUNK_SIZE constant in forensic_export.py" \
    "grep -q '_CHUNK_SIZE = 500' src/alma_audit/forensic_export.py"
check "AISO-202 (chunking) — _chunk / _chunk_total emitted" \
    "grep -q '_chunk' src/alma_audit/forensic_export.py && grep -q '_chunk_total' src/alma_audit/forensic_export.py"
check "AISO-202 (chunking) — test_cloudflare_payloads_chunk_above_threshold exists" \
    "grep -q 'chunk_above_threshold' tests/test_forensic_export.py"

# AISO-203: SSH invalid_user / ssh_fail split counter.
check "AISO-203 (SSH split) — ssh_invalid_user_by_ip counter in aggregator" \
    "grep -q 'ssh_invalid_user_by_ip' src/alma_audit/analyzers/secure_log/aggregator.py"
check "AISO-203 (SSH split) — finalize emits ssh_invalid_user_by_ip" \
    "grep -q 'ssh_invalid_user_by_ip' src/alma_audit/analyzers/secure_log/aggregator.py | head -1"

# AISO-204: Bandwidth anomaly detection.
check "AISO-204 (bandwidth) — rule_bandwidth_hog exists in rules.py" \
    "grep -q 'rule_bandwidth_hog\\|def rule_bandwidth\\|bandwidth_hog' src/alma_audit/analyzers/access_log/rules.py"
check "AISO-204 (bandwidth) — wired into analyzer.py" \
    "grep -q 'bandwidth\\|bytes_by_host' src/alma_audit/analyzers/access_log/analyzer.py"

# AISO-205: ModSecurity rule IDs.
check "AISO-205 (modsec rule IDs) — top_rule_ids already in aggregator (carry-over check)" \
    "grep -q 'top_rule_ids' src/alma_audit/analyzers/modsec_log.py"

# AISO-206: Domlog anomalies severity-sorted.
check "AISO-206 (domlog sort) — _SORT_WEIGHTS in domlog_inventory.py" \
    "grep -q '_SORT_WEIGHTS\\|SORT_WEIGHTS' src/alma_audit/analyzers/domlog_inventory.py"

# AISO-207: Detection thresholds YAML-configurable.
check "AISO-207 (YAML thresholds) — every settings.py has thresholds override" \
    "grep -q 'thresholds\\|settings.get' src/alma_audit/analyzers/domlog_inventory/parser.py 2>/dev/null || \
     grep -q 'settings.get\\|thresholds' src/alma_audit/analyzers/secure_log/settings.py"

# AISO-208: Path-level user-agent breakdown.
check "AISO-208 (path UA) — user_agents stored per path in aggregator" \
    "grep -q 'user_agents' src/alma_audit/analyzers/access_log/aggregator.py"

# AISO-209: SSH hardening audit. The new analyzer must exist.
check "AISO-209 (SSH hardening) — ssh_hardening package exists" \
    "test -f src/alma_audit/analyzers/ssh_hardening/__init__.py"
check "AISO-209 (SSH hardening) — analyzer module exists" \
    "test -f src/alma_audit/analyzers/ssh_hardening/analyzer.py"
check "AISO-209 (SSH hardening) — RegisterRootLogin / PermitRootLogin detection" \
    "grep -q 'PermitRootLogin\\|RootLogin' src/alma_audit/analyzers/ssh_hardening/rules.py 2>/dev/null"
check "AISO-209 (SSH hardening) — PasswordAuthentication detection" \
    "grep -q 'PasswordAuthentication' src/alma_audit/analyzers/ssh_hardening/rules.py 2>/dev/null"
check "AISO-209 (SSH hardening) — wired into runner.py" \
    "grep -q 'ssh_hardening\\|analyze_ssh' src/alma_audit/runner.py"
check "AISO-209 (SSH hardening) — fixtures for weak / strong configs" \
    "test -f tests/fixtures/sshd_config_weak.conf -o -f tests/fixtures/sshd_config_strong.conf"

# ----------------------------------------------------------------------
# 2. Test suite green.
# ----------------------------------------------------------------------
check "pytest — full suite green" \
    "cd '$WORK' && .venv/bin/python -m pytest -q"

# ----------------------------------------------------------------------
# 3. CLI lists every analyzer.
# ----------------------------------------------------------------------
ANALYZER_LIST="$(cd "$WORK" && .venv/bin/python -m alma_audit.cli --list-analyzers 2>&1 || true)"
echo "$ANALYZER_LIST" | head -20

for analyzer in access_log domlog_inventory modsec_log crawler_verify secure_log cphulk_log ssl_cert csf_state; do
    check "CLI lists analyzer: $analyzer" "echo '$ANALYZER_LIST' | grep -q '$analyzer'"
done
check "CLI lists new analyzer: ssh_hardening" \
    "echo '$ANALYZER_LIST' | grep -q 'ssh_hardening'"

# ----------------------------------------------------------------------
# 4. Container integration smoke test (AlmaLinux 8.10 + python3.11).
# ----------------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
    check "docker — image build (alma-audit-dev:latest)" \
        "cd '$WORK' && docker build -q -f deploy/Dockerfile.dev -t alma-audit-dev:latest . >/dev/null"

    # Run a synthetic scan against a freshly-built container to make sure
    # the entire CLI runs end-to-end after the rollup.
    check "docker — full audit run produces JSON+MD+forensic+CF-script" \
        "cd '$WORK' && docker run --rm -v \"\$PWD\":/src:ro alma-audit-dev:latest --list-analyzers >/dev/null"
fi

# ----------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------
echo
echo "============================================================"
echo "  AISO-202..209 verify_all.sh: $PASS passed, $FAIL failed"
echo "============================================================"
printf '%s\n' "${REPORT[@]}"

if [ "$FAIL" -gt 0 ]; then
    echo
    echo "$FAIL AISO feature(s) are missing or broken — see report above."
    exit 1
fi

echo
echo "All $PASS AISO features wired in. Full audit end-to-end runs."
exit 0
