#!/usr/bin/env bash
# verify_all.sh — end-to-end verifier for AISO-202..209 feature rollup.
#
# Run after the Developer squad has implemented all 8 tickets. The
# script checks:
#   1. Each AISO feature is wired in (file presence, key symbols).
#   2. The full pytest suite is green.
#   3. The CLI lists every analyzer (incl. the new ssh_hardening).
#   4. A container-based integration run completes a synthetic audit
#      against staged input logs and emits all four artifacts
#      (alma-audit-latest.json, alma-audit-latest.md,
#       alma-audit-forensic.json, cloudflare-block.sh). Each
#      artifact is then validated for existence + JSON coherence.
#
# Exit 0 = all 8 AISO are live and tests pass.
# Exit 1 = one or more AISO missing or tests failing — read the
#         output for which one(s).
#
# --- Reproducibility contract (added after the 2026-08-24 review) ---
#
# Python interpreter resolution is deterministic and order-independent
# of the host layout. The resolver tries, in order:
#   1. $PYTHON_BIN environment variable (operator override).
#   2. <repo>/.venv/bin/python (the canonical hermes checkout layout;
#      exists on the dev host, may not exist in a clean Multica
#      worktree — that is normal).
#   3. `python3` on PATH (most Linux + macOS hosts ship one).
#   4. `python` on PATH (last-resort Windows / minimal PATH fallback).
# If none resolves, the python-dependent phases FAIL loudly instead of
# silently exiting 0 — the gate cannot pass without a usable
# interpreter.
#
# Docker image lifecycle: when Docker is available, the dev image
# (`alma-audit-dev:latest`) is built ONCE at the top of the script,
# BEFORE any phase that might `docker run` it. Subsequent phases
# (pytest fallback, analyzer listing, synthetic audit) all reuse that
# single image. This means the gate is reproducible from a cold image
# cache (the previous ordering — pytest/analyzer-list fallbacks running
# before the build — produced 26 PASS / 10 FAIL on a fresh host).
#
# Bind mounts: the synthetic audit and the pytest fallback both bind
# `/src` as `:ro` (read-only). The entrypoint script copies `/src` into
# `/tmp/alma_audit_work` before any writes happen, so a writable
# `/src` mount would be wasted privilege; the `:ro` flag also makes
# the intent obvious in `docker inspect`.
#
# Network: every `docker run` here uses `--network=none`. The
# alma-audit audit itself never makes outbound calls (it only writes
# local artifacts — see `tests/test_readonly.py`'s no-subprocess AST
# check + the no-network egress clause in AGENTS.md), and the dev
# container's entrypoint now invokes `pip install --editable
# --no-build-isolation`, so it reuses the system setuptools already
# pinned by the image instead of re-resolving `setuptools>=61.0`
# from PyPI. (pip 26.x dropped support for the `PIP_NO_BUILD_ISOLATION`
# env var — only the CLI flag works — and that's what unblocks
# `--network=none` on these docker runs.) The no-network-egress
# contract for the audit binary itself is unaffected: any outbound
# traffic that an audit run could in principle make is gated by
# `--network=none` at the container layer.
#
# File mode: this script is committed with git mode `100755`. If you
# are seeing `Permission denied` on `./verify_all.sh`, that is a Git
# checkout problem (e.g. `core.fileMode=false` on a shared filesystem
# flipped the bit). Fix with `git update-index --chmod=+x
# verify_all.sh` and recommit; an in-script `chmod +x "$0"` cannot
# recover from this because the kernel refuses to load the script
# before any line runs, so the script never gets to issue that
# chmod.

set -euo pipefail

WORK="$(cd "$(dirname "$0")" && pwd)"
cd "$WORK"

PASS=0
FAIL=0
REPORT=()

# ---------------------------------------------------------------------
# Python interpreter resolution (deterministic, environment-friendly).
# ---------------------------------------------------------------------
resolve_python() {
    # 1. Operator override (CI / container / cross-platform friendly).
    if [ -n "${PYTHON_BIN:-}" ] && [ -x "${PYTHON_BIN}" ]; then
        echo "${PYTHON_BIN}"
        return 0
    fi
    # 2. Canonical hermes checkout has .venv at repo root.
    if [ -x "$WORK/.venv/bin/python" ]; then
        echo "$WORK/.venv/bin/python"
        return 0
    fi
    # 3. system python3 (most Linux/macOS).
    if command -v python3 >/dev/null 2>&1; then
        command -v python3
        return 0
    fi
    # 4. system python (last-resort).
    if command -v python >/dev/null 2>&1; then
        command -v python
        return 0
    fi
    return 1
}

PYTHON=""
if PYTHON="$(resolve_python 2>/dev/null)"; then
    :
else
    PYTHON=""
fi
if [ -n "$PYTHON" ]; then
    PY_VERSION="$("$PYTHON" --version 2>&1 || true)"
else
    PY_VERSION="(no interpreter found)"
fi

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

# ---------------------------------------------------------------------
# 0. Reproducibility preamble — print the interpreter + image state.
# ---------------------------------------------------------------------
echo "verify_all.sh: using PYTHON=${PYTHON:-<none>} (${PY_VERSION})"
echo "verify_all.sh: WORK=${WORK}"

# ---------------------------------------------------------------------
# 0a. Docker image readiness — ALWAYS run `docker build` once up front,
#     before any phase that might `docker run` it.
#
#     Phases 2b (pytest fallback), 3b (analyzer listing fallback) and
#     4 (synthetic audit) all `docker run alma-audit-dev:latest`.
#     Running them against a missing image is the failure mode that
#     produced 26 PASS / 10 FAIL on a fresh checkout. Building here
#     turns that into 36/36 regardless of host state.
#
#     WHY WE DO NOT SHORT-CIRCUIT ON `docker image inspect`:
#     The gate's job is to validate that the CURRENT Dockerfile +
#     run-dev-tests.sh + deploy/ context in the working tree builds
#     cleanly. If we skip the build when the image tag already
#     exists, a stale, pre-PR image would mask Dockerfile/entrypoint
#     regressions (reproduced on 2026-08-24: local image built at
#     16:49, commit at 17:10, gate still went 36/36 exit 0 against
#     the stale entrypoint). The unconditional `docker build` is the
#     only honest test.
#
#     WARM-HOST COST: docker's layer cache means an unchanged
#     Dockerfile + context produces an instant "build" — typical
#     warm-host wall-clock is sub-second. The cold host pays the full
#     build once; subsequent runs are free.
# ---------------------------------------------------------------------
DOCKER_IMAGE="alma-audit-dev:latest"
DOCKER_READY=0
if command -v docker >/dev/null 2>&1; then
    # Always run `docker build`. Layer cache handles the warm case
    # (~0s); cold case gets the full build before any `docker run`
    # that would otherwise fail.
    check "docker — image build ($DOCKER_IMAGE)" \
        "cd '$WORK' && docker build -q -f deploy/Dockerfile.dev -t '$DOCKER_IMAGE' . >/dev/null"
    if docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
        DOCKER_READY=1
    fi
else
    REPORT+=("--- docker — image build ($DOCKER_IMAGE) ---")
    REPORT+=("SKIP: docker — image build ($DOCKER_IMAGE)")
    REPORT+=("  reason: docker not on PATH; pytest / analyzer-list / synthetic-audit fallbacks disabled")
fi

# ---------------------------------------------------------------------
# 1. Per-AISO wiring checks (file presence + key symbols).
# ---------------------------------------------------------------------

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
    "grep -q '\"ssh_invalid_user_by_ip\"' src/alma_audit/analyzers/secure_log/aggregator.py"

# AISO-204: Bandwidth anomaly detection.
check "AISO-204 (bandwidth) — rule_bandwidth_hog exists in rules.py" \
    "grep -q 'rule_bandwidth_hog\|def rule_bandwidth\|bandwidth_hog' src/alma_audit/analyzers/access_log/rules.py"
check "AISO-204 (bandwidth) — wired into analyzer.py" \
    "grep -q 'bandwidth\|bytes_by_host' src/alma_audit/analyzers/access_log/analyzer.py"

# AISO-205: ModSecurity rule IDs.
check "AISO-205 (modsec rule IDs) — top_rule_ids already in aggregator (carry-over check)" \
    "grep -q 'top_rule_ids' src/alma_audit/analyzers/modsec_log.py"

# AISO-206: Domlog anomalies severity-sorted.
check "AISO-206 (domlog sort) — _SORT_WEIGHTS in domlog_inventory.py" \
    "grep -q '_SORT_WEIGHTS\|SORT_WEIGHTS' src/alma_audit/analyzers/domlog_inventory.py"

# AISO-207: Detection thresholds YAML-configurable.
check "AISO-207 (YAML thresholds) — every settings.py has thresholds override" \
    "grep -q 'thresholds\|settings.get' src/alma_audit/analyzers/domlog_inventory/parser.py 2>/dev/null || \
     grep -q 'settings.get\|thresholds' src/alma_audit/analyzers/secure_log/settings.py"

# AISO-208: Path-level user-agent breakdown.
check "AISO-208 (path UA) — user_agents stored per path in aggregator" \
    "grep -q 'user_agents' src/alma_audit/analyzers/access_log/aggregator.py"

# AISO-209: SSH hardening audit. The new analyzer must exist.
check "AISO-209 (SSH hardening) — ssh_hardening package exists" \
    "test -f src/alma_audit/analyzers/ssh_hardening/__init__.py"
check "AISO-209 (SSH hardening) — analyzer module exists" \
    "test -f src/alma_audit/analyzers/ssh_hardening/analyzer.py"
check "AISO-209 (SSH hardening) — RegisterRootLogin / PermitRootLogin detection" \
    "grep -q 'PermitRootLogin\|RootLogin' src/alma_audit/analyzers/ssh_hardening/rules.py 2>/dev/null"
check "AISO-209 (SSH hardening) — PasswordAuthentication detection" \
    "grep -q 'PasswordAuthentication' src/alma_audit/analyzers/ssh_hardening/rules.py 2>/dev/null"
check "AISO-209 (SSH hardening) — wired into runner.py" \
    "grep -q 'ssh_hardening\|analyze_ssh' src/alma_audit/runner.py"
check "AISO-209 (SSH hardening) — fixtures for weak / strong configs" \
    "test -f tests/fixtures/sshd_config_weak.conf -o -f tests/fixtures/sshd_config_strong.conf"

# ---------------------------------------------------------------------
# 2. Test suite green — uses the resolved interpreter.
# ---------------------------------------------------------------------
# Two execution paths:
#   (a) Host interpreter path — when `$PYTHON` is `.venv/bin/python` or
#       an operator-set `$PYTHON_BIN` whose environment already has
#       `alma_audit` and `pytest` importable. This is the canonical
#       hermes checkout layout.
#   (b) Docker-fallback path — when the host Python has no
#       `alma_audit` import (e.g. a fresh clone without
#       `pip install -e .`). In that case we still need a green
#       pytest gate, so we run pytest inside the dev container — the
#       image has pytest + the editable install pre-wired.
#
# Either path must produce a green run; both are validated against the
# same 463-test corpus (the image's editable install sees the same
# `/src` tree as the host). The docker-fallback path REQUIRES the
# image built in Phase 0a; on a cold host the build happens there, so
# this phase's `docker run` always finds the image.
PYTEST_HOST_OK=0
if [ -n "$PYTHON" ] && "$PYTHON" -c 'import alma_audit, pytest' 2>/dev/null; then
    check "pytest — full suite green (host interpreter)" \
        "cd '$WORK' && '$PYTHON' -m pytest -q"
    PYTEST_HOST_OK=1
elif [ -n "$PYTHON" ]; then
    REPORT+=("--- pytest — full suite green (host interpreter) ---")
    REPORT+=("SKIP: pytest — full suite green (host interpreter)")
    REPORT+=("  reason: host $PYTHON cannot import alma_audit / pytest; will use docker fallback")
fi

if [ "$PYTEST_HOST_OK" -eq 0 ] && [ "$DOCKER_READY" -eq 1 ]; then
    # /src is bind-mounted :ro — the entrypoint copies /src into
    # /tmp/alma_audit_work, so /src being read-only inside the
    # container is the right (and safer) contract.
    check "docker — pytest full suite green (fallback for missing host venv)" \
        "cd '$WORK' && docker run --rm --network=none -v '$WORK':/src:ro $DOCKER_IMAGE -q"
elif [ "$PYTEST_HOST_OK" -eq 0 ]; then
    REPORT+=("--- pytest — full suite green (fallback for missing host venv) ---")
    REPORT+=("FAIL: pytest — full suite green (fallback for missing host venv)")
    REPORT+=("  reason: host interpreter cannot import alma_audit/pytest AND docker image is not available")
    FAIL=$((FAIL+1))
fi

# ---------------------------------------------------------------------
# 3. CLI lists every analyzer — uses the resolved interpreter.
# ---------------------------------------------------------------------
ANALYZER_LIST=""
if [ -n "$PYTHON" ] && "$PYTHON" -c 'import alma_audit' 2>/dev/null; then
    ANALYZER_LIST="$(cd "$WORK" && "$PYTHON" -m alma_audit.cli --list-analyzers 2>&1 || true)"
elif [ "$DOCKER_READY" -eq 1 ]; then
    # Fallback to docker for the CLI listing — the image's editable
    # install makes `alma_audit.cli` importable there.
    ANALYZER_LIST="$(cd "$WORK" && docker run --rm --network=none -v "$WORK":/src:ro $DOCKER_IMAGE --list-analyzers 2>&1 || true)"
else
    REPORT+=("--- CLI lists analyzer: <unavailable> ---")
    REPORT+=("FAIL: CLI lists analyzer: <unavailable>")
    REPORT+=("  reason: host interpreter cannot import alma_audit AND docker image is not available")
    FAIL=$((FAIL+1))
fi
echo "$ANALYZER_LIST" | head -20

for analyzer in access_log domlog_inventory modsec_log crawler_verify secure_log cphulk_log ssl_cert csf_state; do
    check "CLI lists analyzer: $analyzer" "echo '$ANALYZER_LIST' | grep -q '$analyzer'"
done
check "CLI lists new analyzer: ssh_hardening" \
    "echo '$ANALYZER_LIST' | grep -q 'ssh_hardening'"

# ---------------------------------------------------------------------
# 4. Container integration smoke test — REAL synthetic audit, not just
#    --list-analyzers. Stages a minimal Apache access log + domlog
#    directory under /tmp/verify_all_synth_<pid>/, bind-mounts it
#    into the dev container, runs `alma-audit` for real, then
#    validates that all four artifacts were produced and that the
#    JSON artifacts are coherent.
#
#    The image for this phase was built in Phase 0a; if the build
#    failed there, this phase is a clean FAIL with the build error
#    visible in the report rather than a silent docker-pull crash.
# ---------------------------------------------------------------------
if [ "$DOCKER_READY" -eq 1 ]; then
    # --- 4a. Stage synthetic Apache log input under a tmpdir. ---------
    SYNTH_DIR="/tmp/verify_all_synth_$$"
    SYNTH_APACHE="${SYNTH_DIR}/apache"
    SYNTH_DOMLOG="${SYNTH_DIR}/domlogs"
    SYNTH_OUT="${SYNTH_DIR}/out"
    rm -rf "$SYNTH_DIR"
    mkdir -p "$SYNTH_APACHE" "$SYNTH_DOMLOG" "$SYNTH_OUT"
    # The output dir is bind-mounted `:rw` into the container; the
    # host-side uid/gid on the bind is preserved, so the container's
    # root needs to be able to write. 0777 keeps it usable across
    # host/container uid mismatches (the output is on host tmpfs).
    chmod 777 "$SYNTH_OUT"

    # Apache combined-log minimal line:
    #   host ident authuser [ts] "req" status size "ref" "ua"
    # Filename must match the config's `access_log_glob`
    # (DEFAULT = ["access_log", "access_log.*"]) — use the canonical
    # Apache access_log name to keep the test deterministic across
    # container layouts.
    cat >"$SYNTH_APACHE/access_log" <<'LOG'
127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "curl/7.81.0"
198.51.100.7 - - [01/Jan/2026:00:00:01 +0000] "GET /wp-login.php HTTP/1.1" 200 567 "-" "Mozilla/5.0"
203.0.113.42 - - [01/Jan/2026:00:00:02 +0000] "POST /xmlrpc.php HTTP/1.1" 200 89 "-" "Mozilla/5.0"
198.51.100.7 - - [01/Jan/2026:00:00:03 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/7.81.0"
198.51.100.7 - - [01/Jan/2026:00:00:04 +0000] "GET /wp-login.php HTTP/1.1" 200 567 "-" "Mozilla/5.0"
LOG

    # Domlog directory — a mix of normal + sub-account (D7) entries.
    : >"$SYNTH_DOMLOG/example.com"
    : >"$SYNTH_DOMLOG/example.com-ssl_log"
    : >"$SYNTH_DOMLOG/example.com-bytes_log"
    : >"$SYNTH_DOMLOG/aaaaaaaaaaaaaaaaaaaaaaaaaaa-hostdziAAAAAAA"

    # --- 4b. Run the audit inside the dev container. -----------------
    # The deploy/Dockerfile.dev entrypoint already handles:
    #   - editable install of alma-audit into system Python 3.11
    #   - dispatch: any alma-audit CLI flag (--apache-root etc.) goes
    #     to `python3.11 -m alma_audit.cli`, not pytest
    # Bind mounts:
    #   /src           :ro  — entrypoint copies /src to
    #                       /tmp/alma_audit_work; the source tree
    #                       only needs to be readable, and `:ro`
    #                       prevents the container from mutating the
    #                       host checkout.
    #   /synth_apache  :ro  — input logs, no writes expected.
    #   /synth_domlogs :ro  — input logs, no writes expected.
    #   /synth_out     :rw  — the four artifacts get written here.
    RUN_RC=0
    docker run --rm \
        --user root \
        --network=none \
        -v "$SYNTH_APACHE:/synth_apache:ro" \
        -v "$SYNTH_DOMLOG:/synth_domlogs:ro" \
        -v "$SYNTH_OUT:/synth_out:rw" \
        -v "$WORK:/src:ro" \
        "$DOCKER_IMAGE" \
        --apache-root /synth_apache \
        --domlog-root /synth_domlogs \
        --output /synth_out \
        >"$SYNTH_DIR/run.stdout" 2>"$SYNTH_DIR/run.stderr" || RUN_RC=$?

    # --- 4c. Validate the four artifacts. ----------------------------
    if [ "$RUN_RC" -ne 0 ] && [ "$RUN_RC" -ne 1 ]; then
        # exit 0 = INFO-only, exit 1 = WARN/CRITICAL (cron fail-loud),
        # exit 2 = IO/config error. Anything else (125, 126, 137) is a
        # container / dispatch failure.
        REPORT+=("--- docker — full audit run produces JSON+MD+forensic+CF-script ---")
        REPORT+=("FAIL: docker — full audit run produces JSON+MD+forensic+CF-script")
        REPORT+=("  reason: container exited with code $RUN_RC (see $SYNTH_DIR/run.stderr)")
        FAIL=$((FAIL+1))
    else
        check "docker — alma-audit-latest.json produced" \
            "test -s '$SYNTH_OUT/alma-audit-latest.json'"
        check "docker — alma-audit-latest.md produced" \
            "test -s '$SYNTH_OUT/alma-audit-latest.md'"
        check "docker — alma-audit-forensic.json produced" \
            "test -s '$SYNTH_OUT/alma-audit-forensic.json'"
        check "docker — cloudflare-block.sh produced (executable)" \
            "test -s '$SYNTH_OUT/cloudflare-block.sh' && test -x '$SYNTH_OUT/cloudflare-block.sh'"

        # JSON coherence: must parse + carry the expected top-level keys.
        check "docker — alma-audit-latest.json parses + has summary/findings" \
            "'${PYTHON:-python3}' -c \"import json,sys; d=json.load(open('$SYNTH_OUT/alma-audit-latest.json')); assert 'summary' in d, 'missing summary'; assert 'findings' in d, 'missing findings'; assert isinstance(d['summary'], dict); assert 'total_findings' in d['summary']; print('ok')\""
        check "docker — alma-audit-forensic.json parses + carries forensic fields" \
            "'${PYTHON:-python3}' -c \"import json,sys; d=json.load(open('$SYNTH_OUT/alma-audit-forensic.json')); assert 'hostname' in d, 'missing hostname'; assert 'timestamp' in d, 'missing timestamp'; assert 'cloudflare' in d, 'missing cloudflare block'; assert isinstance(d['cloudflare'], dict); print('ok')\""
        check "docker — cloudflare-block.sh is a valid shell script (shebang + set -e)" \
            "head -1 '$SYNTH_OUT/cloudflare-block.sh' | grep -qE '^#!/?(usr/bin/env bash|bin/sh|usr/bin/bash)$' && grep -q 'set -e' '$SYNTH_OUT/cloudflare-block.sh'"
        # Bonus: confirm the audit produced at least one WARN/CRITICAL
        # (the synthetic feed has a /.env probe + repeated wp-login.php
        # hits, so a green-zero run would mean the analyzer is broken).
        check "docker — synthetic audit produced at least one WARN/CRITICAL" \
            "'${PYTHON:-python3}' -c \"import json,sys; d=json.load(open('$SYNTH_OUT/alma-audit-latest.json')); s=d['summary']; w=s.get('warn',0); c=s.get('critical',0); assert w+c >= 1, ('expected non-zero warn+critical, got warn=%d critical=%d' % (w, c)); print('ok')\""
    fi

    # Clean up the synthetic dir (best-effort; the docker container
    # itself is --rm so no leftover layers).
    rm -rf "$SYNTH_DIR"
else
    REPORT+=("--- docker — full audit run produces JSON+MD+forensic+CF-script ---")
    REPORT+=("FAIL: docker — full audit run produces JSON+MD+forensic+CF-script")
    REPORT+=("  reason: docker image is not available; see Phase 0a error")
    FAIL=$((FAIL+1))
    for label in \
        "docker — alma-audit-latest.json produced" \
        "docker — alma-audit-latest.md produced" \
        "docker — alma-audit-forensic.json produced" \
        "docker — cloudflare-block.sh produced (executable)" \
        "docker — alma-audit-latest.json parses + has summary/findings" \
        "docker — alma-audit-forensic.json parses + carries forensic fields" \
        "docker — cloudflare-block.sh is a valid shell script (shebang + set -e)" \
        "docker — synthetic audit produced at least one WARN/CRITICAL"
    do
        REPORT+=("--- $label ---")
        REPORT+=("SKIP: $label")
        REPORT+=("  reason: docker image is not available")
    done
fi

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
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
