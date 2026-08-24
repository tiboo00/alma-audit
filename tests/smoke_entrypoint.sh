#!/bin/bash
# AISO-125 — AlmaLinux 8 + Python 3.11 smoke entrypoint.
#
# This is the cron-friendly smoke: stage a chmod-000 domlog_root,
# run alma-audit as `nobody`, and confirm the audit exits with a
# structured WARN finding (not a traceback). Mirrors the Stage 2
# reproduction that the Supervisor cited.

set -e

echo "[smoke] === AISO-125 smoke start ==="

# Stage the fixture
WORKSPACE=/tmp/alma-smoke
rm -rf "$WORKSPACE"
mkdir -p "$WORKSPACE/apache2/domlogs"

cat > "$WORKSPACE/apache2/access_log" <<'EOF'
127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET / HTTP/1.1" 200 1234 "-" "curl/7.68.0"
10.0.0.1 - - [10/Oct/2023:13:55:37 -0700] "GET / HTTP/1.1" 200 1234 "-" "curl/7.68.0"
192.168.1.1 - - [10/Oct/2023:13:55:38 -0700] "GET / HTTP/1.1" 200 1234 "-" "curl/7.68.0"
EOF

# An otherwise-readable domlog entry the audit would pick up if it
# could list the directory. This proves the audit isn't missing the
# data — it's denied access to it.
touch "$WORKSPACE/apache2/domlogs/hostdzire.com"

chmod 755 "$WORKSPACE/apache2"
chmod 000 "$WORKSPACE/apache2/domlogs"

echo "[smoke] fixture ready:"
echo "  apache_root: $WORKSPACE/apache2"
echo "  domlog_root: $WORKSPACE/apache2/domlogs (mode 000)"

# Run the audit as nobody. We deliberately do NOT chmod 000 the
# output dir — nobody needs to write into it.
OUT="$WORKSPACE/out"
rm -rf "$OUT"
mkdir -p "$OUT"
chmod 1777 "$OUT"

echo "[smoke] running alma-audit as nobody..."
set +e
runuser -u nobody -- python3 -m alma_audit.cli \
    --apache-root "$WORKSPACE/apache2" \
    --domlog-root "$WORKSPACE/apache2/domlogs" \
    --output "$OUT"
RC=$?
set -e

echo "[smoke] === alma-audit output ==="
echo "[smoke] exit code: $RC"

if [ ! -f "$OUT/alma-audit-latest.json" ]; then
    echo "[smoke] FAIL: JSON report not written"
    exit 1
fi

# Confirm: no traceback, WARN finding present
if grep -q 'unreadable' "$OUT/alma-audit-latest.json"; then
    echo "[smoke] PASS: WARN finding 'unreadable' present in JSON"
else
    echo "[smoke] FAIL: WARN finding 'unreadable' missing from JSON"
    echo "---------- JSON ----------"
    cat "$OUT/alma-audit-latest.json"
    exit 1
fi

if [ "$RC" = "1" ]; then
    echo "[smoke] PASS: exit code 1 (cron fail-loud)"
else
    echo "[smoke] FAIL: expected exit code 1, got $RC"
    exit 1
fi

# Restore perms so the workspace can be removed
chmod 700 "$WORKSPACE/apache2/domlogs"
chmod -R u+rwX "$WORKSPACE"
rm -rf "$WORKSPACE"

echo "[smoke] === AISO-125 smoke PASS ==="
exit 0