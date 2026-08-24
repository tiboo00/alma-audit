#!/usr/bin/env bash
# Run the alma-audit test suite inside the dev container.
#
# Triggered by `deploy/Dockerfile.dev` as the container entrypoint.
# The repo is expected to be bind-mounted at /src so the editable
# install picks up local source changes without an image rebuild.
#
# Steps:
#   1. (Re)install alma-audit into the system Python 3.11 in editable
#      mode. This is idempotent: pip just touches timestamps if the
#      version hasn't changed.
#   2. Install the runtime + dev + ssl extras into the same Python.
#      `yaml` and `cryptography` MUST be in system site-packages so
#      that the unprivileged test user (`nobody`, invoked via
#      `runuser`) can import them.
#   3. Drop to nobody and run pytest. The ownership of /src is
#      preserved as the host user's UID so tests that touch the
#      filesystem (e.g. tmp_path, FakeFileSystem) work; only the
#      pytest process itself runs as nobody.
#
# Exit code is the pytest exit code. The build pipeline treats a
# non-zero exit as a failed test run.

set -euo pipefail

# Copy /src into a writable working dir. The bind mount is owned by
# the host user, and pip's editable install needs to write
# src/alma_audit.egg-info into the source tree. We do the copy once
# per container start so the test run picks up local source edits
# from the host while keeping all writes local to the container.
WORK_TREE=/tmp/alma_audit_work
rm -rf "$WORK_TREE"
cp -a /src "$WORK_TREE"
chmod -R u+w "$WORK_TREE"
cd "$WORK_TREE"

echo "[dev] python: $(python3.11 --version) ($(python3.11 -c 'import sys; print(sys.executable)'))"

# Editable install of alma-audit into the system Python so the test
# bodies can `import alma_audit` (and so `runuser -u nobody` does too).
# Runtime deps (PyYAML, cryptography, pytest) are pre-installed at
# IMAGE BUILD TIME in Dockerfile.dev — no need to reinstall per run.
echo "[dev] reinstalling alma-audit (editable) ..."
python3.11 -m pip install --quiet --editable "$WORK_TREE"

# Make the work tree world-readable so the inner `runuser -u nobody`
# subprocesses (used by tests/test_exit_codes.py and
# tests/test_unreadable_log_root.py to simulate an unprivileged audit
# invocation) can stat + read the package source and test fixtures.
chmod -R a+rX "$WORK_TREE"

# IMPORTANT: pytest itself runs as root here, not as `nobody`. The
# container is ephemeral (`--rm`) so privilege separation at the test
# layer buys nothing; conversely, dropping to `nobody` at the outer
# layer breaks the *inner* `runuser -u nobody` calls in the test
# bodies (Linux forbids `runuser` from a non-root user). The test
# suite does its own privilege drop inside the cases that need it.
echo "[dev] running pytest as root (test bodies drop privs where needed) ..."
exec python3.11 -m pytest --tb=short -q "$@"
