#!/usr/bin/env bash
# Alma-audit dev container entrypoint.
#
# Triggered by `deploy/Dockerfile.dev` as the container ENTRYPOINT.
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
#   3. Dispatch: default is pytest; if the first arg is a recognized
#      alma-audit CLI flag, hand off to `python3.11 -m alma_audit.cli`
#      instead. This makes the same image usable for both CI runs
#      (`docker run ... alma-audit-dev:latest`) and operator smoke
#      scans (`docker run ... alma-audit-dev:latest --list-analyzers`).
#
# Exit code is the exit code of the dispatched command. The build
# pipeline treats a non-zero exit as a failed test/run.

set -euo pipefail

# Copy /src into a writable working dir. The bind mount is owned by
# the host user, and pip's editable install needs to write
# src/alma_audit.egg-info into the source tree. We do the copy once
# per container start so the test run picks up local source edits
# from the host while keeping all writes local to the container.
#
# We deliberately exclude host-side dev artifacts from the copy:
#   - .venv/, venv/, env/           host virtualenvs — their
#                                    `bin/python` symlinks resolve to
#                                    the HOST'S /usr/bin/python3,
#                                    which inside the container is a
#                                    DIFFERENT interpreter than the
#                                    container's /usr/bin/python3.11.
#                                    If a test then prefers
#                                    `.venv/bin/python` over
#                                    `sys.executable`, `nobody` ends
#                                    up running an interpreter that
#                                    can't `import yaml` (AISO-214
#                                    review finding, 2026-08-24).
#   - .pytest_cache/, .coverage*, htmlcov/, .tox/, .nox/
#                                  host test caches/coverage state.
#   - .git/, .multica/, .agent_context/   host VCS / workspace state.
#   - alma-audit-out/             host run outputs.
#   - uv.lock, multica-delegation-*.md   host tooling artifacts.
#
# .gitignore and .dockerignore are KEPT — they don't break the
# container, they're cheap, and .cursorrules/CLAUDE.md are
# symlinks into AGENTS.md (not affected by the filter).
WORK_TREE=/tmp/alma_audit_work
rm -rf "$WORK_TREE"
mkdir -p "$WORK_TREE"
for entry in /src/* /src/.[!.]*; do
    [ -e "$entry" ] || continue
    base="$(basename "$entry")"
    case "$base" in
        .venv|.venv-*|venv|env)
            continue
            ;;
        .pytest_cache)
            continue
            ;;
        .coverage|.coverage.*|htmlcov|.tox|.nox|coverage.xml)
            continue
            ;;
        .git|.multica|.agent_context|alma-audit-out)
            continue
            ;;
        uv.lock)
            continue
            ;;
        multica-delegation-*.md)
            continue
            ;;
        __pycache__)
            continue
            ;;
    esac
    cp -a "$entry" "$WORK_TREE/"
done
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
#
# The container is dual-purpose: default is `pytest` (what CI runs
# every day), but if the operator passes an alma-audit CLI flag we
# dispatch into the CLI itself. This makes the same image usable for
# both unit-test CI runs and operator smoke scans — no second
# Dockerfile required.
#
# Dispatch rule: only hand off to the alma-audit CLI when the first
# arg is a flag that pytest would NEVER accept AND that the CLI does
# accept. Unambiguous alma-audit flags:
#
#   --list-analyzers      : the smoke signal the verifier uses
#   --ssh-config / --ssh-drop-in-dir : AISO-209 flags (pytest
#                          rejects them)
#   --apache-root / --domlog-root(s) : input path overrides
#   --output / -o         : output dir
#
# Ambiguous flags (`-v`, `--verbose`, `--version`, `--help`, `-h`,
# `-c`, `--config`) default to pytest so existing CI invocations
# like `docker run ... -v`, `docker run ... --tb=short`, and
# `docker run ... -k foo` keep working without surprises. The smoke
# test in verify_all.sh uses --list-analyzers, which is unambiguous.
dispatch_target="pytest"
if [ "$#" -gt 0 ]; then
    first="$1"
    case "$first" in
        --list-analyzers|--ssh-config|--ssh-drop-in-dir|--apache-root|--domlog-root|--domlog-roots|--output|-o)
            dispatch_target="cli" ;;
        -*)
            # Unrecognized long/short flag: default to pytest so
            # existing pytest-only invocations (`docker run ... -k foo`,
            # `docker run ... --tb=short`, `docker run ... -v`) keep
            # working.
            dispatch_target="pytest" ;;
        *)
            # Bare positional: tests/foo.py or tests/foo — pytest.
            dispatch_target="pytest" ;;
    esac
fi

case "$dispatch_target" in
    cli)
        echo "[dev] running alma-audit CLI  as root (CLI args passthrough) ..."
        exec python3.11 -m alma_audit.cli "$@"
        ;;
    pytest)
        echo "[dev] running pytest as root (test bodies drop privs where needed) ..."
        exec python3.11 -m pytest --tb=short -q "$@"
        ;;
esac
