#!/bin/sh
# Explicit campaigns only; helper installation remains a separate attended action.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
QUALIFICATION=${1:-}
shift || true
case "$QUALIFICATION" in
    native)
        exec "$ROOT/Scripts/run-compat-tests.sh" qualification \
            "$ROOT/Tests/Compatibility/test_managed_fuse_interrupt.py" "$@"
        ;;
    prepare)
        # The pytest registrations deliberately refuse acceptance. Only the
        # original parent wrapper owns real PREPARE campaign execution.
        exec "$ROOT/tools/managed-prepare-matrix.sh" "$@"
        ;;
    *)
        echo 'set QUALIFICATION=native|prepare (QUALIFICATION_ARGS supplies explicit campaign CLI arguments)' >&2
        exit 2
        ;;
esac
