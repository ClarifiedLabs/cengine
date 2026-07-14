#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/guest"}
STAMP="$OUTPUT/kernel-input.sha256"

expected=$(
    cat "$ROOT/Configuration/kernel-version" \
        "$ROOT/Configuration/kernel-commit" \
        "$ROOT/Configuration/cengine-kernel.fragment" \
        | shasum -a 256 | awk '{print $1}'
)
actual=$(cat "$STAMP" 2>/dev/null || true)

if [ ! -f "$OUTPUT/vmlinux" ] || [ "$actual" != "$expected" ]; then
    echo "cengine guest kernel is missing or stale; run make kernel" >&2
    exit 2
fi
