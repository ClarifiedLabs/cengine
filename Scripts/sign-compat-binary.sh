#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 PATH-TO-CENGINE" >&2
    exit 64
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=Scripts/compat-network-helper.sh
. "$ROOT_DIR/Scripts/compat-network-helper.sh"

binary="$1"
helper="$(compat_network_helper_local_for_binary "$binary")"

for path in "$binary" "$helper"; do
    if [[ ! -x "$path" ]]; then
        echo "compatibility executable is missing: $path" >&2
        exit 1
    fi
done

sign_path() {
    local path="$1"
    shift
    codesign --force --timestamp=none "$@" --sign - "$path"
}

frameworks_dir="$(dirname "$binary")/PackageFrameworks"
if [[ -d "$frameworks_dir" ]]; then
    while IFS= read -r -d '' component; do
        sign_path "$component"
    done < <(find "$frameworks_dir" -depth \
        \( -type d -name '*.framework' -o -type f -name '*.dylib' \) \
        -print0)
fi

sign_path "$helper" --identifier dev.cengine.network-helper.test-compat
sign_path "$binary" \
    --identifier dev.cengine.engine.test-compat \
    --entitlements "$ROOT_DIR/Configuration/cengine.entitlements"

codesign --verify --strict --verbose=2 "$helper"
codesign --verify --strict --verbose=2 "$binary"

helper_identifier="$({ codesign -dv --verbose=4 "$helper" 2>&1 || true; } | sed -n 's/^Identifier=//p' | head -1)"
binary_identifier="$({ codesign -dv --verbose=4 "$binary" 2>&1 || true; } | sed -n 's/^Identifier=//p' | head -1)"
if [[ "$helper_identifier" != "dev.cengine.network-helper.test-compat" ]]; then
    echo "unexpected compatibility helper identifier: $helper_identifier" >&2
    exit 1
fi
if [[ "$binary_identifier" != "dev.cengine.engine.test-compat" ]]; then
    echo "unexpected compatibility daemon identifier: $binary_identifier" >&2
    exit 1
fi
