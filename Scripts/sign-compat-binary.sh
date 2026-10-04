#!/bin/bash
set -euo pipefail

identity=-
if [[ $# -eq 3 && $1 == --sign ]]; then identity=$2; shift 2; fi
if [[ $# -ne 1 ]]; then
    echo "usage: $0 [--sign DEVELOPER-ID-APPLICATION] PATH-TO-CENGINE" >&2
    exit 64
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=Scripts/compat-network-helper.sh
. "$ROOT_DIR/Scripts/compat-network-helper.sh"
. "$ROOT_DIR/Scripts/managed-signing.sh"
if [[ ${CENGINE_COMPAT_MANAGED_STORAGE+x}${CENGINE_COMPAT_SHARED_STORAGE+x} != '' ]]; then
    echo 'retired compatibility storage selector; lifecycle is the default' >&2
    exit 64
fi
team=$(managed_signing_team "$identity")

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
    if [[ $identity != - ]]; then
        codesign --force --timestamp=none --options runtime "$@" --sign "$identity" "$path"
    else
        codesign --force --timestamp=none "$@" --sign - "$path"
    fi
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

if [[ $identity != - ]]; then
    controller="$(dirname "$binary")/cengine-storage-controller"
    [[ -x $controller ]] || { echo "managed controller is missing: $controller" >&2; exit 1; }
    sign_path "$controller" --identifier dev.cengine.storage-control.test-compat
    managed_signing_verify "$controller" dev.cengine.storage-control.test-compat "$team"
    managed_signing_verify "$helper" dev.cengine.network-helper.test-compat "$team"
    managed_signing_verify "$binary" dev.cengine.engine.test-compat "$team"
fi

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
