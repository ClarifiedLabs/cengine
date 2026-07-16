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

if [[ ! -x "$binary" ]]; then
    echo "compatibility daemon is missing: $binary" >&2
    exit 1
fi

helper="$(compat_network_helper_for_binary "$binary")"

helper_metadata() {
    codesign -dv --verbose=4 "$helper" 2>&1 || true
}

helper_team="$(helper_metadata | sed -n 's/^TeamIdentifier=//p' | head -1)"
helper_identifier="$(helper_metadata | sed -n 's/^Identifier=//p' | head -1)"
identity="-"

if [[ -n "$helper_team" && "$helper_team" != "not set" ]]; then
    identity="${CENGINE_DEVELOPER_ID_APPLICATION:-}"
    if [[ -z "$identity" ]]; then
        identity="$(security find-identity -v -p codesigning | awk -v team="$helper_team" '
            /Developer ID Application:/ && index($0, "(" team ")") { print $2; exit }
        ')"
    fi
    if [[ -z "$identity" ]]; then
        echo "no Developer ID Application identity found for networking helper team $helper_team" >&2
        echo "set CENGINE_DEVELOPER_ID_APPLICATION to the identity fingerprint or name" >&2
        exit 1
    fi
elif ! compat_network_helper_is_installed "$helper"; then
    codesign --force --timestamp=none \
        --identifier dev.cengine.network-helper \
        --sign - \
        "$helper"
    helper_identifier="$(helper_metadata | sed -n 's/^Identifier=//p' | head -1)"
else
    echo "installed networking helper does not have a signing team" >&2
    echo "set CENGINE_COMPAT_NETWORK_HELPER=local to use the freshly built helper" >&2
    exit 1
fi

if [[ "$helper_identifier" != "dev.cengine.network-helper" ]]; then
    echo "networking helper identifier $helper_identifier does not match dev.cengine.network-helper" >&2
    exit 1
fi

sign_path() {
    local path="$1"
    shift
    if [[ "$identity" == "-" ]]; then
        codesign --force "$@" --sign "$identity" "$path"
    else
        codesign --force --timestamp=none --options runtime "$@" --sign "$identity" "$path"
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

sign_path "$binary" \
    --identifier dev.cengine.engine \
    --entitlements "$ROOT_DIR/Configuration/cengine.entitlements"
codesign --verify --strict --verbose=2 "$binary"

binary_team="$({ codesign -dv --verbose=4 "$binary" 2>&1 || true; } | sed -n 's/^TeamIdentifier=//p' | head -1)"
if [[ -n "$helper_team" && "$helper_team" != "not set" && "$binary_team" != "$helper_team" ]]; then
    echo "compatibility daemon team $binary_team does not match helper team $helper_team" >&2
    exit 1
fi
