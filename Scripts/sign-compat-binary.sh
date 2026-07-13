#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 PATH-TO-CENGINE" >&2
    exit 64
fi

binary="$1"
helper="/Applications/cengine.app/Contents/MacOS/cengine-network-helper"

if [[ ! -x "$binary" ]]; then
    echo "compatibility daemon is missing: $binary" >&2
    exit 1
fi
if [[ ! -x "$helper" ]]; then
    echo "installed cengine networking helper is missing: $helper" >&2
    echo "install the current cengine package before running compatibility tests" >&2
    exit 1
fi

helper_team="$({ codesign -dv --verbose=4 "$helper" 2>&1 || true; } | sed -n 's/^TeamIdentifier=//p' | head -1)"
if [[ -z "$helper_team" || "$helper_team" == "not set" ]]; then
    echo "installed networking helper does not have a signing team" >&2
    exit 1
fi

identity="${CENGINE_DEVELOPER_ID_APPLICATION:-}"
if [[ -z "$identity" ]]; then
    identity="$(security find-identity -v -p codesigning | awk -v team="$helper_team" '
        /Developer ID Application:/ && index($0, "(" team ")") { print $2; exit }
    ')"
fi
if [[ -z "$identity" ]]; then
    echo "no Developer ID Application identity found for installed helper team $helper_team" >&2
    echo "set CENGINE_DEVELOPER_ID_APPLICATION to the identity fingerprint or name" >&2
    exit 1
fi

frameworks_dir="$(dirname "$binary")/PackageFrameworks"
if [[ -d "$frameworks_dir" ]]; then
    while IFS= read -r -d '' component; do
        codesign --force --timestamp=none --options runtime \
            --sign "$identity" \
            "$component"
    done < <(find "$frameworks_dir" -depth \
        \( -type d -name '*.framework' -o -type f -name '*.dylib' \) \
        -print0)
fi

codesign --force --timestamp=none --options runtime \
    --identifier dev.cengine.engine \
    --entitlements Configuration/cengine.entitlements \
    --sign "$identity" \
    "$binary"
codesign --verify --strict --verbose=2 "$binary"

binary_team="$({ codesign -dv --verbose=4 "$binary" 2>&1 || true; } | sed -n 's/^TeamIdentifier=//p' | head -1)"
if [[ "$binary_team" != "$helper_team" ]]; then
    echo "compatibility daemon team $binary_team does not match helper team $helper_team" >&2
    exit 1
fi
