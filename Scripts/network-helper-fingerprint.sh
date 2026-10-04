#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

QUALIFICATION=$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" selection)
# Source selection stays independent of generated assets; qualification also
# binds the already-built caller assets so an installed helper cannot drift.
ASSETS_SHA256=
SOURCE_PIN=
if [ -n "$QUALIFICATION" ]; then
    SOURCE_PIN=$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" source-pin "$ROOT")
    : "${CENGINE_COMPAT_MANAGED_ASSET_DIR:?lifecycle qualification requires caller-provided experimental assets}"
    ASSETS_SHA256=$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" assets-sha256 "$ROOT" "$CENGINE_COMPAT_MANAGED_ASSET_DIR")
fi

INPUTS=$(mktemp "${TMPDIR:-/tmp}/cengine-helper-fingerprint.XXXXXX")
trap 'rm -f "$INPUTS"' EXIT HUP INT TERM
{
    printf 'lifecycle-qualification:%s\nlifecycle-source:%s\n' "$QUALIFICATION" "$SOURCE_PIN"
    if [ -n "$QUALIFICATION" ]; then printf 'lifecycle-assets:%s\n' "$ASSETS_SHA256"; fi
    # The same closed source list drives the Xcode support target and standalone
    # tests. Hash the manifest itself as well as every source it selects.
    fingerprint_file() {
        relative=${1#"$ROOT/"}
        printf 'file:%s\n' "$relative"
        /bin/cat "$1"
        printf '\n'
    }
    fingerprint_file "$ROOT/Configuration/helper-support-sources.txt"
    while IFS= read -r relative; do
        fingerprint_file "$ROOT/$relative"
    done < "$ROOT/Configuration/helper-support-sources.txt"
    for path in "$ROOT"/Sources/CEngineNetworkHelper/*.swift \
        "$ROOT/Configuration/network-helper-Info.plist"
    do
        fingerprint_file "$path"
    done
    printf 'swiftc:'
    /usr/bin/xcrun swiftc --version 2>&1
    printf 'xcode:'
    /usr/bin/xcodebuild -version
    printf 'sdk:'
    /usr/bin/xcrun --sdk macosx --show-sdk-build-version
} > "$INPUTS"
/usr/bin/shasum -a 256 "$INPUTS" | /usr/bin/awk '{ print $1 }'
