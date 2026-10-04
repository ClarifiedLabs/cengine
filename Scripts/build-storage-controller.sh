#!/bin/bash
# Build the universal native lifecycle controller.
# This script never installs a helper or launches the controller.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/Scripts/managed-signing.sh"
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || { echo 'requires Darwin arm64' >&2; exit 1; }
# Explicit closed compile-only selection; no environment/default activation
# switch. Only this exact profile adds -tags cengine_prepare_full_compat, and
# only alongside a signed test-compat identity. Production, helper, and
# default builds never carry the tag, so the inert takeover stub compiles.
identity='' compat=0 prepare_profile=''
while [[ $# -gt 1 ]]; do
    case "$1" in
        --sign)
            [[ -z $identity && $# -ge 3 ]] || exit 64
            identity=$2; shift 2 ;;
        --compat) compat=1; shift ;;
        --prepare-compatibility=rtm096-full-nine-v3)
            [[ -z $prepare_profile ]] || exit 64
            prepare_profile=rtm096-full-nine-v3; compat=1; shift ;;
        --prepare-compatibility=*) echo "unknown controller prepare-compatibility profile: $1" >&2; exit 64 ;;
        *) echo "unknown controller build option: $1" >&2; exit 64 ;;
    esac
done
[[ $# == 1 ]] || { echo 'usage: build-storage-controller.sh [--sign IDENTITY [--compat] [--prepare-compatibility=rtm096-full-nine-v3]] OUTPUT_FILE' >&2; exit 64; }
if [[ -n $identity ]]; then team=$(managed_signing_team "$identity"); fi
[[ $compat == 0 || -n $identity ]] || { echo 'compatibility builds require --sign' >&2; exit 64; }
[[ -z $prepare_profile || -z ${CENGINE_COMPAT_LIFECYCLE_FAULT:-} ]] || { echo 'PREPARE cannot combine lifecycle runtime faults' >&2; exit 64; }
qualification=$(python3 "$root/Scripts/storage_lifecycle_qualification.py" selection)
if [[ -n $qualification ]]; then
    [[ -n $identity && $compat == 1 && -z $prepare_profile ]] || {
        echo 'lifecycle qualification requires --sign IDENTITY --compat and no PREPARE selection' >&2; exit 64;
    }
fi
output=$1
[[ $output == /* ]] || output="$PWD/$output"
if [[ -n $qualification ]]; then
    python3 "$root/Scripts/storage_lifecycle_qualification.py" validate-output "$root" "$output"
fi
link_flags=()
if [[ -n $qualification ]]; then
    # The Go child must carry the same sealed receipt as the Swift peers. Its
    # test-only namespace policy reads __info_plist from the signed Mach-O.
    lifecycle_pin=$(python3 "$root/Scripts/storage_lifecycle_qualification.py" source-pin "$root")
    : "${CENGINE_COMPAT_MANAGED_ASSET_DIR:?lifecycle qualification requires caller-provided experimental assets}"
    lifecycle_assets=$(python3 "$root/Scripts/storage_lifecycle_qualification.py" assets-sha256 "$root" "$CENGINE_COMPAT_MANAGED_ASSET_DIR")
    qualification_info=$(mktemp -d /tmp/cengine-lifecycle-plist.XXXXXX)
    trap 'rm -rf "$qualification_info"' EXIT
    python3 - "$qualification_info/Info.plist" "$qualification" "$lifecycle_pin" "$team" "$lifecycle_assets" <<'PY'
import plistlib
import sys
from pathlib import Path
Path(sys.argv[1]).write_bytes(plistlib.dumps({
    "CFBundleIdentifier": "dev.cengine.storage-control.test-compat",
    "CEngineStorageLifecycleQualification": sys.argv[2],
    "CEngineStorageLifecycleSourcePin": sys.argv[3],
    "CEngineTeamIdentifier": sys.argv[4],
    "CEngineStorageLifecycleAssetsSHA256": sys.argv[5],
}))
PY
    link_flags=(-ldflags "-linkmode=external -extldflags=-Wl,-sectcreate,__TEXT,__info_plist,$qualification_info/Info.plist")
fi
mkdir -p "$(dirname "$output")"
cd "$root/Guest"
identifier=dev.cengine.storage-control
timestamp=--timestamp
if [[ $compat == 1 ]]; then
    identifier=dev.cengine.storage-control.test-compat
    timestamp=--timestamp=none
fi
# Namespace only: derive it from the same exact identifier passed to codesign,
# never a runtime assertion or the qualification profile/pin validation switch.
controller_cflags='-O2 -g -UCE_STORAGE_LIFECYCLE_COMPATIBILITY'
if [[ $identifier == dev.cengine.storage-control.test-compat ]]; then
    controller_cflags="$controller_cflags -DCE_STORAGE_LIFECYCLE_COMPATIBILITY=1"
fi
# Close all cgo compile/link flag inputs: CPP defines and forced-include headers
# can run after -U and must not inject namespace or qualification policy.
export CGO_CFLAGS="$controller_cflags" CGO_CPPFLAGS='' CGO_CXXFLAGS='-O2 -g' CGO_LDFLAGS='-O2 -g'
# Lifecycle is universal; tags only select closed test instrumentation.
build_tags=()
if [[ -n $prepare_profile ]]; then build_tags=(-tags cengine_prepare_full_compat); fi
if [[ -n $qualification ]]; then build_tags=(-tags cengine_lifecycle_v2_qualification); fi
GOENV=off GOWORK=off GOFLAGS='' GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -trimpath ${build_tags[@]+"${build_tags[@]}"} ${link_flags[@]+"${link_flags[@]}"} -o "$output" ./cmd/cengine-storage-controller
if [[ -n $qualification ]]; then
    [[ $lifecycle_pin == "$(python3 "$root/Scripts/storage_lifecycle_qualification.py" source-pin "$root")" ]] || {
        echo 'lifecycle qualification source changed during controller build' >&2; exit 1;
    }
    [[ $lifecycle_assets == "$(python3 "$root/Scripts/storage_lifecycle_qualification.py" assets-sha256 "$root" "$CENGINE_COMPAT_MANAGED_ASSET_DIR")" ]] || {
        echo 'lifecycle qualification assets changed during controller build' >&2; exit 1;
    }
fi
if [[ -n $identity ]]; then
    codesign --force --options runtime "$timestamp" --identifier "$identifier" --sign "$identity" "$output"
    managed_signing_verify "$output" "$identifier" "$team"
fi
