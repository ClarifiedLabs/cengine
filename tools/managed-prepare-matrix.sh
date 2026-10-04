#!/bin/sh
# Parent-owned RTM-096 full, RTM-097/099 restart, RTM-100 IO and RTM-103 campaign wrapper.
#
# Usage: tools/managed-prepare-matrix.sh --rtm RTM-096|RTM-097|RTM-098|RTM-099|RTM-100|RTM-103 [--case CASE ...] \
#            [--assets .build/managed-assets-full9] [--evidence .build/managed-prepare-matrix]
#
# Requires the full-nine profile assets built from the current guest sources
# (Scripts/build-guest-assets.sh --prepare-compatibility=rtm096-full-nine-v3 with
# CENGINE_GUEST_OUTPUT pointing at the asset directory), a Developer ID signing
# identity in CENGINE_DEVELOPER_ID_APPLICATION, and the matching Developer ID
# test helper installed through `make test-compat-helper-install`. The wrapper
# builds and signs the managed test-compat pair, validates assets and helper,
# exports the helper environment, takes the compatibility run lock, and hands
# off to tools/managed_prepare_matrix.py on the compat virtualenv.
# RTM-100 defaults to all 46 IO cuts; --case subsets pass without aggregation.
# Its 30 successful sticky cuts intentionally retain uncertainty-bearing roots.
# These cache roots are outside reset's temporary-root scan, so a successful
# wrapper exit does not mean they were disposed. Reset failures still propagate.
# Explicit parent investigation/disposal is required, never automatic deletion.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ASSETS=$ROOT/.build/managed-assets-full9
EVIDENCE=$ROOT/.build/managed-prepare-matrix
previous_argument=
for argument in "$@"; do
    case "$previous_argument" in
        --assets) ASSETS=$argument ;;
        --evidence) EVIDENCE=$argument ;;
    esac
    previous_argument=$argument
done
case "$ASSETS" in /*) ;; *) ASSETS=$ROOT/$ASSETS ;; esac
case "$EVIDENCE" in /*) ;; *) EVIDENCE=$ROOT/$EVIDENCE ;; esac

: "${CENGINE_DEVELOPER_ID_APPLICATION:?managed campaigns require a Developer ID Application signing identity}"
# The Makefile normally supplies these build identity values; the fixture
# compares the daemon's reported GitCommit against the checkout's HEAD.
CENGINE_GIT_COMMIT=${CENGINE_GIT_COMMIT:-$(git -C "$ROOT" rev-parse --short=7 HEAD)}
CENGINE_BUILD_TIME=${CENGINE_BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}
export CENGINE_GIT_COMMIT CENGINE_BUILD_TIME
# Refuse mixed campaigns rather than silently normalizing a caller's selection.
[ -z "${CENGINE_STORAGE_LIFECYCLE_QUALIFICATION:-}" ] &&
[ -z "${CENGINE_COMPAT_LIFECYCLE_FAULT:-}" ] &&
[ "${CENGINE_COMPAT_SHARED_STORAGE+x}${CENGINE_COMPAT_MANAGED_STORAGE+x}" = '' ] &&
[ "${PREPARE_COMPATIBILITY_PROFILE:-rtm096-full-nine-v3}" = rtm096-full-nine-v3 ] &&
[ "${CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY:-rtm096-full-nine-v3}" = rtm096-full-nine-v3 ] || {
    echo 'full PREPARE matrix requires the rtm096-full-nine-v3 profile without storage selectors, qualification or runtime faults' >&2
    exit 2
}
export PREPARE_COMPATIBILITY_PROFILE=rtm096-full-nine-v3
export CENGINE_COMPAT_REQUIRE_EXACT_HELPER=1
export CENGINE_COMPAT_MANAGED_ASSET_DIR=$ASSETS
# Opt this campaign into the closed host-controller full-compat compile
# selection; run-compat-tests.sh forwards it explicitly and signs the
# controller with the managed test-compat identity.
export CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY=rtm096-full-nine-v3

# Resolve the same derived product as run-compat-tests.sh before preparation;
# helper validation, the parent and cleanup must all use that exact signed pair.
absolute_path() {
    case "$1" in /*) printf '%s\n' "$1";; *) printf '%s/%s\n' "$ROOT" "$1";; esac
}
# This campaign has one producer; custom output directories remain supported.
XCODEBUILD=${XCODEBUILD:-xcodebuild}
XCODE_PROJECT=$(absolute_path "${XCODE_PROJECT:-cengine.xcodeproj}")
XCODE_COMPAT_SCHEME=${XCODE_COMPAT_SCHEME:-test-compat}
XCODE_COMMON_FLAGS=${XCODE_COMMON_FLAGS:-'-skipPackagePluginValidation -skipMacroValidation ENABLE_CODE_COVERAGE=NO CLANG_COVERAGE_MAPPING=NO'}
[ "$(command -v "$XCODEBUILD")" = /usr/bin/xcodebuild ] &&
[ "$XCODE_PROJECT" = "$ROOT/cengine.xcodeproj" ] &&
[ "$XCODE_COMPAT_SCHEME" = test-compat ] &&
[ "$XCODE_COMMON_FLAGS" = '-skipPackagePluginValidation -skipMacroValidation ENABLE_CODE_COVERAGE=NO CLANG_COVERAGE_MAPPING=NO' ] || {
    echo 'managed PREPARE campaigns require the standard XCODEBUILD, project, scheme and common flags' >&2
    exit 2
}
XCODEBUILD=/usr/bin/xcodebuild
export XCODEBUILD XCODE_PROJECT XCODE_COMPAT_SCHEME XCODE_COMMON_FLAGS
canonical_path() {
    python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve())' "$(absolute_path "$1")"
}
XCODE_DERIVED_DATA=$(canonical_path "${XCODE_DERIVED_DATA:-.build/xcode-derived}")
XCODE_COMPAT_CONFIGURATION=${XCODE_COMPAT_CONFIGURATION:-test-compat}
BINARY=$(canonical_path "${CENGINE_BINARY:-$XCODE_DERIVED_DATA/Build/Products/$XCODE_COMPAT_CONFIGURATION/cengine}")
[ "$XCODE_COMPAT_CONFIGURATION" = test-compat ] &&
[ "$BINARY" = "$XCODE_DERIVED_DATA/Build/Products/test-compat/cengine" ] || {
    echo 'managed PREPARE campaigns require the derived test-compat binary' >&2
    exit 2
}
export XCODE_DERIVED_DATA XCODE_COMPAT_CONFIGURATION
export CENGINE_BINARY=$BINARY

# Build, sign, validate assets and helper, and recreate the virtualenv exactly
# as a managed `make test-compat` would, without running any pytest selection.
# A deliberately empty selection collects nothing; the exit status is ignored
# only for pytest's "no tests ran" (5) code.
CENGINE_COMPAT_LOCK=$(python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py")
export CENGINE_COMPAT_LOCK
umask 077
status=0
"$ROOT/Scripts/run-compat-tests.sh" suite --collect-only -q -k no_such_test_selected_ "$ROOT/Tests/Compatibility/test_system.py" || status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 5 ]; then
    echo "managed compatibility runtime preparation failed with status $status" >&2
    exit "$status"
fi

. "$ROOT/Scripts/compat-network-helper.sh"
HELPER_FINGERPRINT=$("$ROOT/Scripts/network-helper-fingerprint.sh")
compat_network_helper_require "$BINARY" "$HELPER_FINGERPRINT"
export CENGINE_KERNEL=$ASSETS/vmlinux
export CENGINE_CONTAINER_INITRAMFS=$ASSETS/container-initramfs.cpio.gz
export CENGINE_STORAGE_INITRAMFS=$ASSETS/storage-initramfs.cpio.gz
unset DOCKER_API_VERSION DOCKER_AUTH_CONFIG DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_HOST
unset DOCKER_TLS DOCKER_TLS_VERIFY BUILDX_BUILDER CONTAINER_HOST

if ! mkdir "$CENGINE_COMPAT_LOCK" 2>/dev/null; then
    # Match both other runners: PID publication follows mkdir, so even a
    # missing or apparently dead PID is not authority to steal the lock.
    echo "compatibility lock already exists or is unavailable: $CENGINE_COMPAT_LOCK" >&2
    exit 2
fi
printf '%s\n' "$$" > "$CENGINE_COMPAT_LOCK/pid"
CENGINE_COMPAT_OWNER_PID=$$
export CENGINE_COMPAT_OWNER_PID
CENGINE_COMPAT_CLAIM=$(python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" pin-claim "$$")
export CENGINE_COMPAT_CLAIM
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" verify-claim "$$" || exit 1
    python3 "$ROOT/Scripts/reset-compat-runtime.py" --binary "$BINARY" || status=$?
    python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" release-claim "$$" || status=$?
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$EVIDENCE"
# Run as a child (not exec) so the lock/runtime cleanup trap still runs.
"$ROOT/.build/compat-venv/bin/python" -B "$ROOT/tools/managed_prepare_matrix.py" --assets "$ASSETS" --evidence "$EVIDENCE" "$@"
