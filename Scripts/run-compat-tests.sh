#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=Scripts/compat-network-helper.sh
. "$ROOT/Scripts/compat-network-helper.sh"
MODE=${1:-suite}
shift || true
. "$ROOT/Scripts/managed-signing.sh"
# Build-only lifecycle fault. Validate before normalizing any ambient profile fields.
CENGINE_COMPAT_LIFECYCLE_FAULT=$(python3 "$ROOT/Scripts/compat_lifecycle_fault.py" selection)
export CENGINE_COMPAT_LIFECYCLE_FAULT
CENGINE_STORAGE_LIFECYCLE_QUALIFICATION=$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" selection)
export CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
CENGINE_STORAGE_LIFECYCLE_SOURCE_PIN=
CENGINE_STORAGE_LIFECYCLE_ASSETS_SHA256=
if [ -n "$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION" ]; then
    python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" signed-managed
    XCODE_DERIVED_DATA=${XCODE_DERIVED_DATA:-"$ROOT/.build/$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION/xcode-derived"}
fi
XCODEBUILD=${XCODEBUILD:-xcodebuild}
XCODE_PROJECT=${XCODE_PROJECT:-cengine.xcodeproj}
XCODE_DERIVED_DATA=${XCODE_DERIVED_DATA:-.build/xcode-derived}
XCODE_SOURCE_PACKAGES=${XCODE_SOURCE_PACKAGES:-.build/xcode-source-packages}
XCODE_COMPAT_SCHEME=${XCODE_COMPAT_SCHEME:-test-compat}
XCODE_COMPAT_CONFIGURATION=${XCODE_COMPAT_CONFIGURATION:-test-compat}
XCODE_COMMON_FLAGS=${XCODE_COMMON_FLAGS:-"-skipPackagePluginValidation -skipMacroValidation ENABLE_CODE_COVERAGE=NO CLANG_COVERAGE_MAPPING=NO"}
absolute_path() {
    case "$1" in /*) printf '%s\n' "$1";; *) printf '%s/%s\n' "$ROOT" "$1";; esac
}
XCODE_PROJECT=$(absolute_path "$XCODE_PROJECT")
XCODE_DERIVED_DATA=$(absolute_path "$XCODE_DERIVED_DATA")
XCODE_SOURCE_PACKAGES=$(absolute_path "$XCODE_SOURCE_PACKAGES")
BINARY=$(absolute_path "${CENGINE_BINARY:-$XCODE_DERIVED_DATA/Build/Products/$XCODE_COMPAT_CONFIGURATION/cengine}")
CENGINE_BINARY=$BINARY
if [ -n "$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION" ]; then
    [ "$XCODE_PROJECT" = "$ROOT/cengine.xcodeproj" ] &&
    [ "$XCODE_COMPAT_SCHEME" = test-compat ] && [ "$XCODE_COMPAT_CONFIGURATION" = test-compat ] &&
    [ "$XCODE_COMMON_FLAGS" = '-skipPackagePluginValidation -skipMacroValidation ENABLE_CODE_COVERAGE=NO CLANG_COVERAGE_MAPPING=NO' ] &&
    [ "$BINARY" = "$XCODE_DERIVED_DATA/Build/Products/test-compat/cengine" ] || {
        echo 'lifecycle qualification requires the closed test-compat build settings and derived binary' >&2; exit 2;
    }
    python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" validate-output "$ROOT" "$XCODE_DERIVED_DATA"
    CENGINE_STORAGE_LIFECYCLE_SOURCE_PIN=$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" source-pin "$ROOT")
fi
if [ -n "$CENGINE_COMPAT_LIFECYCLE_FAULT" ]; then
    [ "$XCODE_PROJECT" = "$ROOT/cengine.xcodeproj" ] &&
    [ "$XCODE_COMPAT_SCHEME" = test-compat ] && [ "$XCODE_COMPAT_CONFIGURATION" = test-compat ] &&
    [ "$XCODE_COMMON_FLAGS" = '-skipPackagePluginValidation -skipMacroValidation ENABLE_CODE_COVERAGE=NO CLANG_COVERAGE_MAPPING=NO' ] &&
    [ "$BINARY" = "$XCODE_DERIVED_DATA/Build/Products/test-compat/cengine" ] || {
        echo 'lifecycle fault requires the closed test-compat build settings and derived binary' >&2; exit 2;
    }
fi
# Retired startup selectors are errors, including explicitly empty values.
if [ "${CENGINE_COMPAT_SHARED_STORAGE+x}${CENGINE_COMPAT_MANAGED_STORAGE+x}" != '' ]; then
    echo 'CENGINE_COMPAT_SHARED_STORAGE and CENGINE_COMPAT_MANAGED_STORAGE are retired; lifecycle is the default' >&2
    exit 2
fi
TEAM_IDENTIFIER=$(managed_signing_team "${CENGINE_DEVELOPER_ID_APPLICATION:-}")
BUILD_DEFAULT_ASSETS=0
if [ "${CENGINE_COMPAT_MANAGED_ASSET_DIR+x}" = x ]; then
    [ -n "$CENGINE_COMPAT_MANAGED_ASSET_DIR" ] || { echo 'explicit asset directory must not be empty' >&2; exit 2; }
    CENGINE_COMPAT_MANAGED_ASSET_DIR=$(absolute_path "$CENGINE_COMPAT_MANAGED_ASSET_DIR")
    export CENGINE_COMPAT_MANAGED_ASSET_DIR
    compat_network_helper_select_policy >/dev/null
    if [ -n "$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION" ]; then
        CENGINE_STORAGE_LIFECYCLE_ASSETS_SHA256=$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" assets-sha256 "$ROOT" "$CENGINE_COMPAT_MANAGED_ASSET_DIR")
    else
        python3 "$ROOT/Scripts/check-managed-guest-assets.py" "$CENGINE_COMPAT_MANAGED_ASSET_DIR"
    fi
else
    # Profile qualification requires explicit paired assets. Ordinary assets are
    # rebuilt only after taking the runner lock and resetting owned runtime.
    compat_network_helper_select_policy >/dev/null
    BUILD_DEFAULT_ASSETS=1
    CENGINE_COMPAT_MANAGED_ASSET_DIR="$ROOT/.build/guest"
    export CENGINE_COMPAT_MANAGED_ASSET_DIR
fi
CENGINE_KERNEL="$CENGINE_COMPAT_MANAGED_ASSET_DIR/vmlinux"
CENGINE_CONTAINER_INITRAMFS="$CENGINE_COMPAT_MANAGED_ASSET_DIR/container-initramfs.cpio.gz"
CENGINE_STORAGE_INITRAMFS="$CENGINE_COMPAT_MANAGED_ASSET_DIR/storage-initramfs.cpio.gz"
# Closed opt-in for the managed host-controller full-compat compile selection.
# Only the matrix campaign wrapper (managed-prepare-matrix.sh) sets this; the
# runner forwards it as the explicit closed build-storage-controller.sh flag.
# Empty means the managed controller build stays an ordinary inert production
# binary; any other value is rejected rather than inferred.
CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY=${CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY:-}
case "$CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY" in
    ''|rtm096-full-nine-v3) ;;
    *) echo 'CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY must be rtm096-full-nine-v3' >&2; exit 2;;
esac
CENGINE_KERNEL=$(absolute_path "${CENGINE_KERNEL:-$ROOT/.build/guest/vmlinux}")
CENGINE_CONTAINER_INITRAMFS=$(absolute_path "${CENGINE_CONTAINER_INITRAMFS:-$ROOT/.build/guest/container-initramfs.cpio.gz}")
CENGINE_STORAGE_INITRAMFS=$(absolute_path "${CENGINE_STORAGE_INITRAMFS:-$ROOT/.build/guest/storage-initramfs.cpio.gz}")
export CENGINE_BINARY CENGINE_KERNEL CENGINE_CONTAINER_INITRAMFS CENGINE_STORAGE_INITRAMFS
reset_runtime() { python3 "$ROOT/Scripts/reset-compat-runtime.py" --binary "$BINARY"; }
RESET=reset_runtime
# One owner-private helper-wide claim, independent of caller lock/temp overrides.
LOCK=$(python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py")
CENGINE_COMPAT_LOCK=$LOCK
export CENGINE_COMPAT_LOCK
umask 077

stage() {
    printf '\n==> compatibility: %s\n' "$1"
}

acquire_lock() {
    if mkdir "$LOCK" 2>/dev/null; then
        printf '%s\n' "$$" > "$LOCK/pid"
        return
    fi

    # A creator may not have published its PID yet. Missing, unreadable or
    # apparently dead ownership never authorizes stealing the shared lock.
    echo "compatibility lock already exists or is unavailable: $LOCK" >&2
    exit 2
}

cleanup() {
    status=$?
    cleanup_status=0
    trap - EXIT HUP INT TERM
    stage "cleanup"
    python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" verify-claim "$$" || exit 1
    $RESET || cleanup_status=$?
    if [ -n "${CENGINE_COMPAT_CLIENT_STATE_ROOT:-}" ]; then
        python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" verify-claim "$$" || exit 1
        rm -rf "$CENGINE_COMPAT_CLIENT_STATE_ROOT" || cleanup_status=$?
        if [ -e "$CENGINE_COMPAT_CLIENT_STATE_ROOT" ]; then
            echo "compatibility client state leaked at $CENGINE_COMPAT_CLIENT_STATE_ROOT" >&2
            cleanup_status=1
        fi
    fi
    python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" release-claim "$$" || cleanup_status=$?
    if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
        status=$cleanup_status
    fi
    exit "$status"
}

acquire_lock
CENGINE_COMPAT_OWNER_PID=$$
export CENGINE_COMPAT_OWNER_PID
CENGINE_COMPAT_CLAIM=$(python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" pin-claim "$$")
export CENGINE_COMPAT_CLAIM
CENGINE_COMPAT_CLIENT_STATE_ROOT="$LOCK/client-state"
trap cleanup EXIT HUP INT TERM

AMBIENT_DOCKER_CONFIG=${DOCKER_CONFIG:-"$HOME/.docker"}
CENGINE_COMPAT_RUN_ID=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
DOCKER_CONFIG="$CENGINE_COMPAT_CLIENT_STATE_ROOT/docker"
BUILDX_CONFIG="$CENGINE_COMPAT_CLIENT_STATE_ROOT/buildx"
mkdir -p "$DOCKER_CONFIG/cli-plugins" "$BUILDX_CONFIG"
for plugin in buildx compose; do
    if plugin_path=$(
        "$ROOT/Scripts/find-docker-plugin.sh" "$plugin" "$AMBIENT_DOCKER_CONFIG"
    ); then
        ln -s "$plugin_path" "$DOCKER_CONFIG/cli-plugins/docker-$plugin"
    fi
done
printf '%s %s\n' "$CENGINE_COMPAT_RUN_ID" "$CENGINE_COMPAT_OWNER_PID" \
    > "$CENGINE_COMPAT_CLIENT_STATE_ROOT/.owner-pid"
export CENGINE_COMPAT_CLIENT_STATE_ROOT CENGINE_COMPAT_RUN_ID CENGINE_COMPAT_OWNER_PID
export DOCKER_CONFIG BUILDX_CONFIG

unset DOCKER_API_VERSION DOCKER_AUTH_CONFIG DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_HOST
unset DOCKER_TLS DOCKER_TLS_VERIFY BUILDX_BUILDER CONTAINER_HOST

CENGINE_COMPAT_IPV4_AUTO_POOL=${CENGINE_COMPAT_IPV4_AUTO_POOL:-10.192.0.0/12}
CENGINE_COMPAT_IPV6_AUTO_PREFIX=${CENGINE_COMPAT_IPV6_AUTO_PREFIX:-fdcc::/16}
CENGINE_COMPAT_IPV4_FIXTURE_POOL=${CENGINE_COMPAT_IPV4_FIXTURE_POOL:-10.208.0.0/12}
CENGINE_COMPAT_IPV6_FIXTURE_PREFIX=${CENGINE_COMPAT_IPV6_FIXTURE_PREFIX:-fdcd::/16}
export CENGINE_COMPAT_IPV4_AUTO_POOL CENGINE_COMPAT_IPV6_AUTO_PREFIX
export CENGINE_COMPAT_IPV4_FIXTURE_POOL CENGINE_COMPAT_IPV6_FIXTURE_PREFIX

case "$MODE" in
    helper-install)
        BUILD_STAGE="build and provision compatibility runtime"
        ;;
    suite|soak|oracle)
        BUILD_STAGE="build and validate compatibility runtime"
        ;;
    *)
        echo "unknown compatibility test mode: $MODE" >&2
        exit 2
        ;;
esac

stage "preflight reset"
$RESET

if [ "$BUILD_DEFAULT_ASSETS" = 1 ]; then
    stage "build current default lifecycle guest assets"
    make -C "$ROOT" --no-print-directory guest-initramfs
    "$ROOT/Scripts/check-guest-kernel.sh"
    python3 "$ROOT/Scripts/check-managed-guest-assets.py" "$CENGINE_COMPAT_MANAGED_ASSET_DIR"
    compat_network_helper_select_policy >/dev/null
fi

stage "$BUILD_STAGE"
HELPER_FINGERPRINT=$("$ROOT/Scripts/network-helper-fingerprint.sh")
build_compat_runtime() {
    # Function-local argv preserves the caller's pytest selection.
    # Explicitly clear all outputs on normal builds to prevent stale reuse.
    # The cold-L2 cut is helper-only: Runtime must not parse this helper profile.
    fault_condition= helper_fault_condition= cold_l2_fault=
    case "$CENGINE_COMPAT_LIFECYCLE_FAULT" in
        after-cold-l2-before-a1-v1)
            helper_fault_condition=CENGINE_COMPAT_COLD_L2_FAULT
            cold_l2_fault=$CENGINE_COMPAT_LIFECYCLE_FAULT;;
        '') ;;
        *) fault_condition=CENGINE_COMPAT_LIFECYCLE_FAULT;;
    esac
    set -- "CENGINE_COMPAT_LIFECYCLE_FAULT=$CENGINE_COMPAT_LIFECYCLE_FAULT" \
        "CENGINE_RUNTIME_COMPAT_LIFECYCLE_FAULT_CONDITION=$fault_condition" \
        "CENGINE_HELPER_COMPAT_COLD_L2_FAULT_CONDITION=$helper_fault_condition" \
        "CENGINE_COMPAT_COLD_L2_FAULT=$cold_l2_fault"
    if [ -n "$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION" ]; then
        set -- "$@" 'OTHER_SWIFT_FLAGS=$(inherited) -parse-as-library -D CENGINE_STORAGE_LIFECYCLE_QUALIFICATION' \
            "CENGINE_STORAGE_LIFECYCLE_QUALIFICATION=$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION" \
            "CENGINE_STORAGE_LIFECYCLE_SOURCE_PIN=$CENGINE_STORAGE_LIFECYCLE_SOURCE_PIN" \
            "CENGINE_STORAGE_LIFECYCLE_ASSETS_SHA256=$CENGINE_STORAGE_LIFECYCLE_ASSETS_SHA256"
    fi
    "$XCODEBUILD" -project "$XCODE_PROJECT" -scheme "$XCODE_COMPAT_SCHEME" \
    -configuration "$XCODE_COMPAT_CONFIGURATION" -derivedDataPath "$XCODE_DERIVED_DATA" \
    -clonedSourcePackagesDirPath "$XCODE_SOURCE_PACKAGES" \
    $XCODE_COMMON_FLAGS CENGINE_GIT_COMMIT="${CENGINE_GIT_COMMIT:-unknown}" \
    CENGINE_BUILD_TIME="${CENGINE_BUILD_TIME:-}" \
    CENGINE_NETWORK_HELPER_BUILD_FINGERPRINT="$HELPER_FINGERPRINT" \
    CENGINE_TEAM_IDENTIFIER="$TEAM_IDENTIFIER" "$@" build
}
build_compat_runtime
if [ -n "$CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY" ]; then
    "$ROOT/Scripts/build-storage-controller.sh" --sign "$CENGINE_DEVELOPER_ID_APPLICATION" \
        "--prepare-compatibility=$CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY" \
        "$(dirname "$BINARY")/cengine-storage-controller"
else
    "$ROOT/Scripts/build-storage-controller.sh" --sign "$CENGINE_DEVELOPER_ID_APPLICATION" --compat \
        "$(dirname "$BINARY")/cengine-storage-controller"
fi
if [ -n "$TEAM_IDENTIFIER" ]; then
    "$ROOT/Scripts/sign-compat-binary.sh" --sign "$CENGINE_DEVELOPER_ID_APPLICATION" "$BINARY"
else
    "$ROOT/Scripts/sign-compat-binary.sh" "$BINARY"
fi
if [ -n "$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION" ]; then
    test "$CENGINE_STORAGE_LIFECYCLE_SOURCE_PIN" = "$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" source-pin "$ROOT")"
    test "$CENGINE_STORAGE_LIFECYCLE_ASSETS_SHA256" = "$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" assets-sha256 "$ROOT" "$CENGINE_COMPAT_MANAGED_ASSET_DIR")"
    echo "test-only lifecycle qualification: $CENGINE_STORAGE_LIFECYCLE_QUALIFICATION (attended install and tests must use this same profile)"
fi
HELPER=$(compat_network_helper_local_for_binary "$BINARY")
if [ "$MODE" = helper-install ]; then
    compat_network_helper_provision "$HELPER" "$BINARY" "$HELPER_FINGERPRINT"
    exit 0
fi
compat_network_helper_require "$BINARY" "$HELPER_FINGERPRINT"

stage "validate paired lifecycle guest assets (no rebuild or download)"
python3 "$ROOT/Scripts/check-managed-guest-assets.py" "$CENGINE_COMPAT_MANAGED_ASSET_DIR"
"$ROOT/Scripts/check-compat-network-pools.py"

stage "recreate test environment"
rm -rf "$ROOT/.build/compat-venv"
python3 -m venv "$ROOT/.build/compat-venv"
"$ROOT/.build/compat-venv/bin/pip" install --disable-pip-version-check -q \
    -r "$ROOT/Tests/Compatibility/requirements.txt"
"$ROOT/.build/compat-venv/bin/python" -W error "$ROOT/tools/tests/test-volume-missing-subpath.py"

if [ "$#" -eq 0 ]; then
    set -- "$ROOT/Tests/Compatibility"
fi

run_pytest() {
    "$ROOT/.build/compat-venv/bin/python" -m pytest \
        --rootdir="$ROOT" -c "$ROOT/Tests/Compatibility/pytest.ini" "$@"
}

case "$MODE" in
    suite)
        stage "run compatibility suite"
        run_pytest "$@"
        ;;
    soak)
        for seed in 101 202 303; do
            stage "reset for compatibility soak seed $seed"
            $RESET
            stage "run compatibility soak seed $seed"
            CENGINE_TEST_SEED=$seed run_pytest "$@"
        done
        ;;
    oracle)
        if [ -z "${DOCKER_REFERENCE_HOST:-}" ]; then
            echo "DOCKER_REFERENCE_HOST is required" >&2
            exit 2
        fi
        stage "run Docker oracle suite"
        run_pytest -m oracle "$@"
        ;;
esac
