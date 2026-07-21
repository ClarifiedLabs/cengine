#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=Scripts/compat-network-helper.sh
. "$ROOT/Scripts/compat-network-helper.sh"
MODE=${1:-suite}
shift || true
BINARY=${CENGINE_BINARY:-"$ROOT/.build/xcode-derived/Build/Products/test-compat/cengine"}
CENGINE_BINARY=$BINARY
CENGINE_KERNEL=${CENGINE_KERNEL:-"$ROOT/.build/guest/vmlinux"}
CENGINE_CONTAINER_INITRAMFS=${CENGINE_CONTAINER_INITRAMFS:-"$ROOT/.build/guest/container-initramfs.cpio.gz"}
CENGINE_STORAGE_INITRAMFS=${CENGINE_STORAGE_INITRAMFS:-"$ROOT/.build/guest/storage-initramfs.cpio.gz"}
export CENGINE_BINARY CENGINE_KERNEL CENGINE_CONTAINER_INITRAMFS CENGINE_STORAGE_INITRAMFS
XCODEBUILD=${XCODEBUILD:-xcodebuild}
XCODE_PROJECT=${XCODE_PROJECT:-cengine.xcodeproj}
XCODE_DERIVED_DATA=${XCODE_DERIVED_DATA:-.build/xcode-derived}
XCODE_SOURCE_PACKAGES=${XCODE_SOURCE_PACKAGES:-.build/xcode-source-packages}
XCODE_COMPAT_SCHEME=${XCODE_COMPAT_SCHEME:-test-compat}
XCODE_COMPAT_CONFIGURATION=${XCODE_COMPAT_CONFIGURATION:-test-compat}
XCODE_COMMON_FLAGS=${XCODE_COMMON_FLAGS:-"-skipPackagePluginValidation -skipMacroValidation ENABLE_CODE_COVERAGE=NO CLANG_COVERAGE_MAPPING=NO"}
RESET="python3 $ROOT/Scripts/reset-compat-runtime.py --binary $BINARY"
LOCK=${CENGINE_COMPAT_LOCK:-"${TMPDIR:-/tmp}/cengine-compat-run.lock"}

stage() {
    printf '\n==> compatibility: %s\n' "$1"
}

acquire_lock() {
    if mkdir "$LOCK" 2>/dev/null; then
        printf '%s\n' "$$" > "$LOCK/pid"
        return
    fi

    owner=$(cat "$LOCK/pid" 2>/dev/null || true)
    if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
        echo "another compatibility run owns $LOCK (pid $owner)" >&2
        exit 2
    fi

    rm -rf "$LOCK"
    mkdir "$LOCK"
    printf '%s\n' "$$" > "$LOCK/pid"
}

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    stage "cleanup"
    $RESET || status=$?
    rm -rf "$LOCK"
    exit "$status"
}

acquire_lock
trap cleanup EXIT HUP INT TERM

unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY
unset BUILDX_BUILDER CONTAINER_HOST

CENGINE_COMPAT_IPV4_AUTO_POOL=${CENGINE_COMPAT_IPV4_AUTO_POOL:-10.192.0.0/12}
CENGINE_COMPAT_IPV6_AUTO_PREFIX=${CENGINE_COMPAT_IPV6_AUTO_PREFIX:-fdcc::/16}
CENGINE_COMPAT_IPV4_FIXTURE_POOL=${CENGINE_COMPAT_IPV4_FIXTURE_POOL:-10.208.0.0/12}
CENGINE_COMPAT_IPV6_FIXTURE_PREFIX=${CENGINE_COMPAT_IPV6_FIXTURE_PREFIX:-fdcd::/16}
export CENGINE_COMPAT_IPV4_AUTO_POOL CENGINE_COMPAT_IPV6_AUTO_PREFIX
export CENGINE_COMPAT_IPV4_FIXTURE_POOL CENGINE_COMPAT_IPV6_FIXTURE_PREFIX

stage "preflight reset"
$RESET

stage "build and authorize compatibility runtime"
HELPER_FINGERPRINT=$("$ROOT/Scripts/network-helper-fingerprint.sh")
"$XCODEBUILD" -project "$ROOT/$XCODE_PROJECT" -scheme "$XCODE_COMPAT_SCHEME" \
    -configuration "$XCODE_COMPAT_CONFIGURATION" -derivedDataPath "$ROOT/$XCODE_DERIVED_DATA" \
    -clonedSourcePackagesDirPath "$ROOT/$XCODE_SOURCE_PACKAGES" \
    $XCODE_COMMON_FLAGS CENGINE_GIT_COMMIT="${CENGINE_GIT_COMMIT:-unknown}" \
    CENGINE_BUILD_TIME="${CENGINE_BUILD_TIME:-}" \
    CENGINE_NETWORK_HELPER_BUILD_FINGERPRINT="$HELPER_FINGERPRINT" build
"$ROOT/Scripts/sign-compat-binary.sh" "$BINARY"
HELPER=$(compat_network_helper_local_for_binary "$BINARY")
compat_network_helper_ensure "$HELPER" "$BINARY" "$HELPER_FINGERPRINT"

stage "rebuild and validate guest assets"
make -C "$ROOT" --no-print-directory guest-initramfs
"$ROOT/Scripts/check-guest-kernel.sh"
"$ROOT/Scripts/check-compat-network-pools.py"

stage "recreate test environment"
rm -rf "$ROOT/.build/compat-venv"
python3 -m venv "$ROOT/.build/compat-venv"
"$ROOT/.build/compat-venv/bin/pip" install --disable-pip-version-check -q \
    -r "$ROOT/Tests/Compatibility/requirements.txt"

if [ "$#" -eq 0 ]; then
    set -- "$ROOT/Tests/Compatibility"
fi

run_pytest() {
    "$ROOT/.build/compat-venv/bin/python" -m pytest \
        -c "$ROOT/Tests/Compatibility/pytest.ini" "$@"
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
    *)
        echo "unknown compatibility test mode: $MODE" >&2
        exit 2
        ;;
esac
