#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BINARY=${CENGINE_BINARY:-"$ROOT/.build/xcode-derived/Build/Products/Debug/cengine"}
KERNEL=${CENGINE_KERNEL:-"$ROOT/.build/guest/vmlinux"}
CONTAINER_INITRAMFS=${CENGINE_CONTAINER_INITRAMFS:-"$ROOT/.build/guest/container-initramfs.cpio.gz"}
STORAGE_INITRAMFS=${CENGINE_STORAGE_INITRAMFS:-"$ROOT/.build/guest/storage-initramfs.cpio.gz"}
IMAGE_CACHE=${CENGINE_ISOLATED_IMAGE_CACHE:-"$ROOT/.build/isolated-image-cache-v1"}

if [ "$#" -eq 0 ]; then
    echo "usage: $0 COMMAND [ARG ...]" >&2
    exit 2
fi
for asset in "$BINARY" "$KERNEL" "$CONTAINER_INITRAMFS" "$STORAGE_INITRAMFS"; do
    if [ ! -f "$asset" ]; then
        echo "required isolated runtime asset is missing: $asset" >&2
        exit 2
    fi
done

"$ROOT/Scripts/sign-compat-binary.sh" "$BINARY"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/cengine-compat-tool.XXXXXX")
ENGINE_ROOT="$WORK/root"
SOCKET="$WORK/docker.sock"
LOG="$WORK/daemon.log"
mkdir -p "$ENGINE_ROOT"

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -d "$ENGINE_ROOT/content" ]; then
        mkdir -p "$IMAGE_CACHE"
        temporary_cache="$IMAGE_CACHE/content.tmp.$$"
        rm -rf "$temporary_cache"
        /bin/cp -cR "$ENGINE_ROOT/content" "$temporary_cache" || true
        if [ -d "$temporary_cache" ]; then
            rm -rf "$IMAGE_CACHE/content"
            mv "$temporary_cache" "$IMAGE_CACHE/content"
        fi
    fi
    python3 "$ROOT/Scripts/reset-compat-runtime.py" \
        --binary "$BINARY" --root "$ENGINE_ROOT" >/dev/null 2>&1 || true
    if [ "$status" -ne 0 ] && [ -f "$LOG" ]; then
        echo "cengine isolated daemon log (last 200 lines):" >&2
        tail -n 200 "$LOG" >&2
    fi
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

python3 "$ROOT/Scripts/reset-compat-runtime.py" \
    --binary "$BINARY" --root "$ENGINE_ROOT"
if [ -d "$IMAGE_CACHE/content" ]; then
    /bin/cp -cR "$IMAGE_CACHE/content" "$ENGINE_ROOT/content"
fi
printf '%s\n' "$(CDPATH= cd -- "$(dirname -- "$BINARY")" && pwd)/$(basename -- "$BINARY")" \
    > "$WORK/.cengine-compat-owner"

"$BINARY" daemon \
    --socket "$SOCKET" \
    --root "$ENGINE_ROOT" \
    --kernel "$KERNEL" \
    --container-initramfs "$CONTAINER_INITRAMFS" \
    --storage-initramfs "$STORAGE_INITRAMFS" >"$LOG" 2>&1 &
daemon_pid=$!

attempt=0
while [ ! -S "$SOCKET" ]; do
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
        wait "$daemon_pid" || true
        echo "isolated cengine daemon exited before creating $SOCKET" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 600 ]; then
        echo "timed out waiting for isolated cengine daemon at $SOCKET" >&2
        exit 1
    fi
    sleep 0.1
done

unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY
export DOCKER_HOST="unix://$SOCKET"
docker version --format '{{.Server.Version}}' >/dev/null

"$@"
