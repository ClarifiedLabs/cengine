#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-version")
COMMIT=$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-commit")
CACHE=${CENGINE_GUEST_CACHE:-"$ROOT/.build/guest-cache"}
SOURCE=${KERNEL_SOURCE:-"$CACHE/linux-$VERSION"}
OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/guest"}
IMAGE=${CENGINE_KERNEL_BUILD_IMAGE:-$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-build-image")}
JOBS=${CENGINE_KERNEL_BUILD_JOBS:-${CENGINE_KERNEL_BUILD_CPUS:-auto}}
HOST_OS=${CENGINE_HOST_OS:-$(uname -s)}

mkdir -p "$CACHE" "$OUTPUT"
if [ -f "$SOURCE/Makefile" ] && [ "$(git -C "$SOURCE" rev-parse HEAD 2>/dev/null || true)" != "$COMMIT" ]; then
    rm -rf "$SOURCE"
fi
if [ ! -f "$SOURCE/Makefile" ]; then
    rm -rf "$SOURCE"
    git init -q "$SOURCE"
    git -C "$SOURCE" remote add origin https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
    git -C "$SOURCE" fetch -q --depth 1 origin "$COMMIT"
    git -C "$SOURCE" checkout -q --detach FETCH_HEAD
fi
test "$(git -C "$SOURCE" rev-parse HEAD)" = "$COMMIT" || {
    echo "kernel source is not pinned Linux $VERSION commit $COMMIT" >&2
    exit 2
}

case "$HOST_OS" in
    Linux|Darwin)
        KERNEL_SOURCE="$SOURCE" \
        CENGINE_GUEST_OUTPUT="$OUTPUT" \
        CENGINE_KERNEL_BUILD_IMAGE="$IMAGE" \
        CENGINE_KERNEL_BUILD_JOBS="$JOBS" \
            "$ROOT/Scripts/build-kernel-linux.sh"
        ;;
    *)
        echo "unsupported kernel build host: $HOST_OS" >&2
        exit 2
        ;;
esac

"$ROOT/Scripts/kernel-input-sha256.sh" > "$OUTPUT/kernel-input.sha256"
echo "Built pinned Linux $VERSION ($COMMIT) at $OUTPUT/vmlinux"
