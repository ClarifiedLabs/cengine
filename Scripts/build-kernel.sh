#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-version")
COMMIT=$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-commit")
CACHE=${CENGINE_GUEST_CACHE:-"$ROOT/.build/guest-cache"}
SOURCE=${KERNEL_SOURCE:-"$CACHE/linux-$VERSION"}
OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/guest"}
BINARY=${CENGINE_BINARY:-"$ROOT/.build/xcode-derived/Build/Products/Debug/cengine"}
IMAGE=${CENGINE_KERNEL_BUILD_IMAGE:-debian:trixie-slim}
JOBS=${CENGINE_KERNEL_BUILD_JOBS:-4}
CPUS=${CENGINE_KERNEL_BUILD_CPUS:-4}
MEMORY=${CENGINE_KERNEL_BUILD_MEMORY:-8g}
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
    Linux)
        KERNEL_SOURCE="$SOURCE" \
        CENGINE_GUEST_OUTPUT="$OUTPUT" \
        CENGINE_KERNEL_BUILD_IMAGE="$IMAGE" \
        CENGINE_KERNEL_BUILD_JOBS="$JOBS" \
            "$ROOT/Scripts/build-kernel-linux.sh"
        ;;
    Darwin)
        if [ ! -f "$OUTPUT/vmlinux" ]; then
            bootstrap=${CENGINE_BOOTSTRAP_KERNEL:-}
            if [ -z "$bootstrap" ] && [ -f "$HOME/Library/Application Support/cengine/assets/vmlinux" ]; then
                bootstrap="$HOME/Library/Application Support/cengine/assets/vmlinux"
            fi
            if [ -z "$bootstrap" ] && [ -f "$ROOT/dist/share/cengine/vmlinux" ]; then
                bootstrap="$ROOT/dist/share/cengine/vmlinux"
            fi
            if [ -z "$bootstrap" ] || [ ! -f "$bootstrap" ]; then
                echo "a bootstrap cengine kernel is required; set CENGINE_BOOTSTRAP_KERNEL or install cengine guest assets" >&2
                exit 2
            fi
            cp "$bootstrap" "$OUTPUT/vmlinux"
        fi

        CENGINE_GUEST_OUTPUT="$OUTPUT" "$ROOT/Scripts/build-guest-assets.sh"
        rm -f "$OUTPUT/vmlinux.next"

        CENGINE_BINARY="$BINARY" \
        CENGINE_KERNEL="$OUTPUT/vmlinux" \
        CENGINE_CONTAINER_INITRAMFS="$OUTPUT/container-initramfs.cpio.gz" \
        CENGINE_STORAGE_INITRAMFS="$OUTPUT/storage-initramfs.cpio.gz" \
        "$ROOT/Scripts/run-isolated-cengine.sh" sh -eu -c '
            docker pull "$1"
            docker run --rm \
                --cpus "$7" \
                --memory "$8" \
                --mount "type=bind,src=$2,dst=/linux,readonly" \
                --mount "type=bind,src=$3,dst=/fragment,readonly" \
                --mount "type=bind,src=$4,dst=/compile,readonly" \
                --mount "type=bind,src=$5,dst=/output" \
                "$1" /bin/sh /compile "$6"
        ' cengine-kernel-build \
            "$IMAGE" "$SOURCE" "$ROOT/Configuration/cengine-kernel.fragment" \
            "$ROOT/Scripts/compile-kernel-in-guest.sh" "$OUTPUT" "$JOBS" "$CPUS" "$MEMORY"

        mv "$OUTPUT/vmlinux.next" "$OUTPUT/vmlinux"
        ;;
    *)
        echo "unsupported kernel build host: $HOST_OS" >&2
        exit 2
        ;;
esac

cat "$ROOT/Configuration/kernel-version" \
    "$ROOT/Configuration/kernel-commit" \
    "$ROOT/Configuration/cengine-kernel.fragment" \
    | shasum -a 256 | awk '{print $1}' > "$OUTPUT/kernel-input.sha256"
echo "Built pinned Linux $VERSION ($COMMIT) at $OUTPUT/vmlinux"
