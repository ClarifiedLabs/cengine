#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/guest"}
CONTAINER_ROOT="$OUTPUT/container-root"
STORAGE_ROOT="$OUTPUT/storage-root"
MKE2FS="$OUTPUT/mke2fs"
BINARY_OUTPUT="$OUTPUT/guest-bin"

rm -rf "$CONTAINER_ROOT" "$STORAGE_ROOT" "$BINARY_OUTPUT"
mkdir -p "$OUTPUT" \
    "$CONTAINER_ROOT/bin" "$CONTAINER_ROOT/sbin" "$CONTAINER_ROOT/etc" "$CONTAINER_ROOT/dev" "$CONTAINER_ROOT/proc" "$CONTAINER_ROOT/sys" "$CONTAINER_ROOT/run" "$CONTAINER_ROOT/rootfs" \
    "$STORAGE_ROOT/bin" "$STORAGE_ROOT/sbin" "$STORAGE_ROOT/etc" "$STORAGE_ROOT/dev" "$STORAGE_ROOT/proc" "$STORAGE_ROOT/sys" "$STORAGE_ROOT/run" "$STORAGE_ROOT/data"

if [ ! -f "$OUTPUT/vmlinux" ]; then
    echo "cengine kernel is missing at $OUTPUT/vmlinux; run make kernel" >&2
    exit 2
fi

if [ ! -x "$MKE2FS" ]; then
    "$ROOT/Scripts/build-e2fsprogs.sh" "$MKE2FS"
fi

GO=$(sh "$ROOT/Scripts/ensure-go-toolchain.sh")
mkdir -p "$BINARY_OUTPUT/out"
(
    cd "$ROOT/Guest"
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$GO" build -trimpath -buildvcs=false \
        -ldflags='-s -w -buildid=' -o "$BINARY_OUTPUT/out/cengine-init" ./cmd/cengine-init
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$GO" build -trimpath -buildvcs=false \
        -ldflags='-s -w -buildid=' -o "$BINARY_OUTPUT/out/cengine-storage" ./cmd/cengine-storage
)
install -m 0755 "$BINARY_OUTPUT/out/cengine-init" "$CONTAINER_ROOT/init"
install -m 0755 "$BINARY_OUTPUT/out/cengine-storage" "$STORAGE_ROOT/init"

install -m 0755 "$MKE2FS" "$CONTAINER_ROOT/sbin/mke2fs"
install -m 0755 "$MKE2FS" "$STORAGE_ROOT/sbin/mke2fs"
install -m 0644 "$ROOT/Configuration/mke2fs.conf" "$CONTAINER_ROOT/etc/mke2fs.conf"
install -m 0644 "$ROOT/Configuration/mke2fs.conf" "$STORAGE_ROOT/etc/mke2fs.conf"

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0} python3 "$ROOT/Scripts/make-initramfs.py" "$CONTAINER_ROOT" "$OUTPUT/container-initramfs.cpio.gz"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0} python3 "$ROOT/Scripts/make-initramfs.py" "$STORAGE_ROOT" "$OUTPUT/storage-initramfs.cpio.gz"
(
    cd "$OUTPUT"
    shasum -a 256 vmlinux container-initramfs.cpio.gz storage-initramfs.cpio.gz > SHA256SUMS
)
