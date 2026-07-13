#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-version")
COMMIT=acb7cf4c1184e27622be0faf89244d5001ed1e87
CACHE=${CENGINE_GUEST_CACHE:-"$ROOT/.build/guest-cache"}
SOURCE=${KERNEL_SOURCE:-"$CACHE/linux-$VERSION"}
OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/guest"}
EMPTY_CONTEXT="$CACHE/empty-context"

mkdir -p "$CACHE" "$OUTPUT" "$EMPTY_CONTEXT"
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

docker buildx build \
    --progress plain \
    --platform linux/arm64 \
    --build-context "kernel=$SOURCE" \
    --build-context "config=$ROOT/Configuration" \
    --output "type=local,dest=$OUTPUT" \
    --file - \
    "$EMPTY_CONTEXT" <<'EOF'
# syntax=docker/dockerfile:1.7
FROM debian:trixie-slim AS build
RUN apt-get -o APT::Sandbox::User=root update && \
    DEBIAN_FRONTEND=noninteractive apt-get -o APT::Sandbox::User=root install -y --no-install-recommends bc bison build-essential ca-certificates flex libelf-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=kernel / /linux
COPY --from=config /cengine-kernel.fragment /fragment
RUN mkdir /build && \
    make -C /linux O=/build ARCH=arm64 defconfig && \
    /linux/scripts/kconfig/merge_config.sh -m -O /build /build/.config /fragment && \
    make -C /linux O=/build ARCH=arm64 olddefconfig && \
    grep -qx 'CONFIG_FUSE_FS=y' /build/.config && \
    grep -qx 'CONFIG_VIRTIO_FS=y' /build/.config && \
    make -C /linux O=/build ARCH=arm64 -j"$(nproc)" Image

FROM scratch
COPY --from=build /build/arch/arm64/boot/Image /vmlinux
EOF

echo "Built pinned Linux $VERSION ($COMMIT) at $OUTPUT/vmlinux"
