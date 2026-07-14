#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-version")
SOURCE=${KERNEL_SOURCE:-"$ROOT/.build/guest-cache/linux-$VERSION"}
OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/guest"}
IMAGE=${CENGINE_KERNEL_BUILD_IMAGE:-debian:trixie-slim}
JOBS=${CENGINE_KERNEL_BUILD_JOBS:-4}
CACHE=${CENGINE_GUEST_CACHE:-"$ROOT/.build/guest-cache"}
DOCKER_CONTEXT=${CENGINE_TOOLCHAIN_DOCKER_CONTEXT:-default}
EMPTY_CONTEXT="$CACHE/empty-context"

test -f "$SOURCE/Makefile" || {
    echo "kernel source is missing at $SOURCE" >&2
    exit 2
}

mkdir -p "$OUTPUT" "$EMPTY_CONTEXT"
docker --context "$DOCKER_CONTEXT" buildx build \
    --progress plain \
    --platform linux/arm64 \
    --build-arg "CENGINE_KERNEL_BUILD_JOBS=$JOBS" \
    --build-context "kernel=$SOURCE" \
    --build-context "config=$ROOT/Configuration" \
    --build-context "scripts=$ROOT/Scripts" \
    --output "type=local,dest=$OUTPUT" \
    --file - \
    "$EMPTY_CONTEXT" <<'EOF'
# syntax=docker/dockerfile:1.7
ARG CENGINE_KERNEL_BUILD_JOBS
FROM debian:trixie-slim AS build
ARG CENGINE_KERNEL_BUILD_JOBS
COPY --from=kernel / /linux
COPY --from=config /cengine-kernel.fragment /fragment
COPY --from=scripts /compile-kernel-in-guest.sh /compile-kernel
RUN mkdir -p /output && /bin/sh /compile-kernel "$CENGINE_KERNEL_BUILD_JOBS"

FROM scratch
COPY --from=build /output/vmlinux.next /vmlinux
EOF
