#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-version")
SOURCE=${KERNEL_SOURCE:-"$ROOT/.build/guest-cache/linux-$VERSION"}
OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/guest"}
IMAGE=${CENGINE_KERNEL_BUILD_IMAGE:-$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-build-image")}
CPUS=${CENGINE_KERNEL_BUILD_CPUS:-}
MEMORY=${CENGINE_KERNEL_BUILD_MEMORY:-}
JOBS=${CENGINE_KERNEL_BUILD_JOBS:-${CPUS:-auto}}
CACHE=${CENGINE_GUEST_CACHE:-"$ROOT/.build/guest-cache"}
DOCKER_CONTEXT=${CENGINE_TOOLCHAIN_DOCKER_CONTEXT:-}
EMPTY_CONTEXT="$CACHE/empty-context"

test -f "$SOURCE/Makefile" || {
    echo "kernel source is missing at $SOURCE" >&2
    exit 2
}

case "$CPUS" in
    ''|*[!0-9]*|0)
        if [ -n "$CPUS" ]; then
            echo "CENGINE_KERNEL_BUILD_CPUS must be a positive integer" >&2
            exit 2
        fi
        ;;
esac

docker_cli() {
    if [ -n "$DOCKER_CONTEXT" ]; then
        docker --context "$DOCKER_CONTEXT" "$@"
    else
        docker "$@"
    fi
}

command -v docker >/dev/null 2>&1 || {
    echo "Docker with Buildx is required to build the cengine kernel" >&2
    exit 2
}
if ! docker_cli buildx version >/dev/null 2>&1; then
    echo "Docker Buildx is unavailable for the selected Docker context" >&2
    echo "configure Docker first or set CENGINE_TOOLCHAIN_DOCKER_CONTEXT" >&2
    exit 2
fi

mkdir -p "$OUTPUT" "$EMPTY_CONTEXT"
set -- buildx build \
    --progress plain \
    --platform linux/arm64 \
    --build-arg "CENGINE_KERNEL_BUILD_IMAGE=$IMAGE" \
    --build-arg "CENGINE_KERNEL_BUILD_JOBS=$JOBS" \
    --build-context "kernel=$SOURCE" \
    --build-context "config=$ROOT/Configuration" \
    --build-context "scripts=$ROOT/Scripts" \
    --output "type=local,dest=$OUTPUT" \
    --file -
if [ -n "$CPUS" ]; then
    set -- "$@" --resource "cpu-quota=$((CPUS * 100000))"
fi
if [ -n "$MEMORY" ]; then
    set -- "$@" --resource "memory=$MEMORY"
fi
set -- "$@" "$EMPTY_CONTEXT"
docker_cli "$@" <<'EOF'
# syntax=docker/dockerfile:1.7
ARG CENGINE_KERNEL_BUILD_IMAGE
ARG CENGINE_KERNEL_BUILD_JOBS
FROM ${CENGINE_KERNEL_BUILD_IMAGE} AS build
ARG CENGINE_KERNEL_BUILD_JOBS
COPY --from=kernel / /linux
COPY --from=config /cengine-kernel.fragment /fragment
COPY --from=scripts /compile-kernel-in-guest.sh /compile-kernel
RUN mkdir -p /output && /bin/sh /compile-kernel "$CENGINE_KERNEL_BUILD_JOBS"

FROM scratch
COPY --from=build /output/vmlinux.next /vmlinux
EOF
