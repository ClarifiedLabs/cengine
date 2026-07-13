#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(tr -d '[:space:]' < "$ROOT/Configuration/e2fsprogs-version")
SHA256=08242e64ca0e8194d9c1caad49762b19209a06318199b63ce74ae4ef2d74e63c
OUTPUT=${1:-"$ROOT/.build/guest/mke2fs"}
CACHE=${CENGINE_GUEST_CACHE:-"$ROOT/.build/guest-cache"}
ARCHIVE="$CACHE/e2fsprogs-$VERSION.tar.xz"
URL="https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v$VERSION/e2fsprogs-$VERSION.tar.xz"

mkdir -p "$CACHE" "$(dirname "$OUTPUT")"
if [ ! -f "$ARCHIVE" ]; then
    curl --fail --location --retry 3 --output "$ARCHIVE.tmp" "$URL"
    mv "$ARCHIVE.tmp" "$ARCHIVE"
fi
printf '%s  %s\n' "$SHA256" "$ARCHIVE" | shasum -a 256 -c -

EMPTY_CONTEXT="$CACHE/empty-context"
mkdir -p "$EMPTY_CONTEXT"
docker buildx build \
    --progress plain \
    --platform linux/arm64 \
    --build-arg "E2FS_VERSION=$VERSION" \
    --build-context "source=$CACHE" \
    --output "type=local,dest=$(dirname "$OUTPUT")" \
    --file - \
    "$EMPTY_CONTEXT" <<'EOF'
# syntax=docker/dockerfile:1.7
ARG E2FS_VERSION
FROM debian:trixie-slim AS build
ARG E2FS_VERSION
RUN apt-get -o APT::Sandbox::User=root update && \
    DEBIAN_FRONTEND=noninteractive apt-get -o APT::Sandbox::User=root install -y --no-install-recommends build-essential ca-certificates file pkg-config xz-utils && \
    rm -rf /var/lib/apt/lists/*
COPY --from=source /e2fsprogs-${E2FS_VERSION}.tar.xz /src/e2fsprogs.tar.xz
RUN mkdir /work && tar -C /work --strip-components=1 -xf /src/e2fsprogs.tar.xz && \
    mkdir /work/build && cd /work/build && \
    ../configure --host=aarch64-linux-gnu --disable-shared --enable-static --disable-nls --disable-fsck --disable-uuidd && \
    make -j"$(nproc)" libs && \
    make -C misc -j"$(nproc)" mke2fs.static && \
    install -m 0755 misc/mke2fs.static /mke2fs && \
    file /mke2fs | grep -q "statically linked"

FROM scratch
COPY --from=build /mke2fs /mke2fs
EOF
