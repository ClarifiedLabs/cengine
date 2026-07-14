#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=1.26.5
CACHE=${CENGINE_TOOLCHAIN_CACHE:-"$ROOT/.build/toolchains"}

if [ -n "${CENGINE_GO:-}" ]; then
    test -x "$CENGINE_GO" || { echo "CENGINE_GO is not executable: $CENGINE_GO" >&2; exit 2; }
    printf '%s\n' "$CENGINE_GO"
    exit 0
fi

HOST_OS=${CENGINE_HOST_OS:-$(uname -s)}
HOST_ARCH=${CENGINE_HOST_ARCH:-$(uname -m)}
case "$HOST_OS:$HOST_ARCH" in
    Darwin:arm64)
        PLATFORM=darwin-arm64
        GOOS=darwin
        SHA256=efb87ff28af9a188d0536ef5d42e63dd52ba8263cd7344a993cc48dd11dedb6a
        ;;
    Linux:arm64|Linux:aarch64)
        PLATFORM=linux-arm64
        GOOS=linux
        SHA256=fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49
        ;;
    *)
        echo "unsupported Go toolchain host: $HOST_OS/$HOST_ARCH" >&2
        exit 2
        ;;
esac

TOOLCHAIN="$CACHE/go$VERSION.$PLATFORM"
GO="$TOOLCHAIN/go/bin/go"
ARCHIVE="$CACHE/go$VERSION.$PLATFORM.tar.gz"
URL="https://go.dev/dl/go$VERSION.$PLATFORM.tar.gz"

if [ -x "$GO" ] && "$GO" version | grep -q "go$VERSION $GOOS/arm64"; then
    printf '%s\n' "$GO"
    exit 0
fi

mkdir -p "$CACHE"
if [ ! -f "$ARCHIVE" ]; then
    curl --fail --location --retry 3 --output "$ARCHIVE.tmp" "$URL"
    mv "$ARCHIVE.tmp" "$ARCHIVE"
fi
printf '%s  %s\n' "$SHA256" "$ARCHIVE" | shasum -a 256 -c - >&2

temporary="$TOOLCHAIN.tmp.$$"
trap 'rm -rf "$temporary"' EXIT INT TERM
rm -rf "$temporary" "$TOOLCHAIN"
mkdir -p "$temporary"
tar -C "$temporary" -xzf "$ARCHIVE"
mv "$temporary" "$TOOLCHAIN"
trap - EXIT INT TERM
printf '%s\n' "$GO"
