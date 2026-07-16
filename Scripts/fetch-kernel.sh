#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/guest"}
CACHE=${CENGINE_GUEST_CACHE:-"$ROOT/.build/guest-cache"}
LOCAL_KERNEL=${CENGINE_LOCAL_KERNEL:-}
EXPECTED_INPUT=$("$ROOT/Scripts/kernel-input-sha256.sh")
STAMP="$OUTPUT/kernel-input.sha256"
ASSET=cengine-kernel-arm64

mkdir -p "$OUTPUT" "$CACHE"
install_kernel() {
    source=$1
    test -s "$source" || {
        echo "cengine kernel is missing or empty at $source" >&2
        exit 2
    }
    install -m 0644 "$source" "$OUTPUT/vmlinux.next"
    mv "$OUTPUT/vmlinux.next" "$OUTPUT/vmlinux"
    printf '%s\n' "$EXPECTED_INPUT" > "$STAMP.next"
    mv "$STAMP.next" "$STAMP"
}

if [ -n "$LOCAL_KERNEL" ]; then
    install_kernel "$LOCAL_KERNEL"
    echo "Installed local cengine kernel from $LOCAL_KERNEL"
    exit 0
fi

actual_input=$(cat "$STAMP" 2>/dev/null || true)
if [ -z "${CENGINE_KERNEL_FORCE:-}" ] && [ -s "$OUTPUT/vmlinux" ] && [ "$actual_input" = "$EXPECTED_INPUT" ]; then
    echo "Using prepared cengine kernel at $OUTPUT/vmlinux"
    exit 0
fi

RELEASE=$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-release")
case "$RELEASE" in
    ''|*[!A-Za-z0-9._-]*)
        echo "invalid cengine kernel release tag: $RELEASE" >&2
        exit 2
        ;;
esac
BASE_URL=${CENGINE_KERNEL_RELEASE_BASE_URL:-"https://github.com/ClarifiedLabs/cengine/releases/download/$RELEASE"}
RELEASE_CACHE="$CACHE/kernel-releases/$RELEASE"

validate_release() {
    directory=$1
    [ -s "$directory/$ASSET" ] && \
        [ -s "$directory/kernel-input.sha256" ] && \
        [ -s "$directory/SHA256SUMS" ] && \
        (cd "$directory" && shasum -a 256 -c SHA256SUMS >/dev/null) && \
        [ "$(tr -d '[:space:]' < "$directory/kernel-input.sha256")" = "$EXPECTED_INPUT" ]
}

if ! validate_release "$RELEASE_CACHE"; then
    mkdir -p "$(dirname "$RELEASE_CACHE")"
    work=$(mktemp -d "$CACHE/kernel-release.XXXXXX")
    cleanup() { rm -rf "$work"; }
    trap cleanup EXIT HUP INT TERM
    for name in "$ASSET" kernel-input.sha256 SHA256SUMS; do
        curl --fail --location --retry 3 --output "$work/$name" "$BASE_URL/$name"
    done
    if ! validate_release "$work"; then
        echo "cengine kernel release $RELEASE failed checksum or input verification" >&2
        exit 2
    fi
    replacement="$RELEASE_CACHE.next.$$"
    rm -rf "$replacement"
    mv "$work" "$replacement"
    trap - EXIT HUP INT TERM
    rm -rf "$RELEASE_CACHE"
    mv "$replacement" "$RELEASE_CACHE"
fi

install_kernel "$RELEASE_CACHE/$ASSET"
echo "Installed cengine kernel release $RELEASE at $OUTPUT/vmlinux"
