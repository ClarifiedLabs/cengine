#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/guest"}
CACHE=${CENGINE_GUEST_CACHE:-"$ROOT/.build/guest-cache"}
LOCAL_KERNEL=${CENGINE_LOCAL_KERNEL:-}
EXPECTED_INPUT=$("$ROOT/Scripts/kernel-input-sha256.sh")
STAMP="$OUTPUT/kernel-input.sha256"
ASSET=cengine-kernel-arm64
RELEASE=$(tr -d '[:space:]' < "$ROOT/Configuration/kernel-release")
case "$RELEASE" in
    ''|*[!A-Za-z0-9._-]*) echo "invalid cengine kernel release tag: $RELEASE" >&2; exit 2 ;;
esac
CANONICAL_URL="https://github.com/ClarifiedLabs/cengine/releases/download/$RELEASE"
BASE_URL=${CENGINE_KERNEL_RELEASE_BASE_URL:-"$CANONICAL_URL"}
ORIGIN=canonical-release
RELEASE_CACHE="$CACHE/kernel-releases/canonical/$RELEASE"
if [ "$BASE_URL" != "$CANONICAL_URL" ]; then
    ORIGIN=custom-release
    cache_key=$(printf '%s' "$BASE_URL" | shasum -a 256 | awk '{print $1}')
    RELEASE_CACHE="$CACHE/kernel-releases/custom/$cache_key/$RELEASE"
fi

mkdir -p "$OUTPUT" "$CACHE"
provenance() { python3 "$ROOT/Scripts/guest_asset_provenance.py" "$@"; }
install_kernel() {
    source=$1
    test -s "$source" || { echo "cengine kernel is missing or empty at $source" >&2; exit 2; }
    # Invalidate before changing bytes, including failed/partial installs.
    rm -f "$OUTPUT/disk-bootstrap.json" "$OUTPUT/SHA256SUMS" "$OUTPUT/kernel-origin.json" "$STAMP"
    install -m 0644 "$source" "$OUTPUT/vmlinux.next"
    mv "$OUTPUT/vmlinux.next" "$OUTPUT/vmlinux"
    printf '%s\n' "$EXPECTED_INPUT" > "$STAMP.next"
    mv "$STAMP.next" "$STAMP"
    provenance record-kernel "$ROOT" "$OUTPUT/vmlinux" "$OUTPUT/kernel-origin.json" "$ORIGIN"
}

if [ -n "$LOCAL_KERNEL" ]; then
    ORIGIN=local
    install_kernel "$LOCAL_KERNEL"
    echo "Installed local cengine kernel from $LOCAL_KERNEL"
    exit 0
fi

# A legacy input stamp is not origin proof. Check bytes, release and origin even
# on the prepared fast path; custom/local output cannot acquire canonical origin.
if [ "$ORIGIN" = canonical-release ] && [ -z "${CENGINE_KERNEL_FORCE:-}" ] && \
    provenance check-kernel "$ROOT" "$OUTPUT/vmlinux" "$OUTPUT/kernel-origin.json" "$ORIGIN" 2>/dev/null; then
    echo "Using prepared cengine kernel at $OUTPUT/vmlinux"
    exit 0
fi

validate_release() {
    directory=$1
    # Closed names and complete coverage, unlike shasum -a 256 -c SHA256SUMS
    # alone (which accepts omissions and arbitrary paths).
    provenance verify-download "$ROOT" "$directory" 2>/dev/null
}

# Legacy and custom caches are never promoted. Only a verified canonical fetch
# creates a canonical receipt; subsequent reuse checks the receipt and bytes.
if ! validate_release "$RELEASE_CACHE" || \
    ! provenance check-kernel "$ROOT" "$RELEASE_CACHE/$ASSET" "$RELEASE_CACHE/kernel-origin.json" "$ORIGIN" 2>/dev/null; then
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
    provenance record-kernel "$ROOT" "$work/$ASSET" "$work/kernel-origin.json" "$ORIGIN"
    replacement="$RELEASE_CACHE.next.$$"
    mv "$work" "$replacement"
    trap - EXIT HUP INT TERM
    rm -rf "$RELEASE_CACHE"
    mv "$replacement" "$RELEASE_CACHE"
fi

install_kernel "$RELEASE_CACHE/$ASSET"
echo "Installed cengine kernel release $RELEASE at $OUTPUT/vmlinux"
