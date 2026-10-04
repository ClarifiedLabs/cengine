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
EXPECTED_INPUT=$("$ROOT/Scripts/kernel-input-sha256.sh")
# Never reset, clean, patch or remove a developer's cached/source checkout.
# Export only the pinned committed tree into a disposable build directory.
work=$(mktemp -d "$CACHE/kernel-build.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
if git -C "$SOURCE" cat-file -e "$COMMIT^{commit}" 2>/dev/null; then
    repository=$SOURCE
else
    repository="$work/repository"
    git init -q "$repository"
    git -C "$repository" remote add origin https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
    git -C "$repository" fetch -q --depth 1 origin "$COMMIT"
fi
test "$(git -C "$repository" rev-parse "$COMMIT^{commit}")" = "$COMMIT" || {
    echo "kernel source is not pinned Linux $VERSION commit $COMMIT" >&2
    exit 2
}
git -C "$repository" archive --format=tar "$COMMIT" > "$work/source.tar"
mkdir "$work/source"
tar -xf "$work/source.tar" -C "$work/source"
rm "$work/source.tar"
printf '%s\n' cengine-kernel-build-v1 > "$work/source/.cengine-disposable-kernel"
"$ROOT/Scripts/apply-kernel-patches.sh" "$work/source"
rm "$work/source/.cengine-disposable-kernel"

case "$HOST_OS" in
    Linux|Darwin)
        KERNEL_SOURCE="$work/source" \
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

test "$("$ROOT/Scripts/kernel-input-sha256.sh")" = "$EXPECTED_INPUT" || {
    echo "kernel inputs changed during build; refusing to stamp output" >&2
    exit 2
}
printf '%s\n' "$EXPECTED_INPUT" > "$OUTPUT/kernel-input.sha256.next"
mv "$OUTPUT/kernel-input.sha256.next" "$OUTPUT/kernel-input.sha256"
echo "Built pinned Linux $VERSION ($COMMIT) at $OUTPUT/vmlinux"
