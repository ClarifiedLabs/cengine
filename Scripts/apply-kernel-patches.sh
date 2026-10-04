#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE=${1:?usage: apply-kernel-patches.sh disposable-kernel-source}
PATCHES="$ROOT/Configuration/kernel-patches"
# Prevent Git discovering the enclosing cengine repository and silently skipping
# kernel-relative patch paths when the disposable tree lives under .build/.
SOURCE=$(CDPATH= cd -- "$SOURCE" && pwd)
export GIT_CEILING_DIRECTORIES=${SOURCE%/*}
test "$(cat "$SOURCE/.cengine-disposable-kernel" 2>/dev/null || true)" = cengine-kernel-build-v1 || {
    echo "refusing to patch a source tree not exported by build-kernel.sh" >&2
    exit 2
}
test -f "$SOURCE/Makefile" || { echo "kernel source Makefile is missing" >&2; exit 2; }
# Deliberately accept only basenames; no shell expansion, path traversal or fuzz.
while IFS= read -r patch || [ -n "$patch" ]; do
    case "$patch" in
        ''|'#'*) continue ;;
        *[!A-Za-z0-9._-]*|.*) echo "invalid kernel patch name: $patch" >&2; exit 2 ;;
    esac
    test -f "$PATCHES/$patch" || { echo "missing kernel patch: $patch" >&2; exit 2; }
    # Exported source deliberately has no .git directory. Force no-index mode
    # so Git cannot discover an enclosing project and silently target that tree.
    git -C "$SOURCE" apply --no-index --check --whitespace=error-all "$PATCHES/$patch"
    git -C "$SOURCE" apply --no-index --whitespace=error-all "$PATCHES/$patch"
done < "$PATCHES/series"
