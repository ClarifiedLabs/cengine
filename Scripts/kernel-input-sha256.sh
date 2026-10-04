#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# Materialize inputs before hashing: a missing/rejected series must not yield
# a successful partial digest through a shell pipeline.
inputs=$(mktemp "${TMPDIR:-/tmp}/cengine-kernel-input.XXXXXX")
trap 'rm -f "$inputs"' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

for path in \
    Configuration/kernel-version \
    Configuration/kernel-commit \
    Configuration/kernel-release \
    Configuration/kernel-build-image \
    Configuration/cengine-kernel.fragment \
    Scripts/build-kernel.sh \
    Scripts/apply-kernel-patches.sh \
    Configuration/kernel-patches/series \
    Scripts/build-kernel-linux.sh \
    Scripts/compile-kernel-in-guest.sh
do
    printf '%s\0' "$path"
    cat "$ROOT/$path"
    printf '\0'
done > "$inputs"
while IFS= read -r patch || [ -n "$patch" ]; do
    case "$patch" in
        ''|'#'*) continue ;;
        *[!A-Za-z0-9._-]*|.*) echo "invalid kernel patch name: $patch" >&2; exit 2 ;;
    esac
    printf '%s\0' "Configuration/kernel-patches/$patch"
    cat "$ROOT/Configuration/kernel-patches/$patch"
    printf '\0'
done < "$ROOT/Configuration/kernel-patches/series" >> "$inputs"
shasum -a 256 "$inputs" | awk '{print $1}'
