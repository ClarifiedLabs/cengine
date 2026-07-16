#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

for path in \
    Configuration/kernel-version \
    Configuration/kernel-commit \
    Configuration/kernel-release \
    Configuration/kernel-build-image \
    Configuration/cengine-kernel.fragment \
    Scripts/build-kernel-linux.sh \
    Scripts/compile-kernel-in-guest.sh
do
    printf '%s\0' "$path"
    cat "$ROOT/$path"
    printf '\0'
done | shasum -a 256 | awk '{print $1}'
