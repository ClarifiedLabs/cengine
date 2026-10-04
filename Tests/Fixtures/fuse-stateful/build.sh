#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Compile only. Never boots a VM, mounts a filesystem, or runs the probe.
set -eu
if [ "$#" -ne 2 ]; then
    echo "usage: sh build.sh PATCHED_UAPI_INCLUDE OUTPUT_BINARY" >&2
    exit 2
fi
uapi=$1
output=$2
source=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/probe.c
if [ ! -f "$uapi/linux/fuse.h" ]; then
    echo "required: patched experimental-0002 linux/fuse.h in supplied UAPI directory" >&2
    exit 2
fi
if [ -n "${ZIG_TARGET:-}" ]; then
    exec "${ZIG:-zig}" cc -target "$ZIG_TARGET" -std=gnu11 -Wall -Wextra -Werror \
        -O2 -I"$uapi" "$source" -o "$output"
fi
exec "${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -O2 -I"$uapi" "$source" -o "$output"
