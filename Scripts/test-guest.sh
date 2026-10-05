#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if command -v go >/dev/null 2>&1 && [ "$(go env GOOS)" = linux ]; then
    if [ "$(id -u)" != 0 ] || [ "$(id -g)" != 0 ]; then
        echo "native guest tests require Linux root uid/gid" >&2
        exit 2
    fi
    if [ "$(findmnt -n -o FSTYPE -T "${TMPDIR:-/tmp}")" != ext4 ]; then
        echo "native guest tests require TMPDIR on ext4" >&2
        exit 2
    fi
    cd "$ROOT/Guest"
    # Managed session fixtures use a custom ioctl unavailable on stock kernels.
    # The release workflow runs these packages' ordinary units unprivileged.
    packages=$(go list ./...)
    set --
    for package in $packages; do
        case "$package" in
            dev.cengine/guest/internal/storagemanaged|dev.cengine/guest/internal/storageserver) ;;
            *) set -- "$@" "$package" ;;
        esac
    done
    # Hosted Linux runs component tests on the host kernel. These two families
    # require the patched cengine FUSE ABI and run in the disposable VM below.
    echo "host kernel: excluding patched-FUSE mounted and DATA TLS fixtures" >&2
    # Attachment composition exercises real preflight, which rejects shared
    # mount propagation. Isolate the tests without changing the host's mounts.
    exec unshare --mount --propagation private setsid --wait go test -skip '^TestNative(MountedManagedV3|IssuedDataTLS)' "$@" -p=1 -count=1 -timeout=20m -json
fi

IMAGE=${CENGINE_GUEST_TEST_IMAGE:-golang:1.25-trixie}

FIXTURES="$ROOT/.build/guest-test-fixtures"
mkdir -p "$FIXTURES"

"$ROOT/Scripts/run-isolated-cengine.sh" sh -eu -c '
    docker pull "$1"
    docker run --rm \
        --mount "type=bind,src=$2/Guest,dst=/src/Guest,readonly" \
        --mount "type=bind,src=$2/Tests,dst=/src/Tests,readonly" \
        --mount "type=bind,src=$3,dst=/guest-fixtures,readonly" \
        --workdir /src/Guest \
        --mount type=volume,destination=/scratch,volume-nocopy=true \
        --env TMPDIR=/scratch \
        --privileged \
        "$1" sh -ec '\''
            [ -e /dev/fuse ] || mknod /dev/fuse c 10 229
            printf "1\n" > /proc/sys/fs/protected_hardlinks
            printf "Y\n" > /sys/module/fuse/parameters/enable_uring
            if ! grep -qs " /sys/fs/fuse/connections fusectl " /proc/self/mountinfo; then
                mount -t fusectl fusectl /sys/fs/fuse/connections
            fi
            if [ -f /guest-fixtures/fsx ]; then
                actual="$(sha256sum /guest-fixtures/fsx | awk "{print \$1}")"
                test "$actual" = d4293e6536e184abd383c258104765bbdec783faa7025cde93c797c97067a632
                touch /fsx
                chmod 0555 /fsx
                mount -o ro,bind /guest-fixtures/fsx /fsx
            else
                echo "pinned fsx fixture absent; skipping TestNativeMountedManagedV3FsxGraceful" >&2
            fi
            # The cengine container runtime may leak non-CLOEXEC fds 3/4 into
            # the workload; POSIX sh reliably supports single-digit redirects.
            exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
            # Keep the test binary out of the PID 1 process group: native sparse
            # fixtures require a nonzero pgrp, and storageworker rejects inherited fds.
            if [ -f /guest-fixtures/fsx ]; then
                # Journal crash-image matrices perform thousands of real fsyncs.
                # Bound each package explicitly; serialize packages sharing scratch.
                setsid go test ./... -p=1 -count=1 -timeout=20m -json
            else
                setsid go test -skip '^TestNativeMountedManagedV3FsxGraceful$' ./... -p=1 -count=1 -timeout=20m -json
            fi
        '\''
' cengine-guest-tests "$IMAGE" "$ROOT" "$FIXTURES"
