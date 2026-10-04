#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=Scripts/compat-network-helper.sh
. "$ROOT/Scripts/compat-network-helper.sh"
if [ "${CENGINE_COMPAT_SHARED_STORAGE+x}${CENGINE_COMPAT_MANAGED_STORAGE+x}" != '' ]; then
    echo 'retired compatibility storage selector; lifecycle is the default' >&2
    exit 2
fi
BINARY=${CENGINE_BINARY:-"$ROOT/.build/xcode-derived/Build/Products/test-compat/cengine"}
KERNEL=${CENGINE_KERNEL:-"$ROOT/.build/guest/vmlinux"}
CONTAINER_INITRAMFS=${CENGINE_CONTAINER_INITRAMFS:-"$ROOT/.build/guest/container-initramfs.cpio.gz"}
STORAGE_INITRAMFS=${CENGINE_STORAGE_INITRAMFS:-"$ROOT/.build/guest/storage-initramfs.cpio.gz"}
IMAGE_CACHE=${CENGINE_ISOLATED_IMAGE_CACHE:-"$ROOT/.build/isolated-image-cache-v1"}
# Match run-compat-tests before creating any private temporary state.
LOCK=$(python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py")
CENGINE_COMPAT_LOCK=$LOCK
export CENGINE_COMPAT_LOCK

if [ "$#" -eq 0 ]; then
    echo "usage: $0 COMMAND [ARG ...]" >&2
    exit 2
fi
for asset in "$BINARY" "$KERNEL" "$CONTAINER_INITRAMFS" "$STORAGE_INITRAMFS"; do
    if [ ! -f "$asset" ]; then
        echo "required isolated runtime asset is missing: $asset" >&2
        exit 2
    fi
done
BINARY=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$BINARY")
umask 077
WORK=''

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" verify-claim "$$" || exit 1
    if [ -n "$WORK" ]; then
        cleanup_status=0
        python3 - "$ROOT" "$BINARY" "$WORK" "$IMAGE_CACHE" "$status" "$LOCK" "$$" <<'PY' || cleanup_status=$?
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

repo, binary, work, cache = map(pathlib.Path, sys.argv[1:5])
status = int(sys.argv[5])
staging = None
try:
    sys.path.insert(0, str(repo / "Tests" / "Compatibility"))
    from harness import (
        CompatibilityRootRetention, compatibility_runtime_processes,
        release_compatibility_root, remove_compatibility_root,
        retain_compatibility_root, terminate_compatibility_runtime,
    )

    engine_root = work / "root"
    terminate_compatibility_runtime(binary, roots=(engine_root,))
    if compatibility_runtime_processes(binary, roots=(engine_root,)):
        raise RuntimeError("isolated runtime still present")
    if status:
        raise RuntimeError("isolated command failed")
    lock = pathlib.Path(sys.argv[6])
    if lock.is_symlink() or (lock / "pid").read_text() != sys.argv[7] + "\n":
        raise RuntimeError("isolated lock ownership changed")

    # Never expose a partial clone, or read a cache source still owned by a VM.
    if (engine_root / "content").is_dir():
        cache.mkdir(parents=True, exist_ok=True)
        staging = pathlib.Path(tempfile.mkdtemp(prefix=".content-", dir=cache))
        subprocess.run(
            ["/bin/cp", "-cR", str(engine_root / "content"), str(staging / "content")],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        previous = staging / "previous"
        if (cache / "content").exists():
            (cache / "content").rename(previous)
        try:
            (staging / "content").rename(cache / "content")
        except Exception:
            if previous.exists():
                previous.rename(cache / "content")
            raise
        shutil.rmtree(staging)
        staging = None

    root_identity, marker_identity, contents = json.loads((work / ".retention-receipt").read_text())
    receipt = CompatibilityRootRetention(tuple(root_identity), tuple(marker_identity), contents.encode())
    if not release_compatibility_root(work, binary, receipt):
        raise RuntimeError("isolated retention changed")
    if not remove_compatibility_root(work, binary):
        raise RuntimeError("isolated root retained")
except Exception:
    # Do not print exception text, process argv, or daemon logs (they may contain secrets).
    # Pre-retention also protects evidence if imports or the cleanup census fail.
    try:
        retain_compatibility_root(work, binary, reason="cleanup-incomplete")
    except Exception:
        pass
    if staging is not None:
        print(f"isolated cache staging retained: {staging}", file=sys.stderr)
    sys.exit(1)
PY
        if [ "$cleanup_status" -ne 0 ]; then
            echo "isolated cengine evidence retained: $WORK" >&2
            if [ "$status" -eq 0 ]; then status=$cleanup_status; fi
        fi
    fi
    python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" release-claim "$$" || {
        echo "could not release isolated compatibility lock: $LOCK" >&2
        if [ "$status" -eq 0 ]; then status=1; fi
    }
    exit "$status"
}

# An absent/dead/unreadable PID is not authority to steal a lock.
if ! mkdir "$LOCK" 2>/dev/null; then
    echo "compatibility lock already exists or is unavailable: $LOCK" >&2
    exit 2
fi
printf '%s\n' "$$" > "$LOCK/pid"
CENGINE_COMPAT_OWNER_PID=$$
export CENGINE_COMPAT_OWNER_PID
CENGINE_COMPAT_CLAIM=$(python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" pin-claim "$$")
export CENGINE_COMPAT_CLAIM
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

WORK=$(mktemp -d "${TMPDIR:-/tmp}/cengine-compat-tool.XXXXXX")
ENGINE_ROOT="$WORK/root"
SOCKET="$WORK/docker.sock"
LOG="$WORK/daemon.log"
mkdir -p "$ENGINE_ROOT"
printf '%s\n' "$BINARY" > "$WORK/.cengine-compat-owner"
# Publish retention before signing, cloning, or launching; only a successful,
# verified cleanup may release this exact marker through the harness receipt.
python3 - "$ROOT" "$BINARY" "$WORK" <<'PY'
import json
import pathlib
import sys

repo, binary, work = map(pathlib.Path, sys.argv[1:])
sys.path.insert(0, str(repo / "Tests" / "Compatibility"))
from harness import preretain_compatibility_root

receipt = preretain_compatibility_root(work, binary)
(work / ".retention-receipt").write_text(json.dumps([
    receipt.root_identity, receipt.marker_identity, receipt.contents.decode(),
]))
PY

HELPER_FINGERPRINT=$("$ROOT/Scripts/network-helper-fingerprint.sh")
if [ -n "${CENGINE_DEVELOPER_ID_APPLICATION:-}" ]; then
    "$ROOT/Scripts/sign-compat-binary.sh" --sign "$CENGINE_DEVELOPER_ID_APPLICATION" "$BINARY"
else
    "$ROOT/Scripts/sign-compat-binary.sh" "$BINARY"
fi
compat_network_helper_require "$BINARY" "$HELPER_FINGERPRINT"

CENGINE_COMPAT_IPV4_AUTO_POOL=${CENGINE_COMPAT_IPV4_AUTO_POOL:-10.192.0.0/12}
CENGINE_COMPAT_IPV6_AUTO_PREFIX=${CENGINE_COMPAT_IPV6_AUTO_PREFIX:-fdcc::/16}
export CENGINE_COMPAT_IPV4_AUTO_POOL CENGINE_COMPAT_IPV6_AUTO_PREFIX

if [ -d "$IMAGE_CACHE/content" ]; then
    /bin/cp -cR "$IMAGE_CACHE/content" "$ENGINE_ROOT/content" >"$WORK/cache-import.log" 2>&1
fi

"$BINARY" daemon \
    --socket "$SOCKET" \
    --root "$ENGINE_ROOT" \
    --kernel "$KERNEL" \
    --container-initramfs "$CONTAINER_INITRAMFS" \
    --storage-initramfs "$STORAGE_INITRAMFS" \
    --automatic-ipv4-pool "$CENGINE_COMPAT_IPV4_AUTO_POOL" \
    --automatic-ipv6-prefix "$CENGINE_COMPAT_IPV6_AUTO_PREFIX" >"$LOG" 2>&1 &
daemon_pid=$!

attempt=0
while [ ! -S "$SOCKET" ]; do
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
        wait "$daemon_pid" || true
        echo "isolated cengine daemon exited before creating $SOCKET" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 600 ]; then
        echo "timed out waiting for isolated cengine daemon at $SOCKET" >&2
        exit 1
    fi
    sleep 0.1
done

unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY
export DOCKER_HOST="unix://$SOCKET"
docker version --format '{{.Server.Version}}' >/dev/null

"$@"
