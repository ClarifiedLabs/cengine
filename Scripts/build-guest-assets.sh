#!/bin/sh
set -eu

# Explicit compile-only profile; no environment fault/default activation switch.
PREPARE_COMPATIBILITY_PROFILE=
case "$#:$*" in
    0:) ;;
    1:--prepare-compatibility=rtm096-normal-a7-v1)
        PREPARE_COMPATIBILITY_PROFILE=rtm096-normal-a7-v1 ;;
    1:--prepare-compatibility=rtm096-early-a1-a3-v2)
        PREPARE_COMPATIBILITY_PROFILE=rtm096-early-a1-a3-v2 ;;
    1:--prepare-compatibility=rtm096-full-nine-v3)
        PREPARE_COMPATIBILITY_PROFILE=rtm096-full-nine-v3 ;;
    *) echo 'usage: build-guest-assets.sh [--prepare-compatibility=rtm096-normal-a7-v1|--prepare-compatibility=rtm096-early-a1-a3-v2|--prepare-compatibility=rtm096-full-nine-v3]' >&2; exit 2 ;;
esac

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CENGINE_STORAGE_LIFECYCLE_QUALIFICATION=$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" selection)
LIFECYCLE_SOURCE_PIN=
if [ -n "$PREPARE_COMPATIBILITY_PROFILE" ] && [ -n "${CENGINE_COMPAT_LIFECYCLE_FAULT:-}" ]; then
    echo 'PREPARE cannot combine lifecycle runtime faults' >&2; exit 2
fi
OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/guest"}
if [ -n "$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION" ]; then
    [ -z "$PREPARE_COMPATIBILITY_PROFILE" ] || { echo 'lifecycle qualification cannot combine PREPARE selections' >&2; exit 2; }
    python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" signed-managed
    OUTPUT=${CENGINE_GUEST_OUTPUT:-"$ROOT/.build/$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION/guest"}
    python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" validate-output "$ROOT" "$OUTPUT"
    LIFECYCLE_SOURCE_PIN=$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" source-pin "$ROOT")
fi
CONTAINER_ROOT="$OUTPUT/container-root"
STORAGE_ROOT="$OUTPUT/storage-root"
MKE2FS="$OUTPUT/mke2fs"
BINARY_OUTPUT="$OUTPUT/guest-bin"
PREPARE_COMPATIBILITY_SOURCE_SHA256=
ORDINARY_SOURCE_SHA256=
ORDINARY_PROVENANCE_FILE=
set --
if [ -n "$PREPARE_COMPATIBILITY_PROFILE" ]; then
    python3 "$ROOT/Scripts/prepare_compatibility_assets.py" validate-output "$ROOT" "$OUTPUT"
    PREPARE_COMPATIBILITY_SOURCE_SHA256=$(python3 "$ROOT/Scripts/prepare_compatibility_assets.py" source-pin "$ROOT")
    case "$PREPARE_COMPATIBILITY_PROFILE" in
        rtm096-normal-a7-v1) set -- -tags=cengine_prepare_compat ;;
        rtm096-early-a1-a3-v2) set -- -tags=cengine_prepare_early_compat ;;
        rtm096-full-nine-v3) set -- -tags=cengine_prepare_full_compat ;;
        *) exit 2 ;; # Closed above; never infer a profile from the environment.
    esac
else
    ORDINARY_SOURCE_SHA256=$(python3 "$ROOT/Scripts/prepare_compatibility_assets.py" source-pin "$ROOT")
    if [ -n "$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION" ]; then ORDINARY_SOURCE_SHA256=; fi
fi

# A failed rebuild must never leave a completed metadata/manifest claim.
rm -f "$OUTPUT/disk-bootstrap.json" "$OUTPUT/SHA256SUMS"
rm -rf "$CONTAINER_ROOT" "$STORAGE_ROOT" "$BINARY_OUTPUT"
mkdir -p "$OUTPUT" \
    "$CONTAINER_ROOT/bin" "$CONTAINER_ROOT/sbin" "$CONTAINER_ROOT/etc" "$CONTAINER_ROOT/dev" "$CONTAINER_ROOT/proc" "$CONTAINER_ROOT/sys" "$CONTAINER_ROOT/run" "$CONTAINER_ROOT/rootfs" \
    "$STORAGE_ROOT/bin" "$STORAGE_ROOT/sbin" "$STORAGE_ROOT/etc" "$STORAGE_ROOT/dev" "$STORAGE_ROOT/proc" "$STORAGE_ROOT/sys" "$STORAGE_ROOT/run" "$STORAGE_ROOT/data"

if [ ! -f "$OUTPUT/vmlinux" ]; then
    echo "cengine kernel is missing at $OUTPUT/vmlinux; run make kernel" >&2
    exit 2
fi

if [ ! -x "$MKE2FS" ]; then
    "$ROOT/Scripts/build-e2fsprogs.sh" "$MKE2FS"
fi

GO=$(sh "$ROOT/Scripts/ensure-go-toolchain.sh")
# Provisioning/trust of Go and its standard library remains the existing
# ensure-go-toolchain.sh scope, not a claim that the Guest source pin hashes it.
# Every guest build, ordinary or profiled, uses this same closed, offline
# compilation environment: no ambient GOENV/GOFLAGS/-tags, no workspace, no
# network or toolchain downloads. The fresh private cache keeps external
# caches from silently becoming unpinned Guest build inputs.
GUEST_GO_CACHE=$(mktemp -d "${TMPDIR:-/tmp}/cengine-guest-go.XXXXXX")
trap 'rm -rf "$GUEST_GO_CACHE"' EXIT HUP INT TERM
guest_go() {
    case "$1" in
        build|list) go_command=$1; shift; set -- "$go_command" -mod=vendor "$@" ;;
    esac
    env -i PATH="$PATH" HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" \
        GOCACHE="$GUEST_GO_CACHE/build" GOMODCACHE="$GUEST_GO_CACHE/mod" \
        GOENV=off GOFLAGS= GOWORK=off GO111MODULE=on GOTOOLCHAIN=local \
        GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0 \
        "$GO" "$@"
}
# Production lifecycle sessions are untagged (storageboot/lifecycle_session.go);
# full-nine adds only PREPARE instrumentation, never qualification privileges.
# Listing and compilation use this same finite choice, never ambient build tags.
storage_go() {
    if [ -n "${CENGINE_STORAGE_LIFECYCLE_QUALIFICATION:-}" ]; then
        storage_command=$1; shift
        guest_go "$storage_command" -tags=cengine_lifecycle_v2_qualification "$@"
    elif [ "$PREPARE_COMPATIBILITY_PROFILE" = rtm096-full-nine-v3 ]; then
        storage_command=$1; shift
        guest_go "$storage_command" -tags=cengine_prepare_full_compat "$@"
    else
        guest_go "$@"
    fi
}
mkdir -p "$BINARY_OUTPUT/out"
(
    cd "$ROOT/Guest"
    guest_go list -deps -json "$@" ./cmd/cengine-init > "$BINARY_OUTPUT/init-inputs.json"
    storage_go list -deps -json ./cmd/cengine-storage > "$BINARY_OUTPUT/storage-inputs.json"
    python3 "$ROOT/Scripts/prepare_compatibility_assets.py" audit-inputs "$ROOT" "$(guest_go env GOROOT)" \
        "$BINARY_OUTPUT/init-inputs.json" "$BINARY_OUTPUT/storage-inputs.json"
    python3 "$ROOT/Scripts/guest_asset_provenance.py" audit-selected "$ORDINARY_SOURCE_SHA256" \
        "$BINARY_OUTPUT/init-inputs.json" "$BINARY_OUTPUT/storage-inputs.json"
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 guest_go build "$@" -trimpath -buildvcs=false \
        -ldflags='-s -w -buildid=' -o "$BINARY_OUTPUT/out/cengine-init" ./cmd/cengine-init
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 storage_go build -trimpath -buildvcs=false \
        -ldflags='-s -w -buildid=' -o "$BINARY_OUTPUT/out/cengine-storage" ./cmd/cengine-storage
)
install -m 0755 "$BINARY_OUTPUT/out/cengine-init" "$CONTAINER_ROOT/init"
install -m 0755 "$BINARY_OUTPUT/out/cengine-storage" "$STORAGE_ROOT/init"

install -m 0755 "$MKE2FS" "$CONTAINER_ROOT/sbin/mke2fs"
install -m 0755 "$MKE2FS" "$STORAGE_ROOT/sbin/mke2fs"
install -m 0644 "$ROOT/Configuration/mke2fs.conf" "$CONTAINER_ROOT/etc/mke2fs.conf"
install -m 0644 "$ROOT/Configuration/mke2fs.conf" "$STORAGE_ROOT/etc/mke2fs.conf"

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0} python3 "$ROOT/Scripts/make-initramfs.py" "$CONTAINER_ROOT" "$OUTPUT/container-initramfs.cpio.gz"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0} python3 "$ROOT/Scripts/make-initramfs.py" "$STORAGE_ROOT" "$OUTPUT/storage-initramfs.cpio.gz"
if [ -n "$PREPARE_COMPATIBILITY_PROFILE" ]; then
    test "$PREPARE_COMPATIBILITY_SOURCE_SHA256" = "$(python3 "$ROOT/Scripts/prepare_compatibility_assets.py" source-pin "$ROOT")"
elif [ -n "$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION" ]; then
    test "$LIFECYCLE_SOURCE_PIN" = "$(python3 "$ROOT/Scripts/storage_lifecycle_qualification.py" source-pin "$ROOT")"
else
    ORDINARY_PROVENANCE_FILE="$BINARY_OUTPUT/ordinary-provenance.json"
    python3 "$ROOT/Scripts/guest_asset_provenance.py" create "$ROOT" "$OUTPUT" "$GO" \
        "$ORDINARY_SOURCE_SHA256" "$ORDINARY_PROVENANCE_FILE"
fi
python3 - "$OUTPUT" "${PREPARE_COMPATIBILITY_PROFILE:-}" "${PREPARE_COMPATIBILITY_SOURCE_SHA256:-}" "${ORDINARY_PROVENANCE_FILE:-}" "${CENGINE_STORAGE_LIFECYCLE_QUALIFICATION:-}" "${LIFECYCLE_SOURCE_PIN:-}" <<'PY'
import hashlib
import json
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
metadata = {
    "schemaVersion": 1,
    "protocolVersion": 1,
    "storageServiceBootVersion": 2,
    "storageLifecycleVersion": 2,
    "workloadStorageBootVersion": 1,
    "containerInitramfsSHA256": hashlib.sha256((output / "container-initramfs.cpio.gz").read_bytes()).hexdigest(),
    "storageInitramfsSHA256": hashlib.sha256((output / "storage-initramfs.cpio.gz").read_bytes()).hexdigest(),
}
if sys.argv[2]:
    metadata["prepareCompatibilityProfile"] = sys.argv[2]
    metadata["prepareCompatibilitySourceSHA256"] = sys.argv[3]
if sys.argv[5]:
    metadata["storageLifecycleQualification"] = sys.argv[5]
    metadata["storageLifecycleSourcePin"] = sys.argv[6]
if sys.argv[4]:
    metadata["ordinaryProvenance"] = json.loads(pathlib.Path(sys.argv[4]).read_text())
(output / "disk-bootstrap.json.next").write_text(json.dumps(metadata, indent=2) + "\n")
(output / "disk-bootstrap.json.next").replace(output / "disk-bootstrap.json")
PY
(
    cd "$OUTPUT"
    shasum -a 256 vmlinux container-initramfs.cpio.gz storage-initramfs.cpio.gz disk-bootstrap.json > SHA256SUMS.next
    mv SHA256SUMS.next SHA256SUMS
)
