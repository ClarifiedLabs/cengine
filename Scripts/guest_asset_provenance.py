#!/usr/bin/env python3
"""Inactive ordinary-build receipts and release-only validation; never execute guests.

Receipts describe trusted local build/fetch operations, not signatures against a
malicious checkout owner. Ordinary assets require the universal lifecycle contract.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import zlib

from prepare_compatibility_assets import source_pin, MAX_AUDIT_BYTES

POLICY = "closed-ordinary-go-v1"
MODULE = "dev.cengine/guest"
MAX_COMPRESSED = 64 << 20
MAX_ARCHIVE = 256 << 20
MAX_BINARY = 64 << 20
MAX_KERNEL = 128 << 20
RECEIPT = "kernel-origin.json"
ASSETS = ("vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz", "disk-bootstrap.json")
REQUIRED_SETTINGS = {"-buildmode": "exe", "-compiler": "gc", "-trimpath": "true",
                     "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOARM64": "v8.0"}
INERT = {
    "internal/preparecompat": {"profile_inert.go", "early_profile_inert.go", "full_profile_inert.go"},
    "internal/storageauthority": {"prepare_compatibility_inert.go", "isolation_digest_inert.go"},
    "internal/storageserver": {"tls_failure_inert.go"},
    "internal/storagecontrol": {"lifecycle_public_replay_inert.go"},
    "internal/supervisor": {"copyup_checkpoint_linux.go"},
}

# The ordinary command must close over the universal lifecycle implementation,
# not merely carry an inert PREPARE label. All entries are selected GoFiles.
LIFECYCLE = {
    "cmd/cengine-storage": {"main.go", "shutdown.go"},
    "internal/storageboot": {"lifecycle_run_linux.go", "lifecycle_session.go", "lifecycle_worker_linux.go"},
    "internal/storageservice": {"lifecycle.go", "lifecycle_prepare_compatibility.go"},
}


def read_bytes(path: Path, bound: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= bound:
            raise ValueError(f"nonregular, empty or oversized asset: {path}")
        data = stream.read(bound + 1)
        after = os.fstat(stream.fileno())
    if len(data) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError(f"asset changed while reading: {path}")
    return data


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(data):
    return json.loads(data, object_pairs_hook=unique_object)


def exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError("unexpected provenance fields")
    for key, kind in fields.items():
        if type(value[key]) is not kind:
            raise ValueError(f"invalid provenance type: {key}")


def sha(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("invalid SHA256")
    return value


def atomic_json(path: Path, value) -> None:
    fd, name = tempfile.mkstemp(prefix=".provenance-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def kernel_config(root: Path) -> tuple[str, str]:
    release = (root / "Configuration/kernel-release").read_text().strip()
    if re.fullmatch(r"[A-Za-z0-9._-]+", release) is None:
        raise ValueError("invalid kernel release")
    inputs = subprocess.check_output([str(root / "Scripts/kernel-input-sha256.sh")], text=True).strip()
    return release, sha(inputs)


def kernel_receipt(root: Path, binary: Path, origin: str) -> dict:
    if origin not in ("canonical-release", "custom-release", "local", "unverified"):
        raise ValueError("invalid kernel origin")
    release, inputs = kernel_config(root)
    return {"schemaVersion": 1, "origin": origin, "sha256": digest(read_bytes(binary, MAX_KERNEL)),
            "release": release, "inputSHA256": inputs}


def check_kernel(root: Path, binary: Path, receipt: Path, origin: str | None = None) -> dict:
    value = load_json(read_bytes(receipt, 4096))
    exact(value, {"schemaVersion": int, "origin": str, "sha256": str, "release": str, "inputSHA256": str})
    expected = kernel_receipt(root, binary, origin or value["origin"])
    if value != expected:
        raise ValueError("kernel origin/hash/configuration mismatch")
    return value


def inspect_archive(compressed: bytes) -> dict[str, bytes]:
    if len(compressed) > MAX_COMPRESSED:
        raise ValueError("compressed archive bound")
    decoder = zlib.decompressobj(31)
    data = decoder.decompress(compressed, MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("oversized, truncated or multiple gzip archives")
    offset, names, inodes, result = 0, set(), set(), {}
    for _ in range(8192):
        header = data[offset:offset + 110]
        if len(header) != 110 or header[:6] != b"070701" or re.fullmatch(b"[0-9a-fA-F]{104}", header[6:]) is None:
            raise ValueError("malformed/truncated newc header")
        fields = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
        inode, mode, _, _, nlink, _, size, major, minor, _, _, namesize, check = fields
        if not 1 < namesize <= 4096 or check != 0:
            raise ValueError("invalid newc name/check")
        start = offset + 110
        end = start + namesize
        raw_name = data[start:end]
        if len(raw_name) != namesize or raw_name[-1:] != b"\0" or b"\0" in raw_name[:-1]:
            raise ValueError("malformed/truncated newc name")
        name = raw_name[:-1].decode("utf-8")
        payload_start = (end + 3) & ~3
        payload_end = payload_start + size
        offset = (payload_end + 3) & ~3
        if offset > len(data) or any(data[end:payload_start]) or any(data[payload_end:offset]):
            raise ValueError("truncated newc payload/padding")
        if name == "TRAILER!!!":
            if size or len(data) - offset > 511 or any(data[offset:]):
                raise ValueError("multiple archives or invalid trailer")
            if set(result) != {"init", "sbin/mke2fs"}:
                raise ValueError("missing init/mke2fs")
            return result
        if name != "." and (name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/"))):
            raise ValueError("aliased archive path")
        if name in names:
            raise ValueError("duplicate archive path")
        names.add(name)
        if stat.S_ISDIR(mode):
            if size:
                raise ValueError("directory payload")
        elif stat.S_ISREG(mode):
            identity = (major, minor, inode)
            if nlink != 1 or identity in inodes:
                raise ValueError("hardlinked archive entry")
            inodes.add(identity)
        else:
            raise ValueError("symlink or special archive entry")
        if name in ("init", "sbin/mke2fs"):
            if not stat.S_ISREG(mode) or not mode & 0o111 or not 0 < size <= MAX_BINARY:
                raise ValueError("invalid init/mke2fs file")
            result[name] = data[payload_start:payload_end]
    raise ValueError("archive entry bound/missing trailer")


def closed_environment(cache: Path) -> dict[str, str]:
    # Go 1.26's GOTELEMETRY is read-only, not an environment override. Seed
    # its mode before invoking Go so no telemetry child can race HOME cleanup.
    # XDG_CONFIG_HOME and telemetry test overrides are excluded below.
    config = cache / ("Library/Application Support" if sys.platform == "darwin" else ".config")
    telemetry = config / "go/telemetry"
    telemetry.mkdir(parents=True, exist_ok=True)
    (telemetry / "mode").write_text("off\n")
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(cache), "TMPDIR": str(cache),
            "GOCACHE": str(cache / "build"), "GOMODCACHE": str(cache / "mod"),
            "GOENV": "off", "GOFLAGS": "", "GOWORK": "off", "GO111MODULE": "on", "GOTOOLCHAIN": "local",
            "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOARM64": "v8.0"}


def validate_buildinfo(info: dict, command: str) -> str:
    if type(info) is not dict or info.get("Path") != f"{MODULE}/cmd/{command}" or info.get("Main") != {"Path": MODULE, "Version": "(devel)"}:
        raise ValueError("unexpected guest command/module")
    version = info.get("GoVersion")
    if type(version) is not str or re.fullmatch(r"go1\.[0-9]+\.[0-9]+", version) is None:
        raise ValueError("missing/invalid actual GoVersion")
    settings = {}
    if type(info.get("Settings")) is not list:
        raise ValueError("missing Go build settings")
    for item in info["Settings"]:
        exact(item, {"Key": str, "Value": str})
        key, value = item["Key"], item["Value"]
        if key in settings or key not in {*REQUIRED_SETTINGS, "DefaultGODEBUG"}:
            raise ValueError("tagged/instrumented/unknown Go build setting")
        settings[key] = value
    if any(settings.get(key) != value for key, value in REQUIRED_SETTINGS.items()):
        raise ValueError("nonordinary Go build settings")
    return version


def binary_info(go: Path, payload: bytes, command: str) -> dict:
    # Only our own private filename is passed to trusted host Go, never an archive
    # pathname; version -m parses buildinfo and does not execute the guest ELF.
    with tempfile.TemporaryDirectory(prefix="cengine-buildinfo-") as temporary:
        private = Path(temporary)
        binary = private / "guest"
        binary.write_bytes(payload)
        result = subprocess.run([str(go), "version", "-m", "-json", str(binary)],
                                env=closed_environment(private), capture_output=True, timeout=30, check=True)
        if len(result.stdout) > 1 << 20:
            raise ValueError("Go buildinfo bound")
        version = validate_buildinfo(load_json(result.stdout), command)
    return {"sha256": digest(payload), "goVersion": version}


def audit_selected(documents: list[str]) -> None:
    seen = set()
    decoder = json.JSONDecoder()
    if sum(len(document.encode()) for document in documents) > MAX_AUDIT_BYTES:
        raise ValueError("selected Go input audit bound")
    for document in documents:
        offset = 0
        while offset < len(document):
            if document[offset].isspace():
                offset += 1
                continue
            package, offset = decoder.raw_decode(document, offset)
            path = package.get("ImportPath", "")
            files = set(package.get("GoFiles", []))  # Not IgnoredGoFiles/TestGoFiles.
            if path.startswith(MODULE + "/"):
                relative = path[len(MODULE) + 1:]
                required = INERT.get(relative, set()) | LIFECYCLE.get(relative, set())
                if required:
                    if not required <= files:
                        raise ValueError(f"ordinary lifecycle/inert selection missing: {relative}")
                    seen.add(relative)
                if relative in INERT and any("enabled" in name or "native_" in name or name == "isolation_digest.go" or "compatibility_host_test" in name for name in files):
                    raise ValueError(f"fault-enabled selected Go input: {relative}")
    if seen != set(INERT) | set(LIFECYCLE):
        raise ValueError("ordinary audit missing required packages")


def provenance(root: Path, output: Path, go: Path, pin: str) -> dict:
    if sha(pin) != source_pin(root):
        raise ValueError("ordinary source changed during build")
    try:
        kernel = check_kernel(root, output / "vmlinux", output / RECEIPT)
    except (OSError, ValueError):
        kernel = kernel_receipt(root, output / "vmlinux", "unverified")
    binaries = {}
    mke2fs = None
    for kind, command in (("container", "cengine-init"), ("storage", "cengine-storage")):
        extracted = inspect_archive(read_bytes(output / f"{kind}-initramfs.cpio.gz", MAX_COMPRESSED))
        binaries[kind] = binary_info(go, extracted["init"], command)
        current = digest(extracted["sbin/mke2fs"])
        if mke2fs is not None and mke2fs != current:
            raise ValueError("mke2fs differs between images")
        mke2fs = current
    if source_pin(root) != pin:
        raise ValueError("ordinary source changed while inspecting")
    return {"schemaVersion": 1, "policy": POLICY, "sourceSHA256": pin, "kernel": kernel,
            "containerBinary": binaries["container"], "storageBinary": binaries["storage"], "mke2fsSHA256": mke2fs}


def assert_current_source(root: Path, metadata: dict) -> None:
    """Check an ordinary build's recorded source; never create or repair receipts."""
    if any(key in metadata for key in ("storageLifecycleQualification", "storageLifecycleSourcePin",
                                       "prepareCompatibilityProfile", "prepareCompatibilitySourceSHA256")):
        raise ValueError("current ordinary assets cannot claim qualification or PREPARE provenance")
    value = metadata.get("ordinaryProvenance")
    if type(value) is not dict or type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1 or value.get("policy") != POLICY:
        raise ValueError("current ordinary assets require default-profile provenance")
    if sha(value.get("sourceSHA256")) != source_pin(root):
        raise ValueError("ordinary source pin mismatch; rebuild guest assets")


def assert_current(root: Path, output: Path) -> None:
    """Inspect default-profile bytes and freshness without release kernel policy."""
    assert_current_source(root, load_json(read_bytes(output / "disk-bootstrap.json", 65536)))
    with tempfile.TemporaryDirectory(prefix="cengine-toolchain-") as temporary:
        go = subprocess.check_output(["sh", str(root / "Scripts/ensure-go-toolchain.sh")],
                                     env=closed_environment(Path(temporary)), text=True).strip()
    validate(root, output, Path(go), require_release_kernel=False)


def validate(root: Path, output: Path, go: Path, *, require_release_kernel: bool = True) -> None:
    metadata = load_json(read_bytes(output / "disk-bootstrap.json", 65536))
    if any(key in metadata for key in ("storageLifecycleQualification", "storageLifecycleSourcePin")):
        raise ValueError("lifecycle qualification assets are test-only, never ordinary release assets")
    exact(metadata, {"schemaVersion": int, "protocolVersion": int, "storageServiceBootVersion": int,
                     "workloadStorageBootVersion": int, "storageLifecycleVersion": int, "containerInitramfsSHA256": str,
                     "storageInitramfsSHA256": str, "ordinaryProvenance": dict})
    if any(metadata[key] != 1 for key in ("schemaVersion", "protocolVersion", "workloadStorageBootVersion")):
        raise ValueError("unsupported bootstrap metadata version")
    if metadata["storageLifecycleVersion"] != 2 or metadata["storageServiceBootVersion"] != 2:
        raise ValueError("ordinary release assets require storageLifecycleVersion 2 and storageServiceBootVersion 2")
    value = metadata["ordinaryProvenance"]
    exact(value, {"schemaVersion": int, "policy": str, "sourceSHA256": str, "kernel": dict,
                  "containerBinary": dict, "storageBinary": dict, "mke2fsSHA256": str})
    for name in ("containerBinary", "storageBinary"):
        exact(value[name], {"sha256": str, "goVersion": str})
        sha(value[name]["sha256"])
    exact(value["kernel"], {"schemaVersion": int, "origin": str, "sha256": str, "release": str, "inputSHA256": str})
    origin = "canonical-release" if require_release_kernel else value["kernel"]["origin"]
    if value["kernel"] != kernel_receipt(root, output / "vmlinux", origin):
        raise ValueError("kernel origin/hash/configuration mismatch")
    # Staged assets intentionally do not need the separate fetch receipt: it is
    # embedded in the completed, hashed metadata and compared with actual bytes.
    expected = provenance(root, output, go, value["sourceSHA256"])
    expected["kernel"] = value["kernel"]
    if value != expected:
        raise ValueError("ordinary provenance mismatch")
    for kind in ("container", "storage"):
        if sha(metadata[f"{kind}InitramfsSHA256"]) != digest(read_bytes(output / f"{kind}-initramfs.cpio.gz", MAX_COMPRESSED)):
            raise ValueError("initramfs hash mismatch")
    lines = read_bytes(output / "SHA256SUMS", 4096).decode().splitlines()
    expected_lines = [f"{digest(read_bytes(output / name, MAX_KERNEL))}  {name}" for name in ASSETS]
    if sorted(lines) != sorted(expected_lines):
        raise ValueError("release checksum manifest mismatch")


def main(args: list[str]) -> None:
    command, *args = args
    if command in ("create", "validate"):
        from storage_lifecycle_qualification import selection
        if selection():
            raise ValueError("lifecycle qualification cannot create or validate ordinary release provenance")
    if command == "record-kernel" and len(args) == 4:
        root, binary, receipt, origin = args
        atomic_json(Path(receipt), kernel_receipt(Path(root), Path(binary), origin))
    elif command == "check-kernel" and len(args) == 4:
        root, binary, receipt, origin = args
        check_kernel(Path(root), Path(binary), Path(receipt), origin)
    elif command == "verify-download" and len(args) == 2:
        root, directory = map(Path, args)
        _, inputs = kernel_config(root)
        if read_bytes(directory / "kernel-input.sha256", 128).decode().strip() != inputs:
            raise ValueError("download kernel input mismatch")
        expected = [f"{digest(read_bytes(directory / name, MAX_KERNEL))}  {name}"
                    for name in ("cengine-kernel-arm64", "kernel-input.sha256")]
        if sorted(read_bytes(directory / "SHA256SUMS", 4096).decode().splitlines()) != sorted(expected):
            raise ValueError("download checksum manifest mismatch")
    elif command == "audit-selected" and len(args) == 3:
        pin, *paths = args
        if pin:
            audit_selected([read_bytes(Path(path), MAX_AUDIT_BYTES).decode() for path in paths])
    elif command == "create" and len(args) == 5:
        root, output, go, pin, destination = args
        atomic_json(Path(destination), provenance(Path(root), Path(output), Path(go), pin))
    elif command == "validate" and len(args) == 2:
        root, output = map(Path, args)
        # Toolchain selection remains ensure-go-toolchain.sh's existing trust
        # boundary; close ambient Go variables during provisioning and inspection.
        with tempfile.TemporaryDirectory(prefix="cengine-toolchain-") as temporary:
            environment = closed_environment(Path(temporary))
            go = subprocess.check_output(["sh", str(root / "Scripts/ensure-go-toolchain.sh")], env=environment, text=True).strip()
        validate(root, output, Path(go))
    else:
        raise ValueError("invalid provenance command")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, zlib.error, subprocess.SubprocessError) as error:
        sys.exit(f"ordinary guest assets refused: {error}")
