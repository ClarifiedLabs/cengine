#!/usr/bin/env python3
"""Closed RTM096 source pins and static go-list audit; never builds or activates.

Every regular Guest file is pinned, including vendor metadata and arbitrary embed
payloads. No artifact/extension exclusions are safe for Go compilation. The Go
standard library and toolchain outside Guest remain in ensure-go-toolchain.sh's
existing trusted-toolchain provenance scope; this source pin does NOT hash them.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

PROFILE = "rtm096-normal-a7-v1"
EARLY_PROFILE = "rtm096-early-a1-a3-v2"
FULL_PROFILE = "rtm096-full-nine-v3"
PROFILES = (PROFILE, EARLY_PROFILE, FULL_PROFILE)
PROFILE_FIELD = "prepareCompatibilityProfile"
SOURCE_FIELD = "prepareCompatibilitySourceSHA256"
MAX_FILES = 8192
MAX_SOURCE_BYTES = 128 << 20
MAX_AUDIT_BYTES = 64 << 20
BUILD_INPUTS = (
    "Scripts/build-guest-assets.sh", "Scripts/ensure-go-toolchain.sh",
    "Scripts/build-e2fsprogs.sh",
    "Scripts/make-initramfs.py", "Scripts/prepare_compatibility_assets.py",
    "Scripts/check-managed-guest-assets.py", "Configuration/mke2fs.conf",
    "Scripts/guest_asset_provenance.py", "Configuration/e2fsprogs-version",
    "Scripts/storage_lifecycle_qualification.py",
)


def source_inventory(root: Path) -> dict[str, str]:
    root = root.resolve(strict=True)
    guest = root / "Guest"
    if guest.is_symlink() or not guest.is_dir():
        raise ValueError("guest source directory required")
    paths = [root / name for name in BUILD_INPUTS]

    def walk_error(error: OSError) -> None:
        raise error  # Never silently omit an unreadable subtree.

    directories = 0
    for directory, dirs, files in os.walk(guest, followlinks=False, onerror=walk_error):
        directories += 1
        if directories > MAX_FILES or len(paths) + len(files) > MAX_FILES:
            raise ValueError("guest source inventory file bound")
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError("symlink in guest source inventory")
        paths.extend(Path(directory) / name for name in files)
    if len(paths) == len(BUILD_INPUTS):
        raise ValueError("guest source inventory has no files")
    total, inventory = 0, {}
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix()
        if any(part.is_symlink() for part in [path, *path.parents] if part != root and root in part.parents):
            raise ValueError("symlink in build input")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("non-regular file in guest source inventory")
            if before.st_size > MAX_SOURCE_BYTES - total:
                raise ValueError("guest source inventory byte bound")
            data = stream.read(MAX_SOURCE_BYTES - total + 1)
            after = os.fstat(stream.fileno())
        if len(data) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("source changed while hashing")
        total += len(data)
        inventory[relative] = hashlib.sha256(data).hexdigest()
    return inventory


def source_pin(root: Path) -> str:
    encoded = json.dumps(source_inventory(root), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def audit_selected_inputs(root: Path, goroot: Path, documents: list[str]) -> None:
    """Check bounded `go list -deps -json` output from the closed build environment.

    No -e/-compiled/-export: listing must succeed, without compiling or running
    code. Both actual init and storage dependency closures are used; only the full-nine
    profile also tags storage. The caller supplies those exact selected closures.
    """
    root = root.resolve(strict=True)
    guest = root / "Guest"
    trusted_stdlib = goroot.resolve(strict=True) / "src"
    inventory = source_inventory(root)
    decoder = json.JSONDecoder()
    count = 0
    total_bytes = 0

    def inventoried(path: Path) -> None:
        if not path.is_absolute():
            raise ValueError(f"external selected Go input: {path}")
        # Normalize aliases above the checkout (e.g. /Users -> /Volumes).
        # Symlinks within Guest are already rejected by source_inventory.
        path = path.resolve()
        if not path.is_relative_to(guest):
            raise ValueError(f"external selected Go input: {path}")
        relative = path.relative_to(root).as_posix()
        if relative not in inventory:
            raise ValueError(f"uninventoried selected Go input: {path}")

    def module_inputs(module: dict) -> None:
        # Vendor replacements may name a module with no Dir/GoMod: only the
        # selected files are used then. Any actual external module input fails.
        if module.get("GoMod"):
            inventoried(Path(module["GoMod"]))
        if module.get("Dir"):
            directory = Path(module["Dir"]).resolve(strict=True)
            if not directory.is_relative_to(guest):
                raise ValueError(f"external selected Go module: {directory}")
        if module.get("Replace"):
            module_inputs(module["Replace"])

    for document in documents:
        total_bytes += len(document.encode("utf-8"))
        if total_bytes > MAX_AUDIT_BYTES:
            raise ValueError("selected Go input audit byte bound")
        offset, document_count = 0, 0
        while offset < len(document):
            if document[offset].isspace():
                offset += 1
                continue
            package, offset = decoder.raw_decode(document, offset)
            count += 1
            document_count += 1
            if count > MAX_FILES or not isinstance(package, dict):
                raise ValueError("selected Go input audit package bound/type")
            if package.get("Error") or package.get("DepsErrors") or package.get("Incomplete"):
                raise ValueError("incomplete selected Go input audit")
            directory = Path(package.get("Dir", "")).resolve(strict=True)
            if package.get("Standard") is True:
                if package.get("Goroot") is not True or not directory.is_relative_to(trusted_stdlib):
                    raise ValueError("selected standard library outside trusted toolchain")
                continue  # Deliberately NOT claimed by the Guest source hash.
            if not directory.is_relative_to(guest):
                raise ValueError(f"external selected Go package: {directory}")
            module_inputs(package.get("Module", {}))
            selected = 0
            # Covers Go/C/C++/ObjC/Fortran/assembly/SWIG/syso/embed, including
            # future *Files fields. Even ignored/test files must be inventoried.
            for field, names in package.items():
                if not field.endswith("Files"):
                    continue
                if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
                    raise ValueError("invalid selected Go file list")
                for name in names:
                    inventoried(directory / name)
                    selected += 1
            if not selected:
                raise ValueError("selected Go package has no inventoried files")
        if not document_count:
            raise ValueError("selected Go input audit has no packages")
    if not count:
        raise ValueError("selected Go input audit has no packages")


def validate_metadata(metadata: dict, root: Path) -> None:
    fields = {PROFILE_FIELD, SOURCE_FIELD} & set(metadata)
    if not fields:
        return  # Ordinary paired assets remain unmodified and inert.
    if fields != {PROFILE_FIELD, SOURCE_FIELD} or metadata[PROFILE_FIELD] not in PROFILES:
        raise ValueError("unknown or incomplete PREPARE compatibility asset profile")
    value = metadata[SOURCE_FIELD]
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None or value != source_pin(root):
        raise ValueError("PREPARE compatibility source pin mismatch")


def validate_output(root: Path, output: Path) -> None:
    if not output.is_absolute() or output.resolve() == root.resolve() / ".build/guest":
        raise ValueError("PREPARE compatibility assets require a separate explicit absolute output")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "source-pin":
            print(source_pin(Path(sys.argv[2])))
        elif len(sys.argv) == 6 and sys.argv[1] == "audit-inputs":
            documents = []
            remaining = MAX_AUDIT_BYTES
            for name in sys.argv[4:]:
                with open(name, "rb") as stream:
                    data = stream.read(remaining + 1)
                remaining -= len(data)
                if remaining < 0:
                    raise ValueError("selected Go input audit byte bound")
                documents.append(data.decode("utf-8"))
            audit_selected_inputs(Path(sys.argv[2]), Path(sys.argv[3]), documents)
        elif len(sys.argv) == 4 and sys.argv[1] == "validate-output":
            validate_output(Path(sys.argv[2]), Path(sys.argv[3]))
        else:
            raise ValueError("closed source-pin/audit-inputs/validate-output command required")
    except (OSError, ValueError) as error:
        sys.exit(f"PREPARE compatibility assets refused: {error}")
