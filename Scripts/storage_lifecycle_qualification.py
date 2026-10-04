#!/usr/bin/env python3
"""Closed, test-only lifecycle-v2-native-v1 build selection; never activates guests.

The source receipt extends the existing complete Guest inventory with host Swift
and build-policy inputs. It hashes source bytes, not generated pins, signatures,
DerivedData or this utility's output. Toolchain provenance is not claimed here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from prepare_compatibility_assets import source_inventory, MAX_FILES, MAX_SOURCE_BYTES
from guest_asset_provenance import read_bytes

PROFILE = "lifecycle-v2-native-v1"
ENV = "CENGINE_STORAGE_LIFECYCLE_QUALIFICATION"
PROFILE_FIELD = "storageLifecycleQualification"
SOURCE_FIELD = "storageLifecycleSourcePin"
INPUTS = (
    "Scripts/storage_lifecycle_qualification.py", "Scripts/run-compat-tests.sh",
    "Scripts/build-storage-controller.sh", "Scripts/network-helper-fingerprint.sh",
    "Scripts/compat-network-helper.sh", "Scripts/helper_compatibility_policy.py",
    "Scripts/compat_lifecycle_fault.py",
    "Scripts/sign-compat-binary.sh", "Scripts/managed-signing.sh",
    "Configuration/helper-support-sources.txt",
    "Configuration/cengine-Info.plist", "Configuration/network-helper-Info.plist",
    "Configuration/cengine.entitlements",
    "cengine.xcodeproj/project.pbxproj",
    "cengine.xcodeproj/xcshareddata/xcschemes/test-compat.xcscheme",
)


def selection(environment=None) -> str:
    environment = os.environ if environment is None else environment
    for key in ("CENGINE_COMPAT_MANAGED_STORAGE", "CENGINE_COMPAT_SHARED_STORAGE"):
        if key in environment:
            raise ValueError(f"{key} is retired; lifecycle is the default")
    value = environment.get(ENV, "")
    if value not in ("", PROFILE):
        raise ValueError(f"{ENV} must be empty or {PROFILE}")
    if value:
        for key in ("CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY", "PREPARE_COMPATIBILITY_PROFILE"):
            if environment.get(key):
                raise ValueError("lifecycle qualification cannot combine PREPARE selections")
        for key in ("CENGINE_SIGN_RELEASE", "CENGINE_NOTARIZE"):
            if environment.get(key) not in (None, "", "0"):
                raise ValueError("lifecycle qualification is test-only, not a production/release build")
        for key in ("CONFIGURATION", "XCODE_COMPAT_CONFIGURATION", "XCODE_COMPAT_SCHEME"):
            if environment.get(key) not in (None, "", "test-compat"):
                raise ValueError("lifecycle qualification requires test-compat configuration and scheme")
        for key in ("CODE_SIGNING_ALLOWED", "CODE_SIGNING_REQUIRED"):
            if environment.get(key) not in (None, "", "YES"):
                raise ValueError("lifecycle qualification cannot disable signing")
        if environment.get("CODE_SIGN_IDENTITY") in ("-", ""):
            raise ValueError("lifecycle qualification cannot use an unsigned/ad-hoc identity")
    return value


def require_signed_managed(environment=None) -> None:
    environment = os.environ if environment is None else environment
    if not selection(environment):
        return
    identity = environment.get("CENGINE_DEVELOPER_ID_APPLICATION", "")
    if re.fullmatch(
            r"Developer ID Application: [^\r\n]+ \([A-Z0-9]{10}\)", identity) is None:
        raise ValueError("lifecycle qualification requires signed managed storage and a full Developer ID Application identity")


def validate_output(root: Path, output: Path) -> None:
    root, resolved = root.resolve(), output.resolve()
    # A profile-named component is mandatory even for caller overrides. Resolve
    # aliases before checking, so symlinks cannot reuse ordinary build outputs.
    forbidden = (root / ".build/guest", root / ".build/xcode-derived", root / "dist")
    if not output.is_absolute() or PROFILE not in resolved.parts or any(
            resolved == path or resolved.is_relative_to(path) or path.is_relative_to(resolved)
            for path in forbidden):
        raise ValueError(f"qualification output must be separate, absolute and namespaced by {PROFILE}")


def source_pin(root: Path) -> str:
    root = root.resolve(strict=True)
    inventory = source_inventory(root)
    policy = root / "Sources/CEngineCore/StorageLifecycleNativePolicy.swift"
    if not policy.is_file():
        raise ValueError("missing StorageLifecycleNativePolicy.swift qualification input")
    paths = [root / name for name in INPUTS]
    def walk_error(error):
        raise error
    for directory, dirs, files in os.walk(root / "Sources", followlinks=False, onerror=walk_error):
        if any((Path(directory) / name).is_symlink() for name in dirs):
            raise ValueError("symlink in qualification source inventory")
        paths.extend(Path(directory) / name for name in files if name.endswith(".swift"))
        if len(paths) > MAX_FILES:
            raise ValueError("qualification source inventory file bound")
    if len(paths) + len(inventory) > MAX_FILES:
        raise ValueError("qualification source inventory file bound")
    remaining = MAX_SOURCE_BYTES
    for path in sorted(paths):
        if any(part.is_symlink() for part in (path, *path.parents) if part != root and root in part.parents):
            raise ValueError("symlink in qualification source inventory")
        data = read_bytes(path, remaining)
        remaining -= len(data)
        inventory[path.relative_to(root).as_posix()] = hashlib.sha256(data).hexdigest()
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def assets_sha256(root: Path, directory: Path) -> str:
    """Seal the exact, normally validated caller receipt, never generated source inputs."""
    if selection() != PROFILE:
        raise ValueError("asset pin requires the explicit lifecycle qualification profile")
    root, directory = root.resolve(strict=True), directory.resolve(strict=True)
    validate_output(root, directory)
    receipt = read_bytes(directory / "SHA256SUMS", 65536)
    checked = subprocess.run([sys.executable, str(root / "Scripts/check-managed-guest-assets.py"), str(directory)],
                             capture_output=True, text=True)
    if checked.returncode:
        raise ValueError(checked.stderr.strip() or "managed guest asset validation failed")
    if read_bytes(directory / "SHA256SUMS", 65536) != receipt:
        raise ValueError("managed SHA256SUMS changed during validation")
    return hashlib.sha256(receipt).hexdigest()


def validate_metadata(metadata: dict, root: Path, profile: str) -> None:
    fields = {PROFILE_FIELD, SOURCE_FIELD} & metadata.keys()
    if not profile and not fields:
        return
    if profile != PROFILE or fields != {PROFILE_FIELD, SOURCE_FIELD} or metadata[PROFILE_FIELD] != PROFILE:
        raise ValueError("lifecycle-tagged assets require the exact explicit qualification profile")
    if any(key in metadata for key in ("prepareCompatibilityProfile", "prepareCompatibilitySourceSHA256", "ordinaryProvenance")):
        raise ValueError("lifecycle qualification assets cannot claim PREPARE or ordinary provenance")
    if metadata[SOURCE_FIELD] != source_pin(root):
        raise ValueError("lifecycle qualification source pin mismatch")


def main(args: list[str]) -> None:
    if args == ["selection"]:
        print(selection())
    elif args == ["signed-managed"]:
        require_signed_managed()
    elif len(args) == 2 and args[0] == "source-pin":
        print(source_pin(Path(args[1])))
    elif len(args) == 3 and args[0] == "assets-sha256":
        print(assets_sha256(Path(args[1]), Path(args[2])))
    elif len(args) == 3 and args[0] == "validate-output":
        validate_output(Path(args[1]), Path(args[2]))
    else:
        raise ValueError("unknown lifecycle qualification command")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError) as error:
        sys.exit(f"storage lifecycle qualification refused: {error}")
