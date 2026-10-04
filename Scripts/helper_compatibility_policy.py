#!/usr/bin/env python3
"""Read-only helper qualification selection; never authenticates a helper.

Ordinary compatibility still needs the running helper's authenticated capabilities.
The signed client's lifecycle-v2 requirement includes cold-dead-resolution-v1
and cold-unenrolled-recovery-v1;
keep the selector stable and do not replace semantic admission with an exact-build
fingerprint requirement. Qualification remains a separate exact-build lane.
A public asset label can only select a stricter exact-build policy, never authorize
storage access. Asset hashes/provenance remain the managed asset preflight's job.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys

PREPARE_PROFILES = ("rtm096-normal-a7-v1", "rtm096-early-a1-a3-v2", "rtm096-full-nine-v3")
QUALIFICATION = "lifecycle-v2-native-v1"
KEYS = ("CENGINE_STORAGE_LIFECYCLE_QUALIFICATION",
        "CENGINE_COMPAT_LIFECYCLE_FAULT", "CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY",
        "PREPARE_COMPATIBILITY_PROFILE", "CENGINE_COMPAT_REQUIRE_EXACT_HELPER",
        "CENGINE_COMPAT_MANAGED_ASSET_DIR")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate managed asset metadata field")
        result[key] = value
    return result


def read_metadata(directory: str) -> dict:
    if not directory:
        raise ValueError("managed helper validation requires CENGINE_COMPAT_MANAGED_ASSET_DIR")
    fd = os.open(Path(directory) / "disk-bootstrap.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 65536:
            raise ValueError("invalid managed asset metadata size or type")
        data = stream.read(65537)
        after = os.fstat(stream.fileno())
    if len(data) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("managed asset metadata changed while reading")
    value = json.loads(data, object_pairs_hook=unique_object)
    if type(value) is not dict:
        raise ValueError("managed asset metadata must be an object")
    return value


def profile_pair(metadata: dict, profile_key: str, source_key: str, allowed: tuple[str, ...]) -> str:
    fields = {profile_key, source_key} & metadata.keys()
    if not fields:
        return ""
    if fields != {profile_key, source_key} or metadata[profile_key] not in allowed:
        raise ValueError("unknown or incomplete managed asset profile")
    source = metadata[source_key]
    if type(source) is not str or re.fullmatch(r"[0-9a-f]{64}", source) is None:
        raise ValueError("invalid managed asset profile source pin")
    return metadata[profile_key]


def select(environment: dict[str, str], metadata: dict) -> tuple[str, str]:
    for key in ("CENGINE_COMPAT_SHARED_STORAGE", "CENGINE_COMPAT_MANAGED_STORAGE"):
        if key in environment:
            raise ValueError(f"{key} is retired; lifecycle is the default")
    qualification, fault, controller, prepare, exact = (environment.get(key, "") for key in KEYS[:-1])
    for key, value, allowed in (
        (KEYS[0], qualification, ("", QUALIFICATION)),
        (KEYS[1], fault, ("", "before-configure-v1", "after-replacement-before-completion-v1",
                          "before-takeover-apply-v1", "after-takeover-apply-v1",
                          "after-cold-l2-before-a1-v1", "after-first-cold-completion-v1")),
        (KEYS[2], controller, ("", PREPARE_PROFILES[-1])),
        (KEYS[3], prepare, ("", *PREPARE_PROFILES)),
        (KEYS[4], exact, ("", "1")),
    ):
        if value not in allowed:
            raise ValueError(f"unsupported {key} selection")
    asset_prepare = profile_pair(metadata, "prepareCompatibilityProfile", "prepareCompatibilitySourceSHA256", PREPARE_PROFILES)
    asset_qualification = profile_pair(metadata, "storageLifecycleQualification", "storageLifecycleSourcePin", (QUALIFICATION,))
    if qualification != asset_qualification:
        raise ValueError("lifecycle qualification selection and assets must match")
    if prepare and prepare != asset_prepare:
        raise ValueError("PREPARE selection and assets must match")
    if controller and asset_prepare != controller:
        raise ValueError("controller PREPARE selection requires matching full-profile assets")
    if qualification:
        if fault or controller or prepare or asset_prepare:
            raise ValueError("lifecycle qualification cannot combine ordinary or fault selections")
        return "exact", "lifecycle-qualification"
    if type(metadata.get("storageLifecycleVersion")) is not int or metadata["storageLifecycleVersion"] != 2:
        raise ValueError("ordinary lifecycle assets require storageLifecycleVersion: 2")
    if controller or prepare or asset_prepare:
        if fault or not (controller == prepare == asset_prepare == PREPARE_PROFILES[-1]):
            raise ValueError("lifecycle PREPARE requires matching explicit full-profile selections and assets, without runtime faults")
        return "exact", "lifecycle-v2"
    return ("exact" if exact or fault else "compatible"), "lifecycle-v2"


def main(arguments: list[str]) -> None:
    if len(arguments) != len(KEYS):
        raise ValueError("expected the closed managed helper policy arguments")
    environment: dict[str, str] = {**os.environ, **dict(zip(KEYS, arguments))}
    directory = environment[KEYS[-1]]
    # Doctor/status must work before ordinary assets have been built. This only
    # chooses the authenticated capability contract, never authorizes assets.
    # Explicit directories and qualification/PREPARE profiles still require
    # their exact, bounded metadata; never fall back after a failed read.
    if directory:
        metadata = read_metadata(directory)
    elif any(environment.get(key) for key in (KEYS[0], KEYS[2], KEYS[3])):
        raise ValueError("qualification/PREPARE helper policy requires explicit paired assets")
    else:
        metadata = {"storageLifecycleVersion": 2}
    print(*select(environment, metadata))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError) as error:
        sys.exit(f"managed helper policy refused: {error}")
