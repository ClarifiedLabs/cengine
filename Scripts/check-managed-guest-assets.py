#!/usr/bin/env python3
"""Read-only validation of caller-built, hash-paired experimental guest assets."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import subprocess
import zlib

from guest_asset_provenance import assert_current
from prepare_compatibility_assets import FULL_PROFILE, validate_metadata as validate_prepare_metadata
from storage_lifecycle_qualification import selection, validate_output, validate_metadata as validate_lifecycle_metadata


def validate(directory: Path) -> None:
    profile = selection()
    directory = directory.resolve(strict=True)
    if profile:
        validate_output(Path(__file__).resolve().parents[1], directory)
    names = ('vmlinux', 'container-initramfs.cpio.gz', 'storage-initramfs.cpio.gz', 'disk-bootstrap.json')

    def read(name: str, limit: int | None = None) -> bytes:
        fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or (limit and info.st_size > limit):
                raise ValueError(f'invalid managed guest asset: {name}')
            return stream.read()

    expected = {}
    for line in read('SHA256SUMS', 65536).decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9.-]+)', line)
        if not match or match[2] in expected:
            raise ValueError('invalid or duplicate managed SHA256SUMS entry')
        expected[match[2]] = match[1]
    if set(expected) != set(names):
        raise ValueError('managed SHA256SUMS must bind exactly the kernel, both initramfs images and disk-bootstrap.json')
    contents = b''
    for name in names:
        data = read(name, 65536 if name == 'disk-bootstrap.json' else None)
        if hashlib.sha256(data).hexdigest() != expected[name]:
            raise ValueError(f'managed asset checksum mismatch: {name}')
        if name == 'disk-bootstrap.json':
            contents = data

    def closed_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate managed bootstrap metadata field')
            value[key] = item
        return value

    metadata = json.loads(contents, object_pairs_hook=closed_object)
    validate_lifecycle_metadata(metadata, Path(__file__).resolve().parents[1], profile)
    if type(metadata.get('storageLifecycleVersion')) is not int or metadata['storageLifecycleVersion'] != 2:
        raise ValueError('lifecycle assets require storageLifecycleVersion: 2')
    if not profile:
        controller = os.environ.get('CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY', '')
        prepare = os.environ.get('PREPARE_COMPATIBILITY_PROFILE', '')
        if controller or prepare or any(key in metadata for key in (
                'prepareCompatibilityProfile', 'prepareCompatibilitySourceSHA256')):
            if (os.environ.get('CENGINE_COMPAT_LIFECYCLE_FAULT') or not (
                    controller == prepare == metadata.get('prepareCompatibilityProfile') == FULL_PROFILE)):
                raise ValueError('lifecycle PREPARE requires matching explicit full-profile selections and assets, without runtime faults')
            if 'ordinaryProvenance' in metadata:
                raise ValueError('lifecycle PREPARE assets cannot claim ordinary provenance')
            # Fault-enabled assets use the exact PREPARE source pin below, never
            # the ordinary inert-binary provenance validation branch.
        else:
            assert_current(Path(__file__).resolve().parents[1], directory)
    validate_prepare_metadata(metadata, Path(__file__).resolve().parents[1])
    for name in ('schemaVersion', 'protocolVersion', 'storageServiceBootVersion', 'workloadStorageBootVersion'):
        version = 2 if name == 'storageServiceBootVersion' else 1
        if type(metadata.get(name)) is not int or metadata[name] != version:
            raise ValueError(f'managed guest assets require {name}: {version}')
    for prefix in ('container', 'storage'):
        if metadata.get(f'{prefix}InitramfsSHA256') != expected[f'{prefix}-initramfs.cpio.gz']:
            raise ValueError(f'managed bootstrap metadata does not bind {prefix} initramfs')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('usage: check-managed-guest-assets.py ASSET_DIRECTORY')
        validate(Path(sys.argv[1]))
    except (OSError, ValueError, TypeError, AttributeError, KeyError, zlib.error, subprocess.SubprocessError) as error:
        sys.exit(f'managed guest asset preflight: {error}')
