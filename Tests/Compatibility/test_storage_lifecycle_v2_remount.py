"""RTM-126 ordinary native APFS offline remount; native acceptance is pending.

Selected by the ordinary compatibility runner, not the fresh-only qualification
profile. Requires its updated installed test helper and pinned local Alpine image.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import tempfile

import pytest

import harness
import helper_fixture_lifetime as lifetime
from storage_lifecycle_v2_remount import OfflineRemount, OwnedImage, require


@pytest.fixture(autouse=True)
def verify_docker_cli_target():
    # Two fresh spawn children own their real Daemon/client lifetimes.
    pass


@pytest.fixture(autouse=True)
def daemon_survived():
    pass


@pytest.fixture
def offline_remount(request):
    from conftest import Daemon, HELPER_FIXTURE_BOUNDARY, managed_storage_arguments
    import compat_image_fixtures

    if platform.system() != "Darwin" or platform.machine() != "arm64":
        pytest.skip("RTM-126 requires native Darwin arm64 APFS")
    # No daemon/image-cache fixture, helper install, registry fallback or profile.
    require(not any(os.environ.get(key) for key in (
        "CENGINE_STORAGE_LIFECYCLE_QUALIFICATION", "CENGINE_COMPAT_LIFECYCLE_FAULT",
        "CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY", "PREPARE_COMPATIBILITY_PROFILE")),
        "RTM-126 requires the ordinary lifecycle runner")
    managed_storage_arguments(os.environ)
    paths = {}
    for key in ("CENGINE_BINARY", "CENGINE_KERNEL", "CENGINE_CONTAINER_INITRAMFS", "CENGINE_STORAGE_INITRAMFS"):
        raw = os.environ.get(key, "")
        require(raw and Path(raw).is_absolute() and Path(raw).is_file(), "RTM-126 paired assets unavailable")
        paths[key] = Path(raw).resolve(strict=True)
    compat_image_fixtures.verify("alpine")  # Read-only local preflight before helper mutation.
    # Signed status rejects an old installed helper before any restart or image.
    import json
    import subprocess
    status = subprocess.run([str(paths["CENGINE_BINARY"]), "helper", "status", "--require-managed", "lifecycle-v2"],
                            check=True, capture_output=True, text=True, timeout=10)
    info = lifetime.validate_status(json.loads(status.stdout))
    require("lifecycle-v2-stable-host-identity-v1" in info["capabilities"]["storageContracts"],
            "RTM-126 needs the updated installed test helper; never installs automatically")
    HELPER_FIXTURE_BOUNDARY.prepare(paths["CENGINE_BINARY"])
    work = Path(tempfile.mkdtemp(prefix="cengine-compat-", dir=lifetime.canonical_temp()))
    value = Daemon(binary=paths["CENGINE_BINARY"], kernel=paths["CENGINE_KERNEL"],
                   container_initramfs=paths["CENGINE_CONTAINER_INITRAMFS"],
                   storage_initramfs=paths["CENGINE_STORAGE_INITRAMFS"], work=work)
    HELPER_FIXTURE_BOUNDARY.created(value)
    retention = harness.preretain_compatibility_root(work, value.owner_binary)
    value._managed_fixture_retention = True
    transaction = None
    try:
        (work / "blocker").mkdir(mode=0o700)
        # The ordinary backing is a sparse 512-GiB file; this is virtual image
        # capacity, not preallocation or permission to fill the host filesystem.
        store = OwnedImage.create(work, "store", value.root, "1t")
        blocker = OwnedImage.create(work, "blocker", work / "blocker", "128m")
        transaction = OfflineRemount(value, retention, store, blocker)
        store.attach()
        value.root.chmod(0o700)  # Only this newly-created APFS volume, before first start.
        yield transaction
    finally:
        passed = all(getattr(getattr(request.node, "report_" + phase, None), "passed", False)
                     for phase in ("setup", "call"))
        if transaction is not None and transaction.finished and passed and not value._retain_root:
            # Revalidate at the final teardown outcome; never hand an APFS root
            # to generic recursive cleanup, even after successful normal detach.
            request.node._managed_remount_cleanup = transaction
        else:
            value.retain_root(reason="unsafe-disk-phase")
            print(f"\nRTM-126 owned image/root retained: {work}")


@pytest.mark.compat("RTM-126")
def test_lifecycle_v2_offline_apfs_remount(offline_remount):
    transaction = offline_remount
    try:
        first = transaction.run_child()
        lifetime.restart_for_offline_remount(transaction)
        transaction.remount()
        transaction.run_child(first)
        lifetime.restart_for_offline_remount(transaction)
        transaction.finish()
    except Exception:
        pytest.fail(f"RTM-126 failed; retained owned image/root: {transaction.value.work}", pytrace=False)
