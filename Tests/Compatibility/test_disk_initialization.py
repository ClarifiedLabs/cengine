"""RTM-074: real VZ disk bootstrap, mount-only reboot, and corrupt-disk refusal.

Run only through the isolated compatibility lifecycle runner. This test observes
journals, guest block identity/mountinfo, and persisted data, not bootstrap socket
frames or the kernel-derived peer CID. No mock transport or loop disk is used.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import time
import uuid

import docker
from docker.types import Mount
import pytest

from harness import (compatibility_root_owned_by, compatibility_runtime_processes,
                     compatibility_disk_holder_diagnostics, terminate_compatibility_runtime)
from storage_backend_proof import _file_identity, daemon_startup_mode, verify_backend
from test_volume_discovery import ALPINE, _exec


PHASES = ("created", "spent", "initialized")
OWNER_LABEL = "dev.cengine.compat.disk-initialization-owner"


def _stable_file_identity(descriptor):
    # Match the raw journal encoder; never normalize persisted record values.
    observed = _file_identity(descriptor)
    return {"inode": observed["inode"], "volumeUUID": observed["volumeUUID"].lower()}


def _journal(disk):
    raw = {phase: disk.with_name(f".raw-init-{disk.name}.{phase}.json").read_bytes()
           for phase in PHASES}
    records = {phase: json.loads(data) for phase, data in raw.items()}
    initial = records["created"]
    for phase, record in records.items():
        assert type(record["schemaVersion"]) is int and record["schemaVersion"] == 2 and record["state"] == phase, record
        assert record["diskName"] == disk.name, record
        assert record["expectedSize"] == disk.stat().st_size, record
        for field, path in (("diskIdentity", disk), ("parentIdentity", disk.parent),
                            ("lockIdentity", disk.with_name(f".raw-init-{disk.name}.lock"))):
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                assert record[field] == _stable_file_identity(descriptor), record
            finally:
                os.close(descriptor)
        for field in ("ext4UUID", "operationUUID"):
            assert str(uuid.UUID(record[field])) == record[field], record
            assert uuid.UUID(record[field]).int != 0, record
        expected = {**initial, "state": phase}
        if phase != "created":
            expected["binding"] = records["spent"]["binding"]
            for value in record["binding"].values():
                assert str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
        assert record == expected, (phase, record, expected)
    assert not list(disk.parent.glob(f".raw-init-{disk.name}.*.pending"))
    assert not disk.with_name(f".raw-init-{disk.name}.quarantine").exists()
    return records["initialized"], raw


def _running_spec(daemon, container_id=None):
    paths = ([daemon.root / "infrastructure/shim.json"] if container_id is None else
             (daemon.root / "containers" / container_id / "shim-generations").glob("*/spec.json"))
    running = []
    for path in paths:
        specification = json.loads(path.read_text())
        status_path = Path(specification["socketPath"] + ".status")
        if status_path.exists():
            status = json.loads(status_path.read_text())
            if status["state"] == "running":
                assert status["shimLaunchUUID"] == specification["shimLaunchUUID"]
                assert specification["diskBootstrapVersion"] == 1
                running.append(specification)
    assert len(running) == 1, f"expected one running shim for {container_id or 'storage'}"
    return running[0]


def _mounts(container):
    return [line.split() for line in _exec(container, "cat", "/proc/self/mountinfo").decode().splitlines()]


def _shared_backend(daemon, container):
    return verify_backend(
        daemon.root, "shared", _exec(container, "cat", "/proc/self/mountinfo").decode(),
        "/shared", startup_mode=daemon_startup_mode(daemon),
    )


def _observe(container, expected):
    """Read actual guest devices; expected maps mountpoint to its host journal."""
    mounts = _mounts(container)
    result, devices = {}, set()
    for ordinal, (path, journal) in enumerate(expected.items()):
        device = "vd" + chr(ord("a") + ordinal)
        matches = [fields for fields in mounts if fields[4] == path]
        assert len(matches) == 1, (path, mounts)
        fields = matches[0]
        separator = fields.index("-")
        assert fields[3] == "/" and fields[separator + 1] == "ext4", fields
        assert fields[2] not in devices, fields
        devices.add(fields[2])
        # ext4 UUID is 16 raw bytes at superblock offset 0x68 (disk 1024+104).
        # Reading it directly avoids depending on blkid's optional BusyBox flags.
        output = _exec(container, "sh", "-ec", f"""
            printf '%s\n' "$(cat /sys/class/block/{device}/serial)"
            printf '%s\n' "$(cat /sys/class/block/{device}/size)"
            test -b /dev/{device}
            stat -c '%t:%T' /dev/{device}
            cat /sys/class/block/{device}/dev
            stat -c '%u:%g:%a:%i' {path}
            dd if=/dev/{device} bs=1 skip=1128 count=16 2>/dev/null | od -An -tx1
        """).decode().splitlines()
        serial, sectors, rdev_hex, sysfs_device, metadata, *uuid_hex = output
        # mountinfo's source is cosmetic: secure mount(2) uses a pinned
        # /proc/self/fd/N path. Its major:minor must still identify this exact
        # whole block device, independently of that source string.
        rdev = tuple(int(value, 16) for value in rdev_hex.split(":"))
        assert len(rdev) == 2 and tuple(int(value) for value in fields[2].split(":")) == rdev, (fields, output)
        assert tuple(int(value) for value in sysfs_device.split(":")) == rdev, (fields, output)
        observed_uuid = str(uuid.UUID(bytes=bytes.fromhex(" ".join(uuid_hex))))
        assert serial == ("root" if ordinal == 0 else f"volume{ordinal - 1}"), output
        assert int(sectors) * 512 == journal["expectedSize"], output
        assert observed_uuid == journal["ext4UUID"], (path, observed_uuid, journal)
        result[path] = {"serial": serial, "bytes": int(sectors) * 512,
                        "uuid": observed_uuid, "metadata": metadata,
                        "device": fields[2], "mountSource": fields[separator + 2]}
    return result


def _persistent_observation(observation):
    # FD numbers may change on a new boot. Keep the actual source in evidence,
    # but compare every device identity and filesystem metadata field.
    return {path: {key: value for key, value in fields.items() if key != "mountSource"}
            for path, fields in observation.items()}


def _matched_pids(daemon):
    # Never persist argv: unrelated kernel/spec arguments can contain secrets.
    return [value.pid for value in compatibility_runtime_processes(
        daemon.binary, roots=(daemon.root,))]


def _quiesce(daemon, *, record=None):
    if not __debug__:
        raise RuntimeError("RTM-074 refuses optimized Python")
    assert compatibility_root_owned_by(daemon.work, daemon.binary)
    daemon.stop()
    # Daemon stop alone preserves live shims. Process exit is necessary, but the
    # actual exclusive disk claim below also waits for remotely retained VZ FDs.
    try:
        stopped = terminate_compatibility_runtime(daemon.binary, roots=(daemon.root,))
    except Exception:
        # The shared cleanup helper's failure can include complete argv. Do not
        # expose it through this fixture's exception/evidence path.
        raise RuntimeError("owned runtime termination failed") from None
    result = {"cleanup_matched_pids": [value.pid for value in stopped],
              "remaining_matched_pids": _matched_pids(daemon)}
    _record_disk_event(record, "quiesced", **result)
    assert not result["remaining_matched_pids"], result
    return result


def _disk_holders(disk):
    """Bounded exact-file diagnostics only; lsof is never ownership authority."""
    output = bytearray()
    reason = "eof"
    try:
        process = subprocess.Popen(
            ["/usr/sbin/lsof", "-nP", "-Fpcfn", "--", str(disk)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        return {"error_errno": error.errno}
    assert process.stdout is not None
    try:
        deadline = time.monotonic() + 3.0
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while len(output) < 8192:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    reason = "timeout"
                    break
                chunk = os.read(process.stdout.fileno(), min(4096, 8192 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
            else:
                reason = "output-limit"
    finally:
        # Signal and join only this diagnostic child, never a reported holder.
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
    return {"records": output.decode(errors="replace"), "end": reason,
            "returncode": process.returncode}


class _DiskClaimTimeout(TimeoutError):
    pass


def _record_disk_event(record, phase, **details):
    if record is not None:
        try:
            record(phase, **details)
        except Exception as error:
            # Evidence is not authority and must not replace the primary error.
            return {"type": type(error).__name__, "errno": getattr(error, "errno", None)}
    return None


@contextmanager
def _owned_disk(daemon, disk, journal, *, quiescence, role, record=None, writable=False):
    if not __debug__:
        raise RuntimeError("RTM-074 refuses optimized Python")
    assert compatibility_root_owned_by(daemon.work, daemon.binary)
    assert not quiescence["remaining_matched_pids"] and not _matched_pids(daemon)
    root = daemon.root.resolve(strict=True)
    relative = str(disk.resolve(strict=True).relative_to(root))
    assert not disk.is_symlink(), relative
    descriptor = os.open(disk, (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC)
    started = time.monotonic()

    def validate():
        info = os.fstat(descriptor)
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1, relative
        assert journal["diskIdentity"] == _stable_file_identity(descriptor), relative
        assert info.st_size == journal["expectedSize"], relative
        visible = disk.lstat()
        assert stat.S_ISREG(visible.st_mode) and (visible.st_dev, visible.st_ino) == (
            info.st_dev, info.st_ino), relative
        assert disk.resolve(strict=True).is_relative_to(root), relative

    def diagnose(phase):
        details = {"disk": relative, "role": role,
                   "duration_seconds": time.monotonic() - started,
                   "cleanup_matched_pids": quiescence["cleanup_matched_pids"]}
        for name, capture in (("remaining_matched_pids", lambda: _matched_pids(daemon)),
                              ("lsof", lambda: _disk_holders(disk))):
            try:
                details[name] = capture()
            except Exception as error:
                details[name] = {"type": type(error).__name__, "errno": getattr(error, "errno", None)}
        records = details.get("lsof", {}).get("records", "")
        details["holder_processes"] = compatibility_disk_holder_diagnostics(records, daemon.binary)
        evidence_error = _record_disk_event(record, phase, **details)
        if evidence_error is not None:
            details["evidence_error"] = evidence_error
        return details

    try:
        validate()  # Reject wrong ownership/identity before even attempting a claim.
        contended = False
        while True:
            validate()
            if contended and time.monotonic() - started >= 10.0:
                details = diagnose("disk-claim-timeout")
                raise _DiskClaimTimeout(f"exclusive disk claim timed out: {json.dumps(details)}")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as error:
                if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EINTR):
                    raise
                if not contended:
                    diagnose("disk-claim-contention")
                    contended = True
                time.sleep(min(0.05, max(0.0, 10.0 - (time.monotonic() - started))))
        validate()  # A pathname replacement while waiting must never authorize IO.
        assert not _matched_pids(daemon), relative
        if contended:
            _record_disk_event(record, "disk-claim-acquired", disk=relative, role=role,
                               duration_seconds=time.monotonic() - started)
        yield descriptor  # No byte read or write is permitted before this point.
    finally:
        os.close(descriptor)


def _host_uuid(daemon, disk, journal, *, quiescence, role, record=None):
    with _owned_disk(daemon, disk, journal, quiescence=quiescence, role=role, record=record) as descriptor:
        assert os.pread(descriptor, 2, 1080) == b"\x53\xef", disk
        value = str(uuid.UUID(bytes=os.pread(descriptor, 16, 1128)))
        assert value == journal["ext4UUID"], (disk, value, journal)
        return value


@pytest.mark.compat("RTM-074")
def test_disk_bootstrap_preserves_identity_and_refuses_corrupt_owned_disk(client, daemon):
    if not __debug__:
        raise RuntimeError("RTM-074 refuses optimized Python")
    owner = uuid.uuid4().hex
    labels = {"dev.cengine.compat": "true", OWNER_LABEL: owner}
    evidence = Path(__file__).resolve().parents[2] / ".build/disk-initialization" / owner
    evidence.mkdir(parents=True)
    print(f"disk initialization evidence: {evidence}")
    events, container_names, volume_names, containers = [], [], [], []
    preserve_disks = False
    previous_timeout = client.api.timeout
    client.api.timeout = 180

    def record(phase, **values):
        events.append({"phase": phase, **values})
        (evidence / "evidence.json").write_text(json.dumps(events, indent=2) + "\n")

    def volume(role):
        name = f"rtm074-{role}-{owner}"
        volume_names.append(name)
        return client.volumes.create(name, labels=labels)

    def container(role, mounts, *, privileged=False):
        name = f"rtm074-{role}-{owner}"
        container_names.append(name)
        value = client.containers.create(
            ALPINE, ["sleep", "1800"], name=name, labels=labels, network_mode="none",
            mounts=mounts, privileged=privileged,
        )
        containers.append(value)
        return value

    try:
        storage_disk = daemon.root / "infrastructure/volumes.ext4"
        storage_record, storage_raw = _journal(storage_disk)
        storage_launch = _running_spec(daemon)["shimLaunchUUID"]
        assert storage_record["binding"]["shimLaunchUUID"] == storage_launch
        # Deliberately reverse lexical name order: ordinal mapping follows mounts,
        # not sorted volume names. Exactly one consumer keeps both direct ext4.
        direct = [volume("z-first"), volume("a-second")]
        target = container("direct", [
            Mount(target=path, source=value.name, type="volume", no_copy=True)
            for path, value in zip(("/first", "/second"), direct)
        ], privileged=True)
        root_disk = daemon.root / "containers" / target.id / "root.ext4"
        root_record, root_raw = _journal(root_disk)
        # Container create already booted root-only to apply the image. Workload
        # start pairs that mount-only root with two CREATED direct-volume disks.
        target.start()
        specification = _running_spec(daemon, target.id)
        assert [disk["name"] for disk in specification["volumeDisks"]] == [value.name for value in direct]
        assert Path(specification["rootDiskPath"]).resolve() == root_disk.resolve()
        disks = [root_disk] + [daemon.root / "volumes" /
                 (hashlib.sha256(value.name.encode()).hexdigest() + ".disk") / "disk.ext4" for value in direct]
        assert [Path(disk["path"]).resolve() for disk in specification["volumeDisks"]] == [
            disk.resolve() for disk in disks[1:]]
        journals = [_journal(disk) for disk in disks]
        assert journals[0] == (root_record, root_raw)
        assert journals[1][0]["binding"] == journals[2][0]["binding"]
        assert journals[1][0]["binding"]["shimLaunchUUID"] == specification["shimLaunchUUID"]
        expected = dict(zip(("/", "/first", "/second"), (entry[0] for entry in journals)))
        assert len({entry[0]["ext4UUID"] for entry in journals} | {storage_record["ext4UUID"]}) == 4
        modes = json.loads((daemon.root / "volume-storage.json").read_text())
        assert all(modes[value.name] == "block" for value in direct), modes
        record("initialized", disks=[entry[0] for entry in journals], storage=storage_record,
               guest=_observe(target, expected))

        for index, path in enumerate(expected):
            _exec(target, "sh", "-ec",
                  f"printf '%s' '{owner}-{index}' > {path.rstrip('/')}/rtm074; "
                  f"chown {1000 + index}:{1100 + index} {path}; chmod 3777 {path}; sync")
        baseline = _observe(target, expected)
        for index, path in enumerate(expected):
            assert baseline[path]["metadata"] == f"{1000 + index}:{1100 + index}:3777:2", baseline

        shared = volume("shared")
        peers = [container(f"peer-{index}", [Mount(
            target="/shared", source=shared.name, type="volume", no_copy=True,
        )]) for index in range(2)]
        # Both consumers MUST exist before first start to choose shared storage.
        for peer in peers:
            peer.start()
            record("shared-backend", container=peer.id, proof=_shared_backend(daemon, peer))
        assert json.loads((daemon.root / "volume-storage.json").read_text())[shared.name] == "shared"
        _exec(peers[0], "sh", "-ec", f"printf '%s' '{owner}-storage' > /shared/rtm074; sync")

        def preserved(phase):
            observed = _observe(target, expected)
            assert _persistent_observation(observed) == _persistent_observation(baseline), (observed, baseline)
            for index, path in enumerate(expected):
                assert _exec(target, "cat", path.rstrip("/") + "/rtm074").decode() == f"{owner}-{index}"
            for peer in peers:
                assert _exec(peer, "cat", "/shared/rtm074").decode() == owner + "-storage"
            for disk, journal in zip(disks, journals):
                assert _journal(disk) == journal, disk
            assert _journal(storage_disk) == (storage_record, storage_raw)
            boot_id = _exec(target, "cat", "/proc/sys/kernel/random/boot_id").decode().strip()
            assert uuid.UUID(boot_id).int != 0
            record(phase, boot_id=boot_id, guest=observed,
                   shared_backends=[_shared_backend(daemon, peer) for peer in peers])
            return boot_id

        boots = {preserved("first-workload-boot")}
        for index in range(2):
            target.stop(timeout=5)
            target.start()
            boot_id = preserved(f"mount-only-boot-{index + 1}")
            assert boot_id not in boots, "restart must boot a new guest, not adopt the old VM"
            boots.add(boot_id)

        for value in containers:
            value.stop(timeout=5)
        preserve_disks = True
        quiescence = _quiesce(daemon, record=record)
        for disk, (journal, _), role in zip(disks + [storage_disk], journals + [(storage_record, storage_raw)],
                                          ("root", "direct-0", "direct-1", "storage")):
            _host_uuid(daemon, disk, journal, quiescence=quiescence, role=role, record=record)
        preserve_disks = False
        daemon.start()
        assert _running_spec(daemon)["shimLaunchUUID"] != storage_launch
        for value in containers:
            value.start()
        boot_id = preserved("cold-runtime-restart")
        assert boot_id not in boots

        # Only an owned, INITIALIZED direct disk is damaged. Keep inode, length,
        # UUID, and every phase record intact: this is mount-only, never fresh.
        for value in containers:
            value.stop(timeout=5)
        preserve_disks = True
        quiescence = _quiesce(daemon, record=record)
        for disk, (journal, _), role in zip(disks + [storage_disk], journals + [(storage_record, storage_raw)],
                                          ("root", "direct-0", "direct-1", "storage")):
            _host_uuid(daemon, disk, journal, quiescence=quiescence, role=role, record=record)
        record("cold-restart-host-uuids", storage_uuid=storage_record["ext4UUID"],
               disk_uuids=[entry[0]["ext4UUID"] for entry in journals])
        corrupt_disk, (corrupt_record, _) = disks[2], journals[2]
        with _owned_disk(daemon, corrupt_disk, corrupt_record, quiescence=quiescence,
                         role="direct-1", record=record, writable=True) as descriptor:
            before = os.pread(descriptor, 4096, 0)
            assert before[1080:1082] == b"\x53\xef"
            assert os.pwrite(descriptor, b"\x00\x00", 1080) == 2
            os.fsync(descriptor)
            damaged = before[:1080] + b"\x00\x00" + before[1082:]
            assert os.pread(descriptor, 4096, 0) == damaged
        preserve_disks = False
        for attempt in range(2):
            daemon.start()
            with pytest.raises(docker.errors.APIError) as failure:
                target.start()
            assert failure.value.response.status_code in (409, 500), failure.value
            assert "disk bootstrap" in (failure.value.explanation or "").lower(), failure.value
            target.reload()
            assert not target.attrs["State"]["Running"], target.attrs["State"]
            preserve_disks = True
            quiescence = _quiesce(daemon, record=record)
            with _owned_disk(daemon, corrupt_disk, corrupt_record, quiescence=quiescence,
                             role="direct-1", record=record) as descriptor:
                assert os.pread(descriptor, 4096, 0) == damaged, "mount failure rewrote the corrupt superblock"
            for disk, journal in zip(disks + [storage_disk], journals + [(storage_record, storage_raw)]):
                assert _journal(disk) == journal, disk
            record("corrupt-mount-only-refused", attempt=attempt + 1,
                   status=failure.value.response.status_code, superblock_unchanged=True)
            preserve_disks = False
    except BaseException as error:
        if preserve_disks:
            # Mark before diagnostics: evidence IO can fail too, and both generic
            # fixture teardown and a later reset must preserve this raw-disk root.
            try:
                daemon.retain_root(reason="unsafe-disk-phase")
            except Exception as retention_error:
                # retain_root latches in memory before attempting durable IO.
                # Do not replace the primary failure or print exception secrets.
                print("disk root retention marker unavailable: "
                      f"type={type(retention_error).__name__}, "
                      f"errno={getattr(retention_error, 'errno', None)}; "
                      f"root retained in memory: {daemon.work}")
        # Capture workload stderr before owned cleanup removes the failed shim.
        # Do not copy boot/spec logs: legacy kernel arguments contain a secret.
        diagnostics = []
        client.api.timeout = 5
        for value in containers:
            try:
                value.reload()
                assert value.attrs["Config"]["Labels"].get(OWNER_LABEL) == owner
                diagnostics.append({"id": value.id, "state": value.attrs["State"],
                                    "logs": value.logs(tail=32).decode(errors="replace")[-8192:]})
            except Exception as capture_error:
                diagnostics.append({"id": value.id, "capture_error": str(capture_error)})
        client.api.timeout = previous_timeout
        capture_failure = _record_disk_event(record, "failure", error=str(error), diagnostics=diagnostics)
        if capture_failure is not None:
            print(f"disk failure evidence unavailable: {capture_failure}")
        raise
    finally:
        failed = sys.exc_info()[0] is not None
        errors = []
        try:
            # Latch preservation before quiescence until the ENTIRE raw-disk
            # phase succeeds, regardless of failure type or evidence errors.
            if not preserve_disks and (daemon.process is None or daemon.process.poll() is not None):
                daemon.start()
            # Exact preregistered names handle ambiguous create replies; labels
            # fence ownership. No pruning, forced volume removal or journal repair.
            resources = () if preserve_disks else ((container_names, client.containers, True),
                                                    (volume_names, client.volumes, False))
            for names, collection, force in resources:
                for name in reversed(names):
                    try:
                        resource = collection.get(name)
                        actual_labels = (resource.attrs["Config"]["Labels"] if force else resource.attrs["Labels"])
                        assert actual_labels.get(OWNER_LABEL) == owner, "refusing foreign resource cleanup"
                        resource.remove(force=force)
                    except docker.errors.NotFound:
                        pass
                    except Exception as error:
                        errors.append(f"{name}: {error}")
        except BaseException as error:
            errors.append(f"cleanup daemon: {error}")
        client.api.timeout = previous_timeout
        capture_failure = _record_disk_event(record, "cleanup", errors=errors,
                                            resource_cleanup_skipped=preserve_disks)
        if capture_failure is not None:
            print(f"disk cleanup evidence unavailable: {capture_failure}")
            if not failed:
                raise RuntimeError("disk cleanup evidence could not be recorded")
        if errors and not failed:
            raise AssertionError(errors)
