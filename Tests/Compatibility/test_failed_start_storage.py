"""RTM-077: failed workload launch must not delete an existing writable root.

Rename only this disposable container's configured /bin/sh; never change an
image layer, /bin/busybox, or a volume. Host raw-disk access is read-only, after
owned quiescence and an exclusive claim via RTM-074. No repair or broad reset.

The stopped-root archive API is not required. Userdata and ownership/mode are
verified before stopping; after failures, same inode/size, all initialization
journals, and actual ext4 UUID are checked. These host checks detect root
replacement/deletion, not in-place userdata or filesystem-metadata corruption.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

import docker
import pytest

from harness import compatibility_root_owned_by
from test_disk_initialization import _host_uuid, _journal, _quiesce, _record_disk_event
from test_volume_discovery import ALPINE, _exec


OWNER_LABEL = "dev.cengine.compat.failed-start-storage-owner"
ENTRY = "/bin/sh"
ENTRYPOINT = [ENTRY, "-ec", "sleep 1800"]
DISABLED_ENTRY = "/rtm077-entry.disabled"
DATA_DIRECTORY = "rtm077-data"


def _root_snapshot(daemon, container_id):
    """Metadata only: no raw bytes are read while a VM might hold the disk."""
    assert compatibility_root_owned_by(daemon.work, daemon.binary)
    root = daemon.root.resolve(strict=True)
    directory = daemon.root / "containers" / container_id
    assert directory.resolve(strict=True).is_relative_to(root)
    directory_info = directory.lstat()
    assert stat.S_ISDIR(directory_info.st_mode) and directory_info.st_uid == os.getuid()
    disk = directory / "root.ext4"
    info = disk.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
    journal, raw = _journal(disk)
    return {"directory": (directory_info.st_dev, directory_info.st_ino),
            "disk": (info.st_dev, info.st_ino, info.st_size), "journal": journal, "raw": raw}


def _owned_container(client, name, owner, container_id=None):
    value = client.containers.get(name)
    assert value.name == name, "refusing nonexact container name"
    assert value.attrs["Config"]["Labels"].get(OWNER_LABEL) == owner, "refusing foreign container"
    if container_id is not None:
        assert value.id == container_id, "container identity changed"
    return value


def _stopped(container):
    container.reload()
    state = container.attrs["State"]
    assert state["Status"] == "exited", state
    assert not any(state[key] for key in ("Running", "Paused", "Restarting", "Dead")), state
    assert state["Pid"] == 0, state
    # The failure targets the effective executable, not Config's presentation
    # of the separate image/container entrypoint and command defaults.
    assert container.attrs["Path"] == ENTRY
    assert container.attrs["Args"] == ENTRYPOINT[1:]
    return {key: state[key] for key in ("Status", "Running", "Pid", "ExitCode")}


def _retain(daemon):
    try:
        daemon.retain_root(reason="unsafe-disk-phase")
    except Exception as error:
        # The fixture latches in memory before marker IO; never mask the cause.
        print("failed-start root retention marker unavailable: "
              f"type={type(error).__name__}, errno={getattr(error, 'errno', None)}; "
              f"root retained in memory: {daemon.work}")


@pytest.mark.compat("RTM-077")
def test_failed_start_preserves_writable_root_and_metadata(client, daemon):
    if not __debug__:
        raise RuntimeError("RTM-077 refuses optimized Python")
    owner = uuid.uuid4().hex
    name = "rtm077-" + owner
    labels = {"dev.cengine.compat": "true", OWNER_LABEL: owner}
    payload = ("rtm077-userdata-" + owner + "\n").encode()
    evidence = Path(__file__).resolve().parents[2] / ".build/failed-start-storage" / owner
    evidence.mkdir(parents=True)
    print(f"failed-start storage evidence: {evidence}")
    events = []
    preserve_disks = False
    previous_timeout = client.api.timeout
    client.api.timeout = 180

    def record(phase, **values):
        events.append({"phase": phase, **values})
        encoded = json.dumps(events, indent=2) + "\n"
        assert len(events) <= 32 and len(encoded.encode()) <= 64 * 1024, "evidence bound exceeded"
        (evidence / "evidence.json").write_text(encoded)

    try:
        # A create may commit disk state before its API reply is lost. Retain
        # even that ambiguous outcome; only verified explicit removal clears it.
        preserve_disks = True
        target = client.containers.create(
            ALPINE, [], entrypoint=ENTRYPOINT, name=name, labels=labels,
            network_mode="none",
        )
        target = _owned_container(client, name, owner, target.id)
        baseline = _root_snapshot(daemon, target.id)  # create already prepared the root
        root_directory = daemon.root / "containers" / target.id
        root_disk = root_directory / "root.ext4"
        record("created", container_id=target.id, directory=baseline["directory"],
               disk=baseline["disk"], journal=baseline["journal"],
               journal_sha256={phase: hashlib.sha256(raw).hexdigest()
                               for phase, raw in baseline["raw"].items()})
        target.start()
        # BusyBox remains intact so exec still works after /bin/sh is renamed.
        # The image's sh may be a relative symlink: require the renamed entry to
        # exist as a file or symlink, not to resolve from its new directory.
        _exec(target, "/bin/busybox", "sh", "-ec", f"""
            mkdir /{DATA_DIRECTORY}
            printf '%s\\n' 'rtm077-userdata-{owner}' > /{DATA_DIRECTORY}/payload
            chown 1042:1043 /{DATA_DIRECTORY} /{DATA_DIRECTORY}/payload
            chmod 2750 /{DATA_DIRECTORY}
            chmod 640 /{DATA_DIRECTORY}/payload
            test -x /bin/busybox
            test ! -e {DISABLED_ENTRY}
            test ! -L {DISABLED_ENTRY}
            mv {ENTRY} {DISABLED_ENTRY}
            test ! -e {ENTRY}
            test ! -L {ENTRY}
            test -L {DISABLED_ENTRY} || test -f {DISABLED_ENTRY}
            sync
        """)
        guest_check = ["/bin/busybox", "sh", "-ec", f"cat /{DATA_DIRECTORY}/payload; "
                       f"stat -c '%u:%g:%a' /{DATA_DIRECTORY} /{DATA_DIRECTORY}/payload"]
        expected_guest = payload + b"1042:1043:2750\n1042:1043:640\n"
        assert _exec(target, *guest_check) == expected_guest
        record("initial-userdata-verified", payload_sha256=hashlib.sha256(payload).hexdigest(),
               directory_metadata="1042:1043:2750", payload_metadata="1042:1043:640",
               post_failure_userdata_read=False,
               limitation="host identity/journal/UUID checks do not detect in-place userdata corruption")
        target.stop(timeout=5)
        _stopped(target)
        assert _root_snapshot(daemon, target.id) == baseline, "initial run replaced writable root"

        for attempt in range(2):
            with pytest.raises(docker.errors.APIError) as failure:
                target.start()
            status = getattr(failure.value.response, "status_code", None)
            assert status in (400, 409, 500), "expected an HTTP start refusal"
            explanation = (failure.value.explanation or "").lower()
            missing_entry = ENTRY in explanation and any(fragment in explanation for fragment in (
                "no such file", "not found", "does not exist",
            ))
            # LookPath errors occur in the workload child; the supervisor's
            # readiness pipe reports EOF, not that child's missing-path detail.
            assert missing_entry or "workload failed before becoming ready" in explanation, (
                "expected a workload launch refusal after removing the owned entrypoint"
            )
            state = _stopped(target)
            assert _root_snapshot(daemon, target.id) == baseline, "failed start replaced writable root"
            record("failed-start-preserved", attempt=attempt + 1, status=status, state=state)

            # Daemon restart alone can adopt live shims. Stop the owned runtime,
            # then claim the disk read-only before reading magic/UUID (never write).
            quiescence = _quiesce(daemon, record=record)
            observed_uuid = _host_uuid(daemon, root_disk, baseline["journal"], quiescence=quiescence,
                                       role="failed-start-root", record=record)
            assert observed_uuid == baseline["journal"]["ext4UUID"]
            assert _root_snapshot(daemon, target.id) == baseline
            record("cold-root-verified", attempt=attempt + 1, uuid=observed_uuid)
            daemon.start()
            target = _owned_container(client, name, owner, target.id)
            _stopped(target)
            assert _root_snapshot(daemon, target.id) == baseline, "cold restart replaced writable root"

        # No stopped-root archive GET/PUT or executable restoration: those are
        # not prerequisites of the cleanup regression. Explicit removal is the
        # only operation here authorized to delete this container's root.
        target = _owned_container(client, name, owner, target.id)
        target.remove()
        assert not os.path.lexists(root_directory), "explicit remove retained container root directory"
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(target.id)
        preserve_disks = False
        record("explicit-remove-verified")
    except BaseException as error:
        if preserve_disks:
            _retain(daemon)
        # No argv, daemon logs, boot specs, or entire disk copies in diagnostics.
        _record_disk_event(record, "failure", error_type=type(error).__name__,
                           errno=getattr(error, "errno", None), root_retained=preserve_disks)
        raise
    finally:
        # Success already verified removal of the exact original ID. A second
        # name-only cleanup could delete a same-name replacement; never retry it.
        # Unsafe failures deliberately leave the owned runtime/root retained.
        client.api.timeout = previous_timeout
