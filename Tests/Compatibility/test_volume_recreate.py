"""RTM-070: direct Docker API named-volume deletion/recreation (ORC-024 reduction).

No Compose or application dependency. Both consumers are created before start
for shared storage; block storage has exactly one. Uses the existing isolated
compatibility daemon/helper and bounded Alpine exec transport.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import uuid

import docker
from docker.types import Mount
import pytest

from test_volume_discovery import ALPINE, _exec
from storage_backend_proof import daemon_startup_mode, verify_backend


@pytest.mark.compat("RTM-070")
def test_named_volume_same_name_recreation_has_no_old_data(client, daemon):
    # One collected item per ledger ID; fresh resources for each backend.
    for storage in ("block", "shared"):
        _same_name_recreation(client, daemon, storage)


def _same_name_recreation(client, daemon, storage):
    owner = uuid.uuid4().hex
    name = "volume-recreate-" + owner
    owner_label = "dev.cengine.compat.recreate-owner"
    labels = {"dev.cengine.compat": "true", owner_label: owner}
    directory = Path(__file__).resolve().parents[2] / ".build/volume-hunt" / name
    directory.mkdir(parents=True)
    print(f"volume recreation evidence: {directory}")
    events, intended_names, containers = [], [], []
    old_timeout = client.api.timeout
    client.api.timeout = 60

    def record(phase, **value):
        events.append({"phase": phase, **value})
        (directory / "evidence.json").write_text(json.dumps(events, indent=2) + "\n")

    def create_consumers(generation):
        current = []
        for index in range(2 if storage == "shared" else 1):
            container_name = f"{name}-{generation}-{index}"
            intended_names.append(container_name)
            record("before-container-create", name=container_name)
            container = client.containers.create(
                ALPINE, ["sleep", "600"], name=container_name, labels=labels,
                network_mode="none",
                mounts=[Mount(target="/data", source=name, type="volume", no_copy=True)],
            )
            current.append(container)
            containers.append(container)
        for container in current:
            container.start()
            mounts = _exec(container, "cat", "/proc/self/mountinfo").decode()
            record("mounts", generation=generation, container=container.id, mounts=mounts)
            proof = verify_backend(daemon.root, storage, mounts,
                                   startup_mode=daemon_startup_mode(daemon))
            record("mount-proof", generation=generation, container=container.id, proof=proof)
        modes = json.loads((daemon.root / "volume-storage.json").read_text())
        disk = daemon.root / "volumes" / (hashlib.sha256(name.encode()).hexdigest() + ".disk") / "disk.ext4"
        record("backend", generation=generation, mode=modes.get(name), disk_exists=disk.exists())
        assert modes[name] == storage, modes
        assert disk.exists() == (storage == "block")
        return current

    try:
        record("start", image=ALPINE, storage=storage, volume=name, version=client.version())
        client.volumes.create(name, labels={**labels, "generation": "old"})
        first = create_consumers("old")
        payload = "old-dump-" + owner
        assert _exec(first[0], "sh", "-ec",
                     f"printf '%s' '{payload}' > /data/dump.rdb; sync; cat /data/dump.rdb").decode() == payload
        for container in first:
            assert _exec(container, "cat", "/data/dump.rdb").decode() == payload
        record("old-data-proved", payload=payload)
        # Even force must not destroy a live (or subsequently stopped) consumer.
        for running in (True, False):
            with pytest.raises(docker.errors.APIError) as failure:
                client.api.remove_volume(name, force=True)
            assert failure.value.response.status_code == 409
            record("in-use-denied", running=running, status=409)
            if running:
                for container in first:
                    container.stop(timeout=5)
        for container in first:
            container.remove()
            containers.remove(container)
        record("before-delete", volume=name)
        client.api.remove_volume(name)
        with pytest.raises(docker.errors.NotFound):
            client.api.inspect_volume(name)
        modes = json.loads((daemon.root / "volume-storage.json").read_text())
        assert name not in modes, modes
        record("deleted", mode_absent=True)
        recreated = client.volumes.create(name, labels={**labels, "generation": "new"})
        assert recreated.attrs["Labels"]["generation"] == "new"
        for container in create_consumers("new"):
            result = _exec(container, "sh", "-ec", "test ! -e /data/dump.rdb; echo absent")
            record("new-data-absence", container=container.id, output=result.decode())
            assert result == b"absent\n"
    except BaseException as error:
        record("failure", error=repr(error))
        raise
    finally:
        cleanup_errors = []
        # Exact preregistered names reconcile ambiguous creates; owner labels
        # prevent ever removing ambient resources. Never prune or force a volume.
        for container_name in reversed(intended_names):
            try:
                candidate = client.containers.get(container_name)
                if candidate.attrs["Config"]["Labels"].get(owner_label) != owner:
                    raise RuntimeError("refusing to remove a container with a different owner")
                candidate.remove(force=True)
            except docker.errors.NotFound:
                pass
            except Exception as error:
                cleanup_errors.append(f"{container_name}: {error}")
        try:
            candidate = client.volumes.get(name)
            if candidate.attrs["Labels"].get(owner_label) != owner:
                raise RuntimeError("refusing to remove a volume with a different owner")
            candidate.remove()
        except docker.errors.NotFound:
            pass
        except Exception as error:
            cleanup_errors.append(f"{name}: {error}")
        client.api.timeout = old_timeout
        record("cleanup", errors=cleanup_errors)
        if cleanup_errors and sys.exc_info()[0] is None:
            raise AssertionError(cleanup_errors)
