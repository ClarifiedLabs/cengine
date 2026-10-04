"""Bounded cross-VM lock-scope and simultaneous copy-up investigations.

RTM-068 records the intentional NFS `nolock` architecture gap, not distributed
locking support. RTM-069 is a correctness assertion (never an expected failure).
All readiness/control and retained evidence are outside the volume under test.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import hashlib
import io
import json
import os
import select
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import time
import uuid

import docker
import pytest

from volume_probe import ARTIFACT_ROOT, close_exec_stream, encode, fixture_identity, same_unix_endpoint, tar_bytes
from storage_backend_proof import daemon_startup_mode, mount_identity, verify_backend


_UNSETTLED_STARTS = set()  # Lifecycle truth is independent of fallible evidence writes.


class UnsettledStarts(RuntimeError):
    """No resource cleanup while lifecycle completion is unknown."""



LABELS = {"dev.cengine.compat": "true"}
LOCK_PATH = "/data/g00/f000"
LINUX_EAGAIN = 11  # Linux errno, not the macOS runner's EAGAIN (35).
# Fixed DGN-003 completion calibration, identical for Docker/block/shared.
START_SDK_TIMEOUT = 120
START_WALL_TIMEOUT = 130
SNAPSHOT_HOST_TIMEOUT = 60


def _layer(binary):
    """256 small files, eight directories, varied numeric metadata; no builder."""
    output, expected = io.BytesIO(), {}
    entries = [("probe", binary, 0, 0, 0o755), ("data", None, 10001, 20000, 0o750)]
    for group in range(8):
        entries.append((f"data/g{group:02}", None, 10001 + group, 20000 + group, 0o750))
        for index in range(32):
            number = group * 32 + index
            entries.append((f"data/g{group:02}/f{number:03}",
                            (f"seed-{number:03}\n" * 8).encode(),
                            10001 + group, 20000 + group, 0o640 if index % 2 else 0o600))
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data, uid, gid, mode in entries:
            info = tarfile.TarInfo(name)
            info.uid, info.gid, info.mode = uid, gid, mode
            if data is None:
                info.type = tarfile.DIRTYPE
            else:
                info.size = len(data)
            archive.addfile(info, None if data is None else io.BytesIO(data))
            if name == "data" or name.startswith("data/"):
                value = {"uid": uid, "gid": gid, "mode": mode,
                         "type": "directory" if data is None else "file"}
                if data is not None:
                    value["sha256"] = hashlib.sha256(data).hexdigest()
                expected["." if name == "data" else name[5:]] = value
    return output.getvalue(), expected


@pytest.fixture(scope="module")
def concurrency_fixture(tmp_path_factory):
    binary = tmp_path_factory.mktemp("volume-lock") / "probe"
    subprocess.run(
        ["go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary),
         str(Path(__file__).parent / "fixtures" / "volume-lock.go")],
        env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOWORK": "off"},
        check=True, capture_output=True, timeout=120,
    )
    layer, expected = _layer(binary.read_bytes())
    config = encode({"architecture": "arm64", "os": "linux",
                     "config": {"Cmd": ["/probe", "serve", "/lock.sock"]},
                     "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}})
    digest = hashlib.sha256(config).hexdigest()
    # Reuse the discovery archive's verified logical-tag convention. Docker's
    # containerd engine ID is not necessarily the saved config digest.
    tag = f"compat-volume-probe:{digest}"
    archive = tar_bytes([
        (digest + ".json", config, 0o644), ("layer.tar", layer, 0o644),
        ("manifest.json", encode([{"Config": digest + ".json", "RepoTags": [tag],
                                  "Layers": ["layer.tar"]}]), 0o644),
    ])
    return archive, tag, expected


def _record(directory, value):
    with (directory / "events.jsonl").open("a") as output:
        output.write(encode(value).decode() + "\n")
        output.flush()
        os.fsync(output.fileno())


def _exec(container, directory, *arguments):
    """Scratch-safe exec: guest watchdog plus absolute raw Docker socket deadline."""
    api = container.client.api
    command = ["/probe", *arguments]
    _record(directory, {"phase": "exec-before", "container": container.id, "command": command})
    exec_id = api.exec_create(container.id, command, stdout=True, stderr=True)["Id"]
    stream = api.exec_start(exec_id, socket=True)
    raw = getattr(stream, "_sock", stream)
    data, deadline = bytearray(), time.monotonic() + 30
    try:
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "exec stream deadline exceeded"
            raw.settimeout(remaining)
            chunk = raw.recv(8192)
            if not chunk:
                break
            data.extend(chunk)
            assert len(data) <= 131072, "unbounded fixture output"
    finally:
        close_exec_stream(stream)
        _record(directory, {"phase": "exec-wire", "id": exec_id, "wire_hex": data.hex()})
    output = bytearray()
    while data:
        assert len(data) >= 8, "truncated Docker exec header"
        channel, length = struct.unpack(">BxxxI", data[:8])
        assert channel in (1, 2) and len(data) >= length + 8, "invalid Docker exec frame"
        output.extend(data[8:8 + length])
        del data[:8 + length]
    inspected = api.exec_inspect(exec_id)
    _record(directory, {"phase": "exec-after", "inspect": inspected,
                        "output": output.decode(errors="replace")})
    assert inspected["ExitCode"] == 0, output.decode(errors="replace")
    return json.loads(output)


def _control(container, directory, op, kind=""):
    return _exec(container, directory, "request", "/lock.sock",
                 encode({"op": op, "kind": kind, "path": LOCK_PATH}).decode())


def _fence_start_cleanup(daemon, client, directory, previous_timeout, names, volume, owner):
    client.api.timeout = previous_timeout
    if daemon is not None:
        daemon._retain_root = True  # Latch before marker/fsync can fail.
    try:
        if daemon is not None:
            daemon.retain_root(reason="cleanup-incomplete")
        _record(directory, {"phase": "cleanup-fenced", "containers": names,
                            "volume": volume, "owner": owner,
                            "reason": "start completion unknown; owned resources retained"})
    finally:
        raise UnsettledStarts("cleanup fenced; start completion unknown")


@contextmanager
def _case(client, daemon, fixture, label, consumers, command=None):
    archive, image, _ = fixture
    directory = ARTIFACT_ROOT / ("concurrency-" + label + "-" + uuid.uuid4().hex)
    directory.mkdir(parents=True)
    print(f"volume concurrency artifacts: {directory}")
    (directory / "fixture.tar").write_bytes(archive)
    (directory / "fixture.json").write_bytes(encode({
        "image": image, "archive_sha256": hashlib.sha256(archive).hexdigest(),
    }))
    containers, volume, cleanup_errors = [], None, []
    intended_containers, intended_volume = [], None
    owner = uuid.uuid4().hex
    previous_timeout = client.api.timeout
    client.api.timeout = 45  # Query/cleanup HTTP calls; owned start workers have a separate bound.
    try:
        tag, config, digest = fixture_identity(archive, image)
        client.images.load(archive)
        inspected = client.images.get(tag).attrs
        _record(directory, {"phase": "image", "config_sha256": digest, "inspect": inspected,
                            "version": client.version()})
        assert inspected["Os"] == config["os"] and inspected["Architecture"] == config["architecture"]
        assert inspected["RootFS"] == {"Type": "layers", "Layers": config["rootfs"]["diff_ids"]}
        assert all(inspected["Config"].get(key) == value for key, value in config["config"].items())
        name = "volume-concurrency-" + owner
        labels = {**LABELS, "dev.cengine.compat.concurrency-owner": owner}
        intended_volume = name
        _record(directory, {"phase": "before-create", "volume": name})
        volume = client.volumes.create(name, labels=labels)
        assert volume.attrs.get("Labels", {}).get("dev.cengine.compat.concurrency-owner") == owner
        # All consumers are known before either start, including initialization.
        for index in range(consumers):
            container_name = f"{name}-{index}"
            intended_containers.append(container_name)
            _record(directory, {"phase": "before-container-create", "name": container_name})
            container = client.containers.create(
                tag, command=command, name=container_name, network_mode="none", labels=labels,
                volumes={volume.name: {"bind": "/data", "mode": "rw"}},
            )
            containers.append(container)
            _record(directory, {"phase": "create", "container": container.id, "volume": volume.name})
        yield directory, containers, volume
    except BaseException as error:
        _record(directory, {"phase": "failure", "error": repr(error)})
        raise
    finally:
        if directory in _UNSETTLED_STARTS:
            _fence_start_cleanup(daemon, client, directory, previous_timeout,
                                 intended_containers, intended_volume, owner)
        # Reconcile exact pre-registered names after ambiguous create timeouts.
        # Never discover or remove another test's resources by broad label search.
        known_ids = {container.id for container in containers}
        for name in intended_containers:
            try:
                candidate = client.containers.get(name)
                assert candidate.attrs.get("Config", {}).get("Labels", {}).get(
                    "dev.cengine.compat.concurrency-owner") == owner
                if candidate.id not in known_ids:
                    containers.append(candidate)
                    known_ids.add(candidate.id)
            except docker.errors.NotFound:
                pass
            except Exception as error:
                cleanup_errors.append(f"reconcile container {name}: {error}")
        if volume is None and intended_volume is not None:
            try:
                candidate = client.volumes.get(intended_volume)
                assert candidate.attrs.get("Labels", {}).get("dev.cengine.compat.concurrency-owner") == owner
                volume = candidate
            except docker.errors.NotFound:
                pass
            except Exception as error:
                cleanup_errors.append(f"reconcile volume {intended_volume}: {error}")
        # Release control owners BEFORE any remove; even an assertion or stream
        # deadline must not leave intentional locks held during cleanup.
        for container in containers:
            if command is None:
                try:
                    result = _control(container, directory, "release")
                    assert result == {"errno": 0}, result
                except Exception as error:
                    cleanup_errors.append(f"release {container.id}: {error}")
                    try:
                        container.kill()  # Kernel closes owner FDs before removal.
                    except Exception as kill_error:
                        cleanup_errors.append(f"kill owner {container.id}: {kill_error}")
            try:
                container.reload()
                _record(directory, {"phase": "final-inspect", "inspect": container.attrs})
                (directory / f"{container.id}.log").write_bytes(container.logs(tail=1000))
            except Exception as error:
                cleanup_errors.append(f"evidence {container.id}: {error}")
        if daemon is not None:
            try:
                with daemon.log_path.open("rb") as source:
                    source.seek(max(0, source.seek(0, os.SEEK_END) - 262144))
                    (directory / "daemon.log").write_bytes(source.read(262144))
            except Exception as error:
                cleanup_errors.append(f"daemon evidence: {error}")
        for container in reversed(containers):
            try:
                container.remove(force=True)
            except Exception as error:
                cleanup_errors.append(f"remove {container.id}: {error}")
        if volume is not None:
            try:
                volume.reload()
                assert volume.attrs.get("Labels", {}).get("dev.cengine.compat.concurrency-owner") == owner
                volume.remove()  # Never prune, force a volume removal or delete ambient resources.
            except Exception as error:
                cleanup_errors.append(f"volume cleanup: {error}")
        client.api.timeout = previous_timeout
        _record(directory, {"phase": "cleanup", "errors": cleanup_errors})
        if cleanup_errors and sys.exc_info()[0] is None:
            raise AssertionError(f"cleanup failed; {directory}: {cleanup_errors}")


def _backend(daemon, volume, expected, directory):
    if daemon is not None:
        modes = json.loads((daemon.root / "volume-storage.json").read_text())
        _record(directory, {"phase": "backend", "volume": volume.name, "modes": modes})
        assert modes[volume.name] == expected, modes


def _locking(client, daemon, fixture, label, shared, peer_errno):
    with _case(client, daemon, fixture, label, 2 if shared else 1) as (directory, containers, volume):
        for container in containers:
            _simultaneous_start([container], directory)
            assert _control(container, directory, "status") == {"held": False}
        _backend(daemon, volume, "shared" if shared else "block", directory)
        proofs = []
        for container in containers:
            text = _exec(container, directory, "mountinfo", "/data")
            proof = verify_backend(daemon.root, "shared" if shared else "block", text,
                                   startup_mode=daemon_startup_mode(daemon)) if daemon is not None else {
                                       "mode": "reference", "mount": mount_identity(text)}
            _record(directory, {"phase": "backend-proof", "container": container.id, "proof": proof})
            proofs.append(proof)
            if daemon is not None and shared and proof["mode"] == "legacy":
                assert {"nolock", "local_lock=all"}.intersection(proof["mount"]["super_options"]), proof
        for kind in ("flock", "fcntl"):
            try:
                assert _control(containers[0], directory, "lock", kind) == {"errno": 0}
                # Distinct exec process in the owner's VM is the positive control.
                assert _exec(containers[0], directory, "try", kind, LOCK_PATH) == {"errno": LINUX_EAGAIN}
                if shared:
                    peer = _control(containers[1], directory, "lock", kind)
                    _record(directory, {"phase": "lock-scope", "kind": kind, "peer": peer,
                                        "classification": ("client-local managed FUSE locking" if proofs[0]["mode"] == "lifecycle"
                                                           else "intentional nolock gap") if peer_errno == 0
                                        else "Docker local volume contention"})
                    assert peer == {"errno": peer_errno}
                    if peer_errno == 0:
                        # BOTH servers now hold locks: local contention still works.
                        assert _control(containers[0], directory, "status") == {"held": True}
                        assert _exec(containers[1], directory, "try", kind, LOCK_PATH) == {"errno": LINUX_EAGAIN}
            finally:
                for container in containers:
                    assert _control(container, directory, "release") == {"errno": 0}
            for container in containers:
                assert _exec(container, directory, "try", kind, LOCK_PATH) == {"errno": 0}


def _start_marker(process, marker, deadline):
    """Read only the exact, bounded protocol bytes, tolerating partial pipe reads."""
    received = bytearray()
    while len(received) < len(marker):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UnsettledStarts("start worker protocol deadline exceeded")
        ready, _, _ = select.select([process.stdout], [], [], remaining)
        if not ready:
            raise UnsettledStarts("start worker protocol deadline exceeded")
        chunk = os.read(process.stdout.fileno(), len(marker) - len(received))
        received.extend(chunk)
        if not chunk or not marker.startswith(received):
            raise UnsettledStarts("invalid start worker marker")


def _simultaneous_start(containers, directory):
    # Independent, reapable SDK processes replace unkillable start threads.
    processes, errors = [], []
    _UNSETTLED_STARTS.add(directory)  # Before the first child or fallible journal write.
    deadline = time.monotonic() + START_WALL_TIMEOUT
    try:
        if not containers:
            raise UnsettledStarts("no owned start workers")
        for container in containers:
            socket_path = container.client.api.adapters["http+docker://"].socket_path
            processes.append(subprocess.Popen(
                [sys.executable, "-B", __file__, "--owned-start", "unix://" + socket_path,
                 container.client.api._version, container.id], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL))
            os.set_blocking(processes[-1].stdout.fileno(), False)
        _record(directory, {"phase": "start-barrier", "containers": [c.id for c in containers],
                            "workers": [p.pid for p in processes],
                            "sdk_timeout": START_SDK_TIMEOUT, "wall_timeout": START_WALL_TIMEOUT})
        # Both clients must reach admission before either starts. Import/client
        # setup and HTTP completion share this one direct-child wall deadline.
        for process in processes:
            _start_marker(process, b"ready\n", deadline)
        for process in processes:
            process.stdin.write(b"start\n")
            process.stdin.close()
        for process in processes:
            _start_marker(process, b"started\n", deadline)  # Emitted only after successful HTTP.
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                raise UnsettledStarts("start worker failed or exceeded deadline")
            # Nonblocking, one byte only: trailing output or an inherited live
            # writer is uncertainty, never an unbounded read/communicate buffer.
            if os.read(process.stdout.fileno(), 1) != b"":
                raise UnsettledStarts("unexpected start worker output")
    except BaseException as error:
        errors.append(repr(error))
    finally:
        for process in processes:
            try:
                if process.poll() is None:
                    process.kill()  # Exact direct child; no global PID search/signals.
                process.wait()  # Actual reap; a five-second timeout is not death proof.
            except BaseException as error:
                errors.append(repr(error))
            for stream in (process.stdin, process.stdout):
                try:
                    if stream is not None:
                        stream.close()
                except BaseException as error:
                    errors.append(repr(error))
        # Evidence failure must also leave the lifecycle fence latched.
        _record(directory, {"phase": "start-results", "workers": [p.pid for p in processes],
                            "statuses": [p.returncode for p in processes],
                            "failed": bool(errors), "errors": errors})
    if errors:
        raise UnsettledStarts("start completion unknown; cleanup fenced: " + "; ".join(errors))
    _UNSETTLED_STARTS.discard(directory)  # Positive HTTP, actual reap AND recorded result.


def _owned_start(endpoint, version, container_id):
    # api_deadline clamps to 45s: do not use it for this calibrated start call.
    # The parent's direct-process deadline also bounds imports and SDK/syscalls.
    with closing(docker.DockerClient(base_url=endpoint, version=version,
                                    timeout=START_SDK_TIMEOUT)) as worker:
        print("ready", flush=True)
        if sys.stdin.buffer.readline(16) != b"start\n":
            raise SystemExit("missing parent start barrier")
        worker.api.start(container_id)
        print("started", flush=True)


def _initialization(client, daemon, fixture, label):
    with _case(client, daemon, fixture, label, 2, ["/probe", "snapshot", "/data"]) as (directory, containers, volume):
        for iteration in range(2):  # Same named volume survives a workload restart.
            _simultaneous_start(containers, directory)
            results = []
            for container in containers:
                result = container.wait(timeout=SNAPSHOT_HOST_TIMEOUT)
                container.reload()
                output = container.logs()
                _record(directory, {"phase": "initialization-exit", "iteration": iteration,
                                    "container": container.id, "wait": result,
                                    "state": container.attrs["State"], "output": output.decode(errors="replace")})
                results.append((result, container.attrs["State"], output))
            _backend(daemon, volume, "shared", directory)
            # Inspect BOTH exits before asserting complete tree equality, including
            # root/dir/file numeric metadata and no hidden transaction/staging names.
            for container, (result, state, output) in zip(containers, results):
                text = json.loads(output.splitlines()[-2])  # Logs include earlier executions.
                proof = verify_backend(daemon.root, "shared", text,
                                       startup_mode=daemon_startup_mode(daemon)) if daemon is not None else {
                                           "reference": "Docker local volume", "mount": mount_identity(text)}
                _record(directory, {"phase": "backend-proof", "iteration": iteration,
                                    "container": container.id, "proof": proof})
                assert result["StatusCode"] == 0 and state["ExitCode"] == 0 and state["Status"] == "exited", state
                assert json.loads(output.splitlines()[-1]) == fixture[2], f"partial/corrupt seed; {directory}"


@pytest.mark.compat("RTM-068")
def test_shared_volume_locking_is_client_local(daemon, client, concurrency_fixture):
    _locking(client, daemon, concurrency_fixture, "direct-lock", False, LINUX_EAGAIN)
    _locking(client, daemon, concurrency_fixture, "shared-lock", True, 0)


@pytest.mark.compat("RTM-069")
def test_shared_volume_simultaneous_initialization(daemon, client, concurrency_fixture):
    _initialization(client, daemon, concurrency_fixture, "initialization")


@pytest.mark.oracle
@pytest.mark.skipif(not os.environ.get("DOCKER_REFERENCE_HOST"), reason="requires explicit DOCKER_REFERENCE_HOST")
@pytest.mark.compat("ORC-025")
def test_volume_lock_scope_against_reference(daemon, client, concurrency_fixture):
    host = os.environ["DOCKER_REFERENCE_HOST"]
    assert not same_unix_endpoint(host, daemon.socket), "reference must differ from cengine"
    with closing(docker.DockerClient(base_url=host, timeout=45, version="1.45")) as reference:
        version = reference.version()
        assert version.get("Platform", {}).get("Name", "").lower() != "cengine", version
        assert version.get("Os") == "linux" and version.get("Arch") in ("arm64", "aarch64"), version
        # Same immutable fixture on reference FIRST. No xfail or normalization of
        # the real locking difference; initialization must succeed on both engines.
        _locking(reference, None, concurrency_fixture, "reference-lock", True, LINUX_EAGAIN)
        _initialization(reference, None, concurrency_fixture, "reference-initialization")
        _locking(client, daemon, concurrency_fixture, "oracle-cengine-lock", True, 0)
        _initialization(client, daemon, concurrency_fixture, "oracle-cengine-initialization")


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "--owned-start":
        raise SystemExit("only the owned start worker may execute this module")
    _owned_start(sys.argv[2], sys.argv[3], sys.argv[4])
