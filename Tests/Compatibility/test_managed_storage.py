"""RTM-078 initial managed VM smoke; no fault injection or power-loss claim.

Future attended run: make test-compat
COMPAT_ARGS='Tests/Compatibility/test_managed_storage.py -x'.
The 90s process-supervised campaign starts after daemon fixture setup.
Work ends at 72s; cleanup at 85s; outer kill/reap/retention ends at 90s.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

import docker
import pytest

from managed_storage import (OWNER, digest, image_archive, initialize_evidence, names, owned, public_state,
                             receipt_proof, require, snapshot_proof, step_evidence, error_evidence, write_private_error)
from volume_probe import REPO_ROOT, close_exec_stream, read_bounded

SOURCE = Path(__file__).parent / "fixtures/managed-storage.go"


@pytest.fixture
def image_cache(tmp_path):
    # Reject retired selectors before daemon startup.
    from conftest import managed_storage_arguments
    managed_storage_arguments(os.environ)
    # Override the session cache: this scratch-only case never seeds registry images.
    return tmp_path


@pytest.fixture(autouse=True)
def verify_docker_cli_target():
    # This case never invokes the Docker CLI. Override the global CLI fixture,
    # whose client dependency seeds registry images and creates an extra network.
    # run_campaign verifies GitCommit over its own explicit Unix-socket client.
    pass


def retain_failure(daemon, deadline):
    # No parent filesystem I/O: the latch protects generic fixture teardown even
    # if the bounded marker writer hits ENOSPC or a wedged fsync.
    daemon._retain_root = True
    if time.monotonic() >= deadline - 1:
        return
    command = [sys.executable, "-B", __file__, "--retain", str(daemon.binary), str(daemon.work)]
    marker = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        marker.wait(timeout=max(0.001, min(1, deadline - 1 - time.monotonic())))
    except BaseException:
        os.killpg(marker.pid, signal.SIGKILL)
        marker.wait(timeout=max(0.001, deadline - time.monotonic()))
        raise


@pytest.mark.compat("RTM-078")
def test_initial_managed_storage(daemon):
    # The separate process bounds blocking local file I/O as well as HTTP. Its
    # group owns only this campaign and any offline compiler descendants.
    started = time.monotonic()
    command = [sys.executable, "-B", __file__, "--worker", str(daemon.binary),
               str(daemon.root), str(daemon.socket), str(daemon.work), str(started)]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        status = process.wait(timeout=max(0.001, started + 86 - time.monotonic()))
    except BaseException:
        # The live, unreaped group leader pins the exact-owned process-group ID.
        daemon._retain_root = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=max(0.001, min(1, started + 87 - time.monotonic())))
        finally:
            retain_failure(daemon, started + 90)
        raise
    if status != 0:
        retain_failure(daemon, started + 90)
        pytest.fail("RTM-078 worker failed; public artifacts: .build/managed-storage-smoke; root retained")


def run_campaign(daemon, started):
    from conftest import expected_git_commit, managed_storage_arguments
    from test_volume_workflows import _campaign as campaign

    managed_storage_arguments(os.environ)
    work_deadline, final_deadline = started + 72, started + 85
    plan = names(uuid.uuid4().hex)
    # The plan file, its new directory entry, and every newly created ancestor
    # are durable before constructing the SDK client or making any engine call.
    directory, used = initialize_evidence(REPO_ROOT, plan["owner"], {
        "phase": "plan", "plan": plan, "seconds": 90, "source_sha256": digest(SOURCE.read_bytes())})

    def record(phase, **value):
        nonlocal used
        raw = (json.dumps({"phase": phase, **value}, sort_keys=True) + "\n").encode()
        limit = 4 * 1024 * 1024 - (0 if phase in ("failure", "cleanup") else 65536)
        require(used + len(raw) <= limit, "artifact bound")
        fd = os.open(directory / "evidence.jsonl", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "ab") as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        used += len(raw)

    active_step = step_evidence("client-connect")
    record("step", **active_step)
    client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.47", timeout=15)
    failed = False

    def begin(step, *, consumer=None, command=None):
        nonlocal active_step
        active_step = step_evidence(step, consumer=consumer, command=command)
        record("step", **active_step)

    def failure_details(error):
        return error_evidence(error, api_error=isinstance(error, docker.errors.APIError))[0]

    def call(operation, *args, step, consumer=None, deadline=work_deadline, **kwargs):
        begin(step, consumer=consumer)
        result = campaign.api_call(client, deadline, operation, *args, **kwargs)
        record("step-complete", **active_step)
        return result

    def observe(container, command, **expected):
        require(command in {"snapshot", "open", "unlink", "write", "close"}, "probe command")
        consumer = next(index for index, item in enumerate(containers) if item.id == container.id)
        with campaign.api_deadline(client, min(work_deadline, time.monotonic() + 5)):
            begin("exec-create", consumer=consumer, command=command)
            exec_id = client.api.exec_create(container.id, ["/probe", command], stdout=True, stderr=True)["Id"]
            begin("exec-start", consumer=consumer, command=command)
            stream = client.api.exec_start(exec_id, socket=True)
            raw_socket = getattr(stream, "_sock", stream)
            data = bytearray()
            deadline = min(work_deadline, time.monotonic() + 4)
            try:
                begin("exec-read", consumer=consumer, command=command)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("managed exec deadline")
                    raw_socket.settimeout(remaining)
                    chunk = raw_socket.recv(min(65536, 131073 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    require(len(data) <= 131072, "exec output bound")
            finally:
                close_exec_stream(stream)
            output, errors = bytearray(), bytearray()
            offset = 0
            while offset < len(data):
                require(len(data) - offset >= 8, "truncated exec header")
                header = data[offset:offset + 8]
                channel, length = struct.unpack(">BxxxI", header); offset += 8
                require(channel in (1, 2) and header[1:4] == b"\0\0\0" and length <= len(data) - offset, "exec frame")
                (output if channel == 1 else errors).extend(data[offset:offset + length]); offset += length
            begin("exec-inspect", consumer=consumer, command=command)
            status = client.api.exec_inspect(exec_id)
            record("probe", container=container.id, command=command, stdout=output.decode(errors="replace"),
                   stderr=errors.decode(errors="replace"), exit=status["ExitCode"])
            require(not status["Running"] and status["ExitCode"] == 0 and not errors, "probe failed")
            begin("probe-proof", consumer=consumer, command=command)
            value = json.loads(output)
            snapshot_proof(value, **expected)
            return value

    def receipts(containers, *, stopped=False):
        begin("stopped-receipts" if stopped else "running-receipts")
        manifest, state, hashes = public_state(daemon.root)
        # Persist only a public projection; raw operations/keys/boot files never leave root.
        record("journal-snapshot", stopped=stopped, **hashes)
        proof = receipt_proof(manifest, state, plan["volume"], [c.id for c in containers], stopped=stopped)
        record("stopped-receipts" if stopped else "running-receipts", proof=proof, **hashes)
        return proof

    try:
        require(call(client.version, step="client-version").get("GitCommit") == expected_git_commit(daemon.binary), "daemon commit mismatch")
        binary = directory / "probe"
        begin("compile-probe")
        try:
            subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", str(binary), str(SOURCE)],
                           env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOWORK": "off",
                                "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": ""},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                           timeout=max(0.001, min(20, work_deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            # run() reaps go itself; compiler descendants still share our private
            # group. Kill the whole group, not only its former go leader. Parent
            # observes failure and retains the pre-registered evidence/root.
            os.killpg(os.getpgrp(), signal.SIGKILL)
            raise
        begin("image-archive")
        payload = read_bounded(binary, 8 * 1024 * 1024)
        archive, config = image_archive(payload, plan)
        require(len(archive) <= 9 * 1024 * 1024, "image archive bound")
        record("fixture", binary_sha256=digest(payload), archive_sha256=digest(archive), config=config)
        call(client.images.load, archive, step="image-load")
        image = owned(call(client.images.get, plan["image"], step="image-inspect"), "image", plan["image"], plan["owner"])
        require(image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"], "image layers")
        volume = owned(call(client.volumes.create, plan["volume"], labels={OWNER: plan["owner"]}, step="volume-create"),
                       "volume", plan["volume"], plan["owner"])
        containers = []
        for index, name in enumerate(plan["containers"]):
            container = call(client.containers.create, image.id, name=name, network_mode="none", read_only=True,
                             step="container-create", consumer=index,
                             tmpfs={"/run": "rw,nosuid,nodev,size=8m"}, mem_limit="128m", pids_limit=32,
                             volumes={volume.name: {"bind": "/data", "mode": "rw"}}, labels={OWNER: plan["owner"]})
            containers.append(owned(container, "container", name, plan["owner"]))
        record("both-created", containers=[c.id for c in containers])
        for index, container in enumerate(containers):
            call(container.start, step="container-start", consumer=index)
            observe(container, "snapshot")
        before = receipts(containers)
        for container in containers:
            observe(container, "open")
        observe(containers[1], "unlink", unlinked=True)
        observe(containers[0], "snapshot", unlinked=True)
        observe(containers[0], "write", unlinked=True, written=True)
        observe(containers[1], "snapshot", unlinked=True, written=True)
        for container in containers:
            observe(container, "close", unlinked=True, closed=True)
        for index, container in enumerate(containers):
            call(container.stop, timeout=1, step="container-stop", consumer=index)
        after = receipts(containers, stopped=True)
        begin("final-proof")
        require([i["id"] for i in before["intents"]] == [i["id"] for i in after["intents"]], "launch identity changed")
    except BaseException as error:
        failed = True
        # Latch retention first, even if the artifact filesystem is full.
        daemon.retain_root(reason="unsafe-disk-phase")
        details, raw_error = error_evidence(error, api_error=isinstance(error, docker.errors.APIError))
        record("failure", **active_step, **details, artifact_directory=str(directory.relative_to(REPO_ROOT)))
        if isinstance(error, docker.errors.APIError):
            try:
                private = write_private_error(daemon.root, plan["owner"], raw_error)
                record("private-error", stored=True, **private)
            except Exception as evidence_error:
                record("private-error", stored=False, **failure_details(evidence_error))
        raise
    finally:
        errors = []
        # On failure stop exact-owned workloads but preserve their disks and
        # metadata too. Outer daemon teardown joins the owned VM processes.
        resources = [("container", name, client.containers) for name in reversed(plan["containers"])]
        if not failed:
            resources += [("volume", plan["volume"], client.volumes), ("image", plan["image"], client.images)]
        preserve = failed
        for kind, name, collection in resources:
            if preserve and kind != "container":
                continue
            try:
                with campaign.api_deadline(client, min(final_deadline, time.monotonic() + 3)):
                    begin("cleanup-get")
                    resource = owned(collection.get(name), kind, name, plan["owner"])
                    if preserve and kind == "container":
                        begin("cleanup-stop")
                        resource.stop(timeout=0)
                    else:
                        begin("cleanup-remove")
                        resource.remove(**({"force": True} if kind == "container" else {}))
            except Exception as error:
                if getattr(error, "status_code", None) != 404:
                    preserve = True
                    daemon.retain_root(reason="cleanup-incomplete")
                    errors.append({"kind": kind, "name": name, **active_step, **failure_details(error)})
        client.close()
        if errors:
            daemon.retain_root(reason="cleanup-incomplete")
        record("cleanup", errors=errors, retained=failed or bool(errors), elapsed=time.monotonic() - started)
        if errors and not failed:
            raise RuntimeError(f"managed smoke cleanup failed; evidence: {directory}")


if __name__ == "__main__":
    require(os.getpgrp() == os.getpid(), "private runner process group required")
    from harness import retain_compatibility_root
    if len(sys.argv) == 4 and sys.argv[1] == "--retain":
        retain_compatibility_root(Path(sys.argv[3]), Path(sys.argv[2]), reason="unsafe-disk-phase")
        sys.exit(0)
    require(len(sys.argv) == 7 and sys.argv[1] == "--worker", "private runner worker required")
    binary, root, socket, work = map(Path, sys.argv[2:6])
    daemon = SimpleNamespace(binary=binary, root=root, socket=socket, work=work,
        retain_root=lambda *, reason: retain_compatibility_root(work, binary, reason=reason))
    run_campaign(daemon, float(sys.argv[6]))
