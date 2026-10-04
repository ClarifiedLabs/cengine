"""RTM-079: owned storage-VM SIGKILL after completed consumer drain.

180s after fixture setup: work <=165s, cleanup <=173s, worker reap <=177s,
retention <=180s. The same real Daemon fixture handles kill/restart via a
bounded handshake. No active-consumer crash or physical power-loss claim.
"""
from __future__ import annotations
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

import managed_storage_recovery as worker_recovery

import docker
import pytest
from managed_storage_recovery import (OWNER, MAX_ARTIFACT, ProofFailure, digest, require, names, owned,
    initialize_evidence, image_archive, snapshot_proof, public_state, read_public,
    exact_receipts, historical_receipts, fresh_receipts, lifecycle_owner, recovered_lifecycle_owner,
    native_proof, exact_exit, unchanged_processes, signal_storage,
    workload_target, terminate_drained_workloads, runtime_root_path)
from volume_probe import REPO_ROOT, close_exec_stream, read_bounded

SOURCE = Path(__file__).parent / "fixtures/managed-storage-recovery.go"

@pytest.fixture
def image_cache(tmp_path):
    from conftest import managed_storage_arguments
    managed_storage_arguments(os.environ)
    return tmp_path

@pytest.fixture(autouse=True)
def verify_docker_cli_target():
    pass

@contextmanager
def parent_deadline(deadline):
    # Bounds Daemon.start's readiness curl as well as the fixed-size handshake.
    # All campaign filesystem I/O runs in the killable worker, not this parent.
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "parent timer already owned")
    previous = signal.getsignal(signal.SIGALRM)
    def expired(*_):
        raise TimeoutError("managed recovery parent deadline")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def retain_failure(daemon, deadline):
    daemon._retain_root = True
    if time.monotonic() >= deadline - 1:
        return
    marker = subprocess.Popen([sys.executable, "-B", __file__, "--retain", str(daemon.binary), str(daemon.work)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        marker.wait(timeout=max(0.001, min(1, deadline - 1 - time.monotonic())))
    except BaseException:
        os.killpg(marker.pid, signal.SIGKILL)
        marker.wait(timeout=max(0.001, deadline - time.monotonic()))
        raise


@pytest.mark.compat("RTM-079")
def test_owned_managed_storage_crash_recovery(daemon):
    started = time.monotonic()
    parent, child = socket.socketpair()
    process = None
    try:
        process = subprocess.Popen([sys.executable, "-B", __file__, "--worker", str(daemon.binary),
            str(daemon.root), str(daemon.socket), str(daemon.work), str(started), str(child.fileno())],
            pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)
        child.close()
        with parent_deadline(started + 174):
            for expected in (b"F", b"S", b"D"):
                require(parent.recv(1) == expected, "RTM-079 worker handshake failed")
                if expected == b"F":
                    daemon.stop(kill=True)  # Real fixture; no graceful substitute.
                    require(daemon.process.returncode == -signal.SIGKILL, "API was not SIGKILLed")
                elif expected == b"S":
                    daemon.start()  # Same root, same actual fixture object.
                receipt = struct.pack(">ii", daemon.process.pid, daemon.process.returncode) if expected == b"F" else b""
                parent.sendall(expected + receipt)
            require(process.wait(timeout=max(0.001, started + 174 - time.monotonic())) == 0, "RTM-079 worker failed")
    except BaseException:
        daemon._retain_root = True
        if process is not None and process.returncode is None:
            # Never signal a reaped/reusable PGID. A waiting leader pins its group.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=max(0.001, started + 177 - time.monotonic()))
        retain_failure(daemon, started + 180)
        pytest.fail("RTM-079 failed; public evidence .build/managed-storage-recovery; root retained", pytrace=False)
    finally:
        parent.close(); child.close()


@pytest.mark.compat("RTM-084")
def test_live_managed_storage_worker_replacement(daemon):
    started = time.monotonic()
    parent, child = socket.socketpair()
    process = None
    try:
        process = subprocess.Popen([sys.executable, "-B", __file__, "--worker-084", str(daemon.binary),
            str(daemon.root), str(daemon.socket), str(daemon.work), str(started), str(child.fileno())],
            pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)
        child.close()
        with parent_deadline(started + 174):
            require(parent.recv(1) == b"D", "RTM-084 completion handshake failed")
            parent.sendall(b"D")
            require(process.wait(timeout=max(0.001, started + 174 - time.monotonic())) == 0, "RTM-084 worker failed")
    except BaseException:
        daemon._retain_root = True
        if process is not None and process.returncode is None:
            os.killpg(process.pid, signal.SIGKILL)  # Only the private fixture worker group.
            process.wait(timeout=max(0.001, started + 177 - time.monotonic()))
        retain_failure(daemon, started + 180)
        pytest.fail("RTM-084 failed; public evidence .build/managed-storage-recovery; root retained", pytrace=False)
    finally:
        parent.close(); child.close()


def run_campaign(daemon, started, channel, *, rtm="RTM-079"):
    from conftest import expected_git_commit
    from harness import (_kernel_process, compatibility_runtime_processes,
                         compatibility_root_owned_by)
    from test_volume_workflows import _campaign as campaign

    work_deadline, final_deadline = started + 165, started + 173
    plan = names(uuid.uuid4().hex, rtm)
    directory, used = initialize_evidence(REPO_ROOT, plan["owner"], {
        "phase": "plan", "plan": plan, "seconds": 180, "source_sha256": digest(SOURCE.read_bytes()),
        "controller_source_sha256": digest(Path(__file__).read_bytes()),
        "helper_source_sha256": digest(Path(workload_target.__wrapped__.__code__.co_filename).read_bytes()),
        "boundary": ("ack-file-parent-fsync; completed-consumer-drain; owned-storage-SIGKILL" if rtm == "RTM-079" else
                     "two-running-FUSE-consumers; same-daemon-storage-worker-replacement"), "rtm": rtm}, rtm=rtm)

    last_phase = "plan"
    def record(phase, **value):
        nonlocal used, last_phase
        last_phase = phase
        raw = (json.dumps({"phase": phase, **value}, sort_keys=True) + "\n").encode()
        limit = MAX_ARTIFACT - (0 if phase in ("failure", "cleanup") else 65536)
        require(used + len(raw) <= limit, "artifact bound")
        fd = os.open(directory / "evidence.jsonl", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "ab") as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        used += len(raw)

    def handshake(command):
        channel.settimeout(max(0.001, work_deadline - time.monotonic()))
        channel.sendall(command)
        require(channel.recv(1) == command, "parent lifecycle handshake")
        if command == b"F":
            receipt = bytearray()
            while len(receipt) < 8:
                chunk = channel.recv(8 - len(receipt))
                require(chunk, "parent API join receipt truncated")
                receipt.extend(chunk)
            return struct.unpack(">ii", receipt)

    def processes():
        # ps enumerates only candidate PIDs; every match uses native birth+argv.
        return compatibility_runtime_processes(daemon.binary, roots=(daemon.root, Path("/")))

    def wait_exit(process):
        while not exact_exit(process, _kernel_process(process.pid)):
            require(time.monotonic() < work_deadline, "native exit deadline")
            time.sleep(0.05)
        record("native-exit", process=native_proof(process))

    disk_baseline = worker_recovery.disk_budget(daemon.root)["allocated"] if rtm == "RTM-084" else None
    client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.47", timeout=15)
    failed = False
    def call(operation, *args, deadline=work_deadline, **kwargs):
        if rtm == "RTM-084":
            worker_recovery.disk_budget(daemon.root, disk_baseline)
        try:
            return campaign.api_call(client, deadline, operation, *args, **kwargs)
        finally:
            if rtm == "RTM-084":
                # An API error may follow mutation. If this guard also fails,
                # Python preserves the original API error as its __context__.
                worker_recovery.disk_budget(daemon.root, disk_baseline)

    def observe(container, command, **expected):
        require(command in {"ack", "verify", "write"} or (rtm == "RTM-084" and command == "ack-peer"), "probe command")
        with campaign.api_deadline(client, min(work_deadline, time.monotonic() + 5)):
            exec_id = client.api.exec_create(container.id, ["/probe", "worker-" + command if rtm == "RTM-084" else command], stdout=True, stderr=True)["Id"]
            stream = client.api.exec_start(exec_id, socket=True)
            raw_socket = getattr(stream, "_sock", stream)
            data = bytearray()
            deadline = min(work_deadline, time.monotonic() + 4)
            try:
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
            status = client.api.exec_inspect(exec_id)
            record("probe", container=container.id, command=command, stdout_sha256=digest(output), stderr_sha256=digest(errors), exit=status["ExitCode"])
            require(not status["Running"] and status["ExitCode"] == 0 and not errors, "probe failed")
            value = json.loads(output)
            check = worker_recovery.worker_snapshot_proof if rtm == "RTM-084" else snapshot_proof
            check(value, command=command, **expected)
            record("payload-proof", container=container.id, value={k: v for k, v in value.items() if k != "mountinfo"},
                   mount=check(value, command=command, **expected))
            return value

    def receipts(containers, *, stopped=False, ids=None):
        manifest, state, hashes = public_state(daemon.root)
        record("journal-snapshot", stopped=stopped, **hashes)
        proof = exact_receipts(manifest, state, plan["volume"], [c.id for c in containers], stopped=stopped, ids=ids)
        record("retired-receipts" if stopped else "running-receipts", proof=proof, **hashes)
        return proof

    def owner():
        value, proof, sha = lifecycle_owner(daemon.root, worker=rtm == "RTM-084")
        record("owner-proof", proof=proof, checkpoint_manifest_sha256=sha)
        return value, proof

    def storage_target(proof):
        require(compatibility_root_owned_by(daemon.work, daemon.binary), "unowned compatibility root")
        root = daemon.root.resolve()
        work_info, root_info = daemon.work.lstat(), root.lstat()
        require(work_info.st_uid == os.geteuid() and work_info.st_mode & 0o077 == 0, "private owned root parent")
        require((root_info.st_dev, root_info.st_ino) == (proof["root"]["device"], proof["root"]["inode"]), "native owned root binding")
        from managed_prepare_lifecycle_evidence import storage_target as select
        selected = select(daemon, proof, processes(), read_public)
        path = Path(selected.arguments[3])
        require(path.resolve() == root / path.relative_to(runtime_root_path(daemon.root)), "symlink generation path")
        require(_kernel_process(selected.pid) == selected, "current native storage incarnation")
        record("storage-target", proof=native_proof(selected), backing=worker_recovery.backing_snapshot(root, proof))
        return selected

    def workload_processes(containers, running, owner_proof, rtm="RTM-079"):
        expected = {c.id for c in containers}
        selected = {}
        for process in processes():
            args = process.arguments
            if len(args) > 3 and args[1:3] == ("vm-shim", "--spec"):
                path = Path(args[3])
                if path.resolve().is_relative_to(daemon.root.resolve() / "containers"):
                    spec, _ = read_public(path)
                    container = spec.get("containerID")
                    if container in expected:
                        require(container not in selected, "duplicate native workload")
                        intent = next(i for i in running["intents"] if i["container"] == container)
                        with workload_target(process, daemon.binary, daemon.work, daemon.root, plan,
                                             intent, owner_proof["root"], next(c.name for c in containers if c.id == container), rtm=rtm) as (proof, _):
                            record("workload-target", proof=proof)
                            selected[container] = (process, proof)
        require(set(selected) == expected, "exact two native workload processes")
        return list(selected.values())

    def terminate_workloads(targets, retired, containers, owner_proof):
        ids = [i["id"] for i in retired["intents"]]
        terminate_drained_workloads(targets, retired,
            validate=lambda process, intent: workload_target(process, daemon.binary, daemon.work, daemon.root,
                plan, intent, owner_proof["root"], next(c.name for c in containers if c.id == intent["container"]), rtm=rtm),
            reread=lambda: receipts(containers, stopped=True, ids=ids), processes=processes,
            inspect=_kernel_process, record=record, deadline=work_deadline)

    def replace_worker(containers, running):
        require(rtm == "RTM-084", "worker-only branch")
        ids = [c.id for c in containers]
        before, old_owner, owner_hash = lifecycle_owner(daemon.root, worker=True)
        require(not before["checkpoint"]["serviceLinks"], "fresh owner worker history required")
        old_disk = worker_recovery.backing_snapshot(daemon.root, old_owner)
        require(all(i["serviceEpoch"] == old_owner["serviceEpoch"] and i["controllerEpoch"] == old_owner["controllerEpoch"] for i in running["intents"]), "running worker owner context")
        record("worker-owner-before", proof=old_owner, checkpoint_manifest_sha256=owner_hash)
        workloads = workload_processes(containers, running, old_owner, rtm=rtm)
        storage = storage_target(old_owner)
        before_native = processes()
        apis = [p for p in before_native if len(p.arguments) > 3 and p.arguments[1:4] == ("daemon", "--root", str(daemon.root))]
        require(len(apis) == 1, "exact live API process")
        api = apis[0]
        record("same-daemon-before", proof=native_proof(api), storage=native_proof(storage))
        require(all(p in before_native for p, _ in workloads) and storage in before_native, "captured live native processes")
        request, raw = worker_recovery.worker_request(str(uuid.uuid4()), old_owner["store"],
            {k: old_owner[k] for k in ("serviceEpoch", "workerUUID")})
        old_ids = [i["id"] for i in running["intents"]]
        with worker_recovery.replacement_queue(daemon.root, old_owner["root"]) as (queue, validate):
            # Positive API + native running proof immediately before publication.
            for container, (process, _) in zip(containers, sorted(workloads, key=lambda p: ids.index(p[1]["container"]))):
                call(container.reload)
                require(container.attrs["State"]["Running"] is True and not exact_exit(process, _kernel_process(process.pid)), "both running at submission")
            historical_receipts(running, receipts(containers))
            submitted = int(time.time())
            record("worker-request-intent", request=request, submitted_unix_seconds=submitted,
                   disk=worker_recovery.disk_budget(daemon.root, disk_baseline))
            validate()
            marker_identity = worker_recovery.publish_worker_request(queue, raw)
            seen = {}
            def receipt(name, maximum=1048576):
                contents, stamp = worker_recovery.queue_file(queue, name, maximum)
                if name in seen:
                    require(seen[name] == (contents, stamp), "immutable replacement artifact changed")
                else:
                    seen[name] = (contents, stamp)
                return contents, stamp
            stem = request["operationUUID"]
            while True:
                require(time.monotonic() < work_deadline, "worker replacement deadline")
                validate()
                try:
                    worker_recovery.queue_file(queue, stem + ".failed.json")
                except FileNotFoundError:
                    pass
                else:
                    raise ProofFailure("worker replacement failed receipt")
                try:
                    claimed, stamp = receipt(stem + ".request.json", 512)
                    require(claimed == raw and stamp[:2] == marker_identity, "exact immutable marker claim")
                    pending = json.loads(receipt(stem + ".pending.json")[0])
                    succeeded = json.loads(receipt(stem + ".succeeded.json")[0])
                    break
                except FileNotFoundError:
                    time.sleep(0.05)
            observed = int(time.time())
            worker_recovery.settled_worker_artifacts(queue, stem, seen)
            # A success receipt or contained IDs alone never proves workload death.
            for process, _ in workloads:
                wait_exit(process)
            require(_kernel_process(api.pid) == api and _kernel_process(storage.pid) == storage, "same native daemon and storage shim")
            remaining = {p.pid: p for p in before_native if p not in [w[0] for w in workloads]}
            require({p.pid: p for p in processes()} == remaining, "only old workload native exits")
            after, _, after_hash = lifecycle_owner(daemon.root, worker=True)
            manifest, state, hashes = public_state(daemon.root)
            new_owner = worker_recovery.lifecycle_replacement_proof(before, after, pending, succeeded, request, state, hashes, ids, submitted, observed)
            require(worker_recovery.backing_snapshot(daemon.root, new_owner) == old_disk, "unchanged worker backing filesystem")
            retired = exact_receipts(manifest, state, plan["volume"], ids, stopped=True, ids=old_ids)
            worker_recovery.retired_from_running(running, retired)
            require(storage_target(new_owner) == storage, "same storage shim launch/VM/disk")
            require(call(client.version).get("GitCommit") == expected_git_commit(daemon.binary), "same daemon commit")
            record("worker-replacement", owner=new_owner, owner_state_sha256=after_hash, request=request,
                   owner_request=succeeded["ownerRequest"], successor=succeeded["successor"],
                   history_sha256=digest(json.dumps(worker_recovery.lifecycle_worker_history(after), sort_keys=True).encode()),
                   confirmed_revision=after["checkpoint"]["latestServiceChange"]["revision"],
                   intent_revision=after["checkpoint"]["intentRevision"],
                   artifact_sha256={name: entry[1][-1] for name, entry in seen.items()}, retired=retired, **hashes)
            for container in containers:
                call(container.reload)
                require(container.attrs["State"]["Running"] is False, "old container terminal state")
                call(container.start)  # SAME Docker container records, never recreate.
                value = observe(container, "verify")
                baseline = baseline_payloads[ids.index(container.id)]
                require({k: v for k, v in value.items() if k != "mountinfo"} ==
                        {k: v for k, v in baseline.items() if k != "mountinfo"}, "recovered exact baseline metadata/bytes")
            fresh = receipts(containers)
            fresh_receipts(retired, fresh, new_owner, rtm="RTM-084")
            fresh_native = workload_processes(containers, fresh, new_owner, rtm=rtm)
            for process, proof in fresh_native:
                previous = next(p for p, old in workloads if old["container"] == proof["container"])
                require(process.identity[:2] != previous.identity[:2] and process.identity[2] != previous.identity[2], "fresh workload native launch")
                if process.pid == previous.pid:
                    require(exact_exit(previous, process), "reused PID requires fresh pidversion")
            observe(containers[1], "write", written=True)
            for container in containers:
                observe(container, "verify", written=True)
            historical_receipts(retired, receipts(containers, stopped=True, ids=old_ids))
            settled, _, _ = lifecycle_owner(daemon.root, worker=True)
            require(worker_recovery.lifecycle_worker_history(settled) == worker_recovery.lifecycle_worker_history(after), "completed history immutable after fresh launch")
            worker_recovery.settled_worker_artifacts(queue, stem, seen)
            validate()
            require(_kernel_process(api.pid) == api and storage_target(new_owner) == storage, "daemon/storage unchanged after fresh consumers")
            record("worker-recovery-verified", daemon=native_proof(api), storage=native_proof(storage),
                   disk=worker_recovery.disk_budget(daemon.root, disk_baseline), stale_credential_negative_probe=False)
            def final_check():
                with worker_recovery.replacement_queue(daemon.root, old_owner["root"]) as (final_queue, revalidate):
                    worker_recovery.settled_worker_artifacts(final_queue, stem, seen)
                    revalidate()
                final_owner, _, _ = lifecycle_owner(daemon.root, worker=True)
                require(worker_recovery.lifecycle_worker_history(final_owner) == worker_recovery.lifecycle_worker_history(after), "final worker history immutable")
                require(worker_recovery.backing_snapshot(daemon.root, new_owner) == old_disk, "final unchanged backing filesystem")
                require(_kernel_process(api.pid) == api and storage_target(new_owner) == storage, "final same daemon/storage native identity")
            return retired, fresh, new_owner, old_ids, final_check

    try:
        require(call(client.version).get("GitCommit") == expected_git_commit(daemon.binary), "daemon commit mismatch")
        binary = directory / "probe"
        # Only RTM-084 strips debug/symbol tables; source and artifact hashes remain.
        # Keep RTM-079's original linker flags and the 4MiB total evidence limit.
        linker_flags = "-buildid= -s -w" if rtm == "RTM-084" else "-buildid="
        try:
            subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=" + linker_flags, "-o", str(binary), str(SOURCE)],
                env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOWORK": "off",
                     "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": ""},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                timeout=max(0.001, min(25, work_deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgrp(), signal.SIGKILL)
            raise
        payload = read_bounded(binary, 8 * 1024 * 1024)
        if rtm == "RTM-084":
            # The retained executable counts too; archives stay memory-only.
            used += len(payload)
            require(used + 65536 <= MAX_ARTIFACT, "worker total artifact bound")
        archive, config = image_archive(payload, plan)
        require(len(archive) <= 9 * 1024 * 1024, "image archive bound")
        record("fixture", binary_sha256=digest(payload), archive_sha256=digest(archive), config=config, linker_flags=linker_flags)
        call(client.images.load, archive)
        image = owned(call(client.images.get, plan["image"]), "image", plan["image"], plan["owner"])
        require(image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"], "image layers")
        volume = owned(call(client.volumes.create, plan["volume"], labels={OWNER: plan["owner"]}), "volume", plan["volume"], plan["owner"])
        containers = []
        for name in plan["containers"]:
            container = call(client.containers.create, image.id, name=name, network_mode="none", read_only=True,
                tmpfs={"/run": "rw,nosuid,nodev,size=8m"}, mem_limit="128m", pids_limit=32,
                volumes={volume.name: {"bind": "/data", "mode": "rw"}}, labels={OWNER: plan["owner"]})
            containers.append(owned(container, "container", name, plan["owner"]))
        record("both-created", containers=[c.id for c in containers])
        for container in containers:
            call(container.start)
        observe(containers[0], "ack")  # External evidence fsynced before any fault.
        if rtm == "RTM-084":
            observe(containers[1], "ack-peer")  # Peer independently syncs the same linked baseline.
        baseline_payloads = [observe(container, "verify") for container in containers]
        if rtm == "RTM-084":
            require(all({k: v for k, v in value.items() if k != "mountinfo"} ==
                        {k: v for k, v in baseline_payloads[0].items() if k != "mountinfo"}
                        for value in baseline_payloads), "both consumer baseline metadata/bytes")
        running = receipts(containers)
        if rtm == "RTM-084":
            retired, fresh, new_owner, old_ids, worker_final_check = replace_worker(containers, running)
        else:
            old_record, old_owner = owner()
            old_disk = worker_recovery.backing_snapshot(daemon.root, old_owner)
            require(all(i["serviceEpoch"] == old_owner["serviceEpoch"] and i["controllerEpoch"] == old_owner["controllerEpoch"] for i in running["intents"]), "running owner context")
            workloads = workload_processes(containers, running, old_owner)
            for container in containers:
                call(container.stop, timeout=1)
            old_ids = [i["id"] for i in running["intents"]]
            retired = receipts(containers, stopped=True, ids=old_ids)
            terminate_workloads(workloads, retired, containers, old_owner)  # Drain never substitutes for native exit.
            record("drained-boundary", receipts=retired)
            before_freeze = processes()
            apis = [p for p in before_freeze if len(p.arguments) > 3 and p.arguments[1:4] == ("daemon", "--root", str(daemon.root))]
            require(len(apis) == 1, "exact API process")
            joined = handshake(b"F")  # Parent replies only after actual Popen kill/wait.
            wait_exit(apis[0])
            frozen = worker_recovery.api_exit_survivors(before_freeze, processes(), apis[0],
                joined=joined, inspect=_kernel_process, record=record)
            # Workloads are already natively gone. Select the storage target only
            # after refreshing the surviving census; all later equality is strict.
            historical_receipts(retired, receipts(containers, stopped=True, ids=old_ids))
            old_record, old_owner = owner()  # Settled checkpoint after completed drain and API exit.
            target = storage_target(old_owner)
            require(target in frozen, "storage snapshot changed")
            from managed_prepare_lifecycle_evidence import p as lifecycle_comparison
            old_spec, _ = read_public(Path(target.arguments[3]))
            old_origin = dict(shimLaunchUUID=Path(target.arguments[3]).parent.name,
                              specSHA256=digest(lifecycle_comparison.canonical(old_spec)))
            record("fault-intent", signal="SIGKILL", target=native_proof(target), native_origin=old_origin)
            def before_signal():
                require({p.pid: p for p in processes()} == {p.pid: p for p in frozen}, "unchanged post-API census at signal")
                current, proof, _ = lifecycle_owner(daemon.root)
                require(current == old_record and storage_target(proof) == target, "unchanged owner/native target at signal")
                require(worker_recovery.backing_snapshot(daemon.root, proof) == old_disk, "unchanged backing at signal")
            delivery = signal_storage(target, before_signal=before_signal)  # Positive audit-token delivery only.
            record("fault-delivered", proof=delivery)
            wait_exit(target)
            unchanged_processes(frozen, processes(), target)
            record("fault-complete", target=native_proof(target), other_runtime_changes=0)
            handshake(b"S")
            require(call(client.version).get("GitCommit") == expected_git_commit(daemon.binary), "restarted daemon commit")
            new_record, new_owner = owner()
            recovered_lifecycle_owner(old_record, new_record)
            expected_origin = new_record["checkpoint"]["latestCold"]["request"]["prepare"]["expectedOrigin"]
            require(all(expected_origin[k] == v for k, v in old_origin.items()), "cold predecessor is the killed native launch")
            require(worker_recovery.backing_snapshot(daemon.root, new_owner) == old_disk, "cold recovery preserves physical filesystem")
            historical_receipts(retired, receipts(containers, stopped=True, ids=old_ids))
            replacement = storage_target(new_owner)
            require(replacement.identity != target.identity, "replacement shim birth")
            for container in containers:
                call(container.start)
                observe(container, "verify")
            fresh = receipts(containers)
            fresh_receipts(retired, fresh, new_owner)
            observe(containers[1], "write", written=True)
            for container in containers:
                observe(container, "verify", written=True)
        fresh_workloads = workload_processes(containers, fresh, new_owner, rtm=rtm)
        for container in containers:
            call(container.stop, timeout=1)
        fresh_retired = receipts(containers, stopped=True, ids=[i["id"] for i in fresh["intents"]])
        terminate_workloads(fresh_workloads, fresh_retired, containers, new_owner)
        historical_receipts(retired, receipts(containers, stopped=True, ids=old_ids))
        if rtm == "RTM-084":
            worker_final_check()
        record("acceptance", result="pass", rtm=rtm, claim=("drained-boundary owned storage-VM crash recovery only" if rtm == "RTM-079" else
            "same-daemon worker-only restart; native exits and retired receipts, NOT stale-credential negative-auth proof"))
    except BaseException as error:
        failed = True
        daemon.retain_root(reason="unsafe-disk-phase")
        record("failure", error_type=type(error).__name__, error_name=str(error) if isinstance(error, ProofFailure) else "external-operation-failed",
               last_completed_phase=last_phase, artifact_directory=str(directory.relative_to(REPO_ROOT)))
        raise
    finally:
        errors = []
        resources = [("container", name, client.containers) for name in reversed(plan["containers"])]
        if not failed:
            resources += [("volume", plan["volume"], client.volumes), ("image", plan["image"], client.images)]
        preserve = failed
        for kind, name, collection in resources:
            if preserve and kind != "container":
                continue
            try:
                with campaign.api_deadline(client, min(final_deadline, time.monotonic() + 3)):
                    resource = owned(collection.get(name), kind, name, plan["owner"])
                    if preserve:
                        resource.stop(timeout=0)
                    else:
                        resource.remove(**({"force": True} if kind == "container" else {}))
            except Exception as error:
                if getattr(error, "status_code", None) != 404:
                    preserve = True
                    daemon.retain_root(reason="cleanup-incomplete")
                    errors.append({"kind": kind, "name": name, "error_type": type(error).__name__})
        client.close()
        record("cleanup", errors=errors, retained=failed or bool(errors), elapsed=time.monotonic() - started)
        if errors and not failed:
            raise RuntimeError(rtm + " cleanup failed")
    channel.settimeout(max(0.001, final_deadline - time.monotonic()))
    channel.sendall(b"D")
    require(channel.recv(1) == b"D", "completion handshake")


if __name__ == "__main__":
    require(os.getpgrp() == os.getpid(), "private runner process group required")
    from harness import retain_compatibility_root
    if len(sys.argv) == 4 and sys.argv[1] == "--retain":
        retain_compatibility_root(Path(sys.argv[3]), Path(sys.argv[2]), reason="unsafe-disk-phase")
        sys.exit(0)
    require(len(sys.argv) == 8 and sys.argv[1] in ("--worker", "--worker-084"), "private worker required")
    binary, root, endpoint, work = map(Path, sys.argv[2:6])
    daemon = SimpleNamespace(binary=binary, root=root, socket=endpoint, work=work,
        kernel=Path(os.environ["CENGINE_KERNEL"]), storage_initramfs=Path(os.environ["CENGINE_STORAGE_INITRAMFS"]),
        retain_root=lambda *, reason: retain_compatibility_root(work, binary, reason=reason))
    with socket.socket(fileno=int(sys.argv[7])) as channel:
        run_campaign(daemon, float(sys.argv[6]), channel, rtm="RTM-084" if sys.argv[1] == "--worker-084" else "RTM-079")
