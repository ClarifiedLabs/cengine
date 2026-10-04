"""RTM-081/082/083/085/087: one closed-selection native test per owned managed guest.

Linux FUSE interruption is advisory: an admitted request may complete normally.
240s after daemon setup: prebuilt-fixture validation, boot, test, cleanup and retention.
No attached exec, registry, external Linux VM, stock-kernel fallback, or skip proof.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import uuid

import docker
from docker.types import Mount
import pytest

import managed_fuse_artifact as artifact
import managed_storage as smoke
import storage_backend_proof as backend
import test_volume_xattrs as direct
from test_managed_storage import retain_failure
from test_managed_volume_xattrs import EvidenceJournal
from volume_probe import REPO_ROOT

TEST = "TestNativeMountedManagedV3InterruptGraceful"
TESTS = {key: value["test"] for key, value in artifact.SELECTIONS.items()}
CASE_LABEL = "dev.cengine.compat.case"
TEST_LABEL = "dev.cengine.compat.native-test"
MAX_PROBES = 800
BOUNDED_BYTES = 128 * 1024 * 1024
FAILURE_LOG_BYTES = 16 * 1024


def selected_test(case_id):
    smoke.require(type(case_id) is str and case_id in TESTS, "closed native case required")
    return TESTS[case_id]


def worker_case(arguments):
    smoke.require(len(arguments) == 9 and arguments[1] == "--worker", "private worker arguments")
    selected_test(arguments[8])
    return arguments[8]


@pytest.fixture
def image_cache(tmp_path):
    from conftest import managed_storage_arguments
    managed_storage_arguments(os.environ)
    smoke.require(os.environ.get("CENGINE_RTM081_FIXTURE") and os.environ.get("CENGINE_RTM081_FIXTURE_SHA256"),
                  "native tests require the parent-built pinned fixture before daemon startup")
    return tmp_path


@pytest.fixture(autouse=True)
def verify_docker_cli_target():
    pass  # No CLI/cache dependency: no registry or extra network.


def load_inputs(case_id="RTM-081"):
    return artifact.load_fixture(os.environ["CENGINE_RTM081_FIXTURE"],
                                 os.environ["CENGINE_RTM081_FIXTURE_SHA256"], REPO_ROOT, case_id)


def image_archive(native, helper, formatter, plan, case_id="RTM-081", *, fsx=None):
    test = selected_test(case_id)
    smoke.require(0 < len(native) <= 32 << 20 and 0 < len(helper) <= 8 << 20 and 0 < len(formatter) <= 8 << 20, "binary bound")
    entries = [("native.test", native, 0o755, {}, None), ("setup", helper, 0o755, {}, None),
               ("mke2fs", formatter, 0o755, {}, None),
               ("mke2fs.sha256", (smoke.digest(formatter) + "\n").encode(), 0o444, {}, None),
               ("scratch", None, 0o700, {}, None), ("tmp", None, 0o1777, {}, None)]
    if case_id == "RTM-085":
        entries.append(("fsx", artifact.validate_fsx(fsx), 0o755, {}, None))
    else:
        smoke.require(fsx is None, "fsx input is only permitted for RTM-085")
    layer = direct._tar(entries)
    config = {"architecture": "arm64", "os": "linux", "config": {"Cmd": ["/setup", case_id], "User": "0:0",
              "Labels": {smoke.OWNER: plan["owner"], CASE_LABEL: case_id, TEST_LABEL: test}},
              "rootfs": {"type": "layers", "diff_ids": [direct._digest(layer)]}}
    raw = direct._encode(config)
    def descriptor(data, media):
        return {"mediaType": "application/vnd.oci." + media, "digest": direct._digest(data), "size": len(data)}
    manifest = direct._encode({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": descriptor(raw, "image.config.v1+json"), "layers": [descriptor(layer, "image.layer.v1.tar")]})
    tag = "compat-managed-fuse-interrupt:" + direct._digest(manifest).split(":")[1]
    entry = descriptor(manifest, "image.manifest.v1+json")
    entry["annotations"] = {"io.containerd.image.name": tag, "org.opencontainers.image.ref.name": tag}
    files = [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
             ("index.json", direct._encode({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [entry]}))]
    files += [("blobs/sha256/" + direct._digest(data).split(":")[1], data) for data in (raw, manifest, layer)]
    archive = direct._tar([(name, data, 0o644, {}, None) for name, data in files])
    smoke.require(len(archive) <= 50 << 20, "archive bound")
    return archive, config, tag


def native_proof(raw, state, test_sha, formatter_sha, case_id="RTM-081"):
    test = selected_test(case_id)
    smoke.require(type(raw) is bytes and 0 < len(raw) <= 8192, "native result bound")
    value = json.loads(raw, object_pairs_hook=backend._object)
    fields = {"case", "test", "success", "exit", "passes", "skips", "kernel", "architecture", "root", "scratch", "tmp",
              "fusectl", "uring_enabled", "protected_hardlinks", "test_sha256", "log_sha256", "log_bytes",
              "bounded", "backing_bytes", "loop_autoclear", "loop_clean", "formatter_sha256", "formatter_checked", "passed_tests"}
    smoke.require(isinstance(value, dict) and set(value) == fields, "native result schema")
    smoke.require(state.get("Running") is False and type(state.get("ExitCode")) is int and state["ExitCode"] == 0 and
                  state.get("OOMKilled") is False, "container did not exit successfully")
    smoke.require(value["case"] == case_id and value["test"] == test and value["success"] is True and
                  all(type(value[key]) is int and value[key] == expected for key, expected in (("exit", 0), ("passes", len(artifact.selection(case_id)["expected"])), ("skips", 0))),
                  "exact native test pass/no-skip required")
    smoke.require(value["passed_tests"] == artifact.selection(case_id)["expected"],
                  "every exact native subcase required")
    smoke.require(value["architecture"] == "arm64" and type(value["kernel"]) is str and
                  re.fullmatch(r"6\.18\.[0-9A-Za-z.+_-]+", value["kernel"]), "native kernel profile")
    smoke.require(all(value[key] is True for key in ("fusectl", "uring_enabled", "protected_hardlinks")), "native setup proof")
    smoke.require(value["test_sha256"] == test_sha and re.fullmatch(r"[0-9a-f]{64}", value["log_sha256"]) and
                  type(value["log_bytes"]) is int and 0 < value["log_bytes"] <= 128 << 10, "native byte/hash proof")
    smoke.require(value["loop_autoclear"] is True and value["loop_clean"] is True and
                  type(value["backing_bytes"]) is int and value["backing_bytes"] == BOUNDED_BYTES and
                  value["formatter_sha256"] == formatter_sha and value["formatter_checked"] is True,
                  "bounded loop/formatter/cleanup proof")
    for key, kind, ro, limit in (("root", 0xef53, True, 64 << 30), ("scratch", 0xef53, False, 512 << 30),
                               ("bounded", 0xef53, False, BOUNDED_BYTES), ("tmp", 0x01021994, False, 32 << 20)):
        fs = value[key]
        smoke.require(isinstance(fs, dict) and set(fs) == {"type", "device", "read_only", "bytes"} and
                      type(fs["type"]) is int and fs["type"] == kind and fs["read_only"] is ro and
                      type(fs["bytes"]) is int and 0 < fs["bytes"] <= limit and
                      type(fs["device"]) is int and 0 < fs["device"] < 2**64, "filesystem proof")
    smoke.require(value["root"]["device"] != value["scratch"]["device"], "scratch must be direct ext4 distinct from root")
    smoke.require(len({value[k]["device"] for k in ("root", "scratch", "bounded")}) == 3, "bounded ext4 must be a distinct filesystem")
    return value  # Closed schema; never return raw stdout/error text.


def write_failure_logs(root, owner, payload, deadline):
    """Do not let a slow private fsync consume the failure cleanup budget.

    The writer owns only immutable bytes and fresh files in the retained root,
    never the API client or journal. A stalled daemon thread dies with this
    already-supervised worker; it cannot keep the campaign alive past 240s.
    """
    complete = []
    def write():
        try:
            for index, offset in enumerate(range(0, len(payload), smoke.MAX_PRIVATE_ERROR)):
                smoke.require(time.monotonic() < deadline, "failure log deadline")
                # Reuse the exclusive/no-follow private writer; never publish
                # its filename. Chunks concatenate stdout then stderr.
                token = smoke.digest((owner + ":native-failure:" + str(index)).encode())[:32]
                smoke.write_private_error(root, token, payload[offset:offset + smoke.MAX_PRIVATE_ERROR])
            complete.append(True)
        except BaseException:
            pass
    worker = threading.Thread(target=write, daemon=True)
    worker.start()
    worker.join(timeout=max(0, deadline - time.monotonic()))
    smoke.require(not worker.is_alive() and complete, "private failure log retention incomplete")


def failure_logs(campaign, client, root, plan, case_id, container_id, final_deadline):
    """Best-effort private diagnosis only; a running guest can never pass here."""
    deadline = min(final_deadline, time.monotonic() + 3)
    if time.monotonic() >= deadline:
        return {"status": "expired"}
    if type(container_id) is not str or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
        return {"status": "not-selected"}
    try:
        test = selected_test(case_id)
        with campaign.api_deadline(client, deadline):
            container = smoke.owned(client.containers.get(container_id), "container", plan["containers"][0], plan["owner"])
            smoke.require(container.id == container_id and
                          container.attrs["Config"].get("Cmd") == ["/setup", case_id] and
                          container.attrs["Config"].get("Labels") == {
                              smoke.OWNER: plan["owner"], CASE_LABEL: case_id, TEST_LABEL: test},
                          "failure log container selection mismatch")
        smoke.require(time.monotonic() < deadline, "failure log deadline")
        used = 0
        def bounded_logs(**kwargs):
            nonlocal used
            if used >= FAILURE_LOG_BYTES:
                return
            stream = container.logs(**kwargs)
            try:
                for chunk in stream:
                    smoke.require(time.monotonic() < deadline, "failure log deadline")
                    part = chunk[:FAILURE_LOG_BYTES - used]
                    used += len(part)
                    yield part
                    if used >= FAILURE_LOG_BYTES:
                        break
            finally:
                stream.close()
        stdout, stderr = campaign.read_logs(client, SimpleNamespace(logs=bounded_logs), deadline)
        # Independently enforce the retained bound even if the reader changes.
        stdout = bytes(stdout[:FAILURE_LOG_BYTES])
        stderr = bytes(stderr[:FAILURE_LOG_BYTES - len(stdout)])
        payload = stdout + stderr
        write_failure_logs(root, plan["owner"], payload, deadline)
        smoke.require(time.monotonic() < deadline, "failure log deadline")
        return {"status": "retained", "stdout_bytes": len(stdout), "stdout_sha256": smoke.digest(stdout),
                "stderr_bytes": len(stderr), "stderr_sha256": smoke.digest(stderr),
                "limit_reached": len(payload) == FAILURE_LOG_BYTES}
    except BaseException:
        # No exception text, raw JSON, paths, or inferred pass/failure metadata.
        return {"status": "unavailable"}


def run_campaign(daemon, started, case_id="RTM-081"):
    test = selected_test(case_id)
    from conftest import expected_git_commit
    from test_volume_workflows import _campaign as campaign
    work_deadline, final_deadline = started + 210, started + 232
    plan = smoke.names(uuid.uuid4().hex)
    initial = {"phase": "plan", "plan": plan, "case": case_id, "test": test, "seconds": 240, "max_probes": MAX_PROBES,
               "selected_containers": [plan["containers"][0]], "selected_volumes": [plan["volume"]],
               "bounded_backing_bytes": BOUNDED_BYTES, "native_max_file_bytes": 64 << 20}
    directory, _ = smoke.initialize_evidence(REPO_ROOT, plan["owner"], initial)
    with EvidenceJournal(directory, (json.dumps(initial, sort_keys=True) + "\n").encode()) as journal:
        phase = "plan"
        def record(next_phase, **value):
            nonlocal phase
            phase = next_phase
            journal.append((json.dumps({"phase": phase, **value}, sort_keys=True) + "\n").encode(),
                           reserve=0 if phase in ("failure", "cleanup") else 65536)
        client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.47", timeout=10)
        failed, image_id, container_id = False, None, None
        def call(operation, *args, **kwargs):
            return campaign.api_call(client, min(work_deadline, time.monotonic() + 15), operation, *args, **kwargs)
        try:
            smoke.require(call(client.version).get("GitCommit") == expected_git_commit(daemon.binary), "daemon commit mismatch")
            smoke.require(shutil.disk_usage(directory).free >= 2 << 30 and shutil.disk_usage(daemon.root).free >= 2 << 30,
                          "host build/work free disk budget")
            manifest, files = load_inputs(case_id)
            before = manifest["sources"]
            record("sources", files=before, inventory_sha256=smoke.digest(direct._encode(before)))
            record("compiler", builder=manifest["builder"], toolchain=manifest["toolchain"], cleanup=manifest["cleanup"],
                   fixture_manifest_sha256=os.environ["CENGINE_RTM081_FIXTURE_SHA256"])
            native, helper, formatter = (files[name] for name in ("native.test", "setup", "mke2fs"))
            fsx = None
            if case_id == "RTM-085":
                fsx = artifact.load_fsx(os.environ.get("CENGINE_RTM085_FSX"))
                record("fsx-input", bytes=len(fsx), sha256=smoke.digest(fsx))
            archive, config, tag = image_archive(native, helper, formatter, plan, case_id, fsx=fsx)
            plan["image"] = tag
            record("fixture", test_sha256=smoke.digest(native), helper_sha256=smoke.digest(helper),
                   archive_sha256=smoke.digest(archive), formatter_sha256=smoke.digest(formatter), plan=plan)
            loaded = call(client.images.load, archive)
            smoke.require(len(loaded) == 1, "one owned OCI image required")
            image = smoke.owned(call(client.images.get, tag), "image", tag, plan["owner"])
            image_id = image.id
            smoke.require(loaded[0].id == image_id and image.attrs["Architecture"] == "arm64" and image.attrs["Os"] == "linux" and
                          image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"] and
                          all(image.attrs["Config"].get(k) == v for k, v in config["config"].items()), "loaded image identity")
            volume = smoke.owned(call(client.volumes.create, plan["volume"], labels={smoke.OWNER: plan["owner"]}),
                                 "volume", plan["volume"], plan["owner"])
            container = call(client.containers.create, image.id, command=config["config"]["Cmd"],
                name=plan["containers"][0], network_mode="none",
                privileged=True, read_only=True, mem_limit="768m", nano_cpus=1000000000, pids_limit=128,
                tmpfs={"/tmp": "rw,nosuid,nodev,size=32m"}, labels=config["config"]["Labels"],
                mounts=[Mount(target="/scratch", source=volume.name, type="volume", no_copy=True)])
            smoke.owned(container, "container", plan["containers"][0], plan["owner"])
            smoke.require(container.attrs["Config"].get("Cmd") == config["config"]["Cmd"] and
                          container.attrs["Config"].get("Labels") == config["config"]["Labels"], "container native selection mismatch")
            smoke.require(type(container.id) is str and re.fullmatch(r"[0-9a-f]{64}", container.id), "container ID required")
            container_id = container.id
            record("created", container=container.id, volume=volume.name, privileged=True, root_read_only=True, network="none")
            call(container.start)
            for probe in range(MAX_PROBES):
                call(container.reload)
                state = container.attrs["State"]
                if state.get("Running") is False:
                    break
                smoke.require(time.monotonic() < work_deadline, "native work deadline")
                time.sleep(0.25)
            else:
                raise TimeoutError("native probe count")
            stdout, stderr = campaign.read_logs(client, container, min(work_deadline, time.monotonic() + 5))
            raw = bytes(stdout)
            record("result-envelope", bytes=len(raw), sha256=smoke.digest(raw), probes=probe + 1,
                   stderr_bytes=len(stderr), stderr_sha256=smoke.digest(stderr))
            smoke.require(not stderr, "native stderr must be empty")
            record("native-pass", proof=native_proof(raw, state, smoke.digest(native), smoke.digest(formatter), case_id))
        except BaseException as error:
            failed = True
            daemon.retain_root(reason="unsafe-disk-phase")
            record("failure", failed_phase=phase, **smoke.error_evidence(error, api_error=isinstance(error, docker.errors.APIError))[0])
            try:
                record("failure-logs", **failure_logs(campaign, client, daemon.root, plan, case_id, container_id, final_deadline))
            except BaseException:
                pass  # Diagnostics must not replace the original failure.
            raise
        finally:
            preserve, errors = failed, []
            resources = [("container", plan["containers"][0], client.containers),
                         ("volume", plan["volume"], client.volumes), ("image", plan["image"], client.images)]
            for kind, name, collection in resources:
                if preserve and kind != "container":
                    continue
                try:
                    with campaign.api_deadline(client, min(final_deadline, time.monotonic() + 3)):
                        resource = smoke.owned(collection.get(name), kind, name, plan["owner"])
                        if kind == "image":
                            smoke.require(image_id is not None and resource.id == image_id, "cleanup image identity")
                        if preserve:
                            resource.stop(timeout=0)
                        elif kind == "image":
                            client.images.remove(resource.id, force=False)
                        else:
                            resource.remove(**({"force": True} if kind == "container" else {}))
                        if not preserve:
                            try:
                                collection.get(name)
                            except Exception as absent:
                                smoke.require(getattr(absent, "status_code", None) == 404, "cleanup absence not proven")
                            else:
                                raise ValueError("owned resource remains after removal")
                except Exception as error:
                    if getattr(error, "status_code", None) != 404:
                        preserve = True
                        daemon.retain_root(reason="cleanup-incomplete")
                        errors.append({"kind": kind, **smoke.error_evidence(error, api_error=isinstance(error, docker.errors.APIError))[0]})
            client.close()
            record("cleanup", retained=preserve, errors=errors, elapsed=time.monotonic() - started)
            smoke.require(not errors or failed, "owned cleanup failed")


def run_native_case(daemon, case_id):
    selected_test(case_id)
    started, process = time.monotonic(), None
    try:
        pin = backend._ROOT_PINS[str(daemon.root.absolute())]
        smoke.require(pin["mode"] == "lifecycle", "managed startup required")
        process = subprocess.Popen([sys.executable, "-B", __file__, "--worker", str(daemon.binary),
            str(daemon.root), str(daemon.socket), str(daemon.work), str(started), json.dumps(pin), case_id],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        smoke.require(process.wait(timeout=max(0.001, started + 234 - time.monotonic())) == 0, "worker failed")
    except BaseException:
        daemon._retain_root = True
        try:
            if process is not None and process.returncode is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=max(0.001, started + 237 - time.monotonic()))
        except BaseException:
            pass
        try:
            retain_failure(daemon, started + 240)
        except BaseException:
            pass
        pytest.fail(f"{case_id} failed; public evidence .build/managed-storage-smoke (case {case_id}); root retained", pytrace=False)


@pytest.mark.compat("RTM-081")
def test_native_managed_fuse_interrupt(daemon):
    run_native_case(daemon, "RTM-081")


@pytest.mark.compat("RTM-082")
def test_native_managed_fuse_write_burst(daemon):
    run_native_case(daemon, "RTM-082")


@pytest.mark.compat("RTM-083")
def test_native_managed_fuse_sparse_mmap(daemon):
    run_native_case(daemon, "RTM-083")


@pytest.mark.compat("RTM-085")
def test_native_managed_fuse_full_fsx(daemon):
    run_native_case(daemon, "RTM-085")


@pytest.mark.compat("RTM-087")
def test_native_managed_data_stale_credentials(daemon):
    run_native_case(daemon, "RTM-087")


@pytest.mark.compat("RTM-089")
def test_native_service_faults(daemon):
    run_native_case(daemon, "RTM-089")


@pytest.mark.compat("RTM-090")
def test_native_fault_tuple_regression(daemon):
    run_native_case(daemon, "RTM-090")


@pytest.mark.compat("RTM-091")
def test_native_symlink_root_rollback(daemon):
    run_native_case(daemon, "RTM-091")


@pytest.mark.compat("RTM-092")
def test_native_managed_valid_capability(daemon):
    run_native_case(daemon, "RTM-092")


@pytest.mark.compat("RTM-093")
def test_native_issued_prepare_initializer_preflight(daemon):
    run_native_case(daemon, "RTM-093")


@pytest.mark.compat("RTM-094")
def test_native_pending_prepare_fresh_mount_replay(daemon):
    run_native_case(daemon, "RTM-094")


@pytest.mark.compat("RTM-095")
def test_native_prepare_ext4_identity_and_cleanup(daemon):
    run_native_case(daemon, "RTM-095")

@pytest.mark.compat("RTM-101")
def test_native_prepare_snapshot_fence(daemon):
    # Eight native mounted component cases; no deployed-VM or native-PASS inference.
    run_native_case(daemon, "RTM-101")


@pytest.mark.compat("RTM-102")
def test_native_prepare_ext4_identity_authenticity(daemon):
    run_native_case(daemon, "RTM-102")


@pytest.mark.compat("RTM-104")
def test_native_prepare_process_poll_eintr(daemon):
    run_native_case(daemon, "RTM-104")


@pytest.mark.compat("RTM-107")
def test_native_durability_fail_closed_policy(daemon):
    # Linux process-death component: real ext4 DATA + barrier markers, repeated
    # refused Open and unchanged registry. Not VM death, authenticated bootstrap,
    # Docker recovery, or RTM-098/099 acceptance evidence.
    run_native_case(daemon, "RTM-107")


@pytest.mark.compat("RTM-108")
def test_native_retirement_completion_recovery(daemon):
    # Linux process-death component only; not VM-death or Docker recovery proof.
    run_native_case(daemon, "RTM-108")


@pytest.mark.compat("RTM-109")
def test_native_copy_data_recovery(daemon):
    # Linux process-death component only; not VM-death or Docker recovery proof.
    run_native_case(daemon, "RTM-109")


@pytest.mark.compat("RTM-110")
def test_native_prepare_retirement_recovery(daemon):
    # Linux process-death component only; not VM-death or Docker recovery proof.
    run_native_case(daemon, "RTM-110")


@pytest.mark.compat("RTM-113")
def test_native_storage_lifecycle_checkpoint(daemon):
    # Inactive guest lifecycle-v2 component: fresh empty ext4 store, test-owned
    # ROOT key and real TLS. Not activation, installed-helper auth, DATA/drain,
    # host-history, power-loss, VM-death, or disk-deletion qualification.
    run_native_case(daemon, "RTM-113")


if __name__ == "__main__":
    smoke.require(os.getpgrp() == os.getpid(), "private runner process group required")
    case_id = worker_case(sys.argv)
    from harness import retain_compatibility_root
    binary, root, socket, work = map(Path, sys.argv[2:6])
    pin = json.loads(sys.argv[7])
    smoke.require(pin["mode"] == "lifecycle" and pin["identity"] == backend.root_identity(root), "startup root pin mismatch")
    backend._ROOT_PINS[str(root.absolute())] = pin
    daemon = SimpleNamespace(binary=binary, root=root, socket=socket, work=work,
        retain_root=lambda *, reason: retain_compatibility_root(work, binary, reason=reason))
    try:
        run_campaign(daemon, float(sys.argv[6]), case_id)
    except BaseException:
        sys.exit(1)  # Never expose traceback locals or arbitrary API/native output.
