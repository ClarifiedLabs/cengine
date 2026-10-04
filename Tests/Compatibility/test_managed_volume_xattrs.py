"""RTM-080: actual OCI-source xattrs on two precreated managed consumers.

Linux xattr(7), acl(5), capabilities(7), lsetxattr(2). No registry/cache images.
240s after daemon fixture setup: work 210s, cleanup 232s, reap 237s, retention
240s. Public evidence shares the hardened managed-storage-smoke artifact writer.
ORC-020 exact parity remains required. Only physical power-loss testing is
deferred; this case makes no durability/crash claim.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace
import uuid

import docker
from docker.types import Mount
import pytest

import managed_storage as smoke
import storage_backend_proof as backend
import test_volume_xattrs as direct
from test_managed_storage import retain_failure
from volume_probe import REPO_ROOT, close_exec_stream, read_bounded

SOURCE = Path(__file__).parent / "fixtures/volume-xattrs.go"
# Closed symlink batches replace the prior single-link/follow probes. The
# extended campaign is bounded by the same 400 execs (398 on the success path).
MAX_PROBES = 400


@pytest.fixture
def image_cache(tmp_path):
    # daemon depends on image_cache: skip BEFORE its startup or cache cloning.
    from conftest import managed_storage_arguments
    managed_storage_arguments(os.environ)
    return tmp_path


@pytest.fixture(autouse=True)
def verify_docker_cli_target():
    pass


def image_archive(binary, plan):
    """Reuse extended RTM-073's PAX layer; old 395-probe proof does not cover it."""
    smoke.require(0 < len(binary) <= 8 * 1024 * 1024, "probe binary bound")
    archive, _, config = direct._image_archive(binary)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        layer = source.extractfile("blobs/sha256/" + config["rootfs"]["diff_ids"][0].split(":")[1]).read()
    config["config"]["Labels"] = {smoke.OWNER: plan["owner"], "dev.cengine.compat.case": "RTM-080"}
    raw = direct._encode(config)
    identity = direct._digest(raw)
    content_tag = "compat-managed-xattrs:" + identity.split(":")[1]
    filename = identity.split(":")[1] + ".json"
    manifest = direct._encode([{"Config": filename, "RepoTags": [content_tag], "Layers": ["layer.tar"]}])
    result = direct._tar([(name, data, 0o644, {}, None) for name, data in
                          ((filename, raw), ("layer.tar", layer), ("manifest.json", manifest))])
    smoke.require(len(result) <= 9 * 1024 * 1024, "archive bound")
    return result, config, content_tag


def negative_proof(container, baseline=None):
    """Focused errno vector. Shared observations must equal the source exactly.

    A Linux-supported source variation is recorded, never normalized into a
    shared success. All writes use lsetxattr, including privileged symlink writes.
    """
    observed = []

    def check(args, permitted, user="0:0"):
        value = direct._probe(container, *args, user=user)
        errno = value.get("errno")
        smoke.require(type(errno) is int and errno in permitted, "Linux negative errno")
        observed.append(errno)
        if baseline is not None:
            smoke.require(len(observed) <= len(baseline) and errno == baseline[len(observed) - 1],
                          "source/shared errno mismatch")
        return value

    allowed = check(("read", "/populated/child/file"), (0,), "10001:10001")
    smoke.require(allowed.get("value") == direct.PAYLOAD.hex(), "ACL allowed reader bytes")
    check(("read", "/populated/child/file"), (direct.EACCES,), "10002:10002")
    for path, attrs in (("/empty", direct.DIRECTORY_ATTRS), ("/populated/child/file", direct.FILE_ATTRS)):
        for name, value in attrs.items():
            check(("set", path, name, value.hex()), (direct.EACCES, direct.EPERM), "10001:10001")
        check(("set", path, direct.CAP, "01"), (direct.EINVAL,))
    check(("set", "/populated/child/file", direct.DEFAULT, direct.ACL.hex()), (direct.EACCES,))
    direct._assert_symlink_capability_controls(container)
    for name, value, errno in ((direct.USER, b"must-not-reach-target", direct.EPERM),
                               (direct.ACCESS, direct.ACL, direct.EOPNOTSUPP),
                               (direct.DEFAULT, direct.ACL, direct.EOPNOTSUPP),
                               (direct.CAP, b"\x01", direct.EINVAL)):
        check(("get", "/populated/link", name), (direct.ENODATA, direct.EOPNOTSUPP))
        for user in ("0:0", "10001:10001"):
            check(("set", "/populated/link", name, value.hex()), (errno,), user)
            # After EVERY attempted write: both the targeted attribute and bytes
            # of the outside image-root target must still be unchanged.
            result = direct._probe(container, "get", "/sentinel", name)
            expected = direct.SENTINEL_ATTRS.get(name)
            smoke.require(result.get("errno") == (0 if expected is not None else direct.ENODATA), "symlink target errno")
            smoke.require(result.get("value") == (expected.hex() if expected is not None else ""), "symlink target xattr")
            result = direct._probe(container, "read", "/sentinel")
            smoke.require((result.get("errno"), result.get("value")) == (0, direct.SENTINEL.hex()), "symlink target bytes")
    smoke.require(baseline is None or len(observed) == len(baseline), "errno vector length")
    return observed


def require_assertions():
    smoke.require(sys.flags.optimize == 0 and os.environ.get("PYTHONOPTIMIZE") in (None, "", "0"),
                  "unoptimized Python required for source assertions")


def file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_nlink)


class EvidenceJournal:
    """Pin the freshly initialized journal before engine I/O; never reopen it."""
    def __init__(self, directory, initial):
        self.path, self.directory_fd, self.fd = Path(directory), None, None
        smoke.require(0 < len(initial) <= 65536, "initial evidence bound")
        self.used = len(initial)
        try:
            before = os.stat(self.path, follow_symlinks=False)
            self.directory_fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.directory_identity = (before.st_dev, before.st_ino)
            self.check_directory()
            prior = os.stat("evidence.jsonl", dir_fd=self.directory_fd, follow_symlinks=False)
            self.check_file(prior)
            # Nonblocking plus pre/post regular-file checks also rejects a FIFO
            # swapped in between stat and open, without waiting for a writer.
            self.fd = os.open("evidence.jsonl", os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=self.directory_fd)
            self.stamp = file_stamp(prior)
            self.check()
            smoke.require(os.pread(self.fd, self.used + 1, 0) == initial, "initial evidence mismatch")
            self.check()
        except BaseException:
            self.close()
            raise

    def check_directory(self):
        for info in (os.fstat(self.directory_fd), os.stat(self.path, follow_symlinks=False)):
            smoke.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022 and
                          (info.st_dev, info.st_ino) == self.directory_identity, "evidence directory changed")

    def check_file(self, info):
        smoke.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                      stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == self.used, "unsafe evidence file")

    def check(self):
        self.check_directory()
        for info in (os.fstat(self.fd), os.stat("evidence.jsonl", dir_fd=self.directory_fd, follow_symlinks=False)):
            self.check_file(info)
            smoke.require(file_stamp(info) == self.stamp, "evidence file changed")

    def append(self, raw, *, reserve=65536):
        smoke.require(self.used + len(raw) <= 1024 * 1024 - reserve, "artifact bound")
        self.check()
        smoke.require(os.write(self.fd, raw) == len(raw), "short evidence append")
        os.fsync(self.fd)
        self.used += len(raw)
        info = os.fstat(self.fd)
        self.check_file(info)
        self.stamp = file_stamp(info)
        self.check()

    def close(self):
        try:
            if self.fd is not None:
                os.close(self.fd)
        finally:
            self.fd = None
            if self.directory_fd is not None:
                os.close(self.directory_fd)
                self.directory_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def shared_proof(root, volumes, mountinfo):
    # Unlike a generic bounded reader, topology must not follow an external link.
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        pin = backend._ROOT_PINS[str(Path(root).absolute())]
        smoke.require(backend._identity(directory) == pin["identity"], "topology root pin mismatch")
        fd = os.open("volume-storage.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            smoke.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                          not info.st_mode & 0o022 and info.st_size <= 65536, "unsafe topology file")
            raw = source.read(65537)
            smoke.require(len(raw) <= 65536, "topology byte bound")
            # ctime cannot be restored with utime: equal-size rewrites with a
            # restored mtime must fail both descriptor and directory-entry proof.
            after = os.fstat(source.fileno())
            current = os.stat("volume-storage.json", dir_fd=directory, follow_symlinks=False)
            smoke.require(file_stamp(after) == file_stamp(info) == file_stamp(current), "topology changed during read")
    finally:
        os.close(directory)
    modes = json.loads(raw, object_pairs_hook=backend._object)
    proofs = []
    for role, volume in zip(("empty", "populated"), volumes):
        smoke.require(modes.get(volume.name) == "shared", "shared topology required")
        proof = backend.verify_backend(root, "shared", mountinfo, "/" + role, startup_mode="lifecycle")
        smoke.require(proof["mode"] == "lifecycle", "managed mode required; no fallback")
        # No nested mount may substitute the metadata under proof.
        smoke.require(not any(line.split()[4].startswith("/" + role + "/") for line in mountinfo.splitlines()),
                      "nested mount substitution")
        # The verifier's raw/options/root fields are not a public-log contract.
        public = {key: proof[key] for key in ("schema", "topology", "mode", "lifecycle_manifest_sha256", "root_identity")}
        public["mount"] = {key: proof["mount"][key] for key in ("destination", "filesystem", "source")}
        proofs.append({"volume": volume.name, **public})
    return proofs


def exercise(client, image, volume_names, plan, call, wrap, root, record):
    labels = {smoke.OWNER: plan["owner"]}
    source = call(client.containers.create, image.id, name=plan["volume"] + "-source",
                  network_mode="none", labels=labels, mem_limit="128m", pids_limit=32)
    smoke.owned(source, "container", plan["volume"] + "-source", plan["owner"])
    call(source.start)
    control = wrap(source)
    direct._assert_ext4(control, "/empty", mounted=False)
    direct._assert_ext4(control, "/populated", mounted=False)
    direct._assert_metadata(control)
    baseline = negative_proof(control)
    direct._assert_metadata(control)  # Source denials must not have altered metadata.
    record("source-preflight", errno_vector=baseline)
    # Stop only; preserve exact source disk until campaign cleanup succeeds.
    call(source.stop, timeout=1)
    volumes = [smoke.owned(call(client.volumes.create, name, labels=labels), "volume", name, plan["owner"])
               for name in volume_names]
    consumers = []
    for name in plan["containers"]:
        value = call(client.containers.create, image.id, name=name, network_mode="none", labels=labels,
                     mem_limit="128m", pids_limit=32,
                     mounts=[Mount(target="/" + role, source=volume.name, type="volume", no_copy=False)
                             for role, volume in zip(("empty", "populated"), volumes)])
        consumers.append(smoke.owned(value, "container", name, plan["owner"]))
    record("both-created", containers=[c.id for c in consumers])
    # Deliberately separate loops: BOTH references exist before EITHER start.
    for container in consumers:
        call(container.start)
    targets = [wrap(container) for container in consumers]
    for target in targets:
        mounts = direct._probe(target, "fs", "/empty")["mountinfo"]
        record("backend", proofs=shared_proof(root, volumes, mounts))
        direct._assert_metadata(target)
        negative_proof(target, baseline)
    # Acknowledged set -> other client re-read -> acknowledged restore -> writer
    # re-read. Both the empty volume root and populated file travel both ways.
    for path, original in (("/empty", direct.DIRECTORY_ATTRS[direct.USER]),
                           ("/populated/child/file", direct.FILE_ATTRS[direct.USER])):
        for writer, reader in ((targets[0], targets[1]), (targets[1], targets[0])):
            changed = b"shared-cross-client\x00\xff"
            result = direct._probe(writer, "set", path, direct.USER, changed.hex())
            smoke.require(result["errno"] == 0, "cross-client set acknowledgement")
            direct._get(reader, path, direct.USER, changed)
            result = direct._probe(reader, "set", path, direct.USER, original.hex())
            smoke.require(result["errno"] == 0, "restore acknowledgement")
            direct._get(writer, path, direct.USER, original)
    for target in targets:
        direct._assert_metadata(target)  # A user.* write must not destroy ACL/capability metadata.
    record("cross-client-restored")
    for container in consumers:
        call(container.stop, timeout=1)
    record("completed", boundary="acknowledged xattr operations; no crash or physical-power-loss claim")


class Probe:
    """Bounded exec adapter for the unchanged RTM-073 assertion helpers."""
    def __init__(self, container, client, campaign, deadline, record, budget):
        self.container, self.client, self.campaign = container, client, campaign
        self.deadline, self.record, self.budget = deadline, record, budget

    def exec_run(self, command, user):
        self.budget[0] += 1
        smoke.require(self.budget[0] <= MAX_PROBES, "probe count bound")
        deadline = min(self.deadline, time.monotonic() + 5)
        with self.campaign.api_deadline(self.client, deadline):
            identifier = self.client.api.exec_create(self.container.id, command, user=user, stdout=True, stderr=True)["Id"]
            stream = self.client.api.exec_start(identifier, socket=True)
            raw_socket = getattr(stream, "_sock", stream)
            data = bytearray()
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    smoke.require(remaining > 0, "exec deadline")
                    raw_socket.settimeout(remaining)
                    chunk = raw_socket.recv(min(65536, 131073 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    smoke.require(len(data) <= 131072, "exec output bound")
            finally:
                close_exec_stream(stream)
            output, errors, offset = bytearray(), bytearray(), 0
            while offset < len(data):
                smoke.require(len(data) - offset >= 8, "exec frame header")
                header = data[offset:offset + 8]
                channel, length = struct.unpack(">BxxxI", header)
                offset += 8
                smoke.require(channel in (1, 2) and header[1:4] == b"\0\0\0" and length <= len(data) - offset, "exec frame")
                (output if channel == 1 else errors).extend(data[offset:offset + length])
                offset += length
            status = self.client.api.exec_inspect(identifier)
            smoke.require(status["Running"] is False and status["ExitCode"] == 0 and not errors, "probe failed")
            value = json.loads(output)
            expected_user = tuple(map(int, user.split(":")))
            smoke.require((value.get("uid"), value.get("gid")) == expected_user, "probe credentials")
            errno = value.get("errno")
            smoke.require(errno is None or type(errno) is int and 0 <= errno <= 4095, "errno type/range")
            # No raw stdout/stderr/API exception text: helpers can contain tokens.
            self.record("probe", number=self.budget[0], operation=command[1], path=command[2], errno=errno)
            return SimpleNamespace(exit_code=0, output=bytes(output))


def run_campaign(daemon, started):
    from conftest import expected_git_commit
    from test_volume_workflows import _campaign as campaign

    require_assertions()
    work_deadline, final_deadline = started + 210, started + 232
    plan = smoke.names(uuid.uuid4().hex)
    volume_names = [plan["volume"] + "-" + role for role in ("empty", "populated")]
    initial = {"phase": "plan", "plan": plan, "case": "RTM-080", "volumes": volume_names,
               "source": plan["volume"] + "-source", "seconds": 240, "max_probes": MAX_PROBES,
               "source_sha256": smoke.digest(read_bounded(SOURCE, 65536))}
    directory, _ = smoke.initialize_evidence(REPO_ROOT, plan["owner"], initial)
    initial_raw = (json.dumps(initial, sort_keys=True) + "\n").encode()
    with EvidenceJournal(directory, initial_raw) as journal:
        phase = "plan"

        def record(next_phase, **value):
            nonlocal phase
            phase = next_phase
            raw = (json.dumps({"phase": phase, **value}, sort_keys=True) + "\n").encode()
            journal.append(raw, reserve=0 if phase in ("failure", "cleanup") else 65536)

        client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.47", timeout=10)
        failed, image_id = False, None

        def call(operation, *args, **kwargs):
            return campaign.api_call(client, min(work_deadline, time.monotonic() + 20), operation, *args, **kwargs)

        try:
            smoke.require(call(client.version).get("GitCommit") == expected_git_commit(daemon.binary), "daemon commit mismatch")
            binary = directory / "probe"
            try:
                subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", str(binary), str(SOURCE)],
                    env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOWORK": "off",
                         "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": ""},
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                    timeout=max(0.001, min(30, work_deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgrp(), signal.SIGKILL)
                raise
            payload = read_bounded(binary, 8 * 1024 * 1024)
            archive, config, content_tag = image_archive(payload, plan)
            # Publish the final content-addressed name before even an ambiguous load.
            # One tag permits non-forced exact-ID deletion on Docker as well as CEngine.
            plan["image"] = content_tag
            record("fixture", binary_sha256=smoke.digest(payload), archive_sha256=smoke.digest(archive), plan=plan)
            call(client.images.load, archive)
            image = smoke.owned(call(client.images.get, plan["image"]), "image", plan["image"], plan["owner"])
            image_id = image.id
            smoke.require(call(client.images.get, content_tag).id == image_id, "content image identity")
            smoke.require(image.attrs["Architecture"] == "arm64" and image.attrs["Os"] == "linux" and
                          image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"] and
                          all(image.attrs["Config"].get(key) == value for key, value in config["config"].items()),
                          "source image identity/config")
            budget = [0]
            exercise(client, image, volume_names, plan, call,
                     lambda c: Probe(c, client, campaign, work_deadline, record, budget), daemon.root, record)
        except BaseException as error:
            failed = True
            daemon.retain_root(reason="unsafe-disk-phase")
            record("failure", failed_phase=phase, error_type=type(error).__name__)
            raise
        finally:
            preserve, errors = failed, []
            resources = [("container", name, client.containers) for name in reversed([plan["volume"] + "-source", *plan["containers"]])]
            resources += [("volume", name, client.volumes) for name in reversed(volume_names)]
            resources += [("image", plan["image"], client.images)]
            for kind, name, collection in resources:
                if preserve and kind != "container":
                    continue
                try:
                    with campaign.api_deadline(client, min(final_deadline, time.monotonic() + 3)):
                        resource = smoke.owned(collection.get(name), kind, name, plan["owner"])
                        if kind == "image":
                            smoke.require(image_id is not None and resource.id == image_id, "cleanup image ID mismatch")
                        if preserve:
                            resource.stop(timeout=0)
                        elif kind == "image":
                            client.images.remove(resource.id, force=False)
                        else:
                            resource.remove(**({"force": True} if kind == "container" else {}))
                except Exception as error:
                    if getattr(error, "status_code", None) != 404:
                        preserve = True
                        daemon.retain_root(reason="cleanup-incomplete")
                        errors.append({"kind": kind, "error_type": type(error).__name__})
            client.close()
            record("cleanup", retained=preserve, errors=errors)
            smoke.require(not errors or failed, "owned cleanup failed")


@pytest.mark.compat("RTM-080")
def test_shared_managed_volume_source_xattrs(daemon):
    started, process = time.monotonic(), None
    try:
        require_assertions()
        # Transfer the ORIGINAL pre-Popen root pin, not a fresh post-start capture.
        pin = backend._ROOT_PINS[str(daemon.root.absolute())]
        smoke.require(pin["mode"] == "lifecycle", "managed startup required")
        process = subprocess.Popen([sys.executable, "-B", __file__, "--worker", str(daemon.binary),
            str(daemon.root), str(daemon.socket), str(daemon.work), str(started), json.dumps(pin)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        smoke.require(process.wait(timeout=max(0.001, started + 234 - time.monotonic())) == 0, "worker failed")
    except BaseException:
        daemon._retain_root = True
        try:
            if process is not None and process.returncode is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=max(0.001, started + 237 - time.monotonic()))
        except BaseException:
            pass  # Keep the sticky latch; never expose reap exceptions or argv.
        try:
            retain_failure(daemon, started + 240)
        except BaseException:
            pass  # Generic managed fixture teardown still sees the sticky latch.
        pytest.fail("RTM-080 failed; public evidence .build/managed-storage-smoke (case RTM-080); root retained", pytrace=False)


if __name__ == "__main__":
    smoke.require(os.getpgrp() == os.getpid(), "private runner process group required")
    smoke.require(len(sys.argv) == 8 and sys.argv[1] == "--worker", "private worker arguments")
    from harness import retain_compatibility_root
    binary, root, socket, work = map(Path, sys.argv[2:6])
    pin = json.loads(sys.argv[7])
    smoke.require(pin["mode"] == "lifecycle" and pin["identity"] == backend.root_identity(root), "startup root pin mismatch")
    backend._ROOT_PINS[str(root.absolute())] = pin
    daemon = SimpleNamespace(binary=binary, root=root, socket=socket, work=work,
        retain_root=lambda *, reason: retain_compatibility_root(work, binary, reason=reason))
    try:
        run_campaign(daemon, float(sys.argv[6]))
    except BaseException:
        # Never print traceback locals, raw SDK exceptions, daemon logs or tokens.
        sys.exit(1)
