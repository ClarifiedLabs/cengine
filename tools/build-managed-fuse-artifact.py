#!/usr/bin/env python3
"""Parent-only RTM-081 compilation; never starts/controls a VM or runs a test.

Requires the ORIGINAL compatibility mkdir lock owned by the direct parent, an
explicit Unix endpoint, exact approved daemon ID and pre-cached image ID. No
pull/build/prune, Docker context fallback, host mount, or daemon lifecycle call.
"""
from __future__ import annotations
import argparse
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time
import uuid
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import helper_fixture_lifetime as claims
import managed_fuse_artifact as artifact
from volume_probe import tar_bytes

OWNER = "dev.cengine.compat.rtm081-build"
SCRIPT_TEMPLATE = r'''set -eu
ulimit -n 256
ulimit -c 0
mkdir -p /work/src /work/out /work/cache /work/tmp
tar -xf - -C /work/src
# Hash the ENTIRE immutable Go distribution, not just its version/executables.
test -z "$(find /usr/local/go -type l -print -quit)"
find /usr/local/go -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum --zero > /work/toolchain.before
export CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS= GOENV=off
export GOCACHE=/work/cache GOTMPDIR=/work/tmp GOMAXPROCS=1 GOMEMLIMIT=512MiB
cd /work/src/Guest
timeout -k 2 180 go test -c -mod=vendor -p=1 -trimpath -buildvcs=false -ldflags=-buildid= -o /work/out/native.test __TAGS__ __PACKAGE__
timeout -k 2 30 go build -mod=vendor -p=1 -trimpath -buildvcs=false -ldflags=-buildid= -o /work/out/setup ../Tests/Compatibility/fixtures/managed-fuse-native.go
# Compile (never execute) both architectures; only arm64 artifacts are exported.
GOARCH=amd64 timeout -k 2 180 go test -c -mod=vendor -p=1 -trimpath -buildvcs=false -ldflags=-buildid= -o /work/native-amd64.test __TAGS__ __PACKAGE__
GOARCH=amd64 timeout -k 2 30 go build -mod=vendor -p=1 -trimpath -buildvcs=false -ldflags=-buildid= -o /work/setup-amd64 ../Tests/Compatibility/fixtures/managed-fuse-native.go
find /usr/local/go -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum --zero > /work/out/toolchain.sha256
cmp /work/toolchain.before /work/out/toolchain.sha256
test "$(stat -c %s /work/out/native.test)" -le 33554432
test "$(stat -c %s /work/out/setup)" -le 8388608
test "$(stat -c %s /work/out/toolchain.sha256)" -le 4194304
tar -cf - -C /work/out native.test setup toolchain.sha256
'''


def build_script(case_id):
    selected = artifact.selection(case_id)
    tags = "-tags=cengine_native_faulttest" if selected["tags"] else ""
    return SCRIPT_TEMPLATE.replace("__TAGS__", tags).replace("__PACKAGE__", selected["package"])


SCRIPT = build_script("RTM-081")

def endpoint(host):
    value = urlsplit(host)
    artifact.require(value.scheme == "unix" and not value.netloc and value.path.startswith("/") and
                     value.path != "/" and not value.query and not value.fragment, "explicit local endpoint required")


class OriginalLock:
    """Only verifies the caller's lock; never creates, adopts or removes it."""
    def __init__(self, path, pid):
        artifact.require(pid == os.getppid() and pid > 1, "original lock must belong to direct parent")
        approved = claims.launcher_lock()
        artifact.require(Path(path).absolute() == approved, "original global compatibility lock path required")
        self.path, self.pid = Path(path), pid
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.identity = artifact.stamp(os.fstat(self.fd))[:2]
        self.check()
    def check(self):
        artifact.require(os.getppid() == self.pid, "original lock owner exited")
        info = os.stat(self.path, follow_symlinks=False)
        artifact.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022 and
                         artifact.stamp(info)[:2] == self.identity, "original global lock replaced")
        artifact.require(artifact.read_file(self.path, "pid", 32, private=True) == (str(self.pid) + "\n").encode(), "original lock PID mismatch")
    def close(self):
        os.close(self.fd)


def run_bounded(command, deadline, *, input_file=None, maximum=1 << 20, guard=None):
    """Bound CLI output while reading, not after capture_output has exhausted RAM."""
    if guard is not None:
        guard()
    process = subprocess.Popen(command, stdin=input_file or subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    output, errors = bytearray(), bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            for pipe, target, limit in ((process.stdout, output, maximum), (process.stderr, errors, 128 << 10)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, (target, limit))
            while selector.get_map():
                if guard is not None:
                    guard()
                artifact.require(time.monotonic() < deadline, "build command deadline")
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj); continue
                    target, limit = key.data; target.extend(chunk)
                    artifact.require(len(target) <= limit, "build output bound")
            while process.poll() is None:
                if guard is not None:
                    guard()
                artifact.require(time.monotonic() < deadline, "build command exit deadline")
                time.sleep(0.05)
            status = process.returncode
            if guard is not None:
                guard()
        artifact.require(status == 0, "build CLI failed")
        return bytes(output)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        process.stdout.close(); process.stderr.close()


def unpack(raw):
    artifact.require(0 < len(raw) <= 45 << 20, "build export bound")
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as source:
        for member in source:
            artifact.require(member.name in {"native.test", "setup", "toolchain.sha256"} and member.name not in result and
                             member.isreg() and 0 < member.size <= artifact.BOUNDS[member.name], "build export member")
            result[member.name] = source.extractfile(member).read(member.size + 1)
            artifact.require(len(result[member.name]) == member.size, "truncated build export")
    artifact.require(set(result) == {"native.test", "setup", "toolchain.sha256"}, "build export names")
    artifact.static_arm64(result["native.test"]); artifact.static_arm64(result["setup"])
    artifact.toolchain_proof(result["toolchain.sha256"])
    return result


def owned(value, name, token, identifier=None):
    artifact.require(value.get("Name") == "/" + name and value.get("Config", {}).get("Labels", {}).get(OWNER) == token and
                     (identifier is None or value.get("Id") == identifier), "exact build-container ownership required")
    return value


def container_policy(value, image_id, case_id="RTM-081"):
    script = build_script(case_id)
    host = value["HostConfig"]
    artifact.require(value["Image"] == image_id and value["Config"]["Cmd"] == ["timeout", "-k", "2", "220", "sh", "-ec", script] and
                     host["Memory"] == 1 << 30 and host["MemorySwap"] == 1 << 30 and host["NanoCpus"] == 2000000000 and
                     host["PidsLimit"] == 64 and host["ReadonlyRootfs"] is True and host["NetworkMode"] == "none" and
                     host["Privileged"] is False and host.get("Binds") in (None, []) and host["CapDrop"] == ["ALL"] and
                     host["Tmpfs"] == {"/work": "rw,nosuid,nodev,size=512m", "/tmp": "rw,nosuid,nodev,size=32m"} and
                     any(v in ("no-new-privileges", "no-new-privileges:true") for v in host["SecurityOpt"]), "hard build-container limits")
    limits = {v["Name"]: (v["Soft"], v["Hard"]) for v in host["Ulimits"]}
    artifact.require(limits.get("nofile") == (256, 256) and limits.get("core") == (0, 0), "build FD/core limits")


def write_new(directory, name, raw):
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def build(args):
    selected = artifact.selection(getattr(args, "case", "RTM-081"))
    script = build_script(selected["case"])
    endpoint(args.host)
    artifact.approved_daemon_id(args.daemon_id)
    artifact.sha(args.image_id.removeprefix("sha256:")); artifact.sha(args.mke2fs_sha256)
    artifact.require(args.image_id.startswith("sha256:"), "approved builder IDs required")
    lock = OriginalLock(args.lock, args.lock_pid)
    destination = Path(args.destination).absolute()
    artifact.require(destination.parent.is_dir(), "existing owned artifact parent required")
    parent = os.stat(destination.parent, follow_symlinks=False)
    artifact.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o022, "unsafe artifact parent")
    destination.mkdir(mode=0o700)  # Exclusive; never overwrite/adopt an earlier build.
    token = uuid.uuid4().hex; name = "rtm081-build-" + token
    image_id, container_id = args.image_id, None
    deadline = time.monotonic() + 280
    docker_config = destination / "docker-config"; docker_config.mkdir(mode=0o700)
    command = [args.docker, "--config", str(docker_config), "--host", args.host]
    count = 0
    def call(*values, maximum=1 << 20, input_file=None, cleanup=False):
        nonlocal count
        if cleanup:
            artifact.require(tuple(values[:2]) in {("container", "inspect"), ("container", "ls")} or values[0] == "rm",
                             "authority-loss cleanup is inspect/removal only")
        else:
            lock.check()
        count += 1; artifact.require(count <= 20, "build command count")
        return run_bounded(command + list(values), min(deadline + (15 if cleanup else 0), time.monotonic() + (230 if values[0] == "start" else 10)),
                           input_file=input_file, maximum=maximum, guard=None if cleanup else lock.check)
    def inspect(*, cleanup=False):
        rows = json.loads(call("container", "inspect", name, cleanup=cleanup), object_pairs_hook=artifact.object_pairs)
        artifact.require(len(rows) == 1, "exact builder inspect")
        return owned(rows[0], name, token, container_id)
    plan = {"schema": artifact.SCHEMA, "name": name, "owner": token, "daemon_id": args.daemon_id,
            "reference": artifact.BUILDER, "image_id": image_id, "limits": artifact.LIMITS, "selection": selected}
    write_new(destination, "plan.json", artifact.encode(plan))
    directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); os.fsync(directory); os.close(directory)
    attempted, removed, failed = False, False, True
    try:
        source = artifact.snapshot(ROOT)
        hashes = {n: artifact.digest(b) for n, b in source.items()}
        formatter_path = Path(args.mke2fs).resolve(strict=True)
        formatter = artifact.read_file(formatter_path.parent, formatter_path.name, 8 << 20)
        artifact.require(artifact.digest(formatter) == args.mke2fs_sha256, "formatter asset pin")
        artifact.static_arm64(formatter)
        identity = json.loads(call("info", "--format", "{{json .}}"), object_pairs_hook=artifact.object_pairs)
        artifact.require(identity.get("ID") == args.daemon_id and identity.get("OSType") == "linux" and
                         identity.get("Architecture") in ("aarch64", "arm64") and identity.get("CgroupVersion") == "2", "explicit build daemon identity")
        images = json.loads(call("image", "inspect", artifact.BUILDER), object_pairs_hook=artifact.object_pairs)
        artifact.require(len(images) == 1 and images[0]["Id"] == image_id and artifact.BUILDER in images[0]["RepoDigests"] and
                         images[0]["Architecture"] == "arm64" and images[0]["Os"] == "linux", "trusted cached Go image required; no pulls")
        payload = tar_bytes([(n, b, 0o644) for n, b in source.items()])
        artifact.require(len(payload) <= 140 << 20, "source archive bound")
        write_new(destination, "source.tar", payload)
        attempted = True
        result = call("create", "--pull=never", "--name", name, "--label", OWNER + "=" + token,
            "--platform", "linux/arm64", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--memory", "1g", "--memory-swap", "1g", "--cpus", "2", "--pids-limit", "64",
            "--ulimit", "nofile=256:256", "--ulimit", "core=0:0", "--tmpfs", "/work:rw,nosuid,nodev,size=512m",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "-i", image_id, "timeout", "-k", "2", "220", "sh", "-ec", script)
        container_id = artifact.sha(result.decode().strip())
        container_policy(inspect(), image_id, selected["case"])
        with open(destination / "source.tar", "rb") as stream:
            files = unpack(call("start", "-ai", name, input_file=stream, maximum=45 << 20))
        state = inspect()["State"]
        artifact.require(state["Running"] is False and type(state["ExitCode"]) is int and state["ExitCode"] == 0 and state["OOMKilled"] is False,
                         "compiler exit/OOM proof")
        artifact.require(artifact.inventory(ROOT) == hashes and artifact.read_file(formatter_path.parent, formatter_path.name, 8 << 20) == formatter,
                         "build input or formatter changed")
        files["mke2fs"] = formatter
        for filename, raw in files.items():
            write_new(destination, filename, raw)
        failed = False
    finally:
        try:
            if attempted:
                # Reconcile ambiguous create by exact random name+label only.
                value = inspect(cleanup=True)
                container_id = artifact.sha(value["Id"])
                call("rm", "-f", value["Id"], cleanup=True)
                remaining = json.loads(call("container", "ls", "-a", "--no-trunc", "--filter", "id=" + value["Id"], "--format", "json", cleanup=True) or b"[]")
                artifact.require(remaining == [], "build-container cleanup absence")
                removed = True
        finally:
            try:
                if not failed:
                    try:
                        lock.check()  # Never publish a success fixture after authority loss.
                    except BaseException:
                        failed = True
                        raise
            finally:
                write_new(destination, "cleanup.json", artifact.encode({"container": container_id, "removed": removed, "failed": failed}))
                lock.close()
    artifact.require(removed and not failed, "completed owned build required")
    manifest = {"schema": artifact.SCHEMA, "sources": hashes, "selection": selected,
        "builder": {"reference": artifact.BUILDER, "image_id": image_id, "daemon_id": args.daemon_id,
            "container": container_id, "limits": artifact.LIMITS, "exit": 0, "oom": False,
            "crosscompiled": ["arm64", "amd64"]},
        "binaries": {n: {"sha256": artifact.digest(files[n]), "bytes": len(files[n])} for n in ("native.test", "setup", "mke2fs")},
        "toolchain": artifact.toolchain_proof(files["toolchain.sha256"]), "formatter_sha256": args.mke2fs_sha256,
        "cleanup": {"container": container_id, "removed": True}}
    raw = artifact.encode(manifest); write_new(destination, "fixture.json", raw)
    directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); os.fsync(directory); os.close(directory)
    print(json.dumps({"fixture": str(destination), "manifest_sha256": artifact.digest(raw)}))


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "image-id", "lock", "destination", "mke2fs", "mke2fs-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--daemon-id", type=artifact.approved_daemon_id, required=True)
    parser.add_argument("--lock-pid", type=int, required=True)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--case", choices=tuple(artifact.SELECTIONS), default="RTM-081")
    return parser


if __name__ == "__main__":
    build(argument_parser().parse_args())
