#!/usr/bin/env python3
"""Opt-in disposable Lima Docker reference. Never uses an ambient Docker context.

Prerequisites: Python 3.11+, macOS 26+ arm64, installed Lima 2.2.0 and Docker CLI,
and a local SHA-256-pinned aarch64 cloud image containing the EXACT requested Docker Engine
version, systemd, cloud-init, sudo, SSH and all Lima guest dependencies. No image
is downloaded, no packages are installed, and default Lima templates are NOT used.
The image must have Docker's systemd docker.service/docker.socket units, an empty
Docker data root (including no cloned engine ID), and no automatic update jobs.
The image digest pins the engine inputs too; --engine-version checks the server.

Example (all paths must be absolute, canonical, and free of symlink components):
  python3 tools/volume_reference.py provision --allow-disposable-vm \\
    --root /Volumes/data/vr/run-001 --image /Volumes/data/images/docker.raw \\
    --image-sha256 <64-hex> --engine-version 29.2.1 \\
    --limactl /opt/homebrew/Cellar/lima/2.2.0/bin/limactl \\
    --docker /absolute/canonical/path/to/docker
  python3 tools/volume_reference.py status --root /Volumes/data/vr/run-001
  python3 tools/volume_reference.py crash --root /Volumes/data/vr/run-001 --run-id <UUID>
  python3 tools/volume_reference.py restart --root /Volumes/data/vr/run-001 --run-id <UUID>
  python3 tools/volume_reference.py destroy --root /Volumes/data/vr/run-001 --run-id <UUID>

Use a spacious parent directory; do not use the almost-full home volume. Provision
prints the run UUID and unix:// endpoint. --owned-fixture creates the ONLY optional
host mount, under this new run root, at /mnt/volume-reference; it is a candidate,
NOT a qualified bind-mount oracle. --same-path-fixture requires --owned-fixture and
mounts that newly created root/fixture at its identical absolute guest path instead.
No existing fixture can be imported. No default home mounts or SSH agent forwarding.
Crash means exact-instance `limactl stop --force`, not a clean Docker shutdown.
Restart is explicit, limited to eight attempts per run, and requires a durably
verified crash plus a fresh exact-instance Stopped check. The old daemon ID must
match after startup. Restart intent is fsynced first; interrupted/failed attempts
are terminal (never retried/adopted). Only the expected socket inode may change.
Destroy deletes only that Lima instance; receipts, logs and fixture remain. There
is no automatic cleanup, resume/adoption, reset, process-name scan, or TTL reaper.
Command runtimes are capped; the VM remains until explicitly destroyed. A crash
or interruption before ownership/daemon identity is committed fails closed and
may require manual investigation of the preserved private home; never auto-adopt.
Trust boundary: local POSIX filesystems without ACLs granting extra write access;
root and the invoking UID, the pinned tools and their installed dependencies are
trusted. Every path component must be owned by root or this UID; directories and
regular files must not be writable by group/others. The only exception is the root-owned sticky
system /private/tmp (macOS) or /tmp (Linux), with trusted children; /tmp aliases
must still be canonicalized by the caller. Other writable/sticky roots are refused.
Descriptor-relative no-follow checks pin hashing to the inspected file. Execution
and Lima image consumption remain pathname-based on macOS, so concurrent changes
by trusted actors, ACLs, hostile mounts, or a malicious same-UID/root actor are
unsupported. Receipts guard accidental replacement, not privileged forgery.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import stat
import subprocess
import sys
import time
import uuid

LIMA_VERSION = "2.2.0"
# Lima creates this exact reviewed default even with networks: []. This is NOT
# permission to attach a named network or accept arbitrary global configuration.
NETWORKS_SHA = "2fed4d81dc833fe20760dcb9ba80d265b8802a43d5ab28600edf51ce0dc9cdf3"
MAX_RESTARTS = 8
SCHEMA = "cengine-disposable-volume-reference-v1"
MAX_OUTPUT = 1024 * 1024
FIXTURE_SOURCE = Path(__file__).resolve().parent / "fixtures" / "volume-reference.txt"
LIMITS = {"cpus": (1, 4), "memory_gib": (1, 8), "disk_gib": (8, 64),
          "timeout": (10, 900)}
DIRECTORIES = ("lima", "host-home", "cache", "tmp", "docker-config", "artifacts")


class Refusal(RuntimeError):
    """Fail closed, leaving all artifacts intact."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def canonical(value, *, exists=True):
    path = Path(value)
    require(path.is_absolute(), f"absolute path required: {value}")
    require(str(path) == str(path.resolve(strict=exists)),
            f"noncanonical or symlink path refused: {value}")
    return path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def trusted_info(path, info):
    require(not stat.S_ISLNK(info.st_mode), f"symlink refused: {path}")
    require(info.st_uid in {0, os.getuid()}, f"untrusted owner: {path}")
    system_tmp = Path("/private/tmp" if sys.platform == "darwin" else "/tmp")
    sticky_tmp = (path == system_tmp and stat.S_ISDIR(info.st_mode)
                  and info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
    if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode):
        require(info.st_mode & 0o022 == 0 or sticky_tmp,
                f"group/other-writable path refused: {path}")
    if stat.S_ISREG(info.st_mode):
        require(info.st_nlink == 1, f"hardlinked file refused: {path}")


@contextmanager
def trusted_parent(path):
    """Walk from / using no-follow directory FDs; never follow a replaced parent."""
    path = canonical(path, exists=False)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    current = Path("/")
    try:
        trusted_info(current, os.fstat(fd))
        for part in path.parts[1:-1]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            current /= part
            trusted_info(current, os.fstat(fd))
        yield fd
    finally:
        os.close(fd)


def file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def identity(path, *, hashed=False):
    path = canonical(path)
    with trusted_parent(path) as parent:
        name = path.name or "."
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        trusted_info(path, info)
        result: dict[str, int | str] = {"dev": info.st_dev, "ino": info.st_ino, "uid": info.st_uid,
                  "gid": info.st_gid, "permissions": stat.S_IMODE(info.st_mode),
                  "mode": stat.S_IFMT(info.st_mode)}
        if hashed:
            require(stat.S_ISREG(info.st_mode), f"regular file required: {path}")
            # NONBLOCK prevents a raced-in FIFO from hanging the preflight.
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                require(file_stamp(os.fstat(fd)) == file_stamp(info), f"file changed while opening: {path}")
                result["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
                require(file_stamp(os.fstat(fd)) == file_stamp(info), f"file changed while hashing: {path}")
            require(file_stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == file_stamp(info),
                    f"file replaced while hashing: {path}")
        return result


def check_identity(path, expected):
    require(identity(path, hashed="sha256" in expected) == expected,
            f"ownership/content identity changed: {path}")


def private_directory(path):
    with trusted_parent(path) as parent:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
    return identity(path)


def write_new(path, contents):
    with trusted_parent(path) as parent:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
    with os.fdopen(fd, "wb") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(root, state):
    check_identity(root, state["records"]["."])
    target = root / (".state-" + uuid.uuid4().hex)
    write_new(target, (json.dumps(state, indent=2, sort_keys=True) + "\n").encode())
    os.replace(target, root / "state.json")
    sync_directory(root)


def run_bounded(argv, *, env, cwd, stdin, stdout, stderr, timeout, check):
    """Drain both output pipes with hard byte/deadline caps; kill only OUR child.

    A Lima-launched VM is intentionally not killed on error: its private records
    and logs remain for investigation. No descendant/PID-name guessing occurs.
    """
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(argv, env=env, cwd=cwd, stdin=stdin,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    try:
        with selectors.DefaultSelector() as selector:
            for source, destination in zip(streams, (stdout, stderr)):
                os.set_blocking(source.fileno(), False)
                selector.register(source, selectors.EVENT_READ, [destination, 0])
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in selector.select(remaining):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    destination, count = key.data
                    destination.write(block[:max(0, MAX_OUTPUT - count)])
                    key.data[1] += len(block)
                    require(key.data[1] <= MAX_OUTPUT, "subprocess output limit exceeded; partial logs preserved")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            code = process.wait(timeout=remaining)
            return subprocess.CompletedProcess(argv, code)
    finally:
        primary = sys.exception()
        try:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as cleanup_error:
            if primary is None:
                raise
            primary.add_note(f"Child cleanup failed; child may remain unreaped: {cleanup_error}")
        finally:
            for stream in streams:
                stream.close()
            stdout.flush()
            stderr.flush()


def make_config(state):
    # Lima 2.2.0's installed templates/default.yaml documents guest {{.User}}
    # in scripts and host {{.Dir}} in socket paths; docker-rootful.yaml uses both.
    fixture = state["fixture"]
    return {
        "minimumLimaVersion": LIMA_VERSION, "vmType": "vz", "arch": "aarch64",
        "os": "Linux", "images": [{"location": state["image"], "arch": "aarch64",
                                   "digest": "sha256:" + state["image_sha256"]}],
        "cpus": state["cpus"], "memory": f'{state["memory_gib"]}GiB',
        "disk": f'{state["disk_gib"]}GiB', "additionalDisks": [], "networks": [],
        "mounts": ([{"location": str(Path(state["root"]) / "fixture"),
                     "mountPoint": (str(Path(state["root"]) / "fixture") if state.get("same_path_fixture")
                                    else "/mnt/volume-reference"), "writable": True}]
                   if fixture else []),
        "mountType": "virtiofs", "mountInotify": False,
        "ssh": {"loadDotSSHPubKeys": False, "forwardAgent": False,
                "forwardX11": False, "forwardX11Trusted": False},
        "containerd": {"system": False, "user": False}, "upgradePackages": False,
        "vmOpts": {"vz": {"rosetta": {"enabled": False, "binfmt": False}}},
        "hostResolver": {"enabled": False},
        "portForwards": [
            {"guestSocket": "/var/run/docker.sock",
             "hostSocket": "{{.Dir}}/sock/docker.sock"},
            {"guestPortRange": [1, 65535], "proto": "any", "ignore": True}],
        "provision": [
            {"mode": "dependency", "skipDefaultDependencyResolution": True,
             "script": "#!/bin/sh\nset -eu\ncommand -v docker\ncommand -v systemctl\n"},
            {"mode": "system", "script": (
                "#!/bin/sh\nset -eu\n"
                "install -d -m 0755 /etc/systemd/system/docker.socket.d\n"
                "printf '[Socket]\\nSocketUser={{.User}}\\nSocketMode=0600\\n' "
                "> /etc/systemd/system/docker.socket.d/volume-reference.conf\n"
                "systemctl daemon-reload\nsystemctl stop docker.service docker.socket\n"
                "systemctl start docker.socket docker.service\n")}],
        "probes": [{"mode": "readiness", "description": "preinstalled Docker socket",
                    "script": "#!/bin/sh\nset -eu\ndocker --host unix:///var/run/docker.sock info >/dev/null\n"}],
    }


class Reference:
    def __init__(self, root, runner=run_bounded):
        self.root = canonical(root)
        require(identity(self.root)["mode"] == stat.S_IFDIR, "run root must be a directory")
        self.runner = runner
        self.lock = None
        self.state = {}
        self.receipt_identity = None

    def __enter__(self):
        path = self.root / "lock"
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        self.lock = os.fdopen(fd, "r+")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            canonical(self.root / "state.json")
            info = (self.root / "state.json").stat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and info.st_nlink == 1 and info.st_mode & 0o077 == 0,
                    "state.json must be a private, owned regular file")
            self.receipt_identity = identity(self.root / "state.json", hashed=True)
            self.state = json.loads((self.root / "state.json").read_text())
            require(isinstance(self.state, dict), "state.json must contain an ownership object")
            self.guard()
            return self
        except BaseException:
            self.lock.close()
            raise

    def __exit__(self, *_):
        if self.lock is not None:
            self.lock.close()

    @property
    def vm(self):
        return self.root / "lima" / self.state["name"]

    @property
    def socket(self):
        return self.vm / "sock" / "docker.sock"

    def globals(self):
        # Lima v2.2.0 creates SSH keys and its pinned default networks.yaml.
        # No named networks/additional disks/templates are requested by make_config.
        home = self.root / "lima"
        require(set(p.name for p in home.iterdir()) <= {"_config", self.state["name"]},
                "foreign Lima home entries refused")
        config = home / "_config"
        if not config.exists() and not config.is_symlink():
            return {}
        require(config.is_dir(), "Lima _config must be a directory")
        result = {"lima/_config": identity(config)}
        for item in config.iterdir():
            require(item.name in {"user", "user.pub", "networks.yaml"}, "foreign Lima global configuration refused")
            record = identity(item, hashed=True)
            if item.name == "networks.yaml":
                require(record["sha256"] == NETWORKS_SHA, "unexpected Lima default networks content")
            result[str(item.relative_to(self.root))] = record
        return result

    def persist(self):
        check_identity(self.root / "state.json", self.receipt_identity)
        save(self.root, self.state)
        self.receipt_identity = identity(self.root / "state.json", hashed=True)

    def journal_phase(self, phase, **evidence):
        # The atomic receipt is the durable lifecycle journal, not an advisory log.
        self.state.setdefault("lifecycle", []).append({"phase": phase, "time": time.time(), **evidence})
        self.state["phase"] = phase
        self.persist()

    def guard(self, *, transition=False, socket_replacement=False):
        check_identity(self.root / "state.json", self.receipt_identity)
        s = self.state
        require(s["schema"] == SCHEMA and s["root"] == str(self.root), "foreign run root/receipt")
        run = uuid.UUID(s["run_id"])
        require(s["name"] == "vr-" + run.hex[:12], "foreign VM name")
        require(s["endpoint"] == "unix://" + str(self.socket), "foreign Docker endpoint")
        for key, (low, high) in LIMITS.items():
            require(type(s[key]) is int and low <= s[key] <= high, f"invalid {key} bound")
        require({".", "lock", "config.yaml", *DIRECTORIES} <= s["records"].keys(),
                "incomplete ownership receipt")
        require(not s.get("same_path_fixture") or s["fixture"], "same-path fixture requires owned fixture")
        require(type(s.get("restart_count", 0)) is int and 0 <= s.get("restart_count", 0) <= MAX_RESTARTS,
                "invalid restart count bound")
        if s["fixture"]:
            require("fixture" in s["records"], "missing fixture ownership")
        require(not socket_replacement or s["phase"] == "restarting", "unexpected socket replacement transition")
        for relative, record in s["records"].items():
            require(relative == "." or (not Path(relative).is_absolute() and ".." not in Path(relative).parts),
                    "foreign identity path")
            if s["phase"] == "destroyed" and relative.startswith("lima/" + s["name"]):
                require(not os.path.lexists(self.root / relative), "deleted VM path reappeared")
                continue
            if relative == str(self.socket.relative_to(self.root)) and socket_replacement:
                continue  # Only after OUR successful restart command, never when reopening.
            if relative == str(self.socket.relative_to(self.root)) and not os.path.lexists(self.socket):
                require(s["phase"] in {"crashing", "crashed", "destroying", "restarting",
                                       "restart-unverified", "restart-failed"},
                        "verified live Docker socket disappeared; refusing ownership")
                continue  # Only an expected stop/delete transition may remove it.
            check_identity(self.root / relative, record)
        for relative in (".",) + DIRECTORIES:
            info = (self.root / relative).stat()
            require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                    f"private owned directory required: {relative}")
        for tool in ("limactl", "docker"):
            check_identity(Path(s[tool]), s[tool + "_identity"])
        if not transition:
            require(self.globals() == s["globals"], "Lima global identities changed")
            for relative in (str(self.vm.relative_to(self.root)),
                             str((self.vm / "lima.yaml").relative_to(self.root)),
                             str(self.socket.relative_to(self.root))):
                require(relative in s["records"] or not os.path.lexists(self.root / relative),
                        f"unrecorded VM/config/endpoint; preserve and investigate: {relative}")
        if s["phase"] != "destroyed":
            require(not os.path.lexists(self.vm / "lima.yaml") or
                    str((self.vm / "lima.yaml").relative_to(self.root)) in s["records"] or transition,
                    "unrecorded VM configuration")

    def environment(self):
        s = self.state
        return {"PATH": str(Path(s["limactl"]).parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": str(self.root / "host-home"), "LIMA_HOME": str(self.root / "lima"),
                "XDG_CONFIG_HOME": str(self.root / "host-home"),
                "XDG_CACHE_HOME": str(self.root / "cache"),
                "LIMA_CACHE_HOME": str(self.root / "cache"), "TMPDIR": str(self.root / "tmp"),
                "DOCKER_CONFIG": str(self.root / "docker-config"),
                "LANG": "C", "LC_ALL": "C", "TERM": "dumb"}

    def invoke(self, tool, arguments, label, *, timeout=None):
        self.guard()
        log = self.root / "artifacts" / (label + "-" + uuid.uuid4().hex)
        private_directory(log)
        argv = [self.state[tool], *arguments]
        write_new(log / "command.json", json.dumps(argv).encode())
        sync_directory(log)
        sync_directory(log.parent)
        # File-backed output prevents unbounded Python memory use; timeouts never
        # guess a VM PID or kill unrelated host processes. Partial logs survive.
        with (log / "stdout").open("xb") as stdout, (log / "stderr").open("xb") as stderr:
            result = self.runner(argv, env=self.environment(), cwd=self.root,
                                 stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                 timeout=timeout or self.state["timeout"], check=False)
        require(result.returncode == 0, f"{label} failed ({result.returncode}); logs: {log}")
        require(all((log / stream).stat().st_size <= MAX_OUTPUT for stream in ("stdout", "stderr")),
                f"oversized response: {log}")
        return (log / "stdout").read_text()

    def daemon(self, *, establish=False):
        require(self.socket.exists(), "owned Docker socket unavailable; artifacts preserved")
        record = identity(self.socket)
        require(record["mode"] == stat.S_IFSOCK, "endpoint is not a Unix socket")
        relative = str(self.socket.relative_to(self.root))
        require(self.state["records"].get(relative) == record, "unowned Docker socket")
        result = json.loads(self.invoke("docker", ["--config", str(self.root / "docker-config"),
            "--host", self.state["endpoint"], "info", "--format", "{{json .}}"],
            "docker-info", timeout=min(30, self.state["timeout"])))
        require(result.get("ServerVersion") == self.state["engine_version"], "foreign engine version")
        require(result.get("OSType") == "linux" and result.get("Architecture") in ("aarch64", "arm64"),
                "foreign engine platform")
        require(isinstance(result.get("ID"), str) and bool(result["ID"]), "missing Docker daemon identity")
        require(not any("rootless" in str(option) for option in result.get("SecurityOptions", [])),
                "rootless engine refused")
        if not establish:
            require(result["ID"] == self.state["daemon_id"], "Docker daemon identity changed")
        self.guard()
        return result["ID"]

    def capture_created(self):
        # Only called after OUR successful create, never on a retry or import.
        self.guard(transition=True)
        require(self.vm.is_dir() and (self.vm / "lima.yaml").is_file(),
                "create did not produce the expected VM directory and regular config")
        for path in (self.vm, self.vm / "lima.yaml"):
            self.state["records"][str(path.relative_to(self.root))] = identity(path, hashed=path.is_file())
        require(not os.path.lexists(self.socket), "socket appeared before start; refusing ownership")
        self.state["globals"] = self.globals()
        self.state["phase"] = "created"
        self.persist()
        self.guard()

    def start(self):
        check_identity(Path(self.state["image"]), self.state["image_identity"])
        self.state["phase"] = "starting"
        self.persist()
        self.invoke("limactl", ["start", "--tty=false", "--timeout", f'{self.state["timeout"]}s',
                                self.state["name"]], "start")
        check_identity(Path(self.state["image"]), self.state["image_identity"])
        self.guard(transition=True)
        current_globals = self.globals()
        require(all(current_globals.get(key) == value for key, value in self.state["globals"].items()),
                "Lima global identity replaced during start")
        self.state["globals"] = current_globals
        require((self.vm / "sock").is_dir(), "forwarding socket parent is not a directory")
        for path in (self.vm / "sock", self.socket):
            self.state["records"][str(path.relative_to(self.root))] = identity(path)
        self.state["phase"] = "started-unverified"
        self.persist()
        self.state["daemon_id"] = self.daemon(establish=True)
        self.state["phase"] = "ready"
        self.persist()

    def instance(self, expected):
        require(all(str(path.relative_to(self.root)) in self.state["records"]
                    for path in (self.vm, self.vm / "lima.yaml")), "missing VM ownership")
        output = self.invoke("limactl", ["list", self.state["name"], "--json"],
                             "instance-status", timeout=min(30, self.state["timeout"]))
        rows = [json.loads(line) for line in output.splitlines() if line.strip()]
        require(len(rows) == 1 and isinstance(rows[0], dict), "expected exactly one owned instance")
        row = rows[0]
        require(row.get("name") == self.state["name"] and row.get("dir") == str(self.vm)
                and row.get("vmType") == "vz" and row.get("arch") == "aarch64", "foreign instance status")
        require(isinstance(row.get("status"), str) and row["status"] in expected,
                f'unexpected instance status: {row.get("status")}')
        self.guard()
        return row["status"]

    def restart(self, run_id):
        require(run_id == self.state["run_id"], "--run-id must match the durable receipt")
        self.guard()
        s = self.state
        require(s["phase"] == "crashed" and s.get("crash_verified") is True and s["daemon_id"],
                "restart requires a durably verified crash; no retry/adoption")
        require(all(str(path.relative_to(self.root)) in s["records"]
                    for path in (self.vm / "sock", self.socket)), "missing prior socket ownership")
        require(s.get("restart_count", 0) < MAX_RESTARTS, "restart attempt limit exceeded")
        check_identity(Path(s["image"]), s["image_identity"])
        self.instance({"Stopped"})
        check_identity(Path(s["image"]), s["image_identity"])
        s["restart_count"] = s.get("restart_count", 0) + 1
        s["crash_verified"] = False
        self.journal_phase("restarting", daemon_id=s["daemon_id"], attempt=s["restart_count"])
        try:
            self.invoke("limactl", ["start", "--tty=false", "--timeout", f'{s["timeout"]}s', s["name"]], "restart")
            check_identity(Path(s["image"]), s["image_identity"])
            self.guard(socket_replacement=True)
            relative = str(self.socket.relative_to(self.root))
            old, new = s["records"][relative], identity(self.socket)
            require(new["mode"] == stat.S_IFSOCK and
                    {k: v for k, v in new.items() if k != "ino"} ==
                    {k: v for k, v in old.items() if k != "ino"},
                    "unexpected restarted socket identity")
            s["records"][relative] = new
            self.journal_phase("restart-unverified")
            self.instance({"Running"})
            self.daemon()  # Never establish/adopt a new Docker daemon ID.
            check_identity(Path(s["image"]), s["image_identity"])
            self.journal_phase("ready", daemon_id=s["daemon_id"])
        except BaseException as error:
            try:
                self.journal_phase("restart-failed")
            except BaseException as journal_error:
                error.add_note(f"Unable to record terminal restart failure: {journal_error}")
            raise
        return self.status()

    def status(self):
        self.guard()
        result = {key: self.state[key] for key in ("root", "run_id", "name", "phase", "endpoint", "daemon_id")}
        result["socket_present"] = self.socket.exists()
        if result["phase"] in {"crashed", "crashing", "restarting", "restart-unverified", "restart-failed"}:
            result["instance_status"] = self.instance({"Stopped"} if result["phase"] == "crashed"
                                                       else {"Stopped", "Running"})
            if result["instance_status"] == "Stopped":
                return result
            require(result["socket_present"], "running instance has no verified Docker socket")
        if result["socket_present"]:
            self.daemon()
        return result

    def destructive(self, operation, run_id):
        require(operation in {"crash", "destroy"}, "unsupported destructive operation")
        require(run_id == self.state["run_id"], "--run-id must match the durable receipt")
        self.guard()
        phase = self.state["phase"]
        if operation == "destroy" and phase == "destroyed":
            return self.status()
        require(phase in {"created", "ready", "crashing", "crashed", "destroying",
                          "restarting", "restart-unverified", "restart-failed"},
                "interrupted/unverified provisioning: refusing destructive operation; preserve artifacts")
        require(str(self.vm.relative_to(self.root)) in self.state["records"], "VM was never adopted")
        instance_status = self.instance({"Stopped", "Running"})
        if instance_status == "Running":
            require(self.state["daemon_id"] and self.socket.exists(), "running instance requires verified daemon")
            self.daemon()
        if operation == "crash":
            require(phase == "ready" and instance_status == "Running"
                    and self.state["daemon_id"] and self.socket.exists(),
                    "crash requires a verified live daemon")
            self.state["crash_verified"] = False
            self.journal_phase("crashing")
            args = ["stop", "--force", self.state["name"]]
        else:
            self.state["phase"] = "destroying"
            args = ["delete", "--force", self.state["name"]]
        self.persist()
        self.invoke("limactl", args, operation)  # guard again immediately before mutation
        if operation == "destroy":
            require(not os.path.lexists(self.vm), "delete left VM records; artifacts preserved")
            self.state["phase"] = "destroyed"
            self.persist()
        else:
            self.instance({"Stopped"})
            self.state["crash_verified"] = True
            self.journal_phase("crashed", name=self.state["name"], directory=str(self.vm), status="Stopped")
        return self.status()


def provision(args, runner=run_bounded):
    require(args.allow_disposable_vm, "provision requires --allow-disposable-vm")
    require(not args.same_path_fixture or args.owned_fixture, "--same-path-fixture requires --owned-fixture")
    require(platform.system() == "Darwin" and platform.machine() == "arm64"
            and int(platform.mac_ver()[0].split(".")[0]) >= 26, "requires macOS 26+ Apple silicon")
    for key, (low, high) in LIMITS.items():
        require(low <= getattr(args, key) <= high, f"{key} must be {low}..{high}")
    require(re.fullmatch(r"[0-9a-f]{64}", args.image_sha256), "image SHA-256 must be 64 lowercase hex digits")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", args.engine_version),
            "exact engine version required, not latest/a range")
    root = canonical(args.root, exists=False)
    # Lima expands templates in image/mount paths. A literal owned path containing
    # {{.User}} or {{.Home}} could otherwise redirect the mount to ambient data.
    require(not any(token in str(root) or token in args.image for token in ("{{", "}}")),
            "Lima template delimiters in root/image paths refused")
    require(identity(root.parent)["mode"] == stat.S_IFDIR, "run parent must be a trusted directory")
    forbidden = [(Path.home() / name).resolve() for name in (".lima", ".colima")]
    for name in ("LIMA_HOME", "COLIMA_HOME"):
        if os.environ.get(name):
            forbidden.append(Path(os.environ[name]).expanduser().resolve())
    require(not any(root == p or p in root.parents for p in forbidden), "ambient Lima/Colima home refused")
    require(not os.path.lexists(root), "existing run root refused (including empty directories)")
    image = canonical(args.image)
    require(image.is_file() and image.stat().st_size > 0, "nonempty local boot image required")
    image_id = identity(image, hashed=True)
    require(image_id["sha256"] == args.image_sha256, "boot image digest mismatch")
    tools = {}
    for name in ("limactl", "docker"):
        path = canonical(getattr(args, name))
        require(path.is_file() and os.access(path, os.X_OK), f"executable required: {path}")
        tools[name] = str(path)
        tools[name + "_identity"] = identity(path, hashed=True)
    # Reserve room for a full disk, image copy and a 2 GiB safety margin.
    fs = os.statvfs(root.parent)
    require(fs.f_bavail * fs.f_frsize >= args.disk_gib * 1024**3 + image.stat().st_size + 2 * 1024**3,
            "insufficient free space on selected run volume")
    run_id = str(uuid.uuid4())
    name = "vr-" + uuid.UUID(run_id).hex[:12]
    # Darwin sockaddr_un.sun_path is 104 bytes including the terminator.
    endpoint_path = root / "lima" / name / "sock" / "docker.sock"
    # Lima also uses a longer SSH control socket basename than docker.sock.
    require(len(os.fsencode(root / "lima" / name / "ssh.sock")) < 88
            and len(os.fsencode(endpoint_path)) < 104,
            "run root too long for Lima/macOS Unix sockets")
    fixture_bytes = b""
    if args.owned_fixture:
        fixture_identity = identity(FIXTURE_SOURCE, hashed=True)
        fixture_bytes = FIXTURE_SOURCE.read_bytes()
        require(hashlib.sha256(fixture_bytes).hexdigest() == fixture_identity["sha256"],
                "fixture source changed while reading")
    records = {".": private_directory(root)}
    for directory in DIRECTORIES:
        records[directory] = private_directory(root / directory)
    write_new(root / "lock", b"")
    records["lock"] = identity(root / "lock")
    if args.owned_fixture:
        records["fixture"] = private_directory(root / "fixture")
        write_new(root / "fixture" / "reference.txt", fixture_bytes)
    state = {"schema": SCHEMA, "root": str(root), "run_id": run_id, "name": name,
             "endpoint": "unix://" + str(endpoint_path), "phase": "prepared", "daemon_id": None,
             "image": str(image), "image_sha256": args.image_sha256, "image_identity": image_id,
             "engine_version": args.engine_version, "fixture": args.owned_fixture,
             "same_path_fixture": args.same_path_fixture, "restart_count": 0,
             "crash_verified": False, "lifecycle": [],
             "fixture_seed_sha256": hashlib.sha256(fixture_bytes).hexdigest() if args.owned_fixture else None,
             "globals": {}, "records": records, **tools,
             **{key: getattr(args, key) for key in LIMITS}}
    write_new(root / "config.yaml", (json.dumps(make_config(state), indent=2) + "\n").encode())
    records["config.yaml"] = identity(root / "config.yaml", hashed=True)
    save(root, state)
    sync_directory(root.parent)
    with Reference(root, runner) as ref:
        version = ref.invoke("limactl", ["--version"], "lima-version", timeout=10).strip()
        require(version == "limactl version " + LIMA_VERSION, f"requires exactly Lima {LIMA_VERSION}: {version}")
        check_identity(image, image_id)
        ref.state["phase"] = "creating"
        ref.persist()
        ref.invoke("limactl", ["create", "--tty=false", "--name", name, str(root / "config.yaml")], "create")
        check_identity(image, image_id)
        ref.capture_created()
        ref.start()
        return ref.status()


def parser():
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser("provision", help="create/start a fresh private reference VM (opt-in)")
    create.add_argument("--allow-disposable-vm", action="store_true")
    create.add_argument("--root", required=True)
    create.add_argument("--image", required=True)
    create.add_argument("--image-sha256", required=True)
    create.add_argument("--engine-version", required=True)
    create.add_argument("--limactl", required=True, help="canonical installed Lima 2.2.0 binary")
    create.add_argument("--docker", required=True, help="canonical installed Docker CLI binary")
    create.add_argument("--owned-fixture", action="store_true", help="mount only a newly created owned fixture")
    create.add_argument("--same-path-fixture", action="store_true",
                        help="with --owned-fixture, use its identical absolute guest path")
    for flag, default in (("cpus", 2), ("memory-gib", 4), ("disk-gib", 16), ("timeout", 300)):
        low, high = LIMITS[flag.replace("-", "_")]
        create.add_argument("--" + flag, type=int, default=default, help=f"{low}..{high}; default {default}")
    for command in ("status", "crash", "restart", "destroy"):
        sub = commands.add_parser(command)
        sub.add_argument("--root", required=True)
        if command != "status":
            sub.add_argument("--run-id", required=True)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "provision":
            output = provision(args)
        else:
            with Reference(args.root) as ref:
                if args.command == "status":
                    output = ref.status()
                elif args.command == "restart":
                    output = ref.restart(args.run_id)
                else:
                    output = ref.destructive(args.command, args.run_id)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except (Refusal, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"volume-reference: {error}\nNo automatic cleanup; preserve the run root and artifacts.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
