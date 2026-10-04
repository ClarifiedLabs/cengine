"""RTM-126 support: ordinary lifecycle cold recovery across an owned APFS remount.

No qualification driver, mount force, cache reset, image pull, or generic cleanup.
Failure leaves the fixed work directory and its retention marker intact.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, field
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import tarfile
import uuid
from types import SimpleNamespace
from typing import Any

import harness
import helper_fixture_lifetime as lifetime
import managed_storage_recovery as recovery
from managed_prepare_lifecycle_evidence import storage_target
import storage_backend_proof as backend

MAX_RECEIPT = 262144
CHILD_SECONDS = 300
IMAGE = "cengine-compat-remount:local"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*arguments):
    return subprocess.run(list(arguments), check=True, capture_output=True, timeout=60).stdout


def image_mount(image, mount, table):
    """Select only the exact owned image's sole mounted volume, never a disk guess."""
    matches = [row for row in table["images"] if row.get("image-path") == str(image)]
    require(len(matches) == 1, "owned image missing or ambiguous")
    entities = matches[0]["system-entities"]
    mounted = [row for row in entities if "mount-point" in row]
    require(len(mounted) == 1 and mounted[0]["mount-point"] == str(mount),
            "owned image mount mismatch")
    device = mounted[0].get("dev-entry", "")
    require(re.fullmatch(r"/dev/disk[0-9]+s[0-9]+", device), "invalid owned mount device")
    return device


def hdi_table():
    return plistlib.loads(command("/usr/bin/hdiutil", "info", "-plist"))


@dataclass
class OwnedImage:
    path: Path
    mount: Path
    inode: tuple
    mounted: bool = False
    device: str | None = None

    @classmethod
    def create(cls, work, name, mount, size):
        path = work / (name + ".sparseimage")
        require(not os.path.lexists(path) and mount.parent == work and mount.is_dir(),
                "image requires original fixed work paths")
        command("/usr/bin/hdiutil", "create", "-size", size, "-fs", "APFS",
                "-type", "SPARSE", "-volname", "cengine-" + name, str(path))
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
                "unsafe owned sparseimage")
        return cls(path, mount, (info.st_dev, info.st_ino))

    def validate(self):
        info = self.path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and (info.st_dev, info.st_ino) == self.inode, "owned sparseimage replaced")
        require(self.path.resolve(strict=True) == self.path and not self.mount.is_symlink(),
                "noncanonical image or mount")
        table = hdi_table()
        if self.mounted:
            require(image_mount(self.path, self.mount, table) == self.device,
                    "owned mount changed")
            require(os.path.ismount(self.mount), "owned mount is not mounted")
        else:
            require(not any(row.get("image-path") == str(self.path) for row in table["images"])
                    and not os.path.ismount(self.mount), "unexpected image attachment")

    def attach(self):
        require(not self.mounted, "image already attached")
        self.validate()
        command("/usr/bin/hdiutil", "attach", "-nobrowse", "-owners", "on",
                "-mountpoint", str(self.mount), str(self.path))
        # Any ambiguity after attach retains the image; never guess a detach target.
        self.device = image_mount(self.path, self.mount, hdi_table())
        self.mounted = True
        self.validate()

    def detach(self):
        require(self.mounted, "image not attached")
        self.validate()
        # Address the private fixed mount path, not a reusable /dev/disk number.
        command("/usr/bin/hdiutil", "detach", str(self.mount))  # Intentionally NO -force.
        self.mounted = False
        self.device = None
        self.validate()


def binary_stamp(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and path.resolve(strict=True) == path,
            "offline remount client must remain a canonical regular executable")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@dataclass
class OfflineRemount:
    value: Any
    retention: harness.CompatibilityRootRetention
    store: OwnedImage
    blocker: OwnedImage
    child: Any = None
    receipt: dict | None = None
    restart_pending: bool = False
    helper_released: bool = False
    finished: bool = False
    failure_census: Any = None
    failure_cleanup_incomplete: bool = False
    original_claim: tuple = field(init=False)
    original_work: Path = field(init=False)
    original_binary: Path = field(init=False)
    original_binary_stamp: tuple = field(init=False)

    def __post_init__(self):
        self.original_claim = lifetime.require_claim()
        self.original_work = self.value.work
        self.original_binary = self.value.owner_binary
        self.original_binary_stamp = binary_stamp(self.original_binary)

    def validate_boundary(self, *, detached=False):
        value, receipt = self.value, self.retention
        work = value.work
        require(value.binary == value.owner_binary == self.original_binary
                and binary_stamp(self.original_binary) == self.original_binary_stamp,
                "offline remount helper client changed")
        require(work == self.original_work and work.parent == lifetime.canonical_temp()
                and work.resolve(strict=True) == work and work.name.startswith("cengine-compat-")
                and value.root == work / "root" and value.process is None
                and value._managed_fixture_retention and not value._retain_root,
                "offline remount requires original unstarted fixed-work daemon")
        require(self.child is not None and self.child.exitcode == 0 and not self.child.is_alive()
                and self.receipt is not None and self.receipt.get("complete") is True,
                "offline remount requires joined successful child receipt")
        with harness._compatibility_root_claim(work, value.owner_binary) as directory:
            info = os.fstat(directory)
            require((info.st_dev, info.st_ino) == receipt.root_identity
                    and stat.S_IMODE(info.st_mode) == 0o700, "fixed work identity changed")
            marker = os.open(harness.COMPATIBILITY_RETAIN_FILE,
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(marker)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                        and (info.st_dev, info.st_ino, info.st_ctime_ns) == receipt.marker_identity
                        and os.read(marker, len(receipt.contents) + 1) == receipt.contents,
                        "original retention marker changed")
            finally:
                os.close(marker)
        require(self.store.path == work / "store.sparseimage" and self.store.mount == value.root
                and self.blocker.path == work / "blocker.sparseimage"
                and self.blocker.mount == work / "blocker", "foreign remount image")
        self.store.validate()
        self.blocker.validate()
        require((not self.store.mounted and not self.blocker.mounted) if detached else self.store.mounted,
                "unexpected image mount state")
        require(not harness.compatibility_runtime_processes(value.owner_binary, roots=(value.root,)),
                "owned runtime remains before remount")

    def run_child(self, previous=None):
        self.helper_released = False
        self.receipt = None
        context = multiprocessing.get_context("spawn")
        phase = 1 if previous is None else 2
        # Pickling the unstarted instance does NOT execute Daemon.__post_init__.
        self.child = context.Process(target=child_main, args=(self.value, phase, previous))
        succeeded = False
        try:
            self.child.start()
            self.child.join(timeout=CHILD_SECONDS)
            require(not self.child.is_alive() and self.child.exitcode == 0,
                    "remount child deadline or unsuccessful exit")
            result = read_child_receipt(self.value.work, phase)
            self.receipt = result
            self.validate_boundary()
            succeeded = True
            return result
        finally:
            try:
                if self.child.pid is not None and self.child.is_alive():
                    # Direct Python child only; native cleanup uses kernel ownership.
                    self.child.terminate()
                    self.child.join(timeout=5)
                    if self.child.is_alive():
                        self.child.kill()
                        self.child.join(timeout=5)
            finally:
                if not succeeded:
                    self.failed_child_cleanup()

    def failed_child_cleanup(self):
        """Failure never becomes success or mount-deletion authority."""
        value = self.value
        value._retain_root = True
        owned = False
        try:
            require(value.work == self.original_work and value.root == self.original_work / "root"
                    and value.owner_binary == self.original_binary
                    and binary_stamp(self.original_binary) == self.original_binary_stamp,
                    "failed child ownership changed")
            with harness._compatibility_root_claim(value.work, value.owner_binary) as directory:
                info = os.fstat(directory)
                require((info.st_dev, info.st_ino) == self.retention.root_identity,
                        "failed child work replaced")
                owned = True
                self.failure_census = harness.compatibility_runtime_processes(
                    value.owner_binary, roots=(value.root,))
                harness.terminate_compatibility_runtime(value.owner_binary, roots=(value.root,))
                self.failure_census = harness.compatibility_runtime_processes(
                    value.owner_binary, roots=(value.root,))
                require(not self.failure_census, "failed child runtime remains")
        except Exception:
            self.failure_cleanup_incomplete = True
        finally:
            try:
                if owned:
                    value.retain_root(reason="cleanup-incomplete" if self.failure_cleanup_incomplete
                                      else "unsafe-disk-phase")
            except Exception:
                self.failure_cleanup_incomplete = True

    def remount(self):
        require(self.helper_released, "helper ROOT descriptors not released")
        self.validate_boundary()
        before = backend.root_identity(self.value.root)
        self.store.detach()
        self.blocker.attach()  # Occupy the released device slot before the same store.
        self.store.attach()
        after = backend.root_identity(self.value.root)
        compare_host_identity(before, after)

    def final_cleanup(self):
        """RTM-126's closed, shallow layout only. Never walk either APFS root."""
        require(type(self) is OfflineRemount, "invalid remount cleanup transaction")
        value, work = self.value, self.original_work
        require(self.finished and self.helper_released and not self.restart_pending,
                "remount did not finish helper release and detach")
        self.validate_boundary(detached=True)
        require(lifetime.require_claim() == self.original_claim, "remount runner claim changed")
        owner, marker = harness.COMPATIBILITY_OWNER_FILE, harness.COMPATIBILITY_RETAIN_FILE
        top_files = {owner, marker, "store.sparseimage", "blocker.sparseimage", "daemon.log",
                     "alpine.oci.tar", "alpine-named.oci.tar", "remount-phase1.json", "remount-phase2.json"}
        with ExitStack() as stack:
            directory = stack.enter_context(harness._compatibility_root_claim(work, value.owner_binary))
            parent = os.open(work.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            stack.callback(os.close, parent)
            device = self.retention.root_identity[0]

            def same_work():
                opened, named = os.fstat(directory), os.stat(work.name, dir_fd=parent, follow_symlinks=False)
                require((opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)
                        == self.retention.root_identity and stat.S_ISDIR(named.st_mode)
                        and named.st_uid == os.getuid() and stat.S_IMODE(named.st_mode) == 0o700,
                        "remount work changed during final cleanup")

            def checked(fd, name, expected, opened=None):
                same_work()
                named = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require((named.st_dev, named.st_ino, named.st_mode) == expected
                        and named.st_dev == device and named.st_uid == os.getuid(),
                        "remount entry changed or foreign device")
                if opened is not None:
                    info = os.fstat(opened)
                    require((info.st_dev, info.st_ino, info.st_mode) == expected,
                            "remount opened entry changed or foreign device")
                return named

            def pin(fd, name, directory_entry=False):
                same_work()
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if directory_entry:
                    flags |= os.O_DIRECTORY
                opened = os.open(name, flags, dir_fd=fd)
                stack.callback(os.close, opened)
                info = os.fstat(opened)
                expected = (info.st_dev, info.st_ino, info.st_mode)
                checked(fd, name, expected, opened)
                require(stat.S_ISDIR(info.st_mode) if directory_entry else
                        stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe remount entry type")
                return opened, expected

            same_work()
            names = set(os.listdir(directory))
            require(names <= top_files | {"root", "blocker", "run"}
                    and {owner, marker, "root", "blocker", "run", "store.sparseimage",
                         "blocker.sparseimage"} <= names, "unexpected remount work layout")
            dirs = {name: pin(directory, name, True) for name in ("root", "blocker", "run")}
            files = {name: pin(directory, name) for name in names & top_files}
            for image in (self.store, self.blocker):
                require(files[image.path.name][1][:2] == image.inode, "remount image replaced")
            marker_fd, marker_id = files[marker]
            require(marker_id[:2] == self.retention.marker_identity[:2]
                    and os.fstat(marker_fd).st_ctime_ns == self.retention.marker_identity[2]
                    and stat.S_IMODE(marker_id[2]) == 0o600
                    and os.read(marker_fd, len(self.retention.contents) + 1) == self.retention.contents,
                    "original remount retention changed")
            for name in ("root", "blocker"):
                fd, identity = dirs[name]
                checked(directory, name, identity, fd)
                require(not os.listdir(fd), "remount mountpoint is not empty")
            run, run_id = dirs["run"]
            checked(directory, "run", run_id, run)
            run_names = set(os.listdir(run))
            require(run_names <= {"docker.sock", "docker.sock.lock"}, "unexpected remount run layout")
            run_entries = {}
            for name in run_names:
                checked(directory, "run", run_id, run)
                info = os.stat(name, dir_fd=run, follow_symlinks=False)
                require(info.st_dev == device and info.st_uid == os.getuid() and info.st_nlink == 1
                        and (stat.S_ISSOCK(info.st_mode) if name == "docker.sock" else
                             stat.S_ISREG(info.st_mode)), "unsafe remount run entry")
                run_entries[name] = (info.st_dev, info.st_ino, info.st_mode)
            # All preflight checks precede mutation. Recheck names/devices before
            # every operation; rmdir is the ONLY operation on APFS mountpoints.
            try:
                for name, identity in run_entries.items():
                    checked(directory, "run", run_id, run)
                    checked(run, name, identity)
                    os.unlink(name, dir_fd=run)
                for name, (fd, identity) in dirs.items():
                    checked(directory, name, identity, fd)
                    os.rmdir(name, dir_fd=directory)
                for name, (fd, identity) in files.items():
                    if name not in (owner, marker):
                        checked(directory, name, identity, fd)
                        os.unlink(name, dir_fd=directory)
                same_work()
                require(set(os.listdir(directory)) == {owner, marker}, "remount work not empty at commit")
                require(lifetime.require_claim() == self.original_claim, "remount claim changed at commit")
                # Keep both authority files until the final empty-work commit.
                for name in (marker, owner):
                    fd, identity = files[name]
                    checked(directory, name, identity, fd)
                    os.lseek(fd, 0, os.SEEK_SET)
                    expected = self.retention.contents if name == marker else (str(value.owner_binary) + "\n").encode()
                    require(os.read(fd, len(expected) + 1) == expected, "remount authority contents changed")
                    if name == marker:
                        require(os.fstat(fd).st_ctime_ns == self.retention.marker_identity[2],
                                "remount retention changed at commit")
                    checked(directory, name, identity, fd)
                    os.unlink(name, dir_fd=directory)
                same_work()
                os.rmdir(work.name, dir_fd=parent)
                value._managed_fixture_retention = False
                return True
            except Exception:
                value._retain_root = True
                # A failed final rmdir may need the authority files republished.
                # Never overwrite a concurrent replacement or use a changed name.
                try:
                    same_work()
                    for name, contents in ((owner, (str(value.owner_binary) + "\n").encode()),
                                           (marker, b'{"schemaVersion":1,"reason":"cleanup-incomplete"}\n')):
                        same_work()
                        try:
                            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=directory)
                        except FileExistsError:
                            continue
                        try:
                            require(os.write(fd, contents) == len(contents), "short cleanup marker write")
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                    os.fsync(directory)
                except Exception:
                    pass  # Unknown ownership must not authorize further writes.
                raise

    def finish(self):
        require(self.helper_released, "helper ROOT descriptors not released")
        self.validate_boundary()
        self.store.detach()
        self.blocker.detach()
        require(not os.path.ismount(self.value.root) and not os.path.ismount(self.blocker.mount),
                "mount remains before root cleanup handoff")
        self.finished = True


def receipt_name(phase):
    require(type(phase) is int and phase in (1, 2), "invalid child receipt phase")
    return f"remount-phase{phase}.json"


def write_child_receipt(work, phase, raw):
    require(0 < len(raw) <= MAX_RECEIPT, "invalid child receipt size")
    directory = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(receipt_name(phase), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            require(os.write(fd, raw) == len(raw), "short child receipt write")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
    finally:
        os.close(directory)


def read_child_receipt(work, phase):
    directory = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(receipt_name(phase), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and info.st_dev == os.fstat(directory).st_dev
                    and 0 < info.st_size <= MAX_RECEIPT, "unsafe child receipt file")
            raw = bytearray()
            while len(raw) <= info.st_size:
                chunk = os.read(fd, info.st_size + 1 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            require(len(raw) == info.st_size, "incomplete child receipt file")
            current = os.fstat(fd)
            visible = os.stat(receipt_name(phase), dir_fd=directory, follow_symlinks=False)
            require((current.st_dev, current.st_ino, current.st_size, current.st_ctime_ns)
                    == (visible.st_dev, visible.st_ino, visible.st_size, visible.st_ctime_ns)
                    == (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns),
                    "child receipt changed during read")
            return decode_child_receipt(raw)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def decode_child_receipt(raw):
    require(0 < len(raw) <= MAX_RECEIPT, "invalid remount child receipt size")
    result = json.loads(raw)
    fields = {"manifest", "manifest_sha256", "identity", "root_key", "context", "root",
              "backing", "native", "complete", "volume", "seed"}
    require(type(result) is dict and set(result) == fields and result["complete"] is True,
            "incomplete remount child receipt")
    for key in ("identity", "context", "root", "backing", "native"):
        require(type(result[key]) is dict and bool(result[key]), "incomplete remount child evidence")
    manifest = bytes.fromhex(result["manifest"])
    require(hashlib.sha256(manifest).hexdigest() == result["manifest_sha256"],
            "child manifest bytes/digest mismatch")
    public = json.loads(manifest)
    require(public["identity"] == result["identity"] and public["rootPublicKey"] == result["root_key"],
            "child immutable identity mismatch")
    require(re.fullmatch(r"remount-[0-9a-f]{32}", result["volume"])
            and re.fullmatch(r"[0-9a-f]{32}", result["seed"]), "invalid child DATA receipt")
    return result


def compare_host_identity(before, after):
    require(before["device"] != after["device"], "remount must actually change st_dev")
    require(before["inode"] == after["inode"] and before["volumeUUID"] == after["volumeUUID"],
            "remount changed stable host identity")


def snapshot(value, target):
    record, owner, _ = recovery.lifecycle_owner(value.root)
    raw = (value.root / "managed-storage-owner/manifest.json").read_bytes()
    require(len(raw) <= 32768, "oversized immutable manifest")
    root = backend.root_identity(value.root)
    # backing_snapshot is intentionally strict about LIVE device identity. The
    # durable manifest retains its original device hint across a valid remount.
    backing = dict(owner["backing"], device=(value.root / "infrastructure/volumes.ext4").stat().st_dev)
    disk = recovery.backing_snapshot(value.root, dict(owner, backing=backing))
    with (value.root / "infrastructure/volumes.ext4").open("rb") as stream:
        disk["volumeUUID"] = backend._file_identity(stream.fileno())["volumeUUID"]
    state = record["checkpoint"]
    return dict(manifest=raw.hex(), manifest_sha256=hashlib.sha256(raw).hexdigest(),
                identity=state["identity"], root_key=state["rootPublicKey"],
                context=state["currentContext"], root=root, backing=disk,
                native=recovery.native_proof(target))


def compare_recovery(before, after):
    compare_host_identity(before["root"], after["root"])
    for key in ("manifest", "manifest_sha256", "identity", "root_key"):
        require(before[key] == after[key], "cold remount changed immutable " + key)
    old, new = before["backing"], after["backing"]
    require(old["device"] != new["device"] and
            {k: v for k, v in old.items() if k != "device"} ==
            {k: v for k, v in new.items() if k != "device"}, "cold remount backing identity changed")
    require(before["native"]["birth"] != after["native"]["birth"], "storage native birth reused")
    require(before["context"]["serviceEpoch"] != after["context"]["serviceEpoch"]
            and after["context"]["controllerEpoch"] == before["context"]["controllerEpoch"] + 1,
            "cold recovery context did not advance")


def local_image(client, work):
    # conftest installs tools on sys.path. This archive validates the pinned local
    # fixture graph; no images.pull, fallback registry, or image-cache daemon.
    import compat_image_fixtures
    source, named = work / "alpine.oci.tar", work / "alpine-named.oci.tar"
    compat_image_fixtures.archive("alpine", source)
    with tarfile.open(source, "r:") as incoming, tarfile.open(named, "w") as outgoing:
        for member in incoming:
            if member.name == "index.json":
                index = json.load(incoming.extractfile(member))
                descriptor, = index["manifests"]
                descriptor.setdefault("annotations", {})["io.containerd.image.name"] = IMAGE
                payload = json.dumps(index, separators=(",", ":")).encode()
                member.size = len(payload)
                outgoing.addfile(member, io.BytesIO(payload))
            else:
                outgoing.addfile(member, incoming.extractfile(member) if member.isfile() else None)
    with named.open("rb") as stream:
        for result in client.api.load_image(stream, quiet=False):
            require(not result.get("error") and not result.get("errorDetail"), "local image load failed")
    client.images.get(IMAGE)


def execute(peer, *arguments):
    result = peer.exec_run(list(arguments))
    require(result.exit_code == 0, "remount DATA command failed")
    return result.output


def remount_storage_target(value, owner, census):
    # Foundation spells the canonical /private/var test root as /var in native
    # launch records. Project ONLY that protected system alias, not arbitrary
    # symlinks, while leaving the parent's fixed work/mount identities unchanged.
    root = value.root
    if root.parts[:3] == ("/", "private", "var"):
        alias = Path("/var")
        info = alias.lstat()
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022 and os.readlink(alias) == "private/var",
                "untrusted system var alias")
        projected = alias.joinpath(*root.parts[3:])
        require(projected.resolve(strict=True) == root.resolve(strict=True), "runtime root alias changed")
        root = projected
    observed = SimpleNamespace(root=root, binary=value.binary, kernel=value.kernel,
                               storage_initramfs=value.storage_initramfs)
    return storage_target(observed, owner, census, recovery.read_public)


def quiesce(value, peers, volume, native):
    ids = {peer.id for peer in peers}
    census = harness.compatibility_runtime_processes(value.owner_binary, roots=(value.root,))
    workloads = []
    for process in census:
        if len(process.arguments) >= 4 and process.arguments[1:3] == ("vm-shim", "--spec"):
            spec, _ = recovery.read_public(Path(process.arguments[3]))
            if spec.get("containerID") in ids:
                recovery.native_proof(process)
                workloads.append(process)
    require(len(workloads) == 2, "two exact workload native processes required")

    def receipts():
        manifest, state, _ = recovery.public_state(value.root)
        return recovery.exact_receipts(manifest, state, volume.name, list(ids), stopped=True)

    for peer in peers:
        peer.stop(timeout=1)
        peer.reload()
        require(peer.attrs["State"]["Running"] is False, "workload still running")
    retired = harness.wait_for_value(receipts, bool, timeout=30, description="exact workload drain")
    for peer in peers:
        peer.remove()
    for process in workloads:
        harness.wait_for_value(lambda: recovery.exact_exit(process, harness._kernel_process(process.pid)),
                               bool, timeout=30, description="workload native exit")
    recovery.historical_receipts(retired, receipts())
    value.stop(kill=True)
    require(value.process.poll() == -9, "owned daemon SIGKILL not joined")
    frozen = harness.compatibility_runtime_processes(value.owner_binary, roots=(value.root,))
    record, owner, _ = recovery.lifecycle_owner(value.root)
    target = remount_storage_target(value, owner, frozen)
    require(recovery.native_proof(target) == native, "storage native target changed")

    def before_signal():
        require(value.process.poll() == -9 and
                harness.compatibility_runtime_processes(value.owner_binary, roots=(value.root,)) == frozen
                and harness._kernel_process(target.pid) == target, "storage signal census changed")
        current, owner, _ = recovery.lifecycle_owner(value.root)
        require(current == record and remount_storage_target(value, owner, frozen) == target,
                "storage signal owner changed")
        recovery.historical_receipts(retired, receipts())

    delivery = recovery.signal_storage(target, before_signal=before_signal)
    require(delivery["native_result"] == 0 and delivery["signal"] == "SIGKILL", "storage signal failed")
    harness.wait_for_value(lambda: recovery.exact_exit(target, harness._kernel_process(target.pid)),
                           bool, timeout=30, description="storage native exit")
    harness.wait_for_value(lambda: harness.compatibility_runtime_processes(value.owner_binary, roots=(value.root,)),
                           lambda rows: not rows, timeout=30, description="empty owned native census")


def report_child_failure(phase, error):
    # Report only locations in this fixed support module, never exception text,
    # arbitrary filenames, source lines, locals, API responses or boot secrets.
    lines = []
    frame = error.__traceback__
    while frame is not None:
        if frame.tb_frame.f_code.co_filename == __file__:
            lines.append(frame.tb_lineno)
        frame = frame.tb_next
    print(f"RTM-126 child phase {phase} failed at support lines {lines[-8:]}",
          file=sys.stderr, flush=True)


def child_main(value, phase, previous):
    """Spawn entry: a new interpreter owns every backend-root pin for this mount."""
    import docker
    from docker.types import Mount
    client = None
    try:
        require(value.process is None and not backend._ROOT_PINS, "child must start with fresh root proof cache")
        value.start()  # Real ordinary Daemon.start; never clear or relax _ROOT_PINS.
        client = docker.DockerClient(base_url=f"unix://{value.socket}", timeout=60, version="auto")
        require(client.ping(), "ordinary daemon unavailable")
        if previous is None:
            local_image(client, value.work)
            volume = client.volumes.create("remount-" + uuid.uuid4().hex)
            seed = uuid.uuid4().hex
        else:
            client.images.get(IMAGE)
            volume = client.volumes.get(previous["volume"])
            seed = previous["seed"]
        peers = [client.containers.create(IMAGE, ["sleep", "600"], network_mode="none",
                 restart_policy={"Name": "no"}, mounts=[Mount("/data", volume.name, type="volume", no_copy=True)])
                 for _ in range(2)]
        for peer in peers:
            peer.start()
            backend.verify_backend(value.root, "shared", execute(peer, "cat", "/proc/self/mountinfo").decode(),
                                   startup_mode="lifecycle")
        for index, (writer, reader) in enumerate((peers, list(reversed(peers)))):
            path = "/data/seed-" + str(index)
            if previous is None:
                execute(writer, "sh", "-ec", f"printf '%s' '{seed}-{index}' | dd of={path} conv=fsync")
            require(execute(reader, "cat", path) == f"{seed}-{index}".encode(), "seed bytes changed")
            payload = uuid.uuid4().hex
            execute(writer, "sh", "-ec", f"printf '%s' '{payload}' | dd of=/data/new-{index} conv=fsync")
            require(execute(reader, "cat", f"/data/new-{index}") == payload.encode(), "new shared DATA mismatch")
        _, owner, _ = recovery.lifecycle_owner(value.root)
        target = remount_storage_target(value, owner, harness.compatibility_runtime_processes(
            value.owner_binary, roots=(value.root,)))
        result = snapshot(value, target)
        if previous is not None:
            compare_recovery(previous, result)
            record, _, _ = recovery.lifecycle_owner(value.root)
            require(record["checkpoint"]["latestCold"]["predecessor"]["context"] == previous["context"],
                    "cold transition did not preserve predecessor context")
        quiesce(value, peers, volume, result["native"])
        result.update(complete=True, volume=volume.name, seed=seed)
        raw = json.dumps(result, separators=(",", ":")).encode()
        require(len(raw) <= MAX_RECEIPT, "oversized child receipt")
        write_child_receipt(value.work, phase, raw)
    except BaseException as error:
        report_child_failure(phase, error)
        # No token-bearing diagnostics or automatic mount cleanup on failure.
        value.retain_root(reason="unsafe-disk-phase")
        raise SystemExit(1) from None
    finally:
        # This Popen belongs to this child, even when failure follows readiness.
        try:
            value.stop()
        finally:
            if client is not None:
                client.close()
