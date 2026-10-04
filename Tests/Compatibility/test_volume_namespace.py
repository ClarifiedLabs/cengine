"""Minimal Linux rename(2) contracts, selected from pinned pjdfstest rename tests.

No shell harness, special files, .nfs filtering, or fabricated link counts.
"""
from __future__ import annotations

import time

import pytest

from storage_backend_proof import daemon_startup_mode
from test_volume_corpus import (
    _artifacts, _exec, corpus_fixture, corpus_resources, journal_writer,
)

# Linux NFSv3 has no server-driven invalidation: a peer client's cached positive
# dentry for a name another client renamed away stays valid until the parent
# directory's attribute cache expires (nfs_lookup_revalidate). The guest mounts
# the legacy shared store with actimeo=1, so that window is bounded by one
# second. Direct ext4 and managed FUSE consumers have no such window.
LEGACY_NFS_SETTLE_SECONDS = 2.0


class NamespaceProbe:
    def __init__(self, containers, record, *, settle_seconds=0.0):
        self.containers = containers
        self.record = record
        self.settle_seconds = settle_seconds

    def settle(self, reason):
        """Wait out the legacy NFS attribute cache before peers read a rename."""
        self.record({"phase": "settle", "reason": reason, "seconds": self.settle_seconds})
        if self.settle_seconds:
            time.sleep(self.settle_seconds)

    def call(self, args, expected="0", consumer=0):
        self.record({"phase": "before", "argv": ["/pjdfstest", *args], "consumer": consumer})
        code, stdout, stderr = _exec(self.containers[consumer], ["/pjdfstest", *args])
        value = stdout.strip()
        self.record({"phase": "after", "argv": args, "consumer": consumer,
                     "exit": code, "stdout": stdout, "stderr": stderr})
        if expected is None:
            assert code == 0, (args, code, stdout, stderr)
        else:
            allowed = expected if isinstance(expected, tuple) else (expected,)
            assert value in allowed, (args, allowed, code, stdout, stderr)
            assert code == (1 if value.startswith("E") else 0), (args, code, stdout, stderr)
        return value

    def stat(self, path, field="inode,type,mode,nlink,uid,gid", consumer=0):
        return self.call(["lstat", path, field], None, consumer)

    def snapshot(self, paths):
        return [[self.stat(path, consumer=consumer) for path in paths]
                for consumer in range(len(self.containers))]

    def absent(self, path):
        for consumer in range(len(self.containers)):
            self.call(["lstat", path, "type"], "ENOENT", consumer)

    def preserved_failure(self, args, expected, paths):
        before = self.snapshot(paths)
        self.call(args, expected)
        assert self.snapshot(paths) == before, (args, before)


def directory_rename(probe):
    for path in ("left", "right", "left/tree", "left/tree/child"):
        probe.call(["mkdir", path, "0755"])
    original = probe.stat("left/tree", "inode")
    child = probe.stat("left/tree/child", "inode")
    probe.call(["rename", "left/tree", "right/moved"])
    probe.absent("left/tree")
    for consumer in range(len(probe.containers)):
        assert probe.stat("right/moved", "inode", consumer) == original
        assert probe.stat("right/moved/child", "inode", consumer) == child
        assert probe.stat("right/moved/..", "inode", consumer) == probe.stat("right", "inode", consumer)
        probe.call(["lstat", "left", "nlink"], "2", consumer)
        probe.call(["lstat", "right", "nlink"], "3", consumer)
        probe.call(["lstat", "right/moved", "nlink"], "3", consumer)
    probe.call(["create", "file", "0644"])
    probe.call(["symlink", "file", "link"])
    probe.call(["mkdir", "right/occupied", "0755"])
    probe.call(["create", "right/occupied/entry", "0644"])
    paths = ("left", "right", "right/moved", "right/moved/child", "file", "link",
             "right/occupied", "right/occupied/entry")
    for name in ("file", "link"):
        probe.preserved_failure(["rename", "right/moved", name], "ENOTDIR", paths)
        probe.preserved_failure(["rename", name, "right/moved"], "EISDIR", paths)
    for target in ("right/moved/child", "right/moved/child/cycle"):
        probe.preserved_failure(["rename", "right/moved", target], "EINVAL", paths)
    probe.absent("right/moved/child/cycle")
    probe.preserved_failure(["rename", "right/moved", "right/occupied"],
                            ("EEXIST", "ENOTEMPTY"), paths)


def sticky_overwrite(probe):
    probe.call(["mkdir", "incoming", "0777"])
    probe.call(["chmod", "incoming", "0777"])
    probe.call(["mkdir", "sticky", "0777"])
    probe.call(["chmod", "sticky", "01777"])
    # Both allowed branches: destination ownership, then sticky-directory ownership.
    for index, allowed_owner in enumerate(("destination", "directory")):
        source, target = f"incoming/source{index}", f"sticky/target{index}"
        probe.call(["open", source, "O_CREAT,O_WRONLY", "0644", ":", "write", "0", "new-data"], "0\n0")
        probe.call(["open", target, "O_CREAT,O_WRONLY", "0644", ":", "write", "0", "old-data"], "0\n0")
        probe.call(["chown", source, "65534", "65534"])
        inode = probe.stat(source, "inode")
        args = ["-u", "65534", "-g", "65534", "rename", source, target]
        probe.preserved_failure(args, ("EACCES", "EPERM"), (source, target, "incoming", "sticky"))
        for consumer in range(len(probe.containers)):
            for path, data in ((source, "new-data"), (target, "old-data")):
                probe.call(["open", path, "O_RDONLY", ":", "pread", "0", "8", "0"], "0\n" + data, consumer)
        probe.call(["chown", target if allowed_owner == "destination" else "sticky", "65534", "65534"])
        probe.call(args)
        probe.settle("peer readback after a successful cross-consumer rename")
        probe.absent(source)
        for consumer in range(len(probe.containers)):
            assert probe.stat(target, "inode", consumer) == inode
            probe.call(["open", target, "O_RDONLY", ":", "pread", "0", "8", "0"], "0\nnew-data", consumer)


def _run_namespace(client, daemon, fixture, scenario):
    directory = _artifacts(fixture)
    mode = daemon_startup_mode(daemon)
    for storage in ("block", "shared"):
        settle = LEGACY_NFS_SETTLE_SECONDS if storage == "shared" and mode == "legacy" else 0.0
        record = journal_writer(directory, "namespace-" + storage)
        record({"phase": "scenario", "name": scenario.__name__, "startup_mode": mode,
                "settle_seconds": settle})
        with corpus_resources(client, fixture, storage, record, daemon) as containers:
            scenario(NamespaceProbe(containers, record, settle_seconds=settle))


@pytest.mark.compat("RTM-075")
def test_directory_rename_topology_and_atomic_failures(daemon, client, corpus_fixture):
    """rename/{00,13,14,18,20}.t: topology, wrong type, cycle, nonempty, peer."""
    _run_namespace(client, daemon, corpus_fixture, directory_rename)


@pytest.mark.compat("RTM-076")
def test_sticky_rename_overwrite_ownership(daemon, client, corpus_fixture):
    """rename/10.t regular branch: denied overwrite preserves both; owners succeed."""
    _run_namespace(client, daemon, corpus_fixture, sticky_overwrite)
