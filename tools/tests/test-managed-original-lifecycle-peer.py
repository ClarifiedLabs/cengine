#!/usr/bin/env python3
"""Engine-free immutable peer reader tests; synthetic files, not native proof."""
import copy
import os
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_original_lifecycle_peer as e
from harness import RuntimeProcess
p = e.p
FIXTURES = runpy.run_path(str(ROOT / "tools/tests/test-managed-original-lifecycle-evidence.py"))
uid = FIXTURES["WORKER"]["uid"]


class Fixture:
    def __init__(self, root):
        self.root = root
        self.queue = root / "managed-prepare-compatibility"
        self.queue.mkdir(mode=0o700)
        self.launch_id, self.boot = uid(), uid()
        generation = root / "infrastructure/storage-shim-generations" / self.launch_id
        generation.mkdir(parents=True, mode=0o700)
        self.disk = root / "infrastructure/volumes.ext4"
        self.disk.write_bytes(b"\0" * 4096)
        self.daemon = SimpleNamespace(root=root, binary=root / "cengine", kernel=root / "kernel",
            storage_initramfs=root / "initramfs")
        self.daemon.storage_initramfs.write_bytes(b"pinned initramfs")
        args, self.peers = FIXTURES["fixture"]()
        self.records = args[:2]
        volume = self.records[0]["manifest"]["root"]["volumeUUID"]
        def identity(path):
            info = path.stat()
            return dict(device=info.st_dev, inode=info.st_ino, volumeUUID=volume)
        for record in self.records:
            manifest = record["manifest"]
            manifest.update(root=identity(root), backing=identity(self.disk))
            digest = p.digest(b"cengine.storageauthority.binding.v3\0" + p.canonical(e.lifecycle.manifest_binding(manifest)))
            def rebind(value):
                if type(value) is dict:
                    if set(value) == {"store", "generation", "binding"}: value["binding"] = digest
                    for child in value.values(): rebind(child)
                elif type(value) is list:
                    for child in value: rebind(child)
            rebind(record)
        owner, _ = e.original.owner(self.records[0])
        spec = dict(kernelPath=str(self.daemon.kernel), diskBootstrapVersion=1, kind="storage",
            containerID="cengine-storage", shimLaunchUUID=self.launch_id,
            rootDiskPath=str(self.disk), rootDiskIdentity=owner["backing"], rootDiskSize=4096,
            rootDiskReadOnly=False, volumeDisks=[], bindShares=[], initialRamdiskPath=str(self.daemon.storage_initramfs),
            expectedInitramfsSHA256=p.digest(self.daemon.storage_initramfs.read_bytes()))
        self.spec = generation / "spec.json"
        self.spec.write_bytes(p.canonical(spec))
        digest = p.digest(self.spec.read_bytes())
        intent = dict(schemaVersion=1, protocolVersion=7, specificationSHA256=digest, launchUUID=self.launch_id,
            storeIdentity=identity(root / "infrastructure"), generationIdentity=identity(generation))
        launch = dict(intent=intent, process=dict(pid=55, startSeconds=100, startMicroseconds=2, uniqueID=300, bootUUID=self.boot))
        for name, value in (("launch.json", launch), ("intent.json", intent)):
            (generation / name).write_bytes(p.canonical(value))
        self.process = RuntimeProcess(55, executable=str(self.daemon.binary), identity=(100, 2, 300), pidversion=8,
            arguments=(str(self.daemon.binary), "vm-shim", "--spec", str(self.spec), "--spec-sha256", digest,
                "--storage-disk-fd", "3", "--storage-lifecycle-fd", "4"))
        binding = dict(shimLaunchUUID=self.launch_id, guestBootNonce=uid(), ext4UUID=owner["ext4UUID"], bytes=4096)
        self.values, self.paths, self.projections = [], [], []
        for record, peer in zip(self.records, self.peers):
            peer["dataAddress"] = "192.0.2.1"
            state = record["checkpoint"]; service = state["currentService"]
            ready = dict(identity=copy.deepcopy(state["identity"]), **service["context"],
                revision=service["open_revision"], open_revision=service["open_revision"],
                worker_uuid=state["observedWorker"]["workerUUID"], bootstrap_key=service["boot"]["bootstrap_key"],
                tls_root_der=peer["tlsRootDER"], server_der=peer["serverDER"], server_spki=peer["serverKey"])
            value = dict(version=1, binding=copy.deepcopy(binding), ready=ready, peer=peer)
            self.values.append(value)
            self.paths.append(self.queue / ("lifecycle-peer-" + ready["worker_uuid"] + "-" + str(ready["controller_epoch"]) + ".json"))
            self.projections.append(e.original.owner(record)[1])
        self.publish(0)  # The successor is published only after actual replacement in production.

    def publish(self, index): self.paths[index].write_bytes(p.canonical(self.values[index]))
    def reader(self): return e.PeerReader(self.daemon, lambda: [self.process])


class PeerReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(Path(self.temporary.name).resolve())
        self.boot = patch.object(e.lifecycle, "host_boot_uuid", return_value=self.fixture.boot)
        self.boot.start(); self.addCleanup(self.boot.stop)

    def test_actual_native_proof_and_distinct_retained_worker_files(self):
        f = self.fixture
        with f.reader() as reader:
            self.assertEqual(reader(f.projections[0]), f.peers[0])
            self.assertFalse(f.paths[1].exists())
            f.publish(1)
            self.assertEqual(reader(f.projections[1]), f.peers[1])
            self.assertIn(f.paths[0], reader.files); self.assertIn(f.paths[1], reader.files)
            reader.validate()

    def test_filename_selects_exact_root_controller_epoch_for_same_worker(self):
        f = self.fixture
        first = f.values[0]
        second = copy.deepcopy(first)
        second["ready"]["controller_epoch"] += 1
        second["peer"]["dataAddress"] = "192.0.2.2"
        projection = copy.deepcopy(f.projections[0])
        projection["workerEvidence"]["checkpoint"]["currentService"]["context"]["controller_epoch"] += 1
        path = f.queue / ("lifecycle-peer-" + second["ready"]["worker_uuid"] + "-"
            + str(second["ready"]["controller_epoch"]) + ".json")
        path.write_bytes(p.canonical(second))
        original_bytes = f.paths[0].read_bytes()
        # Filename selection unit: owner/comparison takeover validation belongs to
        # its own oracle. Keep actual Ready/ROOT correlation and retained reads live.
        owner = e.original.owner(f.records[0])[0]
        with patch.object(e.original, "owner", return_value=(owner, projection)), \
                patch.object(e.original, "comparison"), f.reader() as reader:
            self.assertEqual(reader(f.projections[0]), first["peer"])
            self.assertEqual(reader(projection), second["peer"])
            self.assertIn(f.paths[0], reader.files)
            self.assertIn(path, reader.files)
            self.assertEqual(f.paths[0].read_bytes(), original_bytes)
        # A C+1 filename containing the old C payload is never normalized.
        path.write_bytes(original_bytes)
        with patch.object(e.original, "owner", return_value=(owner, projection)), \
                patch.object(e.original, "comparison"), self.assertRaisesRegex(ValueError, "exact ROOT service"), f.reader() as reader:
            reader(projection)

    def test_filename_has_no_legacy_or_noncanonical_epoch_fallback(self):
        f = self.fixture
        raw = f.paths[0].read_bytes()
        f.paths[0].unlink()
        prefix = "lifecycle-peer-" + f.values[0]["ready"]["worker_uuid"]
        epoch = str(f.values[0]["ready"]["controller_epoch"])
        for suffix in ("", "-0" + epoch, "-+" + epoch, "-" + epoch + ".0", "-0", "-18446744073709551616"):
            path = f.queue / (prefix + suffix + ".json")
            path.write_bytes(raw)
            with self.subTest(suffix=suffix), self.assertRaises(FileNotFoundError), f.reader() as reader:
                reader(f.projections[0])
            path.unlink()

    def test_closed_canonical_wire_and_full_identity(self):
        f = self.fixture
        mutations = [(("version",), True), (("ready", "identity", "generation"), 2),
            (("ready", "identity", "generation"), True), (("ready", "worker_uuid"), uid()),
            (("ready", "controller_key"), "0" * 64), (("ready", "open_revision"), 1),
            (("ready", "bootstrap_key"), "0" * 64), (("peer", "serverKey"), "0" * 64),
            (("binding", "shimLaunchUUID"), uid()), (("binding", "bytes"), 8192),
            (("peer", "dataAddress"), "192.0.2.1:1234"), (("peer", "dataAddress"), "localhost"),
            (("binding", "initramfsSHA256"), "0" * 64)]
        for path, value in mutations:
            bad = copy.deepcopy(f.values[0]); target = bad
            for key in path[:-1]: target = target[key]
            target[path[-1]] = value
            f.paths[0].write_bytes(p.canonical(bad))
            with self.subTest(path=path, value=value), self.assertRaises(ValueError), f.reader() as reader:
                reader(f.projections[0])
        raw = p.canonical(f.values[0])
        for bad in (raw + b"\n", raw.replace(b'"version":1', b'"version":1,"version":1'),
                raw.replace(b'"version":1', b'"version":1.0'), raw.replace(b'"version":1', b'"version":null'), b" " * 65537):
            f.paths[0].write_bytes(bad)
            with self.assertRaises(ValueError), f.reader() as reader: reader(f.projections[0])

    def test_finish_revalidates_both_bytes_and_inode_even_after_return(self):
        f = self.fixture
        for index in (0, 1):
            for replace in (False, True):
                f.publish(0); f.publish(1)
                with self.subTest(index=index, replace=replace), self.assertRaises(ValueError):
                    with f.reader() as reader:
                        reader(f.projections[0]); reader(f.projections[1])
                        raw = f.paths[index].read_bytes()
                        if replace:
                            tmp = f.queue / "substitute.json"; tmp.write_bytes(raw); os.replace(tmp, f.paths[index])
                        else: f.paths[index].write_bytes(raw + b" ")

    def test_successor_cannot_reuse_predecessor_file_key_or_boot(self):
        f = self.fixture
        for bad in (f.values[0], {**f.values[1], "peer": f.peers[0]},
                {**f.values[1], "binding": {**f.values[1]["binding"], "guestBootNonce": uid()}}):
            f.paths[1].write_bytes(p.canonical(bad))
            with self.assertRaises(ValueError), f.reader() as reader:
                reader(f.projections[0]); reader(f.projections[1])

    def test_actual_initramfs_pin_remains_mandatory(self):
        f = self.fixture
        f.daemon.storage_initramfs.write_bytes(b"different initramfs")
        with self.assertRaisesRegex(ValueError, "pinned lifecycle initramfs"), f.reader() as reader:
            reader(f.projections[0])

    def test_symlink_and_nonprivate_queue_are_rejected(self):
        f = self.fixture
        raw = f.paths[0].read_bytes(); other = f.root / "other.json"; other.write_bytes(raw)
        f.paths[0].unlink(); f.paths[0].symlink_to(other)
        with self.assertRaises(OSError), f.reader() as reader: reader(f.projections[0])
        f.queue.chmod(0o755)
        with self.assertRaises(ValueError), f.reader(): pass


if __name__ == "__main__": unittest.main()
