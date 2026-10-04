#!/usr/bin/env python3
"""Offline RTM-126 guard tests. Never mount, start a runtime, or contact a helper."""
from __future__ import annotations

import ast
from contextlib import ExitStack
import copy
import json
import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import harness
import storage_lifecycle_v2_remount as remount


class RemountTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(remount.subprocess, "run", side_effect=AssertionError("native command forbidden")))
        self.stack.enter_context(patch.object(os, "kill", side_effect=AssertionError("signal forbidden")))
        self.stack.enter_context(patch.object(harness, "_kernel_process", side_effect=AssertionError("native census forbidden")))
        self.stack.enter_context(patch.object(remount.lifetime, "require_claim", return_value=(1, 2, 3)))
        self.terminate = self.stack.enter_context(patch.object(harness, "terminate_compatibility_runtime", return_value=[]))
        self.census = self.stack.enter_context(patch.object(harness, "compatibility_runtime_processes", return_value=[]))

    def evidence(self):
        before = dict(manifest="abcd", manifest_sha256="a" * 64,
                      identity=dict(store="store", generation=1, binding="b" * 64), root_key="ROOT",
                      root=dict(device=10, inode=2, volumeUUID="APFS"),
                      backing=dict(device=10, inode=9, bytes=4096, volumeUUID="APFS", ext4UUID="EXT4", created="1234"),
                      context=dict(serviceEpoch="old", controllerEpoch=1, controllerKey="old"),
                      native=dict(pid=100, birth=[1, 2, 3], pidversion=4))
        after = copy.deepcopy(before)
        after["root"]["device"] = after["backing"]["device"] = 11
        after["native"] = dict(pid=101, birth=[2, 3, 4], pidversion=5)
        after["context"] = dict(serviceEpoch="new", controllerEpoch=2, controllerKey="new")
        return before, after

    def test_child_receipt_requires_complete_bounded_manifest_and_identity(self):
        result, _ = self.evidence()
        manifest = json.dumps(dict(identity=result["identity"], rootPublicKey=result["root_key"])).encode()
        result.update(manifest=manifest.hex(), manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                      complete=True, volume="remount-" + "a" * 32, seed="b" * 32)
        self.assertEqual(remount.decode_child_receipt(json.dumps(result).encode()), result)
        for mutation in (dict(root_key="changed"), dict(manifest_sha256="0" * 64), dict(complete=False), dict(native={})):
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                remount.decode_child_receipt(json.dumps(dict(result, **mutation)).encode())
        for raw in (b"", b"x" * (remount.MAX_RECEIPT + 1), b'{"complete":true}'):
            with self.assertRaises(RuntimeError):
                remount.decode_child_receipt(raw)

    def test_native_selector_projects_only_protected_var_alias(self):
        root = Path("/private/var/folders/owned/root")
        value = SimpleNamespace(root=root, binary=Path("/binary"), kernel=Path("/kernel"),
                                storage_initramfs=Path("/initramfs"))
        safe = SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=0)
        with patch.object(Path, "lstat", return_value=safe), \
                patch.object(os, "readlink", return_value="private/var"), \
                patch.object(Path, "resolve", return_value=root), \
                patch.object(remount, "storage_target", return_value="native") as selected:
            self.assertEqual(remount.remount_storage_target(value, {}, []), "native")
            self.assertEqual(selected.call_args.args[0].root, Path("/var/folders/owned/root"))
            self.assertEqual(value.root, root)
            for bad in (SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
                        SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=os.getuid()),
                        SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)):
                with patch.object(Path, "lstat", return_value=bad), self.assertRaises(RuntimeError):
                    remount.remount_storage_target(value, {}, [])
            with patch.object(os, "readlink", return_value="foreign"), self.assertRaises(RuntimeError):
                remount.remount_storage_target(value, {}, [])
            with patch.object(Path, "resolve", side_effect=[Path("/foreign"), root]), self.assertRaises(RuntimeError):
                remount.remount_storage_target(value, {}, [])

    def test_device_change_with_stable_durable_identity(self):
        remount.compare_recovery(*self.evidence())

    def test_reject_changed_key_manifest_generation_disk_or_native_identity(self):
        cases = [("root_key", None), ("manifest", None), ("manifest_sha256", None),
                 ("identity", "generation"), ("root", "inode"), ("root", "volumeUUID"),
                 ("backing", "inode"), ("backing", "bytes"), ("backing", "ext4UUID"),
                 ("backing", "created"), ("backing", "volumeUUID")]
        for field, key in cases:
            with self.subTest(field=field, key=key):
                before, after = self.evidence()
                if key is None:
                    after[field] = "changed"
                else:
                    after[field][key] = "changed"
                with self.assertRaises(RuntimeError):
                    remount.compare_recovery(before, after)
        for field, key in (("root", "device"), ("backing", "device"), ("native", "birth"),
                           ("context", "serviceEpoch"), ("context", "controllerEpoch")):
            with self.subTest(field=field, key=key):
                before, after = self.evidence()
                after[field][key] = before[field][key]
                with self.assertRaises(RuntimeError):
                    remount.compare_recovery(before, after)

    def image_table(self):
        return {"images": [{"image-path": "/owned/store.sparseimage", "system-entities": [
            {"dev-entry": "/dev/disk9"}, {"dev-entry": "/dev/disk10s1", "mount-point": "/owned/root"}]}]}

    def test_image_mapping_rejects_foreign_image_mount_duplicate_or_device(self):
        image, mount = Path("/owned/store.sparseimage"), Path("/owned/root")
        self.assertEqual(remount.image_mount(image, mount, self.image_table()), "/dev/disk10s1")
        for mutation in (lambda t: t["images"][0].update({"image-path": "/foreign.sparseimage"}),
                         lambda t: t["images"][0]["system-entities"][1].update({"mount-point": "/foreign"}),
                         lambda t: t["images"].append(copy.deepcopy(t["images"][0])),
                         lambda t: t["images"][0]["system-entities"][1].update({"dev-entry": "/dev/foreign"})):
            table = self.image_table()
            mutation(table)
            with self.assertRaises(RuntimeError):
                remount.image_mount(image, mount, table)

    def transaction(self, work):
        binary_dir = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        binary = binary_dir / "cengine"
        binary.write_bytes(b"offline fixture, never executed")
        (work / harness.COMPATIBILITY_OWNER_FILE).write_text(str(binary) + "\n")
        value = SimpleNamespace(work=work, root=work / "root", binary=binary, owner_binary=binary,
                                process=None, _managed_fixture_retention=True, _retain_root=False,
                                retain_root=Mock())
        retention = harness.preretain_compatibility_root(work, binary)
        store = remount.OwnedImage(work / "store.sparseimage", value.root, (1, 2), True, "/dev/disk10s1")
        blocker = remount.OwnedImage(work / "blocker.sparseimage", work / "blocker", (1, 3))
        transaction = remount.OfflineRemount(value, retention, store, blocker)
        transaction.child = Mock(exitcode=0, is_alive=Mock(return_value=False))
        transaction.receipt = {"complete": True}
        self.stack.enter_context(patch.object(remount.lifetime, "canonical_temp", return_value=work.parent))
        self.stack.enter_context(patch.object(remount.OwnedImage, "validate"))
        return transaction

    def test_original_fixed_work_and_marker_required(self):
        with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
            work = Path(temporary).resolve()
            transaction = self.transaction(work)
            transaction.validate_boundary()
            (work / harness.COMPATIBILITY_RETAIN_FILE).chmod(0o400)
            with self.assertRaisesRegex(RuntimeError, "marker"):
                transaction.validate_boundary()

    def test_no_child_failure_incomplete_receipt_foreign_image_or_runtime(self):
        with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
            transaction = self.transaction(Path(temporary).resolve())
            for exitcode, alive, receipt in ((1, False, {"complete": True}), (None, True, {"complete": True}),
                                             (0, False, None), (0, False, {"complete": False})):
                transaction.child.exitcode = exitcode
                transaction.child.is_alive.return_value = alive
                transaction.receipt = receipt
                with self.assertRaises(RuntimeError):
                    transaction.validate_boundary()
            transaction.child.exitcode = 0
            transaction.child.is_alive.return_value = False
            transaction.receipt = {"complete": True}
            self.census.return_value = ["live"]
            with self.assertRaisesRegex(RuntimeError, "runtime"):
                transaction.validate_boundary()
            self.census.return_value = []
            transaction.store.path = Path("/foreign.sparseimage")
            with self.assertRaisesRegex(RuntimeError, "foreign"):
                transaction.validate_boundary()

    def test_detach_failure_never_attaches_blocker_or_forces_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
            transaction = self.transaction(Path(temporary).resolve())
            transaction.helper_released = True
            with patch.object(remount.backend, "root_identity", return_value=self.evidence()[0]["root"]), \
                    patch.object(remount, "command", side_effect=subprocess.CalledProcessError(1, "hdiutil")) as call, \
                    patch.object(transaction.blocker, "attach") as attach:
                with self.assertRaises(subprocess.CalledProcessError):
                    transaction.remount()
                call.assert_called_once_with("/usr/bin/hdiutil", "detach", str(transaction.value.root))
                attach.assert_not_called()
                self.assertTrue(transaction.store.mounted)
                self.assertFalse(transaction.finished)

    def test_mutated_helper_client_refuses(self):
        with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
            transaction = self.transaction(Path(temporary).resolve())
            transaction.value.binary = Path("/foreign/cengine")
            with self.assertRaisesRegex(RuntimeError, "client changed"):
                transaction.validate_boundary()
            transaction.value.binary = transaction.original_binary
            transaction.value.binary.write_bytes(b"replaced")
            with self.assertRaisesRegex(RuntimeError, "client changed"):
                transaction.validate_boundary()

    def test_detach_requires_helper_release(self):
        with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
            transaction = self.transaction(Path(temporary).resolve())
            with patch.object(transaction.store, "detach") as detach:
                for operation in (transaction.remount, transaction.finish):
                    with self.assertRaises(RuntimeError):
                        operation()
                detach.assert_not_called()

    def test_spawn_receipt_failure_is_not_cleanup_authority(self):
        for payload, exitcode, alive in ((b'{"complete":false}', 0, False),
                                        (b'{"complete":true}', 1, False),
                                        (b'{}', 0, False), (b'{', 0, False),
                                        (b'x' * (remount.MAX_RECEIPT + 1), 0, False),
                                        (b'', None, True)):
            with self.subTest(exitcode=exitcode, alive=alive), tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
                transaction = self.transaction(Path(temporary).resolve())
                path = transaction.value.work / remount.receipt_name(1)
                path.write_bytes(payload)
                path.chmod(0o600)
                context = Mock()
                child = context.Process.return_value = Mock(exitcode=exitcode, pid=123,
                    is_alive=Mock(side_effect=[True, True, False] if alive else [False, False]))
                with patch.object(remount.multiprocessing, "get_context", return_value=context) as selected:
                    with self.assertRaises((RuntimeError, ValueError)):
                        transaction.run_child()
                    selected.assert_called_once_with("spawn")
                    self.assertEqual(child.join.call_args_list[0].kwargs, dict(timeout=remount.CHILD_SECONDS))
                    self.assertIsNone(transaction.receipt)
                    self.assertFalse(transaction.helper_released)
                    self.assertTrue(transaction.value._retain_root)
                    self.terminate.assert_called_with(transaction.original_binary, roots=(transaction.value.root,))
                    self.assertTrue((transaction.value.work / harness.COMPATIBILITY_RETAIN_FILE).exists())
                    context.Pipe.assert_not_called()

    def test_receipt_file_exclusive_bounded_regular_private_and_fixed_phase(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            remount.write_child_receipt(work, 1, b'{}')
            self.assertEqual(stat.S_IMODE((work / remount.receipt_name(1)).stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                remount.write_child_receipt(work, 1, b'{}')
            for phase in (0, 3, True, "../root"):
                with self.assertRaises(RuntimeError):
                    remount.receipt_name(phase)
            path = work / remount.receipt_name(2)
            os.mkfifo(path, 0o600)
            with self.assertRaisesRegex(RuntimeError, "unsafe child receipt"):
                remount.read_child_receipt(work, 2)
            path.unlink()
            path.symlink_to(work / remount.receipt_name(1))
            with self.assertRaises(OSError):
                remount.read_child_receipt(work, 2)

    def test_success_receipt_reader_handles_short_regular_file_reads(self):
        result, _ = self.evidence()
        manifest = json.dumps(dict(identity=result["identity"], rootPublicKey=result["root_key"])).encode()
        result.update(manifest=manifest.hex(), manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                      complete=True, volume="remount-" + "a" * 32, seed="b" * 32)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            remount.write_child_receipt(work, 1, json.dumps(result).encode())
            original = os.read
            with patch.object(os, "read", side_effect=lambda fd, count: original(fd, min(count, 17))):
                self.assertEqual(remount.read_child_receipt(work, 1), result)

    def cleanup_transaction(self, work):
        transaction = self.transaction(work)
        for name in ("root", "blocker", "run"):
            (work / name).mkdir()
        for image in (transaction.store, transaction.blocker):
            image.path.write_bytes(b"owned image")
            info = image.path.stat()
            image.inode = (info.st_dev, info.st_ino)
            image.mounted = False
        transaction.finished = transaction.helper_released = True
        (work / "run/docker.sock.lock").write_bytes(b"lock")
        (work / "daemon.log").write_bytes(b"public offline log")
        return transaction

    def test_final_full_pass_removes_only_closed_owned_tree(self):
        with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
            work = Path(temporary).resolve()
            transaction = self.cleanup_transaction(work)
            self.assertTrue(transaction.final_cleanup())
            self.assertFalse(work.exists())
            self.assertFalse(transaction.value._managed_fixture_retention)

    def test_late_mount_or_device_change_retains_sentinel_and_marker(self):
        for mode in ("mount", "device"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
                work = Path(temporary).resolve()
                transaction = self.cleanup_transaction(work)
                sentinel = work / "root/sentinel"
                sentinel.write_bytes(b"foreign must survive")
                original = os.fstat
                def changed(fd):
                    info = original(fd)
                    if (info.st_dev, info.st_ino) == (sentinel.parent.stat().st_dev, sentinel.parent.stat().st_ino):
                        return SimpleNamespace(**{key: getattr(info, key) for key in dir(info)
                                                  if key.startswith("st_") and key != "st_dev"},
                                               st_dev=info.st_dev + 1)
                    return info
                with ExitStack() as stack:
                    if mode == "mount":
                        stack.enter_context(patch.object(remount.OwnedImage, "validate",
                                                        side_effect=RuntimeError("unexpected image attachment")))
                    else:
                        stack.enter_context(patch.object(os, "fstat", side_effect=changed))
                    with self.assertRaises(RuntimeError):
                        transaction.final_cleanup()
                self.assertEqual(sentinel.read_bytes(), b"foreign must survive")
                self.assertEqual((work / harness.COMPATIBILITY_RETAIN_FILE).read_bytes(), transaction.retention.contents)

    def test_unexpected_nested_directory_refused_before_mutation(self):
        with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
            work = Path(temporary).resolve()
            transaction = self.cleanup_transaction(work)
            (work / "run/nested").mkdir()
            sentinel = work / "run/nested/sentinel"
            sentinel.write_bytes(b"leave alone")
            with self.assertRaisesRegex(RuntimeError, "run layout"):
                transaction.final_cleanup()
            self.assertTrue(sentinel.exists())
            self.assertTrue(transaction.store.path.exists())
            self.assertEqual((work / harness.COMPATIBILITY_RETAIN_FILE).read_bytes(), transaction.retention.contents)

    def test_final_commit_failure_republishes_cleanup_incomplete(self):
        with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
            work = Path(temporary).resolve()
            transaction = self.cleanup_transaction(work)
            original = os.rmdir
            def refuse(name, *, dir_fd=None):
                if name == work.name:
                    raise OSError("injected final commit failure")
                return original(name, dir_fd=dir_fd)
            with patch.object(os, "rmdir", side_effect=refuse):
                with self.assertRaises(OSError):
                    transaction.final_cleanup()
            self.assertIn(b"cleanup-incomplete", (work / harness.COMPATIBILITY_RETAIN_FILE).read_bytes())
            self.assertTrue((work / harness.COMPATIBILITY_OWNER_FILE).exists())
            self.assertTrue(transaction.value._retain_root)

    def test_child_failure_diagnostic_omits_exception_text_and_foreign_frames(self):
        output = io.StringIO()
        try:
            remount.require(False, "secret-token-in-exception")
        except RuntimeError as error:
            with patch.object(remount.sys, "stderr", output):
                remount.report_child_failure(1, error)
        self.assertRegex(output.getvalue(), r"^RTM-126 child phase 1 failed at support lines \[\d+\]\n$")
        self.assertNotIn("secret-token", output.getvalue())
        self.assertNotIn(__file__, output.getvalue())

    def test_child_failure_after_spawn_stops_its_known_daemon(self):
        value = SimpleNamespace(process=None, retain_root=Mock(), stop=Mock())
        def start():
            value.process = Mock()  # The child owns this actual-start Popen slot.
        value.start = start
        value.socket = Path("/never-connect")
        docker = SimpleNamespace(DockerClient=Mock(side_effect=RuntimeError("after spawn")))
        with patch.dict(sys.modules, {"docker": docker, "docker.types": SimpleNamespace(Mount=Mock())}), \
                patch.object(remount.backend, "_ROOT_PINS", {}):
            with self.assertRaises(SystemExit):
                remount.child_main(value, 1, None)
        self.assertIsNotNone(value.process)
        value.stop.assert_called_once_with()
        value.retain_root.assert_called_once_with(reason="unsafe-disk-phase")

    def test_incomplete_runtime_cleanup_latches_failure_and_keeps_census(self):
        with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
            transaction = self.transaction(Path(temporary).resolve())
            self.census.return_value = ["owned native birth"]
            self.terminate.side_effect = RuntimeError("unknown changed process")
            transaction.failed_child_cleanup()
            self.assertEqual(transaction.failure_census, ["owned native birth"])
            self.assertTrue(transaction.failure_cleanup_incomplete)
            self.assertTrue(transaction.value._retain_root)
            transaction.value.retain_root.assert_called_once_with(reason="cleanup-incomplete")

    def test_failed_child_cleanup_never_signals_foreign_work(self):
        with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
            transaction = self.transaction(Path(temporary).resolve())
            transaction.value.root = Path("/foreign/root")
            transaction.failed_child_cleanup()
            self.terminate.assert_not_called()
            self.assertTrue(transaction.value._retain_root)
            self.assertTrue(transaction.failure_cleanup_incomplete)
            transaction.value.retain_root.assert_not_called()

    def test_source_has_no_pin_reset_test_import_pull_force_or_recursive_cleanup(self):
        support = ROOT / "Tests/Compatibility/storage_lifecycle_v2_remount.py"
        source = support.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertFalse((node.module or "").startswith("test_"))
        for prohibited in ("_ROOT_PINS.clear", "rmtree(", '"-force"', ".images.pull("):
            self.assertNotIn(prohibited, source)
        self.assertIn('get_context("spawn")', source)
        self.assertIn("value.start()", source)
        self.assertIn("conv=fsync", source)
        native = (ROOT / "Tests/Compatibility/test_storage_lifecycle_v2_remount.py").read_text()
        self.assertIn('compat("RTM-126")', native)
        self.assertIn("_managed_remount_cleanup = transaction", native)
        self.assertIn("transaction.finished and passed", native)
        self.assertIn('OwnedImage.create(work, "store", value.root, "1t")', native)


if __name__ == "__main__":
    unittest.main()
