#!/usr/bin/env python3
"""Offline regression checks for RTM-130's real timestamp-only asset builder."""
import ast
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Tests/Compatibility/test_storage_lifecycle_v2_runtime.py"
TREE = ast.parse(SOURCE.read_text(), filename=str(SOURCE))
FUNCTIONS = {"changed_gzip_mtime", "stage_guest_update", "storage_launch_history", "storage_guest_proof"}
IMPORTS = {"__future__", "gzip", "hashlib", "json", "pathlib", "subprocess", "sys"}
nodes = []
for node in TREE.body:
    if isinstance(node, ast.Import) and all(alias.name in IMPORTS for alias in node.names):
        nodes.append(node)
    elif isinstance(node, ast.ImportFrom) and node.module in IMPORTS:
        nodes.append(node)
    elif isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS:
        nodes.append(node)
R = ModuleType("storage_guest_update")
R.ROOT = ROOT
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec", optimize=0), R.__dict__)


class GuestUpdateTests(unittest.TestCase):
    def test_real_helpers_loaded_without_vm_or_sdk_imports(self):
        for name in FUNCTIONS:
            self.assertEqual(getattr(R, name).__code__.co_filename, str(SOURCE))
        self.assertNotIn("pytest", R.__dict__)
        self.assertNotIn("Mount", R.__dict__)

    def test_only_four_byte_timestamp_field_changes_and_payload_is_identical(self):
        payload = b"real archive bytes must never be rebuilt\0" * 100
        for timestamp in (0, 1, 255, (1 << 32) - 1):
            with self.subTest(timestamp=timestamp):
                original = gzip.compress(payload, mtime=timestamp)
                updated = R.changed_gzip_mtime(original)
                self.assertNotEqual(updated, original)
                self.assertEqual(updated[:4], original[:4])
                self.assertEqual(updated[8:], original[8:])
                self.assertEqual(int.from_bytes(updated[4:8], "little"), (timestamp + 1) % (1 << 32))
                self.assertEqual(gzip.decompress(updated), payload)
                self.assertNotEqual(hashlib.sha256(updated).digest(), hashlib.sha256(original).digest())
                self.assertNotEqual(R.changed_gzip_mtime(updated), updated)

    def test_refuses_header_crc_reserved_flags_wrong_format_and_corruption(self):
        original = gzip.compress(b"archive", mtime=0)
        for flag in (2, 0x20, 0x40, 0x80, 0xff):
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, "FHCRC"):
                R.changed_gzip_mtime(original[:3] + bytes([flag]) + original[4:])
        for value in (b"", original[:17], b"bad" + original[3:]):
            with self.assertRaises(ValueError):
                R.changed_gzip_mtime(value)
        with self.assertRaises((gzip.BadGzipFile, EOFError)):
            R.changed_gzip_mtime(original[:-1])

    def fixture(self, source):
        source.mkdir()
        files = {"vmlinux": b"unchanged kernel", "container-initramfs.cpio.gz": gzip.compress(b"container", mtime=0),
                 "storage-initramfs.cpio.gz": gzip.compress(b"storage guest and mke2fs", mtime=0)}
        metadata = {"schemaVersion": 1, "storageLifecycleVersion": 2,
                    "storageInitramfsSHA256": hashlib.sha256(files["storage-initramfs.cpio.gz"]).hexdigest(),
                    "ordinaryProvenance": {"sourceSHA256": "original-source",
                                           "storageBinary": {"sha256": "original-binary"}},
                    "containerInitramfsSHA256": hashlib.sha256(files["container-initramfs.cpio.gz"]).hexdigest()}
        files["disk-bootstrap.json"] = json.dumps(metadata).encode()
        files["SHA256SUMS"] = b"original manifest preserved"
        for name, data in files.items():
            (source / name).write_bytes(data)
        return files, metadata

    def test_paired_copy_preserves_source_and_provenance_updates_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = Path(temporary) / "source", Path(temporary) / "update"
            original, before = self.fixture(source)
            with patch.object(R.subprocess, "run") as run:
                digest = R.stage_guest_update(source, destination)
            self.assertEqual(run.call_count, 2)
            self.assertEqual([call.args[0][-1] for call in run.call_args_list], [str(source), str(destination)])
            for call in run.call_args_list:
                self.assertIn("from guest_asset_provenance import assert_current", call.args[0][2])
                self.assertEqual(call.kwargs, dict(check=True, capture_output=True, timeout=120))
            self.assertEqual({p.name: p.read_bytes() for p in source.iterdir()}, original)
            self.assertEqual(set(p.name for p in destination.iterdir()), set(original))
            for name in ("vmlinux", "container-initramfs.cpio.gz"):
                self.assertEqual((destination / name).read_bytes(), original[name])
            storage = (destination / "storage-initramfs.cpio.gz").read_bytes()
            self.assertEqual(storage[:4], original["storage-initramfs.cpio.gz"][:4])
            self.assertEqual(storage[8:], original["storage-initramfs.cpio.gz"][8:])
            self.assertEqual(digest, hashlib.sha256(storage).hexdigest())
            after = json.loads((destination / "disk-bootstrap.json").read_bytes())
            self.assertEqual(after, {**before, "storageInitramfsSHA256": digest})
            lines = (destination / "SHA256SUMS").read_text().splitlines()
            self.assertEqual(sorted(lines), sorted(
                f"{hashlib.sha256((destination / name).read_bytes()).hexdigest()}  {name}"
                for name in original if name != "SHA256SUMS"))

    def test_invalid_source_or_destination_provenance_never_returns_digest(self):
        for which in (0, 1):
            with self.subTest(which=which), tempfile.TemporaryDirectory() as temporary:
                source, destination = Path(temporary) / "source", Path(temporary) / "update"
                original, _ = self.fixture(source)
                calls = [None, None]
                calls[which] = subprocess.CalledProcessError(1, "assert_current")
                with patch.object(R.subprocess, "run", side_effect=calls):
                    with self.assertRaises(subprocess.CalledProcessError):
                        R.stage_guest_update(source, destination)
                self.assertEqual(destination.exists(), which == 1)
                self.assertEqual({p.name: p.read_bytes() for p in source.iterdir()}, original)

    def test_existing_destination_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = Path(temporary) / "source", Path(temporary) / "update"
            self.fixture(source)
            destination.mkdir()
            sentinel = destination / "vmlinux"
            sentinel.write_bytes(b"preserve user bytes")
            with patch.object(R.subprocess, "run"), self.assertRaises(FileExistsError):
                R.stage_guest_update(source, destination)
            self.assertEqual(sentinel.read_bytes(), b"preserve user bytes")

    def test_both_marked_wrappers_use_same_proof_with_upgrade_only_for_rtm130(self):
        namespace = {"interrupted_cold_l2_recovery": Mock()}
        for name, upgrade in (("test_lifecycle_v2_interrupted_cold_l2_recovers", False),
                              ("test_lifecycle_v2_guest_initramfs_update_cold_recovery", True)):
            node = next(n for n in TREE.body if getattr(n, "name", "") == name)
            expected = "RTM-130" if upgrade else "RTM-129"
            self.assertEqual(ast.literal_eval(node.decorator_list[0].args[0]), expected)
            cloned = ast.FunctionDef(name=node.name, args=node.args, body=node.body,
                                     decorator_list=[], returns=node.returns, type_comment=node.type_comment)
            exec(compile(ast.fix_missing_locations(ast.Module(body=[cloned], type_ignores=[])), str(SOURCE), "exec"), namespace)
            namespace[name]("client", "daemon", "shared")
            namespace["interrupted_cold_l2_recovery"].assert_called_with("client", "daemon", "shared", **({"guest_update": True} if upgrade else {}))

    def test_upgrade_is_after_positive_exit_before_start_and_retains_history(self):
        node = next(n for n in TREE.body if getattr(n, "name", "") == "interrupted_cold_l2_recovery")
        code = ast.unparse(node)
        for earlier, later in (("_strict_shutdown(daemon)", "replacement.exact_exit"),
                               ("replacement.exact_exit", "stage_guest_update(source, destination)"),
                               ("stage_guest_update(source, destination)", "daemon.kernel = destination"),
                               ("daemon.storage_initramfs =", "daemon.start(on_spawn=observe"),
                               ("daemon.start(on_spawn=observe", "attempted_spec['expectedInitramfsSHA256'] == expected_digest"),
                               ("attempted_spec['expectedInitramfsSHA256'] == expected_digest", "daemon.start()"),
                               ("daemon.start()", "storage_guest_proof(daemon, fresh, expected_digest)")):
            self.assertLess(code.index(earlier), code.index(later))
        self.assertIn("assert not compatibility_runtime_processes", code)
        self.assertIn("old launch history changed", code)
        self.assertIn("selector.read_bytes() == selector_bytes", code)
        self.assertIn("== owner_bytes", code)
        self.assertIn("new_spec['expectedInitramfsSHA256'] != old_spec['expectedInitramfsSHA256']", code)
        for proof in ("recovered_cold_proof(before, frozen, after)",
                      "attempted_history.get(path) == data for path, data in history.items()",
                      "retained.get(path) == data for path, data in attempted_history.items()",
                      "set(attempted_history) - set(history)", "set(retained) - set(history)",
                      "new_generation != attempted_generation",
                      "for generation in (attempted_generation, new_generation)",
                      "('spec.json', 'intent.json', 'launch.json')"):
            self.assertIn(proof, code)
        calls = [ast.unparse(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)]
        self.assertEqual(calls.count("peer.start"), 1)  # Only initial peers, never manual recovery.
        self.assertEqual(calls.count("daemon.start"), 2)  # Failed attempt then C+2 recovery.
        self.assertEqual(calls.count("stage_guest_update"), 1)  # Same changed assets on recovery.
        self.assertNotIn("peer.restart", calls)
        update = next(n for n in ast.walk(node) if isinstance(n, ast.If) and
                      any(isinstance(c, ast.Call) and ast.unparse(c.func) == "stage_guest_update"
                          for c in ast.walk(n)))
        self.assertEqual(ast.unparse(update.test), "guest_update")
        strict = next(n for n in TREE.body if getattr(n, "name", "") ==
                      "test_lifecycle_v2_two_strict_cold_restarts_with_live_peers")
        self.assertNotIn("guest_update", ast.unparse(strict))
        self.assertNotIn("interrupted_cold_l2_recovery", ast.unparse(strict))

    def test_storage_spec_requires_digest_path_and_actual_native_spec(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "infrastructure").mkdir()
            daemon = SimpleNamespace(root=root, storage_initramfs=root / "storage.cpio.gz")
            spec = dict(expectedInitramfsSHA256="a" * 64, initialRamdiskPath=str(daemon.storage_initramfs))
            raw = json.dumps(spec).encode()
            (root / "infrastructure/shim.json").write_bytes(raw)
            native = {"storage": {"specification": {"sha256": hashlib.sha256(raw).hexdigest()}}}
            self.assertEqual(R.storage_guest_proof(daemon, native, "a" * 64), spec)
            with self.assertRaises(AssertionError):
                R.storage_guest_proof(daemon, native, "b" * 64)
            native["storage"]["specification"]["sha256"] = "b" * 64
            with self.assertRaises(AssertionError):
                R.storage_guest_proof(daemon, native, "a" * 64)


if __name__ == "__main__":
    unittest.main()
