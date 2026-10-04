#!/usr/bin/env python3
"""Offline helper-lifetime guards. Never execute an engine/helper or native census."""
from __future__ import annotations

import ast
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import helper_fixture_lifetime as lifetime


class LifetimeTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.environment = {
            "CENGINE_NETWORK_HELPER_SERVICE_NAME": lifetime.SERVICE,
            "CENGINE_NETWORK_HELPER_IDENTIFIER": lifetime.SERVICE,
            "CENGINE_COMPAT_NETWORK_HELPER_LABEL": lifetime.SERVICE,
            "CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE": lifetime.TOKEN,
            "CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT": "a" * 64,
            "CENGINE_COMPAT_OWNER_PID": "123",
        }
        self.stack.enter_context(patch.dict(os.environ, self.environment, clear=True))
        # Any unmocked subprocess, signal, or native census is a test bug.
        self.command = self.stack.enter_context(patch.object(lifetime.subprocess, "run", side_effect=AssertionError("unmocked command")))
        self.stack.enter_context(patch.object(os, "kill", side_effect=AssertionError("signal forbidden")))
        self.kernel = self.stack.enter_context(patch.object(lifetime.harness, "_kernel_process_argv_excludes_runtime", side_effect=AssertionError("native census forbidden")))
        self.owner_process = self.stack.enter_context(patch.object(lifetime.harness, "_kernel_process",
            return_value=SimpleNamespace(identity=(1, 2, 3), pidversion=4)))
        self.before = dict(protocolVersion=5, buildFingerprint="a" * 64,
                           serviceName=lifetime.SERVICE, ownerUID=os.getuid(), processIdentifier=100,
                           capabilities=dict(schemaVersion=1, securityRevision=1, profile="ordinary",
                                             storageContracts=["lifecycle-v2", "lifecycle-v2-adopted-service-change-v1", "lifecycle-v2-stable-host-identity-v1"]))
        self.after = dict(self.before, processIdentifier=101)

    def mock_guards(self):
        guards = {}
        for name, result in (("require_claim", (1, 2)), ("require_no_roots", None), ("require_no_clients", None)):
            guards[name] = self.stack.enter_context(patch.object(lifetime, name, return_value=result))
        return guards

    def replies(self, *values):
        self.command.side_effect = [SimpleNamespace(stdout=json.dumps(value)) if isinstance(value, dict) else value
                                for value in values]

    def test_single_restart_and_managed_status_on_both_sides(self):
        guards = self.mock_guards()
        self.replies(self.before, self.after, self.after)
        lifetime.restart_before_fixture(Path("/never-executed"))
        self.assertEqual(guards["require_no_roots"].call_count, 3)
        self.assertEqual(guards["require_no_clients"].call_count, 3)
        self.assertEqual([call.args[0][1:] for call in self.command.call_args_list], [
            ["helper", "status", "--require-managed", "lifecycle-v2"],
            ["helper", "restart"], ["helper", "status", "--require-managed", "lifecycle-v2"]])
        self.assertEqual([call.kwargs["timeout"] for call in self.command.call_args_list], [10, 45, 10])

    def test_wrong_status_never_restarts(self):
        self.mock_guards()
        changes = dict(serviceName="dev.cengine.network-helper", ownerUID=os.getuid() + 1,
                       buildFingerprint="b" * 64, protocolVersion=4, processIdentifier=0,
                       capabilities={}, extra_unused=None)
        changes.pop("extra_unused")
        for key, value in changes.items():
            with self.subTest(key=key):
                self.command.reset_mock()
                self.replies(dict(self.before, **{key: value}))
                with self.assertRaises(RuntimeError):
                    lifetime.restart_before_fixture(Path("/never"))
                self.assertEqual(self.command.call_count, 1)

    def test_namespace_or_missing_installed_fingerprint_refuses(self):
        self.mock_guards()
        for key in self.environment:
            if key == "CENGINE_COMPAT_OWNER_PID":
                continue
            with self.subTest(key=key), patch.dict(os.environ, {key: "wrong"}):
                self.command.reset_mock()
                self.replies(self.before)
                with self.assertRaises(RuntimeError):
                    lifetime.restart_before_fixture(Path("/never"))
                self.assertLessEqual(self.command.call_count, 1)

    def test_guard_failures_are_readonly(self):
        guards = self.mock_guards()
        for name, guard in guards.items():
            with self.subTest(name=name):
                guard.side_effect = RuntimeError("unknown/retained/active")
                with self.assertRaises(RuntimeError):
                    lifetime.restart_before_fixture(Path("/never"))
                self.command.assert_not_called()
                guard.side_effect = None

    def test_changed_claim_does_not_restart(self):
        guards = self.mock_guards()
        guards["require_claim"].side_effect = [(1, 2), (1, 3)]
        self.replies(self.before)
        with self.assertRaises(RuntimeError):
            lifetime.restart_before_fixture(Path("/never"))
        self.assertEqual(self.command.call_count, 1)

    def test_timeout_same_pid_and_changed_identity_poison_boundary(self):
        self.mock_guards()
        bad_after = dict(self.after, capabilities=dict(self.after["capabilities"], securityRevision=2))
        cases = [(self.before, subprocess.TimeoutExpired("never", 45)),
                 (self.before, self.before, self.before),
                 (self.before, self.after, bad_after),
                 (self.before, self.after, dict(self.after, processIdentifier=102)),
                 (self.before, subprocess.CalledProcessError(1, "never"))]
        for replies in cases:
            with self.subTest(replies=replies):
                self.command.reset_mock()
                self.replies(*replies)
                boundary = lifetime.FixtureBoundary()
                with self.assertRaises(Exception):
                    boundary.prepare(Path("/never"))
                calls = self.command.call_count
                with self.assertRaises(RuntimeError):
                    boundary.prepare(Path("/never"))
                self.assertEqual(self.command.call_count, calls)

    def test_288_clean_fixtures_and_retention_barrier(self):
        with patch.object(lifetime, "restart_before_fixture") as restart, patch.object(os.path, "lexists", return_value=False):
            boundary = lifetime.FixtureBoundary()
            for _ in range(288):
                boundary.prepare(Path("/never"))
                value = SimpleNamespace(_managed_fixture_retention=True, _retain_root=False, work=Path("/never-root"))
                boundary.created(value)
                # Only final outcome cleanup can clear this pre-retention flag.
                with self.assertRaises(RuntimeError):
                    boundary.prepare(Path("/never"))
                value._managed_fixture_retention = False
            self.assertEqual(restart.call_count, 288)
            with patch.object(os.path, "lexists", return_value=True), self.assertRaises(RuntimeError):
                boundary.prepare(Path("/never"))

    def test_census_refuses_active_unknown_malformed_and_missing_owner(self):
        uid = os.getuid()
        for output, result in ((f"123 {uid}\n456 {uid}\n", False),
                               (f"123 {uid}\n", RuntimeError("unknown")),
                               ("not ids\n", True), ("", True)):
            with self.subTest(output=output):
                self.command.side_effect = None
                self.command.return_value = SimpleNamespace(stdout=output)
                self.kernel.side_effect = result if isinstance(result, Exception) else None
                self.kernel.return_value = result
                with self.assertRaises(RuntimeError):
                    lifetime.require_no_clients()
        self.command.return_value = SimpleNamespace(stdout=f"319 -2\n43960 4294967294\n123 {uid}\n456 {uid}\n")
        self.kernel.side_effect = None
        self.kernel.return_value = True
        lifetime.require_no_clients()

    def test_canonical_lock_ignores_tmp_and_override_cannot_compete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with patch.object(lifetime, "canonical_temp", return_value=root), patch.object(tempfile, "gettempdir", return_value=temporary):
                expected = lifetime.canonical_lock()
                self.assertEqual(lifetime.launcher_lock(), expected)
                with patch.dict(os.environ, {"CENGINE_COMPAT_LOCK": str(root / "different")}):
                    with self.assertRaises(RuntimeError):
                        lifetime.launcher_lock()
                with patch.object(tempfile, "gettempdir", return_value="/not-the-user-temp"):
                    with self.assertRaises(RuntimeError):
                        lifetime.launcher_lock()

    def test_claim_owner_mode_symlink_and_competing_creator(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "lock"
            lock.mkdir(mode=0o700)
            pid = lock / "pid"
            pid.write_text("123\n")
            pid.chmod(0o600)
            with patch.object(lifetime, "launcher_lock", return_value=lock):
                os.environ["CENGINE_COMPAT_CLAIM"] = json.dumps(lifetime.claim_identity())
                lifetime.require_claim()
                with self.assertRaises(FileExistsError):
                    lock.mkdir(mode=0o700)  # A competing supported launcher cannot acquire.
                for mode in (0o755, 0o777):
                    lock.chmod(mode)
                    with self.assertRaises(RuntimeError):
                        lifetime.require_claim()
                lock.chmod(0o700)
                pid.write_text("456\n")
                with self.assertRaises(RuntimeError):
                    lifetime.require_claim()
                pid.unlink()
                pid.symlink_to(Path(temporary) / "missing")
                with self.assertRaises((RuntimeError, OSError)):
                    lifetime.require_claim()

    def test_post_status_roots_or_clients_poison_boundary_without_retry(self):
        guards = self.mock_guards()
        for name in ("require_no_roots", "require_no_clients"):
            with self.subTest(name=name):
                guards[name].side_effect = [None, None, RuntimeError("unexpected fork/root")]
                self.command.reset_mock()
                self.replies(self.before, self.after, self.after)
                boundary = lifetime.FixtureBoundary()
                with self.assertRaises(RuntimeError):
                    boundary.prepare(Path("/never"))
                self.assertEqual(self.command.call_count, 3)
                with self.assertRaises(RuntimeError):
                    boundary.prepare(Path("/never"))
                self.assertEqual(self.command.call_count, 3)
                guards[name].side_effect = None

    def test_claim_pin_rejects_forged_receipt_pid_replacement_and_unknown_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "lock"
            lock.mkdir(mode=0o700)
            pid = lock / "pid"
            pid.write_text("123\n")
            pid.chmod(0o600)
            with patch.object(lifetime, "launcher_lock", return_value=lock):
                identity = lifetime.claim_identity()
                os.environ["CENGINE_COMPAT_CLAIM"] = json.dumps(identity)
                lifetime.require_claim()
                for process in (None, SimpleNamespace(identity=(1, 2, 5), pidversion=6)):
                    self.owner_process.return_value = process
                    with self.assertRaises(RuntimeError):
                        lifetime.require_claim()
                self.owner_process.return_value = SimpleNamespace(identity=(1, 2, 3), pidversion=4)
                with patch.dict(os.environ, {"CENGINE_COMPAT_CLAIM": "[1, 2]"}):
                    with self.assertRaises(RuntimeError):
                        lifetime.require_claim()
                (lock / "unknown-evidence").write_text("preserve")
                with self.assertRaises(RuntimeError):
                    lifetime.release_claim()
                self.assertEqual(pid.read_text(), "123\n")
                (lock / "unknown-evidence").unlink()
                pid.rename(lock / "old-pid")
                pid.write_text("123\n")
                pid.chmod(0o600)
                with self.assertRaises(RuntimeError):
                    lifetime.require_claim()
                with self.assertRaises(RuntimeError):
                    lifetime.release_claim()
                self.assertEqual((lock / "old-pid").read_text(), "123\n")

    def test_unknown_and_retained_roots_are_never_deleted(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "cengine-compat-unknown"
            root.mkdir()
            marker = root / ".cengine-compat-retain"
            marker.write_text("evidence")
            # All census parents use a mock listing; no host filesystem census.
            with patch.object(Path, "iterdir", return_value=iter([root])), patch.object(lifetime, "canonical_temp", return_value=parent):
                with self.assertRaises(RuntimeError):
                    lifetime.require_no_roots()
            self.assertEqual(marker.read_text(), "evidence")

    def test_installer_staging_is_not_a_runtime_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            staging = parent / "cengine-compat-helper.AKcV60"
            staging.mkdir()
            for name in ("manifest", "helper.plist", "client-token"):
                (staging / name).write_text("not read or removed")
            original = Path.iterdir
            with patch.object(Path, "iterdir", lambda path: original(path) if path == staging else iter([staging])), \
                    patch.object(lifetime, "canonical_temp", return_value=parent):
                lifetime.require_no_roots()
                (staging / "root").mkdir()
                with self.assertRaises(RuntimeError):
                    lifetime.require_no_roots()
                (staging / "root").rmdir()
                (staging / "manifest").unlink()
                (staging / "manifest").symlink_to(staging / "client-token")
                with self.assertRaises(RuntimeError):
                    lifetime.require_no_roots()
            self.assertEqual((staging / "client-token").read_text(), "not read or removed")

    def test_changed_home_cannot_hide_retained_matrix_roots(self):
        with patch.object(Path, "home", return_value=Path("/not-the-owner-home")):
            with self.assertRaises(RuntimeError):
                lifetime.launcher_lock()
        self.command.assert_not_called()

    def test_fixture_refusal_precedes_mkdtemp_including_manual_first_start(self):
        source = ROOT / "Tests/Compatibility/conftest.py"
        tree = ast.parse(source.read_text())
        fixture = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "daemon")
        fixture.decorator_list = []
        boundary = Mock()
        boundary.prepare.side_effect = RuntimeError("refuse")
        fail = Mock(side_effect=RuntimeError("fixture failed"))
        namespace = dict(pytest=SimpleNamespace(fail=fail), pathlib=__import__("pathlib"),
                         os=os, tempfile=tempfile, HELPER_FIXTURE_BOUNDARY=boundary,
                         local_build_image_preflight=lambda request: {},
                         managed_storage_arguments=lambda env: [],
                         DEFAULT_BINARY="/never", DEFAULT_KERNEL="/never",
                         DEFAULT_CONTAINER_INITRAMFS="/never", DEFAULT_STORAGE_INITRAMFS="/never")
        # Future annotations avoids importing the native fixture/dependency graph.
        exec(compile("from __future__ import annotations\n" + ast.unparse(fixture), str(source), "exec"), namespace)
        for mode in ("automatic", "lifecycle-first-start"):
            request = SimpleNamespace(param=mode, node=SimpleNamespace(
                get_closest_marker=lambda _: SimpleNamespace(args=("RTM-119",))))
            with patch.dict(os.environ, {"CENGINE_COMPAT_LIFECYCLE_FAULT": "before-configure-v1"}), \
                    patch.object(Path, "is_file", return_value=True), \
                    patch.object(tempfile, "mkdtemp") as create:
                with self.assertRaisesRegex(RuntimeError, "fixture failed"):
                    next(namespace["daemon"](request, Path("/cache")))
                create.assert_not_called()
        self.assertEqual(boundary.prepare.call_count, 2)
        self.command.assert_not_called()

    def remount_transaction(self):
        from storage_lifecycle_v2_remount import OfflineRemount
        self.stack.enter_context(patch("storage_lifecycle_v2_remount.binary_stamp", return_value=(1, 2, 3, 4, 5)))
        transaction = OfflineRemount(SimpleNamespace(binary=Path("/never"), owner_binary=Path("/never"),
                                                     work=Path("/owned/cengine-compat-original")),
                                     None, None, None)
        self.stack.enter_context(patch.object(OfflineRemount, "validate_boundary"))
        self.stack.enter_context(patch.object(lifetime, "canonical_temp", return_value=Path("/owned")))
        self.stack.enter_context(patch.object(Path, "is_symlink", return_value=False))
        self.stack.enter_context(patch.object(Path, "iterdir", return_value=[transaction.value.work]))
        return transaction

    def test_remount_restart_is_separate_and_does_not_relax_generic_roots(self):
        guards = self.mock_guards()
        transaction = self.remount_transaction()
        self.replies(self.before, self.after, self.after)
        lifetime.restart_for_offline_remount(transaction)
        self.assertTrue(transaction.helper_released)
        self.assertFalse(transaction.restart_pending)
        self.assertEqual(guards["require_no_clients"].call_count, 3)
        guards["require_no_roots"].assert_not_called()
        self.assertEqual(transaction.validate_boundary.call_count, 3)
        self.assertEqual(self.command.call_count, 3)

    def test_remount_competing_root_client_claim_or_boundary_refuses_without_restart(self):
        from storage_lifecycle_v2_remount import OfflineRemount
        guards = self.mock_guards()
        template = self.remount_transaction()
        for failure in ("root", "client", "claim", "boundary"):
            with self.subTest(failure=failure), ExitStack() as stack:
                transaction = OfflineRemount(template.value, None, None, None)
                if failure == "root":
                    stack.enter_context(patch.object(Path, "iterdir", return_value=[template.value.work, Path("/owned/cengine-compat-other")]))
                elif failure == "boundary":
                    stack.enter_context(patch.object(OfflineRemount, "validate_boundary", side_effect=RuntimeError("refuse")))
                else:
                    name = "require_no_clients" if failure == "client" else "require_claim"
                    stack.enter_context(patch.object(lifetime, name, side_effect=RuntimeError("refuse")))
                self.command.reset_mock()
                with self.assertRaises(RuntimeError):
                    lifetime.restart_for_offline_remount(transaction)
                self.command.assert_not_called()
                self.assertTrue(transaction.restart_pending)
                with self.assertRaises(RuntimeError):
                    lifetime.restart_for_offline_remount(transaction)
                self.command.assert_not_called()

    def test_remount_old_helper_refusal_and_failed_restart_are_terminal(self):
        from storage_lifecycle_v2_remount import OfflineRemount
        self.mock_guards()
        template = self.remount_transaction()
        old = dict(self.before, capabilities=dict(profile="ordinary", storageContracts=["lifecycle-v2"]))
        for replies in ((old,), (self.before, subprocess.CalledProcessError(1, "never")),
                        (self.before, self.before, self.before)):
            with self.subTest(replies=replies):
                transaction = OfflineRemount(template.value, None, None, None)
                self.command.reset_mock()
                self.replies(*replies)
                with self.assertRaises(Exception):
                    lifetime.restart_for_offline_remount(transaction)
                calls = self.command.call_count
                self.assertFalse(transaction.helper_released)
                self.assertTrue(transaction.restart_pending)
                with self.assertRaises(RuntimeError):
                    lifetime.restart_for_offline_remount(transaction)
                self.assertEqual(self.command.call_count, calls)

    def test_remount_does_not_accept_duck_typed_transaction(self):
        self.mock_guards()
        with self.assertRaises(RuntimeError):
            lifetime.restart_for_offline_remount(SimpleNamespace(restart_pending=False))
        self.command.assert_not_called()

    def test_fixture_integration_location_and_no_start_or_cache_restart(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/conftest.py").read_text())
        fixture = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "daemon")
        source = ast.unparse(fixture)
        self.assertLess(source.index("HELPER_FIXTURE_BOUNDARY.prepare"), source.index("tempfile.mkdtemp"))
        self.assertLess(source.index("HELPER_FIXTURE_BOUNDARY.prepare"), source.index("if not manual:"))
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == "Daemon" or isinstance(node, ast.FunctionDef) and node.name != "daemon":
                self.assertNotIn("HELPER_FIXTURE_BOUNDARY.prepare", ast.unparse(node))
        for path in ("Scripts/run-compat-tests.sh", "Scripts/run-isolated-cengine.sh", "tools/managed-prepare-matrix.sh"):
            source = (ROOT / path).read_text()
            self.assertIn('$(python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py")', source)
            self.assertIn("umask 077", source)
            self.assertNotIn('LOCK=${CENGINE_COMPAT_LOCK:-', source)


if __name__ == "__main__":
    unittest.main()
