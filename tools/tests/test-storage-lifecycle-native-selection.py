#!/usr/bin/env python3
"""Python-only wrapper/ownership/collection regressions. Never launches the driver."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[2]
# Collection needs the same pytest/docker packages as the compatibility runner;
# reuse an existing environment only (no dependency installation or native build).
if importlib.util.find_spec("pytest") is None:
    python = ROOT / ".build/compat-venv/bin/python"
    if not python.is_file() or Path(sys.executable) == python:
        raise SystemExit("requires existing compatibility pytest environment")
    os.execv(str(python), [str(python), __file__, *sys.argv[1:]])

sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import pytest
import conftest
import harness
import test_storage_lifecycle_v2_native as native


def public_receipt(case):
    value = dict(profile=native.PROFILE, case=case, success=True,
                 store="1b999dbf-09e5-4a94-8d0f-34255b3d4688", generation=1,
                 hostReopened=True, rootAuthenticated=True, shimReaped=True,
                 controllerReaped=True, terminal=case != "live-proof-loss")
    if case == "lost-completion":
        value.update(replyDropped=True, stableGrant=True, freshProof=True)
    if case == "live-proof-loss":
        value.update(proofRefused=True, pendingPreserved=True, liveShimObserved=True)
    return value


def process(pid, args, parent=1, birth=1, executable="/native/cengine"):
    return harness.RuntimeProcess(pid, executable=executable, arguments=(executable, *args),
        identity=(birth, 0, pid + birth), pidversion=birth, parent_pid=parent)


class NativeSelectionTests(unittest.TestCase):
    def test_closed_commands_and_exact_receipts(self):
        for case in native.CASES:
            self.assertEqual(native.command(Path("/binary"), Path("/root"), Path("/assets"), case),
                ["/binary", "storage-lifecycle-qualification", "--root", "/root", "--assets", "/assets", "--case", case])
            good = public_receipt(case)
            self.assertEqual(native.receipt(b"diagnostic\n" + json.dumps(good).encode() + b"\n", case), good)
            for key in good:
                missing = {name: value for name, value in good.items() if name != key}
                with self.subTest(case=case, missing=key), self.assertRaises((ValueError, TypeError)):
                    native.receipt(json.dumps(missing).encode(), case)
            for key, value in good.items():
                if type(value) is bool:
                    for wrong in (not value, int(value), str(value), None):
                        with self.subTest(case=case, field=key, wrong=wrong), self.assertRaises(ValueError):
                            native.receipt(json.dumps({**good, key: wrong}).encode(), case)
            for change in (dict(generation=True), dict(generation=2), dict(generation=1.0),
                           dict(store="not-a-uuid"), dict(store="0" * 32), dict(profile="ordinary"), dict(case="RTM-113"),
                           dict(error="cleanup failed"), dict(nativeAccepted=True), dict(digests={"x": "bad"})):
                with self.assertRaises(ValueError):
                    native.receipt(json.dumps({**good, **change}).encode(), case)
            with self.assertRaises(ValueError):
                native.receipt(json.dumps(good).encode()[:-1] + b',"success":true}', case)
            with self.assertRaises(ValueError):
                native.receipt(json.dumps(good).encode() + b"\nnot a receipt\n", case)
        for case in ("RTM-113", "RTM-114", "fresh ", "FRESH", "fresh|lost-completion", "*", "../fresh", ""):
            with self.assertRaises(ValueError): native.command("b", "r", "a", case)
        with self.assertRaises(ValueError): native.receipt(b"{}" * (1024 * 1024), "fresh")

    def test_absent_profile_only_skip_and_missing_opt_in_prerequisites_fail(self):
        with self.assertRaises(pytest.skip.Exception): native.prerequisites({})
        for profile in ("1", "unknown", " " + native.PROFILE):
            with self.assertRaises(ValueError): native.prerequisites({native.PROFILE_ENV: profile})
        selected = {native.PROFILE_ENV: native.PROFILE}
        with self.assertRaises(ValueError): native.prerequisites(selected)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "cengine"; binary.touch(); binary.chmod(0o700)
            controller = binary.with_name("cengine-storage-controller"); controller.touch(); controller.chmod(0o600)
            assets = root / "assets"; assets.mkdir()
            for name in ("vmlinux", "storage-initramfs.cpio.gz", "disk-bootstrap.json", "SHA256SUMS"):
                (assets / name).touch()
            selected.update(CENGINE_BINARY=str(binary), CENGINE_COMPAT_MANAGED_ASSET_DIR=str(assets))
            with self.assertRaisesRegex(ValueError, "paired native controller unavailable"):
                native.prerequisites(selected)
            controller.chmod(0o700)
            self.assertEqual(native.prerequisites(selected), (binary.resolve(), assets.resolve()))
            for key in ("CENGINE_BINARY", "CENGINE_COMPAT_MANAGED_ASSET_DIR"):
                with self.assertRaises((ValueError, OSError)):
                    native.prerequisites({name: value for name, value in selected.items() if name != key})
            with self.assertRaises(ValueError):
                native.prerequisites({**selected, "PREPARE_COMPATIBILITY_PROFILE": "rtm096-full-nine-v3"})

    def test_exact_three_collected_ids_and_no_ordinary_daemon_fixtures(self):
        found = []
        class Selection:
            def pytest_collection_modifyitems(self, items):
                found.extend((item.name, item.get_closest_marker("compat").args, item.fixturenames) for item in items)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / "docker").mkdir(); (root / "buildx").mkdir()
            run_id = "a" * 64
            (root / ".owner-pid").write_text(f"{run_id} {os.getpid()}\n")
            env = dict(CENGINE_COMPAT_CLIENT_STATE_ROOT=str(root), CENGINE_COMPAT_RUN_ID=run_id,
                       CENGINE_COMPAT_OWNER_PID=str(os.getpid()), DOCKER_CONFIG=str(root / "docker"),
                       BUILDX_CONFIG=str(root / "buildx"), PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
            with patch.dict(os.environ, env), patch.object(conftest, "pytest_report_header", return_value=[]), redirect_stdout(io.StringIO()):
                code = pytest.main(["--collect-only", "-q", "-c", str(ROOT / "Tests/Compatibility/pytest.ini"),
                                    str(ROOT / "Tests/Compatibility/test_storage_lifecycle_v2_native.py")], plugins=[Selection()])
            self.assertEqual(code, 0)
            # Reuse the actual exact-parent marker verifier, not just a source check.
            with patch.dict(os.environ, env):
                conftest.pytest_sessionstart(None)
                (root / ".owner-pid").write_text(f"{run_id} {os.getppid()}\n")
                with self.assertRaises(pytest.exit.Exception): conftest.pytest_sessionstart(None)
        self.assertEqual({(name, marker) for name, marker, _ in found}, {
            ("test_native_storage_lifecycle_fresh", ("RTM-114",)),
            ("test_native_storage_lifecycle_lost_completion", ("RTM-115",)),
            ("test_native_storage_lifecycle_live_proof_loss", ("RTM-116",)),
        })
        self.assertEqual(len(found), 3)
        for _, _, fixtures in found:
            self.assertFalse({"daemon", "client", "image_cache"} & set(fixtures))
        ledger = (ROOT / "docs/docker-compatibility.md").read_text()
        self.assertIn('| `RTM-113` | `test_native_storage_lifecycle_checkpoint` |', ledger)
        old = (ROOT / "Tests/Compatibility/test_managed_fuse_interrupt.py").read_text()
        self.assertIn('@pytest.mark.compat("RTM-113")', old)
        self.assertIn('def test_native_storage_lifecycle_checkpoint(', old)

    def test_root_match_never_adopts_naked_shim_or_substring(self):
        binary = Path("/native/cengine"); root = Path("/tmp/cengine-compat-owned/root")
        good = process(10, ("storage-lifecycle-qualification", "--root", str(root), "--assets", "/assets", "--case", "fresh"))
        self.assertTrue(harness._runtime_matches(good, binary, (root,)))
        for args in ((native.SHIM,), ("storage-lifecycle-qualification", "--other", str(root)),
                     ("storage-lifecycle-qualification", "--root", str(root) + "-other"),
                     ("storage-lifecycle-qualification", "--root", str(root), "--root", str(root))):
            self.assertFalse(harness._runtime_matches(process(11, args), binary, (root,)))

    def test_descendant_incarnation_not_naked_shim_is_signal_authority(self):
        driver = process(10, ("storage-lifecycle-qualification", "--root", "/owned/root"))
        shim = process(11, (native.SHIM,), parent=10)
        child = process(12, ("--lifecycle-v2",), parent=10, executable="/native/cengine-storage-controller")
        foreign = process(13, (native.SHIM,), parent=99)
        census = native.OwnedCensus(Path("/native/cengine"))
        census.observe(driver)
        table = {item.pid: item for item in (driver, shim, child, foreign)}
        with patch.object(native, "candidate_processes", return_value=list(table.values())), \
             patch.object(native, "_kernel_process", side_effect=table.get), \
             patch.object(native, "_signal_runtime_process") as send, \
             patch.object(native.time, "monotonic", side_effect=range(100)):
            census.refresh()
            self.assertEqual({item.pid for item in census.owned.values()}, {10, 11, 12})
            with self.assertRaises(RuntimeError): census.require_empty(Path("/owned/root"))
            census.contain()
            self.assertEqual({call.args[0].pid for call in send.call_args_list}, {10, 11, 12})
        reused = native.OwnedCensus(Path("/native/cengine")); reused.observe(driver)
        with patch.object(native, "candidate_processes", return_value=[shim]), \
             patch.object(native, "_kernel_process", return_value=process(10, driver.arguments[1:], birth=2)):
            reused.refresh()
        self.assertNotIn(native.incarnation(shim), reused.owned)

    def test_unobserved_orphan_blocks_release_without_acquiring_signal_rights(self):
        census = native.OwnedCensus(Path("/native/cengine"))
        foreign = process(13, (native.SHIM,))
        with patch.object(native, "candidate_processes", return_value=[foreign]), \
             patch.object(native, "_signal_runtime_process") as send:
            with self.assertRaises(RuntimeError): census.require_empty(Path("/owned/root"))
            census.contain()
            send.assert_not_called()

    def fixture(self, root, passed=True):
        work = root / "cengine-compat-fixture"; work.mkdir(mode=0o700)
        binary = root / "binary"; binary.touch()
        node = SimpleNamespace(report_setup=SimpleNamespace(passed=True), report_call=SimpleNamespace(passed=passed))
        request = SimpleNamespace(node=node, session=None)
        patches = [patch.object(native, "prerequisites", return_value=(binary, root)),
                   patch.object(native.platform, "system", return_value="Darwin"),
                   patch.object(native.platform, "machine", return_value="arm64"),
                   patch.object(sys.modules["conftest"], "pytest_sessionstart"),
                   patch.object(native, "tempfile", SimpleNamespace(mkdtemp=lambda **_: str(work)))]
        for item in patches:
            item.start(); self.addCleanup(item.stop)
        fixture = native.native_qualification.__wrapped__(request)
        value = next(fixture)
        self.assertTrue(harness.compatibility_root_retained(work))
        value.census = Mock()
        return fixture, value, node

    def test_launch_is_preretained_and_receipt_is_only_actual_stdout(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture, value, node = self.fixture(Path(temp))
            child = process(42, tuple(native.command(value.owner_binary, value.root, value.assets, "fresh")[1:]),
                            executable=str(value.owner_binary))
            def spawn(argv, **kwargs):
                self.assertIs(kwargs["env"], value.environment)
                self.assertTrue(harness.compatibility_root_retained(value.work))
                self.assertEqual(argv, native.command(value.owner_binary, value.root, value.assets, "fresh"))
                kwargs["stdout"].write(json.dumps(public_receipt("fresh")).encode())
                return SimpleNamespace(pid=42, poll=lambda: 0, returncode=0, wait=Mock())
            with patch.object(native.subprocess, "Popen", side_effect=spawn), \
                 patch.object(native, "_kernel_process", return_value=child):
                self.assertEqual(value.run("fresh"), public_receipt("fresh"))
            value.census.before_launch.assert_called_once()
            value.census.require_empty.assert_called_once_with(value.root)
            with self.assertRaises(StopIteration): next(fixture)
            self.assertTrue(hasattr(node, "_managed_root_cleanup"))

    def test_success_waits_for_census_and_all_teardown_reports_before_disposal(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture, value, node = self.fixture(Path(temp))
            value.succeeded = True
            with self.assertRaises(StopIteration): next(fixture)
            value.census.require_empty.assert_called_once_with(value.root)
            self.assertTrue(value.work.exists())
            self.assertTrue(harness.compatibility_root_retained(value.work))
            hook = conftest.pytest_runtest_makereport(node, SimpleNamespace(when="teardown"))
            next(hook)
            with self.assertRaises(StopIteration): hook.send(SimpleNamespace(get_result=lambda: SimpleNamespace(passed=True)))
            self.assertFalse(value.work.exists())

    def test_failure_preserves_root_before_containment_and_census(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture, value, node = self.fixture(Path(temp), passed=False)
            value.census.contain.side_effect = lambda: self.assertTrue(harness.compatibility_root_retained(value.work))
            with redirect_stdout(io.StringIO()), self.assertRaises(StopIteration): next(fixture)
            self.assertTrue(value._retain_root)
            self.assertTrue(value.work.exists())
            self.assertFalse(hasattr(node, "_managed_root_cleanup"))
            value.census.contain.assert_called_once()

    def test_preretention_failure_never_launches_or_censuses_runtime(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(native, "preretain_compatibility_root", side_effect=OSError("disk full")), \
             patch.object(native.subprocess, "Popen") as spawn, \
             patch.object(native, "candidate_processes") as census:
            with self.assertRaises(pytest.fail.Exception): self.fixture(Path(temp))
            spawn.assert_not_called()
            census.assert_not_called()

    def test_marker_failure_still_contains_and_stops_unobserved_direct_child(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture, value, node = self.fixture(Path(temp), passed=False)
            value.process = Mock()
            value.process.poll.return_value = None
            with patch.object(native, "retain_compatibility_root", side_effect=OSError("secret")), \
                 redirect_stdout(io.StringIO()), self.assertRaises(pytest.fail.Exception):
                next(fixture)
            value.census.contain.assert_called_once()
            value.process.terminate.assert_called_once()
            value.process.wait.assert_called_once_with(timeout=5)
            self.assertTrue(harness.compatibility_root_retained(value.work))
            self.assertFalse(hasattr(node, "_managed_root_cleanup"))

    def test_census_error_never_prevents_signaling_known_incarnations(self):
        census = native.OwnedCensus(Path("/native/cengine"))
        driver = process(10, ("storage-lifecycle-qualification", "--root", "/owned/root"))
        census.observe(driver)
        with patch.object(native, "candidate_processes", side_effect=RuntimeError("inspection")), \
             patch.object(native, "_signal_runtime_process") as send:
            with self.assertRaises(RuntimeError): census.contain()
            self.assertEqual([call.args for call in send.call_args_list],
                             [(driver, native.signal.SIGTERM), (driver, native.signal.SIGKILL)])

    def test_census_refresh_failure_without_owned_processes_fails_closed(self):
        census = native.OwnedCensus(Path("/native/cengine"))
        with patch.object(census, "refresh", side_effect=[[], RuntimeError("inspection"),
                                                        [], RuntimeError("inspection")]) as refresh, \
             patch.object(native, "_signal_runtime_process") as send:
            with self.assertRaisesRegex(RuntimeError, "native containment incomplete"):
                census.contain()
            self.assertEqual(refresh.call_count, 4)
            send.assert_not_called()

    def test_cleanup_failure_and_failed_late_finalizer_preserve(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture, value, node = self.fixture(Path(temp))
            value.succeeded = True
            value.census.require_empty.side_effect = RuntimeError("secret diagnostic")
            with redirect_stdout(io.StringIO()), self.assertRaises(pytest.fail.Exception) as error: next(fixture)
            self.assertNotIn("secret", str(error.exception))
            self.assertTrue(harness.compatibility_root_retained(value.work))
            self.assertFalse(hasattr(node, "_managed_root_cleanup"))
        with tempfile.TemporaryDirectory() as temp:
            fixture, value, node = self.fixture(Path(temp))
            value.succeeded = True
            with self.assertRaises(StopIteration): next(fixture)
            hook = conftest.pytest_runtest_makereport(node, SimpleNamespace(when="teardown")); next(hook)
            with self.assertRaises(StopIteration): hook.send(SimpleNamespace(get_result=lambda: SimpleNamespace(passed=False)))
            self.assertTrue(harness.compatibility_root_retained(value.work))


if __name__ == "__main__":
    unittest.main()
