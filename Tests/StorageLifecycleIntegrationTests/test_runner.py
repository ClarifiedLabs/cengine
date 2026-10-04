"""Small runner regressions; never run the lifecycle campaign."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("lifecycle_runner", Path(__file__).with_name("run.py"))
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class RunnerBoundaryTests(unittest.TestCase):
    def test_closed_go_environment(self):
        inherited = {key: "hostile" for key in ["GOOS", "GOARCH", "GOFLAGS", "GOTOOLCHAIN", "GOWORK", "GOENV",
                     "GOPROXY", "GOSUMDB", "GODEBUG", "CGO_CFLAGS", "CGO_ENABLED", "CC", "CXX", "CFLAGS", "CPATH"]}
        inherited["PATH"] = "/safe/path"
        env = runner.closed_go_environment(inherited)
        self.assertEqual(env, dict(PATH="/safe/path", GOFLAGS="-mod=vendor", GOWORK="off", GOENV="off",
                                  GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", CGO_ENABLED="0"))

    def test_completed_leader_is_never_signalled(self):
        for code in (0, 3):
            with self.subTest(code=code), mock.patch.object(runner.os, "killpg") as kill:
                args = [sys.executable, "-c", f"raise SystemExit({code})"]
                if code:
                    with self.assertRaises(subprocess.CalledProcessError):
                        runner.run(args, env=os.environ, timeout=5)
                else:
                    runner.run(args, env=os.environ, timeout=5)
                kill.assert_not_called()

    def test_timeout_kills_and_joins_owned_leader(self):
        with mock.patch.object(runner.os, "killpg", wraps=os.killpg) as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.run([sys.executable, "-c", "import time; time.sleep(30)"], env=os.environ, timeout=0.1)
            kill.assert_called_once()
            pid, sig = kill.call_args.args
            self.assertEqual(sig, signal.SIGKILL)
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)  # already joined, not a lingering zombie

    def test_exclusive_evidence_preserves_existing_file_and_symlink(self):
        with tempfile.TemporaryDirectory(prefix="cengine-evidence-test-") as path:
            directory = Path(path)
            target = directory / "target"
            runner.exclusive_json(target, {"original": True})
            original = target.read_bytes()
            alias = directory / "alias"
            alias.symlink_to(target)
            for entry in (target, alias):
                with self.subTest(entry=entry), self.assertRaises(FileExistsError):
                    runner.exclusive_json(entry, {"replacement": True})
                self.assertEqual(target.read_bytes(), original)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_bridge_build_tag_is_opt_in_and_missing_gate_fails(self):
        env = runner.closed_go_environment(os.environ)
        cwd = runner.ROOT / "Guest"
        ordinary = subprocess.check_output(["go", "list", "-f", '{{join .TestGoFiles "\\n"}}',
                                           "./internal/storageauthority"], cwd=cwd, env=env, timeout=30).decode()
        self.assertNotIn("lifecycle_bridge_test.go", ordinary)
        with tempfile.TemporaryDirectory(prefix="cengine-bridge-gate-") as path:
            worker = str(Path(path) / "worker")
            subprocess.run(["go", "test", "-tags=cengine_lifecycle_integration", "-c", "-o", worker,
                            "./internal/storageauthority"], cwd=cwd, env=env, timeout=120, check=True)
            for gate, selection, expected in [
                ("", "^TestLifecycleIntegrationBridge$", "requires explicit test-mode gate"),
                ("unsigned-test-only-v1", "TestLifecycleIntegrationBridge", "exact helper selection required"),
            ]:
                with self.subTest(gate=gate):
                    result = subprocess.run([worker, "-test.run=" + selection, "-test.timeout=5s"],
                                            env=dict(env, CENGINE_LIFECYCLE_BRIDGE=gate),
                                            capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stdout.decode())
                    self.assertNotIn("SKIP", result.stdout.decode())

    def test_manifest_includes_all_vendor_files_and_readme(self):
        hashes = runner.source_hashes()
        vendor = [path for path in (runner.ROOT / "Guest/vendor").rglob("*") if path.is_file()]
        self.assertGreater(len(vendor), 600)
        self.assertTrue(all(str(path.relative_to(runner.ROOT)) in hashes for path in vendor))
        self.assertIn("Tests/StorageLifecycleIntegrationTests/README.md", hashes)
        self.assertIn("Guest/internal/storageauthority/lifecycle_native_linux_test.go", hashes)


if __name__ == "__main__":
    unittest.main()
