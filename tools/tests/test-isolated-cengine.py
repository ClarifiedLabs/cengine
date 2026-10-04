#!/usr/bin/env python3
"""Engine-free runner tests: sandbox every executable and mock process ownership."""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "Tests" / "Compatibility"))
import harness  # noqa: E402


MOCK_EXECUTABLE = r'''
import json
import os
import pathlib
import shutil
import socket
import sys

name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]

def event(name, **values):
    with open(os.environ["MOCK_EVENTS"], "a") as stream:
        stream.write(json.dumps(dict(event=name, **values)) + "\n")

if name == "network-helper-fingerprint.sh":
    print("a" * 64)
elif name == "sign-compat-binary.sh":
    event("sign", args=args)
    sys.exit(int(os.environ.get("MOCK_SIGN_STATUS", "0")))
elif name == "helper":
    event("helper", args=args)
    sys.exit(int(os.environ.get("MOCK_HELPER_STATUS", "0")))
elif name == "cengine-real":
    root = pathlib.Path(args[args.index("--root") + 1])
    work = root.parent
    event("daemon", args=args, work=str(work), mode=work.stat().st_mode & 0o777,
          owner=(work / ".cengine-compat-owner").read_text().strip(),
          retained=(work / ".cengine-compat-retain").exists())
    print("SECRET_DAEMON_LOG", flush=True)
    (work / ".mock-alive").touch()
    if os.environ.get("MOCK_STARTUP_FAIL"):
        sys.exit(43)
    content = root / "content"
    content.mkdir(exist_ok=True)
    (content / "new").write_text("complete")
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(args[args.index("--socket") + 1])
elif name == "docker":
    event("docker", args=args, host=os.environ.get("DOCKER_HOST"))
    sys.exit(int(os.environ.get("MOCK_DOCKER_STATUS", "0")))
elif name == "command":
    if os.environ.get("MOCK_REPLACE_LOCK"):
        lock = pathlib.Path(os.environ["CENGINE_COMPAT_LOCK"])
        lock.rename(lock.with_name("original-lock"))
        lock.mkdir()
        (lock / "pid").write_text("unknown-owner\n")
    event("command", args=args, host=os.environ.get("DOCKER_HOST"),
          ambient=[key for key in ("DOCKER_API_VERSION", "DOCKER_CERT_PATH", "DOCKER_CONTEXT",
                                  "DOCKER_TLS", "DOCKER_TLS_VERIFY") if key in os.environ])
    sys.exit(int(os.environ.get("MOCK_COMMAND_STATUS", "0")))
elif name == "cp":
    assert args[0] == "-cR", args
    source, target = map(pathlib.Path, args[1:])
    direction = "out" if source.parent.name == "root" else "in"
    event("copy-" + direction)
    if direction == "out":
        assert not (source.parent.parent / ".mock-alive").exists(), "copied before exit"
    if os.environ.get("MOCK_CLONE_FAIL") == direction:
        target.mkdir()
        (target / "partial").write_text("incomplete")
        print("SECRET_COPY_ERROR", file=sys.stderr)
        sys.exit(37)
    shutil.copytree(source, target)
else:
    raise AssertionError(name)
'''

MOCK_HARNESS = r'''
from _real_harness import *
import _real_harness as real
import json
import os

def event(name, **values):
    with open(os.environ["MOCK_EVENTS"], "a") as stream:
        stream.write(json.dumps(dict(event=name, **values)) + "\n")

def scoped(binary, roots):
    assert binary == pathlib.Path(os.environ["MOCK_REAL_BINARY"])
    assert len(roots) == 1 and roots[0].name == "root", roots
    work = roots[0].parent
    assert work.parent == pathlib.Path(os.environ["TMPDIR"])
    assert real.compatibility_root_owned_by(work, binary)
    return work

def terminate_compatibility_runtime(binary, *, roots=()):
    work = scoped(binary, roots)
    event("terminate", roots=[str(root) for root in roots])
    if os.environ.get("MOCK_CLEANUP_FAIL") == "terminate":
        raise RuntimeError("SECRET_TERMINATE_ERROR")
    (work / ".mock-alive").unlink(missing_ok=True)
    return []

def compatibility_runtime_processes(binary, *, roots=()):
    scoped(binary, roots)
    event("census", roots=[str(root) for root in roots])
    if os.environ.get("MOCK_CLEANUP_FAIL") == "census":
        raise RuntimeError("SECRET_CENSUS_ERROR")
    return [object()] if os.environ.get("MOCK_CLEANUP_FAIL") == "unresolved" else []

def release_compatibility_root(work, binary, receipt):
    event("release")
    if os.environ.get("MOCK_CLEANUP_FAIL") == "release":
        return False
    return real.release_compatibility_root(work, binary, receipt)

def remove_compatibility_root(work, binary):
    event("remove")
    if os.environ.get("MOCK_CLEANUP_FAIL") == "remove":
        return False
    return real.remove_compatibility_root(work, binary)

def retain_compatibility_root(work, binary, *, reason):
    event("retain")
    return real.retain_compatibility_root(work, binary, reason=reason)
'''


class IsolatedRunnerTests(unittest.TestCase):
    def setUp(self):
        # Keep AF_UNIX paths below Darwin's short socket pathname limit.
        self.temporary = tempfile.TemporaryDirectory(prefix="ict-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.base = pathlib.Path(self.temporary.name).resolve()
        self.repo = self.base / "repo"
        self.scripts = self.repo / "Scripts"
        self.scripts.mkdir(parents=True)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.tmp = self.base / "tmp"
        self.tmp.mkdir()
        self.cache = self.base / "cache"
        (self.cache / "content").mkdir(parents=True)
        (self.cache / "content" / "old").write_text("valid-cache")
        self.events_path = self.base / "events"
        self.lock = self.base / "compat.lock"
        self.real_binary = self.bin / "cengine-real"
        self.binary = self.bin / "cengine"
        self.binary.symlink_to(self.real_binary)
        for name in ("cengine-real", "docker", "command", "helper", "cp"):
            self.executable(self.bin / name, MOCK_EXECUTABLE)
        for name in ("sign-compat-binary.sh", "network-helper-fingerprint.sh"):
            self.executable(self.scripts / name, MOCK_EXECUTABLE)
        (self.scripts / "compat-network-helper.sh").write_text(
            'compat_network_helper_require() { "$MOCK_HELPER" "$@"; }\n'
        )
        # Substitute clone and canonical path discovery only; never claim a host
        # lock in offline tests. Path-policy rejection has its own mocked tests.
        # The runner and ownership/retention helpers remain real.
        runner = (REPO_ROOT / "Scripts/run-isolated-cengine.sh").read_text()
        self.runner = self.scripts / "run-isolated-cengine.sh"
        self.runner.write_text(runner.replace("/bin/cp", str(self.bin / "cp")))
        compatibility = self.repo / "Tests" / "Compatibility"
        compatibility.mkdir(parents=True)
        shutil.copyfile(REPO_ROOT / "Tests/Compatibility/harness.py", compatibility / "_real_harness.py")
        (compatibility / "harness.py").write_text(MOCK_HARNESS)
        shutil.copyfile(REPO_ROOT / "Tests/Compatibility/helper_fixture_lifetime.py",
                        compatibility / "_real_lifetime.py")
        (compatibility / "helper_fixture_lifetime.py").write_text(
            'import os, sys\nfrom pathlib import Path\nfrom types import SimpleNamespace\nimport _real_lifetime as real\n'
            'real.harness._kernel_process = lambda pid: SimpleNamespace(identity=(1, 2, 3), pidversion=4)\n'
            'real.launcher_lock = lambda: Path(os.environ["MOCK_CANONICAL_LOCK"])\n'
            'real.main(sys.argv[1:])\n'
        )
        asset = self.base / "asset"
        asset.touch()
        # No inherited CENGINE configuration, especially no native binaries or locks.
        self.env = {
            "PATH": str(self.bin) + os.pathsep + os.defpath,
            "HOME": str(self.base), "TMPDIR": str(self.tmp),
            "CENGINE_BINARY": str(self.binary), "CENGINE_KERNEL": str(asset),
            "CENGINE_CONTAINER_INITRAMFS": str(asset), "CENGINE_STORAGE_INITRAMFS": str(asset),
            "CENGINE_ISOLATED_IMAGE_CACHE": str(self.cache),
            "CENGINE_COMPAT_LOCK": str(self.lock), "MOCK_CANONICAL_LOCK": str(self.lock),
            "MOCK_EVENTS": str(self.events_path), "MOCK_HELPER": str(self.bin / "helper"),
            "MOCK_REAL_BINARY": str(self.real_binary),
        }
        # The shell's python3 must use this interpreter, not require system Python.
        (self.bin / "python3").symlink_to(sys.executable)

    def executable(self, path, source):
        path.write_text(f"#!{sys.executable}\n" + source)
        path.chmod(0o700)

    def run_runner(self, **environment):
        result = subprocess.run(
            ["/bin/sh", str(self.runner), str(self.bin / "command"), "arg with spaces"],
            env=dict(self.env, **environment), capture_output=True, text=True, timeout=15,
        )
        self.assertNotIn("SECRET", result.stdout + result.stderr)
        self.events = [json.loads(line) for line in self.events_path.read_text().splitlines()] \
            if self.events_path.exists() else []
        self.names = [event["event"] for event in self.events]
        return result

    def retained(self):
        roots = list(self.tmp.glob("cengine-compat-tool.*"))
        self.assertEqual(len(roots), 1)
        work = roots[0]
        self.assertEqual(work.stat().st_mode & 0o777, 0o700)
        self.assertTrue(harness.compatibility_root_owned_by(work, self.real_binary))
        self.assertTrue(harness.compatibility_root_retained(work))
        # A future general reset must refuse to delete failed evidence.
        self.assertFalse(harness.remove_compatibility_root(work, self.real_binary))
        self.assertFalse(self.lock.exists())
        return work

    def assert_cache_unchanged(self):
        self.assertEqual([path.name for path in (self.cache / "content").iterdir()], ["old"])
        self.assertEqual((self.cache / "content" / "old").read_text(), "valid-cache")

    def test_success_scoped_cleanup_then_complete_cache_then_owned_removal(self):
        result = self.run_runner(DOCKER_CONTEXT="ambient", DOCKER_TLS="1", DOCKER_API_VERSION="1.20")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.names, ["sign", "helper", "copy-in", "daemon", "docker", "command",
                                      "terminate", "census", "copy-out", "release", "remove"])
        daemon = next(event for event in self.events if event["event"] == "daemon")
        self.assertEqual(daemon["owner"], str(self.real_binary))
        self.assertEqual(daemon["mode"], 0o700)
        self.assertTrue(daemon["retained"])
        self.assertFalse(pathlib.Path(daemon["work"]).exists())
        command = next(event for event in self.events if event["event"] == "command")
        self.assertEqual(command["host"], f'unix://{daemon["work"]}/docker.sock')
        self.assertEqual(command["ambient"], [])
        self.assertEqual(command["args"], ["arg with spaces"])
        self.assertEqual((self.cache / "content" / "new").read_text(), "complete")
        self.assertEqual((self.cache / "content" / "old").read_text(), "valid-cache")
        self.assertEqual(list(self.cache.glob(".content-*")), [])
        self.assertFalse(self.lock.exists())

    def test_command_failure_preserves_original_status_and_evidence(self):
        result = self.run_runner(MOCK_COMMAND_STATUS="42")
        self.assertEqual(result.returncode, 42)
        work = self.retained()
        self.assertIn(str(work), result.stderr)
        self.assertIn("SECRET_DAEMON_LOG", (work / "daemon.log").read_text())
        self.assertNotIn("copy-out", self.names)
        self.assert_cache_unchanged()

    def test_startup_failure_retains_evidence_without_running_command(self):
        result = self.run_runner(MOCK_STARTUP_FAIL="1")
        self.assertEqual(result.returncode, 1)
        self.retained()
        self.assertNotIn("command", self.names)
        self.assertIn("terminate", self.names)
        self.assertIn("census", self.names)
        self.assertNotIn("copy-out", self.names)
        self.assert_cache_unchanged()

    def test_cleanup_exceptions_and_unresolved_processes_fail_closed(self):
        for fault in ("terminate", "census", "unresolved"):
            with self.subTest(fault=fault):
                # Each subcase needs its own retained work and event stream.
                with IsolatedRunnerTests("runTest") as case:
                    result = case.run_runner(MOCK_CLEANUP_FAIL=fault)
                    self.assertEqual(result.returncode, 1)
                    case.retained()
                    case.assert_cache_unchanged()
                    self.assertNotIn("copy-out", case.names)
                    self.assertNotIn("remove", case.names)

    def test_cleanup_failure_does_not_replace_command_status(self):
        result = self.run_runner(MOCK_COMMAND_STATUS="42", MOCK_CLEANUP_FAIL="terminate")
        self.assertEqual(result.returncode, 42)
        self.retained()
        self.assert_cache_unchanged()

    def test_developer_signing_and_unconditional_helper_guard(self):
        identity = "Developer ID Application: Example (ABCDEFGHIJ)"
        result = self.run_runner(
            CENGINE_DEVELOPER_ID_APPLICATION=identity, MOCK_HELPER_STATUS="29",
            CENGINE_NETWORK_HELPER_SERVICE_NAME="inherited",
            CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE="inherited-token",
            CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT="b" * 64,
        )
        self.assertEqual(result.returncode, 29)
        self.assertEqual(self.events[0], dict(event="sign", args=["--sign", identity, str(self.real_binary)]))
        self.assertEqual(self.events[1], dict(event="helper", args=[str(self.real_binary), "a" * 64]))
        self.assertNotIn("daemon", self.names)
        self.retained()

    def test_ad_hoc_signing_route(self):
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events[0], dict(event="sign", args=[str(self.real_binary)]))

    def test_existing_locks_are_never_stolen(self):
        for owner in (str(os.getpid()), "999999999", "unknown", None):
            with self.subTest(owner=owner):
                self.lock.mkdir()
                if owner is not None:
                    (self.lock / "pid").write_text(owner)
                sentinel = self.lock / "evidence"
                sentinel.write_text("keep")
                result = self.run_runner()
                self.assertEqual(result.returncode, 2)
                self.assertEqual(sentinel.read_text(), "keep")
                self.assertEqual(self.events, [])
                self.assertEqual(list(self.tmp.glob("cengine-compat-tool.*")), [])
                shutil.rmtree(self.lock)

    def test_replaced_lock_is_not_removed_and_evidence_survives(self):
        result = self.run_runner(MOCK_REPLACE_LOCK="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual((self.lock / "pid").read_text(), "unknown-owner\n")
        work, = self.tmp.glob("cengine-compat-tool.*")
        self.assertTrue(harness.compatibility_root_retained(work))
        self.assertNotIn("terminate", self.names)
        self.assertNotIn("census", self.names)
        self.assertNotIn("copy-out", self.names)
        self.assertNotIn("remove", self.names)
        self.assert_cache_unchanged()

    def test_compatibility_runner_cannot_steal_before_pid_publication(self):
        # Pause the creating runner between mkdir and PID publication. Run the
        # actual sibling acquisition function, not its reset/build/VM commands.
        source = (REPO_ROOT / "Scripts/run-compat-tests.sh").read_text()
        acquire = source.split("acquire_lock() {", 1)[1].split("\n}\n", 1)[0]
        ordinary = "acquire_lock() {" + acquire + "\n}\nacquire_lock"
        matrix_source = (REPO_ROOT / "tools/managed-prepare-matrix.sh").read_text()
        matrix = 'if ! mkdir "$CENGINE_COMPAT_LOCK"' + matrix_source.split(
            'if ! mkdir "$CENGINE_COMPAT_LOCK"', 1)[1].split("\ncleanup() {", 1)[0]
        self.lock.mkdir()
        before = self.lock.stat()
        for runner in (ordinary, matrix):
            for owner in (None, "unknown", "999999999"):
                with self.subTest(runner=runner.splitlines()[0], owner=owner):
                    (self.lock / "pid").unlink(missing_ok=True)
                    if owner is not None:
                        (self.lock / "pid").write_text(owner + "\n")
                    result = subprocess.run(
                        ["/bin/sh", "-c", "set -eu\n" + runner],
                        env={**self.env, "LOCK": str(self.lock)}, capture_output=True, timeout=5,
                    )
                    self.assertEqual(result.returncode, 2)
                    after = self.lock.stat()
                    self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
                    if owner is None:
                        self.assertFalse((self.lock / "pid").exists())
                    else:
                        self.assertEqual((self.lock / "pid").read_text(), owner + "\n")

    def test_suite_and_matrix_cleanup_require_original_claim_before_actions(self):
        for path in ("Scripts/run-compat-tests.sh", "tools/managed-prepare-matrix.sh"):
            source = (REPO_ROOT / path).read_text()
            cleanup = "cleanup() {" + source.split("cleanup() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
            for fault in ("none", "receipt", "owner", "pid", "directory", "after-reset"):
                with self.subTest(path=path, fault=fault), IsolatedRunnerTests("runTest") as case:
                    # The real cleanup function and claim codec run in a sandbox;
                    # reset is only an event recorder, never process inspection/signalling.
                    (case.scripts / "reset-compat-runtime.py").write_text('''
import json, os
from pathlib import Path
with open(os.environ["MOCK_EVENTS"], "a") as stream:
    stream.write(json.dumps({"event": "reset"}) + "\\n")
if os.environ["FAULT"] == "after-reset":
    lock = Path(os.environ["CENGINE_COMPAT_LOCK"])
    lock.rename(lock.with_name("previous-claim"))
    lock.mkdir(mode=0o700)
    (lock / "pid").write_text(os.environ["CENGINE_COMPAT_OWNER_PID"] + "\\n")
    (lock / "pid").chmod(0o600)
    (lock / "client-state").mkdir()
    (lock / "client-state/evidence").write_text("keep")
''')
                    script = '''
set -eu
umask 077
LOCK=$CENGINE_COMPAT_LOCK
mkdir "$LOCK"
printf '%s\\n' "$$" > "$LOCK/pid"
CENGINE_COMPAT_OWNER_PID=$$
export CENGINE_COMPAT_OWNER_PID
CENGINE_COMPAT_CLAIM=$(python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py" pin-claim "$$")
export CENGINE_COMPAT_CLAIM
CENGINE_COMPAT_CLIENT_STATE_ROOT="$LOCK/client-state"
mkdir "$CENGINE_COMPAT_CLIENT_STATE_ROOT"
printf keep > "$CENGINE_COMPAT_CLIENT_STATE_ROOT/evidence"
# Matrix has no client-state subtree; retain test evidence outside its claim.
if [ "$RUNNER" = matrix ] && [ "$FAULT" = none ]; then
    mv "$CENGINE_COMPAT_CLIENT_STATE_ROOT" "$ROOT/client-evidence"
fi
case "$FAULT" in
    receipt) CENGINE_COMPAT_CLAIM='[]'; export CENGINE_COMPAT_CLAIM ;;
    owner) CENGINE_COMPAT_OWNER_PID=1; export CENGINE_COMPAT_OWNER_PID ;;
    pid) mv "$LOCK/pid" "$LOCK/old-pid"; printf '%s\\n' "$$" > "$LOCK/pid" ;;
    directory)
        mv "$LOCK" "$ROOT/previous-claim"
        mkdir "$LOCK" "$LOCK/client-state"
        printf '%s\\n' "$$" > "$LOCK/pid"
        printf keep > "$LOCK/client-state/evidence"
        ;;
esac
stage() { :; }
reset_runtime() { python3 "$ROOT/Scripts/reset-compat-runtime.py" --binary "$BINARY"; }
RESET=reset_runtime
''' + cleanup + "\ncleanup\n"
                    result = subprocess.run(["/bin/sh", "-c", script],
                        env={**case.env, "ROOT": str(case.repo), "BINARY": str(case.binary),
                             "FAULT": fault, "RUNNER": "matrix" if path.startswith("tools/") else "suite"},
                        text=True, capture_output=True, timeout=10)
                    events = case.events_path.read_text().splitlines() if case.events_path.exists() else []
                    if fault == "none":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertFalse(case.lock.exists())
                        self.assertEqual(len(events), 1)
                    else:
                        self.assertNotEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(len(events), int(fault == "after-reset"))
                        self.assertEqual((case.lock / "client-state/evidence").read_text(), "keep")
                        self.assertTrue((case.lock / "pid").is_file())

    def test_default_lock_uses_canonical_claim_without_override(self):
        del self.env["CENGINE_COMPAT_LOCK"]
        self.lock.mkdir()
        result = self.run_runner()
        self.assertEqual(result.returncode, 2)
        self.assertTrue(self.lock.is_dir())
        self.assertEqual(self.events, [])

    def test_cache_export_clone_failure_preserves_valid_cache_and_work(self):
        result = self.run_runner(MOCK_CLONE_FAIL="out")
        self.assertEqual(result.returncode, 1)
        self.retained()
        self.assert_cache_unchanged()
        self.assertLess(self.names.index("census"), self.names.index("copy-out"))
        self.assertNotIn("release", self.names)
        self.assertEqual(len(list(self.cache.glob(".content-*/content/partial"))), 1)

    def test_cache_import_clone_failure_retains_partial_work(self):
        result = self.run_runner(MOCK_CLONE_FAIL="in")
        self.assertEqual(result.returncode, 37)
        work = self.retained()
        self.assertTrue((work / "root/content/partial").exists())
        self.assertNotIn("daemon", self.names)
        self.assertNotIn("copy-out", self.names)
        self.assert_cache_unchanged()

    def test_owned_removal_failure_retains_work_and_marker(self):
        result = self.run_runner(MOCK_CLEANUP_FAIL="remove")
        self.assertEqual(result.returncode, 1)
        self.retained()
        self.assertIn("retain", self.names)

    def __enter__(self):
        self.setUp()
        return self

    def __exit__(self, *args):
        self.doCleanups()


if __name__ == "__main__":
    unittest.main()
