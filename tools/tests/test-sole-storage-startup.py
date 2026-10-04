#!/usr/bin/env python3
"""No-helper startup regressions; default checks need no built CLI or native VM.

After building, exercise the real CLI separately:
  python3 tools/tests/test-sole-storage-startup.py --binary \
    .build/xcode-derived/Build/Products/Debug/cengine

This deliberately does not import the VM compatibility harness or install helpers.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
UNSUPPORTED_ERROR = "cengine: unsupported option: --shared-storage; storage is selected automatically\n"
UNSUPPORTED_FORMS = [("--shared-storage",), ("--shared-storage=",)] + [
    form for value in ("legacy", "managed", "lifecycle")
    for form in (("--shared-storage", value), (f"--shared-storage={value}",))
]


def isolated_environment(home: Path, work: Path) -> dict[str, str]:
    # Preserve ordinary process settings, but never inherit asset/helper overrides.
    env = {key: value for key, value in os.environ.items() if not key.startswith("CENGINE_")}
    env.update(HOME=str(home), CFFIXED_USER_HOME=str(home), TMPDIR=str(work))
    return env


def request(socket_path: Path, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("localhost", timeout=1)
    try:
        connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.sock.settimeout(1)
        connection.sock.connect(str(socket_path))
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def check_unsupported_selectors(command: list[str]) -> list[dict]:
    results = []
    for metadata in (False, True):
        for flags in UNSUPPORTED_FORMS:
            # /tmp keeps the UNIX socket below Darwin's short path limit.
            with tempfile.TemporaryDirectory(prefix="ce-selector-", dir="/tmp") as directory:
                work = Path(directory)
                home, root, endpoint = work / "home", work / "root", work / "api.sock"
                home.mkdir()
                args = command + ["daemon", "--root", str(root), "--socket", str(endpoint)]
                args += (["--metadata-only"] if metadata else []) + list(flags)
                result = subprocess.run(args, env=isolated_environment(home, work), cwd=work,
                                        capture_output=True, text=True, timeout=10)
                assert result.returncode == 1, (args, result.returncode, result.stderr)
                assert result.stderr == UNSUPPORTED_ERROR, (args, result.stderr)
                assert result.stdout == "", result.stdout
                assert not root.exists(), "rejected selector touched the requested store"
                assert list(home.iterdir()) == [], "rejected selector touched HOME"
                assert sorted(path.name for path in work.iterdir()) == ["home"], \
                    "rejected selector created a socket, lock, or other startup state"
                results.append(dict(flags=list(flags), metadata_only=metadata,
                                    returncode=result.returncode, stderr=result.stderr))
    return results


def check_metadata_only(command: list[str]) -> dict:
    with tempfile.TemporaryDirectory(prefix="ce-metadata-", dir="/tmp") as directory:
        work = Path(directory)
        home, root, endpoint = work / "home", work / "root", work / "api.sock"
        home.mkdir()
        args = command + ["daemon", "--metadata-only", "--root", str(root),
                          "--socket", str(endpoint)]
        # Files avoid a blocked child if a regression produces excessive logging.
        with (work / "stdout").open("w+") as stdout, (work / "stderr").open("w+") as stderr:
            process = subprocess.Popen(args, env=isolated_environment(home, work), cwd=work,
                                       stdout=stdout, stderr=stderr)
            try:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        stderr.seek(0)
                        raise AssertionError(f"metadata-only exited early: {stderr.read()}")
                    try:
                        ping_status, ping_body = request(endpoint, "/_ping")
                        break
                    except (OSError, http.client.HTTPException):
                        if time.monotonic() >= deadline:
                            raise AssertionError("metadata-only did not become ready")
                        time.sleep(0.05)
                assert (ping_status, ping_body) == (200, b"OK"), (ping_status, ping_body)
                info_status, info_body = request(endpoint, "/v1.44/info")
                assert info_status == 200, (info_status, info_body)
                info = json.loads(info_body)
                assert Path(info["DockerRootDir"]).resolve() == root.resolve(), info
                for key in ("Containers", "ContainersRunning", "Images"):
                    assert info[key] == 0, info
                assert not (home / "Library/Application Support/cengine/assets").exists()
                assert not (root / "infrastructure").exists(), "metadata-only created VM storage"
                process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=10)
                stderr.seek(0)
                diagnostic = stderr.read()
                assert code == 0, (code, diagnostic)
                return dict(ping_status=ping_status, ping=ping_body.decode(),
                            info_status=info_status, containers=info["Containers"],
                            images=info["Images"], sigterm_exit=code, stderr=diagnostic)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


class StartupSourceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "Sources/cengine/main.swift").read_text()
        cls.daemon = source.split("private static func daemon(", 1)[1].split(
            "private static func vmShim(", 1)[0]

    def test_unsupported_selector_is_rejected_before_paths_or_locks(self):
        before_paths = self.daemon.split("let paths = EnginePaths()", 1)[0]
        self.assertIn('$0 == "--shared-storage"', before_paths)
        self.assertIn('$0.hasPrefix("--shared-storage=")', before_paths)
        self.assertIn("throw EngineError(.badRequest", before_paths)
        self.assertNotIn("createDirectories", before_paths)
        self.assertNotIn("CanonicalDataStoreLock", before_paths)

    def test_metadata_branch_precedes_all_native_startup_dependencies(self):
        before, remainder = self.daemon.split("if metadataOnly {", 1)
        metadata, native = remainder.split("} else {", 1)
        self.assertEqual(metadata.strip(), "backend = MetadataOnlyBackend()")
        for dependency in ("ManagedStorageStartup", "ProductionStorageOwnerSetup",
                           "GuestAssetInstaller", "RawVirtualizationBackend", "NetworkHelper"):
            self.assertNotIn(dependency, before + metadata)
        self.assertIn("ManagedStorageStartup.lifecycleConfiguration()", native)
        self.assertIn("GuestAssetInstaller.diskBootstrapMetadata(", native)
        self.assertIn("backend = try await RawVirtualizationBackend(", native)
        self.assertIn("replacementTrigger = metadataOnly ? nil :", native)

    def test_normal_production_startup_checks_but_does_not_claim_owner(self):
        self.assertIn("if sharedStorage.policy.namespace == .production {\n"
                      "                try await ProductionStorageOwnerSetup.checkCurrentOwner()", self.daemon)
        self.assertEqual(self.daemon.count("ProductionStorageOwnerSetup."), 1)
        self.assertLess(self.daemon.index("checkCurrentOwner()"),
                        self.daemon.index("GuestAssetInstaller.diskBootstrapMetadata("))


# The fake only tests this runner's protocol, diagnostics, and process cleanup.
# It is not evidence that Swift startup works; --binary supplies that evidence.
FAKE = r'''
import json, os, pathlib, signal, socket, sys
args = sys.argv[1:]
if any(arg == "--shared-storage" or arg.startswith("--shared-storage=") for arg in args):
    sys.stderr.write("cengine: unsupported option: --shared-storage; storage is selected automatically\n")
    sys.exit(1)
assert "--metadata-only" in args
assert not any(key.startswith("CENGINE_") for key in os.environ)
root = pathlib.Path(args[args.index("--root") + 1])
root.mkdir()
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
with socket.socket(socket.AF_UNIX) as server:
    server.bind(args[args.index("--socket") + 1])
    server.listen()
    while True:
        client, _ = server.accept()
        with client:
            request = client.recv(8192)
            body = b"OK" if b" /_ping " in request else json.dumps(dict(
                DockerRootDir=str(root), Containers=0, ContainersRunning=0, Images=0)).encode()
            client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                           b"\r\nConnection: close\r\n\r\n" + body)
'''


class RunnerTests(unittest.TestCase):
    def test_fake_selector_matrix(self):
        results = check_unsupported_selectors([sys.executable, "-c", FAKE])
        self.assertEqual(len(results), 16)

    def test_fake_metadata_http_and_sigterm_join(self):
        result = check_metadata_only([sys.executable, "-c", FAKE])
        self.assertEqual(result["sigterm_exit"], 0)
        self.assertEqual(result["ping"], "OK")

    def test_wrong_selector_diagnostic_fails(self):
        with self.assertRaises(AssertionError):
            check_unsupported_selectors([sys.executable, "-c", "raise SystemExit(1)"])

    def test_early_exit_reports_stderr(self):
        with self.assertRaisesRegex(AssertionError, "startup failed"):
            check_metadata_only([sys.executable, "-c",
                                 "import sys; sys.stderr.write('startup failed'); sys.exit(1)"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="Run real CLI checks instead of source/runner unit tests")
    options = parser.parse_args()
    if options.binary:
        binary = options.binary.resolve(strict=True)
        report = dict(binary=str(binary), unsupported_selectors=check_unsupported_selectors([str(binary)]),
                      metadata_only=check_metadata_only([str(binary)]))
        print(json.dumps(report, indent=2))
    else:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
