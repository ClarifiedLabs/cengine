"""RTM-071: completed host rewrites must not retain a bind's cached EOF.

This is deliberately not an atomic-snapshot or polling-watcher test: no guest
read overlaps a host write. Diagnostic rereads never turn a failed read into a
pass. Directory/file, writable/read-only and cat/splice/mmap cases share one ID.
Each reader has independent shares: cat must not repair a later mmap/splice open.

Engine-free checks (no daemon): python test_bind_growth.py -v
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from docker.types import Mount
import pytest

from test_volume_discovery import ALPINE, _exec
from volume_probe import tar_bytes


SEED = b"before-up"
REWRITES = (
    ("compose-growth", b"changed-content-not-definition", False),
    ("page-growth", b"p" * 4097, False),
    ("same-size-rewrite", bytes(range(256)) * 16 + b"\x00", False),
    ("shrink", b"end", False),
    ("empty", b"", False),
    ("regrow", b"r" * 8193, False),
    ("fsync-seed", SEED, True),
    ("fsync-growth", b"changed-content-not-definition", True),
)


def _build_reopen_probe(directory: Path, architecture="arm64") -> Path:
    binary = directory / ("bind-reopen-" + architecture)
    subprocess.run(
        ["go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary),
         str(Path(__file__).parent / "fixtures" / "bind-reopen.go")],
        env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux",
             "GOARCH": architecture, "GOWORK": "off"},
        check=True, capture_output=True, timeout=120,
    )
    return binary


@pytest.fixture
def bind_reopen_archive(tmp_path):
    binary = _build_reopen_probe(tmp_path)
    return tar_bytes([("bind-reopen", binary.read_bytes(), 0o755)])


def _read_reopened(container, reader, path, expected):
    if reader == "cat":
        return _exec(container, "cat", path)
    # This is the expected payload length, NEVER a guest stat-derived length.
    return _exec(container, "/tmp/bind-reopen", reader, path, str(len(expected)))


def _summary(data: bytes) -> dict:
    return {
        "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "prefix_hex": data[:64].hex(), "suffix_hex": data[-64:].hex(),
    }


@pytest.mark.compat("RTM-071")
def test_completed_host_bind_rewrites_do_not_retain_cached_eof(
    client, tmp_path, bind_reopen_archive,
):
    owner = "bind-growth-" + uuid.uuid4().hex
    evidence = Path(__file__).resolve().parents[2] / ".build/volume-hunt" / owner
    evidence.mkdir(parents=True)
    print(f"bind growth evidence: {evidence}")
    events, cases, mounts = [], [], []

    def record(phase, **values):
        events.append({"phase": phase, **values})
        (evidence / "evidence.json").write_text(json.dumps(events, indent=2) + "\n")

    # Independent files/shares avoid one view refreshing another view's inode.
    for reader, kind, read_only in itertools.product(
        ("cat", "splice", "mmap"), ("directory", "file"), (False, True),
    ):
        case = f"{kind}-{'ro' if read_only else 'rw'}"
        if reader != "cat":
            case += "-" + reader
        directory = tmp_path / case
        directory.mkdir()
        host_file = directory / "sentinel"
        host_file.write_bytes(SEED)
        target = "/" + case
        source = directory if kind == "directory" else host_file
        guest_file = target + "/sentinel" if kind == "directory" else target
        mounts.append(Mount(
            target=target, source=str(source), type="bind", read_only=read_only,
        ))
        cases.append((case, host_file, guest_file, target, read_only, reader))

    container = client.containers.create(
        ALPINE, ["sleep", "600"], name=owner, network_mode="none",
        labels={"dev.cengine.compat": "true"}, mounts=mounts,
    )
    try:
        container.start()
        # Install only on the image root, never on any of the measured binds.
        assert container.put_archive("/tmp", bind_reopen_archive)
        mountinfo = _exec(container, "cat", "/proc/self/mountinfo").decode()
        record("backend", container=container.id, mountinfo=mountinfo,
               kernel=_exec(container, "uname", "-r").decode(),
               policy_note="host_close_to_open is not currently exposed by mountinfo; "
                           "absence does not prove the policy is disabled")
        for case, host_file, guest_file, target, read_only, reader in cases:
            lines = [line for line in mountinfo.splitlines() if line.split()[4] == target]
            assert len(lines) == 1 and " - virtiofs " in lines[0], lines
            assert ("ro" if read_only else "rw") in lines[0].split()[5].split(","), lines
            record("mount", case=case, reader=reader, mountinfo=lines[0],
                   host_close_to_open_visible="host_close_to_open" in lines[0])
            identity = host_file.stat().st_ino
            # Prime data AND size with a closed guest read, just as CMP-043 does.
            assert _read_reopened(container, reader, guest_file, SEED) == SEED
            previous = SEED
            for phase, expected, synchronize in REWRITES:
                # O_TRUNC preserves the inode. Close completes before exec is
                # requested; default phases intentionally match Path.write_text.
                with host_file.open("wb") as stream:
                    assert stream.write(expected) == len(expected)
                    if synchronize:
                        stream.flush()
                        os.fsync(stream.fileno())
                # No guest stat, cache flush, retry, Compose call or delay before
                # the measured read. In particular, do not repair EOF via statx.
                try:
                    actual = _read_reopened(container, reader, guest_file, expected)
                except Exception as error:
                    # mmap SIGBUS, splice errors and deadlines remain failures.
                    record("read-error", case=case, reader=reader, operation=phase,
                           expected=_summary(expected), error=repr(error))
                    raise
                metadata = host_file.stat()
                assert metadata.st_ino == identity
                assert host_file.read_bytes() == expected
                observation = {
                    "case": case, "reader": reader, "operation": phase,
                    "fsync": synchronize,
                    "previous_size": len(previous), "host_inode": identity,
                    "host_size": metadata.st_size, "host_mtime_ns": metadata.st_mtime_ns,
                    "expected": _summary(expected), "first_read": _summary(actual),
                }
                if actual != expected:
                    observation["failed_read_hex"] = actual.hex()
                # Preserve the measured result even if a diagnostic exec fails.
                record("read", **observation)
                if actual != expected:
                    # These happen only AFTER the failed first read. They help
                    # distinguish stale size from stale data without excusing it.
                    try:
                        observation["guest_stat_after_read"] = _exec(
                            container, "stat", "-c", "%s %i %Y", guest_file,
                        ).decode()
                        observation["diagnostic_reread"] = _summary(
                            _exec(container, "cat", guest_file),
                        )
                    except Exception as error:
                        observation["diagnostic_error"] = repr(error)
                    record("diagnostics", **observation)
                    # Keep the first minimal mismatch authoritative. Continuing
                    # into regrowth after stale EOF can wedge VirtioFS and replace
                    # this useful failure with an unrelated control-socket timeout.
                    pytest.fail(json.dumps(observation, indent=2))
                previous = expected
    finally:
        primary_failure = sys.exc_info()[0] is not None
        try:
            container.remove(force=True)
        except Exception as error:
            # A wedged control socket must not replace the strict read failure.
            # Retain cleanup evidence, but still fail a successful test if its
            # cleanup fails. The fixture owns final daemon teardown either way.
            try:
                record("cleanup-error", error=repr(error))
            except Exception:
                print(f"bind growth cleanup failed: {error!r}", file=sys.stderr)
            if not primary_failure:
                raise


if __name__ == "__main__":
    # Keep engine-free checks out of pytest collection: RTM-071 remains one ID.
    import platform
    import struct
    import tempfile
    from types import SimpleNamespace
    import unittest
    from unittest.mock import Mock, patch

    native_only = unittest.skipUnless(
        sys.platform == "linux" and platform.machine() in ("aarch64", "arm64", "x86_64"),
        "native splice/mmap execution requires Linux arm64/amd64",
    )

    class ProbeTests(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.temporary = tempfile.TemporaryDirectory(prefix="bind-reopen-check-")
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.directory = Path(cls.temporary.name)
            cls.binaries = {
                arch: _build_reopen_probe(cls.directory, arch)
                for arch in ("arm64", "amd64")
            }

        def test_static_linux_cross_compile(self):
            for arch, machine in (("arm64", 183), ("amd64", 62)):
                with self.subTest(architecture=arch):
                    elf = self.binaries[arch].read_bytes()
                    self.assertEqual(elf[:6], b"\x7fELF\x02\x01")
                    self.assertEqual(struct.unpack_from("<H", elf, 18)[0], machine)
                    offset = struct.unpack_from("<Q", elf, 32)[0]
                    size, count = struct.unpack_from("<HH", elf, 54)
                    kinds = [struct.unpack_from("<I", elf, offset + size * i)[0]
                             for i in range(count)]
                    self.assertNotIn(3, kinds)  # PT_INTERP: no dynamic loader.

        def native(self, mode, path, length, *, timeout=5):
            arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}.get(
                platform.machine(),
            )
            if sys.platform != "linux" or arch is None:
                self.skipTest("native splice/mmap execution requires Linux arm64/amd64")
            return subprocess.run(
                [str(self.binaries[arch]), mode, str(path), str(length)],
                capture_output=True, timeout=timeout,
            )

        @native_only
        def test_native_reopen_raw_bytes_and_pipe_capacity(self):
            path = self.directory / "payload"
            # Larger than normal pipe capacity: a produce-all-then-drain probe
            # would hang. Every invocation opens again after write_bytes closes.
            for mode in ("splice", "mmap"):
                for payload in (SEED, *(data for _, data, _ in REWRITES),
                                bytes(range(256)) * 1024 + b"\x00"):
                    with self.subTest(mode=mode, length=len(payload)):
                        path.write_bytes(payload)
                        result = self.native(mode, path, len(payload))
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, payload)
                        self.assertEqual(result.stderr, b"")

        @native_only
        def test_native_does_not_clip_extra_bytes_to_expected_length(self):
            path = self.directory / "extra"
            path.write_bytes(b"abc")
            for mode in ("splice", "mmap"):
                result = self.native(mode, path, 2)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"abc")
                result = self.native(mode, path, 0)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotEqual(result.stdout, b"")

        @native_only
        def test_native_argument_bounds_and_failure_output(self):
            for mode, length in (("unknown", 1), ("mmap", -1),
                                 ("splice", 1024 * 1024 + 1), ("mmap", "bad"),
                                 ("splice", 1)):
                result = self.native(mode, self.directory / "missing", length)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertTrue(result.stderr)

        @native_only
        def test_native_watchdog_bounds_blocked_open(self):
            fifo = self.directory / "blocked-open"
            if sys.platform != "linux":
                self.skipTest("native watchdog execution requires Linux")
            os.mkfifo(fifo)
            try:
                result = self.native("splice", fifo, 1, timeout=25)
                self.assertEqual(result.returncode, 124, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"deadline exceeded", result.stderr)
            finally:
                fifo.unlink()

        def test_same_size_is_distinct_and_probe_arguments_are_expected_length(self):
            index = [phase for phase, _, _ in REWRITES].index("same-size-rewrite")
            before, after = REWRITES[index - 1][1], REWRITES[index][1]
            self.assertEqual(len(before), len(after))
            self.assertNotEqual(before, after)
            container = object()
            for reader in ("cat", "splice", "mmap"):
                with patch(__name__ + "._exec", return_value=b"raw") as execute:
                    self.assertEqual(_read_reopened(container, reader, "/input", after), b"raw")
                    command = ("cat", "/input") if reader == "cat" else (
                        "/tmp/bind-reopen", reader, "/input", str(len(after)),
                    )
                    execute.assert_called_once_with(container, *command)

        def test_matrix_cleanup_and_first_mismatch_remains_authoritative(self):
            # Fake only the engine boundary. Exercise host writes, strict first
            # reads, failure diagnostics and finally cleanup without a daemon.
            for failure, cleanup_failure in (
                (None, False), ("start", False), ("upload", False),
                ("read", False), ("mismatch", False),
                (None, True), ("read", True), ("mismatch", True),
            ):
                with self.subTest(failure=failure, cleanup=cleanup_failure), tempfile.TemporaryDirectory() as root:
                    directory = Path(root)
                    container = SimpleNamespace(
                        id="fake", start=Mock(), put_archive=Mock(return_value=True),
                        remove=Mock(),
                    )
                    if cleanup_failure:
                        container.remove.side_effect = TimeoutError("cleanup")
                    if failure == "start":
                        container.start.side_effect = TimeoutError("start")
                    if failure == "upload":
                        container.put_archive.side_effect = TimeoutError("upload")
                    files, counts, mount_lines = {}, {}, []

                    def create(image, command, **options):
                        self.assertEqual(image, ALPINE)
                        for mount in options["mounts"]:
                            source, target = Path(mount["Source"]), mount["Target"]
                            guest = target + "/sentinel" if source.is_dir() else target
                            files[guest] = source / "sentinel" if source.is_dir() else source
                            access = "ro" if mount["ReadOnly"] else "rw"
                            mount_lines.append(f"1 0 0:1 / {target} {access} - virtiofs tag rw")
                        return container

                    def execute(_, *command):
                        if command == ("cat", "/proc/self/mountinfo"):
                            return "\n".join(mount_lines).encode()
                        if command == ("uname", "-r"):
                            return b"engine-free-kernel\n"
                        if command[0] == "stat":
                            self.assertEqual(failure, "mismatch")
                            self.assertGreaterEqual(counts[command[-1]], 2)
                            return b"diagnostic only\n"
                        guest = command[1] if command[0] == "cat" else command[2]
                        payload = files[guest].read_bytes()
                        counts[guest] = counts.get(guest, 0) + 1
                        if counts[guest] == 2:
                            if failure == "read":
                                raise TimeoutError("read")
                            if failure == "mismatch":
                                return payload[:len(SEED)]
                        if command[0] != "cat":
                            self.assertEqual(command[3], str(len(payload)))
                        return payload

                    client = SimpleNamespace(containers=SimpleNamespace(create=create))
                    with patch(__name__ + "._exec", side_effect=execute), patch(
                        __name__ + ".__file__", str(directory / "Tests/Compatibility/test_bind_growth.py"),
                    ):
                        if failure or cleanup_failure:
                            error = pytest.fail.Exception if failure == "mismatch" else TimeoutError
                            with self.assertRaises(error) as caught:
                                test_completed_host_bind_rewrites_do_not_retain_cached_eof(
                                    client, directory, b"archive",
                                )
                            if failure != "mismatch":
                                self.assertEqual(str(caught.exception), failure or "cleanup")
                        else:
                            test_completed_host_bind_rewrites_do_not_retain_cached_eof(
                                client, directory, b"archive",
                            )
                            self.assertEqual(len(files), 12)
                            self.assertEqual(set(counts.values()), {1 + len(REWRITES)})
                    container.remove.assert_called_once_with(force=True)
                    if failure != "start":
                        container.put_archive.assert_called_once_with("/tmp", b"archive")

    unittest.main()
