#!/usr/bin/env python3
"""Engine-free corpus integrity, build-context, and exec transport regressions."""
from __future__ import annotations

from contextlib import contextmanager

import hashlib
import io
import json
import os
import re
from pathlib import Path
import socket
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from urllib3.exceptions import ReadTimeoutError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import test_volume_corpus as corpus
import test_volume_namespace as namespace

builder = corpus._builder


@contextmanager
def local_http_peer(responses):
    """Engine-free real Unix HTTP peer; joins before its owned socket cleanup."""
    with tempfile.TemporaryDirectory(prefix='corpus-http-') as directory:
        path = str(Path(directory) / 'socket')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(2)
        listener.settimeout(0.1)
        stopped = threading.Event()
        accepted, errors = [], []
        def serve():
            try:
                for chunks in responses:
                    while not stopped.is_set():
                        try:
                            connection, _ = listener.accept()
                            break
                        except socket.timeout:
                            continue
                    else:
                        return
                    accepted.append(connection)
                    with connection:
                        connection.settimeout(1)
                        request = bytearray()
                        while b'\r\n\r\n' not in request:
                            data = connection.recv(1024)
                            if not data:
                                break
                            request.extend(data)
                        try:
                            for chunk in chunks:
                                if stopped.wait(0.02):
                                    return
                                connection.sendall(chunk)
                        except (BrokenPipeError, ConnectionResetError):
                            pass  # Expected when the client's absolute deadline fires.
            except BaseException as error:
                if not stopped.is_set():
                    errors.append(error)
        worker = threading.Thread(target=serve, name='corpus-local-http-peer')
        worker.start()
        try:
            yield 'unix://' + path, accepted
        finally:
            stopped.set()
            for connection in accepted:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            listener.close()
            worker.join(2)
            if worker.is_alive():
                raise AssertionError('local HTTP peer failed to join')
            if errors:
                raise errors[0]


class OracleTests(unittest.TestCase):
    def test_reference_uses_fixture_api_not_cengine_maximum(self):
        host = 'unix:///private/corpus-reference.sock'
        daemon = SimpleNamespace(socket=Path('/private/corpus-cengine.sock'))
        client = SimpleNamespace(api=SimpleNamespace(_version='1.55'))
        fixture = (b'archive', {})
        with patch.dict(os.environ, {'DOCKER_REFERENCE_HOST': host}), \
                patch.object(corpus.docker, 'DockerClient') as sdk, \
                patch.object(corpus, 'api_deadline'), \
                patch.object(corpus, '_artifacts', return_value=Path('/unused')), \
                patch.object(corpus, '_execute_corpus', return_value=[{'passed': True}]) as execute:
            reference = sdk.return_value
            reference.version.return_value = {
                'Platform': {'Name': 'Docker Engine'}, 'Os': 'linux', 'Arch': 'arm64',
                'ApiVersion': '1.53', 'MinAPIVersion': '1.44',
            }
            corpus.test_bounded_upstream_filesystem_corpus_matches_reference(daemon, client, fixture)
            sdk.assert_called_once_with(base_url=host, timeout=45, version='1.45')
            self.assertEqual([call.args[:3] for call in execute.call_args_list], [
                (reference, fixture, 'block'), (client, fixture, 'block'),
                (reference, fixture, 'shared'), (client, fixture, 'shared'),
            ])
            reference.close.assert_called_once_with()


class InputTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ))
        os.environ.pop("CENGINE_CORPUS_FIXTURE", None)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sources = {name: (name + "\n").encode() for name in builder.REQUIRED_SOURCES}
        for name, data in self.sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.manifest = {"version": 1, "sha256": {
            name: hashlib.sha256(data).hexdigest() for name, data in self.sources.items()}}
        self.save_manifest()

    def save_manifest(self):
        (self.root / "provenance.json").write_text(json.dumps(self.manifest))

    def test_current_manifest(self):
        provenance, sources = builder.validated_sources(corpus.SOURCE)
        self.assertEqual(set(provenance["sha256"]), set(sources))
        self.assertEqual(len(corpus.PJD_CASES), provenance["bounds"]["pjdfstest_invocations"])
        self.assertEqual(len(corpus.PEER_CASES), provenance["bounds"]["shared_peer_invocations"])

    def test_fixed_fsx_calibration_preserves_other_limits(self):
        provenance, _ = builder.validated_sources(corpus.SOURCE)
        bounds = provenance['bounds']
        self.assertEqual((bounds['fsx_child_wall_seconds'], bounds['fsx_host_exec_seconds']), (150, 165))
        self.assertEqual((bounds['child_wall_seconds'], bounds['host_exec_seconds']), (30, 45))
        self.assertEqual(corpus._exec_fsx.__kwdefaults__['seconds'], 165)
        self.assertEqual(corpus._exec.__kwdefaults__['seconds'], 45)
        self.assertEqual((bounds['fsx_seed'], bounds['fsx_operations']), (1, 1000))
        self.assertEqual((bounds['max_file_bytes'], bounds['max_operation_bytes']), (4194304, 65536))
        self.assertEqual(bounds['host_exec_output_bytes'], 1048576)
        self.assertEqual(corpus._exec.__kwdefaults__['maximum'], 1048576)
        self.assertEqual((bounds['fsx_diagnostic_seconds'], bounds['fsx_diagnostic_bytes']), (20, 32768))
        self.assertEqual(corpus.BACKEND_SECONDS, 3600)
        self.assertEqual((corpus.PASS_BYTES, corpus.CAMPAIGN_BYTES), (134217728, 536870912))
        source = (corpus.SOURCE / 'limit.c').read_text()
        for declaration in ('struct rlimit cpu = {30, 30};',
                            'struct rlimit memory = {256 * 1024 * 1024, 256 * 1024 * 1024};',
                            'struct rlimit size = {4 * 1024 * 1024, 4 * 1024 * 1024};',
                            'struct rlimit core = {0, 0};', 'setrlimit(RLIMIT_CPU, &cpu)'):
            self.assertIn(declaration, source)
        parent = source.split('if (child > 0)', 1)[1].split('if (setpgid(0, 0))', 1)[0]
        self.assertEqual(re.findall(r'\balarm\((.*)\);', parent),
                         ['strcmp(argv[0], "/fsx") == 0 ? 150 : 30', '0'])
        self.assertNotIn('getenv(', source)

    def test_pjdfstest_commands_exist_in_pinned_dispatch(self):
        source = (corpus.SOURCE / "upstream/pjdfstest/pjdfstest.c").read_text()
        commands = set(re.findall(r'\{\s*"([a-z0-9_]+)",\s*ACTION_', source))
        self.assertNotIn("close", commands)  # Descriptors close on process exit.
        for name, args, _ in corpus.PJD_CASES + corpus.PEER_CASES:
            start = 2 if args[0] == "-u" else 0
            for index in [start] + [i + 1 for i, arg in enumerate(args) if arg == ":"]:
                with self.subTest(case=name, command=args[index]):
                    self.assertIn(args[index], commands)

    def test_changed_source_fails_even_with_optimization(self):
        (self.root / "config.h").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            builder.validated_sources(self.root)
        code = ("import sys; from pathlib import Path; "
                f"sys.path.insert(0, {str(corpus.SOURCE)!r}); import build; "
                f"build.validated_sources(Path({str(self.root)!r}))")
        result = subprocess.run([sys.executable, "-O", "-c", code], capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"digest mismatch", result.stderr)

    def test_symlink_fifo_and_large_inputs_rejected(self):
        path = self.root / "config.h"
        path.unlink()
        path.symlink_to(self.root / "build.py")
        with self.assertRaises((ValueError, OSError)):
            builder.validated_sources(self.root)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(ValueError):
            builder.validated_sources(self.root)
        path.unlink()
        with path.open("wb") as output:
            output.truncate(builder.MAX_SOURCE_BYTES + 1)
        with self.assertRaises(ValueError):
            builder.validated_sources(self.root)

    def test_symlink_parent_and_unsafe_names_rejected(self):
        (self.root / "alias").symlink_to(self.root / "upstream", target_is_directory=True)
        for name in ("alias/fsx-linux.c", "../outside", "/etc/passwd", "upstream/../config.h",
                     "upstream//fsx-linux.c", "./config.h"):
            with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                builder.read_source(self.root, name)

    def test_total_bound_and_self_hash_rejected(self):
        with patch.object(builder, "MAX_TOTAL_BYTES", 1), self.assertRaises(ValueError):
            builder.validated_sources(self.root)
        self.manifest["sha256"]["provenance.json"] = "0" * 64
        self.save_manifest()
        with self.assertRaises(ValueError):
            builder.validated_sources(self.root)

    def test_archive_contains_only_validated_snapshot(self):
        # A quoted include alongside pjdfstest.c must NOT override tracked config.h.
        (self.root / "upstream/pjdfstest/config.h").write_bytes(b"malicious unlisted shadow")
        (self.root / "unlisted-link").symlink_to("/etc/passwd")
        calls = []
        binaries = builder.tar_bytes([( "./" + name, b"synthetic", 0o755)
                                     for name in ("fsx", "pjdfstest", "fsstress", "limit", "compiler.txt")])

        def run(command, **kwargs):
            calls.append((command, kwargs))
            action = command[3]
            output = {"version": b'{"Os":"linux","Arch":"arm64","Platform":{"Name":"Docker Engine"}}',
                      "inspect": b'[{"State":{"ExitCode":0}}]', "start": binaries}.get(action, b"")
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")

        with patch.object(builder, "HERE", self.root), patch.object(builder.subprocess, "run", side_effect=run):
            builder.build("unix:///explicit/build.sock", self.root / "output")
        source = next(kwargs["input"] for command, kwargs in calls if command[3] == "start")
        with tarfile.open(fileobj=io.BytesIO(source)) as archive:
            self.assertEqual(set(archive.getnames()), set(self.sources))
            for name, data in self.sources.items():
                self.assertEqual(archive.extractfile(name).read(), data)
        self.assertEqual([command[3] for command, _ in calls],
                         ["version", "create", "start", "inspect", "rm"])

    def test_fixture_load_checks_current_sources_and_archive(self):
        fixture = self.root / "fixture"
        fixture.mkdir()
        archive = b"synthetic archive"
        metadata = {"image": "synthetic", "archive_sha256": hashlib.sha256(archive).hexdigest(),
                    "provenance": self.manifest}
        (fixture / "fixture.json").write_text(json.dumps(metadata))
        for override in (False, True):
            with self.subTest(override=override), patch.dict(os.environ), \
                    patch.object(corpus, "FIXTURE", fixture), patch.object(corpus, "SOURCE", self.root), \
                    patch.object(corpus, "fixture_identity"):
                if override:
                    os.environ["CENGINE_CORPUS_FIXTURE"] = str(fixture)
                (self.root / "config.h").write_bytes(self.sources["config.h"])
                (fixture / "fixture.tar").write_bytes(archive)
                self.assertEqual(corpus.corpus_fixture.__wrapped__(), (archive, metadata))
                (self.root / "config.h").write_bytes(b"stale source")
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    corpus.corpus_fixture.__wrapped__()
                (fixture / "fixture.tar").write_bytes(b"tampered archive")
                with self.assertRaisesRegex(ValueError, "archive digest mismatch"):
                    corpus.corpus_fixture.__wrapped__()

    def test_explicit_endpoint_authority_and_cengine_rejection(self):
        builder.validate_build_host("unix:///some/authorized/socket")
        for host in ("unix://relative.sock", "unix:relative.sock", "tcp://localhost:2375",
                     "unix:///", "unix:///tmp/socket?redirect=1", "unix:///tmp/socket#other"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                builder.validate_build_host(host)
        for identity in ({"Platform": {"Name": "cengine"}},
                         {"Components": [{"Name": "CEngine"}]}):
            with self.assertRaisesRegex(ValueError, "cengine"):
                builder.validate_build_version({"Os": "linux", "Arch": "arm64", **identity})


class FixtureSelectionTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ))
        os.environ.pop("CENGINE_CORPUS_FIXTURE", None)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fixture = self.root / "new local fixture"
        self.fixture.mkdir()
        self.enterContext(patch.object(corpus, "FIXTURE", self.root / "default"))
        self.layer = builder.tar_bytes([("limit", b"synthetic, never executed", 0o755)])
        self.config = corpus.encode({"architecture": "arm64", "os": "linux",
            "config": {"Cmd": ["/limit", "keeper"]},
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(self.layer).hexdigest()]}})
        self.digest = hashlib.sha256(self.config).hexdigest()
        self.image = "compat-volume-probe:" + self.digest
        self.provenance, _ = builder.validated_sources(corpus.SOURCE)
        self.archive = self.make_archive()
        self.metadata = {"image": self.image, "archive_sha256": hashlib.sha256(self.archive).hexdigest(),
                         "provenance": self.provenance, "builder": builder.BUILDER}
        self.save()

    def make_archive(self, *, config=None, layer=None):
        manifest = [{"Config": self.digest + ".json", "RepoTags": [self.image], "Layers": ["layer.tar"]}]
        return builder.tar_bytes([(self.digest + ".json", self.config if config is None else config, 0o644),
                                  ("layer.tar", self.layer if layer is None else layer, 0o644),
                                  ("manifest.json", corpus.encode(manifest), 0o644)])

    def save(self):
        (self.fixture / "fixture.tar").write_bytes(self.archive)
        (self.fixture / "fixture.json").write_bytes(corpus.encode(self.metadata))

    def test_override_loads_same_validated_bytes_without_changing_default(self):
        self.assertEqual(corpus.corpus_fixture_directory(), corpus.FIXTURE)
        with patch.object(corpus, "FIXTURE", self.fixture):
            expected = corpus.corpus_fixture.__wrapped__()
        os.environ["CENGINE_CORPUS_FIXTURE"] = str(self.fixture)
        self.assertEqual(corpus.corpus_fixture.__wrapped__(), expected)
        self.assertEqual(expected, (self.archive, self.metadata))
        self.assertEqual(expected[1]["provenance"], self.provenance)
        self.assertEqual(hashlib.sha256(expected[0]).hexdigest(), self.metadata["archive_sha256"])
        self.assertFalse(corpus.FIXTURE.exists())
        self.assertEqual((self.fixture / "fixture.tar").read_bytes(), self.archive)
        self.assertEqual((self.fixture / "fixture.json").read_bytes(), corpus.encode(self.metadata))

    def test_invalid_override_never_falls_back_or_reads_inputs(self):
        for value in ("", " ", "relative", "~/fixture", "file:///fixture", "/", "//tmp/fixture",
                      "/tmp/../fixture", "/tmp/./fixture", "/tmp//fixture", "/tmp/fixture/",
                      " /tmp/fixture", "/tmp/fixture ", "/tmp/fixture\n", "/tmp/fi\0xture",
                      "/tmp/fi\txture", "/tmp/fi\x7fxture", "/" + "x" * 4096):
            with self.subTest(value=value), patch.object(corpus.os, "environ", {"CENGINE_CORPUS_FIXTURE": value}), \
                    patch.object(corpus, "read_bounded") as read:
                with self.assertRaisesRegex(ValueError, "CENGINE_CORPUS_FIXTURE"):
                    corpus.corpus_fixture.__wrapped__()
                read.assert_not_called()

    def test_missing_override_does_not_use_valid_default(self):
        os.environ["CENGINE_CORPUS_FIXTURE"] = str(self.root / "missing")
        with patch.object(corpus, "FIXTURE", self.fixture), \
                self.assertRaisesRegex(corpus.pytest.fail.Exception, "corpus fixture missing"):
            corpus.corpus_fixture.__wrapped__()

    def test_digest_and_provenance_pins_fail_for_default_and_override(self):
        for override in (False, True):
            for kind, error in (("archive", "archive digest mismatch"), ("image", "config identity mismatch"),
                                ("config", "content-derived tag"), ("layer", "layer identity mismatch"),
                                ("provenance", "rebuild stale corpus fixture")):
                with self.subTest(override=override, kind=kind), patch.dict(os.environ), \
                        patch.object(corpus, "FIXTURE", self.fixture):
                    if override:
                        os.environ["CENGINE_CORPUS_FIXTURE"] = str(self.fixture)
                    metadata = json.loads(corpus.encode(self.metadata))
                    archive = self.archive
                    if kind == "archive":
                        metadata["archive_sha256"] = "0" * 64
                    elif kind == "image":
                        metadata["image"] = "compat-volume-probe:" + "0" * 64
                    elif kind == "config":
                        archive = self.make_archive(config=self.config + b" ")
                        metadata["archive_sha256"] = hashlib.sha256(archive).hexdigest()
                    elif kind == "layer":
                        archive = self.make_archive(layer=b"changed layer")
                        metadata["archive_sha256"] = hashlib.sha256(archive).hexdigest()
                    else:
                        metadata["provenance"]["sha256"]["config.h"] = "0" * 64
                    (self.fixture / "fixture.tar").write_bytes(archive)
                    (self.fixture / "fixture.json").write_bytes(corpus.encode(metadata))
                    with self.assertRaisesRegex(ValueError, error):
                        corpus.corpus_fixture.__wrapped__()

    def test_override_does_not_relax_profile_allowlist(self):
        os.environ["CENGINE_CORPUS_FIXTURE"] = str(self.fixture)
        for profile in ("", " ", "Soak", "pilot,soak", "soak\n", "stress"):
            with self.subTest(profile=profile), patch.dict(os.environ, {"CENGINE_CORPUS_PROFILE": profile}), \
                    patch.object(corpus, "_execute_pilot") as pilot, patch.object(corpus, "_execute_soak") as soak:
                with self.assertRaisesRegex(ValueError, "must be pilot or soak"):
                    corpus._execute_corpus(None, None, "block", self.root, "test")
                pilot.assert_not_called()
                soak.assert_not_called()

    def test_override_retains_metadata_and_archive_size_bounds(self):
        os.environ["CENGINE_CORPUS_FIXTURE"] = str(self.fixture)
        for name, maximum in (("fixture.json", 1024 * 1024), ("fixture.tar", 16 * 1024 * 1024)):
            with self.subTest(name=name):
                self.save()
                with (self.fixture / name).open("wb") as output:
                    output.truncate(maximum + 1)
                with self.assertRaisesRegex(ValueError, "bounded regular file"):
                    corpus.corpus_fixture.__wrapped__()


class CampaignTests(unittest.TestCase):
    def test_absolute_api_budget_applies_each_request_and_restores(self):
        calls = []
        raw = SimpleNamespace(_sock=SimpleNamespace(settimeout=lambda value: None), readinto=lambda buffer: 0)
        response = SimpleNamespace(close=lambda: calls.append('closed'), status_code=200,
                                   raw=SimpleNamespace(_fp=SimpleNamespace(fp=SimpleNamespace(raw=raw))))
        def send(request, **kwargs):
            self.assertIs(kwargs['stream'], True)
            self.assertIs(kwargs['allow_redirects'], False)
            calls.append(kwargs['timeout'])
            return response
        api = corpus.docker.APIClient(base_url='unix:///unused', version='1.45')
        self.addCleanup(api.close)
        api.send = send
        client = SimpleNamespace(api=api)
        watchdog = SimpleNamespace(expired=False, finish=lambda: None)
        self.enterContext(patch.object(corpus, 'HeaderDeadline', return_value=watchdog))
        with patch.object(corpus.time, 'monotonic', side_effect=[0, 1, 2, 8, 8.5, 9]):
            with corpus.api_deadline(client, 10):
                client.api.send(None, timeout=3)
                client.api.send(None, timeout=45)
        self.assertEqual(calls, [3, 2])
        self.assertIs(client.api.send, send)
        with patch.object(corpus.time, 'monotonic', side_effect=[0, 0, 1]):
            with corpus.api_deadline(client, 10):
                client.api.send(None, timeout=(None, None))
        self.assertEqual(calls[-1], 10)
        with patch.object(corpus.time, 'monotonic', side_effect=[0, 0, 11]):
            with corpus.api_deadline(client, 10), self.assertRaises(TimeoutError):
                client.api.send(None)
        self.assertEqual(calls[-1], 'closed')
        with patch.object(corpus.time, 'monotonic', return_value=11):
            with corpus.api_deadline(client, 10), self.assertRaises(TimeoutError):
                client.api.send(None)
        self.assertIs(client.api.send, send)

    def test_real_dripping_headers_deadline_and_next_request_isolation(self):
        drip = [b'HTTP/1.1 200 OK\r\nX-Drip: '] + [b'x'] * 200
        success = [b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}']
        with local_http_peer([drip, success]) as (endpoint, accepted):
            sdk = corpus.docker.DockerClient(base_url=endpoint, version='1.45')
            self.addCleanup(sdk.close)
            original = sdk.api.adapters['http+docker://']
            started = time.monotonic()
            with corpus.api_deadline(sdk, started + 0.25):
                with self.assertRaisesRegex(TimeoutError, 'header deadline'):
                    sdk.version()
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertIs(sdk.api.adapters['http+docker://'], original)
            self.assertFalse(any(t.name == 'corpus-http-deadline' for t in threading.enumerate()))
            body_guard = corpus.bound_response_body
            def after_watchdog_join(response, deadline):
                self.assertFalse(any(t.name == 'corpus-http-deadline' for t in threading.enumerate()))
                body_guard(response, deadline)
            with corpus.api_deadline(sdk, time.monotonic() + 1), \
                    patch.object(corpus, 'bound_response_body', side_effect=after_watchdog_join):
                self.assertEqual(sdk.version(), {})
            self.assertEqual(len(accepted), 2)

    def test_real_dripping_body_is_bounded_after_headers(self):
        drip = [b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nC8\r\n'] + [b'x'] * 200
        with local_http_peer([drip]) as (endpoint, _):
            sdk = corpus.docker.DockerClient(base_url=endpoint, version='1.45')
            self.addCleanup(sdk.close)
            started = time.monotonic()
            with corpus.api_deadline(sdk, started + 0.25), \
                    patch.object(corpus, 'bound_response_body', wraps=corpus.bound_response_body) as bound:
                with self.assertRaisesRegex((TimeoutError, ReadTimeoutError, ValueError),
                                            r'deadline|[Tt]imed out|time/size budget'):
                    # Actual SDK image-load generator, but synthetic bytes sent
                    # only to the local non-Docker HTTP peer.
                    list(sdk.api.load_image(b'fixture'))
                bound.assert_called_once()
            self.assertGreaterEqual(time.monotonic() - started, 0.20)
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertFalse(any(t.name == 'corpus-http-deadline' for t in threading.enumerate()))

    def test_reference_transport_rejected_before_sdk_constructor(self):
        with tempfile.TemporaryDirectory() as root, \
                patch.dict(os.environ, {'DOCKER_REFERENCE_HOST': 'ssh://unexpected-host'}), \
                patch.object(corpus.docker, 'DockerClient') as constructor:
            with self.assertRaisesRegex(ValueError, 'local build-only unix socket'):
                corpus._execute_soak(None, None, 'block', Path(root), 'reference')
            constructor.assert_not_called()

    def test_empty_response_and_redirect_fail_closed_without_watchdog_leak(self):
        no_content = [b'HTTP/1.1 204 No Content\r\n\r\n']
        # Declares >16 MiB, then drips: reject from adapter headers, never let
        # Session.resolve_redirects consume the body even with redirects off.
        redirect = [b'HTTP/1.1 302 Found\r\nLocation: http://unexpected.invalid/\r\nContent-Length: 17825792\r\n\r\n'] + [b'x'] * 200
        with local_http_peer([no_content, redirect]) as (endpoint, accepted):
            sdk = corpus.docker.DockerClient(base_url=endpoint, version='1.45')
            self.addCleanup(sdk.close)
            with corpus.api_deadline(sdk, time.monotonic() + 1):
                response = sdk.api._get(sdk.api._url('/empty'))
                self.assertEqual(response.content, b'')
                response.close()
                started = time.monotonic()
                with self.assertRaisesRegex(ValueError, 'redirects'):
                    sdk.api._get(sdk.api._url('/redirect'))
                self.assertLess(time.monotonic() - started, 0.25)
            self.assertEqual(len(accepted), 2)
            self.assertFalse(any(t.name == 'corpus-http-deadline' for t in threading.enumerate()))

    def test_header_deadline_owns_only_registered_socket_and_joins(self):
        owned, peer = socket.socketpair()
        other, other_peer = socket.socketpair()
        self.addCleanup(peer.close)
        self.addCleanup(other.close)
        self.addCleanup(other_peer.close)
        watchdog = corpus.HeaderDeadline(time.monotonic() + 0.05)
        watchdog.register(owned)
        self.assertEqual(peer.recv(1), b'')
        watchdog.finish()
        self.assertTrue(watchdog.expired)
        self.assertFalse(watchdog.thread.is_alive())
        other.sendall(b'alive')
        self.assertEqual(other_peer.recv(5), b'alive')
        self.assertEqual(owned.fileno(), -1)

    def test_second_socket_and_late_registration_fail_closed(self):
        first, first_peer = socket.socketpair()
        second, second_peer = socket.socketpair()
        self.addCleanup(first.close)
        self.addCleanup(first_peer.close)
        self.addCleanup(second_peer.close)
        watchdog = corpus.HeaderDeadline(time.monotonic() + 1)
        try:
            watchdog.register(first)
            with self.assertRaisesRegex(ValueError, 'more than one'):
                watchdog.register(second)
            self.assertEqual(second.fileno(), -1)
            first.sendall(b'ok')
            self.assertEqual(first_peer.recv(2), b'ok')
        finally:
            watchdog.finish()
        late, late_peer = socket.socketpair()
        self.addCleanup(late_peer.close)
        with self.assertRaises(TimeoutError):
            watchdog.register(late)
        self.assertEqual(late.fileno(), -1)

    def test_streamed_body_deadline_applies_after_send_returns(self):
        events = []
        raw = SimpleNamespace(_sock=SimpleNamespace(settimeout=lambda value: events.append(value)),
                              readinto=lambda buffer: len(buffer))
        response = SimpleNamespace(close=lambda: events.append('closed'),
                                   raw=SimpleNamespace(_fp=SimpleNamespace(fp=SimpleNamespace(raw=raw))))
        corpus.bound_response_body(response, 10)
        with patch.object(corpus.time, 'monotonic', side_effect=[2, 3, 11]):
            self.assertEqual(raw.readinto(bytearray(100000)), 65536)
            with self.assertRaises(TimeoutError):
                raw.readinto(bytearray(1))
        self.assertEqual(events, [8, 'closed'])
        with self.assertRaises(ValueError):
            corpus.bound_response_body(SimpleNamespace(close=lambda: None), 10)

    def test_soak_joins_and_closes_independent_clients_before_cleanup(self):
        events, clients = [], []
        @contextmanager
        def resources(*args, **kwargs):
            try:
                yield [SimpleNamespace(id='container')]
            finally:
                self.assertEqual(len(clients), 2)
                self.assertEqual(events.count('close'), 2)
                events.append('cleanup')
        def sdk(**kwargs):
            api = corpus.docker.APIClient(base_url='unix:///unused', version='1.45')
            self.addCleanup(api.close)
            value = SimpleNamespace(api=api,
                                    containers=SimpleNamespace(get=lambda value: SimpleNamespace(id=value)),
                                    close=lambda: events.append('close'))
            clients.append(value)
            return value
        transcript = ''.join(f'0/{index}: creat f{index} x:0 0 0\n' for index in range(128))
        def execute(container, command, **kwargs):
            if command[1].endswith('w0'):
                raise TimeoutError('worker failed')
            return 0, ('All operations completed A-OK!' if command[2] == '/fsx' else transcript), ''
        parent = SimpleNamespace(api=SimpleNamespace(_version='1.45'))
        with tempfile.TemporaryDirectory() as root, \
                patch.object(corpus, 'corpus_resources', resources), \
                patch.object(corpus.docker, 'DockerClient', sdk), \
                patch.object(corpus, '_exec', execute), \
                patch.object(corpus, '_exec_fsx', side_effect=lambda container, args, *rest, **kw:
                             execute(container, args, **kw)):
            with self.assertRaisesRegex(TimeoutError, 'worker failed'):
                corpus._execute_soak(parent, None, 'block', Path(root), 'test', SimpleNamespace(socket='/safe'))
        self.assertIsNot(clients[0], clients[1])
        self.assertEqual(events[-1], 'cleanup')

    def test_soak_per_command_limits_use_remaining_work_budget(self):
        item = corpus.soak_schedule()[0]
        parent = SimpleNamespace(api=SimpleNamespace(_version='1.45'))
        for storage in ('block', 'shared'):
            for fsx_remaining, stress_remaining in ((100, 90), (50, 20), (50, 0)):
                with self.subTest(storage=storage, remaining=(fsx_remaining, stress_remaining)), \
                        patch.object(corpus, 'journal_writer', return_value=lambda value: None), \
                        patch.object(corpus, 'soak_schedule', return_value=[item]), \
                        patch.object(corpus, 'corpus_resources') as resources, \
                        patch.object(corpus, 'api_deadline'), \
                        patch.object(corpus.docker, 'DockerClient') as sdk, \
                        patch.object(corpus, '_exec_fsx', return_value=(0, 'All operations completed A-OK!', '')) as fsx, \
                        patch.object(corpus, '_exec', return_value=(1, '', '')) as execute, \
                        patch.object(corpus.time, 'monotonic', side_effect=[
                            0, 0, corpus.BACKEND_SECONDS - 180 - fsx_remaining,
                            corpus.BACKEND_SECONDS - 180 - stress_remaining, 1000]):
                    resources.return_value.__enter__.return_value = [SimpleNamespace(id='owned')]
                    run = lambda: corpus._execute_soak(parent, None, storage, Path('/unused'),
                                                       'test', SimpleNamespace(socket='/unused'))
                    if stress_remaining <= 0:
                        with self.assertRaisesRegex(TimeoutError, 'worker budget exhausted'):
                            run()
                    else:
                        self.assertEqual([result['passed'] for result in run()], [True, False])
                    self.assertEqual(resources.call_args.kwargs,
                                     {'deadline': corpus.BACKEND_SECONDS - 180,
                                      'cleanup_deadline': corpus.BACKEND_SECONDS})
                    calls = fsx.call_args_list + execute.call_args_list
                    self.assertEqual(fsx.call_count, 1)
                    self.assertEqual(fsx.call_args.args[2], Path('/unused'))
                    self.assertEqual(len(calls), 1 if stress_remaining <= 0 else 2)
                    for call, command, cap, remaining in zip(calls, item['commands'],
                                                            (165, 45), (fsx_remaining, stress_remaining)):
                        self.assertEqual(call.args[1], ['--work', item['directory'], *command])
                        self.assertEqual(call.kwargs, {'seconds': min(cap, remaining)})
                    sdk.return_value.close.assert_called_once()

    def test_stress_requires_complete_namespace_transcript(self):
        complete = ''.join(f'0/{index}: creat f{index} x:0 0 0\n' for index in range(128))
        self.assertTrue(corpus.stress_completed(0, complete))
        for code, log in ((1, complete), (124, complete), (0, ''),
                          (0, complete.replace('0/127:', '0/126:')),
                          (0, complete.replace('creat', 'write', 1))):
            self.assertFalse(corpus.stress_completed(code, log))

    def test_namespace_probe_records_raw_errno_and_rejects_wrong_exit(self):
        records = []
        probe = namespace.NamespaceProbe([object()], records.append)
        with patch.object(namespace, '_exec', return_value=(1, 'EPERM\n', 'raw stderr')):
            self.assertEqual(probe.call(['rename', 'a', 'b'], ('EPERM', 'EACCES')), 'EPERM')
        self.assertEqual(records[-1]['stderr'], 'raw stderr')
        with patch.object(namespace, '_exec', return_value=(0, 'EPERM\n', '')):
            with self.assertRaises(AssertionError):
                probe.call(['rename', 'a', 'b'], 'EPERM')

    def test_namespace_failure_checks_both_consumers_before_and_after(self):
        probe = namespace.NamespaceProbe([object(), object()], lambda value: None)
        with patch.object(probe, 'snapshot', side_effect=[['source', 'target'], ['source', 'changed']]) as snapshot, \
                patch.object(probe, 'call'):
            with self.assertRaises(AssertionError):
                probe.preserved_failure(['rename', 'a', 'b'], 'EISDIR', ('a', 'b'))
            self.assertEqual(snapshot.call_count, 2)
        with patch.object(probe, 'stat', side_effect=['a0', 'b0', 'a1', 'b1']):
            self.assertEqual(probe.snapshot(('a', 'b')), [['a0', 'b0'], ['a1', 'b1']])

    def test_seed_schedule_and_bounds(self):
        schedule = corpus.soak_schedule()
        self.assertEqual(len(schedule), 16)
        self.assertEqual({item['seed'] for item in schedule}, set(range(101, 809, 101)))
        self.assertEqual(len({item['directory'] for item in schedule}), 16)
        for item in schedule:
            self.assertEqual(item['commands'][0], ['/fsx', '-d', '-S', str(item['seed']), '-N',
                                                   '1000', '-l', '4194304', '-o', '65536', 'fsx-file'])
            stress = item['commands'][1]
            self.assertEqual(stress, corpus.fsstress_command(item['seed']))
            self.assertEqual(stress[:10], ['/fsstress', '-X', '-c', '-p', '1', '-l', '1', '-n', '128', '-s'])
            self.assertEqual(stress[11:13], ['-v', '-z'])
            self.assertEqual({arg for arg in stress if '=' in arg},
                             {'creat=4', 'mkdir=2', 'rename=2', 'link=1', 'symlink=1',
                              'unlink=2', 'rmdir=1', 'stat=1', 'getdents=1', 'readlink=1'})
            self.assertNotIn('-d', stress)
        # Each worker: <=128 namespace operations + startup dir/file + 3 fsx files.
        self.assertLessEqual(2 * (128 + 6), 512)
        self.assertLessEqual(2 * 3 * 4194304 + 2 * 128 * 4096, 64 * 1024 * 1024)
        for seed in (0, -1, 1000001, True, '101', None):
            with self.assertRaises(ValueError):
                corpus.fsstress_command(seed)

    def test_native_allowlist_matches_schedule(self):
        source = (corpus.SOURCE / 'limit.c').read_text()
        section = source.split('static const char *args[] = {', 1)[1].split('};', 1)[0]
        tokens = re.findall(r'"([^"]*)"|\b(NULL)\b', section)
        args = [text if text else '101' for text, null in tokens]
        self.assertEqual(args, corpus.fsstress_command(101))
        self.assertIn('kill(-(pid_t)child_pid, SIGKILL)', source)
        self.assertIn('RLIMIT_AS', source)
        self.assertIn('if (!work || !stress_ok(argc, argv)) return 125;', source)
        self.assertIn('native[argc] = "-d";', source)
        self.assertIn('native[argc + 1] = ".";', source)
        self.assertLess(source.index('if (chdir(work))'), source.index('native[argc]'))
        upstream = (corpus.SOURCE / 'upstream/fsstress/fsstress.c').read_text()
        self.assertTrue('if (!dirname)' in upstream)

    def test_build_contract_and_cleanup_hazard(self):
        source = (corpus.SOURCE / 'build.py').read_text()
        for flag in ('-static', '-DNO_XFS', '-D_LARGEFILE64_SOURCE', '-D_GNU_SOURCE',
                     '--read-only', '--pids-limit', '--memory', '--network'):
            self.assertIn(flag, source)
        compile_line = next(line for line in source.splitlines() if '-o /out/fsstress' in line)
        self.assertIn(' -I. ', compile_line)
        stress = (corpus.SOURCE / 'upstream/fsstress/fsstress.c').read_text()
        self.assertRegex(stress, r"case 'c':\s*/\*Don't cleanup \*/\s*cleanup = 1;")
        self.assertIn('if (cleanup == 0)', stress)
        self.assertIn('system(cmd);', stress)

    def test_mount_identity_does_not_confuse_fuse_and_nfs(self):
        for fs in ('ext4', 'fuse.managed-v3', 'nfs'):
            raw = f'12 1 0:4 / /data rw - {fs} source rw\n'
            identity = corpus.mount_identity(raw)
            self.assertEqual(identity['filesystem'], fs)
            self.assertEqual(identity['raw'], raw.strip())
        for raw in ('', '12 1 0:4 / /database rw - nfs source rw',
                    '12 1 0:4 / /data rw - nfs source rw\n' * 2):
            with self.assertRaises(ValueError):
                corpus.mount_identity(raw)

    def test_artifact_budget_fails_and_keeps_cleanup_reserve(self):
        with tempfile.TemporaryDirectory() as root:
            record = corpus.journal_writer(Path(root), 'test')
            with patch.object(corpus, 'PASS_BYTES', 4 * 1024 * 1024 + 32):
                with self.assertRaisesRegex(ValueError, 'artifact budget'):
                    record({'phase': 'after', 'stdout': 'x' * 100})
                record({'phase': 'cleanup', 'status': 'complete'})
            self.assertIn('complete', (Path(root) / 'test.jsonl').read_text())

    def test_cleanup_exact_owner_and_attempts_all(self):
        removed = []
        resources = {}
        for name, token in [('owned', 'token'), ('foreign', 'other')]:
            resources[name] = SimpleNamespace(name=name, attrs={'Config': {'Labels': {corpus.OWNER_LABEL: token}}},
                                               remove=lambda name=name, **kw: removed.append(name))
        volume = SimpleNamespace(name='volume', attrs={'Labels': {corpus.OWNER_LABEL: 'token'}},
                                 remove=lambda: removed.append('volume'))
        client = SimpleNamespace(containers=SimpleNamespace(get=resources.__getitem__),
                                 volumes=SimpleNamespace(get=lambda name: volume))
        records = []
        with self.assertRaisesRegex(RuntimeError, 'unowned'):
            corpus.cleanup_owned(client, ['owned', 'foreign'], 'volume', 'token', records.append)
        self.assertEqual(removed, ['owned', 'volume'])
        self.assertTrue(any(item['phase'] == 'cleanup-error' for item in records))
        resources['foreign'].attrs['Config']['Labels'][corpus.OWNER_LABEL] = 'token'
        removed.clear()
        def broken_record(value):
            raise OSError('artifact disk unavailable')
        with self.assertRaisesRegex(RuntimeError, 'cleanup evidence'):
            corpus.cleanup_owned(client, ['owned', 'foreign'], 'volume', 'token', broken_record)
        self.assertEqual(removed, ['foreign', 'owned', 'volume'])


class FsxDiagnosticsTests(unittest.TestCase):
    command = ['/fsx', '-d', '-S', '1', '-N', '1000', '-l', '4194304', '-o', '65536', 'fsx-file']

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.token = 'a' * 32
        self.enterContext(patch.object(corpus.uuid, 'uuid4', return_value=SimpleNamespace(hex=self.token)))
        self.records = []

    def test_pilot_uses_common_calibrated_executor_for_all_backends(self):
        def execute(container, args, **kwargs):
            if args[0] == '--fsx-diagnostics':
                self.assertEqual(args, ['--fsx-diagnostics', self.token, *self.command])
                self.assertEqual(kwargs, {'seconds': 165})
                return 0, 'All operations completed A-OK!', ''
            if args[0] == 'fsx-evidence':
                self.assertEqual(kwargs['seconds'], 165)
                return 2, b'', b''
            self.assertEqual(kwargs, {})  # Ordinary _exec keeps its 45s default.
            _, expected_args, result = next(expected)
            self.assertEqual(args, ['/pjdfstest', *expected_args])
            return (1 if result in ('ENOENT', 'EPERM', 'EACCES') else 0), result, ''
        for label, daemon in (('docker', None), ('cengine', object())):
            for storage in ('block', 'shared'):
                with self.subTest(label=label, storage=storage), \
                        patch.dict(os.environ, {'CENGINE_CORPUS_PROFILE': 'pilot'}), \
                        patch.object(corpus, 'corpus_resources') as resources, \
                        patch.object(corpus, 'journal_writer', return_value=self.records.append), \
                        patch.object(corpus, '_exec', side_effect=execute) as calls, \
                        patch.object(corpus.time, 'monotonic', return_value=0):
                    resources.return_value.__enter__.return_value = [object(), object()]
                    expected = iter(corpus.PJD_CASES + (corpus.PEER_CASES if storage == 'shared' else []))
                    results = corpus._execute_corpus(None, (b'', {}), storage, self.directory, label, daemon)
                    self.assertTrue(all(result['passed'] for result in results))
                    self.assertEqual(calls.call_count, 25 + (8 if storage == 'shared' else 0))
                    self.assertEqual(resources.call_args.args[2], storage)
                    self.assertIs(resources.call_args.args[4], daemon)

    def test_soak_diagnostics_correlate_all_workers_without_changing_results(self):
        parent = SimpleNamespace(api=SimpleNamespace(_version='1.45'))
        transcript = ''.join(f'0/{index}: creat f{index} x:0 0 0\n' for index in range(128))
        for storage in ('block', 'shared'):
            for exit_code in (0, 124):
                with self.subTest(storage=storage, exit=exit_code):
                    directory = self.directory / f'{storage}-{exit_code}'
                    directory.mkdir()
                    records, launches, stress = [], {}, []
                    def execute(container, args, **kwargs):
                        if args[0] == '--fsx-diagnostics':
                            token, work = args[1], args[3]
                            item = next(item for item in corpus.soak_schedule() if item['directory'] == work)
                            self.assertEqual(args[2:], ['--work', work, *item['commands'][0]])
                            self.assertEqual(container.id, f'owned-{item["worker"] if storage == "shared" else 0}')
                            self.assertEqual(kwargs, {'seconds': 165})
                            launches[token] = item
                            return exit_code, ('All operations completed A-OK!' if exit_code == 0 else '000699 trunc'), ''
                        if args[0] == 'fsx-evidence':
                            self.assertIn(args[1], launches)
                            self.assertEqual(kwargs, {'seconds': 165, 'maximum': 40960, 'binary': True})
                            return 0, ('private-' + args[1]).encode(), b''
                        self.assertEqual(args[0], '--work')
                        self.assertEqual(args[2:], corpus.fsstress_command(int(args[1][1]) * 101))
                        self.assertEqual(kwargs, {'seconds': 45})
                        stress.append(args)
                        return 0, transcript, ''
                    with patch.object(corpus, 'journal_writer', return_value=records.append), \
                            patch.object(corpus, 'corpus_resources') as resources, \
                            patch.object(corpus, 'api_deadline'), \
                            patch.object(corpus.docker, 'DockerClient') as sdk, \
                            patch.object(corpus.uuid, 'uuid4', side_effect=[SimpleNamespace(hex=f'{i:032x}') for i in range(16)]), \
                            patch.object(corpus, '_exec', side_effect=execute), \
                            patch.object(corpus.time, 'monotonic', return_value=0):
                        resources.return_value.__enter__.return_value = [SimpleNamespace(id=f'owned-{i}') for i in range(2)]
                        sdk.return_value.containers.get.side_effect = lambda identity: SimpleNamespace(id=identity)
                        results = corpus._execute_soak(parent, None, storage, directory, 'test',
                                                       SimpleNamespace(socket='/unused'))
                    count = 16 if exit_code == 0 else 2
                    self.assertEqual(len(results), 32 if exit_code == 0 else 2)
                    self.assertTrue(all(result['passed'] == (exit_code == 0) for result in results))
                    self.assertEqual(len(stress), 16 if exit_code == 0 else 0)
                    self.assertEqual(len(launches), count)
                    summaries = [value for value in records if value['phase'] == 'fsx-diagnostics']
                    self.assertEqual(len(summaries), count)
                    self.assertEqual(len({value['work'] for value in summaries}), count)
                    for value in summaries:
                        token = value['artifact'][4:-5]
                        item = launches[token]
                        self.assertEqual((value['epoch'], value['worker'], value['seed'], value['work']),
                                         (item['epoch'], item['worker'], item['seed'], item['directory']))
                        data = (directory / value['artifact']).read_bytes()
                        self.assertEqual(data, ('private-' + token).encode())
                        self.assertEqual(value['sha256'], hashlib.sha256(data).hexdigest())
                        self.assertEqual(value['bytes'], len(data))
                        self.assertEqual(value['status'], 'saved')
                    self.assertNotIn('private-', json.dumps(records))

    def test_soak_unavailable_evidence_stays_correlated_and_nonfatal(self):
        for retrieval, status in (((2, b'', b''), 'absent'), ((125, b'', b''), 'unavailable'),
                                  (OSError('private failure'), 'unavailable')):
            with self.subTest(status=status):
                records = []
                def execute(container, args, **kwargs):
                    if args[0] == '--fsx-diagnostics':
                        return 124, '000699 trunc', ''
                    self.assertEqual(args[0], 'fsx-evidence')
                    if isinstance(retrieval, Exception):
                        raise retrieval
                    return retrieval
                with patch.object(corpus, 'journal_writer', return_value=records.append), \
                        patch.object(corpus, 'corpus_resources') as resources, \
                        patch.object(corpus, 'api_deadline'), \
                        patch.object(corpus.docker, 'DockerClient'), \
                        patch.object(corpus, '_exec', side_effect=execute), \
                        patch.object(corpus.time, 'monotonic', return_value=0):
                    resources.return_value.__enter__.return_value = [SimpleNamespace(id='owned')]
                    results = corpus._execute_soak(SimpleNamespace(api=SimpleNamespace(_version='1.45')),
                                                   None, 'block', self.directory, 'test',
                                                   SimpleNamespace(socket='/unused'))
                self.assertEqual([item['passed'] for item in results], [False, False])
                summaries = [value for value in records if value['phase'] == 'fsx-diagnostics']
                self.assertEqual(len(summaries), 2)
                self.assertEqual({(v['epoch'], v['worker'], v['seed'], v['work']) for v in summaries},
                                 {(1, 0, 101, 'e1-w0'), (1, 1, 101, 'e1-w1')})
                self.assertTrue(all(v['status'] == status and 'artifact' not in v for v in summaries))
                self.assertFalse(list(self.directory.iterdir()))
                self.assertNotIn('private', json.dumps(records))

    def test_private_binary_evidence_preserves_failure_and_original_workload(self):
        data = b'kernel-private\xff\nstack errno=13\n'
        calls = []
        def execute(container, args, **kwargs):
            calls.append((args, kwargs))
            return (124, 'MAPWRITE 2', '') if len(calls) == 1 else (0, data, b'')
        with patch.object(corpus, '_exec', side_effect=execute), \
                patch.object(corpus.time, 'monotonic', side_effect=[0, 1, 60]):
            result = corpus._exec_fsx(None, self.command, self.directory, self.records.append)
        self.assertEqual(result, (124, 'MAPWRITE 2', ''))
        self.assertEqual(calls[0], (['--fsx-diagnostics', self.token, *self.command], {'seconds': 164}))
        self.assertEqual(calls[1], (['fsx-evidence', self.token],
                                  {'seconds': 105, 'maximum': 40960, 'binary': True}))
        saved = self.directory / f'fsx-{self.token}.wait'
        self.assertEqual(saved.read_bytes(), data)
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.records, [{'phase': 'fsx-diagnostics', 'status': 'saved',
            'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'artifact': f'fsx-{self.token}.wait'}])
        self.assertNotIn('kernel-private', json.dumps(self.records))

    def test_denied_oversized_malformed_and_failed_retrieval_are_only_data(self):
        for retrieval in ((2, b'', b''), (125, b'', b''),
                          (0, b'x' * (corpus.FSX_EVIDENCE_BYTES + 1), b''),
                          (0, b'private', b'private error'), OSError('secret proc data')):
            with self.subTest(retrieval=type(retrieval)), \
                    patch.object(corpus, '_exec', side_effect=[(0, 'A-OK', ''), retrieval]):
                self.assertEqual(corpus._exec_fsx(None, self.command, self.directory, self.records.append),
                                 (0, 'A-OK', ''))
        self.assertFalse(list(self.directory.iterdir()))
        self.assertNotIn('private', json.dumps(self.records))
        self.assertNotIn('secret', json.dumps(self.records))

    def test_no_extra_budget_after_original_timeout_and_original_exception_survives(self):
        original = TimeoutError('original timeout')
        with patch.object(corpus, '_exec', side_effect=original) as execute, \
                patch.object(corpus.time, 'monotonic', side_effect=[0, 1, 166]):
            with self.assertRaises(TimeoutError) as caught:
                corpus._exec_fsx(None, self.command, self.directory, self.records.append)
        self.assertIs(caught.exception, original)
        execute.assert_called_once()
        self.assertEqual(self.records[-1]['status'], 'deadline-exhausted')
        with patch.object(corpus, '_exec', side_effect=[original, (0, b'private', b'')]):
            with self.assertRaises(TimeoutError) as caught:
                corpus._exec_fsx(None, self.command, self.directory,
                                 lambda value: (_ for _ in ()).throw(OSError('journal unavailable')))
        self.assertIs(caught.exception, original)

    def test_existing_file_and_symlink_are_never_overwritten(self):
        target = self.directory / 'target'
        target.write_bytes(b'untouched')
        saved = self.directory / f'fsx-{self.token}.wait'
        for symlink in (False, True):
            if symlink:
                saved.symlink_to(target)
            else:
                saved.write_bytes(b'untouched')
            with patch.object(corpus, '_exec', side_effect=[(124, '', ''), (0, b'private', b'')]):
                self.assertEqual(corpus._exec_fsx(None, self.command, self.directory, self.records.append)[0], 124)
            self.assertEqual(saved.read_bytes(), b'untouched')
            self.assertEqual(self.records[-1]['status'], 'unavailable')
            saved.unlink()
        self.assertEqual(target.read_bytes(), b'untouched')

    def test_native_source_ownership_bounds_and_async_safe_handler(self):
        source = (corpus.SOURCE / 'limit.c').read_text()
        handler = source.split('static void deadline(int sig)', 1)[1].split('static int seed_ok', 1)[0]
        for forbidden in ('printf', 'fopen', 'malloc', 'snprintf', 'alarm(', 'signal('):
            self.assertNotIn(forbidden, handler)
        self.assertIn('kill(-(pid_t)child_pid, SIGKILL)', handler)
        self.assertIn('_exit(124)', handler)
        collector = source.split('static void *collect_evidence', 1)[1].split('static int native_pidfd', 1)[0]
        self.assertIn('evidence_proc(reader->output, &reader->total, reader->proc, fields[i]);', collector)
        self.assertEqual(source.count('evidence_proc(reader->output,'), 1)
        self.assertLess(collector.index('pthread_sigmask(SIG_BLOCK'), collector.index('evidence_proc('))
        self.assertIn('pthread_create(&collector, NULL, collect_evidence, reader)', source)
        self.assertNotIn('pthread_join(', source)
        self.assertIn('_exit(WIFEXITED(status)', source)
        self.assertEqual(source.count('alarm(strcmp(argv[0], "/fsx") == 0 ? 150 : 30)'), 1)
        self.assertEqual(source.count('waitpid(child, &status, 0)'), 1)
        parent = source.split('if (child > 0)', 1)[1]
        self.assertLess(parent.index('alarm(strcmp(argv[0], "/fsx") == 0 ? 150 : 30)'),
                        parent.index('fsx_evidence(child, diagnostics)'))
        self.assertLess(parent.index('fsx_evidence(child, diagnostics)'), parent.index('waitpid(child, &status, 0)'))
        self.assertIn('SYS_pidfd_open, child, 0', source)
        self.assertIn('if (child <= 1) return;', source)
        self.assertIn('WEXITED | WNOHANG | WNOWAIT', source)
        self.assertIn('if (diagnostics && !fsx_ok(argc, argv, work)) return 125;', source)
        self.assertIn('{"stat", "wchan", "syscall", "stack"}', source)
        self.assertIn('#define EVIDENCE_BYTES 32768', source)
        self.assertIn('#define SAMPLE_SECONDS 20', source)
        self.assertIn('O_WRONLY | O_CREAT | O_EXCL', source)
        self.assertIn('O_NOFOLLOW', source)
        self.assertIn('info.st_uid != geteuid()', source)
        self.assertIn('info.st_nlink != 1', source)
        self.assertNotIn('/proc/1', source)
        self.assertNotIn('ptrace(', source)
        expected = source.split('static const char *expected[] = {', 1)[1].split('};', 1)[0]
        self.assertEqual([text if text else '1' for text, null in re.findall(r'"([^"]*)"|\b(NULL)\b', expected)],
                         self.command)

    def test_native_host_parser_closes_seed_work_and_command_grammar(self):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('no local C compiler')
        # Exercise real main's parsing, stopping BEFORE fork, paths or proc I/O.
        # No resource-limit changes in this parser-only host process.
        unit = self.directory / 'parser.c'
        unit.write_text('''#define _GNU_SOURCE
#include <sys/resource.h>
#include <unistd.h>
static pid_t parse_stop(void) { _exit(42); }
#define setrlimit(...) 0
#define fork parse_stop
#define main launcher_main
#include "''' + str(corpus.SOURCE / 'limit.c') + '''"
#undef main
int main(int argc, char **argv) { return launcher_main(argc, argv); }
''')
        binary = self.directory / 'parser'
        subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-variable',
                        str(unit), '-o', str(binary)], check=True, capture_output=True, timeout=20)
        def check(args, accepted):
            result = subprocess.run([str(binary), *args], capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 42 if accepted else 125, args)
            self.assertEqual((result.stdout, result.stderr), (b'', b''))
        prefix = ['--fsx-diagnostics', self.token]
        check([*prefix, *self.command], True)  # Unchanged seed-1 pilot.
        for item in corpus.soak_schedule():
            command = item['commands'][0]
            check([*prefix, '--work', item['directory'], *command], True)
            check([*prefix, *command], False)
            check([*prefix, '--work', item['directory'], *self.command], False)
            for seed in corpus.SOAK_SEEDS:
                modified = command.copy()
                modified[3] = str(seed)
                check([*prefix, '--work', item['directory'], *modified], seed == item['seed'])
        command = corpus.soak_schedule()[0]['commands'][0]
        for work in ('', '.', '..', '/data/corpus/e1-w0', 'e1-w0/..', 'e1-w0/', 'e01-w0',
                     'e0-w0', 'e9-w0', 'e1-w2', 'e1-w-1', 'e1-w0\n'):
            check([*prefix, '--work', work, *command], False)
        for seed in ('0', '1', '102', '1000000', '0101', '+101', '-101', '101 ', '101\n', ''):
            modified = command.copy()
            modified[3] = seed
            check([*prefix, '--work', 'e1-w0', *modified], False)
        for index, value in ((0, '/pjdfstest'), (0, '/proc/1'), (1, '-R'), (2, '-s'),
                             (4, '-n'), (5, '999'), (6, '-L'), (7, '4194305'),
                             (8, '-O'), (9, '65537'), (10, '/tmp/fsx-file'), (10, '../fsx-file')):
            modified = command.copy()
            modified[index] = value
            check([*prefix, '--work', 'e1-w0', *modified], False)
        for args in ([*command, '-R'], command[:-1], [], corpus.fsstress_command(101)):
            check([*prefix, '--work', 'e1-w0', *args], False)
        check(['--work', 'e1-w0', *prefix, *command], False)
        check([*prefix, *prefix, '--work', 'e1-w0', *command], False)
        check([*prefix, '--work', 'e1-w0', '--work', 'e1-w0', *command], False)
        for token in ('', '../1', 'A' * 32, 'a' * 31, 'a' * 33):
            check(['--fsx-diagnostics', token, '--work', 'e1-w0', *command], False)
        # Non-diagnostic existing commands still reach the same launcher boundary.
        check(self.command, True)
        check(['--work', 'e1-w0', *corpus.fsstress_command(101)], True)

    def test_native_launcher_host_syntax_only(self):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('no local C compiler')
        subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsyntax-only',
                        str(corpus.SOURCE / 'limit.c')], check=True, capture_output=True, timeout=20)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux-only tiny owned-child unit; no VM/build endpoint')
    def test_linux_native_guards_and_owned_child_snapshot(self):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('no local Linux C compiler')
        # Only this tiny launcher unit, never the corpus/upstream binaries. Fake
        # monotonic sampling avoids waiting 20s; the real 5s alarm still bounds it.
        unit = self.directory / 'unit.c'
        unit.write_text('''#define _GNU_SOURCE
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/prctl.h>
static pthread_t owner;
static int block_reads;
static ssize_t sample_read(int fd, void *data, size_t size) {
    if (block_reads && !pthread_equal(owner, pthread_self())) {
        sigset_t mask; assert(!pthread_sigmask(SIG_SETMASK, NULL, &mask));
        assert(sigismember(&mask, SIGALRM));
        for (;;) pause(); /* Collector stalled, main's watchdog must still fire. */
    }
    return read(fd, data, size);
}
static int sample_clock(clockid_t which, struct timespec *value) {
    static int calls; (void)which; value->tv_sec = calls++ ? 20 : 0; value->tv_nsec = 0; return 0;
}
#define clock_gettime sample_clock
#define read sample_read
#define main launcher_main
#include "''' + str(corpus.SOURCE / 'limit.c') + '''"
#undef main
int main(int argc, char **argv) {
    assert(argc == 3 && token_ok(argv[1]));
    owner = pthread_self(); block_reads = !strcmp(argv[2], "blocked");
    assert(!token_ok("../1") && !token_ok("0000000000000000000000000000000/"));
    char *args[] = {"/fsx", "-d", "-S", "1", "-N", "1000", "-l", "4194304", "-o", "65536", "fsx-file"};
    assert(fsx_ok(11, args, NULL)); args[3] = "101"; assert(!fsx_ok(11, args, NULL));
    assert(fsx_ok(11, args, "e1-w0") && !fsx_ok(11, args, "e2-w0"));
    args[3] = "1"; args[5] = "2"; assert(!fsx_ok(11, args, NULL));
    args[5] = "1000"; args[0] = "/pjdfstest"; assert(!fsx_ok(11, args, NULL));
    pid_t parent = getpid(), child = fork(); assert(child >= 0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG, SIGKILL));
        if (getppid() != parent) _exit(0); /* Test assertion/timeout cannot orphan it. */
        setpgid(0, 0); for (;;) pause();
    }
    child_pid = child; setpgid(child, child); signal(SIGALRM, deadline); alarm(block_reads ? 1 : 5);
    fsx_evidence(child, argv[1]);
    if (block_reads) { waitpid(child, NULL, 0); return 99; }
    int fd = evidence_open(argv[1], 0); assert(fd >= 0);
    char snapshot[EVIDENCE_BYTES + 1] = {0};
    for (int attempt = 0; attempt < 100 && !strstr(snapshot, "snapshot-complete"); attempt++) {
        ssize_t bytes = pread(fd, snapshot, sizeof(snapshot) - 1, 0); assert(bytes >= 0); snapshot[bytes] = 0;
        usleep(10000);
    }
    struct stat info; assert(!fstat(fd, &info)); assert((info.st_mode & 0777) == 0600);
    char data[EVIDENCE_BYTES + 1]; ssize_t n = read(fd, data, sizeof(data) - 1); assert(n > 0); data[n] = 0;
    assert(strstr(data, "snapshot-complete") && strstr(data, "stack errno=") && strstr(data, "pidfd_open errno="));
    close(fd); assert(evidence_open(argv[1], 1) < 0 && errno == EEXIST);
    kill(-child, SIGKILL); assert(waitpid(child, NULL, 0) == child); alarm(0);
    return 0;
}
''')
        binary = self.directory / 'unit'
        subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', str(unit), '-o', str(binary)],
                       check=True, capture_output=True, timeout=20)
        for mode, expected in (('snapshot', 0), ('blocked', 124)):
            token = os.urandom(16).hex()  # Fresh token, not an ambient tmp file.
            evidence = Path('/tmp') / f'cengine-fsx-{token}.wait'
            try:
                started = time.monotonic()
                result = subprocess.run([str(binary), token, mode], capture_output=True, timeout=8)
                self.assertEqual(result.returncode, expected, 'tiny launcher unit failed (raw output private)')
                if mode == 'blocked':
                    self.assertLess(time.monotonic() - started, 3)
            finally:
                evidence.unlink(missing_ok=True)


class ExecTests(unittest.TestCase):
    def fake(self, chunks):
        class Stream:
            closed = False
            timeouts = []

            def settimeout(self, value):
                self.timeouts.append(value)

            def recv(self, size):
                chunk = chunks.pop(0) if chunks else b""
                if isinstance(chunk, BaseException):
                    raise chunk
                if len(chunk) > size:
                    chunks.insert(0, chunk[size:])
                return chunk[:size]

            def close(self):
                self.closed = True

        stream = Stream()
        api = SimpleNamespace(timeout=180, exec_create=lambda *args, **kwargs: {"Id": "exec"},
                              exec_start=lambda *args, **kwargs: stream,
                              exec_inspect=lambda *args: {"ExitCode": 1, "Running": False})
        container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
        return container, stream

    def test_demux_partial_frames_and_nonzero_exit(self):
        data = struct.pack(">BxxxI", 1, 3) + b"out" + struct.pack(">BxxxI", 2, 3) + b"err"
        container, stream = self.fake([data[:3], data[3:10], data[10:]])
        self.assertEqual(corpus._exec(container, ["/pjdfstest"]), (1, "out", "err"))
        self.assertTrue(stream.closed)
        self.assertEqual(container.client.api.timeout, 180)
        self.assertTrue(all(0 < value <= 45 for value in stream.timeouts))

    def test_binary_evidence_transport_does_not_decode_private_bytes(self):
        data = b'private\xff'
        container, stream = self.fake([struct.pack('>BxxxI', 1, len(data)) + data])
        self.assertEqual(corpus._exec(container, ['fsx-evidence', 'a' * 32], binary=True), (1, data, b''))
        self.assertTrue(stream.closed)

    def test_malformed_output_limit_and_timeout_close_stream(self):
        for chunks, error in (([b"short"], ValueError),
                              ([struct.pack(">BxxxI", 3, 0)], ValueError),
                              ([struct.pack(">BxxxI", 1, 5) + b"x"], ValueError),
                              ([b"x" * 33], ValueError),
                              ([socket.timeout("synthetic stall")], TimeoutError)):
            with self.subTest(chunks=chunks):
                container, stream = self.fake(chunks)
                with self.assertRaises(error):
                    corpus._exec(container, ["/pjdfstest"], maximum=32)
                self.assertTrue(stream.closed)
                self.assertEqual(container.client.api.timeout, 180)

    def test_absolute_deadline_not_reset_by_dripping_output(self):
        container, stream = self.fake([b"x"])
        with patch.object(corpus.time, "monotonic", side_effect=[0, 1, 2, 3, 46]):
            with self.assertRaises(TimeoutError):
                corpus._exec(container, ["/pjdfstest"])
        self.assertTrue(stream.closed)
        self.assertEqual(container.client.api.timeout, 180)


if __name__ == "__main__":
    unittest.main()
