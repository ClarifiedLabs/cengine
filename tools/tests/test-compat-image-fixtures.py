#!/usr/bin/env python3
"""Offline regressions: no registry, Docker, VM, or privileged helper required."""
from email.message import Message
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("compat_image_fixtures", ROOT / "tools/compat_image_fixtures.py")
assert SPEC is not None and SPEC.loader is not None
FIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIX)


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class Response(io.BytesIO):
    status = 200

    def __init__(self, data, headers=None):
        super().__init__(data)
        self.headers = {"Content-Length": str(len(data))} if headers is None else headers


class Transport:
    def __init__(self, blobs, authorize=True):
        self.blobs = blobs
        self.authorize = authorize
        self.calls = []
        self.headers = None

    def open(self, request, timeout):
        self.calls.append(request)
        assert 0 < timeout <= FIX.SOCKET_TIMEOUT
        assert request.full_url.startswith("https://")
        if request.full_url.startswith("https://auth.docker.io/token?"):
            assert request.get_header("Authorization") is None
            return Response(b'{"token":"test-bearer-token"}')
        if self.authorize and request.get_header("Authorization") != "Bearer test-bearer-token":
            headers = Message()
            headers["WWW-Authenticate"] = 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/python:pull"'
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", headers, None)
        return Response(self.blobs[request.full_url.rsplit("/", 1)[1]], self.headers)


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cache = Path(self.temporary.name) / "cache"
        self.blobs = {}
        self.layer = self.add_blob(b"a tiny compressed layer", "application/vnd.oci.image.layer.v1.tar+gzip")
        self.config = {"os": "linux", "architecture": "arm64", "rootfs": {"type": "layers", "diff_ids": [sha(b"uncompressed tar")]}}
        self.rebuild()
        self.pins = patch.dict(FIX.FIXTURES, {"python": self.reference})
        self.pins.start()
        self.addCleanup(self.pins.stop)
        # Fail the test if offline paths accidentally instantiate network I/O.
        self.network = patch.object(urllib.request, "build_opener", side_effect=AssertionError("unexpected network"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def add_blob(self, data, media_type):
        self.blobs[sha(data)] = data
        return {"digest": sha(data), "size": len(data), "mediaType": media_type}

    def rebuild(self, *, platform=None, extra=None):
        self.config_entry = self.add_blob(FIX.json_bytes(self.config), "application/vnd.oci.image.config.v1+json")
        self.manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": self.config_entry, "layers": [self.layer]}
        self.selected = self.add_blob(FIX.json_bytes(self.manifest), self.manifest["mediaType"])
        self.selected["platform"] = platform or {"os": "linux", "architecture": "arm64", "variant": "v8"}
        other = {"mediaType": self.selected["mediaType"], "digest": "sha256:" + "0" * 64, "size": 200, "platform": {"os": "linux", "architecture": "amd64"}}
        self.root = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [self.selected, other, *(extra or [])]}
        self.pin = self.add_blob(FIX.json_bytes(self.root), self.root["mediaType"])["digest"]
        self.reference = "docker.io/library/python@" + self.pin
        self.transport = Transport(self.blobs)

    def prepare(self):
        return FIX.prepare("python", self.cache, opener=self.transport)

    def write_json(self, path, value):
        path.write_bytes(FIX.json_bytes(value))

    def test_prepare_verify_selected_manifest_and_idempotence(self):
        layout = self.prepare()
        self.assertEqual(layout, self.cache / "python")
        self.assertEqual(FIX.verify("python", self.cache), layout)
        self.assertEqual(FIX.manifest_digest("python", self.cache), self.selected["digest"])
        index = json.loads((layout / "index.json").read_bytes())
        self.assertEqual(index["manifests"], [self.selected])
        self.assertTrue(FIX.blob_path(layout, self.pin).is_file())
        self.assertFalse(FIX.blob_path(layout, "sha256:" + "0" * 64).exists())
        calls = len(self.transport.calls)
        self.assertEqual(FIX.prepare("python", self.cache), layout)
        self.assertEqual(len(self.transport.calls), calls)
        self.assertEqual(len(list(self.cache.iterdir())), 1)
        self.assertEqual(layout.stat().st_mode & 0o777, 0o700)

    def test_archive_is_complete_standard_oci_with_no_provenance(self):
        layout = self.prepare()
        output = Path(self.temporary.name) / "image.tar"
        self.assertEqual(FIX.archive("python", output, self.cache), output)
        with tarfile.open(output) as archive:
            members = archive.getmembers()
            self.assertTrue(all((item.isfile() or item.isdir()) and not item.issym() for item in members))
            names = {item.name for item in members}
            self.assertNotIn("provenance.json", names)
            self.assertIn("oci-layout", names)
            stream = archive.extractfile("index.json")
            assert stream is not None
            index = json.load(stream)
            self.assertEqual(len(index["manifests"]), 1)
            for entry in [self.selected, self.config_entry, self.layer]:
                name = "blobs/sha256/" + entry["digest"].split(":")[1]
                stream = archive.extractfile(name)
                assert stream is not None
                self.assertEqual(sha(stream.read()), entry["digest"])
            self.assertEqual(len(names), 8)  # 2 dirs + 2 metadata + 4 blobs
        with self.assertRaises(FIX.FixtureError):
            FIX.archive("python", output, self.cache)
        with self.assertRaises(FIX.FixtureError):
            FIX.archive("python", layout / "bad.tar", self.cache)

    def test_missing_cache_is_offline_and_actionable(self):
        with self.assertRaisesRegex(FIX.FixtureError, "make test-compat-images"):
            FIX.verify("python", self.cache)
        self.assertFalse(self.cache.exists())

    def test_full_hash_detects_same_size_corruption_at_every_graph_level(self):
        layout = self.prepare()
        for value in [self.pin, self.selected["digest"], self.config_entry["digest"], self.layer["digest"]]:
            with self.subTest(value=value):
                path = FIX.blob_path(layout, value)
                original = path.read_bytes()
                path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                with self.assertRaisesRegex(FIX.FixtureError, "digest mismatch"):
                    FIX.verify("python", self.cache)
                path.write_bytes(original)

    def test_bad_cache_never_repaired_or_downloaded(self):
        layout = self.prepare()
        path = FIX.blob_path(layout, self.layer["digest"])
        path.write_bytes(b"bad")
        with self.assertRaises(FIX.FixtureError):
            FIX.prepare("python", self.cache)
        self.assertEqual(path.read_bytes(), b"bad")

    def test_pin_and_selected_proof_are_required(self):
        layout = self.prepare()
        proof_path = layout / "provenance.json"
        proof = json.loads(proof_path.read_bytes())
        for field, value in [("source", "docker.io/library/python@sha256:" + "1" * 64), ("manifest_digest", self.pin), ("version", 2)]:
            with self.subTest(field=field):
                self.write_json(proof_path, {**proof, field: value})
                with self.assertRaisesRegex(FIX.FixtureError, "provenance"):
                    FIX.verify("python", self.cache)
        self.write_json(proof_path, proof)
        self.write_json(layout / "index.json", self.root)
        with self.assertRaisesRegex(FIX.FixtureError, "only the selected"):
            FIX.verify("python", self.cache)

    def test_changed_checked_in_pin_invalidates_cache(self):
        self.prepare()
        with patch.dict(FIX.FIXTURES, {"python": "docker.io/library/python@sha256:" + "1" * 64}):
            with self.assertRaises(FIX.FixtureError):
                FIX.verify("python", self.cache)

    def test_wrong_config_platform_and_diff_ids_fail_before_publication(self):
        for change in [{"architecture": "amd64"}, {"os": "windows"}, {"variant": "v7"}, {"rootfs": {"type": "layers", "diff_ids": []}}]:
            with self.subTest(change=change):
                original = self.config.copy()
                self.config.update(change)
                self.rebuild()
                with patch.dict(FIX.FIXTURES, {"python": self.reference}):
                    with self.assertRaises(FIX.FixtureError):
                        self.prepare()
                self.assertEqual(list(self.cache.iterdir()), [])
                self.config = original

    def test_index_rejects_missing_ambiguous_and_wrong_platform(self):
        for entries in [[], [self.selected, self.selected], [{**self.selected, "platform": {"os": "linux", "architecture": "amd64"}}]]:
            with self.subTest(entries=entries), self.assertRaises(FIX.FixtureError):
                FIX.select({**self.root, "manifests": entries})

    def test_download_failure_cleans_only_own_staging(self):
        self.cache.mkdir()
        unrelated = self.cache / ".python-someone-else"
        unrelated.mkdir()
        (unrelated / "keep").write_text("preserve")
        self.blobs[self.layer["digest"]] = b"wrong bytes"
        with self.assertRaises(FIX.FixtureError):
            self.prepare()
        self.assertEqual(list(self.cache.iterdir()), [unrelated])
        self.assertEqual((unrelated / "keep").read_text(), "preserve")

    def test_streaming_byte_size_count_time_and_request_bounds(self):
        for constant, limit in [("MAX_TOTAL", 1), ("MAX_METADATA", 1), ("MAX_DESCRIPTORS", 1), ("MAX_SECONDS", 0), ("MAX_REQUESTS", 1)]:
            with self.subTest(constant=constant), patch.object(FIX, constant, limit):
                with self.assertRaises(FIX.FixtureError):
                    self.prepare()
                self.assertEqual(list(self.cache.iterdir()), [])
        registry = FIX.Registry("library/python", FIX.Budget(), self.transport)
        for data, headers, limit in [(b"abcd", {}, 3), (b"a", {"Content-Length": "2"}, 3), (b"a", {"Content-Encoding": "gzip"}, 3)]:
            with self.subTest(headers=headers), self.assertRaises(FIX.FixtureError):
                list(registry.chunks(Response(data, headers), limit))

    def test_descriptor_rejects_path_escape_foreign_urls_and_invalid_sizes(self):
        for change in [{"digest": "../../escape"}, {"size": -1}, {"size": True}, {"size": FIX.MAX_BLOB + 1}, {"urls": ["http://evil"]}, {"data": "inline"}, {"mediaType": "unknown"}]:
            with self.subTest(change=change), self.assertRaises(FIX.FixtureError):
                FIX.descriptor({**self.layer, **change}, FIX.LAYER_TYPES)
        for name in ["../python", "/tmp/python", "unknown"]:
            with self.subTest(name=name), self.assertRaises(FIX.FixtureError):
                FIX.verify(name, self.cache)

    def test_symlinks_missing_and_extra_blobs_are_rejected(self):
        layout = self.prepare()
        path = FIX.blob_path(layout, self.layer["digest"])
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(FIX.FixtureError):
            FIX.verify("python", self.cache)
        other = Path(self.temporary.name) / "other"
        other.write_bytes(original)
        path.symlink_to(other)
        with self.assertRaisesRegex(FIX.FixtureError, "symlinks forbidden"):
            FIX.verify("python", self.cache)
        path.unlink()
        path.write_bytes(original)
        extra = layout / "blobs/sha256" / ("f" * 64)
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(FIX.FixtureError, "unexpected or missing"):
            FIX.verify("python", self.cache)
        extra.unlink()
        linked = Path(self.temporary.name) / "linked"
        linked.symlink_to(self.cache, target_is_directory=True)
        with self.assertRaises(FIX.FixtureError):
            FIX.verify("python", linked)

    def test_https_and_bearer_auth_boundaries(self):
        registry = FIX.Registry("library/python", FIX.Budget(), self.transport)
        for url in ["http://registry-1.docker.io/x", "file:///tmp/a", "https://user:secret@example.com/x"]:
            with self.subTest(url=url), self.assertRaises(FIX.FixtureError):
                registry.request(url)
        for challenge in ['Basic realm="x"', 'Bearer realm="http://auth.docker.io/token",service="registry.docker.io",scope="repository:library/python:pull"', 'Bearer realm="https://evil/token",service="registry.docker.io",scope="repository:library/python:pull"', 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/python:push"']:
            with self.subTest(challenge=challenge), self.assertRaises(FIX.FixtureError):
                registry.authenticate(challenge)
        request = urllib.request.Request("https://registry-1.docker.io/x", headers={"Authorization": "Bearer secret"})
        handler = FIX.HTTPSRedirect()
        redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://cdn.example/x")
        self.assertIsNone(redirected.get_header("Authorization"))
        with self.assertRaises(FIX.FixtureError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://cdn.example/x")

    def test_duplicate_json_and_oversize_metadata_are_rejected(self):
        with self.assertRaises(FIX.FixtureError):
            FIX.parse_json(b'{"schemaVersion":2,"schemaVersion":1}')
        layout = self.prepare()
        (layout / "index.json").write_bytes(b" " * (FIX.MAX_METADATA + 1))
        with self.assertRaisesRegex(FIX.FixtureError, "metadata exceeds"):
            FIX.verify("python", self.cache)

    def test_exclusive_publication_refuses_even_empty_destination(self):
        staging = Path(self.temporary.name) / "staging"
        target = Path(self.temporary.name) / "target"
        staging.mkdir()
        target.mkdir()
        (staging / "keep").write_text("keep")
        with self.assertRaises(FileExistsError):
            FIX.publish(staging, target)
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual((staging / "keep").read_text(), "keep")

    def test_deadline_interrupts_a_stalled_transport_and_cleans_staging(self):
        def stalled(request, timeout):
            time.sleep(1)
            raise AssertionError("deadline did not interrupt transport")
        with patch.object(self.transport, "open", side_effect=stalled), patch.object(FIX, "MAX_SECONDS", 0.01):
            with self.assertRaisesRegex(FIX.FixtureError, "time bound"):
                self.prepare()
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_directory_enumeration_is_bounded(self):
        self.cache.mkdir()
        for number in range(3):
            (self.cache / str(number)).touch()
        with self.assertRaisesRegex(FIX.FixtureError, "entry count bound"):
            FIX.entries(self.cache, 2)

    def test_cli_check_missing_has_actionable_failure(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/compat_image_fixtures.py"), "--cache", str(self.cache), "check", "python"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("make test-compat-images", result.stderr)
        self.assertFalse(self.cache.exists())


class CheckedInPinsTests(unittest.TestCase):
    def test_exact_fixture_names_and_digest_syntax(self):
        self.assertEqual(set(FIX.FIXTURES), {"python", "buildkit", "alpine"})
        for reference in FIX.FIXTURES.values():
            FIX.digest(reference.split("@")[1])


if __name__ == "__main__":
    unittest.main()
