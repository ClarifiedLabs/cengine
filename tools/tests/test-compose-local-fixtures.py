#!/usr/bin/env python3
"""Offline AST/mock coverage: no daemon, helper, native census, or registry calls."""
from __future__ import annotations

import ast
import io
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFTEST = ROOT / "Tests/Compatibility/conftest.py"
TREE = ast.parse(CONFTEST.read_text())
sys.path.insert(0, str(ROOT / "tools"))
import compat_image_fixtures as fixtures


def function(name):
    return next(node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name == name)


def load_functions(*names, **overrides):
    namespace = dict(pathlib=pathlib, io=io, json=json, tempfile=tempfile, tarfile=tarfile,
                     os=os, compat_image_fixtures=fixtures,
                     LOCAL_COMPOSE_IDS={"CMP-008", "CMP-009", "CMP-010"},
                     LOCAL_BUILDX_IDS={"BLD-001", "BLD-003", "BLD-004", "BLD-006", "BLD-007"})
    namespace.update(overrides)
    for name in names:
        node = ast.parse(ast.unparse(function(name))).body[0]
        node.decorator_list = []
        exec(compile("from __future__ import annotations\n" + ast.unparse(node), str(CONFTEST), "exec"), namespace)
    return namespace


def request(compat_id):
    return SimpleNamespace(node=SimpleNamespace(get_closest_marker=lambda _: SimpleNamespace(args=(compat_id,))))


class LocalComposeFixturesTests(unittest.TestCase):
    def setUp(self):
        self.network = patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden"))
        self.commands = patch.object(subprocess, "run", side_effect=AssertionError("native/helper commands forbidden"))
        self.network.start()
        self.commands.start()
        self.addCleanup(self.network.stop)
        self.addCleanup(self.commands.stop)

    def test_local_builds_verify_exact_required_images(self):
        ns = load_functions("local_build_image_preflight")
        for compat_id in ("CMP-008", "CMP-009", "CMP-010"):
            with self.subTest(compat_id=compat_id), patch.object(fixtures, "verify", side_effect=lambda name: pathlib.Path("/cache") / name) as verify:
                result = ns["local_build_image_preflight"](request(compat_id))
                self.assertEqual(set(result), {"python", "buildkit"})
                self.assertEqual(verify.call_args_list, [call("python"), call("buildkit")])
        for compat_id in ("BLD-001", "BLD-003", "BLD-004", "BLD-006", "BLD-007"):
            with self.subTest(compat_id=compat_id), patch.object(fixtures, "verify", side_effect=lambda name: pathlib.Path("/cache") / name) as verify:
                result = ns["local_build_image_preflight"](request(compat_id))
                self.assertEqual(set(result), {"alpine", "buildkit"})
                self.assertEqual(verify.call_args_list, [call("alpine"), call("buildkit")])
        with patch.object(fixtures, "verify") as verify:
            for compat_id in ("CMP-001", "CMP-007", "CMP-011", "BLD-002", "BLD-005", "RTM-119"):
                self.assertEqual(ns["local_build_image_preflight"](request(compat_id)), {})
            verify.assert_not_called()

    def test_missing_or_corrupt_cache_fails_before_any_allocation_or_helper(self):
        ns = load_functions("local_build_image_preflight", "daemon", Daemon=Mock(), HELPER_FIXTURE_BOUNDARY=Mock())
        for bad_image in ("python", "buildkit"):
            for reason in ("missing cache", "blob digest mismatch"):
                def verify(name):
                    if name == bad_image:
                        raise fixtures.FixtureError(reason)
                    return pathlib.Path("/cache") / name
                with self.subTest(image=bad_image, reason=reason), \
                        patch.object(fixtures, "verify", side_effect=verify), \
                        patch.object(fixtures, "prepare") as prepare, \
                        patch.object(tempfile, "mkdtemp") as allocate:
                    with self.assertRaisesRegex(fixtures.FixtureError, reason):
                        next(ns["daemon"](request("CMP-008"), pathlib.Path("/old-cache")))
                    allocate.assert_not_called()
                    prepare.assert_not_called()
                    ns["Daemon"].assert_not_called()
                    ns["HELPER_FIXTURE_BOUNDARY"].prepare.assert_not_called()

    def test_local_daemon_never_clones_old_cache_and_preserves_boundary_order(self):
        node = function("daemon")
        source = ast.unparse(node)
        self.assertLess(source.index("local_build_image_preflight"), source.index("HELPER_FIXTURE_BOUNDARY.prepare"))
        self.assertLess(source.index("HELPER_FIXTURE_BOUNDARY.prepare"), source.index("tempfile.mkdtemp"))
        self.assertLess(source.index("preretain_compatibility_root"), source.index("clone_tree"))
        self.assertIn("if not local_images and cached_content.is_dir():", source)
        self.assertIn("request.node._managed_root_cleanup = (value, receipt)", source)
        branch = next(n for n in ast.walk(node) if isinstance(n, ast.If) and "cached_content.is_dir()" in ast.unparse(n.test))
        with tempfile.TemporaryDirectory() as temporary:
            cached_content = pathlib.Path(temporary)
            clone = Mock()
            exec(compile(ast.Module(body=[branch], type_ignores=[]), str(CONFTEST), "exec"),
                 dict(local_images={"python": "/cache/python"}, cached_content=cached_content, clone_tree=clone))
            clone.assert_not_called()

    def test_local_client_loads_only_buildkit_and_never_pulls_or_copies_cache(self):
        client = Mock()
        client.version.return_value = {"GitCommit": "abc1234"}
        daemon = SimpleNamespace(local_images={"python": "/cache/python", "buildkit": "/cache/buildkit"},
                                 work=pathlib.Path("/work"), binary=pathlib.Path("/binary"))
        class Endpoint(SimpleNamespace):
            def __getitem__(self, key):
                return pathlib.Path("/run/docker.sock")
        daemon = Endpoint(**vars(daemon))
        seed = Mock()
        ns = load_functions("client", docker=SimpleNamespace(DockerClient=Mock(return_value=client)),
                            expected_git_commit=lambda _: "abc1234", seed_local_build_images=seed,
                            fixture_image_seeds=Mock(side_effect=AssertionError("online seeds forbidden")),
                            clone_tree=Mock(side_effect=AssertionError("old cache copy forbidden")))
        generator = ns["client"](daemon, pathlib.Path("/old-cache"))
        self.assertIs(next(generator), client)
        seed.assert_called_once_with(client, daemon.work)
        with self.assertRaises(StopIteration):
            next(generator)
        client.close.assert_called_once()
        client.images.pull.assert_not_called()
        client.api.pull.assert_not_called()

    def test_buildkit_archive_alias_matches_shipped_pin_and_keeps_root_proof(self):
        reference = fixtures.FIXTURES["buildkit"].removeprefix("docker.io/")
        shipped = (ROOT / "Sources/CEngineCore/DockerIntegration.swift").read_text()
        self.assertIn('"' + reference + '"', shipped)
        root_digest = reference.split("@", 1)[1]
        selected = "sha256:" + "a" * 64
        blobs = {"blobs/sha256/" + root_digest.split(":")[1]: b"root index proof",
                 "blobs/sha256/" + "a" * 64: b"selected manifest"}
        original_index = {"schemaVersion": 2, "manifests": [{"digest": selected}]}

        def archive(name, output):
            self.assertEqual(name, "buildkit")
            with tarfile.open(output, "w") as tar:
                for path, payload in {"index.json": json.dumps(original_index).encode(),
                                      "oci-layout": b'{"imageLayoutVersion":"1.0.0"}', **blobs}.items():
                    info = tarfile.TarInfo(path)
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))

        def load(stream, quiet):
            self.assertFalse(quiet)
            with tarfile.open(fileobj=stream, mode="r:") as tar:
                self.assertEqual(tar.getnames().count("index.json"), 1)
                index = json.load(tar.extractfile("index.json"))
                descriptor, = index["manifests"]
                self.assertEqual(descriptor["digest"], selected)
                self.assertNotEqual(descriptor["digest"], root_digest)
                self.assertEqual(descriptor["annotations"]["io.containerd.image.name"], reference)
                for path, payload in blobs.items():
                    self.assertEqual(tar.extractfile(path).read(), payload)
            return iter([{"stream": "Loaded image: " + reference}])

        ns = load_functions("seed_local_build_images")
        client = Mock()
        client.api.load_image.side_effect = load
        with tempfile.TemporaryDirectory() as temporary, patch.object(fixtures, "archive", side_effect=archive):
            ns["seed_local_build_images"](client, pathlib.Path(temporary))
            self.assertEqual(list(pathlib.Path(temporary).iterdir()), [])
        client.images.get.assert_called_once_with(reference)
        client.images.pull.assert_not_called()
        self.assertNotIn("annotations", original_index["manifests"][0])

        # API errors or a missing digest alias must fail, not trigger a pull.
        for response in ([{"errorDetail": {"message": "invalid archive"}}], [{"stream": "loaded"}]):
            client.reset_mock()
            client.api.load_image.side_effect = None
            client.api.load_image.return_value = iter(response)
            client.images.get.side_effect = RuntimeError("missing alias")
            with tempfile.TemporaryDirectory() as temporary, patch.object(fixtures, "archive", side_effect=archive):
                with self.assertRaises(RuntimeError):
                    ns["seed_local_build_images"](client, pathlib.Path(temporary))
            client.images.pull.assert_not_called()

    def test_named_context_is_selected_manifest_and_network_disabled(self):
        fixture = ROOT / "Tests/Fixtures/compose/developer-loop"
        dockerfile = (fixture / "Dockerfile").read_text()
        self.assertEqual(re.findall(r"^FROM (\S+)", dockerfile, re.M), ["python-base", "python-base"])
        self.assertIn("RUN --network=none", dockerfile)
        self.assertIn("pip install --no-index --disable-pip-version-check", dockerfile)
        self.assertNotIn("# syntax=", dockerfile)  # No external Dockerfile frontend pull.
        self.assertTrue(all(not line.strip() or line.lstrip().startswith("#") for line in (fixture / "requirements.txt").read_text().splitlines()))
        compose = (fixture / "compose.yaml").read_text()
        self.assertIn("network: none", compose)
        self.assertIn("python-base: oci-layout://${DEVELOPER_PYTHON_LAYOUT:?local Python fixture required}@${DEVELOPER_PYTHON_MANIFEST:?selected manifest required}", compose)
        source = (ROOT / "Tests/Compatibility/test_compose.py").read_text()
        self.assertIn('str(daemon.local_images["python"])', source)
        self.assertIn('compat_image_fixtures.manifest_digest("python")', source)

    def test_buildx_local_contexts_leave_pull_and_uplink_contracts_online(self):
        path = ROOT / "Tests/Compatibility/test_buildx.py"
        tree = ast.parse(path.read_text())
        tests = {}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                compat_id = node.decorator_list[0].args[0].value
                tests[compat_id] = ast.unparse(node)
        for compat_id in ("BLD-001", "BLD-003", "BLD-004", "BLD-006"):
            self.assertIn("local_build_arguments(daemon)", tests[compat_id])
        for compat_id in ("BLD-002", "BLD-005"):
            self.assertNotIn("local_build_arguments", tests[compat_id])
            self.assertIn("'--pull'", tests[compat_id])
            self.assertIn("'--no-cache'", tests[compat_id])
        self.assertIn("local_alpine_context(daemon)", tests["BLD-007"])
        self.assertIn('network = "none"', tests["BLD-007"])
        namespace = dict(local_alpine_context=lambda _: "oci-layout:///cache/alpine@sha256:abc")
        args = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "local_build_arguments")
        exec(compile(ast.Module(body=[args], type_ignores=[]), str(path), "exec"), namespace)
        self.assertEqual(namespace["local_build_arguments"](None), (
            "--network=none", "--build-arg", "ALPINE_BASE=alpine-base",
            "--build-context", "alpine-base=oci-layout:///cache/alpine@sha256:abc"))
        for name in ("Dockerfile", "Dockerfile.parallel"):
            source = (ROOT / "Tests/Fixtures/buildx" / name).read_text()
            self.assertTrue(source.startswith("ARG ALPINE_BASE=mirror.gcr.io/library/alpine@sha256:"))
            self.assertIn("FROM ${ALPINE_BASE}", source)

    def test_compose_default_builder_and_recovery_assertions_remain(self):
        source = (ROOT / "Tests/Compatibility/test_compose.py").read_text()
        tree = ast.parse(source)
        selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_developer_compose_")]
        self.assertEqual(len(selected), 3)
        developer = "\n".join(ast.unparse(n) for n in selected)
        self.assertNotIn("--builder", developer)
        self.assertNotIn("buildx create", developer)
        self.assertIn("'--context', 'cengine', 'buildx', 'inspect'", developer)
        self.assertIn("assert managed_buildkit_identity(client) == builder_identity", developer)
        self.assertIn("assert recovered_buildkit.attrs['State']['StartedAt'] == buildkit_started_at", developer)
        self.assertIn("assert container_boot_id(recovered_buildkit) == buildkit_boot_id", developer)
        self.assertIn("assert recovered['pid'] == before_recovery['pid']", developer)
        helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "developer_compose")
        self.assertNotIn("--builder", ast.unparse(helper))
        self.assertNotIn("BUILDX_BUILDER", source)


if __name__ == "__main__":
    unittest.main()
