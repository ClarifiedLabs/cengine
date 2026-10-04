#!/usr/bin/env python3
"""Engine-free volume plan/replay/reduction, executor, and native syscall checks."""
from __future__ import annotations

import copy
from contextlib import nullcontext
import gc
import hashlib
import http.client
import importlib.util
import json
import os
import socket
import struct
import threading
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from lifecycle_backend_fixture import create_backend

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests" / "Compatibility"))
import volume_probe as probe


def synthetic_fixture(*, legacy=False):
    layer = probe.tar_bytes([("data", None, 0o755)])
    config = probe.encode({"architecture": "arm64", "os": "linux",
                          "config": {"Cmd": ["/probe", "serve"] if legacy else
                                     ["/probe", "serve", "/data/probe-tree", "/probe.sock"]},
                          "rootfs": {"type": "layers", "diff_ids": [
                              "sha256:" + hashlib.sha256(layer).hexdigest()]}})
    digest = hashlib.sha256(config).hexdigest()
    tag = "compat-volume-probe:" + (digest[:24] if legacy else digest)
    archive = probe.tar_bytes([
        (digest + ".json", config, 0o644), ("layer.tar", layer, 0o644),
        ("manifest.json", probe.encode([{"Config": digest + ".json",
                                        "RepoTags": [tag], "Layers": ["layer.tar"]}]), 0o644),
    ])
    return archive, "sha256:" + digest if legacy else tag


def frame(channel, payload):
    return struct.pack(">BxxxI", channel, len(payload)) + payload


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.timeouts = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        chunk = next(self.chunks, b"")
        if isinstance(chunk, Exception):
            raise chunk
        return chunk

    def close(self):
        self.closed = True


class FakeNotFound(Exception):
    status_code = 404


class FakeClient:
    def __init__(self, directory, fail=False, cleanup_fail=False):
        self.events = []
        self.directory = directory
        self.fail = fail
        self.cleanup_fail = cleanup_fail
        self.names = []
        self.response = lambda step: {"errno": 0, "entries": {}}
        self.api = SimpleNamespace(exec_create=self.exec_create, exec_start=self.exec_start,
                                   exec_inspect=lambda _: {"ExitCode": 0})
        archive, image = probe.replay_fixture(directory / "plan.json")
        self.tag, config, _ = probe.fixture_identity(archive, image)
        self.image_attrs = {"Id": "sha256:engine-specific-manifest",
                            "Os": config["os"], "Architecture": config["architecture"],
                            "RootFS": {"Type": "layers", "Layers": config["rootfs"]["diff_ids"]},
                            "Config": config["config"]}
        self.images = SimpleNamespace(load=self.load, get=self.inspect)
        self.server_volumes = {}
        self.server_containers = {}
        self.lookups = []
        self.volumes = SimpleNamespace(create=self.volume,
                                       get=lambda name: self.get("volume", name))
        self.containers = SimpleNamespace(create=self.container,
                                          get=lambda name: self.get("container", name))

    def get(self, kind, name):
        self.lookups.append((kind, name))
        resources = self.server_volumes if kind == "volume" else self.server_containers
        if name not in resources:
            raise FakeNotFound(name)
        return resources[name]

    def load(self, archive):
        assert (self.directory / "plan.json").exists()
        assert (self.directory / "fixture.tar").read_bytes() == archive
        assert (self.directory / "fixture.json").exists()
        self.events.append("load")

    def inspect(self, image):
        if image != self.tag:
            raise RuntimeError("config digest cannot address containerd image")
        self.events.append("inspect")
        return SimpleNamespace(attrs=self.image_attrs)

    def remove(self, resource, name):
        self.events.append(resource + "-remove")
        if self.cleanup_fail:
            raise RuntimeError("synthetic " + resource + " cleanup failure")
        resources = self.server_volumes if resource == "volume" else self.server_containers
        del resources[name]

    def volume(self, name, **kwargs):
        self.events.append("volume")
        self.names.append(name)
        volume = SimpleNamespace(
            name=name, attrs={"Labels": kwargs["labels"]}, reload=lambda: None,
            remove=lambda: self.remove("volume", name),
        )
        self.server_volumes[name] = volume
        return volume

    def container(self, image, **kwargs):
        if image != self.tag:
            raise RuntimeError("config digest cannot address containerd image")
        self.events.append("create")

        container = SimpleNamespace(
            name=kwargs["name"], attrs={"Config": {"Labels": kwargs["labels"]}},
            id=f"physical-{len(self.events)}", start=lambda: self.events.append("start"),
            restart=lambda **kw: self.events.append("restart"),
            remove=lambda **kw: self.remove("container", kwargs["name"]), client=self,
        )
        self.server_containers[kwargs["name"]] = container
        return container

    def exec_create(self, container_id, command, **kwargs):
        self.events.append("exec")
        if self.fail:
            raise RuntimeError("synthetic transport failure")
        assert command[:2] == ["/probe", "request"]
        assert kwargs == {"stdout": True, "stderr": True, "tty": False}
        self.step = json.loads(command[2])
        return {"Id": "exec-id"}

    def exec_start(self, exec_id, **kwargs):
        assert kwargs == {"socket": True}
        return FakeSocket([frame(1, probe.encode(self.response(self.step)))])


class TransportTests(unittest.TestCase):
    def run_probe(self, chunks, *, exit_code=0, wrapped=False, **kwargs):
        self.stream = FakeSocket(chunks)
        stream = SimpleNamespace(_sock=self.stream, close=self.stream.close) if wrapped else self.stream
        api = SimpleNamespace(exec_create=lambda *a, **kw: {"Id": "exec-id"},
                              exec_start=lambda *a, **kw: stream,
                              exec_inspect=lambda _: {"ExitCode": exit_code})
        container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
        return probe.probe(container, {"op": "snapshot"}, **kwargs)

    def test_fragmented_frames_and_separate_stderr(self):
        data = frame(2, b"diagnostic\n") + frame(1, b'{"errno":0,"entries":{}}')
        for wrapped in (False, True):
            result = self.run_probe([data[:3], data[3:17], data[17:]], wrapped=wrapped)
            self.assertEqual(result, {"errno": 0, "entries": {}})
            self.assertTrue(self.stream.closed)
            self.assertTrue(all(0 < t <= 50 for t in self.stream.timeouts))

    def test_absolute_deadline_even_when_data_keeps_arriving(self):
        with patch.object(probe.time, "monotonic", side_effect=[100, 101, 103, 106]):
            with self.assertRaisesRegex(TimeoutError, "deadline exceeded"):
                self.run_probe([b"a", b"b", b"c"], timeout=5)
        self.assertEqual(self.stream.timeouts, [4, 2])
        self.assertTrue(self.stream.closed)

    def test_real_idle_socket_is_bounded(self):
        local, peer = socket.socketpair()
        api = SimpleNamespace(exec_create=lambda *a, **kw: {"Id": "exec-id"},
                              exec_start=lambda *a, **kw: local)
        container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
        try:
            with self.assertRaises(TimeoutError):
                probe.probe(container, {"op": "snapshot"}, timeout=0.02)
            self.assertEqual(local.fileno(), -1)
        finally:
            local.close()
            peer.close()

    def test_socketio_wrapper_and_raw_socket_are_both_closed(self):
        local, peer = socket.socketpair()
        stream = local.makefile("rb", buffering=0)
        api = SimpleNamespace(exec_create=lambda *a, **kw: {"Id": "exec-id"},
                              exec_start=lambda *a, **kw: stream)
        container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
        try:
            with self.assertRaises(TimeoutError):
                probe.probe(container, {"op": "snapshot"}, timeout=0.02)
            self.assertTrue(stream.closed)
            self.assertEqual(local.fileno(), -1)
        finally:
            stream.close()
            local.close()
            peer.close()

    def test_successful_malformed_outcomes_are_protocol_failures(self):
        for outcome in ({}, [], None, {"errno": False, "entries": {}},
                        {"errno": 0, "entries": []},
                        {"errno": 0, "entries": {}, "extra": 1}):
            with self.subTest(outcome=outcome), self.assertRaisesRegex(RuntimeError, "invalid outcome shape"):
                self.run_probe([frame(1, probe.encode(outcome))])
            self.assertTrue(self.stream.closed)

    def test_idle_stream_timeout_and_reset_close_socket(self):
        for error in (TimeoutError("idle"), ConnectionResetError("reset")):
            with self.assertRaises(type(error)):
                self.run_probe([error])
            self.assertTrue(self.stream.closed)

    def test_rejects_truncated_invalid_oversize_and_failed_transport(self):
        cases = [([b"short"], {}, "truncated"),
                 ([frame(3, b"x")], {}, "invalid"),
                 ([frame(1, b"json")[:-1]], {}, "invalid"),
                 ([b"x" * (2 * 1024 * 1024 + 1)], {}, "size bound"),
                 ([frame(1, b'{}') + frame(2, b"splice: reset")], {"exit_code": 1}, "transport exit 1"),
                 ([frame(1, b'{}')], {"exit_code": None}, "transport exit None"),
                 ([frame(1, b'{"protocol_error":"bad"}')], {}, "protocol error")]
        for chunks, kwargs, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                self.run_probe(chunks, **kwargs)
            self.assertTrue(self.stream.closed)


class StreamCloseTests(unittest.TestCase):
    def test_retained_response_closes_before_wrapper_and_raw_even_on_error(self):
        for failure in (None, "response", "stream", "raw"):
            with self.subTest(failure=failure):
                events = []

                def close(name):
                    events.append(name)
                    if name == failure:
                        raise RuntimeError(name + " close failed")

                raw = SimpleNamespace(close=lambda: close("raw"))
                stream = SimpleNamespace(_sock=raw, close=lambda: close("stream"),
                                         _response=SimpleNamespace(close=lambda: close("response")))
                if failure is None:
                    probe.close_exec_stream(stream)
                else:
                    with self.assertRaisesRegex(RuntimeError, failure + " close failed"):
                        probe.close_exec_stream(stream)
                self.assertEqual(events, ["response", "stream", "raw"])

    def test_response_may_clear_wrapper_socket_reference(self):
        events = []
        raw = SimpleNamespace(close=lambda: events.append("raw"))
        stream = SimpleNamespace(_sock=raw, close=lambda: events.append("stream"))

        def close_response():
            events.append("response")
            stream._sock = None

        stream._response = SimpleNamespace(close=close_response)
        probe.close_exec_stream(stream)
        self.assertEqual(events, ["response", "stream", "raw"])


@unittest.skipUnless(importlib.util.find_spec("docker") and importlib.util.find_spec("pytest"),
                     "requires compatibility Python environment (Docker SDK, not daemon)")
class SDKTransportTests(unittest.TestCase):
    def test_sdk_retained_http_response_teardown_for_all_exec_helpers(self):
        # Real SDK/requests/urllib3/HTTPResponse/SocketIO stack over a socketpair.
        # No Docker daemon, VM, network endpoint or background server is used.
        import docker
        import requests
        import urllib3
        import test_volume_discovery as discovery
        import test_volume_corpus as corpus
        import test_volume_concurrency as concurrency

        outcome = {"errno": 0, "entries": {}}
        calls = {
            "probe": lambda c, d: probe.probe(c, {"op": "snapshot"}),
            "discovery": lambda c, d: discovery._exec(c, "true"),
            "corpus": lambda c, d: corpus._exec(c, ["true"]),
            "concurrency": lambda c, d: concurrency._exec(c, d, "request"),
        }
        sdk = docker.APIClient(base_url="unix:///unused-volume-probe-test.sock", version="1.45")
        self.addCleanup(sdk.close)
        for name, execute in calls.items():
            for malformed in (False, True):
                with self.subTest(helper=name, malformed=malformed), tempfile.TemporaryDirectory() as temporary:
                    local, peer = socket.socketpair()
                    local.settimeout(1)
                    response = requests.Response()
                    http_response = http.client.HTTPResponse(local)
                    stream = None
                    try:
                        peer.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
                        http_response.begin()
                        response.status_code = 101
                        response.raw = urllib3.response.HTTPResponse(
                            body=http_response, original_response=http_response,
                            preload_content=False,
                        )
                        stream = sdk._get_raw_response_socket(response)
                        self.assertIs(stream._response, response)
                        self.assertIs(stream._sock, local)
                        peer.sendall(b"short" if malformed else frame(1, probe.encode(outcome)))
                        peer.shutdown(socket.SHUT_WR)
                        api = SimpleNamespace(timeout=180,
                                              exec_create=lambda *a, **kw: {"Id": "exec-id"},
                                              exec_start=lambda *a, **kw: stream,
                                              exec_inspect=lambda _: {"Running": False, "ExitCode": 0})
                        container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
                        unraisable = []
                        with patch.object(sys, "unraisablehook", unraisable.append):
                            if malformed:
                                with self.assertRaisesRegex((AssertionError, RuntimeError, ValueError), "truncated"):
                                    execute(container, Path(temporary))
                            else:
                                result = execute(container, Path(temporary))
                                expected = (0, probe.encode(outcome).decode(), "") if name == "corpus" else (
                                    probe.encode(outcome) if name == "discovery" else outcome)
                                self.assertEqual(result, expected)
                            self.assertTrue(http_response.closed)
                            self.assertIsNone(http_response.fp)
                            self.assertTrue(stream.closed)
                            self.assertEqual(local.fileno(), -1)
                            self.assertEqual(api.timeout, 180)
                            del stream._response
                            del response, http_response
                            gc.collect()
                        self.assertEqual(unraisable, [])
                    finally:
                        # Failure-path cleanup retains the same response-first order.
                        if stream is not None:
                            probe.close_exec_stream(stream)
                        else:
                            response.close()
                        local.close()
                        peer.close()

    def test_discovery_http_deadlines_and_timeout_restoration(self):
        import test_volume_discovery as discovery

        for failure in (None, "create", "start", "read", "inspect"):
            with self.subTest(failure=failure):
                events = []
                clock = [100]
                raw = FakeSocket([frame(1, b"ok")])

                def request(phase, result):
                    events.append((phase, api.timeout))
                    clock[0] += 5
                    if phase == failure:
                        raise TimeoutError(phase + " timed out")
                    return result

                api = SimpleNamespace(timeout=180,
                                      exec_create=lambda *a, **kw: request("create", {"Id": "exec-id"}),
                                      exec_start=lambda *a, **kw: request("start", raw),
                                      exec_inspect=lambda _: request("inspect", {"ExitCode": 0}))
                if failure == "read":
                    raw.chunks = iter([TimeoutError("read timed out")])
                container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
                with patch.object(discovery.time, "monotonic", side_effect=lambda: clock[0]):
                    if failure:
                        with self.assertRaisesRegex(TimeoutError, failure + " timed out"):
                            discovery._exec(container, "true")
                    else:
                        self.assertEqual(discovery._exec(container, "true"), b"ok")
                self.assertEqual(api.timeout, 180)
                self.assertEqual(events, [("create", 50), ("start", 45), ("inspect", 40)][:len(events)])
                self.assertEqual(raw.closed, failure not in ("create", "start"))
                self.assertTrue(all(timeout == 40 for timeout in raw.timeouts))

    def test_discovery_create_cannot_spend_stream_deadline_before_start(self):
        import test_volume_discovery as discovery

        api = SimpleNamespace(timeout=180, exec_create=lambda *a, **kw: {"Id": "exec-id"},
                              exec_start=lambda *a, **kw: self.fail("started after deadline"))
        container = SimpleNamespace(id="container", client=SimpleNamespace(api=api))
        with patch.object(discovery.time, "monotonic", side_effect=[100, 100, 151]):
            with self.assertRaisesRegex(TimeoutError, "deadline exceeded"):
                discovery._exec(container, "true")
        self.assertEqual(api.timeout, 180)


class PlanTests(unittest.TestCase):
    def setUp(self):
        # Plan/reducer tests own workload observations, not the separate guest
        # mount-probe transport. Keep its structured evidence out-of-band; the
        # real dispatch and verifier are covered by BackendMountTests below and
        # test-storage-backend-proof.py (never patched by this fixture).
        def record_mounts(client, containers, directory, storage, record, *, candidate):
            proofs = []
            for container in containers:
                value = {"schema": 1, "topology": storage, "test_boundary": True,
                         "candidate": candidate, "mount": {"destination": "/data"}}
                record({"phase": "backend-proof", "container": container.id, "proof": value})
                proofs.append(value)
            return proofs

        boundary = patch.object(probe, "record_backend_mounts", side_effect=record_mounts)
        self.mount_proofs = boundary.start()
        self.addCleanup(boundary.stop)

    def test_seeded_replay_and_bounds(self):
        plan = probe.generate(42)
        self.assertEqual(plan, probe.generate(42))
        self.assertNotEqual(plan, probe.generate(43))
        for count in (1, 12, 24, 256):
            self.assertEqual(len(probe.generate(42, count)["steps"]), count)
        for count in (0, 257):
            with self.assertRaises(ValueError):
                probe.generate(42, count)
        selected = probe.plans_from_environment({"CENGINE_VOLUME_PROBE_SEEDS": "3,5", "CENGINE_VOLUME_PROBE_STEPS": "12"})
        self.assertEqual([p["seed"] for p in selected], [3, 5])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            path.write_bytes(probe.encode(plan))
            self.assertEqual(probe.plans_from_environment({"CENGINE_VOLUME_PROBE_PLAN": str(path)}), [plan])

    def test_unix_endpoint_identity_is_not_sdk_base_url(self):
        self.assertFalse(probe.same_unix_endpoint("unix:///tmp/docker.sock", "/tmp/cengine.sock"))
        self.assertTrue(probe.same_unix_endpoint("unix:///tmp/../tmp/cengine.sock", "/tmp/cengine.sock"))
        self.assertTrue(probe.same_unix_endpoint("http+unix:///tmp/cengine.sock", "/tmp/cengine.sock"))
        self.assertFalse(probe.same_unix_endpoint("tcp://127.0.0.1:2375", "/tmp/cengine.sock"))

    def test_validation_and_dependency_closure(self):
        plan = probe.generate(0, 12)
        self.assertEqual(probe.without_dependents(plan, {"s000"})["steps"], [])
        for key, value in (("path", "../outside"), ("path", "/outside"), ("op", "prune"), ("needs", ["s999"]), ("unknown", "x"), ("data", "😀" * 1025)):
            invalid = copy.deepcopy(plan)
            invalid["steps"][0][key] = value
            with self.assertRaises(ValueError):
                probe.validate(invalid)

    def test_malformed_steps_raise_value_error(self):
        malformed = [None, [], 42, "step", {}, {"id": "s000"}]
        for key, values in {"id": [None, 1, []], "op": [None, 1, [], {}],
                            "needs": [None, 1, "s000", [None], [[]], [{}]],
                            "path": [None, 1, [], {}], "data": [None, 1, []]}.items():
            for value in values:
                step = copy.deepcopy(probe.generate(0, 1)["steps"][0])
                step[key] = value
                malformed.append(step)
        for step in malformed:
            with self.subTest(step=step), self.assertRaises(ValueError):
                probe.validate({"version": 1, "seed": 0, "steps": [step]})

    def test_reduction_preserves_failure_dependency_and_input(self):
        plan = {"version": 1, "seed": 0, "steps": [
            {"id": "s000", "needs": [], "op": "create", "path": "a", "data": "x"},
            {"id": "s001", "needs": [], "op": "create", "path": "b", "data": "y"},
            {"id": "s002", "needs": ["s000"], "op": "open", "path": "a", "fd": "f"},
            {"id": "s003", "needs": ["s002"], "op": "write_fd", "fd": "f", "data": "bug"},
            {"id": "s004", "needs": ["s001"], "op": "chmod", "path": "b", "mode": 384},
        ]}
        original = copy.deepcopy(plan)
        calls = []

        def mismatch(candidate):
            probe.validate(candidate)
            calls.append(candidate)
            return any(s["id"] == "s003" for s in candidate["steps"])

        reduced = probe.reduce_plan(plan, mismatch)
        self.assertEqual([s["id"] for s in reduced["steps"]], ["s000", "s002", "s003"])
        self.assertEqual(plan, original)
        self.assertGreater(len(calls), 1)
        with self.assertRaises(ValueError):
            probe.reduce_plan(plan, lambda p: False)

    def test_seeded_multichain_reduction_drops_unrelated_prefix(self):
        plan = probe.generate(5, 24)
        reduced = probe.reduce_plan(plan, lambda p: any(s["id"] == "s015" for s in p["steps"]))
        self.assertEqual([s["id"] for s in reduced["steps"]], ["s012", "s013", "s014", "s015"])

    def test_endpoint_reduction_replays_fresh_resources_and_preserves_signature(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = probe.generate(5, 24)
            fixture = synthetic_fixture()
            directory, _ = probe.prepare_artifacts(plan, root=root, fixture=fixture)
            reference, candidate = FakeClient(directory), FakeClient(directory)
            candidate.response = lambda step: {
                "errno": 5 if step.get("id") == "s015" else 0, "entries": {},
            }
            reduced, replay = probe.reduce_endpoints(
                plan, fixture, reference, candidate, "shared", root=root,
                backend_proof=lambda _: "shared",
            )
            self.assertEqual([s["id"] for s in reduced["steps"]], ["s012", "s013", "s014", "s015"])
            self.assertEqual(json.loads((replay / "plan.json").read_text()), reduced)
            self.assertEqual(probe.replay_fixture(replay / "plan.json"), fixture)
            receipt = json.loads((replay / "reduction.json").read_text())
            self.assertTrue(receipt["accepted"])
            self.assertEqual(receipt["target"]["id"], "s015")
            names = reference.names + candidate.names
            self.assertGreater(len(names), 2)
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(reference.events.count("volume-remove"), len(reference.names))
            self.assertEqual(candidate.events.count("volume-remove"), len(candidate.names))
            self.assertEqual(candidate.events.count("container-remove"), 2 * len(candidate.names))
            before = len(candidate.names)
            budgeted, _ = probe.reduce_endpoints(
                plan, fixture, reference, candidate, "shared", root=root, max_attempts=1,
            )
            self.assertEqual(budgeted, plan)
            self.assertEqual(len(candidate.names), before + 1)
            self.assertTrue((replay / "docker-shared.jsonl").exists())
            self.assertTrue((replay / "cengine-shared.jsonl").exists())
            # A different filesystem mismatch cannot replace the original one.
            wrong = copy.deepcopy(receipt["target"])
            wrong["differences"][0]["actual"]["value"] = 99
            with self.assertRaisesRegex(ValueError, "initial plan does not reproduce"):
                probe.reduce_endpoints(plan, fixture, reference, candidate, "block",
                                       root=root, signature=wrong)

    def test_endpoint_reduction_does_not_accept_transport_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = probe.generate(5, 1)
            fixture = synthetic_fixture()
            directory, _ = probe.prepare_artifacts(plan, root=root, fixture=fixture)
            reference, candidate = FakeClient(directory), FakeClient(directory, fail=True)
            with self.assertRaisesRegex(RuntimeError, "synthetic transport failure"):
                probe.reduce_endpoints(plan, fixture, reference, candidate, "block", root=root)
            self.assertEqual(candidate.events[-2:], ["container-remove", "volume-remove"])
            self.assertEqual(len(reference.names), 1)
            self.assertEqual(len(candidate.names), 1)
            candidate.fail = False
            with self.assertRaisesRegex(ValueError, "initial plan does not reproduce"):
                probe.reduce_endpoints(plan, fixture, reference, candidate, "block", root=root)

    def test_mismatch_signature_ignores_equal_state_not_raw_differences(self):
        expected = [{"id": "s003", "result": {"entries": {
            "unrelated": {"nlink": 1}, "fd:f": {"nlink": 0}}}, "peer": None}]
        actual = copy.deepcopy(expected)
        actual[0]["result"]["entries"]["fd:f"]["nlink"] = 1
        signature = probe.mismatch_signature(expected, actual)
        for rows in (expected, actual):
            del rows[0]["result"]["entries"]["unrelated"]
        self.assertEqual(probe.mismatch_signature(expected, actual), signature)
        self.assertEqual(signature["differences"][0]["path"], ["result", "entries", "fd:f", "nlink"])
        actual[0]["result"]["entries"]["sillyrename"] = {"nlink": 1}
        self.assertNotEqual(probe.mismatch_signature(expected, actual), signature)
        missing = probe.mismatch_signature(expected, actual)["differences"][1]
        self.assertEqual(missing["expected"], {"present": False, "value": None})

    def test_mismatch_signature_requires_aligned_observations(self):
        self.assertIsNone(probe.mismatch_signature([], []))
        for actual in ([], [{"id": "s001"}]):
            with self.assertRaisesRegex(ValueError, "matching step IDs"):
                probe.mismatch_signature([{"id": "s000"}], actual)

    def test_artifact_identity_and_outside_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "small"
            regular.write_bytes(b"12345")
            with self.assertRaises(ValueError):
                probe.read_bounded(regular, 4)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                probe.read_bounded(fifo, 10)
            fixture = (b"immutable-fixture", "sha256:synthetic")
            directory, image = probe.prepare_artifacts(probe.generate(1), root=root / "artifacts", fixture=fixture)
            self.assertEqual(probe.replay_fixture(directory / "plan.json"), fixture)
            self.assertEqual(image, fixture[1])
            (directory / "fixture.tar").write_bytes(b"corrupt")
            with self.assertRaises(ValueError):
                probe.replay_fixture(directory / "plan.json")
            with self.assertRaises(ValueError):
                probe.prepare_artifacts(probe.generate(1), root=root / "daemon" / "artifacts", daemon_root=root / "daemon", fixture=fixture)

    def test_existing_unowned_volume_is_never_used_or_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan = probe.generate(1, 1)
            directory, image = probe.prepare_artifacts(
                plan, root=Path(temporary), fixture=synthetic_fixture(),
            )
            client = FakeClient(directory)
            client.volumes.create = lambda *args, **kwargs: SimpleNamespace(
                attrs={"Labels": {}}, remove=lambda: self.fail("unowned volume deleted"),
            )
            with self.assertRaisesRegex(RuntimeError, "without run ownership"):
                probe.execute(client, plan, image, "block", directory, "docker")
            self.assertEqual(client.events, ["load", "inspect"])

    def test_create_timeout_after_server_commit_reconciles_exact_owned_names(self):
        for kind, create_index in (("volume", 0), ("container", 0), ("container", 1)):
            with self.subTest(kind=kind, index=create_index), tempfile.TemporaryDirectory() as temporary:
                plan = probe.generate(1, 1)
                directory, image = probe.prepare_artifacts(plan, root=Path(temporary), fixture=synthetic_fixture())
                client = FakeClient(directory)
                collection = client.volumes if kind == "volume" else client.containers
                create = collection.create
                calls = 0

                def timeout_after_create(*args, **kwargs):
                    nonlocal calls
                    resource = create(*args, **kwargs)
                    calls += 1
                    if calls == create_index + 1:
                        # The server committed, but the SDK never returns the object.
                        raise TimeoutError("client timed out after server create")
                    return resource

                collection.create = timeout_after_create
                # Even ambient resources with the same label key must be untouched.
                ambient = SimpleNamespace(remove=lambda **kw: self.fail("ambient resource removed"))
                client.server_volumes["ambient"] = ambient
                client.server_containers["ambient"] = ambient
                with self.assertRaisesRegex(TimeoutError, "after server create"):
                    probe.execute(client, plan, image, "shared", directory, "docker")
                self.assertEqual(client.server_volumes, {"ambient": ambient})
                self.assertEqual(client.server_containers, {"ambient": ambient})
                journal = [json.loads(line) for line in (directory / "docker-shared.jsonl").read_text().splitlines()]
                volume_name = next(row["name"] for row in journal if row["phase"] == "before-volume-create")
                container_names = [row["name"] for row in journal if row["phase"] == "before-container-create"]
                self.assertEqual(client.lookups, [("container", name) for name in reversed(container_names)]
                                 + [("volume", volume_name)])
                self.assertEqual(len(container_names), 0 if kind == "volume" else create_index + 1)
                self.assertEqual(client.events[-len(container_names) - 1:],
                                 ["container-remove"] * len(container_names) + ["volume-remove"])
                self.assertNotIn("start", client.events)
                self.assertEqual(journal[-1], {"phase": "cleanup", "errors": []})

    def test_create_timeout_cleanup_refuses_wrong_owner_or_nonexact_name(self):
        for kind in ("volume", "container"):
            for mismatch in ("owner", "name"):
                with self.subTest(kind=kind, mismatch=mismatch), tempfile.TemporaryDirectory() as temporary:
                    plan = probe.generate(1, 1)
                    directory, image = probe.prepare_artifacts(plan, root=Path(temporary), fixture=synthetic_fixture())
                    client = FakeClient(directory)
                    collection = client.volumes if kind == "volume" else client.containers
                    create = collection.create

                    def timeout_after_create(*args, **kwargs):
                        resource = create(*args, **kwargs)
                        if mismatch == "owner":
                            labels = resource.attrs["Labels"] if kind == "volume" else resource.attrs["Config"]["Labels"]
                            labels["dev.cengine.compat.volume-hunt"] = "another-run"
                        else:
                            resource.name += "-not-exact"
                        resource.remove = lambda **kw: self.fail("unowned/nonexact resource removed")
                        raise TimeoutError("ambiguous create")

                    collection.create = timeout_after_create
                    with self.assertRaisesRegex(TimeoutError, "ambiguous create"):
                        probe.execute(client, plan, image, "block", directory, "docker")
                    self.assertNotIn(kind + "-remove", client.events)
                    journal = [json.loads(line) for line in (directory / "docker-block.jsonl").read_text().splitlines()]
                    self.assertEqual(len(journal[-1]["errors"]), 1)
                    self.assertIn("exact name and run ownership", journal[-1]["errors"][0])

    def test_create_timeout_before_server_commit_tolerates_exact_name_not_found(self):
        for kind in ("volume", "container"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                plan = probe.generate(1, 1)
                directory, image = probe.prepare_artifacts(plan, root=Path(temporary), fixture=synthetic_fixture())
                client = FakeClient(directory)
                collection = client.volumes if kind == "volume" else client.containers
                with patch.object(collection, "create", side_effect=TimeoutError("before create")):
                    with self.assertRaisesRegex(TimeoutError, "before create"):
                        probe.execute(client, plan, image, "block", directory, "docker")
                self.assertEqual(client.server_volumes, {})
                self.assertEqual(client.server_containers, {})
                journal = [json.loads(line) for line in (directory / "docker-block.jsonl").read_text().splitlines()]
                self.assertEqual(journal[-1], {"phase": "cleanup", "errors": []})

    def test_cleanup_failures_raise_or_preserve_original_error(self):
        for fail in (False, True):
            with self.subTest(operation_failed=fail), tempfile.TemporaryDirectory() as temporary:
                plan = probe.generate(1, 1)
                directory, image = probe.prepare_artifacts(plan, root=Path(temporary), fixture=synthetic_fixture())
                client = FakeClient(directory, fail=fail, cleanup_fail=True)
                message = "synthetic transport failure" if fail else "volume probe cleanup failed"
                with self.assertRaisesRegex(RuntimeError, message):
                    probe.execute(client, plan, image, "shared", directory, "docker")
                self.assertEqual(client.events[-3:], ["container-remove", "container-remove", "volume-remove"])
                journal = [json.loads(line) for line in (directory / "docker-shared.jsonl").read_text().splitlines()]
                self.assertEqual(journal[-1]["phase"], "cleanup")
                self.assertEqual(len(journal[-1]["errors"]), 3)
                self.assertEqual(any(row["phase"] == "error" for row in journal), fail)

    def test_image_inspection_uses_tag_and_source_identity_including_legacy_replay(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory() as temporary:
                plan = probe.generate(1, 1)
                fixture = synthetic_fixture(legacy=legacy)
                directory, image = probe.prepare_artifacts(plan, root=Path(temporary), fixture=fixture)
                self.assertEqual(probe.replay_fixture(directory / "plan.json"), fixture)
                client = FakeClient(directory)
                probe.execute(client, plan, image, "block", directory, "docker")
                self.assertIn("create", client.events)
                for field, value in (("RootFS", {"Type": "layers", "Layers": []}),
                                     ("Config", {"Cmd": ["wrong"]}), ("Architecture", "amd64")):
                    bad = FakeClient(directory)
                    bad.image_attrs[field] = value
                    with self.subTest(field=field), self.assertRaisesRegex(ValueError, "source config/RootFS"):
                        probe.execute(bad, plan, image, "block", directory, "wrong")
                    self.assertNotIn("volume", bad.events)
                with self.assertRaisesRegex(ValueError, "config identity"):
                    probe.fixture_identity(fixture[0], "sha256:wrong")

    def test_fixture_source_bytes_reject_changed_layers_and_tags(self):
        archive, image = synthetic_fixture()
        with probe.tarfile.open(fileobj=probe.io.BytesIO(archive)) as saved:
            entries = [(member.name, saved.extractfile(member).read(), member.mode)
                       for member in saved.getmembers()]
        for target, replacement, message in (
                ("layer.tar", b"different rootfs", "layer identity"),
                ("manifest.json", probe.encode([{
                    "Config": entries[0][0], "RepoTags": ["unrelated:latest"],
                    "Layers": ["layer.tar"]}]), "content-derived tag"),
                (entries[0][0], entries[0][1] + b" ", "content-derived tag")):
            changed = probe.tar_bytes([(name, replacement if name == target else data, mode)
                                       for name, data, mode in entries])
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, message):
                probe.fixture_identity(changed, image)

    def test_endpoint_neutral_order_cleanup_and_backend_proof(self):
        for storage, consumers in (("block", 1), ("shared", 2)):
            with self.subTest(storage=storage), tempfile.TemporaryDirectory() as temporary:
                plan = probe.generate(1, 12)
                directory, image = probe.prepare_artifacts(plan, root=Path(temporary), fixture=synthetic_fixture())
                clients = [FakeClient(directory), FakeClient(directory)]
                expected = probe.execute(clients[0], plan, image, storage, directory, "docker")
                actual = probe.execute(clients[1], plan, image, storage, directory, "cengine", backend_proof=lambda n: storage)
                self.assertEqual(actual, expected)
                self.assertEqual(clients[0].events, clients[1].events)
                self.assertEqual(clients[1].events[:3 + 2 * consumers], ["load", "inspect", "volume"] + ["create"] * consumers + ["start"] * consumers)
                self.assertEqual(clients[1].events[-consumers - 1:], ["container-remove"] * consumers + ["volume-remove"])
                self.assertEqual(len(actual), 12)
                self.assertEqual(clients[1].events.count("exec"), 12 * consumers)
                self.assertEqual(actual[0]["peer"], {"errno": 0, "entries": {}} if storage == "shared" else None)
                self.assertNotIn("physical-", json.dumps(actual))
                self.assertNotIn("test_boundary", json.dumps(actual))
                for label, candidate in (("docker", False), ("cengine", True)):
                    journal = [json.loads(line) for line in (directory / f"{label}-{storage}.jsonl").read_text().splitlines()]
                    proofs = [row["proof"] for row in journal if row["phase"] == "backend-proof"]
                    self.assertEqual(len(proofs), consumers * (1 + sum(step["op"] == "restart" for step in plan["steps"])))
                    self.assertTrue(all(value["candidate"] == candidate and value["topology"] == storage for value in proofs))
                failed = FakeClient(directory, fail=True)
                with self.assertRaisesRegex(RuntimeError, "synthetic transport"):
                    probe.execute(failed, plan, image, storage, directory, "failure")
                self.assertEqual(failed.events[-1], "volume-remove")
                with self.assertRaisesRegex(AssertionError, "expected"):
                    probe.execute(FakeClient(directory), plan, image, storage, directory, "wrong", backend_proof=lambda n: "wrong")


@unittest.skipUnless(importlib.util.find_spec("docker") and importlib.util.find_spec("pytest"),
                     "requires compatibility Python environment (Docker SDK, not daemon)")
class BackendMountTests(unittest.TestCase):
    def test_actual_mount_dispatch_and_verifier_preserve_historical_archive(self):
        import storage_backend_proof as backend
        import test_volume_corpus as corpus

        historical_source = ROOT / "Tests/Compatibility/fixtures/volume-probe.go"
        original_source_hash = "22c1924ab536f3e7b3ce27415a7bf594cb9698f03b9083199df7bc86845a4db0"
        helper_source_hash = "26978339fb655019c31cfc23815a38b1c1e42013ce140156804dc278c0a4d336"
        self.assertEqual(hashlib.sha256(historical_source.read_bytes()).hexdigest(), original_source_hash)
        self.assertEqual(hashlib.sha256(probe.MOUNT_PROBE_SOURCE).hexdigest(), helper_source_hash)
        for candidate, storage in ((False, "block"), (False, "shared"),
                                   (True, "block"), (True, "shared")):
            with self.subTest(candidate=candidate, storage=storage), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                root = work / "root"
                root.mkdir()
                self.addCleanup(backend._ROOT_PINS.pop, str(root), None)
                with patch.dict(os.environ):
                    os.environ.pop("CENGINE_COMPAT_MANAGED_STORAGE", None)
                    os.environ.pop("CENGINE_CORPUS_SHARED_FS", None)
                    os.environ["CENGINE_BINARY"] = str(Path("/bin/true").resolve())
                    (work / ".cengine-compat-owner").write_text(os.environ["CENGINE_BINARY"])
                    mode_file = create_backend(root)
                    selection = json.loads(mode_file.read_bytes())
                    fixture = synthetic_fixture(legacy=True)
                    directory, image = probe.prepare_artifacts(probe.generate(1, 1), root=work / "artifacts", fixture=fixture)
                    archived = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                                for name in ("fixture.tar", "fixture.json", "plan.json")}
                    text = ("35 20 0:44 / /data rw - fuse.managed-v3 managed-v3 rw\n"
                            if candidate and storage == "shared" else
                            "35 20 254:16 / /data rw - ext4 /proc/self/fd/5 rw\n")
                    payload = b"synthetic-linux-binary-never-executed"
                    command = "cengine-backend-proof-" + hashlib.sha256(payload).hexdigest()
                    events, streams, records = [], [], []

                    def build(argv, **kwargs):
                        self.assertEqual(kwargs["env"]["GOOS"], "linux")
                        self.assertEqual(kwargs["env"]["GOARCH"], "arm64")
                        self.assertEqual(kwargs["env"]["CGO_ENABLED"], "0")
                        self.assertEqual(kwargs["env"]["GOPROXY"], "off")
                        self.assertEqual(Path(argv[-1]).read_bytes(), probe.MOUNT_PROBE_SOURCE)
                        Path(argv[argv.index("-o") + 1]).write_bytes(payload)

                    def install(destination, archive):
                        self.assertEqual(destination, "/")  # Never the volume.
                        with probe.tarfile.open(fileobj=probe.io.BytesIO(archive)) as saved:
                            self.assertEqual(saved.getnames(), [command])
                            self.assertEqual(saved.extractfile(command).read(), payload)
                            member = saved.getmember(command)
                            self.assertTrue(member.isfile())
                            self.assertEqual((member.mode, member.uid, member.gid), (0o555, 0, 0))
                        events.append("archive")
                        return True

                    def create(container_id, argv, **kwargs):
                        self.assertEqual(container_id, "owned")
                        self.assertEqual(argv, ["/" + command])  # Not /probe request.
                        self.assertEqual(kwargs, {"stdout": True, "stderr": True})
                        events.append("create")
                        return {"Id": "mount-exec"}

                    def start(identity, **kwargs):
                        self.assertEqual(identity, "mount-exec")
                        self.assertEqual(kwargs, {"socket": True})
                        events.append("start")
                        stream = FakeSocket([frame(1, probe.encode(text))])
                        streams.append(stream)
                        return stream

                    def inspect(identity):
                        self.assertEqual(identity, "mount-exec")
                        self.assertTrue(streams[-1].closed)
                        events.append("inspect")
                        return {"ExitCode": 0}

                    api = SimpleNamespace(timeout=180, exec_create=create, exec_start=start, exec_inspect=inspect,
                                          adapters={"http+docker://": SimpleNamespace(socket_path=str(work / "run/docker.sock"))})
                    client = SimpleNamespace(api=api)
                    container = SimpleNamespace(id="owned", client=client, put_archive=install)
                    # Only the HTTP watchdog is outside this fake transport's
                    # scope; real SocketIO/deadline coverage remains elsewhere.
                    with patch.object(probe.subprocess, "run", side_effect=build), \
                            patch.object(corpus, "api_deadline", side_effect=lambda *args: nullcontext()):
                        probe.record_backend_mounts(client, [container], directory, storage, records.append, candidate=candidate)
                    self.assertEqual(events, ["archive", "create", "start", "inspect"])
                    self.assertEqual(api.timeout, 180)
                    self.assertEqual([row["phase"] for row in records], ["backend-probe-fixture", "mountinfo", "backend-proof"])
                    self.assertEqual(records[1]["raw"], text)
                    value = records[2]["proof"]
                    self.assertEqual(value["mount"]["raw"], text.rstrip())
                    if candidate:
                        self.assertEqual(value["topology"], storage)
                        self.assertEqual(value["mode"], "lifecycle")
                        self.assertEqual(value["root_identity"], selection["root"])
                        self.assertEqual(value["lifecycle_manifest_sha256"], hashlib.sha256(mode_file.read_bytes()).hexdigest())
                    else:
                        self.assertEqual(value["reference"], "Docker local-volume control")
                    self.assertEqual(records[0]["source_sha256"], helper_source_hash)
                    self.assertEqual(records[0]["binary_sha256"], hashlib.sha256(payload).hexdigest())
                    self.assertEqual(records[0]["archive_sha256"], hashlib.sha256((directory / "backend-probe.tar").read_bytes()).hexdigest())
                    self.assertEqual(probe.replay_fixture(directory / "plan.json"), fixture)
                    self.assertEqual(image, fixture[1])
                    self.assertEqual(archived, {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in archived})
        self.assertEqual(hashlib.sha256(historical_source.read_bytes()).hexdigest(), original_source_hash)

    def test_actual_mount_proof_rejects_foreign_owner_root_and_backend(self):
        import storage_backend_proof as backend

        for failure in ("missing-owner", "foreign-owner", "foreign-uid", "wrong-backend"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ):
                work = Path(temporary)
                root = work / "root"
                root.mkdir()
                self.addCleanup(backend._ROOT_PINS.pop, str(root), None)
                os.environ.pop("CENGINE_COMPAT_MANAGED_STORAGE", None)
                os.environ.pop("CENGINE_CORPUS_SHARED_FS", None)
                os.environ["CENGINE_BINARY"] = str(Path("/bin/true").resolve())
                marker = work / ".cengine-compat-owner"
                if failure != "missing-owner":
                    marker.write_text("/foreign/binary" if failure == "foreign-owner" else os.environ["CENGINE_BINARY"])
                create_backend(root)
                text = ("35 20 254:16 / /data rw - ext4 /proc/self/fd/5 rw\n" if failure == "wrong-backend" else
                        "35 20 0:44 / /data rw - fuse.managed-v3 managed-v3 rw\n")
                api = SimpleNamespace(adapters={"http+docker://": SimpleNamespace(socket_path=str(work / "run/docker.sock"))})
                client = SimpleNamespace(api=api)
                installs, records = [], []
                container = SimpleNamespace(id="owned", client=client,
                                            put_archive=lambda *args: installs.append(args) or True)
                # No chown/elevation: make the real verifier see a different
                # effective UID while retaining the actual directory's stat UID.
                uid = patch.object(backend.os, "geteuid", return_value=os.geteuid() + 1) if failure == "foreign-uid" else nullcontext()
                expected = FileNotFoundError if failure == "missing-owner" else ValueError
                with uid, patch.object(probe, "_mount_probe_archive", return_value=("helper", b"archive", {})), \
                        patch.object(probe, "_mount_probe", return_value=text) as execute:
                    with self.assertRaises(expected):
                        probe.record_backend_mounts(client, [container], work, "shared", records.append, candidate=True)
                    if failure in ("missing-owner", "foreign-owner"):
                        execute.assert_not_called()
                        self.assertEqual(installs, [])
                    else:
                        execute.assert_called_once_with(container, "helper")
                self.assertFalse(any(row["phase"] == "backend-proof" for row in records))

    def test_failed_mount_helper_install_never_executes(self):
        container = SimpleNamespace(put_archive=lambda *args: False)
        with patch.object(probe, "_mount_probe_archive", return_value=("helper", b"archive", {})), \
                patch.object(probe, "_mount_probe") as execute:
            with self.assertRaisesRegex(RuntimeError, "cannot install separate"):
                probe.record_backend_mounts(None, [container], None, "block", lambda value: None, candidate=False)
        execute.assert_not_called()


class NativeProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="vp-", dir="/tmp")
        cls.root = Path(cls.temporary.name)
        cls.binary = cls.root / "probe"
        subprocess.run(["go", "build", "-trimpath", "-o", str(cls.binary),
                        str(ROOT / "Tests/Compatibility/fixtures/volume-probe.go")],
                       env={**os.environ, "CGO_ENABLED": "0", "GOWORK": "off"}, check=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_native_descriptor_rename_link_unlink_and_restart(self):
        mount = self.root / "data"
        mount.mkdir()
        (mount / "lost+found").mkdir()
        data = mount / "probe-tree"  # serve must bootstrap this child itself.
        socket = self.root / "socket"

        def start():
            return subprocess.Popen([str(self.binary), "serve", str(data), str(socket)])

        def request(step):
            result = subprocess.run([str(self.binary), "request", probe.encode(step).decode(), str(socket)], capture_output=True, check=True, timeout=40)
            return json.loads(result.stdout)

        process = start()
        observations = []
        try:
            for step in probe.generate(5, 12)["steps"]:
                if step["op"] == "restart":
                    process.terminate()
                    self.assertEqual(process.wait(timeout=10), 0)
                    process = start()
                    step = {"op": "snapshot"}
                result = request(step)
                self.assertEqual(result["errno"], 0, step)
                observations.append(result["entries"])
            linked = observations[3]
            self.assertEqual(linked["path:file0-link"]["same_as"], linked["fd:file0"]["same_as"])
            self.assertEqual(linked["fd:file0"]["nlink"], 2)
            self.assertEqual(set(observations[7]), {"fd:file0"})
            self.assertEqual(observations[7]["fd:file0"]["nlink"], 0)
            self.assertEqual(observations[8]["fd:file0"]["sha256"], hashlib.sha256(b"seed-9f767c45-open-unlinked").hexdigest())
            self.assertEqual(observations[9], {})
            self.assertEqual(observations[10], observations[11])
            self.assertTrue((mount / "lost+found").is_dir())
            # Never hide workload entries, including empty/nonempty lost+found
            # directories or a symlink bearing that name.
            special = data / "lost+found"
            special.mkdir()
            self.assertIn("path:lost+found", request({"op": "snapshot"})["entries"])
            (special / "evidence").write_text("keep")
            self.assertIn("path:lost+found", request({"op": "snapshot"})["entries"])
            (special / "evidence").unlink()
            special.rmdir()
            special.symlink_to(mount / "lost+found")
            self.assertIn("path:lost+found", request({"op": "snapshot"})["entries"])
            special.unlink()
            self.assertNotEqual(request({"op": "create", "path": "../escape", "data": "x"})["errno"], 0)
            self.assertFalse((self.root / "escape").exists())
            self.assertNotEqual(request({"op": "close", "fd": "absent"})["errno"], 0)
            escaped = {"id": "s000", "needs": [], "op": "create", "path": "escaped", "data": "\u0000" * 3000}
            probe.validate({"version": 1, "seed": 0, "steps": [escaped]})
            self.assertGreater(len(probe.encode(escaped)), 16384)
            self.assertEqual(request(escaped)["errno"], 0)
            self.assertEqual((data / "escaped").read_bytes(), bytes(3000))
            malformed = subprocess.run([str(self.binary), "request", "{", str(socket)], capture_output=True, check=True, timeout=40)
            self.assertIn("protocol_error", json.loads(malformed.stdout))
        finally:
            process.terminate()
            process.wait(timeout=10)

    def test_request_reads_one_json_reply_without_waiting_for_eof(self):
        # Regression for io.Copy's Linux splice path: a complete reply is enough,
        # regardless of whether the peer subsequently closes cleanly or resets.
        address = self.root / "reply.sock"
        release = threading.Event()
        failures = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(address))
            listener.listen(1)
            listener.settimeout(5)

            def reply():
                try:
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(5)
                        while conn.recv(65536):
                            pass  # request must half-close even for malformed JSON
                        conn.sendall(b'{"errno":0,"entries":{}}\n')
                        if not release.wait(5):
                            failures.append("request waited for EOF")
                except Exception as error:
                    failures.append(str(error))

            worker = threading.Thread(target=reply)
            worker.start()
            try:
                result = subprocess.run(
                    [str(self.binary), "request", '{"op":"snapshot"}', str(address)],
                    capture_output=True, timeout=3, check=True,
                )
                self.assertEqual(json.loads(result.stdout), {"errno": 0, "entries": {}})
                self.assertEqual(result.stderr, b"")
            finally:
                release.set()
                worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])

    def test_linux_fixture_archive_is_content_addressed(self):
        build = self.root / "linux-build"
        build.mkdir()
        archive, image = probe.build_fixture(build)
        with probe.tarfile.open(fileobj=probe.io.BytesIO(archive)) as saved:
            manifest = json.load(saved.extractfile("manifest.json"))[0]
            config = saved.extractfile(manifest["Config"]).read()
            self.assertEqual(image, "compat-volume-probe:" + hashlib.sha256(config).hexdigest())
            self.assertEqual(manifest["RepoTags"], [image])
            self.assertEqual(json.loads(config)["config"]["Cmd"], ["/probe", "serve", "/data/probe-tree", "/probe.sock"])
            self.assertEqual(probe.fixture_identity(archive, image)[0], image)
            self.assertEqual(json.loads(config)["architecture"], "arm64")
            layer = saved.extractfile("layer.tar").read()
            self.assertEqual(json.loads(config)["rootfs"]["diff_ids"], ["sha256:" + hashlib.sha256(layer).hexdigest()])


if __name__ == "__main__":
    unittest.main()
