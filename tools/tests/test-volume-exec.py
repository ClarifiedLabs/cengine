#!/usr/bin/env python3
"""Engine-free RTM-086 regressions: subprocesses and all Docker operations are mocked."""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from lifecycle_backend_fixture import create_backend

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import storage_backend_proof as backend
import test_volume_exec as campaign

source = campaign.SOURCE
probe = ModuleType("volume_exec_guest_test")
exec(compile(source.read_bytes(), str(source), "exec"), probe.__dict__)


def outcome(filesystem="ext4", mount_root="/", mount_source="/dev/vdb", options="rw"):
    cases = [{"name": "script", "argv": ["/tmp/rtm086/script"], "exit": 0, "output": "rtm086-script\n"},
             {"name": "echo", "argv": ["/tmp/rtm086/echo", "rtm086-elf"], "exit": 0, "output": "rtm086-elf\n"},
             {"name": "script-noexec", "argv": ["/tmp/rtm086/script-noexec"], "errno": 13},
             {"name": "echo-noexec", "argv": ["/tmp/rtm086/echo-noexec", "rtm086-elf"], "errno": 13}]
    return {"schema": 1, "uid": 10001, "gid": 10001,
            "capabilities": {key: 0 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
            "elf_sha256": "a" * 64, "cases": cases,
            "mountinfo": f"2 1 0:44 {mount_root} /tmp {options} - {filesystem} {mount_source} rw,vers=3\n"}


@contextmanager
def selected_root(root, mode="lifecycle"):
    key = str(root.absolute())
    with patch.dict(os.environ):
        os.environ.pop("CENGINE_COMPAT_MANAGED_STORAGE", None)
        os.environ.pop("CENGINE_CORPUS_SHARED_FS", None)
        assert mode == "lifecycle"
        create_backend(root)
        try:
            yield SimpleNamespace(root=root, process=SimpleNamespace(args=["daemon"]))
        finally:
            backend._ROOT_PINS.pop(key)


class ProbeTests(unittest.TestCase):
    def test_direct_path_and_raw_errno_no_fallback(self):
        for name, arguments in probe.CASES:
            for code in (errno.EINVAL, errno.EACCES):
                with self.subTest(name=name, errno=code), \
                        patch.object(probe.tempfile, "TemporaryFile", return_value=io.BytesIO()), \
                        patch.object(probe.subprocess, "Popen", side_effect=OSError(code, "injected")) as spawn:
                    result = probe.run_case(name, arguments)
                self.assertEqual(result["errno"], code)
                spawn.assert_called_once()
                self.assertEqual(spawn.call_args.args[0], ["/tmp/rtm086/" + name, *arguments])
                self.assertNotIn("shell", spawn.call_args.kwargs)
                self.assertTrue(spawn.call_args.kwargs["start_new_session"])
                self.assertTrue(spawn.call_args.kwargs["close_fds"])

    def test_exact_success_timeout_and_output_bound(self):
        process = Mock(pid=123, poll=Mock(return_value=0), wait=Mock(return_value=0))
        for payload, accepted in ((b"rtm086-elf\n", True), (b"x" * (probe.MAX_OUTPUT + 1), False)):
            with patch.object(probe.tempfile, "TemporaryFile", return_value=io.BytesIO(payload)), \
                    patch.object(probe.subprocess, "Popen", return_value=process):
                if accepted:
                    result = probe.run_case("echo", ["rtm086-elf"])
                    self.assertEqual((result["exit"], result["output"]), (0, payload.decode()))
                else:
                    with self.assertRaises(ValueError):
                        probe.run_case("echo", ["rtm086-elf"])
        process.poll.return_value = None
        process.wait.side_effect = [probe.subprocess.TimeoutExpired("fixture", 5), -9]
        with patch.object(probe.tempfile, "TemporaryFile", return_value=io.BytesIO()), \
                patch.object(probe.subprocess, "Popen", return_value=process), \
                patch.object(probe.os, "killpg") as kill, self.assertRaises(probe.subprocess.TimeoutExpired):
            probe.run_case("script", [])
        kill.assert_called_once_with(123, probe.signal.SIGKILL)
        self.assertEqual(process.wait.call_args.kwargs, {"timeout": 5})

    def test_refuses_wrong_elf_and_oversized_reads_without_spawn(self):
        with patch.object(probe.subprocess, "Popen") as spawn:
            for data in (b"#!not-ELF", b"\x7fELF\x02\x01" + b"\0" * 58):
                with patch.object(probe, "read_bounded", return_value=data), \
                        patch.object(probe, "ROOT") as root, self.assertRaises(ValueError):
                    probe.prepare(True)
                root.mkdir.assert_not_called()
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "data"
                path.write_bytes(b"12345")
                self.assertEqual(probe.read_bounded(path, 5), b"12345")
                with self.assertRaises(ValueError):
                    probe.read_bounded(path, 4)
            spawn.assert_not_called()

    def test_rejects_unknown_case_before_any_io(self):
        with patch.object(probe.tempfile, "TemporaryFile") as capture, self.assertRaises(ValueError):
            probe.run_case("../escape", [])
        capture.assert_not_called()


class EvidenceTests(unittest.TestCase):
    def test_rejects_einval_missing_cases_interpreter_bypass_and_false_permissions(self):
        campaign.validate_result(outcome())
        for index in range(4):
            bad = outcome()
            bad["cases"][index] = {**bad["cases"][index], "errno": errno.EINVAL}
            with self.subTest(index=index), self.assertRaises(AssertionError):
                campaign.validate_result(bad)
        for mutation in (lambda value: value["cases"].pop(),
                         lambda value: value["cases"][0]["argv"].insert(0, "/bin/sh"),
                         lambda value: value["cases"][2].update(errno=errno.EPERM),
                         lambda value: value["capabilities"].update(CapEff=1),
                         lambda value: value.update(uid=0)):
            bad = outcome()
            mutation(bad)
            with self.assertRaises(AssertionError):
                campaign.validate_result(bad)

    def test_real_durable_backend_and_topology_proof(self):
        for mode, topology, value in (("lifecycle", "block", outcome()),
                ("lifecycle", "shared", outcome("fuse.managed-v3", "/", "managed-v3"))):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with selected_root(root, mode) as daemon:
                    (root / "volume-storage.json").write_text(json.dumps({"owned": topology}))
                    proof = campaign.backend_proof(daemon, "owned", topology, value)
                    self.assertEqual(proof["mode"], mode)
                    self.assertEqual(proof["lifecycle_manifest_sha256"], hashlib.sha256(
                        (root / "managed-storage-owner/manifest.json").read_bytes()).hexdigest())
                    for bad in (outcome("tmpfs"), outcome(options="rw,noexec")):
                        with self.assertRaises((ValueError, AssertionError)):
                            campaign.backend_proof(daemon, "owned", topology, bad)
                    with self.assertRaises(AssertionError):
                        campaign.backend_proof(daemon, "missing", topology, value)

    def test_existing_pinned_fixture_image(self):
        self.assertEqual(campaign.IMAGE, campaign.workflow.wheels.IMAGE)
        self.assertTrue(probe.SCRIPT.startswith(b"#!/bin/sh\n"))
        # The pinned /bin/echo is BusyBox: argv[0] must retain the applet name.
        self.assertIn(("echo", ["rtm086-elf"]), probe.CASES)
        self.assertLessEqual(2 * probe.MAX_BINARY + len(probe.SCRIPT) * 2, 3 * 1024 * 1024)


class LifecycleTests(unittest.TestCase):
    def test_cleanup_refuses_wrong_owner_and_continues_after_remove_failure(self):
        token = "a" * 32
        resources = {}
        for name, owner in (("owned", token), ("foreign", "b" * 32)):
            resources[name] = SimpleNamespace(name=name, attrs={"Config": {"Labels": {campaign.OWNER: owner}}}, remove=Mock())
        resources["owned"].remove.side_effect = RuntimeError("injected removal failure")
        volume = SimpleNamespace(name="volume", attrs={"Labels": {campaign.OWNER: token}}, remove=Mock())
        client = SimpleNamespace(containers=SimpleNamespace(get=resources.__getitem__),
                                 volumes=SimpleNamespace(get=lambda name: volume))
        names = [("volume", "volume"), ("container", "owned"), ("container", "foreign")]
        with patch.object(campaign.workflow, "api_deadline", side_effect=lambda *a: nullcontext()):
            errors = campaign.cleanup(client, names, token)
        self.assertEqual(len(errors), 2)
        self.assertIn("wrong cleanup owner", errors[0])
        self.assertIn("injected removal failure", errors[1])
        resources["foreign"].remove.assert_not_called()
        resources["owned"].remove.assert_called_once_with(force=True)
        volume.remove.assert_called_once_with()

    def test_serial_topology_limits_cleanup_and_failure_evidence(self):
        import docker
        for fail in (False, True, "create"):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                objects, events = {}, []
                client = Mock()
                client.images.get.return_value.attrs = {"Os": "linux", "Architecture": "arm64", "RepoDigests": [campaign.IMAGE]}
                def create(kind, name, **kwargs):
                    events.append(("create", kind, name, kwargs))
                    labels = kwargs["labels"]
                    attrs = {"Config": {"Labels": labels}} if kind == "container" else {"Labels": labels}
                    def remove(**options):
                        events.append(("remove", kind, name))
                        del objects[name]
                    value = SimpleNamespace(name=name, attrs=attrs, remove=remove,
                        start=lambda: events.append(("start", kind, name)), wait=lambda **kw: {"StatusCode": 0})
                    objects[name] = value
                    if kind == "volume":
                        (root / "volume-storage.json").write_text(json.dumps({name: name.rsplit("-", 1)[1]}))
                    if fail == "create" and kind == "container":
                        raise TimeoutError("ambiguous create after publication")
                    return value
                client.volumes.create.side_effect = lambda name, **kw: create("volume", name, **kw)
                client.containers.create.side_effect = lambda image, **kw: create("container", **kw)
                def get(name):
                    if name not in objects:
                        raise docker.errors.NotFound("removed")
                    return objects[name]
                client.containers.get.side_effect = client.volumes.get.side_effect = get
                def logs(sdk, container, deadline):
                    shared = "-shared-" in container.name
                    value = outcome("fuse.managed-v3", "/", "managed-v3") if shared else outcome()
                    if fail:
                        value["cases"][0] = {"name": "script", "argv": ["/tmp/rtm086/script"], "errno": errno.EINVAL}
                    return json.dumps(value).encode(), b""
                with selected_root(root) as daemon, patch.object(docker, "DockerClient", return_value=client), \
                        patch.object(campaign, "__file__", str(root / "Tests/Compatibility/test_volume_exec.py")), \
                        patch.object(campaign.workflow, "api_call", side_effect=lambda sdk, deadline, op, *a, **kw: op(*a, **kw)), \
                        patch.object(campaign.workflow, "api_deadline", side_effect=lambda *a: nullcontext()), \
                        patch.object(campaign.workflow, "read_logs", side_effect=logs):
                    daemon.socket = root / "test.sock"
                    if fail:
                        with self.assertRaises(TimeoutError if fail == "create" else AssertionError):
                            campaign.run(daemon)
                    else:
                        campaign.run(daemon)
                self.assertFalse(objects)
                client.close.assert_called_once()
                client.images.pull.assert_not_called()
                for event in events:
                    if event[:2] == ("create", "container"):
                        config = event[3]
                        self.assertEqual(config["user"], "10001:10001")
                        self.assertEqual(config["cap_drop"], ["ALL"])
                        self.assertNotIn("cap_add", config)
                        self.assertEqual(config["pids_limit"], 16)
                        self.assertTrue(config["read_only"])
                        self.assertEqual(config["network_mode"], "none")
                        self.assertFalse(config["mounts"][0].get("VolumeOptions", {}).get("NoCopy", False))
                if not fail:
                    shared_creates = [i for i, e in enumerate(events) if e[:2] == ("create", "container") and "-shared-" in e[2]]
                    shared_starts = [i for i, e in enumerate(events) if e[0] == "start" and "-shared-" in e[2]]
                    self.assertEqual(len(shared_creates), 2)
                    self.assertLess(max(shared_creates), min(shared_starts))
                evidence = list((root / ".build/volume-hunt").glob("exec-*/evidence.jsonl"))
                records = [json.loads(line) for line in evidence[0].read_text().splitlines()]
                self.assertEqual(records[-1], {"phase": "cleanup", "errors": []})
                if fail == "create":
                    self.assertNotIn("result", [record["phase"] for record in records])
                    continue
                self.assertIn("backend", [record["phase"] for record in records])
                if fail:
                    self.assertNotIn("passed", [record["phase"] for record in records])
                    self.assertIn('"errno": 22', next(record["stdout"] for record in records if record["phase"] == "result"))


if __name__ == "__main__":
    unittest.main()
