#!/usr/bin/env python3
"""Engine-free safety/fixture checks: never executes wheels, guest main, Docker or VMs."""
from __future__ import annotations

import ast
import base64
import copy
from contextlib import contextmanager, nullcontext
import csv
import hashlib
import gzip
import io
import importlib.util
import json
import os
from pathlib import Path
import sys
import socket
import struct
import threading
import time
import tarfile
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

from lifecycle_backend_fixture import create_backend

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Tests/Compatibility/fixtures/volume-workflows"
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
sys.path.insert(0, str(ROOT / "tools"))
import compat_image_fixtures
SDK_AVAILABLE = all(importlib.util.find_spec(name) for name in ("docker", "pytest"))
import storage_backend_proof as backend_proof


def load(name):
    path = SOURCE / (name + ".py")
    module = ModuleType("workflow_test_" + name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


campaign, guest, wheels = (load(name) for name in ("campaign", "guest", "wheels"))
TOKEN = "a" * 32


class NotFound(Exception):
    status_code = 404


class FakeClient:
    def __init__(self):
        self.events, self.objects = [], {"container": {}, "volume": {}}
        self.guard = lambda: None
        self.containers = SimpleNamespace(get=lambda name: self.get("container", name))
        self.volumes = SimpleNamespace(get=lambda name: self.get("volume", name))

    def get(self, kind, name):
        self.guard()
        self.events.append(("get", kind, name))
        if name not in self.objects[kind]:
            raise NotFound()
        return self.objects[kind][name]

    def add(self, kind, name, token=TOKEN, failure=False):
        def remove(**kwargs):
            self.guard()
            self.events.append(("remove", kind, name, kwargs))
            if failure:
                raise RuntimeError("injected remove failure")
            del self.objects[kind][name]
        labels = {campaign.OWNER: token}
        attrs = {"Config": {"Labels": labels}} if kind == "container" else {"Labels": labels}
        resource = SimpleNamespace(name=name, attrs=attrs, remove=remove)
        self.objects[kind][name] = resource
        return resource


def member(name, kind=tarfile.REGTYPE, *, link="", size=0):
    value = tarfile.TarInfo(name)
    value.type, value.uid, value.gid, value.mode = kind, guest.UID, guest.UID, 0o700
    value.linkname, value.size = link, size
    return value


def outcome(action="identity"):
    expected = ["python-version", "pip-version"]
    return {"schema": 1, "action": action, "uid": 10001, "gid": 10001,
            "commands": [{"argv": guest.commands()[key], "exit": 0, "output": "version\n"} for key in expected],
            "mountinfo": ["1 0 0:1 / / ro - overlay overlay ro",
                          "2 1 8:1 / /work rw - ext4 /dev/vdb rw"]}


@contextmanager
def selected_root(root, mode="lifecycle"):
    # Model the production pre-Popen pin and the daemon-written selection, using
    # real temporary-directory identity; never mock the proof implementation.
    key = str(root.absolute())
    previous = backend_proof._ROOT_PINS.get(key)
    with patch.dict(os.environ):
        os.environ.pop("CENGINE_COMPAT_MANAGED_STORAGE", None)
        os.environ.pop("CENGINE_CORPUS_SHARED_FS", None)
        assert mode == "lifecycle"
        path = create_backend(root)
        try:
            yield path
        finally:
            if previous is None:
                backend_proof._ROOT_PINS.pop(key, None)
            else:
                backend_proof._ROOT_PINS[key] = previous


class WheelTests(unittest.TestCase):
    def test_determinism_and_complete_record(self):
        hashes = []
        for version in wheels.VERSIONS:
            name, data = wheels.wheel(version)
            self.assertEqual((name, data), wheels.wheel(version))
            self.assertLessEqual(len(data), wheels.MAX_WHEEL)
            hashes.append(hashlib.sha256(data).hexdigest())
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.namelist()
                self.assertEqual(entries, sorted(entries))
                record = f"volume_workflow-{version}.dist-info/RECORD"
                rows = list(csv.reader(io.StringIO(archive.read(record).decode())))
                self.assertEqual({row[0] for row in rows}, set(entries))
                for path, digest, length in rows:
                    if path == record:
                        self.assertEqual((digest, length), ("", ""))
                        continue
                    payload = archive.read(path)
                    expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
                    self.assertEqual((digest, length), ("sha256=" + expected, str(len(payload))))
                for info in archive.infolist():
                    self.assertEqual(info.date_time, (2020, 1, 1, 0, 0, 0))
                    self.assertEqual(info.external_attr >> 16, 0o100644)
                self.assertNotIn("setup.py", entries)
                self.assertNotIn("pyproject.toml", entries)
                self.assertIn(f"volume_workflow/{'v1_only' if version == '1.0' else 'v2_only'}.txt", entries)
                self.assertNotIn(f"volume_workflow/{'v2_only' if version == '1.0' else 'v1_only'}.txt", entries)
        self.assertEqual(hashes, ["f4cb838881260d69d02ae75cc6fac85f6fc6623973e104b68425a37d48b11420",
                                  "2bc3d4ac2a1ed361f2dc79bbdd62f3ac002b93fa9cf175e0b204bb2b33dcc10d"])

    def test_version_input_rejected_before_archive_generation(self):
        for value in (None, True, 1, "3.0", "../escape", "1.0/../../x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wheels.wheel(value)
        with patch.object(wheels, "MAX_WHEEL", 1), self.assertRaises(ValueError):
            wheels.wheel("1.0")

    def test_image_is_exact_existing_pin(self):
        # Compose now uses an OCI named context. Compare the pinned content,
        # not its Dockerfile FROM alias or the registry mirror hostname.
        self.assertEqual(wheels.IMAGE.split("@", 1)[1],
                         compat_image_fixtures.source("python").split("@", 1)[1])
        requirements = (ROOT / "Tests/Fixtures/compose/developer-loop/requirements.txt").read_text().splitlines()
        self.assertFalse([line for line in requirements if line.strip() and not line.startswith("#")])


class SafetyTests(unittest.TestCase):
    def test_fixed_command_allowlist_no_index_no_build_no_shell(self):
        commands = guest.commands()
        self.assertEqual(set(commands), {"python-version", "pip-version", "venv", "entrypoint", "install-1.0", "install-2.0"})
        self.assertIn("--without-pip", commands["venv"])
        for version in ("1.0", "2.0"):
            argv = commands["install-" + version]
            for flag in ("--no-index", "--no-deps", "--no-compile", "--no-cache-dir", "--isolated", "--upgrade"):
                self.assertIn(flag, argv)
            self.assertEqual(argv[argv.index("--python") + 1], guest.VENV + "/bin/python")
            self.assertTrue(argv[-1].endswith(".whl"))
        with patch.object(guest.subprocess, "Popen") as spawn, self.assertRaises(ValueError):
            guest.run_command("rm", [])
        spawn.assert_not_called()
        self.assertLessEqual(guest.MAX_TREE * 2 + guest.MAX_ARCHIVE + 2 * 2 * 1024 * 1024, 32 * 1024 * 1024)
        self.assertLessEqual(guest.MAX_ARCHIVE, 16 * 1024 * 1024)
        self.assertLessEqual(campaign.MAX_ARTIFACTS, 8 * 1024 * 1024)

    def test_request_validation(self):
        valid = {"action": "install", "wheels": {name: base64.b64encode(data).decode()
                 for name, data in (wheels.wheel(v) for v in wheels.VERSIONS)}}
        self.assertEqual(guest.validate_request(valid), valid)
        for invalid in ({}, [], {"action": "identity", "wheels": {}, "extra": 1},
                        {"action": "shell", "wheels": {}}, {"action": [], "wheels": {}},
                        {"action": "install", "wheels": {}},
                        {"action": "identity", "wheels": {"../escape": "a"}}):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                guest.validate_request(invalid)
        for value in ("!", "a" * 45001, base64.b64encode(b"a" * 32769).decode()):
            invalid = copy.deepcopy(valid)
            invalid["wheels"][next(iter(invalid["wheels"]))] = value
            with self.assertRaises(ValueError):
                guest.validate_request(invalid)

    def test_archive_confinement_before_extraction(self):
        root = member("tree", tarfile.DIRTYPE)
        data = member("tree/data", size=3)
        self.assertEqual(len(guest.validate_members([root, data, member("tree/alias", tarfile.LNKTYPE, link="tree/data")])), 3)
        invalids = [member("../escape"), member("/tree/escape"), member("tree/../escape"),
                    member("tree//x"), member("tree/special", tarfile.CHRTYPE),
                    member("tree/pipe", tarfile.FIFOTYPE), member("tree/huge", size=guest.MAX_TREE + 1),
                    member("tree/link", tarfile.SYMTYPE, link="../outside"),
                    member("tree/link", tarfile.SYMTYPE, link="/etc/passwd"),
                    member("tree/link", tarfile.LNKTYPE, link="tree/missing"),
                    member("tree/missing/child")]
        for invalid in invalids:
            with self.subTest(name=invalid.name), self.assertRaises(ValueError):
                guest.validate_members([root, invalid])
        link = member("tree/link", tarfile.SYMTYPE, link="data")
        with self.assertRaises(ValueError):
            guest.validate_members([root, link, member("tree/link/escape")])
        for field, value in (("uid", 0), ("gid", 0), ("mode", 0o4755)):
            bad = copy.deepcopy(data)
            setattr(bad, field, value)
            with self.assertRaises(ValueError):
                guest.validate_members([root, bad])
        with self.assertRaises(ValueError):
            guest.validate_members([root, data, data])
        with self.assertRaises(ValueError):
            guest.validate_members([root] * (guest.MAX_FILES + 1))

    def test_inventory_preserves_raw_links_and_nfs_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "first").write_bytes(b"known")
            (root / "second").hardlink_to(root / "first")
            (root / ".nfs-visible").write_bytes(b"not filtered")
            (root / "literal").symlink_to("first")
            evidence = guest.inventory(root)
            first = evidence["entries"]["first"]
            self.assertEqual(first["nlink"], 2)
            self.assertEqual(first["links"], ["first", "second"])
            self.assertEqual(evidence["entries"]["literal"]["target"], "first")
            self.assertIn(".nfs-visible", evidence["entries"])
            with patch.object(guest, "MAX_TREE", 1), self.assertRaises(ValueError):
                guest.inventory(root)
            with patch.object(guest, "MAX_FILES", 1), self.assertRaises(ValueError):
                guest.inventory(root)

    def test_output_and_backend_schema(self):
        self.assertEqual(campaign.validate_result(outcome(), "identity"), outcome())
        for key, bad in (("schema", True), ("uid", 0), ("commands", []), ("mountinfo", ["bad"]), ("extra", 1)):
            value = outcome()
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                campaign.validate_result(value, "identity")
        mounted = [("/work", "owned", False)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with selected_root(root) as selection:
                evidence = campaign.backend_evidence(outcome(), mounted, {"owned": "block"}, "block", root=root)
                self.assertEqual(evidence["modes"], {"owned": "block"})
                self.assertEqual(evidence["mount_proofs"]["/work"]["lifecycle_manifest_sha256"],
                                 hashlib.sha256(selection.read_bytes()).hexdigest())
                for mode in ({}, {"owned": "shared"}):
                    with self.assertRaises(AssertionError):
                        campaign.backend_evidence(outcome(), mounted, mode, "block", root=root)
                for old, new in (("/work rw", "/work ro"), ("ext4", "tmpfs"), ("/ ro", "/ rw")):
                    value = outcome()
                    value["mountinfo"] = [line.replace(old, new) for line in value["mountinfo"]]
                    with self.assertRaises((AssertionError, backend_proof.BackendProofError)):
                        campaign.backend_evidence(value, mounted, {"owned": "block"}, "block", root=root)

    def test_shared_backend_matches_captured_durable_selection(self):
        mounted = [("/work", "owned", False)]
        for mode, tail in (("lifecycle", "fuse.managed-v3 managed-v3 rw"),):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with selected_root(root, mode) as selection:
                    value = outcome()
                    mount_root = "/"
                    value["mountinfo"][1] = f"2 1 0:44 {mount_root} /work rw - {tail}"
                    evidence = campaign.backend_evidence(value, mounted, {"owned": "shared"}, "shared", root=root)
                    proof = evidence["mount_proofs"]["/work"]
                    self.assertEqual(proof["mode"], mode)
                    self.assertEqual(proof["mount"]["raw"], value["mountinfo"][1])
                    self.assertEqual(proof["lifecycle_manifest_sha256"], hashlib.sha256(selection.read_bytes()).hexdigest())
                    for wrong in ("ext4 /dev/vdb rw", "fuse.other managed-v3 rw",
                                  "fuse.managed-v3 forged rw", "nfs4 100.64.0.1:/ rw,vers=4"):
                        bad = copy.deepcopy(value)
                        bad["mountinfo"][1] = f"2 1 0:44 {mount_root} /work rw - {wrong}"
                        with self.subTest(wrong=wrong), self.assertRaises(backend_proof.BackendProofError):
                            campaign.backend_evidence(bad, mounted, {"owned": "shared"}, "shared", root=root)
                    for key, invalid in (("CENGINE_CORPUS_SHARED_FS", ""),
                                         ("CENGINE_COMPAT_MANAGED_STORAGE", ""),
                                         ("CENGINE_COMPAT_MANAGED_STORAGE", "1")):
                        with patch.dict(os.environ, {key: invalid}), self.assertRaises(backend_proof.BackendProofError):
                            campaign.backend_evidence(value, mounted, {"owned": "shared"}, "shared", root=root)
                    selection.write_text(json.dumps({"schema": 1, "mode": "", "root": proof["root_identity"]}))
                    with self.assertRaises(backend_proof.BackendProofError):
                        campaign.backend_evidence(value, mounted, {"owned": "shared"}, "shared", root=root)

    def test_startup_pin_is_before_daemon_side_effects(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/conftest.py").read_text())
        daemon = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Daemon")
        start = next(node for node in daemon.body if isinstance(node, ast.FunctionDef) and node.name == "start")
        calls = [node for node in ast.walk(start) if isinstance(node, ast.Call)]
        pin = next(node for node in calls if isinstance(node.func, ast.Name) and node.func.id == "capture_backend_root")
        self.assertEqual(ast.unparse(pin.args[0]), "self.root")
        self.assertEqual(ast.unparse(pin.args[1]), "'lifecycle'")
        for expression in ("self.socket.unlink", "self.log_path.open", "subprocess.Popen"):
            call = next(node for node in calls if ast.unparse(node.func) == expression)
            self.assertLess(pin.lineno, call.lineno)
        selector = next(node for node in calls if ast.unparse(node.func) == "managed_storage_arguments")
        self.assertLess(selector.lineno, pin.lineno)

    def test_one_campaign_marker_and_fixed_lifecycle(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_volume_workflows.py").read_text())
        tests = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]
        self.assertEqual(len(tests), 1)
        self.assertEqual(ast.unparse(tests[0].decorator_list[0]), "pytest.mark.compat('VOL-023')")
        for storage, count in (("block", 1), ("shared", 2)):
            volumes, containers = campaign.names(TOKEN, storage)
            self.assertEqual(len(volumes), 3)
            self.assertTrue(all(len(group) == count for group in containers.values()))
            self.assertEqual(tuple(containers), campaign.PHASES)
        for token, mode in (("../x", "block"), (TOKEN, "nfs"), (None, "shared")):
            with self.assertRaises(ValueError):
                campaign.names(token, mode)

    def test_artifact_bound_reserves_cleanup_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = campaign.Journal(Path(temporary))
            journal.size = campaign.MAX_ARTIFACTS - 65536
            with self.assertRaises(ValueError):
                journal.record({"phase": "overflow"})
            journal.record({"phase": "failure", "error": "original failure preserved"})
            journal.record({"phase": "cleanup", "errors": ["preserved"]})
            records = [json.loads(line) for line in (Path(temporary) / "journal.jsonl").read_text().splitlines()]
            self.assertEqual(records[0]["error"], "original failure preserved")
            self.assertEqual(records[1]["errors"], ["preserved"])


class ReviewRegressionTests(unittest.TestCase):
    def test_command_timeout_kills_group_and_preserves_command_evidence(self):
        command = guest.commands()["python-version"]
        process = SimpleNamespace(pid=123, returncode=-9, poll=lambda: None,
                                  wait=Mock(side_effect=[guest.subprocess.TimeoutExpired(command, 35), None]))
        evidence = []
        with patch.object(guest.subprocess, "Popen", return_value=process), \
                patch.object(guest.os, "killpg") as kill, self.assertRaises(guest.subprocess.TimeoutExpired):
            guest.run_command("python-version", evidence)
        kill.assert_called_once_with(123, guest.signal.SIGKILL)
        self.assertEqual([call.kwargs["timeout"] for call in process.wait.call_args_list], [35, 5])
        self.assertEqual(evidence, [{"argv": command, "exit": -9, "output": ""}])

    def test_interpreter_symlinks_are_image_confined(self):
        parents = [member(name, tarfile.DIRTYPE) for name in ("tree", "tree/venv", "tree/venv/bin")]
        for executable in ("python", "python3", f"python3.{sys.version_info.minor}"):
            link = member("tree/venv/bin/" + executable, tarfile.SYMTYPE,
                          link="/usr/local/bin/" + executable)
            with patch.object(guest.os.path, "samefile", return_value=True):
                guest.validate_members(parents + [link])
            with patch.object(guest.os.path, "samefile", return_value=False), self.assertRaises(ValueError):
                guest.validate_members(parents + [link])

    def test_failure_envelope_retains_prior_evidence_without_running_guest(self):
        def fail(action, wheels, result):
            result["commands"] = outcome()["commands"]
            result["mountinfo"] = outcome()["mountinfo"]
            raise RuntimeError("injected upgrade failure")
        with patch.object(guest, "execute", side_effect=fail):
            result, status = guest.run_request({"action": "install", "wheels": {}})
        self.assertEqual(status, 1)
        self.assertEqual(result["commands"], outcome()["commands"])
        self.assertEqual(result["mountinfo"], outcome()["mountinfo"])
        self.assertEqual(result["error"]["message"], "injected upgrade failure")

    def test_source_loads_do_not_write_bytecode(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary)
            for path in SOURCE.glob("*.py"):
                (copied / path.name).write_bytes(path.read_bytes())
            with patch.object(campaign, "SOURCE", copied):
                campaign.load("wheels")
                campaign.load("guest")
            self.assertFalse((copied / "__pycache__").exists())
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse((SOURCE / "campaign.py").read_text()))))

    def test_inventory_schema_and_bounds(self):
        valid = {"entries": {".": {"type": "directory", "mode": 0o700, "uid": 10001,
                                  "gid": 10001, "mtime_ns": 0, "nlink": 2}}, "bytes": 0}
        self.assertEqual(campaign.validate_inventory(valid), valid)
        for bad in ({}, {**valid, "bytes": True}, {**valid, "bytes": guest.MAX_TREE + 1},
                    {**valid, "entries": {}}, {**valid, "entries": {"../escape": valid["entries"]["."]}}):
            with self.assertRaises(ValueError):
                campaign.validate_inventory(bad)


class LifecycleTests(unittest.TestCase):
    def run_fake(self, fail_action=None, ambiguous=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "Tests/Compatibility/fixtures/volume-workflows"
            source.mkdir(parents=True)
            for path in SOURCE.glob("*.py"):
                (source / path.name).write_bytes(path.read_bytes())
            # No Compose Dockerfile: this directly seeded-image campaign must
            # remain independent of Compose's named-context build syntax.
            (root / "Tests/Compatibility/test_volume_workflows.py").write_text("# fixture\n")
            for name in ("test_volume_corpus.py", "storage_backend_proof.py"):
                (root / "Tests/Compatibility" / name).write_bytes(
                    (ROOT / "Tests/Compatibility" / name).read_bytes())
            daemon = SimpleNamespace(socket=root / "unused.sock", root=root)
            fake = FakeClient()
            fake.api = SimpleNamespace(timeout=30)
            active = []
            @contextmanager
            def guarded(client, deadline):
                self.assertIs(client, fake)
                self.assertGreater(deadline, time.monotonic())
                self.assertFalse(active)
                active.append(deadline)
                try:
                    yield
                finally:
                    active.pop()
            fake.guard = lambda: self.assertEqual(len(active), 1, "SDK action lacks absolute guard")
            fake.close = lambda: (self.assertFalse(active), fake.events.append(("close",)))
            fake.version = lambda: (fake.guard(), {"Version": "fake"})[1]
            fake.images = SimpleNamespace(get=lambda name: (fake.guard(), SimpleNamespace(attrs={
                "Os": "linux", "Architecture": "arm64", "RepoDigests": [wheels.IMAGE]}))[1])
            modes = {}
            inventory = {"entries": {".": {"type": "directory", "mode": 0o700, "uid": 10001,
                                           "gid": 10001, "mtime_ns": 0, "nlink": 2}}, "bytes": 0}

            def preregistered(name):
                journal = next((root / ".build/volume-hunt").glob("*/journal.jsonl"))
                plan = json.loads(journal.read_text().splitlines()[0])
                self.assertIn(name, json.dumps(plan["resources"]))

            def volume_create(name, labels):
                fake.guard()
                preregistered(name)
                modes[name] = "shared" if "-shared-" in name else "block"
                (root / "volume-storage.json").write_text(json.dumps(modes))
                return fake.add("volume", name, labels[campaign.OWNER])

            def container_create(image, **kwargs):
                fake.guard()
                name = kwargs["name"]
                preregistered(name)
                self.assertEqual(kwargs["network_mode"], "none")
                self.assertTrue(kwargs["read_only"])
                self.assertEqual(kwargs["pids_limit"], 16)
                self.assertEqual(kwargs["tmpfs"]["/tmp"], "rw,nosuid,nodev,size=2m,mode=1777")
                self.assertEqual(kwargs["mem_limit"], "256m")
                request = json.loads(kwargs["command"][1])
                action = request["action"]
                self.assertEqual(kwargs["user"], "0:0" if action == "initialize" else "10001:10001")
                self.assertLess(len(fake.objects["container"]), 2 if "-shared-" in name else 1)
                result = outcome(action)
                if action == "initialize":
                    result["uid"] = result["gid"] = 0
                command_keys = ["python-version", "pip-version"] + {
                    "install": ["venv", "install-1.0", "entrypoint", "install-2.0", "entrypoint"],
                    "restore": ["entrypoint"], "verify": ["entrypoint"]}.get(action, [])
                result["commands"] = [{"argv": guest.commands()[key], "exit": 0, "output": "observed"} for key in command_keys]
                result["mountinfo"] = [outcome()["mountinfo"][0]]
                for mount in kwargs["mounts"]:
                    target, volume, readonly = mount["target"], mount["source"], mount["read_only"]
                    self.assertTrue(mount["no_copy"])
                    tail = "fuse.managed-v3 managed-v3 rw" if "-shared-" in name else "ext4 /dev/vdb rw"
                    result["mountinfo"].append(f"2 1 8:1 / {target} {'ro' if readonly else 'rw'} - {tail}")
                if action == "install":
                    result.update({"installed-1.0": inventory, "installed-2.0": inventory})
                if action in ("backup", "restore", "verify"):
                    result["inventory"] = inventory
                if action in ("backup", "restore"):
                    result["archive"] = {"bytes": 10240, "sha256": "a" * 64}
                failed = action == fail_action
                if failed:
                    result["error"] = {"type": "RuntimeError", "message": "injected"}
                container = fake.add("container", name, kwargs["labels"][campaign.OWNER])
                container.start = lambda: (fake.guard(), self.assertEqual(len(fake.objects["container"]), 2 if "-shared-" in name else 1))
                container.wait = lambda **kw: (fake.guard(), {"StatusCode": int(failed)})[1]
                def logs(**flags):
                    fake.guard()
                    try:
                        yield json.dumps(result).encode() if flags["stdout"] else b"benign stderr warning\n"
                    finally:
                        fake.guard()
                        fake.events.append(("logs-closed", name))
                container.logs = logs
                if ambiguous and action == "install":
                    raise TimeoutError("create response lost")
                return container

            fake.volumes.create, fake.containers.create = volume_create, container_create
            docker_module, types_module = ModuleType("docker"), ModuleType("docker.types")
            docker_module.DockerClient = lambda **kwargs: fake
            types_module.Mount = lambda target, source, **kwargs: dict(target=target, source=source, **kwargs)
            types_module.Ulimit = lambda **kwargs: kwargs
            with patch.dict(sys.modules, {"docker": docker_module, "docker.types": types_module}), \
                    patch.object(campaign, "ROOT", root), patch.object(campaign, "SOURCE", source), \
                    patch.object(campaign, "api_deadline", side_effect=guarded), selected_root(root):
                if fail_action or ambiguous:
                    with self.assertRaises((AssertionError, TimeoutError)):
                        campaign.run(daemon)
                else:
                    campaign.run(daemon)
            self.assertFalse(fake.objects["container"])
            self.assertFalse(fake.objects["volume"])
            records = [json.loads(line) for line in next((root / ".build/volume-hunt").glob("*/journal.jsonl")).read_text().splitlines()]
            if fail_action and not ambiguous:
                self.assertTrue(any(row["phase"] == "backend" and row["step"] == fail_action for row in records))
            self.assertEqual(records[-1], {"phase": "cleanup", "errors": []})
            return records

    def test_serial_full_campaign_with_bounded_configuration(self):
        records = self.run_fake()
        self.assertEqual([row["storage"] for row in records if row["phase"] == "passed"], ["block", "shared"])
        verified = [row for row in records if row["phase"] == "backend-verified"]
        self.assertEqual(len(verified), len(campaign.PHASES) * 3)
        for row in verified:
            for proof in row["proof"]["mount_proofs"].values():
                self.assertEqual(proof["mode"], "lifecycle")
                self.assertEqual(proof["mount"]["filesystem"],
                                 "ext4" if row["storage"] == "block" else "fuse.managed-v3")
                self.assertRegex(proof["lifecycle_manifest_sha256"], r"^[0-9a-f]{64}$")
        central = "Tests/Compatibility/storage_backend_proof.py"
        self.assertEqual(records[0]["source_sha256"][central],
                         hashlib.sha256((ROOT / central).read_bytes()).hexdigest())

    def test_guest_failure_keeps_backend_and_cleans_every_owned_resource(self):
        self.run_fake(fail_action="install")

    def test_ambiguous_create_reconciles_preregistered_name(self):
        self.run_fake(ambiguous=True)


@contextmanager
def local_http_peer(responses):
    """Real Unix HTTP only; all listener/connection workers join before return."""
    with tempfile.TemporaryDirectory(prefix="workflow-http-") as directory:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        path = str(Path(directory) / "socket")
        listener.bind(path)
        listener.listen(8)
        listener.settimeout(0.05)
        stop = threading.Event()
        connections, workers, requests, errors = [], [], [], []

        def respond(connection, chunks):
            try:
                with connection:
                    connection.settimeout(0.5)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        part = connection.recv(4096)
                        if not part:
                            return
                        request.extend(part)
                        if len(request) > 65536:
                            raise AssertionError("test request exceeds bound")
                    headers, body = request.split(b"\r\n\r\n", 1)
                    length = next((int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n")
                                   if line.lower().startswith(b"content-length:")), 0)
                    if length > 65536:
                        raise AssertionError("test request body exceeds bound")
                    while len(body) < length:
                        part = connection.recv(min(4096, length - len(body)))
                        if not part:
                            return
                        body.extend(part)
                    requests.append(headers.split(b"\r\n")[0].decode())
                    for chunk in chunks:
                        if stop.wait(0.01):
                            return
                        connection.sendall(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except OSError as error:
                if not stop.is_set():
                    errors.append(error)
            except BaseException as error:
                errors.append(error)

        def accept():
            try:
                for chunks in responses:
                    while not stop.is_set():
                        try:
                            connection, _ = listener.accept()
                            break
                        except socket.timeout:
                            continue
                    else:
                        return
                    connections.append(connection)
                    worker = threading.Thread(target=respond, args=(connection, chunks), name="workflow-http-peer")
                    workers.append(worker)
                    worker.start()
            except OSError as error:
                if not stop.is_set():
                    errors.append(error)

        receiver = threading.Thread(target=accept, name="workflow-http-listener")
        receiver.start()
        try:
            yield "unix://" + path, requests
        finally:
            stop.set()
            listener.close()
            receiver.join(2)
            for connection in connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            for worker in workers:
                worker.join(2)
            if receiver.is_alive() or any(worker.is_alive() for worker in workers):
                raise AssertionError("local HTTP peer worker failed to join")
            if errors:
                raise errors[0]


def http_json(value, status="200 OK"):
    body = json.dumps(value).encode()
    return [f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body]


def drip_headers():
    return [b"HTTP/1.1 200 OK\r\nX-Drip: "] + [b"x"] * 200 + [b"\r\nContent-Length: 2\r\n\r\n{}"]


def drip_body():
    body = b'{"drip":"' + b"x" * 200 + b'"}'
    return [f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode()] + [bytes([byte]) for byte in body]


@unittest.skipUnless(SDK_AVAILABLE, "real Unix transport checks require existing compatibility Python SDK/pytest")
class HTTPDeadlineTests(unittest.TestCase):
    def setUp(self):
        import docker
        import test_volume_corpus
        self.docker, self.corpus = docker, test_volume_corpus

    def client(self, endpoint):
        # Never consult the developer's Docker credentials/proxies in local peer tests.
        with patch.object(self.docker.api.client.config, "load_general_config", return_value={}):
            sdk = self.docker.DockerClient(base_url=endpoint, version="1.45", timeout=5)
        self.addCleanup(sdk.close)
        return sdk

    def assert_joined(self):
        self.assertFalse(any(thread.name == "corpus-http-deadline" for thread in threading.enumerate()))

    def bounded_failure(self, operation):
        started = time.monotonic()
        with self.assertRaises(Exception):
            operation(started + 0.2)
        self.assertLess(time.monotonic() - started, 1.2)
        self.assert_joined()

    def test_real_header_drip_and_following_request(self):
        with local_http_peer([drip_headers(), http_json({"Version": "local-peer"})]) as (endpoint, requests):
            sdk = self.client(endpoint)
            original_send, original_adapter = sdk.api.send, sdk.api.adapters["http+docker://"]
            self.bounded_failure(lambda deadline: campaign.api_call(sdk, deadline, sdk.version))
            self.assertEqual(sdk.api.send, original_send)
            self.assertIs(sdk.api.adapters["http+docker://"], original_adapter)
            self.assertEqual(campaign.api_call(sdk, time.monotonic() + 1, sdk.version), {"Version": "local-peer"})
            self.assertEqual(len(requests), 2)
            self.assertEqual(sdk.api.timeout, 5)

    def test_real_image_inspect_body_drip(self):
        with local_http_peer([drip_body()]) as (endpoint, requests):
            sdk = self.client(endpoint)
            self.bounded_failure(lambda deadline: campaign.api_call(sdk, deadline, sdk.images.get, "owned-image"))
            self.assertIn("/images/owned-image/json", requests[0])

    def test_real_compound_create_post_and_inspect_share_one_deadline(self):
        # A successful POST does not reset the deadline for the SDK's implicit GET.
        with local_http_peer([http_json({"Id": "created", "Warnings": []}, "201 Created"), drip_headers()]) as (endpoint, requests):
            sdk = self.client(endpoint)
            self.bounded_failure(lambda deadline: campaign.api_call(
                sdk, deadline, sdk.containers.create, "fixture", name="preregistered",
                labels={campaign.OWNER: TOKEN}))
            self.assertTrue(requests[0].startswith("POST /v1.45/containers/create"), requests)
            self.assertEqual(requests[1], "GET /v1.45/containers/created/json HTTP/1.1")

    def test_real_create_body_drip_is_bounded(self):
        with local_http_peer([drip_body()]) as (endpoint, requests):
            sdk = self.client(endpoint)
            self.bounded_failure(lambda deadline: campaign.api_call(
                sdk, deadline, sdk.volumes.create, "preregistered", labels={campaign.OWNER: TOKEN}))
            self.assertEqual(requests, ["POST /v1.45/volumes/create HTTP/1.1"])

    def test_real_cleanup_get_and_delete_drips_keep_owner_guard(self):
        owned = {"Name": "owned", "Labels": {campaign.OWNER: TOKEN}}
        for responses in ([drip_headers()], [http_json(owned), drip_headers()]):
            with self.subTest(requests=len(responses)), local_http_peer(responses) as (endpoint, requests):
                sdk = self.client(endpoint)
                started = time.monotonic()
                failures = campaign.cleanup(sdk, [], ["owned"], TOKEN, deadline=started + 0.2)
                self.assertEqual(len(failures), 1)
                self.assertLess(time.monotonic() - started, 1.2)
                self.assert_joined()
                self.assertEqual(requests[0], "GET /v1.45/volumes/owned HTTP/1.1")
                if len(responses) == 2:
                    self.assertTrue(requests[1].startswith("DELETE /v1.45/volumes/owned"))
        # DELETE has no result body to decode. Discard a dripping body by closing
        # its owned response; do not let stream=True leak that connection.
        with local_http_peer([http_json(owned), drip_body()]) as (endpoint, requests):
            sdk = self.client(endpoint)
            started = time.monotonic()
            self.assertEqual(campaign.cleanup(sdk, [], ["owned"], TOKEN, deadline=started + 0.2), [])
            self.assertLess(time.monotonic() - started, 0.2)
            self.assert_joined()
        with local_http_peer([http_json({**owned, "Labels": {campaign.OWNER: "foreign"}})]) as (endpoint, requests):
            failures = campaign.cleanup(self.client(endpoint), [], ["owned"], TOKEN, deadline=time.monotonic() + 1)
            self.assertIn("without exact name and owner", failures[0])
            self.assertEqual(len(requests), 1)

    def test_real_log_body_drip_closes_stream_before_cleanup(self):
        frame = struct.pack(">BxxxI", 1, 200)
        logs = [b"HTTP/1.1 200 OK\r\nContent-Length: 208\r\n\r\n" + frame] + [b"x"] * 200
        inspect = http_json({"Id": "owned", "Name": "/owned", "Config": {"Tty": False}})
        with local_http_peer([logs, inspect, http_json({"Name": "owned", "Labels": {campaign.OWNER: "foreign"}})]) as (endpoint, requests):
            sdk = self.client(endpoint)
            container = self.docker.models.containers.Container(attrs={"Id": "owned"}, client=sdk)
            closed = []
            original = self.docker.types.daemon.CancellableStream.close
            def close(stream):
                closed.append(True)
                return original(stream)
            with patch.object(self.docker.types.daemon.CancellableStream, "close", close):
                self.bounded_failure(lambda deadline: campaign.read_logs(sdk, container, deadline))
            self.assertEqual(len(closed), 1)
            failures = campaign.cleanup(sdk, [], ["owned"], TOKEN, deadline=time.monotonic() + 1)
            self.assertIn("without exact name and owner", failures[0])
            self.assertEqual(len(requests), 3)

    def test_unused_delete_responses_close_before_next_cleanup_request(self):
        responses = [http_json({"Name": "one", "Labels": {campaign.OWNER: TOKEN}}), drip_body(),
                     http_json({"Name": "two", "Labels": {campaign.OWNER: TOKEN}}),
                     [b"HTTP/1.1 204 No Content\r\n\r\n"]]
        with local_http_peer(responses) as (endpoint, requests):
            sdk = self.client(endpoint)
            captured = []
            send = sdk.api.send
            def checked_send(request, **kwargs):
                # In particular, DELETE one's ignored body must be closed before
                # GET two starts, not by this test peer's eventual teardown.
                self.assertTrue(all(response.raw.closed for response in captured))
                response = send(request, **kwargs)
                captured.append(response)
                return response
            with patch.object(sdk.api, "send", side_effect=checked_send):
                self.assertEqual(campaign.cleanup(sdk, [], ["one", "two"], TOKEN, deadline=time.monotonic() + 1), [])
            self.assertEqual(len(captured), 4)
            self.assertTrue(all(response.raw.closed for response in captured))
            self.assertEqual(len(requests), 4)
            self.assert_joined()

    def test_gzip_expansion_rejected_before_decode(self):
        compressed = gzip.compress(b"x" * (17 * 1024 * 1024), mtime=0)
        self.assertLess(len(compressed), 65536)
        response = [f"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {len(compressed)}\r\n\r\n".encode() + compressed]
        import requests.models
        import urllib3.response
        with local_http_peer([response]) as (endpoint, _):
            sdk = self.client(endpoint)
            send = sdk.api.send
            def identity_send(request, **kwargs):
                self.assertEqual(request.headers.get("Accept-Encoding"), "identity")
                return send(request, **kwargs)
            started = time.monotonic()
            with patch.object(sdk.api, "send", side_effect=identity_send), \
                    patch.object(requests.models.complexjson, "loads") as decode, \
                    patch.object(urllib3.response.GzipDecoder, "decompress") as decompress:
                with self.assertRaisesRegex(ValueError, "encoded workflow API responses"):
                    campaign.api_call(sdk, started + 0.2, sdk.version)
                decode.assert_not_called()
                decompress.assert_not_called()
            self.assertLess(time.monotonic() - started, 1)
            self.assert_joined()

    def test_real_redirect_rejected_before_body_or_second_endpoint(self):
        redirect = [b"HTTP/1.1 302 Found\r\nLocation: http://unexpected.invalid/\r\nContent-Length: 200\r\n\r\n"] + [b"x"] * 200
        with local_http_peer([redirect]) as (endpoint, requests):
            sdk = self.client(endpoint)
            self.bounded_failure(lambda deadline: campaign.api_call(sdk, deadline, sdk.version))
            self.assertEqual(len(requests), 1)

    def test_real_oversized_body_is_rejected_before_json_decode(self):
        chunk = b"x" * 65536
        response = [f"HTTP/1.1 200 OK\r\nContent-Length: {len(chunk) * 257}\r\n\r\n".encode()] + [chunk] * 257
        import requests.models
        with local_http_peer([response]) as (endpoint, _):
            sdk = self.client(endpoint)
            with patch.object(requests.models.complexjson, "loads") as decode:
                # Closing an active BufferedReader can surface RuntimeError on
                # some CPython versions. The contract is bounded rejection before
                # JSON decoding, not a particular EOF/close exception class.
                with self.assertRaises((ValueError, RuntimeError)):
                    campaign.api_call(sdk, time.monotonic() + 6, sdk.version)
                decode.assert_not_called()
            self.assert_joined()

    def test_independent_clients_do_not_borrow_or_shutdown_other_socket(self):
        with local_http_peer([drip_headers()]) as (slow, _), local_http_peer([http_json({"live": True})]) as (fast, _):
            blocked, healthy = self.client(slow), self.client(fast)
            original_send, original_adapter = healthy.api.send, healthy.api.adapters["http+docker://"]
            errors = []
            def blocked_request():
                try:
                    campaign.api_call(blocked, time.monotonic() + 0.2, blocked.version)
                except Exception as error:
                    errors.append(error)
            worker = threading.Thread(target=blocked_request, name="workflow-independent-client")
            worker.start()
            try:
                self.assertEqual(campaign.api_call(healthy, time.monotonic() + 1, healthy.version), {"live": True})
            finally:
                worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertEqual(healthy.api.send, original_send)
            self.assertIs(healthy.api.adapters["http+docker://"], original_adapter)
            self.assertEqual((blocked.api.timeout, healthy.api.timeout), (5, 5))
            self.assert_joined()


class ResponseOwnershipTests(unittest.TestCase):
    def test_late_sdk_decoding_is_rejected_and_responses_close(self):
        shared = ModuleType("test_volume_corpus")
        shared.api_deadline = lambda *_: nullcontext()
        response = SimpleNamespace(headers={}, close=Mock())
        send = Mock(return_value=response)
        client = SimpleNamespace(api=SimpleNamespace(send=send))
        def decode():
            client.api.send(SimpleNamespace(headers={}))
            return {"decoded": True}
        operation = Mock(side_effect=decode)
        with patch.dict(sys.modules, {"test_volume_corpus": shared}), \
                patch.object(campaign.time, "monotonic", return_value=2):
            with self.assertRaisesRegex(TimeoutError, "operation exceeded absolute deadline"):
                campaign.api_call(client, 1, operation)
        operation.assert_called_once()
        response.close.assert_called_once()
        self.assertIs(client.api.send, send)

    def test_close_failure_still_closes_other_responses_and_preserves_primary_error(self):
        shared = ModuleType("test_volume_corpus")
        shared.api_deadline = lambda *_: nullcontext()
        class LegacyError(ValueError):
            add_note = None
        for primary_failure in (False, True, "legacy"):
            events = []
            def close(name):
                events.append(name)
                if name == "bad":
                    raise RuntimeError("injected close failure")
            responses = [SimpleNamespace(headers={}, close=lambda: close("good")),
                         SimpleNamespace(headers={}, close=lambda: close("bad"))]
            send = Mock(side_effect=responses)
            client = SimpleNamespace(api=SimpleNamespace(send=send))
            with patch.dict(sys.modules, {"test_volume_corpus": shared}):
                expected = ValueError if primary_failure else RuntimeError
                with self.assertRaises(expected) as caught:
                    with campaign.api_deadline(client, time.monotonic() + 1):
                        client.api.send(SimpleNamespace(headers={}))
                        client.api.send(SimpleNamespace(headers={}))
                        if primary_failure:
                            raise (LegacyError if primary_failure == "legacy" else ValueError)("original failure")
            self.assertEqual(events, ["bad", "good"])
            self.assertIs(client.api.send, send)
            if primary_failure:
                self.assertEqual(str(caught.exception), "original failure")
                self.assertIn("response cleanup failed", caught.exception.__notes__[0])


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(campaign, "api_deadline", side_effect=lambda *_: nullcontext()))

    def test_exact_names_and_strict_label_guard(self):
        client = FakeClient()
        for kind in ("container", "volume"):
            for token in (None, "wrong", TOKEN):
                resource = client.add(kind, "exact", token)
                if token == TOKEN:
                    self.assertIs(campaign.owned(resource, kind, "exact", TOKEN), resource)
                else:
                    with self.assertRaises(RuntimeError):
                        campaign.owned(resource, kind, "exact", TOKEN)
            with self.assertRaises(RuntimeError):
                campaign.owned(resource, kind, "other", TOKEN)

    def test_ambiguous_create_is_reconciled_without_listing(self):
        client = FakeClient()
        # Simulate server-side commit and lost create response: only the intended
        # names survive, not any returned object handle.
        client.add("container", "intended")
        client.add("volume", "owned")
        client.add("volume", "unrelated", "other")
        self.assertEqual(campaign.cleanup(client, ["missing", "intended"], ["owned"], TOKEN), [])
        self.assertIn("unrelated", client.objects["volume"])
        removes = [event for event in client.events if event[0] == "remove"]
        self.assertEqual(removes, [("remove", "container", "intended", {"force": True}),
                                   ("remove", "volume", "owned", {})])

    def test_cleanup_failure_continues_and_wrong_owner_never_deleted(self):
        client = FakeClient()
        client.add("container", "failing", failure=True)
        client.add("container", "foreign", token="wrong")
        client.add("volume", "owned")
        failures = campaign.cleanup(client, ["failing", "foreign"], ["owned"], TOKEN)
        self.assertEqual(len(failures), 2)
        self.assertNotIn("owned", client.objects["volume"])
        self.assertNotIn(("remove", "container", "foreign", {"force": True}), client.events)


if __name__ == "__main__":
    unittest.main()
