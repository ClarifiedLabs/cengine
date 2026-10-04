#!/usr/bin/env python3
"""Engine-free RTM-078 guards: stdlib only, no Go/VM/Docker/build/installation."""
import ast
import copy
from contextlib import nullcontext
import io
import json
import os
import signal
import subprocess
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_storage as smoke

SOURCE = ROOT / "Tests/Compatibility/conftest.py"
module = ast.parse(SOURCE.read_text())
selector = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "managed_storage_arguments")
namespace = {}
exec(compile(ast.Module(body=[selector], type_ignores=[]), str(SOURCE), "exec"), namespace)
select = namespace["managed_storage_arguments"]


def uid():
    return str(uuid.uuid4())


def journal():
    store, volume = uid(), uid()
    manifest = dict(schema=1, mode="managed", store=store)
    state = dict(schema=2, store=store, revision=20, reconciliationRequired=False,
                 volumes={volume: dict(id=volume, name="owned-volume")}, intents={})
    containers = ["a" * 64, "b" * 64]
    for container in containers:
        intent = dict(id=uid(), store=store, container=container, containerInstance=uid(), launch=uid(),
                      serviceEpoch=uid(), controllerEpoch=1, prepare=uid(), phase="running", prepareCompleted=True,
                      cleanUnmount=True, specificationDigest="d" * 64,
                      mounts=[dict(volume=volume, destination="/data", subpath="", mode="read-write")], slots=[])
        intent["guestCompletion"] = dict(prepare=intent["prepare"], containerInstance=intent["containerInstance"],
                                         launch=intent["launch"], succeeded=True, cleanCopyUp=True, evidenceDigest="e" * 64)
        for role in ("prepare", "runtime"):
            attachment = uid()
            receipt = dict(store=store, volume=volume, attachment=attachment, prepare=intent["prepare"], launch=intent["launch"], revision=10) if role == "prepare" else None
            intent["slots"].append(dict(attachment=attachment, volume=volume, role=role, mode="read-write", key="f" * 64, receipt=receipt))
        state["intents"][intent["id"]] = intent
    return manifest, state, containers


def snapshot():
    return dict(mountinfo="23 10 0:40 / /data rw,nosuid,nodev - fuse.managed-v3 managed-v3 rw\n", entries=["seed"],
                root=dict(mode=stat.S_IFDIR | 0o750, uid=10001, gid=10002, mtime=smoke.MTIME),
                file=dict(mode=stat.S_IFREG | 0o640, uid=10001, gid=10002, nlink=1, size=len(smoke.SEED), mtime=smoke.MTIME),
                sha256=smoke.digest(smoke.SEED))


class SmokeTests(unittest.TestCase):
    def test_default_and_retired_selectors(self):
        self.assertEqual(select({}), [])
        for key in ("CENGINE_COMPAT_SHARED_STORAGE", "CENGINE_COMPAT_MANAGED_STORAGE"):
            for value in ("", "0", "1", "legacy", "managed", "lifecycle", None):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    select({key: value})

    def test_selector_precedes_side_effects_and_reaches_popen(self):
        daemon = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == "Daemon")
        start = next(n for n in daemon.body if isinstance(n, ast.FunctionDef) and n.name == "start")
        self.assertEqual(ast.unparse(start.body[0]), "storage_arguments = managed_storage_arguments(os.environ)")
        calls = [n for n in ast.walk(start) if isinstance(n, ast.Call) and ast.unparse(n.func) == "subprocess.Popen"]
        self.assertEqual(len(calls), 1)
        self.assertIn("*storage_arguments", ast.unparse(calls[0].args[0]))

    def test_exact_mount_subtype_not_nfs_direct_or_other_fuse(self):
        good = snapshot()["mountinfo"]
        self.assertEqual(smoke.mount_proof(good)["filesystem"], "fuse.managed-v3")
        for bad in ("", good + good, good.replace("/data", "/other"),
                    *(good.replace("fuse.managed-v3", fs) for fs in ("nfs4", "ext4", "fuse", "fuse.other")),
                    good + "x" * 65536):
            with self.subTest(bad=bad[:80]), self.assertRaises(ValueError):
                smoke.mount_proof(bad)

    def test_copyup_bytes_ownership_mode_and_mtime_required(self):
        value = snapshot()
        smoke.snapshot_proof(value)
        for section, field, wrong in (("root", "mode", 0o40755), ("root", "uid", 0), ("root", "mtime", 0),
                                      ("file", "gid", 0), ("file", "nlink", 2), ("file", "mtime", 0), ("file", "size", 0)):
            bad = copy.deepcopy(value); bad[section][field] = wrong
            with self.assertRaises(ValueError): smoke.snapshot_proof(bad)

    def test_unlinked_retained_fd_never_filters_names_or_fakes_nlink(self):
        value = snapshot(); value["entries"] = []; value["file"]["nlink"] = 0
        smoke.snapshot_proof(value, unlinked=True)
        for hidden in (".nfs123", ".cengine-retained", "seed"):
            bad = copy.deepcopy(value); bad["entries"] = [hidden]
            with self.assertRaises(ValueError): smoke.snapshot_proof(bad, unlinked=True)
        bad = copy.deepcopy(value); bad["file"]["nlink"] = 1
        with self.assertRaises(ValueError): smoke.snapshot_proof(bad, unlinked=True)
        value["file"]["size"] = len(smoke.WRITTEN); value["sha256"] = smoke.digest(smoke.WRITTEN)
        smoke.snapshot_proof(value, unlinked=True, written=True)
        del value["file"]; del value["sha256"]
        smoke.snapshot_proof(value, unlinked=True, closed=True)

    def test_durable_running_and_stop_receipts(self):
        manifest, state, containers = journal()
        proof = smoke.receipt_proof(manifest, state, "owned-volume", containers)
        self.assertEqual(len(proof["intents"]), 2)
        self.assertNotIn('"key"', json.dumps(proof))
        for intent in state["intents"].values():
            intent["phase"] = "retired"
            slot = intent["slots"][1]
            slot["receipt"] = dict(store=state["store"], volume=slot["volume"], attachment=slot["attachment"], launch=intent["launch"], revision=19)
        smoke.receipt_proof(manifest, state, "owned-volume", containers, stopped=True)

    def test_wrong_or_missing_lifecycle_evidence_fails(self):
        for mutation in (lambda i: i.update(cleanUnmount=False), lambda i: i.update(prepareCompleted=False),
                         lambda i: i.update(phase="quarantined"), lambda i: i["guestCompletion"].update(launch=uid()),
                         lambda i: i["slots"][0].update(receipt=None),
                         lambda i: i["slots"][0]["receipt"].update(attachment=uid()),
                         lambda i: i["slots"][0]["receipt"].update(revision=True),
                         lambda i: i["slots"][1].update(attachment=i["slots"][0]["attachment"]),
                         lambda i: i.update(controllerEpoch=True), lambda i: i.update(specificationDigest="secret")):
            manifest, state, containers = journal(); mutation(next(iter(state["intents"].values())))
            with self.assertRaises((ValueError, KeyError)):
                smoke.receipt_proof(manifest, state, "owned-volume", containers)

    def test_public_revision_is_bounded_integer(self):
        for value in (True, "secret", {"privateKey": "secret"}, -1, 0, 2 ** 64):
            manifest, state, containers = journal(); state["revision"] = value
            with self.assertRaises(ValueError): smoke.receipt_proof(manifest, state, "owned-volume", containers)

    def test_hijack_lifetime_and_inspect_share_absolute_deadline(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_storage.py").read_text())
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        observe = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "observe")
        guard = next(n for n in observe.body if isinstance(n, ast.With))
        calls = {ast.unparse(n.func) for n in ast.walk(guard) if isinstance(n, ast.Call)}
        self.assertTrue({"client.api.exec_start", "raw_socket.recv", "close_exec_stream", "client.api.exec_inspect"} <= calls)
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and ast.unparse(n.func).endswith("retain_root"):
                self.assertIn(next(k.value.value for k in n.keywords if k.arg == "reason"),
                              ("unsafe-disk-phase", "cleanup-incomplete"))

    def test_no_implicit_registry_seed_or_cli_network_fixture(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_storage.py").read_text())
        override = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "verify_docker_cli_target")
        self.assertEqual(override.args.args, [])
        self.assertEqual(len(override.body), 1)
        self.assertIsInstance(override.body[0], ast.Pass)
        self.assertIn("pytest.fixture(autouse=True)", [ast.unparse(n) for n in override.decorator_list])

    def test_prepare_and_runtime_receipt_revisions_reject_overflow(self):
        for stopped in (False, True):
            manifest, state, containers = journal()
            if stopped:
                for intent in state["intents"].values():
                    intent["phase"] = "retired"
                    slot = intent["slots"][1]
                    slot["receipt"] = dict(store=state["store"], volume=slot["volume"], attachment=slot["attachment"], launch=intent["launch"], revision=19)
            next(iter(state["intents"].values()))["slots"][int(stopped)]["receipt"]["revision"] = 2 ** 64
            with self.assertRaises(ValueError): smoke.receipt_proof(manifest, state, "owned-volume", containers, stopped=stopped)

    def test_parent_reaps_before_retention_failure(self):
        path = ROOT / "Tests/Compatibility/test_managed_storage.py"
        tree = ast.parse(path.read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "test_initial_managed_storage")
        function.decorator_list = []
        process = Mock(pid=12345)
        process.wait.side_effect = [subprocess.TimeoutExpired("worker", 86), 0]
        events = []
        def retain(*args): events.append("retain"); raise OSError("disk full")
        process.wait.side_effect = lambda **kw: (events.append("wait") or (_ for _ in ()).throw(subprocess.TimeoutExpired("worker", 86))) if not events else (events.append("reaped") or 0)
        namespace = dict(time=time, sys=sys, subprocess=SimpleNamespace(Popen=lambda *a, **kw: process, DEVNULL=-3),
                         os=SimpleNamespace(killpg=lambda *a: events.append("kill")), signal=signal,
                         __file__=str(path), retain_failure=retain)
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
        daemon = SimpleNamespace(binary="binary", root="root", socket="socket", work="work", _retain_root=False)
        with self.assertRaises(OSError): namespace[function.name](daemon)
        self.assertEqual(events, ["wait", "kill", "reaped", "retain"])
        self.assertTrue(daemon._retain_root)

    def test_marker_writer_timeout_kills_and_reaps_private_process(self):
        path = ROOT / "Tests/Compatibility/test_managed_storage.py"
        tree = ast.parse(path.read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "retain_failure")
        marker = Mock(pid=12345); marker.wait.side_effect = [subprocess.TimeoutExpired("marker", 1), 0]
        killed = []
        namespace = dict(time=time, sys=sys, subprocess=SimpleNamespace(Popen=lambda *a, **kw: marker, DEVNULL=-3),
                         os=SimpleNamespace(killpg=lambda *a: killed.append(a)), signal=signal, __file__=str(path))
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
        daemon = SimpleNamespace(binary="binary", work="work", _retain_root=False)
        with self.assertRaises(subprocess.TimeoutExpired): namespace[function.name](daemon, time.monotonic() + 3)
        self.assertTrue(daemon._retain_root); self.assertEqual(marker.wait.call_count, 2)
        self.assertEqual(killed, [(12345, signal.SIGKILL)])

    def test_cleanup_fault_stops_deleting_then_only_contains_owned_workloads(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_storage.py").read_text())
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        body = next(n.finalbody for n in run.body if isinstance(n, ast.Try) and n.finalbody)
        plan = smoke.names("a" * 32); events = []
        def container(name):
            def remove(**kw): events.append(("remove", name)); raise TimeoutError()
            return SimpleNamespace(name=name, attrs={"Config": {"Labels": {smoke.OWNER: plan["owner"]}}},
                remove=remove, stop=lambda **kw: events.append(("stop", name)))
        client = SimpleNamespace(containers=SimpleNamespace(get=container), volumes=None, images=None, close=lambda: None)
        namespace = dict(failed=False, plan=plan, client=client, campaign=SimpleNamespace(api_deadline=lambda *a: nullcontext()),
            owned=smoke.owned, time=time, final_deadline=time.monotonic() + 10, started=time.monotonic(), directory="artifacts",
            daemon=SimpleNamespace(retain_root=lambda **kw: events.append(("retain", kw["reason"]))), record=lambda *a, **kw: None,
            begin=lambda *a, **kw: None, active_step=smoke.step_evidence("cleanup-remove"),
            failure_details=lambda error: smoke.error_evidence(error)[0])
        with self.assertRaises(RuntimeError): exec(compile(ast.Module(body=body, type_ignores=[]), "cleanup", "exec"), namespace)
        self.assertEqual([event[0] for event in events], ["remove", "retain", "stop", "retain"])
        self.assertEqual(events[0][1], plan["containers"][1])
        self.assertEqual(events[2][1], plan["containers"][0])

    def test_owner_and_name_required_before_delete(self):
        token = uuid.uuid4().hex; plan = smoke.names(token)
        good = SimpleNamespace(name=plan["volume"], attrs={"Labels": {smoke.OWNER: token}})
        self.assertIs(smoke.owned(good, "volume", plan["volume"], token), good)
        for name, owner in (("other", token), (plan["volume"], "other")):
            with self.assertRaises(ValueError): smoke.owned(good, "volume", name, owner)
        for token in ("", "../escape", "a" * 31, 1):
            with self.assertRaises(ValueError): smoke.names(token)

    def test_fixture_deterministic_copyup_metadata_and_bound(self):
        plan = smoke.names("a" * 32)
        first, config = smoke.image_archive(b"inert-not-executable", plan)
        self.assertEqual((first, config), smoke.image_archive(b"inert-not-executable", plan))
        with tarfile.open(fileobj=io.BytesIO(first)) as outer:
            with tarfile.open(fileobj=io.BytesIO(outer.extractfile("layer.tar").read())) as layer:
                self.assertEqual(layer.getnames(), ["probe", "run", "data", "data/seed"])
                for name, mode in (("data", 0o750), ("data/seed", 0o640)):
                    entry = layer.getmember(name)
                    self.assertEqual((entry.mode, entry.uid, entry.gid, entry.mtime), (mode, 10001, 10002, smoke.MTIME))
        for bad in (b"", b"x" * (8 * 1024 * 1024 + 1)):
            with self.assertRaises(ValueError): smoke.image_archive(bad, plan)

    def test_initial_evidence_atomic_publication_syncs_file_and_directory_chain(self):
        token = "a" * 32
        value = {"phase": "plan", "plan": smoke.names(token), "seconds": 90}
        real_fsync, real_link = os.fsync, os.link
        synced = []
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / ".build/managed-storage-smoke" / token / "evidence.jsonl"
            def sync(fd):
                info = os.fstat(fd)
                synced.append((info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)))
                real_fsync(fd)
            def publish(source, destination, **kwargs):
                self.assertFalse(evidence.exists())
                self.assertEqual(synced[-1][2], stat.S_IFREG)
                return real_link(source, destination, **kwargs)
            with patch.object(smoke.os, "fsync", side_effect=sync), patch.object(smoke.os, "link", side_effect=publish):
                directory, used = smoke.initialize_evidence(root, token, value)
            self.assertEqual(json.loads(evidence.read_bytes()), value)
            self.assertEqual(used, evidence.stat().st_size)
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual([p.name for p in directory.iterdir()], ["evidence.jsonl"])
            expected = [root, root / ".build", evidence, directory, directory.parent]
            self.assertEqual(synced, [(p.stat().st_dev, p.stat().st_ino, stat.S_IFMT(p.stat().st_mode)) for p in expected])

    def test_initial_evidence_rejects_reuse_symlinks_and_sync_failure(self):
        token = "a" * 32
        value = {"phase": "plan", "plan": smoke.names(token)}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory, _ = smoke.initialize_evidence(root, token, value)
            before = (directory / "evidence.jsonl").read_bytes()
            with self.assertRaises(FileExistsError): smoke.initialize_evidence(root, token, value)
            self.assertEqual((directory / "evidence.jsonl").read_bytes(), before)
            other = "b" * 32
            (directory.parent / other).symlink_to(directory, target_is_directory=True)
            with self.assertRaises(FileExistsError):
                smoke.initialize_evidence(root, other, {"phase": "plan", "plan": smoke.names(other)})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / ".build").symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError): smoke.initialize_evidence(root, token, value)
            self.assertFalse((root / "managed-storage-smoke").exists())
        for fail_at in range(1, 6):
            with tempfile.TemporaryDirectory() as temp:
                calls = 0
                real_fsync = os.fsync
                def fail_sync(fd):
                    nonlocal calls
                    calls += 1
                    if calls == fail_at: raise OSError("sync failed")
                    real_fsync(fd)
                with patch.object(smoke.os, "fsync", side_effect=fail_sync), self.assertRaises(OSError):
                    smoke.initialize_evidence(Path(temp), token, value)
                self.assertEqual(calls, fail_at)

    def test_initial_evidence_rejects_unowned_or_shared_writable_ancestors(self):
        token = "a" * 32
        value = {"phase": "plan", "plan": smoke.names(token)}
        for relative in (".", ".build", ".build/managed-storage-smoke"):
            for mode in (0o770, 0o777):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    ancestor = root / relative
                    ancestor.mkdir(parents=True, exist_ok=True)
                    ancestor.chmod(mode)
                    with self.assertRaises(ValueError): smoke.initialize_evidence(root, token, value)
                    self.assertFalse((root / ".build/managed-storage-smoke" / token).exists())
        with tempfile.TemporaryDirectory() as temp:
            wrong_owner = SimpleNamespace(st_uid=os.geteuid() + 1, st_mode=stat.S_IFDIR | 0o700)
            with patch.object(smoke.os, "fstat", return_value=wrong_owner), self.assertRaises(ValueError):
                smoke.initialize_evidence(Path(temp), token, value)
            self.assertFalse((Path(temp) / ".build").exists())

    def test_initial_evidence_finishes_before_any_sdk_client(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_storage.py").read_text())
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        calls = {ast.unparse(n.func): n.lineno for n in ast.walk(run) if isinstance(n, ast.Call)}
        self.assertLess(calls["initialize_evidence"], calls["docker.DockerClient"])

    def test_journal_reader_type_bound_and_hashes(self):
        manifest, state, _ = journal()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); folder = root / "managed-storage"; folder.mkdir()
            for name, value in (("manifest.json", manifest), ("state.json", state)):
                (folder / name).write_text(json.dumps(value))
            actual_manifest, actual_state, hashes = smoke.public_state(root)
            self.assertEqual((actual_manifest, actual_state), (manifest, state))
            self.assertEqual(hashes["state_sha256"], smoke.digest((folder / "state.json").read_bytes()))
            (folder / "state.json").write_bytes(b"x" * (smoke.MAX_STATE + 1))
            with self.assertRaises(ValueError): smoke.public_state(root)
            (folder / "state.json").unlink(); (folder / "state.json").symlink_to(folder / "manifest.json")
            with self.assertRaises(OSError): smoke.public_state(root)


class FakeAPIError(Exception):
    def __init__(self, message, status=500):
        super().__init__(message)
        self.response = SimpleNamespace(status_code=status)


class ErrorObservabilityTests(unittest.TestCase):
    def test_public_error_is_closed_class_status_code_and_hash_only(self):
        error = FakeAPIError('500 URL=http://private.example/token SECRET_BODY')
        public, raw = smoke.error_evidence(error, api_error=True)
        self.assertEqual(set(public), {"error_type", "error_code", "http_status", "raw_error_sha256", "raw_error_bytes"})
        self.assertEqual((public["error_type"], public["http_status"], public["error_code"]), ("APIError", 500, "internal-error"))
        self.assertEqual(public["raw_error_sha256"], smoke.digest(raw))
        self.assertEqual(raw, str(error).encode())
        self.assertNotIn("SECRET", json.dumps(public)); self.assertNotIn("private.example", json.dumps(public))
        unknown = type("SECRET_CLASS", (Exception,), {})("SECRET_BODY")
        public, _ = smoke.error_evidence(unknown)
        self.assertEqual(public["error_type"], "UnexpectedError")
        self.assertNotIn("SECRET", json.dumps(public))

    def test_error_status_and_classification_reject_untyped_or_unbounded_values(self):
        for status in (True, "500 SECRET", {"secret": 500}, 99, 600, None):
            public, _ = smoke.error_evidence(FakeAPIError("private", status), api_error=True)
            self.assertIsNone(public["http_status"])
            self.assertEqual(public["error_code"], "no-http-status")
        for status, code in ((400, "bad-request"), (403, "forbidden"), (409, "conflict"), (503, "service-unavailable"), (418, "http-error")):
            public, _ = smoke.error_evidence(FakeAPIError("private", status), api_error=True)
            self.assertEqual(public["error_code"], code)
        for error, name in ((TimeoutError("private"), "TimeoutError"), (OSError("private"), "OSError"), (ValueError("private"), "ValueError")):
            self.assertEqual(smoke.error_evidence(error)[0]["error_type"], name)
        for value in (1, None, "true"):
            with self.assertRaises(ValueError): smoke.error_evidence(FakeAPIError("private"), api_error=value)

    def test_falsey_http_error_response_keeps_status(self):
        class Response:
            status_code = 500
            def __bool__(self): return False
        error = FakeAPIError("private"); error.response = Response()
        self.assertEqual(smoke.error_evidence(error, api_error=True)[0]["http_status"], 500)

    def test_private_error_first_file_is_0600_bounded_and_synced(self):
        raw = ("private-Ω" * 1000).encode(); token = "a" * 32
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); synced = []; real = os.fsync
            with patch.object(smoke.os, "fsync", side_effect=lambda fd: (synced.append(stat.S_IFMT(os.fstat(fd).st_mode)), real(fd))):
                public = smoke.write_private_error(root, token, raw)
            path = root / public["private_error_file"]
            self.assertEqual(path.read_bytes(), raw[:4096]); self.assertEqual(path.stat().st_size, 4096)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(synced, [stat.S_IFREG, stat.S_IFDIR])
            self.assertTrue(public["private_error_truncated"])
            self.assertNotIn(str(root), json.dumps(public)); self.assertNotIn("Ω", json.dumps(public))
            with self.assertRaises(FileExistsError): smoke.write_private_error(root, token, b"replacement")
            self.assertEqual(path.read_bytes(), raw[:4096])

    def test_private_error_symlinks_shared_roots_and_short_writes_fail_closed(self):
        token = "a" * 32
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); original = root / "original"; original.write_bytes(b"preserve")
            (root / ("rtm078-api-error-" + token + ".log")).symlink_to(original)
            with self.assertRaises(FileExistsError): smoke.write_private_error(root, token, b"private")
            self.assertEqual(original.read_bytes(), b"preserve")
            link = root / "root-link"; link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError): smoke.write_private_error(link, "b" * 32, b"private")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o777)
            with self.assertRaises(ValueError): smoke.write_private_error(root, token, b"private")
            self.assertEqual(list(root.iterdir()), [])
        with tempfile.TemporaryDirectory() as temp, patch.object(smoke.os, "write", return_value=0):
            with self.assertRaises(ValueError): smoke.write_private_error(Path(temp), token, b"private")
        with tempfile.TemporaryDirectory() as temp, patch.object(smoke.os, "fsync", side_effect=OSError("full")):
            with self.assertRaises(OSError): smoke.write_private_error(Path(temp), token, b"private")
        for token in ("../escape", "a" * 31, None):
            with self.assertRaises(ValueError): smoke.write_private_error(Path("/not-opened"), token, b"private")

    def test_private_error_short_writes_retry_and_failed_partial_is_synced(self):
        token = "a" * 32; real_write, real_sync = os.write, os.fsync
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); calls = 0
            def short_write(fd, data):
                nonlocal calls
                calls += 1
                if calls == 1: raise InterruptedError()
                return real_write(fd, data[:1])
            with patch.object(smoke.os, "write", side_effect=short_write):
                public = smoke.write_private_error(root, token, b"private")
            self.assertEqual((root / public["private_error_file"]).read_bytes(), b"private")
            self.assertEqual(calls, 8)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); calls = 0; synced = []
            def fail_after_prefix(fd, data):
                nonlocal calls
                calls += 1
                if calls > 1: raise OSError("disk full")
                return real_write(fd, data[:3])
            with patch.object(smoke.os, "write", side_effect=fail_after_prefix), patch.object(smoke.os, "fsync", side_effect=lambda fd: (synced.append(stat.S_IFMT(os.fstat(fd).st_mode)), real_sync(fd))):
                with self.assertRaises(OSError): smoke.write_private_error(root, token, b"private")
            self.assertEqual((root / ("rtm078-api-error-" + token + ".log")).read_bytes(), b"pri")
            self.assertEqual(synced, [stat.S_IFREG, stat.S_IFDIR])

    def test_steps_reject_private_labels_and_invalid_consumer_indices(self):
        self.assertEqual(smoke.step_evidence("container-start", consumer=0), {"step": "container-start", "consumer": 0, "command": None})
        for step in ("SECRET", {}, None):
            with self.assertRaises(ValueError): smoke.step_evidence(step)
        for consumer in (True, 2, -1, "0"):
            with self.assertRaises(ValueError): smoke.step_evidence("container-start", consumer=consumer)
        with self.assertRaises(ValueError): smoke.step_evidence("exec-start", command="SECRET")

    def test_first_start_step_is_durable_before_API_failure(self):
        path = ROOT / "Tests/Compatibility/test_managed_storage.py"
        tree = ast.parse(path.read_text())
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        call = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "call")
        events = []; namespace = {}
        def begin(step, **kwargs):
            namespace["active_step"] = smoke.step_evidence(step, **kwargs)
            events.append(("step", namespace["active_step"]))
        def api_call(*args, **kwargs):
            events.append(("api", {})); raise FakeAPIError("private start failure")
        namespace.update(begin=begin, campaign=SimpleNamespace(api_call=api_call), client=object(), work_deadline=100,
                         record=lambda phase, **value: events.append((phase, value)))
        exec(compile(ast.Module(body=[call], type_ignores=[]), str(path), "exec"), namespace)
        with self.assertRaises(FakeAPIError): namespace["call"](object(), step="container-start", consumer=0)
        self.assertEqual(events, [("step", smoke.step_evidence("container-start", consumer=0)), ("api", {})])
        wrapper_calls = [n for n in ast.walk(run) if isinstance(n, ast.Call) and ast.unparse(n.func) == "call"]
        self.assertTrue(wrapper_calls)
        self.assertTrue(all(any(k.arg == "step" for k in n.keywords) for n in wrapper_calls))

    def test_failure_latches_retention_and_publishes_public_hash_before_private_log(self):
        path = ROOT / "Tests/Compatibility/test_managed_storage.py"; tree = ast.parse(path.read_text())
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        handler = next(n for n in run.body if isinstance(n, ast.Try) and n.finalbody).handlers[0]
        error = FakeAPIError("PRIVATE_START_FAILURE"); token = "a" * 32
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); events = []
            def record(phase, **value): events.append((phase, value))
            namespace = dict(error=error, daemon=SimpleNamespace(root=root, retain_root=lambda **kw: events.append(("retain", {}))),
                docker=SimpleNamespace(errors=SimpleNamespace(APIError=FakeAPIError)), error_evidence=smoke.error_evidence,
                write_private_error=smoke.write_private_error, active_step=smoke.step_evidence("container-start", consumer=0),
                record=record, plan=smoke.names(token), directory=root / ".build/public", REPO_ROOT=root,
                failure_details=lambda e: smoke.error_evidence(e)[0])
            body = ast.Try(body=[ast.Raise(exc=ast.Name(id="error", ctx=ast.Load()))], handlers=[copy.deepcopy(handler)], orelse=[], finalbody=[])
            ast.fix_missing_locations(body)
            with self.assertRaises(FakeAPIError): exec(compile(ast.Module(body=[body], type_ignores=[]), str(path), "exec"), namespace)
            self.assertEqual([phase for phase, _ in events], ["retain", "failure", "private-error"])
            self.assertEqual(events[1][1]["step"], "container-start"); self.assertEqual(events[1][1]["consumer"], 0)
            self.assertEqual(events[1][1]["http_status"], 500)
            self.assertNotIn("PRIVATE_START_FAILURE", json.dumps(events))
            self.assertEqual((root / events[2][1]["private_error_file"]).read_bytes(), str(error).encode())


if __name__ == "__main__": unittest.main()
