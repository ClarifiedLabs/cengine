#!/usr/bin/env python3
"""Engine-free RTM-080 guards; stdlib only, no Go/Docker/VM/helper execution."""
from __future__ import annotations

import ast
import copy
import io
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from lifecycle_backend_fixture import create_backend

ROOT = Path(__file__).resolve().parents[2]
COMPAT = ROOT / "Tests/Compatibility"
sys.path.insert(0, str(COMPAT))
import managed_storage as smoke
import storage_backend_proof as backend
from volume_probe import read_bounded


def load_functions(path, namespace, *, exclude=()):
    """Do not import optional SDK/pytest or execute a compatibility entrypoint."""
    tree = ast.parse(path.read_text())
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name not in exclude:
            definition = copy.deepcopy(node)
            definition.decorator_list = []
            nodes.append(definition)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            nodes.append(node)
    module = ModuleType(path.stem)
    module.__dict__.update(namespace)
    # Exercise the compatibility assertions even under this proof runner's -O.
    # The actual managed entrypoint separately rejects optimized Python.
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec", optimize=0), module.__dict__)
    return module, tree


DIRECT = COMPAT / "test_volume_xattrs.py"
direct, _ = load_functions(DIRECT, dict(hashlib=__import__("hashlib"), io=io, json=json, struct=struct,
    tarfile=tarfile, Path=Path, __file__=str(DIRECT)))
PATH = COMPAT / "test_managed_volume_xattrs.py"
namespace = dict(io=io, json=json, os=os, Path=Path, signal=signal, stat=stat, struct=struct, subprocess=subprocess,
    sys=sys, tarfile=tarfile, time=time, SimpleNamespace=SimpleNamespace, uuid=__import__("uuid"),
    smoke=smoke, backend=backend, direct=direct, read_bounded=read_bounded, __file__=str(PATH),
    Mount=lambda **kw: kw, REPO_ROOT=ROOT)
case, TREE = load_functions(PATH, namespace)
namespace = case.__dict__


def resource(name, kind="container"):
    labels = {smoke.OWNER: "a" * 32}
    return SimpleNamespace(name=name, id=name, attrs={"Labels": labels} if kind == "volume" else
        {"Config": {"Labels": labels}}, start=Mock(), stop=Mock(), remove=Mock())


def link_proof(path, capability=None):
    target, uid, gid, mtime, attrs = direct.SYMLINKS[path]
    return dict(mode=0o120777, owner=uid, group=gid, target=target, mtime_ns=mtime * 1000000000,
                ctime_ns=1, list_errno=0, attrs={k: (capability if k == direct.CAP and capability is not None else v).hex()
                                               for k, v in attrs.items()})


def outside_proof():
    return dict(mode=0o100644, owner=0, group=0, mtime_ns=0, ctime_ns=1, list_errno=0,
                attrs={direct.USER: direct.SENTINEL_ATTRS[direct.USER].hex()}, value=direct.SENTINEL.hex())


def direct_probe(container, operation, path, *args, user="0:0"):
    if operation == "symlink-proof":
        prefix = "/populated/" if path == "populated" else "/links/"
        return {"links": {p: link_proof(p) for p in direct.SYMLINKS if p.startswith(prefix)}, "outside": outside_proof()}
    if operation == "capability-controls":
        rows = []
        for phase in (("caller", "uid-zero-no-caps") if user == "0:0" else ("caller",)):
            for p in ("/populated/cap-live", "/populated/cap-dangling"):
                allowed = phase == "caller" and user == "0:0"
                row = dict(phase=phase, path=p, caps=1 << 31 if allowed else 0, errno=0 if allowed else 1,
                           link=link_proof(p, direct.CAP_CHANGED if allowed else direct.CAPABILITY),
                           outside_before=outside_proof(), outside_after=outside_proof())
                if allowed:
                    row.update(restore_errno=0, restored=link_proof(p), outside_restored=outside_proof())
                rows.append(row)
        return {"controls": rows}
    if operation == "read":
        return {"errno": 13 if user == "10002:10002" else 0,
                "value": (direct.SENTINEL if path == "/sentinel" else direct.PAYLOAD).hex()}
    if operation == "get-follow":
        return {"errno": 0, "value": direct.SENTINEL_ATTRS[direct.USER].hex()}
    if operation == "get":
        value = direct.SENTINEL_ATTRS.get(args[0]) if path == "/sentinel" else None
        return {"errno": 61 if value is None else 0, "value": "" if value is None else value.hex()}
    name, value = args
    if path == "/populated/link":
        return {"errno": {direct.USER: 1, direct.ACCESS: 95, direct.DEFAULT: 95, direct.CAP: 22}[name]}
    if user != "0:0":
        return {"errno": 13}
    return {"errno": 22 if name == direct.CAP else 13}


class ManagedXattrsTests(unittest.TestCase):
    def test_archive_exact_source_pax_layer_and_owned_content_identity(self):
        plan = smoke.names("a" * 32)
        result = case.image_archive(b"inert-probe", plan)
        self.assertEqual(result, case.image_archive(b"inert-probe", plan))
        archive, config, content_tag = result
        self.assertEqual(config["config"]["Labels"][smoke.OWNER], plan["owner"])
        self.assertTrue(content_tag.endswith(direct._digest(direct._encode(config)).split(":")[1]))
        with tarfile.open(fileobj=io.BytesIO(archive)) as outer:
            manifest = json.loads(outer.extractfile("manifest.json").read())[0]
            self.assertIn(content_tag, manifest["RepoTags"])
            layer = outer.extractfile("layer.tar").read()
            self.assertEqual(direct._digest(layer), config["rootfs"]["diff_ids"][0])
            with tarfile.open(fileobj=io.BytesIO(layer), encoding="utf-8", errors="surrogateescape") as inner:
                for path, expected in direct.EXPECTED.items():
                    attrs = inner.getmember(path.lstrip("/")).pax_headers
                    self.assertEqual({k.removeprefix("SCHILY.xattr."): v.encode("utf-8", "surrogateescape")
                                      for k, v in attrs.items() if k.startswith("SCHILY.xattr.")}, expected)
                self.assertTrue(inner.getmember("populated/link").issym())
        with self.assertRaises(ValueError): case.image_archive(b"", plan)

    def test_both_consumers_created_before_either_start_source_has_no_volumes(self):
        plan = smoke.names("a" * 32)
        events, creates = [], []
        def create(image, **kw):
            value = resource(kw["name"])
            creates.append(kw)
            events.append(("create", value.name))
            value.start.side_effect = lambda: events.append(("start", value.name))
            return value
        client = SimpleNamespace(containers=SimpleNamespace(create=create), volumes=SimpleNamespace(
            create=lambda name, **kw: resource(name, "volume")))
        gets, sets = [], []
        def probe(container, operation, *args, **kw):
            if operation == "fs": return {"mountinfo": "mounts"}
            sets.append((container.name, *args))
            return {"errno": 0}
        with patch.object(direct, "_assert_ext4") as ext4, patch.object(direct, "_assert_metadata") as metadata, \
                patch.object(direct, "_probe", side_effect=probe), patch.object(direct, "_get", side_effect=lambda *a: gets.append(a)), \
                patch.dict(namespace, negative_proof=Mock(return_value=[13]), shared_proof=Mock(return_value=[])):
            case.exercise(client, SimpleNamespace(id="owned-image"), ["empty-volume", "populated-volume"], plan,
                          lambda operation, *a, **kw: operation(*a, **kw), lambda c: c, Path("unused"), lambda *a, **kw: None)
        self.assertNotIn("mounts", creates[0]); self.assertNotIn("volumes", creates[0])
        self.assertEqual(ext4.call_count, 2); self.assertEqual(metadata.call_count, 6)
        for container in plan["containers"]:
            for other in plan["containers"]:
                self.assertLess(events.index(("create", container)), events.index(("start", other)))
        self.assertEqual([mount["source"] for mount in creates[1]["mounts"]], ["empty-volume", "populated-volume"])
        self.assertEqual(creates[1]["mounts"], creates[2]["mounts"])
        self.assertTrue(all(not mount["no_copy"] for mount in creates[1]["mounts"]))
        self.assertEqual(len(sets), 8); self.assertEqual(len(gets), 8)
        self.assertEqual(sets[0][0], gets[1][0].name)  # Restoring reader is checked by original writer.
        self.assertEqual(sets[1][-1], direct.DIRECTORY_ATTRS[direct.USER].hex())

    def test_valid_symlink_controls_reject_loss_denial_target_change_and_credential_shortcuts(self):
        def run(change):
            def probe(*args, **kw):
                result = direct_probe(*args, **kw)
                if args[1] == "capability-controls": change(result["controls"])
                return result
            with patch.object(direct, "_probe", side_effect=probe):
                direct._assert_symlink_capability_controls(None)
        run(lambda rows: None)
        for change in (
            lambda rows: rows[0].update(errno=1),
            lambda rows: rows[0]["link"].update(attrs={}),
            lambda rows: rows[0]["link"].update(mtime_ns=0),
            lambda rows: rows[0]["outside_after"].update(ctime_ns=2),
            lambda rows: rows[0].update(restore_errno=1),
            lambda rows: rows[0].update(caps=0),
        ):
            with self.assertRaises(AssertionError): run(change)
        def lost_caps(*args, **kw):
            result = direct_probe(*args, **kw)
            if args[1] == "symlink-proof": result["links"]["/populated/cap-dangling"]["attrs"] = {}
            return result
        with patch.object(direct, "_probe", side_effect=lost_caps), self.assertRaises(AssertionError):
            direct._assert_symlinks(None)

    def test_extended_campaign_has_398_probes_with_unchanged_400_bound(self):
        plan = smoke.names("a" * 32)
        client = SimpleNamespace(containers=SimpleNamespace(create=lambda image, **kw: resource(kw["name"])),
                                 volumes=SimpleNamespace(create=lambda name, **kw: resource(name, "volume")))
        attrs = copy.deepcopy(direct.EXPECTED)
        calls = []
        def probe(container, operation, path, *args, user="0:0"):
            calls.append((operation, path))
            if operation in ("symlink-proof", "capability-controls", "get-follow") or path == "/populated/link":
                return direct_probe(container, operation, path, *args, user=user)
            if operation == "fs": return {"magic": 0xEF53, "mountinfo": "20 1 254:0 / / rw - ext4 root rw\n"}
            if operation == "stat":
                directory = path in ("/", "/empty", "/populated", "/populated/child")
                return dict(owner=0, group=0, mode=(0o40000 if directory else 0o100000) | (0o644 if path == "/sentinel" else 0o750), dev=0xfe00, rdev=0)
            if operation == "read":
                if path.startswith("/sys/"): return {"errno": 2}
                return direct_probe(container, operation, path, *args, user=user)
            if operation == "get":
                value = attrs.get(path, {}).get(args[0])
                return {"errno": 61 if value is None else 0, "value": "" if value is None else value.hex()}
            if operation == "set" and user == "0:0" and args[0] == direct.USER:
                attrs[path][args[0]] = bytes.fromhex(args[1])
                return {"errno": 0}
            return direct_probe(container, operation, path, *args, user=user)
        with patch.object(direct, "_probe", side_effect=probe), patch.dict(namespace, shared_proof=Mock(return_value=[])):
            case.exercise(client, SimpleNamespace(id="owned-image"), ["v-empty", "v-populated"], plan,
                          lambda operation, *a, **kw: operation(*a, **kw), lambda c: c, Path("unused"), lambda *a, **kw: None)
        self.assertEqual(len(calls), 398)
        self.assertLessEqual(len(calls), case.MAX_PROBES)

    def test_exact_negative_errno_not_normalized(self):
        with patch.object(direct, "_probe", side_effect=direct_probe):
            baseline = case.negative_proof(None)
            self.assertEqual(case.negative_proof(None, baseline), baseline)
        def mismatch(*args, **kw):
            result = direct_probe(*args, **kw)
            if args[1] == "set" and args[2] == "/empty" and kw.get("user") == "10001:10001":
                result["errno"] = 1  # Both source-supported, but NOT the observed 13.
            return result
        with patch.object(direct, "_probe", side_effect=mismatch), self.assertRaisesRegex(ValueError, "mismatch"):
            case.negative_proof(None, baseline)
        for errno in (0, 95, True, "13"):
            def bad(*args, **kw):
                result = direct_probe(*args, **kw)
                if args[1] == "set" and args[2] == "/empty": result["errno"] = errno
                return result
            with self.subTest(errno=errno), patch.object(direct, "_probe", side_effect=bad), self.assertRaises(ValueError):
                case.negative_proof(None)

    def test_symlink_target_mutation_fails(self):
        def bad(*args, **kw):
            result = direct_probe(*args, **kw)
            if args[1:3] == ("get", "/sentinel") and args[3] == direct.USER:
                result["value"] = "00"
            return result
        with patch.object(direct, "_probe", side_effect=bad), self.assertRaisesRegex(ValueError, "symlink target"):
            case.negative_proof(None)

    def test_shared_proof_requires_original_root_managed_selection_exact_fuse_and_topology(self):
        volumes = [SimpleNamespace(name=role) for role in ("v-empty", "v-populated")]
        mounts = "20 1 254:0 / / rw - ext4 root rw\n" + "".join(
            f"{index} 20 0:{index} / /{role} rw - fuse.managed-v3 managed-v3 rw\n"
            for index, role in enumerate(("empty", "populated"), 30))
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ):
            root = Path(temp)
            manifest_path = create_backend(root)
            mode = json.loads(manifest_path.read_bytes())
            identity = mode["root"]
            (root / "volume-storage.json").write_text(json.dumps({v.name: "shared" for v in volumes}))
            self.assertEqual(len(case.shared_proof(root, volumes, mounts)), 2)
            secret_mounts = mounts.replace("managed-v3 rw", "managed-v3 rw,token=PRIVATE_TOKEN")
            self.assertNotIn("PRIVATE_TOKEN", json.dumps(case.shared_proof(root, volumes, secret_mounts)))
            topology = root / "volume-storage.json"
            external = root / "external.json"
            topology.rename(external)
            topology.symlink_to(external)
            with self.assertRaises(OSError): case.shared_proof(root, volumes, mounts)
            topology.unlink()
            external.rename(topology)
            for invalid in (mounts.replace("fuse.managed-v3", "nfs"), mounts.replace("managed-v3 rw", "wrong rw"),
                            mounts.replace("fuse.managed-v3", "ext4"), mounts + mounts,
                            mounts + "40 30 0:40 / /populated/child rw - tmpfs tmpfs rw\n"):
                with self.assertRaises(ValueError): case.shared_proof(root, volumes, invalid)
            for change in ({**mode, "mode": "legacy"}, {**mode, "root": {**identity, "inode": identity["inode"] + 1}}):
                manifest_path.write_text(json.dumps(change))
                with self.assertRaises(ValueError): case.shared_proof(root, volumes, mounts)
            manifest_path.write_text(json.dumps(mode))
            (root / "volume-storage.json").write_text('{"v-empty":"block","v-populated":"shared"}')
            with self.assertRaises(ValueError): case.shared_proof(root, volumes, mounts)
            backend._ROOT_PINS.pop(str(root.absolute()))

    def test_topology_same_size_rewrite_with_restored_mtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backend.capture_backend_root(root)
            self.addCleanup(backend._ROOT_PINS.pop, str(root.absolute()))
            topology = root / "volume-storage.json"
            original = b'{"volume":"shared"}'
            topology.write_bytes(original)
            before = topology.stat()
            calls = 0
            real_fstat = os.fstat
            def observed(fd):
                nonlocal calls
                value = real_fstat(fd)
                if stat.S_ISREG(value.st_mode):
                    calls += 1
                    if calls == 2:  # After read, before descriptor revalidation.
                        topology.write_bytes(original.replace(b"shared", b"block "))
                        os.utime(topology, ns=(before.st_atime_ns, before.st_mtime_ns))
                        value = real_fstat(fd)
                return value
            with patch.object(os, "fstat", side_effect=observed), self.assertRaisesRegex(ValueError, "topology changed during read"):
                case.shared_proof(root, [], "")
            after = topology.stat()
            self.assertEqual((after.st_size, after.st_mtime_ns), (before.st_size, before.st_mtime_ns))
            self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)

    def test_journal_pins_initial_bytes_checks_bound_and_closes_both_descriptors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            plan = smoke.names("a" * 32)
            initial = {"phase": "plan", "plan": plan, "case": "RTM-080"}
            directory, used = smoke.initialize_evidence(root, plan["owner"], initial)
            raw = (json.dumps(initial, sort_keys=True) + "\n").encode()
            self.assertEqual(used, len(raw))
            with case.EvidenceJournal(directory, raw) as journal:
                descriptors = [journal.directory_fd, journal.fd]
                journal.append(b'{"phase":"probe"}\n')
                self.assertEqual((directory / "evidence.jsonl").read_bytes(), raw + b'{"phase":"probe"}\n')
                with self.assertRaisesRegex(ValueError, "artifact bound"):
                    journal.append(b"x" * (1024 * 1024))
            for fd in descriptors:
                with self.assertRaises(OSError): os.fstat(fd)
            with self.assertRaisesRegex(ValueError, "initial evidence mismatch"):
                case.EvidenceJournal(directory, b"x" * (directory / "evidence.jsonl").stat().st_size)

    def test_journal_rejects_replaced_parent_hardlinks_fifo_and_modified_file_before_append(self):
        for replacement in ("parent", "file", "hardlink", "extra-link", "fifo", "mode", "rewrite", "owner"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp) / "journal"
                directory.mkdir(mode=0o700)
                path = directory / "evidence.jsonl"
                initial = b'initial\n'
                path.write_bytes(initial); path.chmod(0o600)
                victim = Path(temp) / "victim"
                victim.write_bytes(initial); victim.chmod(0o600)
                with case.EvidenceJournal(directory, initial) as journal:
                    if replacement == "parent":
                        directory.rename(Path(temp) / "original")
                        directory.mkdir(mode=0o700)
                        path.write_bytes(initial); path.chmod(0o600)
                    elif replacement in ("file", "hardlink", "fifo"):
                        path.unlink()
                        if replacement == "file": path.write_bytes(initial); path.chmod(0o600)
                        elif replacement == "hardlink": os.link(victim, path)
                        else: os.mkfifo(path, 0o600)
                    elif replacement == "extra-link":
                        os.link(path, Path(temp) / "alias")
                    elif replacement == "mode":
                        path.chmod(0o644)
                    elif replacement == "rewrite":
                        before = path.stat()
                        path.write_bytes(b'changed\n')
                        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                    real_fstat = os.fstat
                    def observed(fd):
                        info = real_fstat(fd)
                        if replacement == "owner" and fd == journal.fd:
                            return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1,
                                                   st_nlink=info.st_nlink, st_size=info.st_size)
                        return info
                    with patch.object(os, "fstat", side_effect=observed), patch.object(os, "write") as write:
                        with self.assertRaises(ValueError): journal.append(b'append\n')
                        write.assert_not_called()
                self.assertEqual(victim.read_bytes(), initial)

    def test_journal_fifo_swap_during_open_never_blocks_or_leaks_descriptors(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            path = directory / "evidence.jsonl"
            path.write_bytes(b'initial\n'); path.chmod(0o600)
            real_open = os.open
            opened = []
            def substitute(name, flags, *args, **kwargs):
                if name == "evidence.jsonl":
                    self.assertTrue(flags & os.O_NONBLOCK)
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    path.unlink(); os.mkfifo(path, 0o600)
                fd = real_open(name, flags, *args, **kwargs)
                opened.append(fd)
                return fd
            with patch.object(os, "open", side_effect=substitute), self.assertRaises(ValueError):
                case.EvidenceJournal(directory, b'initial\n')
            self.assertEqual(len(opened), 2)
            for fd in opened:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_optimized_assertions_fail_closed(self):
        # Test the flag and inherited environment independently, even under -O.
        with patch.dict(os.environ, {"PYTHONOPTIMIZE": "0"}):
            with patch.dict(namespace, sys=SimpleNamespace(flags=SimpleNamespace(optimize=1))):
                with self.assertRaises(ValueError): case.require_assertions()
            with patch.dict(namespace, sys=SimpleNamespace(flags=SimpleNamespace(optimize=0))):
                case.require_assertions()
                with patch.dict(os.environ, {"PYTHONOPTIMIZE": "1"}):
                    with self.assertRaises(ValueError): case.require_assertions()

    def test_skip_fixture_no_client_cache_or_cli_dependencies(self):
        functions = {node.name: node for node in TREE.body if isinstance(node, ast.FunctionDef)}
        self.assertEqual([a.arg for a in functions["image_cache"].args.args], ["tmp_path"])
        self.assertNotIn("pytest.skip", ast.unparse(functions["image_cache"]))
        self.assertIn("managed_storage_arguments", ast.unparse(functions["image_cache"]))
        self.assertEqual(functions["verify_docker_cli_target"].args.args, [])
        self.assertEqual([a.arg for a in functions["test_shared_managed_volume_source_xattrs"].args.args], ["daemon"])
        parent = ast.unparse(functions["test_shared_managed_volume_source_xattrs"])
        self.assertIn("backend._ROOT_PINS", parent)
        self.assertNotIn("capture_backend_root", parent)
        self.assertIn("RTM-080", ast.unparse(TREE))

    def test_parent_timeout_reaps_then_retains_without_raw_errors(self):
        daemon = SimpleNamespace(root=Path("/fake-root"), binary="binary", socket="socket", work="work", _retain_root=False)
        process = Mock(pid=12345, returncode=None)
        process.wait.side_effect = [subprocess.TimeoutExpired("secret-token", 234), 0]
        events = []
        # Simulate an admitted, unoptimized parent so -O exercises timeout/reap
        # rather than the separate optimization-rejection guard above.
        with patch.dict(backend._ROOT_PINS, {str(daemon.root): {"mode": "lifecycle", "identity": {}}}), \
                patch.dict(os.environ, {"PYTHONOPTIMIZE": "0"}), \
                patch.object(subprocess, "Popen", return_value=process), \
                patch.object(os, "killpg", side_effect=lambda *a: events.append("kill")), \
                patch.dict(namespace, retain_failure=lambda *a: events.append("retain"),
                           sys=SimpleNamespace(executable=sys.executable, flags=SimpleNamespace(optimize=0)),
                           pytest=SimpleNamespace(fail=Mock(side_effect=ValueError("public failure")))):
            with self.assertRaisesRegex(ValueError, "public failure"):
                case.test_shared_managed_volume_source_xattrs(daemon)
        self.assertEqual(events, ["kill", "retain"])
        self.assertEqual(process.wait.call_count, 2)
        self.assertTrue(daemon._retain_root)

    def test_probe_bounds_credentials_errno_and_no_error_payload_publication(self):
        def run(value, *, exit_code=0, stderr=b"", budget=0):
            payload = json.dumps(value).encode()
            data = struct.pack(">BxxxI", 1, len(payload)) + payload
            if stderr:
                data += struct.pack(">BxxxI", 2, len(stderr)) + stderr
            sock = Mock()
            sock._sock = sock
            sock.recv.side_effect = [data, b""]
            api = SimpleNamespace(exec_create=Mock(return_value={"Id": "exec"}), exec_start=Mock(return_value=sock),
                                  exec_inspect=Mock(return_value={"Running": False, "ExitCode": exit_code}))
            records = []
            probe = case.Probe(SimpleNamespace(id="owned"), SimpleNamespace(api=api),
                               SimpleNamespace(api_deadline=lambda *a: __import__("contextlib").nullcontext()),
                               time.monotonic() + 10, lambda *a, **kw: records.append(kw), [budget])
            with patch.dict(namespace, close_exec_stream=Mock()):
                result = probe.exec_run(["/probe", "get", "/empty", direct.USER], user="0:0")
            return result, records
        good = {"uid": 0, "gid": 0, "errno": 0, "value": "token-must-not-be-in-public-record"}
        _, records = run(good)
        self.assertNotIn("token", json.dumps(records))
        for changes in ({"errno": True}, {"errno": "13"}, {"errno": -1}, {"uid": 10001}):
            with self.assertRaises(ValueError): run({**good, **changes})
        with self.assertRaises(ValueError): run(good, stderr=b"private-token")
        with self.assertRaises(ValueError): run(good, exit_code=1)
        with self.assertRaises(ValueError): run(good, budget=case.MAX_PROBES)

    def test_cleanup_failure_stops_deleting_and_never_removes_foreign_owner(self):
        run = next(node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name == "run_campaign")
        body = next(node.finalbody for node in ast.walk(run) if isinstance(node, ast.Try) and node.finalbody)
        plan = smoke.names("a" * 32)
        events = []
        def get(name):
            value = resource(name)
            if name == plan["containers"][1]:
                value.attrs["Config"]["Labels"][smoke.OWNER] = "foreign"
            value.remove.side_effect = lambda **kw: events.append(("remove", name))
            value.stop.side_effect = lambda **kw: events.append(("stop", name))
            return value
        values = dict(failed=False, plan=plan, volume_names=["empty", "populated"], image_id="owned-image",
            client=SimpleNamespace(containers=SimpleNamespace(get=get), volumes=None, images=None, close=Mock()),
            campaign=SimpleNamespace(api_deadline=lambda *a: __import__("contextlib").nullcontext()),
            final_deadline=time.monotonic() + 10, time=time, smoke=smoke,
            daemon=SimpleNamespace(retain_root=lambda **kw: events.append(("retain", kw["reason"]))),
            record=lambda *a, **kw: None)
        with self.assertRaisesRegex(ValueError, "owned cleanup"):
            exec(compile(ast.Module(body=body, type_ignores=[]), "cleanup", "exec"), values)
        self.assertFalse(any(kind == "remove" for kind, _ in events))
        self.assertEqual([name for kind, name in events if kind == "stop"],
                         [plan["containers"][0], plan["volume"] + "-source"])

    def test_finite_probe_artifact_and_parent_bounds_no_raw_logs(self):
        self.assertEqual(case.MAX_PROBES, 400)
        text = ast.unparse(TREE)
        for required in ("started + 210", "started + 232", "started + 237", "started + 240", "131072", "1024 * 1024",
                         "GOPROXY", "GOSUMDB", "GOTOOLCHAIN", "start_new_session=True"):
            self.assertIn(required, text)
        self.assertNotIn(".logs(", text)
        self.assertNotIn("str(error)", text)
        self.assertNotIn("client.images.pull", text)
        self.assertNotIn("prune", text)


if __name__ == "__main__":
    unittest.main()
