#!/usr/bin/env python3
"""Engine-free RTM-079 guards. No SDK, daemon, VM, install, or host probe execution."""
import ast
import base64
import copy
from contextlib import contextmanager, nullcontext
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import runpy
import signal
import stat
import struct
import subprocess
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
import managed_storage_recovery as recovery
from harness import RuntimeProcess, _runtime_matches

PATH = ROOT / "Tests/Compatibility/test_managed_storage_recovery.py"
TREE = ast.parse(PATH.read_text())
SMOKE = runpy.run_path(str(ROOT / "tools/tests/test-managed-storage-smoke.py"))

def uid(): return str(uuid.uuid4())
def encoded(value): return base64.b64encode(json.dumps(value).encode()).decode()
def envelope(operation, body, request=None):
    return dict(version="bootstrap.v1", operation=operation, request_id=request or uid(), body=body)

def owners():
    store, launch = uid(), uid()
    backing = dict(device=3, inode=40, volumeUUID=uid())
    boot = dict(binding=dict(shimLaunchUUID=launch, guestBootNonce=uid(), ext4UUID=uid(), bytes=4096),
                ready=dict(storeUUID=store, serviceEpoch=uid(), revision=10), diskIdentity=backing)
    before = dict(schema=1, store=store, root=dict(device=3, inode=4, volumeUUID=uid()), backing=backing,
        bytes=4096, revision=10, rootPublicKey=encoded("public-only"), journalExpected=True, bootAttempted=True,
        initialReply=encoded(envelope("registerInitialController", dict(controller=dict(epoch=1, key="f" * 64)))),
        boot=boot, transitions=[])
    after = copy.deepcopy(before); after["revision"] = 20
    keydata = b"public-spki"; key = recovery.digest(keydata); grant = uid()
    issue = envelope("issueTakeoverGrant", dict(grant_id=grant, store=store, expected_epoch=1,
        candidate=dict(public_data=base64.b64encode(keydata).decode())))
    issued = envelope("issueTakeoverGrant", dict(grant=dict(id=grant, store=store, expected_epoch=1, new_key=key),
        signature=base64.b64encode(b"x" * 64).decode()), issue["request_id"])
    confirm = envelope("confirmTakeover", dict(store=store, grant_id=grant, controller=dict(epoch=2, key=key)))
    confirmed = envelope("confirmTakeover", dict(controller=dict(epoch=2, key=key)), confirm["request_id"])
    after["transitions"] = [dict(zip(("issue", "issued", "confirm", "confirmed"), map(encoded, (issue, issued, confirm, confirmed))))]
    newboot = copy.deepcopy(boot); newboot["binding"].update(shimLaunchUUID=uid(), guestBootNonce=uid())
    newboot["ready"].update(serviceEpoch=uid(), revision=11)
    after["serviceTransitions"] = [dict(afterControllerTransitions=1, boot=newboot)]
    return before, after

def snapshot(command="ack", written=False):
    return dict(command=command, ack=command != "verify", file_fsynced=command != "verify", parent_fsynced=command != "verify",
        mountinfo="23 10 0:40 / /data rw,nosuid,nodev - fuse.managed-v3 managed-v3 rw\n", entries=["payload", "seed"],
        root=dict(mode=stat.S_IFDIR | 0o750, uid=10001, gid=10002, nlink=2, size=4096, mtime=recovery.MTIME),
        file=dict(mode=stat.S_IFREG | 0o640, uid=10001, gid=10002, nlink=1, mtime=recovery.MTIME,
                  size=len(recovery.NEXT if written else recovery.PAYLOAD)),
        sha256=recovery.digest(recovery.NEXT if written else recovery.PAYLOAD))

def journal():
    manifest, state, containers = SMOKE["journal"]()
    epoch = uid()
    for intent in state["intents"].values(): intent["serviceEpoch"] = epoch
    return manifest, state, containers

def retire(state):
    for intent in state["intents"].values():
        intent["phase"] = "retired"
        slot = intent["slots"][1]
        slot["receipt"] = dict(store=state["store"], volume=slot["volume"], attachment=slot["attachment"], launch=intent["launch"], revision=19)

def target():
    owner = recovery.owner_proof(owners()[0]); binary = Path("/owned/cengine"); root = Path("/owned/root")
    path = root / "infrastructure/storage-shim-generations" / owner["shimLaunchUUID"] / "spec.json"
    sha = "a" * 64
    process = RuntimeProcess(55, executable=str(binary), identity=(100, 2, 300), pidversion=8,
        arguments=(str(binary), "vm-shim", "--spec", str(path), "--spec-sha256", sha, "--storage-disk-fd", "9"))
    spec = dict(kind="storage", containerID="cengine-storage", storageStartupMode="managed", shimLaunchUUID=owner["shimLaunchUUID"],
        rootDiskPath=str(root / "infrastructure/volumes.ext4"), rootDiskIdentity=owner["backing"], rootDiskSize=owner["bytes"],
        rootDiskReadOnly=False, volumeDisks=[], bindShares=[])
    launch = dict(intent=dict(specificationSHA256=sha, launchUUID=owner["shimLaunchUUID"]),
                  process=dict(pid=55, startSeconds=100, startMicroseconds=2, uniqueID=300))
    disk = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_dev=3, st_ino=40, st_size=4096)
    return [process, binary, root, path, spec, sha, launch, owner, disk]


class RecoveryTests(unittest.TestCase):
    def test_linked_ack_and_new_write(self):
        for command, written in (("ack", False), ("verify", False), ("write", True), ("verify", True)):
            recovery.snapshot_proof(snapshot(command, written), command=command, written=written)

    def test_ack_requires_file_and_parent_sync(self):
        for key in ("ack", "file_fsynced", "parent_fsynced"):
            for bad in (False, 1, None):
                value = snapshot(); value[key] = bad
                with self.assertRaises(ValueError): recovery.snapshot_proof(value, command="ack")

    def test_no_hidden_names_unlinked_data_or_wrong_metadata(self):
        for mutation in (lambda x: x.update(entries=["seed"]), lambda x: x.update(entries=["payload", "seed", ".nfs123"]),
                         lambda x: x["file"].update(nlink=0), lambda x: x["file"].update(uid=0),
                         lambda x: x["file"].update(mtime=0), lambda x: x["file"].update(mode=0o100600),
                         lambda x: x.update(sha256="0" * 64), lambda x: x["file"].update(size=0),
                         lambda x: x.update(mountinfo=x["mountinfo"].replace("fuse.managed-v3", "nfs4"))):
            value = snapshot(); mutation(value)
            with self.assertRaises(ValueError): recovery.snapshot_proof(value, command="ack")

    def test_exact_receipts_require_two_unique_same_context_consumers(self):
        m, s, c = journal(); recovery.exact_receipts(m, s, "owned-volume", c)
        for bad in (c[:1], [c[0], c[0]]):
            with self.assertRaises(ValueError): recovery.exact_receipts(m, s, "owned-volume", bad)
        next(iter(s["intents"].values()))["serviceEpoch"] = uid()
        with self.assertRaises(ValueError): recovery.exact_receipts(m, s, "owned-volume", c)

    def test_death_never_substitutes_for_prepare_or_runtime_drain(self):
        for index in (0, 1):
            m, s, c = journal(); retire(s)
            next(iter(s["intents"].values()))["slots"][index]["receipt"] = None
            with self.assertRaises(ValueError): recovery.exact_receipts(m, s, "owned-volume", c, stopped=True)

    def test_wrong_receipt_binding_rejected(self):
        for key in ("store", "volume", "attachment"):
            m, s, c = journal(); retire(s)
            next(iter(s["intents"].values()))["slots"][1]["receipt"][key] = uid()
            with self.assertRaises(ValueError): recovery.exact_receipts(m, s, "owned-volume", c, stopped=True)

    def test_historical_intents_survive_fresh_same_container_generation(self):
        m, s, c = journal(); retire(s)
        before = recovery.exact_receipts(m, s, "owned-volume", c, stopped=True)
        ids = [i["id"] for i in before["intents"]]
        for original in list(s["intents"].values()):
            fresh = copy.deepcopy(original); fresh["id"] = uid(); fresh["phase"] = "running"; fresh["slots"][1]["receipt"] = None
            s["intents"][fresh["id"]] = fresh
        after = recovery.exact_receipts(m, copy.deepcopy(s), "owned-volume", c, stopped=True, ids=ids)
        recovery.historical_receipts(before, after)
        after["intents"][0]["slots"][0]["receipt"]["revision"] += 1
        with self.assertRaises(ValueError): recovery.historical_receipts(before, after)

    def test_fresh_identity_and_C_plus_one_are_required(self):
        m, s, c = journal(); retire(s)
        before = recovery.exact_receipts(m, s, "owned-volume", c, stopped=True)
        after = copy.deepcopy(before); after["revision"] += 1
        owner = dict(store=before["store"], serviceEpoch=uid(), controllerEpoch=2)
        for i in after["intents"]:
            i.update(id=uid(), launch=uid(), prepare=uid(), serviceEpoch=owner["serviceEpoch"], controllerEpoch=2)
            for slot in i["slots"]: slot["attachment"] = uid()
        recovery.fresh_receipts(before, after, owner)
        for key in ("id", "launch", "prepare", "serviceEpoch", "controllerEpoch"):
            bad = copy.deepcopy(after); bad["intents"][0][key] = before["intents"][0][key]
            with self.assertRaises(ValueError): recovery.fresh_receipts(before, bad, owner)
        bad = copy.deepcopy(after); bad["intents"][0]["slots"][1]["attachment"] = before["intents"][0]["slots"][0]["attachment"]
        with self.assertRaises(ValueError): recovery.fresh_receipts(before, bad, owner)

    def test_root_issue_confirm_observation_and_persistent_identity(self):
        before, after = map(recovery.owner_proof, owners())
        recovery.recovered_owner(before, after)
        self.assertNotIn("signature", json.dumps(after))
        self.assertEqual(set(after["transitions"][0]), {"issue", "issued", "confirm", "confirmed"})
        for key in ("store", "backing", "root", "bytes", "ext4UUID", "rootKeyHash", "controllerEpoch"):
            bad = copy.deepcopy(after); bad[key] = "wrong"
            with self.assertRaises(ValueError): recovery.recovered_owner(before, bad)
        for key in ("shimLaunchUUID", "guestBootNonce", "serviceEpoch", "bootRevision", "serviceTransitions", "transitions"):
            bad = copy.deepcopy(after); bad[key] = before[key]
            with self.assertRaises(ValueError): recovery.recovered_owner(before, bad)

    def test_root_pending_missing_or_mismatched_confirmation_fails(self):
        for key in ("pendingIssue", "pendingIssued", "pendingConfirm", "pendingService"):
            _, record = owners(); record[key] = "pending"
            with self.assertRaises(ValueError): recovery.owner_proof(record)
        for field in ("issue", "issued", "confirm", "confirmed"):
            _, record = owners(); record["transitions"][0][field] = encoded({})
            with self.assertRaises(ValueError): recovery.owner_proof(record)
        for mutation in (lambda v: v.update(request_id=uid()), lambda v: v["body"]["controller"].update(epoch=3)):
            _, record = owners(); value = json.loads(base64.b64decode(record["transitions"][0]["confirmed"]))
            mutation(value); record["transitions"][0]["confirmed"] = encoded(value)
            with self.assertRaises(ValueError): recovery.owner_proof(record)

    def test_retired_v1_target_never_grants_signal_authority(self):
        for selector in ('managed', 'lifecycle', None):
            args = target()
            args[4]['storageStartupMode'] = selector
            with self.subTest(selector=selector), self.assertRaisesRegex(ValueError, 'retired v1 storage target'):
                recovery.target_matches(*args)
        args = target(); del args[4]['storageStartupMode']
        with self.assertRaisesRegex(ValueError, 'retired v1 storage target'):
            recovery.target_matches(*args)

    def test_exact_native_exit_and_pid_reuse_ambiguity(self):
        old = target()[0]
        self.assertTrue(recovery.exact_exit(old, None)); self.assertFalse(recovery.exact_exit(old, old))
        self.assertTrue(recovery.exact_exit(old, replace(old, identity=(101, 3, 301), pidversion=9)))
        for bad in (replace(old, identity=(100, 2, 301)), replace(old, pidversion=9), replace(old, pid=56), replace(old, identity=None)):
            with self.assertRaises(ValueError): recovery.exact_exit(old, bad)

    def test_zero_other_runtime_changes(self):
        old = target()[0]; other = replace(old, pid=56)
        recovery.unchanged_processes([old, other], [other], old)
        for after in ([], [old, other], [replace(other, pidversion=9)], [other, replace(other, pid=57)]):
            with self.assertRaises(ValueError): recovery.unchanged_processes([old, other], after, old)

    def test_joined_api_refresh_allows_only_exact_direct_child_reparenting(self):
        api = replace(target()[0], pid=51)
        child = replace(target()[0], parent_pid=api.pid)
        unrelated = replace(child, pid=56, parent_pid=99)
        orphan = replace(child, parent_pid=1)
        events = []
        for observed in (child, orphan):
            after = [observed, unrelated]
            refreshed = recovery.api_exit_survivors([api, child, unrelated], after, api,
                joined=(api.pid, -signal.SIGKILL), inspect=lambda pid: {p.pid: p for p in after}.get(pid),
                record=lambda phase, **kw: events.append((phase, kw)))
            self.assertEqual(refreshed, after)
            recovery.unchanged_processes(refreshed, [unrelated], observed)
        self.assertEqual(events[-1][1]['survivors'][0]['before']['parentPID'], api.pid)
        self.assertEqual(events[-1][1]['survivors'][0]['after']['parentPID'], 1)
        self.assertEqual(events[-1][1]['survivors'][0]['before']['argumentsSHA256'],
                         events[-1][1]['survivors'][0]['after']['argumentsSHA256'])
        with self.assertRaises(ValueError):  # General equality was NOT weakened.
            recovery.unchanged_processes([api, child], [orphan], api)
        with self.assertRaises(ValueError):  # Nor may later comparisons re-adopt lineage.
            recovery.unchanged_processes([orphan, unrelated], [replace(unrelated, parent_pid=1)], orphan)

    def test_api_refresh_rejects_mismatched_birth_argv_lineage_and_census(self):
        api = replace(target()[0], pid=51)
        child = replace(target()[0], parent_pid=api.pid)
        orphan = replace(child, parent_pid=1)
        changes = [dict(pid=56), dict(pidversion=9), dict(identity=(101, 2, 300)),
                   dict(identity=(100, 3, 300)), dict(identity=(100, 2, 301)),
                   dict(identity=None), dict(executable='/foreign/cengine'),
                   dict(arguments=child.arguments + ('--foreign',)), dict(command='foreign'),
                   dict(parent_pid=2), dict(parent_pid=None)]
        bad_censuses = [[replace(orphan, **change)] for change in changes]
        bad_censuses += [[], [orphan, orphan], [orphan, replace(orphan, pid=56)], [api, orphan]]
        for after in bad_censuses:
            with self.subTest(after=after), self.assertRaises(ValueError):
                recovery.api_exit_survivors([api, child], after, api, joined=(api.pid, -signal.SIGKILL),
                    inspect=lambda pid: {p.pid: p for p in after}.get(pid), record=Mock())
        for before in ([api, replace(child, parent_pid=99)], [api, child, child], [child]):
            with self.assertRaises(ValueError):
                recovery.api_exit_survivors(before, [orphan], api, joined=(api.pid, -signal.SIGKILL),
                    inspect=lambda pid: orphan if pid == orphan.pid else None, record=Mock())

    def test_api_refresh_requires_join_and_current_survivor_liveness(self):
        api = replace(target()[0], pid=51)
        child = replace(target()[0], parent_pid=api.pid)
        orphan = replace(child, parent_pid=1)
        for joined in (None, (api.pid + 1, -9), (api.pid, 0), (api.pid, -signal.SIGTERM)):
            record = Mock()
            with self.assertRaises(ValueError):
                recovery.api_exit_survivors([api, child], [orphan], api, joined=joined,
                    inspect=lambda pid: orphan if pid == orphan.pid else None, record=record)
            record.assert_not_called()
        for api_now, child_now in ((api, orphan), (None, None), (None, child),
                                   (None, replace(orphan, pidversion=9))):
            record = Mock()
            with self.assertRaises(ValueError):
                recovery.api_exit_survivors([api, child], [orphan], api, joined=(api.pid, -9),
                    inspect=lambda pid: api_now if pid == api.pid else child_now, record=record)
            record.assert_not_called()

    def test_worker_reads_complete_join_receipt_and_rejects_truncation(self):
        run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'run_campaign')
        function = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == 'handshake')
        channel = Mock()
        namespace = dict(channel=channel, time=time, work_deadline=time.monotonic() + 10,
                         struct=struct, require=recovery.require)
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(PATH), 'exec'), namespace)
        receipt = struct.pack('>ii', 51, -9)
        channel.recv.side_effect = [b'F', receipt[:3], receipt[3:]]
        self.assertEqual(namespace['handshake'](b'F'), (51, -9))
        channel.recv.side_effect = [b'F', receipt[:3], b'']
        with self.assertRaises(ValueError): namespace['handshake'](b'F')
        text = PATH.read_text()
        refresh = text.index('frozen = worker_recovery.api_exit_survivors')
        select = text.index('target = storage_target(old_owner)', refresh)
        signal_at = text.index('delivery = signal_storage', select)
        self.assertLess(refresh, select)
        self.assertLess(select, signal_at)
        self.assertIn('unchanged post-API census at signal', text[select:signal_at])
        self.assertIn('unchanged_processes(frozen, processes(), target)', text[signal_at:])

    def test_durable_evidence_publication_and_unique_namespace(self):
        token = "a" * 32; value = dict(phase="plan", plan=recovery.names(token))
        self.assertTrue(value["plan"]["volume"].startswith("rtm079-"))
        with tempfile.TemporaryDirectory() as temp:
            synced = []; real = os.fsync
            with patch.object(recovery.os, "fsync", side_effect=lambda fd: (synced.append(stat.S_IFMT(os.fstat(fd).st_mode)), real(fd))):
                folder, used = recovery.initialize_evidence(Path(temp), token, value)
            self.assertEqual(synced, [stat.S_IFDIR, stat.S_IFDIR, stat.S_IFREG, stat.S_IFDIR, stat.S_IFDIR])
            self.assertEqual(json.loads((folder / "evidence.jsonl").read_bytes()), value)
            self.assertEqual(used, (folder / "evidence.jsonl").stat().st_size)
            with self.assertRaises(FileExistsError): recovery.initialize_evidence(Path(temp), token, value)

    def test_evidence_symlinks_and_fsync_fail_closed(self):
        token = "a" * 32; value = dict(phase="plan", plan=recovery.names(token))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / ".build").symlink_to(root)
            with self.assertRaises(OSError): recovery.initialize_evidence(root, token, value)
        with tempfile.TemporaryDirectory() as temp, patch.object(recovery.os, "fsync", side_effect=OSError("full")):
            with self.assertRaises(OSError): recovery.initialize_evidence(Path(temp), token, value)

    def test_public_reader_does_not_follow_symlinks_or_read_unbounded(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "public.json"; path.write_text('{"public":1}')
            value, digest = recovery.read_public(path); self.assertEqual(value, {"public": 1})
            self.assertEqual(digest, recovery.digest(path.read_bytes()))
            with self.assertRaises(ValueError): recovery.read_public(path, 1)
            link = path.with_name("link"); link.symlink_to(path)
            with self.assertRaises(OSError): recovery.read_public(link)

    def test_image_is_scratch_offline_owned_and_bounded(self):
        archive, config = recovery.image_archive(b"inert", recovery.names("a" * 32))
        self.assertEqual(config["config"]["Labels"], {recovery.OWNER: "a" * 32})
        with tarfile.open(fileobj=io.BytesIO(archive)) as outer, tarfile.open(fileobj=io.BytesIO(outer.extractfile("layer.tar").read())) as layer:
            self.assertEqual(layer.getnames(), ["probe", "run", "data", "data/seed"])
        with self.assertRaises(ValueError): recovery.image_archive(b"", recovery.names("a" * 32))

    def test_campaign_storage_selection_uses_current_native_v2_selector(self):
        import managed_prepare_lifecycle_evidence as lifecycle
        run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        function = copy.deepcopy(next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "storage_target"))
        with tempfile.TemporaryDirectory(dir="/tmp") as temp:
            work = Path(temp); root = work / "root"; root.mkdir()
            info = root.stat()
            proof = dict(root=dict(device=info.st_dev, inode=info.st_ino))
            binary = Path("/owned/cengine")
            launch_root = recovery.runtime_root_path(root.resolve())
            path = launch_root / "infrastructure/storage-shim-generations" / uid() / "spec.json"
            process = replace(target()[0], arguments=(str(binary), "vm-shim", "--spec", str(path),
                "--spec-sha256", "a" * 64, "--storage-disk-fd", "3", "--storage-lifecycle-fd", "4"))
            daemon = SimpleNamespace(work=work.resolve(), root=root.resolve(), binary=binary)
            namespace = dict(compatibility_root_owned_by=lambda *a: True, daemon=daemon,
                os=os, Path=Path, require=recovery.require, read_public=recovery.read_public,
                _kernel_process=lambda _: process, processes=lambda: [process],
                runtime_root_path=recovery.runtime_root_path, native_proof=recovery.native_proof,
                worker_recovery=recovery, record=lambda *a, **kw: None)
            exec(compile(ast.Module(body=[function], type_ignores=[]), str(PATH), "exec"), namespace)
            with patch.object(lifecycle, "storage_target", return_value=process) as select, \
                    patch.object(recovery, "backing_snapshot", return_value={}):
                self.assertEqual(namespace[function.name](proof), process)
            select.assert_called_once_with(daemon, proof, [process], recovery.read_public)

    def test_parent_handshake_drives_same_real_fixture_kill_then_start(self):
        function = copy.deepcopy(next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "test_owned_managed_storage_crash_recovery"))
        function.decorator_list = []; events = []; parent = Mock(); child = Mock(); child.fileno.return_value = 4
        parent.recv.side_effect = [b"F", b"S", b"D"]
        process = Mock(returncode=None); process.wait.return_value = 0
        daemon = SimpleNamespace(binary="binary", root="root", socket="socket", work="work", process=SimpleNamespace(pid=51, returncode=-9),
            stop=lambda **kw: events.append(("stop", kw)), start=lambda: events.append(("start", {})))
        namespace = dict(time=time, socket=SimpleNamespace(socketpair=lambda: (parent, child)), sys=sys, __file__=str(PATH),
            subprocess=SimpleNamespace(Popen=lambda *a, **kw: process, DEVNULL=-3), parent_deadline=lambda _: nullcontext(),
            signal=signal, struct=struct, require=recovery.require, pytest=SimpleNamespace(fail=lambda *a, **k: self.fail("parent failed")))
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(PATH), "exec"), namespace)
        namespace[function.name](daemon)
        self.assertEqual(events, [("stop", {"kill": True}), ("start", {})])
        self.assertEqual([call.args[0] for call in parent.sendall.call_args_list], [b"F" + struct.pack(">ii", 51, -9), b"S", b"D"])

    def test_snapshot_includes_actual_daemon_root_and_other_shims(self):
        binary = Path("/owned/cengine"); root = Path("/owned/root")
        daemon = RuntimeProcess(51, executable=str(binary), arguments=(str(binary), "daemon", "--root", str(root)))
        shim = target()[0]
        other = replace(shim, pid=56, arguments=(str(binary), "vm-shim", "--spec", "/other/root/spec.json"))
        self.assertFalse(_runtime_matches(daemon, binary, (Path("/"),)))
        roots = (root, Path("/"))
        for process in (daemon, shim, other):
            self.assertTrue(_runtime_matches(process, binary, roots))
        run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        process_function = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "processes")
        self.assertIn("roots=(daemon.root, Path('/'))", ast.unparse(process_function))

    def test_parent_failure_latches_retention_and_reaps_before_marker(self):
        function = copy.deepcopy(next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "test_owned_managed_storage_crash_recovery"))
        function.decorator_list = []
        events = []; parent = Mock(); child = Mock(); child.fileno.return_value = 4
        parent.recv.return_value = b"wrong"
        process = Mock(pid=12345, returncode=None)
        process.wait.side_effect = lambda **kw: events.append("reap") or 0
        daemon = SimpleNamespace(binary="binary", root="root", socket="socket", work="work", _retain_root=False)
        def fail(*a, **kw): raise RuntimeError("expected failure")
        namespace = dict(time=time, socket=SimpleNamespace(socketpair=lambda: (parent, child)), sys=sys, __file__=str(PATH),
            subprocess=SimpleNamespace(Popen=lambda *a, **kw: process, DEVNULL=-3), parent_deadline=lambda _: nullcontext(),
            signal=signal, require=recovery.require, pytest=SimpleNamespace(fail=fail),
            os=SimpleNamespace(killpg=lambda *a: events.append("kill")), retain_failure=lambda *a: events.append("retain"))
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(PATH), "exec"), namespace)
        with self.assertRaises(RuntimeError): namespace[function.name](daemon)
        self.assertTrue(daemon._retain_root)
        self.assertEqual(events, ["kill", "reap", "retain"])

    def test_public_identity_projection_rejects_extras_types_and_bad_UUIDs(self):
        for field in ("root", "backing"):
            for mutation in (lambda v: v.update(private_key="SENTINEL_SECRET"),
                             lambda v: v.update(inode={"private_key": "SENTINEL_SECRET"}),
                             lambda v: v.update(inode=True), lambda v: v.update(inode=0),
                             lambda v: v.update(device=-1), lambda v: v.update(volumeUUID="SENTINEL_SECRET")):
                before, _ = owners(); mutation(before[field])
                with self.assertRaises(ValueError): recovery.owner_proof(before)
        before, _ = owners(); proof = recovery.owner_proof(before)
        before["root"]["private_key"] = "SENTINEL_SECRET"
        self.assertNotIn("SENTINEL_SECRET", json.dumps(proof))
        for field in ("bytes", "revision"):
            for bad in (True, 0, 2 ** 64, {"private_key": "SENTINEL_SECRET"}):
                before, _ = owners(); before[field] = bad
                with self.assertRaises(ValueError): recovery.owner_proof(before)

    def test_payload_public_metadata_closed_and_mount_options_never_exported(self):
        for section in ("root", "file"):
            for field in ("nlink", "size", "mtime", "mode", "uid", "gid"):
                for bad in (True, "SENTINEL_SECRET", {"private_key": "SENTINEL_SECRET"}):
                    value = snapshot(); value[section][field] = bad
                    with self.assertRaises(ValueError): recovery.snapshot_proof(value, command="ack")
            value = snapshot(); value[section]["private_key"] = "SENTINEL_SECRET"
            with self.assertRaises(ValueError): recovery.snapshot_proof(value, command="ack")
        value = snapshot(); value["mountinfo"] = value["mountinfo"].replace("rw,nosuid", "rw,token=SENTINEL_SECRET,nosuid")
        proof = recovery.snapshot_proof(value, command="ack")
        self.assertEqual(set(proof), {"device", "root", "filesystem", "source"})
        self.assertNotIn("SENTINEL_SECRET", json.dumps(proof))
        value["mountinfo"] = value["mountinfo"].replace("0:40", "SENTINEL_SECRET")
        with self.assertRaises(ValueError): recovery.snapshot_proof(value, command="ack")

    def test_sigkill_requires_positive_native_delivery_and_restores_adapter(self):
        import ctypes
        import harness
        process = target()[0]; original = harness._signal_pid_incarnation
        def syscall(pointer, selected_signal):
            token = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32 * 8)).contents
            self.assertEqual(list(token), [0, 0, 0, 0, 0, process.pid, 0, process.pidversion])
            self.assertEqual(selected_signal, signal.SIGKILL)
            return 0
        native = Mock(); native.proc_signal_with_audittoken.side_effect = syscall
        with patch.object(harness, "_kernel_process", return_value=process), patch.object(ctypes, "CDLL", return_value=native):
            self.assertEqual(recovery.signal_storage(process)["native_result"], 0)
        self.assertIs(harness._signal_pid_incarnation, original)
        for result in (3, 1, -1):  # ESRCH, EPERM, unknown: none proves delivery.
            native = Mock(); native.proc_signal_with_audittoken.return_value = result
            with patch.object(harness, "_kernel_process", return_value=process), patch.object(ctypes, "CDLL", return_value=native), self.assertRaises(ValueError):
                recovery.signal_storage(process)
            self.assertIs(harness._signal_pid_incarnation, original)
        for observed in (None, replace(process, pidversion=process.pidversion + 1)):
            with patch.object(harness, "_kernel_process", return_value=observed), patch.object(ctypes, "CDLL") as library, self.assertRaises((ValueError, RuntimeError)):
                recovery.signal_storage(process)
            library.assert_not_called()
            self.assertIs(harness._signal_pid_incarnation, original)

    def test_no_assert_guards_or_unsafe_storage_signals(self):
        helper_tree = ast.parse((ROOT / "Tests/Compatibility/managed_storage_recovery.py").read_text())
        self.assertFalse(any(isinstance(n, ast.Assert) for t in (TREE, helper_tree) for n in ast.walk(t)))
        calls = [ast.unparse(n) for n in ast.walk(TREE) if isinstance(n, ast.Call)]
        self.assertEqual([c for c in calls if c.startswith("signal_storage(")], ["signal_storage(target, before_signal=before_signal)"])
        self.assertFalse(any(c.startswith("os.kill(") for c in calls))
        self.assertIn("_kernel_process(process.pid)", calls)

    def test_ordered_ack_drain_native_exit_freeze_fault_restart(self):
        text = PATH.read_text()
        markers = ['observe(containers[0], "ack")', 'retired = receipts', 'terminate_workloads(workloads, retired, containers, old_owner)',
                   'handshake(b"F")', 'historical_receipts(retired, receipts', 'delivery = signal_storage(target, before_signal=before_signal)',
                   'wait_exit(target)', 'handshake(b"S")', 'recovered_lifecycle_owner(old_record, new_record)',
                   'fresh_receipts(retired, fresh, new_owner)', 'observe(containers[1], "write", written=True)']
        # The worker-only branch has its own receipts/write before this legacy
        # branch in source order. Trace the RTM-079 markers from its ACK forward.
        offsets = []
        for value in markers:
            offsets.append(text.index(value, offsets[-1] + 1 if offsets else 0))
        self.assertEqual(offsets, sorted(offsets))
        self.assertLess(text.index('initialize_evidence(REPO_ROOT'), text.index('docker.DockerClient('))
        go = (ROOT / "Tests/Compatibility/fixtures/managed-storage-recovery.go").read_text()
        self.assertLess(go.index("must(file.Sync())"), go.index("must(root.Sync())"))
        self.assertLess(go.index("must(root.Sync())"), go.index("json.NewEncoder(os.Stdout)"))


class WorkloadTerminationTests(unittest.TestCase):
    def setUp(self):
        # Preserve the caller spelling; workload launch inputs use Swift's path.
        temporary = tempfile.TemporaryDirectory(dir=getattr(self, "temporary_parent", "/tmp"))
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.root = self.work / "root"
        self.root.mkdir()
        self.binary = Path("/owned/cengine")
        (self.work / ".cengine-compat-owner").write_text(str(self.binary))
        self.plan = recovery.names("d" * 32)
        self.volume_uuid = uid()
        self.root_identity = self.file_identity(self.root)
        self.targets, self.intents, self.paths = [], [], []
        self.now, self.events, self.live = 0.0, [], {}
        for index, character in enumerate("ab"):
            # Sanitized real RTM-079 generation nonces, with VMShimClient's
            # %020llu + canonical lowercase nonce formatter (not uppercase UUID).
            launch = ("94384fec-626a-4d7e-8567-443ca55d5ff4", "b6a7620f-8b61-4c3d-84b1-8abb7b3a27c8")[index]
            # Public identities from cdcdf0d...; private root prefix is replaced
            # by this test's temporary root. Process birth/pidversion stay fake.
            container, instance = (("bb1460b22d394784834ce83474f3461dfc3e1bdc08294480964e1bd403ce0741", "87a503f2-6f71-47a3-b862-1f1b791cb436"),
                                   ("9a9188a5c3bd414aa54ff5476c77b9b62e9dfbb891994ae4a7c8b381b3ef5a4a", "1b30ba7e-d172-43b2-817e-fe846a24544c"))[index]
            directory = recovery.runtime_root_path(self.root.resolve()) / "containers" / container / "shim-generations" / (f"{2:020d}-" + launch)
            directory.mkdir(parents=True)
            disk = directory.parent.parent / "root.ext4"; disk.write_bytes(b"inert disk")
            io_directory = directory.parent.parent / "io"; io_directory.mkdir(mode=0o700)
            spec_path = directory / "spec.json"
            process = RuntimeProcess(700 + index, executable=str(self.binary), identity=(100, index + 2, 300 + index), pidversion=8 + index,
                arguments=(str(self.binary), "vm-shim", "--spec", str(spec_path), "--launch-intent", str(directory / "intent.json")))
            spec = dict(kind="container", workloadStorageMode="managed", containerID=container, shimLaunchUUID=launch,
                generation=2, token="SENTINEL_SECRET", rootDiskPath=str(disk), rootDiskIdentity=self.file_identity(disk),
                rootDiskSize=disk.stat().st_size, rootDiskReadOnly=False, volumeDisks=[],
                bindShares=[dict(tag="cengine-io", source=str(io_directory), readOnly=False, sourceIdentity=self.file_identity(io_directory))])
            intent = dict(schemaVersion=2, nonce=launch, createdAt=123, specificationPath=str(spec_path), executablePath=str(self.binary),
                containerDirectoryIdentity=self.file_identity(directory.parent.parent), generationsDirectoryIdentity=self.file_identity(directory.parent),
                generationDirectoryIdentity=self.file_identity(directory), specification=spec,
                container=dict(id=container, instanceID=instance.upper(), name=self.plan["containers"][index], labels={recovery.OWNER: self.plan["owner"]}))
            record = dict(intent, processIdentifier=process.pid, processStartTime=100000000 + index + 2,
                kernelIdentity=dict(pid=process.pid, startSeconds=100, startMicroseconds=index + 2, uniqueID=300 + index, bootUUID=uid()))
            for name, value in (("spec.json", spec), ("intent.json", intent), ("launch.json", record)):
                (directory / name).write_text(json.dumps(value))
            receipt = dict(id=uid(), container=container, containerInstance=instance, launch=launch, phase="retired", prepare=uid(),
                slots=[dict(role=role, attachment=uid(), receipt={"complete": True}) for role in ("prepare", "runtime")])
            self.paths.append(directory); self.intents.append(receipt); self.live[process.pid] = process
            with self.validate(process, receipt) as (proof, _):
                self.targets.append((process, proof))
        self.retired = dict(store=uid(), volume=uid(), revision=10, intents=self.intents)
        self.other = RuntimeProcess(799, executable=str(self.binary), arguments=(str(self.binary), "daemon", "--root", "/other/root"),
            identity=(101, 1, 399), pidversion=99)
        self.live[self.other.pid] = self.other
        self.events.clear()

    def file_identity(self, path):
        info = path.stat()
        return dict(device=info.st_dev, inode=info.st_ino, volumeUUID=self.volume_uuid)

    def validate(self, process, intent):
        index = next(i for i, value in enumerate(self.intents) if value["container"] == intent["container"])
        self.events.append(("validate", process.pid))
        return recovery.workload_target(process, self.binary, self.work, self.root, self.plan, intent, self.root_identity,
                                        self.plan["containers"][index])

    def mutate(self, index, name, change):
        path = self.paths[index] / name
        value = json.loads(path.read_bytes()); change(value); path.write_text(json.dumps(value))

    def run_termination(self, *, term_exits=True, syscall_result=0, validate=None, reread=None, processes=None, before_delivery=None, deadline=10):
        import ctypes
        import harness
        def syscall(pointer, sig):
            words = list(ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32 * 8)).contents)
            process = self.live[words[5]]
            self.assertEqual(words, [0, 0, 0, 0, 0, process.pid, 0, process.pidversion])
            self.events.append(("signal", process.pid, sig))
            if syscall_result == 0 and (term_exits or sig == signal.SIGKILL):
                self.live.pop(process.pid)
            return syscall_result
        native = SimpleNamespace(proc_signal_with_audittoken=syscall)
        def record(phase, **value):
            self.assertNotIn("SENTINEL_SECRET", json.dumps(value))
            self.events.append((phase, value))
            if before_delivery and phase == "workload-termination-intent": before_delivery()
        def sleep(seconds): self.now += seconds
        with patch.object(harness, "_kernel_process", side_effect=lambda pid: self.live.get(pid)), \
                patch.object(ctypes, "CDLL", return_value=native), patch.object(recovery.time, "monotonic", side_effect=lambda: self.now), \
                patch.object(recovery.time, "sleep", side_effect=sleep):
            recovery.terminate_drained_workloads(self.targets, self.retired, validate=validate or self.validate,
                reread=reread or (lambda: copy.deepcopy(self.retired)), processes=processes or (lambda: list(self.live.values())),
                inspect=lambda pid: self.live.get(pid), record=record, deadline=deadline)

    def test_actual_controller_physical_root_and_lexical_launch_tuples(self):
        # The parent runner supplies /private/tmp; Swift records /tmp. Do NOT
        # substitute the argv spelling for the caller root as the old preflight did.
        run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        function = copy.deepcopy(next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "workload_processes"))
        containers = [SimpleNamespace(id=i["container"], name=self.plan["containers"][index]) for index, i in enumerate(self.intents)]
        namespace = dict(Path=Path, daemon=SimpleNamespace(binary=self.binary, work=self.work.resolve(), root=self.root.resolve()),
            processes=lambda: [p for p, _ in self.targets], require=recovery.require, read_public=recovery.read_public,
            workload_target=recovery.workload_target, plan=self.plan, record=lambda *a, **kw: None)
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(PATH), "exec"), namespace)
        self.assertEqual(namespace[function.name](containers, self.retired, {"root": self.root_identity}), self.targets)

    def test_path_failures_have_distinct_closed_diagnostics(self):
        process = self.targets[0][0]
        path = self.paths[0] / "spec.json"
        cases = [
            (process.arguments + ("SENTINEL_SECRET",), "workload argv length"),
            ((process.arguments[0], "SENTINEL_SECRET", *process.arguments[2:]), "workload argv command"),
            (("SENTINEL_SECRET", *process.arguments[1:]), "workload argv executable"),
            ((*process.arguments[:3], str(path).replace("/spec.json", "/./spec.json"), *process.arguments[4:]), "workload specification path spelling"),
            ((*process.arguments[:3], str(path).replace(self.paths[0].name, "SENTINEL_SECRET"), *process.arguments[4:]), "workload generation nonce"),
            ((*process.arguments[:3], "/SENTINEL_SECRET/" + self.paths[0].name + "/spec.json", *process.arguments[4:]), "workload specification path root"),
            ((*process.arguments[:5], "SENTINEL_SECRET"), "workload intent path"),
        ]
        for arguments, expected in cases:
            with self.subTest(expected=expected), self.assertRaises(recovery.ProofFailure) as error:
                with self.validate(replace(process, arguments=arguments), self.intents[0]): pass
            self.assertEqual(str(error.exception), expected)
            self.assertNotIn("SENTINEL_SECRET", str(error.exception))

    def test_physical_caller_still_pins_alias_and_rejects_rewritten_argv(self):
        if self.work == self.work.resolve(): self.skipTest("no macOS /tmp alias")
        process = self.targets[0][0]
        arguments = tuple(str(Path(arg).resolve()) if arg.startswith("/tmp/") else arg for arg in process.arguments)
        with self.assertRaisesRegex(ValueError, "specification path root"):
            with recovery.workload_target(replace(process, arguments=arguments), self.binary, self.work.resolve(), self.root.resolve(),
                    self.plan, self.intents[0], self.root_identity, self.plan["containers"][0]): pass
        with recovery.workload_target(process, self.binary, self.work.resolve(), self.root.resolve(),
                self.plan, self.intents[0], self.root_identity, self.plan["containers"][0]) as (_, revalidate):
            original = recovery.os.readlink
            with patch.object(recovery.os, "readlink", side_effect=lambda path: "other/tmp" if str(path) == "/tmp" else original(path)):
                with self.assertRaisesRegex(ValueError, "system tmp alias changed"): revalidate()

    def test_runtime_path_projection_is_only_the_system_tmp_prefix(self):
        self.assertEqual(recovery.runtime_root_path(Path("/private/tmp/campaign/root")), Path("/tmp/campaign/root"))
        for value in ("/private/tmp-other/root", "/private/var/tmp/root", "/owned/private/tmp/root", "/tmp/campaign/root"):
            self.assertEqual(recovery.runtime_root_path(Path(value)), Path(value))

    def test_initial_plan_records_controller_and_helper_source_digests(self):
        run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        call = next(n for n in ast.walk(run) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "initialize_evidence")
        values = {key.value: ast.unparse(value) for key, value in zip(call.args[2].keys, call.args[2].values)}
        self.assertEqual(values["controller_source_sha256"], "digest(Path(__file__).read_bytes())")
        self.assertEqual(values["helper_source_sha256"], "digest(Path(workload_target.__wrapped__.__code__.co_filename).read_bytes())")

    def test_fixture_matches_runtime_formatter_and_io_contract(self):
        client = (ROOT / "Sources/CEngineRuntime/VMShimClient.swift").read_text()
        backend = (ROOT / "Sources/CEngineRuntime/RawVirtualizationBackend.swift").read_text()
        self.assertIn('String(format: "%020llu", specification.generation)', client)
        self.assertIn('UUID(uuidString: intent.nonce)?.uuidString.lowercased() == intent.nonce', client)
        self.assertIn('tag: "cengine-io",\n                source: ioDirectory.path,\n                readOnly: false,\n                sourceIdentity: artifacts.ioDirectoryIdentity.shimIdentity', backend)
        self.assertEqual(self.paths[0].name, "00000000000000000002-94384fec-626a-4d7e-8567-443ca55d5ff4")
        self.assertEqual(self.work.parent, Path("/tmp"))

    def update_spec(self, change):
        self.mutate(0, "spec.json", change)
        for name in ("intent.json", "launch.json"):
            self.mutate(0, name, lambda value: change(value["specification"]))

    def test_generation_and_argv_are_exact_not_case_folded_or_resolved(self):
        process = self.targets[0][0]
        path = self.paths[0] / "spec.json"
        for bad in (str(path).replace(self.paths[0].name, self.paths[0].name.upper()),
                    str(path).replace("00000000000000000002-", "000000000000000000002-"),
                    str(path).replace("/spec.json", "/./spec.json"),
                    str(path).replace("/spec.json", "/../" + self.paths[0].name + "/spec.json")):
            args = (*process.arguments[:3], bad, *process.arguments[4:])
            with self.assertRaises(ValueError):
                with self.validate(replace(process, arguments=args), self.intents[0]): pass

    def test_arbitrary_campaign_symlink_is_not_authority(self):
        alias = self.work / "alias"
        alias.symlink_to(self.work, target_is_directory=True)
        process = self.targets[0][0]
        with self.assertRaisesRegex(ValueError, "root spelling"):
            with recovery.workload_target(process, self.binary, alias, alias / "root", self.plan,
                                          self.intents[0], self.root_identity, self.plan["containers"][0]): pass

    def test_legacy_schema2_without_kernel_identity_is_not_authority(self):
        # Actual retained legacy generation: schema 2, but JSONEncoder omits the
        # optional kernelIdentity. Do not invent one or broaden managed authority.
        self.update_spec(lambda value: value.update(workloadStorageMode="legacy"))
        self.mutate(0, "launch.json", lambda value: value.pop("kernelIdentity"))
        with self.assertRaisesRegex(ValueError, "immutable schema-2"):
            with self.validate(self.targets[0][0], self.intents[0]): pass

    def test_only_exact_owned_io_share_is_allowed(self):
        paths = [self.paths[0] / name for name in ("spec.json", "intent.json", "launch.json")]
        originals = [path.read_bytes() for path in paths]
        for change in (lambda v: v.update(bindShares=[]),
                       lambda v: v["bindShares"].append(copy.deepcopy(v["bindShares"][0])),
                       lambda v: v["bindShares"][0].update(tag="bind-0"),
                       lambda v: v["bindShares"][0].update(readOnly=0),
                       lambda v: v["bindShares"][0].update(source=str(self.work)),
                       lambda v: v["bindShares"][0].update(extra="SENTINEL_SECRET"),
                       lambda v: v["bindShares"][0]["sourceIdentity"].update(inode=1),
                       lambda v: v["bindShares"][0]["sourceIdentity"].update(volumeUUID=uid())):
            self.update_spec(change)
            with self.assertRaises(ValueError):
                with self.validate(self.targets[0][0], self.intents[0]): pass
            for path, contents in zip(paths, originals): path.write_bytes(contents)

    def test_io_replacement_or_permission_change_prevents_signal(self):
        directory = self.paths[0].parent.parent / "io"
        for replacement in (False, True):
            def change():
                if replacement:
                    directory.rename(directory.with_name("old-io")); directory.mkdir(mode=0o700)
                else:
                    directory.chmod(0o755)
            with self.assertRaises(ValueError): self.run_termination(before_delivery=change)
            self.assertFalse(any(e[0] == "signal" for e in self.events))
            directory.chmod(0o700)

    def test_system_tmp_alias_is_pinned_through_delivery(self):
        if self.work == self.work.resolve(): self.skipTest("no macOS /tmp alias")
        real = recovery.os.readlink
        changed = False
        def readlink(path, **kwargs):
            return "other/tmp" if str(path) == "/tmp" and changed else real(path, **kwargs)
        def change():
            nonlocal changed
            changed = True
        with patch.object(recovery.os, "readlink", side_effect=readlink), self.assertRaises(ValueError):
            self.run_termination(before_delivery=change)
        self.assertFalse(any(e[0] == "signal" for e in self.events))

    def test_live_stopped_shims_are_terminated_and_both_exits_proven(self):
        self.run_termination()
        self.assertEqual([e for e in self.events if e[0] == "signal"], [("signal", 700, signal.SIGTERM), ("signal", 701, signal.SIGTERM)])
        self.assertEqual(len([e for e in self.events if e[0] == "native-exit"]), 2)
        self.assertEqual(list(self.live), [799])
        text = PATH.read_text()
        self.assertIn("terminate_workloads(fresh_workloads, fresh_retired, containers, new_owner)", text)
        self.assertLess(text.index("terminate_workloads(workloads, retired, containers, old_owner)"), text.index('handshake(b"F")'))

    def test_escalation_revalidates_each_exact_target_and_never_retries(self):
        self.run_termination(term_exits=False)
        self.assertEqual([e for e in self.events if e[0] in ("validate", "signal")], [
            ("validate", 700), ("signal", 700, signal.SIGTERM), ("validate", 700), ("signal", 700, signal.SIGKILL),
            ("validate", 701), ("signal", 701, signal.SIGTERM), ("validate", 701), ("signal", 701, signal.SIGKILL)])
        self.assertLessEqual(self.now, 2.1)

    def test_missing_receipt_on_either_consumer_prevents_every_signal(self):
        for index in (0, 1):
            slot = self.intents[index]["slots"][1]
            prior = slot["receipt"]; slot["receipt"] = None
            with self.assertRaises(ValueError): self.run_termination()
            self.assertFalse(any(e[0] == "signal" for e in self.events))
            slot["receipt"] = prior

    def test_changed_receipts_prevent_termination(self):
        wrong = copy.deepcopy(self.retired); wrong["intents"][0]["launch"] = uid()
        with self.assertRaises(ValueError): self.run_termination(reread=lambda: wrong)
        self.assertFalse(any(e[0] == "signal" for e in self.events))

    def test_capture_is_closed_public_and_full_launch_mismatch_rejected(self):
        process, proof = self.targets[0]
        self.assertEqual(set(proof), {"pid", "birth", "pidversion", "container", "containerInstance", "launch", "name", "owner", "sha256"})
        self.assertNotIn("SENTINEL_SECRET", json.dumps(proof))
        for name, change in (("launch.json", lambda v: v.update(schemaVersion=1)),
                             ("launch.json", lambda v: v["kernelIdentity"].update(uniqueID=999)),
                             ("launch.json", lambda v: v.update(processStartTime=1)),
                             ("launch.json", lambda v: v["container"].update(instanceID=uid())),
                             ("intent.json", lambda v: v["container"]["labels"].update({recovery.OWNER: "wrong"})),
                             ("spec.json", lambda v: v.update(workloadStorageMode="legacy")),
                             ("spec.json", lambda v: v.update(token="changed"))):
            with self.subTest(name=name):
                path = self.paths[0] / name; original = path.read_bytes(); self.mutate(0, name, change)
                with self.assertRaises(ValueError):
                    with self.validate(process, self.intents[0]): pass
                path.write_bytes(original)
        for change in (dict(executable="/foreign/cengine"), dict(arguments=process.arguments + ("--extra",)),
                       dict(identity=(100, 2, 301)), dict(pidversion=None)):
            with self.assertRaises(ValueError):
                with self.validate(replace(process, **change), self.intents[0]): pass

    def test_symlink_parent_input_and_oversized_input_rejected(self):
        process = self.targets[0][0]
        directory = self.paths[0]; moved = directory.with_name(directory.name + "-moved")
        directory.rename(moved); directory.symlink_to(moved)
        try:
            with self.assertRaises(OSError):
                with self.validate(process, self.intents[0]): pass
        finally:
            directory.unlink(); moved.rename(directory)
        path = directory / "spec.json"; contents = path.read_bytes()
        path.unlink(); path.symlink_to(directory / "intent.json")
        with self.assertRaises(OSError):
            with self.validate(process, self.intents[0]): pass
        path.unlink()
        with path.open("wb") as output: output.truncate(1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            with self.validate(process, self.intents[0]): pass
        path.write_bytes(contents)

    def test_file_or_directory_replacement_after_intent_prevents_syscall(self):
        for kind in ("file", "permissions"):
            path = self.paths[0] / "intent.json"
            original = path.read_bytes()
            def change():
                if kind == "file": path.unlink(); path.write_bytes(original)
                else: self.paths[0].chmod(0o777)
            with self.assertRaises(ValueError): self.run_termination(before_delivery=change)
            self.assertFalse(any(e[0] == "signal" for e in self.events))
            self.paths[0].chmod(0o755)

    def test_changed_native_incarnation_never_signals_replacement(self):
        import harness
        process = self.targets[0][0]
        def changed(): self.live[process.pid] = replace(process, pidversion=process.pidversion + 1)
        with self.assertRaises(RuntimeError): self.run_termination(before_delivery=changed)
        self.assertFalse(any(e[0] == "signal" for e in self.events))

    def test_nonzero_native_delivery_fails_and_restores_adapter(self):
        import harness
        original = harness._signal_pid_incarnation
        for result in (3, 1, -1):
            with self.subTest(result=result), self.assertRaises(ValueError): self.run_termination(syscall_result=result)
            self.assertIs(harness._signal_pid_incarnation, original)
        self.assertFalse(any(e[0] == "native-exit" for e in self.events))

    def test_changed_unrelated_runtime_prevents_next_target(self):
        calls = 0
        def processes():
            nonlocal calls
            calls += 1
            values = list(self.live.values())
            return values if calls == 1 else [p for p in values if p != self.other]
        with self.assertRaises(ValueError): self.run_termination(processes=processes)
        self.assertIn(701, self.live)

    def test_consistently_changed_spec_before_escalation_is_not_adopted(self):
        calls = 0
        def validate(process, intent):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.mutate(0, "spec.json", lambda v: v.update(token="replacement"))
                for name in ("intent.json", "launch.json"):
                    self.mutate(0, name, lambda v: v["specification"].update(token="replacement"))
            return self.validate(process, intent)
        with self.assertRaisesRegex(ValueError, "captured workload ownership changed"):
            self.run_termination(term_exits=False, validate=validate)
        self.assertEqual([e for e in self.events if e[0] == "signal"], [("signal", 700, signal.SIGTERM)])

    def test_actual_name_and_root_disk_identity_are_required(self):
        process = self.targets[0][0]
        with self.assertRaisesRegex(ValueError, "campaign container"):
            with recovery.workload_target(process, self.binary, self.work, self.root, self.plan, self.intents[0],
                                          self.root_identity, self.plan["containers"][1]): pass
        disk = self.paths[0].parent.parent / "root.ext4"
        disk.unlink(); disk.write_bytes(b"replacement")
        with self.assertRaisesRegex(ValueError, "root disk binding"):
            with self.validate(process, self.intents[0]): pass

    def test_existing_deadline_is_not_extended(self):
        self.now = 10
        with self.assertRaisesRegex(ValueError, "deadline"): self.run_termination()
        self.assertFalse(any(e[0] == "signal" for e in self.events))
        self.now = 9.5
        with self.assertRaisesRegex(ValueError, "deadline"): self.run_termination(term_exits=False)
        self.assertEqual([e for e in self.events if e[0] == "signal"], [("signal", 700, signal.SIGTERM)])


@unittest.skipUnless(sys.platform == "darwin", "Darwin protected /var alias")
class DarwinVarWorkloadTests(unittest.TestCase):
    def setUp(self):
        self.fixture = WorkloadTerminationTests()
        self.fixture.temporary_parent = "/var/tmp"
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def test_exact_var_caller_and_private_var_launch_accept_both_caller_spellings(self):
        f = self.fixture
        self.assertEqual(f.work.parts[:2], ("/", "var"))
        self.assertEqual(f.paths[0].parts[:3], ("/", "private", "var"))
        for work in (f.work, f.work.resolve()):
            for process, captured in f.targets:
                intent = next(i for i in f.intents if i["container"] == captured["container"])
                with recovery.workload_target(process, f.binary, work, work / "root", f.plan, intent,
                        f.root_identity, captured["name"]) as (proof, revalidate):
                    self.assertEqual(proof, captured)
                    revalidate()
        f.test_actual_controller_physical_root_and_lexical_launch_tuples()
        f.run_termination()  # Doubled syscall only; exact audit-token/native-exit guards still run.
        self.assertEqual([e for e in f.events if e[0] == "signal"],
                         [("signal", 700, signal.SIGTERM), ("signal", 701, signal.SIGTERM)])
        # Storage specs retained /var in both actual failure roots; do not change
        # their shared path projection to repair the workload-only spelling.
        self.assertEqual(recovery.runtime_root_path(f.root), f.root)

    def test_foreign_symlink_below_var_never_authorizes_signal(self):
        f = self.fixture
        f.test_arbitrary_campaign_symlink_is_not_authority()
        process = f.targets[0][0]
        # Even a matching physical inode and caller-owned marker do not allow
        # a different spec/intent argv spelling from the persisted launch.
        arguments = tuple(arg.replace("/private/var/", "/var/") for arg in process.arguments)
        with self.assertRaisesRegex(ValueError, "specification path root"):
            with f.validate(replace(process, arguments=arguments), f.intents[0]): pass
        self.assertFalse(any(e[0] == "signal" for e in f.events))

    def test_var_alias_requires_exact_target_owner_and_nonwritable_symlink(self):
        f = self.fixture; process = f.targets[0][0]
        real_readlink, real_lstat = recovery.os.readlink, recovery.os.lstat
        for target in ("other/var", "/private/var", "private/var/../var"):
            with self.subTest(target=target), patch.object(recovery.os, "readlink",
                    side_effect=lambda path, **kw: target if str(path) == "/var" else real_readlink(path, **kw)), \
                    self.assertRaises(ValueError):
                # resolve() can reject an altered system link before the later
                # pinned-link guard; neither path may authorize a signal.
                with f.validate(process, f.intents[0]): pass
        original = real_lstat("/var")
        for change in (dict(st_uid=501), dict(st_mode=stat.S_IFDIR | 0o755), dict(st_mode=stat.S_IFLNK | 0o777)):
            bad = SimpleNamespace(st_dev=original.st_dev, st_ino=original.st_ino,
                                  st_uid=original.st_uid, st_mode=original.st_mode)
            for key, value in change.items(): setattr(bad, key, value)
            with self.subTest(change=change), patch.object(recovery.os, "lstat",
                    side_effect=lambda path, **kw: bad if str(path) == "/var" else real_lstat(path, **kw)), \
                    self.assertRaises(ValueError):
                # resolve() can reject an altered system link before the later
                # pinned-link guard; neither path may authorize a signal.
                with f.validate(process, f.intents[0]): pass
        self.assertFalse(any(e[0] == "signal" for e in f.events))

    def test_var_alias_is_revalidated_immediately_before_signal(self):
        f = self.fixture
        real = recovery.os.readlink
        changed = False
        def readlink(path, **kwargs):
            return "other/var" if str(path) == "/var" and changed else real(path, **kwargs)
        def change():
            nonlocal changed
            changed = True
        with patch.object(recovery.os, "readlink", side_effect=readlink), \
                self.assertRaisesRegex(ValueError, "system var alias changed"):
            f.run_termination(before_delivery=change)
        self.assertFalse(any(e[0] == "signal" for e in f.events))


class WorkerReplacementTests(unittest.TestCase):
    def fixture(self):
        before = owners()[0]
        before["boot"]["ready"].update(workerUUID=uid(), controllerEpoch=1, controllerKey="f" * 64,
            bootstrapKey="e" * 64, tlsRootDER=encoded("public ca"), serverDER=encoded("public cert"), serverKey="d" * 64)
        before["boot"]["initramfsSHA256"] = "c" * 64
        old, _ = recovery.worker_owner(before)
        request, raw = recovery.worker_request(uid(), old["store"], {k: old[k] for k in ("serviceEpoch", "workerUUID")})
        actual = dict(operationUUID=request["operationUUID"], predecessor=request["predecessor"], nowUnixSeconds=100)
        after = copy.deepcopy(before); after["revision"] += 1
        successor = copy.deepcopy(before["boot"])
        successor["ready"].update(serviceEpoch=uid(), workerUUID=uid(), revision=11,
            tlsRootDER=encoded("new public ca"), serverDER=encoded("new public cert"), serverKey="1" * 64)
        state = dict(store=before["store"], revision=30, reconciliationRequired=False)
        hashes = dict(state_sha256=recovery.digest(json.dumps(state).encode()))
        completed = dict(revision=state["revision"], digest=hashes["state_sha256"])
        after["workerReplacements"] = [dict(afterControllerTransitions=0, predecessor=before["boot"], request=actual,
            successor=successor, lastObservedStatus=dict(request=actual, phase="succeeded", ready=successor["ready"]),
            localAdoption=dict(revision=11, digest="b" * 64), completed=completed)]
        proof = dict(controllerEpoch=1, controllerKey="f" * 64, rootPublicKey=before["rootPublicKey"])
        pending = dict(schema=1, counter=1, phase="pending", request=request, proof=proof)
        ids = ["a" * 64, "b" * 64]
        succeeded = dict(pending, phase="succeeded", ownerRequest=actual,
            successor={k: successor["ready"][k] for k in ("serviceEpoch", "workerUUID")}, containedContainerIDs=ids)
        return [before, after, pending, succeeded, request, state, hashes, ids, 99, 101]

    def worker_snapshot(self, command="ack", written=False):
        value = snapshot("ack" if command == "ack-peer" else command, written)
        value.update(command="worker-" + command, root_xattrs=copy.deepcopy(recovery.WORKER_XATTRS),
                     file_xattrs=copy.deepcopy(recovery.WORKER_XATTRS), inode=123, seed_inode=123)
        data = recovery.WORKER_NEXT if written else recovery.WORKER_PAYLOAD
        value["file"].update(nlink=2, size=len(data)); value["sha256"] = recovery.digest(data)
        value["seed"] = copy.deepcopy(value["file"]); value["seed_sha256"] = value["sha256"]
        return value

    def test_two_consumer_hardlink_binary_empty_xattrs_and_new_write(self):
        for command, written in (("ack", False), ("ack-peer", False), ("verify", False), ("write", True), ("verify", True)):
            recovery.worker_snapshot_proof(self.worker_snapshot(command, written), command=command, written=written)
        for mutate in (lambda v: v["root_xattrs"].pop("user.rtm084.empty"),
                       lambda v: v["file_xattrs"].update({"user.rtm084.binary": ""}),
                       lambda v: v.update(seed_inode=124), lambda v: v["file"].update(nlink=1),
                       lambda v: v.update(seed_sha256="0" * 64), lambda v: v["root"].update(mtime=0),
                       lambda v: v.update(entries=["payload"]), lambda v: v.update(parent_fsynced=False)):
            value = self.worker_snapshot(); mutate(value)
            with self.assertRaises(ValueError): recovery.worker_snapshot_proof(value, command="ack")

    def test_exact_canonical_request_and_all_four_RFC_v4_IDs(self):
        request = self.fixture()[4]
        value, raw = recovery.worker_request(request["operationUUID"], request["store"], request["predecessor"])
        self.assertEqual(raw, ('{"operationUUID":"%s","store":"%s","predecessor":{"serviceEpoch":"%s","workerUUID":"%s"}}' %
            (value["operationUUID"], value["store"], value["predecessor"]["serviceEpoch"], value["predecessor"]["workerUUID"])).encode())
        self.assertLessEqual(len(raw), 512)
        for field in ("operationUUID", "store", "serviceEpoch", "workerUUID"):
            for invalid in (str(uuid.uuid1()), str(uuid.uuid4()).upper(), "00000000-0000-0000-0000-000000000000", 1):
                bad = copy.deepcopy(request)
                (bad if field in bad else bad["predecessor"])[field] = invalid
                with self.assertRaises((ValueError, TypeError)):
                    recovery.worker_request(bad["operationUUID"], bad["store"], bad["predecessor"])

    def test_exact_worker_history_timestamp_and_completed_raw_journal(self):
        args = self.fixture(); result = recovery.replacement_proof(*args)
        self.assertEqual(result["controllerEpoch"], 1)
        self.assertNotEqual(result["serviceEpoch"], args[4]["predecessor"]["serviceEpoch"])
        mutations = [
            lambda a: a[2].update(phase="succeeded"), lambda a: a[3].update(counter=2),
            lambda a: a[3].update(containedContainerIDs=[a[7][0]]), lambda a: a[3].update(ownerRequest={}),
            lambda a: a[3]["ownerRequest"].update(nowUnixSeconds=98),
            lambda a: a[3]["ownerRequest"].update(nowUnixSeconds=102),
            lambda a: a[3]["proof"].update(controllerKey="0" * 64),
            lambda a: a[3]["successor"].update(serviceEpoch=a[4]["predecessor"]["serviceEpoch"]),
            lambda a: a[1]["workerReplacements"][0].pop("completed"),
            lambda a: a[1]["workerReplacements"][0].pop("localAdoption"),
            lambda a: a[1]["workerReplacements"][0]["localAdoption"].update(revision=1),
            lambda a: a[1]["workerReplacements"][0]["completed"].update(digest="0" * 64),
            lambda a: a[1]["workerReplacements"][0]["completed"].update(revision=29),
            lambda a: a[1]["workerReplacements"][0]["successor"]["binding"].update(guestBootNonce=uid()),
            lambda a: a[1]["workerReplacements"][0]["successor"]["binding"].update(shimLaunchUUID=uid()),
            lambda a: a[1]["workerReplacements"][0]["successor"]["ready"].update(workerUUID=a[4]["predecessor"]["workerUUID"]),
            lambda a: a[1].update(rootPublicKey=encoded("wrong ROOT")),
            lambda a: a[1]["backing"].update(inode=41), lambda a: a[5].update(reconciliationRequired=True),
            lambda a: a[6].update(state_sha256="f" * 64),
        ]
        for field in ("tlsRootDER", "serverDER", "serverKey"):
            args = self.fixture()
            args[1]["workerReplacements"][0]["successor"]["ready"][field] = args[0]["boot"]["ready"][field]
            with self.assertRaises(ValueError): recovery.replacement_proof(*args)
        for mutate in mutations:
            args = self.fixture(); mutate(args)
            with self.assertRaises((ValueError, KeyError, TypeError)): recovery.replacement_proof(*args)

    def test_adoption_revision_cannot_follow_completed_revision(self):
        for revision in (11, 30):
            args = self.fixture()
            args[1]["workerReplacements"][0]["localAdoption"]["revision"] = revision
            recovery.replacement_proof(*args)
        for revision in (10, 31):
            args = self.fixture()
            args[1]["workerReplacements"][0]["localAdoption"]["revision"] = revision
            with self.assertRaisesRegex(ValueError, "successor/adoption/completion revision order"):
                recovery.replacement_proof(*args)

    def test_same_C_fresh_P_A_and_exact_old_retired_receipts(self):
        m, s, c = journal()
        running = recovery.exact_receipts(m, s, "owned-volume", c)
        retire(s); s["revision"] += 1
        retired = recovery.exact_receipts(m, s, "owned-volume", c, stopped=True)
        recovery.retired_from_running(running, retired)
        wrong = copy.deepcopy(retired); wrong["intents"][0]["slots"][0]["receipt"]["revision"] += 1
        with self.assertRaises(ValueError): recovery.retired_from_running(running, wrong)
        fresh = copy.deepcopy(retired); fresh["revision"] += 1
        owner = dict(store=fresh["store"], serviceEpoch=uid(), controllerEpoch=1)
        for intent in fresh["intents"]:
            intent.update(id=uid(), launch=uid(), prepare=uid(), serviceEpoch=owner["serviceEpoch"])
            for slot in intent["slots"]: slot["attachment"] = uid()
        recovery.fresh_receipts(retired, fresh, owner, rtm="RTM-084")
        fresh["intents"][0]["controllerEpoch"] += 1
        with self.assertRaises(ValueError): recovery.fresh_receipts(retired, fresh, owner, rtm="RTM-084")

    def test_tagged_names_and_evidence_do_not_change_RTM079_defaults(self):
        token = "a" * 32
        plan = recovery.names(token, "RTM-084")
        self.assertEqual(plan["volume"], "rtm084-" + token)
        self.assertEqual(recovery.names(token)["volume"], "rtm079-" + token)
        with tempfile.TemporaryDirectory() as temp:
            recovery.initialize_evidence(Path(temp), token, dict(phase="plan", plan=plan), rtm="RTM-084")
        with self.assertRaises(ValueError): recovery.names(token, "OTHER")

    @unittest.skipUnless(sys.platform == "darwin", "Darwin exclusive rename ABI")
    def test_exclusive_fsynced_single_link_request_and_immutable_receipt_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / "managed-storage-replacement").mkdir(mode=0o700)
            info = root.stat(); identity = dict(device=info.st_dev, inode=info.st_ino)
            request = self.fixture()[4]
            _, raw = recovery.worker_request(request["operationUUID"], request["store"], request["predecessor"])
            with recovery.replacement_queue(root, identity) as (queue, validate):
                with patch.object(recovery.os, "fsync", wraps=os.fsync) as sync:
                    marker = recovery.publish_worker_request(queue, raw)
                self.assertEqual(sync.call_count, 2)
                contents, stamp = recovery.queue_file(queue, "request.json", 512)
                self.assertEqual(contents, raw); self.assertEqual(stamp[:2], marker)
                other, raw2 = recovery.worker_request(uid(), request["store"], request["predecessor"])
                with self.assertRaises(OSError): recovery.publish_worker_request(queue, raw2)
                self.assertEqual(recovery.queue_file(queue, "request.json")[0], raw)
                os.link(root / "managed-storage-replacement/request.json", root / "managed-storage-replacement/linked")
                with self.assertRaises(ValueError): recovery.queue_file(queue, "request.json")
                validate()

    def test_contradictory_late_failure_writing_artifacts_and_replacement_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); operation = uid(); seen = {}
            queue = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for suffix in (".request.json", ".pending.json", ".succeeded.json"):
                    name = operation + suffix
                    (directory / name).write_bytes(b"{}"); (directory / name).chmod(0o600)
                    seen[name] = recovery.queue_file(queue, name)
                recovery.settled_worker_artifacts(queue, operation, seen)
                for suffix in (".failed.json", ".failed.json.writing", ".succeeded.json.writing"):
                    path = directory / (operation + suffix); path.write_bytes(b"{}")
                    with self.assertRaises(ValueError): recovery.settled_worker_artifacts(queue, operation, seen)
                    path.unlink()
                path = directory / (operation + ".pending.json"); raw = path.read_bytes()
                path.rename(directory / "old"); path.write_bytes(raw); path.chmod(0o600); (directory / "old").unlink()
                with self.assertRaises(ValueError): recovery.settled_worker_artifacts(queue, operation, seen)
            finally:
                os.close(queue)

    def test_queue_post_read_metadata_change_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); path = directory / "receipt.json"; path.write_bytes(b"{}"); path.chmod(0o600)
            queue = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            real = os.pread
            def read(fd, count, offset):
                raw = real(fd, count, offset)
                path.chmod(0o644)
                return raw
            try:
                with patch.object(recovery.os, "pread", side_effect=read), self.assertRaises(ValueError):
                    recovery.queue_file(queue, "receipt.json")
            finally:
                os.close(queue)

    def test_disk_budget_remaining_allowance_plus_reserve_without_allocation(self):
        gib = 1024 ** 3
        self.assertEqual(recovery.DISK_INCREMENT, 2 * gib)
        self.assertEqual(recovery.DISK_RESERVE, 4 * gib)
        # 100GiB logical sparse disks with only 8MiB initially allocated.
        baseline = 8 * 1024 ** 2
        def check(growth, free, initial=False):
            info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_blocks=(baseline + growth) // 512, st_size=100 * gib)
            entry = SimpleNamespace(stat=lambda **kwargs: info)
            with patch.object(recovery.os, "scandir", return_value=nullcontext(iter([entry]))), \
                    patch.object(recovery.os, "statvfs", return_value=SimpleNamespace(f_bavail=free, f_frsize=1)):
                return recovery.disk_budget("/inert-root", None if initial else baseline)
        for growth in (0, gib, 2 * gib):
            required = 6 * gib - growth
            proof = check(growth, required)
            self.assertEqual(proof["growth"], growth)
            self.assertEqual(proof["remaining"], 2 * gib - growth)
            self.assertEqual(proof["headroom"], required)
            with self.assertRaises(ValueError): check(growth, required - 1)
        self.assertEqual(check(0, 6 * gib, initial=True)["headroom"], 6 * gib)
        with self.assertRaises(ValueError): check(0, 6 * gib - 1, initial=True)
        # Ample external space can never excuse exceeding the 2GiB growth cap.
        with self.assertRaisesRegex(ValueError, "allocated increment cap"):
            check(2 * gib + 512, 3500 * gib)
        # A deleted baseline allocation does not mint additional growth budget.
        self.assertEqual(check(-512, 6 * gib)["remaining"], 2 * gib)
        with self.assertRaises(ValueError): check(-512, 6 * gib - 1)

    def test_actual_campaign_call_postchecks_mutation_and_chains_API_failure(self):
        run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        function = copy.deepcopy(next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "call"))
        module = ast.Module(body=[function], type_ignores=[])
        for rtm in ("RTM-084", "RTM-079"):
            for api_fails, disk_fails in ((False, False), (True, False), (False, True), (True, True)):
                with self.subTest(rtm=rtm, api_fails=api_fails, disk_fails=disk_fails):
                    events = []; allocated = 0
                    api_error = RuntimeError("API failed after mutation")
                    disk_error = recovery.ProofFailure("post-call allocation exceeded")
                    client, result = object(), object()
                    def operation(argument, *, option):
                        nonlocal allocated
                        self.assertEqual((argument, option), ("argument", "option"))
                        allocated += 1
                        events.append(("mutation", allocated))
                        if api_fails: raise api_error
                        return result
                    def api_call(observed_client, deadline, selected, *args, **kwargs):
                        self.assertIs(observed_client, client)
                        self.assertEqual(deadline, 123)
                        self.assertIs(selected, operation)
                        return selected(*args, **kwargs)
                    def disk_budget(root, baseline):
                        self.assertEqual((root, baseline), ("inert-root", 17))
                        events.append(("disk-check", allocated))
                        if allocated and disk_fails: raise disk_error
                    namespace = dict(rtm=rtm, work_deadline=123, client=client, disk_baseline=17,
                        daemon=SimpleNamespace(root="inert-root"),
                        campaign=SimpleNamespace(api_call=api_call),
                        worker_recovery=SimpleNamespace(disk_budget=disk_budget))
                    exec(compile(module, str(PATH), "exec"), namespace)
                    selected_error = disk_error if rtm == "RTM-084" and disk_fails else api_error if api_fails else None
                    if selected_error is None:
                        self.assertIs(namespace["call"](operation, "argument", option="option"), result)
                    else:
                        with self.assertRaises(type(selected_error)) as raised:
                            namespace["call"](operation, "argument", option="option")
                        self.assertIs(raised.exception, selected_error)
                        if selected_error is disk_error and api_fails:
                            self.assertIs(raised.exception.__context__, api_error)
                            self.assertFalse(raised.exception.__suppress_context__)
                        else:
                            self.assertIsNone(raised.exception.__context__)
                    self.assertEqual(events, [("disk-check", 0), ("mutation", 1), ("disk-check", 1)]
                                     if rtm == "RTM-084" else [("mutation", 1)])

    def test_only_worker_probe_strips_debug_tables_and_records_build_flags(self):
        run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        assignment = next(n for n in ast.walk(run) if isinstance(n, ast.Assign) and
                          any(isinstance(t, ast.Name) and t.id == "linker_flags" for t in n.targets))
        expression = compile(ast.Expression(assignment.value), str(PATH), "eval")
        self.assertEqual(eval(expression, {"rtm": "RTM-079"}), "-buildid=")
        self.assertEqual(eval(expression, {"rtm": "RTM-084"}), "-buildid= -s -w")
        build = next(n for n in ast.walk(run) if isinstance(n, ast.Call) and ast.unparse(n.func) == "subprocess.run")
        self.assertIn("'-ldflags=' + linker_flags", ast.unparse(build.args[0]))
        fixture = next(n for n in ast.walk(run) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and
                       n.func.id == "record" and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == "fixture")
        self.assertIn("linker_flags", {k.arg for k in fixture.keywords})

    def test_total_evidence_bound_includes_probe_and_reserves_failure_cleanup(self):
        run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        record = copy.deepcopy(next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "record"))
        # Execute the actual recorder with an inert preexisting evidence file.
        record.body = [n for n in record.body if not isinstance(n, ast.Nonlocal)]
        record.body.insert(0, ast.Global(names=["used", "last_phase"]))
        module = ast.fix_missing_locations(ast.Module(body=[record], type_ignores=[]))
        payload = (json.dumps({"phase": "probe", "padding": "x"}, sort_keys=True) + "\n").encode()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); (directory / "evidence.jsonl").touch()
            namespace = dict(json=json, os=os, directory=directory, require=recovery.require,
                             MAX_ARTIFACT=recovery.MAX_ARTIFACT, used=recovery.MAX_ARTIFACT - 65536 - len(payload))
            exec(compile(module, str(PATH), "exec"), namespace)
            namespace["record"]("probe", padding="x")
            self.assertEqual(namespace["used"], recovery.MAX_ARTIFACT - 65536)
            with self.assertRaises(ValueError): namespace["record"]("probe", padding="x")
            namespace["record"]("failure", error="bounded")
            namespace["record"]("cleanup", retained=True)
            self.assertLess(namespace["used"], recovery.MAX_ARTIFACT)
            namespace["used"] = recovery.MAX_ARTIFACT
            with self.assertRaises(ValueError): namespace["record"]("cleanup")
        self.assertEqual(recovery.MAX_ARTIFACT, 4 * 1024 ** 2)
        text = ast.unparse(run)
        self.assertIn("used += len(payload)", text)
        self.assertIn("used + 65536 <= MAX_ARTIFACT", text)

    def test_RTM084_parent_only_completion_never_daemon_stop_start(self):
        function = copy.deepcopy(next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "test_live_managed_storage_worker_replacement"))
        function.decorator_list = []
        parent, child = Mock(), Mock(); child.fileno.return_value = 4; parent.recv.return_value = b"D"
        process = Mock(returncode=None); process.wait.return_value = 0
        daemon = SimpleNamespace(binary="binary", root="root", socket="socket", work="work", stop=Mock(), start=Mock())
        namespace = dict(time=time, socket=SimpleNamespace(socketpair=lambda: (parent, child)), sys=sys, __file__=str(PATH),
            subprocess=SimpleNamespace(Popen=lambda *a, **kw: process, DEVNULL=-3), parent_deadline=lambda _: nullcontext(),
            signal=signal, struct=struct, require=recovery.require, pytest=SimpleNamespace(fail=lambda *a, **k: self.fail("parent failed")))
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(PATH), "exec"), namespace)
        namespace[function.name](daemon)
        daemon.stop.assert_not_called(); daemon.start.assert_not_called()
        self.assertEqual([call.args[0] for call in parent.sendall.call_args_list], [b"D"])
        run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        replace_worker = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "replace_worker")
        text = ast.unparse(replace_worker)
        self.assertNotIn(".stop(", text); self.assertNotIn("signal_storage(", text); self.assertNotIn("terminate_workloads(", text)
        self.assertLess(text.index("publish_worker_request("), text.index("wait_exit(process)"))
        self.assertLess(text.index("wait_exit(process)"), text.index("container.start"))
        self.assertIn("stale_credential_negative_probe=False", text)


class LifecycleRecoveryTests(unittest.TestCase):
    @staticmethod
    def base():
        return runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-lifecycle-evidence.py"))

    def fixture(self):
        # Genuine v2 current/controller/service DTOs and the ordinary campaign's
        # two runtime intents. No v1 conversion or PREPARE fault arm participates.
        base = self.base()
        before = base["owner"]()
        a = before["checkpoint"]
        manifest, state, containers = journal()
        a["identity"]["store"] = state["store"]
        import managed_prepare_lifecycle_evidence as lifecycle
        a["identity"]["binding"] = recovery.digest(b"cengine.storageauthority.binding.v3\0" +
            lifecycle.p.canonical(lifecycle.manifest_binding(before["manifest"])))
        old = a["currentContext"]
        for intent in state["intents"].values():
            intent.update(old, version=1)
        retire(state)
        after = copy.deepcopy(before); b = after["checkpoint"]
        b["revision"] += 10
        current = dict(old, serviceEpoch=uid())
        b["currentContext"] = current
        b["observedWorker"] = dict(context=current, workerUUID=uid())
        service = b["currentService"]
        service["context"]["service_epoch"] = service["boot"]["service_epoch"] = current["serviceEpoch"]
        service["boot"].update(tls_root_sha256="7" * 64, server_spki="8" * 64)
        service["open_revision"] = 14
        request, _ = recovery.worker_request(uid(), a["identity"]["store"],
            dict(serviceEpoch=old["serviceEpoch"], workerUUID=a["observedWorker"]["workerUUID"]))
        change = dict(operation_id=request["operationUUID"], predecessor=a["currentService"])
        retry = dict(request=change, stageRequestID=uid(), completionRequestID=uid(),
            predecessorWorkerUUID=request["predecessor"]["workerUUID"], nowUnixSeconds=100, lifetimeSeconds=300)
        b.update(latestServiceRequest=retry, latestServiceConfirmation=dict(request=change, successor=service),
            latestServiceChange=dict(operationID=request["operationUUID"], predecessor=old, successor=current, revision=14),
            nativeReplacementAttempted=True, serviceReplacement=dict(predecessor_worker_uuid=retry["predecessorWorkerUUID"],
                configuration=dict(action="open", root_public_key=b["rootPublicKey"], signed=b["current"]["original"]["signed"],
                    now_unix_seconds=100, lifetime_seconds=300, reopen=dict(request=change, signature=base["encoded"](b"x" * 64)))))
        b["serviceLinks"] = [b["latestServiceChange"]]
        b["contexts"].append(dict(context=current, controller=b["current"], serviceResult=b["latestServiceChange"]))
        b["intentRevision"] = state["revision"]
        b["references"] = [dict(id=identifier, version=1, original=old, superseded=[])
            for identifier in sorted(state["intents"])]
        proof = dict(controllerEpoch=old["controllerEpoch"], controllerKey=old["controllerKey"], rootPublicKey=a["rootPublicKey"])
        pending = dict(schema=1, counter=1, phase="pending", request=request, proof=proof)
        succeeded = dict(pending, phase="succeeded", ownerRequest=dict(operationUUID=request["operationUUID"],
            predecessor=request["predecessor"], nowUnixSeconds=100),
            successor=dict(serviceEpoch=current["serviceEpoch"], workerUUID=b["observedWorker"]["workerUUID"]),
            containedContainerIDs=sorted(containers))
        hashes = dict(state_sha256=recovery.digest(json.dumps(state).encode()))
        return [before, after, pending, succeeded, request, state, hashes, containers, 99, 101]

    def test_current_v2_reader_and_cold_transition_without_legacy_history(self):
        base = self.base(); before = base["owner"](); after = base["successor"](before, True)
        for value in (before, after):
            reader = Mock(side_effect=[(value["checkpoint"], "a" * 64), (value["manifest"], "b" * 64)])
            actual, proof, stamp = recovery.lifecycle_owner(Path("/owned"), reader=reader)
            self.assertEqual(actual, value)
            self.assertEqual(proof["format"], "storage-lifecycle.v2")
            self.assertEqual(len(stamp), 64)
            self.assertEqual(reader.call_args_list[1].args[0], Path("/owned/managed-storage-owner/manifest.json"))
            self.assertNotIn("transitions", actual)
        result = recovery.recovered_lifecycle_owner(before, after)
        self.assertEqual(result["controllerEpoch"], 2)
        self.assertNotEqual(result["serviceEpoch"], before["checkpoint"]["currentContext"]["serviceEpoch"])
        for worker in (False, True):
            for invalid in (owners()[0], {"version": "storage-lifecycle.v1"}, {"version": None}):
                with self.subTest(worker=worker), self.assertRaises(ValueError):
                    recovery.lifecycle_owner(Path("/owned"), worker=worker, reader=Mock(return_value=(invalid, "a" * 64)))

    def test_cold_refuses_api_only_pending_rewritten_and_wrong_physical_edges(self):
        base = self.base(); before = base["owner"]()
        with self.assertRaises(ValueError): recovery.recovered_lifecycle_owner(before, base["successor"](before))
        for mutate in (lambda v: v["manifest"]["backing"].update(inode=999),
                       lambda v: v["checkpoint"].update(pendingCold={}),
                       lambda v: v["checkpoint"]["latestCold"]["predecessorService"].update(open_revision=1),
                       lambda v: v["checkpoint"]["latestCold"]["completion"]["receipt"].update(revision=99),
                       lambda v: v["checkpoint"]["latestCold"]["request"].update(completionRequestID=uid()),
                       lambda v: v["checkpoint"]["latestCold"]["request"]["prepare"]["mountedGreeting"].update(heldBackingIdentity={})):
            after = json.loads(json.dumps(base["successor"](before, True))); mutate(after)
            with self.assertRaises((ValueError, KeyError)): recovery.recovered_lifecycle_owner(before, after)

    def test_ordinary_v2_worker_two_live_consumers_exact_census_and_receipts(self):
        args = self.fixture()
        result = recovery.lifecycle_replacement_proof(*args)
        self.assertEqual(result["controllerEpoch"], 1)
        self.assertNotEqual(result["serviceEpoch"], args[4]["predecessor"]["serviceEpoch"])
        self.assertNotIn("workerReplacements", args[1])
        history = recovery.lifecycle_worker_history(args[1])
        self.assertEqual(history["latestServiceChange"]["operationID"], args[4]["operationUUID"])
        mutations = [lambda a: a[1]["manifest"]["backing"].update(inode=999),
            lambda a: a[1]["checkpoint"].update(pendingService={}),
            lambda a: a[1]["checkpoint"].update(nativeReplacementAttempted=False),
            lambda a: a[1]["checkpoint"]["latestServiceConfirmation"]["request"].update(operation_id=uid()),
            lambda a: a[1]["checkpoint"]["latestServiceRequest"].update(predecessorWorkerUUID=uid()),
            lambda a: a[1]["checkpoint"]["observedWorker"].update(workerUUID=a[4]["predecessor"]["workerUUID"]),
            lambda a: a[1]["checkpoint"]["currentService"]["boot"].update(server_spki=a[0]["checkpoint"]["currentService"]["boot"]["server_spki"]),
            lambda a: a[1]["checkpoint"]["serviceLinks"].clear(),
            lambda a: a[1]["checkpoint"]["references"].pop(),
            lambda a: a[1]["checkpoint"].update(intentRevision=1),
            lambda a: a[3].update(containedContainerIDs=a[7][:1]),
            lambda a: a[3].update(counter=2), lambda a: a[3].update(schema=True),
            lambda a: a[3]["ownerRequest"].update(nowUnixSeconds=102),
            lambda a: a[3]["proof"].update(controllerKey="0" * 64),
            lambda a: a[5].update(reconciliationRequired=True),
            lambda a: a[6].update(state_sha256="not-a-hash")]
        for index, mutate in enumerate(mutations):
            args = json.loads(json.dumps(self.fixture())); mutate(args)
            with self.subTest(mutation=index), self.assertRaises((ValueError, KeyError)):
                recovery.lifecycle_replacement_proof(*args)
        with self.assertRaises(ValueError): recovery.lifecycle_replacement_proof(*WorkerReplacementTests().fixture())

    def test_physical_backing_snapshot_detects_reformat_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); path = root / "infrastructure/volumes.ext4"; path.parent.mkdir()
            block = bytearray(4096); filesystem = uuid.uuid4()
            block[1080:1082] = b"\x53\xef"; block[1128:1144] = filesystem.bytes
            block[1288:1292] = b"time"; path.write_bytes(block)
            info = path.stat()
            proof = dict(backing=dict(device=info.st_dev, inode=info.st_ino), bytes=4096, ext4UUID=str(filesystem))
            before = recovery.backing_snapshot(root, proof)
            block[1288:1292] = b"new!"; path.write_bytes(block)
            self.assertNotEqual(before, recovery.backing_snapshot(root, proof))
            block[1128:1144] = uuid.uuid4().bytes; path.write_bytes(block)
            with self.assertRaises(ValueError): recovery.backing_snapshot(root, proof)
            other = path.with_name("other"); path.rename(other); path.symlink_to(other)
            with self.assertRaises(OSError): recovery.backing_snapshot(root, proof)

    def test_campaign_checks_native_identity_and_backing_before_signal(self):
        run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign")
        text = ast.unparse(run)
        # Signaling requires authenticated checkpoint evidence, not host-only records.
        calls = {node.func.id for node in ast.walk(run)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue(calls.isdisjoint({"owner_proof", "worker_owner", "target_matches"}))
        self.assertIn("signal_storage(target, before_signal=before_signal)", text)
        self.assertIn("cold predecessor is the killed native launch", text)
        self.assertIn("unchanged backing at signal", text)
        self.assertIn("final unchanged backing filesystem", text)


if __name__ == "__main__": unittest.main()
