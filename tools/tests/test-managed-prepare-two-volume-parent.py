#!/usr/bin/env python3
"""Host-only executable parent regressions; never native/VM acceptance."""
import ast
import copy
from dataclasses import replace
import signal
import io
from pathlib import Path
import runpy
import sys
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import harness
import managed_prepare_faults as p
import managed_prepare_two_volume_parent as parent
import managed_prepare_two_volume_drain as drain

FIXTURE = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-two-volume-drain.py"))
TREE = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())


def function(name, **values):
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name)
    env = dict(proof=p, **values)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "parent-entry", "exec"), env)
    return env[name]


class ParentTests(unittest.TestCase):
    def test_stopped_peer_refresh_only_after_exact_join_keeps_history_and_reads_strict(self):
        api = harness.RuntimeProcess(100, identity=(10, 2, 300), pidversion=8)
        process = replace(api, pid=101, parent_pid=api.pid)
        for reparent in (False, True):
            daemon = SimpleNamespace(process=SimpleNamespace(pid=api.pid, returncode=-signal.SIGKILL))
            current = replace(process, parent_pid=1) if reparent else process
            native = {process.pid: current}
            launch, state = Mock(), Mock()
            retired = dict(phase="retired", prepareCompleted=True)
            owner = parent.stopped_peer_owner(daemon, process, retired, launch, state)
            with patch.object(harness, "_kernel_process", side_effect=native.get):
                if reparent:
                    with self.assertRaises(ValueError): owner[2]()
                launch.reset_mock()
                owner[2].api_joined_refresh(api, [api, current])
                launch.assert_called_once_with(); state.assert_not_called()
                self.assertIs(owner[1], retired)
                self.assertEqual(owner[0], current)
                owner[2]()
                self.assertEqual(launch.call_count, 2); state.assert_called_once_with()
                with self.assertRaises(ValueError): owner[2].api_joined_refresh(api, [api, current])
                native[process.pid] = replace(current, parent_pid=77)
                with self.assertRaises(ValueError): owner[2]()

    def test_stopped_peer_refresh_rejects_unjoined_identity_drift_and_changed_files(self):
        api = harness.RuntimeProcess(100, identity=(10, 2, 300), pidversion=8)
        process = replace(api, pid=101, parent_pid=api.pid)
        changes = [dict(pid=99), dict(identity=(11, 2, 300)), dict(pidversion=99),
            dict(executable="/other"), dict(arguments=("other",)), dict(command="other"),
            dict(parent_pid=77), dict(parent_pid=None)]
        faults = ["unjoined", "wrong-pid", "wrong-signal", "live-api", "ambiguous-api",
                  "missing", "duplicate", "native-drift", "files", *changes]
        for fault in faults:
            with self.subTest(fault=fault):
                daemon = SimpleNamespace(process=SimpleNamespace(pid=api.pid, returncode=-signal.SIGKILL))
                current = replace(process, parent_pid=1)
                if isinstance(fault, dict): current = replace(current, **fault)
                native = {process.pid: current}
                survivors = [api, current]
                launch, state = Mock(), Mock()
                owner = parent.stopped_peer_owner(daemon, process, {}, launch, state)
                if fault == "unjoined": daemon.process.returncode = None
                if fault == "wrong-pid": daemon.process.pid += 1
                if fault == "wrong-signal": daemon.process.returncode = -signal.SIGTERM
                if fault == "live-api": native[api.pid] = api
                if fault == "ambiguous-api": native[api.pid] = replace(api, pidversion=99)
                if fault == "missing": survivors = [api]
                if fault == "duplicate": survivors.append(current)
                if fault == "native-drift": native[process.pid] = replace(current, pidversion=99)
                if fault == "files": launch.side_effect = ValueError("pinned launch changed")
                with patch.object(harness, "_kernel_process", side_effect=native.get), self.assertRaises(ValueError):
                    owner[2].api_joined_refresh(api, survivors)
                self.assertEqual(owner[0], process)
                state.assert_not_called()

    def test_closed_entry_dispatches_real_lifecycle(self):
        dispatch = Mock(return_value="live")
        run = function("run_two_volume_drain_shard", _run_prepare_case=dispatch)
        args = dict(probe=None, probe_sha256=None, source_sha256=None, expected_commit=None, evidence=None)
        for profile, cases in ((p.PROFILE, drain.CASES), (p.FULL_PROFILE, p.FULL_CASES), (p.FULL_PROFILE, ())):
            with self.assertRaises(ValueError): run(None, profile=profile, cases=cases, **args)
        dispatch.assert_not_called()
        self.assertEqual(run(None, profile=p.FULL_PROFILE, cases=drain.CASES, **args), "live")
        call = dispatch.call_args.kwargs
        self.assertTrue(call["two_volume"] and call["storage_restart"] and call["staged"]["runnable"])
        self.assertFalse(call["staged"]["fullAcceptance"])
        self.assertEqual(len(p.FULL_CASES), 9)

    def test_two_owned_containers_both_mount_both_volumes(self):
        client, image = Mock(), Mock(id="image")
        plan = p.names("a" * 32)
        create = function("create_shared_consumers")
        with patch.object(p, "owned", side_effect=lambda obj, *_: obj):
            create(client, image, SimpleNamespace(name="v1"), plan, extra_volume=SimpleNamespace(name="v2"), two_volume=True)
        calls = client.containers.create.call_args_list
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertEqual(set(call.kwargs["volumes"]), {"v1", "v2"})
            self.assertEqual({v["bind"] for v in call.kwargs["volumes"].values()}, {"/data", "/other"})
            self.assertTrue(all(v["mode"] == "rw" for v in call.kwargs["volumes"].values()))
            self.assertEqual(call.kwargs["mem_limit"], "128m")
            self.assertEqual(call.kwargs["labels"], {p.OWNER: plan["owner"]})
        self.assertEqual(calls[0].kwargs["volumes"]["v1"]["bind"], "/data")
        self.assertEqual(calls[1].kwargs["volumes"]["v2"]["bind"], "/data")

    def test_dual_immutable_source_archive_and_pinned_helper(self):
        raw, config = parent.image_archive(b"pinned-helper", p.names("b" * 32))
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            layer = archive.extractfile("layer.tar").read()
        self.assertEqual(config["rootfs"]["diff_ids"], ["sha256:" + p.digest(layer)])
        with tarfile.open(fileobj=io.BytesIO(layer)) as archive:
            self.assertEqual(archive.extractfile("probe").read(), b"pinned-helper")
            for name, data in p.FILES.items():
                for root in ("data", "other"):
                    item = archive.getmember(root + "/" + name)
                    self.assertEqual((item.uid, item.gid, item.mode, item.mtime), (10001, 10002, 0o640, p.MTIME))
                    self.assertEqual(archive.extractfile(item).read(), data)

    def cut(self, fault=None):
        *_, arm, worker, checkpoint, state = FIXTURE["fixture"]()
        physical = FIXTURE["FULL"]["V1"]["observed"](arm)
        physical.update(version=3, profile=p.FULL_PROFILE)
        held = dict(query=drain.storage_query(arm, worker), state="held", observation=checkpoint,
                    retirementStarted=True, acceptedInFlight=0, lateAdmissionRejected=False, receiptReplayCount=0)
        artifacts = {".storage-checkpoint.json": checkpoint, ".checkpoint.json": physical, ".storage-held.json": held}
        if fault == "early": state["intents"][arm["scope"]["intent"]]["phase"] = "prepareAdmitted"
        if fault == "not-held": held["state"] = "observed"
        if fault == "wrong-physical": physical["armDigest"] = "0" * 64
        events = []
        def read(suffix, *_):
            events.append(suffix)
            if fault == "observer-lost" and suffix == ".storage-held.json": raise FileNotFoundError(suffix)
            return artifacts[suffix]
        def validate():
            events.append("owner")
            if fault == "owner-lost": raise ValueError("peer owner lost")
        result = parent.retained_cut(arm=arm, worker=worker, wait_artifact=read, artifact=read,
            read_state=lambda: ({}, state, {"state_sha256": "a" * 64}),
            record=lambda phase, **kw: events.append(phase), validate_peer=validate)
        events.append("helper")
        result[3]()  # The actual helper revalidates the retained independent witness.
        return events

    def test_retained_physical_host_gap_and_held_precede_helper(self):
        events = self.cut()
        self.assertLess(events.index("two-volume-checkpoints-external-fsync"), events.index("helper"))
        self.assertLess(events.index("two-volume-host-gap-external-fsync"), events.index("helper"))
        self.assertEqual(events[-4:], ["owner", ".checkpoint.json", ".storage-checkpoint.json", ".storage-held.json"])

    def test_early_cut_owner_observer_and_physical_loss_fail_before_helper(self):
        for fault in ("early", "owner-lost", "observer-lost", "wrong-physical", "not-held"):
            with self.subTest(fault=fault), self.assertRaises((ValueError, FileNotFoundError)):
                self.cut(fault)

    def test_budget_counts_parent_and_start_children(self):
        process = SimpleNamespace(arguments=("api",))
        parent.resource_budget([process] * 6, [Mock(poll=lambda: None)])
        with self.assertRaises(ValueError): parent.resource_budget([process] * 7, [Mock(poll=lambda: None)])
        directory = Mock()
        directory.__enter__ = Mock(return_value=directory)
        directory.__exit__ = Mock(return_value=False)
        directory.read.return_value = (p.canonical({"memoryBytes": 3 * 1024**3}), None)
        vm = SimpleNamespace(arguments=("engine", "vm-shim", "--spec", "/owned/spec.json"))
        with patch.object(p, "Directory", return_value=directory), self.assertRaises(ValueError):
            parent.resource_budget([vm], [])

    def test_fresh_owner_rejects_old_attachment_key_context_and_replacement(self):
        *_, arm, worker, checkpoint, state = FIXTURE["fixture"]()
        old = state["intents"][arm["scope"]["intent"]]
        current = copy.deepcopy(old)
        current.update(id=FIXTURE["uid"](), launch=FIXTURE["uid"](), prepare=FIXTURE["uid"](),
            phase="running", prepareCompleted=True, serviceEpoch=FIXTURE["uid"](),
            controllerEpoch=old["controllerEpoch"] + 1, controllerKey="a" * 64)
        for index, slot in enumerate(current["slots"]):
            slot.update(attachment=FIXTURE["uid"](), key=str(index + 1) * 64)
        context = {key: current[key] for key in ("store", "serviceEpoch", "controllerEpoch", "controllerKey")}
        parent.fresh_owner(old, current, context)
        for mutate in (lambda value: value["slots"][0].update(attachment=old["slots"][0]["attachment"]),
                       lambda value: value["slots"][0].update(key=old["slots"][0]["key"]),
                       lambda value: value.update(serviceEpoch=old["serviceEpoch"]),
                       lambda value: value.update(predecessor=old["id"]),
                       lambda value: value["slots"].pop()):
            bad = copy.deepcopy(current); mutate(bad)
            with self.assertRaises(ValueError): parent.fresh_owner(old, bad, context)

    def test_unarmed_readback_checks_both_before_any_writer(self):
        tree = ast.parse(Path(parent.__file__).read_text())
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
        text = ast.unparse(run)
        self.assertNotIn("failed_full_prepare", text)
        self.assertNotIn("full_retry_snapshot", text)
        self.assertEqual(text.count("queue_start("), 1)
        clean = text.index("two-volume-all-staging-clean")
        self.assertLess(text.index("baseline=expected"), clean)
        self.assertLess(clean, text.index("observe('writer'"))
        self.assertIn("((container, baseline), (peer, expected_second))", text)
        self.assertIn("held_reader=held_reader, worker=worker, physical=physical", text)
        self.assertIn("for selected, selected_plan in ((volume, plan), (extra_volume, extra_plan))", text)


if __name__ == "__main__":
    unittest.main()
