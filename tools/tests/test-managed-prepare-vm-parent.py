#!/usr/bin/env python3
"""Engine-free staged parent ordering only; no VM/native acceptance evidence."""
import ast
import copy
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p
import managed_prepare_vm_boundaries as cuts
import managed_prepare_storage_vm_faults as recovery

A7 = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-storage-vm.py"))
FULL = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-full.py"))
BOUNDARIES = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-vm-boundaries.py"))
source_witness_for = BOUNDARIES["source_witness_for"]
invalid_source_witnesses = BOUNDARIES["invalid_source_witnesses"]
V1 = A7["SERVICE"]["V1"]
FIXTURE = ROOT / "Tests/Compatibility/test_managed_prepare_faults.py"


def checkpoint_for(arm, original, stage, worker):
    if stage == cuts.CASES[1]:
        arm["caseName"] = stage
        return dict(original, stage=stage, armDigest=p.digest(p.canonical(arm)))
    arm["caseName"] = "transaction-published-bind-reply-lost"
    value = FULL["storage"](arm, worker)
    arm["caseName"] = stage
    value.update(**cuts.storage_query(arm, worker), stage=stage)
    intent = value["bound"]["intent"]
    intent["root"]["backing_uuid"] = original["filesystemUUID"]
    if stage == cuts.CASES[2]:
        metadata = FULL["cleanup"]()
        metadata.update(uid=10001, gid=10002, mode=0o750,
            atime_seconds=str(original["sourceAtimes"]["root"] // 10**9), mtime_seconds=str(p.MTIME),
            atime_nanos=original["sourceAtimes"]["root"] % 10**9,
            manifest=FULL["object_for"](3), staging=FULL["object_for"](4))
        metadata["manifest"]["file_type"] = 32768
        intent.update(phase="CLEANING", manifest_size=100, manifest_digest="a" * 64, cleanup=metadata)
    return value


class ParentEntries(unittest.TestCase):
    def test_three_closed_entries_and_unchanged_denominator(self):
        dispatch = Mock(return_value=object())
        args = dict(probe=None, probe_sha256=None, source_sha256=None, expected_commit=None, evidence=None)
        for name, case in zip(("private", "root", "cleaning"), cuts.CASES):
            run = A7["SERVICE"]["function"]("run_storage_" + name + "_shard", _run_prepare_case=dispatch)
            dispatch.reset_mock()
            for profile, cases in ((p.PROFILE, cuts.CASES), (p.FULL_PROFILE, cuts.CASES[::-1]),
                                   (p.FULL_PROFILE, (*cuts.CASES, "first-child-published"))):
                with self.assertRaises(ValueError): run(None, profile=profile, cases=cases, **args)
            dispatch.assert_not_called()
            run(None, profile=p.FULL_PROFILE, cases=cuts.CASES, **args)
            call = dispatch.call_args.kwargs
            self.assertEqual(call["vm_cut"], case)
            self.assertEqual(call["fault_case"], case)
            self.assertTrue(call["storage_restart"])
            self.assertFalse(call["staged"]["fullAcceptance"])
        self.assertEqual(len(p.FULL_CASES), 9)

    def test_cut_results_accept_profile_from_closed_selection(self):
        import uuid
        import managed_prepare_two_volume_drain as drain
        tree = ast.parse(FIXTURE.read_text())
        results = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "result" for t in n.targets)
            and isinstance(n.value, ast.Call) and any(k.arg == "result" and isinstance(k.value, ast.Constant)
                and k.value.value == "initial-cut-passed" for k in n.value.keywords)]
        self.assertEqual(len(results), 3)  # API, storage and worker result publication.
        for stage in (*cuts.CASES, drain.CASE):
            selected = (drain.selection(p.FULL_PROFILE, (drain.CASE,), stage) if stage == drain.CASE
                else cuts.selection(p.FULL_PROFILE, cuts.CASES, stage))
            selected.update(rtm="RTM-099", boundary=stage)
            original = copy.deepcopy(selected)
            for result in results:
                env = dict(staged=selected, profile=p.FULL_PROFILE, uuid=uuid, proof=p,
                    plan={"owner": "a" * 32}, manifest={"store": str(uuid.uuid4())}, evidence_chain=[])
                exec(compile(ast.Module(body=[result], type_ignores=[]), "cut-result", "exec"), env)
                self.assertEqual(env["result"], dict(selected, profile=p.FULL_PROFILE,
                    result="initial-cut-passed", execution="actual-docker-runtime",
                    runID=str(uuid.UUID("a" * 32)), store=env["manifest"]["store"],
                    evidenceSHA256=p.digest(p.canonical([]))))
                self.assertEqual(selected, original)
                self.assertFalse(env["result"]["fullAcceptance"])

    def test_checkpoint_fsync_precedes_restart_and_no_vm_release(self):
        tree = ast.parse(FIXTURE.read_text())
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run_prepare_case")
        calls = [n for n in ast.walk(run) if isinstance(n, ast.Call)]
        checkpoint = next(n for n in calls if isinstance(n.func, ast.Name) and n.func.id == "record"
            and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == "checkpoint-external-fsync")
        restart = next(n for n in calls if isinstance(n.func, ast.Name) and n.func.id == "restart_storage_at_vm_cut")
        self.assertLess(checkpoint.lineno, restart.lineno)
        branch = next(n for n in ast.walk(run) if isinstance(n, ast.If)
            and ast.unparse(n.test) == "vm_cut is not None" and "restart_storage_at_vm_cut" in ast.unparse(n))
        self.assertIn("artifact(", ast.unparse(branch.body[1]))
        self.assertNotIn("publish(", ast.unparse(branch))
        self.assertNotIn("release", ast.unparse(branch))

    def test_actual_observed_hold_is_validated_and_fsynced_before_restart(self):
        tree = ast.parse(FIXTURE.read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == "vm_cut is not None" and "restart_storage_at_vm_cut" in ast.unparse(n))
        for stage in (cuts.CASES[0], cuts.CASES[2]):
            for change in (None, {"acceptedInFlight": 0}, {"retirementStarted": True},
                           {"acceptedInFlight": True}, {"state": "armed"}, {"query": {}},
                           {"observation": None}, {"missing": True}):
                with self.subTest(stage=stage, change=change):
                    arm = FULL["arm_for"]("first-child-published")
                    worker = FULL["uid"]()
                    checkpoint = checkpoint_for(arm, V1["observed"](arm), stage, worker)
                    held = dict(query=cuts.storage_query(arm, worker), state="observed", observation=copy.deepcopy(checkpoint),
                        retirementStarted=False, acceptedInFlight=1, lateAdmissionRejected=False, receiptReplayCount=0)
                    if change and "missing" not in change:
                        held.update(change)
                    order = []
                    def wait(suffix):
                        order.append(("wait", suffix))
                        if change == {"missing": True}: raise FileNotFoundError(suffix)
                        return held
                    def validate(*args, **kwargs):
                        cuts.storage_status(*args, **kwargs)
                        order.append("validated")
                    def restart(*args, **kwargs):
                        order.append("restart")
                        return [], {}, None
                    from types import SimpleNamespace
                    source_witness = source_witness_for(arm, checkpoint) if stage == cuts.CASES[2] else None
                    def validate_source(*args):
                        cuts.cleaning_source_observation(*args)
                        order.append("source-validated")
                    def artifact(suffix, *args):
                        order.append(("artifact", suffix))
                        return copy.deepcopy(source_witness if suffix == ".checkpoint.json" else checkpoint)
                    proof = SimpleNamespace(storage_status=validate, cleaning_source_observation=validate_source)
                    restart_mock = Mock(side_effect=restart)
                    env = dict(active_ack=None, vm_storage=True, vm_proof=proof, arm=arm, worker=worker, checkpoint=checkpoint,
                        source_witness=source_witness, wait_artifact=wait, artifact=artifact,
                        record=lambda phase, **kwargs: order.append(phase), daemon=None, process=None, before=[],
                        interrupted=None, ledger=None, evidence_files={}, processes=None, remaining=None,
                        start=None, read_state=None, metadata={"storageInitramfsSHA256": "a" * 64})
                    with patch.object(recovery, "restart_storage_at_vm_cut", restart_mock):
                        code = compile(ast.Module(body=branch.body, type_ignores=[]), "active-hold-parent", "exec")
                        if change:
                            with self.assertRaises((ValueError, FileNotFoundError)): exec(code, env)
                            restart_mock.assert_not_called()
                            self.assertNotIn("storage-held-external-fsync", order)
                        else:
                            exec(code, env)
                            restart_mock.assert_called_once()
                            self.assertIs(restart_mock.call_args.kwargs["source_witness"], source_witness)
                            self.assertEqual(order, [("artifact", ".storage-checkpoint.json"),
                                *([("artifact", ".checkpoint.json"), "source-validated"] if source_witness else []),
                                ("wait", ".storage-held.json"), "validated", "storage-held-external-fsync",
                                ("artifact", ".storage-held.json"), "restart"])

    def test_cleaning_captures_and_revalidates_both_artifacts_before_restart(self):
        tree = ast.parse(FIXTURE.read_text())
        capture = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == "vm_storage" and "storage-armed" in ast.unparse(n))
        restart = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == "vm_cut is not None" and "restart_storage_at_vm_cut" in ast.unparse(n))
        artifact = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "artifact")
        fsync = next(n for n in ast.walk(tree) if isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
            and n.value.func.id == "record" and n.value.args
            and isinstance(n.value.args[0], ast.Constant) and n.value.args[0].value == "checkpoint-external-fsync")
        code = compile(ast.Module(body=[artifact, *capture.body, fsync, *restart.body], type_ignores=[]), "cleaning-parent", "exec")
        for fault in (None, "missing-source", "foreign-source", "reread-source-atime", "reread-storage"):
            with self.subTest(fault=fault):
                arm = FULL["arm_for"]("first-child-published")
                worker = FULL["uid"]()
                checkpoint = checkpoint_for(arm, V1["observed"](arm), cuts.CASES[2], worker)
                source = source_witness_for(arm, checkpoint)
                armed = dict(query=cuts.storage_query(arm, worker), state="armed", retirementStarted=False,
                    acceptedInFlight=0, lateAdmissionRejected=False, receiptReplayCount=0)
                held = dict(armed, state="observed", observation=copy.deepcopy(checkpoint), acceptedInFlight=1)
                artifacts = {".storage-armed.json": armed, ".storage-checkpoint.json": checkpoint,
                    ".checkpoint.json": source, ".storage-held.json": held}
                before = copy.deepcopy(artifacts)
                arm_before = copy.deepcopy(arm)
                events, records, reads = [], {}, {}
                def read(name, maximum):
                    suffix = name.removeprefix(arm["requestID"])
                    events.append(("read", suffix))
                    reads[suffix] = reads.get(suffix, 0) + 1
                    value = copy.deepcopy(artifacts[suffix])
                    if suffix == ".checkpoint.json":
                        if fault == "missing-source": raise FileNotFoundError(name)
                        if fault == "foreign-source": value["copyIntent"] = FULL["uid"]()
                        if fault == "reread-source-atime" and reads[suffix] == 2:
                            # Still a valid joint witness, but not the retained pre-fault bytes.
                            value["sourceAtimes"]["a"] += 1
                            cuts.cleaning_source_observation(value, arm, checkpoint, worker)
                    if suffix == ".storage-checkpoint.json" and fault == "reread-storage" and reads[suffix] == 2:
                        value["bound"]["requestSequence"] += 1
                        cuts.cleaning_observation(value, arm, worker)
                    return p.canonical(value), "same-file-stamp"
                def record(phase, **values):
                    events.append(phase); records[phase] = copy.deepcopy(values)
                restart_mock = Mock(side_effect=lambda *a, **kw: events.append("restart") or ([], {}, None))
                env = dict(proof=p, vm_proof=cuts, vm_cut=cuts.CASES[2], vm_storage=True, source_witness=None,
                    active_ack=None, active_ack_probe=None, worker_restart=False, two_volume=False,
                    request=arm["requestID"], seen={}, queue=Mock(read=read), arm=arm, worker=worker,
                    record=record, daemon=None, process=None, before=[], interrupted=None, ledger=None,
                    evidence_files={}, processes=None, remaining=None, start=None, read_state=None,
                    metadata={"storageInitramfsSHA256": "a" * 64})
                env["wait_artifact"] = lambda *args: env["artifact"](*args)
                with patch.object(recovery, "restart_storage_at_vm_cut", restart_mock):
                    if fault:
                        if fault.startswith("reread-"):
                            with self.assertRaisesRegex(ValueError, "immutable carrier artifact changed"):
                                exec(code, env)
                            suffix = ".checkpoint.json" if fault == "reread-source-atime" else ".storage-checkpoint.json"
                            self.assertEqual(reads[suffix], 2)
                            self.assertEqual(events[-1], ("read", suffix))
                            self.assertIn("cleaning-source-witness-external-fsync", records)
                            self.assertIn("checkpoint-external-fsync", records)
                            self.assertNotIn("storage-held-external-fsync", records)
                        else:
                            with self.assertRaises((ValueError, FileNotFoundError)): exec(code, env)
                        restart_mock.assert_not_called()
                    else:
                        exec(code, env)
                        restart_mock.assert_called_once()
                        self.assertEqual(restart_mock.call_args.kwargs["source_witness"], source)
                        self.assertEqual(records["cleaning-source-witness-external-fsync"],
                            dict(physical=source, checkpoint=checkpoint))
                        for phase in ("cleaning-source-witness-external-fsync", "checkpoint-external-fsync", "storage-held-external-fsync"):
                            self.assertLess(events.index(phase), events.index("restart"))
                        self.assertEqual(reads, {suffix: 1 if suffix == ".storage-armed.json" else 2 for suffix in artifacts})
                self.assertEqual(artifacts, before)
                self.assertEqual(arm, arm_before)
                self.assertEqual(env["checkpoint"], checkpoint)
                if "cleaning-source-witness-external-fsync" in records:
                    self.assertEqual(env["source_witness"], source)
                if "held" in env:
                    self.assertEqual(env["held"], held)

    def test_complete_tree_branch_executes_unarmed_readback_only(self):
        tree = ast.parse(FIXTURE.read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == "vm_cut in vm_proof.CASES[1:]")
        text = ast.unparse(ast.Module(body=branch.body, type_ignores=[]))
        for forbidden in ("queue_start", "retry_wait", '"empty"', "full_retry_snapshot"):
            self.assertNotIn(forbidden, text)
        order = []
        current = {"id": "new"}
        env = dict(vm_cut=cuts.CASES[1], vm_proof=cuts, proof=p, source_witness=None,
            start_request=lambda: order.append("start") or "request",
            joined_start=lambda _: order.append("joined"),
            read_state=lambda: ({}, {}, {}), only_intent=lambda *_: current,
            plan={}, container=Mock(id="container"), previous={}, service_recovery={},
            observe=lambda command: order.append(command) or {}, baseline={}, checkpoint={}, arm={},
            record=lambda *_args, **_kw: order.append("record"))
        with patch.object(p, "running_receipts", side_effect=lambda *_: order.append("receipts")), \
             patch.object(recovery, "complete_tree_owner", side_effect=lambda *_: order.append("owner")), \
             patch.object(recovery, "complete_tree_snapshot", side_effect=lambda *_, **_kw: order.append("readback")):
            exec(compile(ast.Module(body=branch.body, type_ignores=[]), "complete-tree-parent", "exec"), env)
        self.assertEqual(order, ["start", "joined", "receipts", "owner", "snapshot", "readback", "record"])
        self.assertEqual(env["retry_seen"], {})
        # Private replay remains exclusively in the other branch, after drain.
        self.assertIn("queue_start(queue, previous, 'normal')", ast.unparse(branch.orelse[0]))
        self.assertIn("full_retry_snapshot", ast.unparse(ast.Module(body=branch.orelse, type_ignores=[])))


class ActualRestartOrdering(unittest.TestCase):
    def test_monitor_is_exclusive_to_vm_cut_and_matches_exact_selected_owners(self):
        from types import SimpleNamespace
        workload, other, third = (A7["harness"].RuntimeProcess(pid) for pid in (10, 11, 12))
        monitor = SimpleNamespace(owners=(workload,))
        cases = [dict(vm_cut=True), dict(owner_exits=monitor),
            dict(active_ack=Mock(processes=(other, third))),
            dict(vm_cut=True, owner_exits=SimpleNamespace(owners=(other,))),
            dict(vm_cut=True, owner_exits=monitor, active_ack=Mock(processes=(other, third))),
            dict(vm_cut=True, owner_exits=SimpleNamespace(owners=(workload, third, other)),
                active_ack=Mock(processes=(other, third)))]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), patch.object(recovery, "signal_storage") as signal, \
                 patch.object(recovery, "read_public") as read, self.assertRaises(ValueError):
                try:
                    recovery.restart_storage_at_a7(None, workload, *([None] * 12), **kwargs)
                finally:
                    signal.assert_not_called(); read.assert_not_called()

    def run_cut(self, stage, mutation=None, fault=None, *, source_fault=None, before_signal=False,
                exit_phase="api-ready", start_exit=None):
        original = recovery.restart_storage_at_a7
        def selected(*args, **kwargs):
            args = list(args)
            arm, witness = args[4], args[5]
            # Current owner is read by the real function. This fixture's storage
            # worker is captured from the mocked read-only owner record.
            # Mock.side_effect is an iterator; tee its first value without loss.
            import itertools
            values = recovery.read_public.side_effect
            first = next(values)
            final = (first[0], "0" * 64) if fault == "changed-owner-at-signal" else first
            recovery.read_public.side_effect = itertools.chain([first, final], values)
            worker = recovery.current_boot(first[0])["ready"]["workerUUID"]
            args[5] = checkpoint_for(arm, witness, stage, worker)
            if mutation: mutation(args[5])
            if stage == cuts.CASES[2]:
                kwargs["source_witness"] = (source_witness_for(arm, args[5]) if source_fault is None else
                    dict(invalid_source_witnesses(arm, args[5]))[source_fault])
            # Exercise the actual VM wrapper as well as the actual restart body.
            with patch.object(recovery, "restart_storage_at_a7", original), \
                 patch.object(recovery, "signal_storage", wraps=recovery.signal_storage) as signal:
                try:
                    return recovery.restart_storage_at_vm_cut(*args, **kwargs)
                finally:
                    if before_signal:
                        signal.assert_not_called()
                        args[0].stop.assert_not_called()
        fixture = A7["RestartTests"]()
        with patch.object(recovery, "restart_storage_at_a7", side_effect=selected):
            return fixture.run_restart(fault, vm_cut=True, exit_phase=exit_phase, start_exit=start_exit)

    def test_three_cuts_share_actual_storage_exit_api_birth_and_drain_order(self):
        for stage in cuts.CASES:
            for phase in ("storage", "api-stop", "api-birth", "api-ready"):
                with self.subTest(stage=stage, phase=phase): self.run_cut(stage, exit_phase=phase)

    def test_joined_api_reparent_refresh_reaches_real_recovery_tail(self):
        for stage in cuts.CASES:
            for phase in ("storage", "api-stop", "api-birth", "api-ready"):
                with self.subTest(stage=stage, phase=phase):
                    self.run_cut(stage, fault="api-reparent", exit_phase=phase)

    def test_eager_vm_containment_may_settle_start_before_api_recovery(self):
        for stage in cuts.CASES:
            for code in (50, 52):
                with self.subTest(stage=stage, code=code):
                    self.run_cut(stage, exit_phase="storage", start_exit=code)

    def test_single_owner_requires_positive_preregistered_exit_early_and_late(self):
        for stage in cuts.CASES:
            for phase in ("storage", "api-ready"):
                for fault in ("missing-workload-event", "wrong-workload-exit", "error-workload-exit"):
                    with self.subTest(stage=stage, phase=phase, fault=fault), self.assertRaises(ValueError):
                        self.run_cut(stage, fault=fault, exit_phase=phase)

    def test_single_owner_prekill_death_refuses_signal_and_live_note_hits_deadline(self):
        for stage in cuts.CASES:
            with self.subTest(stage=stage, fault="prekill"), self.assertRaises(ValueError):
                self.run_cut(stage, fault="prekill-workload-loss", before_signal=True)
            with self.subTest(stage=stage, fault="still-live"), self.assertRaisesRegex(TimeoutError, "mock exit deadline"):
                self.run_cut(stage, fault="workload-still-live")

    def test_single_owner_never_exempts_protected_api_peer_or_storage(self):
        for stage in cuts.CASES:
            for fault in ("early-api-loss", "protected-loss", "protected-replaced", "early-storage-replacement",
                    "bad-api-birth", "wrong-new-storage-identity", "old-storage-returned"):
                with self.subTest(stage=stage, fault=fault), self.assertRaises((ValueError, RuntimeError)):
                    self.run_cut(stage, fault=fault, exit_phase="storage")

    def test_missing_or_invalid_cleaning_source_refuses_before_any_signal(self):
        arm, _, checkpoint = BOUNDARIES["fixture"](cuts.CASES[2])
        for label, _ in invalid_source_witnesses(arm, checkpoint):
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.run_cut(cuts.CASES[2], source_fault=label, before_signal=True)

    def test_unbound_stale_or_foreign_cleaning_storage_refuses_before_signal(self):
        for label, mutate in (
                ("unbound", lambda c: c["bound"]["intent"].update(phase="BOUND")),
                ("stale-worker", lambda c: c.update(workerUUID=FULL["uid"]())),
                ("foreign-filesystem", lambda c: c["bound"]["intent"]["root"].update(backing_uuid="7" * 32))):
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.run_cut(cuts.CASES[2], mutate, before_signal=True)

    def test_duplicate_wrong_scope_and_early_death_rejected(self):
        for stage in cuts.CASES:
            for mutation in (lambda c: c.update(count=2), lambda c: c.update(armDigest="0" * 64)):
                with self.subTest(stage=stage), self.assertRaises(ValueError): self.run_cut(stage, mutation, before_signal=True)
            for fault in ("prekill-workload-loss", "settled-start-before", "missing-storage-event", "missing-drain-operation", "changed-owner-at-signal"):
                with self.subTest(stage=stage, fault=fault), self.assertRaises((ValueError, KeyError)): self.run_cut(stage, fault=fault)


class CompleteTreeReadback(unittest.TestCase):
    def test_fresh_owner_rejects_old_scope_keys_or_attachments(self):
        previous, capture, candidate, context = A7["retry_values"]()
        arm = p.full_arm_candidate(candidate, capture, previous, "normal", service_recovery=context)
        current = {("id" if k == "intent" else k): v for k, v in arm["scope"].items()}
        current.update(phase="running", prepareCompleted=True, slots=copy.deepcopy(arm["slots"]))
        for index, slot in enumerate(current["slots"]): slot["key"] = str(index + 7) * 64
        for slot in previous["slots"]:
            slot.update(volume=arm["mounts"][0]["volume"], mode="read-write")
        self.assertIs(recovery.complete_tree_owner(previous, current, context), current)
        changes = [lambda n: n.update(serviceEpoch=previous["serviceEpoch"]),
            lambda n: n.update(launch=previous["launch"]), lambda n: n.update(prepareCompleted=False),
            lambda n: n["slots"][0].update(key=previous["slots"][0]["key"]),
            lambda n: n["slots"][0].update(attachment=previous["slots"][0]["attachment"])]
        for mutate in changes:
            bad = copy.deepcopy(current); mutate(bad)
            with self.assertRaises(ValueError): recovery.complete_tree_owner(previous, bad, context)

    def test_final_metadata_and_incomplete_tree_fail_closed(self):
        for stage in cuts.CASES[1:]:
            arm = FULL["arm_for"]("first-child-published")
            original = V1["observed"](arm)
            original.update(version=3, profile=p.FULL_PROFILE)
            checkpoint = checkpoint_for(arm, original, stage, FULL["uid"]())
            source = source_witness_for(arm, checkpoint) if stage == cuts.CASES[2] else None
            atimes = (source or checkpoint)["sourceAtimes"]
            baseline = V1["snapshot"]()
            expected = copy.deepcopy(baseline)
            expected["root"]["atimeNS"] = atimes["root"]
            for name in p.FILES:
                expected["files"][name]["atimeNS"] = atimes[name]
                self.assertNotEqual(atimes[name], baseline["files"][name]["atimeNS"])
            retained = copy.deepcopy((expected, baseline, checkpoint, arm, source))
            self.assertIs(recovery.complete_tree_snapshot(expected, baseline, checkpoint, arm, source_witness=source), expected)
            self.assertEqual((expected, baseline, checkpoint, arm, source), retained)
            for name in p.FILES:
                old = copy.deepcopy(expected)
                old["files"][name]["atimeNS"] = baseline["files"][name]["atimeNS"]
                with self.subTest(stage=stage, old_baseline=name), self.assertRaisesRegex(ValueError, "including atime"):
                    recovery.complete_tree_snapshot(old, baseline, checkpoint, arm, source_witness=source)
            mutations = [("namespace-missing", lambda v: v["entries"].remove("z")),
                ("namespace-extra", lambda v: v["entries"].append("transaction")),
                ("file-extra", lambda v: v["files"].update(extra=copy.deepcopy(v["files"]["a"])))]
            for name in ("root", "a", "z"):
                fields = [("uid", 0), ("gid", 0), ("mode", 0o777), ("mtimeNS", 1),
                    ("atimeNS", atimes[name] + 1), ("xattrs", {"user.extra": "value"})]
                if name != "root": fields += [("sha256", "0" * 64), ("size", 0), ("nlink", 2)]
                for key, wrong in fields:
                    def mutate(value, name=name, key=key, wrong=wrong):
                        (value["root"] if name == "root" else value["files"][name])[key] = wrong
                    mutations.append((f"{name}-{key}", mutate))
            for label, mutate in mutations:
                bad = copy.deepcopy(expected); mutate(bad)
                unchanged = copy.deepcopy(bad)
                with self.subTest(stage=stage, mutation=label), self.assertRaises(ValueError):
                    recovery.complete_tree_snapshot(bad, baseline, checkpoint, arm, source_witness=source)
                self.assertEqual(bad, unchanged)
                self.assertEqual((expected, baseline, checkpoint, arm, source), retained)
            if source is not None:
                for label, bad_source in invalid_source_witnesses(arm, checkpoint):
                    with self.subTest(stage=stage, witness=label), self.assertRaises(ValueError):
                        recovery.complete_tree_snapshot(expected, baseline, checkpoint, arm, source_witness=bad_source)
            else:
                with self.assertRaises(ValueError):
                    recovery.complete_tree_snapshot(expected, baseline, checkpoint, arm, source_witness=checkpoint)


if __name__ == "__main__":
    unittest.main()
