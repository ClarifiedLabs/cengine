#!/usr/bin/env python3
"""Engine-free RTM098 A5 proof checks. All process/queue/lifecycle edges doubled."""
import ast
import base64
import copy
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import replace
import errno
import json
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import harness
import managed_prepare_faults as p
import managed_prepare_worker_faults as w
import managed_storage_recovery as r

FULL = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-full.py"))
SERVICE = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-service.py"))
RECOVERY = runpy.run_path(str(ROOT / "tools/tests/test-managed-storage-recovery.py"))
uid = FULL["uid"]


def checkpoint_for_case(arm, worker):
    """One boundary-consistent checkpoint per cut, shaped like the carrier files."""
    case = arm["caseName"]
    if case in p.STORAGE_CASES:
        return FULL["storage"](arm, worker)
    if case in p.EARLY_COUNTERS:
        sent, accepted, written = p.EARLY_COUNTERS[case]
        return dict(version=3, profile=p.FULL_PROFILE, requestID=arm["requestID"], armDigest=p.digest(p.canonical(arm)),
                    stage=case, count=1, targetAttachment=arm["targetAttachment"], requestSequence=1,
                    prepareCommandsSent=sent, prepareCommandsAccepted=accepted, dataBytesWritten=written)
    value = SERVICE["V1"]["observed"](arm)
    value.update(version=3, profile=p.FULL_PROFILE, armDigest=p.digest(p.canonical(arm)))
    return value


def guest_completion(intent):
    return dict(prepare=intent["prepare"], containerInstance=intent["containerInstance"], launch=intent["launch"],
        succeeded=True, cleanCopyUp=True, evidenceDigest="b" * 64)


def values(case="admitted-queued"):
    args = RECOVERY["WorkerReplacementTests"]().fixture()
    before, after, pending, succeeded, request, _, _, _, _, _ = args
    arm = FULL["arm_for"](case)
    arm["scope"].update(store=before["store"], serviceEpoch=before["boot"]["ready"]["serviceEpoch"],
        controllerEpoch=1, controllerKey="f" * 64)
    intent = {("id" if k == "intent" else k): v for k, v in arm["scope"].items()}
    intent.update(phase="prepareAdmitted", prepareCompleted=False, cleanUnmount=False, slots=copy.deepcopy(arm["slots"]))
    for slot in intent["slots"]:
        slot.update(retireOperation=uid(), registerOperation=uid())
        if slot["role"] == "prepare": slot["key"] = arm["credentials"][0]["key"]
    checkpoint = checkpoint_for_case(arm, before["boot"]["ready"]["workerUUID"])
    if case == "drain-durable-reply-lost":
        target = next(s for s in intent["slots"] if s["attachment"] == arm["targetAttachment"])
        checkpoint["drain"]["retireOperation"] = target["retireOperation"]
    prefault = dict(store=before["store"], revision=20, intents={intent["id"]: intent}, operations={}, operationDigests={})
    state = copy.deepcopy(prefault); state.update(revision=30, reconciliationRequired=False)
    failed = state["intents"][intent["id"]]; failed.update(phase="quarantined", quarantineReason="start interrupted")
    for slot in failed["slots"]:
        if slot["role"] != "prepare": continue
        operation = slot["retireOperation"]
        raw = p.canonical(dict(id=0, retire=dict(operation=operation, store=before["store"],
            volume=slot["volume"], attachment=slot["attachment"], launch=intent["launch"])))
        state["operations"][operation] = base64.b64encode(raw).decode()
        state["operationDigests"][operation] = p.digest(raw)
        slot["receipt"] = dict(store=before["store"], volume=slot["volume"], attachment=slot["attachment"],
            prepare=intent["prepare"], launch=intent["launch"], revision=15)
    if case == "drain-durable-reply-lost":
        # Only A8 has successful guest completion before worker death. A6's
        # lost BIND reply interrupts guest PREPARE and remains quarantined.
        # A8's target receipt is the exact pre-death durable replay.
        failed.update(phase="retired", prepareCompleted=True)
        durable = ({k: v for k, v in checkpoint["drain"]["receipt"].items() if k != "schema"}
            if case == "drain-durable-reply-lost" else None)
        for slot in failed["slots"]:
            if durable is not None and slot["attachment"] == arm["targetAttachment"]:
                slot["receipt"] = durable
            else:
                slot["receipt"] = dict(store=before["store"], volume=slot["volume"], attachment=slot["attachment"],
                    launch=intent["launch"], revision=15)
                if slot["role"] == "prepare": slot["receipt"]["prepare"] = intent["prepare"]
    hashes = dict(state_sha256=p.digest(p.canonical(state)))
    after["workerReplacements"][-1]["completed"] = dict(revision=30, digest=hashes["state_sha256"])
    containers = [intent["container"], "e" * 64]
    succeeded["containedContainerIDs"] = sorted(containers)
    args[5:8] = [state, hashes, containers]
    if case in p.CHECKPOINT_EXIT_CASES:
        wait = dict(w.checkpoint_exit_request(arm, checkpoint, before["boot"]), workerPID=42, exitCode=74, reaped=True)
    else:
        wait = dict(w.worker_exit_request(arm, checkpoint, before["boot"]), requestSequence=7, workerPID=42, exitCode=74, reaped=True)
    return args, arm, checkpoint, wait, prefault


@contextmanager
def prepared_fixture(containers):
    """Real temporary files; fake native process only. No engine or native inspection."""
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary).resolve(); root = work / "data"; root.mkdir(mode=0o700)
        binary = work / "cengine"; binary.write_bytes(b"not executable")
        (work / ".cengine-compat-owner").write_text(str(binary))
        parent = root / "containers"; parent.mkdir(mode=0o700)
        for container in containers: (parent / container).mkdir(mode=0o700)
        peer_id = containers[1]; directory = parent / peer_id
        generations = directory / "shim-generations"; generations.mkdir(mode=0o700)
        launch = uid(); generation = generations / ("%020d-%s" % (1, launch)); generation.mkdir(mode=0o700)
        io = directory / "io"; io.mkdir(mode=0o700)
        disk = directory / "root.ext4"; disk.write_bytes(b"mock writable root")
        volume = uid()
        def identity(path):
            info = path.stat(); return dict(device=info.st_dev, inode=info.st_ino, volumeUUID=volume)
        plan = p.names("a" * 32); plan["container"] += "-peer"
        saved = dict(id=peer_id, instanceID=uid(), phase="created", name=plan["container"], labels={p.OWNER: plan["owner"]})
        spec = dict(kind="container", workloadStorageMode="none", containerID=peer_id, shimLaunchUUID=launch, generation=1,
            rootDiskIdentity=identity(disk), rootDiskPath=str(disk), rootDiskReadOnly=False, volumeDisks=[], rootDiskSize=disk.stat().st_size,
            bindShares=[dict(tag="cengine-io", source=str(io), readOnly=False, sourceIdentity=identity(io))])
        common = dict(schemaVersion=2, nonce=launch, createdAt=0, specificationPath=str(generation / "spec.json"), executablePath=str(binary),
            containerDirectoryIdentity=identity(directory), generationsDirectoryIdentity=identity(generations), generationDirectoryIdentity=identity(generation),
            specification=spec, container=saved)
        process = harness.RuntimeProcess(44, executable=str(binary), arguments=(str(binary), "vm-shim", "--spec", str(generation / "spec.json"),
            "--launch-intent", str(generation / "intent.json")), identity=(10, 44, 144), pidversion=44)
        # publishPersistentLaunchRecord omits kernelIdentity for unbound peers.
        record = dict(common, processIdentifier=44, processStartTime=10000044)
        prepared = dict(schemaVersion=3, directoryIdentity=identity(directory), artifacts=dict(directoryIdentity=identity(directory)),
            currentContainer=saved, specification=spec)
        for name, value in (("intent.json", common), ("launch.json", record), ("spec.json", spec)):
            (generation / name).write_bytes(p.canonical(value))
        (directory / "prepared-shim.json").write_bytes(p.canonical(prepared))
        peer = SimpleNamespace(id=peer_id, name=plan["container"], attrs=dict(State=dict(Running=False, Status="created"),
            Config=dict(Labels={p.OWNER: plan["owner"]}), Labels={p.OWNER: plan["owner"]}))
        daemon = SimpleNamespace(root=root, work=work, binary=binary, process=SimpleNamespace(pid=40))
        yield daemon, peer, plan, identity(root), process, prepared, generation


class WorkerProofTests(unittest.TestCase):
    def test_closed_selection_not_full_outcome(self):
        dispatch = Mock(return_value=object())
        run = SERVICE["function"]("run_worker_a5_shard", _run_prepare_case=dispatch)
        kwargs = dict(probe=None, probe_sha256=None, source_sha256=None, expected_commit=None, evidence=None)
        for profile in (None, "", True, p.PROFILE, p.EARLY_PROFILE, p.FULL_PROFILE + " "):
            with self.subTest(profile=profile), self.assertRaises(ValueError): run(None, profile=profile, **kwargs)
        dispatch.assert_not_called()
        self.assertIs(run(None, profile=p.FULL_PROFILE, **kwargs), dispatch.return_value)
        dispatch.assert_called_once_with(None, profile=p.FULL_PROFILE, staged=dict(rtm="RTM-098", boundary="worker-admitted-queued", fullAcceptance=False),
            fault_case="admitted-queued", early=True, full=True, worker_restart=True, **kwargs)
        with self.assertRaises(ValueError): p.aggregate_full([dispatch.call_args.kwargs["staged"]] * 9)

    def test_a4_parent_selection_and_wait_are_bound(self):
        dispatch = Mock(return_value=object())
        run = SERVICE["function"]("run_worker_admission_shard", _run_prepare_case=dispatch)
        kwargs = dict(probe=None, probe_sha256=None, source_sha256=None, expected_commit=None, evidence=None)
        for case in p.HELD_STORAGE_CASES:
            self.assertIs(run(None, profile=p.FULL_PROFILE, fault_case=case, **kwargs), dispatch.return_value)
            self.assertEqual(dispatch.call_args.kwargs["fault_case"], case)
            self.assertFalse(dispatch.call_args.kwargs["staged"]["fullAcceptance"])
            args, arm, checkpoint, waited, _ = values(case)
            self.assertIs(w.worker_wait(waited, arm, checkpoint, args[0]["boot"]), waited)
            wrong = copy.deepcopy(checkpoint)
            wrong["admission"]["admitted"] = not wrong["admission"]["admitted"]
            with self.assertRaises(ValueError): w.worker_exit_request(arm, wrong, args[0]["boot"])
            wrong_wait = {**waited, "stage": next(v for v in p.HELD_STORAGE_CASES if v != case)}
            with self.assertRaises(ValueError): w.worker_wait(wrong_wait, arm, checkpoint, args[0]["boot"])
        # The generic route owns the other seven cuts; the old StorageRelease
        # worker-exit route must reject them.
        for case in set(p.FULL_CASES) - set(p.WORKER_EXIT_CASES):
            with self.assertRaises(ValueError): run(None, profile=p.FULL_PROFILE, fault_case=case, **kwargs)
        with self.assertRaises(ValueError): run(None, profile=p.PROFILE, fault_case=p.WORKER_EXIT_CASES[0], **kwargs)

    def test_checkpoint_parent_selection_and_wait_are_bound(self):
        dispatch = Mock(return_value=object())
        run = SERVICE["function"]("run_checkpoint_exit_shard", _run_prepare_case=dispatch)
        kwargs = dict(probe=None, probe_sha256=None, source_sha256=None, expected_commit=None, evidence=None)
        for case in p.CHECKPOINT_EXIT_CASES:
            self.assertIs(run(None, profile=p.FULL_PROFILE, fault_case=case, **kwargs), dispatch.return_value)
            self.assertEqual(dispatch.call_args.kwargs["fault_case"], case)
            self.assertTrue(dispatch.call_args.kwargs["checkpoint_exit"])
            self.assertFalse(dispatch.call_args.kwargs["staged"]["fullAcceptance"])
            self.assertEqual(dispatch.call_args.kwargs["staged"]["boundary"], "checkpoint-" + case)
        # Held A4/A5 and unknown cuts stay off the generic route.
        for case in (*p.WORKER_EXIT_CASES, "vm-private-bound"):
            with self.assertRaises(ValueError): run(None, profile=p.FULL_PROFILE, fault_case=case, **kwargs)
        with self.assertRaises(ValueError): run(None, profile=p.PROFILE, fault_case=p.CHECKPOINT_EXIT_CASES[0], **kwargs)
        # The old StorageRelease route rejects the moved A6/A8 cuts.
        old = SERVICE["function"]("run_worker_admission_shard", _run_prepare_case=dispatch)
        for case in p.CHECKPOINT_CUT_CASES:
            with self.assertRaises(ValueError): old(None, profile=p.FULL_PROFILE, fault_case=case, **kwargs)
        # Each checkpoint cut binds its one carrier through the strict wait.
        for case in p.CHECKPOINT_EXIT_CASES:
            args, arm, checkpoint, waited, _ = values(case)
            self.assertIs(w.checkpoint_wait(waited, arm, checkpoint, args[0]["boot"]), waited)
            request = w.checkpoint_exit_request(arm, checkpoint, args[0]["boot"])
            carrier = p.checkpoint_carrier(case)
            self.assertEqual(set(request), {"arm", carrier, "workerUUID"})

    def test_wait_exact_fields_and_integer_bounds(self):
        args, arm, checkpoint, waited, _ = values()
        boot = args[0]["boot"]
        self.assertIs(w.worker_wait(waited, arm, checkpoint, boot), waited)
        mutations = [lambda n, k=k: n.pop(k) for k in waited]
        mutations += [lambda n: n.update(extra=True), lambda n: n.update(reaped=False), lambda n: n.update(reaped=1),
            lambda n: n.update(exitCode=0), lambda n: n.update(exitCode=True), lambda n: n.update(stage="full-frame-before-admit"),
            lambda n: n.update(token="f" * 64)]
        for key, bads in (("workerPID", (True, 0, 1, 2**31, "42")), ("requestSequence", (True, 0, 8, 2**64, "7"))):
            mutations += [lambda n, k=key, v=v: n.update({k: v}) for v in bads]
        for key in waited["query"]:
            mutations.append(lambda n, k=key: n["query"].update({k: True}))
        for mutate in mutations:
            bad = copy.deepcopy(waited); mutate(bad)
            with self.subTest(bad=bad), self.assertRaises((ValueError, KeyError)): w.worker_wait(bad, arm, checkpoint, boot)
        for pid in (2, 2**31 - 1): w.worker_wait({**waited, "workerPID": pid}, arm, checkpoint, boot)
        for key in ("workerUUID", "storeUUID", "serviceEpoch", "controllerEpoch", "controllerKey"):
            bad = copy.deepcopy(boot); bad["ready"][key] = 2 if key == "controllerEpoch" else uid()
            with self.subTest(boot=key), self.assertRaises(ValueError): w.worker_wait(waited, arm, checkpoint, bad)
        bad = copy.deepcopy(checkpoint); bad["admission"]["admitted"] = False
        with self.assertRaises(ValueError): w.worker_wait(waited, arm, bad, boot)
        for case in p.STORAGE_CASES:
            if case == "admitted-queued": continue
            bad = copy.deepcopy(arm); bad["caseName"] = case
            with self.assertRaises(ValueError): w.worker_exit_request(bad, checkpoint, boot)
        # The moved A6/A8 storage cuts are rejected by the old StorageRelease
        # route and accepted by the generic checkpoint route.
        for case in p.CHECKPOINT_CUT_CASES:
            args6, arm6, checkpoint6, waited6, _ = values(case)
            with self.assertRaises(ValueError): w.worker_exit_request(arm6, checkpoint6, args6[0]["boot"])
            self.assertIs(w.checkpoint_wait(waited6, arm6, checkpoint6, args6[0]["boot"]), waited6)

    def test_checkpoint_wait_exact_fields_and_carrier_exclusivity(self):
        for case in p.CHECKPOINT_EXIT_CASES:
            args, arm, checkpoint, waited, _ = values(case)
            boot = args[0]["boot"]
            carrier = p.checkpoint_carrier(case)
            mutations = [lambda n, k=k: n.pop(k) for k in waited]
            mutations += [lambda n: n.update(extra=True), lambda n: n.update(reaped=False), lambda n: n.update(reaped=1),
                lambda n: n.update(exitCode=0), lambda n: n.update(exitCode=True)]
            other = next(c for c in ("checkpoint", "earlyCheckpoint", "storageCheckpoint") if c != carrier)
            mutations.append(lambda n, c=carrier, o=other: n.update({o: n.pop(c)}))
            mutations += [lambda n, v=v: n.update({"workerPID": v}) for v in (True, 0, 1, 2**31, "42")]
            for key in ("arm", "workerUUID", carrier):
                mutations.append(lambda n, k=key: n.update({k: True}))
            for mutate in mutations:
                bad = copy.deepcopy(waited); mutate(bad)
                with self.subTest(case=case, bad=bad), self.assertRaises((ValueError, KeyError)):
                    w.checkpoint_wait(bad, arm, checkpoint, boot)
            for pid in (2, 2**31 - 1):
                w.checkpoint_wait({**waited, "workerPID": pid}, arm, checkpoint, boot)
            # The checkpoint is bound to this cut's carrier; another cut rejects it.
            for other_case in ("normal", "data-partial-frame", "transaction-published-bind-reply-lost"):
                if other_case == case: continue
                wrong_arm = copy.deepcopy(arm); wrong_arm["caseName"] = other_case
                with self.subTest(case=case, wrong=other_case), self.assertRaises(ValueError):
                    w.checkpoint_exit_request(wrong_arm, checkpoint, boot)

    def test_worker_context_not_service_or_controller_takeover(self):
        previous, _, _, capture, candidate = SERVICE["V1"]["values"]()
        candidate.update(version=3, profile=p.FULL_PROFILE)
        context = {k: previous[k] for k in ("store", "serviceEpoch", "controllerEpoch", "controllerKey")}
        context["serviceEpoch"] = uid(); candidate["scope"].update(context)
        original = copy.deepcopy((previous, capture, candidate, context))
        p.full_arm_candidate(candidate, capture, previous, "normal", worker_recovery=context)
        self.assertEqual((previous, capture, candidate, context), original)
        for kind in ("service_recovery", "controller_recovery"):
            with self.assertRaises(ValueError): p.full_arm_candidate(candidate, capture, previous, "normal", **{kind: context})
            with self.assertRaisesRegex(ValueError, "one recovery context"):
                p.full_arm_candidate(candidate, capture, previous, "normal", worker_recovery=context, **{kind: context})
        for key, value in (("controllerEpoch", True), ("controllerEpoch", previous["controllerEpoch"] + 1),
            ("controllerKey", "a" * 64), ("store", uid()), ("serviceEpoch", previous["serviceEpoch"]), ("serviceEpoch", True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                p.full_arm_candidate(candidate, capture, previous, "normal", worker_recovery={**context, key: value})
        for case in p.FULL_CASES[1:]:
            with self.assertRaises(ValueError): p.full_arm_candidate(candidate, capture, previous, case, worker_recovery=context)

    def test_replacement_uses_real_history_and_preserves_two_consumer_default(self):
        for case in p.HELD_STORAGE_CASES:
            args, arm, _, _, _ = values(case)
            self.assertNotEqual(r.replacement_proof(*args, prepare_recovery=arm)["serviceEpoch"], arm["scope"]["serviceEpoch"])
        args, arm, _, _, _ = values()
        # Every worker-route cut (held A4/A5 StorageRelease plus the seven
        # checkpoint cuts) binds the same two-owned-container census; the old
        # route's moved A6/A8 cuts are covered here through the generic route.
        for case in p.WORKER_EXIT_CASES + p.CHECKPOINT_EXIT_CASES:
            args_c, arm_c, _, _, _ = values(case)
            with self.subTest(case=case):
                r.replacement_proof(*args_c, prepare_recovery=arm_c)
        for case in ("vm-private-bound", "not-a-cut"):
            bad_arm = copy.deepcopy(arm); bad_arm["caseName"] = case
            with self.subTest(case=case), self.assertRaises((ValueError, KeyError)):
                r.replacement_proof(*args, prepare_recovery=bad_arm)
        r.replacement_proof(*args)  # Existing RTM084 still requires exactly two.
        one = copy.deepcopy(args); one[7] = one[7][:1]; one[3]["containedContainerIDs"] = one[7]
        with self.assertRaisesRegex(ValueError, "two contained IDs"): r.replacement_proof(*one)
        with self.assertRaisesRegex(ValueError, "two-owned-container"): r.replacement_proof(*one, prepare_recovery=arm)
        for mutate in (lambda a: a[3].update(containedContainerIDs=[]), lambda a: a[1]["workerReplacements"][-1].pop("localAdoption"),
            lambda a: a[3]["ownerRequest"].update(operationUUID=uid()), lambda a: a[2].update(phase="succeeded"),
            lambda a: a[6].update(state_sha256="0" * 64), lambda a: a[1]["workerReplacements"][-1]["successor"]["ready"].update(controllerEpoch=2)):
            bad = copy.deepcopy(args); mutate(bad)
            with self.assertRaises((ValueError, KeyError)): r.replacement_proof(*bad, prepare_recovery=arm)

    def test_no_prefault_receipt_and_fresh_authority_drain(self):
        args, arm, _, _, before = values(); after = args[5]; boot = args[1]["workerReplacements"][-1]["successor"]
        proof = w.recovered_worker_drain(before, after, arm, boot)
        self.assertGreater(proof["drains"][0]["receipt"]["revision"], proof["bootRevision"])
        op = proof["drains"][0]["operation"]
        for key in ("operations", "operationDigests"):
            bad = copy.deepcopy(before); bad[key][op] = after[key][op]
            with self.assertRaises(ValueError): w.recovered_worker_drain(bad, after, arm, boot)
        for revision in (True, 0, proof["bootRevision"]):
            bad = copy.deepcopy(after)
            next(s for s in bad["intents"][arm["scope"]["intent"]]["slots"] if s["role"] == "prepare")["receipt"]["revision"] = revision
            with self.assertRaises(ValueError): w.recovered_worker_drain(before, bad, arm, boot)
        bad = copy.deepcopy(after); bad["operationDigests"][op] = "f" * 64
        with self.assertRaises(ValueError): w.recovered_worker_drain(before, bad, arm, boot)

    def test_checkpoint_prefault_drain_requires_exact_planned_replay(self):
        _, arm, checkpoint, _, before = values("drain-durable-reply-lost")
        intent = before["intents"][arm["scope"]["intent"]]
        target = next(s for s in intent["slots"] if s["attachment"] == arm["targetAttachment"])
        operation = target["retireOperation"]
        durable = {k: v for k, v in checkpoint["drain"]["receipt"].items() if k != "schema"}
        self.assertEqual(checkpoint["drain"]["retireOperation"], operation)
        raw = p.canonical(dict(id=0, retire=dict(operation=operation, store=intent["store"],
            volume=target["volume"], attachment=target["attachment"], launch=intent["launch"])))
        before["operations"][operation] = base64.b64encode(raw).decode()
        before["operationDigests"][operation] = p.digest(raw)
        intent.update(phase="runtimeFrozen", prepareCompleted=True, guestCompletion=guest_completion(intent))
        for receipt in (None, durable):
            target["receipt"] = receipt
            w.undrained_prepare(before, intent, arm, interrupted=True, checkpoint=checkpoint)
        with self.assertRaises(ValueError):
            w.undrained_prepare(before, intent, arm)
        bad_checkpoint = copy.deepcopy(checkpoint)
        bad_checkpoint["drain"]["retireOperation"] = uid()
        with self.assertRaises(ValueError):
            w.undrained_prepare(before, intent, arm, interrupted=True, checkpoint=bad_checkpoint)
        target["receipt"] = {**durable, "revision": durable["revision"] + 1}
        with self.assertRaises(ValueError):
            w.undrained_prepare(before, intent, arm, interrupted=True, checkpoint=checkpoint)
        target["receipt"] = durable
        for field in ("operation", "store", "volume", "attachment", "launch"):
            wrong = p.decode(raw)
            wrong["retire"][field] = uid()
            bad_raw = p.canonical(wrong)
            before["operations"][operation] = base64.b64encode(bad_raw).decode()
            before["operationDigests"][operation] = p.digest(bad_raw)
            with self.subTest(field=field), self.assertRaises(ValueError):
                w.undrained_prepare(before, intent, arm, interrupted=True, checkpoint=checkpoint)
        before["operations"][operation] = base64.b64encode(raw).decode()
        before["operationDigests"][operation] = "0" * 64
        with self.assertRaises(ValueError):
            w.undrained_prepare(before, intent, arm, interrupted=True, checkpoint=checkpoint)
        before["operationDigests"].pop(operation)
        with self.assertRaises(ValueError):
            w.undrained_prepare(before, intent, arm, interrupted=True, checkpoint=checkpoint)

    def test_checkpoint_prefault_phase_completion_is_cut_bound(self):
        for case in p.CHECKPOINT_EXIT_CASES:
            _, arm, checkpoint, _, before = values(case)
            intent = before["intents"][arm["scope"]["intent"]]
            for phase, completed in (("prepareAdmitted", True), ("prepareAdmitted", 0),
                ("runtimeFrozen", False), ("prepareDrained", True)):
                intent.update(phase=phase, prepareCompleted=completed)
                with self.subTest(case=case, phase=phase, completed=completed), self.assertRaises(ValueError):
                    w.undrained_prepare(before, intent, arm, interrupted=True, checkpoint=checkpoint)
            if case != "drain-durable-reply-lost":
                intent.update(phase="runtimeFrozen", prepareCompleted=True)
                with self.subTest(case=case), self.assertRaises(ValueError):
                    w.undrained_prepare(before, intent, arm, interrupted=True, checkpoint=checkpoint)

    def test_natural_cut_replays_only_previously_journaled_retire(self):
        for case in ("before-prepare-send", "data-partial-frame"):
            args, arm, checkpoint, _, before = values(case)
            after, boot = args[5], args[1]["workerReplacements"][-1]["successor"]
            intent = before["intents"][arm["scope"]["intent"]]
            slot = next(s for s in intent["slots"] if s["role"] == "prepare")
            final_slot = next(s for s in after["intents"][intent["id"]]["slots"] if s["role"] == "prepare")
            final_slot["receipt"]["revision"] = boot["ready"]["revision"]
            with self.assertRaises(ValueError):
                w.recovered_worker_drain(before, after, arm, boot, worker_interrupted=True)
            op = slot["retireOperation"]
            for key in ("operations", "operationDigests"): before[key][op] = after[key][op]
            for receipt in (None, copy.deepcopy(final_slot["receipt"])):
                slot["receipt"] = receipt
                proof = w.recovered_worker_drain(before, after, arm, boot, worker_interrupted=True)
                self.assertTrue(proof["drains"][0]["replay"])
            final_slot["receipt"]["revision"] += 1
            with self.assertRaises(ValueError):
                w.recovered_worker_drain(before, after, arm, boot, worker_interrupted=True)

    def test_live_checkpoint_refresh_keeps_plan_and_installed_evidence(self):
        _, arm, checkpoint, _, before = values("drain-durable-reply-lost")
        previous = copy.deepcopy(before["intents"][arm["scope"]["intent"]])
        current = before["intents"][previous["id"]]
        current.update(phase="runtimeFrozen", prepareCompleted=True, cleanUnmount=True, version=2,
            guestCompletion=guest_completion(current))
        runtime = next(s for s in current["slots"] if s["role"] == "runtime")
        runtime["key"] = "a" * 64
        self.assertIs(w.checkpoint_prefault_intent(before, previous, arm, checkpoint), current)
        for mutation in (lambda i: i.update(reserveOperation=uid()),
            lambda i: i["slots"][0].update(retireOperation=uid())):
            bad = copy.deepcopy(before); mutation(bad["intents"][previous["id"]])
            with self.assertRaises(ValueError): w.checkpoint_prefault_intent(bad, previous, arm, checkpoint)
        installed = copy.deepcopy(current)
        runtime["key"] = "b" * 64
        with self.assertRaises(ValueError): w.checkpoint_prefault_intent(before, installed, arm, checkpoint)
        runtime["key"] = "a" * 64
        current["cleanUnmount"] = False
        with self.assertRaises(ValueError): w.checkpoint_prefault_intent(before, installed, arm, checkpoint)

    def test_prefault_completion_and_recovered_receipts_are_identity_bound(self):
        args, arm, checkpoint, _, before = values("before-prepare-send")
        intent = before["intents"][arm["scope"]["intent"]]
        intent["guestCompletion"] = guest_completion(intent)
        with self.assertRaises(ValueError):
            w.checkpoint_prefault_intent(before, intent, arm, checkpoint)
        intent.pop("guestCompletion")
        boot = args[1]["workerReplacements"][-1]["successor"]
        for key in ("store", "volume", "attachment", "prepare", "launch"):
            after = copy.deepcopy(args[5])
            slot = next(s for s in after["intents"][intent["id"]]["slots"] if s["role"] == "prepare")
            slot["receipt"][key] = uid()
            with self.subTest(receipt=key), self.assertRaises(ValueError):
                w.recovered_worker_drain(before, after, arm, boot, worker_interrupted=True)
        _, arm, checkpoint, _, before = values("drain-durable-reply-lost")
        intent = before["intents"][arm["scope"]["intent"]]
        previous = copy.deepcopy(intent)
        intent.update(phase="runtimeFrozen", prepareCompleted=True, cleanUnmount=True)
        with self.assertRaises(ValueError): w.checkpoint_prefault_intent(before, previous, arm, checkpoint)
        for key, value in (("prepare", uid()), ("containerInstance", uid()), ("launch", uid()),
            ("succeeded", 1), ("cleanCopyUp", False), ("evidenceDigest", "bad")):
            intent["guestCompletion"] = {**guest_completion(intent), key: value}
            with self.subTest(completion=key), self.assertRaises(ValueError):
                w.checkpoint_prefault_intent(before, previous, arm, checkpoint)

    def test_start_fixed_gated_conflict_and_old_context_unchanged(self):
        for worker, early, case, expected in ((True, True, "admitted-queued", 49), (False, True, "admitted-queued", 50),
            (False, True, "data-partial-frame", 49)):
            join = SERVICE["function"]("joined_start", worker_restart=worker, early=early, fault_case=case,
                io_case=None, signal=__import__("signal"), record=Mock(), remaining=lambda: 1)
            for code in (0, 49, 50, 51, 52, -9):
                process = Mock(); process.wait.return_value = code
                if code == expected: join(process, failed=True, worker_failed=worker)
                else:
                    with self.assertRaises(ValueError): join(process, failed=True, worker_failed=worker)


class LifecycleTests(unittest.TestCase):
    def campaign(self, fault=None, natural=False, peer_natural=False, active=False, checkpoint_case=None, values_override=None):
        # checkpoint_case selects a generic-route cut; the default stays on the
        # held A5 StorageRelease worker-exit route.
        args, arm, checkpoint, waited, prefault = (values_override() if values_override is not None
            else values(checkpoint_case or "admitted-queued"))
        exit_suffix = ".checkpoint-worker-exit" if checkpoint_case else ".storage-worker-exit"
        wait_suffix = ".checkpoint-worker-wait.json" if checkpoint_case else ".storage-worker-wait.json"
        exit_request = ({k: waited[k] for k in waited if k not in ("workerPID", "exitCode", "reaped")}
            if checkpoint_case else {k: waited[k] for k in ("query", "stage", "token")})
        before, after, pending, succeeded, replacement, state, hashes, containers, _, _ = args
        if active:
            containers += ["1" * 64, "2" * 64]
            succeeded["containedContainerIDs"] = sorted(containers)
        if checkpoint_case == "drain-durable-reply-lost":
            prefault_intent = prefault["intents"][arm["scope"]["intent"]]
            target = next(s for s in prefault_intent["slots"] if s["attachment"] == arm["targetAttachment"])
            target["receipt"] = {k: v for k, v in checkpoint["drain"]["receipt"].items() if k != "schema"}
            operation = target["retireOperation"]
            for key in ("operations", "operationDigests"):
                prefault[key][operation] = state[key][operation]
            prefault_intent.update(phase="runtimeFrozen", prepareCompleted=True, guestCompletion=guest_completion(prefault_intent))
        events = []; phase = ["held"]; exits = []
        with ExitStack() as stack:
            daemon, peer, plan, root_identity, peer_process, prepared, generation = stack.enter_context(prepared_fixture(containers))
            if values_override is not None: daemon.storage_initramfs = daemon.root / "mock-initramfs"
            api, storage, workload, unrelated = [harness.RuntimeProcess(pid, identity=(10, pid, pid + 100), pidversion=pid) for pid in (40, 41, 43, 45)]
            primary = daemon.root / "containers" / containers[0] / "shim-generations" / ("%020d-%s" % (2, arm["scope"]["launch"]))
            workload = replace(workload, executable=str(daemon.binary), arguments=(str(daemon.binary), "vm-shim", "--spec", str(primary / "spec.json"), "--launch-intent", str(primary / "intent.json")))
            ack_processes = []
            if active:
                for pid, container in zip((46, 47), containers[2:]):
                    path = daemon.root / "containers" / container / "shim-generations" / "ack" / "spec.json"
                    ack_processes.append(replace(workload, pid=pid, identity=(10, pid, pid + 100), pidversion=pid,
                        arguments=(str(daemon.binary), "vm-shim", "--spec", str(path), "--launch-intent", str(path.parent / "intent.json"))))
            census = [api, storage, workload, peer_process, unrelated, *ack_processes]
            if fault == "peer-missing": census.remove(peer_process)
            if fault == "extra-generation": census.append(replace(peer_process, pid=46, identity=(20, 46, 146), pidversion=46))
            if fault == "extra-directory": (daemon.root / "containers" / ("f" * 64)).mkdir(mode=0o700)
            if fault == "missing-directory": (daemon.root / "containers" / containers[0]).rmdir()
            def inspect(pid):
                if pid == peer_process.pid and (fault == "peer-native-unknown" or fault == "peer-exit-unknown" and phase[0] == "replaced"):
                    raise OSError(errno.EPERM, "unknown, not ESRCH")
                if pid == peer_process.pid and fault == "peer-native-absent-before" and phase[0] == "held": return None
                if pid == peer_process.pid and fault == "peer-reused-before": return replace(peer_process, identity=(20, 55, 244), pidversion=55)
                if pid in (workload.pid, peer_process.pid, *(v.pid for v in ack_processes)) and (phase[0] == "replaced" or
                    phase[0] == "waited" and (natural and pid == workload.pid or peer_natural and pid == peer_process.pid)):
                    if pid == peer_process.pid and fault == "peer-still-live": return peer_process
                    if pid == peer_process.pid and fault == "peer-ambiguous-exit": return replace(peer_process, pidversion=55)
                    if pid == peer_process.pid and fault == "peer-reused-after": return replace(peer_process, identity=(20, 55, 244), pidversion=55)
                    return None
                if phase[0] == "waited" and ((fault == "api-death" and pid == api.pid) or (fault == "storage-death" and pid == storage.pid)
                    or (fault == "unrelated-death" and pid == unrelated.pid)): return None
                return next((v for v in census if v.pid == pid), None)
            def processes(): return [observed for v in census if (observed := inspect(v.pid)) is not None]
            def record(name, **proof):
                events.append(name)
                if name in ("worker-exit-intent", "checkpoint-exit-intent"):
                    self.assertEqual(proof["ownedContainerIDs"], sorted(containers))
                    self.assertEqual(proof["peer"]["pid"], peer_process.pid)
                    self.assertEqual(proof["prepareReceiptsAbsent"], checkpoint_case != "drain-durable-reply-lost")
                    self.assertEqual(proof["retireOperationsAbsent"], checkpoint_case != "drain-durable-reply-lost")
                if name == "worker-replacement-drained": self.assertEqual({v["pid"] for v in proof["containedNative"]}, {workload.pid, peer_process.pid, *(v.pid for v in ack_processes)})
            def publish(name, value): events.append("publish-exit"); self.assertEqual(value, exit_request)
            def artifact(suffix, maximum=65536):
                if suffix == exit_suffix + ".claimed.json": return exit_request
                if suffix == wait_suffix:
                    phase[0] = "waited"; result = copy.deepcopy(waited)
                    if fault == "unreaped": result["reaped"] = False
                    return result
                return checkpoint
            def publish_replacement(queue, raw): events.append("publish-replacement"); phase[0] = "replaced"; return (3, 4)
            raw = r.worker_request(replacement["operationUUID"], replacement["store"], replacement["predecessor"])[1]
            wrong_ids = {"missing-receipt-id": containers[:1], "extra-receipt-id": sorted([*containers, "f" * 64]),
                "wrong-receipt-id": sorted([containers[0], "f" * 64]), "duplicate-receipt-id": [containers[0]] * 2}
            if fault in wrong_ids: succeeded["containedContainerIDs"] = wrong_ids[fault]
            def queue_file(queue, name, maximum=1048576):
                if name.endswith(".failed.json"):
                    if fault == "replacement-failed": return b"failure", ()
                    raise FileNotFoundError(name)
                value = raw if name.endswith(".request.json") else p.canonical(pending if name.endswith(".pending.json") else succeeded)
                return value, (3, 4, 5, 6, p.digest(value))
            def read_state(): return {}, state if phase[0] == "replaced" else prefault, hashes if phase[0] == "replaced" else {"state_sha256": "a" * 64}
            def read_public(path, *_):
                value, stamp = (after, "new") if phase[0] == "replaced" else (before, "old")
                if values_override is not None:
                    return (value["manifest"], "manifest") if path.name == "manifest.json" else (value["checkpoint"], stamp)
                return value, stamp
            def wait_exit(proc):
                exits.append(proc)
                p.require(r.exact_exit(proc, inspect(proc.pid)), "mock exit waiter cannot fabricate containment")
            queue = Mock(); queue.publish.side_effect = publish
            start = Mock(); start.poll.return_value = None
            patches = [(harness, "_kernel_process", inspect), (w, "api_target", lambda *_: api), (w, "storage_target", lambda *_: storage),
                (r, "read_public", read_public), (p, "verify_full_ledger", lambda *_: events.append("verify-fsync")),
                (r, "replacement_queue", lambda *_: nullcontext((10, lambda: None))), (r, "publish_worker_request", publish_replacement),
                (r, "queue_file", queue_file), (r, "settled_worker_artifacts", lambda *_: events.append("settled")),
                (w.time, "time", lambda: 100), (w.uuid, "uuid4", lambda: replacement["operationUUID"])]
            for obj, key, value in patches: stack.enter_context(patch.object(obj, key, value))
            peer_owner = stack.enter_context(w.prepared_peer_owner(daemon, peer, plan, root_identity, census))
            context, final, survivors = w.restart_worker_at_a5(daemon, workload, census, prefault["intents"][arm["scope"]["intent"]], arm,
                checkpoint, queue, artifact, artifact, object(), {}, record, processes, lambda: 1, start, read_state,
                wait_exit, lambda: events.append("joined-409"), "a" * 64 if values_override is not None else before["boot"]["initramfsSHA256"], owned_containers=containers, peer_owner=peer_owner,
                active_ack=SimpleNamespace(ids=containers[2:], interrupted=containers[0], processes=ack_processes, validate=lambda *a: None) if active else None,
                checkpoint_exit=checkpoint_case is not None)
            final()
            self.assertEqual(exits, [workload, peer_process, *ack_processes]); self.assertEqual(survivors, (api, storage, unrelated))
        self.assertEqual(context["controllerEpoch"], 1)
        expected = ["verify-fsync", ("checkpoint-exit-intent" if checkpoint_case else "worker-exit-intent"), "verify-fsync", "publish-exit",
            ("checkpoint-PID1-reaped" if checkpoint_case else "worker-PID1-reaped"), "joined-409", "worker-replacement-intent",
            "verify-fsync", "publish-replacement", "settled", "worker-replacement-drained", "settled"]
        self.assertEqual(events, expected)

    def test_checkpoint_route_campaign_mocked_edges(self):
        # Early-carrier cut (A3) and both moved storage-owned cuts (A6/A8),
        # including the A8 exact durable receipt replay oracle.
        for case in ("data-partial-frame", "transaction-published-bind-reply-lost", "drain-durable-reply-lost"):
            with self.subTest(case=case):
                self.campaign(checkpoint_case=case)
        for fault in ("unreaped", "api-death", "storage-death", "missing-receipt-id", "peer-missing", "extra-directory"):
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.campaign(fault, checkpoint_case="data-partial-frame")

    def test_four_owner_actual_action_wait_replacement_mocked_edges(self):
        self.campaign(active=True)
        for fault in ("unreaped", "api-death", "storage-death", "missing-receipt-id", "peer-missing", "extra-directory"):
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.campaign(fault, active=True)

    def test_whole_worker_campaign_mocked_edges(self):
        self.campaign()
        self.campaign(natural=True)
        self.campaign(peer_natural=True)
        self.campaign(natural=True, peer_natural=True)

    def test_missing_actual_wait_dead_api_and_failed_replacement_fail_closed(self):
        for fault in ("unreaped", "api-death", "storage-death", "unrelated-death", "replacement-failed", "peer-missing", "extra-generation",
            "extra-directory", "missing-directory", "peer-native-absent-before", "peer-reused-before", "peer-still-live", "peer-ambiguous-exit", "peer-reused-after",
            "missing-receipt-id", "extra-receipt-id", "wrong-receipt-id", "duplicate-receipt-id"):
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.campaign(fault)
        for fault in ("peer-native-unknown", "peer-exit-unknown"):
            with self.subTest(fault=fault), self.assertRaises(OSError): self.campaign(fault)

    def test_missing_workload_without_positive_exit_is_rejected(self):
        proc = [harness.RuntimeProcess(pid, identity=(10, pid, pid + 100), pidversion=pid) for pid in (40, 41, 43)]
        with self.assertRaisesRegex(ValueError, "positive natural workload exit"):
            w.surviving_hosts(proc, proc[:2], [proc[2]], *proc[:2], lambda pid: next(v for v in proc if v.pid == pid))

    def test_managed_owner_default_rejects_the_unbound_prepared_peer(self):
        with prepared_fixture(["c" * 64, "e" * 64]) as data:
            daemon, peer, plan, root_identity, process, prepared, _ = data
            identity = dict(container=peer.id, launch=prepared["specification"]["shimLaunchUUID"],
                containerInstance=prepared["currentContainer"]["instanceID"])
            with self.assertRaisesRegex(ValueError, "closed schema"):
                with p.workload_owner(process, daemon, plan, identity, root_identity): pass
            with self.assertRaisesRegex(ValueError, "not a fabricated storage intent"):
                with p.workload_owner(process, daemon, plan, identity, root_identity, prepared=prepared): pass

    def test_actual_unbound_record_binds_live_peer_without_persisted_kernel_identity(self):
        with prepared_fixture(["c" * 64, "e" * 64]) as data:
            daemon, peer, plan, root_identity, process, prepared, generation = data
            record = p.decode((generation / "launch.json").read_bytes(), 1048576)
            self.assertNotIn("kernelIdentity", record)
            with patch.object(harness, "_kernel_process", return_value=process) as inspect:
                with w.prepared_peer_owner(daemon, peer, plan, root_identity, [process]) as (actual, proof, validate):
                    self.assertEqual(actual, process)
                    self.assertEqual(proof["birth"], list(process.identity))
                    self.assertEqual(proof["pidversion"], process.pidversion)
                    validate()
            self.assertEqual(inspect.call_args_list, [((process.pid,),), ((process.pid,),)])

    def test_unbound_record_schema_pid_and_start_are_strict_before_fault(self):
        changes = [(key, value) for key, values in (
            ("processIdentifier", (45, True, "44", 44.0)),
            ("processStartTime", (10000045, True, "10000044", 10000044.0)),
            ("kernelIdentity", (None, {}, dict(pid=44, startSeconds=10, startMicroseconds=44, uniqueID=144, bootUUID=uid()))),
            ("unexpected", (True,))) for value in values]
        changes += [("schemaVersion", v) for v in (1, 3, True, "2", 2.0)]
        changes += [(key, None) for key in ("processIdentifier", "processStartTime")]
        for key, value in changes:
            with self.subTest(key=key, value=value), prepared_fixture(["c" * 64, "e" * 64]) as data:
                daemon, peer, plan, root_identity, process, prepared, generation = data
                path = generation / "launch.json"; record = p.decode(path.read_bytes(), 1048576)
                if value is None and key != "kernelIdentity": record.pop(key)
                else: record[key] = value
                # Deliberately malformed public JSON must reach the reader, not
                # be rejected by the test's strict canonical writer first.
                path.write_text(json.dumps(record))
                if key == "schemaVersion":
                    intent_path = generation / "intent.json"; intent = p.decode(intent_path.read_bytes(), 1048576)
                    intent[key] = value; intent_path.write_text(json.dumps(intent))
                with patch.object(harness, "_kernel_process", return_value=process), self.assertRaises(ValueError):
                    with w.prepared_peer_owner(daemon, peer, plan, root_identity, [process]): pass

    def test_unbound_peer_live_revalidation_rejects_reuse_absence_and_uncertainty(self):
        for change in ("pidversion", "birth", "absent", "unknown"):
            with self.subTest(change=change), prepared_fixture(["c" * 64, "e" * 64]) as data:
                daemon, peer, plan, root_identity, process, _, _ = data
                observed = dict(pidversion=replace(process, pidversion=45), birth=replace(process, identity=(11, 44, 145)),
                    absent=None, unknown=OSError(errno.EPERM, "uncertain native inspection"))[change]
                with patch.object(harness, "_kernel_process", side_effect=[process, observed]):
                    with w.prepared_peer_owner(daemon, peer, plan, root_identity, [process]) as (_, _, validate):
                        with self.assertRaises(OSError if change == "unknown" else ValueError): validate()

    def test_prepared_peer_rejects_legacy_and_already_managed_modes(self):
        for mode in ("legacy", "managed"):
            with self.subTest(mode=mode), prepared_fixture(["c" * 64, "e" * 64]) as data:
                daemon, peer, plan, root_identity, process, prepared, generation = data
                prepared["specification"]["workloadStorageMode"] = mode
                (generation / "spec.json").write_bytes(p.canonical(prepared["specification"]))
                for name in ("intent.json", "launch.json"):
                    value = p.decode((generation / name).read_bytes(), 1048576)
                    value["specification"] = prepared["specification"]
                    (generation / name).write_bytes(p.canonical(value))
                (generation.parent.parent / "prepared-shim.json").write_bytes(p.canonical(prepared))
                with patch.object(harness, "_kernel_process", return_value=process), self.assertRaisesRegex(ValueError, "actual owned workload storage mode"):
                    with w.prepared_peer_owner(daemon, peer, plan, root_identity, [process]): pass

    def test_managed_owner_still_requires_full_persisted_kernel_identity(self):
        with prepared_fixture(["c" * 64, "e" * 64]) as data:
            daemon, peer, plan, root_identity, process, prepared, generation = data
            inputs = {name: p.decode((generation / name).read_bytes(), 1048576) for name in ("intent.json", "launch.json", "spec.json")}
            inputs["spec.json"]["workloadStorageMode"] = "managed"
            for name in ("intent.json", "launch.json"): inputs[name]["specification"] = inputs["spec.json"]
            birth = dict(pid=process.pid, startSeconds=process.identity[0], startMicroseconds=process.identity[1], uniqueID=process.identity[2], bootUUID=uid())
            inputs["launch.json"]["kernelIdentity"] = birth
            for name, value in inputs.items(): (generation / name).write_bytes(p.canonical(value))
            intent = dict(container=peer.id, launch=prepared["specification"]["shimLaunchUUID"], containerInstance=prepared["currentContainer"]["instanceID"])
            with p.workload_owner(process, daemon, plan, intent, root_identity): pass
            for value in (None, {}, {**birth, "uniqueID": birth["uniqueID"] + 1}):
                record = copy.deepcopy(inputs["launch.json"])
                if value is None: record.pop("kernelIdentity")
                else: record["kernelIdentity"] = value
                (generation / "launch.json").write_bytes(p.canonical(record))
                with self.subTest(kernelIdentity=value), self.assertRaises(ValueError):
                    with p.workload_owner(process, daemon, plan, intent, root_identity): pass

    def test_prepared_peer_canonical_corruption_fails_before_any_fault(self):
        for corruption in ("container", "instance", "native-birth", "prepared-spec", "phase", "legacy-mode", "prepared-drift"):
            with self.subTest(corruption=corruption), prepared_fixture(["c" * 64, "e" * 64]) as data:
                daemon, peer, plan, root_identity, process, prepared, generation = data
                path = generation / "launch.json"
                launch = p.decode(path.read_bytes(), 1048576)
                if corruption == "container": prepared["currentContainer"]["id"] = "f" * 64
                if corruption == "instance": prepared["currentContainer"]["instanceID"] = uid()
                if corruption == "native-birth": launch["processStartTime"] += 1; path.write_bytes(p.canonical(launch))
                if corruption == "prepared-spec": prepared["specification"]["rootDiskSize"] += 1
                if corruption == "phase": prepared["currentContainer"]["phase"] = "running"
                if corruption == "legacy-mode": prepared["specification"]["workloadStorageMode"] = "managed"
                prepared_path = generation.parent.parent / "prepared-shim.json"
                prepared_path.write_bytes(p.canonical(prepared))
                with patch.object(harness, "_kernel_process", return_value=process), self.assertRaises(ValueError):
                    with w.prepared_peer_owner(daemon, peer, plan, root_identity, [process]) as (_, _, validate):
                        if corruption == "prepared-drift": prepared_path.write_bytes(p.canonical({**prepared, "extra": True})); validate()

    def test_shared_retry_and_cleanup_use_proven_survivors_not_fabricated_original_census(self):
        tree = ast.parse(SERVICE["FIXTURE"].read_text())
        func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run_prepare_case")
        guard = next(n for n in ast.walk(func) if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "worker_restart"
            and "exact post-containment census before retry" in ast.unparse(n))
        cleanup = next(n for n in ast.walk(func) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "cleanup_survivors" for t in n.targets))
        check = next(n for n in ast.walk(func) if isinstance(n, ast.Expr) and "same daemon/storage through cleanup" in ast.unparse(n))
        survivors = [harness.RuntimeProcess(pid, identity=(10, pid, pid + 100), pidversion=pid) for pid in (40, 41, 45)]
        old = harness.RuntimeProcess(43, identity=(10, 43, 143), pidversion=43)
        peer = harness.RuntimeProcess(44, identity=(10, 44, 144), pidversion=44)
        namespace = dict(proof=p, worker_restart=True, worker_survivors=tuple(survivors), before=[*survivors, old, peer], process=old,
            processes=lambda: survivors, unchanged_processes=Mock(side_effect=AssertionError("must not fabricate removal from original census")))
        code = compile(ast.fix_missing_locations(ast.Module(body=[guard, cleanup, check], type_ignores=[])), "shared-worker-census", "exec")
        exec(code, namespace)
        self.assertEqual(namespace["before"], [*survivors, old, peer])
        for extra in (old, peer):
            namespace["processes"] = lambda extra=extra: [*survivors, extra]
            with self.assertRaises(ValueError): exec(code, namespace)

    def test_only_initial_a5_receipt_no_full_outcome(self):
        tree = ast.parse(SERVICE["FIXTURE"].read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If) and isinstance(n.test, ast.Name)
            and n.test.id == "worker_restart" and "worker-cut-result" in ast.unparse(n))
        function = ast.FunctionDef(name="finish", args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
            body=branch.body, decorator_list=[])
        proof = SimpleNamespace(**p.__dict__); proof.verify_full_ledger = Mock()
        namespace = dict(proof=proof, worker_final=Mock(), record=Mock(), staged=dict(rtm="RTM-098", boundary="worker-admitted-queued", fullAcceptance=False),
            profile=p.FULL_PROFILE, uuid=__import__("uuid"), plan=dict(owner="a" * 32), manifest=dict(store=uid()), evidence_chain=[], ledger=object(), evidence_files={})
        exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), "initial-only-result", "exec"), namespace)
        result = namespace["finish"]()
        self.assertEqual(result["result"], "initial-cut-passed"); self.assertIs(result["fullAcceptance"], False)
        self.assertEqual(result["boundary"], "worker-admitted-queued"); self.assertEqual(result["rtm"], "RTM-098")
        namespace["worker_final"].assert_called_once(); proof.verify_full_ledger.assert_called_once()
        with self.assertRaises(ValueError): p.aggregate_full([result] * 9)

    def test_worker_recovery_never_waits_for_dead_storage_finished_and_normal_a8_are_unarmed(self):
        tree = ast.parse(SERVICE["FIXTURE"].read_text())
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run_prepare_case")
        finish = next(n for n in ast.walk(run) if isinstance(n, ast.If) and
            "fault_case not in proof.HELD_STORAGE_CASES" in ast.unparse(n.test))
        condition = compile(ast.Expression(finish.test), "storage-finished-selection", "eval")
        for case in p.CHECKPOINT_CUT_CASES:
            env = dict(full=True, worker=uid(), fault_case=case, proof=p, io_case=None, vm_cut=None, matrix=None)
            self.assertFalse(eval(condition, {**env, "worker_restart": True}))
            self.assertTrue(eval(condition, {**env, "worker_restart": False}))
        branch = next(n for n in ast.walk(run) if isinstance(n, ast.If) and
            any(isinstance(child, ast.Expr) and "worker-complete-tree-readback" in ast.unparse(child) for child in n.body))
        condition = compile(ast.Expression(branch.test), "complete-tree-selection", "eval")
        for case in p.CHECKPOINT_EXIT_CASES:
            for checkpoint_exit in (False, True):
                self.assertEqual(eval(condition, dict(matrix=None, worker_restart=True,
                    checkpoint_exit=checkpoint_exit, fault_case=case)),
                    case == "drain-durable-reply-lost" or (checkpoint_exit and case == "normal"))
        import managed_prepare_storage_vm_faults as vm
        proof = SimpleNamespace(**p.__dict__)
        proof.running_receipts = Mock(); proof.full_observation = Mock(return_value="physical")
        proof.full_retry_snapshot = Mock()
        current = {"id": uid()}; owner = Mock()
        namespace = dict(matrix=None, worker_restart=True, fault_case="drain-durable-reply-lost", matrix_variant=None,
            worker_recovery={"serviceEpoch": uid()}, controller_recovery=None, service_recovery=None,
            previous={}, current=current, joined_start=Mock(), start_request=Mock(return_value="start"),
            read_state=lambda: ({}, {}, {}), only_intent=lambda *_: current, proof=proof,
            plan={}, container=SimpleNamespace(id="c" * 64), checkpoint={}, arm={},
            artifact=Mock(return_value="checkpoint"), observe=Mock(return_value="tree"), baseline="baseline",
            record=Mock(side_effect=lambda name, **event: p.canonical(event)))
        with patch.object(vm, "complete_tree_owner", owner):
            exec(compile(ast.fix_missing_locations(ast.Module(body=branch.body, type_ignores=[])), "complete-tree-body", "exec"), namespace)
        owner.assert_called_once_with({}, current, namespace["worker_recovery"])
        namespace["start_request"].assert_called_once_with()
        namespace["joined_start"].assert_called_once_with("start")
        self.assertEqual(namespace["retry_seen"], {})
        proof.full_retry_snapshot.assert_called_once_with("tree", "baseline", "physical", {})
        namespace["record"].assert_called_once_with("worker-complete-tree-readback", journal={}, firstPublicationRequired=False)
        # Execute the actual NORMAL branch with the original physical checkpoint:
        # no new arm, no synthesized observation, and the exact worker context.
        namespace.update(fault_case="normal", checkpoint_exit=True, checkpoint={"original": "physical"},
            queue_start=Mock(side_effect=AssertionError("complete tree must not be armed")))
        owner.reset_mock(); proof.full_retry_snapshot.reset_mock(); proof.full_observation.reset_mock()
        namespace["artifact"].reset_mock(); namespace["record"].reset_mock()
        namespace["start_request"].reset_mock(); namespace["joined_start"].reset_mock()
        with patch.object(vm, "complete_tree_owner", owner):
            exec(compile(ast.fix_missing_locations(ast.Module(body=[branch], type_ignores=[])), "normal-complete-tree", "exec"), namespace)
        owner.assert_called_once_with({}, current, namespace["worker_recovery"])
        namespace["start_request"].assert_called_once_with()
        namespace["joined_start"].assert_called_once_with("start")
        namespace["queue_start"].assert_not_called()
        namespace["artifact"].assert_not_called(); proof.full_observation.assert_not_called()
        proof.full_retry_snapshot.assert_called_once_with("tree", "baseline", namespace["checkpoint"], {})
        self.assertEqual(namespace["retry_seen"], {})
        self.assertEqual(namespace["successor"], {"scope": {"intent": current["id"]}})
        namespace["record"].assert_called_once_with("worker-complete-tree-readback", journal={}, firstPublicationRequired=False)

        # A7 is still held at first publication and must take the armed replay.
        retry_wait = Mock(return_value="retry-checkpoint")
        namespace.update(fault_case="first-child-published", vm_cut=None, vm_proof=SimpleNamespace(CASES=(None, "vm-cut")),
            queue=object(), queue_start=Mock(return_value=("retry", "fresh-arm", retry_wait, None, {})), full=True)
        proof.full_observation.return_value = "fresh-physical"
        proof.full_retry_snapshot.reset_mock(); namespace["joined_start"].reset_mock()
        exec(compile(ast.fix_missing_locations(ast.Module(body=[branch], type_ignores=[])), "a7-armed-retry", "exec"), namespace)
        namespace["queue_start"].assert_called_once_with(namespace["queue"], {}, "normal")
        proof.full_observation.assert_called_once_with("retry-checkpoint", "fresh-arm")
        proof.full_retry_snapshot.assert_called_once_with("tree", "baseline", "fresh-physical", "fresh-arm")
        namespace["joined_start"].assert_called_once_with("retry")

        namespace.update(worker_restart=False, fault_case="drain-durable-reply-lost", matrix_variant="interrupted", service_recovery={"controllerEpoch": 2})
        namespace["record"].reset_mock()
        with patch.object(vm, "complete_tree_owner", owner):
            exec(compile(ast.fix_missing_locations(ast.Module(body=branch.body, type_ignores=[])), "complete-tree-matrix-body", "exec"), namespace)
        namespace["record"].assert_called_once_with("matrix-complete-tree-readback", journal={},
            firstPublicationRequired=False, variant="interrupted")

    def test_normal_complete_tree_snapshot_keeps_original_physical_metadata(self):
        arm = FULL["arm_for"]("normal")
        checkpoint = checkpoint_for_case(arm, uid())
        baseline = SERVICE["V1"]["snapshot"]()
        recovered = copy.deepcopy(baseline)
        recovered["root"]["atimeNS"] = checkpoint["sourceAtimes"]["root"]
        for name in p.FILES:
            recovered["files"][name]["atimeNS"] = checkpoint["sourceAtimes"][name]
        p.full_retry_snapshot(recovered, baseline, checkpoint, arm)
        # A rollback/recopy cannot silently substitute fresh source timestamps,
        # incomplete contents, or relaxed metadata for the original witness.
        for name in ("root", *p.FILES):
            row = recovered["root"] if name == "root" else recovered["files"][name]
            for key, value in row.items():
                with self.subTest(name=name, key=key):
                    bad = copy.deepcopy(recovered)
                    target = bad["root"] if name == "root" else bad["files"][name]
                    target[key] = value + 1 if type(value) is int else {"unexpected": "xattr"} if type(value) is dict else "0" * 64
                    with self.assertRaises(ValueError):
                        p.full_retry_snapshot(bad, baseline, checkpoint, arm)
        partial = copy.deepcopy(recovered); partial["entries"] = ["a"]
        with self.assertRaises(ValueError):
            p.full_retry_snapshot(partial, baseline, checkpoint, arm)

    def test_worker_branch_has_no_release_signal_or_launcher(self):
        tree = ast.parse(SERVICE["FIXTURE"].read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If) and isinstance(n.test, ast.Name)
            and n.test.id == "worker_restart" and "restart_worker_at_a5" in ast.unparse(n))
        text = ast.unparse(ast.Module(body=branch.body, type_ignores=[]))
        for forbidden in ("SIGKILL", "storage-release", "daemon.start", "daemon.stop", "publish("):
            self.assertNotIn(forbidden, text)
        source = (ROOT / "Tests/Compatibility/managed_prepare_worker_faults.py").read_text()
        for forbidden in ("Popen", "os.kill", "signal_storage", "daemon.start(", "daemon.stop("):
            self.assertNotIn(forbidden, source)
        # The shared prepared-peer validator may inspect a joined API returncode,
        # but the worker route still cannot deliver a signal or launch a process.
        uses = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Compare)
            and "SIGKILL" in ast.unparse(node)]
        self.assertEqual([ast.unparse(node) for node in uses],
            ["daemon.process.returncode == -signal.SIGKILL"])
        self.assertEqual(source.count("SIGKILL"), 1)


if __name__ == "__main__": unittest.main()
