#!/usr/bin/env python3
"""Engine-free worker-only v2 comparisons; no native qualification claim."""
import base64
import copy
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p
import managed_prepare_lifecycle_evidence as shared
import managed_prepare_worker_lifecycle_evidence as e
import managed_prepare_worker_faults as worker

BASE = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-lifecycle-evidence.py"))
WORKER = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-worker.py"))
uid = BASE["uid"]


def fixture(case="admitted-queued"):
    args, arm, checkpoint, waited, prefault = WORKER["values"](case)
    before = BASE["owner"]()
    a = before["checkpoint"]
    old = a["currentContext"]
    mapping = {arm["scope"]["store"]: a["identity"]["store"], arm["scope"]["serviceEpoch"]: old["serviceEpoch"],
        arm["scope"]["controllerKey"]: old["controllerKey"], args[0]["boot"]["ready"]["workerUUID"]: a["observedWorker"]["workerUUID"]}
    def replace(value):
        if isinstance(value, dict): return {k: replace(v) for k, v in value.items()}
        if isinstance(value, list): return [replace(v) for v in value]
        return mapping.get(value, value) if isinstance(value, str) else value
    arm, prefault, state = map(replace, (arm, prefault, args[5]))
    # Rebuild byte-bound operation digests for the actual selected store.
    for operation, encoded in state["operations"].items():
        raw = p.canonical(replace(p.decode(base64.b64decode(encoded), 65536)))
        state["operations"][operation] = base64.b64encode(raw).decode()
        state["operationDigests"][operation] = p.digest(raw)
    checkpoint = WORKER["checkpoint_for_case"](arm, a["observedWorker"]["workerUUID"])
    if case == "drain-durable-reply-lost":
        target = next(s for s in state["intents"][arm["scope"]["intent"]]["slots"] if s["attachment"] == arm["targetAttachment"])
        checkpoint["drain"]["retireOperation"] = target["retireOperation"]
        target["receipt"] = {k: v for k, v in checkpoint["drain"]["receipt"].items() if k != "schema"}
    after = copy.deepcopy(before); b = after["checkpoint"]
    b["revision"] += 10
    current = copy.deepcopy(old); current["serviceEpoch"] = uid()
    b["currentContext"] = current
    b["observedWorker"] = dict(context=current, workerUUID=uid())
    new = b["currentService"]
    new["context"]["service_epoch"] = new["boot"]["service_epoch"] = current["serviceEpoch"]
    new["boot"].update(tls_root_sha256="7" * 64, server_spki="8" * 64)
    new["open_revision"] = 14
    request, _ = e.recovery.worker_request(uid(), a["identity"]["store"], dict(serviceEpoch=old["serviceEpoch"], workerUUID=a["observedWorker"]["workerUUID"]))
    change = dict(operation_id=request["operationUUID"], predecessor=a["currentService"])
    retry = dict(request=change, stageRequestID=uid(), completionRequestID=uid(), predecessorWorkerUUID=request["predecessor"]["workerUUID"], nowUnixSeconds=100, lifetimeSeconds=300)
    b.update(latestServiceRequest=retry, latestServiceConfirmation=dict(request=change, successor=new),
        latestServiceChange=dict(operationID=request["operationUUID"], predecessor=old, successor=current, revision=14), nativeReplacementAttempted=True,
        serviceReplacement=dict(predecessor_worker_uuid=retry["predecessorWorkerUUID"], configuration=dict(action="open", root_public_key=b["rootPublicKey"],
            signed=b["current"]["original"]["signed"], now_unix_seconds=100, lifetime_seconds=300,
            reopen=dict(request=change, signature=BASE["encoded"](b"x" * 64)))))
    b["serviceLinks"] = [b["latestServiceChange"]]
    b["contexts"].append(dict(context=current, controller=b["current"], serviceResult=b["latestServiceChange"]))
    b["intentRevision"] = state["revision"]
    for intent in state["intents"].values():
        intent["version"] = 1
        b["references"].append(dict(id=intent["id"], version=1, original=old, superseded=[]))
    proof = dict(controllerEpoch=old["controllerEpoch"], controllerKey=old["controllerKey"], rootPublicKey=a["rootPublicKey"])
    pending = dict(schema=1, counter=1, phase="pending", request=request, proof=proof)
    containers = args[7]
    succeeded = dict(pending, phase="succeeded", ownerRequest=dict(operationUUID=request["operationUUID"], predecessor=request["predecessor"], nowUnixSeconds=100),
        successor=dict(serviceEpoch=current["serviceEpoch"], workerUUID=b["observedWorker"]["workerUUID"]), containedContainerIDs=sorted(containers))
    return [before, after, pending, succeeded, request, state, dict(state_sha256=p.digest(p.canonical(state))), containers, 99, 101], arm, checkpoint, prefault


class WorkerLifecycleTests(unittest.TestCase):
    def test_explicit_projection_and_pinned_manifest_read(self):
        args, _, _, _ = fixture()
        for value in args[:2]:
            reader = Mock(side_effect=[(value["checkpoint"], "a" * 64), (value["manifest"], "b" * 64)])
            actual, digest = e.read_owner(Path("/owned"), reader)
            self.assertEqual(actual, value); self.assertEqual(len(digest), 64)
            owner, projection = e.owner(actual)
            self.assertEqual(projection["format"], shared.VERSION)
            self.assertNotIn("ready", projection); self.assertNotIn("boot", actual)
            self.assertEqual(worker.public_boot(projection)["workerUUID"], owner["workerUUID"])
        with self.assertRaises(ValueError): shared.owner_context(args[1])

    def test_unknown_versions_and_nonfresh_claim_counter_are_refused(self):
        for version in ("storage-lifecycle.v1", "storage-lifecycle.v3", None):
            reader = Mock(return_value=({"version": version}, "a" * 64))
            with self.subTest(version=version), self.assertRaises(ValueError): e.read_owner(Path("/owned"), reader)
            reader.assert_called_once()
        args, arm, _, _ = fixture()
        args[2]["counter"] = args[3]["counter"] = 2
        with self.assertRaises(ValueError): e.replacement_proof(*args, prepare_recovery=arm)

    def test_all_nine_cuts_keep_actual_wait_and_drain_oracles(self):
        for case in p.WORKER_EXIT_CASES + p.CHECKPOINT_EXIT_CASES:
            with self.subTest(case=case):
                args, arm, checkpoint, prefault = fixture(case)
                e.replacement_proof(*args, prepare_recovery=arm)
                _, old = e.owner(args[0]); _, new = e.owner(args[1])
                if case in p.WORKER_EXIT_CASES:
                    wait = dict(worker.worker_exit_request(arm, checkpoint, old), requestSequence=checkpoint["admission"]["requestSequence"], workerPID=42, exitCode=74, reaped=True)
                    validate = worker.worker_wait
                else:
                    wait = dict(worker.checkpoint_exit_request(arm, checkpoint, old), workerPID=42, exitCode=74, reaped=True)
                    validate = worker.checkpoint_wait
                validate(wait, arm, checkpoint, old)
                with self.assertRaises(ValueError): validate({**wait, "reaped": False}, arm, checkpoint, old)
                with self.assertRaises(ValueError): validate({**wait, "exitCode": 0}, arm, checkpoint, old)
                if case == "drain-durable-reply-lost":
                    intent = args[5]["intents"][arm["scope"]["intent"]]
                    worker.retired_checkpoint_cut(intent, arm, checkpoint)
                    bad = copy.deepcopy(intent)
                    next(s for s in bad["slots"] if s["attachment"] == arm["targetAttachment"])["receipt"]["revision"] += 1
                    with self.assertRaises(ValueError): worker.retired_checkpoint_cut(bad, arm, checkpoint)
                else:
                    worker.recovered_worker_drain(prefault, args[5], arm, new, worker_interrupted=case in p.CHECKPOINT_EXIT_CASES)
                    bad = copy.deepcopy(args[5])
                    next(s for s in bad["intents"][arm["scope"]["intent"]]["slots"] if s["role"] == "prepare")["receipt"]["revision"] = 14
                    with self.assertRaises(ValueError): worker.recovered_worker_drain(prefault, bad, arm, new, worker_interrupted=case in p.CHECKPOINT_EXIT_CASES)

    def test_reject_mutated_confirmation_native_receipt_and_census(self):
        changes = [
            (1, ("checkpoint", "observedWorker", "workerUUID"), uid()),
            (1, ("checkpoint", "currentContext", "controllerKey"), "9" * 64),
            (1, ("checkpoint", "currentContext", "controllerEpoch"), True),
            (1, ("checkpoint", "latestServiceChange", "operationID"), uid()),
            (1, ("checkpoint", "latestServiceRequest", "predecessorWorkerUUID"), uid()),
            (1, ("checkpoint", "latestServiceRequest", "nowUnixSeconds"), 90),
            (1, ("checkpoint", "nativeReplacementAttempted"), False),
            (1, ("checkpoint", "serviceReplacement", "configuration", "action"), "initialize"),
            (1, ("checkpoint", "serviceReplacement", "configuration", "root_public_key"), BASE["encoded"](b"z" * 32)),
            (1, ("checkpoint", "latestServiceConfirmation", "request", "predecessor", "open_revision"), 9),
            (1, ("checkpoint", "intentRevision"), 31),
            (1, ("checkpoint", "references"), []),
            (1, ("checkpoint", "serviceLinks"), []),
            (1, ("manifest", "bytes"), 8192),
            (2, ("counter",), True), (2, ("counter",), 2),
            (3, ("containedContainerIDs",), ["a" * 64]),
            (3, ("successor", "workerUUID"), uid()),
            (3, ("ownerRequest", "nowUnixSeconds"), 90),
            (5, ("reconciliationRequired",), True),
        ]
        for index, path, value in changes:
            args, arm, _, _ = fixture(); args = [copy.deepcopy(value) for value in args]
            target = args[index]
            for part in path[:-1]: target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises((ValueError, KeyError)):
                e.replacement_proof(*args, prepare_recovery=arm)

    def test_census_rejects_matching_malformed_references_and_validates_recovery_direction(self):
        for field, value in (("version", True), ("supersededSuccessors", ["bad"]),
                ("supersededSuccessors", [uid()] * 2), ("predecessor", uid())):
            args, arm, _, _ = fixture()
            intent = args[5]["intents"][arm["scope"]["intent"]]
            intent[field] = value
            row = args[1]["checkpoint"]["references"][0]
            row["superseded" if field == "supersededSuccessors" else field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): e.replacement_proof(*args, prepare_recovery=arm)
        args, arm, _, _ = fixture()
        b, journal = args[1]["checkpoint"], args[5]
        original = journal["intents"][arm["scope"]["intent"]]
        child = copy.deepcopy(original); child.update(id=uid(), predecessor=original["id"], **b["currentContext"])
        original["successor"] = child["id"]
        child["replacementRecovery"] = dict(b["latestServiceChange"]["predecessor"], provenanceReference=b["provenanceReference"],
            workerHistoryReference=p.digest(p.canonical(b["latestServiceChange"])))
        journal["intents"][child["id"]] = child
        b["references"][0]["successor"] = child["id"]
        b["references"].append(dict(id=child["id"], version=1, original=b["currentContext"], predecessor=original["id"],
            superseded=[], recovery=child["replacementRecovery"]))
        b["references"].sort(key=lambda row: row["id"])
        e.replacement_proof(*args, prepare_recovery=arm)
        child["replacementRecovery"].update(b["currentContext"])
        with self.assertRaises(ValueError): e.replacement_proof(*args, prepare_recovery=arm)

    def test_old_receipt_not_rewritten_and_tls_must_rotate(self):
        args, arm, _, _ = fixture()
        self.assertNotEqual(args[1]["checkpoint"]["current"]["directResult"]["service_epoch"], args[1]["checkpoint"]["currentContext"]["serviceEpoch"])
        for field in ("tls_root_sha256", "server_spki"):
            bad = copy.deepcopy(args)
            bad[1]["checkpoint"]["currentService"]["boot"][field] = bad[0]["checkpoint"]["currentService"]["boot"][field]
            with self.assertRaises(ValueError): e.replacement_proof(*bad, prepare_recovery=arm)

    def test_versioned_campaign_routes_keep_containment_and_final_checks(self):
        for case, active in (("admitted-queued", False), ("admitted-queued", True),
                ("data-partial-frame", False), ("transaction-published-bind-reply-lost", False),
                ("drain-durable-reply-lost", False)):
            def values():
                args, arm, checkpoint, prefault = fixture(case)
                _, projection = e.owner(args[0])
                if case in p.WORKER_EXIT_CASES:
                    waited = dict(worker.worker_exit_request(arm, checkpoint, projection), requestSequence=checkpoint["admission"]["requestSequence"], workerPID=42, exitCode=74, reaped=True)
                else:
                    waited = dict(worker.checkpoint_exit_request(arm, checkpoint, projection), workerPID=42, exitCode=74, reaped=True)
                return args, arm, checkpoint, waited, prefault
            for fault in (None, "unreaped", "peer-still-live", "missing-receipt-id", "storage-death"):
                with self.subTest(case=case, active=active, fault=fault), patch.object(shared, "asset_digest", return_value="a" * 64):
                    campaign = WORKER["LifecycleTests"]().campaign
                    kwargs = dict(active=active, checkpoint_case=case if case in p.CHECKPOINT_EXIT_CASES else None, values_override=values)
                    if fault is None: campaign(**kwargs)
                    else:
                        with self.assertRaises(ValueError): campaign(fault=fault, **kwargs)

    def test_worker_path_uses_all_five_versioned_reads_and_hardened_native_target(self):
        import ast
        tree = ast.parse((ROOT / "Tests/Compatibility/managed_prepare_worker_faults.py").read_text())
        route = next(n for n in tree.body if getattr(n, "name", "") == "restart_worker_at_a5")
        calls = [ast.unparse(n.func) for n in ast.walk(route) if isinstance(n, ast.Call)]
        self.assertEqual(calls.count("lifecycle.read_owner"), 5)
        self.assertNotIn("recovery.read_public", calls)
        self.assertIs(worker.storage_target, BASE["api"].storage_target)


if __name__ == "__main__": unittest.main()
