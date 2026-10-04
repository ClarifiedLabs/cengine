#!/usr/bin/env python3
"""Engine-free v3 rejection/ordering checks. No engine/native acceptance evidence."""
import ast
import copy
import json
from pathlib import Path
import runpy
import struct
import tempfile
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p
V1 = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-faults.py"))
V2 = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-early.py"))
FIXTURE = ROOT / "Tests/Compatibility/test_managed_prepare_faults.py"


def uid(): return str(uuid.uuid4())


def arm_for(case):
    previous, _, _, capture, candidate = V1["values"]()
    candidate.update(version=3, profile=p.FULL_PROFILE)
    return p.full_arm_candidate(candidate, capture, previous, case)


def object_for(inode=0):
    return dict(inode=inode, generation=7 if inode else 0, file_type=16384 if inode else 0,
        handle_type=1 if inode else 0, handle_size=8 if inode else 0,
        handle=struct.pack("<II", inode, 7 if inode else 0).hex())


def cleanup():
    return dict(uid=0, gid=0, mode=0, atime_seconds="0", mtime_seconds="0", atime_nanos=0, mtime_nanos=0,
        manifest=object_for(), staging=object_for())


def storage(arm, worker):
    value = dict(**p.storage_query(arm, worker), stage=arm["caseName"], count=1, targetAttachment=arm["targetAttachment"])
    if arm["caseName"] in p.HELD_STORAGE_CASES:
        value["admission"] = dict(requestSequence=7, admitted=arm["caseName"] == "admitted-queued", releaseToken="1"*64)
    else:
        scope = arm["scope"]
        target = next(s for s in arm["slots"] if s["role"] == "prepare")
        if arm["caseName"] == "transaction-published-bind-reply-lost":
            owner = dict(store=scope["store"], volume=target["volume"], attachment=target["attachment"], prepare=scope["prepare"],
                container=scope["container"], launch=scope["launch"], key=arm["credentials"][0]["key"], role="prepare", mode="read-write")
            initial = cleanup(); initial.update(uid=10001, gid=10002, mode=0o750, atime_seconds="-1")
            intent = dict(id=uid(), owner=owner, epoch=scope["serviceEpoch"], root=dict(store=scope["store"], volume=target["volume"], backing_uuid="8"*32, root=object_for(1)),
                transaction=object_for(2), manifest_digest="0"*64, manifest_size=0, phase="BOUND", initial=initial, cleanup=cleanup(), initial_captured=True)
            value["bound"] = dict(requestSequence=9, intent=intent)
        else:
            value["drain"] = dict(retireOperation=uid(), receipt=dict(schema=3, store=scope["store"],
                volume=target["volume"], attachment=target["attachment"], prepare=scope["prepare"],
                launch=scope["launch"], revision=20))
    return value


def status(arm, worker, checkpoint=None, phase="armed"):
    value = dict(query=p.storage_query(arm, worker), state=phase, retirementStarted=phase != "armed", acceptedInFlight=0, lateAdmissionRejected=False, receiptReplayCount=0)
    if checkpoint is not None: value["observation"] = copy.deepcopy(checkpoint)
    if phase == "observed" and arm["caseName"] == "admitted-queued": value["acceptedInFlight"] = 1
    if phase == "finished":
        value["lateAdmissionRejected"] = arm["caseName"] == "full-frame-before-admit"
        value["receiptReplayCount"] = int(arm["caseName"] == "drain-durable-reply-lost")
    return value


class FullTests(unittest.TestCase):
    def test_closed_nine_case_selection_before_dispatch(self):
        expected = ("normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame", "full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost", "first-child-published", "drain-durable-reply-lost")
        self.assertEqual(p.FULL_CASES, expected)
        for case in expected:
            result = p.full_selection(p.FULL_PROFILE, expected, case)
            self.assertEqual(result["coverage"], "1/9"); self.assertFalse(result["fullAcceptance"])
        for profile, cases, case in ((p.PROFILE, expected, "normal"), (p.EARLY_PROFILE, expected, "normal"), (p.FULL_PROFILE, expected[::-1], "normal"), (p.FULL_PROFILE, expected[:-1], "normal"), (p.FULL_PROFILE, expected, "A4")):
            with self.assertRaises(ValueError): p.full_selection(profile, cases, case)
        tree = ast.parse(FIXTURE.read_text())
        wrapper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_full_shard")
        calls = []
        namespace = dict(proof=p, _run_prepare_case=lambda *a, **k: calls.append(k))
        exec(compile(ast.Module(body=[wrapper], type_ignores=[]), "selector-only", "exec"), namespace)
        kwargs = dict(probe=None, probe_sha256=None, source_sha256=None, expected_commit=None, evidence=None)
        namespace["run_full_shard"](None, profile=p.FULL_PROFILE, cases=expected, fault_case=expected[4], **kwargs)
        self.assertEqual(len(calls), 1); self.assertIs(calls[0]["full"], True)
        with self.assertRaises(ValueError): namespace["run_full_shard"](None, profile=p.PROFILE, cases=expected, fault_case=expected[4], **kwargs)
        self.assertEqual(len(calls), 1)

    def test_aggregate_requires_nine_distinct_live_current_receipts(self):
        rows = [dict(profile=p.FULL_PROFILE, caseName=c, runID=uid(), store=uid(), result="case-passed", evidenceSHA256="1"*64, execution="actual-docker-runtime", fullAcceptance=False) for c in p.FULL_CASES]
        self.assertIsNone(p._validate_full_receipts(rows))
        with self.assertRaises(ValueError): p.aggregate_full(rows)
        with self.assertRaises(TypeError): p.FullOutcome()
        for bad in (rows[:-1], rows + [rows[0]], [rows[0]]*9, tuple(rows)):
            with self.assertRaises(ValueError): p._validate_full_receipts(bad)
        for field, value in (("profile", p.PROFILE), ("result", "source-only-passed"), ("execution", "source-only"), ("fullAcceptance", True), ("caseName", "skip"), ("runID", rows[1]["runID"]), ("store", rows[1]["store"]), ("evidenceSHA256", "")):
            bad = copy.deepcopy(rows); bad[0][field] = value
            with self.assertRaises(ValueError): p._validate_full_receipts(bad)
        bad = copy.deepcopy(rows); bad[0]["extra"] = 1
        with self.assertRaises(ValueError): p._validate_full_receipts(bad)

    def test_v3_observation_dialects_never_optionalize_physical_fields(self):
        for case in p.FULL_CASES:
            arm = arm_for(case)
            if case in p.EARLY_COUNTERS:
                value = V2["observation"](arm)
            else:
                value = V1["observed"](arm)
            value.update(version=3, profile=p.FULL_PROFILE)
            if case in p.STORAGE_CASES and case != "drain-durable-reply-lost":
                with self.assertRaises(ValueError): p.full_observation(value, arm)
                continue
            p.full_observation(value, arm)
            with self.assertRaises(ValueError): p.observation(value, arm)
            with self.assertRaises(ValueError): p.early_observation(value, arm)
            for key in value:
                bad = copy.deepcopy(value); del bad[key]
                with self.assertRaises((ValueError, KeyError)): p.full_observation(bad, arm)

    def test_storage_closed_payload_and_worker_arm_binding(self):
        for case in p.STORAGE_CASES:
            arm, worker = arm_for(case), uid(); value = storage(arm, worker)
            self.assertEqual(p.storage_observation(value, arm, worker), value)
            for change in (dict(version=True), dict(profile=p.PROFILE), dict(workerUUID=uid()), dict(requestID=uid()), dict(armDigest="0"*64), dict(count=2), dict(count=True), dict(targetAttachment=uid()), dict(stage="normal"), dict(extra=1)):
                bad = copy.deepcopy(value); bad.update(change)
                with self.assertRaises(ValueError): p.storage_observation(bad, arm, worker)
            for key in value:
                bad = copy.deepcopy(value); del bad[key]
                with self.assertRaises(ValueError): p.storage_observation(bad, arm, worker)
            for key in ("admission", "bound", "drain"):
                bad = copy.deepcopy(value); bad[key] = None
                with self.assertRaises(ValueError): p.storage_observation(bad, arm, worker)

    def test_bound_requires_full_unsealed_identity_owner_and_signed_seconds(self):
        arm, worker = arm_for("transaction-published-bind-reply-lost"), uid()
        value = storage(arm, worker); intent = value["bound"]["intent"]
        mutations = [lambda i: i.update(phase="SEALED"), lambda i: i.update(manifest_digest="1"*64), lambda i: i.update(manifest_size=True), lambda i: i.update(initial_captured=False),
            lambda i: i["owner"].update(key="0"*64), lambda i: i["owner"].update(extra=1), lambda i: i.update(epoch=uid()),
            lambda i: i["root"].update(backing_uuid="0"*32), lambda i: i.update(transaction=copy.deepcopy(i["root"]["root"])),
            lambda i: i["transaction"].update(handle="0"*16), lambda i: i["cleanup"].update(uid=1)]
        for change in mutations:
            bad = copy.deepcopy(intent); change(bad)
            with self.assertRaises(ValueError): p.storage_bound_intent(bad, arm)
        for seconds in (0, "00", "-0", "+1", "1.0", " 1", str(2**63), str(-(2**63)-1)):
            bad = copy.deepcopy(intent); bad["initial"]["atime_seconds"] = seconds
            with self.assertRaises(ValueError): p.storage_bound_intent(bad, arm)
        for seconds in ("0", "-1", str(-(2**63)), str(2**63-1)):
            bad = copy.deepcopy(intent); bad["initial"]["atime_seconds"] = seconds
            p.storage_bound_intent(bad, arm)

    def test_pending_is_required_before_exact_release_and_never_finish(self):
        for case in p.HELD_STORAGE_CASES:
            arm, worker = arm_for(case), uid(); checkpoint = storage(arm, worker)
            pending = status(arm, worker, checkpoint, "observed")
            release = p.storage_release(pending, arm, worker, checkpoint)
            self.assertEqual(release, dict(query=p.storage_query(arm, worker), stage=case, token=checkpoint["admission"]["releaseToken"]))
            for change in (dict(retirementStarted=False), dict(retirementStarted=1), dict(state="finished"), dict(lateAdmissionRejected=True), dict(receiptReplayCount=1), dict(acceptedInFlight=0 if case == "admitted-queued" else 1)):
                bad = copy.deepcopy(pending); bad.update(change)
                with self.assertRaises(ValueError): p.storage_release(bad, arm, worker, checkpoint)
            bad = copy.deepcopy(pending); bad["observation"]["admission"]["requestSequence"] += 1
            with self.assertRaises(ValueError): p.storage_release(bad, arm, worker, checkpoint)

    def test_finished_requires_real_fence_zero_guards_and_actual_replay(self):
        for case in p.STORAGE_CASES:
            arm, worker = arm_for(case), uid(); checkpoint = storage(arm, worker)
            value = status(arm, worker, checkpoint, "finished")
            p.storage_status(value, arm, worker, phase="finished", checkpoint=checkpoint)
            for change in (dict(retirementStarted=False), dict(acceptedInFlight=1), dict(state="observed"), dict(lateAdmissionRejected=case != "full-frame-before-admit"), dict(receiptReplayCount=0 if case == "drain-durable-reply-lost" else 1)):
                bad = copy.deepcopy(value); bad.update(change)
                with self.assertRaises(ValueError): p.storage_status(bad, arm, worker, phase="finished", checkpoint=checkpoint)
            armed = status(arm, worker)
            p.storage_status(armed, arm, worker, phase="armed")
            armed["observation"] = checkpoint
            with self.assertRaises(ValueError): p.storage_status(armed, arm, worker, phase="armed")

    def test_a8_receipt_exact_full_tuple_not_synthetic_drain(self):
        arm, worker = arm_for("drain-durable-reply-lost"), uid()
        receipt = storage(arm, worker)["drain"]["receipt"]
        for key in receipt:
            bad = copy.deepcopy(receipt); bad[key] = 0 if key in ("schema", "revision") else uid()
            with self.assertRaises(ValueError): p.storage_receipt(bad, arm)
        for key in receipt:
            bad = copy.deepcopy(receipt); del bad[key]
            with self.assertRaises(ValueError): p.storage_receipt(bad, arm)

    def test_full_failed_and_recovery_use_actual_full_tuple_current_atimes(self):
        for case in p.FULL_CASES[1:-1]:
            arm = arm_for(case); intent = V2["failed"](arm)
            p.failed_full_prepare(intent, arm)
            intent["slots"][0]["mode"] = "read-only"
            with self.assertRaises(ValueError): p.failed_full_prepare(intent, arm)
        for case in ("normal", "drain-durable-reply-lost"):
            arm = arm_for(case); checkpoint = V1["observed"](arm); checkpoint.update(version=3, profile=p.FULL_PROFILE)
            baseline = V1["snapshot"](); recovered = copy.deepcopy(baseline)
            recovered["root"]["atimeNS"] = checkpoint["sourceAtimes"]["root"]
            for name in p.FILES: recovered["files"][name]["atimeNS"] = checkpoint["sourceAtimes"][name]
            p.full_retry_snapshot(recovered, baseline, checkpoint, arm)
            recovered["files"]["z"]["atimeNS"] = 0
            with self.assertRaises(ValueError): p.full_retry_snapshot(recovered, baseline, checkpoint, arm)

    def test_shared_full_nine_canonical_vectors(self):
        vectors = json.loads((ROOT / "Guest/internal/preparecompat/testdata/full-vectors.json").read_text())
        self.assertEqual(tuple(v["name"] for v in vectors), p.FULL_CASES)
        for vector in vectors:
            arm = copy.deepcopy(vector["arm"])
            arm["mounts"].sort(key=lambda m: m["index"])
            arm["slots"].sort(key=lambda s: s["attachment"])
            arm["credentials"].sort(key=lambda c: c["attachment"])
            self.assertEqual(p.canonical(arm).decode(), vector["canonical"])
            self.assertEqual(p.digest(p.canonical(arm)), vector["sha256"])
            raw = p.canonical(vector["observation"])
            self.assertEqual(raw.decode(), vector["observationCanonical"])
            self.assertEqual(p.digest(raw), vector["observationSHA256"])
            if vector["name"] in p.STORAGE_CASES:
                worker = vector["storageArm"]["workerUUID"]
                checkpoint = p.storage_observation(vector["storageObservation"], arm, worker)
                self.assertEqual(p.storage_query(arm, worker), vector["storageQuery"])
                self.assertEqual(p.canonical(checkpoint).decode(), vector["storageObservationCanonical"])
                self.assertEqual(p.digest(p.canonical(checkpoint)), vector["storageObservationSHA256"])
                if "storageRelease" in vector:
                    pending = status(arm, worker, checkpoint, "observed")
                    self.assertEqual(p.storage_release(pending, arm, worker, checkpoint), vector["storageRelease"])
                if "physicalObservation" in vector:
                    p.full_observation(vector["physicalObservation"], arm)
                    self.assertEqual(p.canonical(vector["physicalObservation"]).decode(), vector["physicalObservationCanonical"])
                    self.assertEqual(p.digest(p.canonical(vector["physicalObservation"])), vector["physicalObservationSHA256"])
            else:
                p.full_observation(p.decode(raw, 8192), arm)

    def test_external_ledger_replacement_and_content_edits_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve()
            with p.Directory(path) as directory:
                directory.publish("001-checkpoint.json", {"phase": "checkpoint"})
                files = {"001-checkpoint.json": directory.read("001-checkpoint.json", pin_file=True)}
                p.verify_full_ledger(directory, files)
                (path / "001-checkpoint.json").write_bytes(b'{"phase":"tampered"}')
                with self.assertRaises(ValueError): p.verify_full_ledger(directory, files)
                (path / "001-checkpoint.json").write_bytes(files["001-checkpoint.json"][0])
                p.verify_full_ledger(directory, files)
                directory.publish("unexpected.json", {"extra": True})
                with self.assertRaises(ValueError): p.verify_full_ledger(directory, files)

    def test_natural_failure_set_is_exact_and_shared_by_status_and_containment(self):
        tree = ast.parse(FIXTURE.read_text())
        natural = next(n for n in tree.body if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "NATURAL_FAILURE_CASES" for t in n.targets))
        self.assertEqual(ast.literal_eval(natural.value),
            ("before-prepare-send", "data-partial-frame", "transaction-published-bind-reply-lost"))
        users = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id in ("expected", "natural_failure") for t in n.targets)
                 and any(isinstance(c, ast.Name) and c.id == "NATURAL_FAILURE_CASES" for c in ast.walk(n.value))]
        self.assertEqual(len(users), 3)  # joined result, pre-publication wait, containment.
        branch = next(n for n in users if n.targets[0].id == "natural_failure")
        for early in (False, True):
            for case in p.FULL_CASES:
                namespace = dict(early=early, fault_case=case, io_case=None)
                exec(compile(ast.Module(body=[natural, branch], type_ignores=[]), "natural-routing", "exec"), namespace)
                self.assertEqual(namespace["natural_failure"], early and case in
                    ("before-prepare-send", "data-partial-frame", "transaction-published-bind-reply-lost"))

    def test_actual_lifecycle_ordering_not_mocked_native_results(self):
        source = FIXTURE.read_text()
        ordered = ['record("checkpoint-external-fsync"', 'proc_signal_with_audittoken', 'wait_exit(process)', 'wait_artifact(".storage-pending.json")', 'proof.storage_release(pending', 'record("storage-retirement-pending"', 'queue.publish(arm["requestID"] + ".storage-release.json"', 'wait_artifact(".storage-finished.json")', 'joined_start(start, failed=True)']
        offset = source.index('record("checkpoint-external-fsync"')
        for text in ordered:
            next_offset = source.index(text, offset); self.assertGreaterEqual(next_offset, offset); offset = next_offset
        self.assertIn('"no fresh successor mutation while held"', source)
        self.assertIn('"running intent uses exact immutable dropped/replayed receipt"', source)
        self.assertEqual(source.count('@pytest.mark.compat("RTM-096")'), 1)
        for forbidden in ("pytest.skip", "parametrize", "unittest.mock", "client.retire", "signal_storage"):
            self.assertNotIn(forbidden, source)
        tree = ast.parse(source)
        handler = next(n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler) and "_contain_early_owner" in ast.unparse(n))
        self.assertNotIn("storage-release", ast.unparse(handler))


if __name__ == "__main__": unittest.main()
