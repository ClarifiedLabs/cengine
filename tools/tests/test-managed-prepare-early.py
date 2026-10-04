#!/usr/bin/env python3
"""Engine-free v2 early fixture guards. Not native, channel or VM PASS evidence."""
import ast
import copy
import json
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p

# Reuse unchanged synthetic v1 fixture values, not its tests or any engine API.
V1 = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-faults.py"))
FIXTURE = ROOT / "Tests/Compatibility/test_managed_prepare_faults.py"


def values(case="before-prepare-send"):
    previous, _, _, capture, candidate = V1["values"]()
    candidate.update(version=2, profile=p.EARLY_PROFILE)
    arm = p.early_arm_candidate(candidate, capture, previous, case)
    return previous, capture, candidate, arm


def observation(arm):
    sent, accepted, written = p.EARLY_COUNTERS[arm["caseName"]]
    return dict(version=2, profile=p.EARLY_PROFILE, requestID=arm["requestID"], armDigest=p.digest(p.canonical(arm)),
        stage=arm["caseName"], count=1, targetAttachment=arm["targetAttachment"], requestSequence=7,
        prepareCommandsSent=sent, prepareCommandsAccepted=accepted, dataBytesWritten=written)


def failed(arm):
    value = {**arm["scope"], "id": arm["scope"]["intent"], "phase": "quarantined", "prepareCompleted": False,
        "cleanUnmount": False, "quarantineReason": "start interrupted", "slots": copy.deepcopy(arm["slots"])}
    for slot in value["slots"]:
        if slot["role"] == "prepare":
            slot["key"] = arm["credentials"][0]["key"]
            slot["receipt"] = dict(store=value["store"], volume=slot["volume"], attachment=slot["attachment"],
                prepare=value["prepare"], launch=value["launch"], revision=10)
    return value


class EarlyTests(unittest.TestCase):
    def test_exact_four_case_selection_per_fault_receipt_is_only_two(self):
        self.assertEqual(p.EARLY_CASES, ("normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame"))
        for index, case in enumerate(p.EARLY_CASES[1:], 1):
            selected = p.early_selection(p.EARLY_PROFILE, p.EARLY_CASES, case)
            self.assertEqual(selected["boundaries"], ["NORMAL", "A" + str(index)])
            self.assertEqual(selected["coverage"], "2/9")
            self.assertEqual(selected["implementedCoverage"], "4/9")
            self.assertEqual(selected["implementedBoundaries"], ["NORMAL", "A1", "A2", "A3"])
            self.assertFalse(selected["fullAcceptance"])
            self.assertIn("A7", selected["missing"])
            self.assertEqual(len(selected["missing"]), 7)
        for profile, cases, fault in ((p.PROFILE, p.EARLY_CASES, p.EARLY_CASES[1]), (p.EARLY_PROFILE, p.CASES, p.EARLY_CASES[1]),
            (p.EARLY_PROFILE, p.EARLY_CASES[::-1], p.EARLY_CASES[1]), (p.EARLY_PROFILE, p.EARLY_CASES[1:], p.EARLY_CASES[1]),
            (p.EARLY_PROFILE, (*p.EARLY_CASES, "first-child-published"), p.EARLY_CASES[1]),
            (p.EARLY_PROFILE, p.EARLY_CASES, "normal"), (p.EARLY_PROFILE, p.EARLY_CASES, "A1"), (p.EARLY_PROFILE, p.EARLY_CASES, "first-child-published")):
            with self.assertRaises(ValueError): p.early_selection(profile, cases, fault)

    def test_old_profile_does_not_accept_early_cases_or_dialect(self):
        self.assertEqual(p.CASES, ("normal", "first-child-published"))
        self.assertEqual(p.selection(p.PROFILE, p.CASES)["coverage"], "2/9")
        for case in p.EARLY_CASES[1:]:
            previous, capture, candidate, arm = values(case)
            with self.assertRaises(ValueError): p.arm_candidate(candidate, capture, previous, case)
            with self.assertRaises(ValueError): p.observation(observation(arm), arm)
            candidate.update(version=1, profile=p.PROFILE)
            with self.assertRaises(ValueError): p.early_arm_candidate(candidate, capture, previous, case)
            with self.assertRaises(ValueError): p.arm_candidate(candidate, capture, previous, case)
        with self.assertRaises(ValueError): p.selection(p.EARLY_PROFILE, p.EARLY_CASES)

    def test_early_arm_matches_exact_public_tuple_and_fresh_credential(self):
        previous, capture, candidate, arm = values()
        self.assertEqual(arm["scope"], candidate["scope"])
        self.assertEqual(capture["version"], 1)  # Existing scheduling-only capture wire.
        self.assertEqual(set(arm), p.CANDIDATE | {"caseName", "targetAttachment"})
        changes = [lambda c: c.update(version=1), lambda c: c.update(version=True), lambda c: c.update(profile=p.PROFILE),
            lambda c: c["scope"].update(intent=previous["id"]), lambda c: c["scope"].update(launch=previous["launch"]),
            lambda c: c["scope"].update(prepare=previous["prepare"]), lambda c: c["scope"].update(specificationDigest="0"*64),
            lambda c: c["mounts"].append(copy.deepcopy(c["mounts"][0])), lambda c: c["credentials"][0].update(key=previous["slots"][0]["key"]),
            lambda c: c["slots"][0].update(attachment=previous["slots"][0]["attachment"]),
            lambda c: c["credentials"].append(copy.deepcopy(c["credentials"][0]))]
        for change in changes:
            bad = copy.deepcopy(candidate); change(bad)
            with self.assertRaises(ValueError): p.early_arm_candidate(bad, capture, previous, arm["caseName"])
        for case in ("first-child-published", "admit", "A1", ""):
            with self.assertRaises(ValueError): p.early_arm_candidate(candidate, capture, previous, case)
        for extra in ({"binding": copy.deepcopy(candidate["binding"])}, {"credentials": copy.deepcopy(candidate["credentials"])}):
            with self.assertRaises(ValueError): p.early_arm_candidate(candidate, capture, {**previous, **extra}, "normal")

    def test_exact_early_counters_have_no_physical_fields(self):
        for case, counters in zip(p.EARLY_CASES[1:], ((0, 0, 0), (1, 1, 0), (1, 1, 5))):
            _, _, _, arm = values(case); value = observation(arm)
            self.assertEqual(p.early_observation(value, arm), value)
            self.assertEqual(tuple(value[k] for k in ("prepareCommandsSent", "prepareCommandsAccepted", "dataBytesWritten")), counters)
            self.assertEqual(set(value), p.EARLY_FIELDS)
            for key in ("copyIntent", "filesystemUUID", "manifestDigest", "manifestSize", "root", "transaction", "published", "staged", "sourceAtimes", "admitSequence", "path"):
                bad = copy.deepcopy(value); bad[key] = 1
                with self.assertRaises(ValueError): p.early_observation(bad, arm)
            for key in p.EARLY_FIELDS:
                bad = copy.deepcopy(value); del bad[key]
                with self.assertRaises(ValueError): p.early_observation(bad, arm)
            for key in ("prepareCommandsSent", "prepareCommandsAccepted", "dataBytesWritten"):
                bad = copy.deepcopy(value); bad[key] += 1
                with self.assertRaises(ValueError): p.early_observation(bad, arm)

    def test_early_observation_types_bounds_replay_and_case_mismatch(self):
        for case in p.EARLY_CASES[1:]:
            _, _, _, arm = values(case); value = observation(arm)
            mutations = [dict(version=1), dict(version=True), dict(profile=p.PROFILE), dict(count=0), dict(count=True),
                dict(requestID=str(uuid.uuid4())), dict(targetAttachment=str(uuid.uuid4())), dict(armDigest="0"*64),
                dict(stage="normal"), dict(stage="first-child-published"), dict(requestSequence=0), dict(requestSequence=True), dict(requestSequence=2**64)]
            for key in ("prepareCommandsSent", "prepareCommandsAccepted", "dataBytesWritten"):
                mutations.extend({key: invalid} for invalid in (True, None, -1, 2**32, "0", 0.0))
            for change in mutations:
                bad = copy.deepcopy(value); bad.update(change)
                with self.assertRaises(ValueError): p.early_observation(bad, arm)
            value["requestSequence"] = 2**64 - 1
            p.early_observation(value, arm)
            for raw in (p.canonical(value) + b"\n", b'{"requestSequence":7,"requestSequence":8}', b'{"dataBytesWritten":null}'):
                with self.assertRaises(ValueError): p.decode(raw, 8192)
            with self.assertRaises(ValueError): p.decode(b" "*8193, 8192)

    def test_shared_guest_host_early_vectors(self):
        vectors = json.loads((ROOT / "Guest/internal/preparecompat/testdata/early-vectors.json").read_text())
        self.assertEqual(tuple(v["name"] for v in vectors), p.EARLY_CASES)
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
            validator = p.early_normal_observation if vector["name"] == "normal" else p.early_observation
            self.assertEqual(validator(p.decode(raw, 8192), arm), vector["observation"])

    def test_retry_needs_its_own_v2_normal_physical_witness_and_atimes(self):
        _, _, _, arm = values("normal")
        checkpoint = V1["observed"](arm)
        checkpoint.update(version=2, profile=p.EARLY_PROFILE)
        p.early_normal_observation(checkpoint, arm)
        baseline = V1["snapshot"](); original = copy.deepcopy(baseline)
        recovered = copy.deepcopy(baseline)
        recovered["root"]["atimeNS"] = checkpoint["sourceAtimes"]["root"]
        for name in p.FILES: recovered["files"][name]["atimeNS"] = checkpoint["sourceAtimes"][name]
        p.early_retry_snapshot(recovered, baseline, checkpoint, arm)
        self.assertEqual(original, baseline)
        with self.assertRaises(ValueError): p.retry_snapshot(recovered, baseline, checkpoint, arm)
        for change in (lambda v: v["root"].update(atimeNS=0), lambda v: v["files"]["a"].update(atimeNS=0),
            lambda v: v["files"]["z"].update(atimeNS=0), lambda v: v["root"].update(uid=0), lambda v: v["files"]["z"].update(sha256="0"*64),
            lambda v: v["entries"].append("transaction")):
            bad = copy.deepcopy(recovered); change(bad)
            with self.assertRaises(ValueError): p.early_retry_snapshot(bad, baseline, checkpoint, arm)
        for case in p.EARLY_CASES[1:]:
            _, _, _, early = values(case)
            with self.assertRaises(ValueError): p.early_retry_snapshot(recovered, baseline, observation(early), early)
            physical = copy.deepcopy(checkpoint)
            physical.update(requestID=early["requestID"], targetAttachment=early["targetAttachment"], armDigest=p.digest(p.canonical(early)))
            with self.assertRaises(ValueError): p.early_normal_observation(physical, early)
        for change in (dict(version=1), dict(profile=p.PROFILE), dict(sourceAtimes={}), dict(armDigest="0"*64)):
            bad = copy.deepcopy(checkpoint); bad.update(change)
            with self.assertRaises(ValueError): p.early_retry_snapshot(recovered, baseline, bad, arm)

    def test_full_failed_prepare_receipts_not_just_disappearance(self):
        for case in p.EARLY_CASES[1:]:
            _, _, _, arm = values(case); intent = failed(arm)
            self.assertEqual(p.failed_early_prepare(intent, arm), intent)
            prep = lambda i: next(s for s in i["slots"] if s["role"] == "prepare")
            runtime = lambda i: next(s for s in i["slots"] if s["role"] == "runtime")
            changes = [lambda i: i.update(phase="retired"), lambda i: i.update(prepareCompleted=True), lambda i: i.update(cleanUnmount=True),
                lambda i: i.update(guestCompletion={"succeeded": True}), lambda i: runtime(i).update(key="1"*64),
                lambda i: prep(i).update(key="0"*64), lambda i: prep(i).update(mode="read-only"), lambda i: prep(i).update(receipt=None),
                lambda i: prep(i)["receipt"].update(prepare=str(uuid.uuid4())), lambda i: prep(i)["receipt"].update(revision=True),
                lambda i: prep(i)["receipt"].update(extra=1), lambda i: i["slots"].pop()]
            for change in changes:
                bad = copy.deepcopy(intent); change(bad)
                with self.assertRaises(ValueError): p.failed_early_prepare(bad, arm)

    def test_per_fault_root_must_be_fresh_not_reused_after_cleanup(self):
        state = {"intents": {}, "volumes": {"id": {"name": "owned"}}}
        p.early_fresh_state(state, "owned")
        for value in ({"intents": {"old": {"phase": "retired"}}, "volumes": state["volumes"]},
            {"intents": {}, "volumes": {}}, {"intents": {}, "volumes": {**state["volumes"], "old": {"name": "deleted"}}},
            {"intents": {}, "volumes": {"id": {"name": "owned", "deletedRevision": 8}}}):
            with self.assertRaises(ValueError): p.early_fresh_state(value, "owned")
        with self.assertRaises(ValueError): p.early_fresh_state(state, "foreign")

    def test_wrappers_route_only_after_closed_selection_without_importing_sdk(self):
        tree = ast.parse(FIXTURE.read_text())
        definitions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ("run_staged_shard", "run_early_shard")]
        calls = []
        def pure_dispatch(*args, **kwargs):
            calls.append((args, kwargs)); return kwargs["staged"]
        namespace = {"proof": p, "_run_prepare_case": pure_dispatch}
        exec(compile(ast.Module(body=definitions, type_ignores=[]), "selector-only", "exec"), namespace)
        inputs = dict(probe=None, probe_sha256=None, source_sha256=None, expected_commit=None, evidence=None)
        for case in p.EARLY_CASES[1:]:
            result = namespace["run_early_shard"](None, profile=p.EARLY_PROFILE, cases=p.EARLY_CASES, fault_case=case, **inputs)
            self.assertFalse(result["fullAcceptance"])
            self.assertIs(calls[-1][1]["early"], True)
            self.assertEqual(calls[-1][1]["fault_case"], case)
        namespace["run_staged_shard"](None, profile=p.PROFILE, cases=p.CASES, **inputs)
        self.assertIs(calls[-1][1]["early"], False)
        self.assertEqual(calls[-1][1]["fault_case"], "first-child-published")
        count = len(calls)
        with self.assertRaises(ValueError): namespace["run_early_shard"](None, profile=p.PROFILE, cases=p.EARLY_CASES, fault_case=p.EARLY_CASES[1], **inputs)
        with self.assertRaises(ValueError): namespace["run_staged_shard"](None, profile=p.EARLY_PROFILE, cases=p.EARLY_CASES, **inputs)
        self.assertEqual(len(calls), count)

    def test_early_post_arm_publication_can_race_success_or_natural_failure(self):
        # Execute just the Python wait loop against an in-memory publication
        # interleaving. No SDK, process probe, signal or native result is faked.
        tree = ast.parse(FIXTURE.read_text())
        loop = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "wait_artifact")
        natural = next(n for n in tree.body if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "NATURAL_FAILURE_CASES" for t in n.targets))
        for case in p.EARLY_CASES:
            status = 0 if case == "normal" else 49 if case in ("before-prepare-send", "data-partial-frame") else 50
            for suffix in (".armed.json", ".arm.claimed.json", ".checkpoint.json"):
                reads = []
                def artifact(*args):
                    reads.append(args)
                    if len(reads) == 1: raise FileNotFoundError()
                    return {"actualPublished": True}
                namespace = dict(proof=p, remaining=lambda: 1, queue=SimpleNamespace(validate=lambda: None), artifact=artifact,
                    process=SimpleNamespace(poll=lambda: status), joined_start=lambda _: None,
                    early=True, case=case, io_case=None, time=SimpleNamespace(sleep=lambda _: None))
                exec(compile(ast.Module(body=[natural, loop], type_ignores=[]), "wait-loop-only", "exec"), namespace)
                self.assertEqual(namespace["wait_artifact"](suffix), {"actualPublished": True})
                self.assertEqual(len(reads), 2)
                # Preserve v1 settlement rejection and reject pre-arm settlement.
                for early, requested in ((False, suffix), (True, ".candidate.json"), (True, ".capture.json")):
                    reads.clear(); namespace["early"] = early
                    with self.assertRaises(ValueError): namespace["wait_artifact"](requested)
                    self.assertEqual(len(reads), 1)
                reads.clear(); namespace.update(early=True, process=SimpleNamespace(poll=lambda: 51))
                with self.assertRaises(ValueError): namespace["wait_artifact"](suffix)

    def test_early_evidence_is_fresh_and_disjoint_from_daemon_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve(); work = base / "daemon"; root = work / "root"; evidence = base / "evidence"
            root.mkdir(parents=True, mode=0o700); evidence.mkdir(mode=0o700)
            p.early_evidence_location(evidence, work, root)
            for bad in (base, work, root, root / "evidence", work / "evidence"):
                with self.assertRaises(ValueError): p.early_evidence_location(bad, work, root)
            with self.assertRaises(ValueError): p.early_evidence_location(evidence, work, base / "other-root")
            with p.Directory(evidence) as directory:
                p.early_empty_evidence(directory)
                directory.publish("old-receipt.json", {"version": 1})
                with self.assertRaises(ValueError): p.early_empty_evidence(directory)

    def test_emergency_containment_is_failure_only_exact_owned_and_bounded(self):
        tree = ast.parse(FIXTURE.read_text())
        emergency = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_contain_early_owner")
        text = ast.unparse(emergency)
        for required in ("exact_exit", "proof.workload_owner", "validate()", "current == process", "proc_signal_with_audittoken",
                         "KQ_NOTE_EXIT", "remaining()", "fullAcceptance=False"):
            self.assertIn(required, text)
        self.assertLess(text.index("exact_exit"), text.index("proof.workload_owner"))
        self.assertIn("signalDelivered=False", text)
        self.assertNotIn("os.kill(", text)
        caller = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run_prepare_case")
        handlers = [n for n in ast.walk(caller) if isinstance(n, ast.ExceptHandler)]
        owner_handler = next(n for n in handlers if "_contain_early_owner" in ast.unparse(n))
        handler_text = ast.unparse(owner_handler)
        self.assertIn("if early:", handler_text)
        self.assertIn("if pending_owner is not None:", handler_text)
        self.assertIn("deadline + 6", handler_text)
        self.assertIn("time.monotonic() + 3", handler_text)
        self.assertIn("failure_record", handler_text)
        self.assertIsInstance(owner_handler.body[-1], ast.Raise)

    def test_natural_failure_branch_never_looks_up_or_signals_dead_owner(self):
        source = FIXTURE.read_text(); tree = ast.parse(source)
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "natural_failure")
        natural = ast.unparse(ast.Module(body=branch.body, type_ignores=[]))
        killed = ast.unparse(ast.Module(body=branch.orelse, type_ignores=[]))
        for forbidden in ("target(", "workload_owner(", "_kernel_process(", "SIGKILL", "proc_signal_with_audittoken"):
            self.assertNotIn(forbidden, natural)
        self.assertIn("pending_owner", natural)
        for required in ("workload_owner", "SIGKILL", "proc_signal_with_audittoken", "KQ_NOTE_EXIT", "wait_exit(process)"):
            self.assertIn(required, killed)
        self.assertLess(source.index('record("early-owner-before-arm"'), source.index('queue.publish(request + ".arm.json"'))
        self.assertLess(source.index('record("checkpoint-external-fsync"'), source.index('proc_signal_with_audittoken'))
        self.assertIn('joined_start(start, failed=True)', source)
        self.assertIn('proof.failed_early_prepare if early else proof.failed_prepare', source)
        self.assertIn('proof.early_retry_snapshot(recovered, baseline, retry_checkpoint, successor)', source)
        self.assertIn('"old drain receipts immutable"', source)
        self.assertIn('"production ReplacePrepare historical link"', source)
        self.assertEqual(source.count('@pytest.mark.compat("RTM-096")'), 1)
        for forbidden in ("pytest.skip", "parametrize", "unittest.mock", "terminate_drained_workloads"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__": unittest.main()
