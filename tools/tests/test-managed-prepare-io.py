#!/usr/bin/env python3
"""Engine-free closed RTM-100 inventory checks; no native acceptance evidence."""
import ast
import copy
import dataclasses
import runpy
import signal
import tempfile
import uuid
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as carrier
import managed_prepare_io_faults as io
from managed_storage_recovery import ProofFailure

V1 = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-faults.py"))


def arm_for(case):
    previous, _, _, capture, candidate = V1["values"]()
    candidate.update(version=3, profile=carrier.FULL_PROFILE)
    return io.arm_candidate(candidate, capture, previous, case)


def checkpoint(arm, worker=None):
    selected = io.case_definition(arm["caseName"])
    row = dict(version=3, profile=carrier.FULL_PROFILE, requestID=arm["requestID"],
               armDigest=carrier.digest(carrier.canonical(arm)), stage=selected.name,
               count=1, targetAttachment=arm["targetAttachment"])
    cut = dict(point=selected.point, errno=selected.errno, occurrence=1)
    if worker is not None:
        row["workerUUID"] = worker
        cut.update(requestSequence=0 if selected.operation == "retire" else 17,
                   retireOperation=str(uuid.uuid4()) if selected.operation == "retire" else "")
        row["io"] = cut
    else:
        row.update(copyIntent=str(uuid.uuid4()), **cut)
    return row


def sticky_state(arm):
    intent = {k if k != "intent" else "id": v for k, v in arm["scope"].items()}
    keys = {c["attachment"]: c["key"] for c in arm["credentials"]}
    slots = copy.deepcopy(arm["slots"])
    for slot in slots:
        if slot["role"] == "prepare": slot["key"] = keys[slot["attachment"]]
    intent.update(phase="quarantined", prepareCompleted=False, quarantineReason="failed", slots=slots)
    return dict(intents={intent["id"]: intent}, store=arm["scope"]["store"])


class IOInventoryTests(unittest.TestCase):
    def test_finite_independent_errno_matrix(self):
        self.assertEqual(len(io.CASES), 46)
        self.assertEqual(len(set(io.CASES)), 46)
        points = {case.point for case in io.CASE_DEFINITIONS}
        self.assertEqual(len(points), 23)
        for point in points:
            cases = [case for case in io.CASE_DEFINITIONS if case.point == point]
            self.assertEqual({case.errno for case in cases}, {"EIO", "ENOSPC"})
            self.assertTrue(all(case.occurrence == 1 for case in cases))
            self.assertEqual(len({(case.owner, case.operation, case.expected) for case in cases}), 1)
        self.assertEqual(sum(c.expected == "recoverable" for c in io.CASE_DEFINITIONS), 16)
        self.assertEqual(sum(c.expected == "sticky-uncertainty" for c in io.CASE_DEFINITIONS), 30)

    def test_inventory_is_immutable_and_report_only(self):
        first = io.CASE_DEFINITIONS[0]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.occurrence = 2
        report = io.inventory()
        report["cases"][0]["expected"] = "accept-anything"
        self.assertEqual(io.inventory()["cases"][0]["expected"], "sticky-uncertainty")
        self.assertFalse(report["fullAcceptance"])
        self.assertFalse(report["nativeExecuted"])

    def test_closed_selection_rejects_partial_or_changed_matrix(self):
        for cases in (io.CASES[:-1], io.CASES[::-1], io.CASES + (io.CASES[0],), "EIO"):
            with self.assertRaises(ProofFailure):
                io.selection(carrier.FULL_PROFILE, cases, io.CASES[0])
        for profile in (carrier.PROFILE, carrier.EARLY_PROFILE, "", None):
            with self.assertRaises(ProofFailure):
                io.selection(profile, io.CASES, io.CASES[0])
        for case in ("normal", "io-eio-fsync", "io-enospc-next-write", io.CASES[0].upper(), None):
            with self.assertRaises(ProofFailure):
                io.selection(carrier.FULL_PROFILE, io.CASES, case)

    def test_every_case_selection_remains_report_only(self):
        for case in io.CASES:
            plan = io.selection(carrier.FULL_PROFILE, io.CASES, case)
            self.assertFalse(plan["fullAcceptance"])
            self.assertEqual(io.require_deployed_case(carrier.FULL_PROFILE, io.CASES, case), plan)

    def test_all_observation_domains_match_exact_case_and_errno(self):
        for selected in io.CASE_DEFINITIONS:
            arm = arm_for(selected.name)
            worker = str(uuid.uuid4()) if selected.owner == "storage-authority" else None
            row = checkpoint(arm, worker)
            self.assertEqual(io.observation(row, arm, worker), row)
            for key, replacement in (("count", True), ("count", 2), ("armDigest", "0" * 64),
                                     ("stage", "io-eio-next-fsync"), ("targetAttachment", str(uuid.uuid4()))):
                bad = copy.deepcopy(row); bad[key] = replacement
                with self.assertRaises(ProofFailure): io.observation(bad, arm, worker)
            for key, replacement in (("errno", "EPERM"), ("occurrence", True), ("occurrence", 2), ("point", "fsync")):
                bad = copy.deepcopy(row)
                (bad["io"] if worker else bad)[key] = replacement
                with self.assertRaises(ProofFailure): io.observation(bad, arm, worker)
            bad = copy.deepcopy(row); bad["receipt"] = {}
            with self.assertRaises(ProofFailure): io.observation(bad, arm, worker)

    def test_authority_observation_request_or_retirement_not_both(self):
        for name in ("io-eio-copy-operation-write", "io-enospc-retire-receipt-persist"):
            arm = arm_for(name); worker = str(uuid.uuid4()); row = checkpoint(arm, worker)
            row["io"]["requestSequence"] = 0 if row["io"]["requestSequence"] else 1
            with self.assertRaises(ProofFailure): io.observation(row, arm, worker)

    def test_sticky_requires_no_drain_runtime_or_successor_and_immutable_retry(self):
        arm = arm_for("io-enospc-seal-persist"); before = sticky_state(arm)
        io.sticky_unchanged(before, copy.deepcopy(before), arm)
        for field, value in (("successor", str(uuid.uuid4())), ("prepareCompleted", True), ("phase", "running")):
            bad = copy.deepcopy(before); bad["intents"][arm["scope"]["intent"]][field] = value
            with self.assertRaises(ProofFailure): io.sticky_intent(bad, arm)
        for role, field in (("prepare", "receipt"), ("runtime", "key")):
            bad = copy.deepcopy(before)
            slot = next(s for s in bad["intents"][arm["scope"]["intent"]]["slots"] if s["role"] == role)
            slot[field] = {} if field == "receipt" else "a" * 64
            with self.assertRaises(ProofFailure): io.sticky_intent(bad, arm)
        bad = copy.deepcopy(before); bad["revision"] = 7
        with self.assertRaises(ProofFailure): io.sticky_unchanged(before, bad, arm)
        with self.assertRaises(ProofFailure): io.sticky_intent(before, arm_for("io-eio-root-fsync"))

    def test_io_outcome_retains_external_ledger_and_rejects_serialized_aggregate(self):
        with tempfile.TemporaryDirectory() as temporary:
            with carrier.Directory(Path(temporary).resolve()) as ledger:
                files = {}
                event = dict(phase="plan", testOnly=True)
                ledger.publish("001-plan.json", event); files["001-plan.json"] = ledger.read("001-plan.json", pin_file=True)
                result = dict(rtm="RTM-100", profile=carrier.FULL_PROFILE, caseName=io.CASES[0],
                    runID=str(uuid.uuid4()), store=str(uuid.uuid4()), result="sticky-uncertainty-passed",
                    expected="sticky-uncertainty", execution="actual-docker-runtime", fullAcceptance=False,
                    evidenceSHA256=carrier.digest(carrier.canonical([carrier.digest(carrier.canonical(event))])))
                ledger.publish("002-io-case-result.json", dict(phase="io-case-result", **result))
                files["002-io-case-result.json"] = ledger.read("002-io-case-result.json", pin_file=True)
                self.assertFalse(hasattr(io, "completed_outcome"))
                with self.assertRaises(TypeError): io.IOOutcome()
                with self.assertRaises(ProofFailure): io.aggregate([result] * 46)
                with self.assertRaises(ProofFailure):
                    io.validate_case_evidence([event, dict(phase="io-case-result", **result)], result)
                before = io.carrier_census(ledger)
                io.preserve_observed_carrier(before, files)
                changed = copy.deepcopy(before)
                changed["001-plan.json"] = (b"changed", before["001-plan.json"][1])
                with self.assertRaises(ProofFailure): io.preserve_observed_carrier(changed, files)
                ledger.publish("extra.json", dict(changed=True))
                self.assertNotEqual(io.carrier_census(ledger), before)

    def test_46_distinct_synthetic_ledgers_cannot_be_promoted(self):
        for case in io.CASES:
            event = dict(phase="plan", testOnly=True)
            selected = io.case_definition(case)
            result = dict(caseName=case, runID=str(uuid.uuid4()), store=str(uuid.uuid4()),
                expected=selected.expected, result=selected.expected + "-passed",
                evidenceSHA256=carrier.digest(carrier.canonical([carrier.digest(carrier.canonical(event))])))
            with self.assertRaises(ProofFailure):
                io.validate_case_evidence([event, dict(phase="io-case-result", **result)], result)
        self.assertFalse(hasattr(io, "completed_outcome"))

    def fixture_function(self, name, **bindings):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())
        function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
        namespace = dict(proof=carrier, io_proof=io, signal=signal,
                         NATURAL_FAILURE_CASES=("before-prepare-send", "data-partial-frame", "transaction-published-bind-reply-lost"),
                         remaining=lambda: 1, record=Mock())
        namespace.update(bindings)
        exec(compile(ast.Module(body=[function], type_ignores=[]), "actual-IO-start-oracle", "exec"), namespace)
        return namespace[name]

    def test_closed_io_start_phase_and_failure_family(self):
        for selected in io.CASE_DEFINITIONS:
            expected = 49 if selected.owner == "workload-supervisor" else 50
            self.assertEqual(io.expected_start_exit(selected, phase="initial-failure"), expected)
            for phase in (None, "", "retry", "initial", 409):
                with self.assertRaises(ProofFailure): io.expected_start_exit(selected, phase=phase)
            if selected.expected == "sticky-uncertainty":
                self.assertEqual(io.expected_start_exit(selected, phase="quarantine-retry"), 49)
            else:
                with self.assertRaises(ProofFailure): io.expected_start_exit(selected, phase="quarantine-retry")
        selected = io.CASE_DEFINITIONS[0]
        for bad in (None, selected.name, dataclasses.replace(selected, name="io-eio-unknown"),
                    dataclasses.replace(selected, owner="workload-supervisor"),
                    dataclasses.replace(selected, expected="recoverable")):
            with self.assertRaises(ProofFailure): io.expected_start_exit(bad, phase="initial-failure")

    def test_actual_join_and_checkpoint_require_one_exact_io_status(self):
        class EndWait(Exception): pass
        for selected in io.CASE_DEFINITIONS:
            expected = 49 if selected.expected == "recoverable" else 50
            joined = self.fixture_function("joined_start", io_case=selected, early=True, fault_case=selected.name)
            for failed in (False, True):
                for code in (0, 49, 50, 51, 52, -9):
                    with self.subTest(case=selected.name, failed=failed, code=code):
                        process = Mock(); process.wait.return_value = code
                        if code == (expected if failed else 0): joined(process, failed=failed)
                        else:
                            with self.assertRaises(ProofFailure): joined(process, failed=failed)
            for case in (selected.name, "normal"):
                for suffix in (".armed.json", ".arm.claimed.json", ".checkpoint.json", ".storage-checkpoint.json"):
                    for code in (None, 0, 49, 50, 51, 52, -9):
                        with self.subTest(case=case, suffix=suffix, code=code):
                            process = Mock(); process.poll.return_value = code
                            clock = Mock(); clock.sleep.side_effect = EndWait
                            events = Mock(); events.require.side_effect = carrier.require
                            # Returning from diagnostics must not bypass the closed-exit guard.
                            events.joined_start.return_value = None
                            wait = self.fixture_function("wait_artifact", io_case=selected, early=True, case=case,
                                process=process, queue=Mock(), artifact=Mock(side_effect=FileNotFoundError), time=clock,
                                joined_start=events.joined_start, proof=SimpleNamespace(require=events.require))
                            accepted = code in (None, 0 if case == "normal" else expected)
                            with self.assertRaises(EndWait if accepted else ProofFailure):
                                wait(suffix)
                            self.assertEqual(clock.sleep.call_count, int(accepted))
                            expected_calls = [] if accepted else [call.joined_start(process)]
                            expected_calls.append(call.require(accepted, "unexpected settled start before checkpoint"))
                            self.assertEqual(events.mock_calls, expected_calls)

    def test_actual_sticky_retry_call_is_explicit_conflict_not_initial_error(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == "joined_start" and n.args and isinstance(n.args[0], ast.Name)
                    and n.args[0].id == "rejected")
        self.assertEqual({k.arg: ast.literal_eval(k.value) for k in call.keywords},
                         {"failed": True, "io_phase": "quarantine-retry"})
        for selected in io.CASE_DEFINITIONS:
            if selected.expected != "sticky-uncertainty": continue
            joined = self.fixture_function("joined_start", io_case=selected, early=True, fault_case=selected.name)
            for code in (0, 49, 50, 51, 52):
                process = Mock(); process.wait.return_value = code
                invoke = lambda: eval(compile(ast.Expression(body=call), "actual-sticky-retry-call", "eval"),
                                      dict(joined_start=joined, rejected=process))
                if code == 49: invoke()
                else:
                    with self.assertRaises(ProofFailure): invoke()

    def test_fixture_reuses_actual_lifecycle_and_refuses_before_daemon_access(self):
        source = (ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text()
        tree = ast.parse(source)
        wrapper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_io_shard")
        calls = []
        namespace = dict(_run_prepare_case=lambda *a, **kw: calls.append(kw))
        exec(compile(ast.Module(body=[wrapper], type_ignores=[]), "IO-selector-only", "exec"), namespace)
        with self.assertRaises(ProofFailure):
            namespace["run_io_shard"](None, profile="ordinary", cases=io.CASES, fault_case=io.CASES[0],
                probe=None, probe_sha256=None, source_sha256=None, expected_commit=None, evidence=None)
        self.assertEqual(calls, [])
        self.assertIn("io_proof.sticky_unchanged(before_retry, after_retry, arm)", source)
        self.assertIn("return complete_io_result(result)", source)
        self.assertIn("before_carrier = io_proof.carrier_census(queue)", source)
        self.assertIn("io_proof.carrier_census(queue) == before_carrier", source)


if __name__ == "__main__":
    unittest.main()
