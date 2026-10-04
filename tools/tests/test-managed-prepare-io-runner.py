#!/usr/bin/env python3
"""Offline runner regressions: mocked execution is never native IO evidence."""
import ast
import dataclasses
import json
import os
from pathlib import Path
import resource
import runpy
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
ACK = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-active-ack.py"))
p = ACK["p"]
import managed_prepare_io_faults as io

TREE = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())


def fixture_function(name, namespace):
    node = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "actual-IO-fixture-entry", "exec"), namespace)
    return namespace[name]


class IORunnerTests(unittest.TestCase):
    def setUp(self):
        self.support = ACK["ActiveACKRunnerTests"]()
        self.support.setUp()
        self.addCleanup(self.support.doCleanups)
        self.ns = self.support.ns
        self.ns["resource"] = resource
        self.outcomes = []
        # Full offline ledgers also retain descriptors; restore the test process
        # soft limit after closing them, and never change the hard limit.
        limits = resource.getrlimit(resource.RLIMIT_NOFILE)
        self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE, limits)
        self.ns["prepare_descriptor_budget"](io_count=46, evidence_root=self.support.evidence)
        self.dispatch = Mock()
        self.entry = fixture_function("run_io_shard", {"_run_prepare_case": self.dispatch})
        self.ns["fixture"].run_io_shard.side_effect = self.entry

    def outcome(self, case):
        # Invoke the actual nested registrar with explicitly synthetic runtime
        # bindings. These objects exercise pinning/validation, not native proof.
        selected = io.case_definition(case)
        phases = ["plan", "assets", "both-created", "normal-owned", "normal-stopped-drained",
                  "capture-intent", "arm-intent", "guest-armed", "checkpoint-external-fsync",
                  "production-channel-failure-contained", "docker-start-joined"]
        phases += (["sticky-quarantine-no-drain", "sticky-evidence-retained"]
                   if selected.expected == "sticky-uncertainty" else
                   ["production-quarantine-drain", "retry-source-witness", "recovered-runtime", "owned-cleanup"])
        events = [dict(phase=phase, testOnly=True) for phase in phases]
        events[0]["staged"] = dict(faultCase=dataclasses.asdict(selected))
        receipt = dict(rtm="RTM-100", profile=p.FULL_PROFILE, caseName=case,
            runID=str(uuid.uuid4()), store=str(uuid.uuid4()), expected=selected.expected,
            result=selected.expected + "-passed", execution="actual-docker-runtime", fullAcceptance=False,
            evidenceSHA256=p.digest(p.canonical([p.digest(p.canonical(row)) for row in events])))
        events.append(dict(phase="io-case-result", **receipt))
        directory = self.support.base / f"ledger-{uuid.uuid4()}"
        directory.mkdir(mode=0o700)
        with p.Directory(directory) as ledger:
            files = {}
            for index, event in enumerate(events):
                name = f"{index:03d}-{event['phase']}.json"
                ledger.publish(name, event)
                files[name] = ledger.read(name, pin_file=True)
            complete = fixture_function("complete_io_result", dict(proof=p, io_proof=io,
                io_case=selected, client=object(), starts=[Mock(poll=Mock(return_value=0)) for _ in range(3)],
                ledger=ledger, evidence_files=files, os=os))
            outcome = complete(receipt)
        self.outcomes.append(outcome)
        self.addCleanup(outcome.close)
        return outcome

    def test_complete_ordered_catalog_and_actual_fixture_dispatch_for_all_46(self):
        self.assertEqual(self.ns["selected_cases"]("RTM-100"), list(io.CASES))
        self.assertEqual(len(io.CASES), 46)
        families = {"recoverable": 0, "sticky-uncertainty": 0}
        for case in io.CASES:
            with self.subTest(case=case):
                expected = io.case_definition(case).expected
                families[expected] += 1
                outcome = self.outcome(case)
                self.dispatch.return_value = outcome
                self.support.daemon._retain_root = expected == "sticky-uncertainty"
                self.ns["harness"].reset_mock()
                self.assertIs(self.ns["run_cell"]("RTM-100", case, **self.support.args), outcome)
                call = self.ns["fixture"].run_io_shard.call_args
                self.assertEqual(call.args, (self.support.daemon,))
                self.assertEqual(call.kwargs, dict(profile=p.FULL_PROFILE, cases=io.CASES, fault_case=case,
                    probe=self.support.args["probe"], probe_sha256="a" * 64, source_sha256="b" * 64,
                    expected_commit="c0ffee0", evidence=call.kwargs["evidence"]))
                self.assertEqual(call.kwargs["evidence"].parent, self.support.evidence)
                dispatched = self.dispatch.call_args
                self.assertEqual(dispatched.args, (self.support.daemon,))
                self.assertEqual(dispatched.kwargs["io_case"], io.case_definition(case))
                self.assertEqual(dispatched.kwargs["staged"], io.selection(p.FULL_PROFILE, io.CASES, case))
                self.assertTrue(dispatched.kwargs["full"])
                self.assertTrue(dispatched.kwargs["early"])
                if expected == "sticky-uncertainty":
                    self.ns["harness"].release_compatibility_root.assert_not_called()
                    self.ns["harness"].remove_compatibility_root.assert_not_called()
                    self.assertTrue(self.support.daemon._retain_root)
                else:
                    self.ns["harness"].remove_compatibility_root.assert_called_once()
        self.assertEqual(families, {"recoverable": 16, "sticky-uncertainty": 30})
        self.ns["fixture"].run_restart_matrix_shard.assert_not_called()
        self.assertEqual(self.support.daemon.stop.call_count, 46)

    def test_receipts_unregistered_closed_or_changed_evidence_rejected(self):
        case = io.CASES[0]
        live = self.outcome(case)
        closed = self.outcome(case)
        closed.close()
        altered = self.outcome(case)
        name = next(iter(altered._files))
        (altered._directory.path / name).write_bytes(b"changed")
        for invalid in (live.receipt, Mock(), object.__new__(io.IOOutcome), closed, altered):
            with self.subTest(invalid=type(invalid)):
                self.dispatch.return_value = invalid
                with self.assertRaises(ValueError):
                    self.ns["run_cell"]("RTM-100", case, **self.support.args)
        self.ns["harness"].release_compatibility_root.assert_not_called()
        self.ns["harness"].remove_compatibility_root.assert_not_called()

    def test_exact_case_result_family_checked_even_for_partial_selection(self):
        case = io.CASES[0]
        outcome = self.outcome(case)
        self.dispatch.return_value = outcome
        for changes in (dict(caseName=io.CASES[1]), dict(expected="recoverable", result="recoverable-passed"),
                        dict(result="case-passed"), dict(fullAcceptance=True), dict(rtm="RTM-099"),
                        dict(execution="receipt"), dict(extra=True), dict(store="bad")):
            with self.subTest(changes=changes), patch.object(io.IOOutcome, "validate", return_value={**outcome.receipt, **changes}):
                with self.assertRaises(ValueError):
                    self.ns["run_cell"]("RTM-100", case, **self.support.args)
        self.ns["harness"].remove_compatibility_root.assert_not_called()

    def run_main(self, cases=None, *, fail=None, continuing=False, tamper=None):
        self.support.mock_main_work()
        def cell(rtm, case, **kwargs):
            self.assertEqual(rtm, "RTM-100")
            if case == fail:
                raise ValueError("failed IO cell")
            result = self.outcome(case)
            if tamper:
                return tamper(result)
            return result
        self.ns["run_cell"] = Mock(side_effect=cell)
        original = self.ns["main"]
        if continuing:
            def main():
                with patch.object(ACK["sys"], "argv", [*ACK["sys"].argv, "--continue-on-failure"]):
                    return original()
            self.ns["main"] = main
        with patch.object(io, "aggregate", wraps=io.aggregate) as aggregate:
            code = self.support.run_main("RTM-100", cases)
            if fail is None and cases is None:
                aggregate.assert_called_once_with(self.outcomes)
                self.assertTrue(all(type(o) is io.IOOutcome for o in aggregate.call_args.args[0]))
            else:
                aggregate.assert_not_called()
        self.ns["matrix"].aggregate_matrix.assert_not_called()
        self.ns["prepare_descriptor_budget"].assert_called_once_with(io_count=len(cases or io.CASES), evidence_root=self.support.evidence)
        for outcome in self.outcomes:
            with self.assertRaises(ValueError): outcome.validate()
        result = json.loads(next(self.support.evidence.glob("runner-RTM-100-*-result.json")).read_text())
        return code, result

    def test_full_live_aggregate_only(self):
        code, result = self.run_main()
        self.assertEqual(code, 0)
        self.assertTrue(result["fullAcceptance"])
        self.assertEqual(result["aggregate"]["result"], "full-acceptance-passed")
        self.assertEqual(result["aggregate"]["cases"], 46)
        self.assertEqual(result["aggregate"]["recoverableCases"], 16)
        self.assertEqual(result["aggregate"]["stickyContainedCases"], 30)
        self.assertFalse(result["aggregate"]["physicalPowerLoss"])

    def test_partial_sticky_and_recoverable_pass_without_aggregate(self):
        code, result = self.run_main([io.CASES[0], "io-eio-root-fsync"])
        self.assertEqual(code, 0)
        self.assertFalse(result["fullAcceptance"])
        self.assertNotIn("aggregate", result)

    def test_continued_failure_prevents_aggregate(self):
        code, result = self.run_main(fail=io.CASES[1], continuing=True)
        self.assertEqual(code, 1)
        self.assertNotIn("aggregate", result)
        self.assertFalse(result["fullAcceptance"])
        self.assertIn(io.CASES[1], result["failures"])

    def test_fail_fast_closes_preceding_live_outcome(self):
        with patch.object(io, "aggregate") as aggregate, self.assertRaisesRegex(ValueError, "failed IO cell"):
            self.run_main(fail=io.CASES[1])
        aggregate.assert_not_called()
        for outcome in self.outcomes:
            with self.assertRaises(ValueError): outcome.validate()

    def test_main_never_promotes_receipts_or_accepts_duplicate_stores(self):
        for tamper in (lambda o: o.receipt,
                       lambda o: (o._receipt.update(store="00000000-0000-4000-8000-000000000001") or o)):
            with self.subTest(tamper=tamper), self.assertRaises(ValueError):
                self.run_main(tamper=tamper)

    def test_descriptor_bound_uses_max_files_and_pinned_ancestors(self):
        # Tie the reservation to the actual fixture's record() file ceiling.
        record = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == "record")
        bound = next(n for n in ast.walk(record) if isinstance(n, ast.Compare)
                     and isinstance(n.left, ast.Name) and n.left.id == "sequence")
        self.assertEqual(ast.literal_eval(bound.comparators[0]), 60)
        budget = self.ns["prepare_descriptor_budget"]
        root = self.support.evidence
        wanted = ((1024 + 46 * (60 + len(root.parts) + 1) + 1023) // 1024) * 1024
        for count, required in ((0, 2048), (1, 2048), (9, 2048), (46, wanted)):
            with self.subTest(count=count), patch.object(resource, "getrlimit", side_effect=[(256, 8192), (required, 8192)]), patch.object(resource, "setrlimit") as setter:
                self.assertEqual(budget(io_count=count, evidence_root=root), required)
                setter.assert_called_once_with(resource.RLIMIT_NOFILE, (required, 8192))
        for limits in ((8192, 8192), (resource.RLIM_INFINITY, resource.RLIM_INFINITY)):
            with patch.object(resource, "getrlimit", return_value=limits), patch.object(resource, "setrlimit") as setter:
                self.assertEqual(budget(io_count=46, evidence_root=root), limits[0])
                setter.assert_not_called()
        with patch.object(resource, "getrlimit", return_value=(256, 2048)), patch.object(resource, "setrlimit") as setter:
            with self.assertRaisesRegex(ValueError, "hard limit"):
                budget(io_count=46, evidence_root=root)
            setter.assert_not_called()
        with patch.object(resource, "setrlimit") as setter:
            with self.assertRaisesRegex(ValueError, "bounded descriptor"):
                budget(io_count=46, evidence_root=Path("/").joinpath(*(["deep"] * 100)))
            setter.assert_not_called()


if __name__ == "__main__": unittest.main()
