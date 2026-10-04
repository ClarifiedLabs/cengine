#!/usr/bin/env python3
"""Executable AST runner regressions; no engine, native build, or VM acceptance."""
import ast
import copy
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import Mock
import uuid

ROOT = Path(__file__).resolve().parents[2]
ACK = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-active-ack.py"))
p = ACK["p"]
CASE = "vm-two-volume-drain-reply-gap"


def fixture_entry(dispatch):
    tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_two_volume_drain_shard")
    env = dict(proof=p, _run_prepare_case=dispatch)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "two-volume-entry", "exec"), env)
    return env[node.name]


def fixture_report(staged):
    # Execute the actual successful return expression, not an invented report schema.
    tree = ast.parse((ROOT / "Tests/Compatibility/managed_prepare_two_volume_parent.py").read_text())
    run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
    result = next(n.value for n in ast.walk(run) if isinstance(n, ast.Return)
                  and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
                  and n.value.func.id == "dict")
    env = dict(p=p, uuid=uuid, staged=staged, manifest={"store": str(uuid.uuid4())},
               plan={"owner": uuid.uuid4().hex}, files={"proof": (None, ["f" * 64])})
    return eval(compile(ast.Expression(body=result), "two-volume-result", "eval"), env)


class TwoVolumeRunnerTests(unittest.TestCase):
    run_main = ACK["ActiveACKRunnerTests"].run_main
    mock_main_work = ACK["ActiveACKRunnerTests"].mock_main_work

    def setUp(self):
        ACK["ActiveACKRunnerTests"].setUp(self)
        self.dispatch = Mock(side_effect=lambda daemon, **kwargs: fixture_report(kwargs["staged"]))
        self.entry = fixture_entry(self.dispatch)
        self.report = self.entry(self.daemon, profile=p.FULL_PROFILE, cases=(CASE,),
            probe=self.args["probe"], probe_sha256=self.args["probe_sha256"],
            source_sha256=self.args["source_sha256"], expected_commit=self.args["commit"], evidence=self.evidence)
        self.dispatch.reset_mock()
        self.ns["fixture"].run_two_volume_drain_shard.return_value = self.report

    def test_default_nine_unchanged_and_closed_optin(self):
        for rtm in ("RTM-097", "RTM-098", "RTM-099"):
            self.assertEqual(self.ns["selected_cases"](rtm), list(p.FULL_CASES))
            self.assertEqual(len(self.ns["selected_cases"](rtm)), 9)
        for defaults in self.ns["CAMPAIGNS"].values():
            self.assertNotIn(CASE, defaults)
        self.assertEqual(self.ns["selected_cases"]("RTM-099", [CASE]), [CASE])
        self.assertEqual(self.ns["selected_cases"]("RTM-098", [ACK["ACK_CASE"]]), [ACK["ACK_CASE"]])

    def test_foreign_unknown_and_duplicate_cases_fail_before_work(self):
        self.mock_main_work()
        invalid = [(rtm, [CASE]) for rtm in ("RTM-097", "RTM-098", "RTM-103")]
        invalid += [("RTM-099", cases) for cases in ([CASE, CASE], ["unknown"],
                    ["vm-private-bound-unknown"], ["normal", "unknown"], [ACK["ACK_CASE"]])]
        for rtm, cases in invalid:
            with self.subTest(rtm=rtm, cases=cases), self.assertRaises(ValueError):
                self.run_main(rtm, cases, evidence=self.base / "must-not-exist")
        self.assertFalse((self.base / "must-not-exist").exists())
        for name in ("run_cell", "build_probe", "asset_metadata", "expected_commit", "prepare_descriptor_budget"):
            self.ns[name].assert_not_called()

    def test_dispatch_executes_actual_singleton_fixture_and_result_schema(self):
        shard = self.ns["fixture"].run_two_volume_drain_shard
        shard.side_effect = self.entry
        result = self.ns["run_cell"]("RTM-099", CASE, **self.args)
        shard.assert_called_once_with(self.daemon, profile=p.FULL_PROFILE, cases=(CASE,),
            probe=self.args["probe"], probe_sha256="a" * 64, source_sha256="b" * 64,
            expected_commit="c0ffee0", evidence=next(self.evidence.iterdir()))
        self.dispatch.assert_called_once()
        self.assertEqual(len(self.ns["fixture"].mock_calls), 1)
        self.assertEqual(set(result), {"rtm", "boundary", "caseName", "runnable", "result", "fullAcceptance",
                                     "profile", "execution", "runID", "store", "evidenceSHA256"})
        self.assertEqual(result["boundary"], CASE)
        self.assertEqual(result["caseName"], CASE)
        self.assertNotIn("CaseName", result)
        self.assertEqual(result["result"], "initial-cut-passed")
        self.assertIs(result["fullAcceptance"], False)
        self.daemon.start.assert_called_once()
        self.daemon.stop.assert_called_once()

    def test_existing_fixture_rejects_full_nine_catalog(self):
        with self.assertRaises(ValueError):
            self.entry(self.daemon, profile=p.FULL_PROFILE, cases=p.FULL_CASES,
                probe=self.args["probe"], probe_sha256="a" * 64, source_sha256="b" * 64,
                expected_commit="c0ffee0", evidence=self.evidence)
        self.dispatch.assert_not_called()

    def test_ack_arguments_are_rejected_before_any_two_volume_work(self):
        for args in (dict(ack_probe=self.probe), dict(ack_probe_sha256=self.pin),
                     dict(ack_probe=self.probe, ack_probe_sha256=self.pin)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.ns["run_cell"]("RTM-099", CASE, **self.args, **args)
        self.assertFalse(self.ns["WORK_PARENT"].exists())
        self.assertEqual(list(self.evidence.iterdir()), [])
        self.ns["conftest"].Daemon.assert_not_called()
        self.assertEqual(self.ns["harness"].mock_calls, [])
        self.assertEqual(self.ns["fixture"].mock_calls, [])

    def test_invalid_results_fail_closed_and_retain_root(self):
        changes = dict(rtm="RTM-097", boundary="drain-durable-reply-lost", caseName="normal", runnable=False,
            result="case-passed", fullAcceptance=True, profile=p.PROFILE, execution="replayed",
            runID="invalid", store="invalid", evidenceSHA256="A" * 64)
        invalid = [dict(self.report, **{key: value}) for key, value in changes.items()]
        invalid += [{key: value for key, value in self.report.items() if key != missing} for missing in self.report]
        invalid += [dict(self.report, CaseName=CASE), dict(self.report, nativeAcceptance=False),
                    dict(self.report, fullAcceptance=0), dict(self.report, runnable=1),
                    None, list(self.report.items()), type("ReportSubclass", (dict,), {})(self.report)]
        for report in invalid:
            self.ns["fixture"].run_two_volume_drain_shard.return_value = report
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.ns["run_cell"]("RTM-099", CASE, **self.args)
        self.assertEqual(self.daemon.stop.call_count, len(invalid))
        self.ns["harness"].release_compatibility_root.assert_not_called()
        self.ns["harness"].remove_compatibility_root.assert_not_called()

    def test_addon_alone_or_as_ninth_or_tenth_never_aggregates_or_builds_ack(self):
        selections = ([CASE], ["normal", CASE], [*p.FULL_CASES[:-1], CASE], [*p.FULL_CASES, CASE])
        for index, cases in enumerate(selections):
            self.evidence = self.base / f"addon-{index}"
            self.mock_main_work()
            retained = []
            def cell(rtm, case, **kwargs):
                if case == CASE:
                    return copy.deepcopy(self.report)
                outcome = Mock(receipt={"caseName": case})
                retained.append(outcome)
                return outcome
            self.ns["run_cell"].side_effect = cell
            self.assertEqual(self.run_main("RTM-099", cases), 0)
            self.ns["build_probe"].assert_called_once_with(self.evidence / "probe")
            self.assertEqual([c.args for c in self.ns["run_cell"].call_args_list], [("RTM-099", c) for c in cases])
            for call in self.ns["run_cell"].call_args_list:
                self.assertNotIn("ack_probe", call.kwargs)
                self.assertNotIn("ack_probe_sha256", call.kwargs)
            self.ns["matrix"].aggregate_matrix.assert_not_called()
            result = json.loads(next(self.evidence.glob("runner-RTM-099-*-result.json")).read_text())
            self.assertIs(result["fullAcceptance"], False)
            self.assertNotIn("aggregate", result)
            self.assertEqual(set(result["cases"]), set(cases))
            self.assertEqual(result["cases"][CASE], self.report)
            for outcome in retained:
                outcome.close.assert_called_once_with()

    def test_default_and_explicit_nine_still_aggregate_without_ack(self):
        for index, (rtm, cases) in enumerate((("RTM-097", None), ("RTM-099", None),
                                             ("RTM-099", list(reversed(p.FULL_CASES))))):
            self.evidence = self.base / f"matrix-{index}"
            self.mock_main_work()
            outcomes = [Mock(receipt={"caseName": case}) for case in (cases or p.FULL_CASES)]
            self.ns["run_cell"].side_effect = outcomes
            aggregate = self.ns["matrix"].aggregate_matrix
            aggregate.reset_mock()
            aggregate.return_value = dict(fullAcceptance=True, result="matrix-passed", variants=[])
            self.assertEqual(self.run_main(rtm, cases), 0)
            self.ns["build_probe"].assert_called_once_with(self.evidence / "probe")
            aggregate.assert_called_once_with(outcomes, rtm)
            result = json.loads(next(self.evidence.glob(f"runner-{rtm}-*-result.json")).read_text())
            self.assertIs(result["fullAcceptance"], True)
            self.assertEqual(set(result["cases"]), set(p.FULL_CASES))
            for outcome in outcomes:
                outcome.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
