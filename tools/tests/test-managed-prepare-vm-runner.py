#!/usr/bin/env python3
"""Engine-free VM addon runner contracts; no build, VM or native acceptance."""
import ast
import copy
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import Mock, call
import uuid

ROOT = Path(__file__).resolve().parents[2]
ACK = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-active-ack.py"))
p, vm = ACK["p"], ACK["vm"]
ACK_CASE = "vm-private-bound-active-ack"
CASES = (*vm.CASES, ACK_CASE)
ENTRIES = dict(zip(CASES, ("run_storage_private_shard", "run_storage_root_shard",
    "run_storage_cleaning_shard", "run_storage_private_active_ack_shard")))
FIXTURE = ROOT / "Tests/Compatibility/test_managed_prepare_faults.py"
TREE = ast.parse(FIXTURE.read_text())


def fixture_entry(case, dispatch):
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == ENTRIES[case])
    env = dict(proof=p, _run_prepare_case=dispatch)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(FIXTURE), "exec"), env)
    return env[node.name]


def fixture_report(staged):
    # Execute the storage branch's actual report expression with the entry's
    # actual selection, rather than inventing a schema that agrees with the runner.
    run = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "_run_prepare_case")
    branch = next(n for n in ast.walk(run) if isinstance(n, ast.If)
        and ast.unparse(n.test) == "storage_restart"
        and any(isinstance(s, ast.Return) for s in n.body))
    result = next(n.value for n in branch.body if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "result" for t in n.targets))
    env = dict(staged=staged, profile=p.FULL_PROFILE, proof=p, uuid=uuid,
        plan={"owner": "a" * 12 + "4" + "a" * 3 + "8" + "a" * 15},
        manifest={"store": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}, evidence_chain=["e" * 64])
    return eval(compile(ast.Expression(body=result), str(FIXTURE), "eval"), env)


class VMRunnerTests(unittest.TestCase):
    run_main = ACK["ActiveACKRunnerTests"].run_main
    mock_main_work = ACK["ActiveACKRunnerTests"].mock_main_work

    def setUp(self):
        ACK["ActiveACKRunnerTests"].setUp(self)
        self.dispatch = Mock(side_effect=lambda daemon, **kwargs: fixture_report(kwargs["staged"]))
        self.entries = {case: fixture_entry(case, self.dispatch) for case in CASES}
        self.reports = {case: entry(self.daemon, **self.entry_args(case, self.evidence))
                        for case, entry in self.entries.items()}
        self.dispatch.reset_mock()
        for case, entry in self.entries.items():
            getattr(self.ns["fixture"], ENTRIES[case]).side_effect = entry

    def ack_args(self, case):
        return dict(ack_probe=self.probe, ack_probe_sha256=self.pin) if case == ACK_CASE else {}

    def entry_args(self, case, evidence):
        return dict(profile=p.FULL_PROFILE, probe=self.args["probe"], probe_sha256="a" * 64,
            source_sha256="b" * 64, expected_commit="c0ffee0", evidence=evidence,
            **(self.ack_args(case) if case == ACK_CASE else dict(cases=vm.CASES)))

    def assert_no_work(self):
        self.assertFalse(self.ns["WORK_PARENT"].exists())
        self.assertEqual(list(self.evidence.iterdir()), [])
        self.ns["conftest"].Daemon.assert_not_called()
        self.daemon.start.assert_not_called()
        self.assertEqual(self.ns["harness"].mock_calls, [])
        self.assertEqual(self.ns["fixture"].mock_calls, [])
        self.dispatch.assert_not_called()

    def test_closed_catalog_and_defaults_are_exact_and_disjoint(self):
        self.assertEqual(vm.CASES, ("vm-private-bound", "vm-root-synced-before-cleanup",
                                  "vm-cleaning-transaction-removed"))
        self.assertEqual(self.ns["ADDON_CASES"], {"RTM-098": (ACK["ACK_CASE"],),
            "RTM-099": ("vm-two-volume-drain-reply-gap", *CASES)})
        for rtm in ("RTM-097", "RTM-098", "RTM-099"):
            self.assertEqual(self.ns["selected_cases"](rtm), list(p.FULL_CASES))
            self.assertEqual(len(self.ns["selected_cases"](rtm)), 9)
        for defaults in self.ns["CAMPAIGNS"].values():
            self.assertTrue(set(defaults).isdisjoint(CASES))
        for case in CASES:
            self.assertEqual(self.ns["selected_cases"]("RTM-099", [case]), [case])
        self.assertEqual(self.ns["selected_cases"]("RTM-099", ["normal", *CASES]), ["normal", *CASES])

    def test_unknown_foreign_duplicate_and_entry_names_fail_before_any_work(self):
        invalid = [(rtm, [case]) for rtm in ("RTM-097", "RTM-098", "RTM-103", "RTM-000") for case in CASES]
        invalid += [("RTM-099", cases) for cases in ([ACK["ACK_CASE"]], ["unknown"], ["normal", "unknown"],
            ["managed_prepare_vm_boundaries"], ["normal", "normal"], *([case, case] for case in CASES),
            *([entry] for entry in ENTRIES.values()))]
        # Direct cells reject invalid routes even if a valid ACK probe was supplied.
        for rtm, cases in invalid:
            if len(cases) == 1:
                with self.subTest(rtm=rtm, cases=cases), self.assertRaises(ValueError):
                    self.ns["run_cell"](rtm, cases[0], **self.args,
                        ack_probe=self.probe, ack_probe_sha256=self.pin)
        self.assert_no_work()
        self.mock_main_work()
        for rtm, cases in invalid:
            if rtm == "RTM-000":
                with self.assertRaises(ValueError): self.ns["selected_cases"](rtm, cases)
                continue  # argparse independently closes the campaign names.
            with self.subTest(rtm=rtm, cases=cases), self.assertRaises(ValueError):
                self.run_main(rtm, cases, evidence=self.base / "must-not-exist")
        self.assertFalse((self.base / "must-not-exist").exists())
        for name in ("run_cell", "build_probe", "asset_metadata", "expected_commit", "prepare_descriptor_budget"):
            self.ns[name].assert_not_called()

    def test_all_four_routes_execute_real_entries_and_storage_result_schema(self):
        for case in CASES:
            with self.subTest(case=case):
                self.ns["fixture"].reset_mock()
                self.dispatch.reset_mock()
                before = set(self.evidence.iterdir())
                result = self.ns["run_cell"]("RTM-099", case, **self.args, **self.ack_args(case))
                evidence, = set(self.evidence.iterdir()) - before
                shard = getattr(self.ns["fixture"], ENTRIES[case])
                shard.assert_called_once_with(self.daemon, **self.entry_args(case, evidence))
                self.assertEqual(len(self.ns["fixture"].mock_calls), 1)
                staged = (dict(rtm="RTM-099", boundary=case, fullAcceptance=False) if case == ACK_CASE else
                    dict(vm.selection(p.FULL_PROFILE, vm.CASES, case), rtm="RTM-099", boundary=case))
                forwarded = self.entry_args(case, evidence)
                forwarded.pop("cases", None)
                forwarded.pop("ack_probe", None)
                forwarded.pop("ack_probe_sha256", None)
                cut = vm.CASES[0] if case == ACK_CASE else case
                self.dispatch.assert_called_once_with(self.daemon, **forwarded, staged=staged,
                    fault_case=cut, vm_cut=cut, storage_restart=True, early=True, full=True,
                    **(dict(active_ack_probe=(self.probe, self.pin)) if case == ACK_CASE else {}))
                self.assertEqual(result, self.reports[case])
                self.assertEqual(set(result), {"rtm", "boundary", "result", "fullAcceptance", "profile",
                    "execution", "runID", "store", "evidenceSHA256"} |
                    (set() if case == ACK_CASE else {"caseName", "recovery"}))
                self.assertIs(result["fullAcceptance"], False)
                if case != ACK_CASE:
                    self.assertEqual(result["caseName"], case)
                    self.assertEqual(result["recovery"], "fresh-owner-private-replay" if case == vm.CASES[0]
                        else "complete-tree-readback")
        self.assertEqual(self.daemon.start.call_count, 4)
        self.assertEqual(self.daemon.stop.call_count, 4)
        self.ns["matrix"].aggregate_matrix.assert_not_called()

    def test_real_entries_require_complete_ordered_catalog_and_ack_has_no_cases_argument(self):
        for case in vm.CASES:
            args = self.entry_args(case, self.evidence)
            for catalog in ((case,), vm.CASES[::-1], p.FULL_CASES, (*vm.CASES, ACK_CASE), ()):
                with self.subTest(case=case, catalog=catalog), self.assertRaises(ValueError):
                    self.entries[case](self.daemon, **dict(args, cases=catalog))
            with self.assertRaises(ValueError):
                self.entries[case](self.daemon, **dict(args, profile=p.PROFILE))
        with self.assertRaises(TypeError):
            self.entries[ACK_CASE](self.daemon, **self.entry_args(ACK_CASE, self.evidence), cases=vm.CASES)
        self.dispatch.assert_not_called()

    def test_wrong_ack_arguments_and_missing_or_tampered_probe_fail_before_work(self):
        bad = [{}, dict(ack_probe=self.probe), dict(ack_probe_sha256=self.pin),
            dict(ack_probe=str(self.probe), ack_probe_sha256=self.pin),
            dict(ack_probe=self.base / "missing", ack_probe_sha256=self.pin),
            dict(ack_probe=self.base, ack_probe_sha256=self.pin)]
        bad += [dict(ack_probe=self.probe, ack_probe_sha256=pin) for pin in (None, True, 1, "", "A" * 64, "f" * 64)]
        for args in bad:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.ns["run_cell"]("RTM-099", ACK_CASE, **self.args, **args)
        for case in (*vm.CASES, "normal", "vm-two-volume-drain-reply-gap"):
            for args in (dict(ack_probe=self.probe), dict(ack_probe_sha256=self.pin), self.ack_args(ACK_CASE)):
                with self.subTest(case=case, args=args), self.assertRaises(ValueError):
                    self.ns["run_cell"]("RTM-099", case, **self.args, **args)
        self.probe.write_bytes(b"tampered after pinning")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.ns["run_cell"]("RTM-099", ACK_CASE, **self.args, **self.ack_args(ACK_CASE))
        self.assert_no_work()

    def test_malformed_reports_fail_closed_and_retain_roots(self):
        count = 0
        for case, report in self.reports.items():
            changes = dict(rtm="RTM-098", boundary="normal", result="matrix-case-passed", fullAcceptance=True,
                profile=p.PROFILE, execution="serialized", runID="invalid", store="invalid", evidenceSHA256="A" * 64)
            if case != ACK_CASE:
                changes.update(caseName="normal", recovery="complete-tree-readback" if case == vm.CASES[0]
                               else "fresh-owner-private-replay")
            invalid = [dict(report, **{key: value}) for key, value in changes.items()]
            invalid += [{key: value for key, value in report.items() if key != missing} for missing in report]
            invalid += [dict(report, **{key: value}) for key in report for value in (None, True, 0, [], {})]
            invalid += [dict(report, **{key: value}) for key in ("runID", "store") for value in
                (report[key].upper(), report[key].replace("-", ""), str(uuid.uuid1()))]
            invalid += [dict(report, evidenceSHA256=value) for value in ("e" * 63, "e" * 65, "g" * 64)]
            invalid += [dict(report, caseName="normal"), dict(report, recovery="wrong"), dict(report, CaseName=case),
                dict(report, runnable=True), dict(report, nativeAcceptance=False), dict(report, fullAcceptance=0),
                None, list(report.items()), json.dumps(report), type("ReportSubclass", (dict,), {})(report)]
            shard = getattr(self.ns["fixture"], ENTRIES[case])
            shard.side_effect = None
            for value in invalid:
                shard.return_value = value
                with self.subTest(case=case, report=value), self.assertRaises(ValueError):
                    self.ns["run_cell"]("RTM-099", case, **self.args, **self.ack_args(case))
                count += 1
        self.assertEqual(self.daemon.stop.call_count, count)
        self.ns["harness"].release_compatibility_root.assert_not_called()
        self.ns["harness"].remove_compatibility_root.assert_not_called()

    def test_addons_alone_mixed_nine_and_ten_never_aggregate(self):
        for case in CASES:
            for index, cases in enumerate(([case], ["normal", case], [*p.FULL_CASES[:-1], case], [*p.FULL_CASES, case])):
                self.evidence = self.base / f"{case}-{index}"
                self.mock_main_work()
                retained = []
                def cell(rtm, selected, **kwargs):
                    if selected == case: return copy.deepcopy(self.reports[case])
                    outcome = Mock(receipt={"caseName": selected})
                    retained.append(outcome)
                    return outcome
                self.ns["run_cell"].side_effect = cell
                self.assertEqual(self.run_main("RTM-099", cases), 0)
                expected = [call(self.evidence / "probe")]
                if case == ACK_CASE: expected.append(call(self.evidence / "ack-probe", active_ack=True))
                self.assertEqual(self.ns["build_probe"].call_args_list, expected)
                self.ns["matrix"].aggregate_matrix.assert_not_called()
                result = json.loads(next(self.evidence.glob("runner-RTM-099-*-result.json")).read_text())
                self.assertIs(result["fullAcceptance"], False)
                self.assertNotIn("aggregate", result)
                self.assertEqual(set(result["cases"]), set(cases))
                self.assertEqual(result["cases"][case], self.reports[case])
                for outcome in retained: outcome.close.assert_called_once_with()

    def test_build_selection_both_ack_kinds_and_mixed_cells_get_no_extra_ack_args(self):
        selections = [("RTM-098", ["normal", ACK["ACK_CASE"], "admitted-queued"], ACK["ACK_CASE"]),
            ("RTM-099", ["normal", *CASES, "vm-two-volume-drain-reply-gap"], ACK_CASE),
            ("RTM-099", [*vm.CASES, "normal", "vm-two-volume-drain-reply-gap"], None),
            ("RTM-098", None, None), ("RTM-103", None, None)]
        for index, (rtm, cases, ack_case) in enumerate(selections):
            self.evidence = self.base / f"build-{index}"
            self.mock_main_work()
            self.assertEqual(self.run_main(rtm, cases), 0)
            expected = [call(self.evidence / "probe")]
            if ack_case: expected.append(call(self.evidence / "ack-probe", active_ack=True))
            self.assertEqual(self.ns["build_probe"].call_args_list, expected)
            calls = self.ns["run_cell"].call_args_list
            self.assertEqual([c.args for c in calls], [(rtm, c) for c in (cases or self.ns["CAMPAIGNS"][rtm])])
            for invocation in calls:
                if invocation.args[1] == ack_case:
                    self.assertEqual(invocation.kwargs["ack_probe"], self.probe)
                    self.assertEqual(invocation.kwargs["ack_probe_sha256"], self.pin)
                else:
                    self.assertNotIn("ack_probe", invocation.kwargs)
                    self.assertNotIn("ack_probe_sha256", invocation.kwargs)
            self.ns["matrix"].aggregate_matrix.assert_not_called()

    def test_serialized_addon_reports_never_become_default_matrix_outcomes(self):
        for report in self.reports.values():
            with self.assertRaises(ValueError):
                ACK["matrix"].aggregate_matrix([copy.deepcopy(report) for _ in range(9)], "RTM-099")
            self.ns["fixture"].run_restart_matrix_shard.return_value = report
            with self.assertRaisesRegex(ValueError, "live MatrixOutcome"):
                self.ns["run_cell"]("RTM-099", "normal", **self.args)
        # Even a mocked caller cannot obtain full acceptance by returning nine
        # serialized addon receipts for the nine default matrix selectors.
        self.mock_main_work()
        self.ns["run_cell"].return_value = self.reports[ACK_CASE]
        self.ns["matrix"].aggregate_matrix = ACK["matrix"].aggregate_matrix
        with self.assertRaises(ValueError): self.run_main("RTM-099")
        result = json.loads(next(self.evidence.glob("runner-RTM-099-*-result.json")).read_text())
        self.assertIs(result["fullAcceptance"], False)
        self.assertNotIn("aggregate", result)
        self.ns["build_probe"].assert_called_once_with(self.evidence / "probe")


if __name__ == "__main__":
    unittest.main()
