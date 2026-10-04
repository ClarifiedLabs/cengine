#!/usr/bin/env python3
"""Engine-free parent routing checks; synthetic ledgers are not native evidence."""
from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
ACK = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-active-ack.py"))
p = ACK["p"]
import managed_prepare_io_faults as io


class APIReparentTests(unittest.TestCase):
    def setUp(self):
        self.matrix, self.harness = ACK["matrix"], ACK["harness"]
        self.api = self.harness.RuntimeProcess(100, executable="/fixture/cengine", arguments=("cengine", "daemon"),
            identity=(1000, 1, 10), pidversion=20, parent_pid=99)
        self.storage = replace(self.api, pid=101, identity=(1000, 2, 11), pidversion=21,
            arguments=("cengine", "storage"), parent_pid=self.api.pid)
        self.workload = replace(self.storage, pid=102, identity=(1000, 3, 12), pidversion=22,
            arguments=("cengine", "workload"))
        self.other = replace(self.storage, pid=103, identity=(1000, 4, 13), pidversion=23, parent_pid=88)
        self.before = [self.api, self.storage, self.workload, self.other]
        self.after = [replace(self.storage, parent_pid=1), replace(self.workload, parent_pid=1), self.other]
        self.daemon = SimpleNamespace(process=SimpleNamespace(pid=self.api.pid, returncode=-signal.SIGKILL))
        self.record = Mock(side_effect=lambda phase, **fields: p.canonical(dict(phase=phase, **fields)))

    def refresh(self, after=None, **kwargs):
        return self.matrix._api_exit_survivors(self.daemon, self.api, self.before,
            self.after if after is None else after, self.record, **kwargs)

    def test_joined_api_children_refresh_and_later_checks_remain_strict(self):
        original = list(self.before)
        with patch.object(self.harness, "_kernel_process", return_value=None):
            refreshed = self.refresh()
        self.assertEqual(self.before, original)
        self.assertEqual(refreshed, [self.api, *self.after])
        self.assertIs(refreshed[1], self.after[0])
        self.assertNotEqual(self.storage, self.after[0])  # Global equality is unchanged.
        with self.assertRaises(ValueError):
            self.matrix.unchanged_processes(self.before, self.after, self.api)
        self.matrix.unchanged_processes(refreshed, self.after, self.api)
        with self.assertRaises(ValueError):
            self.matrix.unchanged_processes(refreshed, [replace(self.after[0], parent_pid=88), *self.after[1:]], self.api)
        phase, = self.record.call_args.args
        self.assertEqual(phase, "matrix-api-survivors-observed")
        self.assertNotIn("exitedWorkload", self.record.call_args.kwargs)
        evidence = self.record.call_args.kwargs["survivors"]
        self.assertEqual(len(evidence), 3)
        self.assertEqual(evidence[0]["before"]["parentPID"], self.api.pid)
        self.assertEqual(evidence[0]["after"]["parentPID"], 1)
        self.assertEqual(evidence[0]["before"]["birth"], evidence[0]["after"]["birth"])
        self.assertEqual(evidence[2]["before"], evidence[2]["after"])
        self.assertEqual(evidence[0]["after"]["argumentsSHA256"], p.digest(p.canonical(list(self.storage.arguments))))

    def test_no_refresh_without_positive_joined_exact_api_exit(self):
        for code, pid, observed in ((None, 100, None), (0, 100, None), (-signal.SIGTERM, 100, None),
                                    (-signal.SIGKILL, 999, None), (-signal.SIGKILL, 100, self.api)):
            with self.subTest(code=code, pid=pid, observed=observed):
                self.daemon.process.returncode, self.daemon.process.pid = code, pid
                with patch.object(self.harness, "_kernel_process", return_value=observed), self.assertRaises(ValueError):
                    self.refresh()
                self.record.assert_not_called()

    def test_every_other_field_change_and_wrong_parent_refused(self):
        changes = dict(pid=999, command="changed", executable="/other/cengine", arguments=("different",),
            pidversion=99, parent_pid=88)
        mutations = [replace(self.after[0], **{key: value}) for key, value in changes.items()]
        mutations += [replace(self.after[0], identity=identity) for identity in
                      ((1001, 2, 11), (1000, 3, 11), (1000, 2, 99), None)]
        with patch.object(self.harness, "_kernel_process", return_value=None):
            for changed in mutations:
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    self.refresh([changed, *self.after[1:]])
            for parent in (1, self.api.pid, None):
                with self.subTest(unrelated_parent=parent), self.assertRaises(ValueError):
                    self.refresh([*self.after[:2], replace(self.other, parent_pid=parent)])
        self.record.assert_not_called()

    def test_exact_unchanged_survivors_allowed_but_missing_extra_duplicates_refused(self):
        with patch.object(self.harness, "_kernel_process", return_value=None):
            self.assertEqual(self.refresh(self.before[1:]), self.before)
            for after in (self.after[1:], [*self.after, self.api], [*self.after, self.other],
                          [*self.after, replace(self.other, pid=999)]):
                with self.subTest(after=after), self.assertRaises(ValueError): self.refresh(after)
            for before in ([*self.before, self.other], self.before[1:]):
                with self.subTest(before=before), self.assertRaises(ValueError):
                    self.matrix._api_exit_survivors(self.daemon, self.api, before, self.after, self.record)

    def test_restart_api_refreshes_storage_workload_and_census_only_after_kill(self):
        for early_reparent in (False, True):
            with self.subTest(early_reparent=early_reparent), ExitStack() as patches:
                stage = "before"
                fresh_api = replace(self.api, pid=200, identity=(2000, 1, 20), pidversion=30)
                def processes():
                    if stage == "before":
                        return [self.api, *self.after] if early_reparent else self.before
                    return ([fresh_api] if stage == "ready" else []) + self.after
                def kernel(pid):
                    return next((v for v in processes() if v.pid == pid), None)
                def stop(*, kill):
                    nonlocal stage
                    self.assertTrue(kill)
                    self.assertEqual(stage, "before")
                    stage = "killed"
                    self.daemon.process.returncode = -signal.SIGKILL
                def restart(daemon, api, workload, live, no_early_exit, record, remaining, phase):
                    nonlocal stage
                    self.assertEqual(stage, "killed")
                    self.assertEqual(workload, self.after[1])
                    self.assertTrue(live)
                    self.assertTrue(no_early_exit)
                    stage = "ready"
                    return fresh_api, False
                self.daemon.process.returncode = None
                self.daemon.stop = Mock(side_effect=stop)
                self.daemon.root, self.daemon.work, self.daemon.binary = map(Path, ("/fixture/root", "/fixture", "/fixture/cengine"))
                directory = Mock()
                directory.__enter__ = Mock(return_value=directory)
                directory.__exit__ = Mock(return_value=False)
                directory.read.return_value = (b"/fixture/cengine", None)
                owner = {"root": {"device": 1, "inode": 2}}
                selected = dict(caseName="normal", profile=p.FULL_PROFILE, version=3, scope={})
                replacements = ((self.matrix, "validate_checkpoint", None),
                    (self.matrix, "prefault_intent", "running"),
                    (self.matrix.lifecycle, "read_owner", ({}, "owner-hash")),
                    (self.matrix, "owner_context", (owner, {})),
                    (self.matrix, "storage_target", self.storage),
                    (self.matrix, "api_target", self.api),
                    (self.matrix, "sdk_versions", {}),
                    (self.matrix, "api_owner_transition", {}),
                    (self.matrix, "recovered_intent", {}),
                    (p, "verify_full_ledger", None), (self.matrix.os, "fstat", None))
                for target, name, result in replacements:
                    patches.enter_context(patch.object(target, name, return_value=result))
                directory_type = patches.enter_context(patch.object(p, "Directory", return_value=directory))
                directory_type.stamp.return_value = (1, 2)
                patches.enter_context(patch.object(self.harness, "_kernel_process", side_effect=kernel))
                observer = patches.enter_context(patch.object(self.matrix, "_restart_api_observing", side_effect=restart))
                args = (self.daemon, self.workload, self.before, {}, selected, {"armDigest": "arm"},
                    None, None, self.record, processes, Mock(), Mock(wait=Mock(return_value=0), returncode=0),
                    Mock(return_value=({}, {}, {})))
                if early_reparent:
                    with self.assertRaisesRegex(ValueError, "unchanged complete census"):
                        self.matrix.restart_api(*args)
                    self.daemon.stop.assert_not_called()
                    observer.assert_not_called()
                else:
                    result = self.matrix.restart_api(*args)
                    self.assertEqual(result[0], [fresh_api, *self.after])
                    self.assertEqual(result[3:], ("settled-success", False))
                    self.daemon.stop.assert_called_once_with(kill=True)
                    observer.assert_called_once()

    def test_restart_storage_refreshes_only_joined_api_survivors_and_exact_replacement_tail(self):
        scenarios = ('reparented', 'unchanged', 'natural-absent', 'natural-exits', 'early-reparent',
                     'wrong-parent', 'changed-birth', 'changed-arguments', 'missing-peer', 'extra-peer',
                     'held-absent', 'reused-workload', 'api-not-killed')
        for scenario in scenarios:
            with self.subTest(scenario=scenario), ExitStack() as patches:
                self.record.reset_mock()
                stage = 'before'
                fresh_api = replace(self.api, pid=200, identity=(2000, 1, 20), pidversion=30)
                fresh_storage = replace(self.storage, pid=201, identity=(2000, 2, 21), pidversion=31, parent_pid=200)
                natural = scenario.startswith('natural')
                absent = scenario in ('natural-absent', 'natural-exits', 'held-absent')
                post_workload = self.workload if scenario == 'unchanged' else replace(self.workload, parent_pid=1)
                peer = self.other
                if scenario == 'wrong-parent': post_workload = replace(post_workload, parent_pid=88)
                if scenario in ('changed-birth', 'reused-workload'):
                    post_workload = replace(post_workload, identity=(3000, 1, 1), pidversion=99)
                if scenario == 'changed-arguments': post_workload = replace(post_workload, arguments=('changed',))
                def processes():
                    if stage == 'before':
                        if scenario == 'early-reparent': return [self.api, *self.after]
                        return [v for v in self.before if not (scenario == 'natural-absent' and v == self.workload)]
                    if stage == 'storage-dead':
                        return [v for v in self.before if v != self.storage and not (scenario == 'natural-absent' and v == self.workload)]
                    if stage == 'ready': return [fresh_api, fresh_storage, peer]
                    rows = ([] if absent else [post_workload]) + ([] if scenario == 'missing-peer' else [peer])
                    if scenario == 'extra-peer': rows.append(replace(peer, pid=999))
                    return rows
                def kernel(pid):
                    return next((v for v in processes() if v.pid == pid), None)
                delivery = dict(signal='SIGKILL', transport='audit-token', pid=self.storage.pid, pidversion=self.storage.pidversion)
                def signal_storage(selected):
                    nonlocal stage
                    self.assertEqual(selected, self.storage)
                    self.assertEqual(stage, 'before')
                    stage = 'storage-dead'
                    return delivery
                def stop(*, kill):
                    nonlocal stage
                    self.assertTrue(kill)
                    self.assertEqual(stage, 'storage-dead')
                    stage = 'killed'
                    self.daemon.process.returncode = 0 if scenario == 'api-not-killed' else -signal.SIGKILL
                def restart(daemon, api, workload, live, no_early_exit, record, remaining, phase):
                    nonlocal stage
                    self.assertEqual(stage, 'killed')
                    self.assertEqual(workload, self.workload if absent else post_workload)
                    self.assertEqual(live, not absent)
                    self.assertEqual(no_early_exit, not natural)
                    stage = 'ready'
                    return fresh_api, False
                self.daemon.process.returncode = None
                self.daemon.stop = Mock(side_effect=stop)
                self.daemon.root, self.daemon.work, self.daemon.binary = map(Path, ('/fixture/root', '/fixture', '/fixture/cengine'))
                self.daemon.storage_initramfs = Path('/fixture/initramfs')
                directory = Mock()
                directory.__enter__ = Mock(return_value=directory)
                directory.__exit__ = Mock(return_value=False)
                directory.read.return_value = (b'/fixture/cengine', None)
                owner = {'root': {'device': 1, 'inode': 2}}
                selected = dict(caseName='data-partial-frame' if natural else 'first-child-published',
                    profile=p.FULL_PROFILE, version=3, scope={'intent': 'intent'})
                state = dict(intents={'intent': dict(phase='retired', slots=[])})
                replacements = ((self.matrix, 'validate_checkpoint', None), (self.matrix, 'prefault_intent', 'quarantined'),
                    (self.matrix.lifecycle, 'read_owner', ({}, 'owner-hash')), (self.matrix, 'owner_context', (owner, {})),
                    (self.matrix.lifecycle, 'is_v2', True), (self.matrix.lifecycle, 'asset_digest', 'a' * 64),
                    (self.matrix, 'api_target', self.api), (self.matrix, 'sdk_versions', {}),
                    (self.matrix, 'storage_owner_transition', {}), (p, 'verify_full_ledger', None), (self.matrix.os, 'fstat', None))
                for target, name, result in replacements:
                    patches.enter_context(patch.object(target, name, return_value=result))
                directory_type = patches.enter_context(patch.object(p, 'Directory', return_value=directory))
                directory_type.stamp.return_value = (1, 2)
                patches.enter_context(patch.object(self.harness, '_kernel_process', side_effect=kernel))
                signal_mock = patches.enter_context(patch.object(self.matrix, 'signal_storage', side_effect=signal_storage))
                patches.enter_context(patch.object(self.matrix, 'storage_target', side_effect=[self.storage, fresh_storage]))
                observer = patches.enter_context(patch.object(self.matrix, '_restart_api_observing', side_effect=restart))
                refresh = patches.enter_context(patch.object(self.matrix, '_api_exit_survivors', wraps=self.matrix._api_exit_survivors))
                event = SimpleNamespace(ident=self.storage.pid, filter=self.matrix.select.KQ_FILTER_PROC,
                    flags=0, fflags=self.matrix.select.KQ_NOTE_EXIT)
                queue = Mock(); queue.control.side_effect = [[], [event]]
                patches.enter_context(patch.object(self.matrix.select, 'kqueue', return_value=queue))
                start = Mock(poll=Mock(return_value=None), wait=Mock(return_value=52), returncode=52)
                args = (self.daemon, self.workload, self.before, {}, selected, {'armDigest': 'arm'},
                    None, None, self.record, processes, Mock(return_value=1), start,
                    Mock(return_value=({}, state, {})), 'a' * 64)
                if scenario not in ('reparented', 'unchanged', 'natural-absent', 'natural-exits'):
                    with self.assertRaises(ValueError): self.matrix.restart_storage(*args)
                    observer.assert_not_called()
                    if scenario == 'early-reparent':
                        signal_mock.assert_not_called(); self.daemon.stop.assert_not_called(); refresh.assert_not_called()
                    if scenario == 'api-not-killed': refresh.assert_not_called()
                    continue
                result = self.matrix.restart_storage(*args)
                historical_workload = self.workload if absent else post_workload
                self.assertEqual(result[0], [fresh_api, fresh_storage, historical_workload, peer])
                self.assertEqual(result[3:], ('interrupted', True))
                self.assertEqual(refresh.call_args.args[2], [self.api, self.workload, peer])
                self.assertEqual(refresh.call_args.kwargs, {'exited_workload': self.workload if absent else None})
                signal_mock.assert_called_once_with(self.storage)
                self.daemon.stop.assert_called_once_with(kill=True)
                evidence = {call.args[0]: call.kwargs for call in self.record.call_args_list}
                self.assertEqual(evidence['matrix-storage-SIGKILL-delivered']['proof'], delivery)
                survivor_evidence = evidence['matrix-api-survivors-observed']
                self.assertNotIn(self.storage.pid, [row['before']['pid'] for row in survivor_evidence['survivors']])
                self.assertEqual('exitedWorkload' in survivor_evidence, absent)
                self.assertNotEqual(self.workload, replace(self.workload, parent_pid=1))

    def test_naturally_exited_workload_is_not_fabricated_survivor_evidence(self):
        with patch.object(self.harness, "_kernel_process", return_value=None):
            refreshed = self.refresh([self.after[0], self.other], exited_workload=self.workload)
        self.assertEqual(refreshed, [self.api, self.after[0], self.workload, self.other])
        evidence = self.record.call_args.kwargs
        self.assertEqual(evidence["exitedWorkload"], p.native_proof(self.workload))
        self.assertEqual([row["after"]["pid"] for row in evidence["survivors"]], [101, 103])
        for observed in (self.workload, replace(self.workload, identity=(1001, 5, 99), pidversion=99)):
            with patch.object(self.harness, "_kernel_process", side_effect=[None, observed]), self.assertRaises(ValueError):
                self.refresh([self.after[0], self.other], exited_workload=self.workload)


class FullRunnerTests(unittest.TestCase):
    def setUp(self):
        self.support = ACK["ActiveACKRunnerTests"]()
        self.support.setUp()
        self.addCleanup(self.support.doCleanups)
        self.ns = self.support.ns
        # Routing tests stay engine-free; admission is exercised separately below.
        self.ns["admit_environment"] = Mock(return_value=self.support.probe)
        self.outcomes = []

    def outcome(self, case):
        directory = self.support.base / f"ledger-{uuid.uuid4()}"
        directory.mkdir(mode=0o700)
        row = dict(profile=p.FULL_PROFILE, caseName=case, runID=str(uuid.uuid4()), store=str(uuid.uuid4()),
                   result="case-passed", evidenceSHA256=p.digest(p.canonical([])),
                   execution="actual-docker-runtime", fullAcceptance=False)
        with p.Directory(directory) as ledger:
            ledger.publish("001-result.json", dict(phase="full-case-result", **row))
            outcome = p._completed_full_outcome(row, ledger, {"001-result.json": ledger.read("001-result.json")})
        self.addCleanup(outcome.close)
        self.outcomes.append(outcome)
        return outcome

    def test_full_campaign_dispatches_all_nine_to_preserved_fixture_and_validates(self):
        self.assertEqual(self.ns["selected_cases"]("RTM-096"), list(p.FULL_CASES))
        for case in p.FULL_CASES:
            with self.subTest(case=case):
                outcome = self.outcome(case)
                self.ns["fixture"].reset_mock()
                self.ns["fixture"].run_full_shard.return_value = outcome
                with patch.object(p.FullOutcome, "validate", autospec=True, return_value=outcome.receipt) as validate:
                    self.assertIs(self.ns["run_cell"]("RTM-096", case, **self.support.args), outcome)
                    validate.assert_called_once_with(outcome)
                call = self.ns["fixture"].run_full_shard.call_args
                self.assertEqual(call.args, (self.support.daemon,))
                self.assertEqual(call.kwargs, dict(profile=p.FULL_PROFILE, cases=p.FULL_CASES, fault_case=case,
                    probe=self.support.args["probe"], probe_sha256="a" * 64, source_sha256="b" * 64,
                    expected_commit="c0ffee0", evidence=call.kwargs["evidence"]))
                self.assertEqual(call.kwargs["evidence"].parent, self.support.evidence)
                self.assertEqual(len(self.ns["fixture"].mock_calls), 1)

    def test_receipts_wrong_types_and_nonlive_outcomes_fail_closed(self):
        live = self.outcome("normal")
        for invalid in (live.receipt, Mock(), object.__new__(p.FullOutcome)):
            self.ns["fixture"].run_full_shard.return_value = invalid
            with self.assertRaises(ValueError):
                self.ns["run_cell"]("RTM-096", "normal", **self.support.args)
        self.ns["harness"].release_compatibility_root.assert_not_called()
        self.ns["harness"].remove_compatibility_root.assert_not_called()
        self.assertEqual(self.support.daemon.stop.call_count, 3)

    def run_main(self, cases=None, fail=None, continuing=False):
        self.support.mock_main_work()
        def cell(rtm, case, **kwargs):
            if case == fail:
                raise ValueError("failed cell")
            return self.outcome(case)
        self.ns["run_cell"] = Mock(side_effect=cell)
        selected = list(cases or p.FULL_CASES)
        if continuing:
            # The helper appends each entry as a --case argument; supply the
            # continuation flag directly through its argv patch instead.
            original = self.ns["main"]
            def main():
                with patch.object(ACK["sys"], "argv", [*ACK["sys"].argv, "--continue-on-failure"]):
                    return original()
            self.ns["main"] = main
        with patch.object(p, "aggregate_full", wraps=p.aggregate_full) as aggregate:
            code = self.support.run_main("RTM-096", cases)
            self.assertEqual([c.args[1] for c in self.ns["run_cell"].call_args_list], selected)
            if len(selected) == 9 and fail is None:
                aggregate.assert_called_once_with(self.outcomes)
            else:
                aggregate.assert_not_called()
        self.ns["matrix"].aggregate_matrix.assert_not_called()
        self.ns["build_probe"].assert_called_once_with(self.support.evidence / "probe")
        for outcome in self.outcomes:
            with self.assertRaises(ValueError): outcome.validate()
        result = json.loads(next(self.support.evidence.glob("runner-RTM-096-*-result.json")).read_text())
        return code, result

    def test_only_nine_live_outcomes_aggregate(self):
        code, result = self.run_main()
        self.assertEqual(code, 0)
        self.assertTrue(result["fullAcceptance"])
        self.assertEqual(result["aggregate"]["coverage"], "9/9")
        self.assertEqual(set(result["cases"]), set(p.FULL_CASES))

    def test_partial_normal_a4_never_aggregate(self):
        code, result = self.run_main(["normal", "full-frame-before-admit"])
        self.assertEqual(code, 0)
        self.assertFalse(result["fullAcceptance"])
        self.assertNotIn("aggregate", result)

    def test_continued_failed_cell_never_aggregates(self):
        code, result = self.run_main(fail="full-frame-before-admit", continuing=True)
        self.assertEqual(code, 1)
        self.assertFalse(result["fullAcceptance"])
        self.assertNotIn("aggregate", result)
        self.assertIn("full-frame-before-admit", result["failures"])

    def test_fail_fast_never_aggregates_and_closes_previous_outcomes(self):
        with patch.object(p, "aggregate_full") as aggregate, self.assertRaisesRegex(ValueError, "failed cell"):
            self.run_main(fail="full-frame-before-admit")
        aggregate.assert_not_called()
        for outcome in self.outcomes:
            with self.assertRaises(ValueError): outcome.validate()


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.ns = ACK["runner_namespace"]()
        self.ns["REPO_ROOT"] = self.root
        self.assets = self.root / "assets"
        self.evidence = self.root / "evidence"
        self.calls = self.root / "calls"
        scripts = self.root / "Scripts"
        scripts.mkdir()
        # Reuse the real constants, but never run native validation in this test.
        # The stub asserts the exact subprocess inputs and pre-evidence ordering.
        helper = (ROOT / "Scripts/compat-network-helper.sh").read_text()
        helper += '''
compat_network_helper_require() {
    [ "$ROOT" = "$EXPECTED_ROOT" ] &&
    [ "$1" = "$EXPECTED_BINARY" ] && [ "$CENGINE_BINARY" = "$EXPECTED_BINARY" ] &&
    [ "$2" = "$CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT" ] &&
    [ "$CENGINE_COMPAT_MANAGED_ASSET_DIR" = "$EXPECTED_ROOT/assets" ] &&
    [ "$CENGINE_COMPAT_REQUIRE_EXACT_HELPER" = 1 ] &&
    [ "$PREPARE_COMPATIBILITY_PROFILE" = rtm096-full-nine-v3 ] &&
    [ "$CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY" = rtm096-full-nine-v3 ] &&
    [ ! -e "$EXPECTED_ROOT/evidence" ] || return 91
    printf '%s:%s\\n' "$1" "$2" >> "$EXPECTED_ROOT/calls"
    compat_network_helper_validate_fingerprint "$2" || return $?
    [ "$2" = "$EXPECTED_FINGERPRINT" ] || return 92
    return "${VALIDATION_STATUS:-0}"
}
'''
        (scripts / "compat-network-helper.sh").write_text(helper)
        self.ns.update(asset_metadata=Mock(return_value={"prepareCompatibilitySourceSHA256": "b" * 64}),
            build_probe=Mock(return_value=(self.root / "probe", "a" * 64)),
            expected_commit=Mock(return_value="c0ffee0"), prepare_descriptor_budget=Mock(return_value=2048),
            run_cell=Mock(return_value={}))
        self.env = dict(PATH=os.environ["PATH"],
            CENGINE_DEVELOPER_ID_APPLICATION="Developer ID Application: fixture",
            PREPARE_COMPATIBILITY_PROFILE=p.FULL_PROFILE,
            CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY=p.FULL_PROFILE,
            CENGINE_COMPAT_REQUIRE_EXACT_HELPER="1", CENGINE_COMPAT_MANAGED_ASSET_DIR=str(self.assets),
            CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT="a" * 64,
            CENGINE_NETWORK_HELPER_SERVICE_NAME="dev.cengine.network-helper.test-compat",
            CENGINE_NETWORK_HELPER_IDENTIFIER="dev.cengine.network-helper.test-compat",
            CENGINE_COMPAT_NETWORK_HELPER_LABEL="dev.cengine.network-helper.test-compat",
            CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE="/Library/Application Support/cengine/compat/dev.cengine.network-helper.test-compat/client-token",
            EXPECTED_ROOT=str(self.root), EXPECTED_FINGERPRINT="a" * 64)
        self.select_binary()

    def select_binary(self, derived=None):
        directory = self.root / (derived or ".build/xcode-derived")
        binary = directory / "Build/Products/test-compat/cengine"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.touch()
        self.env.update(CENGINE_BINARY=str(binary), EXPECTED_BINARY=str(binary))
        if derived is not None:
            self.env["XCODE_DERIVED_DATA"] = str(derived)
        return binary

    def run_main(self, env, rtm="RTM-096", case="normal"):
        argv = ["runner", "--rtm", rtm, "--case", case, "--assets", str(self.assets),
                "--evidence", str(self.evidence)]
        with patch.dict(os.environ, env, clear=True), patch.object(ACK["sys"], "argv", argv):
            return self.ns["main"]()

    def assert_no_work(self):
        self.assertFalse(self.evidence.exists())
        for name in ("asset_metadata", "build_probe", "expected_commit", "run_cell"):
            self.ns[name].assert_not_called()

    def test_direct_minimal_environment_rejected_before_validation_probe_or_evidence(self):
        minimal = {key: self.env[key] for key in ("CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT", "CENGINE_BINARY")}
        with self.assertRaises(ValueError):
            self.run_main(minimal)
        self.assert_no_work()
        self.assertFalse(self.calls.exists())

    def test_missing_or_mixed_selections_rejected_before_validation(self):
        changes = [{key: value} for key, value in (
            ("CENGINE_COMPAT_MANAGED_STORAGE", "0"), ("CENGINE_COMPAT_SHARED_STORAGE", ""),
            ("CENGINE_DEVELOPER_ID_APPLICATION", ""), ("PREPARE_COMPATIBILITY_PROFILE", ""),
            ("CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY", "rtm096-normal-a7-v1"),
            ("CENGINE_COMPAT_REQUIRE_EXACT_HELPER", ""), ("CENGINE_COMPAT_REQUIRE_EXACT_HELPER", "0"),
            ("CENGINE_STORAGE_LIFECYCLE_QUALIFICATION", "lifecycle-v2-native-v1"),
            ("CENGINE_COMPAT_LIFECYCLE_FAULT", "before-configure-v1"),
            ("XCODE_COMPAT_CONFIGURATION", "Debug"), ("CENGINE_BINARY", str(self.root / "other")),
            ("CENGINE_BINARY", ""), ("CENGINE_COMPAT_MANAGED_ASSET_DIR", str(self.root / "other-assets")),
            ("CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT", ""))]
        changes += [{key: ""} for key in ("CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY",
                                         "CENGINE_COMPAT_MANAGED_ASSET_DIR")]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.run_main({**self.env, **change})
            self.assert_no_work()
            self.assertFalse(self.calls.exists())

    def test_helper_validation_failure_and_fingerprint_mismatch_precede_evidence(self):
        for change in ({"VALIDATION_STATUS": "1"}, {"CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT": "b" * 64},
                       {"CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT": "not-a-fingerprint"},
                       {"CENGINE_NETWORK_HELPER_SERVICE_NAME": "other-helper"}):
            with self.subTest(change=change), self.assertRaises(subprocess.CalledProcessError):
                self.run_main({**self.env, **change})
            self.assert_no_work()

    def test_io_has_no_helper_or_lifecycle_environment_bypass(self):
        for change in ({"CENGINE_COMPAT_SHARED_STORAGE": ""}, {"CENGINE_COMPAT_REQUIRE_EXACT_HELPER": "0"},
                       {"CENGINE_DEVELOPER_ID_APPLICATION": ""}, {"CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT": ""}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.run_main({**self.env, **change}, "RTM-100", io.CASES[0])
            self.assert_no_work()
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_main({**self.env, "VALIDATION_STATUS": "1"}, "RTM-100", io.CASES[0])
        self.assert_no_work()
        self.assertEqual(self.run_main(self.env, "RTM-100", io.CASES[0]), 0)
        self.assertEqual(self.ns["run_cell"].call_args.args, ("RTM-100", io.CASES[0]))

    def test_standard_and_custom_derived_admitted_only_after_exact_validation(self):
        for derived in (None, ".build/custom derived", str(self.root / "absolute derived")):
            with self.subTest(derived=derived):
                binary = self.select_binary(derived)
                self.assertEqual(self.run_main(self.env), 0)
                self.assertEqual(self.calls.read_text().splitlines()[-1], f"{binary}:{'a' * 64}")
                self.assertEqual(self.ns["run_cell"].call_args.kwargs["binary"], binary)
                shutil.rmtree(self.evidence)
        self.assertEqual(len(self.calls.read_text().splitlines()), 3)


class WrapperBinaryTests(unittest.TestCase):
    def run_wrapper(self, changes, *, shadow_xcodebuild=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            scripts = root / "Scripts"
            scripts.mkdir()
            (root / "tools").mkdir()
            wrapper = root / "tools/managed-prepare-matrix.sh"
            shutil.copyfile(ROOT / "tools/managed-prepare-matrix.sh", wrapper)
            # Exercise real claim receipts/release, but never discover or touch
            # the host claim or query native process identity in this sandbox.
            compatibility = root / "Tests/Compatibility"
            compatibility.mkdir(parents=True)
            shutil.copyfile(ROOT / "Tests/Compatibility/helper_fixture_lifetime.py",
                            compatibility / "_real_lifetime.py")
            (compatibility / "harness.py").write_text(
                'from types import SimpleNamespace\n'
                '_kernel_process = lambda pid: SimpleNamespace(identity=(1, 2, 3), pidversion=4)\n'
            )
            (compatibility / "helper_fixture_lifetime.py").write_text(
                'import os, sys\nfrom pathlib import Path\nimport _real_lifetime as real\n'
                'real.launcher_lock = lambda: Path(os.environ["MOCK_CANONICAL_LOCK"])\n'
                'real.main(sys.argv[1:])\n'
            )
            # Use the real preparation runner's path-resolution block, not an
            # independently invented default; everything executable is stubbed.
            source = (ROOT / "Scripts/run-compat-tests.sh").read_text()
            resolution = source[source.index("XCODE_PROJECT=${XCODE_PROJECT:-cengine.xcodeproj}"):
                                source.index("if [ -n \"$CENGINE_STORAGE_LIFECYCLE_QUALIFICATION\" ]; then", source.index("CENGINE_BINARY=$BINARY"))]
            prep = '#!/bin/sh\nset -eu\nROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\n' + resolution
            prep += '[ "$XCODEBUILD" = /usr/bin/xcodebuild ]\n'
            prep += 'printf "prep:%s:%s\\n" "$BINARY" "$XCODE_DERIVED_DATA" >> "$CALLS"\nexit 5\n'
            files = {
                "Scripts/run-compat-tests.sh": prep,
                "Scripts/compat-network-helper.sh": 'compat_network_helper_require() { printf "helper:%s\\n" "$1" >> "$CALLS"; }\n',
                "Scripts/network-helper-fingerprint.sh": '#!/bin/sh\nprintf fingerprint\n',
                ".build/compat-venv/bin/python": '#!/bin/sh\nprintf "run:%s\\n" "$CENGINE_BINARY" >> "$CALLS"\n',
                "Scripts/reset-compat-runtime.py": 'import os, sys\nwith open(os.environ["CALLS"], "a") as log: log.write("cleanup:" + sys.argv[2] + "\\n")\n',
            }
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                path.chmod(0o755)
            env = {k: v for k, v in os.environ.items() if not k.startswith(("CENGINE_", "XCODE_", "PREPARE_")) and k != "XCODEBUILD"}
            env.update(CENGINE_DEVELOPER_ID_APPLICATION="stub", CENGINE_GIT_COMMIT="fixture", CENGINE_BUILD_TIME="fixture",
                       CENGINE_COMPAT_LOCK=str(root / "lock"), MOCK_CANONICAL_LOCK=str(root / "lock"),
                       CALLS=str(root / "calls"))
            env.update(changes)
            if shadow_xcodebuild:
                shim = root / "bin/xcodebuild"
                shim.parent.mkdir()
                shim.write_text('#!/bin/sh\nexit 99\n')
                shim.chmod(0o755)
                env["PATH"] = str(shim.parent) + os.pathsep + env["PATH"]
            result = subprocess.run(["/bin/sh", str(wrapper), "--rtm", "RTM-096", "--case", "normal"],
                                    env=env, text=True, capture_output=True)
            calls = (root / "calls").read_text().splitlines() if (root / "calls").exists() else []
            return root, result, calls

    def test_default_and_relative_and_absolute_custom_derived_used_everywhere(self):
        for derived in (None, ".build/custom derived", "/tmp/custom-derived"):
            with self.subTest(derived=derived):
                root, result, calls = self.run_wrapper({} if derived is None else {"XCODE_DERIVED_DATA": derived})
                self.assertEqual(result.returncode, 0, result.stderr)
                directory = (root / (derived or ".build/xcode-derived")).resolve()
                binary = directory / "Build/Products/test-compat/cengine"
                self.assertEqual(calls, [f"prep:{binary}:{directory}", f"helper:{binary}", f"run:{binary}", f"cleanup:{binary}"])

    def test_other_build_producers_rejected_before_preparation(self):
        for change in ({"XCODEBUILD": "/tmp/other-xcodebuild"}, {"XCODE_PROJECT": "other.xcodeproj"},
                       {"XCODE_COMPAT_SCHEME": "cengine"}, {"XCODE_COMMON_FLAGS": "OTHER_SWIFT_FLAGS=-DOTHER"}):
            with self.subTest(change=change):
                _, result, calls = self.run_wrapper(change)
                self.assertEqual(result.returncode, 2)
                self.assertIn("standard XCODEBUILD, project, scheme and common flags", result.stderr)
                self.assertEqual(calls, [])

    def test_path_shadowed_xcodebuild_rejected_before_preparation(self):
        _, result, calls = self.run_wrapper({}, shadow_xcodebuild=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("standard XCODEBUILD", result.stderr)
        self.assertEqual(calls, [])

    def test_explicit_standard_build_producer_accepted(self):
        for producer in ("xcodebuild", "/usr/bin/xcodebuild"):
            with self.subTest(producer=producer):
                _, result, calls = self.run_wrapper(dict(XCODEBUILD=producer, XCODE_PROJECT="cengine.xcodeproj",
                    XCODE_COMPAT_SCHEME="test-compat", XCODE_COMMON_FLAGS="-skipPackagePluginValidation -skipMacroValidation ENABLE_CODE_COVERAGE=NO CLANG_COVERAGE_MAPPING=NO"))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 4)

    def test_arbitrary_binary_or_weaker_configuration_rejected_before_preparation(self):
        for change in ({"CENGINE_BINARY": "/tmp/arbitrary-cengine"}, {"XCODE_COMPAT_CONFIGURATION": "Debug"}):
            with self.subTest(change=change):
                _, result, calls = self.run_wrapper(change)
                self.assertEqual(result.returncode, 2)
                self.assertIn("derived test-compat binary", result.stderr)
                self.assertEqual(calls, [])


if __name__ == "__main__": unittest.main()
