#!/usr/bin/env python3
"""Engine-free RTM-097/RTM-099 restart-matrix checks; no signals, engines or VMs."""
import ast
import copy
import json
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import managed_prepare_faults as p
import managed_prepare_restart_matrix as m
FIXTURE = ROOT / 'Tests/Compatibility/test_managed_prepare_faults.py'
SERVICE = runpy.run_path(str(ROOT / 'tools/tests/test-managed-prepare-service.py'))
VECTORS = {v['name']: v for v in json.loads((ROOT / 'Guest/internal/preparecompat/testdata/full-vectors.json').read_text())}


V1 = SERVICE['V1']


def fixture_arm(case):
    """Fixture-shaped v3 arm: one volume, two sorted slots, one PREPARE credential."""
    normal, _, _, capture, candidate = V1['values']()
    candidate.update(version=3, profile=p.FULL_PROFILE)
    return p.full_arm_candidate(candidate, capture, {**normal, 'intent': normal['id']}, case)


def arm_and_intent(case, phase='prepareAdmitted'):
    arm = fixture_arm(case)
    intent = {('id' if k == 'intent' else k): v for k, v in arm['scope'].items()}
    slots = copy.deepcopy(arm['slots'])
    for slot in slots:
        slot.update(retireOperation=SERVICE['uid'](), registerOperation=SERVICE['uid']())
        if slot['role'] == 'prepare':
            slot['key'] = next(c['key'] for c in arm['credentials'] if c['attachment'] == slot['attachment'])
    intent.update(phase=phase, prepareCompleted=phase == 'running', slots=slots)
    state = dict(store=arm['scope']['store'], revision=10, intents={intent['id']: intent}, operations={}, operationDigests={})
    return arm, intent, state


def checkpoint_for(arm, worker):
    """One boundary-consistent checkpoint per case, shaped like the live carrier files."""
    case = arm['caseName']
    if case in p.EARLY_COUNTERS:
        sent, accepted, written = p.EARLY_COUNTERS[case]
        return dict(version=3, profile=p.FULL_PROFILE, requestID=arm['requestID'], armDigest=p.digest(p.canonical(arm)), stage=case, count=1,
                    targetAttachment=arm['targetAttachment'], requestSequence=1, prepareCommandsSent=sent, prepareCommandsAccepted=accepted, dataBytesWritten=written)
    if case not in p.STORAGE_CASES:
        value = V1['observed'](arm)
        value.update(version=3, profile=p.FULL_PROFILE, armDigest=p.digest(p.canonical(arm)))
        return value
    query = p.storage_query(arm, worker)
    value = dict(query, stage=case, count=1, targetAttachment=arm['targetAttachment'])
    target = next(s for s in arm['slots'] if s['attachment'] == arm['targetAttachment'])
    if case in p.HELD_STORAGE_CASES:
        value['admission'] = dict(requestSequence=3, admitted=case == 'admitted-queued', releaseToken='7' * 64)
    elif case == 'drain-durable-reply-lost':
        value['drain'] = dict(retireOperation=SERVICE['uid'](), receipt=dict(schema=3, store=arm['scope']['store'], volume=target['volume'],
                              attachment=target['attachment'], launch=arm['scope']['launch'], prepare=arm['scope']['prepare'], revision=11))
    else:
        intent = copy.deepcopy(VECTORS[case]['storageObservation']['bound']['intent'])
        key = next(c['key'] for c in arm['credentials'] if c['attachment'] == target['attachment'])
        intent['owner'] = dict(store=arm['scope']['store'], volume=target['volume'], attachment=target['attachment'], prepare=arm['scope']['prepare'],
                               container=arm['scope']['container'], launch=arm['scope']['launch'], key=key, role='prepare', mode='read-write')
        intent['epoch'] = arm['scope']['serviceEpoch']
        intent['root'].update(store=arm['scope']['store'], volume=target['volume'])
        value['bound'] = dict(requestSequence=3, intent=intent)
    return value


class SelectionTests(unittest.TestCase):
    def test_every_boundary_has_exactly_one_kind_and_closed_variants(self):
        self.assertEqual(set(m.KINDS), set(p.FULL_CASES))
        self.assertEqual(sorted(m.KINDS.values()), sorted(['held-guest'] * 2 + ['held-storage'] * 2 + ['natural'] * 3 + ['successful'] * 2))
        for restart, table in m.VARIANTS.items():
            self.assertEqual(set(table), {'held-guest', 'held-storage', 'natural', 'successful'})
            for variants in table.values():
                self.assertTrue(all(v in m.START_EXIT for v in variants))
                self.assertIn('interrupted', variants)
        self.assertEqual(m.VARIANTS['api']['held-guest'], ('interrupted',))
        self.assertNotIn('service-loss-failure', m.VARIANTS['api']['natural'])
        self.assertIn('service-loss-failure', m.VARIANTS['storage']['natural'])

    def test_selection_is_closed_to_full_profile_nine_cases_and_two_matrices(self):
        for rtm in ('RTM-097', 'RTM-099'):
            for case in p.FULL_CASES:
                value = m.selection(rtm, p.FULL_PROFILE, p.FULL_CASES, case)
                self.assertEqual(value['boundary'], p.FULL_BOUNDARIES[case])
                self.assertEqual(value['restart'], 'api' if rtm == 'RTM-097' else 'storage')
                self.assertIs(value['fullAcceptance'], False)
        for bad in [('RTM-098', p.FULL_PROFILE, p.FULL_CASES, 'admitted-queued'), ('RTM-097', p.PROFILE, p.FULL_CASES, 'normal'),
                    ('RTM-097', p.FULL_PROFILE, p.FULL_CASES[:-1], 'normal'), ('RTM-097', p.FULL_PROFILE, p.FULL_CASES, 'vm-private-bound')]:
            with self.assertRaises(ValueError): m.selection(*bad)

    def test_start_variant_maps_only_boundary_consistent_exit_codes(self):
        for restart in ('api', 'storage'):
            for case in p.FULL_CASES:
                allowed = m.VARIANTS[restart][m.kind(case)]
                for variant in allowed:
                    start = Mock(); start.wait.return_value = m.START_EXIT[variant]
                    self.assertEqual(m.start_variant(start, restart, case, lambda: 1), variant)
                for code in (None, 1, 51, -9, 0 if 'settled-success' not in allowed else 49):
                    start = Mock(); start.wait.return_value = code
                    with self.assertRaises(ValueError): m.start_variant(start, restart, case, lambda: 1)


class OracleTests(unittest.TestCase):
    def test_prefault_phase_follows_boundary_kind(self):
        for case in p.FULL_CASES:
            kind = m.kind(case)
            for phase in ('prepareAdmitted', 'quarantined', 'running', 'prepareSucceeded'):
                arm, intent, state = arm_and_intent(case, phase)
                if phase in m.PREFAULT_PHASES[kind]:
                    self.assertEqual(m.prefault_intent(state, intent, arm, case), phase)
                else:
                    with self.assertRaises(ValueError): m.prefault_intent(state, intent, arm, case)

    def test_prefault_intent_rejects_foreign_scope_runtime_issuance_and_prior_receipts(self):
        arm, intent, state = arm_and_intent('first-child-published')
        other = copy.deepcopy(intent); other['launch'] = SERVICE['uid'](); state['intents'][intent['id']] = other
        with self.assertRaises(ValueError): m.prefault_intent(state, other, arm, 'first-child-published')
        arm, intent, state = arm_and_intent('admitted-queued')
        next(s for s in intent['slots'] if s['role'] == 'runtime')['key'] = '1' * 64
        with self.assertRaises(ValueError): m.prefault_intent(state, intent, arm, 'admitted-queued')
        arm, intent, state = arm_and_intent('admitted-queued')
        next(s for s in intent['slots'] if s['role'] == 'prepare')['receipt'] = {}
        with self.assertRaises(ValueError): m.prefault_intent(state, intent, arm, 'admitted-queued')

    def recovered(self, case, variant, phase='quarantined', receipt_revision=12):
        arm, intent, state = arm_and_intent(case, phase)
        if phase == 'quarantined':
            intent.update(cleanUnmount=False, quarantineReason='recovering interrupted execution')
            for slot in intent['slots']:
                if slot['role'] == 'prepare':
                    slot['receipt'] = dict(store=intent['store'], volume=slot['volume'], attachment=slot['attachment'],
                                           prepare=intent['prepare'], launch=intent['launch'], revision=receipt_revision)
        return arm, intent, state, checkpoint_for(arm, SERVICE['uid']())

    def test_recovered_intent_requires_quarantine_receipts_or_adoption(self):
        arm, _, state, checkpoint = self.recovered('first-child-published', 'interrupted')
        self.assertEqual(m.recovered_intent(state, arm, 'interrupted', checkpoint)['phase'], 'quarantined')
        arm, _, state, checkpoint = self.recovered('normal', 'settled-success', phase='running')
        self.assertEqual(m.recovered_intent(state, arm, 'settled-success', checkpoint)['phase'], 'running')
        arm, _, state, checkpoint = self.recovered('normal', 'interrupted', phase='running')
        with self.assertRaises(ValueError): m.recovered_intent(state, arm, 'interrupted', checkpoint)
        arm, _, state, checkpoint = self.recovered('first-child-published', 'interrupted', phase='prepareAdmitted')
        with self.assertRaises(ValueError): m.recovered_intent(state, arm, 'interrupted', checkpoint)

    def test_a8_recovery_requires_the_exact_durable_receipt_replay(self):
        arm, intent, state, checkpoint = self.recovered('drain-durable-reply-lost', 'interrupted')
        durable = checkpoint['drain']['receipt']
        target = next(s for s in intent['slots'] if s['attachment'] == arm['targetAttachment'])
        target['receipt'] = {k: v for k, v in durable.items() if k != 'schema'}
        self.assertEqual(m.recovered_intent(state, arm, 'interrupted', checkpoint)['phase'], 'quarantined')
        target['receipt']['revision'] += 1
        with self.assertRaises(ValueError): m.recovered_intent(state, arm, 'interrupted', checkpoint)

    def retired(self, case='drain-durable-reply-lost', issued_runtime=False):
        arm, intent, state, checkpoint = self.recovered(case, 'interrupted')
        intent.update(phase='retired', prepareCompleted=True)
        prepare = next(s for s in intent['slots'] if s['role'] == 'prepare')
        runtime = next(s for s in intent['slots'] if s['role'] == 'runtime')
        if case == 'drain-durable-reply-lost':
            prepare['receipt'] = {k: v for k, v in checkpoint['drain']['receipt'].items() if k != 'schema'}
        if issued_runtime:
            runtime['key'] = '1' * 64
            runtime['receipt'] = dict(store=intent['store'], volume=runtime['volume'], attachment=runtime['attachment'],
                                      launch=intent['launch'], revision=13)
        return arm, intent, state, checkpoint, prepare, runtime

    def test_retired_successful_intent_preserves_unissued_runtime_slot_and_exact_a8_receipt(self):
        for case in m.SUCCESSFUL:
            for issued in (False, True):
                with self.subTest(case=case, issued=issued):
                    arm, intent, state, checkpoint, prepare, runtime = self.retired(case, issued)
                    before = p.canonical(state)
                    self.assertIs(m.recovered_intent(state, arm, 'interrupted', checkpoint), intent)
                    self.assertEqual(p.canonical(state), before)
                    self.assertEqual(len(intent['slots']), 2)
                    self.assertEqual(len(arm['credentials']), 1)
                    if not issued:
                        self.assertNotIn('key', runtime)
                        self.assertNotIn('receipt', runtime)

    def test_missing_runtime_key_is_not_unissued_with_any_persisted_operation_or_digest(self):
        for journal in ('operations', 'operationDigests'):
            for operation in ('registerOperation', 'retireOperation'):
                with self.subTest(journal=journal, operation=operation):
                    arm, _, state, checkpoint, _, runtime = self.retired()
                    state[journal][runtime[operation]] = 'persisted'
                    with self.assertRaisesRegex(ValueError, 'unissued runtime has no persisted operation'):
                        m.recovered_intent(state, arm, 'interrupted', checkpoint)

    def test_retired_issued_keys_receipts_and_durable_replay_fail_closed(self):
        mutations = [
            lambda prepare, runtime, intent, checkpoint: prepare.pop('key'),
            lambda prepare, runtime, intent, checkpoint: prepare.update(key='2' * 64),
            lambda prepare, runtime, intent, checkpoint: runtime.pop('key'),
            lambda prepare, runtime, intent, checkpoint: prepare.pop('receipt'),
            lambda prepare, runtime, intent, checkpoint: runtime.pop('receipt'),
            lambda prepare, runtime, intent, checkpoint: prepare['receipt'].update(attachment=SERVICE['uid']()),
            lambda prepare, runtime, intent, checkpoint: runtime['receipt'].update(launch=SERVICE['uid']()),
            lambda prepare, runtime, intent, checkpoint: prepare['receipt'].update(revision=99),
            lambda prepare, runtime, intent, checkpoint: checkpoint['drain']['receipt'].update(revision=99),
            lambda prepare, runtime, intent, checkpoint: intent['slots'].remove(runtime),
            lambda prepare, runtime, intent, checkpoint: runtime.update(role='prepare'),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                arm, intent, state, checkpoint, prepare, runtime = self.retired(issued_runtime=True)
                mutate(prepare, runtime, intent, checkpoint)
                p.canonical(state); p.canonical(checkpoint)
                with self.assertRaises(ValueError): m.recovered_intent(state, arm, 'interrupted', checkpoint)

    def test_retired_a8_missing_durable_receipt_is_not_accepted(self):
        for missing in ('receipt', 'revision'):
            with self.subTest(missing=missing):
                arm, _, state, checkpoint, _, _ = self.retired()
                if missing == 'receipt': checkpoint['drain'].pop('receipt')
                else: checkpoint['drain']['receipt'].pop('revision')
                p.canonical(checkpoint)
                with self.assertRaises((KeyError, ValueError)):
                    m.recovered_intent(state, arm, 'interrupted', checkpoint)

    def test_checkpoint_validator_routes_storage_cuts_to_the_storage_observation(self):
        for case in p.FULL_CASES:
            arm = fixture_arm(case)
            worker = SERVICE['uid']()
            observation = checkpoint_for(arm, worker)
            if case in p.STORAGE_CASES:
                self.assertEqual(m.validate_checkpoint(observation, arm, worker), observation)
                with self.assertRaises(ValueError): m.validate_checkpoint(observation, arm, None)
                with self.assertRaises(ValueError): m.validate_checkpoint(observation, arm, SERVICE['uid']())
            else:
                self.assertEqual(m.validate_checkpoint(observation, arm, None), observation)
            wrong = copy.deepcopy(observation); wrong['armDigest'] = '0' * 64
            with self.assertRaises(ValueError): m.validate_checkpoint(wrong, arm, worker)


class OutcomeTests(unittest.TestCase):
    def test_outcomes_are_live_only_and_aggregate_requires_nine_unique_cells(self):
        with self.assertRaises(TypeError): m.MatrixOutcome()
        fake = object.__new__(m.MatrixOutcome)
        with self.assertRaises(ValueError): fake.validate()
        with self.assertRaises(ValueError): m.aggregate_matrix([fake] * 9, 'RTM-097')
        with self.assertRaises(ValueError): m.aggregate_matrix([], 'RTM-097')
        with self.assertRaises(ValueError): m.aggregate_matrix([dict()] * 9, 'RTM-099')

    def test_receipt_validation_is_exact(self):
        row = dict(rtm='RTM-097', restart='api', profile=p.FULL_PROFILE, caseName='admitted-queued', boundary='A5', kind='held-storage',
                   variant='interrupted', runID=SERVICE['uid'](), store=SERVICE['uid'](), result='matrix-case-passed',
                   execution='actual-docker-runtime', fullAcceptance=False, evidenceSHA256='a' * 64)
        self.assertEqual(m.validate_receipt(row, 'RTM-097'), row)
        for change in [dict(restart='storage'), dict(boundary='A7'), dict(kind='natural'), dict(variant='settled-failure'),
                       dict(result='initial-cut-passed'), dict(fullAcceptance=True), dict(rtm='RTM-099')]:
            bad = dict(row, **change)
            with self.assertRaises(ValueError): m.validate_receipt(bad, 'RTM-097')
        with self.assertRaises(ValueError): m.validate_receipt(dict(row, extra=1), 'RTM-097')


class FixtureWiringTests(unittest.TestCase):
    def setUp(self):
        self.source = FIXTURE.read_text()
        self.tree = ast.parse(self.source)
        self.run = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == '_run_prepare_case')

    def branches(self, name):
        return [n for n in ast.walk(self.run) if isinstance(n, ast.If) and name in ast.unparse(n.test) and 'matrix' in ast.unparse(n.test)
                and isinstance(n.test, ast.BoolOp)]

    def test_matrix_branches_precede_and_leave_the_accepted_cut_branches_intact(self):
        for name, accepted in (('api_restart', 'restart_api_at_a7'), ('storage_restart', 'restart_storage_at_a7')):
            matrix_branch = next(n for n in self.branches(name) if 'matrix_proof.restart_' in ast.unparse(n.body[0]) or any('matrix_proof.restart_' in ast.unparse(s) for s in n.body))
            original = next(n for n in ast.walk(self.run) if isinstance(n, ast.If) and isinstance(n.test, ast.Name)
                            and n.test.id == name and accepted in ast.unparse(n))
            self.assertLess(matrix_branch.lineno, original.lineno)
            guard = ast.unparse(original.body[1])
            self.assertIn('start.poll() is None and pending_owner is not None', guard)
            self.assertIn('live held PREPARE', guard)
            text = ast.unparse(ast.Module(body=matrix_branch.body, type_ignores=[]))
            self.assertIn('joined_start(start, failed=matrix_variant', text)
            self.assertIn('reattach_one()', text)
            self.assertNotIn('SIGKILL', text)

    def test_matrix_callers_refresh_process_and_pending_owner_from_returned_census(self):
        for name, method in (('api_restart', 'restart_api'), ('storage_restart', 'restart_storage')):
            branch = next(n for n in self.branches(name) if any('matrix_proof.' + method + '(' in ast.unparse(s) for s in n.body))
            old = SimpleNamespace(pid=42, parent_pid=100)
            refreshed = SimpleNamespace(pid=42, parent_pid=1)
            before = [SimpleNamespace(pid=200), refreshed]
            restart = Mock(return_value=(before, {}, ({}, 'hash'), 'interrupted', True))
            ns = dict(proof=p, pending_owner=(old, [old]), read_state=lambda: ({}, {'intents': {'intent': {}}}, {}),
                arm={'scope': {'intent': 'intent'}}, matrix_proof=SimpleNamespace(**{method: restart}, START_EXIT=m.START_EXIT),
                metadata={'storageInitramfsSHA256': 'a' * 64}, joined_start=Mock(), reattach_one=Mock())
            ns.update({key: object() for key in ('daemon', 'checkpoint', 'ledger', 'evidence_files', 'record', 'processes', 'remaining', 'start', 'worker')})
            exec(compile(ast.Module(body=branch.body, type_ignores=[]), str(FIXTURE), 'exec'), ns)
            self.assertIs(ns['process'], refreshed)
            self.assertEqual(ns['pending_owner'], (refreshed, before))
            self.assertIs(restart.call_args.args[1], old)
            ns['joined_start'].assert_called_once_with(ns['start'], failed=True, expected_exit=52)
            ns['reattach_one'].assert_called_once_with()

    def test_matrix_gate_is_closed(self):
        gate = next(n for n in ast.walk(self.run) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == 'require' and n.args and isinstance(n.args[-1], ast.Constant)
                    and n.args[-1].value == 'closed restart matrix selection')
        text = ast.unparse(gate)
        for required in ('api_restart != storage_restart', 'not worker_restart', 'vm_cut is None', 'io_case is None',
                         'original_consumer_case is None', 'not two_volume', 'active_ack_probe is None', 'matrix_proof.selection('):
            self.assertIn(required, text)

    def test_matrix_never_releases_holds_or_waits_for_dead_pumps(self):
        self.assertIn('fault_case in proof.HELD_STORAGE_CASES and not worker_restart and matrix is None', self.source)
        self.assertIn('io_case is None and vm_cut is None and matrix is None:', self.source)
        self.assertIn('if matrix is not None: natural_failure = False', self.source)
        self.assertIn('if (api_restart or storage_restart) and matrix is None:', self.source)

    def test_parent_entry_selects_before_engine_io_and_returns_only_live_outcomes(self):
        entry = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_restart_matrix_shard')
        text = ast.unparse(entry)
        self.assertLess(text.index('matrix_proof.selection('), text.index('_run_prepare_case('))
        self.assertIn("api_restart=staged['restart'] == 'api'", text)
        self.assertIn("storage_restart=staged['restart'] == 'storage'", text)
        self.assertIn('matrix=staged', text)
        result = next(n for n in ast.walk(self.run) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                      and n.func.attr == 'completed_matrix_outcome')
        record = next(n for n in ast.walk(self.run) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'record'
                      and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == 'matrix-case-result')
        self.assertLess(record.lineno, result.lineno)


if __name__ == '__main__':
    unittest.main()
