#!/usr/bin/env python3
"""Ordinary host regressions; mocked native edges are not durability evidence."""
import ast
import copy
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import replace
from types import SimpleNamespace
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import harness
import managed_prepare_faults as p
import managed_prepare_active_ack as ack
import managed_prepare_start_diagnostic as start_diagnostic
import managed_prepare_storage_vm_faults as recovery
import managed_prepare_vm_boundaries as vm
PARENT = runpy.run_path(str(ROOT / 'tools/tests/test-managed-prepare-vm-parent.py'))
A7 = PARENT['A7']


def ack_restart_fixture():
    """Reuse only A7's external-edge setup, not its single-workload assertions.

    The unmodified fixture is exercised separately for the non-ACK baseline.
    No production AST is rewritten: real Daemon.start, restart and monitor run.
    """
    tree = ast.parse((ROOT/'tools/tests/test-managed-prepare-storage-vm.py').read_text())
    fixture = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'run_restart')
    end = next(i for i, n in enumerate(fixture.body) if isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute)
        and n.value.func.attr == 'assertEqual')
    fixture.body = [*fixture.body[:end], ast.Return(value=ast.Name(id='result', ctx=ast.Load()))]
    record = next(n for n in fixture.body if isinstance(n, ast.FunctionDef) and n.name == 'record')
    record.body = [n for n in record.body if not (isinstance(n, ast.If)
        and ast.unparse(n.test) == "phase == 'storage-only-death-joined'")]
    env = dict(A7)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fixture], type_ignores=[])),
        'ACK-external-edge-fixture', 'exec'), env)
    return env['run_restart']


ACK_RESTART = ack_restart_fixture()

class PrivateACK(unittest.TestCase):
    def test_closed_parent_entry(self):
        dispatch = Mock()
        run = A7['SERVICE']['function']('run_storage_private_active_ack_shard', _run_prepare_case=dispatch)
        args = dict(probe=None, probe_sha256=None, ack_probe=None, ack_probe_sha256='a'*64,
            source_sha256=None, expected_commit=None, evidence=None)
        with self.assertRaises(ValueError): run(None, profile=p.PROFILE, **args)
        dispatch.assert_not_called()
        run(None, profile=p.FULL_PROFILE, **args)
        value = dispatch.call_args.kwargs
        self.assertEqual(value['vm_cut'], 'vm-private-bound')
        self.assertEqual(value['staged']['boundary'], 'vm-private-bound-active-ack')
        self.assertFalse(value['staged']['fullAcceptance'])
        self.assertEqual(len(p.FULL_CASES), 9)

    def run_cut(self, fault=None, schedule=('api-ready',) * 3):
        original = recovery.restart_storage_at_a7
        events, evidence, observed = [], {}, []
        def selected(*args, **kwargs):
            args = list(args)
            daemon = args[0]
            records = list(recovery.read_public.side_effect)
            recovery.read_public.side_effect = [records[0], records[0], *records[1:]]
            worker = recovery.current_boot(records[0][0])['ready']['workerUUID']
            arm = args[4]
            args[5] = PARENT['checkpoint_for'](arm, args[5], vm.CASES[0], worker)
            held = dict(query=vm.storage_query(arm, worker), state='observed', observation=args[5],
                retirementStarted=False, acceptedInFlight=1, lateAdmissionRejected=False, receiptReplayCount=0)
            containers = [arm['scope']['container'], '3'*64, '1'*64, '2'*64]
            old_workload = args[1]
            def owner(process, container):
                return replace(process, executable=str(daemon.binary), arguments=(str(daemon.binary),
                    'vm-shim', '--spec', str(daemon.root/'containers'/container/'spec.json')))
            workload = owner(old_workload, containers[0])
            extra = [owner(replace(workload, pid=60+i, identity=(60+i, 4, 500+i), pidversion=20+i),
                container) for i, container in enumerate(containers[1:])]
            exposed = (workload, *extra[1:])
            args[1] = workload
            args[2] = [workload if v == old_workload else v for v in args[2]] + extra
            old_native, census = harness._kernel_process.side_effect, args[9]
            api = old_native(daemon.process.pid)
            live = {v.pid: v for v in exposed}
            pending, watches, queues = [], [], []
            stage = None
            signal_target = None
            def native(pid):
                if pid == signal_target and fault and fault.startswith('storage-guard-owner-loss-'):
                    index = int(fault.rsplit('-', 1)[1])
                    self.assertIn('storage-SIGKILL-intent', events)
                    self.assertGreaterEqual(events.count('ack-active'), 2)
                    self.assertEqual(watches, [v.pid for v in exposed])
                    live.pop(exposed[index].pid)
                    events.append('storage-guard-owner-loss')
                if pid in {v.pid for v in exposed}: return live.get(pid)
                if pid == extra[0].pid:
                    if stage and fault == 'peer-gone': return None
                    if stage and fault == 'peer-replaced': return replace(extra[0], pidversion=999)
                    return extra[0]  # Created, never booted: not storage-exposed.
                if pid == api.pid and stage == 'api-stop' and fault == 'no-api-death': return api
                if stage == 'api-birth' and fault == 'no-api-birth' and pid == daemon.process.pid: return None
                return old_native(pid)
            harness._kernel_process.side_effect = native
            def current():
                result = [v for v in census() if v.pid != workload.pid]
                result += [v for v in (native(v.pid) for v in (*exposed, extra[0])) if v is not None]
                if stage:
                    if fault == 'census-extra': result.append(replace(extra[0], pid=99))
                    if fault == 'census-duplicate': result.append(extra[0])
                    if fault == 'census-replaced':
                        result = [replace(v, pidversion=999) if v.pid == extra[0].pid else v for v in result]
                return result
            args[9] = current
            def advance(phase):
                nonlocal stage
                stage = phase; events.append(phase)
                for index, process in enumerate(exposed):
                    if schedule[index] != phase: continue
                    event = SimpleNamespace(ident=process.pid, filter=recovery.select.KQ_FILTER_PROC,
                        flags=0, fflags=recovery.select.KQ_NOTE_EXIT)
                    if fault != ('workload-live', 'ack-1-live', 'ack-2-live')[index]:
                        live.pop(process.pid, None)
                    if fault == f'missing-event-{index}': continue
                    if fault == f'wrong-pid-{index}': event.ident = 999
                    if fault == f'wrong-filter-{index}': event.filter = 0
                    if fault == f'error-event-{index}': event.flags = recovery.select.KQ_EV_ERROR
                    if fault == f'receipt-event-{index}': event.flags = 0x40
                    if fault == f'wrong-note-{index}': event.fflags = 0
                    pending.append(event)
            old_factory = recovery.select.kqueue.side_effect
            def kqueue():
                queue = Mock(); delegate = None
                def control(changes, maximum, timeout=None):
                    nonlocal delegate
                    if changes is not None:
                        if len(changes) != 3:
                            delegate = old_factory()
                            return delegate.control(changes, maximum, timeout)
                        self.assertEqual([c.ident for c in changes], [v.pid for v in exposed])
                        self.assertEqual((maximum, timeout), (0, 0))
                        for change in changes:
                            self.assertEqual(change.filter, recovery.select.KQ_FILTER_PROC)
                            self.assertEqual(change.fflags, recovery.select.KQ_NOTE_EXIT)
                            self.assertEqual(change.flags, recovery.select.KQ_EV_ADD |
                                recovery.select.KQ_EV_ENABLE | recovery.select.KQ_EV_ONESHOT)
                        watches.extend(c.ident for c in changes); events.append('watch-exposed')
                        if fault == 'prekill-death': live.pop(exposed[1].pid)
                        return []
                    if delegate is not None: return delegate.control(changes, maximum, timeout)
                    self.assertEqual((maximum, timeout), (3, 0))
                    result = pending[:maximum]; del pending[:maximum]
                    return result
                queue.control.side_effect = control
                queue.close.side_effect = lambda: delegate.close() if delegate is not None else None
                queues.append(queue)
                return queue
            native_call = A7['ctypes'].CDLL.return_value.proc_signal_with_audittoken
            old_deliver = native_call.side_effect
            def deliver(*a):
                self.assertEqual(watches, [v.pid for v in exposed])
                result = old_deliver(*a)
                if result == 0: advance('storage')
                return result
            native_call.side_effect = deliver
            old_stop = daemon.stop.side_effect
            def stop(**kw):
                old_stop(**kw); advance('api-stop')
            daemon.stop.side_effect = stop
            subprocess = daemon.start.__func__.__globals__['subprocess']
            old_spawn, old_ready = subprocess.Popen.side_effect, subprocess.run.side_effect
            def spawn(*a, **kw):
                value = old_spawn(*a, **kw); advance('api-birth'); return value
            def ready(*a, **kw):
                value = old_ready(*a, **kw); advance('api-ready'); return value
            subprocess.Popen.side_effect, subprocess.run.side_effect = spawn, ready
            obj = Mock(ids=containers[2:], processes=extra[1:], interrupted=containers[0])
            count = 0
            def validate(*a):
                nonlocal count
                count += 1; events.append('ack-active')
                if fault == 'inactive-ack' and count > 2: raise ValueError('inactive ACK')
            obj.validate.side_effect = validate
            def held_reader():
                events.append('held')
                if fault == 'lost-hold' and events.count('held') > 1: raise FileNotFoundError('held')
                value = copy.deepcopy(held)
                if fault == 'not-inflight': value['acceptedInFlight'] = 0
                return value
            record = args[8]
            def record_event(phase, **value):
                events.append(phase); evidence[phase] = value; record(phase, **value)
                if phase == 'storage-exposed-owner-exit-observed': observed.append(value)
            args[8] = record_event
            peer_proof = dict(container=containers[1], containerInstance=A7['uid']())
            def validate_peer():
                p.require(native(extra[0].pid) == extra[0], 'same live prepared peer incarnation')
                p.require(not stage or fault != 'peer-canonical', 'immutable prepared peer changed')
            validator = Mock(side_effect=validate_peer)
            peer = (extra[0], peer_proof, validator)
            snapshots = list(args[12].side_effect)
            # Retired receipts cannot replace any of the three independent exits.
            for container in obj.ids:
                retired = copy.deepcopy(snapshots[-1][1]['intents'][arm['scope']['intent']])
                retired.update(id=A7['uid'](), container=container, phase='retired', prepareCompleted=True)
                for slot in retired['slots']:
                    slot.update(key='a'*64, receipt=dict(store=retired['store'], volume=slot['volume'],
                        attachment=slot['attachment'], prepare=retired['prepare'], launch=retired['launch'],
                        revision=snapshots[-1][1]['revision']))
                snapshots[-1][1]['intents'][retired['id']] = retired
            snapshots.append(copy.deepcopy(snapshots[-1]))
            if fault in ('peer-prefault-intent', 'peer-recovered-intent', 'peer-late-intent'):
                intent_id = A7['uid']()
                peer_intent = dict(container=peer_proof['container'], containerInstance=A7['uid'](),
                    phase='retired', slots=[dict(role='runtime', key=None)])
                selected_snapshots = (snapshots[:2] if fault == 'peer-prefault-intent' else
                    snapshots[2:] if fault == 'peer-recovered-intent' else snapshots[-1:])
                for snapshot in selected_snapshots:
                    snapshot[1]['intents'][intent_id] = copy.deepcopy(peer_intent)
            args[12].side_effect = snapshots
            original_signal = recovery.signal_storage
            def guarded_signal(process, *, before_signal=None):
                nonlocal signal_target
                self.assertIsNotNone(before_signal)
                def final_owner_check():
                    events.append('final-owner-check')
                    before_signal()
                signal_target = process.pid
                try:
                    return original_signal(process, before_signal=final_owner_check)
                finally:
                    signal_target = None
            with patch.object(recovery, 'restart_storage_at_a7', original), \
                 patch.object(recovery.select, 'kqueue', side_effect=kqueue), \
                 patch.object(ack.os, 'listdir', return_value=containers), \
                 patch.object(recovery, 'signal_storage', side_effect=guarded_signal) as signal:
                try:
                    result = recovery.restart_storage_at_vm_cut(*args, **kwargs,
                        active_ack=obj, peer_owner=peer, held_reader=held_reader)
                except ValueError as error:
                    if fault == 'peer-prefault-intent':
                        self.assertIn('unstarted peer has no managed intent', str(error))
                    if fault in ('peer-prefault-intent', 'prekill-death'): signal.assert_not_called()
                    if fault in ('bad-delivery', 'missing-storage-event'): daemon.stop.assert_not_called()
                    if fault and fault.startswith('storage-guard-owner-loss-'):
                        self.assertIn('same live exposed owner before storage signal', str(error))
                        signal.assert_called_once()
                        native_call.assert_not_called()
                        daemon.stop.assert_not_called()
                        self.assertNotIn('storage-SIGKILL-delivered', events)
                        self.assertLess(events.index('storage-guard-owner-loss'), events.index('final-owner-check'))
                    raise
                finally:
                    for queue in queues: queue.close.assert_called_once_with()
            self.assertEqual(args[12].call_count, 4)  # Fresh intent census after exposed exits.
            self.assertIn(extra[0], result[0])
            self.assertEqual(len(result[0]), 3)  # Fresh API + storage + unchanged idle peer.
            self.assertTrue(all(v not in result[0] for v in exposed))
            validator.assert_called()
            daemon.stop.assert_called_once_with(kill=True)
            native_call.assert_called_once()
            subprocess.Popen.assert_called_once()
            self.assertEqual(evidence['storage-exposed-owners-contained']['native'],
                [p.native_proof(v) for v in exposed])
            self.assertEqual(evidence['storage-exposed-owners-contained']['preservedPeer'], peer_proof)
            self.assertCountEqual([v['native'] for v in observed], [p.native_proof(v) for v in exposed])
            expected_phase = dict(storage='storage-exit-joined', **{'api-stop': 'api-exit-joined',
                'api-birth': 'api-birth', 'api-ready': 'recovery-ready'})
            for process, phase in zip(exposed, schedule):
                self.assertEqual(next(v['observedAt'] for v in observed if v['native'] == p.native_proof(process)),
                    expected_phase[phase])
            self.assertTrue(evidence['storage-new-epoch-drain']['proof']['drains'])
            return result
        with patch.object(recovery, 'restart_storage_at_a7', side_effect=selected):
            ACK_RESTART(self, fault if fault in ('bad-delivery', 'missing-storage-event') else None)
        self.assertLess(events.index('watch-exposed'), events.index('storage-SIGKILL-intent'))
        self.assertLess(events.index('held'), events.index('storage-SIGKILL-intent'))
        self.assertLess(max(i for i,x in enumerate(events) if x == 'held'), events.index('storage-SIGKILL-delivered'))
        self.assertLess(events.index('storage-only-death-joined'), events.index('api-recovery-SIGKILL-intent'))
        self.assertLess(events.index('storage-new-epoch-drain'), events.index('storage-exposed-owners-contained'))
        self.assertLess(events.index('storage-exposed-owners-contained'), events.index('storage-reopened-reconciled'))

    def test_unchanged_idle_peer_survives_three_positive_exposed_exits(self): self.run_cut()

    def test_independent_early_mixed_and_late_exits_continue_real_api_recovery(self):
        schedules = [('storage',) * 3, ('api-stop',) * 3, ('api-birth',) * 3, ('api-ready',) * 3,
            ('storage', 'api-stop', 'api-birth'), ('api-ready', 'storage', 'api-stop'),
            ('api-birth', 'api-ready', 'storage')]
        for schedule in schedules:
            with self.subTest(schedule=schedule): self.run_cut(schedule=schedule)

    def test_each_exit_requires_preregistered_exact_event_even_when_absent(self):
        for fault in ('missing-event', 'wrong-pid', 'wrong-filter', 'error-event', 'receipt-event', 'wrong-note'):
            for index in range(3):
                with self.subTest(fault=fault, owner=index), self.assertRaises(ValueError):
                    self.run_cut(f'{fault}-{index}', schedule=('storage',) * 3)

    def test_predeath_api_loss_and_census_mutations_still_reject(self):
        for fault in ('prekill-death', 'no-api-death', 'no-api-birth',
                      'census-extra', 'census-replaced', 'census-duplicate'):
            with self.subTest(fault=fault), self.assertRaises((ValueError, RuntimeError)):
                self.run_cut(fault)

    def test_owner_loss_during_storage_guard_reinspection_refuses_native_sigkill(self):
        # This is a final pre-syscall observation, not atomic cross-process causation.
        for index in range(3):
            with self.subTest(owner=index), self.assertRaisesRegex(ValueError, 'same live exposed owner'):
                self.run_cut(f'storage-guard-owner-loss-{index}')

    def test_non_ack_baseline_keeps_original_workload_birth_and_waiter_order(self):
        baseline = A7['RestartTests']()
        baseline.run_restart()
        for fault in ('early-workload-loss', 'exit-before-start', 'exit-before-birth',
                      'exit-during-birth', 'exit-during-birth-lookup'):
            with self.subTest(fault=fault), self.assertRaises((ValueError, RuntimeError)):
                baseline.run_restart(fault)


    def test_each_exposed_owner_must_exit_even_with_retired_receipts(self):
        for fault in ('workload-live', 'ack-1-live', 'ack-2-live'):
            with self.subTest(fault=fault), self.assertRaises(TimeoutError): self.run_cut(fault)

    def test_peer_loss_replacement_canonical_change_or_any_intent_fails(self):
        for fault in ('peer-gone', 'peer-replaced', 'peer-canonical'):
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.run_cut(fault)
        for fault in ('peer-prefault-intent', 'peer-recovered-intent', 'peer-late-intent'):
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, 'unstarted peer has no managed intent'):
                self.run_cut(fault)

    def test_missing_hold_inactive_ack_or_unconfirmed_storage_exit_fail_closed(self):
        for fault in ('lost-hold', 'not-inflight', 'inactive-ack', 'bad-delivery', 'missing-storage-event'):
            with self.subTest(fault=fault), self.assertRaises((ValueError, FileNotFoundError, TimeoutError)):
                self.run_cut(fault)

    def test_parent_children_and_vm_memory_caps_include_reservations(self):
        from types import SimpleNamespace
        from contextlib import nullcontext
        census = [harness.RuntimeProcess(100+i, arguments=('cengine', 'vm-shim', '--spec', '/owned/spec.json')) for i in range(5)]
        api = harness.RuntimeProcess(200)
        directory = SimpleNamespace(read=lambda *args: (b'{"memoryBytes":536870912}', None))
        with patch.object(p, 'Directory', side_effect=lambda *a, **k: nullcontext(directory)):
            # Four real allocated VMs + one positively owned never-booted peer.
            ack.resource_budget([*census, api], [Mock(poll=lambda: None)], idle=(census[0],))
            with self.assertRaisesRegex(ValueError, 'two-GiB'):
                ack.resource_budget([*census, api], [])
            with self.assertRaisesRegex(ValueError, 'eight-process'):
                ack.resource_budget([*census, api], [Mock(poll=lambda: None)], reserve=1, idle=(census[0],))
            with self.assertRaisesRegex(ValueError, 'two-GiB'):
                ack.resource_budget(census[:4], [], memory_reserve=512*1024**2)

    def test_vm_shared_recovery_executes_fresh_controller_and_read_before_write(self):
        tests = runpy.run_path(str(ROOT/'tools/tests/test-managed-prepare-active-ack.py'))
        original = ack.ActiveACK.recover
        def recover(obj, context):
            try: return original(obj, context, storage_vm=True)
            finally: self.assertEqual(ack.r.fresh_receipts.call_args.kwargs['rtm'], 'RTM-079')
        with patch.object(ack.ActiveACK, 'recover', recover):
            tests['ActiveACKTests']().test_recover_live_order_and_bad_readback_never_rewrites()

    def test_ack_probe_uses_bounded_nofollow_reader_before_any_engine_call(self):
        import tempfile
        with tempfile.TemporaryDirectory() as path:
            target = Path(path)/'helper'; target.write_bytes(b'probe')
            link = Path(path)/'link'; link.symlink_to(target)
            for helper in (link, target):
                client = Mock()
                def read(name, limit):
                    self.assertEqual(limit, 8*1024*1024)
                    raise ValueError('bounded pinned read refused')
                from contextlib import nullcontext
                from types import SimpleNamespace
                with patch.object(p, 'Directory', return_value=nullcontext(SimpleNamespace(read=read))):
                    with self.assertRaisesRegex(ValueError, 'bounded pinned'):
                        ack.ActiveACK(None, client, helper, 'a'*64, read_state=None, target=None, observe=None,
                            start=None, join=None, processes=None, remaining=None, record=None, ledger=None, files=None, wait_exit=None)
                client.images.load.assert_not_called()

    def test_storage_recovery_requires_fresh_controller_before_readback(self):
        # Execute shared recovery test with VM-specific fresh_receipts dispatch.
        source = (ROOT/'Tests/Compatibility/managed_prepare_active_ack.py').read_text()
        tree = ast.parse(source)
        recover = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'recover')
        self.assertIn("'RTM-079' if storage_vm else 'RTM-084'", ast.unparse(recover))
        parent = (ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text()
        self.assertIn('active_ack.reattach(client)', parent)
        self.assertIn('active_ack.recover(service_recovery, storage_vm=True)', parent)
        calls = [n for n in ast.walk(ast.parse(parent)) if isinstance(n, ast.Call)]
        joined = next(n for n in calls if isinstance(n.func, ast.Name) and n.func.id == 'joined_start'
            and any(k.arg == 'vm_recovery' for k in n.keywords))
        self.assertEqual(ast.unparse(joined),
            'joined_start(start, failed=True, disconnected=True, vm_recovery=vm_cut is not None)')
        recovered = next(n for n in calls if isinstance(n.func, ast.Attribute)
            and ast.unparse(n.func) == 'active_ack.recover')
        self.assertLess(joined.lineno, recovered.lineno)

class VMACKStartOutcome(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse((ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
        joined = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'joined_start')
        cls.code = compile(ast.Module(body=[joined], type_ignores=[]), 'real-parent-joined-start', 'exec')

    @contextmanager
    def joined(self, code, diagnostic, *, context=None, wait_error=None):
        env = dict(proof=p, signal=signal, remaining=Mock(return_value=1), record=Mock(),
            io_case=None, early=False, fault_case=None, NATURAL_FAILURE_CASES=(),
            active_ack=Mock(), storage_restart=True, vm_cut='vm-private-bound', full=False, two_volume=False)
        env.update(context or {})
        exec(self.code, env)
        process = Mock()
        process.wait.return_value = code
        process.wait.side_effect = wait_error
        with patch.object(start_diagnostic, 'receive', return_value=diagnostic) as receive:
            yield SimpleNamespace(run=lambda **kwargs: env['joined_start'](process, **kwargs),
                process=process, receive=receive, record=env['record'])

    def test_real_join_accepts_only_matching_http500_or_disconnect(self):
        from itertools import product
        outcomes = ((50, 'HTTP_INTERNAL_ERROR'), (52, 'CONNECTION_LOST'))
        for cut, active, (code, diagnostic) in product(vm.CASES, (None, Mock()), outcomes):
            with self.subTest(cut=cut, ack=active is not None, code=code), \
                 self.joined(code, diagnostic, context=dict(vm_cut=cut, active_ack=active)) as f, \
                 patch.object(ack, 'vm_start_failure', wraps=ack.vm_start_failure) as classify:
                self.assertIsNone(f.run(failed=True, disconnected=True, vm_recovery=True))
                f.process.wait.assert_called_once_with(timeout=1)
                f.receive.assert_called_once_with(f.process)
                classify.assert_called_once_with(code, diagnostic)
                f.record.assert_called_once_with('docker-start-joined', failed=True,
                    returncode=code, diagnostic=diagnostic)

    def test_real_join_rejects_success_all_conflicts_and_other_exit_codes(self):
        conflicts = ['MANAGED_STORAGE_OWNERSHIP_UNRESOLVED', 'HTTP_CONFLICT_UNKNOWN',
            *[dict(category=category, stage=None, kind=None, role=None, code=None)
                for category in start_diagnostic.PRIVATE_CATEGORIES]]
        class ExitCode(int): pass
        cases = [(0, 'SUCCESS'), *[(49, diagnostic) for diagnostic in conflicts],
            (51, 'HTTP_OTHER'), (-signal.SIGKILL, 'UNKNOWN'), (True, 'HTTP_INTERNAL_ERROR'),
            (False, 'SUCCESS'), (50.0, 'HTTP_INTERNAL_ERROR'), (52.0, 'CONNECTION_LOST'),
            (ExitCode(50), 'HTTP_INTERNAL_ERROR'), (ExitCode(52), 'CONNECTION_LOST'),
            (256, 'HTTP_INTERNAL_ERROR')]
        for code, diagnostic in cases:
            with self.subTest(code=code, type=type(code), diagnostic=diagnostic):
                with self.assertRaises(ValueError): ack.vm_start_failure(code, diagnostic)
                with self.joined(code, diagnostic) as f, self.assertRaises(ValueError):
                    f.run(failed=True, disconnected=True, vm_recovery=True)

    def test_real_join_rejects_wrong_or_missing_diagnostic(self):
        for code, expected in ((50, 'HTTP_INTERNAL_ERROR'), (52, 'CONNECTION_LOST')):
            for diagnostic in (None, '', 'UNKNOWN', 'SUCCESS', 'HTTP_CONFLICT_UNKNOWN',
                    'CONNECTION_LOST' if code == 50 else 'HTTP_INTERNAL_ERROR',
                    {'category': expected}, {}):
                with self.subTest(code=code, diagnostic=diagnostic):
                    with self.assertRaises(ValueError): ack.vm_start_failure(code, diagnostic)
                    with self.joined(code, diagnostic) as f, self.assertRaises(ValueError):
                        f.run(failed=True, disconnected=True, vm_recovery=True)

    def test_real_join_timeout_never_receives_or_records_a_start_outcome(self):
        error = subprocess.TimeoutExpired('docker-start', 1)
        with self.joined(50, 'HTTP_INTERNAL_ERROR', wait_error=error) as f:
            with self.assertRaises(subprocess.TimeoutExpired):
                f.run(failed=True, disconnected=True, vm_recovery=True)
            f.process.wait.assert_called_once_with(timeout=1)
            f.receive.assert_not_called()
            f.record.assert_not_called()

    def test_real_join_requires_every_vm_recovery_gate_before_classification(self):
        cases = [({}, {'failed': False}), ({}, {'disconnected': False}),
            ({'storage_restart': False}, {}), ({'vm_cut': None}, {}), ({'vm_cut': 'vm-ready'}, {}),
            *[({'vm_cut': cut}, {}) for cut in ('first-child-published', 'worker-private-bound',
                'two-volume-drain', '', True)],
            ({}, {'expected_exit': 50}), ({}, {'expected_exit': 52}),
            ({}, {'expected_exit': 0}), ({}, {'expected_exit': False}), ({}, {'worker_failed': True})]
        for context, overrides in cases:
            with self.subTest(context=context, overrides=overrides), \
                 self.joined(50, 'HTTP_INTERNAL_ERROR', context=context) as f, \
                 patch.object(ack, 'vm_start_failure', wraps=ack.vm_start_failure) as classify:
                args = dict(failed=True, disconnected=True, vm_recovery=True)
                args.update(overrides)
                with self.assertRaisesRegex(ValueError, 'VM cut start outcome only after storage recovery'):
                    f.run(**args)
                classify.assert_not_called()

    def test_two_volume_real_join_accepts_only_correlated_recovery_outcomes(self):
        context = dict(vm_cut=None, full=True, two_volume=True, fault_case='vm-two-volume-drain-reply-gap')
        for code, diagnostic in ((50, 'HTTP_INTERNAL_ERROR'), (52, 'CONNECTION_LOST')):
            with self.subTest(code=code), self.joined(code, diagnostic, context=context) as f, \
                 patch.object(ack, 'vm_start_failure', wraps=ack.vm_start_failure) as classify:
                f.run(failed=True, disconnected=True, vm_recovery=True)
                classify.assert_called_once_with(code, diagnostic)
                f.record.assert_called_once_with('docker-start-joined', failed=True,
                    returncode=code, diagnostic=diagnostic)

    def test_two_volume_real_join_refuses_mismatched_codes_diagnostics_conflicts_and_success(self):
        context = dict(vm_cut=None, full=True, two_volume=True, fault_case='vm-two-volume-drain-reply-gap')
        cases = [(0, 'SUCCESS'), (49, 'HTTP_CONFLICT_UNKNOWN'),
            (49, 'MANAGED_STORAGE_OWNERSHIP_UNRESOLVED'), (51, 'HTTP_OTHER'),
            (-signal.SIGKILL, 'UNKNOWN'), (True, 'HTTP_INTERNAL_ERROR'),
            *[(49, dict(category=category)) for category in start_diagnostic.PRIVATE_CATEGORIES]]
        for code in (50, 52):
            cases.extend((code, diagnostic) for diagnostic in (None, '', 'UNKNOWN', 'SUCCESS',
                'HTTP_CONFLICT_UNKNOWN', 'CONNECTION_LOST' if code == 50 else 'HTTP_INTERNAL_ERROR',
                {'category': 'HTTP_INTERNAL_ERROR'}, {}))
        for code, diagnostic in cases:
            with self.subTest(code=code, diagnostic=diagnostic), self.joined(code, diagnostic, context=context) as f:
                with self.assertRaises(ValueError):
                    f.run(failed=True, disconnected=True, vm_recovery=True)

    def test_two_volume_real_join_requires_explicit_full_case_and_every_recovery_gate(self):
        selected = dict(vm_cut=None, full=True, two_volume=True, fault_case='vm-two-volume-drain-reply-gap')
        cases = [({'full': False}, {}), ({'two_volume': False}, {}), ({'storage_restart': False}, {}),
            *[({'fault_case': case}, {}) for case in (None, 'first-child-published', 'two-volume-drain', '')],
            ({'vm_cut': 'vm-two-volume-drain-reply-gap'}, {}),
            ({}, {'failed': False}), ({}, {'disconnected': False}), ({}, {'worker_failed': True}),
            *[({}, {'expected_exit': code}) for code in (0, 50, 52, False)]]
        for context, overrides in cases:
            with self.subTest(context=context, overrides=overrides), \
                 self.joined(50, 'HTTP_INTERNAL_ERROR', context={**selected, **context}) as f, \
                 patch.object(ack, 'vm_start_failure', wraps=ack.vm_start_failure) as classify:
                args = dict(failed=True, disconnected=True, vm_recovery=True)
                args.update(overrides)
                with self.assertRaisesRegex(ValueError, 'VM cut start outcome only after storage recovery'):
                    f.run(**args)
                classify.assert_not_called()

    def test_real_join_default_and_non_ack_disconnect_still_require_exit52(self):
        # Without explicit recovery opt-in, even the full two-volume case requires exit52.
        for context in ({}, {'active_ack': None, 'vm_cut': None},
                {'storage_restart': False, 'vm_cut': None},
                {'active_ack': None, 'vm_cut': None, 'two_volume': True},
                {'vm_cut': None, 'two_volume': True, 'full': True, 'fault_case': 'vm-two-volume-drain-reply-gap'}):
            for code, diagnostic in ((52, 'CONNECTION_LOST'), (50, 'HTTP_INTERNAL_ERROR')):
                with self.subTest(context=context, code=code), self.joined(code, diagnostic, context=context) as f, \
                     patch.object(ack, 'vm_start_failure', wraps=ack.vm_start_failure) as classify:
                    if code == 52:
                        f.run(failed=True, disconnected=True)
                    else:
                        with self.assertRaisesRegex(ValueError, 'real Docker start response'):
                            f.run(failed=True, disconnected=True)
                    classify.assert_not_called()


class UnexposedVMPeer(unittest.TestCase):
    def test_full_intent_inventory_rejects_every_peer_instance_phase_and_key(self):
        proof = dict(container='3'*64, containerInstance=A7['uid']())
        unrelated = dict(container='4'*64, containerInstance=proof['containerInstance'])
        state = dict(intents={A7['uid'](): unrelated})
        saved = copy.deepcopy((state, proof))
        self.assertIs(ack.unexposed_vm_peer(state, proof), proof)
        self.assertEqual((state, proof), saved)
        for instance in (proof['containerInstance'], A7['uid']()):
            for phase in ('prepareAdmitted', 'running', 'quarantined', 'retired'):
                for key in ('missing', None, 'a'*64):
                    with self.subTest(instance=instance, phase=phase, key=key):
                        slot = dict(role='runtime')
                        if key != 'missing': slot['key'] = key
                        bad = copy.deepcopy(state)
                        bad['intents'][A7['uid']()] = dict(container=proof['container'],
                            containerInstance=instance, phase=phase, slots=[slot])
                        with self.assertRaises(ValueError): ack.unexposed_vm_peer(bad, proof)
        for field, value in (('container', 'bad'), ('containerInstance', 'bad'),
                             ('containerInstance', '00000000-0000-0000-0000-000000000000')):
            bad = dict(proof, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                ack.unexposed_vm_peer(state, bad)

    @contextmanager
    def fixture(self, fault=None):
        """Real prepared-peer and new guards; mock only files/native launch edges."""
        ids = ['1'*64, '2'*64, '3'*64, '4'*64]
        plan = dict(container='idle-peer', owner='fixture-owner')
        daemon = SimpleNamespace(root=Path('/owned/root'))
        peer = Mock(id=ids[2], attrs=dict(State=dict(Status='created', Running=False),
            Config=dict(Labels={p.OWNER: plan['owner']})))
        peer.name = plan['container']
        prepared = dict(currentContainer=dict(id=peer.id, instanceID=A7['uid']()),
            specification=dict(containerID=peer.id, generation=1, shimLaunchUUID=A7['uid']()))
        def arguments():
            spec = prepared['specification']
            generation = '%020d-%s' % (spec['generation'], spec['shimLaunchUUID'])
            path = daemon.root/'containers'/peer.id/'shim-generations'/generation/'spec.json'
            return ('/owned/cengine', 'vm-shim', '--spec', str(path), '--launch-intent', str(path.parent/'intent.json'))
        native = harness.RuntimeProcess(60, executable='/owned/cengine', arguments=arguments(), identity=(10, 2, 300), pidversion=8)
        hosts = [replace(native, pid=70+i, arguments=(), identity=(20+i, 3, 400+i), pidversion=20+i) for i in range(3)]
        survivors = [*hosts, native]
        census = list(survivors)
        state = dict(intents={A7['uid'](): dict(container=ids[0], phase='retired')})
        def native_proof(process):
            return dict(p.native_proof(process), container=peer.id,
                generation=prepared['specification']['generation'], launch=prepared['specification']['shimLaunchUUID'])
        initial_raw = p.canonical(prepared)
        original = (native, dict(native_proof(native), preparedSHA256=p.digest(initial_raw),
            containerInstance=prepared['currentContainer']['instanceID']))
        validator = Mock()
        @contextmanager
        def workload_owner(process, *args, **kwargs):
            self.assertIsNone(args[2])  # Never fabricate a storage intent for this peer.
            yield native_proof(process), None, validator
        directory = Mock(fd=900)
        directory.validate = Mock()
        reads = []
        def read(name, limit, **kwargs):
            self.assertEqual(name, 'prepared-shim.json'); self.assertEqual(limit, 1024*1024)
            reads.append(name)
            raw = p.canonical(prepared)
            digest = 'f'*64 if fault == 'canonical-reread' and len(reads) > 1 else p.digest(raw)
            return raw, (3, 4, digest)
        directory.read.side_effect = read
        client = Mock()
        client.containers.list.return_value = [SimpleNamespace(id=value) for value in ids]
        inventory = list(ids)
        live = {v.pid: v for v in survivors}
        events = []
        record = Mock(side_effect=lambda phase, **value: events.append(phase))
        read_state = Mock(return_value=({'root': {}}, state, {}))
        def mutate():
            if fault == 'peer-gone': census.remove(native); live.pop(native.pid)
            elif fault in ('peer-replaced', 'peer-incarnation'):
                changed = (replace(native, pid=61) if fault == 'peer-replaced' else
                    replace(native, identity=(50, 6, 999), pidversion=99))
                census[census.index(native)] = changed; live.pop(native.pid); live[changed.pid] = changed
            elif fault in ('instance', 'generation', 'canonical'):
                if fault == 'instance': prepared['currentContainer']['instanceID'] = A7['uid']()
                elif fault == 'generation': prepared['specification']['generation'] += 1
                else: prepared['canonicalRevision'] = 2
                changed = replace(native, arguments=arguments())
                census[census.index(native)] = changed; live[native.pid] = changed
            elif fault in ('running', 'exited', 'running-status-created'):
                peer.attrs['State'].update(Status='created' if fault == 'running-status-created' else fault,
                    Running=fault != 'exited')
            elif fault == 'peer-intent':
                state['intents'][A7['uid']()] = dict(container=peer.id, containerInstance=A7['uid'](),
                    phase='retired', slots=[dict(role='runtime', key=None)])
            elif fault and fault.startswith('api-'):
                values = client.containers.list.return_value
                if fault == 'api-missing': values.pop()
                elif fault == 'api-extra': values.append(SimpleNamespace(id='5'*64))
                elif fault == 'api-duplicate': values.append(values[0])
            elif fault and fault.startswith('canonical-') and fault != 'canonical-reread':
                if fault == 'canonical-missing': inventory.pop()
                elif fault == 'canonical-extra': inventory.append('5'*64)
                elif fault == 'canonical-duplicate': inventory.append(inventory[0])
            elif fault == 'unrelated-gone': census.remove(hosts[0]); live.pop(hosts[0].pid)
            elif fault == 'unrelated-birth': live[hosts[0].pid] = replace(hosts[0], identity=(99, 1, 999))
            elif fault == 'unrelated-replaced':
                changed = replace(hosts[0], identity=(99, 1, 999), pidversion=99)
                census[census.index(hosts[0])] = changed; live[hosts[0].pid] = changed
            elif fault == 'census-extra':
                changed = replace(hosts[0], pid=99); census.append(changed); live[99] = changed
            elif fault == 'census-duplicate': census.append(hosts[0])
            elif fault == 'validator': validator.side_effect = ValueError('native launch changed')
            elif fault == 'root': read_state.return_value[0]['root'] = {'inode': 99}
        with ExitStack() as stack:
            stack.enter_context(patch.object(p, 'Directory', side_effect=lambda *a, **k: nullcontext(directory)))
            stack.enter_context(patch.object(p, 'workload_owner', side_effect=workload_owner))
            stack.enter_context(patch.object(harness, '_kernel_process', side_effect=lambda pid: live.get(pid)))
            stack.enter_context(patch.object(ack.os, 'listdir', side_effect=lambda fd: list(inventory)))
            yield SimpleNamespace(daemon=daemon, client=client, peer=peer, peer_plan=plan, root_identity={},
                census=census, expected_survivors=survivors, original_owner=original, containers=ids,
                read_state=read_state, record=record, mutate=mutate, events=events, validator=validator)

    def revalidate(self, fixture):
        return ack.revalidate_vm_peer(**{key: getattr(fixture, key) for key in (
            'daemon', 'client', 'peer', 'peer_plan', 'root_identity', 'census', 'expected_survivors',
            'original_owner', 'containers', 'read_state', 'record')})

    def test_actual_revalidation_accepts_only_unchanged_created_unexposed_peer(self):
        with self.fixture() as f:
            self.assertIsNone(self.revalidate(f))
            self.assertEqual(f.validator.call_count, 2)  # Enter plus explicit fresh-context revalidation.
            f.peer.reload.assert_called_once()
            f.client.containers.list.assert_called_once_with(all=True)
            f.read_state.assert_called_once()
            self.assertEqual(f.events, ['storage-unstarted-peer-revalidated'])
            f.peer.start.assert_not_called()
            f.peer.stop.assert_not_called()
            f.peer.remove.assert_not_called()

    def test_parent_reattachment_runs_real_guard_before_any_ack_restart(self):
        tree = ast.parse((ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
        guard = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == 'active_ack is not None'
            and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                and c.func.id == 'revalidate_vm_peer' for c in ast.walk(n)))
        siblings = next(n.body for n in ast.walk(tree) if isinstance(getattr(n, 'body', None), list)
            and guard in n.body)
        start = next(i for i, n in enumerate(siblings) if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'ids' for t in n.targets))
        recovery_tail = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == '(api_restart or storage_restart) and matrix is None')
        self.assertLess(guard.lineno, recovery_tail.lineno)
        code = compile(ast.Module(body=[*siblings[start:siblings.index(guard)+1],
            *recovery_tail.body], type_ignores=[]), 'same-client-peer-revalidation', 'exec')
        for fault in (None, 'peer-intent', 'instance', 'generation', 'canonical', 'running',
                      'api-missing', 'api-extra', 'api-duplicate', 'canonical-extra', 'unrelated-birth'):
            with self.subTest(fault=fault), self.fixture(fault) as f:
                old_client = Mock()
                plan = dict(container='prepare', volume='volume', image='image', owner='fixture-owner')
                container = Mock(id=f.containers[0], attrs=dict(Config=dict(Labels={p.OWNER: plan['owner']})))
                container.name = plan['container']
                volume = Mock(attrs=dict(Labels={p.OWNER: plan['owner']})); volume.name = plan['volume']
                image = Mock(id='image-id', attrs=dict(RepoTags=[plan['image']], Config=dict(Labels={p.OWNER: plan['owner']})))
                f.client.containers.get.side_effect = {container.id: container, f.peer.id: f.peer}.__getitem__
                f.client.volumes.get.return_value = volume; f.client.images.get.return_value = image
                f.client.version.return_value = dict(GitCommit='commit')
                f.daemon.socket = '/owned/socket'
                active = Mock(ids=[f.containers[1], f.containers[3]])
                active.reattach.side_effect = lambda client: f.events.append('ack-reattached')
                active.recover.side_effect = lambda *a, **kw: f.events.append('ack-restarted')
                closed_validator = Mock(side_effect=AssertionError('closed original validator reused'))
                interrupted = replace(f.original_owner[0], pid=99)
                def fresh_client(**kwargs):
                    f.events.append('fresh-client'); f.mutate(); return f.client
                env = dict(client=old_client, docker=SimpleNamespace(DockerClient=fresh_client),
                    daemon=f.daemon, proof=p, expected_commit='commit', container=container, peer=f.peer,
                    volume=volume, image=image, plan=plan, peer_plan=f.peer_plan, active_ack=active,
                    manifest={'root': f.root_identity}, processes=lambda: f.census,
                    before=[*f.expected_survivors, interrupted], process=interrupted,
                    peer_owner=(*f.original_owner, closed_validator), read_state=f.read_state,
                    record=f.record, start=Mock(), joined_start=Mock(), service_recovery={},
                    vm_cut=vm.CASES[0])
                if fault:
                    with self.assertRaises(ValueError): exec(code, env)
                    active.reattach.assert_not_called(); active.recover.assert_not_called()
                    self.assertNotIn('storage-unstarted-peer-revalidated', f.events)
                else:
                    exec(code, env)
                    self.assertEqual(f.events, ['fresh-client', 'storage-unstarted-peer-revalidated',
                        'ack-reattached', 'ack-restarted'])
                    active.reattach.assert_called_once_with(f.client)
                    active.recover.assert_called_once_with({}, storage_vm=True)
                    env['joined_start'].assert_called_once_with(env['start'], failed=True,
                        disconnected=True, vm_recovery=True)
                old_client.close.assert_called_once()
                closed_validator.assert_not_called()

    def test_actual_revalidation_rejects_post_api_only_mutations_before_ack_restart(self):
        faults = ('peer-gone', 'peer-replaced', 'peer-incarnation', 'instance', 'generation', 'canonical',
            'canonical-reread', 'running', 'exited', 'running-status-created', 'peer-intent',
            'api-missing', 'api-extra', 'api-duplicate', 'canonical-missing', 'canonical-extra',
            'canonical-duplicate', 'unrelated-gone', 'unrelated-birth', 'unrelated-replaced',
            'census-extra', 'census-duplicate', 'validator', 'root')
        for fault in faults:
            with self.subTest(fault=fault), self.fixture(fault) as f:
                restart_ack = Mock()
                f.mutate()  # Only the newly reattached API/native view changes.
                with self.assertRaises(ValueError):
                    self.revalidate(f)
                    restart_ack()
                restart_ack.assert_not_called()
                self.assertNotIn('storage-unstarted-peer-revalidated', f.events)


if __name__ == '__main__': unittest.main()
