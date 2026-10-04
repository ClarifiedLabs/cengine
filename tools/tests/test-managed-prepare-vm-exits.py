#!/usr/bin/env python3
"""Direct monitor regressions; native/kqueue mocks are not VM durability evidence."""
from contextlib import ExitStack
from dataclasses import replace
from itertools import permutations
from pathlib import Path
from types import SimpleNamespace
import select
import signal
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import harness
import managed_prepare_faults as p
import managed_prepare_vm_exits as exits
import managed_storage_recovery as r


def process(pid):
    return harness.RuntimeProcess(pid, executable="/owned/cengine",
        arguments=("/owned/cengine", "vm-shim", "--spec", f"/owned/{pid}/spec.json"),
        identity=(1700000000 + pid, pid, pid + 10000), pidversion=pid + 100)


def event(pid, **changes):
    fields = dict(ident=pid, filter=select.KQ_FILTER_PROC,
        flags=select.KQ_EV_ONESHOT, fflags=select.KQ_NOTE_EXIT, data=0)
    fields.update(changes)
    return SimpleNamespace(**fields)


class Queue:
    def __init__(self):
        self.registrations, self.pending, self.reads = [], [], []
        self.closed = 0
        self.registration_error = self.read_error = self.on_read = None
        self.registration_result = []

    def control(self, changes, maximum, timeout):
        if changes is not None:
            self.registrations.extend(changes)
            if self.registration_error:
                raise self.registration_error
            return self.registration_result
        self.reads.append((maximum, timeout))
        if self.read_error:
            raise self.read_error
        if self.on_read:
            self.on_read()
        result, self.pending = self.pending[:maximum], self.pending[maximum:]
        return result

    def close(self):
        self.closed += 1


class Edges:
    def __init__(self, owner_count=3):
        self.owners = tuple(process(pid) for pid in (101, 102, 103)[:owner_count])
        self.api, self.idle = process(200), process(201)
        self.expected = [self.api, self.idle, *self.owners]
        self.native = {value.pid: value for value in self.expected}
        self.runtime = self.native.copy()
        self.queue, self.records = Queue(), []
        self.census_calls = self.budget_calls = 0
        self.budget_limit = 100
        self.before_census = self.after_census = self.before_native = None

    def remaining(self):
        self.budget_calls += 1
        if self.budget_calls > self.budget_limit:
            raise TimeoutError("test campaign deadline")
        return 0.0001

    def processes(self):
        self.census_calls += 1
        if self.before_census:
            self.before_census()
        result = list(self.runtime.values())
        if self.after_census:
            self.after_census()
        return result

    def kernel(self, pid):
        if self.before_native:
            self.before_native(pid)
        return self.native.get(pid)

    def record(self, name, **value):
        self.records.append((name, value))

    def monitor(self, owners=None):
        return exits.VMExposedOwnerExits(self.owners if owners is None else owners,
            self.processes, self.remaining, self.record)

    def patches(self):
        stack = ExitStack()
        stack.enter_context(patch.object(select, "kqueue", return_value=self.queue))
        stack.enter_context(patch.object(harness, "_kernel_process", side_effect=self.kernel))
        return stack

    def die(self, owner, *, note=True, replacement=None, runtime_replacement=False):
        self.native.pop(owner.pid, None)
        self.runtime.pop(owner.pid, None)
        if replacement is not None:
            self.native[owner.pid] = replacement
            if runtime_replacement:
                self.runtime[owner.pid] = replacement
        if note:
            self.queue.pending.append(event(owner.pid))

    def kill_all(self):
        for owner in self.owners:
            self.die(owner)


class VMExposedOwnerExitsTests(unittest.TestCase):
    def assert_record(self, edge, owner, phase):
        self.assertIn(("storage-exposed-owner-exit-observed",
            dict(native=p.native_proof(owner), observedAt=phase)), edge.records)

    def test_registration_is_original_three_proc_exit_oneshots_before_delivery(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            self.assertEqual([v.ident for v in edge.queue.registrations], [v.pid for v in edge.owners])
            for value in edge.queue.registrations:
                self.assertEqual(value.filter, select.KQ_FILTER_PROC)
                self.assertEqual(value.fflags, select.KQ_NOTE_EXIT)
                self.assertEqual(value.flags, select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT)
            monitor.before_signal()
            self.assertFalse(edge.records)
        self.assertEqual(edge.queue.closed, 1)
        self.assertTrue(all(maximum == 3 and timeout == 0 for maximum, timeout in edge.queue.reads))
        self.assertEqual(set(edge.native), {v.pid for v in edge.expected})  # No implicit kills.

    def test_late_all_after_recovery_api_birth(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.before_signal(); monitor.delivered()
            self.assertEqual(monitor.observe(edge.expected, "storage-death"), edge.expected)
            self.assertFalse(edge.records)
            edge.kill_all()
            self.assertEqual(monitor.join_all(edge.expected, "recovery-api-born"), [edge.api, edge.idle])
            for owner in edge.owners:
                self.assert_record(edge, owner, "recovery-api-born")
            monitor.observe(edge.expected, "reopened")
            self.assertEqual(len(edge.records), 3)

    def test_early_all_before_api_recovery(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered(); edge.kill_all()
            self.assertEqual(monitor.observe(edge.expected, "storage-death"), [edge.api, edge.idle])
            self.assertEqual(monitor.join_all(edge.expected, "later"), [edge.api, edge.idle])
            for owner in edge.owners:
                self.assert_record(edge, owner, "storage-death")
            self.assertEqual(len(edge.records), 3)

    def test_eager_exits_during_audited_signal_return_are_observed_not_dated(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.before_signal()
            # Model synchronous containment during successful signal_storage().
            # The parent's delivered marker necessarily follows that call.
            edge.kill_all()
            monitor.delivered()
            self.assertEqual(monitor.observe(edge.expected, "after-signal-return"), [edge.api, edge.idle])
            for owner in edge.owners:
                self.assert_record(edge, owner, "after-signal-return")
            self.assertTrue(all(set(value) == {"native", "observedAt"} for _, value in edge.records))

    def test_mixed_exits_across_known_api_and_storage_censuses(self):
        edge = Edges()
        first, second, third = edge.owners
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered(); edge.die(first)
            self.assertEqual(monitor.observe(edge.expected, "storage-death"), [edge.api, edge.idle, second, third])
            edge.die(edge.api, note=False)
            expected = [edge.idle, *edge.owners]
            self.assertEqual(monitor.observe(expected, "api-death"), [edge.idle, second, third])
            fresh_api, fresh_storage = process(210), process(211)
            for value in (fresh_api, fresh_storage):
                edge.native[value.pid] = edge.runtime[value.pid] = value
            expected += [fresh_api, fresh_storage]
            edge.die(second)
            monitor.observe(expected, "api-born")
            edge.die(third)
            self.assertEqual(monitor.join_all(expected, "storage-born"), [edge.idle, fresh_api, fresh_storage])
            for owner, phase in zip(edge.owners, ("storage-death", "api-born", "storage-born")):
                self.assert_record(edge, owner, phase)
            self.assertEqual(len(edge.records), 3)

    def test_every_selected_exit_order_preserves_first_observed_phase(self):
        for order in permutations(range(3)):
            with self.subTest(order=order):
                edge = Edges()
                with edge.patches(), edge.monitor() as monitor:
                    monitor.delivered()
                    for phase, index in enumerate(order):
                        edge.die(edge.owners[index])
                        monitor.observe(edge.expected, str(phase))
                        self.assert_record(edge, edge.owners[index], str(phase))
                    monitor.join_all(edge.expected, "final")
                self.assertEqual(len(edge.records), 3)

    def test_original_owner_count_type_and_unique_pid_required(self):
        edge = Edges()
        for owners in ((), edge.owners[:2], (*edge.owners, edge.api),
                (edge.owners[0], edge.owners[0], edge.owners[2]),
                (p.native_proof(edge.owners[0]), *edge.owners[1:])):
            with self.subTest(owners=owners), self.assertRaises(r.ProofFailure):
                edge.monitor(owners)

    def test_complete_original_native_birth_and_pidversion_required(self):
        edge = Edges()
        for change in (dict(pid=1), dict(pid=True), dict(identity=None), dict(identity=(1, 2)),
                dict(identity=(0, 0, 1)), dict(identity=(1, 1000000, 1)),
                dict(identity=(1, 0, 0)), dict(identity=(1, False, 2)),
                dict(pidversion=None), dict(pidversion=0), dict(pidversion=2**32)):
            with self.subTest(change=change), self.assertRaises(r.ProofFailure):
                edge.monitor((replace(edge.owners[0], **change), *edge.owners[1:]))

    def test_preexisting_death_rejected_before_queue_allocation(self):
        edge = Edges(); edge.die(edge.owners[0])
        with edge.patches(), self.assertRaises(r.ProofFailure):
            with edge.monitor():
                self.fail("entered with dead owner")
        self.assertFalse(edge.queue.registrations)
        self.assertFalse(edge.records)

    def test_death_after_enter_before_signal_is_rejected_and_queue_closed(self):
        for note in (False, True):
            edge = Edges()
            with self.subTest(note=note), edge.patches(), self.assertRaises(r.ProofFailure):
                with edge.monitor() as monitor:
                    edge.die(edge.owners[1], note=note)
                    monitor.before_signal()
            self.assertEqual(edge.queue.closed, 1)
            self.assertFalse(edge.records)

    def test_event_before_delivery_is_rejected_even_with_original_live(self):
        edge = Edges(); edge.queue.pending.append(event(edge.owners[0].pid))
        with edge.patches(), self.assertRaisesRegex(r.ProofFailure, "before storage delivery"):
            with edge.monitor():
                self.fail("entered with prekill event")
        self.assertEqual(edge.queue.closed, 1)
        self.assertFalse(edge.records)

    def test_event_during_prekill_native_checks_is_rejected(self):
        edge = Edges()
        with edge.patches(), self.assertRaises(r.ProofFailure):
            with edge.monitor() as monitor:
                def during(pid):
                    if pid == edge.owners[-1].pid:
                        edge.queue.pending.append(event(edge.owners[0].pid))
                edge.before_native = during
                monitor.before_signal()
        self.assertEqual(edge.queue.closed, 1)

    def test_pre_registration_pid_replacement_rejected(self):
        edge = Edges()
        edge.native[edge.owners[0].pid] = replace(edge.owners[0], pidversion=999)
        with edge.patches(), self.assertRaises(r.ProofFailure):
            with edge.monitor():
                self.fail("replaced original")
        self.assertFalse(edge.queue.registrations)

    def test_delivery_is_required_before_observation(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            edge.kill_all()
            with self.assertRaises(r.ProofFailure):
                monitor.observe(edge.expected, "pre-delivery")
            with self.assertRaises(r.ProofFailure):
                monitor.join_all(edge.expected, "pre-delivery")
            self.assertFalse(edge.records)

    def test_delivery_requires_open_validated_context_and_cannot_repeat(self):
        edge = Edges(); monitor = edge.monitor()
        with self.assertRaises(r.ProofFailure): monitor.delivered()
        with edge.patches(), monitor:
            monitor.delivered()
            with self.assertRaises(r.ProofFailure): monitor.delivered()
            with self.assertRaises(r.ProofFailure): monitor.before_signal()
        with self.assertRaises(r.ProofFailure): monitor.delivered()
        with self.assertRaises(r.ProofFailure): monitor.__enter__()

    def test_native_absence_without_event_never_passes(self):
        for index in range(3):
            edge = Edges()
            with self.subTest(index=index), edge.patches(), self.assertRaisesRegex(r.ProofFailure, "without preregistered"):
                with edge.monitor() as monitor:
                    monitor.delivered(); edge.die(edge.owners[index], note=False)
                    monitor.observe(edge.expected, "absent")
            self.assertFalse(edge.records)
            self.assertEqual(edge.queue.closed, 1)

    def test_malformed_note_filter_error_receipt_or_pid_is_not_death(self):
        bad = (dict(ident=999), dict(filter=select.KQ_FILTER_READ),
            dict(flags=select.KQ_EV_ERROR), dict(flags=0x40),
            dict(fflags=0), dict(fflags=select.KQ_NOTE_FORK),
            dict(fflags=select.KQ_NOTE_EXIT | select.KQ_NOTE_FORK))
        for change in bad:
            edge = Edges()
            with self.subTest(change=change), edge.patches(), self.assertRaises(r.ProofFailure):
                with edge.monitor() as monitor:
                    monitor.delivered(); edge.die(edge.owners[0], note=False)
                    edge.queue.pending.append(event(edge.owners[0].pid, **change))
                    monitor.observe(edge.expected, "invalid")
            self.assertFalse(edge.records)
            self.assertEqual(edge.queue.closed, 1)

    def test_duplicate_events_are_not_independent_proofs(self):
        edge = Edges()
        with edge.patches(), self.assertRaises(r.ProofFailure):
            with edge.monitor() as monitor:
                monitor.delivered(); edge.die(edge.owners[0])
                edge.queue.pending.append(event(edge.owners[0].pid))
                monitor.observe(edge.expected, "duplicate")
        self.assertFalse(edge.records)

    def test_repeated_consumed_event_is_rejected(self):
        edge = Edges()
        with edge.patches(), self.assertRaises(r.ProofFailure):
            with edge.monitor() as monitor:
                monitor.delivered(); edge.die(edge.owners[0])
                monitor.observe(edge.expected, "first")
                edge.queue.pending.append(event(edge.owners[0].pid))
                monitor.observe(edge.expected, "replayed")
        self.assertEqual(len(edge.records), 1)

    def test_event_with_still_live_original_is_not_death_proof(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered()
            edge.queue.pending.extend(event(v.pid) for v in edge.owners)
            self.assertEqual(monitor.observe(edge.expected, "live-note"), edge.expected)
            self.assertFalse(edge.records)
            for owner in edge.owners: edge.die(owner, note=False)
            monitor.join_all(edge.expected, "native-exit")
            for owner in edge.owners: self.assert_record(edge, owner, "native-exit")

    def test_live_owner_even_with_all_events_hits_bounded_join_deadline(self):
        edge = Edges()
        with edge.patches(), self.assertRaises(TimeoutError):
            with edge.monitor() as monitor:
                monitor.delivered()
                edge.queue.pending.extend(event(v.pid) for v in edge.owners)
                edge.budget_limit = edge.budget_calls + 5
                monitor.join_all(edge.expected, "still-live")
        self.assertFalse(edge.records)
        self.assertEqual(edge.queue.closed, 1)

    def test_zero_remaining_budget_rejected(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered()
            monitor.remaining = lambda: 0
            with self.assertRaisesRegex(r.ProofFailure, "deadline"):
                monitor.observe(edge.expected, "expired")

    def test_duplicate_expected_census_and_missing_original_fail_before_snapshot(self):
        for kind in ("duplicate", "missing", "changed"):
            edge = Edges()
            with self.subTest(kind=kind), edge.patches(), edge.monitor() as monitor:
                monitor.delivered()
                expected = list(edge.expected)
                if kind == "duplicate": expected.append(edge.idle)
                elif kind == "missing": expected.remove(edge.owners[0])
                else: expected[-1] = replace(edge.owners[-1], pidversion=999)
                with self.assertRaises(r.ProofFailure): monitor.observe(expected, "bad-expected")
                self.assertEqual(edge.census_calls, 0)

    def test_duplicate_actual_census_rejected_before_map(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered()
            monitor.processes = lambda: [*edge.expected, edge.idle]
            with self.assertRaisesRegex(r.ProofFailure, "duplicate"):
                monitor.observe(edge.expected, "duplicate")

    def test_extra_or_changed_census_process_rejected_without_retry(self):
        for change in ("extra", "birth", "pidversion", "argv", "executable"):
            for selected in (False, True):
                edge = Edges(); owner = edge.owners[0] if selected else edge.idle
                with self.subTest(change=change, selected=selected), edge.patches(), edge.monitor() as monitor:
                    monitor.delivered()
                    if change == "extra": edge.runtime[900] = process(900)
                    else:
                        fields = dict(birth=dict(identity=(10, 20, 30)), pidversion=dict(pidversion=999),
                            argv=dict(arguments=("changed",)), executable=dict(executable="/different"))
                        edge.runtime[owner.pid] = replace(owner, **fields[change])
                    with self.assertRaises(r.ProofFailure): monitor.observe(edge.expected, "changed")
                    self.assertEqual(edge.census_calls, 1)
                    self.assertFalse(edge.records)

    def test_missing_protected_api_or_idle_rejected_even_if_all_selected_exit(self):
        for idle in (False, True):
            edge = Edges(); owner = edge.idle if idle else edge.api
            with self.subTest(idle=idle), edge.patches(), edge.monitor() as monitor:
                monitor.delivered(); edge.kill_all(); edge.die(owner, note=False)
                with self.assertRaisesRegex(r.ProofFailure, "missing protected"):
                    monitor.observe(edge.expected, "protected-missing")
                self.assertEqual(edge.census_calls, 1)

    def test_protected_native_death_or_replacement_rejected_with_stale_census(self):
        for current in (None, process(999)):
            edge = Edges()
            with self.subTest(current=current), edge.patches(), edge.monitor() as monitor:
                monitor.delivered()
                edge.native[edge.idle.pid] = current
                with self.assertRaisesRegex(r.ProofFailure, "protected native"):
                    monitor.observe(edge.expected, "protected-changed")
                self.assertEqual(edge.census_calls, 1)

    def test_protected_death_during_selected_native_inspection_is_rejected(self):
        for replacement in (None, process(999)):
            edge = Edges()
            with self.subTest(replacement=replacement), edge.patches(), edge.monitor() as monitor:
                monitor.delivered()
                def during(pid):
                    if pid == edge.owners[0].pid:
                        edge.native[edge.idle.pid] = replacement
                edge.before_native = during
                with self.assertRaisesRegex(r.ProofFailure, "protected native"):
                    monitor.observe(edge.expected, "late-protected-change")
                self.assertEqual(edge.census_calls, 1)

    def test_selected_live_native_argv_change_rejected(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered()
            edge.native[edge.owners[0].pid] = replace(edge.owners[0], arguments=("changed",))
            with self.assertRaises(r.ProofFailure): monitor.observe(edge.expected, "exec")
            self.assertFalse(edge.records)

    def test_selected_filtered_missing_but_native_live_rejected(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered(); edge.runtime.pop(edge.owners[0].pid)
            edge.queue.pending.append(event(edge.owners[0].pid))
            with self.assertRaisesRegex(r.ProofFailure, "live exposed owner missing"):
                monitor.observe(edge.expected, "filtered")
            self.assertFalse(edge.records)

    def test_fully_reused_pid_outside_runtime_can_prove_original_exit(self):
        edge = Edges(); owner = edge.owners[0]
        reused = replace(process(999), pid=owner.pid, executable="/outsider", arguments=("/outsider",))
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered(); edge.die(owner, replacement=reused)
            result = monitor.observe(edge.expected, "reused-outside")
            self.assertNotIn(owner, result)
            self.assert_record(edge, owner, "reused-outside")

    def test_selected_reused_runtime_pid_is_always_rejected(self):
        edge = Edges(); owner = edge.owners[0]
        reused = replace(process(999), pid=owner.pid)
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered(); edge.die(owner, replacement=reused, runtime_replacement=True)
            with self.assertRaisesRegex(r.ProofFailure, "extra or changed"):
                monitor.observe(edge.expected, "reused-runtime")
            self.assertFalse(edge.records)

    def test_ambiguous_native_reuse_or_wrong_pid_rejected(self):
        for change in (dict(pidversion=999), dict(identity=(10, 20, 30)), dict(pid=999),
                dict(identity=(10, 20, 30), pidversion=None)):
            edge = Edges(); owner = edge.owners[0]
            with self.subTest(change=change), edge.patches(), edge.monitor() as monitor:
                monitor.delivered(); edge.die(owner, replacement=replace(owner, **change))
                with self.assertRaises(r.ProofFailure): monitor.observe(edge.expected, "ambiguous")
                self.assertFalse(edge.records)

    def test_selected_exit_during_census_safely_reobserves_once(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered()
            def during():
                edge.after_census = None
                edge.die(edge.owners[0])
            edge.after_census = during
            result = monitor.observe(edge.expected, "snapshot-race")
            self.assertNotIn(edge.owners[0], result)
            self.assertEqual(edge.census_calls, 2)
            self.assert_record(edge, edge.owners[0], "snapshot-race")

    def test_three_monotonic_census_exit_transitions_are_bounded(self):
        edge = Edges(); remaining = list(edge.owners)
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered()
            def during():
                if remaining: edge.die(remaining.pop(0))
            edge.after_census = during
            self.assertEqual(monitor.observe(edge.expected, "racing"), [edge.api, edge.idle])
            self.assertEqual(edge.census_calls, 4)
            self.assertEqual(len(edge.records), 3)

    def test_stale_census_without_positive_event_cannot_retry(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered()
            edge.after_census = lambda: edge.die(edge.owners[0], note=False)
            with self.assertRaises(r.ProofFailure): monitor.observe(edge.expected, "unproved-race")
            self.assertEqual(edge.census_calls, 1)
            self.assertFalse(edge.records)

    def test_persistently_stale_dead_owner_census_does_not_retry_arbitrarily(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered(); edge.die(edge.owners[0])
            edge.runtime[edge.owners[0].pid] = edge.owners[0]
            with self.assertRaisesRegex(r.ProofFailure, "previously exited"):
                monitor.observe(edge.expected, "stale")
            self.assertEqual(edge.census_calls, 2)
            self.assertEqual(len(edge.records), 1)

    def test_native_original_cannot_revive_after_proven_exit(self):
        edge = Edges()
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered(); edge.die(edge.owners[0])
            monitor.observe(edge.expected, "first")
            edge.native[edge.owners[0].pid] = edge.owners[0]
            with self.assertRaises(r.ProofFailure): monitor.observe(edge.expected, "revived")
            self.assertEqual(len(edge.records), 1)

    def test_native_and_census_inspection_errors_propagate_without_retry(self):
        for kernel in (False, True):
            edge = Edges(); failure = RuntimeError("inspection failure")
            with self.subTest(kernel=kernel), edge.patches(), self.assertRaises(RuntimeError) as raised:
                with edge.monitor() as monitor:
                    monitor.delivered()
                    def fail(*args): raise failure
                    if kernel: edge.before_native = fail
                    else: edge.before_census = fail
                    monitor.observe(edge.expected, "inspection")
            self.assertIs(raised.exception, failure)
            self.assertEqual(edge.census_calls, 1)
            self.assertEqual(edge.queue.closed, 1)

    def test_registration_error_and_receipt_close_queue(self):
        for error in (False, True):
            edge = Edges()
            if error: edge.queue.registration_error = OSError("registration failed")
            else: edge.queue.registration_result = [event(edge.owners[0].pid, flags=0x40)]
            with self.subTest(error=error), edge.patches(), self.assertRaises((OSError, r.ProofFailure)):
                with edge.monitor(): self.fail("bad registration")
            self.assertEqual(edge.queue.closed, 1)

    def test_queue_drain_failure_closes_queue(self):
        edge = Edges(); edge.queue.read_error = OSError("kqueue failure")
        with edge.patches(), self.assertRaises(OSError):
            with edge.monitor(): self.fail("bad queue")
        self.assertEqual(edge.queue.closed, 1)

    def test_body_failure_and_repeated_close_never_signal(self):
        edge = Edges(); monitor = edge.monitor()
        with edge.patches(), self.assertRaisesRegex(RuntimeError, "body failure"):
            with monitor: raise RuntimeError("body failure")
        monitor.__exit__(None, None, None)
        self.assertEqual(edge.queue.closed, 1)
        self.assertEqual(list(edge.native.values()), edge.expected)

    def test_record_failure_propagates_and_closes_queue(self):
        edge = Edges()
        with edge.patches(), self.assertRaisesRegex(OSError, "record failure"):
            with edge.monitor() as monitor:
                monitor.delivered(); edge.die(edge.owners[0])
                def fail(*args, **kwargs): raise OSError("record failure")
                monitor.record = fail
                monitor.observe(edge.expected, "record")
        self.assertEqual(edge.queue.closed, 1)


class APIJoinedRefreshTests(unittest.TestCase):
    def edge(self, count=3):
        edge = Edges(count)
        edge.owners = tuple(replace(v, parent_pid=edge.api.pid) for v in edge.owners)
        edge.idle = replace(edge.idle, parent_pid=edge.api.pid)
        edge.expected = [edge.api, edge.idle, *edge.owners]
        edge.native = {v.pid: v for v in edge.expected}
        edge.runtime = edge.native.copy()
        edge.daemon = SimpleNamespace(process=SimpleNamespace(pid=edge.api.pid, returncode=-signal.SIGKILL))
        return edge

    def reparent(self, edge):
        edge.die(edge.api, note=False)
        for pid, value in list(edge.runtime.items()):
            edge.native[pid] = edge.runtime[pid] = replace(value, parent_pid=1)

    def test_single_and_ack_live_pins_refresh_without_changing_historical_owners(self):
        for count in (1, 3):
            for early in (False, True):
                edge = self.edge(count)
                with self.subTest(count=count, early=early), edge.patches(), edge.monitor() as monitor:
                    monitor.delivered()
                    if early:
                        edge.die(edge.owners[0])
                        monitor.observe(edge.expected, "storage-exit-joined")
                    original_events, original_exited = monitor._events.copy(), monitor._exited.copy()
                    self.reparent(edge)
                    refreshed = monitor.api_joined_refresh(edge.daemon, edge.api, edge.expected)
                    self.assertEqual(monitor.owners, edge.owners)
                    self.assertEqual(monitor._owners, {v.pid: v for v in edge.owners})
                    self.assertEqual((monitor._events, monitor._exited), (original_events, original_exited))
                    self.assertTrue(monitor._entered and monitor._ready and monitor._delivered)
                    self.assertEqual(refreshed, [edge.api, replace(edge.idle, parent_pid=1), *edge.owners])
                    expected = [v for v in refreshed if v != edge.api]
                    self.assertEqual(monitor.observe(expected, "api-birth"), list(edge.runtime.values()))
                    for owner in edge.owners:
                        if owner.pid not in monitor._exited: edge.die(owner)
                    self.assertEqual(monitor.join_all(expected, "recovery-ready"), [replace(edge.idle, parent_pid=1)])
                    self.assertEqual([v['native'] for _, v in edge.records], [p.native_proof(v) for v in edge.owners])
                    with self.assertRaises(r.ProofFailure):
                        monitor.api_joined_refresh(edge.daemon, edge.api, refreshed)

    def test_exact_join_and_delivery_are_required(self):
        for fault in ("live-api", "wrong-pid", "unjoined", "wrong-signal", "undelivered", "ambiguous-api"):
            edge = self.edge()
            with self.subTest(fault=fault), edge.patches(), edge.monitor() as monitor:
                if fault != "undelivered": monitor.delivered()
                self.reparent(edge)
                if fault == "live-api": edge.native[edge.api.pid] = edge.api
                if fault == "ambiguous-api": edge.native[edge.api.pid] = replace(edge.api, pidversion=999)
                if fault == "wrong-pid": edge.daemon.process.pid += 1
                if fault == "unjoined": edge.daemon.process.returncode = None
                if fault == "wrong-signal": edge.daemon.process.returncode = -signal.SIGTERM
                with self.assertRaises(r.ProofFailure):
                    monitor.api_joined_refresh(edge.daemon, edge.api, edge.expected)
                self.assertEqual(edge.census_calls, 0)
                self.assertEqual(monitor._pinned, monitor._owners)

    def test_refresh_rejects_every_other_field_and_wrong_parent(self):
        changes = [dict(command="changed"), dict(executable="/other"), dict(arguments=("other",)),
            dict(identity=(1, 2, 3)), dict(pidversion=999), dict(parent_pid=42), dict(parent_pid=None)]
        for selected in (False, True):
            for change in changes:
                edge = self.edge()
                with self.subTest(selected=selected, change=change), edge.patches(), edge.monitor() as monitor:
                    monitor.delivered(); self.reparent(edge)
                    owner = edge.owners[0] if selected else edge.idle
                    edge.native[owner.pid] = edge.runtime[owner.pid] = replace(edge.runtime[owner.pid], **change)
                    with self.assertRaises(r.ProofFailure):
                        monitor.api_joined_refresh(edge.daemon, edge.api, edge.expected)

    def test_non_api_parent_cannot_reparent_and_ordinary_observation_stays_strict(self):
        for prior in (None, 88, 1, 200):
            edge = self.edge(1)
            edge.idle = replace(edge.idle, parent_pid=prior)
            edge.expected[1] = edge.idle
            edge.native[edge.idle.pid] = edge.runtime[edge.idle.pid] = edge.idle
            with self.subTest(prior=prior), edge.patches(), edge.monitor() as monitor:
                monitor.delivered(); self.reparent(edge)
                with self.assertRaises(r.ProofFailure):
                    monitor.observe([v for v in edge.expected if v != edge.api], "api-exit-joined")
                if prior in (None, 88):
                    with self.assertRaises(r.ProofFailure):
                        monitor.api_joined_refresh(edge.daemon, edge.api, edge.expected)

    def test_refresh_preserves_exit_proof_and_protected_census_guards(self):
        for fault in ("no-note", "missing-protected", "native-changed", "extra", "duplicate", "revived", "api-in-census"):
            edge = self.edge()
            with self.subTest(fault=fault), edge.patches(), edge.monitor() as monitor:
                monitor.delivered()
                if fault == "revived":
                    edge.die(edge.owners[0]); monitor.observe(edge.expected, "early")
                self.reparent(edge)
                if fault == "no-note": edge.die(edge.owners[0], note=False)
                if fault == "missing-protected": edge.die(edge.idle, note=False)
                if fault == "native-changed": edge.native[edge.idle.pid] = replace(edge.idle, pidversion=999)
                if fault == "extra": edge.runtime[999] = process(999)
                if fault == "duplicate": monitor.processes = lambda: [*edge.runtime.values(), edge.runtime[edge.idle.pid]]
                if fault == "revived": edge.native[edge.owners[0].pid] = edge.runtime[edge.owners[0].pid] = edge.owners[0]
                if fault == "api-in-census": edge.runtime[edge.api.pid] = edge.api
                with self.assertRaises(r.ProofFailure):
                    monitor.api_joined_refresh(edge.daemon, edge.api, edge.expected)

    def test_later_parent_change_and_signal_guard_remain_strict(self):
        for selected in (False, True):
            edge = self.edge()
            with self.subTest(selected=selected), edge.patches(), edge.monitor() as monitor:
                monitor.delivered(); self.reparent(edge)
                expected = monitor.api_joined_refresh(edge.daemon, edge.api, edge.expected)
                owner = edge.owners[0] if selected else edge.idle
                edge.native[owner.pid] = edge.runtime[owner.pid] = replace(owner, parent_pid=77)
                with self.assertRaises(r.ProofFailure):
                    monitor.observe([v for v in expected if v != edge.api], "api-birth")
                with self.assertRaises(r.ProofFailure): monitor.before_signal()
        edge = self.edge()
        with edge.patches(), edge.monitor() as monitor:
            edge.native[edge.owners[0].pid] = replace(edge.owners[0], parent_pid=1)
            with self.assertRaises(r.ProofFailure): monitor.before_signal()


class SingleOwnerExitsTests(unittest.TestCase):
    def test_single_registration_early_and_late_native_exit_retains_protected_census(self):
        for phase in ("storage-exit-joined", "api-birth", "recovery-ready"):
            edge = Edges(1); owner, = edge.owners
            with self.subTest(phase=phase), edge.patches(), edge.monitor() as monitor:
                change, = edge.queue.registrations
                self.assertEqual(change.ident, owner.pid)
                self.assertEqual(change.filter, select.KQ_FILTER_PROC)
                self.assertEqual(change.fflags, select.KQ_NOTE_EXIT)
                self.assertEqual(change.flags, select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT)
                monitor.before_signal()
                # An eager exit can precede the parent's delivered marker, but
                # never registration or the audited signal's prekill checks.
                if phase == "storage-exit-joined": edge.die(owner)
                monitor.delivered()
                if phase != "storage-exit-joined":
                    self.assertEqual(monitor.observe(edge.expected, "storage-exit-joined"), edge.expected)
                    self.assertFalse(edge.records)
                    edge.die(owner)
                self.assertEqual(monitor.join_all(edge.expected, phase), [edge.api, edge.idle])
                self.assertEqual(monitor.join_all(edge.expected, "later"), [edge.api, edge.idle])
                self.assertEqual(edge.records, [("storage-exposed-owner-exit-observed",
                    dict(native=p.native_proof(owner), observedAt=phase))])
            self.assertEqual(edge.queue.closed, 1)
            self.assertTrue(all(value == (1, 0) for value in edge.queue.reads))

    def test_single_native_absence_needs_exact_preregistered_note(self):
        for bad in (None, dict(ident=999), dict(filter=select.KQ_FILTER_READ),
                dict(flags=select.KQ_EV_ERROR), dict(flags=0x40), dict(fflags=0),
                dict(fflags=select.KQ_NOTE_EXIT | select.KQ_NOTE_FORK)):
            edge = Edges(1); owner, = edge.owners
            with self.subTest(bad=bad), edge.patches(), self.assertRaises(r.ProofFailure):
                with edge.monitor() as monitor:
                    monitor.delivered(); edge.die(owner, note=False)
                    if bad is not None: edge.queue.pending.append(event(owner.pid, **bad))
                    monitor.join_all(edge.expected, "absent")
            self.assertFalse(edge.records)
            self.assertEqual(edge.queue.closed, 1)

    def test_single_prekill_death_or_event_refuses_delivery(self):
        for kind in ("absent", "event", "replacement"):
            edge = Edges(1); owner, = edge.owners
            with self.subTest(kind=kind), edge.patches(), self.assertRaises(r.ProofFailure):
                with edge.monitor() as monitor:
                    if kind == "absent": edge.die(owner, note=False)
                    elif kind == "event": edge.queue.pending.append(event(owner.pid))
                    else: edge.native[owner.pid] = replace(owner, pidversion=999)
                    monitor.before_signal()
            self.assertFalse(edge.records)
            self.assertEqual(edge.queue.closed, 1)

    def test_single_exit_never_exempts_protected_loss_replacement_or_extra_census(self):
        for kind in ("missing", "native-missing", "replacement", "extra", "duplicate"):
            edge = Edges(1)
            with self.subTest(kind=kind), edge.patches(), self.assertRaises(r.ProofFailure):
                with edge.monitor() as monitor:
                    monitor.delivered(); edge.kill_all()
                    if kind == "missing": edge.die(edge.idle, note=False)
                    elif kind == "native-missing": edge.native.pop(edge.api.pid)
                    elif kind == "replacement": edge.runtime[edge.idle.pid] = replace(edge.idle, pidversion=999)
                    elif kind == "extra": edge.runtime[999] = process(999)
                    else: monitor.processes = lambda: [*edge.runtime.values(), edge.api]
                    monitor.join_all(edge.expected, "protected")
            self.assertEqual(edge.census_calls, 0 if kind == "duplicate" else 1)
            self.assertFalse(edge.records)
            self.assertEqual(edge.queue.closed, 1)

    def test_single_note_with_live_original_never_substitutes_for_native_exit(self):
        for note in (False, True):
            edge = Edges(1)
            with self.subTest(note=note), edge.patches(), self.assertRaises(TimeoutError):
                with edge.monitor() as monitor:
                    monitor.delivered()
                    if note: edge.queue.pending.append(event(edge.owners[0].pid))
                    edge.budget_limit = edge.budget_calls + 5
                    monitor.join_all(edge.expected, "still-live")
            self.assertFalse(edge.records)
            self.assertEqual(edge.queue.closed, 1)

    def test_single_exact_native_reuse_requires_both_birth_and_pidversion_change(self):
        for change in (dict(identity=(10, 20, 30)), dict(pidversion=999),
                dict(identity=(10, 20, 30), pidversion=999)):
            edge = Edges(1); owner, = edge.owners
            with self.subTest(change=change), edge.patches(), edge.monitor() as monitor:
                monitor.delivered(); edge.die(owner, replacement=replace(owner, **change))
                if len(change) == 2:
                    self.assertEqual(monitor.join_all(edge.expected, "reused"), [edge.api, edge.idle])
                    self.assertEqual(len(edge.records), 1)
                else:
                    with self.assertRaises(r.ProofFailure): monitor.join_all(edge.expected, "ambiguous")
                    self.assertFalse(edge.records)

    def test_single_exit_census_race_retries_only_one_proven_transition(self):
        edge = Edges(1)
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered()
            def during():
                edge.after_census = None
                edge.kill_all()
            edge.after_census = during
            self.assertEqual(monitor.join_all(edge.expected, "snapshot-race"), [edge.api, edge.idle])
            self.assertEqual(edge.census_calls, 2)
            self.assertEqual(len(edge.records), 1)

    def test_single_missing_original_expectation_is_not_a_survivor_shortcut(self):
        edge = Edges(1)
        with edge.patches(), edge.monitor() as monitor:
            monitor.delivered(); edge.kill_all()
            with self.assertRaisesRegex(r.ProofFailure, "retains all original"):
                monitor.join_all([edge.api, edge.idle], "incomplete")
            self.assertFalse(edge.records)
            self.assertEqual(edge.census_calls, 0)


if __name__ == "__main__":
    unittest.main()
