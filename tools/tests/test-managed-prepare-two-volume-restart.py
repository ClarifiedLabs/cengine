#!/usr/bin/env python3
"""Engine-free execution of the real two-volume storage/API recovery ordering."""
import copy
from dataclasses import replace
from pathlib import Path
import runpy
import signal
import sys
import unittest
from unittest.mock import Mock, call, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import harness
import managed_prepare_faults as p
import managed_prepare_storage_vm_faults as recovery
import managed_prepare_two_volume_drain as two
import managed_prepare_two_volume_parent as parent

A7 = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-storage-vm.py"))
TWO = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-two-volume-drain.py"))


class TwoVolumeRestart(unittest.TestCase):
    def run_cut(self, fault=None, *, rollback=0, trace=None, reparent=False, exit_phase="api-ready"):
        original = recovery.restart_storage_at_a7
        trace = {} if trace is None else trace
        order = trace["order"] = []
        def selected(*args, **kwargs):
            args = list(args)
            records = list(recovery.read_public.side_effect)
            before = records[0]
            final = (before[0], "0" * 64) if fault == "owner-loss" else before
            recovery.read_public.side_effect = [before, final, *records[1:]]
            *_, intent, arm, worker, checkpoint, state = TWO["fixture"]()
            context = recovery.owner_context(before[0])[1]
            arm["scope"].update(context)
            intent.update(context)
            state["store"] = context["store"]
            worker = recovery.public_boot(recovery.current_boot(before[0]))["workerUUID"]
            prepare = [s for s in intent["slots"] if s["role"] == "prepare"]
            prepare[0]["receipt"].update(store=state["store"], revision=1)
            checkpoint.update(**two.storage_query(arm, worker))
            checkpoint["drain"]["receipt"].update(store=state["store"], revision=2)
            for slot in prepare:
                TWO["persist"](state, slot["retireOperation"], dict(id=0, retire=dict(
                    operation=slot["retireOperation"], store=state["store"], volume=slot["volume"],
                    attachment=slot["attachment"], launch=intent["launch"])))
            physical = copy.deepcopy(args[5])
            physical.update(requestID=arm["requestID"], armDigest=checkpoint["armDigest"], targetAttachment=arm["targetAttachment"])
            held = dict(query=two.storage_query(arm, worker), state="held", observation=checkpoint,
                retirementStarted=True, acceptedInFlight=0, lateAdmissionRejected=False, receiptReplayCount=0)
            quiescent = TWO["stopped"](state, rollback)
            after = TWO["recovered"](quiescent, checkpoint)
            final_state = copy.deepcopy(state)
            current = quiescent["intents"][intent["id"]]
            if fault == "prerecovery-phase": current["phase"] = "prepareSucceeded"
            if fault == "prerecovery-reason": current["quarantineReason"] = "start interrupted"
            if fault == "prerecovery-count":
                current["version"] = intent["version"] + 4
                quiescent["revision"] = state["revision"] + 4
            if fault == "prerecovery-receipt": current["slots"][0]["receipt"]["revision"] += 1
            if fault == "prerecovery-request": TWO["persist"](quiescent, current["completeOperation"], dict(id=0))
            if fault == "prerecovery-owner": quiescent["intents"][TWO["uid"]()] = copy.deepcopy(current)
            if fault == "prerecovery-store": quiescent["store"] = TWO["uid"]()
            if fault == "prerecovery-revision": quiescent["revision"] += 1
            if fault == "prerecovery-type": current["prepareCompleted"] = 0
            if fault == "prefault-recovery-baseline": after = TWO["recovered"](state, checkpoint)
            if fault == "early-kill": prepare[0].pop("receipt")
            if fault == "journal-loss": final_state["intents"][intent["id"]]["prepareCompleted"] = True
            if fault == "new-receipt":
                after["intents"][intent["id"]]["slots"][2]["receipt"]["revision"] += 1
            daemon = trace["daemon"] = args[0]
            old_api_pid = daemon.process.pid
            old_api = harness._kernel_process(old_api_pid)
            stop_api = daemon.stop.side_effect
            def stop(*, kill=False):
                order.append("api-stop-entered")
                stop_api(kill=kill)
                if daemon.process.returncode == -signal.SIGKILL and harness._kernel_process(old_api_pid) is None:
                    order.append("api-stop-joined")
            daemon.stop.side_effect = stop
            daemon.start = Mock(wraps=daemon.start)
            states = iter(zip(("prefault", "final-before-storage-kill", "after-old-api-exit", "after-new-recovery"),
                              (state, final_state, quiescent, after)))
            trace["read_state"] = args[12]
            trace["snapshots"] = []
            def read_state():
                label, snapshot = next(states)
                trace["snapshots"].append(label)
                order.append("journal-" + label)
                if label == "after-old-api-exit":
                    self.assertIn("api-stop-joined", order)
                    self.assertEqual(daemon.process.returncode, -signal.SIGKILL)
                    self.assertIsNone(harness._kernel_process(old_api_pid))
                    daemon.stop.assert_called_once_with(kill=True)
                    daemon.start.assert_not_called()
                elif label == "after-new-recovery":
                    daemon.start.assert_called_once()
                    self.assertIn("storage-recovery-api-born", order)
                else:
                    daemon.stop.assert_not_called()
                return None, snapshot, {"state_sha256": p.digest(p.canonical(snapshot))}
            args[12].side_effect = read_state
            args[3:6] = [intent, arm, checkpoint]
            record = args[8]
            trace["records"] = {}
            def retain(phase, **value):
                order.append(phase)
                trace["records"][phase] = copy.deepcopy(value)
                record(phase, **value)
            args[8] = retain
            count = 0
            def held_reader():
                nonlocal count
                count += 1
                order.append("observer-read")
                if count == 2 and fault == "observer-loss": raise FileNotFoundError("held witness removed")
                return held
            # Production reconcileExecutions prepares containment for ALL owners,
            # including terminal peers, but settles only nonterminal intents.
            workload = args[1]
            peer = replace(workload, pid=60, pidversion=60, identity=(60, 4, 360))
            trace["original_workload"], trace["original_peer"] = workload, peer
            args[2] = [*args[2], peer]
            native = harness._kernel_process.side_effect
            census = args[9]
            def peer_live():
                if fault == "peer-before-kill" and "storage-SIGKILL-intent" in order: return False
                if fault == "peer-before-api" and "storage-only-death-joined" in order: return False
                if fault == "peer-at-birth" and "api-recovery-SIGKILL-intent" in order: return False
                return "storage-recovery-api-born" not in order or native(workload.pid) is not None or fault in ("peer-uncontained", "peer-reused")
            def selected_native(pid):
                if pid == old_api_pid and fault == "api-still-live" and "api-stop-entered" in order:
                    return old_api
                if pid != peer.pid: return native(pid)
                if not peer_live(): return None
                if fault == "peer-reused" and native(workload.pid) is None:
                    return replace(peer, pidversion=61, identity=None)
                return replace(peer, parent_pid=1) if reparent and "api-stop-joined" in order else peer
            harness._kernel_process.side_effect = selected_native
            args[9] = lambda: [*census(), *([selected_native(peer.pid)] if peer_live() else [])]
            proof = dict(container="3" * 64, phase="retired", prepareCompleted=True)
            validate_launch, validate_state = Mock(), Mock()
            peer_owner = trace["peer_owner"] = parent.stopped_peer_owner(daemon, peer, proof, validate_launch, validate_state)
            with patch.object(recovery, "restart_storage_at_a7", original):
                result = recovery.restart_storage_at_two_volume_drain(*args, **kwargs,
                    held_reader=held_reader, worker=worker, physical=physical, peer_owner=peer_owner)
            self.assertEqual(peer_owner[1], proof)
            self.assertEqual(validate_launch.call_count, validate_state.call_count + 1)
            trace["result"] = result
            self.assertNotIn(peer, result[0])
            self.assertIn("storage-two-volume-owners-contained", order)
            # The reused A7 double expects its historical workload entry. Keep
            # the actual two-volume return in trace for strict caller assertions.
            return ([workload if v.pid == workload.pid else v for v in result[0]], *result[1:])
        with patch.object(recovery, "restart_storage_at_a7", side_effect=selected):
            result = A7["RestartTests"]().run_restart("api-reparent" if reparent else fault if fault not in (
                "owner-loss", "observer-loss", "journal-loss", "early-kill", "new-receipt",
                "peer-before-kill", "peer-before-api", "peer-at-birth", "peer-uncontained", "peer-reused",
                "prefault-recovery-baseline", "api-still-live") and not (fault or "").startswith("prerecovery-") else None,
                two_volume=True, exit_phase=exit_phase)
        self.assertLess(order.index("two-volume-host-gap-external-fsync"), order.index("storage-SIGKILL-intent"))
        self.assertLess(max(i for i, item in enumerate(order) if item == "observer-read"), order.index("storage-SIGKILL-delivered"))
        self.assertLess(order.index("storage-only-death-joined"), order.index("api-recovery-SIGKILL-intent"))
        phases = ["journal-prefault", "journal-final-before-storage-kill", "storage-SIGKILL-delivered",
                  "api-stop-entered", "api-stop-joined", "journal-after-old-api-exit",
                  "two-volume-api-exited-journal-external-fsync", "storage-recovery-api-born",
                  "journal-after-new-recovery", "storage-identical-old-completed-set", "storage-reopened-reconciled"]
        self.assertEqual(sorted(phases, key=order.index), phases)
        self.assertEqual(trace["snapshots"], ["prefault", "final-before-storage-kill", "after-old-api-exit", "after-new-recovery"])
        trace["read_state"].assert_has_calls([call()] * 4)
        self.assertEqual(trace["read_state"].call_count, 4)
        self.assertLess(order.index("storage-identical-old-completed-set"), order.index("storage-reopened-reconciled"))
        self.assertNotIn("storage-new-epoch-drain", order)
        return result

    def test_actual_parent_opts_in_only_after_audited_restart_returns(self):
        import ast
        tree = ast.parse(Path(parent.__file__).read_text())
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
        block = next(n.body for n in ast.walk(run) if isinstance(n, ast.With)
            and any(isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Name)
                and stmt.value.func.id == "restart_storage_at_two_volume_drain" for stmt in n.body))
        first = next(i for i, n in enumerate(block) if isinstance(n, ast.Assign)
            and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
            and n.value.func.id == "restart_storage_at_two_volume_drain")
        last = next(i for i, n in enumerate(block) if isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
            and n.value.func.id == "joined_start")
        self.assertLess(first, last)
        code = compile(ast.Module(body=block[first:last + 1], type_ignores=[]), "actual-two-volume-recovery-join", "exec")
        for error in (None, ValueError("audited recovery refused")):
            with self.subTest(error=error):
                env = {n.id: Mock() for n in ast.walk(ast.Module(body=block[first:last + 1], type_ignores=[]))
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
                env["metadata"] = {"storageInitramfsSHA256": "a" * 64}
                env["next"] = next
                events = Mock()
                env["restart_storage_at_two_volume_drain"] = events.restart
                env["joined_start"] = events.join
                events.restart.return_value = ([env["process"]], {}, Mock())
                events.restart.side_effect = error
                if error is not None:
                    with self.assertRaisesRegex(ValueError, "audited recovery refused"):
                        exec(code, env)
                    events.join.assert_not_called()
                else:
                    exec(code, env)
                    events.join.assert_called_once_with(env["start"], failed=True, disconnected=True, vm_recovery=True)
                    self.assertEqual([c[0] for c in events.mock_calls], ["restart", "join"])

    def test_real_recovery_orders_gap_hold_death_api_and_identical_completed_set(self):
        self.run_cut()

    def test_exact_join_reparents_both_owners_without_extra_journal_reads(self):
        for rollback in range(4):
            with self.subTest(rollback=rollback):
                trace = {}
                self.run_cut(rollback=rollback, trace=trace, reparent=True)
                workload, peer = trace["original_workload"], trace["original_peer"]
                self.assertIn(workload, trace["result"][0])  # Original exit-proof sentinel.
                self.assertEqual(trace["peer_owner"][0], replace(peer, parent_pid=1))
                self.assertNotIn(trace["peer_owner"][0], trace["result"][0])
                phases = trace["order"]
                self.assertLess(phases.index("api-stop-joined"), phases.index("journal-after-old-api-exit"))
                # Execute the actual caller's refreshed-pin handoff and strict removal.
                import ast
                tree = ast.parse(Path(parent.__file__).read_text())
                run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run")
                assignment = next(n for n in ast.walk(run) if isinstance(n, ast.Assign)
                    and ast.unparse(n).startswith("process = next("))
                env = dict(process=workload, before=trace["result"][0])
                exec(compile(ast.Module(body=[assignment], type_ignores=[]), "caller-handoff", "exec"), env)
                self.assertEqual(env["process"], workload)
                parent.unchanged_processes(env["before"], [v for v in env["before"] if v != workload], env["process"])
                cleanup = next(n for n in ast.walk(run) if isinstance(n, ast.Assign)
                    and ast.unparse(n).startswith("survivors = ["))
                env["peer_process"] = peer
                exec(compile(ast.Module(body=[cleanup], type_ignores=[]), "caller-cleanup", "exec"), env)
                self.assertEqual(len(env["survivors"]), 2)  # Only replacement API/storage.
                self.assertTrue({workload.pid, peer.pid}.isdisjoint(v.pid for v in env["survivors"]))

    def test_quiescent_snapshot_after_api_join_before_spawn_for_every_rollback_prefix(self):
        for rollback in range(4):
            with self.subTest(rollback=rollback):
                trace = {}
                self.run_cut(rollback=rollback, trace=trace)
                prefault = trace["records"]["two-volume-host-gap-external-fsync"]["state"]
                retained = trace["records"]["two-volume-api-exited-journal-external-fsync"]
                self.assertEqual(retained["state"], TWO["stopped"](prefault, rollback))
                self.assertEqual(retained["journal"]["state_sha256"], p.digest(p.canonical(retained["state"])))
                old = next(iter(retained["state"]["intents"].values()))
                current = trace["records"]["storage-identical-old-completed-set"]["proof"]
                self.assertEqual(current["version"], old["version"] + 4)

    def test_bad_quiescent_snapshot_rejected_before_recovery_spawn(self):
        for fault in ("phase", "reason", "count", "receipt", "request", "owner", "store", "revision", "type"):
            trace = {}
            with self.subTest(fault=fault):
                with self.assertRaises(ValueError):
                    self.run_cut("prerecovery-" + fault, rollback=1, trace=trace)
                trace["daemon"].stop.assert_called_once_with(kill=True)
                trace["daemon"].start.assert_not_called()
                self.assertEqual(trace["snapshots"], ["prefault", "final-before-storage-kill", "after-old-api-exit"])
                self.assertIn("two-volume-api-exited-journal-external-fsync", trace["order"])
                retained = trace["records"]["two-volume-api-exited-journal-external-fsync"]
                self.assertEqual(retained["journal"]["state_sha256"], p.digest(p.canonical(retained["state"])))
                self.assertNotIn("storage-recovery-api-born", trace["order"])

    def test_unjoined_api_exit_cannot_supply_quiescent_snapshot_or_spawn(self):
        for fault in ("bad-api-exit", "api-still-live"):
            trace = {}
            with self.subTest(fault=fault):
                with self.assertRaisesRegex(ValueError, "actual recovery API SIGKILL and join"):
                    self.run_cut(fault, trace=trace)
                trace["daemon"].stop.assert_called_once_with(kill=True)
                trace["daemon"].start.assert_not_called()
                self.assertEqual(trace["snapshots"], ["prefault", "final-before-storage-kill"])

    def test_recovery_version_must_use_quiescent_not_prefault_baseline(self):
        for rollback in (1, 2, 3):
            trace = {}
            with self.subTest(rollback=rollback), self.assertRaisesRegex(ValueError, "exact four production recovery updates"):
                self.run_cut("prefault-recovery-baseline", rollback=rollback, trace=trace)
            trace["daemon"].start.assert_called_once()
            self.assertEqual(len(trace["snapshots"]), 4)
            self.assertNotIn("storage-identical-old-completed-set", trace["order"])

    def test_held_owner_exit_requires_positive_event_at_every_boundary(self):
        for phase in ("storage", "api-stop", "api-birth", "api-ready"):
            with self.subTest(phase=phase):
                self.run_cut(exit_phase=phase)
            for fault in ("missing-workload-event", "wrong-workload-exit", "error-workload-exit"):
                with self.subTest(phase=phase, fault=fault), self.assertRaises(RuntimeError if phase == "api-birth" else ValueError):
                    self.run_cut(fault, exit_phase=phase)

    def test_terminal_peer_must_survive_until_api_birth_then_exit(self):
        for fault in ("peer-before-kill", "peer-before-api", "peer-at-birth", "peer-uncontained", "peer-reused"):
            with self.subTest(fault=fault), self.assertRaises((ValueError, TimeoutError)):
                self.run_cut(fault)

    def test_early_kill_owner_observer_and_journal_loss_fail_closed(self):
        for fault in ("early-kill", "owner-loss", "observer-loss", "journal-loss", "new-receipt",
                      "settled-start-before", "prekill-workload-loss", "missing-storage-event", "bad-delivery"):
            with self.subTest(fault=fault), self.assertRaises((ValueError, KeyError, FileNotFoundError)):
                self.run_cut(fault)


if __name__ == "__main__": unittest.main()
