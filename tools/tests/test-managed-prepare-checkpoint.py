#!/usr/bin/env python3
"""Engine-free RTM098 generic checkpoint-exit route checks.

Covers the carrier schema (exactly one of checkpoint/earlyCheckpoint/
storageCheckpoint selected by the arm's case), the strict PID1 Wait validator,
the A6/A8 retired-cut and five-cut quarantined-drain oracles, the dual route
in restart_worker_at_a5, and the nine-cell RTM-098 campaign selection.
No engine, VM, or native inspection.
"""
import copy
from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p
import managed_prepare_worker_faults as w

WORKER = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-worker.py"))
values = WORKER["values"]
MATRIX_SOURCE = (ROOT / "tools/managed_prepare_matrix.py").read_text()
WORKER_SOURCE = (ROOT / "Tests/Compatibility/managed_prepare_worker_faults.py").read_text()


class CutPartitionTests(unittest.TestCase):
    def test_worker_and_checkpoint_routes_partition_the_nine_cuts(self):
        self.assertEqual(set(p.WORKER_EXIT_CASES), set(p.HELD_STORAGE_CASES), "A4/A5 keep the strict StorageRelease route")
        self.assertEqual(set(p.CHECKPOINT_CARRIERS), set(p.CHECKPOINT_EXIT_CASES), "one carrier per checkpoint cut")
        self.assertTrue(set(p.WORKER_EXIT_CASES).isdisjoint(p.CHECKPOINT_EXIT_CASES), "routes are disjoint")
        self.assertEqual(set(p.WORKER_EXIT_CASES) | set(p.CHECKPOINT_EXIT_CASES), set(p.FULL_CASES), "nine cuts covered")
        self.assertEqual(set(p.CHECKPOINT_CUT_CASES), set(p.CHECKPOINT_EXIT_CASES) & set(p.STORAGE_CASES), "A6/A8 only")
        self.assertEqual(p.NATURAL_FAILURE_CASES,
            ("before-prepare-send", "data-partial-frame", "transaction-published-bind-reply-lost"))
        self.assertTrue(set(p.NATURAL_FAILURE_CASES) < set(p.CHECKPOINT_EXIT_CASES), "natural trio is checkpoint-routed")
        self.assertEqual(p.checkpoint_carrier("normal"), "checkpoint")
        self.assertEqual(p.checkpoint_carrier("first-child-published"), "checkpoint")
        self.assertEqual(p.checkpoint_carrier("before-prepare-send"), "earlyCheckpoint")
        self.assertEqual(p.checkpoint_carrier("guest-accepted-before-prepare"), "earlyCheckpoint")
        self.assertEqual(p.checkpoint_carrier("data-partial-frame"), "earlyCheckpoint")
        self.assertEqual(p.checkpoint_carrier("transaction-published-bind-reply-lost"), "storageCheckpoint")
        self.assertEqual(p.checkpoint_carrier("drain-durable-reply-lost"), "storageCheckpoint")
        for bad in ("full-frame-before-admit", "admitted-queued", "vm-private-bound", ""):
            with self.assertRaises(ValueError): p.checkpoint_carrier(bad)

    def test_artifact_suffixes_mirror_the_storage_worker_exit_flow(self):
        self.assertEqual(w.CHECKPOINT_EXIT_SUFFIXES,
            (".checkpoint-worker-exit.json", ".checkpoint-worker-exit.claimed.json", ".checkpoint-worker-wait.json"))


class CarrierTests(unittest.TestCase):
    def test_request_carries_exactly_one_carrier_bound_to_cut(self):
        for case in p.CHECKPOINT_EXIT_CASES:
            args, arm, checkpoint, waited, _ = values(case)
            boot = args[0]["boot"]
            request = w.checkpoint_exit_request(arm, checkpoint, boot)
            carrier = p.checkpoint_carrier(case)
            self.assertEqual(set(request), {"arm", carrier, "workerUUID"}, "exactly one union field")
            self.assertIs(request[carrier], checkpoint)
            self.assertEqual(request["workerUUID"], boot["ready"]["workerUUID"])
            self.assertEqual(request["arm"], arm)
            # The owned worker binds through the storage observation for A6/A8;
            # other cuts only require a canonical UUID.
            bad_boot = copy.deepcopy(boot)
            bad_boot["ready"]["workerUUID"] = WORKER["uid"]()
            if case in p.STORAGE_CASES:
                with self.subTest(case=case), self.assertRaises(ValueError):
                    w.checkpoint_exit_request(arm, checkpoint, bad_boot)
            else:
                with self.subTest(case=case), self.assertRaises(ValueError):
                    w.checkpoint_exit_request(arm, checkpoint, {**bad_boot, "ready": {**bad_boot["ready"], "workerUUID": "not-a-uuid"}})
                self.assertEqual(w.checkpoint_exit_request(arm, checkpoint, bad_boot)["workerUUID"], bad_boot["ready"]["workerUUID"])
            # A checkpoint from a different cut is rejected by its own validator.
            for other in ("normal", "data-partial-frame", "transaction-published-bind-reply-lost"):
                if other == case: continue
                wrong_arm = copy.deepcopy(arm); wrong_arm["caseName"] = other
                with self.subTest(case=case, other=other), self.assertRaises(ValueError):
                    w.checkpoint_exit_request(wrong_arm, checkpoint, boot)
            # v2/held arms never enter the generic route.
            v2_arm = copy.deepcopy(arm); v2_arm.update(version=2, profile=p.EARLY_PROFILE)
            with self.subTest(case=case), self.assertRaises(ValueError):
                w.checkpoint_exit_request(v2_arm, checkpoint, boot)

    def test_old_route_rejects_all_seven_checkpoint_cuts(self):
        for case in p.CHECKPOINT_EXIT_CASES:
            args, arm, checkpoint, _, _ = values(case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                w.worker_exit_request(arm, checkpoint, args[0]["boot"])


class OracleTests(unittest.TestCase):
    def test_recovered_checkpoint_intent_routes_by_cut(self):
        # Guest cuts and A6 have no successful guest completion: quarantine+drain.
        for case in set(p.CHECKPOINT_EXIT_CASES) - {"drain-durable-reply-lost"}:
            args, arm, checkpoint, _, _ = values(case)
            state = args[5]
            intent = state["intents"][arm["scope"]["intent"]]
            self.assertIs(w.recovered_checkpoint_intent(intent, arm, checkpoint), intent)
        # Held A4/A5 stay on the strict route; unknown cuts fail closed.
        for case in p.WORKER_EXIT_CASES:
            args, arm, checkpoint, _, _ = values(case)
            state = args[5]
            intent = state["intents"][arm["scope"]["intent"]]
            with self.subTest(case=case), self.assertRaises(ValueError):
                w.recovered_checkpoint_intent(intent, arm, checkpoint)
        bad_arm = copy.deepcopy(FIX["arm_for"]("normal"))
        with self.assertRaises((ValueError, KeyError)):
            w.recovered_checkpoint_intent({}, bad_arm, {})

    def test_a8_retired_cut_requires_completion_and_exact_replay(self):
        for case in ("drain-durable-reply-lost",):
            args, arm, checkpoint, _, _ = values(case)
            state = args[5]
            intent = state["intents"][arm["scope"]["intent"]]
            self.assertEqual(intent["phase"], "retired")
            self.assertIs(w.retired_checkpoint_cut(intent, arm, checkpoint), intent)
            bad = copy.deepcopy(intent); bad["prepareCompleted"] = False
            with self.subTest(case=case), self.assertRaises(ValueError):
                w.retired_checkpoint_cut(bad, arm, checkpoint)
            bad = copy.deepcopy(intent); bad["phase"] = "quarantined"
            with self.subTest(case=case), self.assertRaises(ValueError):
                w.retired_checkpoint_cut(bad, arm, checkpoint)
            bad = copy.deepcopy(intent)
            next(s for s in bad["slots"] if s["role"] == "runtime").pop("receipt")
            with self.subTest(case=case), self.assertRaises(ValueError):
                w.retired_checkpoint_cut(bad, arm, checkpoint)
        # A8's target receipt must be the exact pre-death durable replay.
        args, arm, checkpoint, _, _ = values("drain-durable-reply-lost")
        intent = args[5]["intents"][arm["scope"]["intent"]]
        target = next(s for s in intent["slots"] if s["attachment"] == arm["targetAttachment"])
        target["receipt"] = dict(target["receipt"], revision=target["receipt"]["revision"] + 1)
        with self.assertRaises(ValueError):
            w.retired_checkpoint_cut(intent, arm, checkpoint)

    def test_a6_cannot_fabricate_completion_from_a_durable_bind(self):
        args, arm, checkpoint, _, prefault = values("transaction-published-bind-reply-lost")
        intent = args[5]["intents"][arm["scope"]["intent"]]
        self.assertEqual(intent["phase"], "quarantined")
        self.assertIs(intent["prepareCompleted"], False)
        self.assertIs(w.recovered_checkpoint_intent(intent, arm, checkpoint), intent)
        with self.assertRaises(ValueError): w.retired_checkpoint_cut(intent, arm, checkpoint)
        wrong = copy.deepcopy(intent); wrong.update(phase="retired", prepareCompleted=True)
        with self.assertRaises(ValueError): w.recovered_checkpoint_intent(wrong, arm, checkpoint)

    def test_recovered_worker_cut_reuses_the_retired_oracle(self):
        args, arm, checkpoint, _, prefault = values("drain-durable-reply-lost")
        state, boot = args[5], args[1]["workerReplacements"][-1]["successor"]
        proof = w.recovered_worker_cut(prefault, state, arm, boot, checkpoint)
        self.assertEqual(proof["phase"], "retired")
        self.assertIs(proof["completed"], True)
        bad = copy.deepcopy(state); bad["revision"] = prefault["revision"]
        with self.assertRaises(ValueError):
            w.recovered_worker_cut(prefault, bad, arm, boot, checkpoint)


class RouteGateTests(unittest.TestCase):
    def test_restart_worker_at_a5_requires_route_matching_the_cut(self):
        args, arm, _, _, _ = values("admitted-queued")
        checkpoint_arm = copy.deepcopy(arm); checkpoint_arm["caseName"] = "normal"
        base = dict(daemon=None, workload=None, census=[], intent=None, checkpoint=None, queue=None,
            wait_artifact=None, artifact=None, ledger=None, files={}, record=None, processes=lambda: [],
            remaining=lambda: 1, start=None, read_state=None, wait_exit=None, join_failed_start=lambda: None,
            storage_initramfs_sha256="f" * 64, owned_containers=[], peer_owner=None)
        # Mismatched routes fail at the gate before any I/O.
        with self.assertRaises(ValueError):
            w.restart_worker_at_a5(**base, arm=arm, checkpoint_exit=True)
        with self.assertRaises(ValueError):
            w.restart_worker_at_a5(**base, arm=checkpoint_arm, checkpoint_exit=False)
        with self.assertRaises(ValueError):
            w.restart_worker_at_a5(**base, arm=arm, checkpoint_exit="yes")

    def test_dual_route_source_uses_distinct_artifacts_and_oracles(self):
        self.assertIn('checkpoint_exit_request(arm, checkpoint, boot) if checkpoint_exit else worker_exit_request(arm, checkpoint, boot)', WORKER_SOURCE)
        self.assertIn('exit_suffix = ".checkpoint-worker-exit" if checkpoint_exit else ".storage-worker-exit"', WORKER_SOURCE)
        self.assertIn('checkpoint_wait if checkpoint_exit else worker_wait', WORKER_SOURCE)
        self.assertIn('worker_interrupted=checkpoint_exit', WORKER_SOURCE)
        self.assertNotIn("LATE_WORKER_EXIT_CASES", WORKER_SOURCE)


class MatrixSelectionTests(unittest.TestCase):
    def test_rtm098_campaign_selects_all_nine_cuts_without_aggregate(self):
        self.assertIn('CAMPAIGNS["RTM-098"] = [case for case in proof.FULL_CASES', MATRIX_SOURCE)
        self.assertIn("CHECKPOINT_EXIT_CASES", MATRIX_SOURCE)
        self.assertIn("run_checkpoint_exit_shard", MATRIX_SOURCE)
        self.assertIn('outcome.get("result") == "initial-cut-passed"', MATRIX_SOURCE)
        self.assertIn('outcome.get("fullAcceptance") is False', MATRIX_SOURCE)
        # Nine cells keep per-cell reports only: no nine-cell aggregate token.
        import managed_prepare_restart_matrix as m
        self.assertNotIn("RTM-098", m.MATRICES)
        aggregate = 'if arguments.rtm in matrix.MATRICES and set(cases) == set(proof.FULL_CASES) and len(outcomes) == 9:'
        self.assertIn(aggregate, MATRIX_SOURCE)
        # Descriptor budget stays at the established 2048 soft bound.
        self.assertIn("required = 2048", MATRIX_SOURCE)


FIX = {"arm_for": WORKER["FULL"]["arm_for"]}


if __name__ == "__main__":
    unittest.main()
