#!/usr/bin/env python3
"""Source-contract checks only; not execution of Swift or RTM-103."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
def source(name):
    return (ROOT / "Sources/CEngineRuntime" / (name + ".swift")).read_text()

class DiagnosticContractTests(unittest.TestCase):
    def test_wire_value_is_closed(self):
        text = source("OriginalConsumerContainmentFailure")
        value = text.split("struct OriginalConsumerFailureDiagnostic:", 1)[1]
        fields = value.split("    init(stage:", 1)[0]
        self.assertEqual(re.findall(r"    let (\w+): (\w+)", fields),
                         [("stage", "Stage"), ("category", "Category")])
        self.assertNotIn("localizedDescription", value)
        self.assertNotIn("String(describing:", value)
        self.assertIn("remaining: 4", value)
        self.assertIn("private struct Failure: Error {", value)
        self.assertNotIn("private struct Failure: Codable", value)

    def test_each_worker_await_distinguishes_reply_validation(self):
        text = source("ManagedStorageLifecycleOriginalConsumer").split("    private func observeOriginalConsumer(", 1)[1]
        for command, reply in [("workerArm", "workerArmReply"), ("workerQuery", "workerQueryReply"),
                               ("workerFinalize", "workerFinalizeReply")]:
            self.assertLess(text.index("." + command), text.index("try await session.command"))
            self.assertGreater(text.index("." + reply), text.index("try await session.command"))
        for stage, call in [("originalProbe", "observation.probe(probe)"),
                            ("originalResult", "observation.result(payload:"),
                            ("workerPollSleep", "Task.sleep(nanoseconds:")]:
            self.assertRegex(text, r"point.stage = \." + stage + r"\s+do \{.*" + re.escape(call))
        self.assertIn("try session.check()", text)
        self.assertIn("try observation.remainingDeadline()", text)

    def test_preflight_failures_are_annotated_before_observation_cursor_exists(self):
        raw = source("RawVirtualizationBackend")
        preflight = raw.split("    private func prepareOriginalConsumerObservation(", 1)[1].split(
            "    public func validateManagedStorageReplacement(", 1)[0]
        self.assertIn("var stage = OriginalConsumerFailureDiagnostic.Stage.preflightIdentity", preflight)
        self.assertIn("catch { throw OriginalConsumerFailureDiagnostic.annotate(error, at: stage) }", preflight)
        stages = ["preflightFreeze", "preflightJoin", "preflightBinding", "preflightCandidate",
                  "preflightArm", "preflightArmReturn", "preflightArmedPublication", "preflightBaselineWait",
                  "preflightBaselineValidation", "preflightBaselineRecord", "preflightBaselinePublication"]
        offsets = [preflight.index("stage = ." + stage + "\n") for stage in stages]
        self.assertEqual(offsets, sorted(offsets))
        for stage, call, next_stage in [
            ("preflightArm", "managedStorage.armOriginalRuntime(", "preflightArmReturn"),
            ("preflightArmedPublication", "phase: .armed", "preflightBaselineWait"),
            ("preflightBaselineWait", "compatibility.originalBaseline(", "preflightBaselineValidation"),
            ("preflightBaselineValidation", "managedStorage.validateOriginalBaseline(", "preflightBaselineRecord"),
            ("preflightBaselineRecord", "observation.recordBackingBaseline(", "preflightBaselinePublication"),
        ]:
            self.assertLess(preflight.index("stage = ." + stage + "\n"), preflight.index(call))
            self.assertLess(preflight.index(call), preflight.index("stage = ." + next_stage + "\n"))
        # The observation must be retained before any failing return fence, and
        # baseline waiting retains the original budget rather than restarting it.
        self.assertLess(preflight.index("originalConsumerObservation = ("), preflight.index("stage = .preflightArmReturn"))
        self.assertEqual(preflight.count("OriginalConsumerPreflightDeadline()"), 1)
        self.assertIn("min(.milliseconds(10), deadline.remaining())", preflight)
        self.assertLess(preflight.index("while true {"), preflight.index("stage = .preflightBaselineWait"))
        self.assertNotIn("reopen()", preflight)

    def test_both_failure_receipts_receive_projection(self):
        raw = source("RawVirtualizationBackend")
        publish = raw.index("diagnostic: OriginalConsumerFailureDiagnostic.find(in: failure)")
        cleanup = raw.index("if !replacementEntered", publish)
        self.assertLess(publish, cleanup)
        self.assertIn("var diagnostic: OriginalConsumerFailureDiagnostic? = nil", source("OriginalConsumerPreflight"))
        trigger = source("ManagedStorageReplacementTrigger")
        self.assertIn("originalConsumerDiagnostic: OriginalConsumerFailureDiagnostic.find(in: error)", trigger)
        self.assertIn("originalConsumerDiagnostic: phase == .failed ? originalConsumerDiagnostic : nil", trigger)

    def test_cleanup_and_post_adoption_stages_stay_ordered(self):
        # The sole lifecycle owner retains diagnostics across cleanup, inventory
        # reconciliation, exact evidence checks, and admission reopening.
        raw = source("RawManagedStorageBackend").split("    private func replaceLifecycleService(", 1)[1].split("\n    }\n", 1)[0]
        stages = ["adoptionReturn", "release", "containment", "joinWork", "inventorySnapshot", "volumePlan",
                  "inventoryReconcile", "completionCommit", "freshObservation", "admissionReopen"]
        offsets = [raw.index("D.step(diagnosticsEnabled ? ." + stage + " : nil)") for stage in stages]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("let diagnosticsEnabled = observation != nil", raw)
        self.assertNotIn("D.step(.", raw)
        outer = source("RawVirtualizationBackend")
        for stage in ["resultPublication", "workReopen"]:
            self.assertIn("Diagnostic.step(claim != nil ? ." + stage + " : nil)", outer)
        rejected = raw.split("guard !maintenance else {", 1)[1].split("\n        }", 1)[0]
        self.assertRegex(rejected, r"(?s)if let observation \{\s+fenceOriginalConsumerFailure\(\)\s+"
                         r"return try await OriginalConsumerCleanup.run\(operation: \{.*?"
                         r"\}, release: \{ _ = try await observation.release\(\) \}, "
                         r"contain: \{ _ = try await contain\(\) \}\)")
        self.assertIn("let session = try await OriginalConsumerCleanup.run(operation: {", raw)
        self.assertRegex(raw, r"\}, release: \{\s+try await D.step\(diagnosticsEnabled \? \.release : nil\) \{\s+"
                         r"if let observation \{ _ = try await observation.release\(\) \}")
        self.assertRegex(raw, r"\}, contain: \{\s+contained = try await "
                         r"D.step\(diagnosticsEnabled \? \.containment : nil\) \{ try await contain\(\) \}")
        self.assertIn("adopted = try await adoption.wait(deadline: deadline)", raw)
        self.assertIn("min(20_000_000, deadline - now)", source("ManagedStorageLifecycleOriginalConsumer"))

    def test_lifecycle_cleanup_precedes_reconciliation_and_admission(self):
        text = source("RawManagedStorageBackend")
        dispatch = text.split("    func replaceService(", 1)[1].split("\n        }", 1)[0]
        self.assertIn("containers: containers, observation: observation, originalClaim: originalClaim,", dispatch)
        self.assertIn("compatibility: compatibility, contain: contain)", dispatch)
        self.assertNotIn("guard observation == nil", dispatch)
        raw = text.split("    private func replaceLifecycleService(", 1)[1].split("\n    }\n", 1)[0]
        steps = ["let session = try await OriginalConsumerCleanup.run(operation: {",
                 "if observation != nil { try await preamble() }", "try await observation.begin()",
                 "phase: .begun", "runtime.observeOriginalConsumerRoots(",
                 "runtime.observeOriginalConsumerSameE(", "runtime.observeOriginalConsumerWrongHello(",
                 "let adoption = OriginalConsumerAdoptionWait {", "try await runtime.replaceService(",
                 "adopted = try await adoption.wait(deadline: deadline)",
                 "try await observation.observeReplacement(adopted, owner: runtime)",
                 "}, release: {", "try await observation.release()", "}, contain: {",
                 "try await contain()", "try await self.joinServiceReplacementWork()",
                 "try runtime.maintenanceSnapshot(session)", "try runtime.planReplacementVolumes(",
                 "try await self.reconcileInventory(", "try runtime.completeServiceReplacement(session) {",
                 "guard !settled.reconciliationRequired,", "negative.original.arm == .init(observation.binding)",
                 "roots.binding == observation.binding", "self.lifecycle = session.lifecycle",
                 "try self.admission.reopen()", "try self.notificationWork.reopen()",
                 "self.maintenance = false; self.workerUnavailable = false; self.reconciled = true",
                 "return BackendServiceReplacementResult("]
        # Restrict to retained task: the early maintenance-rejection cleanup is separate.
        task = raw.split("let task = Task { @MainActor in", 1)[1]
        offsets = [task.index(step) for step in steps]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("replacementLifecycle: session.lifecycle, replacementSnapshot: runtime.maintenanceSnapshot(session)", raw)
        self.assertNotIn("adopted.request == request", raw)
        self.assertIn("try observation.validateInstalled(client: installed.shim, boot: installed.boot)", raw)
        self.assertIn("contained.contains(claim.request.container)", raw)
        for branch in ["if dispatch == .roots", "else if dispatch == .sameE", "else if dispatch == .wrongHello"]:
            self.assertLess(task.index(branch), task.index("let adoption = OriginalConsumerAdoptionWait"))
        self.assertLess(task.index("adopted = try await adoption.wait(deadline: deadline)"),
                        task.index("if let observation, dispatch == .replacement"))

    def test_native_late_adoption_cannot_reopen_or_renew_observation(self):
        text = source("RawManagedStorageBackend")
        raw = text.split("    private func replaceLifecycleService(", 1)[1].split("\n    }\n", 1)[0]
        self.assertLess(raw.index("guard !originalLifecycleOperations.contains(request.operationUUID)"),
                        raw.index("runtime.validateServiceReplacementRetry(request)"))
        self.assertLess(raw.index("originalLifecycleOperations.insert(request.operationUUID)"),
                        raw.index("let task = Task { @MainActor in"))
        adoption = raw.split("let adoption = OriginalConsumerAdoptionWait {", 1)[1].split("\n                    }", 1)[0]
        self.assertIn("runtime.replaceService(", adoption)
        for forbidden in ["reopen", "reconcile", "completeServiceReplacement", "observation.begin", ".cancel()"]:
            self.assertNotIn(forbidden, adoption)
        self.assertIn("originalLifecycleAdoptions[request.operationUUID] = adoption", raw)
        self.assertIn("let deadline = try observation.remainingDeadline()", raw)
        self.assertIn("if observation == nil { try await preamble() }", raw)
        native = source("VMShimClient").split("func observeReplacement(_ session: ManagedStorageLifecycleOwner.ServiceReplacementMaintenance,", 1)[1].split("\n        }", 1)[0]
        self.assertIn("try await owner.observeOriginalConsumerReplacement(self, session: session)", native)

    def test_native_original_comparisons_never_fabricate_legacy_boot(self):
        text = source("RawManagedStorageBackend")
        self.assertNotIn("enum OriginalConsumerService", text)
        self.assertNotIn("VerifiedStorageServiceBoot(", text)
        self.assertIn("ready.serverSPKI", text)
        for method, next_method in [("func originalRuntimeBinding(", "static func selectOriginalRuntimeCredential("),
                                    ("private func attestFreshGetattr(", "static func pollCheckpointWorkerExit(")]:
            body = text.split(method, 1)[1].split(next_method, 1)[0]
            self.assertIn("owner.workloadSession().service.ready", body)
            self.assertNotIn("owner.serviceBoot()", body)
        self.assertEqual(text.count("policy: .drainLifecycle"), 2)

if __name__ == "__main__":
    unittest.main()
