#!/usr/bin/env python3
"""Isolated scope/profile regressions; no signed policies, helper, or VM access."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "Sources/CEngineRuntime"


def function(source, name):
    """Extract these small Swift functions, retaining the actual implementation."""
    return declaration(source, "func " + name + "(")


def declaration(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


class LifecyclePolicyBoundaryTests(unittest.TestCase):
    def test_unenrolled_cold_discovery_never_opens_mutating_adoption_routes(self):
        source = (ROOT / 'Sources/CEngineNetworkHelper/StorageBootstrapLifecycleQualification.swift').read_text()
        route = source.split('case StorageLifecycleAdoptionRootProtocol.xpcOperation:', 1)[1].split(
            'case StorageBootstrapLifecycleAdoptionXPC.resumeEnrollmentOperation:', 1)[0]
        cases = route.split('switch request.body {', 1)[1].split('guard let origin', 1)[0]
        discovery, mutation = cases.split('case .recoverHandoff', 1)
        self.assertIn('case .handoffStatus(let identity):', discovery)
        self.assertIn('requireIdentity(identity)', discovery)
        self.assertNotIn('guardColdPublication', discovery)
        recovery, ordinary = mutation.split('default:', 1)
        for branch in (recovery, ordinary):
            self.assertIn('guardColdPublication(store: binding.store.rawValue)', branch)
        self.assertIn('guardHandoffPublication', ordinary)
        for guard in ('withDescriptors', 'withObservedLocks', 'observed.validate().root == binding.root',
                      'try daemon(message) == sender', 'scope.validateRoot()',
                      'scope.rpc.handoffStatus(identity: identity, daemon: sender)'):
            self.assertIn(guard, route)
        authority = (ROOT / 'Sources/CEngineNetworkHelper/StorageBootstrapLifecycleAuthority.swift').read_text()
        for name in ('handoffStatus', 'statusCold', 'prepareCold'):
            self.assertIn('try requireColdPredecessor(store)', function(authority, name))
        self.assertIn('!store.coldFenced', function(authority, 'recoverHandoff'))
        self.assertIn('coldFenced != true', function(authority, 'guardColdPublication'))

    def test_recovery_authorization_is_file_sealed_and_immutable(self):
        source = (RUNTIME / "ManagedStorageLifecycleOwner.swift").read_text()
        authorization = declaration(source, "struct RecoveryAuthorization {")
        self.assertIn("fileprivate init(", authorization)
        for field in ("current", "history", "workerHistoryReference"):
            self.assertIn("let " + field + ":", authorization)
        # Compile the actual declaration in its own file: same-file minting is
        # allowed, but another Runtime file cannot mint or mutate the seal.
        # DTO stand-ins here carry no ROOT/Query/census authority.
        owner = """
struct ManagedStorageControlClient { struct Context {} }
struct ManagedStorageLifecycleCheckpoint { struct Context {} }
struct ManagedStorageLifecycleOwner {
    typealias Checkpoint = ManagedStorageLifecycleCheckpoint
""" + authorization + """
    static func provenPoint() -> RecoveryAuthorization {
        RecoveryAuthorization(current: .init(), history: [], workerHistoryReference: nil)
    }
}
"""
        with tempfile.TemporaryDirectory(prefix="cengine-recovery-boundary-") as work:
            owner_path = Path(work) / "Owner.swift"
            caller_path = Path(work) / "Caller.swift"
            owner_path.write_text(owner)

            def check(caller):
                caller_path.write_text(caller)
                return subprocess.run(["swiftc", "-typecheck", str(owner_path), str(caller_path)],
                                      text=True, capture_output=True, timeout=120)

            allowed = check("func observe() { _ = ManagedStorageLifecycleOwner.provenPoint().history }")
            self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
            forged = check("""
func forge() {
    _ = ManagedStorageLifecycleOwner.RecoveryAuthorization(
        current: .init(), history: [], workerHistoryReference: nil)
}
""")
            self.assertNotEqual(forged.returncode, 0)
            self.assertIn("'fileprivate' protection level", forged.stderr)
            mutated = check("""
func mutate() {
    var authorization = ManagedStorageLifecycleOwner.provenPoint()
    authorization.current = .init()
    authorization.history = []
    authorization.workerHistoryReference = nil
}
""")
            self.assertNotEqual(mutated.returncode, 0)
            for field in ("current", "history", "workerHistoryReference"):
                self.assertIn("'" + field + "' is a 'let' constant", mutated.stderr)

    def test_shared_recovery_factory_requires_owner_seal(self):
        shared = (RUNTIME / "ManagedStorageSharedTypes.swift").read_text()
        factory = function(shared, "lifecycle")
        self.assertTrue(factory.startswith(
            "func lifecycle(_ authorization: ManagedStorageLifecycleOwner.RecoveryAuthorization)"))
        self.assertIn("previous: authorization.history", factory)
        self.assertIn("workerHistoryReference: authorization.workerHistoryReference", factory)
        self.assertIn("private static func makeLifecycle(", shared)
        self.assertIn("fileprivate init(current:", shared)
        self.assertNotIn("func lifecycle(current:", shared)
        replacement = function(shared, "lifecycleReplacement")
        self.assertIn("ManagedStorageLifecycleOwner.ReplacementRecoveryAuthorization", replacement)
        self.assertIn("return try makeLifecycle(current: current,", replacement)

    def test_recovery_seal_is_minted_only_at_existing_proven_point(self):
        source = (RUNTIME / "ManagedStorageLifecycleOwner.swift").read_text()
        recovery = function(source, "recoverWorkload")
        ordered = (
            "try await connectWorkload()",  # Existing fresh ROOT + child check.
            "let query = try await queryWorkload()",
            "current.original.signed.grant.operation == .takeover",
            "Checkpoint.censusMatches(state, intents: intents.checkedSnapshot())",
            "Self.attestedHistory(required: required,",
            "history.append(contentsOf: coldHistory.sorted {",
            "if let replacementPredecessor { history.append(replacementPredecessor) }",
            "let authorization = RecoveryAuthorization(current: context, history: history,",
            "workerHistoryReference: try state.latestServiceChange?.reference)",
            "ManagedStorageControllerRecovery.lifecycle(authorization)",
            "try worker.publish(())",
            "recoveryPermission = (context, recovery)",
        )
        positions = [recovery.index(fragment) for fragment in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(recovery.index("if let fresh = freshColdCompletion"),
                        recovery.index("Self.attestedHistory(required: required,"))
        self.assertIn("retained.value == bridge", recovery)
        self.assertIn("coldHistory = required.intersection(proven)", recovery)
        self.assertIn("required.subtract(coldHistory)", recovery)
        # The resolve-dead audit is not a fresh completion capability.
        resolution = function(source, "resolveInterruptedColdLocked")
        self.assertNotIn("freshColdCompletion =", resolution)
        self.assertIn("persist(.stageColdResolution(retry))", resolution)
        self.assertLess(resolution.index("persist(.stageColdResolution(retry))"),
                        resolution.index("await checkedColdRequest("))
        self.assertEqual(source.count("= RecoveryAuthorization("), 1)
        self.assertEqual(source.count("ManagedStorageControllerRecovery.lifecycle("), 1)

    def test_actual_scope_binding_uses_profile_not_namespace(self):
        source = (RUNTIME / "ManagedStorageLifecycleOwner.swift").read_text()
        binding = function(source, "bindOrdinaryScope")
        # Compile the real small worker method with IO-only stand-ins. This does
        # not construct StorageLifecycleNativePolicy or assert native authority.
        program = r'''
import Foundation
struct Policy {
    enum Namespace { case production, compatibility }
    let namespace: Namespace
    let isQualification: Bool
}
struct ScopeRoot { let descriptor: Int32 }
enum Failure: Error { case invalid, binding }
final class StorageLifecycleRootClient {
    var calls = 0
    var fails = false
    func bindScope(store: String, rootFD: Int32, timeout: TimeInterval) throws {
        precondition(store == "store" && rootFD == 42 && timeout == 7)
        calls += 1
        if fails { throw Failure.binding }
    }
}
struct Worker {
    let policy: Policy
    let store: String?
    let scopeRoot: ScopeRoot?
''' + binding + r'''
}
for namespace: Policy.Namespace in [.production, .compatibility] {
    for qualification in [false, true] {
        let policy = Policy(namespace: namespace, isQualification: qualification)
        let root = StorageLifecycleRootClient()
        let worker = Worker(policy: policy, store: "store", scopeRoot: .init(descriptor: 42))
        try worker.bindOrdinaryScope(root, timeout: 7)
        try worker.bindOrdinaryScope(root, timeout: 7)
        precondition(root.calls == (qualification ? 0 : 2)) // Rebind after helper restart.
        root.fails = true
        do {
            try worker.bindOrdinaryScope(root, timeout: 7)
            precondition(qualification)
        } catch Failure.binding { precondition(!qualification) }
        for missingStore in [false, true] {
            let missing = Worker(policy: policy, store: missingStore ? nil : "store",
                                 scopeRoot: missingStore ? .init(descriptor: 42) : nil)
            do {
                try missing.bindOrdinaryScope(root, timeout: 7)
                precondition(qualification)
            } catch Failure.invalid { precondition(!qualification) }
        }
    }
}
'''
        result = subprocess.run(["swift", "-"], input=program, text=True,
                                capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_every_native_request_binds_before_transport_in_debug_and_release(self):
        source = (RUNTIME / "ManagedStorageLifecycleOwner.swift").read_text()
        worker = source[source.index("nonisolated private final class Worker:"):]
        for name in ("request", "adoptionRequest", "coldRequest", "resumeRequest"):
            with self.subTest(request=name):
                body = function(worker, name)
                # Both branches (DEBUG without seam, and release) must bind first.
                self.assertEqual(body.count("try bindOrdinaryScope(root"), 2)
                call = ("reply = try nativeAdoptionRequest(" if name == "adoptionRequest"
                        else "reply = try root." + name + "(")
                native_calls = body.split(call)
                self.assertEqual(len(native_calls), 3)
                for prefix in native_calls[:-1]:
                    self.assertIn("try bindOrdinaryScope(root", prefix)
        adoption = function(worker, "nativeAdoptionRequest")
        self.assertIn("try root.completeAdoptionForConnection(request,", adoption)
        self.assertIn("return try root.adoptionRequest(request,", adoption)

    def test_adopted_connection_authorization_is_file_sealed(self):
        source = (RUNTIME / "ManagedStorageLifecycleOwner.swift").read_text()
        authorization = declaration(source, "struct StorageLifecycleAdoptedConnectionAuthorization:")
        self.assertIn("fileprivate init(", authorization)
        self.assertNotIn("Codable", authorization)
        stubs = """
struct StorageLifecycleAdoptionRootProtocol { struct Status: Sendable {} }
struct StorageLifecycleAdoptionProtocol { struct Request: Sendable {} }
struct StorageLifecycleNativePolicy: Sendable {}
"""
        with tempfile.TemporaryDirectory(prefix="cengine-adoption-boundary-") as work:
            owner = Path(work) / "Owner.swift"
            caller = Path(work) / "Caller.swift"
            owner.write_text(stubs + authorization + """
func provenPoint() -> StorageLifecycleAdoptedConnectionAuthorization {
    .init(status: .init(), request: .init(), policy: .init())
}
""")
            caller.write_text("func observe() { _ = provenPoint().status }")
            command = ["swiftc", "-typecheck", str(owner), str(caller)]
            allowed = subprocess.run(command, text=True, capture_output=True, timeout=120)
            self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
            caller.write_text("""
func forge() {
    _ = StorageLifecycleAdoptedConnectionAuthorization(
        status: .init(), request: .init(), policy: .init())
}
""")
            denied = subprocess.run(command, text=True, capture_output=True, timeout=120)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("'fileprivate' protection level", denied.stderr)
        mint = function(source, "completeAdoptionForConnection")
        for fragment in ("try adoptionRequest(envelope", "status.latest == request",
                         "status.pending == nil", "status.committedEpoch == request.epoch"):
            self.assertIn(fragment, mint)
        self.assertLess(mint.index("status.latest == request"), mint.index("return (reply, .init("))

    def test_qualification_entry_points_require_profile_before_side_effects(self):
        cases = (
            ("StorageLifecycleRootClient.swift", "armQualificationCompletionLoss", "policy.currentIdentity"),
            ("StorageLifecycleRootScope.swift", "bindQualificationScope", "try bindScope("),
            ("StorageLifecycleShimProcess.swift", "launch", "policy == .qualification(role: .engine)"),
            ("RawStorageLifecycleShim.swift", "qualificationCheckLiveVM", "try requireControlReady()"),
        )
        for file, name, next_check in cases:
            with self.subTest(file=file, function=name):
                body = function((RUNTIME / file).read_text(), name)
                self.assertNotIn("policy.namespace", body)
                self.assertLess(body.index("guard policy.isQualification"), body.index(next_check))
        body = function((RUNTIME / "RawStorageLifecycleShim.swift").read_text(),
                        "qualificationRevokeServiceProof")
        self.assertLess(body.index("try qualificationCheckLiveVM()"), body.index("service.close()"))


if __name__ == "__main__":
    unittest.main()
