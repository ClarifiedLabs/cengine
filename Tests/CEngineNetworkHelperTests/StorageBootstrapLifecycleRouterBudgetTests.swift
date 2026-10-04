import CEngineCore
import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

@Suite struct StorageBootstrapLifecycleRouterBudgetTests {
    @Test func onlyColdRootGets120SecondsFromReceipt() {
        let receivedAt = DispatchTime.now()
        #expect(StorageBootstrapLifecycleColdRootXPC.budget == 120)
        #expect(StorageBootstrapLifecycleRouter.requestDeadline(
            operation: StorageLifecycleColdRootProtocol.xpcOperation, receivedAt: receivedAt) == receivedAt + 120)
        let shortOperations = [
            StorageLifecycleAdoptionRootProtocol.xpcOperation,
            StorageLifecycleResumeRootProtocol.xpcOperation,
            StorageLifecycleRootProtocol.xpcOperation,
            StorageBootstrapLifecycleRouter.scopeBindOperation,
            StorageBootstrapLifecycleColdXPC.greetingOperation,
            StorageBootstrapLifecycleResumeXPC.greetingOperation,
            StorageBootstrapLifecycleAdoptionXPC.greetingOperation,
            StorageBootstrapLifecycleAdoptionXPC.enrollmentOperation,
            StorageBootstrapLifecycleAdoptionXPC.coldEnrollmentOperation,
            StorageBootstrapLifecycleAdoptionXPC.resumeEnrollmentOperation,
            "storage-lifecycle-child", "storage-lifecycle-fresh-shim", "storage-lifecycle-service-shim",
            "unknown-operation"
        ]
        for operation in shortOperations {
            #expect(StorageBootstrapLifecycleRouter.requestDeadline(
                operation: operation, receivedAt: receivedAt) == receivedAt + 30)
        }
    }

    /// Actual scoped transport checks with simulated queue age, not signed/native
    /// caller acceptance. No sleeps, installation, production files, or XPC peers.
    @Test func coldScopedRequestSurvivesBeyond30ButWithin120Seconds() throws {
        let worker = StorageBootstrapLifecycleChildWorker()
        let key = try StorageIdentity.RootPublicKey(publicData: Data(repeating: 7, count: 32))
        let adoption = StorageBootstrapLifecycleAdoptionXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ",
            expectedRootPublicKey: key, worker: worker,
            lookupOrigin: { _ in nil }, verifyFreshOrigin: { _, _, _ in throw BootstrapFailure(.unauthorized) },
            verifyCandidate: { _, _, _ in throw BootstrapFailure(.unauthorized) })
        let cold = StorageBootstrapLifecycleColdXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ",
            expectedRootPublicKey: key, rootFD: -1, worker: worker,
            candidate: { _, _, _ in throw BootstrapFailure(.unauthorized) })
        let receivedAt = DispatchTime.now() - 45
        let deadline = StorageBootstrapLifecycleRouter.requestDeadline(
            operation: StorageLifecycleColdRootProtocol.xpcOperation, receivedAt: receivedAt)
        try worker.perform {
            var checks = 0, completed = false
            try adoption.withRequest(deadline: deadline, check: { checks += 1 }) {
                try cold.withRequest(check: adoption.checkRequest) {
                    try cold.checkRecoveryRequest()
                    completed = true
                }
            }
            #expect(completed && checks == 5)
            #expect(throws: BootstrapFailure.self) { try adoption.checkRequest() }
            #expect(throws: BootstrapFailure.self) { try cold.checkRecoveryRequest() }
            for operation in [StorageLifecycleAdoptionRootProtocol.xpcOperation, StorageLifecycleResumeRootProtocol.xpcOperation] {
                let shortDeadline = StorageBootstrapLifecycleRouter.requestDeadline(operation: operation, receivedAt: receivedAt)
                #expect(throws: BootstrapFailure.self) {
                    try adoption.withRequest(deadline: shortDeadline, check: {}) {
                        Issue.record("30-second route accepted a request aged 45 seconds")
                    }
                }
            }
        }
    }

    @Test func coldQueueAgeConsumesTheWholeBudgetWithoutRenewal() throws {
        let worker = StorageBootstrapLifecycleChildWorker()
        let adoption = StorageBootstrapLifecycleAdoptionXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ",
            expectedRootPublicKey: try .init(publicData: Data(repeating: 7, count: 32)), worker: worker,
            lookupOrigin: { _ in nil }, verifyFreshOrigin: { _, _, _ in throw BootstrapFailure(.unauthorized) },
            verifyCandidate: { _, _, _ in throw BootstrapFailure(.unauthorized) })
        let deadline = StorageBootstrapLifecycleRouter.requestDeadline(
            operation: StorageLifecycleColdRootProtocol.xpcOperation, receivedAt: DispatchTime.now() - 121)
        try worker.perform {
            var checked = false, called = false
            #expect(throws: BootstrapFailure.self) {
                try adoption.withRequest(deadline: deadline, check: { checked = true }) { called = true }
            }
            #expect(!checked && !called)
        }
    }
}
