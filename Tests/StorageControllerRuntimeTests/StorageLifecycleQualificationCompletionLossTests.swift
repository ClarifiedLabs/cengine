#if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
import CEngineCore
import Foundation
import Testing
@testable import StorageControllerRuntime

/// Negative/local bookkeeping only: never supplies an authenticated reply or
/// constructs a signed qualification policy. Native completion is integration-only.
@Suite struct StorageLifecycleQualificationCompletionLossTests {
    @Test func completionLossIsOneShotAndCannotBeRearmed() throws {
        var state = StorageLifecycleRootClient.QualificationCompletionLossState()
        let beforeArming = state.consume()
        #expect(!beforeArming)
        try state.arm()
        #expect(throws: (any Error).self) { try state.arm() }
        let firstCompletion = state.consume()
        #expect(firstCompletion) // A rejected second arm did not disarm the first.
        let nextCompletion = state.consume()
        #expect(!nextCompletion)
        #expect(throws: (any Error).self) { try state.arm() }
        let afterRejectedRearm = state.consume()
        #expect(!afterRejectedRearm)
    }

    @Test func productionPolicyCannotArmOrPublishDiscardedCompletion() throws {
        let client = try StorageLifecycleRootClient(installedHelperTeam: "ABCDEFGHIJ")
        for _ in 0..<2 {
            do {
                try client.armQualificationCompletionLoss()
                Issue.record("ordinary policy armed qualification fault")
            } catch let failure as StorageLifecycleRootClient.Failure {
                #expect(failure.code == .unauthorized)
            }
            #expect(client.qualificationDiscardedCompletion == nil)
        }
        let request = try StorageLifecycleRootProtocol.Request(
            requestID: .init(UUID().uuidString.lowercased()), body: .rootPublicKey)
        #expect(throws: (any Error).self) { try client.request(request, timeout: 0) }
        #expect(client.qualificationDiscardedCompletion == nil)
    }

    @Test func ordinaryPolicyCannotBindQualificationScope() throws {
        let client = try StorageLifecycleRootClient(installedHelperTeam: "ABCDEFGHIJ")
        let store = try StorageIdentity.StoreID(UUID().uuidString.lowercased())
        do {
            try client.bindQualificationScope(store: store, rootFD: -1)
            Issue.record("ordinary policy bound qualification scope")
        } catch let failure as StorageLifecycleRootClient.Failure {
            #expect(failure.code == .invalidRequest)
        }
    }

    @Test func unsignedProcessCannotMintQualificationPolicy() {
        #expect(throws: (any Error).self) {
            try StorageLifecycleNativePolicy.qualification(role: .engine)
        }
    }

    @Test func lostReplyHasDistinctErrorType() {
        let error: any Error = StorageLifecycleRootClient.QualificationCompletionReplyLost()
        #expect(!(error is StorageLifecycleRootClient.Failure))
    }
}
#endif
