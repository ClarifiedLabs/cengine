#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import CEngineRuntime

@Suite struct StorageLifecycleColdShimTests {
    private typealias W = StorageLifecycleColdShimProtocol
    private func challenge(_ f: ColdContractFixture, counter: UInt64 = 1, nonce: UInt8 = 3,
                           prepare: String? = nil, signed: String? = nil, base: UInt64? = nil) throws -> W.Challenge {
        try .init(greeting: f.prepare.mountedGreeting, prepareSHA256: prepare ?? f.prepare.digest,
            unsignedGrant: f.prepared.signedOpen.request.takeover.grant,
            signedOpenSHA256: signed ?? f.prepared.signedOpenSHA256, baseEpoch: base ?? f.prepared.baseEpoch,
            shimAudit: Data(repeating: 1, count: 32), shimUniqueID: 20,
            daemonAudit: Data(repeating: 2, count: 32), daemonUniqueID: 10,
            counter: counter, nonce: Data(repeating: nonce, count: 32), expiresUnixMS: 40_000)
    }
    private func seed(_ f: ColdContractFixture, operation: String? = nil, digest: String? = nil,
                      base: UInt64? = nil) throws -> W.ColdEnrollmentSeed {
        try .init(operationID: operation ?? f.prepare.operationID,
            signedOpenSHA256: digest ?? f.prepared.signedOpenSHA256,
            successorOrigin: f.prepared.successorOrigin, baseEpoch: base ?? f.prepared.baseEpoch)
    }
    @Test func frozenClaimCountersNonceReplayAndExactRetry() throws {
        let f = try ColdContractFixture(), first = try challenge(f)
        var state = StorageLifecycleColdClaimState()
        try state.accept(first, now: 10_000)
        try state.accept(first, now: 10_001)
        #expect(throws: (any Error).self) { try state.accept(first, now: 40_000) }
        for changed in [try challenge(f, counter: 1, nonce: 4), try challenge(f, counter: 2),
            try challenge(f, counter: 2, nonce: 4, prepare: String(repeating: "0", count: 64)),
            try challenge(f, counter: 2, nonce: 4, signed: String(repeating: "0", count: 64)),
            try challenge(f, counter: 2, nonce: 4, base: 2)] {
            #expect(throws: (any Error).self) { try state.accept(changed, now: 10_000) }
        }
        let second = try challenge(f, counter: 2, nonce: 4)
        try state.accept(second, now: 10_000)
        try state.accept(second, now: 10_000)
        #expect(throws: (any Error).self) { try state.accept(first, now: 10_000) }
        #expect(throws: (any Error).self) { try state.accept(challenge(f, counter: 3, nonce: 3), now: 10_000) }
        #expect(state.first == first)
    }
    @Test func claimHistoryIsBoundedWithoutEvictingReplayEvidence() throws {
        let f = try ColdContractFixture(), template = try challenge(f)
        var state = StorageLifecycleColdClaimState()
        var latest = template
        for index in 1...StorageLifecycleColdClaimState.maximumChallenges {
            var nonce = Data(repeating: 0, count: 32)
            var value = UInt64(index).bigEndian
            withUnsafeBytes(of: &value) { nonce.replaceSubrange(0..<8, with: $0) }
            latest = try .init(greeting: template.greeting, prepareSHA256: template.prepareSHA256,
                unsignedGrant: template.unsignedGrant, signedOpenSHA256: template.signedOpenSHA256,
                baseEpoch: template.baseEpoch, shimAudit: template.shimAudit, shimUniqueID: template.shimUniqueID,
                daemonAudit: template.daemonAudit, daemonUniqueID: template.daemonUniqueID,
                counter: UInt64(index), nonce: nonce, expiresUnixMS: template.expiresUnixMS)
            try state.accept(latest, now: 10_000)
        }
        try state.accept(latest, now: 10_000) // Exact latest retry needs no allocation.
        #expect(throws: (any Error).self) {
            try state.accept(challenge(f, counter: UInt64(StorageLifecycleColdClaimState.maximumChallenges + 1), nonce: 255), now: 10_000)
        }
        try state.validate(seed(f))
    }
    @Test func enrollmentMustJoinAllFrozenFields() throws {
        let f = try ColdContractFixture()
        var state = StorageLifecycleColdClaimState()
        #expect(throws: (any Error).self) { try state.validate(seed(f)) }
        try state.accept(challenge(f), now: 10_000)
        try state.validate(seed(f))
        for bad in [try seed(f, operation: UUID().uuidString.lowercased()),
                    try seed(f, digest: String(repeating: "0", count: 64)), try seed(f, base: 2)] {
            #expect(throws: (any Error).self) { try state.validate(bad) }
        }
    }
    @Test func locallyCreatedPlausibleRootMessageIsNotAuthenticated() throws {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_bool(message, "ok", true)
        xpc_dictionary_set_string(message, "operation", "storage-lifecycle-cold-enrollment")
        let data = try W.encode(seed(ColdContractFixture()))
        data.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        #expect(throws: (any Error).self) { try StorageLifecycleColdShim.authenticateRoot(message, team: "TEAM") }
    }
    @Test func coldRegistrationTransfersSeedAndFDButReconnectIsOrdinaryOrigin() throws {
        let f = try ColdContractFixture(), seed = try seed(f), origin = f.prepared.successorOrigin
        let pipe = Pipe()
        let message = try StorageLifecycleAdoptionShim.registration(origin: origin,
            enrolling: pipe.fileHandleForReading.fileDescriptor, coldSeed: seed)
        #expect(String(cString: try #require(xpc_dictionary_get_string(message, "operation"))) == "storage-lifecycle-cold-adoption-enroll")
        var count = 0
        let raw = try #require(xpc_dictionary_get_data(message, "cold-seed", &count))
        #expect(try W.decodeEnrollmentSeed(Data(bytes: raw, count: count)) == seed)
        let descriptor = xpc_dictionary_dup_fd(message, "backing-fd")
        try #require(descriptor >= 0)
        Darwin.close(descriptor)
        let reconnect = try StorageLifecycleAdoptionShim.registration(origin: origin, enrolling: nil)
        #expect(String(cString: try #require(xpc_dictionary_get_string(reconnect, "operation"))) == "storage-lifecycle-adoption-shim")
        #expect(xpc_dictionary_get_value(reconnect, "cold-seed") == nil)
        #expect(xpc_dictionary_get_value(reconnect, "backing-fd") == nil)
        #expect(throws: (any Error).self) { try StorageLifecycleAdoptionShim.registration(origin: origin, enrolling: nil, coldSeed: seed) }
    }
    @Test func resumeNativeClaimAndEnrollmentKeepGenesisPurpose() throws {
        let f = try ResumeContractFixture(), prepare = try #require(f.prepare)
        let claim = try W.Challenge(greeting: f.probeGreeting, prepareSHA256: prepare.digest,
            unsignedGrant: f.prepared.signedOpen.request.takeover.grant,
            signedOpenSHA256: f.prepared.signedOpenSHA256, baseEpoch: 1,
            shimAudit: Data(repeating: 1, count: 32), shimUniqueID: 20,
            daemonAudit: Data(repeating: 2, count: 32), daemonUniqueID: 10,
            counter: 1, nonce: Data(repeating: 3, count: 32), expiresUnixMS: 40_000)
        let seed = try W.ColdEnrollmentSeed(operationID: prepare.operationID,
            signedOpenSHA256: f.prepared.signedOpenSHA256, successorOrigin: f.prepared.successorOrigin,
            baseEpoch: 1, purpose: .resumeReadOnly)
        var state = StorageLifecycleColdClaimState()
        #expect(throws: (any Error).self) { try state.validate(seed) }
        try state.accept(claim, now: 10_000)
        try state.validate(seed)
        let cold = try W.ColdEnrollmentSeed(operationID: seed.operationID, signedOpenSHA256: seed.signedOpenSHA256,
            successorOrigin: seed.successorOrigin, baseEpoch: 2, purpose: .cold)
        #expect(throws: (any Error).self) { try state.validate(cold) }
        let pipe = Pipe()
        let message = try StorageLifecycleAdoptionShim.registration(origin: seed.successorOrigin,
            enrolling: pipe.fileHandleForReading.fileDescriptor, coldSeed: seed)
        #expect(String(cString: try #require(xpc_dictionary_get_string(message, "operation"))) == "storage-lifecycle-resume-adoption-enroll")
        #expect(xpc_dictionary_get_value(message, "cold-seed") == nil)
        var count = 0
        let raw = try #require(xpc_dictionary_get_data(message, "resume-seed", &count))
        #expect(try W.decodeEnrollmentSeed(Data(bytes: raw, count: count)) == seed)
    }

    @Test func coldAdoptionNeverResetsLargeBaseEpochToOne() throws {
        let f = try ColdContractFixture(), origin = f.prepared.successorOrigin, base = f.prepared.baseEpoch
        var fence = StorageLifecycleAdoptionFence(origin: origin, baseEpoch: base)
        func request(_ expected: UInt64) throws -> StorageLifecycleAdoptionProtocol.Request {
            try .init(id: UUID().uuidString.lowercased(), origin: origin, expectedEpoch: expected,
                daemonAudit: Data(repeating: 1, count: 32), daemonUniqueID: 1,
                controllerAudit: Data(repeating: 2, count: 32), controllerUniqueID: 2)
        }
        #expect(throws: (any Error).self) { try fence.fence(request(1)) }
        #expect(throws: (any Error).self) { try fence.fence(request(base - 1)) }
        let current = try request(base)
        #expect(try fence.fence(current))
        try fence.commit(current)
        #expect(try !fence.fence(current))
    }
}
#endif
