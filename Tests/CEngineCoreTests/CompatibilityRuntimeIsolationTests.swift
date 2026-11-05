#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

@Suite struct CompatibilityRuntimeIsolationTests {
    typealias Isolation = CompatibilityRuntimeIsolation
    private let team = "ABCDEFGHIJ"

    private func generation(uniqueID: UInt64 = 123, version: UInt32 = 7) -> Data {
        var bytes = Data(count: 56)
        withUnsafeBytes(of: uniqueID) { bytes.replaceSubrange(16..<24, with: $0) }
        withUnsafeBytes(of: version) { bytes.replaceSubrange(32..<36, with: $0) }
        return bytes
    }

    private func observation(generation: Data? = nil, uid: UInt32 = 501, realUID: UInt32 = 501,
                             seconds: UInt64 = 100, microseconds: UInt64 = 1,
                             status: UInt32 = 0x10001) -> Isolation.Observation {
        Isolation.Observation(generation: generation ?? self.generation(), uid: uid, realUID: realUID,
            startSeconds: seconds, startMicroseconds: microseconds, codeStatus: status)
    }

    @Test func onlyExactProductionRolesAndTrustedTeamPassFieldRejection() throws {
        let production = SignedStorageIdentity.Namespace.production
        for identifier in [production.engineIdentifier, production.controllerIdentifier] {
            try Isolation.validateSigningFields(identifier: identifier, team: team, expectedTeam: team)
            #expect(throws: (any Error).self) {
                try Isolation.validateSigningFields(identifier: identifier, team: "0123456789", expectedTeam: team)
            }
        }
        for identifier in [production.helperIdentifier,
                           SignedStorageIdentity.Namespace.compatibility.engineIdentifier,
                           SignedStorageIdentity.Namespace.compatibility.controllerIdentifier,
                           SignedStorageIdentity.Namespace.compatibility.helperIdentifier, "dev.cengine.app", ""] {
            #expect(throws: (any Error).self) {
                try Isolation.validateSigningFields(identifier: identifier, team: team, expectedTeam: team)
            }
        }
    }

    @Test func exactKernelGenerationIsRequired() throws {
        try Isolation.validateGeneration(generation(), uniqueID: 123, pidVersion: 7)
        for invalid: Data? in [nil, Data(), Data(count: 55), Data(count: 57), generation(uniqueID: 124),
                               generation(version: 8), generation(uniqueID: 0)] {
            #expect(throws: (any Error).self) {
                try Isolation.validateGeneration(invalid, uniqueID: 123, pidVersion: 7)
            }
        }
        #expect(throws: (any Error).self) {
            try Isolation.validateGeneration(generation(uniqueID: 0), uniqueID: 0, pidVersion: 7)
        }
    }

    @Test func generationCredentialsStartAndCodeStatusMustRemainStable() throws {
        let before = observation()
        try Isolation.requireUnchanged(before: before, after: before)
        for after: Isolation.Observation? in [nil, observation(generation: generation(uniqueID: 124)),
                observation(generation: generation(version: 8)), observation(uid: 502), observation(realUID: 502),
                observation(seconds: 101), observation(microseconds: 2), observation(status: 0x10003)] {
            #expect(throws: (any Error).self) { try Isolation.requireUnchanged(before: before, after: after) }
        }
        #expect(throws: (any Error).self) { try Isolation.requireUnchanged(before: nil, after: before) }
        #expect(throws: (any Error).self) { try Isolation.requireUnchanged(before: nil, after: nil) }
    }

    @Test func kernelStatusFailsClosed() throws {
        try Isolation.validateCodeStatus(0x10001)
        for status: UInt32 in [0, 1, 0x10000, 0x10003, 0x10010001] {
            #expect(throws: (any Error).self) { try Isolation.validateCodeStatus(status) }
        }
    }

    @Test func fabricatedFieldsCannotReplaceNativeSignature() throws {
        // These are rejection checks returning Void, not identity/capability factories.
        try Isolation.validateSigningFields(identifier: SignedStorageIdentity.Namespace.production.engineIdentifier,
            team: team, expectedTeam: team)
        try Isolation.validateGeneration(generation(), uniqueID: 123, pidVersion: 7)
        try Isolation.requireUnchanged(before: observation(), after: observation())
        // An unsigned/ad-hoc test runner cannot become a Developer-ID production client.
        #expect(throws: (any Error).self) { try Isolation.verifyRunningCode(pid: getpid(), expectedTeam: team) }
        #expect(throws: (any Error).self) { try Isolation.verifyRunningCode(pid: -1, expectedTeam: team) }
        #expect(throws: (any Error).self) {
            try Isolation.verifyProductionClient(pid: getpid(), uniqueID: 123, pidVersion: 7)
        }
        #expect(throws: (any Error).self) {
            try Isolation.verifyProductionClient(pid: -1, uniqueID: 123, pidVersion: 7)
        }
    }
}
#endif
