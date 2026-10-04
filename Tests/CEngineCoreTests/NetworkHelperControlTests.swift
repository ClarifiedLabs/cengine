#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import CEngineRuntime

@Suite struct NetworkHelperControlTests {
    private func reply() -> xpc_object_t {
        let value = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_bool(value, "ok", true)
        xpc_dictionary_set_int64(value, "protocol-version", PrivilegedPortProtocol.version)
        xpc_dictionary_set_string(value, "build-fingerprint", "diagnostic-only")
        xpc_dictionary_set_string(value, "service-name", PrivilegedPortProtocol.testCompatServiceName)
        xpc_dictionary_set_int64(value, "pid", 123)
        xpc_dictionary_set_uint64(value, "owner-uid", UInt64(geteuid()))
        return value
    }

    private func decode(_ value: xpc_object_t) throws -> NetworkHelperStatus {
        try NetworkHelperControl.decodeStatus(value, expectedService: PrivilegedPortProtocol.testCompatServiceName)
    }

    @Test func legacyStatusMayOmitCapabilitiesButCannotOmitProtocol() throws {
        #expect(try decode(reply()).capabilities == nil)
        for version in [Int64(0), PrivilegedPortProtocol.version - 1, PrivilegedPortProtocol.version + 1] {
            let value = reply()
            xpc_dictionary_set_int64(value, "protocol-version", version)
            #expect(throws: (any Error).self) { try decode(value) }
        }
        let value = reply()
        xpc_dictionary_set_value(value, "protocol-version", nil)
        #expect(throws: (any Error).self) { try decode(value) }
    }

    @Test func unknownStatusFieldsAndNonBooleanSuccessAreRejected() throws {
        let value = reply()
        xpc_dictionary_set_bool(value, "native-proof", true)
        #expect(throws: (any Error).self) { try decode(value) }
        xpc_dictionary_set_value(value, "native-proof", nil)
        xpc_dictionary_set_int64(value, "ok", 1)
        #expect(throws: (any Error).self) { try decode(value) }
        xpc_dictionary_set_bool(value, "ok", false)
        #expect(throws: (any Error).self) { try decode(value) }
    }

    @Test func exactXPCScalarTypesAndPositivePIDAreRequired() throws {
        for key in ["protocol-version", "build-fingerprint", "service-name", "pid", "owner-uid"] {
            let value = reply()
            xpc_dictionary_set_bool(value, key, false)
            #expect(throws: (any Error).self) { try decode(value) }
            xpc_dictionary_set_value(value, key, nil)
            #expect(throws: (any Error).self) { try decode(value) }
        }
        for pid in [Int64(0), -1, Int64(Int32.max) + 1] {
            let value = reply()
            xpc_dictionary_set_int64(value, "pid", pid)
            #expect(throws: (any Error).self) { try decode(value) }
        }
        let value = reply()
        xpc_dictionary_set_uint64(value, "owner-uid", UInt64(UInt32.max) + 1)
        #expect(throws: (any Error).self) { try decode(value) }
        xpc_dictionary_set_uint64(value, "owner-uid", 0)
        xpc_dictionary_set_string(value, "service-name", PrivilegedPortProtocol.defaultServiceName)
        #expect(throws: (any Error).self) { try decode(value) }
    }

    @Test func capabilityDataIsBoundedAndStrict() throws {
        let value = reply()
        xpc_dictionary_set_string(value, "capabilities", "{}")
        #expect(throws: (any Error).self) { try decode(value) }
        for bytes in [Data(), Data("{}".utf8), Data(repeating: 0, count: NetworkHelperCapabilities.maximumBytes + 1)] {
            bytes.withUnsafeBytes { xpc_dictionary_set_data(value, "capabilities", $0.baseAddress, $0.count) }
            #expect(throws: (any Error).self) { try decode(value) }
        }
        let advertisement = NetworkHelperCapabilities.Advertisement(profile: .ordinary, storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange])
        let bytes = try NetworkHelperCapabilities.encode(advertisement)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(value, "capabilities", $0.baseAddress, $0.count) }
        // Decoding a public DTO does not produce native authority.
        #expect(try decode(value).capabilities == advertisement)
    }

    @Test func oldLifecycleStatusDecodesButDoesNotSatisfyManagedRequirement() throws {
        for (profile, requirement) in [(NetworkHelperCapabilities.Profile.ordinary, NetworkHelperCapabilities.Requirement.lifecycleV2),
                                       (.lifecycleQualification, .lifecycleQualification)] {
            let value = reply()
            let advertisement = NetworkHelperCapabilities.Advertisement(profile: profile, storageContracts: [.lifecycleV2, .lifecycleV2AdoptedServiceChange, .lifecycleV2StableHostIdentity])
            let bytes = try NetworkHelperCapabilities.encode(advertisement)
            bytes.withUnsafeBytes { xpc_dictionary_set_data(value, "capabilities", $0.baseAddress, $0.count) }
            let capabilities = try #require(decode(value).capabilities)
            #expect(capabilities == advertisement)
            #expect(throws: (any Error).self) { try NetworkHelperCapabilities.validate(capabilities, for: requirement) }
        }
    }

    @Test(arguments: NetworkHelperCapabilities.Requirement.allCases)
    func unsignedProcessCannotSelectManagedPolicy(requirement: NetworkHelperCapabilities.Requirement) {
        #expect(throws: (any Error).self) { try NetworkHelperControl.managedPolicy(for: requirement) }
    }

    @Test func unsignedEngineCannotQueryProductionOwnerStatus() async {
        await #expect(throws: (any Error).self) { try await NetworkHelperControl.storageOwnerStatus() }
    }

    @Test func actualSelfAuditCannotAuthenticateAsROOTHelper() throws {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        try #require(result == KERN_SUCCESS)
        #expect(throws: (any Error).self) {
            try StorageLifecycleRootClient.authenticate(token: token, team: "ABCDEFGHIJ")
        }
    }

    @Test func cancellationBeforeContinuationDoesNotStartTransport() async {
        let state = NetworkHelperRequestState<Bool>()
        state.finish(.failure(CancellationError()))
        do {
            let _: Bool = try await withCheckedThrowingContinuation { continuation in
                state.start(continuation) {
                    Issue.record("cancelled request started transport")
                    return {}
                }
            }
            Issue.record("cancelled request succeeded")
        } catch { #expect(error is CancellationError) }
    }

    @Test func completionRacesResumeAndCleanUpExactlyOnce() async throws {
        let state = NetworkHelperRequestState<Bool>()
        let cleanup = Counter()
        let value: Bool = try await withCheckedThrowingContinuation { continuation in
            state.start(continuation) { { cleanup.increment() } }
            DispatchQueue.concurrentPerform(iterations: 32) { _ in state.finish(.success(true)) }
            state.finish(.failure(CancellationError()))
        }
        #expect(value)
        #expect(cleanup.value == 1)
    }

    @Test func timeoutAndLateReplyReleaseOwnedResources() async {
        let state = NetworkHelperRequestState<Bool>()
        let cleanup = Counter()
        do {
            let _: Bool = try await withCheckedThrowingContinuation { continuation in
                state.start(continuation) { { cleanup.increment() } }
                state.finish(.failure(EngineError(.serviceUnavailable, "fixture timeout")))
                state.finish(.success(true))
                state.finish(.failure(CancellationError()))
            }
            Issue.record("late reply replaced timeout")
        } catch { #expect((error as? EngineError)?.code == .serviceUnavailable) }
        #expect(cleanup.value == 1)
    }

    @Test func setupFailureCompletesOnce() async {
        let state = NetworkHelperRequestState<Bool>()
        do {
            let _: Bool = try await withCheckedThrowingContinuation { continuation in
                state.start(continuation) { throw CancellationError() }
                state.finish(.success(true))
            }
            Issue.record("setup failure succeeded")
        } catch { #expect(error is CancellationError) }
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        var value: Int { lock.withLock { count } }
        func increment() { lock.withLock { count += 1 } }
    }
}
#endif
