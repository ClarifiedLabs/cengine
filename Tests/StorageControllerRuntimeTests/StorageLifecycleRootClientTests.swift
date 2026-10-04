import CEngineCore
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageControllerRuntime

@Suite struct StorageLifecycleRootClientTests {
    @Test func localizedFailureContainsOnlyClosedErrorCode() {
        for code in StorageIdentity.ErrorCode.allCases {
            let failure = StorageLifecycleRootClient.Failure(code)
            #expect(failure.errorDescription == code.rawValue)
            let error: any Error = failure
            #expect(error.localizedDescription == code.rawValue)
            #expect((error as NSError).localizedDescription == code.rawValue)
        }
    }
    @Test func closedEnvelopeRejectsUnknownAndWrongTypes() throws {
        let request = try StorageLifecycleRootProtocol.Request(requestID: .init(UUID().uuidString.lowercased()), body: .rootPublicKey)
        let bytes = try StorageLifecycleRootProtocol.encode(StorageLifecycleRootProtocol.Reply(for: request,
            body: .rootPublicKey(.init(publicData: Data(repeating: 1, count: 32)))))
        let reply = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_bool(reply, "ok", true)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress, $0.count) }
        #expect(try StorageLifecycleRootClient.decodeResponse(reply) == bytes) // Shape, not authentication.
        xpc_dictionary_set_bool(reply, "receiptProof", true)
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.decodeResponse(reply) }
        xpc_dictionary_set_value(reply, "receiptProof", nil); xpc_dictionary_set_int64(reply, "ok", 1)
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.decodeResponse(reply) }
    }
    @Test func descriptorMismatchAndInvalidDeadlinesFailBeforeTransport() throws {
        let request = try StorageLifecycleRootProtocol.Request(requestID: .init(UUID().uuidString.lowercased()), body: .rootPublicKey)
        let client = try StorageLifecycleRootClient(installedHelperTeam: "ABCDEFGHIJ")
        for pair: (Int32, Int32) in [(0, -1), (-1, 0), (0, 0)] {
            #expect(throws: (any Error).self) { try StorageLifecycleRootClient.message(request, rootFD: pair.0, backingFD: pair.1) }
        }
        for timeout in [0, -1, .infinity, .nan, 120.001] {
            #expect(throws: (any Error).self) { try client.request(request, timeout: timeout) }
        }
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient(installedHelperTeam: "bad") }
    }
    @Test func nativeSelfAuditCannotAuthenticateAsProductionUIDZeroHelper() throws {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        try #require(result == KERN_SUCCESS)
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.authenticate(token: token, team: "ABCDEFGHIJ") }
    }
}

@Suite struct StorageLifecycleRootAdoptionClientTests {
    private typealias W = StorageLifecycleAdoptionRootProtocol
    @Test func closedThreeDescriptorEnvelope() throws {
        let request = try W.Request(requestID: .init(UUID().uuidString.lowercased()), body: .status)
        let fd = open(NSTemporaryDirectory(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        defer { close(fd) }
        let message = try StorageLifecycleRootClient.adoptionMessage(request, pathFD: fd, rootFD: fd, lockFD: fd)
        var keys = Set<String>()
        xpc_dictionary_apply(message) { key, _ in keys.insert(String(cString: key)); return true }
        #expect(keys == ["operation", "request", "path-lock", "store-root", "daemon-lock"])
        #expect(String(cString: xpc_dictionary_get_string(message, "operation")!) == W.xpcOperation)
        for key in ["path-lock", "store-root", "daemon-lock"] {
            let copy = xpc_dictionary_dup_fd(message, key)
            #expect(copy >= 0)
            if copy >= 0 { close(copy) }
        }
        var length = 0
        let bytes = try #require(xpc_dictionary_get_data(message, "request", &length))
        #expect(try W.decodeRequest(Data(bytes: bytes, count: length)) == request)
        for fds: (Int32, Int32, Int32) in [(-1, fd, fd), (fd, -1, fd), (fd, fd, -1)] {
            #expect(throws: (any Error).self) {
                try StorageLifecycleRootClient.adoptionMessage(request, pathFD: fds.0, rootFD: fds.1, lockFD: fds.2)
            }
        }
    }
    @Test func actualReplyCorrelationAndHelperErrorsAreRequired() throws {
        let uuid = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = try StorageIdentity.StoreBinding(storeID: .init(uuid.rawValue), root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        let origin = try StorageLifecycleAdoptionProtocol.Origin(binding: .init(binding), rootPublicKey: Data(repeating: 7, count: 32),
            shimLaunchUUID: uuid.rawValue, specSHA256: String(repeating: "a", count: 64))
        let status = try W.Status(origin: origin, shimAudit: Data(repeating: 3, count: 32), shimUniqueID: 3,
            baseEpoch: 1, committedEpoch: 1, allocatedEpoch: 1, pending: nil, latest: nil)
        let request = try W.Request(requestID: .init(UUID().uuidString.lowercased()), body: .status)
        let reply = try W.Reply(for: request, body: .status(status))
        #expect(try StorageLifecycleRootClient.decodeAdoptionResponse(W.encode(reply), for: request) == reply)
        let other = try W.Request(requestID: .init(UUID().uuidString.lowercased()), body: .status)
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.decodeAdoptionResponse(W.encode(reply), for: other) }
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.decodeAdoptionResponse(W.encode(reply) + Data([10]), for: request) }
        let denied = try W.Reply(for: request, body: .failure(.unauthorized))
        do {
            _ = try StorageLifecycleRootClient.decodeAdoptionResponse(W.encode(denied), for: request)
            Issue.record("helper denial accepted")
        } catch let failure as StorageLifecycleRootClient.Failure { #expect(failure.code == .unauthorized) }
    }
}

@Suite struct StorageLifecycleRootScopeMessageTests {
    @Test func scopePinDoesNotRetainOrReleaseDaemonDirectoryLock() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        var owner = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        try #require(owner >= 0)
        defer { if owner >= 0 { close(owner) } }
        try #require(flock(owner, LOCK_EX | LOCK_NB) == 0)
        let contender = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        try #require(contender >= 0)
        defer { close(contender) }
        let store = try StorageIdentity.StoreID(UUID().uuidString.lowercased())
        let message = try StorageLifecycleRootClient.scopeMessage(store: store, rootFD: owner)
        let receiver = xpc_dictionary_dup_fd(message, "store-root")
        try #require(receiver >= 0)
        defer { close(receiver) }
        var original = stat(), received = stat()
        try #require(fstat(owner, &original) == 0 && fstat(receiver, &received) == 0)
        #expect(original.st_dev == received.st_dev && original.st_ino == received.st_ino)
        #expect(flock(contender, LOCK_EX | LOCK_NB) == -1)
        #expect(errno == EWOULDBLOCK)
        close(owner); owner = -1
        // Both the XPC message and the helper's retained copy remain alive.
        // Neither may keep the daemon lease alive after daemon death.
        withExtendedLifetime(message) {
            #expect(flock(contender, LOCK_EX | LOCK_NB) == 0)
        }
    }
    @Test func scopePinRejectsNonDirectoryDescriptor() throws {
        let fd = open("/dev/null", O_RDONLY | O_CLOEXEC)
        try #require(fd >= 0)
        defer { close(fd) }
        let store = try StorageIdentity.StoreID(UUID().uuidString.lowercased())
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.scopeMessage(store: store, rootFD: fd) }
    }
    @Test func productionScopeBindEnvelopeIsClosed() throws {
        let fd = open(NSTemporaryDirectory(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); defer { close(fd) }
        let store = try StorageIdentity.StoreID("11111111-1111-4111-8111-111111111111")
        let message = try StorageLifecycleRootClient.scopeMessage(store: store, rootFD: fd)
        var keys = Set<String>()
        xpc_dictionary_apply(message) { key, _ in keys.insert(String(cString: key)); return true }
        #expect(keys == ["operation", "request", "store-root"])
        #expect(String(cString: xpc_dictionary_get_string(message, "operation")!) == StorageLifecycleScopeProtocol.xpcOperation)
        var length = 0
        let bytes = try #require(xpc_dictionary_get_data(message, "request", &length))
        #expect(try StorageLifecycleScopeProtocol.decode(Data(bytes: bytes, count: length)) == .init(store: store))
        #expect(throws: (any Error).self) { try StorageLifecycleRootClient.scopeMessage(store: store, rootFD: -1) }
        // Production client is a real production-policy client (no qualification selector).
        #expect(try StorageLifecycleRootClient(installedHelperTeam: "ABCDEFGHIJ").policy == .production)
    }
}
