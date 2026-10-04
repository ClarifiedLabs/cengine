import CEngineCore
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageBootstrapHelper

private typealias Root = StorageLifecycleColdRootProtocol
private typealias Adapter = StorageBootstrapLifecycleColdRootXPC
private typealias Shim = StorageLifecycleColdShimProtocol

@Suite struct StorageBootstrapLifecycleColdNativeTests {
    private func request() throws -> Root.Request {
        try .init(requestID: .init(UUID().uuidString.lowercased()), body: .complete(
            operationID: UUID().uuidString.lowercased(), signedOpenSHA256: String(repeating: "a", count: 64)))
    }
    private func envelope(_ request: Root.Request) throws -> xpc_object_t {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", Root.xpcOperation)
        let bytes = try Root.encode(request)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        let fd = open("/dev/null", O_RDONLY | O_CLOEXEC); defer { close(fd) }
        #expect(fd >= 0)
        for key in Adapter.descriptorKeys { xpc_dictionary_set_fd(message, key, fd) }
        return message
    }
    @Test func routesRequireThreeCanonicalLocksAndRejectExtraClaims() throws {
        let request = try request(), message = try envelope(request)
        #expect(try Adapter.decodeRequest(message) == request)
        #expect(try StorageBootstrapLifecycleRouter.validateAdmission(message) == Root.xpcOperation)
        #expect(StorageBootstrapLifecycleRouter.recognizes(Root.xpcOperation))
        for op in ["storage-lifecycle-cold-shim", "storage-lifecycle-cold-adoption-enroll"] {
            #expect(StorageBootstrapLifecycleRouter.recognizes(op))
        }
        for key in Adapter.descriptorKeys {
            let bad = try envelope(request)
            xpc_dictionary_set_value(bad, key, nil)
            #expect(throws: (any Error).self) { try Adapter.decodeRequest(bad) }
            xpc_dictionary_set_int64(bad, key, 3)
            #expect(throws: (any Error).self) { try StorageBootstrapLifecycleRouter.validateAdmission(bad) }
        }
        xpc_dictionary_set_bool(message, "old-shim-exited", true)
        #expect(throws: (any Error).self) { try Adapter.decodeRequest(message) }
    }
    @Test func borrowedDescriptorsCloseOnFailureAndCannotCrossRequest() throws {
        let request = try request(), message = try envelope(request)
        var borrowed: [Int32] = []
        #expect(throws: (any Error).self) {
            try Adapter.withDescriptors(message, request: request) { a, b, c in
                borrowed = [a, b, c]
                #expect(borrowed.allSatisfy { fcntl($0, F_GETFD) & FD_CLOEXEC != 0 })
                throw BootstrapFailure(.unauthorized)
            }
        }
        #expect(borrowed.count == 3 && borrowed.allSatisfy { fcntl($0, F_GETFD) == -1 })
        #expect(throws: (any Error).self) {
            try Adapter.withDescriptors(message, request: self.request()) { _, _, _ in Issue.record("used mismatched descriptors") }
        }
    }
    @Test func wrongBackingFDIsClosedAndMissingFDRefused() throws {
        let message = xpc_dictionary_create(nil, nil, 0)
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleColdXPC.withBacking(message) { _ in Issue.record("missing fd") } }
        let fd = open("/dev/null", O_RDONLY | O_CLOEXEC); defer { close(fd) }
        xpc_dictionary_set_fd(message, "backing-fd", fd)
        var borrowed: Int32 = -1
        #expect(throws: (any Error).self) {
            try StorageBootstrapLifecycleColdXPC.withBacking(message) { duplicate in
                borrowed = duplicate
                _ = try StorageBootstrapBindings(ownerUID: geteuid()).identity(duplicate, type: S_IFREG, role: .backing)
            }
        }
        #expect(borrowed >= 0 && fcntl(borrowed, F_GETFD) == -1)
        #expect(fcntl(fd, F_GETFD) >= 0)
    }
    @Test func replyCorrelationIncludesBodyNotOnlyRequestID() throws {
        let original = try request()
        let changed = try Root.Request(requestID: original.requestID, body: .complete(
            operationID: UUID().uuidString.lowercased(), signedOpenSHA256: String(repeating: "b", count: 64)))
        let bytes = try Root.encode(Root.Reply(for: original, body: .failure(.unavailable)))
        #expect(try Root.decodeReply(bytes, for: original).body == .failure(.unavailable))
        #expect(throws: (any Error).self) { try Root.decodeReply(bytes, for: changed) }
    }
    @Test func localGreetingDictionaryCannotEnrollWithoutNativeScopeDaemon() throws {
        let volume = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = try StorageIdentity.StoreBinding(storeID: .init(UUID().uuidString.lowercased()),
            root: .init(volumeUUID: volume, inode: 2),
            backing: .init(identity: .init(volumeUUID: volume, inode: 3), size: 4096), expectedExt4UUID: volume)
        let root = try StorageIdentity.RootPublicKey(publicData: Data(repeating: 7, count: 32))
        let launch = try StorageLifecycleColdProtocol.Launch(shimLaunchUUID: UUID().uuidString.lowercased(),
            specSHA256: String(repeating: "a", count: 64), initramfsSHA256: String(repeating: "b", count: 64), ext4UUID: volume.rawValue, bytes: 4096)
        let greeting = try Shim.Greeting(channelID: UUID().uuidString.lowercased(), daemonUniqueID: 123,
            rootPublicKey: root.publicData, binding: .init(binding), bootBinding: .init(shimLaunchUUID: launch.shimLaunchUUID,
                guestBootNonce: UUID().uuidString.lowercased(), ext4UUID: volume.rawValue, bytes: 4096), launch: launch,
            heldBackingIdentity: .init(.init(stableIdentity: binding.backing.identity, device: 1)))
        let message = xpc_dictionary_create(nil, nil, 0), reply = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", "storage-lifecycle-cold-shim")
        xpc_dictionary_set_string(message, "role", "storage-shim")
        xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
        let bytes = try Shim.encode(greeting)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        #expect(try StorageBootstrapLifecycleRouter.validateAdmission(message) == "storage-lifecycle-cold-shim")
        let worker = StorageBootstrapLifecycleChildWorker()
        let transport = StorageBootstrapLifecycleColdXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ", expectedRootPublicKey: root,
            rootFD: -1, worker: worker, candidate: { _, _, _ in throw BootstrapFailure(.unauthorized) })
        let peer = xpc_connection_create(nil, nil)
        xpc_connection_set_event_handler(peer) { _ in }
        xpc_connection_resume(peer)
        defer { xpc_connection_cancel(peer) }
        try worker.perform {
            #expect(throws: (any Error).self) { try transport.greet(message, reply: reply, peer: peer) }
            #expect(!xpc_dictionary_get_bool(reply, "ok"))
        }
    }
}
