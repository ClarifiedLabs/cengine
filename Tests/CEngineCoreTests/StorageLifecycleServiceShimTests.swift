#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization
import Testing
@testable import CEngineRuntime
@preconcurrency import XPC

@_silgen_name("xpc_dictionary_get_audit_token")
private func serviceShimTestMessageAudit(_ message: xpc_object_t, _ token: UnsafeMutablePointer<audit_token_t>)

@Suite struct StorageLifecycleServiceShimTests {
    @Test func successorGreetingKeepsChannelBindingAndRotatesOnlyBootTrust() throws {
        typealias W = StorageLifecycleServiceProofProtocol
        func id() -> String { UUID().uuidString.lowercased() }
        let root = try StorageIdentity.RootPublicKey(publicData: Data(repeating: 7, count: 32))
        let volume = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        let binding = try StorageIdentity.StoreBinding(storeID: .init(id()), root: .init(volumeUUID: volume, inode: 2),
            backing: .init(identity: .init(volumeUUID: volume, inode: 3), size: 4096), expectedExt4UUID: volume)
        let bootBinding = DiskInitializationProtocol.Binding(shimLaunchUUID: id(), guestBootNonce: id(),
            ext4UUID: volume.rawValue, bytes: 4096)
        let identity = try StorageLifecycleProtocol.Identity(binding: binding, generation: 1)
        func trust(_ epoch: String, _ ca: String, _ spki: String, generation: UInt64 = 1) throws -> StorageLifecycleBootTrust {
            try .init(identity: generation == 1 ? identity : .init(binding: binding, generation: generation), serviceEpoch: epoch,
                tlsRootSHA256: String(repeating: ca, count: 64), serverSPKI: String(repeating: spki, count: 64),
                bootstrapKey: root.fingerprint.rawValue)
        }
        func greeting(channel: String, daemon: UInt64 = 10, boot: StorageLifecycleBootTrust,
                      bootBinding value: DiskInitializationProtocol.Binding = bootBinding,
                      initramfs: String = "a") throws -> W.Greeting {
            try .init(channelID: channel, daemonUniqueID: daemon, rootPublicKey: root.publicData, binding: .init(binding),
                bootBinding: value, initramfsSHA256: String(repeating: initramfs, count: 64), boot: boot)
        }
        let channel = id(), epoch = id(), old = try greeting(channel: channel, boot: trust(epoch, "b", "c"))
        let next = try trust(id(), "d", "e")
        #expect(try StorageLifecycleServiceShim.isSuccessor(greeting(channel: channel, boot: next), of: old))
        #expect(try StorageLifecycleServiceShim.isSuccessor(old, of: old))
        let rejected = try [greeting(channel: id(), boot: next), greeting(channel: channel, daemon: 11, boot: next),
            greeting(channel: channel, boot: next, bootBinding: .init(shimLaunchUUID: id(), guestBootNonce: id(),
                ext4UUID: volume.rawValue, bytes: 4096)),
            greeting(channel: channel, boot: next, initramfs: "f"),
            greeting(channel: channel, boot: trust(epoch, "d", "e")), greeting(channel: channel, boot: trust(id(), "b", "e")),
            greeting(channel: channel, boot: trust(id(), "d", "c")), greeting(channel: channel, boot: trust(id(), "d", "e", generation: 2))]
        for candidate in rejected { #expect(try !StorageLifecycleServiceShim.isSuccessor(candidate, of: old)) }
    }

    @Test func rejectsActualUnsignedMachRootReply() async throws {
        // An actual anonymous Mach exchange, not a fabricated audit trailer. No
        // named service, installed helper, VM, or elevation is needed.
        try await Task.detached {
            let queue = DispatchQueue(label: "dev.cengine.test.service-native-reply")
            let listener = xpc_connection_create(nil, queue)
            let peers = Mutex<[xpc_connection_t]>([])
            xpc_connection_set_event_handler(listener) { peer in
                guard xpc_get_type(peer) == XPC_TYPE_CONNECTION else { return }
                peers.withLock { $0.append(peer) }
                xpc_connection_set_event_handler(peer) { message in
                    guard xpc_get_type(message) == XPC_TYPE_DICTIONARY,
                          let reply = xpc_dictionary_create_reply(message) else { return }
                    xpc_dictionary_set_bool(reply, "ok", true)
                    xpc_dictionary_set_string(reply, "operation", "storage-lifecycle-service-challenge")
                    xpc_connection_send_message(peer, reply)
                }
                xpc_connection_resume(peer)
            }
            xpc_connection_resume(listener)
            let client = xpc_connection_create_from_endpoint(xpc_endpoint_create(listener))
            xpc_connection_set_event_handler(client) { _ in }
            xpc_connection_resume(client)
            defer {
                xpc_connection_cancel(client)
                xpc_connection_cancel(listener)
                let retained = peers.withLock { value in let result = value; value.removeAll(); return result }
                for peer in retained { xpc_connection_cancel(peer) }
            }
            let received = DispatchSemaphore(value: 0)
            let request = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(request, "operation", "storage-lifecycle-service-shim")
            xpc_connection_send_message_with_reply(client, request, queue) { reply in
                defer { received.signal() }
                guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
                    Issue.record("native XPC did not deliver a dictionary reply"); return
                }
                var token = audit_token_t()
                serviceShimTestMessageAudit(reply, &token)
                #expect(token.val.5 == UInt32(getpid()))
                #expect(token.val.1 == geteuid())
                #expect(token.val.3 == getuid())
                #expect(throws: (any Error).self) {
                    try StorageLifecycleServiceShim.authenticateRoot(reply, team: "ABCDEFGHIJ")
                }
                #expect(throws: (any Error).self) {
                    try StorageLifecycleAdoptionShim.authenticateRoot(reply, team: "ABCDEFGHIJ")
                }
            }
            func waitForReply() -> Bool { received.wait(timeout: .now() + 5) == .success }
            try #require(waitForReply())
        }.value
    }
}
#endif
