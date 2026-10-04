import CEngineCore
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageBootstrapHelper

private typealias FreshWire = StorageLifecycleFreshProtocol
private typealias FreshEndpoint = StorageBootstrapLifecycleFreshEndpoint
private func freshID() -> String { UUID().uuidString.lowercased() }
private func freshProcess(_ pid: Int32) -> BootstrapProcess {
    .init(pid: pid, startSeconds: 1, startMicroseconds: 2, boot: "unsigned-seam",
          signingIdentity: "not-native-evidence", uniqueID: UInt64(pid), pidVersion: 1,
          auditToken: Data(repeating: UInt8(truncatingIfNeeded: pid), count: 32))
}
private final class FreshClock: @unchecked Sendable {
    private let lock = NSLock()
    private var wall: UInt64 = 1_000_000
    private var monotonic: TimeInterval = 100
    func now() -> UInt64 { lock.withLock { wall } }
    func uptime() -> TimeInterval { lock.withLock { monotonic } }
    func expire(wallClock: Bool) { lock.withLock { if wallClock { wall += FreshWire.lifetimeMS } else { monotonic += 31 } } }
}
private final class FreshFixture: @unchecked Sendable {
    let daemon = freshProcess(10), shim = freshProcess(11)
    let worker = StorageBootstrapLifecycleChildWorker()
    let clock = FreshClock()
    let root: StorageIdentity.RootPublicKey
    let binding: StorageIdentity.StoreBinding
    let greeting: FreshWire.Greeting
    let grant: Lifecycle.Grant
    init() throws {
        root = try .init(publicData: Data(repeating: 7, count: 32))
        let volume = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        binding = try .init(storeID: .init(freshID()), root: .init(volumeUUID: volume, inode: 2),
            backing: .init(identity: .init(volumeUUID: volume, inode: 3), size: 4096), expectedExt4UUID: volume)
        greeting = try .init(channelID: freshID(), daemonUniqueID: daemon.uniqueID, rootPublicKey: root.publicData,
            store: binding.storeID.rawValue, shimLaunchUUID: freshID(), guestBootNonce: freshID(), operationUUID: freshID(),
            ext4UUID: volume.rawValue, bytes: 4096, initramfsSHA256: String(repeating: "a", count: 64),
            device: 1, inode: 3, volumeUUID: volume.rawValue)
        grant = try .init(operation: .initialize, id: freshID(), identity: .init(binding: binding, generation: 1),
            serial: 1, expectedEpoch: 0, newKey: String(repeating: "b", count: 64))
    }
    func reply(_ challenge: FreshWire.Challenge) throws -> FreshEndpoint.Received {
        try .init(shim: shim, bytes: Lifecycle.encode(FreshWire.Reply(challengeSHA256: challenge.digest)))
    }
    func endpoint(counter: StorageBootstrapLifecycleChildCounter = .init(), timeout: TimeInterval = 1,
                  root override: StorageIdentity.RootPublicKey? = nil, sender: FreshEndpoint.Sender? = nil) throws -> FreshEndpoint {
        try .init(greeting: greeting, daemon: daemon, shim: shim, channel: StorageBootstrapChildChannel(),
            expectedRoot: override ?? root, counter: counter, worker: worker, timeout: timeout,
            now: clock.now, uptime: clock.uptime, sender: sender ?? { [self] challenge, complete in complete(.success(try reply(challenge))) })
    }
    func prove(_ endpoint: FreshEndpoint, grant override: Lifecycle.Grant? = nil,
               daemon owner: BootstrapProcess? = nil, binding disk: StorageIdentity.StoreBinding? = nil,
               repin: () throws -> Void = {}) throws {
        try worker.perform { try endpoint.prove(binding: disk ?? binding, grant: override ?? grant, daemon: owner ?? daemon, repin: repin) }
    }
}

/// Direct-exchange state seams only. Real positive signed native acceptance remains
/// separate; none of these fabricated tuples is passed to a native audit SPI.
@Suite struct StorageBootstrapLifecycleFreshTests {
    @Test func enrollmentExpiryCannotInvalidateExactLiveRegreeting() throws {
        let daemon = freshProcess(10)
        let select = StorageBootstrapLifecycleEnrollment.daemon
        #expect(try select(daemon, daemon.uniqueID, nil, nil, 100) == daemon)
        #expect(try select(daemon, daemon.uniqueID, daemon, 50, 100) == daemon)
        #expect(try select(nil, daemon.uniqueID, daemon, 101, 100) == daemon)
        #expect(throws: (any Error).self) { try select(nil, daemon.uniqueID, daemon, 100, 100) }
        #expect(throws: (any Error).self) { try select(nil, daemon.uniqueID, nil, nil, 100) }
        #expect(throws: (any Error).self) { try select(daemon, 11, daemon, 101, 100) }
        // This selects metadata only; greet still independently re-pins native
        // processes and compares the entire immutable channel greeting.
    }

    @Test func repeatedFreshExactClaimsUseNewNoncesWithoutLifetimeHistory() throws {
        let f = try FreshFixture()
        var counters: [UInt64] = [], nonces = Set<Data>(), pins = 0
        let endpoint = try f.endpoint { challenge, complete in
            counters.append(challenge.counter); nonces.insert(challenge.nonce)
            complete(.success(try f.reply(challenge)))
        }
        for _ in 0..<130 { try f.prove(endpoint, repin: { pins += 1 }) }
        #expect(counters == Array(UInt64(1)...130))
        #expect(nonces.count == 130 && pins == 260 && endpoint.channel.isOpen)
    }
    @Test func consumedInitializationCannotBindAnotherGrantOrGeneration() throws {
        for newGeneration in [false, true] {
            let f = try FreshFixture(), endpoint = try f.endpoint()
            try f.prove(endpoint)
            let grant = try Lifecycle.Grant(operation: .initialize, id: freshID(),
                identity: .init(binding: f.binding, generation: newGeneration ? 2 : 1), serial: 2,
                expectedEpoch: 0, newKey: f.grant.newKey)
            #expect(throws: (any Error).self) { try f.prove(endpoint, grant: grant) }
            #expect(!endpoint.channel.isOpen)
        }
    }
    @Test func badRootDaemonBindingAndGrantRefuseBeforeExchange() throws {
        let f = try FreshFixture()
        #expect(throws: (any Error).self) { try f.endpoint(root: .init(publicData: Data(repeating: 8, count: 32))) }
        let other = try FreshFixture()
        for kind in 0..<3 {
            var calls = 0
            let endpoint = try f.endpoint { _, _ in calls += 1 }
            #expect(throws: (any Error).self) {
                try f.prove(endpoint, grant: kind == 0 ? other.grant : nil,
                    daemon: kind == 1 ? freshProcess(12) : nil, binding: kind == 2 ? other.binding : nil)
            }
            #expect(calls == 0 && !endpoint.channel.isOpen)
        }
    }
    @Test func replyMustHaveCurrentChallengeAndIndependentlyPinnedShim() throws {
        for kind in 0..<5 {
            let f = try FreshFixture()
            var previous: FreshEndpoint.Received?
            let endpoint = try f.endpoint { challenge, complete in
                let actual = try f.reply(challenge)
                if previous == nil { previous = actual; complete(.success(actual)); return }
                switch kind {
                case 0: complete(.success(previous!))
                case 1: complete(.success(.init(shim: f.daemon, bytes: actual.bytes)))
                case 2: complete(.success(.init(shim: f.shim, bytes: actual.bytes + Data([10]))))
                case 3: complete(.failure(BootstrapFailure(.unavailable)))
                default: complete(.success(actual)); complete(.success(actual))
                }
            }
            try f.prove(endpoint)
            #expect(throws: (any Error).self) { try f.prove(endpoint) }
            #expect(!endpoint.channel.isOpen)
        }
    }
    @Test func expirationPostPinLossAndCallbackLossRevoke() throws {
        for kind in 0..<5 {
            let f = try FreshFixture(), endpoint = try f.endpoint()
            var pins = 0
            #expect(throws: (any Error).self) {
                try f.prove(endpoint, repin: {
                    pins += 1
                    if pins == 2 {
                        switch kind {
                        case 0: f.clock.expire(wallClock: true)
                        case 1: f.clock.expire(wallClock: false)
                        case 2: endpoint.revoke()
                        default: throw BootstrapFailure(.unauthorized)
                        }
                    }
                })
            }
            #expect(!endpoint.channel.isOpen)
        }
    }
    @Test func timeoutLateCallbackAndCounterOverflowNeverRevive() throws {
        let f = try FreshFixture()
        var late: FreshEndpoint.Completion?, response: FreshEndpoint.Received?
        let endpoint = try f.endpoint(timeout: 0.01) { challenge, completion in
            late = completion; response = try f.reply(challenge)
        }
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
        late?(.success(try #require(response)))
        #expect(!endpoint.channel.isOpen)
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
        let last = try f.endpoint(counter: .init(initialValue: UInt64.max - 1))
        try f.prove(last)
        #expect(throws: (any Error).self) { try f.prove(last) }
        #expect(!last.channel.isOpen)
    }
    @Test func disconnectWakesWithoutAcquiringProofWorker() async throws {
        let f = try FreshFixture()
        var endpoint: FreshEndpoint!
        endpoint = try f.endpoint(timeout: 5) { _, _ in
            let value = endpoint!
            // A disconnect must run independently of both the proof worker and
            // Swift Testing's cooperative/global executor under parallel load.
            Thread.detachNewThread {
                #expect(throws: (any Error).self) { try f.worker.requireCurrent() }
                value.revoke()
            }
        }
        let value = endpoint!
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            Thread.detachNewThread {
                defer { continuation.resume() }
                let start = ProcessInfo.processInfo.systemUptime
                #expect(throws: (any Error).self) { try f.prove(value) }
                #expect(ProcessInfo.processInfo.systemUptime - start < 2)
                #expect(!value.channel.isOpen)
            }
        }
    }
    @Test func greetingEnvelopeIsNotNativeEvidence() throws {
        let f = try FreshFixture(), message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", "storage-lifecycle-fresh-shim")
        xpc_dictionary_set_string(message, "role", "storage-shim")
        let bytes = try Lifecycle.encode(f.greeting)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        #expect(try StorageBootstrapLifecycleFreshXPC.decodeGreeting(message) == f.greeting)
        xpc_dictionary_set_string(message, "role", "daemon")
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleFreshXPC.decodeGreeting(message) }
    }
}
