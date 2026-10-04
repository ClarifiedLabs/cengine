import CEngineCore
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageBootstrapHelper

private typealias ServiceWire = StorageLifecycleServiceProofProtocol
private typealias ServiceEndpoint = StorageBootstrapLifecycleServiceEndpoint
private func serviceID() -> String { UUID().uuidString.lowercased() }
private func serviceProcess(_ pid: Int32, uniqueID: UInt64? = nil, pidVersion: UInt32 = 1,
                            tokenByte: UInt8? = nil, boot: String = "unsigned-seam") -> BootstrapProcess {
    .init(pid: pid, startSeconds: 1, startMicroseconds: 2, boot: boot,
          signingIdentity: "not-native-evidence", uniqueID: uniqueID ?? UInt64(pid), pidVersion: pidVersion,
          auditToken: Data(repeating: tokenByte ?? UInt8(truncatingIfNeeded: pid), count: 32))
}
private final class ServiceClock: @unchecked Sendable {
    private let lock = NSLock()
    private var wall: UInt64 = 1_000_000
    private var monotonic: TimeInterval = 100
    func now() -> UInt64 { lock.withLock { wall } }
    func uptime() -> TimeInterval { lock.withLock { monotonic } }
    func expire(wallClock: Bool) {
        lock.withLock { if wallClock { wall += ServiceWire.lifetimeMS } else { monotonic += 31 } }
    }
}
private final class ServiceFixture: @unchecked Sendable {
    let daemon = serviceProcess(10), shim = serviceProcess(11)
    let worker: StorageBootstrapLifecycleChildWorker
    let clock = ServiceClock()
    let root: StorageIdentity.RootPublicKey
    let binding: StorageIdentity.StoreBinding
    let greeting: ServiceWire.Greeting
    init(worker: StorageBootstrapLifecycleChildWorker = .init()) throws {
        self.worker = worker
        root = try .init(publicData: Data(repeating: 7, count: 32))
        let volume = try StorageIdentity.FilesystemUUID("11111111-1111-4111-8111-111111111111")
        binding = try .init(storeID: .init(serviceID()), root: .init(volumeUUID: volume, inode: 2),
            backing: .init(identity: .init(volumeUUID: volume, inode: 3), size: 4096), expectedExt4UUID: volume)
        greeting = try .init(channelID: serviceID(), daemonUniqueID: daemon.uniqueID, rootPublicKey: root.publicData,
            binding: .init(binding), bootBinding: .init(shimLaunchUUID: serviceID(), guestBootNonce: serviceID(),
                ext4UUID: volume.rawValue, bytes: 4096), initramfsSHA256: String(repeating: "a", count: 64),
            boot: .init(identity: .init(binding: binding, generation: 1), serviceEpoch: serviceID(),
                tlsRootSHA256: String(repeating: "b", count: 64), serverSPKI: String(repeating: "c", count: 64),
                bootstrapKey: root.fingerprint.rawValue))
    }
    func grant(_ operation: Lifecycle.Operation = .initialize, epoch: UInt64 = 0, serial: UInt64 = 1,
               identity: Lifecycle.Identity? = nil) throws -> Lifecycle.Grant {
        try .init(operation: operation, id: serviceID(), identity: identity ?? greeting.boot.identity,
            serial: serial, expectedEpoch: epoch, newKey: String(repeating: serial % 2 == 0 ? "d" : "e", count: 64))
    }
    func reply(_ challenge: ServiceWire.Challenge, boot: StorageLifecycleBootTrust? = nil) throws -> ServiceEndpoint.Received {
        try .init(shim: shim, bytes: Lifecycle.encode(ServiceWire.Reply(challengeSHA256: challenge.digest,
            boot: boot ?? greeting.boot)))
    }
    func endpoint(counter: StorageBootstrapLifecycleChildCounter = .init(), timeout: TimeInterval = 1,
                  root override: StorageIdentity.RootPublicKey? = nil, shim peer: BootstrapProcess? = nil,
                  sender: ServiceEndpoint.Sender? = nil, onRevoke: @escaping () -> Void = {}) throws -> ServiceEndpoint {
        try .init(greeting: greeting, daemon: daemon, shim: peer ?? shim, channel: StorageBootstrapChildChannel(),
            expectedRoot: override ?? root, counter: counter, worker: worker, timeout: timeout,
            now: clock.now, uptime: clock.uptime, onRevoke: onRevoke,
            sender: sender ?? { [self] challenge, complete in complete(.success(try reply(challenge))) })
    }
    @discardableResult
    func prove(_ endpoint: ServiceEndpoint, grant override: Lifecycle.Grant? = nil,
               daemon owner: BootstrapProcess? = nil, repin: () throws -> Void = {}) throws -> StorageLifecycleBootTrust {
        try worker.perform { try endpoint.prove(grant: override ?? grant(), daemon: owner ?? daemon, repin: repin) }
    }
}
private final class ServiceConcurrentResults: @unchecked Sendable {
    private let lock = NSLock()
    private var challenges: [ServiceWire.Challenge] = []
    private var boots: [StorageLifecycleBootTrust] = []
    private var failures: [String] = []
    private var pins = 0
    func sent(_ value: ServiceWire.Challenge) { lock.withLock { challenges.append(value) } }
    func succeeded(_ value: StorageLifecycleBootTrust) { lock.withLock { boots.append(value) } }
    func failed(_ error: any Error) { lock.withLock { failures.append(String(describing: error)) } }
    func pin() { lock.withLock { pins += 1 } }
    func snapshot() -> ([ServiceWire.Challenge], [StorageLifecycleBootTrust], [String], Int) {
        lock.withLock { (challenges, boots, failures, pins) }
    }
}

/// Unsigned direct-exchange seams only: real endpoint/parser/worker code, not native
/// signature acceptance, guest TLS, installed ROOT, VM boot or production activation.
@Suite struct StorageBootstrapLifecycleServiceTests {
    @Test func originMetadataRejectsCrossBindingChangedLaunchAndWrongRoot() throws {
        let f = try ServiceFixture(), other = try ServiceFixture()
        func origin(binding: StorageLifecycleStoreBinding? = nil, root: Data? = nil, launch: String? = nil) throws -> Adoption.Origin {
            try .init(binding: binding ?? f.greeting.binding, rootPublicKey: root ?? f.root.publicData,
                shimLaunchUUID: launch ?? f.greeting.bootBinding.shimLaunchUUID, specSHA256: String(repeating: "a", count: 64))
        }
        try StorageBootstrapLifecycleServiceXPC.validateOriginMetadata(origin(), greeting: f.greeting, expectedBoot: f.greeting.boot)
        for invalid in try [origin(binding: other.greeting.binding), origin(root: Data(repeating: 8, count: 32)), origin(launch: serviceID())] {
            #expect(throws: (any Error).self) {
                try StorageBootstrapLifecycleServiceXPC.validateOriginMetadata(invalid, greeting: f.greeting, expectedBoot: f.greeting.boot)
            }
        }
        // DTO consistency above is deliberately insufficient for native admission.
        let native = StorageBootstrapLifecycleServiceXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ", expectedRootPublicKey: f.root, worker: f.worker)
        let principal = BootstrapPrincipal(daemon: f.daemon, child: serviceProcess(12), incarnation: serviceID(),
            controllerSPKI: try StorageIdentity.Ed25519SPKI(rawPublicKey: Data(repeating: 9, count: 32)).publicData)
        #expect(throws: (any Error).self) {
            try f.worker.perform { try native.nativeOrigin(origin(), sender: .init(token: audit_token_t()),
                grant: f.grant(), principal: principal, expectedBoot: f.greeting.boot) }
        }
    }

    @Test func sameIdentityAllowsEveryOperationAndControllerEpochWithFreshReplies() throws {
        let f = try ServiceFixture()
        var challenges: [ServiceWire.Challenge] = [], pins = 0
        let endpoint = try f.endpoint { challenge, complete in
            challenges.append(challenge)
            // Round-trip the actual outbound wire before constructing the correlated reply.
            let decoded = try ServiceWire.decodeChallenge(Lifecycle.encode(challenge))
            complete(.success(try f.reply(decoded)))
        }
        let grants = try [f.grant(), f.grant(.takeover, epoch: 1, serial: 2),
            f.grant(.takeover, epoch: 129, serial: 3), f.grant(.takeover, epoch: .max - 1, serial: 4),
            f.grant(.retire, epoch: 1, serial: 5), f.grant(.retire, epoch: .max, serial: 6)]
        for grant in grants {
            #expect(try f.prove(endpoint, grant: grant, repin: { pins += 1 }) == f.greeting.boot)
        }
        // Fresh proof remains possible beyond v1's historical nonce-count limit.
        for _ in 0..<130 { #expect(try f.prove(endpoint, grant: grants[1]) == f.greeting.boot) }
        #expect(challenges.prefix(grants.count).map(\.grant) == grants)
        #expect(challenges.map(\.counter) == Array(UInt64(1)...UInt64(challenges.count)))
        #expect(Set(challenges.map(\.nonce)).count == challenges.count)
        #expect(challenges.allSatisfy {
            $0.greeting == f.greeting && $0.shimAudit == f.shim.auditToken &&
                $0.shimUniqueID == f.shim.uniqueID && $0.daemonAudit == f.daemon.auditToken &&
                $0.expiresUnixMS == f.clock.now() + ServiceWire.lifetimeMS
        })
        #expect(pins == grants.count * 2 && endpoint.channel.isOpen)
    }

    @Test func crossGenerationStoreBindingAndDaemonRefuseBeforeExchange() throws {
        let f = try ServiceFixture(), identity = f.greeting.boot.identity
        let otherBacking = try StorageIdentity.StoreBinding(storeID: f.binding.storeID, root: f.binding.root,
            backing: .init(identity: .init(volumeUUID: f.binding.backing.identity.volumeUUID, inode: 4), size: 4096),
            expectedExt4UUID: f.binding.expectedExt4UUID)
        let identities = try [Lifecycle.Identity(binding: f.binding, generation: 2),
            Lifecycle.Identity(binding: otherBacking, generation: 1),
            Lifecycle.Identity(store: serviceID(), generation: 1, binding: identity.binding)]
        for changed in identities {
            var sent = 0, pins = 0
            let endpoint = try f.endpoint { _, _ in sent += 1 }
            #expect(throws: (any Error).self) {
                try f.prove(endpoint, grant: f.grant(identity: changed), repin: { pins += 1 })
            }
            #expect(sent == 0 && pins == 0 && !endpoint.channel.isOpen)
        }
        var sent = 0
        let endpoint = try f.endpoint { _, _ in sent += 1 }
        #expect(throws: (any Error).self) { try f.prove(endpoint, daemon: serviceProcess(10, pidVersion: 2)) }
        #expect(sent == 0 && !endpoint.channel.isOpen)
    }

    @Test func constructorRejectsWrongRootNativeTupleAndInvalidTimeout() throws {
        let f = try ServiceFixture()
        #expect(throws: (any Error).self) { try f.endpoint(root: .init(publicData: Data(repeating: 8, count: 32))) }
        for shim in [f.daemon, serviceProcess(11, boot: "other-boot"), serviceProcess(11, uniqueID: 0)] {
            #expect(throws: (any Error).self) { try f.endpoint(shim: shim) }
        }
        for timeout in [0, -1, .infinity, .nan, 30.001] {
            #expect(throws: (any Error).self) { try f.endpoint(timeout: timeout) }
        }
    }

    @Test func matchingDigestCannotSubstituteAnyBootTrustField() throws {
        let f = try ServiceFixture(), boot = f.greeting.boot
        for kind in 0..<7 {
            let identity = try Lifecycle.Identity(store: kind == 0 ? serviceID() : boot.identity.store,
                generation: kind == 1 ? 2 : 1, binding: kind == 2 ? String(repeating: "f", count: 64) : boot.identity.binding)
            let changed = try StorageLifecycleBootTrust(identity: identity,
                serviceEpoch: kind == 3 ? serviceID() : boot.serviceEpoch,
                tlsRootSHA256: kind == 4 ? String(repeating: "f", count: 64) : boot.tlsRootSHA256,
                serverSPKI: kind == 5 ? String(repeating: "f", count: 64) : boot.serverSPKI,
                bootstrapKey: kind == 6 ? String(repeating: "f", count: 64) : boot.bootstrapKey)
            let endpoint = try f.endpoint { challenge, complete in complete(.success(try f.reply(challenge, boot: changed))) }
            #expect(throws: (any Error).self) { try f.prove(endpoint) }
            #expect(!endpoint.channel.isOpen)
        }
    }

    @Test func replyRequiresExactIndependentlyPinnedProcessTuple() throws {
        let f = try ServiceFixture()
        for wrong in [f.daemon, serviceProcess(12), serviceProcess(11, uniqueID: 12),
                      serviceProcess(11, pidVersion: 2), serviceProcess(11, tokenByte: 99),
                      serviceProcess(11, boot: "other-boot")] {
            let endpoint = try f.endpoint { challenge, complete in
                complete(.success(.init(shim: wrong, bytes: try f.reply(challenge).bytes)))
            }
            #expect(throws: (any Error).self) { try f.prove(endpoint) }
            #expect(!endpoint.channel.isOpen)
        }
    }

    @Test func malformedFailedAndDuplicateCallbacksRevokeExactlyOnce() throws {
        for kind in 0..<4 {
            let f = try ServiceFixture()
            var revocations = 0
            let endpoint = try f.endpoint(sender: { challenge, complete in
                let actual = try f.reply(challenge)
                switch kind {
                case 0: complete(.success(.init(shim: f.shim, bytes: actual.bytes + Data([10]))))
                case 1: complete(.failure(BootstrapFailure(.unavailable)))
                case 2: throw BootstrapFailure(.unavailable)
                default: complete(.success(actual)); complete(.success(actual))
                }
            }, onRevoke: { revocations += 1 })
            #expect(throws: (any Error).self) { try f.prove(endpoint) }
            endpoint.revoke()
            #expect(!endpoint.channel.isOpen && revocations == 1)
        }
    }

    @Test func historicalReplyCannotAnswerANewChallenge() throws {
        let f = try ServiceFixture(), grant = try f.grant()
        var previous: ServiceEndpoint.Received?
        let endpoint = try f.endpoint { challenge, complete in
            let response = try previous ?? f.reply(challenge)
            previous = response; complete(.success(response))
        }
        #expect(try f.prove(endpoint, grant: grant) == f.greeting.boot)
        #expect(throws: (any Error).self) { try f.prove(endpoint, grant: grant) }
        #expect(!endpoint.channel.isOpen)
    }

    @Test func delayedPriorCompletionRevokesRatherThanSatisfyingNextProof() throws {
        let f = try ServiceFixture()
        var prior: ServiceEndpoint.Completion?, response: ServiceEndpoint.Received?
        let endpoint = try f.endpoint { challenge, complete in
            let current = try f.reply(challenge)
            if let prior, let response { prior(.success(response)) }
            else { prior = complete; response = current }
            complete(.success(current))
        }
        try f.prove(endpoint)
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
        #expect(!endpoint.channel.isOpen)
    }

    @Test func timeoutAndLateCallbackNeverReviveEndpoint() throws {
        let f = try ServiceFixture()
        var late: ServiceEndpoint.Completion?, response: ServiceEndpoint.Received?, sends = 0
        let endpoint = try f.endpoint(timeout: 0.01) { challenge, complete in
            sends += 1; late = complete; response = try f.reply(challenge)
        }
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
        #expect(!endpoint.channel.isOpen)
        let callback = try #require(late)
        callback(.success(try #require(response)))
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
        #expect(!endpoint.channel.isOpen && sends == 1)
    }

    @Test func wallAndMonotonicExpiryAtReplyAndAfterRepinRevoke() throws {
        for wallClock in [false, true] {
            for atReply in [false, true] {
                let f = try ServiceFixture()
                let endpoint = try f.endpoint { challenge, complete in
                    let reply = try f.reply(challenge)
                    if atReply { f.clock.expire(wallClock: wallClock) }
                    complete(.success(reply))
                }
                var pins = 0
                #expect(throws: (any Error).self) {
                    try f.prove(endpoint, repin: {
                        pins += 1
                        if !atReply && pins == 2 { f.clock.expire(wallClock: wallClock) }
                    })
                }
                #expect(pins == (atReply ? 1 : 2) && !endpoint.channel.isOpen)
            }
        }
    }

    @Test func repinLossBeforeAndAfterReplyRevokes() throws {
        for failedPin in [1, 2] {
            let f = try ServiceFixture()
            var sends = 0, pins = 0
            let endpoint = try f.endpoint { challenge, complete in
                sends += 1; complete(.success(try f.reply(challenge)))
            }
            #expect(throws: (any Error).self) {
                try f.prove(endpoint, repin: {
                    pins += 1
                    if pins == failedPin { throw BootstrapFailure(.unauthorized) }
                })
            }
            #expect(pins == failedPin && sends == failedPin - 1 && !endpoint.channel.isOpen)
        }
    }

    @Test func disconnectWakesPendingProofOutsideWorker() throws {
        let f = try ServiceFixture()
        var endpoint: ServiceEndpoint!
        endpoint = try f.endpoint(timeout: 5) { _, _ in
            let value = endpoint!
            // A blocked proof must not share its executor pool with revocation.
            Thread.detachNewThread {
                #expect(throws: (any Error).self) { try f.worker.requireCurrent() }
                value.revoke()
            }
        }
        do {
            try f.prove(endpoint)
            Issue.record("disconnected proof unexpectedly succeeded")
        } catch let error as BootstrapFailure {
            // A signaled revoked proof is unauthorized; a semaphore timeout is
            // unavailable. This checks wakeup, not unrelated wall-clock scheduling.
            #expect(error.code == .unauthorized)
        }
        #expect(!endpoint.channel.isOpen)
    }

    @Test func nestedProofAndCounterOverflowRefuse() throws {
        let f = try ServiceFixture()
        var endpoint: ServiceEndpoint!
        endpoint = try f.endpoint { _, _ in
            #expect(throws: (any Error).self) { try f.prove(endpoint) }
        }
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
        #expect(!endpoint.channel.isOpen)
        let last = try f.endpoint(counter: .init(initialValue: .max - 1))
        try f.prove(last)
        #expect(throws: (any Error).self) { try f.prove(last) }
        #expect(!last.channel.isOpen)
    }

    @Test func simultaneousCallersUseSameExternallySharedSerialWorkerWithoutDeadlock() throws {
        let worker = StorageBootstrapLifecycleChildWorker(), f = try ServiceFixture(worker: worker)
        let results = ServiceConcurrentResults(), firstSent = DispatchSemaphore(value: 0)
        let secondAttempted = DispatchSemaphore(value: 0), group = DispatchGroup()
        let grants = try [f.grant(), f.grant(.takeover, epoch: 1, serial: 2)]
        let endpoint = try f.endpoint(timeout: 5) { challenge, complete in
            try worker.requireCurrent()
            results.sent(challenge)
            let response = try f.reply(challenge)
            if challenge.counter == 1 { firstSent.signal() }
            // Dedicated fixture threads keep blocking callers and replies out of
            // the global pool used by other synchronous parallel tests.
            Thread.detachNewThread {
                #expect(throws: (any Error).self) { try worker.requireCurrent() }
                if challenge.counter == 1 { #expect(secondAttempted.wait(timeout: .now() + 2) == .success) }
                complete(.success(response))
            }
        }
        for index in grants.indices {
            if index == 1 { try #require(firstSent.wait(timeout: .now() + 2) == .success) }
            group.enter()
            Thread.detachNewThread {
                defer { group.leave() }
                if index == 1 { secondAttempted.signal() }
                do {
                    // The authority/transport caller owns and enters this SAME worker.
                    let boot = try worker.perform {
                        try endpoint.prove(grant: grants[index], daemon: f.daemon, repin: results.pin)
                    }
                    results.succeeded(boot)
                } catch { results.failed(error) }
            }
        }
        try #require(group.wait(timeout: .now() + 8) == .success)
        let (challenges, boots, failures, pins) = results.snapshot()
        #expect(failures.isEmpty && boots == [f.greeting.boot, f.greeting.boot])
        #expect(challenges.map(\.grant) == grants && challenges.map(\.counter) == [1, 2])
        #expect(Set(challenges.map(\.nonce)).count == 2 && pins == 4 && endpoint.channel.isOpen)
    }

    @Test func offWorkerAndDifferentWorkerRefuseWithoutSendingOrRevoking() throws {
        let f = try ServiceFixture(), grant = try f.grant(), wrongWorker = StorageBootstrapLifecycleChildWorker()
        var sends = 0, pins = 0
        let endpoint = try f.endpoint { challenge, complete in
            sends += 1; complete(.success(try f.reply(challenge)))
        }
        #expect(throws: (any Error).self) {
            try endpoint.prove(grant: grant, daemon: f.daemon, repin: { pins += 1 })
        }
        #expect(throws: (any Error).self) {
            try wrongWorker.perform { try endpoint.prove(grant: grant, daemon: f.daemon, repin: { pins += 1 }) }
        }
        #expect(sends == 0 && pins == 0 && endpoint.channel.isOpen)
        #expect(try f.prove(endpoint, grant: grant) == f.greeting.boot)
        #expect(sends == 1)
    }

    @Test func xpcGreetingEnvelopeIsShapeOnlyAndRejectsWrongRoleOperationAndPayload() throws {
        let f = try ServiceFixture(), data = try Lifecycle.encode(f.greeting)
        func message(_ bytes: Data, operation: String = "storage-lifecycle-service-shim", role: String = "storage-shim") -> xpc_object_t {
            let value = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(value, "operation", operation)
            xpc_dictionary_set_string(value, "role", role)
            bytes.withUnsafeBytes { xpc_dictionary_set_data(value, "request", $0.baseAddress, $0.count) }
            return value
        }
        #expect(try StorageBootstrapLifecycleServiceXPC.decodeGreeting(message(data)) == f.greeting)
        for bad in [message(data, operation: "storage-lifecycle-fresh-shim"), message(data, role: "daemon"),
                    message(Data()), message(Data(count: Lifecycle.maximumPayloadBytes + 1)),
                    message(data + Data([10])), xpc_string_create("not-a-dictionary")] {
            #expect(throws: (any Error).self) { try StorageBootstrapLifecycleServiceXPC.decodeGreeting(bad) }
        }
        // Never pass local dictionaries to greet: they have no immutable Mach trailer.
    }

    @Test func xpcRequiresSharedWorkerAndCannotBootWithoutEnrolledNativePeer() throws {
        let f = try ServiceFixture(), grant = try f.grant()
        let transport = StorageBootstrapLifecycleServiceXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ",
            expectedRootPublicKey: f.root, worker: f.worker)
        #expect(throws: (any Error).self) { try transport.remember(f.daemon) }
        #expect(throws: (any Error).self) { try transport.boot(grant: grant, daemon: f.daemon) }
        #expect(throws: (any Error).self) {
            try f.worker.perform { try transport.boot(grant: grant, daemon: f.daemon) }
        }
    }

    @Test func xpcRememberRejectsUnsignedTestProcessWithRealSelfAuditToken() throws {
        // Kernel-provided self token, never a fabricated Mach message/audit trailer.
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        try #require(result == KERN_SUCCESS)
        let audit = BootstrapAuditIdentity(token: token), kernel = try #require(BootstrapKernelIdentity.read(getpid()))
        try #require(audit.pid == getpid() && audit.matches(kernel, owner: geteuid()))
        let process = BootstrapProcess(pid: getpid(), startSeconds: 0, startMicroseconds: 0,
            boot: "not-authenticated", signingIdentity: "unsigned-test", uniqueID: kernel.uniqueID,
            pidVersion: kernel.pidVersion, auditToken: audit.data)
        let f = try ServiceFixture()
        let transport = StorageBootstrapLifecycleServiceXPC(ownerUID: geteuid(), team: "ABCDEFGHIJ",
            expectedRootPublicKey: f.root, worker: f.worker)
        // Native pinning independently refuses this executable, before tuple comparison.
        #expect(throws: (any Error).self) {
            try StorageBootstrapProcesses(ownerUID: geteuid(), team: "ABCDEFGHIJ", policy: .production).daemon(audit: audit)
        }
        #expect(throws: (any Error).self) { try f.worker.perform { try transport.remember(process) } }
    }
    private func successor(_ f: ServiceFixture, boot: StorageLifecycleBootTrust? = nil,
                           channelID: String? = nil, daemon: UInt64? = nil) throws -> ServiceWire.Greeting {
        let g = f.greeting
        return try .init(channelID: channelID ?? g.channelID, daemonUniqueID: daemon ?? g.daemonUniqueID,
            rootPublicKey: g.rootPublicKey, binding: g.binding, bootBinding: g.bootBinding,
            initramfsSHA256: g.initramfsSHA256, boot: boot ?? .init(identity: g.boot.identity, serviceEpoch: serviceID(),
                tlsRootSHA256: String(repeating: "1", count: 64), serverSPKI: String(repeating: "2", count: 64),
                bootstrapKey: g.boot.bootstrapKey))
    }

    @Test func sameChannelSuccessorUpdateRequiresAuthorityAndRevokesOldBoot() throws {
        let f = try ServiceFixture(), next = try successor(f)
        var replyBoot: StorageLifecycleBootTrust? = nil, counters: [UInt64] = []
        let endpoint = try f.endpoint { challenge, complete in
            counters.append(challenge.counter)
            complete(.success(try f.reply(challenge, boot: replyBoot ?? challenge.greeting.boot)))
        }
        #expect(try f.prove(endpoint) == f.greeting.boot)
        var seen: [(StorageLifecycleBootTrust, StorageLifecycleBootTrust)] = []
        try f.worker.perform {
            try StorageBootstrapLifecycleServiceXPC.update(endpoint, to: next) { seen.append(($0, $1)) }
        }
        #expect(seen.count == 1 && seen.first?.0 == f.greeting.boot && seen.first?.1 == next.boot)
        #expect(endpoint.greeting == next && endpoint.channel.isOpen)
        #expect(try f.prove(endpoint) == next.boot)
        // Exact duplicate is idempotent and needs no new authorization.
        try f.worker.perform {
            try StorageBootstrapLifecycleServiceXPC.update(endpoint, to: next) { _, _ in throw BootstrapFailure(.blocked) }
        }
        #expect(try f.prove(endpoint) == next.boot && counters == [1, 2, 3])
        // The old boot trust is no longer proven on this channel.
        replyBoot = f.greeting.boot
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
        #expect(!endpoint.channel.isOpen)
    }

    @Test func successorUpdateFailsClosedWithoutAuthorityOrOnMismatch() throws {
        let f = try ServiceFixture(), g = f.greeting
        let otherIdentity = try Lifecycle.Identity(binding: f.binding, generation: 2)
        func boot(identity: Lifecycle.Identity? = nil, epoch: String? = nil, ca: String = "1", spki: String = "2",
                  key: String? = nil) throws -> StorageLifecycleBootTrust {
            try .init(identity: identity ?? g.boot.identity, serviceEpoch: epoch ?? serviceID(),
                tlsRootSHA256: String(repeating: ca, count: 64), serverSPKI: String(repeating: spki, count: 64),
                bootstrapKey: key ?? g.boot.bootstrapKey)
        }
        let unrelatedKey = String(repeating: "9", count: 64)
        var cases: [(ServiceWire.Greeting?, Bool)] = [
            (try successor(f), false), // No ROOT authority wired.
            (try successor(f), true), // Authority refuses (no exact pending change).
            (try successor(f, boot: boot(epoch: g.boot.serviceEpoch)), true),
            (try successor(f, boot: boot(ca: "b")), true),
            (try successor(f, boot: boot(spki: "c")), true),
            (try successor(f, channelID: serviceID()), true),
            (try successor(f, daemon: 99), true)]
        cases.append((try? successor(f, boot: boot(identity: otherIdentity)), true))
        cases.append((try? successor(f, boot: boot(key: unrelatedKey)), true))
        for (index, (next, wired)) in cases.enumerated() {
            guard let next else { continue } // Greeting itself refuses a foreign identity/bootstrap key.
            let endpoint = try f.endpoint()
            var asked = 0
            let authorize: ((StorageLifecycleBootTrust, StorageLifecycleBootTrust) throws -> Void)? = wired ? { _, _ in
                asked += 1; if index == 1 { throw BootstrapFailure(.blocked) }
            } : nil
            #expect(throws: (any Error).self) {
                try f.worker.perform { try StorageBootstrapLifecycleServiceXPC.update(endpoint, to: next, authorize: authorize) }
            }
            #expect(!endpoint.channel.isOpen && endpoint.greeting == g && asked == (index == 1 ? 1 : 0))
        }
        // Off-worker update refuses.
        let endpoint = try f.endpoint()
        #expect(throws: (any Error).self) { try endpoint.update(to: try successor(f)) { _, _ in } }
        #expect(endpoint.greeting == g)
    }
}
