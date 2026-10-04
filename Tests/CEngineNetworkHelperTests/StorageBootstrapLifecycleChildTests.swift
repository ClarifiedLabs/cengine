import CEngineCore
import CryptoKit
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageBootstrapHelper

private typealias ChildWire = StorageLifecycleChildProtocol
private typealias ChildEndpoint = StorageBootstrapLifecycleChildEndpoint
private typealias ChildLifecycle = StorageLifecycleProtocol
private func childUUID() -> String { UUID().uuidString.lowercased() }
private func childProcess(_ pid: Int32) -> BootstrapProcess {
    .init(pid: pid, startSeconds: 1, startMicroseconds: 2, boot: "unsigned-seam",
          signingIdentity: "not-native-evidence", uniqueID: UInt64(pid), pidVersion: 1,
          auditToken: Data(repeating: UInt8(truncatingIfNeeded: pid), count: 32))
}
private final class ChildClock: @unchecked Sendable {
    private let lock = NSLock()
    private var wall: UInt64 = 1_000_000
    private var monotonic: TimeInterval = 100
    func now() -> UInt64 { lock.withLock { wall } }
    func uptime() -> TimeInterval { lock.withLock { monotonic } }
    func expireWall() { lock.withLock { wall += ChildWire.lifetimeMS } }
    func expireMonotonic() { lock.withLock { monotonic += 31 } }
}
private final class ChildFixture: @unchecked Sendable {
    let key = Curve25519.Signing.PrivateKey()
    let rootKey = Curve25519.Signing.PrivateKey()
    let daemon = childProcess(10)
    let child: BootstrapProcess
    let worker = StorageBootstrapLifecycleChildWorker()
    let clock = ChildClock()
    let greeting: ChildWire.Greeting
    let grant: ChildLifecycle.Grant
    var root: StorageIdentity.RootPublicKey { get throws { try .init(publicData: rootKey.publicKey.rawRepresentation) } }
    init(pid: Int32 = 11) throws {
        child = childProcess(pid)
        let spki = try StorageIdentity.Ed25519SPKI(rawPublicKey: key.publicKey.rawRepresentation)
        let identity = try ChildLifecycle.Identity(store: childUUID(), generation: 1, binding: String(repeating: "a", count: 64))
        grant = try .init(operation: .initialize, id: childUUID(), identity: identity, serial: 1, expectedEpoch: 0, newKey: spki.fingerprint.rawValue)
        greeting = try .init(channelID: childUUID(), incarnationID: childUUID(), daemonUniqueID: daemon.uniqueID,
            controllerSPKI: spki.publicData, rootPublicKey: rootKey.publicKey.rawRepresentation,
            store: identity.store, binding: identity.binding, expectedEpoch: 0)
    }
    var boot: StorageLifecycleBootTrust {
        get throws {
            try .init(identity: grant.identity, serviceEpoch: greeting.incarnationID,
                      tlsRootSHA256: String(repeating: "b", count: 64), serverSPKI: String(repeating: "c", count: 64),
                      bootstrapKey: root.fingerprint.rawValue)
        }
    }
    func signed(_ challenge: ChildWire.Challenge, receipt override: ChildLifecycle.Receipt? = nil) throws -> Data {
        let receipt: ChildLifecycle.Receipt?
        if let override { receipt = override }
        else if challenge.purpose == .result {
            receipt = try .init(grant: challenge.grant, nonce: challenge.nonce, serviceEpoch: try #require(challenge.boot).serviceEpoch, revision: 1)
        } else { receipt = nil }
        let unsigned = try ChildWire.Reply(challengeSHA256: challenge.digest, receipt: receipt, signature: Data(repeating: 0, count: 64))
        return try ChildLifecycle.encode(ChildWire.Reply(challengeSHA256: unsigned.challengeSHA256,
            receipt: receipt, signature: key.signature(for: unsigned.signingBytes)))
    }
    func endpoint(counter: StorageBootstrapLifecycleChildCounter = .init(), timeout: TimeInterval = 1,
                  root override: StorageIdentity.RootPublicKey? = nil,
                  sender: ChildEndpoint.Sender? = nil) throws -> ChildEndpoint {
        try identityEndpoint(counter: counter, timeout: timeout, root: override, sender: sender)
    }
    func identityEndpoint(counter: StorageBootstrapLifecycleChildCounter = .init(), timeout: TimeInterval = 1,
                  root override: StorageIdentity.RootPublicKey? = nil,
                  identitySender: ChildEndpoint.IdentitySender? = nil,
                  sender: ChildEndpoint.Sender? = nil) throws -> ChildEndpoint {
        try ChildEndpoint(greeting: greeting, daemon: daemon, child: child, connectionID: UUID(),
            channel: StorageBootstrapChildChannel(), expectedRoot: override ?? root, counter: counter,
            worker: worker, timeout: timeout, now: clock.now, uptime: clock.uptime,
            identitySender: identitySender ?? { [self] challenge, complete in
                let unsigned = try ChildWire.IdentityReply(challengeSHA256: challenge.digest, signature: Data(repeating: 0, count: 64))
                let signed = try ChildWire.IdentityReply(challengeSHA256: challenge.digest, signature: key.signature(for: unsigned.signingBytes))
                complete(.success(.init(child: child, bytes: try ChildLifecycle.encode(signed))))
            },
            sender: sender ?? { [self] challenge, complete in
                complete(.success(.init(child: child, bytes: try signed(challenge))))
            })
    }
    @discardableResult
    func prove(_ endpoint: ChildEndpoint, grant: ChildLifecycle.Grant? = nil,
               purpose: ChildWire.Purpose = .candidate, nonce: Data? = nil,
               repin: () throws -> Void = {}) throws -> ChildWire.Reply {
        try worker.perform {
            try endpoint.prove(principal: endpoint.principal, grant: grant ?? self.grant,
                purpose: purpose, nonce: nonce, boot: purpose == .result ? boot : nil, repin: repin)
        }
    }
}

/// Cryptographic/unsigned state seams ONLY. No test fabricates an audit trailer or
/// claims native Developer ID, parent identity, installed service or TLS acceptance.
@Suite struct StorageBootstrapLifecycleChildTests {
    @Test func identityExchangeUsesRemainingOverallBudget() throws {
        let f = try ChildFixture()
        let endpoint = try f.identityEndpoint(timeout: 1, identitySender: { _, _ in })
        let started = DispatchTime.now()
        #expect(throws: (any Error).self) {
            try f.worker.perform {
                try endpoint.proveIdentity(principal: endpoint.principal, requestSHA256: Data(repeating: 1, count: 32),
                    deadline: started + 0.03, repin: {})
            }
        }
        #expect(DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds < 500_000_000)
        #expect(!endpoint.channel.isOpen)
    }

    @Test func repeatedFreshProofsDoNotHaveTheV1SixtyFourNonceLimit() throws {
        let f = try ChildFixture()
        var challenges: [ChildWire.Challenge] = []
        let endpoint = try f.endpoint { challenge, completion in
            challenges.append(challenge)
            completion(.success(.init(child: f.child, bytes: try f.signed(challenge))))
        }
        var pins = 0
        for _ in 0..<130 { try f.prove(endpoint, repin: { pins += 1 }) }
        #expect(pins == 260)
        #expect(challenges.map(\.counter) == Array(UInt64(1)...130))
        #expect(Set(challenges.map(\.nonce)).count == 130)
        #expect(challenges.allSatisfy { $0.purpose == .candidate })
        let nonce = Data(repeating: 7, count: 32)
        let reply = try f.prove(endpoint, purpose: .result, nonce: nonce)
        #expect(reply.receipt?.nonce == nonce && reply.receipt?.grant == f.grant)
        #expect(challenges.last?.purpose == .result)
        #expect(endpoint.channel.isOpen)
    }
    @Test func historicalReplyIsNotEvidenceForNextProof() throws {
        let f = try ChildFixture()
        var previous: Data?
        let endpoint = try f.endpoint { challenge, complete in
            let bytes = try previous ?? f.signed(challenge)
            previous = bytes
            complete(.success(.init(child: f.child, bytes: bytes)))
        }
        try f.prove(endpoint)
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
        #expect(!endpoint.channel.isOpen)
    }
    @Test func wrongAuditedPrincipalAndMalformedRepliesRevoke() throws {
        for kind in 0..<5 {
            let f = try ChildFixture()
            let endpoint = try f.endpoint { challenge, complete in
                let bytes = try f.signed(challenge)
                switch kind {
                case 0: complete(.success(.init(child: f.daemon, bytes: bytes)))
                case 1: complete(.success(.init(child: f.child, bytes: bytes + Data([10]))))
                case 2: complete(.success(.init(child: f.child, bytes: Data(repeating: 0, count: 64))))
                case 3:
                    let wrong = try ChildWire.Reply(challengeSHA256: challenge.digest, receipt: nil, signature: Data(repeating: 0, count: 64))
                    complete(.success(.init(child: f.child, bytes: try ChildLifecycle.encode(wrong))))
                default: complete(.failure(BootstrapFailure(.unavailable)))
                }
            }
            #expect(throws: (any Error).self) { try f.prove(endpoint) }
            #expect(!endpoint.channel.isOpen)
        }
    }
    @Test func wrongPrincipalGrantAndRootAreRejected() throws {
        let f = try ChildFixture()
        let otherRoot = try StorageIdentity.RootPublicKey(publicData: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        #expect(throws: (any Error).self) { try f.endpoint(root: otherRoot) }
        let endpoint = try f.endpoint()
        let wrong = BootstrapPrincipal(daemon: childProcess(12), child: f.child,
            incarnation: f.greeting.incarnationID, controllerSPKI: f.greeting.controllerSPKI)
        #expect(throws: (any Error).self) {
            try f.worker.perform { try endpoint.prove(principal: wrong, grant: f.grant, purpose: .candidate, repin: {}) }
        }
        #expect(!endpoint.channel.isOpen)
        let other = try ChildFixture()
        let second = try f.endpoint()
        #expect(throws: (any Error).self) { try f.prove(second, grant: other.grant) }
        #expect(!second.channel.isOpen)
    }
    @Test func resultRequiresExactGrantRootNonceAndTypedResult() throws {
        for kind in 0..<4 {
            let f = try ChildFixture(), other = try ChildFixture()
            let endpoint = try f.endpoint { challenge, complete in
                let receipt = try ChildLifecycle.Receipt(grant: kind == 0 ? other.grant : challenge.grant,
                    nonce: kind == 1 ? Data(repeating: 9, count: 32) : challenge.nonce,
                    serviceEpoch: kind == 3 ? childUUID() : try #require(challenge.boot).serviceEpoch, revision: 1)
                let bytes: Data
                if kind == 2 {
                    let unsigned = try ChildWire.Reply(challengeSHA256: challenge.digest, receipt: nil, signature: Data(repeating: 0, count: 64))
                    bytes = try ChildLifecycle.encode(ChildWire.Reply(challengeSHA256: unsigned.challengeSHA256,
                        receipt: nil, signature: f.key.signature(for: unsigned.signingBytes)))
                } else { bytes = try f.signed(challenge, receipt: receipt) }
                complete(.success(.init(child: f.child, bytes: bytes)))
            }
            #expect(throws: (any Error).self) { try f.prove(endpoint, purpose: .result, nonce: Data(repeating: 1, count: 32)) }
            #expect(!endpoint.channel.isOpen)
        }
    }
    @Test func wallAndMonotonicExpiryAndPostPinLossRevoke() throws {
        for kind in 0..<4 {
            let f = try ChildFixture()
            let endpoint = try f.endpoint()
            var pins = 0
            #expect(throws: (any Error).self) {
                try f.prove(endpoint, repin: {
                    pins += 1
                    if pins == 2 {
                        switch kind {
                        case 0: f.clock.expireWall()
                        case 1: f.clock.expireMonotonic()
                        case 2: endpoint.revoke()
                        default: throw BootstrapFailure(.unauthorized)
                        }
                    }
                })
            }
            #expect(!endpoint.channel.isOpen)
        }
    }
    @Test func expiryAtCallbackAndDuplicateCallbacksRevoke() throws {
        for kind in 0..<3 {
            let f = try ChildFixture()
            let endpoint = try f.endpoint { challenge, complete in
                let received = ChildEndpoint.Received(child: f.child, bytes: try f.signed(challenge))
                if kind == 0 { f.clock.expireWall() }
                if kind == 1 { f.clock.expireMonotonic() }
                complete(.success(received))
                if kind == 2 { complete(.success(received)) }
            }
            #expect(throws: (any Error).self) { try f.prove(endpoint) }
            #expect(!endpoint.channel.isOpen)
        }
    }
    @Test func timeoutCancelsAndDelayedReplyCannotResurrectEndpoint() throws {
        let f = try ChildFixture()
        var delayed: ChildEndpoint.Completion?
        var bytes = Data()
        let endpoint = try f.endpoint(timeout: 0.01) { challenge, completion in
            delayed = completion; bytes = try f.signed(challenge)
        }
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
        #expect(!endpoint.channel.isOpen)
        delayed?(.success(.init(child: f.child, bytes: bytes)))
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
    }
    @Test func disconnectWakesPendingWaitOutsideWorker() async throws {
        let f = try ChildFixture()
        var endpoint: ChildEndpoint!
        endpoint = try f.endpoint(timeout: 5) { _, _ in
            let retained = endpoint!
            // Do not queue disconnect behind synchronous tests sharing the
            // cooperative/global executor with the blocked proof caller.
            Thread.detachNewThread {
                #expect(throws: (any Error).self) { try f.worker.requireCurrent() }
                retained.revoke()
            }
        }
        let retained = endpoint!
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            Thread.detachNewThread {
                defer { continuation.resume() }
                let start = ProcessInfo.processInfo.systemUptime
                #expect(throws: (any Error).self) { try f.prove(retained) }
                #expect(ProcessInfo.processInfo.systemUptime - start < 2)
                #expect(!retained.channel.isOpen)
            }
        }
    }
    @Test func nestedExchangeIsRefusedAndCounterCannotWrap() throws {
        let f = try ChildFixture()
        var endpoint: ChildEndpoint!
        endpoint = try f.endpoint { _, _ in
            #expect(throws: (any Error).self) { try f.prove(endpoint) }
        }
        #expect(throws: (any Error).self) { try f.prove(endpoint) }
        #expect(!endpoint.channel.isOpen)
        let counter = StorageBootstrapLifecycleChildCounter(initialValue: UInt64.max - 1)
        let last = try f.endpoint(counter: counter)
        try f.prove(last)
        #expect(throws: (any Error).self) { try f.prove(last) }
        #expect(!last.channel.isOpen)
    }
    @Test func capacityCountsLiveEndpointsAndPrunesOnlyDisconnected() throws {
        let state = StorageBootstrapLifecycleChildState()
        var endpoints: [ChildEndpoint] = []
        for pid in Int32(11)...138 {
            let f = try ChildFixture(pid: pid)
            let endpoint = try f.endpoint(counter: state.counter)
            try state.insert(endpoint); endpoints.append(endpoint)
        }
        let extra = try ChildFixture(pid: 139)
        let endpoint = try extra.endpoint(counter: state.counter)
        #expect(throws: (any Error).self) { try state.insert(endpoint) }
        endpoints[0].revoke()
        try state.insert(endpoint)
        #expect(try state.endpoint(pid: 139) === endpoint)
        #expect(throws: (any Error).self) { try state.endpoint(pid: 11) }
        #expect(try state.endpoint(pid: 12) === endpoints[1])
    }
    @Test func reconnectDoesNotResetCounterOrReviveOldCallback() throws {
        let f = try ChildFixture(), state = StorageBootstrapLifecycleChildState()
        var counters: [UInt64] = []
        let first = try f.endpoint(counter: state.counter) { challenge, complete in
            counters.append(challenge.counter)
            complete(.success(.init(child: f.child, bytes: try f.signed(challenge))))
        }
        try state.insert(first); try f.prove(first); first.revoke()
        let replacement = try ChildFixture(pid: f.child.pid)
        let second = try replacement.endpoint(counter: state.counter) { challenge, complete in
            counters.append(challenge.counter)
            complete(.success(.init(child: replacement.child, bytes: try replacement.signed(challenge))))
        }
        try state.insert(second); try replacement.prove(second)
        #expect(counters == [1, 2])
        #expect(first.greeting.channelID != second.greeting.channelID)
        #expect(!first.channel.isOpen && second.channel.isOpen)
    }
    @Test @MainActor func mainThreadCannotEnterBlockingWorker() {
        #expect(Thread.isMainThread)
        let worker = StorageBootstrapLifecycleChildWorker()
        #expect(throws: (any Error).self) { try worker.perform {} }
        #expect(throws: (any Error).self) { try worker.requireCurrent() }
    }
    @Test func fabricatedGreetingEnvelopeIsShapeOnlyNotNativeAcceptance() throws {
        let f = try ChildFixture(), message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", "storage-lifecycle-child")
        xpc_dictionary_set_string(message, "role", "controller-child")
        let bytes = try ChildLifecycle.encode(f.greeting)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        #expect(try StorageBootstrapLifecycleChildXPC.decodeGreeting(message) == f.greeting)
        xpc_dictionary_set_string(message, "role", "daemon")
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleChildXPC.decodeGreeting(message) }
        // Do not invoke greet: local dictionaries have no immutable Mach audit trailer.
    }
    @Test func resultWithoutCheckedBootFailsBeforeSending() throws {
        let f = try ChildFixture()
        var sent = false
        let endpoint = try f.endpoint { _, _ in sent = true }
        #expect(throws: (any Error).self) {
            try f.worker.perform {
                try endpoint.prove(principal: endpoint.principal, grant: f.grant, purpose: .result, repin: {})
            }
        }
        #expect(!sent && !endpoint.channel.isOpen)
    }

}

extension StorageBootstrapLifecycleChildTests {
    @Test func serviceProbeAndCommitBindExactStagedRequestAndFreshCounter() throws {
        let f = try ChildFixture(), oldBoot = try f.boot
        let context = try ChildLifecycle.ServiceContext(serviceEpoch: oldBoot.serviceEpoch, controllerEpoch: 1, controllerKey: f.grant.newKey)
        let predecessor = try ChildLifecycle.ServiceState(grant: f.grant, context: context, openRevision: 1, boot: oldBoot)
        let boot = try StorageLifecycleBootTrust(identity: f.grant.identity, serviceEpoch: childUUID(),
            tlsRootSHA256: String(repeating: "d", count: 64), serverSPKI: String(repeating: "e", count: 64), bootstrapKey: oldBoot.bootstrapKey)
        let successor = try ChildLifecycle.ServiceState(grant: f.grant,
            context: .init(serviceEpoch: boot.serviceEpoch, controllerEpoch: 1, controllerKey: f.grant.newKey), openRevision: 2, boot: boot)
        let change = try ChildLifecycle.ServiceChangeRequest(operationID: childUUID(), predecessor: predecessor)
        let confirmation = try ChildLifecycle.ServiceChangeConfirmation(request: change, successor: successor)
        var challenges: [ChildWire.Challenge] = []
        let endpoint = try f.endpoint { challenge, complete in
            challenges.append(challenge)
            let result = try ChildLifecycle.ServiceResult(identity: f.grant.identity, grant: f.grant, nonce: challenge.nonce,
                serviceEpoch: boot.serviceEpoch, controllerEpoch: 1, controllerKey: f.grant.newKey, openRevision: 2)
            let unsigned = try ChildWire.Reply(challengeSHA256: challenge.digest, receipt: nil, signature: Data(repeating: 0, count: 64), serviceResult: result)
            let signed = try ChildWire.Reply(challengeSHA256: challenge.digest, receipt: nil,
                signature: f.key.signature(for: unsigned.signingBytes), serviceResult: result)
            complete(.success(.init(child: f.child, bytes: try ChildLifecycle.encode(signed))))
        }
        var pins = 0
        for commit in [false, true, true] {
            let reply = try f.worker.perform {
                try endpoint.prove(principal: endpoint.principal, grant: f.grant, purpose: commit ? .serviceCommit : .serviceResult,
                    boot: boot, changeRequest: commit ? nil : change, confirmation: commit ? confirmation : nil, repin: { pins += 1 })
            }
            #expect(try reply.serviceResult?.state(boot: boot) == successor)
        }
        #expect(pins == 6 && challenges.map(\.counter) == [1, 2, 3])
        #expect(Set(challenges.map(\.nonce)).count == 3)
        #expect(challenges[0].changeRequest == change && challenges[0].confirmation == nil)
        #expect(challenges[1].changeRequest == nil && challenges[1].confirmation == confirmation)
        #expect(endpoint.channel.isOpen)
    }
}


extension StorageBootstrapLifecycleChildTests {
    @Test func identityAndGrantShareCounterAndSingleSlot() throws {
        let f = try ChildFixture()
        var counters: [UInt64] = []
        let endpoint = try f.identityEndpoint(identitySender: { challenge, complete in
            counters.append(challenge.counter)
            let unsigned = try ChildWire.IdentityReply(challengeSHA256: challenge.digest, signature: Data(repeating: 0, count: 64))
            let signed = try ChildWire.IdentityReply(challengeSHA256: challenge.digest, signature: f.key.signature(for: unsigned.signingBytes))
            complete(.success(.init(child: f.child, bytes: try ChildLifecycle.encode(signed))))
        }, sender: { challenge, complete in
            counters.append(challenge.counter)
            complete(.success(.init(child: f.child, bytes: try f.signed(challenge))))
        })
        var pins = 0
        _ = try f.worker.perform {
            try endpoint.proveIdentity(principal: endpoint.principal, requestSHA256: Data(repeating: 1, count: 32), repin: { pins += 1 })
        }
        try f.prove(endpoint)
        #expect(counters == [1, 2] && pins == 2 && endpoint.channel.isOpen)
        var nested: ChildEndpoint!
        nested = try f.identityEndpoint(identitySender: { _, _ in
            #expect(throws: (any Error).self) { try f.prove(nested) }
        })
        #expect(throws: (any Error).self) {
            try f.worker.perform { try nested.proveIdentity(principal: nested.principal, requestSHA256: Data(repeating: 1, count: 32), repin: {}) }
        }
        #expect(!nested.channel.isOpen)
    }
    @Test func identityRejectsWrongSenderReplayExpiryAndPostPinLoss() throws {
        for kind in 0..<6 {
            let f = try ChildFixture()
            var previous: Data?
            let endpoint = try f.identityEndpoint(identitySender: { challenge, complete in
                let unsigned = try ChildWire.IdentityReply(challengeSHA256: challenge.digest, signature: Data(repeating: 0, count: 64))
                let signed = try ChildWire.IdentityReply(challengeSHA256: challenge.digest, signature: f.key.signature(for: unsigned.signingBytes))
                let fresh = try ChildLifecycle.encode(signed)
                let bytes = kind == 1 ? previous ?? fresh : fresh
                previous = fresh
                if kind == 2 { f.clock.expireWall() }
                if kind == 3 { f.clock.expireMonotonic() }
                complete(.success(.init(child: kind == 0 ? f.daemon : f.child, bytes: bytes)))
                if kind == 4 { complete(.success(.init(child: f.child, bytes: bytes))) }
            })
            var pins = 0
            func prove() throws {
                _ = try f.worker.perform {
                    try endpoint.proveIdentity(principal: endpoint.principal, requestSHA256: Data(repeating: 1, count: 32), repin: {
                        pins += 1
                        if kind == 5 && pins == 2 { throw BootstrapFailure(.unauthorized) }
                    })
                }
            }
            if kind == 1 { try prove() }
            #expect(throws: (any Error).self) { try prove() }
            #expect(!endpoint.channel.isOpen)
        }
    }
}

extension StorageBootstrapLifecycleChildTests {
    @Test func adoptionSelectorsRequireProtectedOriginAndStableEnrollment() throws {
        typealias A = StorageLifecycleAdoptionProtocol
        let f = try ChildFixture()
        let uuid = try StorageIdentity.FilesystemUUID(childUUID())
        let binding = try StorageIdentity.StoreBinding(storeID: .init(f.greeting.store),
            root: .init(volumeUUID: uuid, inode: 2),
            backing: .init(identity: .init(volumeUUID: uuid, inode: 3), size: 4096), expectedExt4UUID: uuid)
        let origin = try A.Origin(binding: .init(binding), rootPublicKey: f.root.publicData,
            shimLaunchUUID: childUUID(), specSHA256: String(repeating: "a", count: 64))
        let greeting = try ChildWire.Greeting(channelID: f.greeting.channelID, incarnationID: f.greeting.incarnationID,
            daemonUniqueID: f.daemon.uniqueID, controllerSPKI: f.greeting.controllerSPKI,
            rootPublicKey: f.root.publicData, store: binding.storeID.rawValue,
            binding: ChildLifecycle.bindingDigest(binding), expectedEpoch: 1)
        let principal = BootstrapPrincipal(daemon: f.daemon, child: f.child,
            incarnation: greeting.incarnationID, controllerSPKI: greeting.controllerSPKI)
        let request = try A.Request(id: childUUID(), origin: origin, expectedEpoch: 1,
            daemonAudit: f.daemon.auditToken, daemonUniqueID: f.daemon.uniqueID,
            controllerAudit: f.child.auditToken, controllerUniqueID: f.child.uniqueID)
        func validate(_ value: A.Request, origin protected: A.Origin?, greeting selected: ChildWire.Greeting) throws {
            try StorageBootstrapLifecycleAdoptionSelection.validate(request: value, origin: protected,
                greeting: selected, principal: principal, daemon: f.daemon, root: f.root)
        }
        try validate(request, origin: origin, greeting: greeting)
        #expect(throws: (any Error).self) { try validate(request, origin: nil, greeting: greeting) }
        #expect(throws: (any Error).self) { try validate(request, origin: origin, greeting: f.greeting) }
        for kind in 0..<4 {
            let changed = try A.Request(id: kind == 0 ? childUUID() : request.id, origin: origin,
                expectedEpoch: kind == 1 ? 2 : 1,
                daemonAudit: f.daemon.auditToken, daemonUniqueID: f.daemon.uniqueID,
                controllerAudit: kind == 2 ? Data(repeating: 7, count: 32) : f.child.auditToken,
                controllerUniqueID: kind == 3 ? f.child.uniqueID + 1 : f.child.uniqueID)
            #expect(try ChildWire.adoptionRequestDigest(changed) != ChildWire.adoptionRequestDigest(request))
            if kind >= 2 { #expect(throws: (any Error).self) { try validate(changed, origin: origin, greeting: greeting) } }
        }
        let wrongRoot = try A.Origin(binding: .init(binding), rootPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation,
            shimLaunchUUID: origin.shimLaunchUUID, specSHA256: origin.specSHA256)
        #expect(throws: (any Error).self) { try validate(request, origin: wrongRoot, greeting: greeting) }
    }
}
