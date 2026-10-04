import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageBootstrapHelper

private typealias R = StorageLifecycleRootProtocol
private func rootID() -> String { UUID().uuidString.lowercased() }
private final class RootJournal: StorageLifecycleJournal {
    let key = Curve25519.Signing.PrivateKey()
    var data: Data?
    var writes = 0
    func load() throws -> Data? { data }
    func lifecycleRootPublicKey() throws -> StorageIdentity.RootPublicKey { try .init(publicData: key.publicKey.rawRepresentation) }
    func checkpoint(_ data: Data) throws { self.data = data; writes += 1 }
    func signLifecycle(_ grant: Lifecycle.Grant) throws -> Lifecycle.SignedGrant {
        try .init(grant: grant, signature: key.signature(for: grant.signingBytes))
    }
    func signServiceChange(_ request: Lifecycle.ServiceChangeRequest) throws -> Lifecycle.SignedServiceChange {
        try .init(request: request, signature: key.signature(for: request.signingBytes))
    }
}
private final class RootProofs: StorageLifecycleProcessChecking, StorageLifecycleFreshBindingChecking {
    let worker: StorageBootstrapLifecycleChildWorker
    var root = ""
    var rootPublicKey = Data()
    let epoch = rootID()
    private var formed: [String: StorageLifecycleFreshOrigin] = [:]
    init(_ worker: StorageBootstrapLifecycleChildWorker) { self.worker = worker }
    func candidate(_ candidate: StorageIdentity.Candidate, daemon: BootstrapProcess, grant: Lifecycle.Grant) throws -> BootstrapPrincipal {
        try worker.requireCurrent()
        return .init(daemon: daemon, child: .init(pid: candidate.childPIDHint, startSeconds: 1, startMicroseconds: 0,
            boot: "unsigned", signingIdentity: "unsigned", uniqueID: UInt64(candidate.childPIDHint), pidVersion: 1,
            auditToken: Data(repeating: 2, count: 32)), incarnation: candidate.incarnationID.rawValue,
            controllerSPKI: candidate.publicKey.publicData)
    }
    func liveness(_ process: BootstrapProcess) -> BootstrapLiveness { .exited }
    func validateRecipient(_ principal: BootstrapPrincipal, daemon: BootstrapProcess, grant: Lifecycle.Grant) throws {
        try worker.requireCurrent()
    }
    func serviceBootTrust(_ principal: BootstrapPrincipal, daemon: BootstrapProcess, grant: Lifecycle.Grant) throws -> StorageLifecycleBootTrust {
        try worker.requireCurrent()
        return try .init(identity: grant.identity, serviceEpoch: epoch, tlsRootSHA256: String(repeating: "a", count: 64),
                         serverSPKI: String(repeating: "b", count: 64), bootstrapKey: root)
    }
    func serviceResult(_ principal: BootstrapPrincipal, daemon: BootstrapProcess, grant: Lifecycle.Grant,
                       nonce: Data, boot: StorageLifecycleBootTrust, changeRequest: Lifecycle.ServiceChangeRequest?,
                       confirmation: Lifecycle.ServiceChangeConfirmation?) throws -> Lifecycle.ServiceResult {
        try worker.requireCurrent()
        return try .init(identity: grant.identity, grant: grant, nonce: nonce, serviceEpoch: epoch,
                         controllerEpoch: grant.expectedEpoch + 1, controllerKey: grant.newKey, openRevision: 1)
    }
    func receipt(_ principal: BootstrapPrincipal, daemon: BootstrapProcess, grant: Lifecycle.Grant, nonce: Data) throws -> Lifecycle.Receipt {
        try worker.requireCurrent()
        return try .init(grant: grant, nonce: nonce, serviceEpoch: epoch, revision: grant.serial)
    }
    func verifyFresh(_ binding: StorageIdentity.StoreBinding, grant: Lifecycle.Grant, daemon: BootstrapProcess,
                     principal: BootstrapPrincipal, rootFD: Int32, backingFD: Int32) throws -> StorageLifecycleFreshOrigin {
        try worker.requireCurrent()
        if let existing = formed[grant.id] { return existing }
        let greeting = try StorageLifecycleFreshProtocol.Greeting(channelID: rootID(), daemonUniqueID: daemon.uniqueID,
            rootPublicKey: rootPublicKey, store: binding.storeID.rawValue, shimLaunchUUID: rootID(),
            guestBootNonce: rootID(), operationUUID: rootID(), ext4UUID: binding.expectedExt4UUID.rawValue,
            bytes: binding.backing.size, initramfsSHA256: String(repeating: "c", count: 64),
            device: 1, inode: binding.backing.identity.inode,
            volumeUUID: binding.backing.identity.volumeUUID.rawValue)
        let shim = BootstrapProcess(pid: 210, startSeconds: 1, startMicroseconds: 0, boot: daemon.boot,
            signingIdentity: "unsigned", uniqueID: 210, pidVersion: 1, auditToken: Data(repeating: 3, count: 32))
        let origin = StorageLifecycleFreshOrigin(greeting: greeting, shim: shim, daemon: daemon, grant: grant, principal: principal)
        formed[grant.id] = origin
        return origin
    }
}
private final class RootFixture: @unchecked Sendable {
    let worker = StorageBootstrapLifecycleChildWorker()
    let journal = RootJournal()
    let daemon = BootstrapProcess(pid: 20, startSeconds: 1, startMicroseconds: 0, boot: "unsigned", signingIdentity: "unsigned",
        uniqueID: 20, pidVersion: 1, auditToken: Data(repeating: 1, count: 32))
    let binding: StorageIdentity.StoreBinding
    let candidate: StorageIdentity.Candidate
    let adapter: StorageBootstrapLifecycleXPC
    init() throws {
        let volume = try StorageIdentity.FilesystemUUID(rootID())
        binding = try .init(storeID: .init(rootID()), root: .init(volumeUUID: volume, inode: 2),
            backing: .init(identity: .init(volumeUUID: volume, inode: 3), size: 4096), expectedExt4UUID: volume)
        candidate = try .init(publicKey: .init(rawPublicKey: Data(repeating: 9, count: 32)), childPIDHint: 21, incarnationID: .init(rootID()))
        let proofs = RootProofs(worker)
        proofs.root = try journal.lifecycleRootPublicKey().fingerprint.rawValue
        proofs.rootPublicKey = try journal.lifecycleRootPublicKey().publicData
        adapter = try .init(ownerUID: geteuid(), team: "ABCDEFGHIJ", journal: journal, processes: proofs, bindings: proofs,
            worker: worker, remember: { _ in try proofs.worker.requireCurrent() })
    }
    func request(_ body: R.Body) throws -> R.Request { try .init(requestID: .init(rootID()), body: body) }
    func message(_ request: R.Request, fds: Bool = false) throws -> xpc_object_t {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", R.xpcOperation)
        let bytes = try R.encode(request)
        bytes.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        if fds {
            let fd = open("/dev/null", O_RDONLY); defer { close(fd) }
            xpc_dictionary_set_fd(message, "store-root", fd); xpc_dictionary_set_fd(message, "store-backing", fd)
        }
        return message
    }
    func call(_ body: R.Body, initial: Bool = false) throws -> R.ResultBody {
        let request = try request(body)
        let rootFD = initial ? open("/dev/null", O_RDONLY) : -1
        let backingFD = initial ? open("/dev/null", O_RDONLY) : -1
        defer { if rootFD >= 0 { close(rootFD) }; if backingFD >= 0 { close(backingFD) } }
        let result = try worker.perform { try adapter.dispatch(request, daemon: daemon, rootFD: rootFD, backingFD: backingFD) }
        return try R.decodeReply(R.encode(R.Reply(for: request, body: result)), for: request).body
    }
}

@Suite struct StorageBootstrapLifecycleRootTests {
    @Test func everyOperationUsesSharedWorkerAndActualAuthority() throws {
        let f = try RootFixture(), id = rootID()
        guard case .rootPublicKey(let key) = try f.call(.rootPublicKey) else { Issue.record("key"); return }
        #expect(f.journal.writes == 0)
        let provision = R.Body.provision(id: id, binding: f.binding, candidate: f.candidate, initialDescriptors: true)
        guard case .grant(let grant) = try f.call(provision, initial: true) else { Issue.record("grant"); return }
        #expect(grant.isValidSignature(using: key))
        let identity = grant.grant.identity
        for body in [R.Body.provision(id: id, binding: f.binding, candidate: f.candidate, initialDescriptors: false),
                     .read(identity: identity, id: id)] {
            guard case .grant(let retry) = try f.call(body) else { Issue.record("retry grant"); return }
            // CryptoKit may randomize signatures; the immutable grant is the retry identity.
            #expect(retry.grant == grant.grant && retry.isValidSignature(using: key))
        }
        guard case .completed(let receipt) = try f.call(.complete(identity: identity, id: id)) else { Issue.record("receipt"); return }
        #expect(receipt.grant == grant.grant)
        guard case .serviceBootTrust(let boot, let bootGrant, let changeID) = try f.call(.serviceBootTrust(identity: identity, grantID: id, serviceChangeID: nil)),
              case .serviceResult(let live) = try f.call(.serviceResult(identity: identity, grantID: id)) else {
            Issue.record("live service"); return
        }
        #expect(bootGrant == id && changeID == nil && live.serviceEpoch == boot.serviceEpoch)
        #expect(live.grant == grant.grant && live.openRevision == 1)
        guard case .status(let controller) = try f.call(.status(identity: identity)) else { Issue.record("status"); return }
        #expect(controller.epoch.rawValue == 1)
        let next = try StorageIdentity.Candidate(publicKey: .init(rawPublicKey: Data(repeating: 8, count: 32)),
            childPIDHint: 22, incarnationID: .init(rootID()))
        let takeoverID = rootID()
        _ = try f.call(.issue(operation: .takeover, id: takeoverID, identity: identity, expectedEpoch: 1, candidate: next))
        _ = try f.call(.complete(identity: identity, id: takeoverID))
        let retirementID = rootID()
        _ = try f.call(.issue(operation: .retire, id: retirementID, identity: identity, expectedEpoch: 2, candidate: next))
        _ = try f.call(.complete(identity: identity, id: retirementID))
        #expect(try f.call(.reclaim(identity: identity, id: retirementID)) == .reclaimed)
        #expect(try f.call(.reclaim(identity: identity, id: retirementID)) == .reclaimed)
    }
    @Test func closedCanonicalRequestRejectsUnknownDuplicateMissingAndCrossOperationFields() throws {
        let f = try RootFixture(), request = try f.request(.rootPublicKey)
        let bytes = try R.encode(request), text = String(decoding: bytes, as: UTF8.self)
        #expect(try R.decodeRequest(bytes) == request)
        let invalid = [text + "\n", text.replacingOccurrences(of: "{", with: "{\"unknown\":true,"),
            text.replacingOccurrences(of: "{", with: "{\"version\":\"storage-root-lifecycle.v2\","),
            text.replacingOccurrences(of: "{", with: "{\"id\":\"\(rootID())\","),
            text.replacingOccurrences(of: "\"rootPublicKey\"", with: "\"complete\""),
            text.replacingOccurrences(of: "\"rootPublicKey\"", with: "true"),
            text.replacingOccurrences(of: R.version, with: "bootstrap.v1")]
        for value in invalid { #expect(throws: (any Error).self) { try R.decodeRequest(Data(value.utf8)) } }
    }
    @Test func correlationIncludesRequestIDOperationIdentityAndCandidate() throws {
        let f = try RootFixture(), identity = try Lifecycle.Identity(binding: f.binding, generation: 1), id = rootID()
        let request = try f.request(.read(identity: identity, id: id))
        let failure = try R.encode(R.Reply(for: request, body: .failure(.blocked)))
        #expect(try R.decodeReply(failure, for: request).body == .failure(.blocked))
        let changed = try Lifecycle.Identity(binding: f.binding, generation: 2)
        for body in [R.Body.complete(identity: identity, id: id), .read(identity: changed, id: id), .read(identity: identity, id: rootID())] {
            let other = try R.Request(requestID: request.requestID, body: body)
            #expect(throws: (any Error).self) { try R.decodeReply(failure, for: other) }
        }
        #expect(throws: (any Error).self) { try R.decodeReply(failure, for: f.request(request.body)) }
        #expect(throws: (any Error).self) { try R.Reply(for: request, body: .reclaimed) }
        let issue = try f.request(.issue(operation: .takeover, id: id, identity: identity, expectedEpoch: 1, candidate: f.candidate))
        let issueFailure = try R.encode(R.Reply(for: issue, body: .failure(.blocked)))
        let candidate = try StorageIdentity.Candidate(publicKey: f.candidate.publicKey, childPIDHint: 99, incarnationID: f.candidate.incarnationID)
        let changedCandidate = try R.Request(requestID: issue.requestID, body: .issue(operation: .takeover,
            id: id, identity: identity, expectedEpoch: 1, candidate: candidate))
        #expect(throws: (any Error).self) { try R.decodeReply(issueFailure, for: changedCandidate) }
        let failureText = String(decoding: failure, as: UTF8.self)
        for invalid in [failureText.replacingOccurrences(of: "{", with: "{\"unknown\":true,"),
                        failureText.replacingOccurrences(of: "{", with: "{\"error\":\"blocked\","), failureText + "\\n"] {
            #expect(throws: (any Error).self) { try R.decodeReply(Data(invalid.utf8), for: request) }
        }
        #expect(throws: (any Error).self) { try f.request(.issue(operation: .initialize, id: id, identity: identity, expectedEpoch: 0, candidate: f.candidate)) }
    }
    @Test func actualEnvelopeRejectsFDTypePresenceAndUnexpectedKeysBeforeDuplication() throws {
        let f = try RootFixture()
        let root = try f.request(.rootPublicKey)
        let provision = try f.request(.provision(id: rootID(), binding: f.binding, candidate: f.candidate, initialDescriptors: true))
        #expect(try StorageBootstrapLifecycleXPC.decodeRequest(f.message(root)) == root)
        #expect(try StorageBootstrapLifecycleXPC.decodeRequest(f.message(provision, fds: true)) == provision)
        let unknown = try f.message(root); xpc_dictionary_set_bool(unknown, "proof", true)
        let wrongType = try f.message(provision, fds: true); xpc_dictionary_set_int64(wrongType, "store-root", 5)
        let missing = try f.message(provision, fds: true); xpc_dictionary_set_value(missing, "store-root", nil)
        for bad in [unknown, wrongType, missing, try f.message(root, fds: true), try f.message(provision)] {
            var called = false
            #expect(throws: (any Error).self) { try StorageBootstrapLifecycleXPC.withDescriptors(bad, request: provision) { _, _ in called = true } }
            #expect(!called)
        }
    }
    @Test func borrowedDescriptorsCloseOnSuccessAndThrownOperation() throws {
        let f = try RootFixture()
        let request = try f.request(.provision(id: rootID(), binding: f.binding, candidate: f.candidate, initialDescriptors: true))
        let message = try f.message(request, fds: true)
        for fail in [false, true] {
            var observed: [Int32] = []
            do {
                try StorageBootstrapLifecycleXPC.withDescriptors(message, request: request) { root, backing in
                    observed = [root, backing]; #expect(root >= 0 && backing >= 0 && root != backing)
                    if fail { throw BootstrapFailure(.blocked) }
                }
            } catch { #expect(fail) }
            #expect(observed.count == 2)
            for fd in observed { #expect(fcntl(fd, F_GETFD) == -1 && errno == EBADF) }
        }
    }
    @Test func schedulingDoesNotBlockCallerAndCallbackNeverRunsOnProofWorker() async throws {
        let f = try RootFixture(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        defer { release.signal() }
        f.adapter.schedule({
            try f.worker.requireCurrent(); #expect(!Thread.isMainThread); entered.signal()
            #expect(release.wait(timeout: .now() + 3) == .success)
        }, completion: { result in
            #expect(throws: (any Error).self) { try f.worker.requireCurrent() }
            if case .failure = result { Issue.record("schedule failed") }; finished.signal()
        })
        try #require(await waitForBootstrapTestSignal(entered, timeout: 2) == .success)
        release.signal(); #expect(await waitForBootstrapTestSignal(finished, timeout: 2) == .success)
        let request = try f.request(.rootPublicKey)
        #expect(throws: (any Error).self) { try f.adapter.dispatch(request, daemon: f.daemon) }
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleChildWorker().perform { try f.adapter.dispatch(request, daemon: f.daemon) } }
    }
    @Test func nativeHandleRejectsUnsignedMachSenderWithoutJournalMutation() async throws {
        let f = try RootFixture(), done = DispatchSemaphore(value: 0), request = try f.request(.rootPublicKey)
        let queue = DispatchQueue(label: "root-test.native-events")
        let listener = xpc_connection_create(nil, queue)
        xpc_connection_set_event_handler(listener) { peer in
            guard xpc_get_type(peer) == XPC_TYPE_CONNECTION else { return }
            xpc_connection_set_event_handler(peer) { message in
                guard xpc_get_type(message) == XPC_TYPE_DICTIONARY, let reply = xpc_dictionary_create_reply(message) else { return }
                f.adapter.handle(message, reply: reply) { result in
                    if case .failure = result { Issue.record("uncorrelated failure") }
                    xpc_connection_send_message(peer, reply)
                }
            }
            xpc_connection_resume(peer)
        }
        xpc_connection_resume(listener)
        let client = xpc_connection_create_from_endpoint(xpc_endpoint_create(listener))
        xpc_connection_set_event_handler(client) { _ in }; xpc_connection_resume(client)
        defer { xpc_connection_cancel(client); xpc_connection_cancel(listener) }
        xpc_connection_send_message_with_reply(client, try f.message(request), queue) { response in
            defer { done.signal() }
            var count = 0
            guard let bytes = xpc_dictionary_get_data(response, "reply", &count) else { Issue.record("missing reply"); return }
            do { #expect(try R.decodeReply(Data(bytes: bytes, count: count), for: request).body == .failure(.unauthorized)) }
            catch { Issue.record("bad reply: \(error)") }
        }
        #expect(await waitForBootstrapTestSignal(done, timeout: 5) == .success)
        #expect(f.journal.writes == 0)
    }
}
