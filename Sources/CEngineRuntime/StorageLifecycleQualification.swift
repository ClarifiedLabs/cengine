#if os(macOS) && CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
import CEngineCore
import CryptoKit
import Darwin
import Foundation

/// Closed signed test entry, not an ordinary storage mode or production rollout.
/// Receipts describe this one empty-store chain; none authorizes disk deletion.
public enum StorageLifecycleQualification {
    enum Case: String, Sendable { case fresh, lostCompletion = "lost-completion", liveProofLoss = "live-proof-loss" }
    struct Options: Sendable {
        let root: URL
        let assets: URL
        let selection: Case
        init(_ arguments: [String]) throws {
            guard arguments.count == 6, arguments[0] == "--root", arguments[2] == "--assets", arguments[4] == "--case",
                  let selection = Case(rawValue: arguments[5]),
                  [arguments[1], arguments[3]].allSatisfy({ $0.hasPrefix("/") && !$0.utf8.contains(0) }) else { throw failure() }
            root = URL(filePath: arguments[1]).standardizedFileURL
            assets = URL(filePath: arguments[3]).standardizedFileURL
            self.selection = selection
        }
    }
    private struct Assets: Sendable {
        let kernel: URL, storage: URL
        let kernelHash: String, storageHash: String, sourcePin: String
        private struct Metadata: Decodable {
            let schemaVersion: Int, protocolVersion: Int, storageServiceBootVersion: Int, workloadStorageBootVersion: Int
            let storageLifecycleQualification: String, storageLifecycleSourcePin: String
            let containerInitramfsSHA256: String, storageInitramfsSHA256: String
        }
        init(directory: URL, policy: StorageLifecycleNativePolicy) throws {
            let held = try PersistentStateDirectory.open(directory)
            guard directory.pathComponents.contains(StorageLifecycleShimBootstrap.version),
                  let pin = policy.qualificationSourcePin,
                  let sumData = try held.readRegularFile(named: "SHA256SUMS", maximumBytes: 4096),
                  let metadataBytes = try held.readRegularFile(named: "disk-bootstrap.json", maximumBytes: 65536) else { throw failure() }
            let hashes = try StorageLifecycleShimBootstrap.assetHashes(sumData, metadata: metadataBytes, expected: policy.qualificationAssetsSHA256)
            for name in hashes.keys {
                let file = try held.openRegularFile(named: name, access: .readOnly)
                var hash = SHA256()
                while let bytes = try file.handle.read(upToCount: 1 << 20), !bytes.isEmpty { hash.update(data: bytes) }
                guard hex(hash.finalize()) == hashes[name],
                      try held.regularFileIdentity(named: name) == file.identity else { throw failure() }
            }
            guard hex(SHA256.hash(data: metadataBytes)) == hashes["disk-bootstrap.json"], held.pathStillNamesThisDirectory() else { throw failure() }
            let metadata = try JSONDecoder().decode(Metadata.self, from: metadataBytes)
            guard metadata.schemaVersion == 1, metadata.protocolVersion == 1,
                  metadata.storageServiceBootVersion == 2, metadata.workloadStorageBootVersion == 1,
                  metadata.storageLifecycleQualification == StorageLifecycleShimBootstrap.version,
                  metadata.storageLifecycleSourcePin == pin,
                  metadata.storageInitramfsSHA256 == hashes["storage-initramfs.cpio.gz"],
                  metadata.containerInitramfsSHA256 == hashes["container-initramfs.cpio.gz"] else { throw failure() }
            kernel = directory.appending(path: "vmlinux"); storage = directory.appending(path: "storage-initramfs.cpio.gz")
            kernelHash = hashes["vmlinux"]!; storageHash = metadata.storageInitramfsSHA256; sourcePin = pin
        }
    }
    private struct Fresh: Sendable {
        let lock: CanonicalDataStoreLock
        let directory: PersistentStateDirectory
        let disk: FileHandle
        let binding: StorageIdentity.StoreBinding
    }
    nonisolated private static func prepare(_ options: Options, executable: URL) throws -> Fresh {
        // The external harness owns cleanup. Refuse arbitrary existing roots and
        // require its pre-retention marker BEFORE creating any disk or authority.
        guard options.root.lastPathComponent == "root",
              options.root.deletingLastPathComponent().lastPathComponent.hasPrefix("cengine-compat-") else { throw failure() }
        let work = try PersistentStateDirectory.open(options.root.deletingLastPathComponent())
        guard let owner = try work.readRegularFile(named: ".cengine-compat-owner", maximumBytes: 4096),
              String(data: owner, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) == executable.path,
              let retained = try work.readRegularFile(named: ".cengine-compat-retain", maximumBytes: 4096), !retained.isEmpty else { throw failure() }
        let directory = try work.openDirectory(named: "root")
        var info = stat()
        guard fstat(directory.descriptor, &info) == 0, info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700,
              try directory.entryNames().isEmpty else { throw failure() }
        let lock = try CanonicalDataStoreLock(root: options.root)
        let pinned = try lock.duplicateRetainedDirectory(); defer { Darwin.close(pinned) }
        guard try PersistentFileIdentity.capture(descriptor: pinned) == directory.identity else { throw failure() }
        guard case .created(let created) = try RawDiskInitialization.createNewDisk(in: directory, named: "storage.ext4", size: 64 << 20) else { throw failure() }
        let disk = try directory.openRegularFile(named: "storage.ext4", access: .readWrite)
        let record = created.record
        let binding = try StorageIdentity.StoreBinding(storeID: .init(UUID().uuidString.lowercased()),
            root: rootIdentity(directory.identity), backing: .init(identity: rootIdentity(disk.identity), size: record.expectedSize),
            expectedExt4UUID: .init(record.ext4UUID))
        return Fresh(lock: lock, directory: directory, disk: disk.handle, binding: binding)
    }
    nonisolated private static func rootIdentity(_ value: PersistentFileIdentity) throws -> StorageIdentity.RootIdentity {
        guard let volume = value.volumeUUID else { throw failure() }
        return try .init(volumeUUID: .init(volume.uuidString.lowercased()), inode: value.inode)
    }
    @MainActor public static func run(arguments: [String]) async throws {
        let options = try Options(arguments)
        let policy = try await StorageLifecycleQualificationShim.worker { try StorageLifecycleNativePolicy.qualification(role: .engine) }
        let identity = try await StorageLifecycleQualificationShim.worker { try policy.currentIdentity(role: .engine) }
        let assets = try await StorageLifecycleQualificationShim.worker { try Assets(directory: options.assets, policy: policy) }
        let fresh = try await StorageLifecycleQualificationShim.worker { try prepare(options, executable: identity.executable) }
        let client = try StorageLifecycleRootClient(installedHelperTeam: identity.teamIdentifier, policy: policy)
        var owner: ManagedStorageLifecycleOwner?
        var shim: StorageLifecycleShimProcess?
        var phase = "scope"
        do {
            try await StorageLifecycleQualificationShim.worker {
                try client.bindQualificationScope(store: fresh.binding.storeID, rootFD: fresh.directory.descriptor)
            }
            owner = try ManagedStorageLifecycleOwner(rootClient: client, installedHelperTeam: identity.teamIdentifier,
                root: fresh.directory, backingDescriptor: fresh.disk.fileDescriptor, binding: fresh.binding,
                provenanceReference: assets.sourcePin, policy: policy)
            phase = "prepare-child"
            let preparation = try await owner!.prepareFresh()
            phase = "spawn-shim"
            shim = try await StorageLifecycleShimProcess.launch(root: preparation.rootPublicKey, binding: fresh.binding,
                storeLock: fresh.lock, backingFile: fresh.lock.root.appending(path: "storage.ext4"), kernel: assets.kernel,
                initialRamdisk: assets.storage, expectedInitramfsSHA256: assets.storageHash, expectedKernelSHA256: assets.kernelHash, policy: policy)
            // Refresh the authenticated enrollment hint; this is not a substitute
            // for the fresh/service responder's independently audited direct proof.
            try await refresh(client, expected: preparation.rootPublicKey)
            phase = "initialize-disk"
            let greeting = try await shim!.connection.prepareFreshDisk()
            guard greeting.matches(binding: fresh.binding) else { throw failure() }
            phase = "provision"
            try await owner!.provisionFresh()
            let pending = try owner!.snapshot()
            guard let initial = pending.pending, pending.identity.generation == 1 else { throw failure() }
            let childPID = initial.recipient.childPID
            let boot = StorageLifecycleServiceBootProtocol.Binding(shimLaunchUUID: greeting.shimLaunchUUID,
                guestBootNonce: greeting.guestBootNonce, ext4UUID: greeting.ext4UUID, bytes: greeting.bytes)
            try await refresh(client, expected: preparation.rootPublicKey)
            if options.selection == .lostCompletion {
                try await StorageLifecycleQualificationShim.worker { try client.armQualificationCompletionLoss() }
            }
            phase = "boot-and-complete"
            do {
                try await owner!.bootFresh(using: shim!.connection, expectedBinding: boot,
                    nowUnixSeconds: UInt64(Date().timeIntervalSince1970), lifetimeSeconds: 3600)
                guard options.selection != .lostCompletion else { throw failure() }
            } catch is StorageLifecycleRootClient.QualificationCompletionReplyLost {
                guard options.selection == .lostCompletion, let discarded = client.qualificationDiscardedCompletion,
                      discarded.grant == initial.signed.grant,
                      try owner!.snapshot().pending?.signed.grant == initial.signed.grant else { throw failure() }
                // Same semantic request, genuinely fresh native service+child proof.
                try await owner!.complete()
                guard let retried = try owner!.snapshot().current?.directResult,
                      retried.grant == discarded.grant, retried.serviceEpoch == discarded.serviceEpoch,
                      retried.revision == discarded.revision, retried.nonce != discarded.nonce else { throw failure() }
            }
            phase = "workload"
            try await owner!.connectWorkload()
            phase = "stage-retire"
            try await owner!.stageRetire()
            if options.selection == .liveProofLoss {
                phase = "revoke-live-proof"
                try await shim!.connection.qualificationRevokeServiceProof()
                let before = try owner!.snapshot()
                guard before.pending?.signed.grant.operation == .retire else { throw failure() }
                phase = "refuse-seal"
                var refused = false
                do { try await owner!.seal() }
                catch let error as StorageLifecycleRootClient.Failure {
                    guard [.unauthorized, .unavailable].contains(error.code) else { throw error }
                    refused = true
                }
                guard refused, try owner!.snapshot() == before else { throw failure() }
                try await shim!.connection.qualificationCheckLiveVM()
                // A second authenticated query must still report the ROOT fence,
                // not grant an epoch/generation because a proof channel went away.
                let request = try StorageLifecycleRootProtocol.Request(requestID: .init(UUID().uuidString.lowercased()), body: .status(identity: before.identity))
                let reply = try await StorageLifecycleQualificationShim.worker { try client.request(request) }
                guard case .failure(.blocked) = reply.body else { throw failure() }
            } else {
                phase = "seal"
                try await owner!.seal()
                phase = "reclaim"
                try await owner!.reclaim()
            }
            let final = try owner!.snapshot()
            guard (final.terminal != nil) == (options.selection != .liveProofLoss) else { throw failure() }
            phase = "stop-shim"
            try await shim!.stop()
            try await shim!.reap()
            phase = "reap-controller"
            await owner!.close()
            try await StorageLifecycleQualificationShim.worker {
                var status: Int32 = 0
                let result = waitpid(childPID, &status, WNOHANG)
                guard result == childPID || (result < 0 && errno == ECHILD) else { throw failure() }
            }
            owner = nil // Release the physical HOST checkpoint lease before reopen.
            phase = "reopen-host"
            let reopened = try ManagedStorageLifecycleCheckpoint.open(in: fresh.directory, backingDescriptor: fresh.disk.fileDescriptor,
                identity: final.identity, rootPublicKey: preparation.rootPublicKey.publicData, provenanceReference: assets.sourcePin)
            guard try reopened.snapshot() == final else { throw failure() }
            try fresh.lock.validateRetainedOwnership()
            var result: [String: Any] = ["profile": StorageLifecycleShimBootstrap.version, "case": options.selection.rawValue,
                "success": true, "store": final.identity.store, "generation": final.identity.generation,
                "hostReopened": true, "rootAuthenticated": true, "shimReaped": true, "controllerReaped": true,
                "terminal": final.terminal != nil, "digests": ["source": assets.sourcePin, "kernel": assets.kernelHash, "storage": assets.storageHash]]
            if options.selection == .lostCompletion { result.merge(["replyDropped": true, "stableGrant": true, "freshProof": true]) { _, new in new } }
            if options.selection == .liveProofLoss { result.merge(["proofRefused": true, "pendingPreserved": true, "liveShimObserved": true]) { _, new in new } }
            let bytes = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
            print(String(decoding: bytes, as: UTF8.self))
        } catch {
            // Only bounded phase text; no private keys, raw argv or grant payloads.
            FileHandle.standardError.write(Data("storage-lifecycle-qualification failed stage=\(phase)\n".utf8))
            await owner?.close()
            do { try await shim?.teardown() }
            catch { FileHandle.standardError.write(Data("storage-lifecycle-qualification containment incomplete\n".utf8)) }
            throw error
        }
    }
    nonisolated private static func refresh(_ client: StorageLifecycleRootClient, expected: StorageIdentity.RootPublicKey) async throws {
        try await StorageLifecycleQualificationShim.worker { guard try client.rootPublicKey() == expected else { throw failure() } }
    }
    nonisolated private static func hex(_ digest: SHA256.Digest) -> String { digest.map { String(format: "%02x", $0) }.joined() }
    nonisolated private static func failure() -> EngineError { .init(.conflict, "native lifecycle qualification refused; retain this test scope") }
}
#endif
