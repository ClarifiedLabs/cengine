#if os(macOS)
import CEngineCore
import Foundation
import Darwin

/// Bounded PUBLIC correlation, never format, exit, or recovery authority. Every
/// phase is exclusive and durable; an interrupted write is evidence, not cleanup.
@MainActor final class ManagedStorageInitialization {
    typealias Checkpoint = ManagedStorageLifecycleCheckpoint
    typealias Resume = StorageLifecycleResumeRootProtocol
    static let directoryName = "managed-storage-initialization"
    struct Manifest: Codable, Equatable {
        let version: String
        let binding: StorageLifecycleStoreBinding
        let provenance: String
    }
    struct Request: Codable, Equatable {
        let prepare: Resume.Prepare
        let recipient: Checkpoint.Recipient
        let prepareRequestID: String
        let completionRequestID: String
    }
    let directory: PersistentStateDirectory
    let manifest: Manifest
    private static let names: Set<String> = ["manifest.json", "request.json", "prepared.json", "attempt.json", "completed.json", "admitted.json"]

    static func create(in root: PersistentStateDirectory, binding: StorageIdentity.StoreBinding,
                       provenance: String) throws -> ManagedStorageInitialization {
        guard try root.entryMetadata(named: Checkpoint.directoryName) == nil,
              try root.entryMetadata(named: "managed-storage") == nil else { throw Checkpoint.Failure.blocked }
        _ = try StorageIdentity.SPKISHA256(provenance)
        let directory = try root.createDirectory(named: directoryName)
        let manifest = Manifest(version: "storage-host-initialization.v2", binding: .init(binding), provenance: provenance)
        try write("manifest.json", data: Checkpoint.encode(manifest), in: directory)
        return try open(in: root)
    }
    static func open(in root: PersistentStateDirectory) throws -> ManagedStorageInitialization {
        let directory = try root.openDirectory(named: directoryName)
        let manifest: Manifest = try read("manifest.json", in: directory)
        let binding = try manifest.binding.value()
        guard manifest.version == "storage-host-initialization.v2",
              binding.root.inode == root.identity.inode,
              binding.root.volumeUUID.rawValue == root.identity.volumeUUID?.uuidString.lowercased(),
              Set(try directory.entryNames()).isSubset(of: names) else { throw Checkpoint.Failure.invalid }
        _ = try StorageIdentity.SPKISHA256(manifest.provenance)
        return .init(directory: directory, manifest: manifest)
    }
    private init(directory: PersistentStateDirectory, manifest: Manifest) { self.directory = directory; self.manifest = manifest }
    func value<T: Codable>(_ name: String, as: T.Type) throws -> T? {
        guard try directory.entryMetadata(named: name) != nil else { return nil }
        return try Self.read(name, in: directory)
    }
    func retain<T: Codable & Equatable>(_ name: String, _ value: T) throws {
        guard Self.names.contains(name), directory.pathStillNamesThisDirectory(),
              Set(try directory.entryNames()).isSubset(of: Self.names) else { throw Checkpoint.Failure.blocked }
        if let prior: T = try self.value(name, as: T.self) {
            guard prior == value else { throw Checkpoint.Failure.blocked }; return
        }
        try Self.write(name, data: Checkpoint.encode(value), in: directory)
    }
    private static func write(_ name: String, data: Data, in directory: PersistentStateDirectory) throws {
        let fd = openat(directory.descriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        defer { Darwin.close(fd) } // Never unlink an uncertain or partial phase.
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
                offset += count
            }
        }
        guard fsync(fd) == 0, fsync(directory.descriptor) == 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
    }
    private static func read<T: Codable>(_ name: String, in directory: PersistentStateDirectory) throws -> T {
        let bytes = try HostStorageIntentCommit.readPrivateFile(in: directory, named: name, maximumBytes: 131_072)
        let value = try JSONDecoder().decode(T.self, from: bytes)
        guard try Checkpoint.encode(value) == bytes else { throw Checkpoint.Failure.invalid }
        return value
    }
    /// Exact bounded bytes across suspension points. No cleanup or commit recovery.
    func markerEvidence(in root: PersistentStateDirectory) throws -> [String: Data] {
        let current = try Self.open(in: root)
        guard current.manifest == manifest, current.directory.identity == directory.identity else { throw Checkpoint.Failure.blocked }
        var result: [String: Data] = [:]
        for name in try directory.entryNames() {
            result[name] = try HostStorageIntentCommit.readPrivateFile(in: directory, named: name, maximumBytes: 131_072)
        }
        return result
    }
    func evidence(in root: PersistentStateDirectory) throws -> [String: Data] {
        var result = try markerEvidence(in: root)
        for name in [Checkpoint.directoryName, "managed-storage"] where try root.entryMetadata(named: name) != nil {
            let child = try root.openDirectory(named: name)
            guard Set(try child.entryNames()) == ["lease", "manifest.json", "state.json"] else { throw Checkpoint.Failure.blocked }
            for file in ["manifest.json", "state.json"] {
                result[name + "/" + file] = try HostStorageIntentCommit.readPrivateFile(in: child, named: file, maximumBytes: Checkpoint.maximumBytes)
            }
        }
        return result
    }
    /// A completed pair selects ordinary recovery, not admission. All values here
    /// are public; that path must still obtain fresh native ROOT proof and Query.
    /// Missing/partial publication is never repaired from a cached completion.
    func hasCompletedPair(in root: PersistentStateDirectory) throws -> Bool {
        guard let completed = try value("completed.json", as: Resume.Completed.self) else { return false }
        guard let request = try value("request.json", as: Request.self),
              let prepared = try value("prepared.json", as: Resume.Prepared.self),
              try value("attempt.json", as: Bool.self) == true else { throw Checkpoint.Failure.blocked }
        try prepared.validate(for: request.prepare)
        try completed.validate(prepared: prepared)
        guard request.prepare.probeGreeting.binding == manifest.binding,
              prepared.successorOrigin.binding == manifest.binding else { throw Checkpoint.Failure.invalid }
        _ = try markerEvidence(in: root)
        let ownerDirectory = try root.openDirectory(named: Checkpoint.directoryName)
        guard Set(try ownerDirectory.entryNames()) == ["lease", "manifest.json", "state.json"] else { throw Checkpoint.Failure.blocked }
        let ownerManifest = try Checkpoint.readManifest(in: root)
        let binding = try manifest.binding.value()
        guard ownerManifest.root == root.identity, ownerManifest.directory == ownerDirectory.identity,
              ownerManifest.lease == (try ownerDirectory.regularFileIdentity(named: "lease", expectedSize: 0)),
              ownerManifest.backing.inode == binding.backing.identity.inode,
              ownerManifest.backing.volumeUUID?.uuidString.lowercased() == binding.backing.identity.volumeUUID.rawValue,
              ownerManifest.bytes == binding.backing.size, ownerManifest.ext4UUID == binding.expectedExt4UUID.rawValue,
              ownerManifest.identity == request.prepare.identity,
              ownerManifest.rootPublicKey == request.prepare.probeGreeting.rootPublicKey,
              ownerManifest.provenanceReference == manifest.provenance else { throw Checkpoint.Failure.invalid }
        let state = try Checkpoint.decode(HostStorageIntentCommit.readPrivateFile(in: ownerDirectory,
            named: "state.json", maximumBytes: Checkpoint.maximumBytes))
        let intents = try HostStorageIntents.inspect(in: root, store: binding.storeID.rawValue,
            provenanceReference: manifest.provenance)
        let initial = try Checkpoint.resumeBaseline(request: request, prepared: prepared, completion: completed,
            provenance: manifest.provenance, intentRevision: intents.revision)
        guard state.identity == initial.identity, state.rootPublicKey == initial.rootPublicKey,
              state.provenanceReference == initial.provenanceReference,
              let current = state.current, let context = state.currentContext,
              let initialCurrent = initial.current, let initialContext = initial.currentContext,
              context.controllerEpoch >= initialContext.controllerEpoch else { throw Checkpoint.Failure.invalid }
        if context.controllerEpoch == initialContext.controllerEpoch {
            guard current == initialCurrent, state.currentService != nil else { throw Checkpoint.Failure.invalid }
        } else {
            // Ordinary takeover/cold recovery may have compacted the resume C2
            // context before admitted.json was written. The validated checkpoint
            // retains a ROOT-signed successor, not necessarily that old context.
            // This is ONLY a routing check: pending work, unsigned receipts and
            // the current service still require ordinary fresh ROOT/Query proof.
            guard current.original.signed.grant.operation == .takeover,
                  current.original.signed.grant.serial > initialCurrent.original.signed.grant.serial else {
                throw Checkpoint.Failure.invalid
            }
        }
        return true
    }
    /// Detect changes even when an authenticated exchange loses its reply. This
    /// is only a physical guard; the operation itself supplies authentication.
    func preservingEvidence<T>(in root: PersistentStateDirectory, operation: () async throws -> T) async throws -> T {
        let before = try evidence(in: root)
        let result: Result<T, any Error>
        do { result = .success(try await operation()) } catch { result = .failure(error) }
        guard try evidence(in: root) == before else { throw Checkpoint.Failure.blocked }
        return try result.get()
    }
    static func requireEmpty(_ state: HostStorageIntents.State) throws {
        guard state.volumes.isEmpty, state.intents.isEmpty, state.operations.isEmpty, state.operationDigests.isEmpty,
              state.reconciliationEvidence == nil, state.liveAdoptionEvidence == nil else { throw Checkpoint.Failure.blocked }
    }
    /// Closed census BEFORE HostStorageIntents.open (which otherwise recovers
    /// commits). Never adopt arbitrary partial directories or commit candidates.
    static func inspectPair(in root: PersistentStateDirectory, original: StorageLifecycleProtocol.Grant? = nil) throws {
        if try root.entryMetadata(named: Checkpoint.directoryName) != nil {
            let directory = try root.openDirectory(named: Checkpoint.directoryName)
            guard Set(try directory.entryNames()) == ["lease", "manifest.json", "state.json"] else { throw Checkpoint.Failure.blocked }
            let manifest = try Checkpoint.readManifest(in: root)
            let state = try Checkpoint.decode(HostStorageIntentCommit.readPrivateFile(in: directory, named: "state.json", maximumBytes: Checkpoint.maximumBytes))
            guard state.identity == manifest.identity, state.rootPublicKey == manifest.rootPublicKey,
                  state.provenanceReference == manifest.provenanceReference else { throw Checkpoint.Failure.invalid }
            try Checkpoint.requireUnusedInitialization(state, original: original)
        }
        if try root.entryMetadata(named: "managed-storage") != nil {
            guard try root.entryMetadata(named: Checkpoint.directoryName) != nil else { throw Checkpoint.Failure.blocked }
            let directory = try root.openDirectory(named: "managed-storage")
            guard Set(try directory.entryNames()) == ["lease", "manifest.json", "state.json"] else { throw Checkpoint.Failure.blocked }
            let state: HostStorageIntents.State = try read("state.json", in: directory)
            try requireEmpty(state)
        }
    }
}
#endif
