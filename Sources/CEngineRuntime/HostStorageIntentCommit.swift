#if os(macOS)
import CryptoKit
import Darwin
import Foundation

/// A single-owner, descriptor-relative COW commit for host intent metadata only.
/// The caller holds the live lease and validates canonical manifest/state semantics.
/// Inspection grants no authority: finish the caller's validation before recovery.
/// Any observed write/hook error must poison the owner and call `poison()`; it is
/// not equivalent to a process disappearing at one of the crash checkpoints.
@MainActor final class HostStorageIntentCommit {
    enum Step: String, CaseIterable, Sendable {
        case inspection, commitPreflight, recoveryPreflight
        case initialProofCreate, initialProofWrite, initialProofPermissions
        case initialProofSync, initialProofClose, initialProofValidate
        case initialProofPublish, initialProofDirectorySync
        case candidateCreate, candidateWrite, candidatePermissions
        case candidateSync, candidateClose, candidateValidate
        case readyProofCreate, readyProofWrite, readyProofPermissions
        case readyProofSync, readyProofClose, readyProofValidate
        case readyProofPublish, readyProofDirectorySync
        case statePublish, stateDirectorySync, recoveryDirectorySync
        case stageDeletionObserved, stageDeletionClaimed, stageDeletionRemoved, stageDeletionDirectorySync
        case candidateDeletionObserved, candidateDeletionClaimed, candidateDeletionRemoved, candidateDeletionDirectorySync
        case proofDeletionObserved, proofDeletionClaimed, proofDeletionRemoved, proofDeletionDirectorySync
        case cleanupValidate
    }
    enum Moment: Sendable { case before, after }
    typealias Hook = (Step, Moment) throws -> Void
    enum Failure: Error { case invalid, changed }

    static let leaseName = "lease"
    static let manifestName = "manifest.json"
    static let stateName = "state.json"
    static let proofName = "intent-commit-v1.json"
    static let proofStageName = "intent-proof-v1.tmp"
    static let candidateName = "intent-state-v1.tmp"
    static let proofClaimName = proofName + ".claim"
    static let proofStageClaimName = proofStageName + ".claim"
    static let candidateClaimName = candidateName + ".claim"
    static let maximumProofBytes = 4096
    static let maximumStateBytes = 1_048_576
    static let maximumEntries = 9

    struct Proof: Codable, Equatable, Sendable {
        let version: UInt64
        let attempt: String
        let manifestDigest: String
        let priorRevision: UInt64
        let nextRevision: UInt64
        let priorSHA: String
        let nextSHA: String
        let ready: Bool
    }

    /// Only this file can seal an inspection, and only its originating helper can
    /// consume it. The complete census, identities, and bytes are checked again.
    struct Recovery {
        fileprivate let owner: UUID
        fileprivate let files: [String: FileSnapshot]

        private init(owner: UUID, files: [String: FileSnapshot]) {
            self.owner = owner
            self.files = files
        }

        fileprivate static func seal(owner: UUID, files: [String: FileSnapshot]) -> Recovery {
            Recovery(owner: owner, files: files)
        }
    }

    fileprivate struct FileSnapshot: Equatable {
        let identity: PersistentFileIdentity
        let bytes: Data
        let mode: mode_t
        let flags: UInt32
    }

    private struct WriteSteps {
        let create: Step
        let write: Step
        let permissions: Step
        let sync: Step
        let close: Step
        let validate: Step
    }
    private struct RemovalSteps {
        let observed: Step
        let claimed: Step
        let removed: Step
        let sync: Step
    }

    private static let baseNames: Set<String> = [leaseName, manifestName, stateName]
    private static let allowedNames = baseNames.union([
        proofName, proofClaimName, proofStageName, proofStageClaimName, candidateName, candidateClaimName,
    ])
    private let directory: PersistentStateDirectory
    private let manifest: Data
    private let hook: Hook?
    private let owner = UUID()

    init(directory: PersistentStateDirectory, manifest: Data, hook: Hook? = nil) {
        self.directory = directory
        self.manifest = manifest
        self.hook = hook
    }

    static func readPrivateFile(
        in directory: PersistentStateDirectory, named name: String, maximumBytes: Int
    ) throws -> Data {
        try readSnapshot(in: directory, named: name, maximumBytes: maximumBytes).bytes
    }

    /// Read-only, including for incomplete stages and already-claimed cleanup.
    /// Scratch is never adopted as state, even when it has a valid next-state hash.
    func inspect(state: Data, revision: UInt64) throws -> Recovery {
        try checkpoint(.inspection) {
            try validateInputs(state: state, revision: revision)
            let files = try census()
            guard files[Self.manifestName]?.bytes == manifest,
                  files[Self.stateName]?.bytes == state else { throw Failure.changed }
            try validateRecovery(files, state: state, revision: revision)
            return Recovery.seal(owner: owner, files: files)
        }
    }

    /// Call only after the host has validated the entire current state. No state
    /// file is ever written here. Cleanup failures attempt to persist a poison fence.
    func recover(_ inspection: Recovery) throws {
        try checkpoint(.recoveryPreflight) {
            guard inspection.owner == owner else { throw Failure.invalid }
            try requireCensus(inspection.files)
        }
        guard Set(inspection.files.keys) != Self.baseNames else { return }
        do {
            try synchronize(.recoveryDirectorySync, files: inspection.files)
            try cleanup(inspection.files)
        } catch {
            // Read-only preflight failures above leave the directory untouched.
            // Once recovery IO begins, a reported failure remains a sticky fence.
            poison()
            throw error
        }
    }

    func commit(
        prior: Data, priorRevision: UInt64, next: Data, nextRevision: UInt64,
        boundary: HostStorageIntents.Hook? = nil
    ) throws {
        try validateInputs(state: prior, revision: priorRevision)
        try validateInputs(state: next, revision: nextRevision)
        guard priorRevision < UInt64.max, nextRevision == priorRevision + 1 else { throw Failure.invalid }
        let attempt = UUID().uuidString.lowercased()
        let initial = Proof(version: 1, attempt: attempt, manifestDigest: Self.digest(manifest),
            priorRevision: priorRevision, nextRevision: nextRevision,
            priorSHA: Self.digest(prior), nextSHA: Self.digest(next), ready: false)
        let ready = Proof(version: initial.version, attempt: initial.attempt, manifestDigest: initial.manifestDigest,
            priorRevision: initial.priorRevision, nextRevision: initial.nextRevision,
            priorSHA: initial.priorSHA, nextSHA: initial.nextSHA, ready: true)
        let initialBytes = try Self.encodeProof(initial)
        let readyBytes = try Self.encodeProof(ready)

        // Preserve the old boundary's no-I/O failure behavior.
        try boundary?(.beforeMarker)
        var files = try checkpoint(.commitPreflight) {
            let files = try census()
            guard Set(files.keys) == Self.baseNames,
                  files[Self.manifestName]?.bytes == manifest,
                  files[Self.stateName]?.bytes == prior else { throw Failure.changed }
            return files
        }
        files[Self.proofStageName] = try writeExclusive(
            named: Self.proofStageName, bytes: initialBytes, files: files,
            steps: WriteSteps(create: .initialProofCreate, write: .initialProofWrite,
                permissions: .initialProofPermissions, sync: .initialProofSync,
                close: .initialProofClose, validate: .initialProofValidate))
        try publish(from: Self.proofStageName, to: Self.proofName, exclusive: true,
            step: .initialProofPublish, files: &files)
        try synchronize(.initialProofDirectorySync, files: files)
        try boundary?(.afterMarker)

        // Candidate I/O cannot start until the initial proof's parent sync has
        // succeeded. Thus a stage without a proof can only precede publication.
        files[Self.candidateName] = try writeExclusive(
            named: Self.candidateName, bytes: next, files: files,
            steps: WriteSteps(create: .candidateCreate, write: .candidateWrite,
                permissions: .candidatePermissions, sync: .candidateSync,
                close: .candidateClose, validate: .candidateValidate))
        files[Self.proofStageName] = try writeExclusive(
            named: Self.proofStageName, bytes: readyBytes, files: files,
            steps: WriteSteps(create: .readyProofCreate, write: .readyProofWrite,
                permissions: .readyProofPermissions, sync: .readyProofSync,
                close: .readyProofClose, validate: .readyProofValidate))
        try publish(from: Self.proofStageName, to: Self.proofName, exclusive: false,
            step: .readyProofPublish, files: &files)
        try synchronize(.readyProofDirectorySync, files: files)

        // This census checks both the prior state and the fully synced candidate
        // by identity and exact bytes immediately before the replacing rename.
        try publish(from: Self.candidateName, to: Self.stateName, exclusive: false,
            step: .statePublish, files: &files)
        try synchronize(.stateDirectorySync, files: files)
        try boundary?(.afterState)
        try boundary?(.beforeUnmark)
        try cleanup(files)
        try boundary?(.afterUnmark)
    }

    /// Best effort and deliberately independent of fault hooks. Never truncate,
    /// replace, or clear existing uncertainty; even an incomplete marker refuses
    /// future opens because it is outside the closed census.
    func poison() {
        let file = Darwin.openat(directory.descriptor, "uncertain",
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        if file >= 0 {
            var byte: UInt8 = 1
            var count: Int
            repeat { count = Darwin.write(file, &byte, 1) } while count < 0 && errno == EINTR
            _ = Darwin.fchmod(file, 0o600)
            _ = Darwin.fsync(file)
            _ = Darwin.close(file)
        }
        _ = Darwin.fsync(directory.descriptor)
    }

    static func encodeProof(_ proof: Proof) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(proof)
        guard !bytes.isEmpty, bytes.count <= maximumProofBytes else { throw Failure.invalid }
        return bytes
    }

    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func validateInputs(state: Data, revision: UInt64) throws {
        guard revision > 0, !state.isEmpty, state.count <= Self.maximumStateBytes,
              !manifest.isEmpty, manifest.count <= Self.maximumStateBytes else { throw Failure.invalid }
    }

    private func validateRecovery(_ files: [String: FileSnapshot], state: Data, revision: UInt64) throws {
        for (original, claim) in [
            (Self.proofName, Self.proofClaimName), (Self.proofStageName, Self.proofStageClaimName),
            (Self.candidateName, Self.candidateClaimName),
        ] {
            guard files[original] == nil || files[claim] == nil else { throw Failure.invalid }
        }
        let stage = files[Self.proofStageName] ?? files[Self.proofStageClaimName]
        let candidate = files[Self.candidateName] ?? files[Self.candidateClaimName]
        guard let published = files[Self.proofName] ?? files[Self.proofClaimName] else {
            // Only a prepublication proof stage can survive without a proof.
            guard candidate == nil else { throw Failure.invalid }
            return
        }
        if files[Self.proofClaimName] != nil {
            guard stage == nil, candidate == nil else { throw Failure.invalid }
        }
        let proof = try JSONDecoder().decode(Proof.self, from: published.bytes)
        guard try Self.encodeProof(proof) == published.bytes,
              proof.version == 1,
              let attempt = UUID(uuidString: proof.attempt), attempt.uuidString.lowercased() == proof.attempt,
              proof.manifestDigest == Self.digest(manifest),
              Self.isDigest(proof.priorSHA), Self.isDigest(proof.nextSHA),
              proof.priorRevision > 0, proof.priorRevision < UInt64.max,
              proof.nextRevision == proof.priorRevision + 1 else { throw Failure.invalid }
        let hash = Self.digest(state)
        let isPrior = revision == proof.priorRevision && hash == proof.priorSHA
        let isNext = revision == proof.nextRevision && hash == proof.nextSHA
        guard isPrior || (isNext && proof.ready) else { throw Failure.invalid }
        guard !isNext || candidate == nil else { throw Failure.invalid }
        if proof.ready, let candidate {
            guard Self.digest(candidate.bytes) == proof.nextSHA else { throw Failure.invalid }
        }
    }

    private static func isDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private func checkpoint<T>(_ step: Step, _ operation: () throws -> T) throws -> T {
        try hook?(step, .before)
        let result = try operation()
        try hook?(step, .after)
        return result
    }

    private func synchronize(_ step: Step, files: [String: FileSnapshot]) throws {
        try checkpoint(step) {
            try requireCensus(files)
            try directory.synchronize()
        }
    }

    private func publish(
        from source: String, to destination: String, exclusive: Bool,
        step: Step, files: inout [String: FileSnapshot]
    ) throws {
        try checkpoint(step) {
            try requireCensus(files)
            guard let sourceFile = files[source], exclusive ? files[destination] == nil : files[destination] != nil else {
                throw Failure.changed
            }
            let result = exclusive
                ? Darwin.renameatx_np(directory.descriptor, source, directory.descriptor, destination, UInt32(RENAME_EXCL))
                : Darwin.renameat(directory.descriptor, source, directory.descriptor, destination)
            guard result == 0 else { throw Self.posixError() }
            files.removeValue(forKey: source)
            files[destination] = sourceFile
        }
    }

    private func writeExclusive(
        named name: String, bytes: Data, files: [String: FileSnapshot], steps: WriteSteps
    ) throws -> FileSnapshot {
        var file: CInt = -1
        // On any failure preserve every created artifact. Closing a descriptor
        // is not a license to erase evidence of an observed error.
        defer { if file >= 0 { _ = Darwin.close(file) } }
        try checkpoint(steps.create) {
            try requireCensus(files)
            guard files[name] == nil else { throw Failure.changed }
            file = Darwin.openat(directory.descriptor, name,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
            guard file >= 0 else { throw Self.posixError() }
        }
        var created = stat()
        guard Darwin.fstat(file, &created) == 0 else { throw Self.posixError() }
        try Self.validateFile(created, in: directory, maximumBytes: Self.limit(for: name))
        let identity = PersistentFileIdentity(created, volumeUUID: directory.identity.volumeUUID)
        try checkpoint(steps.write) {
            try bytes.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let count = Darwin.write(file, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                    if count < 0, errno == EINTR { continue }
                    guard count > 0 else { throw Self.posixError() }
                    offset += count
                }
            }
        }
        try checkpoint(steps.permissions) {
            guard Darwin.fchmod(file, 0o600) == 0 else { throw Self.posixError() }
        }
        try checkpoint(steps.sync) {
            guard Darwin.fsync(file) == 0 else { throw Self.posixError() }
        }
        try checkpoint(steps.close) {
            let closing = file
            file = -1 // Never retry close(2), including after EINTR.
            guard Darwin.close(closing) == 0 else { throw Self.posixError() }
        }
        return try checkpoint(steps.validate) {
            let result = try Self.readSnapshot(in: directory, named: name, maximumBytes: Self.limit(for: name))
            guard result.identity == identity, result.bytes == bytes else { throw Failure.changed }
            return result
        }
    }

    private func cleanup(_ originalFiles: [String: FileSnapshot]) throws {
        var files = originalFiles
        // Every scratch deletion and its parent sync precedes proof deletion.
        // A claimed proof therefore never authorizes a remaining scratch file.
        try remove(named: Self.proofStageName, claim: Self.proofStageClaimName, files: &files,
            steps: RemovalSteps(observed: .stageDeletionObserved, claimed: .stageDeletionClaimed,
                removed: .stageDeletionRemoved, sync: .stageDeletionDirectorySync))
        try remove(named: Self.candidateName, claim: Self.candidateClaimName, files: &files,
            steps: RemovalSteps(observed: .candidateDeletionObserved, claimed: .candidateDeletionClaimed,
                removed: .candidateDeletionRemoved, sync: .candidateDeletionDirectorySync))
        try remove(named: Self.proofName, claim: Self.proofClaimName, files: &files,
            steps: RemovalSteps(observed: .proofDeletionObserved, claimed: .proofDeletionClaimed,
                removed: .proofDeletionRemoved, sync: .proofDeletionDirectorySync))
        try checkpoint(.cleanupValidate) {
            guard Set(files.keys) == Self.baseNames else { throw Failure.invalid }
            try requireCensus(files)
        }
    }

    private func remove(
        named name: String, claim: String, files: inout [String: FileSnapshot], steps: RemovalSteps
    ) throws {
        guard let file = files[name] ?? files[claim] else { return }
        try requireCensus(files)
        guard files[name] == nil || files[claim] == nil else { throw Failure.invalid }
        // The optional helper callback is escaping in its type, although the
        // helper calls it synchronously. Do not capture this method's inout.
        var remaining = files
        // The helper supplies the identity-bound rename/unlink and directory
        // fsync. Both observation moments precede exact revalidation, including
        // any changes made by an after hook. Sync moments bracket the helper's
        // own fsync, not an extra synchronization.
        let removed = try directory.removeEntryIfMatching(
            named: name, identity: file.identity, type: S_IFREG, claimName: claim
        ) { [self] event in
            switch event {
            case .deletionObserved:
                try hook?(steps.observed, .before)
                try hook?(steps.observed, .after)
                try requireCensus(remaining)
            case .deletionClaimed:
                remaining.removeValue(forKey: name)
                remaining[claim] = file
                try hook?(steps.claimed, .before)
                try hook?(steps.claimed, .after)
                try requireCensus(remaining)
            case .deletionRemoved:
                remaining.removeValue(forKey: claim)
                try hook?(steps.removed, .before)
                try hook?(steps.removed, .after)
                try hook?(steps.sync, .before)
                try requireCensus(remaining)
            default:
                throw Failure.invalid
            }
        }
        guard removed else { throw Failure.changed }
        try hook?(steps.sync, .after)
        try requireCensus(remaining)
        files = remaining
    }

    private func requireCensus(_ expected: [String: FileSnapshot]) throws {
        guard try census() == expected else { throw Failure.changed }
    }

    private func census() throws -> [String: FileSnapshot] {
        let names = try Self.boundedNames(in: directory)
        guard Self.baseNames.isSubset(of: Set(names)) else { throw Failure.invalid }
        var files: [String: FileSnapshot] = [:]
        for name in names {
            files[name] = try Self.readSnapshot(in: directory, named: name, maximumBytes: Self.limit(for: name))
        }
        guard try Self.boundedNames(in: directory) == names else { throw Failure.changed }
        return files
    }

    private static func limit(for name: String) -> Int {
        switch name {
        case leaseName: return 0
        case proofName, proofClaimName, proofStageName, proofStageClaimName: return maximumProofBytes
        default: return maximumStateBytes
        }
    }

    private static func boundedNames(in directory: PersistentStateDirectory) throws -> [String] {
        try validateDirectory(directory)
        let scan = Darwin.openat(directory.descriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard scan >= 0 else { throw posixError() }
        guard let stream = Darwin.fdopendir(scan) else {
            let error = posixError()
            _ = Darwin.close(scan)
            throw error
        }
        var open = true
        defer { if open { _ = Darwin.closedir(stream) } }
        var names = Set<String>()
        while true {
            errno = 0
            guard let entry = Darwin.readdir(stream) else {
                guard errno == 0 else { throw posixError() }
                break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            guard names.count < maximumEntries, allowedNames.contains(name), names.insert(name).inserted else {
                throw Failure.invalid
            }
        }
        open = false
        guard Darwin.closedir(stream) == 0 else { throw posixError() }
        return names.sorted()
    }

    private static func readSnapshot(
        in directory: PersistentStateDirectory, named name: String, maximumBytes: Int
    ) throws -> FileSnapshot {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0"),
              name.utf8.count <= Int(MAXNAMLEN), maximumBytes >= 0, maximumBytes <= maximumStateBytes else {
            throw Failure.invalid
        }
        try validateDirectory(directory)
        let namedBefore = try metadata(in: directory, named: name)
        try validateFile(namedBefore, in: directory, maximumBytes: maximumBytes)
        let file = Darwin.openat(directory.descriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard file >= 0 else { throw posixError() }
        var open = true
        defer { if open { _ = Darwin.close(file) } }
        var before = stat()
        guard Darwin.fstat(file, &before) == 0 else { throw posixError() }
        try validateFile(before, in: directory, maximumBytes: maximumBytes)
        guard sameMetadata(before, namedBefore),
              sameMetadata(before, try metadata(in: directory, named: name)) else { throw Failure.changed }
        var bytes = Data()
        bytes.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](repeating: 0, count: min(16 * 1024, maximumBytes + 1))
        while true {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(file, $0.baseAddress, min($0.count, maximumBytes + 1 - bytes.count))
            }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw posixError() }
            if count == 0 { break }
            bytes.append(contentsOf: buffer.prefix(count))
            guard bytes.count <= maximumBytes else { throw Failure.invalid }
        }
        var after = stat()
        guard Darwin.fstat(file, &after) == 0 else { throw posixError() }
        try validateFile(after, in: directory, maximumBytes: maximumBytes)
        guard after.st_size == off_t(bytes.count), sameMetadata(before, after),
              sameMetadata(after, try metadata(in: directory, named: name)) else { throw Failure.changed }
        open = false
        guard Darwin.close(file) == 0 else { throw posixError() }
        return FileSnapshot(identity: PersistentFileIdentity(after, volumeUUID: directory.identity.volumeUUID),
            bytes: bytes, mode: after.st_mode, flags: after.st_flags)
    }

    private static func validateDirectory(_ directory: PersistentStateDirectory) throws {
        var information = stat()
        guard Darwin.fstat(directory.descriptor, &information) == 0 else { throw posixError() }
        guard information.st_mode & S_IFMT == S_IFDIR, information.st_uid == geteuid(),
              information.st_mode & 0o7077 == 0, UInt64(information.st_dev) == directory.identity.device,
              PersistentFileIdentity(information, volumeUUID: directory.identity.volumeUUID) == directory.identity else {
            throw Failure.invalid
        }
    }

    private static func validateFile(_ information: stat, in directory: PersistentStateDirectory, maximumBytes: Int) throws {
        guard information.st_mode & S_IFMT == S_IFREG, information.st_uid == geteuid(),
              information.st_mode & 0o7077 == 0, information.st_nlink == 1,
              UInt64(information.st_dev) == directory.identity.device,
              information.st_size >= 0, information.st_size <= off_t(maximumBytes) else { throw Failure.invalid }
    }

    private static func metadata(in directory: PersistentStateDirectory, named name: String) throws -> stat {
        var information = stat()
        guard Darwin.fstatat(directory.descriptor, name, &information, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw posixError()
        }
        return information
    }

    private static func sameMetadata(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_mode == rhs.st_mode
            && lhs.st_uid == rhs.st_uid && lhs.st_gid == rhs.st_gid && lhs.st_nlink == rhs.st_nlink
            && lhs.st_size == rhs.st_size && lhs.st_flags == rhs.st_flags
            && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
            && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
#endif
