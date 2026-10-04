#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation

/// Storage-only launch journal. The canonical daemon/store lease is held by main;
/// this journal neither substitutes for that lease nor infers death from sockets.
/// Histories are never retired automatically, including interrupted publications.
enum RawStorageShimRecovery {
    static let directoryName = "storage-shim-generations"

    struct ProcessIdentity: Codable, Equatable, Sendable {
        let pid: Int32
        let startSeconds: UInt64
        let startMicroseconds: UInt64
        let bootUUID: String
        let uniqueID: UInt64

        var valid: Bool {
            pid > 0 && startSeconds > 0 && startMicroseconds < 1_000_000
                && DiskInitializationProtocol.validUUID(bootUUID) && uniqueID > 0
        }
    }

    enum Observation: Equatable {
        case process(ProcessIdentity)
        case absent(bootUUID: String)
        // Native boot evidence only; the current PID's birth remains unknown.
        case bootOnly(bootUUID: String)
        case unknown
    }

    enum Liveness: Equatable { case alive, dead, unknown }

    static func liveness(_ old: ProcessIdentity, observation: Observation) -> Liveness {
        guard old.valid else { return .unknown }
        switch observation {
        case .unknown: return .unknown
        case let .bootOnly(boot):
            // An earlier boot cannot retain a process, even when its numeric PID
            // now belongs to an unreadable system service. Never infer same-boot
            // exit or authorize a live peer from boot evidence alone.
            return DiskInitializationProtocol.validUUID(boot) && boot != old.bootUUID ? .dead : .unknown
        case let .absent(boot):
            return DiskInitializationProtocol.validUUID(boot) ? .dead : .unknown
        case let .process(current):
            guard current.valid, current.pid == old.pid else { return .unknown }
            if current.bootUUID != old.bootUUID { return .dead }
            if current == old { return .alive }
            // Both independent kernel birth fields must differ. Exec, partial
            // reads, inconsistent snapshots and permission failures prove nothing.
            let differentStart = current.startSeconds != old.startSeconds
                || current.startMicroseconds != old.startMicroseconds
            return current.uniqueID != old.uniqueID && differentStart ? .dead : .unknown
        }
    }

    static func queryFailure(byteCount: Int32, error: Int32, bootBefore: String?, bootAfter: String?) -> Observation {
        guard let bootBefore, DiskInitializationProtocol.validUUID(bootBefore),
              bootBefore == bootAfter else { return .unknown }
        if byteCount <= 0, error == ESRCH { return .absent(bootUUID: bootBefore) }
        return .bootOnly(bootUUID: bootBefore)
    }

    /// PROC_PIDUNIQIDENTIFIERINFO's native XNU ABI (56 bytes, uniqueid at 16).
    /// Two complete birth snapshots bracket the BSD info read; errno is captured
    /// immediately. ESRCH alone is absence; EPERM, short reads and all other
    /// errors leave the PID unknown but retain a stable native boot observation.
    /// No kill(0), proc-list or socket fallback exists.
    static func observe(_ pid: Int32) -> Observation {
        guard pid > 0, let boot = bootUUID() else { return .unknown }
        func unique() -> (UInt64?, Int32) {
            var bytes = [UInt8](repeating: 0, count: 56)
            errno = 0
            let count = proc_pidinfo(pid, 17, 0, &bytes, 56)
            let error = errno
            guard count == 56 else { return (nil, count <= 0 ? error : 0) }
            return (bytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self) }, 0)
        }
        func failure(_ code: Int32) -> Observation {
            queryFailure(byteCount: 0, error: code, bootBefore: boot, bootAfter: bootUUID())
        }
        let (before, beforeError) = unique()
        guard let before else { return failure(beforeError) }
        var info = proc_bsdinfo()
        errno = 0
        let count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout.size(ofValue: info)))
        let infoError = errno
        guard count == MemoryLayout.size(ofValue: info) else { return failure(count <= 0 ? infoError : 0) }
        let (after, afterError) = unique()
        guard let after else { return failure(afterError) }
        guard before == after, info.pbi_pid == UInt32(pid),
              info.pbi_start_tvsec > 0, info.pbi_start_tvusec < 1_000_000,
              bootUUID() == boot else { return .unknown }
        let identity = ProcessIdentity(pid: pid, startSeconds: UInt64(info.pbi_start_tvsec),
            startMicroseconds: UInt64(info.pbi_start_tvusec), bootUUID: boot, uniqueID: after)
        return identity.valid ? .process(identity) : .unknown
    }

    private static func bootUUID() -> String? {
        var bytes = [CChar](repeating: 0, count: 128)
        var size = bytes.count
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0,
              size > 1, size <= bytes.count, bytes[size - 1] == 0,
              let uuid = UUID(uuidString: String(cString: bytes)) else { return nil }
        return uuid.uuidString.lowercased()
    }

    struct Intent: Codable, Equatable, Sendable {
        let schemaVersion: UInt32
        let protocolVersion: UInt32
        let launchUUID: String
        let specificationSHA256: String
        let storeIdentity: PersistentFileIdentity
        let generationIdentity: PersistentFileIdentity
    }

    struct LaunchRecord: Codable, Equatable, Sendable {
        let intent: Intent
        let process: ProcessIdentity
    }

    struct Generation: Sendable {
        let specification: VMShimProtocol.Specification
        let data: Data
        let record: LaunchRecord
    }

    struct PreparedLaunch: Sendable {
        let specification: VMShimProtocol.Specification
        let specificationURL: URL
        let data: Data
        // This exact open-file description crosses spawn; closing the parent's
        // copy must never unlock the child's inherited copy.
        let diskHandle: FileHandle
    }

    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func conflict() -> EngineError {
        EngineError(.conflict, "storage shim ownership is ambiguous or incompatible; explicit quiescence is required; preserve disk and storage-shim-generations evidence")
    }

    private static func validate(_ specification: VMShimProtocol.Specification) throws {
        guard specification.kind == .storage, specification.containerID == "cengine-storage",
              let uuid = specification.shimLaunchUUID, DiskInitializationProtocol.validUUID(uuid),
              specification.diskBootstrapVersion == 1,
              specification.expectedInitramfsSHA256?.count == 64,
              specification.rootDiskIdentity?.volumeUUID != nil,
              specification.rootDiskSize != nil, !specification.rootDiskReadOnly,
              specification.volumeDisks.isEmpty, specification.bindShares.isEmpty else { throw conflict() }
    }

    private static func matchesStore(_ old: VMShimProtocol.Specification, _ proposed: VMShimProtocol.Specification) -> Bool {
        // Retained launch bytes describe the original mount, not today's st_dev.
        // Device and guest changes additionally require positive death in publishedGeneration.
        guard let oldIdentity = old.rootDiskIdentity, let proposedIdentity = proposed.rootDiskIdentity,
              let volume = oldIdentity.volumeUUID, volume == proposedIdentity.volumeUUID,
              DiskInitializationProtocol.validUUID(volume.uuidString.lowercased()),
              oldIdentity.inode > 0, oldIdentity.inode == proposedIdentity.inode else { return false }
        return old.kind == proposed.kind && old.containerID == proposed.containerID
            && VMShimClient.launchPathsMatch(old.rootDiskPath, proposed.rootDiskPath)
            && old.rootDiskSize == proposed.rootDiskSize
            && old.diskBootstrapVersion == proposed.diskBootstrapVersion
            && proposed.expectedInitramfsSHA256?.count == 64
            && VMShimClient.launchPathsMatch(old.logPath, proposed.logPath)
    }

    private static func loadIntent(in generation: PersistentStateDirectory, store: PersistentStateDirectory,
                                   data: Data) throws -> (VMShimProtocol.Specification, Intent) {
        let specification = try JSONDecoder().decode(VMShimProtocol.Specification.self, from: data)
        try validate(specification)
        guard let intentData = try generation.readRegularFile(named: "intent.json") else { throw conflict() }
        let intent = try JSONDecoder().decode(Intent.self, from: intentData)
        guard intent.schemaVersion == 1, intent.protocolVersion == VMShimProtocol.version,
              intent.launchUUID == specification.shimLaunchUUID,
              generation.url.lastPathComponent == intent.launchUUID,
              intent.specificationSHA256 == digest(data),
              intent.storeIdentity == store.identity, intent.generationIdentity == generation.identity,
              store.pathStillNamesThisDirectory(), generation.pathStillNamesThisDirectory(),
              VMShimClient.launchPathsMatch(VMShimClient.specificationURL(for: specification).deletingLastPathComponent().path, store.url.path)
        else { throw conflict() }
        return (specification, intent)
    }

    /// Validate every retained generation, not just shim.json: an unselected,
    /// unpublished intent may still belong to a child about to acquire the disk.
    static func publishedGeneration(for proposed: VMShimProtocol.Specification,
                                    observe: (Int32) -> Observation = Self.observe) throws -> Generation? {
        let currentURL = VMShimClient.specificationURL(for: proposed)
        let store = try PersistentStateDirectory.open(currentURL.deletingLastPathComponent())
        let current = try store.readRegularFile(named: currentURL.lastPathComponent, required: false)
        let histories = try store.openDirectoryIfPresent(named: directoryName)
        let names = try histories?.entryNames() ?? []
        guard let current else {
            guard names.isEmpty else { throw conflict() }
            return nil
        }
        guard let histories, !names.isEmpty else { throw conflict() }
        var selected: Generation?
        for name in names {
            guard DiskInitializationProtocol.validUUID(name) else { throw conflict() }
            let directory = try histories.openDirectory(named: name)
            guard let data = try directory.readRegularFile(named: "spec.json"),
                  let recordData = try directory.readRegularFile(named: "launch.json") else { throw conflict() }
            let (specification, intent) = try loadIntent(in: directory, store: store, data: data)
            let record = try JSONDecoder().decode(LaunchRecord.self, from: recordData)
            guard record.intent == intent, record.process.valid,
                  matchesStore(specification, proposed) else { throw conflict() }
            // Different guest bytes are valid only for a fresh launch after proven
            // predecessor death, never for adoption of a live or unknown writer.
            if data != current || specification.rootDiskIdentity?.device != proposed.rootDiskIdentity?.device
                || specification.expectedInitramfsSHA256 != proposed.expectedInitramfsSHA256 {
                guard liveness(record.process, observation: observe(record.process.pid)) == .dead else { throw conflict() }
            }
            if data == current {
                guard selected == nil else { throw conflict() }
                selected = Generation(specification: specification, data: data, record: record)
            }
        }
        guard let selected else { throw conflict() }
        return selected
    }

    /// Must run under the daemon's canonical store lease. The actual validated
    /// storage block FD is held exclusively before allocating a fresh UUID or
    /// writing intent. PreparedLaunch retains it through readiness and spawn
    /// transfers the same open-file description to the child, without unlocking.
    static func prepareLaunch(_ proposed: VMShimProtocol.Specification,
                              observe: (Int32) -> Observation = Self.observe) throws -> PreparedLaunch {
        let old = try publishedGeneration(for: proposed, observe: observe)
        if let old {
            guard liveness(old.record.process, observation: observe(old.record.process.pid)) == .dead else { throw conflict() }
        }
        guard proposed.kind == .storage, !proposed.rootDiskReadOnly,
              proposed.volumeDisks.isEmpty, proposed.bindShares.isEmpty else { throw conflict() }
        let resources = try VMShimAttachmentResolver.resolve(proposed)
        guard resources.disks.count == 1, let disk = resources.disks.first,
              try PersistentFileIdentity.capture(descriptor: disk.handle.fileDescriptor).shimIdentity == proposed.rootDiskIdentity
        else { throw conflict() }
        var specification = proposed
        specification.shimLaunchUUID = UUID().uuidString.lowercased()
        if let old {
            guard old.specification.generation < UInt64.max else { throw conflict() }
            specification.generation = old.specification.generation + 1
        }
        try validate(specification)
        let currentURL = VMShimClient.specificationURL(for: specification)
        let store = try PersistentStateDirectory.open(currentURL.deletingLastPathComponent())
        let histories = try store.openOrCreateDirectory(named: directoryName)
        let generation = try histories.createDirectory(named: specification.shimLaunchUUID!)
        let data = try JSONEncoder().encode(specification)
        let intent = Intent(schemaVersion: 1, protocolVersion: VMShimProtocol.version,
            launchUUID: specification.shimLaunchUUID!, specificationSHA256: digest(data),
            storeIdentity: store.identity, generationIdentity: generation.identity)
        // No rollback: even an incomplete directory remains explicit ambiguity.
        try generation.writeExclusiveRegularFile(named: "spec.json", data: data)
        try generation.writeExclusiveRegularFile(named: "intent.json", data: JSONEncoder().encode(intent))
        try store.replaceRegularFile(named: currentURL.lastPathComponent, data: data)
        return PreparedLaunch(specification: specification,
            specificationURL: generation.url.appending(path: "spec.json"), data: data,
            diskHandle: disk.handle)
    }

    /// Called only by the shim itself, before listeners and before any VZ object.
    /// O_EXCL publication also prevents a second process replaying the same intent.
    static func publishLaunch(specificationURL: URL, data: Data, diskHandle: FileHandle,
                              identity: () -> Observation = { observe(getpid()) }) throws -> VMShimProtocol.Specification {
        guard specificationURL.lastPathComponent == "spec.json" else { throw conflict() }
        let generation = try PersistentStateDirectory.open(specificationURL.deletingLastPathComponent())
        let historiesURL = generation.url.deletingLastPathComponent()
        guard historiesURL.lastPathComponent == directoryName else { throw conflict() }
        let store = try PersistentStateDirectory.open(historiesURL.deletingLastPathComponent())
        let (specification, intent) = try loadIntent(in: generation, store: store, data: data)
        guard try generation.readRegularFile(named: "spec.json") == data,
              try store.readRegularFile(named: "shim.json") == data,
              case let .process(process) = identity(), process.valid,
              process.pid == getpid() else { throw conflict() }
        // Validation must precede publication, listeners and all VZ objects.
        // resolve adopts this handle and cannot acquire a replacement lease.
        let resources = try VMShimAttachmentResolver.resolve(specification, inheritedStorageDisk: diskHandle)
        defer { withExtendedLifetime(resources) {} }
        let record = LaunchRecord(intent: intent, process: process)
        try generation.writeExclusiveRegularFile(named: "launch.json", data: JSONEncoder().encode(record))
        return specification
    }
}
#endif
