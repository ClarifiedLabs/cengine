#if os(macOS)
import Darwin
import Foundation

/// HOST prerequisite only. This is not a guest block-writer lease, activation,
/// or the complete host/guest handoff. No disk header is ever used as evidence
/// of freshness. Only this helper's successful O_EXCL creation can publish
/// CREATED; a crash before that publication leaves a legacy MOUNT_ONLY disk.
///
/// Future ext4 integration must hold its own descriptor-pinned writer lease,
/// bind the command to the exact shim launch and guest boot, set the supplied
/// ext4 UUID, and verify the authenticated guest's UUID + operation + binding
/// and completed filesystem/block-device sync before calling completion. A
/// lost command/reply is NOT permission to format again. SPENT is terminal for
/// authorization even across daemon restart. This helper never sends commands.
///
/// The directory must be private to the owner. All cooperating host callers
/// use the stable per-disk lock; arbitrary same-UID metadata tampering is not a
/// supported recovery mechanism. Records/locks must not be deleted or restored
/// independently of their disk. Failures preserve artifacts for inspection.
enum RawDiskInitialization {
    enum State: String, Codable, Sendable { case created, spent, initialized }
    enum Failure: Error, Equatable { case unsafePath, invalidSize, quarantined, alreadySpent, acknowledgementMismatch }
    enum Boundary: String, Sendable {
        case diskCreated, diskSynchronized, recordPrepared, recordPublished, recordSynchronized, beforeFullSync
    }
    typealias Hook = (Boundary, State) throws -> Void

    struct Binding: Codable, Equatable, Sendable {
        let shimLaunchUUID: String
        let guestBootNonce: String

        init(shimLaunchUUID: UUID, guestBootNonce: UUID) {
            self.shimLaunchUUID = shimLaunchUUID.uuidString.lowercased()
            self.guestBootNonce = guestBootNonce.uuidString.lowercased()
        }
    }

    /// Durable identity deliberately excludes the boot-local st_dev value.
    struct FileIdentity: Codable, Equatable, Sendable {
        let inode: UInt64
        let volumeUUID: String

        fileprivate init(_ identity: PersistentFileIdentity) throws {
            guard let uuid = identity.volumeUUID, identity.inode != 0,
                  validUUID(uuid.uuidString.lowercased()) else { throw Failure.unsafePath }
            inode = identity.inode
            volumeUUID = uuid.uuidString.lowercased()
        }
    }

    /// Exact, non-persistable observation for one live operation. Never use
    /// PersistentFileIdentity == here: it permits device-number changes.
    struct LiveObservation: Equatable, Sendable {
        let stableIdentity: FileIdentity
        let device: UInt64

        init(_ identity: PersistentFileIdentity) throws {
            stableIdentity = try FileIdentity(identity)
            device = identity.device
        }

        func requireSame(as other: LiveObservation) throws {
            guard self == other else { throw Failure.unsafePath }
        }
    }

    struct Record: Codable, Equatable, Sendable {
        let schemaVersion: Int
        let diskName: String
        let diskIdentity: FileIdentity
        let parentIdentity: FileIdentity
        let lockIdentity: FileIdentity
        let expectedSize: UInt64
        let ext4UUID: String
        let operationUUID: String
        let state: State
        let binding: Binding?

        func matches(disk: LiveObservation, parent: LiveObservation, lock: LiveObservation) -> Bool {
            diskIdentity == disk.stableIdentity && parentIdentity == parent.stableIdentity
                && lockIdentity == lock.stableIdentity
        }

        fileprivate func transitioning(to state: State, binding: Binding?) -> Record {
            Record(schemaVersion: schemaVersion, diskName: diskName, diskIdentity: diskIdentity,
                   parentIdentity: parentIdentity, lockIdentity: lockIdentity, expectedSize: expectedSize,
                   ext4UUID: ext4UUID, operationUUID: operationUUID, state: state, binding: binding)
        }
    }

    struct CreatedDisk: Sendable {
        let record: Record
        fileprivate init(record: Record) { self.record = record }
    }
    enum Creation: Sendable { case created(CreatedDisk), alreadyExists }
    enum Inspection: Equatable, Sendable { case mountOnly, journal(Record), quarantined }

    /// Constructible only by a successful durable CREATED -> SPENT transition.
    /// Do not cache/replay this value; the transport must send it at most once.
    struct Authorization: Sendable {
        let record: Record
        fileprivate init(record: Record) { self.record = record }
    }

    static let maximumRecordBytes = 4096

    static func createNewDisk(
        in directory: PersistentStateDirectory, named name: String, size: UInt64,
        hook: Hook? = nil
    ) throws -> Creation {
        try validate(name: name, size: size)
        return try withLock(in: directory, name: name) { lock in
            // EEXIST never adopts the winner, even if it has a valid journal.
            if try directory.entryMetadata(named: name) != nil { return .alreadyExists }
            guard try artifactNames(name).allSatisfy({ try directory.entryMetadata(named: $0) == nil }) else {
                throw Failure.quarantined
            }
            let disk = Darwin.openat(directory.descriptor, name,
                                     O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
            guard disk >= 0 else {
                if errno == EEXIST { return .alreadyExists }
                throw posixError()
            }
            defer { Darwin.close(disk) } // Never unlink a published disk, including a partial creation.
            do {
                try hook?(.diskCreated, .created)
                guard Darwin.ftruncate(disk, off_t(size)) == 0, Darwin.fsync(disk) == 0 else { throw posixError() }
                try directory.synchronize()
                try fullSync(disk)
                try hook?(.diskSynchronized, .created)
                let diskIdentity = try checkedFile(disk, in: directory, named: name, size: size)
                let record = Record(schemaVersion: 2, diskName: name, diskIdentity: diskIdentity.stableIdentity,
                                    parentIdentity: try FileIdentity(directory.identity), lockIdentity: lock.stableIdentity,
                                    expectedSize: size, ext4UUID: UUID().uuidString.lowercased(),
                                    operationUUID: UUID().uuidString.lowercased(), state: .created, binding: nil)
                try revalidate(record, in: directory, lock: lock, expectedDisk: diskIdentity)
                try publish(record, in: directory, lock: lock, disk: diskIdentity, hook: hook)
                try revalidate(record, in: directory, lock: lock, expectedDisk: diskIdentity)
                return .created(CreatedDisk(record: record))
            } catch {
                // Missing CREATED is never reconstructed from an existing disk.
                quarantine(in: directory, name: name)
                throw error
            }
        }
    }

    static func inspectExisting(
        in directory: PersistentStateDirectory, named name: String, expectedSize: UInt64,
        heldDiskDescriptor: CInt? = nil, createLock: Bool = true
    ) throws -> Inspection {
        try validate(name: name, size: expectedSize)
        return try withLock(in: directory, name: name, create: createLock) { lock in
            try inspect(in: directory, name: name, size: expectedSize, lock: lock,
                        heldDiskDescriptor: heldDiskDescriptor)
        }
    }

    /// Classification only: no lock acquisition, creation, sync, or recovery.
    /// The canonical store lock serializes startup; this does not acquire the
    /// live VM's backing-file lease or wait for an initialization writer.
    static func inspectReadOnly(
        in directory: PersistentStateDirectory, named name: String, expectedSize: UInt64,
        heldDiskDescriptor: CInt
    ) throws -> Inspection {
        try validate(name: name, size: expectedSize)
        let lockName = prefix(name) + ".lock"
        let fd = try openChecked(in: directory, named: lockName, size: 0)
        defer { Darwin.close(fd) }
        let lock = try checkedFile(fd, in: directory, named: lockName, size: 0)
        let result = try inspect(in: directory, name: name, size: expectedSize, lock: lock,
            heldDiskDescriptor: heldDiskDescriptor)
        guard try checkedFile(fd, in: directory, named: lockName, size: 0) == lock else { throw Failure.unsafePath }
        return result
    }

    /// SPENT reaches stable storage before an authorization can escape. A
    /// duplicate begin on SPENT throws; INITIALIZED/MOUNT_ONLY return nil.
    static func begin(
        in directory: PersistentStateDirectory, named name: String, expectedSize: UInt64,
        binding: Binding, heldDiskDescriptor: CInt? = nil, hook: Hook? = nil
    ) throws -> Authorization? {
        try validate(name: name, size: expectedSize)
        guard valid(binding) else { throw Failure.unsafePath }
        return try withLock(in: directory, name: name) { lock in
            switch try inspect(in: directory, name: name, size: expectedSize, lock: lock,
                               heldDiskDescriptor: heldDiskDescriptor) {
            case .mountOnly: return nil
            case .quarantined: throw Failure.quarantined
            case .journal(let record):
                switch record.state {
                case .initialized: return nil
                case .spent: throw Failure.alreadySpent
                case .created:
                    let spent = record.transitioning(to: .spent, binding: binding)
                    do {
                        let disk = try revalidate(spent, in: directory, lock: lock, heldDiskDescriptor: heldDiskDescriptor)
                        try publish(spent, in: directory, lock: lock, disk: disk, hook: hook)
                        try revalidate(spent, in: directory, lock: lock, heldDiskDescriptor: heldDiskDescriptor, expectedDisk: disk)
                        return Authorization(record: spent)
                    } catch {
                        quarantine(in: directory, name: name)
                        throw error
                    }
                }
            }
        }
    }

    /// Caller must first verify an authenticated guest acknowledgement of sync,
    /// not merely receipt of the format request. The fields are the values from
    /// that acknowledgement, NOT a cached Authorization. No transport is wired.
    /// An exact duplicate completion is idempotent, including after lost reply.
    static func completeAfterVerifiedGuestSync(
        in directory: PersistentStateDirectory, named name: String, expectedSize: UInt64,
        operationUUID: UUID, ext4UUID: UUID, binding: Binding,
        heldDiskDescriptor: CInt? = nil, hook: Hook? = nil
    ) throws {
        try validate(name: name, size: expectedSize)
        try withLock(in: directory, name: name) { lock in
            guard case .journal(let record) = try inspect(in: directory, name: name, size: expectedSize, lock: lock,
                                                        heldDiskDescriptor: heldDiskDescriptor),
                  record.state != .created,
                  record.operationUUID == operationUUID.uuidString.lowercased(),
                  record.ext4UUID == ext4UUID.uuidString.lowercased(), record.binding == binding else {
                throw Failure.acknowledgementMismatch
            }
            let disk = try revalidate(record, in: directory, lock: lock, heldDiskDescriptor: heldDiskDescriptor)
            if let heldDiskDescriptor {
                guard Darwin.fsync(heldDiskDescriptor) == 0 else { throw posixError() }
                try fullSync(heldDiskDescriptor)
            }
            if record.state == .initialized {
                // A previous process may have died after rename but before the
                // full-storage barrier. An idempotent reply must finish that
                // barrier, not merely observe a currently visible JSON file.
                do {
                    let fd = try openChecked(in: directory, named: recordName(name, .initialized))
                    defer { Darwin.close(fd) }
                    let identity = try checkedFile(fd, in: directory, named: recordName(name, .initialized))
                    guard try decode(readRecord(fd)) == record else { throw Failure.quarantined }
                    try revalidate(record, in: directory, lock: lock, heldDiskDescriptor: heldDiskDescriptor, expectedDisk: disk)
                    try directory.synchronize()
                    try hook?(.beforeFullSync, .initialized)
                    try fullSync(fd)
                    try hook?(.recordSynchronized, .initialized)
                    try checkedFile(fd, in: directory, named: recordName(name, .initialized)).requireSame(as: identity)
                    try revalidate(record, in: directory, lock: lock, heldDiskDescriptor: heldDiskDescriptor, expectedDisk: disk)
                    return
                } catch {
                    quarantine(in: directory, name: name)
                    throw error
                }
            }
            let initialized = record.transitioning(to: .initialized, binding: binding)
            do {
                try revalidate(initialized, in: directory, lock: lock, heldDiskDescriptor: heldDiskDescriptor, expectedDisk: disk)
                try publish(initialized, in: directory, lock: lock, disk: disk, hook: hook)
                try revalidate(initialized, in: directory, lock: lock, heldDiskDescriptor: heldDiskDescriptor, expectedDisk: disk)
            } catch {
                quarantine(in: directory, name: name)
                throw error
            }
        }
    }

    // Immutable phase files: never replace any previously published record.
    // A deterministic .pending file is itself a fail-closed crash marker.
    private static func prefix(_ name: String) -> String { ".raw-init-\(name)" }
    private static func recordName(_ name: String, _ state: State) -> String { "\(prefix(name)).\(state.rawValue).json" }
    private static func artifactNames(_ name: String) -> [String] {
        [State.created, .spent, .initialized].flatMap { [recordName(name, $0), recordName(name, $0) + ".pending"] }
            + [prefix(name) + ".quarantine"]
    }

    private static func validate(name: String, size: UInt64) throws {
        // Restrict the namespace as well as traversal; disk names cannot alias
        // helper artifacts, and all derived names fit NAME_MAX.
        guard !name.isEmpty, name.utf8.count <= 128, name.first != ".",
              name.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0)
                  || (97...122).contains($0) || [45, 46, 95].contains($0) }) else { throw Failure.unsafePath }
        guard size > 0, size <= UInt64(Int64.max) else { throw Failure.invalidSize }
    }

    private static func validUUID(_ value: String) -> Bool {
        value != "00000000-0000-0000-0000-000000000000"
            && UUID(uuidString: value)?.uuidString.lowercased() == value
    }
    private static func valid(_ binding: Binding) -> Bool {
        validUUID(binding.shimLaunchUUID) && validUUID(binding.guestBootNonce)
    }
    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }
    private static func decode(_ data: Data) throws -> Record {
        let record = try JSONDecoder().decode(Record.self, from: data)
        // Canonical framing rejects duplicate/unknown keys, trailing bytes,
        // optional nulls, noncanonical UUIDs and alternate numeric encodings.
        guard data.count <= maximumRecordBytes, try encoder().encode(record) == data,
              record.schemaVersion == 2, validUUID(record.operationUUID), validUUID(record.ext4UUID),
              [record.diskIdentity, record.parentIdentity, record.lockIdentity].allSatisfy({ $0.inode != 0 && validUUID($0.volumeUUID) }),
              (record.state == .created ? record.binding == nil : record.binding.map(valid) == true) else {
            throw Failure.quarantined
        }
        try validate(name: record.diskName, size: record.expectedSize)
        return record
    }

    private static func inspect(
        in directory: PersistentStateDirectory, name: String, size: UInt64, lock: LiveObservation,
        heldDiskDescriptor: CInt? = nil
    ) throws -> Inspection {
        do {
            try checkParent(directory)
            let heldIdentity = try heldDiskDescriptor.map {
                try checkedFile($0, in: directory, named: name, size: size)
            }
            let disk = try openChecked(in: directory, named: name, size: size)
            defer { Darwin.close(disk) }
            let diskIdentity = try checkedFile(disk, in: directory, named: name, size: size)
            if let heldIdentity { try diskIdentity.requireSame(as: heldIdentity) }
            if try directory.entryMetadata(named: prefix(name) + ".quarantine") != nil { return .quarantined }
            for state in [State.created, .spent, .initialized] {
                if try directory.entryMetadata(named: recordName(name, state) + ".pending") != nil { return .quarantined }
            }
            var records: [Record] = []
            for state in [State.created, .spent, .initialized] {
                let path = recordName(name, state)
                guard try directory.entryMetadata(named: path) != nil else { continue }
                let fd = try openChecked(in: directory, named: path)
                defer { Darwin.close(fd) }
                let identity = try checkedFile(fd, in: directory, named: path)
                let data = try readRecord(fd)
                guard try checkedFile(fd, in: directory, named: path) == identity else { return .quarantined }
                let record = try decode(data)
                guard record.state == state, record.diskName == name, record.expectedSize == size else { return .quarantined }
                try revalidate(record, in: directory, lock: lock,
                               heldDiskDescriptor: heldDiskDescriptor, expectedDisk: diskIdentity)
                records.append(record)
            }
            try checkedFile(disk, in: directory, named: name, size: size).requireSame(as: diskIdentity)
            if let heldDiskDescriptor {
                try checkedFile(heldDiskDescriptor, in: directory, named: name, size: size).requireSame(as: diskIdentity)
            }
            guard let created = records.first else { return .mountOnly }
            guard created.state == .created else { return .quarantined }
            if records.count > 1 {
                guard records[1].state == .spent,
                      records[1] == created.transitioning(to: .spent, binding: records[1].binding) else { return .quarantined }
            }
            if records.count > 2 {
                guard records[2] == records[1].transitioning(to: .initialized, binding: records[1].binding) else { return .quarantined }
            }
            return .journal(records.last!)
        } catch let error as POSIXError { throw error }
        catch { return .quarantined }
    }

    private static func readRecord(_ fd: CInt) throws -> Data {
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0 else { throw posixError() }
        guard info.st_size > 0, info.st_size <= maximumRecordBytes else { throw Failure.quarantined }
        var bytes = [UInt8](repeating: 0, count: maximumRecordBytes + 1)
        var count = 0
        while count < bytes.count {
            let readCount = bytes.withUnsafeMutableBytes {
                Darwin.pread(fd, $0.baseAddress!.advanced(by: count), $0.count - count, off_t(count))
            }
            if readCount < 0 && errno == EINTR { continue }
            guard readCount >= 0 else { throw posixError() }
            if readCount == 0 { break }
            count += readCount
        }
        guard count <= maximumRecordBytes else { throw Failure.quarantined }
        return Data(bytes.prefix(count))
    }

    private static func requireNoACL(_ fd: CInt) throws {
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
            // Darwin reports ENOENT when the descriptor has no extended ACL.
            if errno == ENOENT { return }
            throw posixError()
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        // Darwin returns -1 / EINVAL at the end of an empty ACL, unlike Linux.
        errno = 0
        let result = acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry)
        guard result == -1, errno == EINVAL else { throw Failure.unsafePath }
    }

    private static func fullSync(_ fd: CInt) throws {
        // fsync alone does not flush a macOS drive's volatile cache. This
        // checked barrier follows the directory fsync, ordering data AND names
        // onto stable storage before an initialization command can escape.
        guard fcntl(fd, F_FULLFSYNC) == 0 else { throw posixError() }
    }

    @discardableResult
    private static func checkParent(_ directory: PersistentStateDirectory) throws -> LiveObservation {
        try requireNoACL(directory.descriptor)
        var info = stat()
        guard Darwin.fstat(directory.descriptor, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(), info.st_mode & 0o077 == 0,
              directory.pathStillNamesThisDirectory() else { throw Failure.unsafePath }
        let observed = try LiveObservation(PersistentFileIdentity.capture(descriptor: directory.descriptor))
        guard observed.device == UInt64(info.st_dev), observed.stableIdentity.inode == UInt64(info.st_ino) else {
            throw Failure.unsafePath
        }
        try observed.requireSame(as: LiveObservation(directory.identity))
        try observed.requireSame(as: LiveObservation(PersistentStateDirectory.open(directory.url).identity))
        return observed
    }

    private static func checkedFile(
        _ fd: CInt, in directory: PersistentStateDirectory, named name: String, size: UInt64? = nil
    ) throws -> LiveObservation {
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == geteuid(), info.st_nlink == 1, info.st_size >= 0,
              size == nil || UInt64(info.st_size) == size else { throw Failure.unsafePath }
        try requireNoACL(fd)
        let identity = try LiveObservation(PersistentFileIdentity.capture(descriptor: fd))
        guard identity.device == UInt64(info.st_dev), identity.stableIdentity.inode == UInt64(info.st_ino),
              let entry = try directory.entryMetadata(named: name), entry.type == S_IFREG else { throw Failure.unsafePath }
        try identity.requireSame(as: LiveObservation(entry.identity))
        return identity
    }
    private static func openChecked(
        in directory: PersistentStateDirectory, named name: String, size: UInt64? = nil
    ) throws -> CInt {
        let fd = Darwin.openat(directory.descriptor, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw posixError() }
        do { _ = try checkedFile(fd, in: directory, named: name, size: size); return fd }
        catch { Darwin.close(fd); throw error }
    }
    @discardableResult
    private static func revalidate(
        _ record: Record, in directory: PersistentStateDirectory, lock: LiveObservation,
        heldDiskDescriptor: CInt? = nil, expectedDisk: LiveObservation? = nil
    ) throws -> LiveObservation {
        let parent = try checkParent(directory)
        let disk = try openChecked(in: directory, named: record.diskName, size: record.expectedSize)
        defer { Darwin.close(disk) }
        let observed = try checkedFile(disk, in: directory, named: record.diskName, size: record.expectedSize)
        if let expectedDisk { try observed.requireSame(as: expectedDisk) }
        if let heldDiskDescriptor {
            try checkedFile(heldDiskDescriptor, in: directory, named: record.diskName,
                            size: record.expectedSize).requireSame(as: observed)
        }
        let lockFD = try openChecked(in: directory, named: prefix(record.diskName) + ".lock", size: 0)
        defer { Darwin.close(lockFD) }
        let observedLock = try checkedFile(lockFD, in: directory, named: prefix(record.diskName) + ".lock", size: 0)
        try observedLock.requireSame(as: lock)
        guard record.matches(disk: observed, parent: parent, lock: observedLock) else { throw Failure.unsafePath }
        return observed
    }

    private static func withLock<T>(
        in directory: PersistentStateDirectory, name: String, create: Bool = true, body: (LiveObservation) throws -> T
    ) throws -> T {
        try checkParent(directory)
        let path = prefix(name) + ".lock"
        // Each call opens an independent OFD, never dup() or a cached handle.
        // O_CREAT does not truncate; this stable inode is never removed here.
        // Darwin can return ENOENT to concurrent non-exclusive O_CREAT callers
        // while another caller creates this name. Elect one creator explicitly;
        // losers open only the existing inode, with no retry on missing paths.
        let flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        var fd = Darwin.openat(directory.descriptor, path, create ? flags | O_CREAT | O_EXCL : flags, 0o600)
        if create, fd < 0, errno == EEXIST {
            fd = Darwin.openat(directory.descriptor, path, flags)
        }
        guard fd >= 0 else { throw posixError() }
        defer { Darwin.close(fd) }
        let identity = try checkedFile(fd, in: directory, named: path, size: 0)
        while flock(fd, LOCK_EX) != 0 { if errno != EINTR { throw posixError() } }
        defer { _ = flock(fd, LOCK_UN) }
        guard try checkedFile(fd, in: directory, named: path, size: 0) == identity else { throw Failure.unsafePath }
        try checkParent(directory)
        if create {
            guard Darwin.fsync(fd) == 0 else { throw posixError() }
            try directory.synchronize()
        }
        let result = try body(identity)
        try checkedFile(fd, in: directory, named: path, size: 0).requireSame(as: identity)
        try checkParent(directory)
        return result
    }

    private static func publish(
        _ record: Record, in directory: PersistentStateDirectory,
        lock: LiveObservation, disk: LiveObservation, hook: Hook?
    ) throws {
        let data = try encoder().encode(record)
        guard data.count <= maximumRecordBytes else { throw Failure.quarantined }
        let final = recordName(record.diskName, record.state)
        let pending = final + ".pending"
        let fd = Darwin.openat(directory.descriptor, pending,
                               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard fd >= 0 else { throw posixError() }
        defer { Darwin.close(fd) } // Keep partial writes: their name quarantines recovery.
        let identity = try checkedFile(fd, in: directory, named: pending)
        try directory.synchronize()
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if written < 0 && errno == EINTR { continue }
                guard written > 0 else { throw posixError() }
                offset += written
            }
        }
        guard Darwin.fsync(fd) == 0 else { throw posixError() }
        try hook?(.recordPrepared, record.state)
        try revalidate(record, in: directory, lock: lock, expectedDisk: disk)
        try checkedFile(fd, in: directory, named: pending).requireSame(as: identity)
        guard Darwin.renameatx_np(directory.descriptor, pending, directory.descriptor, final, UInt32(RENAME_EXCL)) == 0 else {
            throw posixError()
        }
        try hook?(.recordPublished, record.state)
        try directory.synchronize()
        try hook?(.beforeFullSync, record.state)
        try fullSync(fd)
        try hook?(.recordSynchronized, record.state)
        try checkedFile(fd, in: directory, named: final).requireSame(as: identity)
    }

    private static func quarantine(in directory: PersistentStateDirectory, name: String) {
        // Best effort under the same lock. If the filesystem cannot persist even
        // this marker, the thrown error is ambiguous: the caller must quarantine
        // the entire store externally, never retain optimistic memory authority.
        let fd = Darwin.openat(directory.descriptor, prefix(name) + ".quarantine",
                               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        if fd >= 0 {
            _ = Darwin.fsync(fd)
            try? directory.synchronize()
            try? fullSync(fd)
            Darwin.close(fd)
        }
    }
    private static func posixError() -> POSIXError { POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
}
#endif
