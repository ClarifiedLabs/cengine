#if os(macOS)
import CEngineCore
import Darwin
import Foundation

/// A short, private namespace for ephemeral VM-shim sockets. The durable epoch
/// record lets daemon replacements reuse live shim paths during one macOS boot,
/// while a new boot always receives a fresh unpredictable directory name.
struct VMShimRuntimeNamespace: Sendable {
    struct EpochRecord: Codable, Equatable, Sendable {
        static let currentSchemaVersion = 1

        let schemaVersion: Int
        let bootSessionUUID: UUID
        let ownerUID: UInt32
        let directoryPath: String
        let directoryIdentity: PersistentFileIdentity

        init(
            bootSessionUUID: UUID,
            ownerUID: uid_t,
            directory: PersistentStateDirectory
        ) {
            schemaVersion = Self.currentSchemaVersion
            self.bootSessionUUID = bootSessionUUID
            self.ownerUID = UInt32(ownerUID)
            directoryPath = directory.url.path
            directoryIdentity = directory.identity
        }
    }

    static let epochRecordName = "shim-runtime-epoch.json"
    static let maximumCreationAttempts = 32

    let bootSessionUUID: UUID
    let ownerUID: uid_t
    let directory: PersistentStateDirectory

    var url: URL { directory.url }

    static func acquire(
        stateDirectory: PersistentStateDirectory,
        runtimeParentURL: URL = URL(filePath: "/tmp", directoryHint: .isDirectory),
        bootSessionUUID suppliedBootSessionUUID: UUID? = nil,
        ownerUID: uid_t = getuid(),
        nonceProvider: () -> String = {
            UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        }
    ) throws -> VMShimRuntimeNamespace {
        let bootSessionUUID = try suppliedBootSessionUUID ?? currentBootSessionUUID()
        let runtimeParent = try PersistentStateDirectory.open(runtimeParentURL)
        guard runtimeParent.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "VM shim runtime parent directory was replaced")
        }

        if let data = try stateDirectory.readRegularFile(
            named: epochRecordName, required: false
        ) {
            let record = try JSONDecoder().decode(EpochRecord.self, from: data)
            try validate(record, runtimeParent: runtimeParent, ownerUID: ownerUID)
            if record.bootSessionUUID == bootSessionUUID {
                let directory = try PersistentStateDirectory.open(
                    URL(filePath: record.directoryPath, directoryHint: .isDirectory)
                )
                guard directory.identity == record.directoryIdentity,
                      directory.pathStillNamesThisDirectory() else {
                    throw EngineError(
                        .conflict,
                        "VM shim runtime namespace ownership changed during this boot"
                    )
                }
                try requireSecure(directory, ownerUID: ownerUID)
                return VMShimRuntimeNamespace(
                    bootSessionUUID: bootSessionUUID,
                    ownerUID: ownerUID,
                    directory: directory
                )
            }
        }

        let directory = try createFreshDirectory(
            in: runtimeParent,
            ownerUID: ownerUID,
            nonceProvider: nonceProvider
        )
        let record = EpochRecord(
            bootSessionUUID: bootSessionUUID,
            ownerUID: ownerUID,
            directory: directory
        )
        guard stateDirectory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "VM shim runtime epoch state directory was replaced")
        }
        try stateDirectory.replaceRegularFile(
            named: epochRecordName,
            data: try JSONEncoder().encode(record)
        )
        guard stateDirectory.pathStillNamesThisDirectory(),
              directory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "VM shim runtime epoch publication was replaced")
        }
        return VMShimRuntimeNamespace(
            bootSessionUUID: bootSessionUUID,
            ownerUID: ownerUID,
            directory: directory
        )
    }

    /// Creates an unrecorded process-lifetime namespace for focused tests that
    /// need valid short shim socket paths without constructing the raw backend.
    static func createEphemeral(
        runtimeParentURL: URL = URL(filePath: "/tmp", directoryHint: .isDirectory),
        ownerUID: uid_t = getuid(),
        nonceProvider: () -> String = {
            UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        }
    ) throws -> VMShimRuntimeNamespace {
        let runtimeParent = try PersistentStateDirectory.open(runtimeParentURL)
        let directory = try createFreshDirectory(
            in: runtimeParent,
            ownerUID: ownerUID,
            nonceProvider: nonceProvider
        )
        return VMShimRuntimeNamespace(
            bootSessionUUID: try currentBootSessionUUID(),
            ownerUID: ownerUID,
            directory: directory
        )
    }

    func makeSocketPath() throws -> String {
        guard directory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "VM shim runtime namespace was replaced")
        }
        try Self.requireSecure(directory, ownerUID: ownerUID)
        let path = directory.url.appending(
            path: "\(UUID().uuidString).sock", directoryHint: .notDirectory
        ).path
        guard path.utf8.count < MemoryLayout<sockaddr_un>.size - 2 else {
            throw EngineError(.badRequest, "VM shim Unix socket path is too long: \(path)")
        }
        return path
    }

    static func currentBootSessionUUID() throws -> UUID {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0,
              size > 1 else {
            throw EngineError(
                .internalError,
                "could not read macOS boot session identity: \(String(cString: strerror(errno)))"
            )
        }
        var bytes = [CChar](repeating: 0, count: size)
        let result = bytes.withUnsafeMutableBytes { buffer in
            sysctlbyname(
                "kern.bootsessionuuid", buffer.baseAddress, &size, nil, 0
            )
        }
        guard result == 0,
              let value = UUID(uuidString: String(cString: bytes)) else {
            throw EngineError(.internalError, "invalid macOS boot session identity")
        }
        return value
    }

    private init(
        bootSessionUUID: UUID,
        ownerUID: uid_t,
        directory: PersistentStateDirectory
    ) {
        self.bootSessionUUID = bootSessionUUID
        self.ownerUID = ownerUID
        self.directory = directory
    }

    private static func createFreshDirectory(
        in runtimeParent: PersistentStateDirectory,
        ownerUID: uid_t,
        nonceProvider: () -> String
    ) throws -> PersistentStateDirectory {
        for _ in 0..<maximumCreationAttempts {
            let nonce = nonceProvider().lowercased()
            guard nonce.count >= 20,
                  nonce.allSatisfy({ $0.isHexDigit }) else {
                throw EngineError(.internalError, "invalid VM shim runtime namespace nonce")
            }
            let name = "ce-\(ownerUID)-\(nonce.prefix(24))"
            do {
                let directory = try runtimeParent.createDirectory(
                    named: name, permissions: 0o700
                )
                guard Darwin.fchmod(directory.descriptor, 0o700) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                try requireSecure(directory, ownerUID: ownerUID)
                guard directory.pathStillNamesThisDirectory() else {
                    throw EngineError(.conflict, "new VM shim runtime namespace was replaced")
                }
                return directory
            } catch let error as POSIXError where error.code == .EEXIST {
                continue
            }
        }
        throw EngineError(.conflict, "could not allocate a unique VM shim runtime namespace")
    }

    private static func validate(
        _ record: EpochRecord,
        runtimeParent: PersistentStateDirectory,
        ownerUID: uid_t
    ) throws {
        let directoryURL = URL(
            filePath: record.directoryPath, directoryHint: .isDirectory
        )
        let expectedPrefix = "ce-\(ownerUID)-"
        guard record.schemaVersion == EpochRecord.currentSchemaVersion,
              record.ownerUID == UInt32(ownerUID),
              VMShimClient.exactLaunchPathKey(record.directoryPath) != nil,
              VMShimClient.launchPathsMatch(
                  directoryURL.deletingLastPathComponent().path,
                  runtimeParent.url.path
              ),
              directoryURL.lastPathComponent.hasPrefix(expectedPrefix),
              directoryURL.lastPathComponent.count == expectedPrefix.count + 24 else {
            throw EngineError(.conflict, "invalid VM shim runtime epoch record")
        }
    }

    private static func requireSecure(
        _ directory: PersistentStateDirectory,
        ownerUID: uid_t
    ) throws {
        var information = stat()
        guard Darwin.fstat(directory.descriptor, &information) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard information.st_mode & S_IFMT == S_IFDIR,
              information.st_uid == ownerUID,
              information.st_mode & 0o7777 == 0o700 else {
            throw EngineError(
                .unauthorized,
                "VM shim runtime namespace is not a private directory owned by the current user"
            )
        }
    }
}
#endif
