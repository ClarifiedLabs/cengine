import CEngineCore
import Darwin
import Foundation

/// A bounded, single-pass ustar/GNU/PAX reader for Docker archive uploads.
/// Extraction is rooted at one retained destination descriptor and no archive
/// symlink is ever followed while resolving a later member.
enum TarArchive {
    private static let blockSize = 512
    private static let metadataPayloadLimit = 1 * 1_024 * 1_024

    private struct EntryMetadata {
        let path: String
        let components: [String]
        let type: UInt8
        let link: String
        let size: UInt64
        let mode: mode_t
        let uid: uid_t
        let gid: gid_t
    }

    private struct Overrides {
        var path: String?
        var link: String?
        var size: UInt64?
        var uid: UInt64?
        var gid: UInt64?

        mutating func merge(_ other: Overrides) {
            if let value = other.path { path = value }
            if let value = other.link { link = value }
            if let value = other.size { size = value }
            if let value = other.uid { uid = value }
            if let value = other.gid { gid = value }
        }
    }

    private struct Budget {
        let policy: ArchivePolicy
        var wireBytes: UInt64 = 0
        var expandedBytes: UInt64 = 0
        var entries = 0
        var metadataRecords = 0

        mutating func consumeWire(_ count: Int) throws {
            wireBytes = try quotaAdd(wireBytes, UInt64(count), name: "archive wire bytes")
            guard wireBytes <= policy.wireBytes else { throw quota("archive wire size limit exceeded") }
        }

        mutating func consumeEntry() throws {
            entries = try quotaAdd(entries, 1, name: "archive entry count")
            guard entries <= policy.entries else { throw quota("archive entry limit exceeded") }
        }

        mutating func consumeMetadata() throws {
            metadataRecords = try quotaAdd(metadataRecords, 1, name: "archive metadata count")
            guard metadataRecords <= policy.metadataRecords else {
                throw quota("archive metadata record limit exceeded")
            }
        }

        mutating func consumeExpanded(_ count: UInt64) throws {
            expandedBytes = try quotaAdd(expandedBytes, count, name: "archive expanded bytes")
            guard expandedBytes <= policy.expandedBytes else {
                throw quota("archive expansion limit exceeded")
            }
        }

        private func quotaAdd<Value: FixedWidthInteger>(
            _ left: Value,
            _ right: Value,
            name: String
        ) throws -> Value {
            do { return try CheckedArithmetic.add(left, right) }
            catch { throw EngineError(.payloadTooLarge, "\(name) overflows") }
        }

        private func quota(_ message: String) -> EngineError {
            EngineError(.payloadTooLarge, message)
        }
    }

    private final class ExtractionRoot {
        let descriptor: CInt
        private var explicitTypes: [String: UInt8] = [:]
        private var regularSizes: [String: UInt64] = [:]
        private var deferredDirectories: [(components: [String], mode: mode_t, uid: uid_t, gid: gid_t)] = []

        init(destination: URL) throws {
            if mkdir(destination.path, mode_t(0o700)) != 0, errno != EEXIST {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            descriptor = Darwin.open(
                destination.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard descriptor >= 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            var information = stat()
            guard Darwin.fstat(descriptor, &information) == 0,
                  information.st_mode & S_IFMT == S_IFDIR else {
                Darwin.close(descriptor)
                throw EngineError(.badRequest, "archive destination is not a directory")
            }
        }

        deinit { Darwin.close(descriptor) }

        func install(
            _ entry: EntryMetadata,
            reader: FileHandle,
            budget: inout Budget
        ) throws {
            let key = entry.components.joined(separator: "/")
            if entry.components.isEmpty {
                guard entry.type == 0x35 else {
                    throw EngineError(.badRequest, "archive root member must be a directory")
                }
                return
            }
            guard explicitTypes[key] == nil else {
                throw EngineError(.badRequest, "archive contains duplicate path \(entry.path)")
            }
            for index in 1..<entry.components.count {
                let parent = entry.components.prefix(index).joined(separator: "/")
                if explicitTypes[parent] == 0x32 {
                    throw EngineError(.badRequest, "archive member traverses a symbolic link")
                }
                if let type = explicitTypes[parent], type != 0x35 {
                    throw EngineError(.badRequest, "archive member traverses a non-directory")
                }
            }

            switch entry.type {
            case 0, 0x30:
                guard entry.size <= budget.policy.fileBytes else {
                    throw EngineError(.payloadTooLarge, "archive file exceeds its size limit")
                }
                try budget.consumeExpanded(entry.size)
                let (parent, leaf) = try openParent(entry.components, create: true)
                defer { Darwin.close(parent) }
                let outputFD = Darwin.openat(
                    parent, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    mode_t(0o600)
                )
                guard outputFD >= 0 else { throw posixArchiveError() }
                let output = FileHandle(fileDescriptor: outputFD, closeOnDealloc: true)
                do {
                    try copyPayload(
                        reader: reader, output: output, size: entry.size, budget: &budget
                    )
                    guard Darwin.fchmod(outputFD, entry.mode) == 0 else {
                        throw posixArchiveError()
                    }
                    try output.synchronize()
                    try output.close()
                } catch {
                    try? output.close()
                    _ = Darwin.unlinkat(parent, leaf, 0)
                    throw error
                }
                explicitTypes[key] = 0x30
                regularSizes[key] = entry.size

            case 0x35:
                guard entry.size == 0 else {
                    throw EngineError(.badRequest, "archive directory has a data payload")
                }
                let (parent, leaf) = try openParent(entry.components, create: true)
                defer { Darwin.close(parent) }
                if Darwin.mkdirat(parent, leaf, mode_t(0o700)) != 0, errno != EEXIST {
                    throw posixArchiveError()
                }
                let child = Darwin.openat(
                    parent, leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                )
                guard child >= 0 else { throw posixArchiveError() }
                Darwin.close(child)
                explicitTypes[key] = 0x35
                deferredDirectories.append((entry.components, entry.mode, entry.uid, entry.gid))

            case 0x32:
                guard entry.size == 0 else {
                    throw EngineError(.badRequest, "archive symbolic link has a data payload")
                }
                let (parent, leaf) = try openParent(entry.components, create: true)
                defer { Darwin.close(parent) }
                guard entry.link.withCString({ Darwin.symlinkat($0, parent, leaf) }) == 0 else {
                    throw posixArchiveError()
                }
                explicitTypes[key] = 0x32

            case 0x31:
                guard entry.size == 0 else {
                    throw EngineError(.badRequest, "archive hard link has a data payload")
                }
                let targetComponents = try TarArchive.safeComponents(
                    entry.link, policy: budget.policy
                )
                let targetKey = targetComponents.joined(separator: "/")
                guard explicitTypes[targetKey] == 0x30,
                      let targetSize = regularSizes[targetKey] else {
                    throw EngineError(.badRequest, "archive hard link must reference an earlier regular file")
                }
                try budget.consumeExpanded(targetSize)
                let (sourceParent, sourceLeaf) = try openParent(targetComponents, create: false)
                defer { Darwin.close(sourceParent) }
                var sourceBefore = stat()
                guard Darwin.fstatat(
                    sourceParent, sourceLeaf, &sourceBefore, AT_SYMLINK_NOFOLLOW
                ) == 0, sourceBefore.st_mode & S_IFMT == S_IFREG else {
                    throw EngineError(.badRequest, "archive hard link source is unsafe")
                }
                let (parent, leaf) = try openParent(entry.components, create: true)
                defer { Darwin.close(parent) }
                guard Darwin.linkat(sourceParent, sourceLeaf, parent, leaf, 0) == 0 else {
                    throw posixArchiveError()
                }
                var sourceAfter = stat()
                var destination = stat()
                guard Darwin.fstatat(
                    sourceParent, sourceLeaf, &sourceAfter, AT_SYMLINK_NOFOLLOW
                ) == 0,
                      Darwin.fstatat(parent, leaf, &destination, AT_SYMLINK_NOFOLLOW) == 0,
                      sourceBefore.st_dev == sourceAfter.st_dev,
                      sourceBefore.st_ino == sourceAfter.st_ino,
                      sourceBefore.st_dev == destination.st_dev,
                      sourceBefore.st_ino == destination.st_ino else {
                    _ = Darwin.unlinkat(parent, leaf, 0)
                    throw EngineError(.badRequest, "archive hard link changed during extraction")
                }
                explicitTypes[key] = 0x30
                regularSizes[key] = targetSize

            default:
                throw EngineError(.badRequest, "archive contains an unsupported entry type")
            }
        }

        func finish() throws {
            for item in deferredDirectories.reversed() {
                let directory = try openDirectory(item.components, create: false)
                defer { Darwin.close(directory) }
                guard Darwin.fchmod(directory, item.mode) == 0 else {
                    throw posixArchiveError()
                }
            }
        }

        private func openParent(
            _ components: [String],
            create: Bool
        ) throws -> (CInt, String) {
            precondition(!components.isEmpty)
            var current = Darwin.dup(descriptor)
            guard current >= 0 else { throw posixArchiveError() }
            do {
                for component in components.dropLast() {
                    var next = Darwin.openat(
                        current, component,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                    )
                    if next < 0, errno == ENOENT, create {
                        guard Darwin.mkdirat(current, component, mode_t(0o700)) == 0
                            || errno == EEXIST else { throw posixArchiveError() }
                        next = Darwin.openat(
                            current, component,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                        )
                    }
                    guard next >= 0 else { throw posixArchiveError() }
                    Darwin.close(current)
                    current = next
                }
                return (current, components.last!)
            } catch {
                Darwin.close(current)
                throw error
            }
        }

        private func openDirectory(
            _ components: [String],
            create: Bool
        ) throws -> CInt {
            if components.isEmpty {
                let duplicate = Darwin.dup(descriptor)
                guard duplicate >= 0 else { throw posixArchiveError() }
                return duplicate
            }
            let (parent, leaf) = try openParent(components, create: create)
            defer { Darwin.close(parent) }
            let child = Darwin.openat(
                parent, leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard child >= 0 else { throw posixArchiveError() }
            return child
        }
    }

    static func extract(
        _ archive: URL,
        to destination: URL,
        policy: ArchivePolicy = .default
    ) throws -> [ArchiveOwnership] {
        let root = try ExtractionRoot(destination: destination)
        let ownership = try read(archive, policy: policy, root: root)
        try root.finish()
        return ownership
    }

    static func inspect(
        _ archive: URL,
        policy: ArchivePolicy = .default
    ) throws -> [ArchiveOwnership] {
        try read(archive, policy: policy, root: nil)
    }

    private static func read(
        _ archive: URL,
        policy: ArchivePolicy,
        root: ExtractionRoot?
    ) throws -> [ArchiveOwnership] {
        let descriptor = Darwin.open(
            archive.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        )
        guard descriptor >= 0 else { throw posixArchiveError() }
        var information = stat()
        guard Darwin.fstat(descriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG,
              information.st_size >= 0,
              let wireSize = UInt64(exactly: information.st_size),
              wireSize <= policy.wireBytes else {
            Darwin.close(descriptor)
            throw EngineError(.payloadTooLarge, "archive input exceeds its wire size limit")
        }
        let input = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? input.close() }

        var budget = Budget(policy: policy)
        var ownership: [ArchiveOwnership] = []
        var global = Overrides()
        var pending = Overrides()
        var zeroBlocks = 0
        while true {
            guard let header = try readExactly(
                input, count: blockSize, allowCleanEOF: true, budget: &budget
            ) else { break }
            if header.allSatisfy({ $0 == 0 }) {
                zeroBlocks += 1
                if zeroBlocks == 2 { break }
                continue
            }
            guard zeroBlocks == 0 else {
                throw EngineError(.badRequest, "archive has data after an end marker")
            }
            try validateChecksum(header)
            let type = header[156]
            let headerSize = try numeric(header, offset: 124, length: 12)

            if type == 0x4c || type == 0x4b || type == 0x78 || type == 0x67 {
                try budget.consumeMetadata()
                guard headerSize <= UInt64(metadataPayloadLimit),
                      let count = Int(exactly: headerSize) else {
                    throw EngineError(.payloadTooLarge, "archive metadata payload is too large")
                }
                let payload = try readPayload(input, count: count, budget: &budget)
                if type == 0x4c || type == 0x4b {
                    let value = try metadataString(payload)
                    guard value.utf8.count <= (type == 0x4c ? policy.pathBytes : policy.linkBytes) else {
                        throw EngineError(.payloadTooLarge, "archive metadata path is too long")
                    }
                    if type == 0x4c { pending.path = value } else { pending.link = value }
                } else {
                    let parsed = try pax(payload, budget: &budget)
                    if type == 0x67 { global.merge(parsed) } else { pending.merge(parsed) }
                }
                continue
            }

            try budget.consumeEntry()
            var effective = global
            effective.merge(pending)
            pending = Overrides()
            let rawName = try headerPath(header)
            let path = effective.path ?? rawName
            let components = try safeComponents(path, policy: policy)
            let link = effective.link ?? field(header, offset: 157, length: 100)
            guard link.utf8.count <= policy.linkBytes, !link.utf8.contains(0) else {
                throw EngineError(.payloadTooLarge, "archive link target is too long")
            }
            let size = effective.size ?? headerSize
            let rawUID = try effective.uid ?? numeric(header, offset: 108, length: 8)
            let rawGID = try effective.gid ?? numeric(header, offset: 116, length: 8)
            guard let uid = uid_t(exactly: rawUID),
                  let gid = gid_t(exactly: rawGID) else {
                throw EngineError(.badRequest, "archive ownership value is out of range")
            }
            let rawMode = try numeric(header, offset: 100, length: 8)
            guard rawMode <= 0o7777, let mode = mode_t(exactly: rawMode) else {
                throw EngineError(.badRequest, "archive mode is out of range")
            }
            let normalizedType: UInt8 = type == 0 ? 0x30 : type
            let entry = EntryMetadata(
                path: path,
                components: components,
                type: normalizedType,
                link: link,
                size: size,
                mode: mode,
                uid: uid,
                gid: gid
            )
            ownership.append(.init(path: path, user: UInt32(uid), group: UInt32(gid)))
            if let root {
                try root.install(entry, reader: input, budget: &budget)
                if normalizedType != 0x30 {
                    try skipPayload(input, size: size, budget: &budget)
                }
            } else {
                if normalizedType == 0x30 {
                    guard size <= policy.fileBytes else {
                        throw EngineError(.payloadTooLarge, "archive file exceeds its size limit")
                    }
                    try budget.consumeExpanded(size)
                }
                try skipPayload(input, size: size, budget: &budget)
            }
        }
        guard zeroBlocks == 2 else {
            throw EngineError(.badRequest, "archive is truncated before its end marker")
        }
        return ownership
    }

    private static func copyPayload(
        reader: FileHandle,
        output: FileHandle,
        size: UInt64,
        budget: inout Budget
    ) throws {
        var remaining = size
        while remaining > 0 {
            let count = Int(min(remaining, 128 * 1_024))
            guard let chunk = try readExactly(
                reader, count: count, allowCleanEOF: false, budget: &budget
            ) else { throw EngineError(.badRequest, "archive file payload is truncated") }
            try output.write(contentsOf: chunk)
            remaining -= UInt64(chunk.count)
        }
        try skipPadding(reader, size: size, budget: &budget)
    }

    private static func readPayload(
        _ input: FileHandle,
        count: Int,
        budget: inout Budget
    ) throws -> Data {
        let payload = try readExactly(
            input, count: count, allowCleanEOF: false, budget: &budget
        ) ?? Data()
        try skipPadding(input, size: UInt64(count), budget: &budget)
        return payload
    }

    private static func skipPayload(
        _ input: FileHandle,
        size: UInt64,
        budget: inout Budget
    ) throws {
        var remaining = size
        while remaining > 0 {
            let count = Int(min(remaining, 128 * 1_024))
            _ = try readExactly(
                input, count: count, allowCleanEOF: false, budget: &budget
            )
            remaining -= UInt64(count)
        }
        try skipPadding(input, size: size, budget: &budget)
    }

    private static func skipPadding(
        _ input: FileHandle,
        size: UInt64,
        budget: inout Budget
    ) throws {
        let aligned: UInt64
        do { aligned = try CheckedArithmetic.alignedToTarBlock(size) }
        catch { throw EngineError(.payloadTooLarge, "archive padding offset overflows") }
        let padding = aligned - size
        if padding > 0 {
            guard try readExactly(
                input, count: Int(padding), allowCleanEOF: false, budget: &budget
            ) != nil else {
                throw EngineError(.badRequest, "archive padding is truncated")
            }
        }
    }

    private static func readExactly(
        _ input: FileHandle,
        count: Int,
        allowCleanEOF: Bool,
        budget: inout Budget
    ) throws -> Data? {
        var result = Data()
        result.reserveCapacity(count)
        while result.count < count {
            guard let chunk = try input.read(upToCount: count - result.count),
                  !chunk.isEmpty else {
                if allowCleanEOF, result.isEmpty { return nil }
                throw EngineError(.badRequest, "archive is truncated")
            }
            try budget.consumeWire(chunk.count)
            result.append(chunk)
        }
        return result
    }

    private static func validateChecksum(_ header: Data) throws {
        let expected = try numeric(header, offset: 148, length: 8, allowBase256: false)
        var actual: UInt64 = 0
        for index in header.indices {
            let byte: UInt8 = (148..<156).contains(index) ? 0x20 : header[index]
            actual = try CheckedArithmetic.add(actual, UInt64(byte))
        }
        guard expected == actual else {
            throw EngineError(.badRequest, "archive header checksum is invalid")
        }
    }

    private static func headerPath(_ header: Data) throws -> String {
        let name = try fieldStrict(header, offset: 0, length: 100)
        let prefix = try fieldStrict(header, offset: 345, length: 155)
        return prefix.isEmpty ? name : "\(prefix)/\(name)"
    }

    private static func field(
        _ data: Data,
        offset: Int,
        length: Int
    ) -> String {
        let bytes = data[offset..<(offset + length)].prefix { $0 != 0 }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func fieldStrict(
        _ data: Data,
        offset: Int,
        length: Int
    ) throws -> String {
        let bytes = Data(data[offset..<(offset + length)].prefix { $0 != 0 })
        guard let value = String(data: bytes, encoding: .utf8), !value.utf8.contains(0) else {
            throw EngineError(.badRequest, "archive path is not valid UTF-8")
        }
        return value
    }

    private static func numeric(
        _ data: Data,
        offset: Int,
        length: Int,
        allowBase256: Bool = true
    ) throws -> UInt64 {
        let bytes = Array(data[offset..<(offset + length)])
        guard let first = bytes.first else { return 0 }
        if first & 0x80 != 0 {
            guard allowBase256, first & 0x40 == 0 else {
                throw EngineError(.badRequest, "archive contains an invalid base-256 number")
            }
            var value = UInt64(first & 0x3f)
            for byte in bytes.dropFirst() {
                do {
                    value = try CheckedArithmetic.add(
                        try CheckedArithmetic.multiply(value, 256), UInt64(byte)
                    )
                } catch {
                    throw EngineError(.badRequest, "archive numeric field overflows")
                }
            }
            return value
        }
        let text = String(decoding: bytes, as: UTF8.self)
            .trimmingCharacters(in: CharacterSet(charactersIn: " \0"))
        if text.isEmpty { return 0 }
        guard text.utf8.allSatisfy({ $0 >= 48 && $0 <= 55 }),
              let value = UInt64(text, radix: 8) else {
            throw EngineError(.badRequest, "archive contains an invalid octal number")
        }
        return value
    }

    private static func metadataString(_ data: Data) throws -> String {
        let trimmed = data.prefix { $0 != 0 }
        guard let value = String(data: trimmed, encoding: .utf8), !value.isEmpty else {
            throw EngineError(.badRequest, "archive metadata string is invalid")
        }
        return value
    }

    private static func pax(
        _ data: Data,
        budget: inout Budget
    ) throws -> Overrides {
        var result = Overrides()
        var offset = 0
        while offset < data.count {
            try budget.consumeMetadata()
            guard let space = data[offset...].firstIndex(of: 0x20), space > offset,
                  let length = Int(String(decoding: data[offset..<space], as: UTF8.self)),
                  length > 0,
                  length <= data.count - offset else {
                throw EngineError(.badRequest, "archive PAX record is malformed")
            }
            let end = offset + length
            guard data[end - 1] == 0x0a,
                  let equals = data[(space + 1)..<(end - 1)].firstIndex(of: 0x3d) else {
                throw EngineError(.badRequest, "archive PAX record is malformed")
            }
            let key = String(decoding: data[(space + 1)..<equals], as: UTF8.self)
            if key.hasPrefix("GNU.sparse") || key.hasPrefix("SCHILY.dev") {
                throw EngineError(.badRequest, "archive sparse or special metadata is unsupported")
            }
            let valueBytes = data[(equals + 1)..<(end - 1)]
            func textValue() throws -> String {
                guard let value = String(data: valueBytes, encoding: .utf8) else {
                    throw EngineError(.badRequest, "archive PAX value is invalid UTF-8")
                }
                return value
            }
            switch key {
            case "path": result.path = try textValue()
            case "linkpath": result.link = try textValue()
            case "size":
                guard let size = try UInt64(textValue()) else {
                    throw EngineError(.badRequest, "archive PAX size is invalid")
                }
                result.size = size
            case "uid":
                guard let uid = try UInt64(textValue()) else {
                    throw EngineError(.badRequest, "archive PAX uid is invalid")
                }
                result.uid = uid
            case "gid":
                guard let gid = try UInt64(textValue()) else {
                    throw EngineError(.badRequest, "archive PAX gid is invalid")
                }
                result.gid = gid
            default:
                // PAX permits implementation-specific binary values (for
                // example SCHILY xattrs). They are ignored unless they alter a
                // security-relevant path, size, ownership, or sparse field.
                break
            }
            offset = end
        }
        return result
    }

    fileprivate static func safeComponents(
        _ path: String,
        policy: ArchivePolicy
    ) throws -> [String] {
        guard !path.isEmpty,
              !path.hasPrefix("/"),
              !path.utf8.contains(0),
              path.utf8.count <= policy.pathBytes else {
            throw EngineError(.badRequest, "archive contains an unsafe or overlong path")
        }
        var components: [String] = []
        for component in path.split(separator: "/", omittingEmptySubsequences: false) {
            if component.isEmpty || component == "." { continue }
            guard component != "..", !component.utf8.contains(0) else {
                throw EngineError(.badRequest, "archive contains a parent path component")
            }
            components.append(String(component))
        }
        guard components.count <= policy.depth else {
            throw EngineError(.payloadTooLarge, "archive path depth limit exceeded")
        }
        return components
    }

    private static func posixArchiveError() -> Error {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}
