import CEngineCore
import Darwin
import Foundation

enum OCIArchive {
    static func tar(entries: [(String, Data)]) -> Data {
        var archive = Data()
        for (name, contents) in entries.sorted(by: { $0.0 < $1.0 }) {
            guard let header = try? header(name: name, size: UInt64(contents.count)) else {
                return Data()
            }
            archive.append(header)
            archive.append(contents)
            if contents.count % 512 != 0 {
                archive.append(Data(repeating: 0, count: 512 - contents.count % 512))
            }
        }
        archive.append(Data(repeating: 0, count: 1_024))
        return archive
    }

    static func write(
        dataEntries: [(String, Data)],
        blobEntries: [(String, OCIDescriptor)],
        to destination: URL,
        policy: ArchivePolicy = .default,
        copyBlob: (OCIDescriptor, FileHandle) throws -> Void
    ) throws {
        let descriptor = Darwin.open(
            destination.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode_t(0o600)
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let output = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var outputBytes: UInt64 = 0
        func append(_ data: Data) throws {
            do { outputBytes = try CheckedArithmetic.add(outputBytes, UInt64(data.count)) }
            catch { throw EngineError(.payloadTooLarge, "archive output size overflows") }
            guard outputBytes <= policy.outputBytes else {
                throw EngineError(.payloadTooLarge, "archive output exceeds its size limit")
            }
            try output.write(contentsOf: data)
        }
        func writePadding(for size: UInt64) throws {
            let aligned: UInt64
            do { aligned = try CheckedArithmetic.alignedToTarBlock(size) }
            catch { throw EngineError(.payloadTooLarge, "archive output alignment overflows") }
            let count = Int(aligned - size)
            if count > 0 { try append(Data(repeating: 0, count: count)) }
        }
        do {
            enum Source {
                case data(Data)
                case blob(OCIDescriptor)
            }
            var entries: [(String, UInt64, Source)] = dataEntries.map {
                ($0.0, UInt64($0.1.count), .data($0.1))
            }
            entries.append(contentsOf: try blobEntries.map { name, descriptor in
                let validated = try descriptor.validated(errorCode: .internalError)
                return (name, validated.size, .blob(descriptor))
            })
            guard entries.count <= policy.entries else {
                throw EngineError(.payloadTooLarge, "archive output entry limit exceeded")
            }
            for (name, size, source) in entries.sorted(by: { $0.0 < $1.0 }) {
                guard size <= policy.fileBytes else {
                    throw EngineError(.payloadTooLarge, "archive output file exceeds its size limit")
                }
                try append(header(name: name, size: size))
                let before = outputBytes
                switch source {
                case .data(let data):
                    try append(data)
                case .blob(let blob):
                    // The callback streams directly to the owner-only output.
                    // Charge the declared bytes before the copy and verify the
                    // file offset afterwards so a callback cannot bypass quota.
                    do { outputBytes = try CheckedArithmetic.add(outputBytes, size) }
                    catch { throw EngineError(.payloadTooLarge, "archive output size overflows") }
                    guard outputBytes <= policy.outputBytes else {
                        throw EngineError(.payloadTooLarge, "archive output exceeds its size limit")
                    }
                    try copyBlob(blob, output)
                }
                let expected = try CheckedArithmetic.add(before, size)
                guard outputBytes == expected else {
                    throw EngineError(.internalError, "archive writer byte accounting mismatch")
                }
                try writePadding(for: size)
            }
            try append(Data(repeating: 0, count: 1_024))
            try output.synchronize()
            try output.close()
        } catch {
            try? output.close()
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    private static func header(name: String, size: UInt64) throws -> Data {
        guard !name.hasPrefix("/"), !name.utf8.contains(0), name.utf8.count <= 255 else {
            throw EngineError(.internalError, "OCI archive path is not representable")
        }
        let fields = try ustarName(name)
        var header = Data(repeating: 0, count: 512)
        write(fields.name, to: &header, offset: 0, length: 100)
        writeOctal(0o644, to: &header, offset: 100, length: 8)
        writeOctal(0, to: &header, offset: 108, length: 8)
        writeOctal(0, to: &header, offset: 116, length: 8)
        try writeOctal(size, to: &header, offset: 124, length: 12)
        writeOctal(0, to: &header, offset: 136, length: 12)
        for index in 148..<156 { header[index] = 0x20 }
        header[156] = Character("0").asciiValue!
        write("ustar", to: &header, offset: 257, length: 6)
        write("00", to: &header, offset: 263, length: 2)
        write(fields.prefix, to: &header, offset: 345, length: 155)
        let checksum = header.reduce(0) { $0 + UInt64($1) }
        try writeOctal(checksum, to: &header, offset: 148, length: 8, checksum: true)
        return header
    }

    private static func ustarName(_ path: String) throws -> (name: String, prefix: String) {
        if path.utf8.count <= 100 { return (path, "") }
        let components = path.split(separator: "/")
        for split in stride(from: components.count - 1, through: 1, by: -1) {
            let prefix = components[..<split].joined(separator: "/")
            let name = components[split...].joined(separator: "/")
            if prefix.utf8.count <= 155, name.utf8.count <= 100 {
                return (name, prefix)
            }
        }
        throw EngineError(.internalError, "OCI archive path cannot be represented by ustar")
    }

    private static func write(
        _ value: String,
        to data: inout Data,
        offset: Int,
        length: Int
    ) {
        let bytes = Array(value.utf8.prefix(max(0, length - 1)))
        data.replaceSubrange(offset..<(offset + bytes.count), with: bytes)
    }

    private static func writeOctal(
        _ value: Int,
        to data: inout Data,
        offset: Int,
        length: Int
    ) {
        write(String(format: "%0*o", length - 1, value), to: &data, offset: offset, length: length)
    }

    private static func writeOctal(
        _ value: UInt64,
        to data: inout Data,
        offset: Int,
        length: Int,
        checksum: Bool = false
    ) throws {
        let digits = checksum ? length - 2 : length - 1
        let text = String(value, radix: 8)
        guard text.count <= digits else {
            throw EngineError(.payloadTooLarge, "OCI archive numeric field overflows ustar")
        }
        let encoded = String(repeating: "0", count: digits - text.count) + text
            + (checksum ? "\0 " : "\0")
        let bytes = Data(encoded.utf8)
        guard bytes.count == length else {
            throw EngineError(.internalError, "OCI archive numeric encoding failed")
        }
        data.replaceSubrange(offset..<(offset + length), with: bytes)
    }
}
