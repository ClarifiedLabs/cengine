import CEngineCore
import Foundation

enum SystemTar {
    static func ownership(in archive: Data) throws -> [ArchiveOwnership] {
        var result: [ArchiveOwnership] = []; var offset = 0
        while offset + 512 <= archive.count {
            let header = archive.subdata(in: offset..<(offset + 512)); if header.allSatisfy({ $0 == 0 }) { break }
            let name = field(header, 0, 100); let prefix = field(header, 345, 155); let path = prefix.isEmpty ? name : prefix + "/" + name
            guard let size = octal(header, 124, 12), let uid = octal(header, 108, 8), let gid = octal(header, 116, 8) else { throw EngineError(.badRequest, "invalid tar numeric field") }
            if !path.isEmpty { result.append(.init(path: path, user: UInt32(clamping: uid), group: UInt32(clamping: gid))) }
            offset += 512 + ((size + 511) / 512) * 512
        }
        return result
    }
    static func extract(_ archive: URL, to destination: URL) throws {
        let listing = try run(["-tf", archive.path], captureOutput: true)
        let unsafe = String(decoding: listing, as: UTF8.self).split(whereSeparator: \.isNewline).map(String.init).filter { path in
            path.hasPrefix("/") || path.split(separator: "/").contains("..") || path.utf8.contains(0)
        }
        guard unsafe.isEmpty else { throw EngineError(.badRequest, "archive contains unsafe paths: \(unsafe.joined(separator: ", "))") }
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        _ = try run(["-xpf", archive.path, "-C", destination.path], captureOutput: false)
    }

    static func create(from directory: URL, at archive: URL) throws {
        _ = try run(["-cpf", archive.path, "-C", directory.path, "."], captureOutput: false)
    }

    @discardableResult private static func run(_ arguments: [String], captureOutput: Bool) throws -> Data {
        let process = Process(); process.executableURL = URL(filePath: "/usr/bin/tar"); process.arguments = arguments
        var environment = ProcessInfo.processInfo.environment
        environment["COPYFILE_DISABLE"] = "1"
        process.environment = environment
        let output = Pipe(); let errors = Pipe(); process.standardError = errors
        if captureOutput { process.standardOutput = output }
        try process.run()
        let data = captureOutput ? output.fileHandleForReading.readDataToEndOfFile() : Data()
        let errorData = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw EngineError(.badRequest, "invalid tar archive: \(String(decoding: errorData, as: UTF8.self))") }
        return data
    }

    private static func field(_ data: Data, _ offset: Int, _ length: Int) -> String {
        let bytes = data[offset..<(offset + length)].prefix { $0 != 0 }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func octal(_ data: Data, _ offset: Int, _ length: Int) -> Int? {
        let value = field(data, offset, length).trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? 0 : Int(value, radix: 8)
    }
}
