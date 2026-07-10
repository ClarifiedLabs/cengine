import CEngineCore
import ContainerizationArchive
import CryptoKit
import Foundation

public enum KernelInstaller {
    public static let version = "3.28.0"
    public static let archiveURL = URL(string: "https://github.com/kata-containers/kata-containers/releases/download/3.28.0/kata-static-3.28.0-arm64.tar.zst")!
    public static let archiveSHA256 = "f63d54507d1f18635d94475077e4c2330de4d8e05cedf25f7c38f063b0e66a91"
    public static let archiveMember = "opt/kata/share/kata-containers/vmlinux-6.18.15-186"

    public static func install(to destination: URL) async throws {
        let (temporaryArchive, response) = try await URLSession.shared.download(from: archiveURL)
        guard let http = response as? HTTPURLResponse else {
            throw EngineError(.internalError, "Kata kernel download returned a non-HTTP response")
        }
        guard http.statusCode == 200 else {
            throw EngineError(.internalError, "Kata kernel download failed with HTTP \(http.statusCode) from \(archiveURL.absoluteString)")
        }
        guard try sha256(of: temporaryArchive) == archiveSHA256 else {
            throw EngineError(.internalError, "Kata kernel archive checksum mismatch")
        }

        try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        let temporaryKernel = destination.appendingPathExtension("installing")
        try? FileManager.default.removeItem(at: temporaryKernel)
        FileManager.default.createFile(atPath: temporaryKernel.path, contents: nil)
        do {
            let archive = try ArchiveReader(file: temporaryArchive)
            var iterator = archive.makeStreamingIterator()
            var found = false
            while let (entry, stream) = iterator.next() {
                guard entry.path == archiveMember || entry.path == "./\(archiveMember)" else { continue }
                let output = try FileHandle(forWritingTo: temporaryKernel)
                defer { try? output.close() }
                var buffer = [UInt8](repeating: 0, count: 1024 * 1024)
                while true {
                    let count = buffer.withUnsafeMutableBufferPointer {
                        guard let base = $0.baseAddress else { return 0 }
                        return stream.read(base, maxLength: $0.count)
                    }
                    guard count > 0 else { break }
                    try output.write(contentsOf: Data(buffer.prefix(count)))
                }
                found = true
                break
            }
            guard found else { throw EngineError(.internalError, "Kata archive does not contain \(archiveMember)") }
        } catch {
            try? FileManager.default.removeItem(at: temporaryKernel)
            throw error
        }
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.moveItem(at: temporaryKernel, to: destination)
    }

    private static func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hash = SHA256()
        while let data = try handle.read(upToCount: 1024 * 1024), !data.isEmpty { hash.update(data: data) }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
