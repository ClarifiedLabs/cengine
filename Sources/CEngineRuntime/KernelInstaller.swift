import CEngineCore
import ContainerizationArchive
import CryptoKit
import Foundation

public enum KernelInstaller {
    public static let version = "3.32.0"
    public static let archiveURL = URL(string: "https://github.com/kata-containers/kata-containers/releases/download/3.32.0/kata-static-3.32.0-arm64.tar.zst")!
    public static let archiveSHA256 = "8736c054d9223974735394f822000823baef509e1c33405ec798240fa9b6e4b5"
    public static let archiveMember = "opt/kata/share/kata-containers/vmlinux-6.18.35-197"
    public static let kernelSHA256 = "f437320bab94f19105d12b932aa29735f0d54d2588218872254367f312c1027c"

    public static func isInstalled(at destination: URL) -> Bool {
        guard FileManager.default.fileExists(atPath: destination.path) else { return false }
        return (try? sha256(of: destination)) == kernelSHA256
    }

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

    static func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hash = SHA256()
        while let data = try handle.read(upToCount: 1024 * 1024), !data.isEmpty { hash.update(data: data) }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
