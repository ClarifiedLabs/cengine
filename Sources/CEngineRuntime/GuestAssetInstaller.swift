import CEngineCore
import CryptoKit
import Foundation

public enum GuestAssetInstaller {
    public static let names = ["vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz"]

    public static func isInstalled(paths: EnginePaths) -> Bool {
        [paths.kernel, paths.containerInitialRamdisk, paths.storageInitialRamdisk].allSatisfy {
            guard let values = try? $0.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]) else { return false }
            return values.isRegularFile == true && (values.fileSize ?? 0) > 0
        }
    }

    public static func install(paths: EnginePaths) throws {
        let source = try locateSourceDirectory()
        let destination = paths.kernel.deletingLastPathComponent()
        let staging = destination.deletingLastPathComponent().appending(path: ".assets-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
        do {
            for name in names {
                let input = source.appending(path: name)
                guard FileManager.default.fileExists(atPath: input.path) else {
                    throw EngineError(.notFound, "guest asset \(name) is missing from \(source.path)")
                }
                try FileManager.default.copyItem(at: input, to: staging.appending(path: name))
            }
            let manifest = source.appending(path: "SHA256SUMS")
            if FileManager.default.fileExists(atPath: manifest.path) {
                try verify(directory: staging, manifest: String(contentsOf: manifest, encoding: .utf8))
            }
            if FileManager.default.fileExists(atPath: destination.path) {
                _ = try FileManager.default.replaceItemAt(destination, withItemAt: staging)
            } else {
                try FileManager.default.moveItem(at: staging, to: destination)
            }
        } catch {
            try? FileManager.default.removeItem(at: staging)
            throw error
        }
    }

    public static func locateSourceDirectory(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        executable: URL? = Bundle.main.executableURL,
        resources: URL? = Bundle.main.resourceURL
    ) throws -> URL {
        var candidates: [URL] = []
        if let configured = environment["CENGINE_GUEST_ASSET_DIR"] {
            candidates.append(URL(filePath: configured, directoryHint: .isDirectory))
        }
        if let resources { candidates.append(resources.appending(path: "guest", directoryHint: .isDirectory)) }
        if let executable {
            let bin = executable.deletingLastPathComponent()
            candidates.append(bin.deletingLastPathComponent().appending(path: "Resources/guest", directoryHint: .isDirectory))
            candidates.append(bin.appending(path: "share/cengine", directoryHint: .isDirectory))
            candidates.append(bin.deletingLastPathComponent().appending(path: "share/cengine", directoryHint: .isDirectory))
            candidates.append(bin.appending(path: "../share/cengine", directoryHint: .isDirectory).standardizedFileURL)
        }
        candidates.append(URL(filePath: FileManager.default.currentDirectoryPath).appending(path: ".build/guest", directoryHint: .isDirectory))
        if let found = candidates.first(where: { directory in
            names.allSatisfy { FileManager.default.fileExists(atPath: directory.appending(path: $0).path) }
        }) { return found }
        throw EngineError(.notFound, "cengine guest assets were not found; run `make guest-assets` or install vmlinux and both initramfs files under share/cengine")
    }

    private static func verify(directory: URL, manifest: String) throws {
        let expected = Dictionary(uniqueKeysWithValues: manifest.split(whereSeparator: \.isNewline).compactMap { line -> (String, String)? in
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 2 else { return nil }
            return (String(fields[1]).trimmingCharacters(in: CharacterSet(charactersIn: "*")), String(fields[0]))
        })
        for name in names {
            guard let digest = expected[name] else { throw EngineError(.badRequest, "SHA256SUMS does not contain \(name)") }
            let data = try Data(contentsOf: directory.appending(path: name), options: .mappedIfSafe)
            let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            guard actual == digest.lowercased() else { throw EngineError(.badRequest, "checksum mismatch for guest asset \(name)") }
        }
    }
}
