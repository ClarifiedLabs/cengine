import CEngineCore
import CryptoKit
import Foundation

public enum GuestAssetInstaller {
    public static let diskBootstrapMetadataName = "disk-bootstrap.json"
    public static let names = ["vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz", diskBootstrapMetadataName]

    public struct DiskBootstrapMetadata: Decodable, Sendable, Equatable {
        public let schemaVersion: Int
        public let protocolVersion: Int
        public let storageServiceBootVersion: Int?
        public let workloadStorageBootVersion: Int?
        public var prepareCompatibilityProfile: String? = nil
        public var prepareCompatibilitySourceSHA256: String? = nil
        /// Storage ownership protocol version supported by the storage initramfs.
        /// Required for startup.
        public var storageLifecycleVersion: Int? = nil
        /// Qualification-only assets; never accepted as production capability.
        public var storageLifecycleQualification: String? = nil

        public func requireLifecycleStorageSupport() throws {
            try requireLifecycleStorageSelection(namespace: .production)
        }

        /// PREPARE assets require the actual ordinary signed compatibility engine,
        /// not an environment assertion or a qualification namespace alone.
        public func requireLifecycleStorageSupport(policy: StorageLifecycleNativePolicy) throws {
            guard !policy.isQualification else { throw ManagedPrepareCompatibilityProtocol.Failure.unsupported }
            try requireLifecycleStorageSelection(namespace: policy.namespace)
            if prepareCompatibilityProfile != nil {
                _ = try policy.currentIdentity(role: .engine)
            }
        }

        /// Pure rejection seam only; selecting a namespace never authenticates it.
        func requireLifecycleStorageSelection(namespace: SignedStorageIdentity.Namespace) throws {
            try requireManagedStorageSupport()
            try ManagedPrepareCompatibilityProtocol.validateProfile(prepareCompatibilityProfile,
                sourceSHA256: prepareCompatibilitySourceSHA256)
            guard storageLifecycleVersion == 2, storageLifecycleQualification == nil,
                  prepareCompatibilityProfile == nil ||
                    (namespace == .compatibility && prepareCompatibilityProfile == ManagedPrepareCompatibilityProtocol.fullProfile) else {
                throw EngineError(.unsupported, "guest assets do not match this engine's storage profile; rebuild paired guest assets (storageLifecycleVersion must be 2; qualification assets are not accepted; PREPARE full-v3 requires the signed compatibility engine)")
            }
        }

        /// Checks that both guest images support the required storage protocols.
        public func requireManagedStorageSupport() throws {
            guard schemaVersion == 1, protocolVersion == 1, storageLifecycleVersion == 2,
                  storageServiceBootVersion == 2, workloadStorageBootVersion == 1 else {
                throw EngineError(.unsupported, "managed storage requires storageLifecycleVersion 2, storageServiceBootVersion 2 and workloadStorageBootVersion 1 in disk-bootstrap.json; rebuild paired guest assets")
            }
        }
        public let containerInitramfsSHA256: String
        public let storageInitramfsSHA256: String

        public func expectedInitramfsSHA256(for kind: VMShimProtocol.Specification.Kind) -> String {
            switch kind {
            case .container: containerInitramfsSHA256
            case .storage: storageInitramfsSHA256
            }
        }
    }

    /// Validates both selected images against installed metadata, including explicit overrides.
    /// The shim must also hash the same pinned initramfs descriptor it supplies to VZ before start.
    public static func diskBootstrapMetadata(
        paths: EnginePaths,
        containerInitialRamdisk: URL? = nil,
        storageInitialRamdisk: URL? = nil,
        requireManagedStorage: Bool = false
    ) throws -> DiskBootstrapMetadata {
        try validatedDiskBootstrapMetadata(
            directory: paths.kernel.deletingLastPathComponent(),
            containerInitialRamdisk: containerInitialRamdisk ?? paths.containerInitialRamdisk,
            storageInitialRamdisk: storageInitialRamdisk ?? paths.storageInitialRamdisk,
            requireManagedStorage: requireManagedStorage
        )
    }

    /// URL-based variant for backends selecting explicit guest assets. Metadata
    /// stays beside the selected kernel, never beside an initramfs override.
    public static func diskBootstrapMetadata(
        kernel: URL,
        containerInitialRamdisk: URL,
        storageInitialRamdisk: URL,
        requireManagedStorage: Bool = false
    ) throws -> DiskBootstrapMetadata {
        try validatedDiskBootstrapMetadata(
            directory: kernel.deletingLastPathComponent(),
            containerInitialRamdisk: containerInitialRamdisk,
            storageInitialRamdisk: storageInitialRamdisk,
            requireManagedStorage: requireManagedStorage
        )
    }

    public static func isInstalled(paths: EnginePaths) -> Bool {
        installedFiles(paths: paths).allSatisfy(isNonemptyRegularFile) && (try? diskBootstrapMetadata(paths: paths)) != nil
    }

    public static func needsInstall(paths: EnginePaths, source: URL? = nil) -> Bool {
        needsInstall(paths: paths, sourceLookup: { try source ?? locateSourceDirectory() })
    }

    static func needsInstall(paths: EnginePaths, sourceLookup: () throws -> URL) -> Bool {
        guard isInstalled(paths: paths) else { return true }
        do {
            return !matchesSource(paths: paths, source: try sourceLookup())
        } catch let error as EngineError where error.code == .notFound {
            // A valid installation can run without any bundled source directory.
            return false
        } catch {
            // An explicitly selected but incompatible source must not be ignored.
            return true
        }
    }

    static func matchesSource(paths: EnginePaths, source: URL) -> Bool {
        guard isInstalled(paths: paths), (try? validatedDiskBootstrapMetadata(directory: source)) != nil else { return false }
        let manifestFile = source.appending(path: "SHA256SUMS")
        let manifest: [String: String]
        if FileManager.default.fileExists(atPath: manifestFile.path) {
            guard let text = try? String(contentsOf: manifestFile, encoding: .utf8),
                  let parsed = try? digests(fromManifest: text), names.allSatisfy({ parsed[$0] != nil }) else { return false }
            manifest = parsed
        } else {
            manifest = [:]
        }
        for (name, installed) in zip(names, installedFiles(paths: paths)) {
            let expected = manifest[name]?.lowercased() ?? (try? digest(of: source.appending(path: name)))
            guard let expected, let actual = try? digest(of: installed), actual == expected else { return false }
        }
        return true
    }

    public static func install(paths: EnginePaths, source: URL? = nil) throws {
        let source = try source ?? locateSourceDirectory()
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
            try validateSourceDirectory(staging)
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
            let directory = URL(filePath: configured, directoryHint: .isDirectory)
            try validateSourceDirectory(directory)
            return directory
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
            names.contains { FileManager.default.fileExists(atPath: directory.appending(path: $0).path) }
        }) {
            try validateSourceDirectory(found)
            return found
        }
        throw EngineError(.notFound, "cengine guest assets were not found; run `make guest-assets` or install vmlinux, both initramfs files and disk-bootstrap.json under share/cengine")
    }

    private static func verify(directory: URL, manifest: String) throws {
        let expected = try digests(fromManifest: manifest)
        for name in names {
            guard let digest = expected[name] else { throw EngineError(.badRequest, "SHA256SUMS does not contain \(name)") }
            guard try self.digest(of: directory.appending(path: name)) == digest.lowercased() else {
                throw EngineError(.badRequest, "checksum mismatch for guest asset \(name)")
            }
        }
    }

    private static func installedFiles(paths: EnginePaths) -> [URL] {
        [paths.kernel, paths.containerInitialRamdisk, paths.storageInitialRamdisk,
         paths.kernel.deletingLastPathComponent().appending(path: diskBootstrapMetadataName)]
    }

    private static func isNonemptyRegularFile(_ file: URL) -> Bool {
        guard let values = try? file.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]) else { return false }
        return values.isRegularFile == true && (values.fileSize ?? 0) > 0
    }

    private static func validateSourceDirectory(_ directory: URL) throws {
        for name in names where !isNonemptyRegularFile(directory.appending(path: name)) {
            throw EngineError(.badRequest, "guest asset \(name) is missing or empty in \(directory.path); rebuild guest assets")
        }
        _ = try validatedDiskBootstrapMetadata(directory: directory)
    }

    private static func validatedDiskBootstrapMetadata(
        directory: URL,
        containerInitialRamdisk: URL? = nil,
        storageInitialRamdisk: URL? = nil,
        requireManagedStorage: Bool = false
    ) throws -> DiskBootstrapMetadata {
        let file = directory.appending(path: diskBootstrapMetadataName)
        guard isNonemptyRegularFile(file),
              let data = try? Data(contentsOf: file),
              let metadata = try? JSONDecoder().decode(DiskBootstrapMetadata.self, from: data),
              metadata.schemaVersion == 1, metadata.protocolVersion == 1,
              isSHA256(metadata.containerInitramfsSHA256), isSHA256(metadata.storageInitramfsSHA256) else {
            throw EngineError(.badRequest, "missing or incompatible disk-bootstrap.json in \(directory.path); rebuild guest assets")
        }
        // Qualification has separate signed policy, even with the same lifecycle wire versions.
        // Reject presence, including null/partial/unknown fields ignored by Decodable.
        let fields = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard fields?["storageLifecycleQualification"] == nil,
              fields?["storageLifecycleSourcePin"] == nil else {
            throw EngineError(.unsupported, "lifecycle qualification guest assets cannot be used by the ordinary guest installer or managed runtime")
        }
        if fields?["prepareCompatibilityProfile"] != nil || fields?["prepareCompatibilitySourceSHA256"] != nil {
            guard fields?["prepareCompatibilityProfile"] is String,
                  fields?["prepareCompatibilitySourceSHA256"] is String else {
                throw ManagedPrepareCompatibilityProtocol.Failure.unsupported
            }
        }
        try ManagedPrepareCompatibilityProtocol.validateProfile(metadata.prepareCompatibilityProfile, sourceSHA256: metadata.prepareCompatibilitySourceSHA256)
        for (image, expected) in [
            (containerInitialRamdisk ?? directory.appending(path: "container-initramfs.cpio.gz"), metadata.containerInitramfsSHA256),
            (storageInitialRamdisk ?? directory.appending(path: "storage-initramfs.cpio.gz"), metadata.storageInitramfsSHA256),
        ] {
            guard isNonemptyRegularFile(image), try digest(of: image) == expected else {
                throw EngineError(.badRequest, "disk bootstrap checksum mismatch for guest asset \(image.path)")
            }
        }
        // No ordinary installation or lookup may retain legacy/v1 storage assets.
        try metadata.requireManagedStorageSupport()
        return metadata
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func digests(fromManifest manifest: String) throws -> [String: String] {
        var digests: [String: String] = [:]
        for line in manifest.split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count == 2, isSHA256(String(fields[0]).lowercased()) else {
                throw EngineError(.badRequest, "invalid guest asset SHA256SUMS entry")
            }
            let name = String(fields[1]).trimmingCharacters(in: CharacterSet(charactersIn: "*"))
            guard digests.updateValue(String(fields[0]).lowercased(), forKey: name) == nil else {
                throw EngineError(.badRequest, "duplicate guest asset SHA256SUMS entry for \(name)")
            }
        }
        return digests
    }

    private static func digest(of file: URL) throws -> String {
        let data = try Data(contentsOf: file, options: .mappedIfSafe)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
