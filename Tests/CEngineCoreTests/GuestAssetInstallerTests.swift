import CryptoKit
import Foundation
import Testing
import CEngineCore
@testable import CEngineRuntime

enum GuestAssetTestFixture {
    static func write(to directory: URL, prefix: String = "asset") throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for name in GuestAssetInstaller.names where name != GuestAssetInstaller.diskBootstrapMetadataName {
            try Data("\(prefix) \(name)".utf8).write(to: directory.appending(path: name))
        }
        let metadata: [String: Any] = [
            "schemaVersion": 1,
            "protocolVersion": 1,
            "storageServiceBootVersion": 2,
            "workloadStorageBootVersion": 1,
            "storageLifecycleVersion": 2,
            "containerInitramfsSHA256": try digest(directory.appending(path: "container-initramfs.cpio.gz")),
            "storageInitramfsSHA256": try digest(directory.appending(path: "storage-initramfs.cpio.gz")),
        ]
        try JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys])
            .write(to: directory.appending(path: GuestAssetInstaller.diskBootstrapMetadataName))
    }

    static func digest(_ file: URL) throws -> String {
        SHA256.hash(data: try Data(contentsOf: file)).map { String(format: "%02x", $0) }.joined()
    }
}

@Suite struct GuestAssetInstallerTests {
    @Test(arguments: ["storageServiceBootVersion", "workloadStorageBootVersion", "storageLifecycleVersion"])
    func managedModeRequiresBothExplicitSupportedVersions(field: String) throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root)
        let assets = paths.kernel.deletingLastPathComponent()
        try GuestAssetTestFixture.write(to: assets)
        let file = assets.appending(path: GuestAssetInstaller.diskBootstrapMetadataName)
        let base = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        var missing = base
        missing.removeValue(forKey: field)
        try JSONSerialization.data(withJSONObject: missing).write(to: file)
        #expect(!GuestAssetInstaller.isInstalled(paths: paths))
        #expect(throws: (any Error).self) {
            try GuestAssetInstaller.diskBootstrapMetadata(paths: paths)
        }
        for unsupported: Any in [NSNull(), 0, field == "workloadStorageBootVersion" ? 2 : 1, -1, true, "1"] {
            var metadata = base
            metadata["storageServiceBootVersion"] = 2
            metadata["workloadStorageBootVersion"] = 1
            metadata[field] = unsupported
            try JSONSerialization.data(withJSONObject: metadata).write(to: file)
            #expect(throws: (any Error).self) {
                try GuestAssetInstaller.diskBootstrapMetadata(paths: paths, requireManagedStorage: true)
            }
        }
        var valid = base
        valid["storageServiceBootVersion"] = 2
        valid["workloadStorageBootVersion"] = 1
        try JSONSerialization.data(withJSONObject: valid).write(to: file)
        let metadata = try GuestAssetInstaller.diskBootstrapMetadata(kernel: paths.kernel,
            containerInitialRamdisk: paths.containerInitialRamdisk,
            storageInitialRamdisk: paths.storageInitialRamdisk, requireManagedStorage: true)
        try metadata.requireManagedStorageSupport()
        #expect(metadata.storageServiceBootVersion == 2)
        #expect(metadata.workloadStorageBootVersion == 1)
        try Data("tampered".utf8).write(to: paths.containerInitialRamdisk)
        #expect(throws: (any Error).self) {
            try GuestAssetInstaller.diskBootstrapMetadata(paths: paths, requireManagedStorage: true)
        }
    }

    @Test func ordinaryProvenanceDoesNotOverrideLifecycleVersionRequirements() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root)
        let assets = paths.kernel.deletingLastPathComponent()
        try GuestAssetTestFixture.write(to: assets)
        let file = assets.appending(path: GuestAssetInstaller.diskBootstrapMetadataName)
        var metadata = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        // Runtime intentionally does not interpret this release-tooling receipt.
        metadata["ordinaryProvenance"] = ["schemaVersion": 1, "policy": "closed-ordinary-go-v1"]
        try JSONSerialization.data(withJSONObject: metadata).write(to: file)
        #expect(GuestAssetInstaller.isInstalled(paths: paths))
        try GuestAssetInstaller.diskBootstrapMetadata(paths: paths).requireLifecycleStorageSupport()
        metadata["storageServiceBootVersion"] = 1
        try JSONSerialization.data(withJSONObject: metadata).write(to: file)
        #expect(!GuestAssetInstaller.isInstalled(paths: paths))
        #expect(throws: (any Error).self) {
            try GuestAssetInstaller.diskBootstrapMetadata(paths: paths)
        }
    }

    @Test func ordinaryBuildMetadataInstallsAndSupportsManagedAndLifecycleStorage() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root)
        let assets = paths.kernel.deletingLastPathComponent()
        try GuestAssetTestFixture.write(to: assets)
        let file = assets.appending(path: GuestAssetInstaller.diskBootstrapMetadataName)
        var metadata = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        // Exact key set written by Scripts/build-guest-assets.sh ordinary builds.
        metadata["storageServiceBootVersion"] = 2
        metadata["workloadStorageBootVersion"] = 1
        metadata["storageLifecycleVersion"] = 2
        metadata["ordinaryProvenance"] = ["schemaVersion": 1, "policy": "closed-ordinary-go-v1"]
        try JSONSerialization.data(withJSONObject: metadata).write(to: file)
        #expect(GuestAssetInstaller.isInstalled(paths: paths))
        let decoded = try GuestAssetInstaller.diskBootstrapMetadata(paths: paths, requireManagedStorage: true)
        try decoded.requireManagedStorageSupport()
        try decoded.requireLifecycleStorageSupport()
        let destination = EnginePaths(home: root.appending(path: "ordinary"))
        try GuestAssetInstaller.install(paths: destination, source: assets)
        try GuestAssetInstaller.diskBootstrapMetadata(paths: destination, requireManagedStorage: true)
            .requireLifecycleStorageSupport()
        for unsupported: Any in [1, 3, "2"] {
            metadata["storageLifecycleVersion"] = unsupported
            try JSONSerialization.data(withJSONObject: metadata).write(to: file)
            #expect(throws: (any Error).self) {
                try GuestAssetInstaller.diskBootstrapMetadata(paths: paths).requireLifecycleStorageSupport()
            }
        }
    }

    private func lifecycleMetadata(_ fields: [String: Any] = [:]) throws -> GuestAssetInstaller.DiskBootstrapMetadata {
        var metadata: [String: Any] = [
            "schemaVersion": 1, "protocolVersion": 1, "storageLifecycleVersion": 2,
            "storageServiceBootVersion": 2, "workloadStorageBootVersion": 1,
            "containerInitramfsSHA256": String(repeating: "a", count: 64),
            "storageInitramfsSHA256": String(repeating: "b", count: 64),
        ]
        metadata.merge(fields) { _, value in value }
        return try JSONDecoder().decode(GuestAssetInstaller.DiskBootstrapMetadata.self,
            from: JSONSerialization.data(withJSONObject: metadata))
    }

    private var fullPrepareFields: [String: Any] {
        ["prepareCompatibilityProfile": ManagedPrepareCompatibilityProtocol.fullProfile,
         "prepareCompatibilitySourceSHA256": String(repeating: "c", count: 64)]
    }

    @Test func lifecyclePrepareFullRemainsRefusedByDefaultAndProductionPolicy() throws {
        let ordinary = try lifecycleMetadata()
        try ordinary.requireLifecycleStorageSupport()
        try ordinary.requireLifecycleStorageSupport(policy: .production)
        let full = try lifecycleMetadata(fullPrepareFields)
        #expect(throws: (any Error).self) { try full.requireLifecycleStorageSupport() }
        #expect(throws: (any Error).self) { try full.requireLifecycleStorageSupport(policy: .production) }
        // This pure selection check is not a native identity proof.
        try full.requireLifecycleStorageSelection(namespace: .compatibility)
        #expect(throws: (any Error).self) {
            try full.requireLifecycleStorageSelection(namespace: .production)
        }
    }

    @Test func lifecyclePrepareSelectionRejectsPartialUnknownOldAndQualificationProfiles() throws {
        let invalid: [[String: Any]] = [
            ["prepareCompatibilityProfile": ManagedPrepareCompatibilityProtocol.fullProfile],
            ["prepareCompatibilitySourceSHA256": String(repeating: "c", count: 64)],
            ["prepareCompatibilityProfile": "unknown"],
            ["prepareCompatibilityProfile": ManagedPrepareCompatibilityProtocol.profile],
            ["prepareCompatibilityProfile": ManagedPrepareCompatibilityProtocol.earlyProfile],
            ["prepareCompatibilitySourceSHA256": ""],
            ["prepareCompatibilitySourceSHA256": String(repeating: "C", count: 64)],
            ["prepareCompatibilitySourceSHA256": String(repeating: "g", count: 64)],
            ["prepareCompatibilitySourceSHA256": String(repeating: "c", count: 63)],
            ["storageServiceBootVersion": 1], ["storageServiceBootVersion": NSNull()],
            ["workloadStorageBootVersion": 2],
            ["storageLifecycleVersion": 1], ["storageLifecycleVersion": 3],
            ["storageLifecycleVersion": NSNull()],
            ["storageLifecycleQualification": "lifecycle-v2-native-v1"],
            ["storageLifecycleQualification": "unknown"],
        ]
        for (index, overrides) in invalid.enumerated() {
            // First two cases intentionally omit the other PREPARE field.
            let fields = index < 2 ? overrides : fullPrepareFields.merging(overrides) { _, value in value }
            let metadata = try lifecycleMetadata(fields)
            #expect(throws: (any Error).self) {
                try metadata.requireLifecycleStorageSelection(namespace: .compatibility)
            }
            #expect(throws: (any Error).self) { try metadata.requireLifecycleStorageSupport() }
        }
    }

    @Test func unsignedTestProcessCannotAuthorizeLifecyclePrepareAssets() throws {
        let full = try lifecycleMetadata(fullPrepareFields)
        // No test factory can mint a compatibility policy. The real signed positive
        // path is exercised by native RTM-096, not by a supplied namespace or Bool.
        #expect(throws: (any Error).self) {
            try full.requireLifecycleStorageSupport(policy: StorageLifecycleNativePolicy.current(role: .engine))
        }
    }

    @Test func malformedPrepareMetadataCannotInstallOrSelectLifecycleAssets() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root)
        let assets = paths.kernel.deletingLastPathComponent()
        try GuestAssetTestFixture.write(to: assets)
        let file = assets.appending(path: GuestAssetInstaller.diskBootstrapMetadataName)
        var base = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        base["storageLifecycleVersion"] = 2
        let invalid: [[String: Any]] = [
            ["prepareCompatibilityProfile": NSNull()],
            ["prepareCompatibilitySourceSHA256": NSNull()],
            ["prepareCompatibilityProfile": NSNull(), "prepareCompatibilitySourceSHA256": NSNull()],
            ["prepareCompatibilityProfile": ManagedPrepareCompatibilityProtocol.fullProfile],
            ["prepareCompatibilitySourceSHA256": String(repeating: "c", count: 64)],
            fullPrepareFields.merging(["prepareCompatibilityProfile": "unknown"]) { _, value in value },
            fullPrepareFields.merging(["prepareCompatibilitySourceSHA256": "bad-pin"]) { _, value in value },
        ]
        for fields in invalid {
            try JSONSerialization.data(withJSONObject: base.merging(fields) { _, value in value }).write(to: file)
            #expect(!GuestAssetInstaller.isInstalled(paths: paths))
            #expect(throws: (any Error).self) {
                try GuestAssetInstaller.diskBootstrapMetadata(paths: paths)
            }
            let destination = EnginePaths(home: root.appending(path: "rejected"))
            #expect(throws: (any Error).self) {
                try GuestAssetInstaller.install(paths: destination, source: assets)
            }
            #expect(!FileManager.default.fileExists(atPath: destination.kernel.path))
        }
    }

    @Test(arguments: ["storageLifecycleQualification", "storageLifecycleSourcePin"])
    func qualificationImagesNeverBecomeOrdinaryManagedAssets(field: String) throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root)
        let assets = paths.kernel.deletingLastPathComponent()
        try GuestAssetTestFixture.write(to: assets)
        let file = assets.appending(path: GuestAssetInstaller.diskBootstrapMetadataName)
        var metadata = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        metadata["storageServiceBootVersion"] = 2
        metadata["workloadStorageBootVersion"] = 1
        for value: Any in ["lifecycle-v2-native-v1", "unknown", "", NSNull()] {
            metadata[field] = value
            try JSONSerialization.data(withJSONObject: metadata).write(to: file)
            #expect(!GuestAssetInstaller.isInstalled(paths: paths))
            #expect(throws: (any Error).self) {
                try GuestAssetInstaller.diskBootstrapMetadata(paths: paths, requireManagedStorage: true)
            }
            let destination = EnginePaths(home: root.appending(path: "ordinary"))
            #expect(throws: (any Error).self) { try GuestAssetInstaller.install(paths: destination, source: assets) }
            #expect(!FileManager.default.fileExists(atPath: destination.kernel.path))
        }
    }

    @Test func installsMetadataAndReturnsExpectedDigestsForBothKinds() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appending(path: "source")
        let paths = EnginePaths(home: root.appending(path: "home"))
        try GuestAssetTestFixture.write(to: source)
        try GuestAssetInstaller.install(paths: paths, source: source)

        #expect(GuestAssetInstaller.isInstalled(paths: paths))
        let installed = paths.kernel.deletingLastPathComponent()
        #expect(try Data(contentsOf: installed.appending(path: "disk-bootstrap.json")) == Data(contentsOf: source.appending(path: "disk-bootstrap.json")))
        let metadata = try GuestAssetInstaller.diskBootstrapMetadata(paths: paths)
        #expect(metadata.schemaVersion == 1)
        #expect(metadata.protocolVersion == 1)
        #expect(try metadata.expectedInitramfsSHA256(for: .container) == GuestAssetTestFixture.digest(paths.containerInitialRamdisk))
        #expect(try metadata.expectedInitramfsSHA256(for: .storage) == GuestAssetTestFixture.digest(paths.storageInitialRamdisk))
    }

    @Test(arguments: ["missing", "malformed", "schema", "protocol", "missing-digest", "uppercase", "short", "nonhex", "null", "boolean-version"])
    func incompatibleMetadataNeverFallsBackToImagePresence(failure: String) throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root.appending(path: "home"))
        let assets = paths.kernel.deletingLastPathComponent()
        try GuestAssetTestFixture.write(to: assets)
        let file = assets.appending(path: "disk-bootstrap.json")
        var metadata = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        switch failure {
        case "missing": try FileManager.default.removeItem(at: file)
        case "malformed": try Data("not json".utf8).write(to: file)
        default:
            switch failure {
            case "schema": metadata["schemaVersion"] = 2
            case "protocol": metadata["protocolVersion"] = 2
            case "missing-digest": metadata.removeValue(forKey: "storageInitramfsSHA256")
            case "uppercase":
                let digest = try #require(metadata["containerInitramfsSHA256"] as? String)
                metadata["containerInitramfsSHA256"] = digest.uppercased()
            case "short": metadata["containerInitramfsSHA256"] = "abc"
            case "nonhex": metadata["storageInitramfsSHA256"] = String(repeating: "g", count: 64)
            case "null": metadata["storageInitramfsSHA256"] = NSNull()
            case "boolean-version": metadata["protocolVersion"] = true
            default: Issue.record("unknown fixture")
            }
            try JSONSerialization.data(withJSONObject: metadata).write(to: file)
        }
        #expect(!GuestAssetInstaller.isInstalled(paths: paths))
        #expect(GuestAssetInstaller.needsInstall(paths: paths, source: assets))
        #expect(throws: (any Error).self) { try GuestAssetInstaller.diskBootstrapMetadata(paths: paths) }
        let otherPaths = EnginePaths(home: root.appending(path: "other-home"))
        #expect(throws: (any Error).self) { try GuestAssetInstaller.install(paths: otherPaths, source: assets) }
        #expect(!FileManager.default.fileExists(atPath: otherPaths.kernel.path))
    }

    @Test(arguments: ["container-initramfs.cpio.gz", "storage-initramfs.cpio.gz"])
    func rejectsEitherTamperedImageAndPreservesInstalledAssets(name: String) throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root.appending(path: "home"))
        let assets = paths.kernel.deletingLastPathComponent()
        let source = root.appending(path: "source")
        try GuestAssetTestFixture.write(to: assets, prefix: "installed")
        try GuestAssetTestFixture.write(to: source, prefix: "new")
        let original = try Data(contentsOf: paths.kernel)
        try Data("tampered".utf8).write(to: source.appending(path: name))
        #expect(GuestAssetInstaller.needsInstall(paths: paths, source: source))
        #expect(throws: (any Error).self) { try GuestAssetInstaller.install(paths: paths, source: source) }
        #expect(try Data(contentsOf: paths.kernel) == original)
        #expect(GuestAssetInstaller.isInstalled(paths: paths))
        let siblings = try FileManager.default.contentsOfDirectory(atPath: assets.deletingLastPathComponent().path)
        #expect(!siblings.contains { $0.hasPrefix(".assets-") })

        try Data("tampered".utf8).write(to: assets.appending(path: name))
        #expect(!GuestAssetInstaller.isInstalled(paths: paths))
        #expect(throws: (any Error).self) { try GuestAssetInstaller.diskBootstrapMetadata(paths: paths) }
    }

    @Test(arguments: ["container-initramfs.cpio.gz", "storage-initramfs.cpio.gz"])
    func validatesExplicitOverridesAgainstInstalledMetadata(name: String) throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root.appending(path: "home"))
        let assets = paths.kernel.deletingLastPathComponent()
        try GuestAssetTestFixture.write(to: assets)
        let override = root.appending(path: "override")
        try FileManager.default.copyItem(at: assets.appending(path: name), to: override)
        let container = name.hasPrefix("container") ? override : paths.containerInitialRamdisk
        let storage = name.hasPrefix("storage") ? override : paths.storageInitialRamdisk
        let metadata = try GuestAssetInstaller.diskBootstrapMetadata(paths: paths, containerInitialRamdisk: container, storageInitialRamdisk: storage)
        #expect(metadata.protocolVersion == 1)
        try Data("old auto-format guest".utf8).write(to: override)
        #expect(throws: (any Error).self) {
            try GuestAssetInstaller.diskBootstrapMetadata(paths: paths, containerInitialRamdisk: container, storageInitialRamdisk: storage)
        }
        try FileManager.default.removeItem(at: override)
        #expect(throws: (any Error).self) {
            try GuestAssetInstaller.diskBootstrapMetadata(paths: paths, containerInitialRamdisk: container, storageInitialRamdisk: storage)
        }
    }

    @Test func overridesCannotSupplyTheirOwnMetadataOrBypassMissingInstalledMetadata() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root.appending(path: "home"))
        let assets = paths.kernel.deletingLastPathComponent()
        let overrides = root.appending(path: "overrides")
        try GuestAssetTestFixture.write(to: assets)
        try GuestAssetTestFixture.write(to: overrides, prefix: "old")
        let container = overrides.appending(path: "container-initramfs.cpio.gz")
        let storage = overrides.appending(path: "storage-initramfs.cpio.gz")
        #expect(throws: (any Error).self) {
            try GuestAssetInstaller.diskBootstrapMetadata(paths: paths, containerInitialRamdisk: container, storageInitialRamdisk: storage)
        }
        try GuestAssetTestFixture.write(to: overrides)
        try FileManager.default.removeItem(at: assets.appending(path: "disk-bootstrap.json"))
        #expect(throws: (any Error).self) {
            try GuestAssetInstaller.diskBootstrapMetadata(paths: paths, containerInitialRamdisk: container, storageInitialRamdisk: storage)
        }
    }

    @Test(arguments: ["duplicate", "missing-metadata", "malformed"])
    func invalidChecksumManifestsRequireReinstallAndFailWithoutCrashing(failure: String) throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root.appending(path: "home"))
        let assets = paths.kernel.deletingLastPathComponent()
        let source = root.appending(path: "source")
        try GuestAssetTestFixture.write(to: assets)
        try GuestAssetTestFixture.write(to: source)
        var lines = try GuestAssetInstaller.names.map { name in
            "\(try GuestAssetTestFixture.digest(source.appending(path: name)))  \(name)"
        }
        switch failure {
        case "duplicate": lines.append(lines[0])
        case "missing-metadata": lines.removeLast()
        default: lines[0] = "not a checksum"
        }
        try Data((lines.joined(separator: "\n") + "\n").utf8).write(to: source.appending(path: "SHA256SUMS"))
        #expect(GuestAssetInstaller.needsInstall(paths: paths, source: source))
        #expect(throws: (any Error).self) { try GuestAssetInstaller.install(paths: paths, source: source) }
        #expect(GuestAssetInstaller.isInstalled(paths: paths))
    }

    @Test func sourceLookupOnlyIgnoresGenuinelyAbsentSources() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let paths = EnginePaths(home: root.appending(path: "home"))
        try GuestAssetTestFixture.write(to: paths.kernel.deletingLastPathComponent())
        #expect(!GuestAssetInstaller.needsInstall(paths: paths, sourceLookup: {
            throw EngineError(.notFound, "no source directory")
        }))
        let old = root.appending(path: "old")
        try GuestAssetTestFixture.write(to: old)
        try FileManager.default.removeItem(at: old.appending(path: "disk-bootstrap.json"))
        #expect(GuestAssetInstaller.needsInstall(paths: paths, sourceLookup: {
            try GuestAssetInstaller.locateSourceDirectory(environment: ["CENGINE_GUEST_ASSET_DIR": old.path], executable: nil, resources: nil)
        }))
    }

    @Test func explicitAndBundledOldAssetsDoNotFallBackToAnotherSource() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let old = root.appending(path: "old")
        let resources = root.appending(path: "Resources")
        let guest = resources.appending(path: "guest")
        let executable = root.appending(path: "bin/cengine")
        let share = root.appending(path: "share/cengine")
        try GuestAssetTestFixture.write(to: old)
        try FileManager.default.removeItem(at: old.appending(path: "disk-bootstrap.json"))
        try GuestAssetTestFixture.write(to: guest)
        try GuestAssetTestFixture.write(to: share)
        #expect(throws: (any Error).self) {
            try GuestAssetInstaller.locateSourceDirectory(environment: ["CENGINE_GUEST_ASSET_DIR": old.path], executable: executable, resources: resources)
        }
        #expect(try GuestAssetInstaller.locateSourceDirectory(environment: [:], executable: executable, resources: resources).path == guest.path)
        try FileManager.default.removeItem(at: guest.appending(path: "disk-bootstrap.json"))
        #expect(throws: (any Error).self) {
            try GuestAssetInstaller.locateSourceDirectory(environment: [:], executable: executable, resources: resources)
        }
    }
}
