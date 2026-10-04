#if os(macOS) && CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import CEngineRuntime

/// Unsigned rejection/closed-wire tests only. None constitutes native acceptance,
/// Guest startup, ROOT authentication, or lifecycle qualification evidence.
@Suite struct StorageLifecycleQualificationShimTests {

    // Real descriptor observation for these metadata-only specifications; it is
    // not evidence that the synthetic bootstrap locator names this file.
    private func observedBackingIdentity() throws -> VMShimProtocol.FileIdentity {
        let file = try FileHandle(forReadingFrom: URL(filePath: #filePath))
        defer { try? file.close() }
        let observed = try PersistentFileIdentity.capture(descriptor: file.fileDescriptor)
        return .init(device: observed.device, inode: observed.inode, volumeUUID: observed.volumeUUID)
    }

    private func fixture() throws -> StorageLifecycleShimBootstrap {
        let filesystem = try StorageIdentity.FilesystemUUID("00000000-0000-4000-8000-000000000001")
        let root = try StorageIdentity.RootIdentity(volumeUUID: filesystem, inode: 2)
        let observed = try observedBackingIdentity()
        let backing = try StorageIdentity.BackingIdentity(identity: .init(
            volumeUUID: .init(#require(observed.volumeUUID).uuidString.lowercased()), inode: observed.inode), size: 16 << 20)
        let binding = StorageIdentity.StoreBinding(storeID: try .init("00000000-0000-4000-8000-000000000002"),
            root: root, backing: backing, expectedExt4UUID: filesystem)
        return .init(profile: "lifecycle-v2-native-v1", rootPublicKey: Data(repeating: 7, count: 32),
            binding: .init(binding), storeRoot: "/private/tmp/lifecycle-store",
            backingFile: "/private/tmp/lifecycle-store/disk.raw", kernel: "/private/tmp/assets/vmlinux",
            initialRamdisk: "/private/tmp/assets/storage-initramfs.cpio.gz",
            initramfsSHA256: String(repeating: "a", count: 64), kernelSHA256: String(repeating: "b", count: 64),
            launchUUID: "00000000-0000-4000-8000-000000000003")
    }

    @Test func bootstrapCannotSelectGeneralVMConfiguration() throws {
        let frozen = try fixture()
        let bytes = try StorageLifecycleProtocol.encode(frozen)
        let decoded = try StorageLifecycleShimBootstrap.decode(bytes)
        let spec = try decoded.specification(backingIdentity: observedBackingIdentity())
        #expect(spec.kind == .storage)
        #expect(spec.workloadStorageMode == .none)
        #expect(spec.volumeDisks.isEmpty && spec.bindShares.isEmpty && spec.socketRelays.isEmpty)
        #expect(spec.kernelArguments == ["cengine.management_address=192.0.2.2/30", "cengine.management_vlan=4094"])
        #expect(!spec.rosetta && !spec.rootDiskReadOnly)
        #expect(spec.cpus == 2 && spec.memoryBytes == 512 << 20)
        #expect(spec.networkSocketPath == nil)
        #expect(spec.diskBootstrapVersion == 1 && spec.shimLaunchUUID == frozen.launchUUID)
        #expect(decoded.rootPublicKey == frozen.rootPublicKey)
        #expect(try decoded.binding.value() == frozen.binding.value())
        // The decoded record is metadata and cannot become an existing proof type.
        #expect(!(decoded as Any is RawDiskBootTransaction.VerifiedStorageDiskBoot))
    }

    @Test func durableBootstrapUsesFreshLiveDeviceForEachLaunch() throws {
        let frozen = try fixture()
        let bytes = try StorageLifecycleProtocol.encode(frozen)
        let decoded = try StorageLifecycleShimBootstrap.decode(bytes)
        let before = try observedBackingIdentity()
        let remounted = VMShimProtocol.FileIdentity(device: before.device + 1,
            inode: before.inode, volumeUUID: before.volumeUUID)
        let first = try decoded.specification(backingIdentity: before)
        let second = try decoded.specification(backingIdentity: remounted)
        #expect(first.rootDiskIdentity?.device == before.device)
        #expect(second.rootDiskIdentity?.device == remounted.device)
        #expect(try StorageLifecycleProtocol.encode(decoded) == bytes)
        for foreign in [
            VMShimProtocol.FileIdentity(device: remounted.device, inode: before.inode + 1, volumeUUID: before.volumeUUID),
            VMShimProtocol.FileIdentity(device: remounted.device, inode: before.inode, volumeUUID: UUID()),
            VMShimProtocol.FileIdentity(device: remounted.device, inode: before.inode, volumeUUID: nil)
        ] {
            #expect(throws: (any Error).self) { try decoded.specification(backingIdentity: foreign) }
        }
    }

    @Test func bootstrapSuppliesRequiredPrivateGuestManagementSettings() throws {
        let specification = try fixture().specification(backingIdentity: observedBackingIdentity())
        let arguments = try VMShimServer.bootstrapKernelArguments(specification)
        // PID1 requires these before calling RunLifecycle/opening port 4106,
        // even though qualification uses only private VSOCK, not DATA traffic.
        #expect(arguments == ["cengine.management_address=192.0.2.2/30",
                              "cengine.management_vlan=4094", "cengine.storage_mode=lifecycle"])
        #expect(RawVirtualMachineConfiguration.kernelCommandLine(id: specification.containerID,
            kernelArguments: arguments).split(separator: " ").contains("cengine.management_address=192.0.2.2/30"))
        #expect(specification.networkSocketPath == nil && specification.socketRelays.isEmpty)
    }

    @Test func privateInitramfsPreservesInitialPinnedDigestGuard() throws {
        let frozen = try fixture()
        var specification = try frozen.specification(backingIdentity: observedBackingIdentity())
        #expect(try StorageLifecycleQualificationShim.bootstrapInitramfsExpectedDigest(specification) == frozen.initramfsSHA256)
        for hash: String? in [nil, "", String(repeating: "A", count: 64), String(repeating: "a", count: 63)] {
            specification.expectedInitramfsSHA256 = hash
            #expect(throws: (any Error).self) { try StorageLifecycleQualificationShim.bootstrapInitramfsExpectedDigest(specification) }
        }
        specification.expectedInitramfsSHA256 = frozen.initramfsSHA256
        specification.diskBootstrapVersion = 2
        #expect(throws: (any Error).self) { try StorageLifecycleQualificationShim.bootstrapInitramfsExpectedDigest(specification) }
    }

    @Test func unknownFieldsDuplicateKeysAndNoncanonicalWireAreRejected() throws {
        let bytes = try StorageLifecycleProtocol.encode(fixture())
        var fields = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        for field in ["policy", "executable", "environment", "specification", "rootReplacement", "cpus", "kernelArguments", "managementAddress", "managementVLAN"] {
            var changed = fields; changed[field] = "untrusted"
            let malformed = try JSONSerialization.data(withJSONObject: changed, options: [.sortedKeys, .withoutEscapingSlashes])
            #expect(throws: (any Error).self) { try StorageLifecycleShimBootstrap.decode(malformed) }
        }
        fields["profile"] = "production"
        #expect(throws: (any Error).self) {
            try StorageLifecycleShimBootstrap.decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
        }
        #expect(throws: (any Error).self) { try StorageLifecycleShimBootstrap.decode(bytes + Data("\n".utf8)) }
        let duplicate = Data("{\"profile\":\"lifecycle-v2-native-v1\",".utf8) + bytes.dropFirst()
        #expect(throws: (any Error).self) { try StorageLifecycleShimBootstrap.decode(duplicate) }
    }

    @Test func malformedBindingsAndEscapingPathsAreRejected() throws {
        let bytes = try StorageLifecycleProtocol.encode(fixture())
        let fields = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        for (field, values) in [
            "backingFile": ["/private/tmp/lifecycle-store-other/disk.raw", "/private/tmp/lifecycle-store/../disk.raw", "relative", "/private/tmp/lifecycle-store/disk.raw\u{0}"],
            "initialRamdisk": ["/another/path/storage-initramfs.cpio.gz"],
            "initramfsSHA256": [String(repeating: "A", count: 64), ""],
            "kernelSHA256": [String(repeating: "A", count: 64), ""],
            "launchUUID": ["invalid"], "rootPublicKey": [Data(repeating: 1, count: 31).base64EncodedString()]
        ] {
            for value in values {
                var changed = fields; changed[field] = value
                let malformed = try JSONSerialization.data(withJSONObject: changed, options: [.sortedKeys, .withoutEscapingSlashes])
                #expect(throws: (any Error).self) { try StorageLifecycleShimBootstrap.decode(malformed) }
            }
        }
    }

    @Test func canonicalLockedRootIsAcceptedWithoutFoundationAliasRewriting() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "lifecycle-bootstrap-path-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let lock = try CanonicalDataStoreLock(root: directory)
        let frozen = try fixture()
        var fields = try #require(JSONSerialization.jsonObject(with: StorageLifecycleProtocol.encode(frozen)) as? [String: Any])
        fields["storeRoot"] = lock.root.path
        fields["backingFile"] = lock.root.appending(path: "storage.ext4").path
        let bytes = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
        let decoded = try StorageLifecycleShimBootstrap.decode(bytes)
        #expect(decoded.storeRoot == lock.root.path)
        #expect(try decoded.specification(backingIdentity: observedBackingIdentity()).rootDiskPath == lock.root.appending(path: "storage.ext4").path)
        // Validate lexical form without resolving symlinks or rewriting aliases.
        for suffix in ["/../escape", "/./disk", "//disk", "/disk/"] {
            fields["backingFile"] = lock.root.path + suffix
            #expect(throws: (any Error).self) {
                try StorageLifecycleShimBootstrap.decode(JSONSerialization.data(withJSONObject: fields,
                    options: [.sortedKeys, .withoutEscapingSlashes]))
            }
        }
        try lock.validateRetainedOwnership()
    }

    @Test func unsignedEntryRejectsBeforeReadingInheritedDescriptor() async {
        await #expect(throws: (any Error).self) {
            try await StorageLifecycleQualificationShim.run(arguments: [StorageLifecycleQualificationShim.argument])
        }
        for arguments in [[], ["--other"], [StorageLifecycleQualificationShim.argument, "--root", "/tmp"]] {
            await #expect(throws: (any Error).self) { try await StorageLifecycleQualificationShim.run(arguments: arguments) }
        }
    }

    @Test func ordinaryPolicyCannotLaunchOrOpenBackingFile() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "lifecycle-launch-negative-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let storeLock = try CanonicalDataStoreLock(root: directory)
        let frozen = try fixture(), disk = storeLock.root.appending(path: "never-created.raw")
        await #expect(throws: (any Error).self) {
            try await StorageLifecycleShimProcess.launch(root: .init(publicData: frozen.rootPublicKey),
                binding: frozen.binding.value(), storeLock: storeLock, backingFile: disk,
                kernel: URL(filePath: frozen.kernel), initialRamdisk: URL(filePath: frozen.initialRamdisk),
                expectedInitramfsSHA256: frozen.initramfsSHA256, expectedKernelSHA256: frozen.kernelSHA256,
                policy: .production)
        }
        #expect(!FileManager.default.fileExists(atPath: disk.path))
        try storeLock.validateRetainedOwnership()
    }
}

@Suite struct StorageLifecyclePrivateAssetTests {
    private func withSource(_ body: (FileHandle, URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "lifecycle-private-asset-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appending(path: "source")
        try Data("signed asset bytes".utf8).write(to: path)
        let source = try FileHandle(forUpdating: path)
        defer { try? source.close() }
        try body(source, directory)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["source"])
    }

    private func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    @Test func sourceInodeMutationAfterCopyCannotChangeHeldPrivateBytes() throws {
        try withSource { source, directory in
            let expected = Data("signed asset bytes".utf8)
            let copy = try StorageLifecyclePrivateAsset(source: source, temporaryDirectory: directory)
            // Mutate the SAME open source inode after copying, before validation.
            try source.seek(toOffset: 0)
            try source.write(contentsOf: Data(repeating: 0x78, count: expected.count))
            let held = try copy.validated(expectedSHA256: digest(expected))
            defer { try? held.close() }
            var original = stat(), privateFile = stat()
            #expect(fstat(source.fileDescriptor, &original) == 0)
            #expect(fstat(held.fileDescriptor, &privateFile) == 0)
            #expect(original.st_ino != privateFile.st_ino || original.st_dev != privateFile.st_dev)
            #expect(privateFile.st_mode & S_IFMT == S_IFREG && privateFile.st_nlink == 0)
            #expect(privateFile.st_size == expected.count)
            #expect(fcntl(held.fileDescriptor, F_GETFD) & FD_CLOEXEC != 0)
            #expect(fcntl(held.fileDescriptor, F_GETFL) & O_ACCMODE == O_RDONLY)
            #expect(try held.offset() == 0)
            #expect(try held.readToEnd() == expected)
            var byte: UInt8 = 1
            #expect(Darwin.write(held.fileDescriptor, &byte, 1) == -1 && errno == EBADF)
            // Mutation after validation is also irrelevant to VZ's retained bytes.
            try source.truncate(atOffset: 0)
            try held.seek(toOffset: 0)
            #expect(try held.readToEnd() == expected)
            let descriptor = held.fileDescriptor
            try held.close()
            #expect(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF)
        }
    }

    @Test func changedSourceAndBadExpectedDigestRejectAndClosePrivateDescriptor() throws {
        try withSource { source, directory in
            let expected = digest(Data("signed asset bytes".utf8))
            try source.seek(toOffset: 0)
            try source.write(contentsOf: Data("tampered".utf8))
            for hash in [expected, String(repeating: "0", count: 64), "not-a-digest"] {
                let copy = try StorageLifecyclePrivateAsset(source: source, temporaryDirectory: directory)
                let descriptor = try #require(copy.handle).fileDescriptor
                #expect(throws: (any Error).self) { try copy.validated(expectedSHA256: hash) }
                #expect(copy.handle == nil)
                #expect(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF)
                #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["source"])
            }
        }
    }

    @Test func oversizeNonregularAndUnboundedLimitsAreRejected() throws {
        try withSource { source, directory in
            #expect(StorageLifecyclePrivateAsset.maximumBytes == 256 << 20)
            // Sparse size rejects without reading/allocating a 256 MiB test payload.
            try source.truncate(atOffset: UInt64(StorageLifecyclePrivateAsset.maximumBytes + 1))
            #expect(throws: (any Error).self) {
                try StorageLifecyclePrivateAsset(source: source, temporaryDirectory: directory)
            }
            #expect(throws: (any Error).self) {
                try StorageLifecyclePrivateAsset(source: source, temporaryDirectory: directory, maximumBytes: 0)
            }
            try source.truncate(atOffset: 0)
            let empty = try StorageLifecyclePrivateAsset(source: source, temporaryDirectory: directory, maximumBytes: 0)
            let heldEmpty = try empty.validated(expectedSHA256: digest(Data()))
            defer { try? heldEmpty.close() }
            #expect(try heldEmpty.readToEnd()?.isEmpty != false)
            for limit in [-1, StorageLifecyclePrivateAsset.maximumBytes + 1] {
                #expect(throws: (any Error).self) {
                    try StorageLifecyclePrivateAsset(source: source, temporaryDirectory: directory, maximumBytes: limit)
                }
            }
            let descriptor = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
            try #require(descriptor >= 0)
            let nonregular = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            defer { try? nonregular.close() }
            #expect(throws: (any Error).self) {
                try StorageLifecyclePrivateAsset(source: nonregular, temporaryDirectory: directory)
            }
        }
    }

    @Test func exactLimitAndAbandonedCopyLeaveNoTemporaryNameOrDescriptor() throws {
        try withSource { source, directory in
            let expected = Data("signed asset bytes".utf8)
            var copy: StorageLifecyclePrivateAsset? = try .init(source: source, temporaryDirectory: directory, maximumBytes: expected.count)
            let descriptor = try #require(copy?.handle).fileDescriptor
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["source"])
            copy = nil
            #expect(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF)
            let exact = try StorageLifecyclePrivateAsset(source: source, temporaryDirectory: directory, maximumBytes: expected.count)
            let held = try exact.validated(expectedSHA256: digest(expected))
            defer { try? held.close() }
            #expect(try held.readToEnd() == expected)
            #expect(throws: (any Error).self) {
                try StorageLifecyclePrivateAsset(source: source, temporaryDirectory: directory, maximumBytes: expected.count - 1)
            }
        }
    }
}
#endif
