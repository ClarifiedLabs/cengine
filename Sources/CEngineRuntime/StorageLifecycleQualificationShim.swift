#if os(macOS) && CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
import CEngineCore
import CryptoKit
import Darwin
import Foundation
import Security

/// Closed launch metadata, not a capability. Only the authenticated private parent
/// may send this once; ordinary shim commands cannot replace any of these fields.
struct StorageLifecycleShimBootstrap: Codable, Sendable {
    static let version = "lifecycle-v2-native-v1"
    let profile: String
    let rootPublicKey: Data
    let binding: StorageLifecycleStoreBinding
    let storeRoot: String
    let backingFile: String
    let kernel: String
    let initialRamdisk: String
    let initramfsSHA256: String
    let kernelSHA256: String
    let launchUUID: String

    func validate() throws {
        guard profile == Self.version, rootPublicKey.count == 32,
              DiskInitializationProtocol.validUUID(launchUUID),
              [initramfsSHA256, kernelSHA256].allSatisfy({ digest in
                  digest.utf8.count == 64 && digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
              }),
              [storeRoot, backingFile, kernel, initialRamdisk].allSatisfy(Self.validPath),
              backingFile.hasPrefix(storeRoot + "/"),
              URL(filePath: kernel).deletingLastPathComponent() == URL(filePath: initialRamdisk).deletingLastPathComponent(),
              binding.bytes >= 16 << 20, binding.bytes % 4096 == 0 else { throw failure() }
        _ = try binding.value()
    }
    private static func validPath(_ path: String) -> Bool {
        // Foundation standardization rewrites valid /private/var aliases. Keep
        // the physical spelling supplied by the canonical lock; descriptor identity
        // checks below, not lexical normalization, establish root/disk ownership.
        path.hasPrefix("/") && path != "/" && !path.utf8.contains(0)
            && path.utf8.count < 4096
            && path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().allSatisfy {
                !$0.isEmpty && $0 != "." && $0 != ".."
            }
    }
    func specification(backingIdentity: VMShimProtocol.FileIdentity) throws -> VMShimProtocol.Specification {
        try validate()
        let bound = try binding.value()
        guard backingIdentity.inode == bound.backing.identity.inode,
              backingIdentity.volumeUUID?.uuidString.lowercased() == bound.backing.identity.volumeUUID.rawValue else {
            throw failure()
        }
        return .init(kind: .storage, containerID: "storage-lifecycle-qualification", generation: 1,
            token: launchUUID, kernelPath: kernel, initialRamdiskPath: initialRamdisk,
            rootDiskPath: backingFile,
            rootDiskIdentity: backingIdentity,
            rootDiskSize: bound.backing.size, cpus: 2, memoryBytes: 512 << 20,
            macAddress: "02:00:00:00:00:02", socketPath: "", logPath: "",
            // PID1 configures management before listening on the private boot port.
            // This fixed TEST-NET address stays on the VM's unconnected packet trunk;
            // qualification creates no host fabric, route, NAT or DATA consumer.
            kernelArguments: ["cengine.management_address=192.0.2.2/30",
                              "cengine.management_vlan=\(VMShimProtocol.managementVLAN)"],
            shimLaunchUUID: launchUUID, diskBootstrapVersion: 1,
            expectedInitramfsSHA256: initramfsSHA256)
    }
    static func decode(_ bytes: Data) throws -> Self {
        let value = try StorageLifecycleProtocol.decode(Self.self, from: bytes)
        try value.validate()
        return value
    }
    /// Rejection-only parsing of the exact build-time sealed asset receipt.
    /// It returns public hashes, not authority or permission to boot arbitrary bytes.
    static func assetHashes(_ bytes: Data, metadata: Data, expected: String?) throws -> [String: String] {
        guard let expected, SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == expected,
              let text = String(data: bytes, encoding: .utf8) else { throw failure() }
        var hashes: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let fields = line.components(separatedBy: "  ")
            guard fields.count == 2, fields[0].utf8.count == 64,
                  fields[0].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  hashes[fields[1]] == nil else { throw failure() }
            hashes[fields[1]] = fields[0]
        }
        guard Set(hashes.keys) == ["vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz", "disk-bootstrap.json"],
              SHA256.hash(data: metadata).map({ String(format: "%02x", $0) }).joined() == hashes["disk-bootstrap.json"] else { throw failure() }
        return hashes
    }
    func validateRoot(descriptor: Int32) throws {
        let identity = try PersistentFileIdentity.capture(descriptor: descriptor)
        let expected = try binding.value().root
        guard identity.inode == expected.inode,
              identity.volumeUUID?.uuidString.lowercased() == expected.volumeUUID.rawValue else { throw failure() }
    }
    func validateFreshDisk(_ disk: VMShimHeldDisk) throws {
        let bound = try binding.value()
        guard disk.identity.inode == bound.backing.identity.inode,
              disk.identity.volumeUUID?.uuidString.lowercased() == bound.backing.identity.volumeUUID.rawValue,
              disk.bytes == bound.backing.size,
              case .journal(let record) = try RawDiskInitialization.inspectExisting(in: disk.parent,
                named: disk.name, expectedSize: disk.bytes, heldDiskDescriptor: disk.handle.fileDescriptor),
              record.state == .created, record.binding == nil,
              record.ext4UUID == bound.expectedExt4UUID.rawValue else { throw failure() }
    }
    private func failure() -> EngineError { Self.failure() }
    static func failure() -> EngineError { .init(.conflict, "closed lifecycle qualification bootstrap refused") }
}

/// A bounded, private inode: no source descriptor or writable descriptor reaches VZ.
/// The empty temporary name exists only long enough to obtain a genuinely read-only
/// descriptor (Darwin /dev/fd duplicates access flags), and is removed before copying.
final class StorageLifecyclePrivateAsset {
    static let maximumBytes = 256 << 20
    private(set) var handle: FileHandle?
    private let bytes: Int

    init(source: FileHandle, temporaryDirectory: URL = FileManager.default.temporaryDirectory,
        maximumBytes: Int = StorageLifecyclePrivateAsset.maximumBytes) throws {
        guard maximumBytes >= 0, maximumBytes <= Self.maximumBytes else { throw StorageLifecycleShimBootstrap.failure() }
        var original = stat()
        guard fstat(source.fileDescriptor, &original) == 0, original.st_mode & S_IFMT == S_IFREG,
              original.st_size >= 0, original.st_size <= maximumBytes else { throw StorageLifecycleShimBootstrap.failure() }
        let directory = Darwin.open(temporaryDirectory.resolvingSymlinksInPath().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw StorageLifecycleShimBootstrap.failure() }
        defer { Darwin.close(directory) }
        let name = ".cengine-private-asset-\(UUID().uuidString)"
        let writer = Darwin.openat(directory, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard writer >= 0 else { throw StorageLifecycleShimBootstrap.failure() }
        defer { Darwin.close(writer) }
        var unlinked = false
        defer { if !unlinked { Darwin.unlinkat(directory, name, 0) } }
        // Acquire the independent RO description while empty; never reopen the source.
        let reader = Darwin.openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        unlinked = Darwin.unlinkat(directory, name, 0) == 0
        var retained = false
        defer { if reader >= 0 && !retained { Darwin.close(reader) } }
        var written = stat(), readable = stat()
        guard unlinked, reader >= 0, fstat(writer, &written) == 0, fstat(reader, &readable) == 0,
              written.st_mode & S_IFMT == S_IFREG, readable.st_mode & S_IFMT == S_IFREG,
              written.st_dev == readable.st_dev, written.st_ino == readable.st_ino,
              written.st_nlink == 0, readable.st_nlink == 0,
              fcntl(reader, F_GETFL) & O_ACCMODE == O_RDONLY else { throw StorageLifecycleShimBootstrap.failure() }
        var total = 0
        var buffer = [UInt8](repeating: 0, count: 1 << 20)
        while true {
            // One extra byte detects growth past the limit; it is never written.
            let count = pread(source.fileDescriptor, &buffer, min(buffer.count, maximumBytes - total + 1), off_t(total))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, count <= maximumBytes - total else { throw StorageLifecycleShimBootstrap.failure() }
            if count == 0 { break }
            try buffer.withUnsafeBytes { raw in
                var offset = 0
                while offset < count {
                    let copied = Darwin.write(writer, raw.baseAddress!.advanced(by: offset), count - offset)
                    if copied < 0 && errno == EINTR { continue }
                    guard copied > 0 else { throw StorageLifecycleShimBootstrap.failure() }
                    offset += copied
                }
            }
            total += count
        }
        guard fstat(source.fileDescriptor, &original) == 0, original.st_size == total,
              fstat(reader, &readable) == 0, readable.st_size == total, readable.st_nlink == 0 else {
            throw StorageLifecycleShimBootstrap.failure()
        }
        bytes = total
        handle = FileHandle(fileDescriptor: reader, closeOnDealloc: true)
        retained = true
        // writer closes on return, before either digest validation or VM construction.
    }

    /// Hash the actual completed private file, not bytes observed while reading source.
    func validated(expectedSHA256: String) throws -> FileHandle {
        guard let handle else { throw StorageLifecycleShimBootstrap.failure() }
        var transferred = false
        defer {
            if !transferred { try? handle.close() }
            self.handle = nil
        }
        try handle.seek(toOffset: 0)
        var hash = SHA256(), total = 0
        while let chunk = try handle.read(upToCount: min(1 << 20, bytes - total + 1)), !chunk.isEmpty {
            guard chunk.count <= bytes - total else { throw StorageLifecycleShimBootstrap.failure() }
            total += chunk.count
            hash.update(data: chunk)
        }
        var information = stat()
        guard total == bytes, fstat(handle.fileDescriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG, information.st_nlink == 0,
              information.st_size == bytes,
              hash.finalize().map({ String(format: "%02x", $0) }).joined() == expectedSHA256 else {
            throw StorageLifecycleShimBootstrap.failure()
        }
        try handle.seek(toOffset: 0)
        transferred = true
        return handle
    }
}

/// The sole qualification shim entry. No argv/environment configuration, default
/// runtime route, path listener, adoption, deletion, or publication is provided.
public enum StorageLifecycleQualificationShim {
    public static let argument = "--storage-lifecycle-qualification-shim"

    public static func run(arguments: [String]) async throws {
        guard arguments == [argument] else { throw StorageLifecycleShimBootstrap.failure() }
        let prepared = try await worker {
            let policy = try StorageLifecycleNativePolicy.qualification(role: .engine)
            // MUST precede even the first private frame read or journal inspection.
            let observed = try StorageLifecycleFreshShim.authenticatedParent(parentFD: 3, policy: policy)
            let parent = try StorageLifecycleShimChannel(borrowedFD: 3)
            Darwin.close(3)
            do {
                let lease = try parent.lease()
                let packet = try StorageLifecycleShimChannel.receive(fd: lease.fileDescriptor,
                    permitsDescriptor: true, deadline: .now() + 30)
                let frozen = try StorageLifecycleShimBootstrap.decode(packet.body)
                let current = try StorageLifecycleFreshShim.authenticatedParent(parentFD: lease.fileDescriptor, policy: policy)
                guard current.0 == observed.0, current.1 == observed.1, let disk = packet.descriptor else {
                    throw StorageLifecycleShimBootstrap.failure()
                }
                let rootDirectory = try PersistentStateDirectory.open(URL(filePath: frozen.storeRoot))
                try frozen.validateRoot(descriptor: rootDirectory.descriptor)
                let observed = try PersistentFileIdentity.capture(descriptor: disk.fileDescriptor)
                let spec = try frozen.specification(backingIdentity: observed.shimIdentity)
                let kernelArguments = try VMShimServer.bootstrapKernelArguments(spec)
                let assets = try pinnedAssets(frozen, specification: spec, policy: policy)
                let attachments = try VMShimAttachmentResolver.resolve(spec, inheritedStorageDisk: disk)
                guard let held = attachments.disks.first, attachments.disks.count == 1 else {
                    throw StorageLifecycleShimBootstrap.failure()
                }
                try frozen.validateFreshDisk(held)
                let transaction = try RawDiskBootTransaction(specification: spec, disks: attachments.disks)
                let configuration = RawVirtualMachineConfiguration(id: spec.containerID,
                    kernel: URL(filePath: "/dev/fd/\(assets.kernel.fileDescriptor)"),
                    initialRamdisk: URL(filePath: "/dev/fd/\(assets.initramfs.fileDescriptor)"),
                    rootDisk: attachments.rootDisk, cpus: spec.cpus, memoryBytes: spec.memoryBytes,
                    macAddress: spec.macAddress,
                    retainedAttachmentHandles: attachments.retainedHandles + [assets.kernel, assets.initramfs],
                    kernelArguments: kernelArguments)
                return Prepared(parent: parent, frozen: frozen, configuration: configuration,
                    transaction: transaction, policy: policy)
            } catch { parent.close(); throw error }
        }
        let lease = try prepared.parent.lease()
        let owner = try await MainActor.run {
            try RawStorageLifecycleShim(configuration: prepared.configuration, bootstrap: prepared.transaction,
                binding: prepared.frozen.binding.value(),
                root: .init(publicData: prepared.frozen.rootPublicKey),
                parentBorrowedFD: lease.fileDescriptor, policy: prepared.policy)
        }
        do {
            let server = try await worker {
                let server = try StorageLifecycleShimServer(owner: owner, parentBorrowedFD: lease.fileDescriptor,
                    policy: prepared.policy)
                try server.start()
                // Setup-only acknowledgement, never Guest readiness or ROOT proof.
                try StorageLifecycleShimChannel.send(Data("lifecycle-v2-native-v1:bound".utf8),
                    fd: lease.fileDescriptor, deadline: .now() + 30)
                return server
            }
            defer { server.close(); prepared.parent.close() }
            try await withTaskCancellationHandler {
                try await worker { try waitForClosure(lease.fileDescriptor) }
            } onCancel: { server.close(); prepared.parent.close() }
            try await owner.stop()
        } catch {
            prepared.parent.close()
            // A failed stop is terminal, not evidence permitting storage deletion.
            // The process owner must retain its lease and explicitly kill/reap us.
            try await owner.stop()
            throw error
        }
    }

    private struct Prepared: Sendable {
        let parent: StorageLifecycleShimChannel
        let frozen: StorageLifecycleShimBootstrap
        let configuration: RawVirtualMachineConfiguration
        let transaction: RawDiskBootTransaction
        let policy: StorageLifecycleNativePolicy
    }
    private struct Metadata: Decodable {
        let schemaVersion: Int
        let protocolVersion: Int
        let storageServiceBootVersion: Int
        let storageInitramfsSHA256: String
        let storageLifecycleQualification: String
        let storageLifecycleSourcePin: String
    }
    private static func pinnedAssets(_ frozen: StorageLifecycleShimBootstrap,
        specification: VMShimProtocol.Specification, policy: StorageLifecycleNativePolicy) throws -> (kernel: FileHandle, initramfs: FileHandle) {
        let directory = try PersistentStateDirectory.open(URL(filePath: frozen.kernel).deletingLastPathComponent())
        guard let bytes = try directory.readRegularFile(named: "disk-bootstrap.json") else {
            throw StorageLifecycleShimBootstrap.failure()
        }
        guard let receipt = try directory.readRegularFile(named: "SHA256SUMS", maximumBytes: 4096) else { throw StorageLifecycleShimBootstrap.failure() }
        let hashes = try StorageLifecycleShimBootstrap.assetHashes(receipt, metadata: bytes, expected: policy.qualificationAssetsSHA256)
        let metadata = try JSONDecoder().decode(Metadata.self, from: bytes)
        guard hashes["vmlinux"] == frozen.kernelSHA256, hashes["storage-initramfs.cpio.gz"] == frozen.initramfsSHA256,
              let pin = policy.qualificationSourcePin,
              metadata.schemaVersion == 1, metadata.protocolVersion == 1,
              metadata.storageServiceBootVersion == 2,
              metadata.storageLifecycleQualification == StorageLifecycleShimBootstrap.version,
              metadata.storageLifecycleSourcePin == pin,
              metadata.storageInitramfsSHA256 == frozen.initramfsSHA256 else {
            throw StorageLifecycleShimBootstrap.failure()
        }
        // Retain pinnedBootstrapInitramfs's initial protocol/hash guard, but do its
        // digest read on the bounded private inode. The ordinary helper cannot read
        // /dev/fd through PersistentStateDirectory (its filesystem identity differs),
        // and hashing the mutable source with its unbounded loop would bypass our cap.
        let expectedInitramfs = try bootstrapInitramfsExpectedDigest(specification)
        guard expectedInitramfs == frozen.initramfsSHA256 else { throw StorageLifecycleShimBootstrap.failure() }
        let initramfsSource = try directory.openRegularFile(named: URL(filePath: frozen.initialRamdisk).lastPathComponent, access: .readOnly)
        defer { try? initramfsSource.handle.close() }
        let initramfsCopy = try StorageLifecyclePrivateAsset(source: initramfsSource.handle)
        let initramfs = try initramfsCopy.validated(expectedSHA256: expectedInitramfs)
        var retained = false
        defer { if !retained { try? initramfs.close() } }
        let kernelName = URL(filePath: frozen.kernel).lastPathComponent
        let kernel = try directory.openRegularFile(named: kernelName, access: .readOnly)
        defer { try? kernel.handle.close() }
        let kernelCopy = try StorageLifecyclePrivateAsset(source: kernel.handle)
        guard directory.pathStillNamesThisDirectory(),
              try directory.regularFileIdentity(named: kernelName) == kernel.identity else {
            throw StorageLifecycleShimBootstrap.failure()
        }
        let privateKernel = try kernelCopy.validated(expectedSHA256: frozen.kernelSHA256)
        retained = true
        return (privateKernel, initramfs)
    }
    static func bootstrapInitramfsExpectedDigest(_ specification: VMShimProtocol.Specification) throws -> String {
        // Same initial guard as VMShimServer.pinnedBootstrapInitramfs. The signed v2
        // capability is checked above, not through that helper's ordinary v1 check.
        guard specification.diskBootstrapVersion == 1,
              let expected = specification.expectedInitramfsSHA256,
              expected.utf8.count == 64,
              expected.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw StorageLifecycleShimBootstrap.failure()
        }
        return expected
    }
    private static func waitForClosure(_ descriptor: Int32) throws {
        while true {
            var item = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let result = poll(&item, 1, 100)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { throw StorageLifecycleShimBootstrap.failure() }
            if result == 0 { continue }
            var byte: UInt8 = 0
            let count = recv(descriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
            if count == 0 { return }
            if count < 0 && ![EAGAIN, EINTR].contains(errno) { throw StorageLifecycleShimBootstrap.failure() }
            // The server alone consumes frames; do not spin while it dispatches.
            usleep(20_000)
        }
    }
    static func worker<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            Thread.detachNewThread {
                do { continuation.resume(returning: try body()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }
}
#endif
