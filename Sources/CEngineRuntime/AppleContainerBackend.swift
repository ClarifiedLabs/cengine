#if os(macOS)
import CEngineCore
import Containerization
import ContainerizationArchive
import ContainerizationEXT4
import ContainerizationExtras
import ContainerizationOCI
import ContainerizationOS
import Darwin
import Foundation
import SystemPackage
import Virtualization
import vmnet

/// Executes Linux containers with Apple's Virtualization.framework-backed runtime.
/// The actor owns ContainerManager because its image/network bookkeeping is mutable.
public actor AppleContainerBackend: ContainerBackend {
    public static let defaultVminitReference = "ghcr.io/apple/containerization/vminit:0.37.0"

    private var manager: ContainerManager
    private let vmm: VZVirtualMachineManager
    private var networks: [String: ManagedVmnetNetwork] = [:]
    private var networkRecords: [String: NetworkRecord] = [:]
    private var interfaces: [String: [String: any Containerization.Interface]] = [:]
    private let subnetCandidates: [String]
    private let portForwarder = PortForwarder()
    private var containers: [String: LinuxContainer] = [:]
    private var ioBridges: [String: ContainerIOBridge] = [:]
    private var waitTasks: [String: Task<Int32, Never>] = [:]
    private var execProcesses: [String: LinuxProcess] = [:]
    private var execBridges: [String: ContainerIOBridge] = [:]
    private var execWaitTasks: [String: Task<Int32, Never>] = [:]
    private var execExitCodes: [String: Int32] = [:]
    private var preparedRecords: [String: ContainerRecord] = [:]
    private var preparedImages: [String: Containerization.Image] = [:]
    private struct StagedCopy: Sendable { let source: URL; let destination: String }
    private var stagedCopies: [String: [StagedCopy]] = [:]
    private let volumeRoot: URL
    private let logRoot: URL
    private let stagingRoot: URL
    private let runtimeContainerRoot: URL

    public init(
        root: URL,
        kernel: URL,
        vminitReference: String = defaultVminitReference,
        rosetta: Bool = true
    ) async throws {
        let runtimeRoot = root.appending(path: "runtime", directoryHint: .isDirectory)
        self.volumeRoot = root.appending(path: "volumes", directoryHint: .isDirectory)
        self.logRoot = root.appending(path: "container-logs", directoryHint: .isDirectory)
        self.stagingRoot = root.appending(path: "staged-copies", directoryHint: .isDirectory)
        self.runtimeContainerRoot = runtimeRoot.appending(path: "containers", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: runtimeRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: volumeRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: logRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: stagingRoot, withIntermediateDirectories: true)
        self.subnetCandidates = try Self.loadSubnetCandidates(root: root)
        let imageStore = try ImageStore(path: runtimeRoot)
        let initPath = runtimeRoot.appending(path: "initfs.ext4")
        let initfs: Containerization.Mount
        if FileManager.default.fileExists(atPath: initPath.path) {
            initfs = .block(format: "ext4", source: initPath.path, destination: "/", options: ["ro"])
        } else {
            initfs = try await imageStore.getInitImage(reference: vminitReference).initBlock(at: initPath, for: .linuxArm)
        }
        let machineManager = VZVirtualMachineManager(
            kernel: Kernel(path: kernel, platform: .linuxArm), initialFilesystem: initfs, rosetta: rosetta
        )
        self.vmm = machineManager
        self.manager = try ContainerManager(
            kernel: Kernel(path: kernel, platform: .linuxArm), initfs: initfs,
            imageStore: imageStore, network: nil, rosetta: rosetta
        )
    }

    private struct ConfigurationFile: Decodable {
        struct Network: Decodable { var ipv4Pools: [String]? }
        var network: Network?
    }

    private static let defaultPools = ["192.168.224.0/20", "172.29.0.0/16", "10.240.0.0/16"]

    static func loadSubnetCandidates(root: URL) throws -> [String] {
        let url = root.appending(path: "config.json")
        let pools: [String]
        if FileManager.default.fileExists(atPath: url.path) {
            do { pools = try JSONDecoder().decode(ConfigurationFile.self, from: Data(contentsOf: url)).network?.ipv4Pools ?? defaultPools }
            catch { throw EngineError(.badRequest, "invalid cengine configuration at \(url.path): \(error.localizedDescription)") }
        } else { pools = defaultPools }
        guard !pools.isEmpty else { throw EngineError(.badRequest, "network.ipv4Pools must not be empty") }
        var expanded: [[String]] = []
        for pool in pools { expanded.append(try expand(pool: pool)) }
        var result: [String] = []
        for index in 0..<(expanded.map(\.count).max() ?? 0) {
            for values in expanded where values.indices.contains(index) { result.append(values[index]) }
        }
        guard Set(result).count == result.count else { throw EngineError(.badRequest, "network.ipv4Pools contain overlapping /24 subnets") }
        return result
    }

    static func expand(pool: String) throws -> [String] {
        let components = pool.split(separator: "/")
        guard components.count == 2, let prefix = Int(components[1]), prefix >= 8, prefix <= 24,
              let value = ipv4Value(String(components[0])) else {
            throw EngineError(.badRequest, "invalid IPv4 network pool: \(pool)")
        }
        let mask = prefix == 0 ? UInt32(0) : UInt32.max << UInt32(32 - prefix)
        let lower = value & mask
        let upper = lower | ~mask
        guard isPrivate(lower), isPrivate(upper) else { throw EngineError(.badRequest, "network pool must be RFC1918: \(pool)") }
        return stride(from: UInt64(lower), through: UInt64(upper), by: 256).map {
            "\(($0 >> 24) & 255).\(($0 >> 16) & 255).\(($0 >> 8) & 255).0/24"
        }
    }

    private static func ipv4Value(_ address: String) -> UInt32? {
        let parts = address.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4, parts.allSatisfy({ $0 <= 255 }) else { return nil }
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    }

    private static func isPrivate(_ value: UInt32) -> Bool {
        value >> 24 == 10 || value >> 20 == 0xAC1 || value >> 16 == 0xC0A8
    }

    private static func randomIPv6Prefix() -> String {
        let hex = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        return "fd\(hex.prefix(2)):\(hex.dropFirst(2).prefix(4)):\(hex.dropFirst(6).prefix(4))::/64"
    }

    public func restoreNetworks(_ records: [NetworkRecord]) async throws -> [NetworkRecord] {
        var restored: [NetworkRecord] = []
        for record in records {
            var lastError: Error?
            for attempt in 0..<5 {
                do {
                    restored.append(try allocateNetwork(
                        record, restoring: true, allowAutomaticRemap: attempt == 4
                    ))
                    lastError = nil
                    break
                } catch {
                    lastError = error
                    guard attempt < 4 else { break }
                    try await Task.sleep(for: .milliseconds(500 * (1 << attempt)))
                }
            }
            if let lastError { throw lastError }
        }
        return restored
    }

    public func createNetwork(_ record: NetworkRecord) async throws -> NetworkRecord {
        try allocateNetwork(record, restoring: false)
    }

    public func deleteNetwork(_ record: NetworkRecord) async throws {
        networks.removeValue(forKey: record.id)
        networkRecords.removeValue(forKey: record.id)
    }

    public func shutdown() async {
        for task in waitTasks.values { task.cancel() }
        waitTasks.removeAll()
        for container in containers.values { try? await container.stop() }
        containers.removeAll()
        for bridge in ioBridges.values { bridge.finishOutput() }
        ioBridges.removeAll()
        portForwarder.stopAll()
        interfaces.removeAll()
        preparedRecords.removeAll()
        preparedImages.removeAll()
        networks.removeAll()
        networkRecords.removeAll()
    }

    private func allocateNetwork(
        _ requested: NetworkRecord, restoring: Bool, allowAutomaticRemap: Bool = true
    ) throws -> NetworkRecord {
        var attempts: [(String, String)] = []
        if restoring, let serialization = requested.vmnetSerialization {
            do {
                let value = try ManagedVmnetNetwork(serialization: serialization)
                var record = requested
                record.subnet = value.subnet.description
                record.gateway = value.ipv4Gateway.description
                record.ipv6Subnet = value.prefixV6?.description ?? ""
                record.ipv6Gateway = value.ipv6Gateway?.description ?? ""
                record.vmnetSerialization = try value.serialization()
                networks[record.id] = value
                networkRecords[record.id] = record
                return record
            } catch {
                attempts.append(("serialized reservation", error.localizedDescription))
            }
        }
        let used = Set(networkRecords.values.map(\.subnet))
        var candidates: [String] = []
        if !requested.subnet.isEmpty { candidates.append(requested.subnet) }
        if requested.ipv4AllocationMode == .automatic, allowAutomaticRemap {
            candidates.append(contentsOf: subnetCandidates.filter { !used.contains($0) && $0 != requested.subnet })
        }
        guard !candidates.isEmpty else {
            throw EngineError(.conflict, "no available IPv4 /24 subnets in the configured network pools")
        }
        for subnet in candidates {
            let ipv6: String
            if requested.ipv6AllocationMode == .explicit {
                ipv6 = requested.ipv6Subnet
            } else if restoring, subnet == requested.subnet, !requested.ipv6Subnet.isEmpty {
                ipv6 = requested.ipv6Subnet
            } else {
                ipv6 = Self.randomIPv6Prefix()
            }
            do {
                let ipv4CIDR = try CIDRv4(subnet)
                let ipv6CIDR = try CIDRv6(ipv6)
                guard ipv4CIDR.prefix.length == 24 else {
                    throw EngineError(.badRequest, "cengine networks require an IPv4 /24 subnet: \(subnet)")
                }
                guard Self.isUniqueLocal(prefix: ipv6CIDR) else {
                    throw EngineError(.badRequest, "cengine networks require an RFC 4193 ULA /64 prefix: \(ipv6)")
                }
                let mode: vmnet.operating_modes_t = requested.internalNetwork ? .VMNET_HOST_MODE : .VMNET_SHARED_MODE
                let value = try ManagedVmnetNetwork(mode: mode, subnet: ipv4CIDR, prefixV6: ipv6CIDR)
                if requested.ipv4AllocationMode == .explicit, !requested.gateway.isEmpty,
                   requested.gateway != value.ipv4Gateway.description {
                    throw EngineError(.badRequest, "IPv4 gateway must be \(value.ipv4Gateway) for subnet \(subnet)")
                }
                if requested.ipv6AllocationMode == .explicit, !requested.ipv6Gateway.isEmpty,
                   requested.ipv6Gateway != value.ipv6Gateway?.description {
                    throw EngineError(.badRequest, "IPv6 gateway must be \(value.ipv6Gateway?.description ?? "") for prefix \(ipv6)")
                }
                var record = requested
                record.subnet = value.subnet.description
                record.gateway = value.ipv4Gateway.description
                record.ipv6Subnet = value.prefixV6?.description ?? ""
                record.ipv6Gateway = value.ipv6Gateway?.description ?? ""
                record.vmnetSerialization = try value.serialization()
                networks[record.id] = value; networkRecords[record.id] = record
                return record
            } catch { attempts.append((subnet, error.localizedDescription)) }
        }
        let details = attempts.map { "\($0.0): \($0.1)" }.joined(separator: "; ")
        throw EngineError(.internalError, "could not allocate network \(requested.name) (\(details))")
    }

    static func isUniqueLocal(prefix: CIDRv6) -> Bool {
        prefix.prefix.length == 64 && (UInt8(prefix.lower.value >> 120) & 0xfe) == 0xfc
    }

    public func pullImage(_ reference: String, platform: String) async throws {
        guard platform == "linux/arm64" || platform == "linux/amd64" else {
            throw EngineError(.unsupported, "unsupported platform \(platform)")
        }
        _ = try await image(reference: reference, platform: platform, pull: true)
    }

    public func pullImage(_ reference: String, platform: String, credentials: RegistryCredentials?, progress: @escaping ImagePullProgressHandler) async throws {
        let selected = try Self.platform(platform)
        let authentication: (any Authentication)? = credentials.flatMap {
            let secret = $0.identityToken.isEmpty ? $0.password : $0.identityToken
            return $0.username.isEmpty && secret.isEmpty ? nil : BasicAuthentication(username: $0.username, password: secret)
        }
        let insecure = reference.hasPrefix("localhost:") || reference.hasPrefix("127.0.0.1:")
        var lastError: Error?
        for attempt in 0..<3 {
            let accumulator = PullProgressAccumulator()
            do {
                _ = try await manager.imageStore.pull(
                    reference: reference, platform: selected, insecure: insecure, auth: authentication,
                    progress: { events in await progress(await accumulator.apply(events)) }
                )
                return
            } catch {
                lastError = error
                guard attempt < 2 else { break }
                try await Task.sleep(for: .milliseconds(500 * (attempt + 1)))
            }
        }
        throw lastError ?? EngineError(.internalError, "image pull failed")
    }

    public func imageHistory(reference: String, platform: String) async throws -> [ImageHistoryEntry] {
        let image = try await image(reference: reference, platform: platform, pull: false)
        let config = try await image.config(for: Self.platform(platform))
        let formatter = ISO8601DateFormatter()
        return (config.history ?? []).reversed().map {
            ImageHistoryEntry(
                created: $0.created.flatMap { formatter.date(from: $0) }.map { Int64($0.timeIntervalSince1970) } ?? 0,
                createdBy: $0.createdBy ?? "", comment: $0.comment ?? "", emptyLayer: $0.emptyLayer ?? false
            )
        }
    }

    public func prepare(_ record: ContainerRecord) async throws {
        guard record.platform == "linux/arm64" || record.platform == "linux/amd64" else {
            throw EngineError(.unsupported, "unsupported platform \(record.platform); expected linux/arm64 or linux/amd64")
        }

        let io = ContainerIOBridge(tty: record.tty, logURL: logRoot.appending(path: "\(record.id).log"))
        let image = try await image(reference: record.image, platform: record.platform, pull: true)
        if interfaces[record.id] == nil { interfaces[record.id] = try allocateInterfaces(for: record) }
        preparedRecords[record.id] = record
        preparedImages[record.id] = image
        ioBridges[record.id] = io
    }

    private func allocateInterfaces(for record: ContainerRecord) throws -> [String: any Containerization.Interface] {
        var result: [String: any Containerization.Interface] = [:]
        for (index, endpoint) in record.networks.enumerated() {
            guard var network = networks[endpoint.networkID], let networkRecord = networkRecords[endpoint.networkID] else {
                throw EngineError(.notFound, "network \(endpoint.networkID) is unavailable")
            }
            let allocationID = "\(record.id)-\(endpoint.networkID)"
            let requestedIPv4 = endpoint.ipv4AddressIsStatic
                ? try CIDRv4(IPv4Address(endpoint.ipv4Address ?? ""), prefix: network.subnet.prefix) : nil
            let requestedIPv6 = endpoint.ipv6AddressIsStatic
                ? try CIDRv6(IPv6Address(endpoint.ipv6Address ?? ""), prefix: network.prefixV6?.prefix ?? .ipv6(64)!) : nil
            do {
                result[endpoint.networkID] = try network.createInterface(
                    allocationID, withDefaultRoute: index == 0,
                    requestedIPv4: requestedIPv4, requestedIPv6: requestedIPv6
                )
            } catch {
                throw EngineError(.badRequest, "could not allocate endpoint on network \(networkRecord.name): \(error.localizedDescription)")
            }
            networks[endpoint.networkID] = network
        }
        return result
    }

    private func createPreparedContainer(_ record: ContainerRecord) async throws -> LinuxContainer {
        guard let io = ioBridges[record.id] else { throw EngineError(.notFound, "container I/O is unavailable") }
        let volumeRoot = self.volumeRoot
        let staged = stagedCopies[record.id] ?? []
        guard let interfaceMap = interfaces[record.id], !interfaceMap.isEmpty else { throw EngineError(.internalError, "container network is unavailable") }
        let configuredInterfaces = record.networks.compactMap { interfaceMap[$0.networkID] }
        let peerHosts = hostEntries(for: record, records: Array(preparedRecords.values))
        guard let image = preparedImages[record.id] else { throw EngineError(.notFound, "prepared image is unavailable") }
        let selectedPlatform = try Self.platform(record.platform)
        let selectedConfig = try await image.config(for: selectedPlatform)
        let imageConfig = selectedConfig.config
        let resolvedArguments = (record.entrypoint ?? imageConfig?.entrypoint ?? []) + (record.command ?? imageConfig?.cmd ?? [])
        let containerPath = runtimeContainerRoot.appending(path: record.id, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: containerPath, withIntermediateDirectories: false)
        let unpacker = EXT4Unpacker(blockSizeInBytes: max(record.memoryBytes * 4, 8 * 1_024 * 1_024 * 1_024))
        let rootfsURL = containerPath.appending(path: "rootfs.ext4")
        var rootfs = try await unpacker.unpack(image, for: selectedPlatform, at: rootfsURL)
        try await populateEmptyVolumes(for: record, from: image, platform: selectedPlatform)
        try await prepareVolumeImages(for: record)
        if record.readOnlyRootfs { rootfs.options.append("ro") }
        let container = try LinuxContainer(record.id, rootfs: rootfs, vmm: vmm) { config in
            if let imageConfig { config.process = .init(from: imageConfig) }
            config.cpus = max(record.cpus, 1)
            config.memoryInBytes = max(record.memoryBytes, 256 * 1_024 * 1_024)
            config.hostname = record.hostname
            config.useInit = record.useInit
            config.interfaces = configuredInterfaces
            if let gateway = configuredInterfaces.first?.ipv4Gateway { config.dns = .init(nameservers: [gateway.description]) }
            config.hosts = Hosts(entries: Hosts.default.entries + peerHosts)
            config.bootLog = BootLog.file(path: containerPath.appending(path: "bootlog.log"))
            config.process.arguments = resolvedArguments
            if !record.environment.isEmpty { config.process.environmentVariables.append(contentsOf: record.environment) }
            if !config.process.environmentVariables.contains(where: { $0.hasPrefix("PATH=") }) {
                config.process.environmentVariables.append("PATH=\(LinuxProcessConfiguration.defaultPath)")
            }
            if !record.workingDirectory.isEmpty { config.process.workingDirectory = record.workingDirectory }
            config.process.terminal = record.tty
            if record.openStdin { config.process.stdin = io }
            config.process.stdout = io.writer(.stdout)
            if !record.tty { config.process.stderr = io.writer(.stderr) }
            if !record.user.isEmpty { config.process.user = Self.parseUser(record.user) }
            if record.privileged {
                config.process.capabilities = .allCapabilities
            }

            for (mountIndex, mount) in record.mounts.enumerated() {
                switch mount.kind {
                case .bind:
                    let requested = URL(filePath: mount.source).standardizedFileURL
                    let source: String
                    if FileManager.default.fileExists(atPath: requested.path) || mount.createSourceIfMissing != true {
                        source = requested.path
                    } else {
                        let directory = containerPath.appending(path: "bind-sources/\(mountIndex)", directoryHint: .isDirectory)
                        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                        source = directory.path
                    }
                    config.mounts.append(.share(
                        source: source, destination: mount.destination,
                        options: mount.readOnly ? ["ro"] : []
                    ))
                case .volume:
                    let directory = volumeRoot.appending(path: mount.source, directoryHint: .isDirectory)
                    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                    if record.privileged, mount.destination == "/var" {
                        config.mounts.append(.block(
                            format: "ext4", source: directory.appending(path: "volume.ext4").path,
                            destination: mount.destination, options: mount.readOnly ? ["ro"] : []
                        ))
                    } else if let subpath = mount.subpath, !subpath.isEmpty {
                        let components = subpath.split(separator: "/", omittingEmptySubsequences: false)
                        guard !subpath.hasPrefix("/"), !components.contains(".."), !components.contains(".") else {
                            throw EngineError(.badRequest, "invalid volume subpath: \(subpath)")
                        }
                        let root = directory.standardizedFileURL.resolvingSymlinksInPath()
                        let source = root.appending(path: subpath, directoryHint: .isDirectory)
                            .standardizedFileURL.resolvingSymlinksInPath()
                        guard source.path.hasPrefix(root.path + "/") else {
                            throw EngineError(.badRequest, "volume subpath escapes the volume root: \(subpath)")
                        }
                        var isDirectory: ObjCBool = false
                        guard FileManager.default.fileExists(atPath: source.path, isDirectory: &isDirectory), isDirectory.boolValue else {
                            throw EngineError(.badRequest, "volume subpath does not exist: \(subpath)")
                        }
                        config.mounts.append(.share(
                            source: source.path, destination: mount.destination,
                            options: mount.readOnly ? ["ro"] : []
                        ))
                    } else {
                        config.mounts.append(.share(
                            source: directory.path, destination: mount.destination,
                            options: mount.readOnly ? ["ro"] : []
                        ))
                    }
                case .tmpfs:
                    var options = ["nosuid", "nodev"]
                    if mount.readOnly { options.append("ro") }
                    if let size = mount.tmpfsSizeBytes { options.append("size=\(size)") }
                    if let mode = mount.tmpfsMode { options.append("mode=\(String(mode, radix: 8))") }
                    config.mounts.append(.any(
                        type: "tmpfs", source: "tmpfs", destination: mount.destination,
                        options: options
                    ))
                }
            }
            for copy in staged {
                let entries = try FileManager.default.contentsOfDirectory(
                    at: copy.source, includingPropertiesForKeys: nil, options: []
                )
                for entry in entries {
                    let destination = URL(filePath: copy.destination, directoryHint: .isDirectory)
                        .appending(path: entry.lastPathComponent).path
                    config.mounts.append(.share(source: entry.path, destination: destination))
                }
            }
        }
        return container
    }

    private func populateEmptyVolumes(
        for record: ContainerRecord, from image: Containerization.Image, platform: Platform
    ) async throws {
        let candidates = try record.mounts.filter { mount in
            guard mount.kind == .volume, !mount.noCopy else { return false }
            let directory = volumeRoot.appending(path: mount.source, directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            return try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty
        }
        guard !candidates.isEmpty else { return }

        let work = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString, directoryHint: .isDirectory)
        let extracted = work.appending(path: "rootfs", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: extracted, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        let selectedPaths = candidates.map { $0.destination.split(separator: "/").map(String.init) }
        let manifest = try await image.manifest(for: platform)
        for (index, descriptor) in manifest.layers.enumerated() {
            let layer = work.appending(path: "layer-\(index)", directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: layer, withIntermediateDirectories: true)
            let content = try await image.getContent(digest: descriptor.digest)
            do {
                try Self.extractImageLayer(ArchiveReader(file: content.path), paths: selectedPaths, to: layer)
            } catch {
                throw EngineError(
                    .internalError,
                    "failed to extract image layer \(index) for volume copy-up: \(String(describing: error))"
                )
            }
            for path in selectedPaths {
                let relative = path.joined(separator: "/")
                let source = layer.appending(path: relative, directoryHint: .isDirectory)
                guard FileManager.default.fileExists(atPath: source.path) else { continue }
                try Self.applyImageLayer(source, to: extracted.appending(path: relative, directoryHint: .isDirectory))
            }
            try FileManager.default.removeItem(at: layer)
        }

        for mount in candidates {
            let relative = mount.destination.split(separator: "/").map(String.init).joined(separator: "/")
            guard !relative.contains("..") else { throw EngineError(.badRequest, "invalid volume destination: \(mount.destination)") }
            let source = extracted.appending(path: relative, directoryHint: .isDirectory)
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: source.path, isDirectory: &isDirectory), isDirectory.boolValue else { continue }
            let destination = volumeRoot.appending(path: mount.source, directoryHint: .isDirectory)
            for entry in try FileManager.default.contentsOfDirectory(at: source, includingPropertiesForKeys: nil) {
                try FileManager.default.copyItem(at: entry, to: destination.appending(path: entry.lastPathComponent))
            }
        }
    }

    private func prepareVolumeImages(for record: ContainerRecord) async throws {
        for mount in record.mounts
            where mount.kind == .volume && record.privileged && mount.destination == "/var" {
            let directory = volumeRoot.appending(path: mount.source, directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let image = directory.appending(path: "volume.ext4")
            guard !FileManager.default.fileExists(atPath: image.path) else { continue }

            let entries = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            if entries.isEmpty {
                let formatter = try EXT4.Formatter(FilePath(image.path), minDiskSize: 8 * 1_024 * 1_024 * 1_024)
                try formatter.close()
                continue
            }

            let work = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString, directoryHint: .isDirectory)
            let archive = work.appending(path: "volume.tar")
            try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: work) }
            let writer = try ArchiveWriter(format: .paxRestricted, filter: .none, file: archive)
            try writer.archiveDirectory(directory)
            try writer.finishEncoding()
            let unpacker = EXT4Unpacker(blockSizeInBytes: 8 * 1_024 * 1_024 * 1_024)
            try await unpacker.unpack(archive: archive, compression: .none, at: image)
        }
    }

    private static func extractImageLayer(
        _ reader: ArchiveReader, paths selectedPaths: [[String]], to destination: URL
    ) throws {
        let manager = FileManager.default
        var hardlinks: [(URL, URL)] = []
        for (entry, data) in reader.makeStreamingIterator() {
            guard let rawPath = entry.path else { continue }
            let components = rawPath.split(separator: "/").map(String.init).filter { $0 != "." }
            guard !components.contains(".."), selectedPaths.contains(where: { components.starts(with: $0) }) else { continue }
            let target = destination.appending(path: components.joined(separator: "/"))
            try manager.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)

            if let hardlink = entry.hardlink {
                let linkComponents = hardlink.split(separator: "/").map(String.init).filter { $0 != "." }
                guard !linkComponents.contains(".."), selectedPaths.contains(where: { linkComponents.starts(with: $0) }) else { continue }
                hardlinks.append((target, destination.appending(path: linkComponents.joined(separator: "/"))))
                continue
            }
            if itemExists(target) { try manager.removeItem(at: target) }
            switch entry.fileType {
            case .directory:
                try manager.createDirectory(at: target, withIntermediateDirectories: true)
            case .symbolicLink:
                if let link = entry.symlinkTarget { try manager.createSymbolicLink(atPath: target.path, withDestinationPath: link) }
            case .regular:
                guard manager.createFile(atPath: target.path, contents: nil) else {
                    throw EngineError(.internalError, "failed to create volume copy-up file: \(target.path)")
                }
                let handle = try FileHandle(forWritingTo: target)
                defer { try? handle.close() }
                var buffer = [UInt8](repeating: 0, count: 128 * 1_024)
                while true {
                    let count = data.read(&buffer, maxLength: buffer.count)
                    guard count >= 0 else { throw EngineError(.internalError, "failed to read image layer entry: \(rawPath)") }
                    guard count > 0 else { break }
                    try handle.write(contentsOf: Data(buffer.prefix(count)))
                }
            default:
                continue
            }
            try? manager.setAttributes([.posixPermissions: NSNumber(value: entry.permissions & 0o7777)], ofItemAtPath: target.path)
        }
        for (target, source) in hardlinks where itemExists(source) {
            if itemExists(target) { try manager.removeItem(at: target) }
            try manager.linkItem(at: source, to: target)
        }
    }

    private static func itemExists(_ url: URL) -> Bool {
        FileManager.default.fileExists(atPath: url.path)
            || (try? FileManager.default.destinationOfSymbolicLink(atPath: url.path)) != nil
    }

    private static func applyImageLayer(_ source: URL, to destination: URL) throws {
        let manager = FileManager.default
        try manager.createDirectory(at: destination, withIntermediateDirectories: true)
        let entries = try manager.contentsOfDirectory(
            at: source, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey]
        )

        if entries.contains(where: { $0.lastPathComponent == ".wh..wh..opq" }) {
            for existing in try manager.contentsOfDirectory(at: destination, includingPropertiesForKeys: nil) {
                try manager.removeItem(at: existing)
            }
        }
        for entry in entries where entry.lastPathComponent.hasPrefix(".wh.") {
            guard entry.lastPathComponent != ".wh..wh..opq" else { continue }
            let target = destination.appending(path: String(entry.lastPathComponent.dropFirst(4)))
            if itemExists(target) { try manager.removeItem(at: target) }
        }
        for entry in entries where !entry.lastPathComponent.hasPrefix(".wh.") {
            let target = destination.appending(path: entry.lastPathComponent)
            let values = try entry.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            if values.isDirectory == true, values.isSymbolicLink != true {
                var targetIsDirectory: ObjCBool = false
                if manager.fileExists(atPath: target.path, isDirectory: &targetIsDirectory), !targetIsDirectory.boolValue {
                    try manager.removeItem(at: target)
                }
                try applyImageLayer(entry, to: target)
            } else {
                if itemExists(target) { try manager.removeItem(at: target) }
                try manager.copyItem(at: entry, to: target)
            }
        }
    }

    public func start(_ record: ContainerRecord) async throws -> [PortBinding] {
        guard preparedRecords[record.id] != nil else { throw EngineError(.notFound, "container was not prepared") }
        let container = try await createPreparedContainer(record)
        containers[record.id] = container
        try await container.create()
        try await container.start()
        var resolvedPorts = record.ports
        if !record.ports.isEmpty, let primaryID = record.networks.first?.networkID,
           let interface = interfaces[record.id]?[primaryID] {
            do {
                resolvedPorts = try await portForwarder.start(
                    containerID: record.id,
                    guestIPv4Address: interface.ipv4Address.address.description,
                    guestIPv6Address: interface.ipv6Address?.address.description,
                    bindings: record.ports
                )
            } catch {
                try? await container.stop()
                throw error
            }
        }
        let io = ioBridges[record.id]
        waitTasks[record.id] = Task {
            do {
                let status = try await container.wait()
                io?.finishOutput()
                try? await container.stop()
                return status.exitCode
            } catch {
                io?.finishOutput()
                return 127
            }
        }
        await synchronizeHosts()
        return resolvedPorts
    }

    public func wait(_ record: ContainerRecord) async throws -> Int32 {
        guard containers[record.id] != nil else { return record.exitCode ?? 137 }
        guard let task = waitTasks[record.id] else {
            throw EngineError(.conflict, "container has not been started")
        }
        return await task.value
    }

    public func stop(_ record: ContainerRecord, timeoutSeconds: Int) async throws -> Int32 {
        guard let container = containers[record.id] else { return record.exitCode ?? 137 }
        let signal = try Signal(record.stopSignal)
        do {
            try await container.kill(timeoutSeconds == 0 ? .kill : signal)
            let status: ExitStatus
            do {
                status = try await container.wait(timeoutInSeconds: Int64(max(timeoutSeconds, 1)))
            } catch {
                try await container.kill(.kill)
                status = try await container.wait(timeoutInSeconds: 5)
            }
            try await container.stop()
            portForwarder.stop(containerID: record.id)
            return status.exitCode
        } catch {
            try? await container.stop()
            portForwarder.stop(containerID: record.id)
            return record.exitCode ?? 137
        }
    }

    public func delete(_ record: ContainerRecord) async throws {
        if let container = containers.removeValue(forKey: record.id) {
            try? await container.stop()
        }
        portForwarder.stop(containerID: record.id)
        waitTasks.removeValue(forKey: record.id)?.cancel()
        ioBridges.removeValue(forKey: record.id)?.finishOutput()
        preparedRecords.removeValue(forKey: record.id)
        preparedImages.removeValue(forKey: record.id)
        let released = interfaces.removeValue(forKey: record.id) ?? [:]
        for networkID in released.keys {
            guard var network = networks[networkID] else { continue }
                network.releaseInterface("\(record.id)-\(networkID)")
            networks[networkID] = network
        }
        stagedCopies.removeValue(forKey: record.id)
        try? FileManager.default.removeItem(at: stagingRoot.appending(path: record.id))
        try? manager.delete(record.id)
    }

    public func deleteLogs(for record: ContainerRecord) async throws {
        try? FileManager.default.removeItem(at: logRoot.appending(path: "\(record.id).log"))
        try? FileManager.default.removeItem(at: logRoot.appending(path: "\(record.id).log.entries"))
    }

    public func io(for record: ContainerRecord) async throws -> ContainerIOBridge {
        guard let io = ioBridges[record.id] else { throw EngineError(.notFound, "container I/O is unavailable") }
        return io
    }

    public func resize(_ record: ContainerRecord, width: UInt16, height: UInt16) async throws {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        try await container.resize(to: Terminal.Size(width: width, height: height))
    }

    public func endpointAddresses(for record: ContainerRecord) async -> [String: BackendEndpointAddress] {
        (interfaces[record.id] ?? [:]).reduce(into: [:]) { result, pair in
            result[pair.key] = .init(
                ipv4Address: pair.value.ipv4Address.address.description,
                ipv6Address: pair.value.ipv6Address?.address.description ?? ""
            )
        }
    }

    public func statistics(_ record: ContainerRecord) async throws -> BackendStatistics {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        let value = try await container.statistics(categories: .all)
        return BackendStatistics(
            cpuTotalNanoseconds: (value.cpu?.usageUsec ?? 0) * 1_000,
            cpuUserNanoseconds: (value.cpu?.userUsec ?? 0) * 1_000,
            cpuSystemNanoseconds: (value.cpu?.systemUsec ?? 0) * 1_000,
            memoryUsage: value.memory?.usageBytes ?? 0, memoryLimit: value.memory?.limitBytes ?? record.memoryBytes,
            memoryCache: value.memory?.cacheBytes ?? 0, pids: value.process?.current ?? 0,
            blockReadBytes: value.blockIO?.devices.reduce(0) { $0 + $1.readBytes } ?? 0,
            blockWriteBytes: value.blockIO?.devices.reduce(0) { $0 + $1.writeBytes } ?? 0,
            networks: (value.networks ?? []).map {
                .init(name: $0.interface, rxBytes: $0.receivedBytes, rxPackets: $0.receivedPackets,
                      rxErrors: $0.receivedErrors, txBytes: $0.transmittedBytes,
                      txPackets: $0.transmittedPackets, txErrors: $0.transmittedErrors)
            }
        )
    }

    public func top(_ record: ContainerRecord, arguments: [String]) async throws -> (titles: [String], processes: [[String]]) {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        let capture = CaptureWriter()
        let process = try await container.exec("top-\(UUID().uuidString)") { config in
            config.arguments = ["/bin/sh", "-c", "for d in /proc/[0-9]*; do p=${d##*/}; n=$(cat $d/comm 2>/dev/null); printf '%s|%s\\n' \"$p\" \"$n\"; done"]
            config.stdout = capture; config.stderr = capture
        }
        try await process.start()
        let status = try await process.wait()
        try? await process.delete()
        guard status.exitCode == 0 else { throw EngineError(.internalError, "ps exited with status \(status.exitCode)") }
        let rows = capture.string.split(whereSeparator: \.isNewline).map { line in
            line.split(separator: "|", maxSplits: 1).map(String.init)
        }
        return (["PID", "CMD"], rows)
    }

    public func runHealthcheck(_ record: ContainerRecord, arguments: [String], timeoutSeconds: Int64) async throws -> (exitCode: Int32, output: String) {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        let capture = CaptureWriter()
        let process = try await container.exec("health-\(UUID().uuidString)") { config in
            config.arguments = arguments; config.stdout = capture; config.stderr = capture
        }
        try await process.start()
        do {
            let status = try await process.wait(timeoutInSeconds: max(timeoutSeconds, 1))
            try? await process.delete()
            return (status.exitCode, capture.string)
        } catch {
            try? await process.kill(.kill); try? await process.delete()
            return (1, "health check timed out")
        }
    }

    public func deleteVolume(_ name: String) async throws {
        let url = volumeRoot.appending(path: name, directoryHint: .isDirectory)
        if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
    }

    public func cleanupOrphans(keeping containerIDs: Set<String>) async throws {
        guard FileManager.default.fileExists(atPath: runtimeContainerRoot.path) else { return }
        for entry in try FileManager.default.contentsOfDirectory(at: runtimeContainerRoot, includingPropertiesForKeys: nil) {
            guard !containerIDs.contains(entry.lastPathComponent) else { continue }
            try FileManager.default.removeItem(at: entry)
        }
        for entry in try FileManager.default.contentsOfDirectory(at: logRoot, includingPropertiesForKeys: nil) {
            let name = entry.lastPathComponent
            let id = name.split(separator: ".", maxSplits: 1).first.map(String.init) ?? name
            if !containerIDs.contains(id) { try? FileManager.default.removeItem(at: entry) }
        }
    }

    public func updateNetworkRecords(_ records: [ContainerRecord]) async throws {
        let byID = Dictionary(uniqueKeysWithValues: records.map { ($0.id, $0) })
        for id in Array(preparedRecords.keys) {
            guard let record = byID[id] else { continue }
            preparedRecords[id] = record
            guard containers[id] == nil else { continue }
            let old = interfaces.removeValue(forKey: id) ?? [:]
            for networkID in old.keys {
                guard var network = networks[networkID] else { continue }
                network.releaseInterface("\(id)-\(networkID)")
                networks[networkID] = network
            }
            interfaces[id] = try allocateInterfaces(for: record)
        }
        await synchronizeHosts()
    }

    private func hostEntries(for record: ContainerRecord, records: [ContainerRecord]) -> [Hosts.Entry] {
        let networkIDs = Set(record.networks.map(\.networkID))
        return records.flatMap { peer -> [Hosts.Entry] in
            guard let peerInterfaces = interfaces[peer.id] else { return [] }
            let shared = peer.id == record.id ? Set(peer.networks.map(\.networkID))
                : networkIDs.intersection(peer.networks.map(\.networkID))
            return shared.flatMap { networkID -> [Hosts.Entry] in
                guard let peerInterface = peerInterfaces[networkID] else { return [] }
                let aliases = peer.networks.first(where: { $0.networkID == networkID })?.aliases ?? []
                let names = Set([peer.name, peer.hostname] + aliases).filter {
                    !$0.isEmpty && $0.allSatisfy { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" }
                }.sorted()
                guard !names.isEmpty else { return [] }
                var entries = [Hosts.Entry(ipAddress: peerInterface.ipv4Address.address.description, hostnames: names)]
                if let ipv6 = peerInterface.ipv6Address {
                    entries.append(.init(ipAddress: ipv6.address.description, hostnames: names))
                }
                return entries
            }
        }
    }

    private func synchronizeHosts() async {
        let records = Array(preparedRecords.values)
        for record in records {
            guard let container = containers[record.id] else { continue }
            let hosts = Hosts(entries: Hosts.default.entries + hostEntries(for: record, records: records)).hostsFile
            let escaped = hosts.replacingOccurrences(of: "'", with: "'\"'\"'")
            guard let process = try? await container.exec("hosts-\(UUID().uuidString)", configuration: {
                var config = LinuxProcessConfiguration(); config.arguments = ["/bin/sh", "-c", "printf '%s' '\(escaped)' > /etc/hosts"]
                return config
            }()) else { continue }
            try? await process.start(); _ = try? await process.wait(timeoutInSeconds: 5); try? await process.delete()
        }
    }

    public func completion(_ record: ContainerRecord) async -> Int32? {
        guard let task = waitTasks[record.id] else { return nil }
        return await task.value
    }

    public func logs(for record: ContainerRecord) async throws -> Data {
        guard let io = ioBridges[record.id] else {
            let url = logRoot.appending(path: "\(record.id).log")
            guard FileManager.default.fileExists(atPath: url.path) else { return Data() }
            return try Data(contentsOf: url)
        }
        return try io.logData()
    }

    public func logs(for record: ContainerRecord, options: DockerLogOptions) async throws -> Data {
        if let io = ioBridges[record.id] { return try io.logData(options: options) }
        return try await logs(for: record)
    }

    public func kill(_ record: ContainerRecord, signal: String) async throws {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        try await container.kill(try Signal(signal))
    }

    public func pause(_ record: ContainerRecord) async throws {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        try await container.withVirtualMachineInstance { try await $0.pause() }
    }

    public func resume(_ record: ContainerRecord) async throws {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        try await container.withVirtualMachineInstance { try await $0.resume() }
    }

    public func prepareExec(_ exec: ExecRecord, container record: ContainerRecord) async throws -> ContainerIOBridge {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        let io = ContainerIOBridge(tty: exec.configuration.tty)
        let process = try await container.exec(exec.id) { config in
            config.arguments = exec.configuration.arguments
            config.environmentVariables = record.environment + exec.configuration.environment
            if !config.environmentVariables.contains(where: { $0.hasPrefix("PATH=") }) {
                config.environmentVariables.append("PATH=\(LinuxProcessConfiguration.defaultPath)")
            }
            config.workingDirectory = exec.configuration.workingDirectory.isEmpty
                ? (record.workingDirectory.isEmpty ? "/" : record.workingDirectory)
                : exec.configuration.workingDirectory
            let user = exec.configuration.user.isEmpty ? record.user : exec.configuration.user
            if !user.isEmpty { config.user = Self.parseUser(user) }
            config.terminal = exec.configuration.tty
            if exec.configuration.attachStdin { config.stdin = io }
            if exec.configuration.attachStdout { config.stdout = io.writer(.stdout) }
            if exec.configuration.attachStderr && !exec.configuration.tty { config.stderr = io.writer(.stderr) }
            if exec.configuration.privileged { config.capabilities = .allCapabilities }
        }
        execProcesses[exec.id] = process
        execBridges[exec.id] = io
        return io
    }

    public func startExec(_ exec: ExecRecord) async throws {
        guard let process = execProcesses[exec.id], let io = execBridges[exec.id] else {
            throw EngineError(.notFound, "No such exec instance: \(exec.id)")
        }
        try await process.start()
        execWaitTasks[exec.id] = Task { [weak self] in
            do {
                let status = try await process.wait()
                await self?.recordExecExit(exec.id, code: status.exitCode, io: io, process: process)
                return status.exitCode
            } catch {
                await self?.recordExecExit(exec.id, code: 127, io: io, process: process)
                return 127
            }
        }
    }

    public func execCompletion(_ exec: ExecRecord) async -> Int32? {
        guard let task = execWaitTasks[exec.id] else { return nil }
        return await task.value
    }

    public func execIO(_ exec: ExecRecord) async throws -> ContainerIOBridge {
        guard let io = execBridges[exec.id] else { throw EngineError(.notFound, "No such exec instance: \(exec.id)") }
        return io
    }

    public func execPID(_ exec: ExecRecord) async -> Int32 { execProcesses[exec.id]?.pid ?? 0 }
    public func execStatus(_ exec: ExecRecord) async -> Int32? { execExitCodes[exec.id] }

    public func resizeExec(_ exec: ExecRecord, width: UInt16, height: UInt16) async throws {
        guard let process = execProcesses[exec.id] else { throw EngineError(.notFound, "No such exec instance: \(exec.id)") }
        try await process.resize(to: Terminal.Size(width: width, height: height))
    }

    private func recordExecExit(_ id: String, code: Int32, io: ContainerIOBridge, process: LinuxProcess) async {
        execExitCodes[id] = code
        io.finishOutput()
        try? await process.delete()
    }

    public func copyIn(_ record: ContainerRecord, extractedDirectory: URL, destination: String,
                       ownership: [ArchiveOwnership]) async throws {
        if containers[record.id] == nil {
            guard preparedRecords[record.id] != nil else { throw EngineError(.notFound, "container runtime is unavailable") }
            let directory = stagingRoot.appending(path: record.id).appending(path: UUID().uuidString, directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: directory.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.copyItem(at: extractedDirectory, to: directory)
            stagedCopies[record.id, default: []].append(.init(source: directory, destination: destination))
            return
        }
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        let entries = try FileManager.default.contentsOfDirectory(
            at: extractedDirectory, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]
        )
        for entry in entries {
            try await container.copyIn(from: entry, to: URL(filePath: destination, directoryHint: .isDirectory))
        }
        for value in ownership {
            let target = URL(filePath: destination, directoryHint: .isDirectory).appending(path: value.path).path
            let process = try await container.exec("chown-\(UUID().uuidString)") { config in
                config.arguments = ["/bin/chown", "\(value.user):\(value.group)", target]
            }
            try await process.start()
            let status = try await process.wait()
            try? await process.delete()
            guard status.exitCode == 0 else {
                throw EngineError(.internalError, "failed to preserve archive ownership for \(value.path)")
            }
        }
    }

    public func copyOut(_ record: ContainerRecord, source: String, destinationDirectory: URL) async throws {
        guard let container = containers[record.id] else { throw EngineError(.notFound, "container runtime is unavailable") }
        try FileManager.default.createDirectory(at: destinationDirectory, withIntermediateDirectories: true)
        let destination = destinationDirectory.appending(path: URL(filePath: source).lastPathComponent)
        try await container.copyOut(from: URL(filePath: source), to: destination)
    }

    public func loadImages(fromOCILayout directory: URL) async throws -> [BackendImage] {
        let images = try await manager.imageStore.load(from: directory)
        return try await describe(images)
    }

    public func listImages() async throws -> [BackendImage]? {
        try await describe(manager.imageStore.list())
    }

    public func deleteImage(reference: String) async throws {
        try await manager.imageStore.delete(reference: reference, performCleanup: true)
    }

    public func tagImage(existing: String, new: String) async throws {
        _ = try await manager.imageStore.tag(existing: existing, new: new)
    }

    public func pushImage(reference: String, platform: String, credentials: RegistryCredentials?) async throws {
        let authentication: (any Authentication)? = credentials.flatMap {
            let secret = $0.identityToken.isEmpty ? $0.password : $0.identityToken
            return $0.username.isEmpty && secret.isEmpty ? nil : BasicAuthentication(username: $0.username, password: secret)
        }
        let insecure = reference.hasPrefix("localhost:") || reference.hasPrefix("127.0.0.1:")
        try await manager.imageStore.push(
            reference: reference, platform: try Self.platform(platform), insecure: insecure, auth: authentication
        )
    }

    public func saveImages(references: [String], platform: String) async throws -> Data {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString, directoryHint: .isDirectory)
        let archive = directory.appending(path: "images.tar")
        let layout = directory.appending(path: "layout", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try await manager.imageStore.save(references: references, out: layout, platform: try Self.platform(platform))
        let writer = try ArchiveWriter(format: .pax, filter: .none, file: archive)
        try writer.archiveDirectory(layout)
        try writer.finishEncoding()
        return try Data(contentsOf: archive)
    }

    private func describe(_ images: [Containerization.Image]) async throws -> [BackendImage] {
        try await images.asyncMap { image in
            let config = try await image.config(for: .current)
            return BackendImage(id: image.digest, reference: image.reference, size: image.descriptor.size,
                                architecture: config.architecture, os: config.os)
        }
    }

    private static func parseUser(_ value: String) -> ContainerizationOCI.User {
        guard !value.isEmpty else { return ContainerizationOCI.User() }
        let components = value.split(separator: ":", maxSplits: 1).map(String.init)
        if let uid = UInt32(components[0]) {
            return ContainerizationOCI.User(uid: uid, gid: components.count == 2 ? UInt32(components[1]) ?? uid : uid)
        }
        return ContainerizationOCI.User(username: value)
    }

    private static func platform(_ value: String) throws -> ContainerizationOCI.Platform {
        let parts = value.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2, parts[0] == "linux", parts[1] == "arm64" || parts[1] == "amd64" else {
            throw EngineError(.unsupported, "unsupported platform \(value)")
        }
        return .init(arch: parts[1], os: parts[0])
    }

    private func image(reference: String, platform: String, pull: Bool) async throws -> Containerization.Image {
        let selected = try Self.platform(platform)
        for candidate in Self.imageLookupCandidates(reference) {
            if let existing = try? await manager.imageStore.get(reference: candidate),
               (try? await existing.config(for: selected)) != nil { return existing }
        }
        guard pull else { throw EngineError(.notFound, "image \(reference) does not contain \(platform)") }
        return try await manager.imageStore.pull(reference: reference, platform: selected)
    }

    private static func imageLookupCandidates(_ reference: String) -> [String] {
        let normalized = ImageReference.normalized(reference)
        var candidates = [reference, normalized]
        if normalized.hasPrefix("docker.io/library/") {
            candidates.append(String(normalized.dropFirst("docker.io/library/".count)))
        } else if normalized.hasPrefix("docker.io/") {
            candidates.append(String(normalized.dropFirst("docker.io/".count)))
        }
        var seen = Set<String>()
        return candidates.filter { seen.insert($0).inserted }
    }
}

private extension Sequence {
    func asyncMap<T>(_ transform: (Element) async throws -> T) async rethrows -> [T] {
        var result: [T] = []
        for element in self { result.append(try await transform(element)) }
        return result
    }
}

private final class CaptureWriter: Writer, @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    var string: String { lock.withLock { String(decoding: data, as: UTF8.self) } }
    func write(_ value: Data) throws { lock.withLock { data.append(value) } }
    func close() throws {}
}

private actor PullProgressAccumulator {
    private var value = ImagePullProgress()
    func apply(_ events: [ProgressEvent]) -> ImagePullProgress {
        var items = value.completedItems, totalItems = value.totalItems
        var bytes = value.completedBytes, totalBytes = value.totalBytes
        for event in events {
            switch event {
            case .addItems(let amount): items += amount
            case .addTotalItems(let amount): totalItems += amount
            case .addSize(let amount): bytes += amount
            case .addTotalSize(let amount): totalBytes += amount
            }
        }
        value = .init(completedItems: items, totalItems: totalItems, completedBytes: bytes, totalBytes: totalBytes)
        return value
    }
}
#endif
