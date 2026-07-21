#if os(macOS)
import CEngineCore
import Darwin
import Foundation

enum VMShimAttachmentBoundary: Equatable, Sendable {
    case rootDiskOpened
    case volumeDiskOpened(String)
    case bindShareOpened(String)
}

typealias VMShimAttachmentHook = (VMShimAttachmentBoundary) throws -> Void

struct VMShimAttachmentResources: Sendable {
    let rootDisk: URL
    let additionalDisks: [RawVirtualMachineConfiguration.BlockDisk]
    let bindShares: [RawVirtualMachineConfiguration.BindShare]
    let retainedHandles: [FileHandle]
}

/// Resolves mutable attachment paths once, through no-follow descriptors, and
/// converts them to `/dev/fd` URLs while retaining every descriptor for the VM
/// lifetime. Later path replacement therefore cannot change what VZ opens.
enum VMShimAttachmentResolver {
    static func resolve(
        _ specification: VMShimProtocol.Specification,
        hook: VMShimAttachmentHook? = nil
    ) throws -> VMShimAttachmentResources {
        let root = try openRegularFile(
            path: specification.rootDiskPath,
            expected: specification.rootDiskIdentity,
            expectedSize: specification.rootDiskSize,
            identityRequired: true
        )
        try hook?(.rootDiskOpened)
        try root.validate()

        var handles = [root.handle]
        var disks: [RawVirtualMachineConfiguration.BlockDisk] = []
        for (index, disk) in specification.volumeDisks.enumerated() {
            if specification.kind == .container,
               disk.identity == nil || disk.size == nil {
                throw EngineError(.conflict, "container VM volume disk has no durable identity")
            }
            let opened = try openRegularFile(
                path: disk.path,
                expected: disk.identity,
                expectedSize: disk.size,
                identityRequired: specification.kind == .container
            )
            try hook?(.volumeDiskOpened(disk.name))
            try opened.validate()
            handles.append(opened.handle)
            disks.append(.init(
                identifier: "volume\(index)", source: descriptorURL(opened.handle)
            ))
        }
        var shares: [RawVirtualMachineConfiguration.BindShare] = []
        for share in specification.bindShares {
            if specification.kind == .container, share.sourceIdentity == nil {
                throw EngineError(.conflict, "container VM share has no durable identity")
            }
            let directory = try PersistentStateDirectory.open(URL(filePath: share.source))
            if let expected = share.sourceIdentity {
                guard directory.identity.device == expected.device,
                      directory.identity.inode == expected.inode else {
                    throw EngineError(.conflict, "container VM share identity changed")
                }
            }
            let duplicate = Darwin.fcntl(directory.descriptor, F_DUPFD_CLOEXEC, 0)
            guard duplicate >= 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            let handle = FileHandle(fileDescriptor: duplicate, closeOnDealloc: true)
            try hook?(.bindShareOpened(share.tag))
            guard directory.pathStillNamesThisDirectory() else {
                throw EngineError(.conflict, "container VM share path changed")
            }
            let stableURL = volumeURL(directory.identity)
            let stableDescriptor = Darwin.open(
                stableURL.path,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
            )
            guard stableDescriptor >= 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            var stableInformation = stat()
            let stableMatches = Darwin.fstat(stableDescriptor, &stableInformation) == 0
                && stableInformation.st_mode & S_IFMT == S_IFDIR
                && PersistentFileIdentity(stableInformation) == directory.identity
            Darwin.close(stableDescriptor)
            guard stableMatches else {
                throw EngineError(.conflict, "container VM stable share identity changed")
            }
            handles.append(handle)
            shares.append(.init(
                tag: share.tag,
                source: stableURL,
                readOnly: share.readOnly
            ))
        }
        return .init(
            rootDisk: descriptorURL(root.handle),
            additionalDisks: disks,
            bindShares: shares,
            retainedHandles: handles
        )
    }

    private struct OpenedRegularFile {
        let parent: PersistentStateDirectory
        let name: String
        let handle: FileHandle
        let identity: PersistentFileIdentity
        let expectedSize: UInt64?

        func validate() throws {
            var information = stat()
            guard parent.pathStillNamesThisDirectory(),
                  let current = try parent.entryMetadata(named: name),
                  current.identity == identity,
                  current.type == S_IFREG,
                  Darwin.fstat(handle.fileDescriptor, &information) == 0,
                  information.st_mode & S_IFMT == S_IFREG,
                  PersistentFileIdentity(information) == identity,
                  information.st_size >= 0,
                  expectedSize == nil || UInt64(information.st_size) == expectedSize else {
                throw EngineError(.conflict, "container VM root disk path changed")
            }
        }
    }

    private static func openRegularFile(
        path: String,
        expected: VMShimProtocol.FileIdentity?,
        expectedSize: UInt64?,
        identityRequired: Bool
    ) throws -> OpenedRegularFile {
        guard !identityRequired || expected != nil && expectedSize != nil else {
            throw EngineError(.conflict, "VM disk has no durable identity or size")
        }
        let url = URL(filePath: path).standardizedFileURL
        let parent = try PersistentStateDirectory.open(url.deletingLastPathComponent())
        let expectedIdentity = expected.map {
            PersistentFileIdentity(device: $0.device, inode: $0.inode)
        }
        let opened = try parent.openRegularFile(
            named: url.lastPathComponent,
            expectedIdentity: expectedIdentity,
            access: .readWrite
        )
        return .init(
            parent: parent,
            name: url.lastPathComponent,
            handle: opened.handle,
            identity: opened.identity,
            expectedSize: expectedSize
        )
    }

    private static func descriptorURL(_ handle: FileHandle) -> URL {
        URL(filePath: "/dev/fd/\(handle.fileDescriptor)")
    }

    private static func volumeURL(_ identity: PersistentFileIdentity) -> URL {
        URL(filePath: "/.vol/\(identity.device)/\(identity.inode)")
    }
}

@MainActor public final class VMShimServer {
    private struct NetworkBridgeRegistration {
        let generation: UUID
        let bridge: NetworkStreamBridge
    }

    private struct UplinkRecovery {
        let generation: UUID
        let task: Task<Void, Never>
    }

    private let specification: VMShimProtocol.Specification
    private let launchIntentURL: URL?
    private var runtimeArtifactPublication: VMShimClient.PersistentRuntimeArtifactPublication?
    private var machine: RawContainerVirtualMachine?
    private var state: VMShimProtocol.State = .created
    private var exitCode: Int32?
    private var failure: String?
    private var listener: Int32 = -1
    private var statusDescriptor: Int32 = -1
    private var serviceListener: Int32 = -1
    private var serviceRelays: [UUID: BidirectionalDescriptorRelay] = [:]
    private var hostSocketRelays: [UnixVirtioSocketRelay] = []
    private let fabric = TrunkNetworkFabric()
    private var networkListener: Int32 = -1
    private var networkBridge: NetworkStreamBridge?
    private var networkBridges: [String: NetworkBridgeRegistration] = [:]
    private var activeVLANs: [UInt16]
    private var uplinks: [String: VMNetUplink] = [:]
    private var uplinkRecoveries: [String: UplinkRecovery] = [:]
    private var fabricNetworks: [String: VMShimClient.FabricNetwork] = [:]

    public init(
        specification: VMShimProtocol.Specification,
        launchIntentURL: URL? = nil
    ) {
        self.specification = specification
        self.launchIntentURL = launchIntentURL
        activeVLANs = specification.vlans
    }

    public static func run(
        specificationURL: URL,
        launchIntentURL: URL? = nil
    ) async throws -> Never {
        let specification = try launchSpecification(
            specificationURL: specificationURL,
            launchIntentURL: launchIntentURL
        )
        let server = VMShimServer(
            specification: specification, launchIntentURL: launchIntentURL
        )
        if let launchIntentURL {
            server.runtimeArtifactPublication = try VMShimClient.preparePersistentRuntimeArtifacts(
                intentURL: launchIntentURL,
                socketPaths: ownedSocketPaths(specification),
                statusPath: specification.socketPath + ".status"
            )
        }
        do {
            try server.startListener()
            if specification.kind == .storage {
                try server.startStorageProxy()
                try server.startNetworkFabric()
            }
            try server.persist()
            if let publication = server.runtimeArtifactPublication {
                _ = try VMShimClient.publishPersistentRuntimeArtifacts(publication)
            }
        } catch {
            if let launchIntentURL {
                try? VMShimClient.cleanupPersistentRuntimeArtifacts(
                    intentURL: launchIntentURL
                )
            }
            throw error
        }
        server.activateListener()
        await withUnsafeContinuation { (_: UnsafeContinuation<Void, Never>) in }
        fatalError("VM shim listener returned")
    }

    static func launchSpecification(
        specificationURL: URL,
        launchIntentURL: URL?,
        publish: (URL) throws -> VMShimClient.PersistentLaunchRecord = {
            try VMShimClient.publishPersistentLaunchIdentity(intentURL: $0)
        }
    ) throws -> VMShimProtocol.Specification {
        guard let launchIntentURL else {
            return try JSONDecoder().decode(
                VMShimProtocol.Specification.self,
                from: Data(contentsOf: specificationURL)
            )
        }
        // The immutable publication is the single source of launch truth.
        // Re-reading the lexical spec path here would allow a replacement
        // between ownership validation and VM construction.
        let record = try publish(launchIntentURL)
        guard VMShimClient.launchPathsMatch(
            record.specificationPath, specificationURL.path
        ) else {
            throw EngineError(.conflict, "published VM shim specification path changed")
        }
        return record.specification
    }

    private func startListener() throws {
        listener = try UnixSocket.listen(path: try runtimeArtifactPath(
            specification.socketPath
        ))
    }

    private func activateListener() {
        let descriptor = listener
        Task.detached { [weak self] in
            while let self {
                do {
                    let client = try UnixSocket.accept(descriptor)
                    Task { @MainActor in await self.handle(client) }
                } catch { return }
            }
        }
    }

    private func handle(_ descriptor: Int32) async {
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var request: VMShimProtocol.Envelope?
        do {
            let decoded = try VMShimProtocol.decode(try readFrame(file))
            request = decoded
            guard decoded.token == specification.token else { throw EngineError(.unauthorized, "invalid VM shim token") }
            switch decoded.operation {
            case .startExecStream:
                try await startExecStream(decoded, local: file)
                return
            case .startPortStream:
                try await startPortStream(decoded, local: file)
                return
            default:
                break
            }
            let payload = try await perform(decoded)
            try file.write(contentsOf: VMShimProtocol.encode(.init(id: decoded.id, token: specification.token, operation: decoded.operation, payload: payload)))
            if decoded.operation == .shutdown {
                if let launchIntentURL {
                    try VMShimClient.cleanupPersistentRuntimeArtifacts(
                        intentURL: launchIntentURL
                    )
                } else {
                    for path in Self.ownedSocketPaths(specification)
                        + [specification.socketPath + ".status"] {
                        try? FileManager.default.removeItem(atPath: path)
                    }
                }
                Darwin.exit(0)
            }
        } catch {
            let code = error is BackendResourceRollbackIncompleteError
                ? GuestProtocol.resourceRollbackIncompleteErrorCode
                : "shim_error"
            let failure = GuestProtocol.Failure(code: code, message: error.localizedDescription)
            try? file.write(contentsOf: VMShimProtocol.encode(.init(
                id: request?.id ?? UUID().uuidString,
                token: specification.token,
                operation: request?.operation ?? .status,
                error: failure
            )))
        }
    }

    nonisolated static func ownedSocketPaths(
        _ specification: VMShimProtocol.Specification
    ) -> [String] {
        var paths = [specification.socketPath]
        if specification.kind == .storage {
            paths.append(contentsOf: [specification.fileSystemSocketPath, specification.networkSocketPath].compactMap { $0 })
        }
        return paths
    }

    nonisolated static func guestConnectTimeout(
        deadlineNanoseconds: UInt64?,
        nowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) throws -> Duration {
        guard let deadlineNanoseconds else { return .seconds(5) }
        guard deadlineNanoseconds > nowNanoseconds else {
            throw AsyncTimeout.TimeoutError()
        }
        return .nanoseconds(Int64(min(
            deadlineNanoseconds - nowNanoseconds, UInt64(Int64.max)
        )))
    }

    private func perform(_ request: VMShimProtocol.Envelope) async throws -> Data {
        switch request.operation {
        case .status: return try JSONEncoder().encode(status())
        case .boot:
            try await boot()
            return try JSONEncoder().encode(status())
        case .guest:
            guard let payload = request.payload else { throw EngineError(.badRequest, "guest request has no payload") }
            let call = try JSONDecoder().decode(VMShimClient.GuestCall.self, from: payload)
            guard let machine else { throw EngineError(.conflict, "VM guest control is unavailable") }
            let connectTimeout = try Self.guestConnectTimeout(
                deadlineNanoseconds: call.deadlineNanoseconds
            )
            let connection = try await machine.connect(
                toPort: GuestProtocol.controlPort, timeout: connectTimeout
            )
            defer { connection.close() }
            let control = GuestControlConnection(connection: SendableVirtioSocketConnection(connection))
            return try await control.requestRaw(
                operation: call.operation,
                payload: call.payload,
                deadlineNanoseconds: call.deadlineNanoseconds
            )
        case .prepareRootFS:
            guard let payload = request.payload, let machine else { throw EngineError(.conflict, "VM is not booted") }
            let value = try JSONDecoder().decode(VMShimClient.RootFSRequest.self, from: payload)
            let store = try OCIContentStore(root: URL(filePath: value.contentStorePath))
            try await RootFSContentStreamer(store: store).prepare(machine: machine, layers: value.layers)
            return try JSONEncoder().encode(Empty())
        case .startExecStream, .startPortStream:
            throw EngineError(.internalError, "streams must be upgraded before dispatch")
        case .configureNetwork:
            struct Configuration: Decodable { let vlans: [UInt16] }
            guard let payload = request.payload else { throw EngineError(.badRequest, "network configuration has no payload") }
            let configuration = try JSONDecoder().decode(Configuration.self, from: payload)
            guard configuration.vlans.allSatisfy({ (1...4094).contains($0) }) else { throw EngineError(.badRequest, "invalid VLAN membership") }
            activeVLANs = Array(Set(configuration.vlans).union([VMShimProtocol.managementVLAN])).sorted()
            if let machine {
                guard let path = specification.networkSocketPath else {
                    throw EngineError(.internalError, "container shim has no network transport socket")
                }
                try connectFabric(machine, path: path)
            }
            try persist()
            return try JSONEncoder().encode(status())
        case .configureFabric:
            guard specification.kind == .storage else { throw EngineError(.unsupported, "fabric configuration belongs to the infrastructure shim") }
            struct Configuration: Decodable { let networks: [VMShimClient.FabricNetwork] }
            guard let payload = request.payload else { throw EngineError(.badRequest, "fabric configuration has no payload") }
            let configuration = try JSONDecoder().decode(Configuration.self, from: payload)
            try await configureFabric(configuration.networks)
            return try JSONEncoder().encode(status())
        case .pause:
            guard let machine else { throw EngineError(.conflict, "VM is not booted") }
            try await machine.pause(); state = .paused; try persist(); return try JSONEncoder().encode(status())
        case .resume:
            guard let machine else { throw EngineError(.conflict, "VM is not booted") }
            try await machine.resume(); state = .running; try persist(); return try JSONEncoder().encode(status())
        case .stop:
            if let machine { try await machine.forceStop() }
            if specification.kind == .storage { await fabric.unregister(.init("storage-service")) }
            machine = nil; hostSocketRelays.removeAll(); state = .stopped; try persist(); return try JSONEncoder().encode(status())
        case .shutdown:
            if let machine { try? await machine.forceStop() }
            if specification.kind == .storage { await fabric.unregister(.init("storage-service")) }
            machine = nil; hostSocketRelays.removeAll(); state = .stopped; try persist(); return try JSONEncoder().encode(status())
        }
    }

    private func boot() async throws {
        guard machine == nil else { return }
        state = .starting; try persist()
        do {
            let attachments = try VMShimAttachmentResolver.resolve(specification)
            let config = RawVirtualMachineConfiguration(
                id: specification.containerID,
                kernel: URL(filePath: specification.kernelPath),
                initialRamdisk: URL(filePath: specification.initialRamdiskPath),
                rootDisk: attachments.rootDisk,
                rootDiskReadOnly: specification.rootDiskReadOnly,
                additionalDisks: attachments.additionalDisks,
                cpus: specification.cpus,
                memoryBytes: specification.memoryBytes,
                macAddress: specification.macAddress,
                bindShares: attachments.bindShares,
                retainedAttachmentHandles: attachments.retainedHandles,
                kernelArguments: specification.kernelArguments
            )
            let value = try RawContainerVirtualMachine(configuration: config)
            hostSocketRelays = try specification.socketRelays.map { specification in
                let relay = UnixVirtioSocketRelay(socketPath: specification.path)
                try value.install(listener: relay.listener, port: specification.port)
                return relay
            }
            if specification.kind == .storage {
                try await value.startInfrastructure(servicePort: GuestProtocol.fileSystemPort)
                await fabric.register(.init("storage-service"), file: value.trunk.fabricFileHandle, vlans: Set(activeVLANs))
            } else {
                try await value.start()
                guard let networkPath = specification.networkSocketPath else {
                    throw EngineError(.internalError, "container shim network transport socket is missing")
                }
                try connectFabric(value, path: networkPath)
            }
            machine = value; state = .running; failure = nil; try persist()
        } catch {
            if specification.kind == .storage { await fabric.unregister(.init("storage-service")) }
            hostSocketRelays.removeAll()
            state = .failed; failure = error.localizedDescription; try? persist(); throw error
        }
    }

    private func status() -> VMShimProtocol.Status {
        .init(
            containerID: specification.containerID,
            generation: specification.generation,
            state: state,
            processIdentifier: getpid(),
            processStartTime: VMShimClient.processStartTime(for: getpid()),
            exitCode: exitCode,
            error: failure
        )
    }

    private func persist() throws {
        if statusDescriptor < 0 {
            let creationFlags = launchIntentURL == nil
                ? O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC
                : O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC
            statusDescriptor = Darwin.open(
                try runtimeArtifactPath(specification.socketPath + ".status"),
                creationFlags,
                S_IRUSR | S_IWUSR
            )
            guard statusDescriptor >= 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        var information = stat()
        guard Darwin.fstat(statusDescriptor, &information) == 0,
              information.st_mode & S_IFMT == S_IFREG,
              Darwin.ftruncate(statusDescriptor, 0) == 0,
              Darwin.lseek(statusDescriptor, 0, SEEK_SET) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let data = try JSONEncoder().encode(status())
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    statusDescriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    bytes.count - offset
                )
                if count > 0 { offset += count; continue }
                if errno == EINTR { continue }
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        guard Darwin.fsync(statusDescriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    private func startStorageProxy() throws {
        guard let finalPath = specification.fileSystemSocketPath else {
            throw EngineError(.internalError, "storage shim has no filesystem transport socket")
        }
        let path = try runtimeArtifactPath(finalPath)
        serviceListener = try UnixSocket.listen(path: path)
        let descriptor = serviceListener
        Task.detached { [weak self] in
            while let self {
                do {
                    let client = try UnixSocket.accept(descriptor)
                    Task { @MainActor in await self.acceptStorageClient(client) }
                } catch { return }
            }
        }
    }

    private func connectFabric(_ machine: RawContainerVirtualMachine, path: String) throws {
        networkBridge?.finish()
        let descriptor = try UnixSocket.connect(path: path)
        let stream = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let bridge = try NetworkStreamBridge(
            datagrams: machine.trunk.fabricFileHandle,
            stream: stream,
            registration: .init(endpointID: specification.containerID, vlans: activeVLANs)
        )
        networkBridge = bridge
        bridge.start()
    }

    private func startNetworkFabric() throws {
        guard let finalPath = specification.networkSocketPath else {
            throw EngineError(.internalError, "storage shim has no network transport socket")
        }
        let path = try runtimeArtifactPath(finalPath)
        networkListener = try UnixSocket.listen(path: path)
        let descriptor = networkListener
        Task.detached { [weak self] in
            while let self {
                do {
                    let client = try UnixSocket.accept(descriptor)
                    let (registration, stream) = try NetworkStreamBridge.readRegistration(client)
                    Task { @MainActor in await self.acceptNetworkClient(registration, stream: stream) }
                } catch { continue }
            }
        }
    }

    private func runtimeArtifactPath(_ finalPath: String) throws -> String {
        guard let runtimeArtifactPublication else { return finalPath }
        return try runtimeArtifactPublication.stagedPath(for: finalPath)
    }

    private func acceptNetworkClient(_ registration: NetworkRegistration, stream: FileHandle) async {
        do {
            let trunk = try RawPacketTrunk()
            let id = TrunkNetworkFabric.EndpointID(registration.endpointID)
            let generation = UUID()
            let bridge = try NetworkStreamBridge(datagrams: trunk.virtualMachineFileHandle, stream: stream) { [weak self] in
                Task { @MainActor in
                    await self?.removeNetworkBridge(
                        endpointID: registration.endpointID,
                        generation: generation
                    )
                }
            }
            let previous = networkBridges.updateValue(
                .init(generation: generation, bridge: bridge),
                forKey: registration.endpointID
            )
            previous?.bridge.finish()
            await fabric.register(
                id,
                file: trunk.fabricFileHandle,
                vlans: Set(registration.vlans),
                registration: generation
            )
            bridge.start()
        } catch {
            try? stream.close()
        }
    }

    private func removeNetworkBridge(endpointID: String, generation: UUID) async {
        guard networkBridges[endpointID]?.generation == generation else { return }
        networkBridges.removeValue(forKey: endpointID)
        await fabric.unregister(.init(endpointID), registration: generation)
    }

    private func configureFabric(_ values: [VMShimClient.FabricNetwork]) async throws {
        let desired = Dictionary(uniqueKeysWithValues: values.map { ($0.id, $0) })
        let dockerHostGateways = Dictionary(uniqueKeysWithValues: values.compactMap { network in
            network.internalNetwork || network.isolated || network.gateway.isEmpty ? nil : (network.vlan, network.gateway)
        })
        await fabric.configureDockerHostDNS(gateways: dockerHostGateways)
        for id in Set(fabricNetworks.keys).union(desired.keys) where fabricNetworks[id] != desired[id] {
            await cancelUplinkRecovery(id: id)
            if let existing = uplinks.removeValue(forKey: id) {
                await fabric.unregister(.init("uplink-\(id)")); await existing.stop()
            }
            fabricNetworks.removeValue(forKey: id)
            guard let network = desired[id] else { continue }
            fabricNetworks[id] = network
            if network.isolated { continue }
            let uplink = try await VMNetUplink.start(
                network: network,
                namespace: specification.networkNamespace
            )
            await installUplink(uplink, network: network)
        }
    }

    private func installUplink(_ uplink: VMNetUplink, network: VMShimClient.FabricNetwork) async {
        let registration = UUID()
        let onDisconnect: @Sendable () -> Void = { [weak self, weak uplink] in
            Task { @MainActor [weak self, weak uplink] in
                guard let self, let uplink else { return }
                self.uplinkDisconnected(
                    id: network.id,
                    uplink: uplink,
                    registration: registration
                )
            }
        }
        uplinks[network.id] = uplink
        uplink.setDisconnectHandler(onDisconnect)
        await fabric.register(
            .init("uplink-\(network.id)"),
            file: uplink.fabricFileHandle,
            vlans: [network.vlan],
            registration: registration,
            onDisconnect: onDisconnect
        )
    }

    private func uplinkDisconnected(id: String, uplink: VMNetUplink, registration: UUID) {
        guard uplinks[id] === uplink else { return }
        uplinks.removeValue(forKey: id)
        FileHandle.standardError.write(Data("vmnet uplink \(id) disconnected; recreating it\n".utf8))
        let fabric = self.fabric
        Task {
            await fabric.unregister(.init("uplink-\(id)"), registration: registration)
            await uplink.stop()
        }

        uplinkRecoveries.removeValue(forKey: id)?.task.cancel()
        let generation = UUID()
        let task = Task { @MainActor [weak self] in
            guard let self else { return }
            await self.recoverUplink(id: id, generation: generation)
        }
        uplinkRecoveries[id] = .init(generation: generation, task: task)
    }

    private func recoverUplink(id: String, generation: UUID) async {
        var failures = 0
        defer {
            if uplinkRecoveries[id]?.generation == generation {
                uplinkRecoveries.removeValue(forKey: id)
            }
        }

        while !Task.isCancelled, uplinkRecoveries[id]?.generation == generation,
              uplinks[id] == nil, let network = fabricNetworks[id], !network.isolated {
            do {
                let replacement = try await VMNetUplink.start(
                    network: network,
                    namespace: specification.networkNamespace
                )
                guard !Task.isCancelled,
                      uplinkRecoveries[id]?.generation == generation,
                      uplinks[id] == nil,
                      fabricNetworks[id] == network else {
                    await replacement.stop()
                    return
                }
                await installUplink(replacement, network: network)
                FileHandle.standardError.write(Data("vmnet uplink \(id) restored\n".utf8))
                return
            } catch {
                guard !Task.isCancelled, uplinkRecoveries[id]?.generation == generation else { return }
                failures += 1
                if failures == 1 {
                    FileHandle.standardError.write(Data("vmnet uplink \(id) recovery failed; retrying: \(error)\n".utf8))
                }
                let delayMilliseconds = min(100 * (1 << min(failures, 5)), 5_000)
                do { try await Task.sleep(for: .milliseconds(delayMilliseconds)) }
                catch { return }
            }
        }
    }

    private func cancelUplinkRecovery(id: String) async {
        guard let recovery = uplinkRecoveries.removeValue(forKey: id) else { return }
        recovery.task.cancel()
        await recovery.task.value
    }

    private func acceptStorageClient(_ descriptor: Int32) async {
        let local = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            guard let machine else { throw EngineError(.conflict, "storage VM is unavailable") }
            let target = try await machine.connect(toPort: GuestProtocol.fileSystemPort)
            let storageConnection = SendableVirtioSocketConnection(target)
            let id = UUID()
            let relay = BidirectionalDescriptorRelay(
                left: local,
                right: FileHandle(fileDescriptor: storageConnection.connection.fileDescriptor, closeOnDealloc: false),
                close: { try? local.close(); storageConnection.connection.close() },
                completion: { [weak self] in Task { @MainActor in self?.serviceRelays.removeValue(forKey: id) } }
            )
            serviceRelays[id] = relay
            relay.start()
        } catch {
            try? local.close()
        }
    }

    private func startExecStream(_ request: VMShimProtocol.Envelope, local: FileHandle) async throws {
        guard let payload = request.payload else { throw EngineError(.badRequest, "exec stream request has no payload") }
        guard let machine else { throw EngineError(.conflict, "VM guest control is unavailable") }
        _ = try JSONDecoder().decode(VMShimClient.ExecStreamRequest.self, from: payload)

        let connection = try await machine.connect(toPort: GuestProtocol.execIOPort)
        let streamConnection = SendableVirtioSocketConnection(connection)
        let target = FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false)
        let setupDescriptor = Darwin.dup(connection.fileDescriptor)
        guard setupDescriptor >= 0 else {
            streamConnection.connection.close()
            throw EngineError(.internalError, "duplicate exec stream descriptor: \(String(cString: strerror(errno)))")
        }
        let setup = FileHandle(fileDescriptor: setupDescriptor, closeOnDealloc: true)
        do {
            let guestRequest = GuestProtocol.Envelope(operation: "start-exec-stream", payload: payload)
            let setupData = try GuestProtocol.encode(guestRequest)

            try local.write(contentsOf: VMShimProtocol.encode(.init(
                id: request.id,
                token: specification.token,
                operation: request.operation,
                payload: try JSONEncoder().encode(Empty())
            )))

            let id = UUID()
            let relay = BidirectionalDescriptorRelay(
                left: local,
                right: target,
                close: { try? local.close(); streamConnection.connection.close() },
                completion: { [weak self] in Task { @MainActor in self?.serviceRelays.removeValue(forKey: id) } }
            )
            serviceRelays[id] = relay
            do {
                try setup.write(contentsOf: setupData)
                try setup.close()
            } catch {
                relay.cancel()
                throw error
            }
            relay.start(afterActivationByte: VMShimProtocol.execStreamActivationByte)
        } catch {
            try? setup.close()
            streamConnection.connection.close()
            throw error
        }
    }

    private func startPortStream(_ request: VMShimProtocol.Envelope, local: FileHandle) async throws {
        guard let payload = request.payload else {
            throw EngineError(.badRequest, "port stream request has no payload")
        }
        guard let machine else { throw EngineError(.conflict, "VM guest control is unavailable") }
        let value = try JSONDecoder().decode(VMShimClient.PortStreamRequest.self, from: payload)
        guard ["tcp", "udp"].contains(value.transport), value.port != 0 else {
            throw EngineError(.badRequest, "invalid port stream target")
        }

        let connection = try await machine.connect(toPort: GuestProtocol.portProxyPort)
        let streamConnection = SendableVirtioSocketConnection(connection)
        let target = FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false)
        let setupDescriptor = Darwin.dup(connection.fileDescriptor)
        guard setupDescriptor >= 0 else {
            streamConnection.connection.close()
            throw EngineError(.internalError, "duplicate port stream descriptor: \(String(cString: strerror(errno)))")
        }
        let setup = FileHandle(fileDescriptor: setupDescriptor, closeOnDealloc: true)
        do {
            let guestRequest = GuestProtocol.Envelope(operation: "start-port-stream", payload: payload)
            try setup.write(contentsOf: GuestProtocol.encode(guestRequest))
            let guestReply = try GuestProtocol.decode(try readFrame(setup))
            guard guestReply.id == guestRequest.id else {
                throw EngineError(.internalError, "guest port stream response id mismatch")
            }
            if let failure = guestReply.error {
                throw EngineError(.internalError, "guest port proxy \(failure.code): \(failure.message)")
            }
            try setup.close()

            try local.write(contentsOf: VMShimProtocol.encode(.init(
                id: request.id,
                token: specification.token,
                operation: request.operation,
                payload: try JSONEncoder().encode(Empty())
            )))

            let id = UUID()
            let relay = BidirectionalDescriptorRelay(
                left: local,
                right: target,
                close: { try? local.close(); streamConnection.connection.close() },
                completion: { [weak self] in Task { @MainActor in self?.serviceRelays.removeValue(forKey: id) } }
            )
            serviceRelays[id] = relay
            relay.start()
        } catch {
            try? setup.close()
            streamConnection.connection.close()
            throw error
        }
    }

    private func readFrame(_ file: FileHandle) throws -> Data {
        let prefix = try readExactly(file, count: 4)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= VMShimProtocol.maximumFrameSize else { throw EngineError(.badRequest, "invalid VM shim frame") }
        return prefix + (try readExactly(file, count: Int(size)))
    }

    private func readExactly(_ file: FileHandle, count: Int) throws -> Data {
        var data = Data()
        while data.count < count {
            guard let next = try file.read(upToCount: count - data.count), !next.isEmpty else { throw EngineError(.badRequest, "VM shim frame is truncated") }
            data.append(next)
        }
        return data
    }

    private struct Empty: Codable {}
}
#endif
