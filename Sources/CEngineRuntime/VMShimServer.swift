#if os(macOS)
import CEngineCore
import Darwin
import Foundation

@MainActor public final class VMShimServer {
    private let specification: VMShimProtocol.Specification
    private var machine: RawContainerVirtualMachine?
    private var state: VMShimProtocol.State = .created
    private var exitCode: Int32?
    private var failure: String?
    private var listener: Int32 = -1
    private var serviceListener: Int32 = -1
    private var filesystemRelay: UnixVirtioSocketRelay?
    private var serviceRelays: [UUID: BidirectionalDescriptorRelay] = [:]
    private let fabric = TrunkNetworkFabric()
    private var networkListener: Int32 = -1
    private var networkBridge: NetworkStreamBridge?
    private var networkBridges: [String: NetworkStreamBridge] = [:]
    private var activeVLANs: [UInt16]
    private var uplinks: [String: VMNetUplink] = [:]
    private var fabricNetworks: [String: VMShimClient.FabricNetwork] = [:]

    public init(specification: VMShimProtocol.Specification) {
        self.specification = specification
        activeVLANs = specification.vlans
    }

    public static func run(specificationURL: URL) async throws -> Never {
        let specification = try JSONDecoder().decode(VMShimProtocol.Specification.self, from: Data(contentsOf: specificationURL))
        let server = VMShimServer(specification: specification)
        try server.startListener()
        if specification.kind == .storage {
            try server.startStorageProxy()
            try server.startNetworkFabric()
        }
        await withUnsafeContinuation { (_: UnsafeContinuation<Void, Never>) in }
        fatalError("VM shim listener returned")
    }

    private func startListener() throws {
        listener = try UnixSocket.listen(path: specification.socketPath)
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
            let payload = try await perform(decoded)
            try file.write(contentsOf: VMShimProtocol.encode(.init(id: decoded.id, token: specification.token, operation: decoded.operation, payload: payload)))
            if decoded.operation == .shutdown {
                for path in [specification.socketPath, specification.fileSystemSocketPath, specification.networkSocketPath].compactMap({ $0 }) {
                    try? FileManager.default.removeItem(atPath: path)
                }
                Darwin.exit(0)
            }
        } catch {
            let failure = GuestProtocol.Failure(code: "shim_error", message: error.localizedDescription)
            try? file.write(contentsOf: VMShimProtocol.encode(.init(
                id: request?.id ?? UUID().uuidString,
                token: specification.token,
                operation: request?.operation ?? .status,
                error: failure
            )))
        }
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
            let connection = try await machine.connect(toPort: GuestProtocol.controlPort)
            defer { connection.close() }
            let control = GuestControlConnection(connection: SendableVirtioSocketConnection(connection))
            return try await control.requestRaw(operation: call.operation, payload: call.payload)
        case .prepareRootFS:
            guard let payload = request.payload, let machine else { throw EngineError(.conflict, "VM is not booted") }
            let value = try JSONDecoder().decode(VMShimClient.RootFSRequest.self, from: payload)
            let store = try OCIContentStore(root: URL(filePath: value.contentStorePath))
            try await RootFSContentStreamer(store: store).prepare(machine: machine, layers: value.layers)
            return try JSONEncoder().encode(Empty())
        case .configureNetwork:
            struct Configuration: Decodable { let vlans: [UInt16] }
            guard let payload = request.payload else { throw EngineError(.badRequest, "network configuration has no payload") }
            let configuration = try JSONDecoder().decode(Configuration.self, from: payload)
            guard configuration.vlans.allSatisfy({ (1...4094).contains($0) }) else { throw EngineError(.badRequest, "invalid VLAN membership") }
            activeVLANs = configuration.vlans
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
            machine = nil; state = .stopped; try persist(); return try JSONEncoder().encode(status())
        case .shutdown:
            if let machine { try? await machine.forceStop() }
            machine = nil; state = .stopped; try persist(); return try JSONEncoder().encode(status())
        }
    }

    private func boot() async throws {
        guard machine == nil else { return }
        state = .starting; try persist()
        do {
            let config = RawVirtualMachineConfiguration(
                id: specification.containerID,
                kernel: URL(filePath: specification.kernelPath),
                initialRamdisk: URL(filePath: specification.initialRamdiskPath),
                rootDisk: URL(filePath: specification.rootDiskPath),
                rootDiskReadOnly: specification.rootDiskReadOnly,
                cpus: specification.cpus,
                memoryBytes: specification.memoryBytes,
                macAddress: specification.macAddress,
                bindShares: specification.bindShares.map { .init(tag: $0.tag, source: URL(filePath: $0.source), readOnly: $0.readOnly) },
                kernelArguments: specification.kernelArguments
            )
            let value = try RawContainerVirtualMachine(configuration: config)
            if specification.kind == .storage {
                try await value.startInfrastructure(servicePort: GuestProtocol.fileSystemPort)
            } else {
                try await value.start()
                guard let fileSystemPath = specification.fileSystemSocketPath,
                      let networkPath = specification.networkSocketPath else {
                    throw EngineError(.internalError, "container shim transport sockets are missing")
                }
                let relay = UnixVirtioSocketRelay(socketPath: fileSystemPath)
                try value.install(listener: relay.listener, port: GuestProtocol.fileSystemPort)
                filesystemRelay = relay
                try connectFabric(value, path: networkPath)
            }
            machine = value; state = .running; failure = nil; try persist()
        } catch {
            state = .failed; failure = error.localizedDescription; try? persist(); throw error
        }
    }

    private func status() -> VMShimProtocol.Status {
        .init(containerID: specification.containerID, generation: specification.generation, state: state, processIdentifier: getpid(), exitCode: exitCode, error: failure)
    }

    private func persist() throws {
        let url = URL(filePath: specification.socketPath + ".status")
        try JSONEncoder().encode(status()).write(to: url, options: .atomic)
    }

    private func startStorageProxy() throws {
        guard let path = specification.fileSystemSocketPath else {
            throw EngineError(.internalError, "storage shim has no filesystem transport socket")
        }
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
        guard let path = specification.networkSocketPath else {
            throw EngineError(.internalError, "storage shim has no network transport socket")
        }
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

    private func acceptNetworkClient(_ registration: NetworkRegistration, stream: FileHandle) async {
        do {
            let trunk = try RawPacketTrunk()
            let id = TrunkNetworkFabric.EndpointID(registration.endpointID)
            await fabric.register(id, file: trunk.fabricFileHandle, vlans: Set(registration.vlans))
            let bridge = try NetworkStreamBridge(datagrams: trunk.virtualMachineFileHandle, stream: stream) { [weak self] in
                Task { @MainActor in
                    await self?.fabric.unregister(id)
                    self?.networkBridges.removeValue(forKey: registration.endpointID)
                }
            }
            networkBridges[registration.endpointID]?.finish()
            networkBridges[registration.endpointID] = bridge
            bridge.start()
        } catch {
            try? stream.close()
        }
    }

    private func configureFabric(_ values: [VMShimClient.FabricNetwork]) async throws {
        let desired = Dictionary(uniqueKeysWithValues: values.map { ($0.id, $0) })
        for id in Set(fabricNetworks.keys).union(desired.keys) where fabricNetworks[id] != desired[id] {
            if let existing = uplinks.removeValue(forKey: id) {
                await fabric.unregister(.init("uplink-\(id)")); existing.stop()
            }
            fabricNetworks.removeValue(forKey: id)
            guard let network = desired[id] else { continue }
            fabricNetworks[id] = network
            if network.isolated { continue }
            let uplink = try await VMNetUplink.start(network: network)
            uplinks[id] = uplink
            await fabric.register(.init("uplink-\(id)"), file: uplink.fabricFileHandle, vlans: [network.vlan])
        }
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
