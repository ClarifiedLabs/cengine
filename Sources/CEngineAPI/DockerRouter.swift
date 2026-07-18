import CEngineCore
import CEngineRuntime
import Foundation
import NIOHTTP1

public struct APIRequest: Sendable {
    public let method: HTTPMethod
    public let uri: String
    public let headers: HTTPHeaders
    public let body: Data

    public init(method: HTTPMethod, uri: String, headers: HTTPHeaders = [:], body: Data = Data()) {
        self.method = method; self.uri = uri; self.headers = headers; self.body = body
    }
}

public struct APIResponse: Sendable {
    public var status: HTTPResponseStatus
    public var headers: HTTPHeaders
    public var body: Data

    public init(status: HTTPResponseStatus, headers: HTTPHeaders = [:], body: Data = Data()) {
        self.status = status; self.headers = headers; self.body = body
    }
}

public struct DockerRouter: Sendable {
    private let runtime: EngineRuntime
    private let root: URL
    private let containerResourceOverride: ContainerResourceOverride?
    private let resourceScopeManager: ContainerResourceScopeManager?
    private let decoder = JSONDecoder()

    private func nonEmpty(_ value: String?) -> String? {
        value.flatMap { $0.isEmpty ? nil : $0 }
    }
    private func endpointDriverOptions(
        _ endpoint: ContainerCreateRequest.EndpointSettingsRequest?,
        version: DockerAPIVersion
    ) throws -> [String: String]? {
        guard let options = endpoint?.DriverOpts, !options.isEmpty else { return nil }
        guard version >= .init(major: 1, minor: 46) else {
            throw EngineError(.badRequest, "endpoint DriverOpts require API v1.46 or newer")
        }
        return options
    }
    private let encoder = JSONEncoder()

    public init(
        runtime: EngineRuntime,
        root: URL,
        containerResourceOverride: ContainerResourceOverride? = nil,
        resourceScopeManager: ContainerResourceScopeManager? = nil
    ) {
        self.runtime = runtime
        self.root = root
        self.containerResourceOverride = containerResourceOverride
        self.resourceScopeManager = resourceScopeManager
    }

    public func route(_ request: APIRequest) async -> APIResponse {
        do { return try await handle(request) }
        catch let error as EngineError { return dockerErrorResponse(error) }
        catch let error as DecodingError {
            return dockerErrorResponse(EngineError(.badRequest, "invalid request body: \(error.localizedDescription)"))
        }
        catch { return json(status: .internalServerError, DockerErrorBody(message: EngineError.message(for: error))) }
    }

    private func handle(_ request: APIRequest) async throws -> APIResponse {
        let target = try DockerRequestTarget.parse(request.uri)
        let components = target.components
        let path = target.path
        let version = target.version
        let queries = multiQueryItems(components)
        let query = queryItems(components)

        switch (request.method, path) {
        case (.POST, "/_cengine/v1/resource-scopes"):
            guard let resourceScopeManager else { throw EngineError(.notFound, "page not found") }
            let input = try decoder.decode(ContainerResourceScopeCreateRequest.self, from: request.body)
            let scope = try await resourceScopeManager.create(
                ownerPID: input.ownerPID,
                resources: .init(cpus: input.cpus, memoryGiB: input.memoryGiB)
            )
            return json(status: .created, scope)
        case (.DELETE, let value) where value.hasPrefix("/_cengine/v1/resource-scopes/"):
            guard let resourceScopeManager else { throw EngineError(.notFound, "page not found") }
            let id = String(value.dropFirst("/_cengine/v1/resource-scopes/".count))
            guard !id.isEmpty else { throw EngineError(.badRequest, "resource scope ID is required") }
            await resourceScopeManager.remove(id)
            return APIResponse(status: .noContent)
        case (.GET, "/_ping"), (.HEAD, "/_ping"):
            return APIResponse(status: .ok, headers: ["Api-Version": DockerAPIVersion.maximum.description, "Docker-Experimental": "true"], body: request.method == .HEAD ? Data() : Data("OK".utf8))
        case (.GET, "/version"):
            return json(status: .ok, DockerVersionResponse())
        case (.GET, "/info"):
            let all = await runtime.listContainers(all: true)
            return json(status: .ok, DockerInfoResponse(
                Containers: all.count,
                ContainersRunning: all.filter { $0.phase == .running }.count,
                ContainersPaused: all.filter { $0.phase == .paused }.count,
                ContainersStopped: all.filter { $0.phase == .exited || $0.phase == .created }.count,
                DockerRootDir: root.path
            ))
        case (.GET, "/system/df"):
            return json(status: .ok, SystemDiskUsageResponse(
                containers: await runtime.listContainers(all: true),
                images: await runtime.listImages(),
                volumes: await runtime.listVolumes()
            ))
        case (.GET, "/containers/json"):
            let all = parseBool(query["all"]) ?? false
            let containers = filteredContainers(await runtime.listContainers(all: all), filters: query["filters"])
            let networks = await runtime.listNetworks()
            return json(status: .ok, containers.map {
                ContainerSummaryResponse($0, networks: networks, version: version)
            })
        case (.POST, "/containers/create"):
            let input = try decoder.decode(ContainerCreateRequest.self, from: request.body)
            let name = query["name"].flatMap { $0.isEmpty ? nil : $0 } ?? String(Identifier.random().prefix(12))
            var record = ContainerRecord(name: name, image: ImageReference.normalized(input.Image), processArguments: (input.Entrypoint ?? []) + (input.Cmd ?? []))
            let defaults = try ContainerSettings.load(from: root.appending(path: ContainerSettings.fileName))
            record.memoryBytes = defaults.memoryBytes
            record.cpus = defaults.cpus
            record.platform = query["platform"] ?? "linux/arm64"
            record.entrypoint = input.Entrypoint
            record.command = input.Cmd
            record.environment = input.Env ?? []
            record.workingDirectory = input.WorkingDir ?? ""
            record.user = input.User ?? ""
            if let hostname = input.Hostname, !hostname.isEmpty { record.hostname = hostname }
            record.labels = input.Labels ?? [:]
            record.tty = input.Tty ?? false
            record.openStdin = input.OpenStdin ?? false
            record.autoRemove = input.HostConfig?.AutoRemove ?? false
            record.privileged = input.HostConfig?.Privileged ?? false
            record.readOnlyRootfs = input.HostConfig?.ReadonlyRootfs ?? false
            record.useInit = input.HostConfig?.Init ?? false
            if let memory = input.HostConfig?.Memory, memory > 0 { record.memoryBytes = UInt64(memory) }
            if let nano = input.HostConfig?.NanoCpus, nano > 0 {
                record.cpus = max(1, Int((nano + 999_999_999) / 1_000_000_000))
            } else if let quota = input.HostConfig?.CpuQuota, quota > 0 {
                let period = max(input.HostConfig?.CpuPeriod ?? 100_000, 1)
                record.cpus = max(1, Int((quota + period - 1) / period))
            }
            if let memoryBytes = containerResourceOverride?.memoryBytes { record.memoryBytes = memoryBytes }
            if let cpus = containerResourceOverride?.cpus { record.cpus = cpus }
            record.stopSignal = input.StopSignal ?? "SIGTERM"
            record.stopTimeoutSeconds = input.StopTimeout ?? 10
            record.restartPolicy = .init(name: input.HostConfig?.RestartPolicy?.Name ?? "no", maximumRetryCount: input.HostConfig?.RestartPolicy?.MaximumRetryCount ?? 0)
            if let health = input.Healthcheck, let test = health.Test, test.first != "NONE" {
                record.healthcheck = .init(
                    test: test, intervalNanoseconds: health.Interval ?? 30_000_000_000,
                    timeoutNanoseconds: health.Timeout ?? 30_000_000_000, retries: health.Retries ?? 3,
                    startPeriodNanoseconds: health.StartPeriod ?? 0
                )
                record.healthStatus = "starting"; record.healthFailingStreak = 0
            }
            record.mounts = try mounts(from: input)
            for destination in (input.Volumes ?? [:]).keys.sorted()
                where !record.mounts.contains(where: { $0.destination == destination }) {
                record.mounts.append(.init(kind: .volume, source: "", destination: destination))
            }
            for index in record.mounts.indices where record.mounts[index].kind == .volume && record.mounts[index].source.isEmpty {
                let name = Identifier.random()
                _ = try await runtime.createVolume(name: name, anonymous: true)
                record.mounts[index].source = name
            }
            record.ports = ports(from: input)
            record.networkDisabled = input.HostConfig?.NetworkMode == "none"
            for (networkName, endpoint) in input.NetworkingConfig?.EndpointsConfig ?? [:] {
                let network = try await runtime.network(networkName)
                let requestedIPv4 = nonEmpty(endpoint?.IPAMConfig?.IPv4Address) ?? nonEmpty(endpoint?.IPAddress)
                let requestedIPv6 = nonEmpty(endpoint?.IPAMConfig?.IPv6Address) ?? nonEmpty(endpoint?.GlobalIPv6Address)
                record.networks.append(.init(
                    networkID: network.id, aliases: endpoint?.Aliases ?? [],
                    ipv4Address: requestedIPv4, ipv6Address: requestedIPv6,
                    ipv4AddressIsStatic: requestedIPv4 != nil, ipv6AddressIsStatic: requestedIPv6 != nil,
                    macAddress: nonEmpty(endpoint?.MacAddress),
                    gatewayPriority: endpoint?.GwPriority,
                    driverOptions: try endpointDriverOptions(endpoint, version: version)
                ))
            }
            if record.networkDisabled == true, !record.networks.isEmpty {
                throw EngineError(.badRequest, "network mode none cannot be combined with another network")
            }
            if record.networkDisabled == true, !record.ports.isEmpty {
                throw EngineError(.badRequest, "network mode none cannot be combined with published ports")
            }
            if let networkMode = input.HostConfig?.NetworkMode,
               !networkMode.isEmpty, networkMode != "default", networkMode != "bridge", networkMode != "none" {
                let network = try await runtime.network(networkMode)
                if !record.networks.contains(where: { $0.networkID == network.id }) {
                    record.networks.append(.init(networkID: network.id))
                }
            }
            let created = try await runtime.createContainer(record)
            return json(status: .created, ContainerCreateResponse(Id: created.id, Warnings: []))
        case (.GET, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/json"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/json".count))
            return json(status: .ok, try await inspectContainer(id, version: version))
        case (.GET, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/logs"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/logs".count))
            _ = try await runtime.container(id)
            guard parseBool(query["follow"]) != true else {
                throw EngineError(.unsupported, "follow logs is not supported yet")
            }
            return APIResponse(
                status: .ok,
                headers: ["Content-Type": "application/vnd.docker.raw-stream"],
                body: try await runtime.containerLogs(id, options: logOptions(components))
            )
        case (.GET, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/stats"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/stats".count))
            let record = try await runtime.container(id)
            return json(status: .ok, ContainerStatsResponse(try await runtime.containerStatistics(id), container: record, version: version))
        case (.GET, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/top"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/top".count))
            let result = try await runtime.containerTop(id, arguments: (query["ps_args"] ?? "-ef").split(whereSeparator: \.isWhitespace).map(String.init))
            return json(status: .ok, ContainerTopResponse(Titles: result.titles, Processes: result.processes))
        case (.PUT, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/archive"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/archive".count))
            guard let path = query["path"], !path.isEmpty else { throw EngineError(.badRequest, "path is required") }
            try await runtime.copyArchiveIntoContainer(id, path: path, archive: request.body)
            return APIResponse(status: .ok)
        case (.HEAD, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/archive"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/archive".count))
            _ = try await runtime.container(id)
            guard let path = query["path"], !path.isEmpty else { throw EngineError(.badRequest, "path is required") }
            let stat = ContainerPathStat(
                name: URL(filePath: path).lastPathComponent, size: 0,
                mode: 2_147_484_141, mtime: ISO8601DateFormatter().string(from: Date()), linkTarget: ""
            )
            let encoded = try encoder.encode(stat).base64EncodedString()
            return APIResponse(status: .ok, headers: ["X-Docker-Container-Path-Stat": encoded])
        case (.GET, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/archive"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/archive".count))
            guard let path = query["path"], !path.isEmpty else { throw EngineError(.badRequest, "path is required") }
            let stat = ContainerPathStat(
                name: URL(filePath: path).lastPathComponent, size: 0,
                mode: 0, mtime: ISO8601DateFormatter().string(from: Date()), linkTarget: ""
            )
            return APIResponse(
                status: .ok,
                headers: [
                    "Content-Type": "application/x-tar",
                    "X-Docker-Container-Path-Stat": try encoder.encode(stat).base64EncodedString(),
                ],
                body: try await runtime.copyArchiveOutOfContainer(id, path: path)
            )
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/start"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/start".count))
            try await runtime.startContainer(id); return APIResponse(status: .noContent)
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/stop"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/stop".count))
            try await runtime.stopContainer(id, timeoutSeconds: query["t"].flatMap(Int.init)); return APIResponse(status: .noContent)
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/wait"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/wait".count))
            return json(status: .ok, ContainerWaitResponse(
                StatusCode: try await runtime.waitContainer(id, condition: query["condition"]), Error: nil
            ))
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/resize"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/resize".count))
            guard let width = query["w"].flatMap(UInt16.init), let height = query["h"].flatMap(UInt16.init) else {
                throw EngineError(.badRequest, "resize requires w and h")
            }
            try await runtime.resizeContainer(id, width: width, height: height)
            return APIResponse(status: .ok)
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/kill"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/kill".count))
            try await runtime.killContainer(id, signal: query["signal"] ?? "SIGKILL")
            return APIResponse(status: .noContent)
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/pause"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/pause".count))
            try await runtime.pauseContainer(id); return APIResponse(status: .noContent)
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/unpause"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/unpause".count))
            try await runtime.resumeContainer(id); return APIResponse(status: .noContent)
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/restart"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/restart".count))
            try await runtime.restartContainer(id, timeoutSeconds: query["t"].flatMap(Int.init))
            return APIResponse(status: .noContent)
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/rename"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/rename".count))
            guard let name = query["name"], !name.isEmpty else { throw EngineError(.badRequest, "name is required") }
            try await runtime.renameContainer(id, name: name)
            return APIResponse(status: .noContent)
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/update"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/update".count))
            let input = try decoder.decode(ContainerUpdateRequest.self, from: request.body)
            let policy = input.RestartPolicy.map {
                RestartPolicyRecord(name: $0.Name, maximumRetryCount: $0.MaximumRetryCount ?? 0)
            }
            let nanoCPUs: Int64? = try {
                if let value = input.NanoCpus, value > 0 { return value }
                guard let quota = input.CpuQuota, quota > 0 else { return nil }
                let period = max(input.CpuPeriod ?? 100_000, 1)
                let (scaled, overflow) = quota.multipliedReportingOverflow(by: 1_000_000_000)
                guard !overflow else { throw EngineError(.badRequest, "CPU quota is too large") }
                return scaled / period + (scaled % period == 0 ? 0 : 1)
            }()
            _ = try await runtime.updateContainer(id, memoryBytes: input.Memory, nanoCPUs: nanoCPUs, restartPolicy: policy)
            return json(status: .ok, ContainerUpdateResponse(Warnings: []))
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/exec"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/exec".count))
            let input = try decoder.decode(ExecCreateRequest.self, from: request.body)
            let exec = try await runtime.createExec(container: id, configuration: .init(
                arguments: input.Cmd, environment: input.Env ?? [], workingDirectory: input.WorkingDir ?? "",
                user: input.User ?? "", tty: input.Tty ?? false, attachStdin: input.AttachStdin ?? false,
                attachStdout: input.AttachStdout ?? true, attachStderr: input.AttachStderr ?? true,
                privileged: input.Privileged ?? false
            ))
            return json(status: .created, ExecCreateResponse(Id: exec.id))
        case (.POST, let value) where value.hasPrefix("/exec/") && value.hasSuffix("/start"):
            let id = String(value.dropFirst("/exec/".count).dropLast("/start".count))
            let input = try decoder.decode(ExecStartRequest.self, from: request.body)
            guard input.Detach == true else { throw EngineError(.badRequest, "attached exec requires a connection upgrade") }
            try await runtime.startExec(id)
            return APIResponse(status: .ok)
        case (.GET, let value) where value.hasPrefix("/exec/") && value.hasSuffix("/json"):
            let id = String(value.dropFirst("/exec/".count).dropLast("/json".count))
            return json(status: .ok, ExecInspectResponse(try await runtime.inspectExec(id)))
        case (.POST, let value) where value.hasPrefix("/exec/") && value.hasSuffix("/resize"):
            let id = String(value.dropFirst("/exec/".count).dropLast("/resize".count))
            guard let width = query["w"].flatMap(UInt16.init), let height = query["h"].flatMap(UInt16.init) else {
                throw EngineError(.badRequest, "resize requires w and h")
            }
            try await runtime.resizeExec(id, width: width, height: height)
            return APIResponse(status: .ok)
        case (.DELETE, let value) where value.hasPrefix("/containers/"):
            let id = String(value.dropFirst("/containers/".count))
            try await runtime.removeContainer(id, force: parseBool(query["force"]) ?? false, removeVolumes: parseBool(query["v"]) ?? false)
            return APIResponse(status: .noContent)
        case (.GET, "/networks"):
            let containers = await runtime.listContainers(all: true)
            return json(
                status: .ok,
                filteredNetworks(await runtime.listNetworks(), filters: query["filters"]).map {
                    DockerNetworkResponse($0, containers: containers, version: version, includeStatus: false)
                }
            )
        case (.GET, let value) where value.hasPrefix("/networks/"):
            return json(status: .ok, DockerNetworkResponse(
                try await runtime.network(String(value.dropFirst("/networks/".count))),
                containers: await runtime.listContainers(all: true),
                version: version
            ))
        case (.POST, "/networks/create"):
            let input = try decoder.decode(NetworkCreateRequest.self, from: request.body)
            let configs = input.IPAM?.Config ?? []
            if let driver = nonEmpty(input.IPAM?.Driver), driver != "default" {
                throw EngineError(.unsupported, "IPAM driver \(driver) is not supported")
            }
            if input.IPAM?.Options?.isEmpty == false {
                throw EngineError(.unsupported, "custom IPAM options are not supported")
            }
            if let config = configs.first(where: { $0.Subnet == nil || $0.Subnet?.isEmpty == true }) {
                _ = config
                throw EngineError(.badRequest, "IPAM config requires a subnet")
            }
            if configs.contains(where: { $0.IPRange != nil || $0.AuxiliaryAddresses?.isEmpty == false }) {
                throw EngineError(.unsupported, "IPAM IP ranges and auxiliary addresses are not supported")
            }
            let ipv4Configs = configs.filter { $0.Subnet?.contains(":") == false }
            let ipv6Configs = configs.filter { $0.Subnet?.contains(":") == true }
            guard ipv4Configs.count <= 1, ipv6Configs.count <= 1 else {
                throw EngineError(.unsupported, "multiple IPAM subnets per address family are not supported")
            }
            let ipv4 = ipv4Configs.first
            let ipv6 = ipv6Configs.first
            // EnableIPv4 was introduced in API v1.48. Older negotiated APIs
            // retain legacy IPv4-enabled behavior even if a newer client field
            // is present in the JSON body.
            let enableIPv4 = version >= .init(major: 1, minor: 48) ? input.EnableIPv4 ?? true : true
            let enableIPv6 = input.EnableIPv6 ?? false
            guard enableIPv4 || enableIPv6 else {
                throw EngineError(.badRequest, "network must enable IPv4, IPv6, or both")
            }
            if !enableIPv4, ipv4 != nil {
                throw EngineError(.badRequest, "IPv4 IPAM config cannot be used when EnableIPv4 is false")
            }
            if !enableIPv6, ipv6 != nil {
                throw EngineError(.badRequest, "IPv6 IPAM config requires EnableIPv6 to be true")
            }
            let network = try await runtime.createNetwork(
                name: input.Name,
                subnet: ipv4?.Subnet, gateway: ipv4?.Gateway,
                ipv6Subnet: ipv6?.Subnet, ipv6Gateway: ipv6?.Gateway,
                enableIPv4: enableIPv4, enableIPv6: enableIPv6,
                driver: input.Driver,
                internalNetwork: input.Internal ?? false,
                labels: input.Labels ?? [:], options: input.Options ?? [:]
            )
            return json(status: .created, NetworkCreateResponse(Id: network.id, Warning: ""))
        case (.POST, let value) where value.hasPrefix("/networks/") && value.hasSuffix("/connect"):
            let id = String(value.dropFirst("/networks/".count).dropLast("/connect".count))
            let input = try decoder.decode(NetworkConnectRequest.self, from: request.body)
            try await runtime.connectNetwork(
                id, container: input.Container, aliases: input.EndpointConfig?.Aliases ?? [],
                ipv4Address: nonEmpty(input.EndpointConfig?.IPAMConfig?.IPv4Address) ?? nonEmpty(input.EndpointConfig?.IPAddress),
                ipv6Address: nonEmpty(input.EndpointConfig?.IPAMConfig?.IPv6Address) ?? nonEmpty(input.EndpointConfig?.GlobalIPv6Address),
                macAddress: nonEmpty(input.EndpointConfig?.MacAddress),
                gatewayPriority: input.EndpointConfig?.GwPriority,
                driverOptions: try endpointDriverOptions(input.EndpointConfig, version: version)
            )
            return APIResponse(status: .ok)
        case (.POST, let value) where value.hasPrefix("/networks/") && value.hasSuffix("/disconnect"):
            let id = String(value.dropFirst("/networks/".count).dropLast("/disconnect".count))
            let input = try decoder.decode(NetworkDisconnectRequest.self, from: request.body)
            try await runtime.disconnectNetwork(id, container: input.Container, force: input.Force ?? false)
            return APIResponse(status: .ok)
        case (.POST, "/networks/prune"):
            let selected = try filteredNetworksForPrune(await runtime.listNetworks(), filters: query["filters"])
            return json(status: .ok, PruneResponse(networks: try await runtime.pruneNetworks(
                identifiers: Set(selected.map(\.id))
            )))
        case (.POST, "/containers/prune"):
            return json(status: .ok, PruneResponse(containers: try await runtime.pruneContainers()))
        case (.POST, "/images/prune"):
            return json(status: .ok, PruneResponse(images: try await runtime.pruneImages()))
        case (.POST, "/volumes/prune"):
            return json(status: .ok, PruneResponse(volumes: try await runtime.pruneVolumes()))
        case (.DELETE, let value) where value.hasPrefix("/networks/"):
            try await runtime.removeNetwork(String(value.dropFirst("/networks/".count))); return APIResponse(status: .noContent)
        case (.GET, "/volumes"):
            return json(status: .ok, VolumeListEnvelope(Volumes: filteredVolumes(await runtime.listVolumes(), filters: query["filters"]).map { DockerVolumeResponse($0) }, Warnings: []))
        case (.GET, let value) where value.hasPrefix("/volumes/"):
            return json(status: .ok, DockerVolumeResponse(try await runtime.volume(String(value.dropFirst("/volumes/".count)))))
        case (.POST, "/volumes/create"):
            let input = try decoder.decode(VolumeCreateRequest.self, from: request.body)
            let name = input.Name.flatMap { $0.isEmpty ? nil : $0 } ?? Identifier.random()
            return json(status: .created, DockerVolumeResponse(try await runtime.createVolume(name: name, labels: input.Labels ?? [:], options: input.DriverOpts ?? [:])))
        case (.DELETE, let value) where value.hasPrefix("/volumes/"):
            try await runtime.removeVolume(String(value.dropFirst("/volumes/".count)), force: parseBool(query["force"]) ?? false); return APIResponse(status: .noContent)
        case (.GET, "/images/json"):
            let allContainers = await runtime.listContainers(all: true)
            let includeIdentity = version >= .init(major: 1, minor: 54)
                && (parseBool(query["identity"]) ?? false)
            let includeManifests = version >= .init(major: 1, minor: 47)
                && ((parseBool(query["manifests"]) ?? false) || includeIdentity)
            return json(status: .ok, filteredImages(await runtime.listImages(), filters: query["filters"]).map { image in
                ImageSummaryResponse(
                    image,
                    containers: version >= .init(major: 1, minor: 51)
                        ? allContainers.filter {
                            $0.imageID == image.id || $0.image == image.id || image.references.contains($0.image)
                        }.count
                        : -1,
                    containerRecords: allContainers,
                    includeDescriptor: version >= .init(major: 1, minor: 48),
                    includeManifests: includeManifests,
                    includeIdentity: includeIdentity
                )
            })
        case (.POST, "/images/create"):
            let collector = PullProgressCollector()
            let image = try await pullImage(request, progress: { await collector.append($0) })
            let updates = await collector.values
            let lines = updates.map {
                "{\"status\":\"Downloading\",\"progressDetail\":{\"current\":\($0.completedBytes),\"total\":\($0.totalBytes)}}\n"
            }.joined() + "{\"status\":\"Pull complete\",\"id\":\"\(image.id)\"}\n"
            return APIResponse(status: .ok, headers: ["Content-Type": "application/json"], body: Data(lines.utf8))
        case (.POST, "/images/load"):
            let platforms = version >= .init(major: 1, minor: 48)
                ? try imagePlatforms(
                    queries["platform"] ?? [],
                    repeated: version >= .init(major: 1, minor: 52)
                )
                : []
            let images = try await runtime.loadImages(
                archive: request.body,
                platforms: platforms
            )
            let output = images.map { "{\"stream\":\"Loaded image: \($0.references.first ?? $0.id)\\n\"}\n" }.joined()
            return APIResponse(status: .ok, headers: ["Content-Type": "application/json"], body: Data(output.utf8))
        case (.GET, let value) where value.hasPrefix("/images/") && value.hasSuffix("/json"):
            let id = String(value.dropFirst("/images/".count).dropLast("/json".count)).removingPercentEncoding ?? value
            let includeManifests = version >= .init(major: 1, minor: 48)
                && (parseBool(query["manifests"]) ?? false)
            let platform = version >= .init(major: 1, minor: 49)
                ? try query["platform"].map(decodeImagePlatform)
                : nil
            if includeManifests && platform != nil {
                throw EngineError(.badRequest, "manifests and platform options are mutually exclusive")
            }
            let image = try await runtime.image(id)
            let selected = try selectedManifest(in: image, platform: platform)
            return json(status: .ok, ImageInspectResponse(
                image,
                selectedManifest: selected,
                includeManifests: includeManifests,
                version: version
            ))
        case (.GET, let value) where value.hasPrefix("/images/") && value.hasSuffix("/attestations"):
            guard version >= .init(major: 1, minor: 55) else { throw EngineError(.notFound, "page not found") }
            let id = String(value.dropFirst("/images/".count).dropLast("/attestations".count)).removingPercentEncoding ?? value
            let platformValues = queries["platform"] ?? []
            guard platformValues.count <= 1 else {
                throw EngineError(.badRequest, "only one platform value is supported")
            }
            let platform = try platformValues.first.map(decodeImagePlatform)
            let attestations = try await runtime.imageAttestations(
                id,
                platform: platform,
                predicateTypes: queries["type"] ?? [],
                includeStatement: parseBool(query["statement"]) ?? false
            )
            return json(status: .ok, try attestations.map(AttestationStatementResponse.init))
        case (.GET, let value) where value.hasPrefix("/images/") && value.hasSuffix("/history"):
            let id = String(value.dropFirst("/images/".count).dropLast("/history".count)).removingPercentEncoding ?? value
            let platform = version >= .init(major: 1, minor: 48)
                ? try query["platform"].map(decodeImagePlatform)
                : nil
            let (image, history) = try await runtime.imageHistory(id, platform: platform)
            let selected = try selectedManifest(in: image, platform: platform)
            return json(status: .ok, history.enumerated().map { index, entry in
                ImageHistoryResponse(
                    Id: index == 0 ? selected?.imageID ?? image.id : "<missing>", Created: entry.created,
                    CreatedBy: entry.createdBy, Tags: index == 0 ? image.references : [],
                    Size: entry.emptyLayer ? 0 : image.size, Comment: entry.comment
                )
            })
        case (.POST, let value) where value.hasPrefix("/images/") && value.hasSuffix("/tag"):
            let id = String(value.dropFirst("/images/".count).dropLast("/tag".count)).removingPercentEncoding ?? value
            guard let repository = query["repo"], !repository.isEmpty else { throw EngineError(.badRequest, "repo is required") }
            let reference = query["tag"].flatMap { $0.isEmpty ? nil : "\(repository):\($0)" } ?? repository
            try await runtime.tagImage(id, reference: reference)
            return APIResponse(status: .created)
        case (.POST, let value) where value.hasPrefix("/images/") && value.hasSuffix("/push"):
            let id = String(value.dropFirst("/images/".count).dropLast("/push".count)).removingPercentEncoding ?? value
            let reference = query["tag"].flatMap { $0.isEmpty ? nil : "\(id):\($0)" } ?? id
            let platform = version >= .init(major: 1, minor: 46)
                ? try query["platform"].map(decodeImagePlatform)
                : nil
            let output: String
            do {
                try await runtime.pushImage(
                    reference,
                    platform: platform,
                    credentials: registryCredentials(request.headers)
                )
                output = "{\"status\":\"Pushed\",\"progressDetail\":{}}\n"
            } catch {
                let message = "failed to resolve \(ImageReference.normalized(reference)): \(error.localizedDescription)"
                let escaped = message.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
                output = "{\"errorDetail\":{\"message\":\"\(escaped)\"},\"error\":\"\(escaped)\"}\n"
            }
            return APIResponse(status: .ok, headers: ["Content-Type": "application/json"], body: Data(output.utf8))
        case (.GET, let value) where value.hasPrefix("/images/") && value.hasSuffix("/get"):
            let id = String(value.dropFirst("/images/".count).dropLast("/get".count)).removingPercentEncoding ?? value
            let platforms = version >= .init(major: 1, minor: 48)
                ? try imagePlatforms(
                    queries["platform"] ?? [],
                    repeated: version >= .init(major: 1, minor: 52)
                )
                : []
            return APIResponse(
                status: .ok,
                headers: ["Content-Type": "application/x-tar"],
                body: try await runtime.saveImage(
                    id,
                    platforms: platforms
                )
            )
        case (.DELETE, let value) where value.hasPrefix("/images/"):
            let id = String(value.dropFirst("/images/".count)).removingPercentEncoding ?? value
            let force = parseBool(query["force"]) ?? false
            let platforms = version >= .init(major: 1, minor: 50)
                ? try imagePlatforms(queries["platforms"] ?? [], repeated: true)
                : []
            if !platforms.isEmpty && !force {
                throw EngineError(.conflict, "platform-specific image removal requires force=true")
            }
            let deleted = try await runtime.removeImage(id, force: force, platforms: platforms)
            return json(status: .ok, deleted.map(ImageDeleteResponse.init))
        case (.POST, "/build"):
            throw EngineError(.unsupported, "the integrated builder is not supported; use the managed cengine-builder with docker buildx")
        default:
            throw EngineError(.notFound, "page not found")
        }
    }

    private func json<T: Encodable>(status: HTTPResponseStatus, _ value: T) -> APIResponse {
        do { return APIResponse(status: status, headers: ["Content-Type": "application/json"], body: try encoder.encode(value)) }
        catch { return APIResponse(status: .internalServerError, body: Data(#"{"message":"encoding error"}"#.utf8)) }
    }

    private func parsedComponents(_ uri: String) throws -> URLComponents {
        guard let value = URLComponents(string: uri) else { throw EngineError(.badRequest, "invalid request URI") }
        return value
    }
    private func multiQueryItems(_ components: URLComponents) -> [String: [String]] {
        Dictionary(grouping: components.queryItems ?? [], by: \.name)
            .mapValues { $0.map { $0.value ?? "" } }
    }
    private func queryItems(_ components: URLComponents) -> [String: String] {
        multiQueryItems(components).compactMapValues(\.first)
    }
    private func decodeImagePlatform(_ value: String) throws -> OCIPlatform {
        guard let data = value.data(using: .utf8) else {
            throw EngineError(.badRequest, "invalid platform value")
        }
        do {
            let platform = try decoder.decode(OCIPlatform.self, from: data)
            guard !platform.os.isEmpty, !platform.architecture.isEmpty else {
                throw EngineError(.badRequest, "platform os and architecture are required")
            }
            return platform
        } catch let error as EngineError {
            throw error
        } catch {
            throw EngineError(.badRequest, "invalid platform value: \(error.localizedDescription)")
        }
    }
    private func imagePlatforms(_ values: [String], repeated: Bool) throws -> [OCIPlatform] {
        guard repeated || values.count <= 1 else {
            throw EngineError(.badRequest, "multiple platform values require API v1.52 or newer")
        }
        return try values.map(decodeImagePlatform)
    }
    private func selectedManifest(in image: ImageRecord, platform: OCIPlatform?) throws -> ImageManifestRecord? {
        guard let platform else { return image.preferredManifest }
        guard let manifest = image.manifests.first(where: {
            $0.kind == .image && $0.available && $0.platform?.matches(platform) == true
        }) else {
            throw EngineError(.notFound, "image has no \(platform.description) manifest")
        }
        return manifest
    }
    private func parseBool(_ value: String?) -> Bool? { value.map { $0 == "1" || $0.lowercased() == "true" } }

    private func registryCredentials(_ headers: HTTPHeaders) -> RegistryCredentials? {
        guard let encoded = headers.first(name: "X-Registry-Auth"),
              let data = Data(base64Encoded: encoded),
              let auth = try? decoder.decode(RegistryAuthRequest.self, from: data) else { return nil }
        return .init(username: auth.username ?? "", password: auth.password ?? "", identityToken: auth.identitytoken ?? "")
    }

    private func filteredContainers(_ containers: [ContainerRecord], filters encoded: String?) -> [ContainerRecord] {
        guard let encoded, let data = encoded.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return containers }
        func values(_ key: String) -> [String] {
            if let array = object[key] as? [String] { return array }
            if let map = object[key] as? [String: Bool] { return map.compactMap { $0.value ? $0.key : nil } }
            return []
        }
        let labels = values("label")
        let names = values("name")
        let ids = values("id")
        let statuses = values("status")
        return containers.filter { container in
            labels.allSatisfy { expression in
                guard let (key, expected) = labelExpression(expression),
                      let actual = container.labels[key] else { return false }
                return expected == nil || actual == expected
            } && (names.isEmpty || names.contains { container.name.contains($0) })
              && (ids.isEmpty || ids.contains { container.id.hasPrefix($0) })
              && (statuses.isEmpty || statuses.contains(container.phase.rawValue))
        }
    }

    private func filterValues(_ encoded: String?, key: String) -> [String] {
        guard let encoded, let data = encoded.replacingOccurrences(of: "+", with: " ").data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        if let array = object[key] as? [String] { return array }
        if let map = object[key] as? [String: Bool] { return map.compactMap { $0.value ? $0.key : nil } }
        return []
    }

    private func labelsMatch(_ labels: [String: String], expressions: [String]) -> Bool {
        expressions.allSatisfy { expression in
            guard let (key, expected) = labelExpression(expression),
                  let actual = labels[key] else { return false }
            return expected == nil || actual == expected
        }
    }

    private func labelExpression(_ expression: String) -> (key: String, expected: String?)? {
        let parts = expression.split(
            separator: "=", maxSplits: 1, omittingEmptySubsequences: false
        ).map(String.init)
        guard let key = parts.first, !key.isEmpty else { return nil }
        return (key, parts.count == 2 ? parts[1] : nil)
    }

    private func filteredNetworks(_ networks: [NetworkRecord], filters: String?) -> [NetworkRecord] {
        let labels = filterValues(filters, key: "label")
        let names = filterValues(filters, key: "name")
        return networks.filter { labelsMatch($0.labels, expressions: labels) && (names.isEmpty || names.contains($0.name)) }
    }

    private func filteredNetworksForPrune(_ networks: [NetworkRecord], filters: String?) throws -> [NetworkRecord] {
        guard let filters else { return networks }
        guard let data = filters.replacingOccurrences(of: "+", with: " ").data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw EngineError(.badRequest, "invalid network prune filters")
        }
        let supported = Set(["label", "label!", "until"])
        if let key = object.keys.first(where: { !supported.contains($0) }) {
            throw EngineError(.badRequest, "unsupported network prune filter \(key)")
        }
        func values(_ key: String) throws -> [String] {
            guard let value = object[key] else { return [] }
            if let array = value as? [String] { return array }
            if let map = value as? [String: Bool] { return map.compactMap { $0.value ? $0.key : nil } }
            throw EngineError(.badRequest, "invalid network prune filter \(key)")
        }
        let requiredLabels = try values("label")
        let excludedLabels = try values("label!")
        let untilValues = try values("until")
        guard (requiredLabels + excludedLabels).allSatisfy({ labelExpression($0) != nil }) else {
            throw EngineError(.badRequest, "network prune label filters require a non-empty label key")
        }
        guard untilValues.count <= 1 else { throw EngineError(.badRequest, "network prune accepts one until filter") }
        let until = try untilValues.first.map { value in
            guard let date = parseDockerPruneUntil(value) else {
                throw EngineError(.badRequest, "invalid network prune until filter \(value)")
            }
            return date
        }
        return networks.filter { network in
            labelsMatch(network.labels, expressions: requiredLabels)
                && excludedLabels.allSatisfy { !labelsMatch(network.labels, expressions: [$0]) }
                && (until.map { network.createdAt < $0 } ?? true)
        }
    }

    private func filteredVolumes(_ volumes: [VolumeRecord], filters: String?) -> [VolumeRecord] {
        let labels = filterValues(filters, key: "label")
        let names = filterValues(filters, key: "name")
        return volumes.filter { labelsMatch($0.labels, expressions: labels) && (names.isEmpty || names.contains($0.name)) }
    }

    private func filteredImages(_ images: [ImageRecord], filters: String?) -> [ImageRecord] {
        let references = filterValues(filters, key: "reference")
        let dangling = filterValues(filters, key: "dangling").first.flatMap(parseBool)
        return images.filter { image in
            let referenceMatches = references.isEmpty || references.contains { pattern in
                image.references.contains { reference in
                    if pattern.hasSuffix("*") { return reference.hasPrefix(String(pattern.dropLast())) }
                    return reference == ImageReference.normalized(pattern)
                }
            }
            return referenceMatches && (dangling == nil || dangling == image.references.isEmpty)
        }
    }

    private func inspectContainer(_ identifier: String, version: DockerAPIVersion) async throws -> ContainerInspectResponse {
        .init(try await runtime.container(identifier), networks: await runtime.listNetworks(), version: version)
    }

    public func containerIO(_ identifier: String) async throws -> ContainerIOBridge {
        try await runtime.containerIO(identifier)
    }

    public func containerLogs(_ identifier: String, options: DockerLogOptions = .init()) async throws -> Data {
        try await runtime.containerLogs(identifier, options: options)
    }
    public func events(since: Date? = nil, until: Date? = nil) async -> AsyncStream<RuntimeEvent> {
        await runtime.events(since: since, until: until)
    }
    public func statistics(_ identifier: String, version: DockerAPIVersion = .maximum) async throws -> ContainerStatsResponse {
        let record = try await runtime.container(identifier)
        return ContainerStatsResponse(try await runtime.containerStatistics(identifier), container: record, version: version)
    }
    public func pullImage(_ request: APIRequest, progress: @escaping ImagePullProgressHandler) async throws -> ImageRecord {
        let components = try parsedComponents(request.uri)
        let query = queryItems(components)
        guard let reference = query["fromImage"], !reference.isEmpty else {
            throw EngineError(.badRequest, "fromImage is required")
        }
        let tag = query["tag"].flatMap { $0.isEmpty ? nil : $0 }
        let fullReference = ImageReference.normalized(tag.map {
            $0.hasPrefix("sha256:") ? "\(reference)@\($0)" : "\(reference):\($0)"
        } ?? reference)
        return try await runtime.pullImage(
            fullReference, platform: query["platform"] ?? "linux/arm64",
            credentials: registryCredentials(request.headers), progress: progress
        )
    }

    public func execIO(_ identifier: String) async throws -> ContainerIOBridge { try await runtime.execIO(identifier) }
    public func startExec(_ identifier: String) async throws { try await runtime.startExec(identifier) }
    public func startAttachedExec(_ identifier: String) async throws -> CInt? { try await runtime.startAttachedExec(identifier) }
    public func containerWait(_ identifier: String, condition: String?) async throws -> ContainerWaitSubscription {
        try await runtime.subscribeContainerWait(identifier, condition: condition)
    }

    private func mounts(from input: ContainerCreateRequest) throws -> [MountRecord] {
        var result = try ((input.Mounts ?? []) + (input.HostConfig?.Mounts ?? [])).map { mount in
            if let subpath = mount.VolumeOptions?.Subpath, !subpath.isEmpty {
                let components = subpath.split(separator: "/", omittingEmptySubsequences: false)
                guard !subpath.hasPrefix("/"), !components.contains(".."), !components.contains(".") else {
                    throw EngineError(.badRequest, "invalid volume subpath: \(subpath)")
                }
            }
            return MountRecord(
                kind: MountRecord.Kind(rawValue: mount.Type) ?? .bind,
                source: mount.Source ?? "", destination: mount.Target, readOnly: mount.ReadOnly ?? false,
                noCopy: mount.VolumeOptions?.NoCopy ?? false, subpath: mount.VolumeOptions?.Subpath,
                tmpfsSizeBytes: mount.TmpfsOptions?.SizeBytes, tmpfsMode: mount.TmpfsOptions?.Mode
            )
        }
        for bind in input.HostConfig?.Binds ?? [] {
            let fields = bind.split(separator: ":", maxSplits: 2).map(String.init)
            guard fields.count >= 2 else { throw EngineError(.badRequest, "invalid bind mount: \(bind)") }
            let kind: MountRecord.Kind = fields[0].hasPrefix("/") ? .bind : .volume
            result.append(.init(
                kind: kind, source: fields[0], destination: fields[1],
                readOnly: fields.count == 3 && fields[2].split(separator: ",").contains("ro"),
                createSourceIfMissing: kind == .bind ? true : nil
            ))
        }
        for (destination, options) in input.HostConfig?.Tmpfs ?? [:] {
            let values = options.split(separator: ",").map(String.init)
            result.append(.init(
                kind: .tmpfs, source: options, destination: destination,
                readOnly: values.contains("ro"),
                tmpfsSizeBytes: values.first(where: { $0.hasPrefix("size=") }).flatMap {
                    parseDockerByteSize(String($0.dropFirst("size=".count)))
                },
                tmpfsMode: values.first(where: { $0.hasPrefix("mode=") }).flatMap {
                    UInt32($0.dropFirst("mode=".count), radix: 8)
                }
            ))
        }
        return result
    }

    private func logOptions(_ components: URLComponents) -> DockerLogOptions {
        let query = queryItems(components)
        let tail: Int? = query["tail"].flatMap { $0 == "all" ? nil : Int($0) }
        return .init(
            stdout: parseBool(query["stdout"]) ?? true,
            stderr: parseBool(query["stderr"]) ?? true,
            since: query["since"].flatMap(parseDockerTimestamp),
            until: query["until"].flatMap(parseDockerTimestamp),
            timestamps: parseBool(query["timestamps"]) ?? false,
            tail: tail
        )
    }

    private func ports(from input: ContainerCreateRequest) -> [PortBinding] {
        (input.HostConfig?.PortBindings ?? [:]).flatMap { key, bindings -> [PortBinding] in
            let parts = key.split(separator: "/", maxSplits: 1).map(String.init)
            guard let containerPort = UInt16(parts[0]) else { return [] }
            return bindings.compactMap { binding in
                let rawHostPort = binding.HostPort ?? ""
                guard let hostPort = rawHostPort.isEmpty ? 0 : UInt16(rawHostPort) else { return nil }
                return PortBinding(hostIP: binding.HostIp ?? "0.0.0.0", hostPort: hostPort, containerPort: containerPort, proto: parts.count == 2 ? parts[1] : "tcp")
            }
        }
    }
}

func parseDockerTimestamp(_ value: String) -> Date? {
    if let seconds = Double(value) { return Date(timeIntervalSince1970: seconds) }
    let fractional = ISO8601DateFormatter(); fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value)
}

func parseDockerPruneUntil(_ value: String, now: Date = Date()) -> Date? {
    if let timestamp = parseDockerTimestamp(value) { return timestamp }
    var remainder = value[...]
    var duration = 0.0
    let units: [(String, Double)] = [
        ("ns", 1e-9), ("us", 1e-6), ("µs", 1e-6), ("ms", 1e-3),
        ("s", 1), ("m", 60), ("h", 3600),
    ]
    while !remainder.isEmpty {
        let number = remainder.prefix { $0.isNumber || $0 == "." }
        guard !number.isEmpty, let amount = Double(number) else { return nil }
        remainder.removeFirst(number.count)
        guard let unit = units.first(where: { remainder.hasPrefix($0.0) }) else { return nil }
        remainder.removeFirst(unit.0.count)
        duration += amount * unit.1
    }
    return duration > 0 ? now.addingTimeInterval(-duration) : nil
}

private func parseDockerByteSize(_ value: String) -> Int64? {
    let normalized = value.lowercased()
    let units: [(String, Int64)] = [("gb", 1 << 30), ("g", 1 << 30), ("mb", 1 << 20), ("m", 1 << 20), ("kb", 1 << 10), ("k", 1 << 10), ("b", 1)]
    for (suffix, multiplier) in units where normalized.hasSuffix(suffix) {
        return Int64(normalized.dropLast(suffix.count)).map { $0 * multiplier }
    }
    return Int64(normalized)
}

private struct VolumeListEnvelope: Encodable { let Volumes: [DockerVolumeResponse]; let Warnings: [String] }
private struct RegistryAuthRequest: Decodable { let username: String?; let password: String?; let identitytoken: String? }
private actor PullProgressCollector {
    private(set) var values: [ImagePullProgress] = []
    func append(_ value: ImagePullProgress) { values.append(value) }
}

public struct ContainerInspectResponse: Codable, Sendable {
    public let Id: String
    public let Name: String
    public let Created: String
    public let Path: String
    public let Args: [String]
    public let Image: String
    public let ImageManifestDescriptor: OCIDescriptor?
    public let State: StateResponse
    public let Config: ConfigResponse
    public let RestartCount: Int
    public let NetworkSettings: NetworkSettingsResponse
    public let HostConfig: HostConfigResponse
    public let Mounts: [MountResponse]

    public struct StateResponse: Codable, Sendable {
        let Status: String; let Running: Bool; let Paused: Bool; let Restarting: Bool; let OOMKilled: Bool
        let Dead: Bool; let Pid: Int; let ExitCode: Int32; let Error: String; let StartedAt: String; let FinishedAt: String
        let Health: HealthStateResponse?
    }
    public struct HealthStateResponse: Codable, Sendable { let Status: String; let FailingStreak: Int; let Log: [String] }
    public struct ConfigResponse: Codable, Sendable {
        let Hostname: String; let User: String; let Tty: Bool; let OpenStdin: Bool; let Env: [String]
        let Cmd: [String]; let Image: String; let WorkingDir: String; let Labels: [String: String]
        let Healthcheck: HealthcheckResponse?
    }
    public struct HealthcheckResponse: Codable, Sendable {
        let Test: [String]; let Interval: Int64; let Timeout: Int64; let Retries: Int; let StartPeriod: Int64
    }
    public struct HostConfigResponse: Codable, Sendable {
        let Memory: UInt64; let NanoCpus: Int64; let AutoRemove: Bool; let Privileged: Bool
        let ReadonlyRootfs: Bool; let Init: Bool; let RestartPolicy: RestartPolicy
        let Binds: [String]; let Mounts: [MountResponse]
        let PortBindings: [String: [PortBindingResponse]]
        let NetworkMode: String; let LogConfig: LogConfigResponse
        struct RestartPolicy: Codable, Sendable { let Name: String; let MaximumRetryCount: Int }
        struct LogConfigResponse: Codable, Sendable { let `Type`: String; let Config: [String: String] }
    }
    public struct MountResponse: Codable, Sendable {
        let `Type`: String; let Name: String?; let Source: String; let Destination: String
        let Driver: String; let Mode: String; let RW: Bool; let Propagation: String
        let VolumeOptions: VolumeOptionsResponse?; let TmpfsOptions: TmpfsOptionsResponse?
        struct VolumeOptionsResponse: Codable, Sendable { let NoCopy: Bool; let Subpath: String? }
        struct TmpfsOptionsResponse: Codable, Sendable { let SizeBytes: Int64?; let Mode: UInt32? }
    }
    public struct NetworkSettingsResponse: Codable, Sendable {
        let Bridge: String?; let SandboxID: String; let HairpinMode: Bool?
        let Ports: [String: [PortBindingResponse]?]
        let Networks: [String: EndpointResponse]
    }
    public struct PortBindingResponse: Codable, Sendable { let HostIp: String; let HostPort: String }
    public struct EndpointResponse: Codable, Sendable {
        let IPAMConfig: [String: String]?; let Links: [String]?; let Aliases: [String]
        let DriverOpts: [String: String]?
        let NetworkID: String; let EndpointID: String; let Gateway: String
        let IPAddress: String; let IPPrefixLen: Int; let IPv6Gateway: String
        let GlobalIPv6Address: String; let GlobalIPv6PrefixLen: Int; let MacAddress: String
        let GwPriority: Int?; let DNSNames: [String]
    }

    init(_ record: ContainerRecord, networks: [NetworkRecord] = [], version: DockerAPIVersion = .maximum) {
        let formatter = ISO8601DateFormatter()
        Id = record.id; Name = "/\(record.name)"; Created = formatter.string(from: record.createdAt)
        Path = record.processArguments.first ?? ""; Args = Array(record.processArguments.dropFirst())
        Image = record.imageID.isEmpty ? record.image : record.imageID
        ImageManifestDescriptor = version >= .init(major: 1, minor: 48) ? record.imageManifestDescriptor : nil
        State = .init(Status: record.phase.rawValue, Running: record.phase == .running, Paused: record.phase == .paused, Restarting: false, OOMKilled: false, Dead: record.phase == .dead, Pid: 0, ExitCode: record.exitCode ?? 0, Error: "", StartedAt: record.startedAt.map(formatter.string) ?? "0001-01-01T00:00:00Z", FinishedAt: record.finishedAt.map(formatter.string) ?? "0001-01-01T00:00:00Z", Health: record.healthStatus.map { .init(Status: $0, FailingStreak: record.healthFailingStreak ?? 0, Log: []) })
        Config = .init(Hostname: record.hostname, User: record.user, Tty: record.tty, OpenStdin: record.openStdin, Env: record.environment, Cmd: record.processArguments, Image: record.image, WorkingDir: record.workingDirectory.isEmpty ? "/" : record.workingDirectory, Labels: record.labels, Healthcheck: record.healthcheck.map { .init(Test: $0.test, Interval: $0.intervalNanoseconds, Timeout: $0.timeoutNanoseconds, Retries: $0.retries, StartPeriod: $0.startPeriodNanoseconds) })
        RestartCount = record.restartCount
        let mounts = record.mounts.map { mount in
            MountResponse(
                Type: mount.kind.rawValue, Name: mount.kind == .volume ? mount.source : nil,
                Source: mount.source, Destination: mount.destination, Driver: mount.kind == .volume ? "local" : "",
                Mode: mount.readOnly ? "ro" : "", RW: !mount.readOnly, Propagation: "rprivate",
                VolumeOptions: mount.kind == .volume ? .init(NoCopy: mount.noCopy, Subpath: mount.subpath) : nil,
                TmpfsOptions: mount.kind == .tmpfs ? .init(SizeBytes: mount.tmpfsSizeBytes, Mode: mount.tmpfsMode) : nil
            )
        }
        let portBindings = Dictionary(grouping: record.ports, by: { "\($0.containerPort)/\($0.proto)" }).mapValues {
            $0.map { PortBindingResponse(HostIp: $0.hostIP, HostPort: String($0.hostPort)) }
        }
        let networkByID = Dictionary(uniqueKeysWithValues: networks.map { ($0.id, $0) })
        let networkMode = record.networkDisabled == true
            ? "none"
            : record.networks.first.flatMap { networkByID[$0.networkID]?.name } ?? "default"
        HostConfig = .init(
            Memory: record.memoryBytes, NanoCpus: Int64(record.cpus) * 1_000_000_000,
            AutoRemove: record.autoRemove, Privileged: record.privileged,
            ReadonlyRootfs: record.readOnlyRootfs, Init: record.useInit,
            RestartPolicy: .init(Name: record.restartPolicy.name, MaximumRetryCount: record.restartPolicy.maximumRetryCount),
            Binds: record.mounts.filter { $0.kind != .tmpfs }.map {
                "\($0.source):\($0.destination)\($0.readOnly ? ":ro" : "")"
            },
            Mounts: mounts, PortBindings: portBindings, NetworkMode: networkMode,
            LogConfig: .init(Type: "json-file", Config: [:])
        )
        Mounts = mounts
        let endpoints = record.networks.reduce(into: [String: EndpointResponse]()) { result, endpoint in
            let network = networkByID[endpoint.networkID]
            let name = network?.name ?? endpoint.networkID
            let shortID = String(record.id.prefix(12))
            let aliases = version < .init(major: 1, minor: 45)
                ? Array(Set(endpoint.aliases + [shortID])).sorted()
                : endpoint.aliases
            let dnsNames = Array(Set([record.name, record.hostname, shortID] + endpoint.aliases)).sorted()
            result[name] = .init(
                IPAMConfig: nil, Links: nil, Aliases: aliases, DriverOpts: endpoint.driverOptions,
                NetworkID: endpoint.networkID,
                EndpointID: "\(record.id)-\(endpoint.networkID)", Gateway: network?.gateway ?? "",
                IPAddress: endpoint.ipv4Address ?? "",
                IPPrefixLen: network?.subnet.split(separator: "/").last.flatMap { Int($0) } ?? 0,
                IPv6Gateway: network?.ipv6Gateway ?? "",
                GlobalIPv6Address: endpoint.ipv6Address ?? "",
                GlobalIPv6PrefixLen: network?.ipv6Subnet.split(separator: "/").last.flatMap { Int($0) } ?? 0,
                MacAddress: endpoint.macAddress
                    ?? EndpointMacAddress.generated(seed: record.id + endpoint.networkID),
                GwPriority: version >= .init(major: 1, minor: 48) ? endpoint.gatewayPriority ?? 0 : nil,
                DNSNames: dnsNames
            )
        }
        let ports = Dictionary(grouping: record.ports, by: { "\($0.containerPort)/\($0.proto)" }).mapValues {
            Optional($0.map { PortBindingResponse(HostIp: $0.hostIP, HostPort: String($0.hostPort)) })
        }
        let includeLegacyNetworkSettings = version < .init(major: 1, minor: 52)
        NetworkSettings = .init(
            Bridge: includeLegacyNetworkSettings ? "" : nil,
            SandboxID: record.id,
            HairpinMode: includeLegacyNetworkSettings ? false : nil,
            Ports: ports,
            Networks: endpoints
        )
    }
}
