import CEngineCore
import CEngineRuntime
import Foundation
import NIOHTTP1

enum DockerFilterValues: Decodable {
    case list([String])
    case map([String: Bool])

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let values = try? container.decode([String].self) {
            self = .list(values)
        } else {
            self = .map(try container.decode([String: Bool].self))
        }
    }

    var active: [String] {
        switch self {
        case .list(let values): Array(Set(values)).sorted()
        case .map(let values): values.compactMap { $0.value ? $0.key : nil }.sorted()
        }
    }
}

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
        _ endpoint: ContainerCreateRequest.EndpointSettingsRequest?
    ) -> [String: String]? {
        guard let options = endpoint?.DriverOpts, !options.isEmpty else { return nil }
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
            let images = await runtime.listImages()
            return json(status: .ok, DockerInfoResponse(
                Containers: all.count,
                ContainersRunning: all.filter { $0.phase == .running }.count,
                ContainersPaused: all.filter { $0.phase == .paused }.count,
                ContainersStopped: all.filter { $0.phase == .exited || $0.phase == .created }.count,
                Images: images.count,
                DockerRootDir: root.path,
                version: version
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
            let parsedMounts = try validateRuntimeInput(input)
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
            if version >= .init(major: 1, minor: 43) {
                record.annotations = input.HostConfig?.Annotations ?? [:]
            }
            record.tty = input.Tty ?? false
            record.attachStdin = input.AttachStdin ?? false
            record.openStdin = input.OpenStdin ?? false
            record.autoRemove = input.HostConfig?.AutoRemove ?? false
            record.privileged = input.HostConfig?.Privileged ?? false
            record.capabilityAdd = try normalizedCapabilities(input.HostConfig?.CapAdd ?? [])
            record.capabilityDrop = try normalizedCapabilities(input.HostConfig?.CapDrop ?? [])
            record.readOnlyRootfs = input.HostConfig?.ReadonlyRootfs ?? false
            record.useInit = input.HostConfig?.Init ?? false
            record.pidsLimit = try validatedPidsLimit(input.HostConfig?.PidsLimit) ?? 0
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
            record.mounts = parsedMounts
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
                    driverOptions: endpointDriverOptions(endpoint)
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
            try validateRuntimeInput(input)
            let policy = input.RestartPolicy.map {
                RestartPolicyRecord(name: $0.Name ?? "no", maximumRetryCount: $0.MaximumRetryCount ?? 0)
            }
            let nanoCPUs: Int64? = try {
                if let value = input.NanoCpus, value > 0 { return value }
                guard let quota = input.CpuQuota, quota > 0 else { return nil }
                let period = max(input.CpuPeriod ?? 100_000, 1)
                let (scaled, overflow) = quota.multipliedReportingOverflow(by: 1_000_000_000)
                guard !overflow else { throw EngineError(.badRequest, "CPU quota is too large") }
                return scaled / period + (scaled % period == 0 ? 0 : 1)
            }()
            _ = try await runtime.updateContainer(
                id, memoryBytes: input.Memory, nanoCPUs: nanoCPUs,
                pidsLimit: try validatedPidsLimit(input.PidsLimit), restartPolicy: policy
            )
            return json(status: .ok, ContainerUpdateResponse(Warnings: []))
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/exec"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/exec".count))
            let input = try decoder.decode(ExecCreateRequest.self, from: request.body)
            try validateRuntimeInput(input)
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
            try validateRuntimeInput(input)
            guard input.Detach == true else { throw EngineError(.badRequest, "attached exec requires a connection upgrade") }
            let exec = try await runtime.inspectExec(id)
            if let tty = input.Tty, tty != exec.configuration.tty {
                throw EngineError(.badRequest, "exec start Tty must match the exec configuration")
            }
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
                driverOptions: endpointDriverOptions(input.EndpointConfig)
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
            let candidates = try containerPruneCandidates(
                await runtime.listContainers(all: true), filters: query["filters"]
            )
            return json(status: .ok, PruneResponse(containers: try await runtime.pruneContainers(ids: candidates)))
        case (.POST, "/images/prune"):
            let scope = try imagePruneScope(filters: query["filters"])
            return json(status: .ok, PruneResponse(images: try await runtime.pruneImages(scope: scope)))
        case (.POST, "/volumes/prune"):
            let scope = try volumePruneScope(filters: query["filters"], version: version)
            return json(status: .ok, PruneResponse(volumes: try await runtime.pruneVolumes(scope: scope)))
        case (.DELETE, let value) where value.hasPrefix("/networks/"):
            try await runtime.removeNetwork(String(value.dropFirst("/networks/".count))); return APIResponse(status: .noContent)
        case (.GET, "/volumes"):
            return json(status: .ok, VolumeListEnvelope(Volumes: filteredVolumes(await runtime.listVolumes(), filters: query["filters"]).map { DockerVolumeResponse($0) }, Warnings: []))
        case (.GET, let value) where value.hasPrefix("/volumes/"):
            return json(status: .ok, DockerVolumeResponse(try await runtime.volume(String(value.dropFirst("/volumes/".count)))))
        case (.POST, "/volumes/create"):
            let input = try decoder.decode(VolumeCreateRequest.self, from: request.body)
            if let driver = input.Driver, !driver.isEmpty, driver != "local" {
                throw EngineError(.unsupported, "volume driver \(driver) is not supported")
            }
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

    private func containerPruneCandidates(
        _ containers: [ContainerRecord], filters encoded: String?, now: Date = Date()
    ) throws -> Set<String> {
        let filters = try decodedContainerPruneFilters(encoded)
        let positiveLabels = filters["label"] ?? []
        let negativeLabels = filters["label!"] ?? []
        let labelExpressions = positiveLabels + negativeLabels
        guard labelExpressions.allSatisfy({
            $0.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).first?.isEmpty == false
        }) else {
            throw EngineError(.badRequest, "container prune label filters require a label name")
        }
        let cutoffs = try (filters["until"] ?? []).map { value -> Date in
            guard let cutoff = pruneCutoff(value, now: now) else {
                throw EngineError(.badRequest, "invalid container prune until filter: \(value)")
            }
            return cutoff
        }
        guard cutoffs.count <= 1 else {
            throw EngineError(.badRequest, "multiple container prune until filters are not supported")
        }

        return Set(containers.compactMap { container in
            let positiveMatches = positiveLabels.allSatisfy {
                pruneLabel($0, matches: container.labels)
            }
            // Docker combines negated label filters into one negative constraint. A container is
            // excluded only when it matches every negated expression.
            let negativeMatches = negativeLabels.isEmpty || !negativeLabels.allSatisfy {
                pruneLabel($0, matches: container.labels)
            }
            let untilMatches = cutoffs.isEmpty || cutoffs.contains { container.createdAt < $0 }
            return positiveMatches && negativeMatches && untilMatches ? container.id : nil
        })
    }

    private func decodedContainerPruneFilters(_ encoded: String?) throws -> [String: [String]] {
        guard let encoded, !encoded.isEmpty else { return [:] }
        let normalized = encoded.replacingOccurrences(of: "+", with: " ")
        guard let data = normalized.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw EngineError(.badRequest, "invalid container prune filters")
        }
        let allowed = Set(["until", "label", "label!"])
        if let key = object.keys.first(where: { !allowed.contains($0) }) {
            throw EngineError(.badRequest, "unsupported container prune filter: \(key)")
        }
        var result: [String: [String]] = [:]
        for (key, raw) in object {
            if let values = raw as? [String] {
                result[key] = values
            } else if let values = raw as? [String: Bool] {
                // Docker's legacy map-shaped filter encoding treats map keys as
                // values; the boolean payload is not an enable/disable switch.
                result[key] = Array(values.keys)
            } else {
                throw EngineError(.badRequest, "invalid values for container prune filter: \(key)")
            }
        }
        return result
    }

    private func pruneLabel(_ expression: String, matches labels: [String: String]) -> Bool {
        let parts = expression.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        guard let actual = labels[parts[0]] else { return false }
        return parts.count == 1 || actual == parts[1]
    }

    private func pruneCutoff(_ value: String, now: Date) -> Date? {
        if let timestamp = parseDockerTimestamp(value) { return timestamp }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        for format in ["yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS", "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd'T'HH:mm", "yyyy-MM-dd"] {
            formatter.dateFormat = format
            if let date = formatter.date(from: value) { return date }
        }
        guard let duration = goDurationSeconds(value) else { return nil }
        return now.addingTimeInterval(-duration)
    }

    private func goDurationSeconds(_ value: String) -> TimeInterval? {
        var input = value
        var sign = 1.0
        if input.first == "+" { input.removeFirst() }
        else if input.first == "-" { sign = -1; input.removeFirst() }
        guard !input.isEmpty,
              let expression = try? NSRegularExpression(
                pattern: #"(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)"#
              ) else { return nil }
        let range = NSRange(input.startIndex..<input.endIndex, in: input)
        let matches = expression.matches(in: input, range: range)
        guard !matches.isEmpty else { return nil }
        var offset = 0
        var seconds = 0.0
        let factors: [String: Double] = [
            "ns": 1e-9, "us": 1e-6, "µs": 1e-6, "μs": 1e-6,
            "ms": 1e-3, "s": 1, "m": 60, "h": 3_600,
        ]
        for match in matches {
            guard match.range.location == offset,
                  let amountRange = Range(match.range(at: 1), in: input),
                  let unitRange = Range(match.range(at: 2), in: input),
                  let amount = Double(input[amountRange]),
                  let factor = factors[String(input[unitRange])] else { return nil }
            seconds += amount * factor
            offset = match.range.location + match.range.length
        }
        guard offset == range.length else { return nil }
        return sign * seconds
    }

    private func filterValues(_ encoded: String?, key: String) -> [String] {
        guard let encoded, let data = encoded.replacingOccurrences(of: "+", with: " ").data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        if let array = object[key] as? [String] { return array }
        if let map = object[key] as? [String: Bool] { return map.compactMap { $0.value ? $0.key : nil } }
        return []
    }

    private func activePruneFilters(_ encoded: String?) throws -> [String: [String]] {
        guard let encoded, !encoded.isEmpty else { return [:] }
        guard let data = encoded.replacingOccurrences(of: "+", with: " ").data(using: .utf8) else {
            throw EngineError(.badRequest, "invalid prune filters")
        }
        do {
            return try decoder.decode([String: DockerFilterValues].self, from: data).mapValues(\.active)
        } catch {
            throw EngineError(.badRequest, "invalid prune filters")
        }
    }

    private func pruneBoolean(_ values: [String], key: String) throws -> Bool {
        guard !values.isEmpty else {
            throw EngineError(.badRequest, "invalid filter \(key)")
        }
        let normalized = Set(values.map { $0.lowercased() })
        let hasTrue = !normalized.isDisjoint(with: ["1", "true"])
        let hasFalse = !normalized.isDisjoint(with: ["0", "false"])
        guard hasTrue != hasFalse else {
            throw EngineError(.badRequest, "invalid filter \(key)=\(values.joined(separator: ","))")
        }
        return hasTrue
    }

    private func imagePruneScope(filters encoded: String?) throws -> ImagePruneScope {
        let filters = try activePruneFilters(encoded)
        for (key, values) in filters where key != "dangling" && !values.isEmpty {
            throw EngineError(.unsupported, "image prune filter \(key) is not supported")
        }
        guard let values = filters["dangling"] else { return .dangling }
        return try pruneBoolean(values, key: "dangling") ? .dangling : .allUnused
    }

    private func volumePruneScope(filters encoded: String?, version: DockerAPIVersion) throws -> VolumePruneScope {
        let filters = try activePruneFilters(encoded)
        for (key, values) in filters where key != "all" && !values.isEmpty {
            throw EngineError(.unsupported, "volume prune filter \(key) is not supported")
        }
        // Docker API versions before 1.42 pruned all unused local volumes by default.
        // Cengine's supported API envelope starts at 1.44, but keep the version rule explicit here.
        let defaultAll = version < .init(major: 1, minor: 42)
        guard let values = filters["all"] else { return defaultAll ? .allUnused : .anonymous }
        return try pruneBoolean(values, key: "all") ? .allUnused : .anonymous
    }

    private func validateVolumeDrivers(in input: ContainerCreateRequest) throws {
        if let driver = input.HostConfig?.VolumeDriver, !driver.isEmpty, driver != "local" {
            throw EngineError(.unsupported, "volume driver \(driver) is not supported")
        }
        for mount in (input.Mounts ?? []) + (input.HostConfig?.Mounts ?? []) {
            guard let configuration = mount.VolumeOptions?.DriverConfig else { continue }
            if let driver = configuration.Name, !driver.isEmpty, driver != "local" {
                throw EngineError(.unsupported, "volume driver \(driver) is not supported")
            }
            if configuration.Options?.isEmpty == false {
                throw EngineError(.unsupported, "local volume driver options are not supported")
            }
        }
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
    public func validateAttachedExecStart(_ identifier: String, body: Data) async throws {
        let input = try decoder.decode(ExecStartRequest.self, from: body)
        try validateRuntimeInput(input)
        guard input.Detach != true else {
            throw EngineError(.badRequest, "attached exec start requires Detach=false")
        }
        let exec = try await runtime.inspectExec(identifier)
        if let tty = input.Tty, tty != exec.configuration.tty {
            throw EngineError(.badRequest, "exec start Tty must match the exec configuration")
        }
    }
    public func startAttachedExec(_ identifier: String) async throws -> CInt? { try await runtime.startAttachedExec(identifier) }
    public func containerWait(_ identifier: String, condition: String?) async throws -> ContainerWaitSubscription {
        try await runtime.subscribeContainerWait(identifier, condition: condition)
    }

    private func validateRuntimeInput(_ input: ContainerCreateRequest) throws -> [MountRecord] {
        try rejectActiveRuntimeFields([
            (!(input.Domainname ?? "").isEmpty, "Domainname"),
            (input.ArgsEscaped == true, "ArgsEscaped"),
            (input.NetworkDisabled == true, "NetworkDisabled"),
            (!(input.Shell ?? []).isEmpty, "Shell"),
        ], prefix: "ContainerConfig")
        if let timeout = input.StopTimeout, timeout < 0 {
            throw EngineError(.badRequest, "StopTimeout must not be negative")
        }
        try validateStopSignal(input.StopSignal)
        try validateHealthcheck(input.Healthcheck)
        try validateHostRuntimeInput(input.HostConfig)
        try validateVolumeDrivers(in: input)
        return try mounts(from: input)
    }

    private func validateRuntimeInput(_ input: ContainerUpdateRequest) throws {
        try validateResourceValues(
            memory: input.Memory, nanoCPUs: input.NanoCpus,
            cpuPeriod: input.CpuPeriod, cpuQuota: input.CpuQuota,
            pidsLimit: input.PidsLimit
        )
        try validateUnsupportedResourceValues(
            memory: input.Memory, cpuShares: input.CpuShares, blkioWeight: input.BlkioWeight,
            weightDevices: input.BlkioWeightDevice,
            throttleDevices: [
                input.BlkioDeviceReadBps, input.BlkioDeviceWriteBps,
                input.BlkioDeviceReadIOps, input.BlkioDeviceWriteIOps,
            ],
            cpuRealtimePeriod: input.CpuRealtimePeriod,
            cpuRealtimeRuntime: input.CpuRealtimeRuntime,
            memoryReservation: input.MemoryReservation, memorySwap: input.MemorySwap,
            update: true
        )
        if let swappiness = input.MemorySwappiness,
           swappiness != -1, !(0...100).contains(swappiness) {
            throw EngineError(.badRequest, "MemorySwappiness must be -1 or between 0 and 100")
        }
        try rejectActiveRuntimeFields([
            (input.CpuShares != nil && input.CpuShares != 0, "CpuShares"),
            (!(input.CgroupParent ?? "").isEmpty, "CgroupParent"),
            (input.BlkioWeight != nil && input.BlkioWeight != 0, "BlkioWeight"),
            (!(input.BlkioWeightDevice ?? []).isEmpty, "BlkioWeightDevice"),
            (!(input.BlkioDeviceReadBps ?? []).isEmpty, "BlkioDeviceReadBps"),
            (!(input.BlkioDeviceWriteBps ?? []).isEmpty, "BlkioDeviceWriteBps"),
            (!(input.BlkioDeviceReadIOps ?? []).isEmpty, "BlkioDeviceReadIOps"),
            (!(input.BlkioDeviceWriteIOps ?? []).isEmpty, "BlkioDeviceWriteIOps"),
            (input.CpuRealtimePeriod != nil && input.CpuRealtimePeriod != 0, "CpuRealtimePeriod"),
            (input.CpuRealtimeRuntime != nil && input.CpuRealtimeRuntime != 0, "CpuRealtimeRuntime"),
            (!(input.CpusetCpus ?? "").isEmpty, "CpusetCpus"),
            (!(input.CpusetMems ?? "").isEmpty, "CpusetMems"),
            (!(input.Devices ?? []).isEmpty, "Devices"),
            (!(input.DeviceCgroupRules ?? []).isEmpty, "DeviceCgroupRules"),
            (!(input.DeviceRequests ?? []).isEmpty, "DeviceRequests"),
            (input.MemoryReservation != nil && input.MemoryReservation != 0, "MemoryReservation"),
            (input.MemorySwap != nil && input.MemorySwap != 0, "MemorySwap"),
            (input.MemorySwappiness != nil && input.MemorySwappiness != -1, "MemorySwappiness"),
            (input.OomKillDisable == true, "OomKillDisable"),
            (!(input.Ulimits ?? []).isEmpty, "Ulimits"),
            (input.CpuCount != nil && input.CpuCount != 0, "CpuCount"),
            (input.CpuPercent != nil && input.CpuPercent != 0, "CpuPercent"),
            (input.IOMaximumIOps != nil && input.IOMaximumIOps != 0, "IOMaximumIOps"),
            (input.IOMaximumBandwidth != nil && input.IOMaximumBandwidth != 0, "IOMaximumBandwidth"),
        ], prefix: "ContainerUpdate")
        try validateRestartPolicy(
            name: input.RestartPolicy?.Name,
            maximumRetryCount: input.RestartPolicy?.MaximumRetryCount
        )
    }

    private func validateRuntimeInput(_ input: ExecCreateRequest) throws {
        if let detachKeys = input.DetachKeys, !detachKeys.isEmpty {
            throw EngineError(.unsupported, "ExecConfig.DetachKeys is not supported")
        }
        try validateConsoleSize(input.ConsoleSize, field: "ExecConfig.ConsoleSize")
    }

    private func validateRuntimeInput(_ input: ExecStartRequest) throws {
        try validateConsoleSize(input.ConsoleSize, field: "ExecStartConfig.ConsoleSize")
    }

    private func validateHostRuntimeInput(_ host: ContainerCreateRequest.HostConfig?) throws {
        try validateResourceValues(
            memory: host?.Memory, nanoCPUs: host?.NanoCpus,
            cpuPeriod: host?.CpuPeriod, cpuQuota: host?.CpuQuota,
            pidsLimit: host?.PidsLimit
        )
        try validateUnsupportedResourceValues(
            memory: host?.Memory, cpuShares: host?.CpuShares, blkioWeight: host?.BlkioWeight,
            weightDevices: host?.BlkioWeightDevice,
            throttleDevices: [
                host?.BlkioDeviceReadBps, host?.BlkioDeviceWriteBps,
                host?.BlkioDeviceReadIOps, host?.BlkioDeviceWriteIOps,
            ],
            cpuRealtimePeriod: host?.CpuRealtimePeriod,
            cpuRealtimeRuntime: host?.CpuRealtimeRuntime,
            memoryReservation: host?.MemoryReservation, memorySwap: host?.MemorySwap,
            update: false
        )
        if let swappiness = host?.MemorySwappiness,
           swappiness != -1, !(0...100).contains(swappiness) {
            throw EngineError(.badRequest, "HostConfig.MemorySwappiness must be -1 or between 0 and 100")
        }
        try rejectActiveRuntimeFields([
            (host?.CpuShares != nil && host?.CpuShares != 0, "CpuShares"),
            (!(host?.CgroupParent ?? "").isEmpty && host?.CgroupParent != "/docker/buildx", "CgroupParent"),
            (host?.BlkioWeight != nil && host?.BlkioWeight != 0, "BlkioWeight"),
            (!(host?.BlkioWeightDevice ?? []).isEmpty, "BlkioWeightDevice"),
            (!(host?.BlkioDeviceReadBps ?? []).isEmpty, "BlkioDeviceReadBps"),
            (!(host?.BlkioDeviceWriteBps ?? []).isEmpty, "BlkioDeviceWriteBps"),
            (!(host?.BlkioDeviceReadIOps ?? []).isEmpty, "BlkioDeviceReadIOps"),
            (!(host?.BlkioDeviceWriteIOps ?? []).isEmpty, "BlkioDeviceWriteIOps"),
            (host?.CpuRealtimePeriod != nil && host?.CpuRealtimePeriod != 0, "CpuRealtimePeriod"),
            (host?.CpuRealtimeRuntime != nil && host?.CpuRealtimeRuntime != 0, "CpuRealtimeRuntime"),
            (!(host?.CpusetCpus ?? "").isEmpty, "CpusetCpus"),
            (!(host?.CpusetMems ?? "").isEmpty, "CpusetMems"),
            (!(host?.DeviceRequests ?? []).isEmpty, "DeviceRequests"),
            (host?.MemoryReservation != nil && host?.MemoryReservation != 0, "MemoryReservation"),
            (host?.MemorySwap != nil && host?.MemorySwap != 0, "MemorySwap"),
            (host?.MemorySwappiness != nil && host?.MemorySwappiness != -1, "MemorySwappiness"),
            (host?.OomKillDisable == true, "OomKillDisable"),
            (host?.CpuCount != nil && host?.CpuCount != 0, "CpuCount"),
            (host?.CpuPercent != nil && host?.CpuPercent != 0, "CpuPercent"),
            (host?.IOMaximumIOps != nil && host?.IOMaximumIOps != 0, "IOMaximumIOps"),
            (host?.IOMaximumBandwidth != nil && host?.IOMaximumBandwidth != 0, "IOMaximumBandwidth"),
            (!(host?.Ulimits ?? []).isEmpty, "Ulimits"),
            (!(host?.Devices ?? []).isEmpty, "Devices"),
            (!(host?.DeviceCgroupRules ?? []).isEmpty, "DeviceCgroupRules"),
            (!(host?.Sysctls ?? [:]).isEmpty, "Sysctls"),
            (!(host?.MaskedPaths ?? []).isEmpty, "MaskedPaths"),
            (!(host?.ReadonlyPaths ?? []).isEmpty, "ReadonlyPaths"),
            (!(host?.VolumesFrom ?? []).isEmpty, "VolumesFrom"),
            (!(host?.GroupAdd ?? []).isEmpty, "GroupAdd"),
            (!(host?.StorageOpt ?? [:]).isEmpty, "StorageOpt"),
            (!(host?.Runtime ?? "").isEmpty, "Runtime"),
        ])
        try validateSecurityOptions(host?.SecurityOpt, privileged: host?.Privileged == true)
        try validateConsoleSize(host?.ConsoleSize, field: "HostConfig.ConsoleSize")
        try validateNamespaceModes(host)
        try validateOOMScore(host?.OomScoreAdj)
        try validateSharedMemorySize(host?.ShmSize)
        try validateIsolation(host?.Isolation)
        try validateRestartPolicy(
            name: host?.RestartPolicy?.Name,
            maximumRetryCount: host?.RestartPolicy?.MaximumRetryCount
        )
        let restartName = host?.RestartPolicy?.Name ?? "no"
        if host?.AutoRemove == true && restartName != "" && restartName != "no" {
            throw EngineError(.badRequest, "AutoRemove cannot be combined with a restart policy")
        }
    }

    private func validateSecurityOptions(_ values: [String]?, privileged: Bool) throws {
        guard let values, !values.isEmpty else { return }
        let privilegedDefaults: Set<String> = ["seccomp=unconfined", "apparmor=unconfined"]
        if privileged, values.allSatisfy(privilegedDefaults.contains) { return }
        throw EngineError(.unsupported, "HostConfig.SecurityOpt is not supported")
    }

    private func validateResourceValues(
        memory: Int64?, nanoCPUs: Int64?, cpuPeriod: Int64?, cpuQuota: Int64?, pidsLimit: Int64?
    ) throws {
        if let memory, memory < 0 { throw EngineError(.badRequest, "Memory must not be negative") }
        if let memory, memory > 0, memory < 6 * 1_024 * 1_024 {
            throw EngineError(.badRequest, "Memory must be at least 6 MiB")
        }
        if let nanoCPUs, nanoCPUs < 0 { throw EngineError(.badRequest, "NanoCpus must not be negative") }
        if let cpuPeriod, cpuPeriod < 0 { throw EngineError(.badRequest, "CpuPeriod must not be negative") }
        if let cpuQuota, cpuQuota < -1 { throw EngineError(.badRequest, "CpuQuota is invalid") }
        if let cpuPeriod, cpuPeriod != 0, !(1_000...1_000_000).contains(cpuPeriod) {
            throw EngineError(.badRequest, "CpuPeriod must be between 1000 and 1000000 microseconds")
        }
        if let cpuQuota, cpuQuota > 0, cpuQuota < 1_000 {
            throw EngineError(.badRequest, "CpuQuota must be at least 1000 microseconds")
        }
        if cpuQuota == -1 { throw EngineError(.unsupported, "unlimited CpuQuota is not supported") }
        if let nanoCPUs, nanoCPUs > 0, let cpuPeriod, cpuPeriod > 0 {
            throw EngineError(.badRequest, "NanoCpus and CpuPeriod cannot both be set")
        }
        if let nanoCPUs, nanoCPUs > 0, let cpuQuota, cpuQuota > 0 {
            throw EngineError(.badRequest, "NanoCpus and CpuQuota cannot both be set")
        }
        if let cpuPeriod, cpuPeriod > 0, !(cpuQuota.map { $0 > 0 } ?? false) {
            throw EngineError(.unsupported, "CpuPeriod without a positive CpuQuota is not supported")
        }
        _ = try validatedPidsLimit(pidsLimit)
    }

    private func validateUnsupportedResourceValues(
        memory: Int64?, cpuShares: Int64?, blkioWeight: UInt16?,
        weightDevices: [ContainerCreateRequest.HostConfig.WeightDeviceRequest]?,
        throttleDevices: [[ContainerCreateRequest.HostConfig.ThrottleDeviceRequest]?],
        cpuRealtimePeriod: Int64?, cpuRealtimeRuntime: Int64?,
        memoryReservation: Int64?, memorySwap: Int64?, update: Bool
    ) throws {
        if let cpuShares, cpuShares < 0 {
            throw EngineError(.badRequest, "CpuShares must not be negative")
        }
        if let blkioWeight, blkioWeight != 0, !(10...1_000).contains(blkioWeight) {
            throw EngineError(.badRequest, "BlkioWeight must be zero or between 10 and 1000")
        }
        if let cpuRealtimePeriod, cpuRealtimePeriod < 0 {
            throw EngineError(.badRequest, "CpuRealtimePeriod must not be negative")
        }
        if let cpuRealtimeRuntime, cpuRealtimeRuntime < -1 {
            throw EngineError(.badRequest, "CpuRealtimeRuntime must be -1 or greater")
        }
        if let memoryReservation, memoryReservation < 0 {
            throw EngineError(.badRequest, "MemoryReservation must not be negative")
        }
        if let memoryReservation, memoryReservation > 0,
           memoryReservation < 6 * 1_024 * 1_024 {
            throw EngineError(.badRequest, "MemoryReservation must be at least 6 MiB")
        }
        if let memory, memory > 0, let memoryReservation, memoryReservation > memory {
            throw EngineError(.badRequest, "MemoryReservation cannot exceed Memory")
        }
        if let memorySwap, memorySwap < -1 {
            throw EngineError(.badRequest, "MemorySwap must be -1 or greater")
        }
        if !update, let memorySwap, memorySwap > 0, !(memory.map { $0 > 0 } ?? false) {
            throw EngineError(.badRequest, "MemorySwap requires a positive Memory limit")
        }
        if let memory, memory > 0, let memorySwap, memorySwap > 0, memorySwap < memory {
            throw EngineError(.badRequest, "MemorySwap cannot be less than Memory")
        }
        for device in weightDevices ?? [] {
            guard let path = device.Path, path.hasPrefix("/"),
                  let weight = device.Weight, (10...1_000).contains(weight) else {
                throw EngineError(.badRequest, "BlkioWeightDevice requires an absolute Path and Weight from 10 to 1000")
            }
        }
        for device in throttleDevices.compactMap({ $0 }).flatMap({ $0 }) {
            guard let path = device.Path, path.hasPrefix("/"),
                  let rate = device.Rate, rate > 0 else {
                throw EngineError(.badRequest, "blkio throttle devices require an absolute Path and positive Rate")
            }
        }
    }

    private func validateNamespaceModes(_ host: ContainerCreateRequest.HostConfig?) throws {
        try validateMode(
            host?.CgroupnsMode, field: "HostConfig.CgroupnsMode",
            supported: ["", "private"], unsupported: ["host"]
        )
        try validateMode(
            host?.IpcMode, field: "HostConfig.IpcMode",
            supported: ["", "private"], unsupported: ["none", "shareable", "host"],
            unsupportedPrefix: "container:"
        )
        try validateMode(
            host?.PidMode, field: "HostConfig.PidMode",
            supported: [""], unsupported: ["host"], unsupportedPrefix: "container:"
        )
        try validateMode(
            host?.UTSMode, field: "HostConfig.UTSMode",
            supported: [""], unsupported: ["host"]
        )
        try validateMode(
            host?.UsernsMode, field: "HostConfig.UsernsMode",
            supported: ["", "host"], unsupported: []
        )
        if let cgroup = host?.Cgroup, !cgroup.isEmpty {
            if cgroup.hasPrefix("container:"), cgroup.count > "container:".count {
                throw EngineError(.unsupported, "HostConfig.Cgroup container sharing is not supported")
            }
            throw EngineError(.badRequest, "invalid HostConfig.Cgroup value: \(cgroup)")
        }
        if let networkMode = host?.NetworkMode {
            if networkMode == "host" {
                throw EngineError(.unsupported, "HostConfig.NetworkMode=host is not supported")
            }
            if networkMode.hasPrefix("container:") {
                guard networkMode.count > "container:".count else {
                    throw EngineError(.badRequest, "HostConfig.NetworkMode requires a container identifier")
                }
                throw EngineError(.unsupported, "HostConfig.NetworkMode container sharing is not supported")
            }
        }
    }

    private func validateMode(
        _ value: String?, field: String, supported: Set<String>, unsupported: Set<String>,
        unsupportedPrefix: String? = nil
    ) throws {
        guard let value else { return }
        if supported.contains(value) { return }
        if unsupported.contains(value) {
            throw EngineError(.unsupported, "\(field)=\(value) is not supported")
        }
        if let prefix = unsupportedPrefix, value.hasPrefix(prefix) {
            guard value.count > prefix.count else {
                throw EngineError(.badRequest, "\(field) requires a container identifier")
            }
            throw EngineError(.unsupported, "\(field) container sharing is not supported")
        }
        throw EngineError(.badRequest, "invalid \(field) value: \(value)")
    }

    private func validateOOMScore(_ value: Int?) throws {
        guard let value else { return }
        guard (-1_000...1_000).contains(value) else {
            throw EngineError(.badRequest, "HostConfig.OomScoreAdj must be between -1000 and 1000")
        }
        if value != 0 { throw EngineError(.unsupported, "HostConfig.OomScoreAdj is not supported") }
    }

    private func validateSharedMemorySize(_ value: Int64?) throws {
        guard let value else { return }
        guard value >= 0 else { throw EngineError(.badRequest, "HostConfig.ShmSize must not be negative") }
        if value != 0 && value != 64 * 1_024 * 1_024 {
            throw EngineError(.unsupported, "HostConfig.ShmSize values other than 64 MiB are not supported")
        }
    }

    private func validateIsolation(_ value: String?) throws {
        guard let value else { return }
        let normalized = value.lowercased()
        guard !normalized.isEmpty, normalized != "default" else { return }
        if normalized == "process" || normalized == "hyperv" {
            throw EngineError(.unsupported, "HostConfig.Isolation=\(value) is not supported")
        }
        throw EngineError(.badRequest, "invalid HostConfig.Isolation value: \(value)")
    }

    private func validateConsoleSize(_ value: [Int]?, field: String) throws {
        guard let value else { return }
        guard value.count == 2, value.allSatisfy({ $0 >= 0 }) else {
            throw EngineError(.badRequest, "\(field) must be [height, width] with non-negative values")
        }
        if value.contains(where: { $0 != 0 }) {
            throw EngineError(.unsupported, "\(field) is not supported")
        }
    }

    private func validateRestartPolicy(name: String?, maximumRetryCount: Int?) throws {
        guard name != nil || maximumRetryCount != nil else { return }
        let name = name ?? ""
        guard ["", "no", "always", "unless-stopped", "on-failure"].contains(name) else {
            throw EngineError(.badRequest, "invalid restart policy: \(name)")
        }
        let maximum = maximumRetryCount ?? 0
        guard maximum >= 0 else {
            throw EngineError(.badRequest, "restart policy MaximumRetryCount must not be negative")
        }
        if maximum != 0 && name != "on-failure" {
            throw EngineError(.badRequest, "MaximumRetryCount requires the on-failure restart policy")
        }
    }

    private func validateHealthcheck(_ health: ContainerCreateRequest.HealthcheckRequest?) throws {
        guard let health else { return }
        for (value, field) in [
            (health.Interval, "Interval"),
            (health.Timeout, "Timeout"),
            (health.StartPeriod, "StartPeriod"),
            (health.StartInterval, "StartInterval"),
        ] {
            guard let value else { continue }
            guard value == 0 || value >= 1_000_000 else {
                throw EngineError(.badRequest, "Healthcheck.\(field) must be zero or at least 1ms")
            }
        }
        if let retries = health.Retries, retries < 0 {
            throw EngineError(.badRequest, "Healthcheck.Retries must not be negative")
        }
        if let startInterval = health.StartInterval, startInterval != 0 {
            throw EngineError(.unsupported, "Healthcheck.StartInterval is not supported")
        }
        guard let test = health.Test else { return }
        guard let kind = test.first else {
            throw EngineError(.unsupported, "inheriting an image healthcheck is not supported")
        }
        switch kind {
        case "NONE":
            guard test.count == 1 else {
                throw EngineError(.badRequest, "Healthcheck.NONE does not accept arguments")
            }
        case "CMD", "CMD-SHELL":
            guard test.count > 1 else {
                throw EngineError(.badRequest, "Healthcheck.\(kind) requires a command")
            }
        default:
            throw EngineError(.badRequest, "invalid healthcheck test form: \(kind)")
        }
    }

    private func validateStopSignal(_ value: String?) throws {
        guard let value, !value.isEmpty else { return }
        let normalized = value.uppercased().hasPrefix("SIG")
            ? String(value.uppercased().dropFirst(3))
            : value.uppercased()
        if let number = Int(normalized) {
            guard (1...64).contains(number) else {
                throw EngineError(.badRequest, "invalid StopSignal: \(value)")
            }
            return
        }
        if dockerImplementedSignalNames.contains(normalized) { return }
        if dockerLinuxSignalNames.contains(normalized) || validRealtimeSignalName(normalized) {
            throw EngineError(.unsupported, "StopSignal \(value) is not supported by the guest runtime")
        }
        throw EngineError(.badRequest, "invalid StopSignal: \(value)")
    }

    private func validRealtimeSignalName(_ value: String) -> Bool {
        if value == "RTMIN" || value == "RTMAX" { return true }
        if value.hasPrefix("RTMIN+"), let offset = Int(value.dropFirst("RTMIN+".count)) {
            return (0...30).contains(offset)
        }
        if value.hasPrefix("RTMAX-"), let offset = Int(value.dropFirst("RTMAX-".count)) {
            return (0...30).contains(offset)
        }
        return false
    }

    private func rejectActiveRuntimeFields(
        _ fields: [(Bool, String)], prefix: String = "HostConfig"
    ) throws {
        if let field = fields.first(where: \.0)?.1 {
            let qualified = field.contains(".") ? field : "\(prefix).\(field)"
            throw EngineError(.unsupported, "\(qualified) is not supported")
        }
    }

    private func mounts(from input: ContainerCreateRequest) throws -> [MountRecord] {
        var result = try ((input.Mounts ?? []) + (input.HostConfig?.Mounts ?? [])).map { mount in
            guard mount.Target.hasPrefix("/") else {
                throw EngineError(.badRequest, "mount target must be an absolute path: \(mount.Target)")
            }
            let kind: MountRecord.Kind
            switch mount.Type {
            case "bind": kind = .bind
            case "volume": kind = .volume
            case "tmpfs": kind = .tmpfs
            case "image", "npipe", "cluster":
                throw EngineError(.unsupported, "mount type \(mount.Type) is not supported")
            default:
                throw EngineError(.badRequest, "invalid mount type: \(mount.Type)")
            }
            if mount.BindOptions != nil, kind != .bind {
                throw EngineError(.badRequest, "BindOptions is only valid for bind mounts")
            }
            if mount.VolumeOptions != nil, kind != .volume {
                throw EngineError(.badRequest, "VolumeOptions is only valid for volume mounts")
            }
            if mount.TmpfsOptions != nil, kind != .tmpfs {
                throw EngineError(.badRequest, "TmpfsOptions is only valid for tmpfs mounts")
            }
            if mount.ImageOptions != nil {
                throw EngineError(.badRequest, "ImageOptions is only valid for image mounts")
            }
            if mount.ClusterOptions != nil {
                throw EngineError(.badRequest, "ClusterOptions is only valid for cluster mounts")
            }
            if let consistency = mount.Consistency {
                switch consistency {
                case "", "default", "consistent": break
                case "cached", "delegated":
                    throw EngineError(.unsupported, "mount Consistency=\(consistency) is not supported")
                default:
                    throw EngineError(.badRequest, "invalid mount Consistency: \(consistency)")
                }
            }
            if kind == .bind {
                guard let source = mount.Source, source.hasPrefix("/") else {
                    throw EngineError(.badRequest, "bind mount source must be an absolute path")
                }
            } else if kind == .tmpfs, let source = mount.Source, !source.isEmpty {
                throw EngineError(.badRequest, "tmpfs mounts do not accept a source")
            } else if kind == .volume, let source = mount.Source,
                      !source.isEmpty, !Identifier.validateName(source) {
                throw EngineError(.badRequest, "invalid volume name: \(source)")
            }
            let bindOptions = mount.BindOptions
            if bindOptions?.NonRecursive == true || bindOptions?.ReadOnlyNonRecursive == true
                || bindOptions?.ReadOnlyForceRecursive == true {
                throw EngineError(.unsupported, "non-recursive bind mount options are not supported")
            }
            if mount.VolumeOptions?.Labels?.isEmpty == false {
                throw EngineError(.unsupported, "VolumeOptions.Labels is not supported")
            }
            if let subpath = mount.VolumeOptions?.Subpath, !subpath.isEmpty {
                let components = subpath.split(separator: "/", omittingEmptySubsequences: false)
                guard !subpath.hasPrefix("/"), !components.contains(".."), !components.contains(".") else {
                    throw EngineError(.badRequest, "invalid volume subpath: \(subpath)")
                }
            }
            if let size = mount.TmpfsOptions?.SizeBytes, size < 0 {
                throw EngineError(.badRequest, "TmpfsOptions.SizeBytes must not be negative")
            }
            if let mode = mount.TmpfsOptions?.Mode, mode > 0o7777 {
                throw EngineError(.badRequest, "TmpfsOptions.Mode is invalid")
            }
            if let options = mount.TmpfsOptions?.Options, !options.isEmpty {
                guard options.allSatisfy({ $0.count == 1 || $0.count == 2 }) else {
                    throw EngineError(.badRequest, "TmpfsOptions.Options entries require one or two values")
                }
                throw EngineError(.unsupported, "TmpfsOptions.Options is not supported")
            }
            return MountRecord(
                kind: kind,
                source: mount.Source ?? "", destination: mount.Target, readOnly: mount.ReadOnly ?? false,
                noCopy: mount.VolumeOptions?.NoCopy ?? false, subpath: mount.VolumeOptions?.Subpath,
                tmpfsSizeBytes: mount.TmpfsOptions?.SizeBytes, tmpfsMode: mount.TmpfsOptions?.Mode,
                createSourceIfMissing: kind == .bind ? (bindOptions?.CreateMountpoint ?? false) : nil,
                propagation: kind == .bind ? try validatedMountPropagation(bindOptions?.Propagation) : nil
            )
        }
        for bind in input.HostConfig?.Binds ?? [] {
            let fields = bind.split(separator: ":", maxSplits: 2).map(String.init)
            guard fields.count >= 2 else { throw EngineError(.badRequest, "invalid bind mount: \(bind)") }
            let kind: MountRecord.Kind = fields[0].hasPrefix("/") ? .bind : .volume
            guard fields[1].hasPrefix("/") else {
                throw EngineError(.badRequest, "mount target must be an absolute path: \(fields[1])")
            }
            if kind == .volume, !Identifier.validateName(fields[0]) {
                throw EngineError(.badRequest, "invalid volume name: \(fields[0])")
            }
            let options = fields.count == 3
                ? fields[2].split(separator: ",", omittingEmptySubsequences: false).map(String.init).filter { !$0.isEmpty }
                : []
            let recognized = Set([
                "ro", "rw", "nocopy", "z", "Z",
                "private", "rprivate", "shared", "rshared", "slave", "rslave",
            ])
            if let option = options.first(where: { !recognized.contains($0) }) {
                throw EngineError(.badRequest, "invalid bind mount option: \(option)")
            }
            if options.contains("ro") && options.contains("rw") {
                throw EngineError(.badRequest, "conflicting bind mount access modes")
            }
            if kind == .bind, options.contains("nocopy") {
                throw EngineError(.badRequest, "nocopy is only valid for volume mounts")
            }
            if options.contains("nocopy") {
                throw EngineError(.unsupported, "legacy bind option nocopy is not supported")
            }
            if options.contains("z") || options.contains("Z") {
                throw EngineError(.unsupported, "SELinux bind relabeling is not supported")
            }
            let requestedPropagation = options.filter { MountRecord.Propagation(rawValue: $0) != nil }
            if kind != .bind, !requestedPropagation.isEmpty {
                throw EngineError(.badRequest, "bind propagation is only valid for bind mounts")
            }
            guard requestedPropagation.count <= 1 else {
                throw EngineError(.badRequest, "conflicting bind propagation modes: \(fields[2])")
            }
            guard kind == .bind || requestedPropagation.isEmpty else {
                throw EngineError(.badRequest, "mount propagation is only valid for bind mounts")
            }
            result.append(.init(
                kind: kind, source: fields[0], destination: fields[1],
                readOnly: options.contains("ro"),
                createSourceIfMissing: kind == .bind ? true : nil,
                propagation: try validatedMountPropagation(requestedPropagation.first)
            ))
        }
        for (destination, options) in input.HostConfig?.Tmpfs ?? [:] {
            guard destination.hasPrefix("/") else {
                throw EngineError(.badRequest, "tmpfs target must be an absolute path: \(destination)")
            }
            let values = options.split(separator: ",", omittingEmptySubsequences: false)
                .map(String.init).filter { !$0.isEmpty }
            if values.contains("ro") && values.contains("rw") {
                throw EngineError(.badRequest, "conflicting tmpfs access modes")
            }
            var size: Int64?
            var mode: UInt32?
            for value in values {
                switch value {
                case "ro", "rw", "exec", "nosuid", "nodev": break
                case "noexec", "suid", "dev":
                    throw EngineError(.unsupported, "tmpfs option \(value) is not supported")
                default:
                    if value.hasPrefix("size=") {
                        guard size == nil,
                              let parsed = parseDockerByteSize(String(value.dropFirst("size=".count))),
                              parsed >= 0 else {
                            throw EngineError(.badRequest, "invalid tmpfs size option: \(value)")
                        }
                        size = parsed
                    } else if value.hasPrefix("mode=") {
                        guard mode == nil,
                              let parsed = UInt32(value.dropFirst("mode=".count), radix: 8),
                              parsed <= 0o7777 else {
                            throw EngineError(.badRequest, "invalid tmpfs mode option: \(value)")
                        }
                        mode = parsed
                    } else {
                        throw EngineError(.badRequest, "invalid tmpfs option: \(value)")
                    }
                }
            }
            result.append(.init(
                kind: .tmpfs, source: options, destination: destination,
                readOnly: values.contains("ro"),
                tmpfsSizeBytes: size,
                tmpfsMode: mode
            ))
        }
        if let duplicate = Dictionary(grouping: result, by: \.destination)
            .first(where: { $0.value.count > 1 })?.key {
            throw EngineError(.badRequest, "duplicate mount target: \(duplicate)")
        }
        return result
    }

    private func validatedPidsLimit(_ value: Int64?) throws -> Int64? {
        guard let value else { return nil }
        guard value >= -1 else {
            throw EngineError(.badRequest, "invalid PID limit: \(value)")
        }
        return value
    }

    private func validatedMountPropagation(_ value: String?) throws -> MountRecord.Propagation {
        guard let value, !value.isEmpty else { return .rprivate }
        guard let propagation = MountRecord.Propagation(rawValue: value) else {
            throw EngineError(.badRequest, "invalid mount propagation mode: \(value)")
        }
        guard propagation == .private || propagation == .rprivate else {
            throw EngineError(
                .unsupported,
                "bind propagation mode \(value) is unavailable for virtiofs-backed host mounts"
            )
        }
        return propagation
    }

    private func normalizedCapabilities(_ values: [String]) throws -> [String] {
        var seen = Set<String>()
        return try values.compactMap { raw in
            var normalized = raw.uppercased()
            if normalized.hasPrefix("CAP_") { normalized.removeFirst("CAP_".count) }
            guard normalized == "ALL" || dockerLinuxCapabilities.contains(normalized) else {
                throw EngineError(.badRequest, "unknown Linux capability: \(raw)")
            }
            let result = normalized == "ALL" ? normalized : "CAP_\(normalized)"
            return seen.insert(result).inserted ? result : nil
        }
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

private let dockerLinuxCapabilities: Set<String> = [
    "AUDIT_CONTROL", "AUDIT_READ", "AUDIT_WRITE", "BLOCK_SUSPEND", "BPF",
    "CHECKPOINT_RESTORE", "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID",
    "IPC_LOCK", "IPC_OWNER", "KILL", "LEASE", "LINUX_IMMUTABLE", "MAC_ADMIN", "MAC_OVERRIDE",
    "MKNOD", "NET_ADMIN", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_RAW", "PERFMON",
    "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_ADMIN", "SYS_BOOT", "SYS_CHROOT",
    "SYS_MODULE", "SYS_NICE", "SYS_PACCT", "SYS_PTRACE", "SYS_RAWIO", "SYS_RESOURCE",
    "SYS_TIME", "SYS_TTY_CONFIG", "SYSLOG", "WAKE_ALARM",
]

private let dockerImplementedSignalNames: Set<String> = [
    "HUP", "INT", "QUIT", "KILL", "USR1", "USR2", "PIPE", "ALRM", "TERM",
    "CHLD", "CONT", "STOP", "TSTP",
]

private let dockerLinuxSignalNames: Set<String> = dockerImplementedSignalNames.union([
    "ABRT", "BUS", "FPE", "ILL", "POLL", "PROF", "PWR", "SEGV", "STKFLT",
    "SYS", "TRAP", "TTIN", "TTOU", "URG", "VTALRM", "WINCH", "XCPU", "XFSZ",
    "IOT", "IO", "CLD",
])

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
        let Hostname: String; let User: String; let Tty: Bool; let AttachStdin: Bool; let OpenStdin: Bool; let Env: [String]
        let Cmd: [String]; let Image: String; let WorkingDir: String; let Labels: [String: String]
        let Healthcheck: HealthcheckResponse?
    }
    public struct HealthcheckResponse: Codable, Sendable {
        let Test: [String]; let Interval: Int64; let Timeout: Int64; let Retries: Int; let StartPeriod: Int64
    }
    public struct HostConfigResponse: Codable, Sendable {
        let Memory: UInt64; let NanoCpus: Int64; let PidsLimit: Int64
        let AutoRemove: Bool; let Privileged: Bool
        let CapAdd: [String]; let CapDrop: [String]
        let ReadonlyRootfs: Bool; let Init: Bool; let RestartPolicy: RestartPolicy
        let Annotations: [String: String]?
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
        Config = .init(Hostname: record.hostname, User: record.user, Tty: record.tty, AttachStdin: record.attachStdin, OpenStdin: record.openStdin, Env: record.environment, Cmd: record.processArguments, Image: record.image, WorkingDir: record.workingDirectory.isEmpty ? "/" : record.workingDirectory, Labels: record.labels, Healthcheck: record.healthcheck.map { .init(Test: $0.test, Interval: $0.intervalNanoseconds, Timeout: $0.timeoutNanoseconds, Retries: $0.retries, StartPeriod: $0.startPeriodNanoseconds) })
        RestartCount = record.restartCount
        let mounts = record.mounts.map { mount in
            MountResponse(
                Type: mount.kind.rawValue, Name: mount.kind == .volume ? mount.source : nil,
                Source: mount.source, Destination: mount.destination, Driver: mount.kind == .volume ? "local" : "",
                Mode: mount.readOnly ? "ro" : "", RW: !mount.readOnly,
                Propagation: mount.propagation?.rawValue ?? "",
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
            PidsLimit: record.pidsLimit,
            AutoRemove: record.autoRemove, Privileged: record.privileged,
            CapAdd: record.capabilityAdd, CapDrop: record.capabilityDrop,
            ReadonlyRootfs: record.readOnlyRootfs, Init: record.useInit,
            RestartPolicy: .init(Name: record.restartPolicy.name, MaximumRetryCount: record.restartPolicy.maximumRetryCount),
            Annotations: record.annotations.isEmpty ? nil : record.annotations,
            Binds: record.mounts.filter { $0.kind != .tmpfs }.map {
                var options = $0.readOnly ? ["ro"] : []
                if let propagation = $0.propagation, propagation != .rprivate {
                    options.append(propagation.rawValue)
                }
                return "\($0.source):\($0.destination)\(options.isEmpty ? "" : ":" + options.joined(separator: ","))"
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
                IPAMConfig: nil, Links: nil, Aliases: aliases,
                DriverOpts: version >= .init(major: 1, minor: 46) ? endpoint.driverOptions : nil,
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
