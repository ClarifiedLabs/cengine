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
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    public init(runtime: EngineRuntime, root: URL) { self.runtime = runtime; self.root = root }

    public func route(_ request: APIRequest) async -> APIResponse {
        do { return try await handle(request) }
        catch let error as EngineError { return errorResponse(error) }
        catch { return json(status: .internalServerError, DockerErrorBody(message: error.localizedDescription)) }
    }

    private func handle(_ request: APIRequest) async throws -> APIResponse {
        let components = try parsedComponents(request.uri)
        let path = components.path.replacingOccurrences(of: #"^/v1\.44"#, with: "", options: .regularExpression)
        let query = queryItems(components)

        switch (request.method, path) {
        case (.GET, "/_ping"), (.HEAD, "/_ping"):
            return APIResponse(status: .ok, headers: ["Api-Version": "1.44", "Docker-Experimental": "true"], body: request.method == .HEAD ? Data() : Data("OK".utf8))
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
        case (.GET, "/containers/json"):
            let all = parseBool(query["all"]) ?? false
            return json(status: .ok, await runtime.listContainers(all: all).map(ContainerSummaryResponse.init))
        case (.POST, "/containers/create"):
            let input = try decoder.decode(ContainerCreateRequest.self, from: request.body)
            let name = query["name"].flatMap { $0.isEmpty ? nil : $0 } ?? String(Identifier.random().prefix(12))
            var record = ContainerRecord(name: name, image: ImageReference.normalized(input.Image), processArguments: (input.Entrypoint ?? []) + (input.Cmd ?? []))
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
            if let nano = input.HostConfig?.NanoCpus, nano > 0 { record.cpus = max(1, Int((nano + 999_999_999) / 1_000_000_000)) }
            record.stopSignal = input.StopSignal ?? "SIGTERM"
            record.stopTimeoutSeconds = input.StopTimeout ?? 10
            record.restartPolicy = .init(name: input.HostConfig?.RestartPolicy?.Name ?? "no", maximumRetryCount: input.HostConfig?.RestartPolicy?.MaximumRetryCount ?? 0)
            record.mounts = try mounts(from: input)
            record.ports = ports(from: input)
            let created = try await runtime.createContainer(record)
            return json(status: .created, ContainerCreateResponse(Id: created.id, Warnings: []))
        case (.GET, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/json"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/json".count))
            return json(status: .ok, try await inspectContainer(runtime.container(id)))
        case (.GET, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/logs"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/logs".count))
            _ = try await runtime.container(id)
            guard parseBool(query["follow"]) != true else {
                throw EngineError(.unsupported, "follow logs is not supported yet")
            }
            return APIResponse(
                status: .ok,
                headers: ["Content-Type": "application/vnd.docker.raw-stream"],
                body: try await runtime.containerLogs(id)
            )
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
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/start"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/start".count))
            try await runtime.startContainer(id); return APIResponse(status: .noContent)
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/stop"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/stop".count))
            try await runtime.stopContainer(id, timeoutSeconds: query["t"].flatMap(Int.init)); return APIResponse(status: .noContent)
        case (.POST, let value) where value.hasPrefix("/containers/") && value.hasSuffix("/wait"):
            let id = String(value.dropFirst("/containers/".count).dropLast("/wait".count))
            return json(status: .ok, ContainerWaitResponse(StatusCode: try await runtime.waitContainer(id), Error: nil))
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
            try await runtime.removeContainer(id, force: parseBool(query["force"]) ?? false); return APIResponse(status: .noContent)
        case (.GET, "/networks"):
            return json(status: .ok, await runtime.listNetworks().map(DockerNetworkResponse.init))
        case (.GET, let value) where value.hasPrefix("/networks/"):
            return json(status: .ok, DockerNetworkResponse(try await runtime.network(String(value.dropFirst("/networks/".count)))))
        case (.POST, "/networks/create"):
            let input = try decoder.decode(NetworkCreateRequest.self, from: request.body)
            let network = try await runtime.createNetwork(name: input.Name, labels: input.Labels ?? [:])
            return json(status: .created, NetworkCreateResponse(Id: network.id, Warning: ""))
        case (.DELETE, let value) where value.hasPrefix("/networks/"):
            try await runtime.removeNetwork(String(value.dropFirst("/networks/".count))); return APIResponse(status: .noContent)
        case (.GET, "/volumes"):
            return json(status: .ok, VolumeListEnvelope(Volumes: await runtime.listVolumes().map(DockerVolumeResponse.init), Warnings: []))
        case (.GET, let value) where value.hasPrefix("/volumes/"):
            return json(status: .ok, DockerVolumeResponse(try await runtime.volume(String(value.dropFirst("/volumes/".count)))))
        case (.POST, "/volumes/create"):
            let input = try decoder.decode(VolumeCreateRequest.self, from: request.body)
            let name = input.Name.flatMap { $0.isEmpty ? nil : $0 } ?? Identifier.random()
            return json(status: .created, DockerVolumeResponse(try await runtime.createVolume(name: name, labels: input.Labels ?? [:], options: input.DriverOpts ?? [:])))
        case (.DELETE, let value) where value.hasPrefix("/volumes/"):
            try await runtime.removeVolume(String(value.dropFirst("/volumes/".count)), force: parseBool(query["force"]) ?? false); return APIResponse(status: .noContent)
        case (.GET, "/images/json"):
            return json(status: .ok, await runtime.listImages().map(ImageSummaryResponse.init))
        case (.POST, "/images/create"):
            guard let reference = query["fromImage"], !reference.isEmpty else { throw EngineError(.badRequest, "fromImage is required") }
            let tag = query["tag"].flatMap { $0.isEmpty ? nil : $0 }
            let fullReference = ImageReference.normalized(tag.map { "\(reference):\($0)" } ?? reference)
            let platform = query["platform"] ?? "linux/arm64"
            _ = try await runtime.pullImage(fullReference, platform: platform)
            let progress = "{\"status\":\"Pull complete\",\"id\":\"\(fullReference)\"}\n"
            return APIResponse(status: .ok, headers: ["Content-Type": "application/json"], body: Data(progress.utf8))
        case (.GET, let value) where value.hasPrefix("/images/") && value.hasSuffix("/json"):
            let id = String(value.dropFirst("/images/".count).dropLast("/json".count)).removingPercentEncoding ?? value
            return json(status: .ok, ImageInspectResponse(try await runtime.image(id)))
        case (.DELETE, let value) where value.hasPrefix("/images/"):
            let id = String(value.dropFirst("/images/".count)).removingPercentEncoding ?? value
            let image = try await runtime.image(id)
            try await runtime.removeImage(id, force: parseBool(query["force"]) ?? false)
            return json(status: .ok, [ImageDeleteResponse(Deleted: image.id)])
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

    private func errorResponse(_ error: EngineError) -> APIResponse {
        let status: HTTPResponseStatus = switch error.code {
        case .badRequest: .badRequest
        case .unauthorized: .unauthorized
        case .notFound: .notFound
        case .conflict: .conflict
        case .unsupported: .notImplemented
        case .internalError: .internalServerError
        }
        return json(status: status, DockerErrorBody(message: error.message))
    }

    private func parsedComponents(_ uri: String) throws -> URLComponents {
        guard let value = URLComponents(string: uri) else { throw EngineError(.badRequest, "invalid request URI") }
        return value
    }
    private func queryItems(_ components: URLComponents) -> [String: String] { Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value ?? "") }) }
    private func parseBool(_ value: String?) -> Bool? { value.map { $0 == "1" || $0.lowercased() == "true" } }

    private func inspectContainer(_ record: ContainerRecord) -> ContainerInspectResponse { .init(record) }

    public func containerIO(_ identifier: String) async throws -> ContainerIOBridge {
        try await runtime.containerIO(identifier)
    }

    public func execIO(_ identifier: String) async throws -> ContainerIOBridge { try await runtime.execIO(identifier) }
    public func startExec(_ identifier: String) async throws { try await runtime.startExec(identifier) }

    private func mounts(from input: ContainerCreateRequest) throws -> [MountRecord] {
        var result = (input.Mounts ?? []).map { mount in
            MountRecord(
                kind: MountRecord.Kind(rawValue: mount.Type) ?? .bind,
                source: mount.Source ?? "", destination: mount.Target, readOnly: mount.ReadOnly ?? false
            )
        }
        for bind in input.HostConfig?.Binds ?? [] {
            let fields = bind.split(separator: ":", maxSplits: 2).map(String.init)
            guard fields.count >= 2 else { throw EngineError(.badRequest, "invalid bind mount: \(bind)") }
            result.append(.init(kind: fields[0].hasPrefix("/") ? .bind : .volume, source: fields[0], destination: fields[1], readOnly: fields.count == 3 && fields[2].split(separator: ",").contains("ro")))
        }
        for (destination, options) in input.HostConfig?.Tmpfs ?? [:] {
            result.append(.init(
                kind: .tmpfs, source: options, destination: destination,
                readOnly: options.split(separator: ",").contains("ro")
            ))
        }
        return result
    }

    private func ports(from input: ContainerCreateRequest) -> [PortBinding] {
        (input.HostConfig?.PortBindings ?? [:]).flatMap { key, bindings -> [PortBinding] in
            let parts = key.split(separator: "/", maxSplits: 1).map(String.init)
            guard let containerPort = UInt16(parts[0]) else { return [] }
            return bindings.compactMap { binding in
                guard let hostPort = UInt16(binding.HostPort ?? "") else { return nil }
                return PortBinding(hostIP: binding.HostIp ?? "0.0.0.0", hostPort: hostPort, containerPort: containerPort, proto: parts.count == 2 ? parts[1] : "tcp")
            }
        }
    }
}

private struct VolumeListEnvelope: Encodable { let Volumes: [DockerVolumeResponse]; let Warnings: [String] }

public struct ContainerInspectResponse: Codable, Sendable {
    public let Id: String
    public let Name: String
    public let Created: String
    public let Path: String
    public let Args: [String]
    public let Image: String
    public let State: StateResponse
    public let Config: ConfigResponse
    public let RestartCount: Int

    public struct StateResponse: Codable, Sendable { let Status: String; let Running: Bool; let Paused: Bool; let Restarting: Bool; let OOMKilled: Bool; let Dead: Bool; let Pid: Int; let ExitCode: Int32; let Error: String; let StartedAt: String; let FinishedAt: String }
    public struct ConfigResponse: Codable, Sendable { let Hostname: String; let User: String; let Tty: Bool; let OpenStdin: Bool; let Env: [String]; let Cmd: [String]; let Image: String; let WorkingDir: String; let Labels: [String: String] }

    init(_ record: ContainerRecord) {
        let formatter = ISO8601DateFormatter()
        Id = record.id; Name = "/\(record.name)"; Created = formatter.string(from: record.createdAt)
        Path = record.processArguments.first ?? ""; Args = Array(record.processArguments.dropFirst()); Image = record.image
        State = .init(Status: record.phase.rawValue, Running: record.phase == .running, Paused: record.phase == .paused, Restarting: false, OOMKilled: false, Dead: record.phase == .dead, Pid: 0, ExitCode: record.exitCode ?? 0, Error: "", StartedAt: record.startedAt.map(formatter.string) ?? "0001-01-01T00:00:00Z", FinishedAt: record.finishedAt.map(formatter.string) ?? "0001-01-01T00:00:00Z")
        Config = .init(Hostname: record.hostname, User: record.user, Tty: record.tty, OpenStdin: record.openStdin, Env: record.environment, Cmd: record.processArguments, Image: record.image, WorkingDir: record.workingDirectory.isEmpty ? "/" : record.workingDirectory, Labels: record.labels)
        RestartCount = record.restartCount
    }
}
