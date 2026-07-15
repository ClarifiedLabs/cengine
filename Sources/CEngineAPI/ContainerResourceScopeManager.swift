import CEngineCore
import CEngineRuntime
import Darwin
import Dispatch
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

public struct ContainerResourceScope: Codable, Equatable, Sendable {
    public let id: String
    public let dockerHost: String

    public init(id: String, dockerHost: String) {
        self.id = id
        self.dockerHost = dockerHost
    }
}

public actor ContainerResourceScopeManager {
    private struct Scope {
        let listener: ScopedDockerListener
        let processMonitor: DispatchSourceProcess
    }

    private let runtime: EngineRuntime
    private let root: URL
    private let socketDirectory: URL
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: max(2, System.coreCount / 2))
    private let monitorQueue = DispatchQueue(label: "dev.cengine.resource-scopes")
    private var scopes: [String: Scope] = [:]
    private var isShutdown = false

    public init(
        runtime: EngineRuntime,
        root: URL,
        socketDirectory: URL = URL(filePath: "/tmp/cengine-\(getuid())-scopes", directoryHint: .isDirectory)
    ) {
        self.runtime = runtime
        self.root = root
        self.socketDirectory = socketDirectory
    }

    public func create(ownerPID: Int32, resources: ContainerResourceOverride) async throws -> ContainerResourceScope {
        guard !isShutdown else { throw EngineError(.conflict, "container resource scopes are shutting down") }
        try resources.validate()
        guard ownerPID > 0, kill(ownerPID, 0) == 0 else {
            throw EngineError(.badRequest, "resource scope owner process \(ownerPID) is not running")
        }
        try prepareSocketDirectory()

        let id = UUID().uuidString.lowercased()
        let socket = socketDirectory.appending(
            path: "\(getpid())-\(id.prefix(12)).sock",
            directoryHint: .notDirectory
        )
        let router = DockerRouter(runtime: runtime, root: root, containerResourceOverride: resources)
        let listener = ScopedDockerListener(group: group, socketPath: socket.path, router: router)
        try await listener.start()

        let monitor = DispatchSource.makeProcessSource(
            identifier: pid_t(ownerPID), eventMask: .exit, queue: monitorQueue
        )
        monitor.setEventHandler { [weak self] in
            Task { await self?.remove(id) }
        }
        scopes[id] = Scope(listener: listener, processMonitor: monitor)
        monitor.resume()
        return ContainerResourceScope(id: id, dockerHost: "unix://\(socket.path)")
    }

    public func remove(_ id: String) async {
        guard let scope = scopes.removeValue(forKey: id) else { return }
        scope.processMonitor.setEventHandler {}
        scope.processMonitor.cancel()
        try? await scope.listener.stop()
    }

    public func shutdown() async throws {
        guard !isShutdown else { return }
        isShutdown = true
        let current = scopes
        scopes.removeAll()
        for scope in current.values {
            scope.processMonitor.setEventHandler {}
            scope.processMonitor.cancel()
            try? await scope.listener.stop()
        }
        try await group.shutdownGracefully()
    }

    private func prepareSocketDirectory() throws {
        try FileManager.default.createDirectory(at: socketDirectory, withIntermediateDirectories: true)
        let attributes = try FileManager.default.attributesOfItem(atPath: socketDirectory.path)
        guard attributes[.type] as? FileAttributeType == .typeDirectory,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else {
            throw EngineError(.unauthorized, "resource scope directory is not owned by the current user")
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: socketDirectory.path)
    }
}

private final class ScopedDockerListener: @unchecked Sendable {
    private let group: MultiThreadedEventLoopGroup
    private let socketPath: String
    private let router: DockerRouter
    private let lock = NSLock()
    private var channel: Channel?
    private var children: [ObjectIdentifier: Channel] = [:]

    init(group: MultiThreadedEventLoopGroup, socketPath: String, router: DockerRouter) {
        self.group = group
        self.socketPath = socketPath
        self.router = router
    }

    func start() async throws {
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .childChannelInitializer { [router, weak self] channel in
                self?.track(channel)
                let upgrader = DockerTCPUpgrader(router: router)
                let upgrade: NIOHTTPServerUpgradeSendableConfiguration = (
                    upgraders: [upgrader],
                    completionHandler: { _ in }
                )
                return channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: upgrade).flatMap {
                    channel.pipeline.addHandler(DockerHTTPHandler(router: router), name: "docker-http")
                }
            }
        channel = try await bootstrap.bind(unixDomainSocketPath: socketPath).get()
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: socketPath)
    }

    func stop() async throws {
        let listener = lock.withLock { () -> Channel? in
            defer { channel = nil }
            return channel
        }
        if let listener, listener.isActive { try? await listener.close().get() }
        let active = lock.withLock { Array(children.values) }
        for child in active where child.isActive { try? await child.close().get() }
        lock.withLock { children.removeAll() }
        try? FileManager.default.removeItem(atPath: socketPath)
    }

    private func track(_ child: Channel) {
        let id = ObjectIdentifier(child as AnyObject)
        lock.withLock { children[id] = child }
        child.closeFuture.whenComplete { [weak self] _ in
            self?.lock.withLock { self?.children.removeValue(forKey: id) }
        }
    }
}
