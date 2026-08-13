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
        let owner: ProcessIdentity
        let listener: ScopedDockerListener
        let processMonitor: DispatchSourceProcess
        let createdAt: ContinuousClock.Instant
    }

    private static let maximumScopes = 64
    private static let maximumScopesPerUID = 32
    private static let maximumScopesPerOwner = 8
    private static let idleLifetime: Duration = .seconds(30 * 60)
    private static let maximumLifetime: Duration = .seconds(24 * 60 * 60)

    private let runtime: EngineRuntime
    private let root: URL
    private let socketDirectory: URL
    private let admission: APIAdmissionController
    private let group = MultiThreadedEventLoopGroup(
        numberOfThreads: max(2, System.coreCount / 2)
    )
    private let monitorQueue = DispatchQueue(label: "dev.cengine.resource-scopes")
    private var scopes: [String: Scope] = [:]
    private var reaperTask: Task<Void, Never>?
    private var isShutdown = false

    public init(
        runtime: EngineRuntime,
        root: URL,
        socketDirectory: URL = URL(
            filePath: "/tmp/cengine-\(getuid())-scopes",
            directoryHint: .isDirectory
        ),
        admission: APIAdmissionController = APIAdmissionController()
    ) {
        self.runtime = runtime
        self.root = root
        self.socketDirectory = socketDirectory
        self.admission = admission
    }

    public func create(
        owner: ProcessIdentity,
        resources: ContainerResourceOverride
    ) async throws -> ContainerResourceScope {
        guard !isShutdown else {
            throw EngineError(.conflict, "container resource scopes are shutting down")
        }
        try resources.validate()
        startReaperIfNeeded()
        guard owner.effectiveUserIdentifier == geteuid() else {
            throw EngineError(.forbidden, "resource scope owner UID is not authorized")
        }
        try owner.revalidate()
        try enforceScopeLimits(owner: owner)
        try prepareSocketDirectory()

        let id = UUID().uuidString.lowercased()
        let socket = socketDirectory.appending(
            path: "\(getpid())-\(id.prefix(12)).sock",
            directoryHint: .notDirectory
        )
        let router = DockerRouter(
            runtime: runtime,
            root: root,
            containerResourceOverride: resources
        )
        let listener = ScopedDockerListener(
            group: group,
            socketPath: socket.path,
            router: router,
            admission: admission,
            owner: owner
        )
        do {
            try owner.revalidate()
            try await listener.start()
            try owner.revalidate()
        } catch {
            try? await listener.stop()
            throw error
        }

        let monitor = DispatchSource.makeProcessSource(
            identifier: owner.processIdentifier,
            eventMask: .exit,
            queue: monitorQueue
        )
        monitor.setEventHandler { [weak self] in
            Task { await self?.remove(id) }
        }
        scopes[id] = Scope(
            owner: owner,
            listener: listener,
            processMonitor: monitor,
            createdAt: ContinuousClock.now
        )
        monitor.resume()
        do {
            try owner.revalidate()
        } catch {
            await remove(id)
            throw error
        }
        return ContainerResourceScope(id: id, dockerHost: "unix://\(socket.path)")
    }

    /// In-process compatibility helper. Remote ownership is always derived from
    /// the accepted Unix peer and never from this PID-only interface.
    public func create(
        ownerPID: Int32,
        resources: ContainerResourceOverride
    ) async throws -> ContainerResourceScope {
        try await create(
            owner: ProcessIdentity.read(processIdentifier: ownerPID),
            resources: resources
        )
    }

    public func remove(
        _ id: String,
        requestedBy requester: ProcessIdentity
    ) async throws {
        guard let scope = scopes[id] else { return }
        guard requester.processIdentifier == scope.owner.processIdentifier,
              requester.startTimeMicroseconds == scope.owner.startTimeMicroseconds,
              requester.effectiveUserIdentifier == scope.owner.effectiveUserIdentifier else {
            throw EngineError(.forbidden, "resource scope is owned by another process")
        }
        await remove(id)
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
        reaperTask?.cancel()
        reaperTask = nil
        let current = scopes
        scopes.removeAll()
        for scope in current.values {
            scope.processMonitor.setEventHandler {}
            scope.processMonitor.cancel()
            try? await scope.listener.stop()
        }
        try await group.shutdownGracefully()
    }

    private func startReaperIfNeeded() {
        guard reaperTask == nil else { return }
        reaperTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                guard !Task.isCancelled else { return }
                await self?.reapExpiredScopes()
            }
        }
    }

    private func reapExpiredScopes() async {
        let now = ContinuousClock.now
        let expired = scopes.compactMap { id, scope -> String? in
            if now - scope.createdAt >= Self.maximumLifetime { return id }
            if scope.listener.isIdle(for: Self.idleLifetime, now: now) { return id }
            return nil
        }
        for id in expired { await remove(id) }
    }

    private func enforceScopeLimits(owner: ProcessIdentity) throws {
        guard scopes.count < Self.maximumScopes else {
            throw EngineError(.tooManyRequests, "global resource scope limit reached")
        }
        let uidCount = scopes.values.filter {
            $0.owner.effectiveUserIdentifier == owner.effectiveUserIdentifier
        }.count
        guard uidCount < Self.maximumScopesPerUID else {
            throw EngineError(.tooManyRequests, "resource scope UID limit reached")
        }
        let ownerCount = scopes.values.filter {
            $0.owner.processIdentifier == owner.processIdentifier
                && $0.owner.startTimeMicroseconds == owner.startTimeMicroseconds
        }.count
        guard ownerCount < Self.maximumScopesPerOwner else {
            throw EngineError(.tooManyRequests, "resource scope owner limit reached")
        }
    }

    private func prepareSocketDirectory() throws {
        if mkdir(socketDirectory.path, mode_t(0o700)) != 0, errno != EEXIST {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var information = stat()
        guard Darwin.lstat(socketDirectory.path, &information) == 0,
              information.st_mode & S_IFMT == S_IFDIR,
              information.st_uid == geteuid(),
              information.st_mode & mode_t(0o777) == mode_t(0o700) else {
            throw EngineError(
                .forbidden,
                "resource scope directory must be an owner-only real directory"
            )
        }
    }
}

private final class ScopedDockerListener: @unchecked Sendable {
    private static let maximumChildren = 32

    private let group: MultiThreadedEventLoopGroup
    private let socketPath: String
    private let router: DockerRouter
    private let admission: APIAdmissionController
    private let owner: ProcessIdentity
    private let lock = NSLock()
    private var channel: Channel?
    private var socketIdentity: (device: dev_t, inode: ino_t)?
    private var children: [ObjectIdentifier: Channel] = [:]
    private var lastActivity = ContinuousClock.now

    init(
        group: MultiThreadedEventLoopGroup,
        socketPath: String,
        router: DockerRouter,
        admission: APIAdmissionController,
        owner: ProcessIdentity
    ) {
        self.group = group
        self.socketPath = socketPath
        self.router = router
        self.admission = admission
        self.owner = owner
    }

    func start() async throws {
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 32)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .childChannelInitializer {
                [router, admission, owner, weak self] channel in
                guard self?.track(channel) == true else {
                    return channel.close()
                }
                return configureAdmittedDockerHTTPPipeline(
                    channel: channel,
                    router: router,
                    admission: admission,
                    authorizePeer: { peer in
                        guard peer.process.isOwnerOrDescendant(of: owner) else {
                            throw EngineError(
                                .forbidden,
                                "scoped Docker socket requires the owner or a proven descendant"
                            )
                        }
                    }
                )
            }
        channel = try await bootstrap.bind(unixDomainSocketPath: socketPath).get()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: socketPath
        )
        var information = stat()
        guard Darwin.lstat(socketPath, &information) == 0,
              information.st_mode & S_IFMT == S_IFSOCK,
              information.st_uid == geteuid(),
              information.st_mode & mode_t(0o777) == mode_t(0o600) else {
            try? await stop()
            throw EngineError(.forbidden, "resource scope socket publication is unsafe")
        }
        lock.withLock {
            socketIdentity = (information.st_dev, information.st_ino)
        }
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
        let identity = lock.withLock { () -> (device: dev_t, inode: ino_t)? in
            defer { socketIdentity = nil }
            return socketIdentity
        }
        if let identity {
            var information = stat()
            if Darwin.lstat(socketPath, &information) == 0,
               information.st_mode & S_IFMT == S_IFSOCK,
               information.st_dev == identity.device,
               information.st_ino == identity.inode {
                _ = Darwin.unlink(socketPath)
            }
        }
    }

    func isIdle(
        for duration: Duration,
        now: ContinuousClock.Instant
    ) -> Bool {
        lock.withLock {
            children.isEmpty && now - lastActivity >= duration
        }
    }

    private func track(_ child: Channel) -> Bool {
        let id = ObjectIdentifier(child as AnyObject)
        let admitted = lock.withLock { () -> Bool in
            guard children.count < Self.maximumChildren else { return false }
            children[id] = child
            lastActivity = .now
            return true
        }
        guard admitted else { return false }
        child.closeFuture.whenComplete { [weak self] _ in
            self?.lock.withLock {
                self?.children.removeValue(forKey: id)
                self?.lastActivity = .now
            }
        }
        return true
    }
}
