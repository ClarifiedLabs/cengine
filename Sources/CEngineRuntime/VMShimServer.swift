#if os(macOS)
import CEngineCore
import CryptoKit
import Darwin
import Foundation

enum VMShimAttachmentBoundary: Equatable, Sendable {
    case rootDiskOpened
    case volumeDiskOpened(String)
    case bindShareOpened(String)
}

typealias VMShimAttachmentHook = (VMShimAttachmentBoundary) throws -> Void

struct VMShimHeldDisk: Sendable {
    let ordinal: Int
    let role: String
    let volumeName: String?
    let parent: PersistentStateDirectory
    let name: String
    let handle: FileHandle
    let identity: PersistentFileIdentity
    let bytes: UInt64

    var blockIdentifier: String { ordinal == 0 ? "root" : "volume\(ordinal - 1)" }
}

struct VMShimAttachmentResources: Sendable {
    let disks: [VMShimHeldDisk]
    let rootDisk: URL
    let additionalDisks: [RawVirtualMachineConfiguration.BlockDisk]
    let bindShares: [RawVirtualMachineConfiguration.BindShare]
    let retainedHandles: [FileHandle]
}

/// Resolves mutable attachment paths once, through no-follow descriptors, and
/// converts them to `/dev/fd` URLs while retaining every descriptor for the VM
/// lifetime. Later path replacement therefore cannot change what VZ opens.
/// Disk flock leases live on those same descriptors: never unlock separately
/// from VM attachment teardown. This only excludes cooperating shims; upgrades
/// from older shims require all old VMs to be quiescent first. It is not a drain
/// or host-quarantine proof, nor protection against non-cooperating writers.
enum VMShimAttachmentResolver {
    static func resolve(
        _ specification: VMShimProtocol.Specification,
        inheritedStorageDisk: FileHandle? = nil,
        hook: VMShimAttachmentHook? = nil
    ) throws -> VMShimAttachmentResources {
        let root: OpenedRegularFile
        if let inheritedStorageDisk {
            root = try adoptStorageDisk(inheritedStorageDisk, specification: specification)
        } else {
            root = try openRegularFile(
                path: specification.rootDiskPath,
                expected: specification.rootDiskIdentity,
                expectedSize: specification.rootDiskSize,
                identityRequired: true,
                readOnly: specification.rootDiskReadOnly
            )
        }
        try hook?(.rootDiskOpened)
        try root.validate()

        guard let rootBytes = specification.rootDiskSize,
              specification.volumeDisks.count <= 25,
              specification.kind == .container || specification.volumeDisks.isEmpty else {
            throw EngineError(.conflict, "invalid disk bootstrap attachment set")
        }
        var heldDisks = [VMShimHeldDisk(
            ordinal: 0, role: specification.kind == .container ? "container-root" : "storage-root",
            volumeName: nil, parent: root.parent, name: root.name, handle: root.handle,
            identity: root.identity, bytes: rootBytes
        )]
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
                identityRequired: specification.kind == .container,
                readOnly: false
            )
            try hook?(.volumeDiskOpened(disk.name))
            try opened.validate()
            guard let bytes = disk.size else { throw EngineError(.conflict, "disk size absent") }
            heldDisks.append(VMShimHeldDisk(
                ordinal: index + 1, role: "direct-volume", volumeName: disk.name,
                parent: opened.parent, name: opened.name, handle: opened.handle,
                identity: opened.identity, bytes: bytes
            ))
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
                guard expected.volumeUUID != nil,
                      directory.identity == .persistedIdentity(expected) else {
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
                && PersistentFileIdentity(
                    stableInformation, volumeUUID: directory.identity.volumeUUID
                ) == directory.identity
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
            disks: heldDisks,
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
                  PersistentFileIdentity(
                      information, volumeUUID: identity.volumeUUID
                  ) == identity,
                  information.st_size >= 0,
                  expectedSize == nil || UInt64(information.st_size) == expectedSize else {
                throw EngineError(.conflict, "container VM root disk path changed")
            }
        }
    }

    /// Prove the transferred description already owns an exclusive lease: an
    /// independent shared lock must fail, while reaffirming EX on this same
    /// description succeeds. Never LOCK_UN or open a replacement writer.
    private static func adoptStorageDisk(
        _ handle: FileHandle, specification: VMShimProtocol.Specification
    ) throws -> OpenedRegularFile {
        guard specification.kind == .storage, !specification.rootDiskReadOnly,
              specification.volumeDisks.isEmpty, specification.bindShares.isEmpty,
              let expected = specification.rootDiskIdentity, expected.volumeUUID != nil,
              let bytes = specification.rootDiskSize else {
            throw EngineError(.conflict, "invalid inherited storage disk attachment")
        }
        let descriptor = handle.fileDescriptor
        let flags = Darwin.fcntl(descriptor, F_GETFL)
        guard descriptor > STDERR_FILENO, flags >= 0, flags & O_ACCMODE == O_RDWR,
              Darwin.fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
            throw EngineError(.conflict, "invalid inherited storage disk descriptor")
        }
        let identity = try PersistentFileIdentity.capture(descriptor: descriptor)
        guard identity == .persistedIdentity(expected) else {
            throw EngineError(.conflict, "inherited storage disk identity changed")
        }
        let url = URL(filePath: specification.rootDiskPath).standardizedFileURL
        let parent = try PersistentStateDirectory.open(url.deletingLastPathComponent())
        let result = OpenedRegularFile(parent: parent, name: url.lastPathComponent,
            handle: handle, identity: identity, expectedSize: bytes)
        try result.validate()
        var filesystem = statfs()
        guard Darwin.fstatfs(descriptor, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw EngineError(.conflict, "inherited storage disk requires local filesystem locking")
        }
        let probe = try parent.openRegularFile(named: url.lastPathComponent,
            expectedIdentity: identity, access: .readOnly)
        let probeResult = flock(probe.handle.fileDescriptor, LOCK_SH | LOCK_NB)
        let probeError = errno
        guard probeResult == -1, probeError == EWOULDBLOCK,
              flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            throw EngineError(.conflict, "inherited storage disk has no exclusive writer lease")
        }
        return result
    }

    private static func openRegularFile(
        path: String,
        expected: VMShimProtocol.FileIdentity?,
        expectedSize: UInt64?,
        identityRequired: Bool,
        readOnly: Bool
    ) throws -> OpenedRegularFile {
        guard !identityRequired || expected != nil && expectedSize != nil else {
            throw EngineError(.conflict, "VM disk has no durable identity or size")
        }
        let url = URL(filePath: path).standardizedFileURL
        let parent = try PersistentStateDirectory.open(url.deletingLastPathComponent())
        let opened = try parent.openRegularFile(
            named: url.lastPathComponent,
            access: readOnly ? .readOnly : .readWrite
        )
        if let expected {
            guard expected.volumeUUID != nil,
                  opened.identity == .persistedIdentity(expected) else {
                throw EngineError(.conflict, "VM disk identity changed")
            }
        }
        let result = OpenedRegularFile(
            parent: parent,
            name: url.lastPathComponent,
            handle: opened.handle,
            identity: opened.identity,
            expectedSize: expectedSize
        )
        try result.validate()
        // Lock the validated disk inode, not a pathname-sidecar. NB also makes
        // duplicate attachments in one specification fail rather than deadlock.
        // Persistent identity alone does not establish local flock semantics.
        var filesystem = statfs()
        guard Darwin.fstatfs(opened.handle.fileDescriptor, &filesystem) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw EngineError(.conflict, "VM disk requires local filesystem locking")
        }
        // Unsupported flock implementations fail closed, before any hook/VZ.
        guard flock(
            opened.handle.fileDescriptor, (readOnly ? LOCK_SH : LOCK_EX) | LOCK_NB
        ) == 0 else {
            let code = errno
            throw EngineError(
                .conflict,
                "VM disk lock unavailable for \(path): \(String(cString: strerror(code)))"
            )
        }
        return result
    }

    private static func descriptorURL(_ handle: FileHandle) -> URL {
        URL(filePath: "/dev/fd/\(handle.fileDescriptor)")
    }

    private static func volumeURL(_ identity: PersistentFileIdentity) -> URL {
        URL(filePath: "/.vol/\(identity.device)/\(identity.inode)")
    }
}

/// Executable-only completion for a failed initializer or a private stop whose
/// matching reply channel has ended. Object construction never
/// installs a process exit action. Reentrant terminal callbacks may return while
/// another stop owns teardown, so decide here, after the shared stop has joined.
@MainActor final class VMShimInitializerExit {
    var onExit: (@MainActor (Int32) -> Void)?
    var tokenStopRequested = false
    private var exited = false

    func joinStop(_ stop: @MainActor () async throws -> Void,
                  eligible: @MainActor () -> Bool,
                  machineRetained: @MainActor () -> Bool,
                  exitStatus: @MainActor () -> Int32 = { EXIT_FAILURE }) async throws {
        try await stop()
        guard !exited, !tokenStopRequested, eligible(), !machineRetained(), let onExit else { return }
        exited = true // Publish before invoking even a reentrant test callback.
        onExit(exitStatus())
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
    // Retain through all preboot/failure states, until this storage shim exits.
    private var inheritedStorageDisk: FileHandle?
    // Lifecycle-v2 hosting: inherited authenticated parent channel (FD4) and the
    // ONE owner/server bound to `machineOwner`'s machine. Retained until exit.
    private var lifecycleParent: FileHandle?
    private var lifecycleHost: (owner: RawStorageLifecycleShim, server: StorageLifecycleShimServer?)?
    private let lifecycleHosting = VMShimLifecycleHosting<RawContainerVirtualMachine>()
    private let lifecycleInitializerExit = VMShimInitializerExit()
    private var runtimeArtifactPublication: VMShimClient.PersistentRuntimeArtifactPublication?
    private var earlyPrepareObserver: PrivatePrepareObservation?
    private let machineOwner = VMShimMachineOwner<RawContainerVirtualMachine>()
    private var machine: RawContainerVirtualMachine? {
        get { machineOwner.machine }
        set { machineOwner.machine = newValue }
    }
    private let bootGate = VMShimBootGate()
    private let originalConsumerLease = OriginalConsumerObservationLease()
    private var originalConsumerBinding: OriginalConsumerObservationProtocol.Binding?
    private var originalConsumerTransport: VMShimManagedTransport?
    private var originalConsumerTask: Task<Data, Error>?
    private var originalConsumerTeardownTask: Task<Data?, Error>?
    private var originalConsumerEvidence: OriginalConsumerObservationProtocol.Evidence?
    private var originalConsumerExpiry: Task<Void, Never>?
    private var observationStopInProgress = false
    private var workloadConfigurationAttempted = false
    private var managedRootPreparationInFlight = false
    private var outputSpooler: VMShimOutputSpooler?
    private var state: VMShimProtocol.State = .created
    private var exitCode: Int32?
    private var failure: String?
    private var listener: Int32 = -1
    private var statusDescriptor: Int32 = -1
    private var serviceRelays: [UUID: BidirectionalDescriptorRelay] = [:]
    private var hostSocketRelays: [UnixVirtioSocketRelay] = []
    private let fabric: TrunkNetworkFabric
    private let startUplink: @MainActor (VMShimClient.FabricNetwork, String) async throws -> any VMShimUplink
    private var fabricConfiguration: Task<Void, Error>?
    private var fabricConfigurationGeneration: UUID?
    private var networkListener: Int32 = -1
    private var networkBridge: NetworkStreamBridge?
    private var networkBridges: [String: NetworkBridgeRegistration] = [:]
    private var activeVLANs: [UInt16]
    private var uplinks: [String: any VMShimUplink] = [:]
    private var uplinkRecoveries: [String: UplinkRecovery] = [:]
    private var desiredFabricNetworks: [String: VMShimClient.FabricNetwork] = [:]
    private(set) var fabricNetworks: [String: VMShimClient.FabricNetwork] = [:]

    public convenience init(
        specification: VMShimProtocol.Specification,
        launchIntentURL: URL? = nil
    ) {
        self.init(
            specification: specification,
            launchIntentURL: launchIntentURL,
            startUplink: { try await VMNetUplink.start(network: $0, namespace: $1) }
        )
    }

    init(
        specification: VMShimProtocol.Specification,
        launchIntentURL: URL? = nil,
        fabric: TrunkNetworkFabric = TrunkNetworkFabric(),
        startUplink: @escaping @MainActor (VMShimClient.FabricNetwork, String) async throws -> any VMShimUplink
    ) {
        self.specification = specification
        self.launchIntentURL = launchIntentURL
        self.fabric = fabric
        self.startUplink = startUplink
        activeVLANs = specification.vlans
    }

    public static func run(
        specificationURL: URL,
        launchIntentURL: URL? = nil,
        expectedSpecificationSHA256: String? = nil,
        storageDiskDescriptor: Int32? = nil,
        storageLifecycleDescriptor: Int32? = nil
    ) async throws -> Never {
        let inheritedStorageDisk: FileHandle?
        if let storageDiskDescriptor {
            guard storageDiskDescriptor == VMShimClient.storageDiskDescriptor,
                  fcntl(storageDiskDescriptor, F_SETFD, FD_CLOEXEC) == 0 else {
                throw EngineError(.conflict, "invalid inherited storage disk descriptor")
            }
            inheritedStorageDisk = FileHandle(fileDescriptor: storageDiskDescriptor, closeOnDealloc: true)
        } else {
            inheritedStorageDisk = nil
        }
        let specification = try launchSpecification(
            specificationURL: specificationURL,
            launchIntentURL: launchIntentURL,
            expectedSpecificationSHA256: expectedSpecificationSHA256,
            inheritedStorageDisk: inheritedStorageDisk
        )
        let lifecycleParent = try Self.inheritLifecycleDescriptor(storageLifecycleDescriptor, specification: specification)
        let server = VMShimServer(
            specification: specification, launchIntentURL: launchIntentURL
        )
        server.inheritedStorageDisk = inheritedStorageDisk
        server.lifecycleParent = lifecycleParent
        // No artifact cleanup: failed initialization diagnostics and format state
        // survive. Process exit releases remaining resources only after safe stop.
        server.lifecycleInitializerExit.onExit = { Darwin.exit($0) }
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
        if let lifecycleParent { server.startLifecycleHosting(parent: lifecycleParent) }
        await withUnsafeContinuation { (_: UnsafeContinuation<Void, Never>) in }
        fatalError("VM shim listener returned")
    }

    static func launchSpecification(
        specificationURL: URL,
        launchIntentURL: URL?,
        expectedSpecificationSHA256: String? = nil,
        inheritedStorageDisk: FileHandle? = nil,
        publish: (URL) throws -> VMShimClient.PersistentLaunchRecord = {
            try VMShimClient.publishPersistentLaunchIdentity(intentURL: $0)
        }
    ) throws -> VMShimProtocol.Specification {
        guard let launchIntentURL else {
            guard let expectedSpecificationSHA256 else {
                throw EngineError(.conflict, "unpinned VM shim specification")
            }
            let parent = try PersistentStateDirectory.open(specificationURL.deletingLastPathComponent())
            guard let data = try parent.readRegularFile(named: specificationURL.lastPathComponent) else {
                throw EngineError(.conflict, "missing VM shim specification")
            }
            guard SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == expectedSpecificationSHA256 else {
                throw EngineError(.conflict, "VM shim specification digest changed")
            }
            let specification = try JSONDecoder().decode(VMShimProtocol.Specification.self, from: data)
            if specification.kind == .storage {
                guard let inheritedStorageDisk else {
                    throw EngineError(.conflict, "storage shim requires an inherited disk writer lease")
                }
                return try RawStorageShimRecovery.publishLaunch(specificationURL: specificationURL,
                    data: data, diskHandle: inheritedStorageDisk)
            }
            guard inheritedStorageDisk == nil else {
                throw EngineError(.conflict, "only storage shims may inherit a disk writer lease")
            }
            return specification
        }
        guard inheritedStorageDisk == nil else {
            throw EngineError(.conflict, "storage disk transfer cannot use a container launch intent")
        }
        // The immutable publication is the single source of launch truth.
        // Re-reading the lexical spec path here would allow a replacement
        // between ownership validation and VM construction.
        let record = try publish(launchIntentURL)
        guard record.specification.kind != .storage,
              VMShimClient.launchPathsMatch(
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

    private nonisolated let managedAdmission = VMShimManagedAdmission()

    private func activateListener() {
        let descriptor = listener
        // Admission bounds only the initial frame for managed workloads. It
        // does not impose a lifetime deadline on an ordinary workload command.
        let managed = Self.requiresBoundedInitialFrame(specification)
        let admission = managedAdmission
        Task.detached { [weak self] in
            while let self {
                do {
                    let client = try UnixSocket.accept(descriptor)
                    if managed {
                        let deadline = DispatchTime.now().uptimeNanoseconds + VMShimManagedTransport.maximumNanoseconds
                        guard let permit = admission.reserve(client, deadline: deadline) else { Darwin.close(client); continue }
                        Task { @MainActor in
                            defer { withExtendedLifetime(permit) {} }
                            guard let owned = permit.take() else { return }
                            await self.handle(owned, acceptedDeadline: deadline, initialPermit: permit)
                        }
                    } else { Task { @MainActor in await self.handle(client) } }
                } catch is UnixSocket.AcceptedPeerConfigurationError {
                    continue
                } catch { return }
            }
        }
    }

    private func handle(_ descriptor: Int32, acceptedDeadline suppliedDeadline: UInt64? = nil,
                        initialPermit: VMShimManagedAdmission.Permit? = nil) async {
        let boundedInitialFrame = Self.requiresBoundedInitialFrame(specification)
        let lifecycle = specification.kind == .storage
        let acceptedDeadline = suppliedDeadline ?? DispatchTime.now().uptimeNanoseconds + VMShimManagedTransport.maximumNanoseconds
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var request: VMShimProtocol.Envelope?
        var requestAuthenticated = false
        var responseStarted = false
        var hostDiagnostic: OriginalConsumerHostDiagnostic?
        do {
            let frame: Data
            if boundedInitialFrame {
                let maximum = lifecycle ? VMShimManagedTransport.maximumInitialStorageRequestFrameSize : VMShimProtocol.maximumFrameSize
                frame = try await Self.managedSocketIO(descriptor, deadline: acceptedDeadline) {
                    if lifecycle {
                        return try StorageLifecycleShimChannel.receiveInitialRoute(fd: $0.ownedDescriptor(),
                            maximum: maximum, deadline: DispatchTime(uptimeNanoseconds: acceptedDeadline))
                    }
                    return try Self.readInitialManagedRequestFrame(using: $0, maximum: maximum)
                }
                if lifecycle && frame == StorageLifecycleShimProtocol.adoptionPreface {
                    // No token parse, token-bearing error, or ordinary fallback.
                    try? await attachLifecycleControl(descriptor, deadline: DispatchTime(uptimeNanoseconds: acceptedDeadline))
                    return
                }
                if !lifecycle { initialPermit?.finishInitialFrame() }
            } else { frame = try readFrame(file) }
            var decoded = try VMShimProtocol.decode(frame)
            if lifecycle { decoded.deadlineNanoseconds = min(acceptedDeadline, decoded.deadlineNanoseconds ?? acceptedDeadline) }
            request = decoded
            guard decoded.token == specification.token else { throw EngineError(.unauthorized, "invalid VM shim token") }
            requestAuthenticated = true
            if decoded.operation == .originalConsumerObservation {
                hostDiagnostic = OriginalConsumerHostDiagnostic(
                    enabled: OriginalConsumerHostDiagnostic.enabled(originalConsumerBinding), stage: .shimDispatchAdmission)
            }
            try requireOrdinaryAdmission(decoded.operation)
            try Self.requireLifecycleHostingAdmission(decoded.operation, specification: specification,
                enrolled: lifecycleHost?.owner.controlLifetime.isEnrolled == true)
            if decoded.operation == .stop || decoded.operation == .shutdown {
                // Serialize unenrolled stop admission against enrollment: a late
                // native completion cannot persist a machine already stopping.
                if let control = lifecycleHost?.owner.controlLifetime {
                    try control.reserveTokenStop()
                }
                lifecycleInitializerExit.tokenStopRequested = true
            }
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
            let ownsStopResponse = decoded.operation == .stop || decoded.operation == .shutdown
            if ownsStopResponse { bootGate.beginStopResponse(shutdown: decoded.operation == .shutdown) }
            defer { if ownsStopResponse { bootGate.endStopResponse() } }
            hostDiagnostic?.stage = .shimDispatch
            let payload = try await perform(decoded)
            hostDiagnostic?.stage = .shimReplyAdmission
            try requireOrdinaryAdmission(decoded.operation)
            hostDiagnostic?.stage = .shimReplyEncode
            let response = try VMShimProtocol.encode(.init(id: decoded.id, token: specification.token, operation: decoded.operation, payload: payload))
            hostDiagnostic?.stage = .shimReplyTransport
            if let replyDeadline = Self.replyAcknowledgementDeadline(specification,
                acceptedDeadline: acceptedDeadline, requestDeadline: decoded.deadlineNanoseconds) {
                responseStarted = true
                let completedShutdown = decoded.operation == .shutdown
                do {
                    let diagnostic = hostDiagnostic
                    _ = try await Self.managedSocketIO(descriptor, deadline: replyDeadline) {
                        try Self.writeManagedReply(response, using: $0, completedShutdown: completedShutdown, hostDiagnostic: diagnostic); return Data()
                    }
                } catch {
                    // Include transport setup/expired-deadline failures before
                    // the writer starts in the completed-shutdown guarantee.
                    guard completedShutdown else { throw error }
                }
            } else { try file.write(contentsOf: response) }
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
            hostDiagnostic?.report(error)
            if requestAuthenticated, request?.operation == .originalConsumerObservation, originalConsumerBinding != nil {
                let observerError = error
                do { try await arbitrateObservationStop(.forced, message: "original consumer reply failed") }
                catch {
                    failure = OriginalConsumerContainmentFailure(observation: observerError, containment: error).localizedDescription
                    try? persist()
                }
            }
            // A missing/invalid/late acknowledgement must only close this owned
            // session, never append a second response or replay the operation.
            guard !responseStarted else { return }
            // Pre-authentication failures must not create ack waiters (workload
            // admission is deliberately unbounded), or return a private token.
            if Self.silentlyClosesUnauthenticatedFailure(specification, authenticated: requestAuthenticated) { return }
            let code: String
            if error is BackendResourceRollbackIncompleteError {
                code = GuestProtocol.resourceRollbackIncompleteErrorCode
            } else if let engineError = error as? EngineError,
                      case .badRequest = engineError.code {
                code = GuestProtocol.badRequestErrorCode
            } else {
                code = "shim_error"
            }
            let nsError = error as NSError
            let failure = GuestProtocol.Failure(
                code: code,
                message: "\(error.localizedDescription) [\(nsError.domain) \(nsError.code)]"
            )
            if let response = try? VMShimProtocol.encode(VMShimProtocol.Envelope(
                id: request?.id ?? UUID().uuidString, token: specification.token,
                operation: request?.operation ?? .status, error: failure)) {
                if let replyDeadline = Self.replyAcknowledgementDeadline(specification,
                    acceptedDeadline: acceptedDeadline, requestDeadline: request?.deadlineNanoseconds,
                    requestAuthenticated: requestAuthenticated) {
                    _ = try? await Self.managedSocketIO(descriptor, deadline: replyDeadline) {
                        try Self.writeManagedReply(response, using: $0); return Data()
                    }
                } else { try? file.write(contentsOf: response) }
            }
        }
    }

    nonisolated private static func prepareCompatibilityProfile(_ specification: VMShimProtocol.Specification) throws -> String? {
        struct Metadata: Decodable {
            let prepareCompatibilityProfile: String?
            let prepareCompatibilitySourceSHA256: String?
            let containerInitramfsSHA256: String
        }
        let directory = try PersistentStateDirectory.open(URL(filePath: specification.kernelPath).deletingLastPathComponent())
        guard let data = try directory.readRegularFile(named: "disk-bootstrap.json") else { throw PrivateWorkloadStorageCoordinator.failure() }
        let metadata = try JSONDecoder().decode(Metadata.self, from: data)
        try ManagedPrepareCompatibilityProtocol.validateProfile(metadata.prepareCompatibilityProfile, sourceSHA256: metadata.prepareCompatibilitySourceSHA256)
        guard metadata.containerInitramfsSHA256 == specification.expectedInitramfsSHA256 else { throw PrivateWorkloadStorageCoordinator.failure() }
        return metadata.prepareCompatibilityProfile
    }

    nonisolated static func requiresBoundedInitialFrame(_ specification: VMShimProtocol.Specification) -> Bool {
        specification.kind == .storage
            || (specification.kind == .container && specification.workloadStorageMode == .managed)
    }

    nonisolated static func silentlyClosesUnauthenticatedFailure(_ specification: VMShimProtocol.Specification,
                                                                 authenticated: Bool) -> Bool {
        !authenticated && requiresBoundedInitialFrame(specification)
    }

    nonisolated static func readInitialManagedRequestFrame(using transport: VMShimManagedTransport,
        maximum: Int = VMShimManagedTransport.maximumInitialStorageRequestFrameSize) throws -> Data {
        try transport.readFrame(maximum: maximum)
    }

    nonisolated static func replyAcknowledgementDeadline(_ specification: VMShimProtocol.Specification,
        acceptedDeadline: UInt64, requestDeadline: UInt64?,
        nowNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds,
        requestAuthenticated: Bool = true) -> UInt64? {
        guard requestAuthenticated else { return nil }
        if specification.kind == .storage {
            return min(acceptedDeadline, requestDeadline ?? acceptedDeadline)
        }
        if specification.kind == .container, specification.workloadStorageMode == .managed {
            // Called only after the operation completes. Never turn an unbounded
            // workload wait into a bounded operation or renew a supplied budget.
            let replyLimit = nowNanoseconds + VMShimManagedTransport.maximumNanoseconds
            return min(requestDeadline ?? replyLimit, replyLimit)
        }
        return nil
    }

    nonisolated static let managedReplyAcknowledgement: UInt8 = 1

    nonisolated static func writeManagedReply(_ response: Data, using transport: VMShimManagedTransport,
                                              completedShutdown: Bool = false, hostDiagnostic: OriginalConsumerHostDiagnostic? = nil) throws {
        do {
            hostDiagnostic?.stage = .shimReplyWrite
            try transport.write(response)
            hostDiagnostic?.stage = .shimReplyAck
            // Darwin LOCAL_PEERPID returns ENOTCONN after the remote socket closes,
            // even while the process lives. Retain this exact session until the
            // client completes BOTH immutable process/specification proofs. The
            // caller's absolute reply deadline bounds this read; it is either
            // the existing operation budget or a post-operation-only window.
            guard try transport.readExactly(1) == Data([managedReplyAcknowledgement]) else {
                throw VMShimManagedTransport.failure()
            }
        } catch {
            // Only a successfully performed shutdown may continue cleanup/exit
            // after delivery/ack failure. Never strand its closed boot gate just
            // because the daemon disconnected; ordinary replies still fail.
            guard completedShutdown else { throw error }
        }
    }

    nonisolated static func managedSocketIO(_ descriptor: CInt, deadline: UInt64,
        operation: @escaping @Sendable (VMShimManagedTransport) throws -> Data) async throws -> Data {
        let transport = VMShimManagedTransport(deadlineNanoseconds: deadline)
        let owned = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard owned >= 0 else { throw POSIXError(.EIO) }
        do { try transport.adopt(owned) } catch { Darwin.close(owned); throw error }
        defer { transport.close() }
        let result = try await transport.run(operation)
        // The duplicate shares status flags with the original accepted socket.
        // Restore blocking before a successful request can upgrade to a relay.
        Darwin.close(try transport.takeDescriptor())
        return result
    }

    private static func managedDeadline(_ request: VMShimProtocol.Envelope) throws -> UInt64 {
        let now = DispatchTime.now().uptimeNanoseconds
        guard let deadline = request.deadlineNanoseconds, deadline > now else { throw VMShimManagedTransport.failure() }
        return min(deadline, now + VMShimManagedTransport.maximumNanoseconds)
    }

    nonisolated static func ownedSocketPaths(
        _ specification: VMShimProtocol.Specification
    ) -> [String] {
        var paths = [specification.socketPath]
        if specification.kind == .storage {
            paths.append(contentsOf: [specification.networkSocketPath].compactMap { $0 })
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
        if request.operation == .originalConsumerObservation {
            return try await originalConsumerObservation(request)
        }
        try requireOrdinaryAdmission(request.operation)
        switch request.operation {
        case .originalConsumerObservation: throw OriginalConsumerObservationProtocol.Failure.invalid
        case .status: return try JSONEncoder().encode(status())
        case .boot:
            guard specification.kind == .container, specification.workloadStorageMode == .none else {
                throw EngineError(.conflict, "managed storage requires its private boot configuration")
            }
            try await boot()
            return try JSONEncoder().encode(status())
        case .workloadStorageBoot:
            guard specification.kind == .container, specification.workloadStorageMode == .managed,
                  request.payload == nil else { throw PrivateWorkloadStorageCoordinator.failure() }
            try await boot()
            guard state == .running, !bootGate.isStopping, let machine else {
                throw PrivateWorkloadStorageCoordinator.failure()
            }
            return try JSONEncoder().encode(machine.workloadStorageReceipt())
        case .workloadStorageConfigure:
            guard specification.kind == .container, specification.workloadStorageMode == .managed,
                  state == .running, !bootGate.isStopping, let machine, let payload = request.payload,
                  !workloadConfigurationAttempted, !managedRootPreparationInFlight else {
                throw PrivateWorkloadStorageCoordinator.failure()
            }
            let configuration = try JSONDecoder().decode(WorkloadStorageConfiguration.self, from: payload)
            workloadConfigurationAttempted = true
            let receipt = try await machine.configureWorkloadStorage(configuration)
            try requireCurrentOperation(machine)
            if [ManagedPrepareCompatibilityProtocol.earlyProfile, ManagedPrepareCompatibilityProtocol.fullProfile].contains(receipt.hello.data.compatibilityProfile ?? "") {
                earlyPrepareObserver = machine.prepareObserver
            }
            return try JSONEncoder().encode(receipt)
        case .workloadStoragePrepareObservation:
            guard specification.kind == .container, specification.workloadStorageMode == .managed,
                  let payload = request.payload else { throw PrivateWorkloadStorageCoordinator.failure() }
            let arm = try ManagedPrepareCompatibilityProtocol.decode(ManagedPrepareCompatibilityProtocol.Arm.self, from: payload)
            try ManagedPrepareCompatibilityProtocol.validate(arm)
            if [ManagedPrepareCompatibilityProtocol.earlyProfile, ManagedPrepareCompatibilityProtocol.fullProfile].contains(arm.profile),
               (ManagedPrepareCompatibilityProtocol.isEarlyCase(arm.caseName)
                    || ManagedPrepareCompatibilityProtocol.ioCase(arm.caseName)?.workload == true) {
                guard let earlyPrepareObserver else { throw PrivateWorkloadStorageCoordinator.failure() }
                let frame = try await earlyPrepareObserver.observation(arm)
                try ManagedPrepareCompatibilityProtocol.validateObservation(frame, arm: arm)
                return Data(try WorkloadStorageProtocol.encode(frame).dropFirst(4))
            }
            guard state == .running, !bootGate.isStopping, let machine else { throw PrivateWorkloadStorageCoordinator.failure() }
            let frame = try await machine.prepareObservation(arm)
            try requireCurrentOperation(machine)
            return Data(try WorkloadStorageProtocol.encode(frame).dropFirst(4))
        case .workloadStorageStatus:
            guard specification.kind == .container, specification.workloadStorageMode == .managed,
                  state == .running, !bootGate.isStopping, let machine, let payload = request.payload,
                  let deadline = request.deadlineNanoseconds else {
                throw PrivateWorkloadStorageCoordinator.failure(stage: .statusGuard, kind: .status)
            }
            let scope = try JSONDecoder().decode(WorkloadStorageProtocol.Scope.self, from: payload)
            let reply = try await machine.observeRunningWorkloadStorage(expectedScope: scope,
                deadlineNanoseconds: deadline)
            try requireCurrentOperation(machine)
            guard state == .running else {
                throw PrivateWorkloadStorageCoordinator.failure(stage: .statusGuard, kind: .status)
            }
            return Data(try WorkloadStorageProtocol.encode(reply).dropFirst(4))
        case .workloadStorageCommand:
            guard specification.kind == .container, specification.workloadStorageMode == .managed,
                  state == .running, !bootGate.isStopping, let machine, let payload = request.payload else {
                throw PrivateWorkloadStorageCoordinator.failure()
            }
            let command = try WorkloadStorageProtocol.decode(from: payload)
            let reply = try await machine.workloadStorageCommand(command)
            try requireCurrentOperation(machine)
            return Data(try WorkloadStorageProtocol.encode(reply).dropFirst(4))
        case .guest:
            guard let payload = request.payload else { throw EngineError(.badRequest, "guest request has no payload") }
            let call = try JSONDecoder().decode(VMShimClient.GuestCall.self, from: payload)
            try Self.validateGenericWorkloadOperation(call.operation, specification: specification)
            guard state == .running, let machine else { throw EngineError(.conflict, "VM guest control is unavailable") }
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
            guard state == .running, !bootGate.isStopping, let payload = request.payload, let machine else { throw EngineError(.conflict, "VM is not booted") }
            if specification.workloadStorageMode == .managed {
                guard !workloadConfigurationAttempted, !managedRootPreparationInFlight,
                      machine.permitsManagedRootPreparation else { throw PrivateWorkloadStorageCoordinator.failure() }
                managedRootPreparationInFlight = true
            }
            defer { managedRootPreparationInFlight = false }
            let value = try JSONDecoder().decode(VMShimClient.RootFSRequest.self, from: payload)
            let store = try OCIContentStore(root: URL(filePath: value.contentStorePath))
            try await RootFSContentStreamer(store: store).prepare(machine: machine, layers: value.layers)
            try requireCurrentOperation(machine)
            return try JSONEncoder().encode(Empty())
        case .startExecStream, .startPortStream:
            throw EngineError(.internalError, "streams must be upgraded before dispatch")
        case .configureNetwork:
            struct Configuration: Decodable { let vlans: [UInt16] }
            guard let payload = request.payload else { throw EngineError(.badRequest, "network configuration has no payload") }
            let configuration = try JSONDecoder().decode(Configuration.self, from: payload)
            guard configuration.vlans.allSatisfy({ (1...4094).contains($0) }) else { throw EngineError(.badRequest, "invalid VLAN membership") }
            activeVLANs = Array(Set(configuration.vlans).union([VMShimProtocol.managementVLAN])).sorted()
            if state == .running, let machine {
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
            guard state == .running || state == .paused, let machine else { throw EngineError(.conflict, "VM is not booted") }
            try await machine.pause()
            try requireCurrentOperation(machine)
            state = .paused; try persist(); return try JSONEncoder().encode(status())
        case .resume:
            guard state == .running || state == .paused, let machine else { throw EngineError(.conflict, "VM is not booted") }
            do {
                try await machine.resume()
            } catch let error as BackendResourceRollbackIncompleteError {
                try requireCurrentOperation(machine)
                state = .failed
                failure = error.localizedDescription
                try? persist()
                throw error
            }
            try requireCurrentOperation(machine)
            state = .running; failure = nil; try persist(); return try JSONEncoder().encode(status())
        case .stop, .shutdown:
            try await stopBootAndMachine()
            return try JSONEncoder().encode(status())
        }
    }

    private func requireCurrentOperation(_ candidate: RawContainerVirtualMachine) throws {
        try machineOwner.requireCurrent(candidate, teardownInProgress: bootGate.isStopping)
        guard !candidate.workloadStorageIsTerminal, !observationStopInProgress else {
            throw PrivateWorkloadStorageCoordinator.failure()
        }
    }

    private func requireOrdinaryAdmission(_ operation: VMShimProtocol.Operation) throws {
        guard specification.workloadStorageMode == .managed,
              machine?.workloadStorageIsTerminal == true || observationStopInProgress else { return }
        guard [.status, .stop, .shutdown, .originalConsumerObservation].contains(operation)
                || earlyPrepareObserver?.permitsTerminalOperation(operation) == true else {
            throw PrivateWorkloadStorageCoordinator.failure()
        }
    }

    private func stopBootAndMachine() async throws {
        try await arbitrateObservationStop(.forced)
    }

    /// All three destructive paths enter here. Cancellation is joined before the
    /// existing boot gate, and no observer result substitutes for containment.
    private func arbitrateObservationStop(_ reason: OriginalConsumerObservationLease.Stop,
                                          message: String? = nil) async throws {
        if let message { state = .failed; failure = message; try? persist() }
        if let deadline = originalConsumerLease.stop(reason, now: DispatchTime.now().uptimeNanoseconds) {
            if originalConsumerExpiry == nil {
                originalConsumerExpiry = Task { @MainActor in
                    let now = DispatchTime.now().uptimeNanoseconds
                    if deadline > now { try? await Task.sleep(nanoseconds: deadline - now) }
                    guard !Task.isCancelled else { return }
                    try? await self.arbitrateObservationStop(.forced, message: self.failure)
                }
            }
            return
        }
        observationStopInProgress = true
        originalConsumerExpiry?.cancel(); originalConsumerExpiry = nil
        // Interrupt even a Release already owned by the retained teardown task.
        originalConsumerTransport?.cancel(); originalConsumerTask?.cancel()
        do { _ = try await joinOriginalConsumerTeardown() }
        catch { /* Observer failure cannot skip the existing positive VM stop. */ }
        try await lifecycleInitializerExit.joinStop({
            try await self.bootGate.stop(willStop: { self.state = .stopping }) {
                try await self.performStop()
                self.originalConsumerLease.releaseMachineIdentity()
                if let message { self.state = .failed; self.failure = message; try self.persist() }
            }
        }, eligible: {
            self.lifecycleHost?.owner.shouldExitAfterFreshAbort == true ||
                self.lifecycleHost?.owner.shouldExitAfterPrivateStop == true
        }, machineRetained: { self.machineOwner.machine != nil }, exitStatus: {
            self.lifecycleHost?.owner.shouldExitAfterPrivateStop == true ? EXIT_SUCCESS : EXIT_FAILURE
        })
    }

    /// The retained teardown task covers cancellation, the WHOLE exchange's
    /// post-IO checks/slot cleanup, and (for Release) its own guest IO. A forced
    /// stop can interrupt that exact Release without creating a second lane.
    private func joinOriginalConsumerTeardown(release: OriginalConsumerObservationProtocol.Request? = nil) async throws -> Data? {
        if let task = originalConsumerTeardownTask { return try await task.value }
        let task = Task<Data?, Error> { @MainActor in
            let active = self.originalConsumerTask
            self.originalConsumerTransport?.cancel()
            active?.cancel()
            if let active { _ = await active.result }
            guard let release else { return nil }
            guard !self.observationStopInProgress, let machine = self.machine,
                  self.originalConsumerLease.matchesMachine(machine),
                  self.machineOwner.isCurrent(machine) else { throw CancellationError() }
            let now = DispatchTime.now().uptimeNanoseconds
            let deadline = min(self.originalConsumerLease.deadline ?? now + 1_000_000_000, now + 1_000_000_000)
            return try await self.startOriginalConsumerExchange(release, machine: machine, deadline: deadline)
        }
        originalConsumerTeardownTask = task
        // Never cancel the retained teardown owner with an individual caller.
        defer { originalConsumerTeardownTask = nil }
        return try await task.value
    }

    private func originalConsumerObservation(_ envelope: VMShimProtocol.Envelope) async throws -> Data {
        do { return try await prepareOriginalConsumerExchange(envelope) }
        catch {
            let observationError = error
            // All post-Arm failures, INCLUDING decoding/validation/duplicate
            // requests before IO, consume the lease and contain the original VM.
            guard originalConsumerBinding != nil else { throw observationError }
            originalConsumerLease.cancel()
            do { try await arbitrateObservationStop(.forced, message: "original consumer observation failed") }
            catch { throw OriginalConsumerContainmentFailure(observation: observationError, containment: error) }
            throw observationError
        }
    }

    private func prepareOriginalConsumerExchange(_ envelope: VMShimProtocol.Envelope) async throws -> Data {
        let diagnostic = OriginalConsumerHostDiagnostic(enabled: OriginalConsumerHostDiagnostic.enabled(originalConsumerBinding), stage: .shimSignedIdentity)
        do {
            typealias Wire = OriginalConsumerObservationProtocol
            _ = try SignedCompatibilityIdentity.current(role: .engine)
            diagnostic.stage = .shimAdmission
            guard specification.kind == .container, specification.workloadStorageMode == .managed,
                  let payload = envelope.payload, let machine, !bootGate.isStopping,
                  !observationStopInProgress else { throw Wire.Failure.invalid }
            diagnostic.stage = .shimRequestDecode
            let request = try Wire.decodeRequest(payload)
            diagnostic.stage = .shimRequestValidation
            try Wire.validate(request)
            let binding = request.binding
            diagnostic.stage = .shimBinding
            guard binding.generation == specification.generation,
                  binding.boot.shimLaunchUUID == specification.shimLaunchUUID,
                  binding.scope.container == specification.containerID else { throw Wire.Failure.invalid }
            let now = DispatchTime.now().uptimeNanoseconds
            let deadline: UInt64
            diagnostic.stage = .shimLeaseAdmission
            if request.command == .resume {
                guard state == .running, binding == originalConsumerBinding,
                      originalConsumerTeardownTask == nil, originalConsumerTask == nil,
                      originalConsumerEvidence != nil else { throw Wire.Failure.invalid }
                try originalConsumerLease.requireResumable(binding.armDigest, machine: machine)
                // The existing VM owns the configured session, leaf and client.
                // Revalidate that exact original configuration, never reconfigure it.
                try machine.validateOriginalConsumer(binding)
                let resumeDeadline = min(now + 1_000_000_000, try Self.managedDeadline(envelope))
                let result = try await startOriginalConsumerExchange(request, machine: machine, deadline: resumeDeadline)
                // A successful Guest reply cannot revive a lease stopped during IO.
                try originalConsumerLease.requireResumable(binding.armDigest, machine: machine)
                try machine.validateOriginalConsumer(binding)
                return result
            }
            if request.command == .arm {
                guard state == .running, originalConsumerBinding == nil else { throw Wire.Failure.invalid }
                try machine.validateOriginalConsumer(binding)
                try originalConsumerLease.arm(binding.armDigest)
                originalConsumerBinding = binding
                try originalConsumerLease.bindMachine(machine)
                deadline = now + 1_000_000_000
            } else {
                guard binding == originalConsumerBinding, originalConsumerLease.matchesMachine(machine) else { throw Wire.Failure.invalid }
                if request.command == .release {
                    try originalConsumerLease.release(binding.armDigest)
                    diagnostic.stage = .shimReleaseTeardown
                    guard let result = try await joinOriginalConsumerTeardown(release: request) else { throw Wire.Failure.invalid }
                    originalConsumerExpiry?.cancel(); originalConsumerExpiry = nil
                    diagnostic.stage = .shimReleaseStop
                    if originalConsumerLease.pendingStop { try await arbitrateObservationStop(.forced, message: failure) }
                    return result
                }
                guard originalConsumerTeardownTask == nil else { throw Wire.Failure.invalid }
                if request.command == .begin {
                    try machine.validateOriginalConsumer(binding)
                    guard !originalConsumerLease.closed, originalConsumerLease.deadline == nil else { throw Wire.Failure.invalid }
                    deadline = now + 1_000_000_000
                } else {
                    diagnostic.stage = .shimLeaseDeadline
                    deadline = try originalConsumerLease.require(binding.armDigest, now: now)
                }
            }
            diagnostic.stage = .shimStartExchange
            return try await startOriginalConsumerExchange(request, machine: machine, deadline: deadline)
        } catch { diagnostic.report(error); throw error }
    }

    private func startOriginalConsumerExchange(_ request: OriginalConsumerObservationProtocol.Request,
        machine: RawContainerVirtualMachine, deadline: UInt64) async throws -> Data {
        let diagnostic = OriginalConsumerHostDiagnostic(enabled: OriginalConsumerHostDiagnostic.enabled(originalConsumerBinding), stage: .shimReserve)
        do {
            typealias Wire = OriginalConsumerObservationProtocol
            let binding = request.binding
            let id = try originalConsumerLease.reserveExchange()
            diagnostic.stage = .shimPreviousEvidence
            let previous = originalConsumerEvidence
            if request.command != .arm && request.command != .release && previous == nil {
                _ = originalConsumerLease.finishExchange(id)
                throw Wire.Failure.invalid
            }
            diagnostic.stage = .shimTransportSetup
            let transport = VMShimManagedTransport(deadlineNanoseconds: deadline)
            originalConsumerTransport = transport
            // This is the full exchange, not just its blocking FD worker. Teardown
            // joins validation, lease transitions AND identity-qualified cleanup.
            let task = Task { @MainActor in
                defer {
                    if self.originalConsumerLease.finishExchange(id) {
                        self.originalConsumerTask = nil; self.originalConsumerTransport = nil
                    }
                }
                do {
                    diagnostic.stage = .shimGuestConnectDeadline
                    let timeout = try Self.guestConnectTimeout(deadlineNanoseconds: deadline)
                    diagnostic.stage = .shimGuestConnect
                    let connection = try await machine.connect(toPort: GuestProtocol.controlPort, timeout: timeout)
                    defer { connection.close() }
                    diagnostic.stage = .shimConnectCancellation
                    try Task.checkCancellation()
                    diagnostic.stage = .shimConnectIdentity
                    guard self.machineOwner.isCurrent(machine), self.originalConsumerBinding == binding,
                          !self.observationStopInProgress else { throw Wire.Failure.invalid }
                    diagnostic.stage = .shimDuplicateFD
                    let fd = fcntl(connection.fileDescriptor, F_DUPFD_CLOEXEC, 0)
                    guard fd >= 0 else { throw POSIXError(.EIO) }
                    diagnostic.stage = .shimAdoptFD
                    do { try transport.adopt(fd) } catch { Darwin.close(fd); throw error }
                    defer { transport.close() }
                    let call = GuestProtocol.Envelope(operation: request.command.rawValue, payload: request.payload)
                    diagnostic.stage = .shimGuestRun
                    let bytes = try await transport.run { io in
                        diagnostic.stage = .shimGuestEncode
                        let encoded = try GuestProtocol.encode(call)
                        diagnostic.stage = .shimGuestWrite
                        try io.write(encoded)
                        diagnostic.stage = .shimGuestRead
                        let frame = try io.readFrame(maximum: Wire.maximumPayload)
                        diagnostic.stage = .shimGuestDecode
                        let reply = try GuestProtocol.decode(frame)
                        diagnostic.stage = .shimGuestIODeadline
                        try io.check()
                        diagnostic.stage = .shimGuestReplyBinding
                        guard reply.id == call.id, reply.operation == call.operation else { throw Wire.Failure.invalid }
                        diagnostic.stage = .shimGuestRemoteFailure
                        guard reply.error == nil else { throw Wire.Failure.invalid }
                        diagnostic.stage = .shimGuestPayload
                        guard let data = reply.payload else { throw Wire.Failure.invalid }
                        diagnostic.stage = .shimGuestWorkerReturn
                        return data
                    }
                    diagnostic.stage = .shimGuestReturnCancellation
                    try Task.checkCancellation()
                    diagnostic.stage = .shimGuestReturnIdentity
                    guard self.machineOwner.isCurrent(machine), self.originalConsumerLease.matchesMachine(machine),
                          self.originalConsumerBinding == binding, !self.observationStopInProgress else { throw Wire.Failure.invalid }
                    diagnostic.stage = .shimCheckedReply
                    let checked = try Wire.checkedReply(bytes, request: request, previous: previous)
                    diagnostic.stage = .shimValidationDeadline
                    try transport.check() // Actor resumption/validation cannot turn an expired exchange into success.
                    if let evidence = checked.evidence { self.originalConsumerEvidence = evidence }
                    diagnostic.stage = .shimLeaseTransition
                    if request.command == .begin {
                        try machine.validateOriginalConsumer(binding)
                        try self.originalConsumerLease.begin(binding.armDigest, now: DispatchTime.now().uptimeNanoseconds)
                        let deadline = self.originalConsumerLease.deadline!
                        self.originalConsumerExpiry = Task { @MainActor in
                            let now = DispatchTime.now().uptimeNanoseconds
                            if deadline > now { try? await Task.sleep(nanoseconds: deadline - now) }
                            guard !Task.isCancelled else { return }
                            do { try await self.arbitrateObservationStop(.forced, message: "original consumer observation expired") }
                            catch { self.failure = error.localizedDescription; try? self.persist() }
                        }
                    } else if request.command != .arm && request.command != .release && request.command != .resume {
                        _ = try self.originalConsumerLease.require(binding.armDigest, now: DispatchTime.now().uptimeNanoseconds)
                    }
                    diagnostic.stage = .shimTaskReturn
                    return checked.data // Typed re-encoding; never pass raw guest fields.
                } catch {
                    // Close the lease in the full exchange itself, before its slot
                    // becomes reusable or another MainActor request can resume.
                    self.originalConsumerLease.cancel()
                    throw error
                }
            }
            originalConsumerTask = task
            let result = try await withTaskCancellationHandler { try await task.value }
                onCancel: { transport.cancel(); task.cancel() }
            diagnostic.stage = .shimReturnCancellation
            try Task.checkCancellation()
            diagnostic.stage = .shimReturnDeadline
            try transport.check()
            return result
        } catch { diagnostic.report(error); throw error }
    }

    private func performStop() async throws {
        do {
            try await stopAndReleaseMachine()
            state = .stopped
            try persist()
        } catch {
            state = .failed
            failure = "VM teardown incomplete; disk leases retained"
            try? persist()
            throw BackendResourceRollbackIncompleteError(failure!)
        }
    }

    private func stopAndReleaseMachine() async throws {
        // Containment first; the owner retains its disk transaction (leases).
        if let host = lifecycleHost { host.server?.close(); host.owner.terminate() }
        try await machineOwner.stopAndRelease(stop: { machine in
            if let host = self.lifecycleHost, host.owner.machine === machine {
                try await host.owner.stopForRollback()
            } else { try await machine.forceStop() }
        }) {
            try await self.outputSpooler?.stop()
            self.outputSpooler = nil
            if self.specification.kind == .storage { await self.fabric.unregister(.init("storage-service")) }
            self.hostSocketRelays.removeAll()
            for relay in self.serviceRelays.values { relay.cancel() }
            self.serviceRelays.removeAll()
        }
    }

    private func boot() async throws {
        try await bootGate.boot {
            if self.state == .running { return }
            guard self.machine == nil else { throw EngineError(.conflict, "failed VM retains disk leases") }
            try await self.performBoot()
        }
    }

    private func performBoot() async throws {
        // A fresh boot supersedes any prior generation's stop arbitration: the new
        // machine invalidates the old stop scope, so the admission flag must not
        // leak across boots (legacy exec was rejected with state=.running while
        // this stayed true after a stop->reboot cycle).
        observationStopInProgress = false
        state = .starting; try persist()
        var step = "resolve attachments and build configuration (rosetta=\(specification.rosetta))"
        do {
            let (config, transaction) = try await bootResources()
            step = "create virtual machine"
            let value = try RawContainerVirtualMachine(configuration: config)
            // Publish ownership before any await, but forwarding requires running.
            machine = value
            try await performBoot(value, transaction: transaction, step: &step)
        } catch {
            do {
                try await stopAndReleaseMachine()
            } catch {
                state = .failed; failure = "VM rollback incomplete; disk leases retained"; try? persist()
                throw BackendResourceRollbackIncompleteError(failure!)
            }
            state = .failed; failure = error.localizedDescription; try? persist()
            let nsError = error as NSError
            throw EngineError(
                .internalError,
                "boot step '\(step)' failed: \(error.localizedDescription) [\(nsError.domain) \(nsError.code)]"
            )
        }
    }

    private func bootResources(policy: RawDiskBootTransaction.Policy = .journalDriven) async throws -> (RawVirtualMachineConfiguration, RawDiskBootTransaction) {
            let kernelArguments = try Self.bootstrapKernelArguments(specification)
            let attachments = try VMShimAttachmentResolver.resolve(specification, inheritedStorageDisk: inheritedStorageDisk)
            let immutableSpecification = specification
            let preflight = Task.detached {
                let initramfs = try Self.pinnedBootstrapInitramfs(immutableSpecification)
                let transaction = try RawDiskBootTransaction(specification: immutableSpecification, disks: attachments.disks, policy: policy)
                return (initramfs, transaction)
            }
            let (initramfs, transaction) = try await preflight.value
            try Task.checkCancellation()
            let config = RawVirtualMachineConfiguration(
                id: specification.containerID,
                kernel: URL(filePath: specification.kernelPath),
                initialRamdisk: URL(filePath: "/dev/fd/\(initramfs.fileDescriptor)"),
                rootDisk: attachments.rootDisk,
                rootDiskReadOnly: specification.rootDiskReadOnly,
                additionalDisks: attachments.additionalDisks,
                cpus: specification.cpus,
                memoryBytes: specification.memoryBytes,
                macAddress: specification.macAddress,
                bindShares: attachments.bindShares,
                retainedAttachmentHandles: attachments.retainedHandles + [initramfs],
                kernelArguments: kernelArguments,
                rosetta: specification.rosetta
            )
            return (config, transaction)
    }

    private func performBoot(_ value: RawContainerVirtualMachine, transaction: RawDiskBootTransaction,
                             step: inout String) async throws {
            if specification.kind == .container {
                step = "start output spool"
                outputSpooler = try makeOutputSpooler()
                outputSpooler?.start { [weak self, weak value] error in
                    Task { @MainActor in
                        guard let value else { return }
                        await self?.outputSpoolFailed(error, machine: value)
                    }
                }
            }
            step = "start virtual machine"
            guard specification.kind == .container else {
                throw EngineError(.conflict, "storage boot requires private lifecycle control")
            }
            do {
                if specification.workloadStorageMode == .managed {
                    value.workloadStorageDidTerminate = { [weak self, weak value] in
                        Task { @MainActor in
                            guard let value else { return }
                            await self?.workloadStorageFailed(machine: value)
                        }
                    }
                    try await value.startManagedWorkload(bootstrap: transaction, compatibilityProfile: Self.prepareCompatibilityProfile(specification))
                } else {
                    try await value.start(bootstrap: transaction)
                }
                guard let networkPath = specification.networkSocketPath else {
                    throw EngineError(.internalError, "container shim network transport socket is missing")
                }
                try connectFabric(value, path: networkPath)
            }
            try Task.checkCancellation()
            guard !bootGate.isStopping else { throw CancellationError() }
            step = "install socket relays"
            hostSocketRelays = try specification.socketRelays.map { specification in
                let relay = UnixVirtioSocketRelay(socketPath: specification.path)
                try value.install(listener: relay.listener, port: specification.port)
                return relay
            }
            state = .running; failure = nil; try persist()
    }

    // MARK: Lifecycle-v2 hosting

    /// A lifecycle spec requires exactly FD4; every other spec forbids it.
    nonisolated static func inheritLifecycleDescriptor(_ descriptor: Int32?,
        specification: VMShimProtocol.Specification) throws -> FileHandle? {
        let lifecycle = specification.kind == .storage
        guard let descriptor else {
            guard !lifecycle else { throw EngineError(.conflict, "lifecycle storage shim requires its private channel") }
            return nil
        }
        guard lifecycle, descriptor == VMShimClient.storageLifecycleDescriptor,
              fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
            throw EngineError(.conflict, "invalid inherited storage lifecycle descriptor")
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    /// Storage boot is exclusive to the private authenticated lifecycle channel.
    nonisolated static func requireLifecycleHostingAdmission(_ operation: VMShimProtocol.Operation,
        specification: VMShimProtocol.Specification, enrolled: Bool = false) throws {
        guard specification.kind == .storage else { return }
        // The launch token is not an adoption capability and cannot destroy or
        // pause the enrolled VM. Fabric configuration remains the existing
        // infrastructure networking surface, not storage-owner authority.
        switch operation {
        case .status, .configureFabric: return // Retained infrastructure surface only.
        case .stop where !enrolled, .shutdown where !enrolled: return
        default:
            throw EngineError(.unauthorized, "lifecycle owner requires private authenticated control")
        }
    }

    private func attachLifecycleControl(_ descriptor: Int32, deadline: DispatchTime) async throws {
        guard let host = lifecycleHost, !bootGate.isStopping else { throw StorageLifecycleShimProtocol.Failure.closed }
        let (session, generation) = try await host.owner.adoptControl(candidateFD: descriptor)
        do {
            let server = try await Self.lifecycleWorker {
                try StorageLifecycleShimServer(owner: host.owner, acceptedFD: descriptor,
                    session: session, generation: generation, deadline: deadline)
            }
            try server.start()
            lifecycleHost = (host.owner, server)
            // Dropping the predecessor server cannot detach this new generation.
        } catch { host.owner.controlLifetime.detach(generation); throw error }
    }

    private func startLifecycleHosting(parent: FileHandle) {
        Task { @MainActor in
            do {
                // Join only startup, not the enrolled owner's control lifetime.
                // Token stop cancels and joins every outstanding startup worker.
                try await self.bootGate.boot { try await self.hostLifecycle(parent: parent) }
            }
            catch { await self.lifecycleHostTerminated(nil, message: "storage lifecycle hosting failed: \(EngineError.message(for: error))") }
        }
    }

    nonisolated static func requireLifecycleHostingPublication(state: VMShimProtocol.State, stopping: Bool) throws {
        guard state == .starting, !stopping else { throw EngineError(.conflict, "lifecycle hosting was stopped during preparation") }
    }

    private func hostLifecycle(parent: FileHandle) async throws {
        let policy = try StorageLifecycleNativePolicy.current(role: .engine)
        let fd = parent.fileDescriptor
        // Child authenticates its parent BEFORE any channel IO or VM construction.
        let host = try await Self.lifecycleWorker {
            _ = try StorageLifecycleFreshShim.authenticatedParent(parentFD: fd, policy: policy)
            let packet = try StorageLifecycleShimChannel.receive(fd: fd, permitsDescriptor: false,
                deadline: StorageLifecycleShimChannel.deadline(30))
            return try StorageLifecycleShimProtocol.decodeHost(packet.body)
        }
        let root = try StorageIdentity.RootPublicKey(publicData: host.rootPublicKey)
        let binding = try host.binding.value()
        guard state == .created, !bootGate.isStopping else { throw EngineError(.conflict, "lifecycle host is not startable") }
        state = .starting; try persist()
        let (config, transaction) = try await bootResources(policy: host.diskMode.policy)
        // Token stop may have completed while resources were being prepared and
        // before an owner existed. Never publish a fresh private owner afterward.
        try Self.requireLifecycleHostingPublication(state: state, stopping: bootGate.isStopping)
        let value = try RawContainerVirtualMachine(configuration: config)
        try lifecycleHosting.host(value, owner: machineOwner)
        let owner = try RawStorageLifecycleShim(machine: value, bootstrap: transaction, binding: binding,
            root: root, parentBorrowedFD: fd, policy: policy)
        owner.onReady = { [weak self, weak value] in
            guard let self, let value else { return }
            Task { @MainActor in await self.lifecycleHostReady(value) }
        }
        owner.onTerminal = { [weak self, weak value] in
            guard let self, let value else { return }
            Task { @MainActor in await self.lifecycleHostTerminated(value, message: "storage lifecycle owner terminated") }
        }
        // Stop must retain and join this exact owner's fresh-abort path even if
        // native server construction fails or is cancelled before publication.
        lifecycleHost = (owner, nil)
        try await Self.publishLifecycleHost(construct: {
            try await Self.lifecycleWorker {
                try StorageLifecycleShimServer(owner: owner, parentBorrowedFD: fd, policy: policy)
            }
        }, admit: {
            try Self.requireLifecycleHostingPublication(state: self.state, stopping: self.bootGate.isStopping)
            try self.machineOwner.requireCurrent(value)
            try owner.controlLifetime.withAdmission {}
        }, publish: { server in
            self.lifecycleHost = (owner, server)
        }, bind: {
            try await Self.lifecycleWorker {
                try StorageLifecycleShimChannel.send(StorageLifecycleShimProtocol.HostBootstrap.bound, fd: fd,
                    deadline: StorageLifecycleShimChannel.deadline(30))
            }
        }, start: { try $0.start() }, close: { $0.close() })
    }

    /// Revalidate both suspension boundaries before exposing an executable host.
    /// The boot gate joins construction/bind workers before VM teardown; cancelled
    /// construction still returns an owned server that must be explicitly closed.
    static func publishLifecycleHost<Server: Sendable>(
        construct: @MainActor () async throws -> Server,
        admit: @MainActor () throws -> Void,
        publish: @MainActor (Server) -> Void,
        bind: @MainActor () async throws -> Void,
        start: @MainActor (Server) throws -> Void,
        close: @MainActor (Server) -> Void
    ) async throws {
        let server = try await construct()
        do {
            try Task.checkCancellation()
            try admit()
            publish(server)
            try await bind()
            try Task.checkCancellation()
            try admit()
            try start(server)
        } catch {
            close(server)
            throw error
        }
    }

    /// Workload DATA/FUSE reaches the storage VM through the same trunk as v1.
    private func lifecycleHostReady(_ value: RawContainerVirtualMachine) async {
        guard lifecycleHosting.ready(value, owner: machineOwner), !bootGate.isStopping else { return }
        await fabric.register(.init("storage-service"), file: value.trunk.fabricFileHandle, vlans: Set(activeVLANs))
        guard machineOwner.isCurrent(value), !bootGate.isStopping, state == .starting else { return }
        state = .running; failure = nil; try? persist()
    }

    /// Failure/EOF/stop of the owner joins the ordinary stop arbitration; a
    /// failed VZ stop keeps `machineOwner` and every disk lease.
    private func lifecycleHostTerminated(_ value: RawContainerVirtualMachine?, message: String) async {
        guard lifecycleHosting.terminate(value) else { return }
        if let host = lifecycleHost { host.server?.close(); host.owner.terminate() }
        guard !bootGate.isStopping, state != .stopping, state != .stopped else { return }
        if machine == nil { state = .failed; failure = message; try? persist(); return }
        do { try await arbitrateObservationStop(.forced, message: message) }
        catch { failure = error.localizedDescription; try? persist() }
    }

    private nonisolated static func lifecycleWorker<Value: Sendable>(
        _ operation: @escaping @Sendable () throws -> Value) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            Thread.detachNewThread {
                do { continuation.resume(returning: try operation()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    nonisolated static func validateGenericWorkloadOperation(_ operation: String,
        specification: VMShimProtocol.Specification) throws {
        if OriginalConsumerObservationProtocol.Command(rawValue: operation) != nil {
            throw OriginalConsumerObservationProtocol.Failure.unsupported
        }
        if specification.workloadStorageMode == .managed,
           ["prepare", "start", "prepare-rootfs"].contains(operation) {
            throw PrivateWorkloadStorageCoordinator.failure()
        }
    }

    nonisolated static func bootstrapKernelArguments(_ specification: VMShimProtocol.Specification) throws -> [String] {
        // These private ports are never eligible for a user-supplied general relay.
        guard specification.socketRelays.allSatisfy({ !(4_105...4_109).contains($0.port) }),
              !specification.kernelArguments.contains(where: { argument in
                  argument.split(whereSeparator: { $0.isWhitespace }).contains(where: {
                      $0 == "cengine.storage_mode" || $0.hasPrefix("cengine.storage_mode=")
                          || $0 == "cengine.workload_storage_mode" || $0.hasPrefix("cengine.workload_storage_mode=")
                  })
              }), specification.kind == .container || specification.workloadStorageMode == .none else {
            throw VMShimManagedTransport.failure()
        }
        guard specification.kind == .storage else {
            return specification.kernelArguments + (specification.workloadStorageMode == .managed
                ? ["cengine.workload_storage_mode=managed"] : [])
        }
        return specification.kernelArguments + ["cengine.storage_mode=lifecycle"]
    }

    nonisolated static func pinnedBootstrapInitramfs(_ specification: VMShimProtocol.Specification) throws -> FileHandle {
        guard specification.diskBootstrapVersion == 1,
              let expected = specification.expectedInitramfsSHA256,
              expected.count == 64,
              expected.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw EngineError(.conflict, "bootstrap-compatible guest assets required")
        }
        if specification.workloadStorageMode == .managed {
            _ = try prepareCompatibilityProfile(specification)
            struct Capability: Decodable {
                let schemaVersion: Int
                let protocolVersion: Int
                let workloadStorageBootVersion: Int
                let containerInitramfsSHA256: String
            }
            let directory = try PersistentStateDirectory.open(
                URL(filePath: specification.kernelPath).deletingLastPathComponent())
            guard specification.kind == .container,
                  let metadata = try directory.readRegularFile(named: "disk-bootstrap.json"),
                  let capability = try? JSONDecoder().decode(Capability.self, from: metadata),
                  capability.schemaVersion == 1, capability.protocolVersion == 1,
                  capability.workloadStorageBootVersion == 1,
                  capability.containerInitramfsSHA256 == expected else {
                throw EngineError(.conflict, "managed workloads require workloadStorageBootVersion 1 guest assets")
            }
        }
        if specification.kind == .storage {
            // Reject pre-lifecycle images before VZ exists; no legacy boot fallback.
            struct Capability: Decodable {
                let schemaVersion: Int
                let protocolVersion: Int
                let storageServiceBootVersion: Int
                let storageLifecycleVersion: Int
                let workloadStorageBootVersion: Int
                let storageInitramfsSHA256: String
            }
            let assetDirectory = try PersistentStateDirectory.open(
                URL(filePath: specification.kernelPath).deletingLastPathComponent())
            guard let metadata = try assetDirectory.readRegularFile(named: "disk-bootstrap.json"),
                  let capability = try? JSONDecoder().decode(Capability.self, from: metadata),
                  capability.schemaVersion == 1, capability.protocolVersion == 1,
                  capability.storageServiceBootVersion == 2,
                  capability.storageLifecycleVersion == 2,
                  capability.workloadStorageBootVersion == 1,
                  capability.storageInitramfsSHA256 == expected else {
                throw EngineError(.conflict, "guest assets do not meet the shared-storage protocol requirements; rebuild paired guest assets")
            }
        }
        let url = URL(filePath: specification.initialRamdiskPath)
        let parent = try PersistentStateDirectory.open(url.deletingLastPathComponent())
        let opened = try parent.openRegularFile(named: url.lastPathComponent, access: .readOnly)
        var hash = SHA256()
        while let data = try opened.handle.read(upToCount: 1 << 20), !data.isEmpty { hash.update(data: data) }
        guard hash.finalize().map({ String(format: "%02x", $0) }).joined() == expected,
              parent.pathStillNamesThisDirectory(),
              try parent.regularFileIdentity(named: url.lastPathComponent) == opened.identity else {
            throw EngineError(.conflict, "guest initramfs digest changed")
        }
        try opened.handle.seek(toOffset: 0)
        return opened.handle
    }

    private func makeOutputSpooler() throws -> VMShimOutputSpooler? {
        guard let spool = specification.outputSpool else { return nil }
        guard spool.retainedBytes > 0,
              spool.segmentBytes > 0,
              spool.maximumSegments > 0 else {
            throw EngineError(.badRequest, "invalid output spool policy")
        }
        let directory = try PersistentStateDirectory.open(
            URL(filePath: spool.directoryPath, directoryHint: .isDirectory)
        )
        guard directory.identity == PersistentFileIdentity.persistedIdentity(
            spool.directoryIdentity
        ), directory.pathStillNamesThisDirectory() else {
            throw EngineError(.conflict, "container I/O directory changed")
        }
        let stdout = try directory.openRegularFile(
            named: "stdout",
            expectedIdentity: PersistentFileIdentity.persistedIdentity(
                spool.stdoutIdentity
            ),
            access: .readWrite
        ).handle
        let stderr = try directory.openRegularFile(
            named: "stderr",
            expectedIdentity: PersistentFileIdentity.persistedIdentity(
                spool.stderrIdentity
            ),
            access: .readWrite
        ).handle
        do {
            let stdoutDirectory = try directory.openDirectory(named: "stdout.spool")
            let stderrDirectory = try directory.openDirectory(named: "stderr.spool")
            guard stdoutDirectory.identity == PersistentFileIdentity.persistedIdentity(
                spool.stdoutSpoolDirectoryIdentity
            ), stderrDirectory.identity == PersistentFileIdentity.persistedIdentity(
                spool.stderrSpoolDirectoryIdentity
            ), stdoutDirectory.pathStillNamesThisDirectory(),
               stderrDirectory.pathStillNamesThisDirectory() else {
                throw EngineError(.conflict, "container output spool directory changed")
            }
            return try VMShimOutputSpooler(
                stdout: stdout,
                stderr: stderr,
                stdoutDirectory: stdoutDirectory,
                stderrDirectory: stderrDirectory,
                retainedBytes: spool.retainedBytes,
                segmentBytes: spool.segmentBytes,
                maximumSegments: spool.maximumSegments
            )
        } catch {
            try? stdout.close()
            try? stderr.close()
            throw error
        }
    }

    private func outputSpoolFailed(_ error: Error, machine: RawContainerVirtualMachine) async {
        guard machineOwner.isCurrent(machine), outputSpooler != nil else { return }
        try? await arbitrateObservationStop(.forced, message: "output spool failed: \(error.localizedDescription)")
    }

    private func workloadStorageFailed(machine: RawContainerVirtualMachine) async {
        guard machineOwner.isCurrent(machine) else { return }
        try? await arbitrateObservationStop(.storageTerminal, message: "private workload storage channel terminated")
    }

    private func status() -> VMShimProtocol.Status {
        let privateChannelFailed = machine?.workloadStorageIsTerminal == true
            && !bootGate.isStopping && state != .stopped
        return .init(
            containerID: specification.containerID,
            generation: specification.generation,
            state: privateChannelFailed ? .failed : state,
            processIdentifier: getpid(),
            processStartTime: VMShimClient.processStartTime(for: getpid()),
            executableUUID: RunningExecutableIdentity.uuid,
            shimLaunchUUID: specification.shimLaunchUUID,
            exitCode: exitCode,
            error: privateChannelFailed ? "private workload storage channel terminated" : failure
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
                let client: CInt
                do {
                    client = try UnixSocket.accept(descriptor)
                } catch is UnixSocket.AcceptedPeerConfigurationError {
                    continue
                } catch { return }
                do {
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

    func configureFabric(_ values: [VMShimClient.FabricNetwork]) async throws {
        // MainActor alone does not serialize across helper/fabric awaits. Queue
        // whole reconciliations so an older start cannot outlive a removal.
        let previous = fabricConfiguration
        let generation = UUID()
        let task = Task { @MainActor in
            _ = try? await previous?.value
            try Task.checkCancellation()
            try await self.applyFabric(values)
        }
        fabricConfiguration = task
        fabricConfigurationGeneration = generation
        defer {
            if fabricConfigurationGeneration == generation {
                fabricConfiguration = nil
                fabricConfigurationGeneration = nil
            }
        }
        try await withTaskCancellationHandler {
            if Task.isCancelled { task.cancel() }
            try await task.value
        } onCancel: {
            task.cancel()
        }
    }

    var dockerHostGateways: [UInt16: String] {
        Dictionary(uniqueKeysWithValues: fabricNetworks.values.compactMap { network in
            network.internalNetwork || network.isolated || network.gateway.isEmpty
                ? nil : (network.vlan, network.gateway)
        })
    }

    private func refreshFabricDNS() async {
        await fabric.configureDockerHostDNS(gateways: dockerHostGateways)
    }

    private func applyFabric(_ values: [VMShimClient.FabricNetwork]) async throws {
        let desired = Dictionary(uniqueKeysWithValues: values.map { ($0.id, $0) })
        desiredFabricNetworks = desired
        let ids = Set(fabricNetworks.keys).union(desired.keys).union(uplinkRecoveries.keys)
        let changed = ids.sorted().filter { id in
            guard let network = desired[id] else { return true }
            return fabricNetworks[id] != network || (!network.isolated && uplinks[id] == nil)
        }
        // Detach ownership before any suspension: a delayed disconnect must not
        // launch recovery while this reconciliation is stopping its old uplink.
        let retired = changed.map { id in
            let uplink = uplinks.removeValue(forKey: id)
            let recovery = uplinkRecoveries.removeValue(forKey: id)
            recovery?.task.cancel()
            fabricNetworks.removeValue(forKey: id)
            return (id: id, uplink: uplink, recovery: recovery)
        }
        await refreshFabricDNS()
        for entry in retired {
            await entry.recovery?.task.value
            if let uplink = entry.uplink {
                await fabric.unregister(.init("uplink-\(entry.id)"))
                await uplink.stop()
            }
        }
        try Task.checkCancellation()
        // Complete removals/isolation before any fallible start. An unrelated
        // helper rejection must not leave an obsolete external uplink active.
        for id in changed {
            if let network = desired[id], network.isolated { fabricNetworks[id] = network }
        }
        for id in changed {
            guard let network = desired[id], !network.isolated else { continue }
            let uplink = try await startUplink(network, specification.networkNamespace)
            try await installUplink(uplink, network: network)
        }
        try Task.checkCancellation()
        // A disconnect can arrive while another network is being installed.
        guard desired.allSatisfy({ id, network in
            fabricNetworks[id] == network && (network.isolated || uplinks[id] != nil)
        }) else {
            throw EngineError(.internalError, "network fabric uplink disconnected during configuration")
        }
    }

    private func installUplink(_ uplink: any VMShimUplink, network: VMShimClient.FabricNetwork) async throws {
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
        guard !Task.isCancelled, uplinks[network.id] === uplink else {
            if uplinks[network.id] === uplink { uplinks.removeValue(forKey: network.id) }
            await fabric.unregister(.init("uplink-\(network.id)"), registration: registration)
            await uplink.stop()
            throw CancellationError()
        }
        fabricNetworks[network.id] = network
        await refreshFabricDNS()
    }

    private func uplinkDisconnected(id: String, uplink: any VMShimUplink, registration: UUID) {
        guard uplinks[id] === uplink else { return }
        uplinks.removeValue(forKey: id)
        fabricNetworks.removeValue(forKey: id)
        FileHandle.standardError.write(Data("vmnet uplink \(id) disconnected; recreating it\n".utf8))
        let fabric = self.fabric
        let cleanup = Task {
            await fabric.unregister(.init("uplink-\(id)"), registration: registration)
            await self.refreshFabricDNS()
            await uplink.stop()
        }

        uplinkRecoveries.removeValue(forKey: id)?.task.cancel()
        let generation = UUID()
        let task = Task { @MainActor [weak self] in
            // A stop uses the same helper resource ID as its replacement.
            await cleanup.value
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
              uplinks[id] == nil, let network = desiredFabricNetworks[id], !network.isolated {
            do {
                let replacement = try await startUplink(network, specification.networkNamespace)
                guard !Task.isCancelled,
                      uplinkRecoveries[id]?.generation == generation,
                      uplinks[id] == nil,
                      desiredFabricNetworks[id] == network else {
                    await replacement.stop()
                    return
                }
                try await installUplink(replacement, network: network)
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

    nonisolated static func requireStreamAdmission(isCurrent: Bool, terminal: Bool,
        stopping: Bool, state: VMShimProtocol.State) throws {
        guard isCurrent, !terminal, !stopping, state == .running else {
            throw EngineError(.conflict, "VM stream belongs to an unavailable generation")
        }
    }

    private func startExecStream(_ request: VMShimProtocol.Envelope, local: FileHandle) async throws {
        guard let payload = request.payload else { throw EngineError(.badRequest, "exec stream request has no payload") }
        guard state == .running, let machine else { throw EngineError(.conflict, "VM guest control is unavailable") }
        _ = try JSONDecoder().decode(VMShimClient.ExecStreamRequest.self, from: payload)

        let connection = try await machine.connect(toPort: GuestProtocol.execIOPort)
        do {
            try Self.requireStreamAdmission(isCurrent: machineOwner.isCurrent(machine),
                terminal: machine.workloadStorageIsTerminal,
                stopping: bootGate.isStopping || observationStopInProgress, state: state)
        } catch { connection.close(); throw error }
        let streamConnection = SendableVirtioSocketConnection(connection)
        let target = FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false)
        let setupDescriptor = Darwin.dup(connection.fileDescriptor)
        guard setupDescriptor >= 0 else {
            streamConnection.connection.close()
            throw EngineError(.internalError, "duplicate exec stream descriptor: \(String(cString: strerror(errno)))")
        }
        let setup = FileHandle(fileDescriptor: setupDescriptor, closeOnDealloc: true)
        var acknowledgementStarted = false
        do {
            let setupData = try GuestProtocol.encode(GuestProtocol.Envelope(operation: "start-exec-stream", payload: payload))
            let deadline = DispatchTime.now().uptimeNanoseconds + VMShimManagedTransport.maximumNanoseconds
            let response = try VMShimProtocol.encode(.init(id: request.id, token: specification.token,
                operation: request.operation, payload: JSONEncoder().encode(Empty())))
            acknowledgementStarted = true
            _ = try await Self.managedSocketIO(local.fileDescriptor, deadline: deadline) {
                try $0.write(response); return Data()
            }
            try Self.requireStreamAdmission(isCurrent: machineOwner.isCurrent(machine),
                terminal: machine.workloadStorageIsTerminal,
                stopping: bootGate.isStopping || observationStopInProgress, state: state)
            _ = try await Self.managedSocketIO(setup.fileDescriptor, deadline: deadline) {
                try $0.write(setupData); return Data()
            }
            try setup.close()
            try Self.requireStreamAdmission(isCurrent: machineOwner.isCurrent(machine),
                terminal: machine.workloadStorageIsTerminal,
                stopping: bootGate.isStopping || observationStopInProgress, state: state)
            let id = UUID()
            let relay = BidirectionalDescriptorRelay(
                left: local,
                right: target,
                close: { try? local.close(); streamConnection.connection.close() },
                completion: { [weak self] in Task { @MainActor in self?.serviceRelays.removeValue(forKey: id) } }
            )
            serviceRelays[id] = relay
            relay.start(afterActivationByte: VMShimProtocol.execStreamActivationByte)
        } catch {
            try? setup.close()
            streamConnection.connection.close()
            // After any ACK byte, close this exact session; never let handle
            // append an ordinary error frame or revisit a closed/reused FD.
            if acknowledgementStarted { try? local.close(); return }
            throw error
        }
    }

    nonisolated static func preparePortStreamSetup(_ descriptor: Int32, payload: Data, deadline: UInt64) async throws {
        let request = GuestProtocol.Envelope(operation: "start-port-stream", payload: payload)
        let frame = try await managedSocketIO(descriptor, deadline: deadline) { io in
            try io.write(GuestProtocol.encode(request))
            return try io.readFrame()
        }
        let reply = try GuestProtocol.decode(frame)
        guard reply.id == request.id, reply.operation == request.operation else {
            throw EngineError(.internalError, "guest port stream response does not match request")
        }
        if let failure = reply.error {
            throw EngineError(.internalError, "guest port proxy \(failure.code): \(failure.message)")
        }
    }

    private func startPortStream(_ request: VMShimProtocol.Envelope, local: FileHandle) async throws {
        guard let payload = request.payload else {
            throw EngineError(.badRequest, "port stream request has no payload")
        }
        guard state == .running, let machine else { throw EngineError(.conflict, "VM guest control is unavailable") }
        let value = try JSONDecoder().decode(VMShimClient.PortStreamRequest.self, from: payload)
        guard ["tcp", "udp"].contains(value.transport), value.port != 0 else {
            throw EngineError(.badRequest, "invalid port stream target")
        }

        let connection = try await machine.connect(toPort: GuestProtocol.portProxyPort)
        do {
            try Self.requireStreamAdmission(isCurrent: machineOwner.isCurrent(machine),
                terminal: machine.workloadStorageIsTerminal,
                stopping: bootGate.isStopping || observationStopInProgress, state: state)
        } catch { connection.close(); throw error }
        let streamConnection = SendableVirtioSocketConnection(connection)
        let target = FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false)
        let setupDescriptor = Darwin.dup(connection.fileDescriptor)
        guard setupDescriptor >= 0 else {
            streamConnection.connection.close()
            throw EngineError(.internalError, "duplicate port stream descriptor: \(String(cString: strerror(errno)))")
        }
        let setup = FileHandle(fileDescriptor: setupDescriptor, closeOnDealloc: true)
        var acknowledgementStarted = false
        do {
            try await Self.preparePortStreamSetup(setup.fileDescriptor, payload: payload,
                deadline: DispatchTime.now().uptimeNanoseconds + VMShimManagedTransport.maximumNanoseconds)
            try setup.close()
            try Self.requireStreamAdmission(isCurrent: machineOwner.isCurrent(machine),
                terminal: machine.workloadStorageIsTerminal,
                stopping: bootGate.isStopping || observationStopInProgress, state: state)

            let response = try VMShimProtocol.encode(.init(id: request.id, token: specification.token,
                operation: request.operation, payload: JSONEncoder().encode(Empty())))
            acknowledgementStarted = true
            _ = try await Self.managedSocketIO(local.fileDescriptor,
                deadline: DispatchTime.now().uptimeNanoseconds + VMShimManagedTransport.maximumNanoseconds) {
                try $0.write(response); return Data()
            }
            try Self.requireStreamAdmission(isCurrent: machineOwner.isCurrent(machine),
                terminal: machine.workloadStorageIsTerminal,
                stopping: bootGate.isStopping || observationStopInProgress, state: state)

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
            // After any ACK byte, close this exact session; never let handle
            // append an ordinary error frame or revisit a closed/reused FD.
            if acknowledgementStarted { try? local.close(); return }
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
