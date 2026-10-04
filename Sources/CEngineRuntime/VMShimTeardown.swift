import CEngineCore
import Foundation

/// Stops every VM shim whose durable ownership records belong to one engine root.
/// Uninstall uses this before removing the privileged helper or moving engine data.
/// Upgrades require complete shutdown before replacing shared VM infrastructure.
public enum VMShimTeardown {
    @MainActor public static func terminateAll(
        in root: URL,
        expectedExecutable: URL = Bundle.main.executableURL
            ?? URL(filePath: CommandLine.arguments[0]),
        gracePeriodMilliseconds: Int32 = 5_000,
        forceWaitMilliseconds: Int32 = 1_000,
        requireCompleteShutdown: Bool = false,
        storeLock: CanonicalDataStoreLock? = nil
    ) async throws -> Int {
        guard let existingRoot = try PersistentStateDirectory.openIfPresent(root) else { return 0 }
        // All administrative callers, including best-effort uninstall, serialize
        // against daemon startup. Never acquire a second lease when CLI owns it.
        let storeLock = try storeLock ?? CanonicalDataStoreLock(root: root)
        let rootDirectory = try PersistentStateDirectory.retaining(storeLock)
        guard existingRoot.identity == rootDirectory.identity else {
            throw EngineError(.conflict, "administrative shutdown root does not match held lock")
        }
        try storeLock.validateRetainedOwnership()
        defer { withExtendedLifetime(storeLock) {} }

        var containerShims: [VMShimClient] = []
        var failures: [String] = []
        if let containers = try rootDirectory.openDirectoryIfPresent(named: "containers") {
            for name in try containers.reconciledEntryNames() {
                let directory = try containers.openDirectory(named: name)
                let launches = try VMShimClient.persistedLaunches(
                    in: directory,
                    expectedContainerID: name,
                    expectedExecutable: expectedExecutable
                )
                failures.append(contentsOf: launches.quarantined.map {
                    "\(name): \($0.name): \($0.reason)"
                })
                containerShims.append(contentsOf: launches.map(\.client))
            }
        }

        failures.append(contentsOf: await terminate(
            containerShims,
            gracePeriodMilliseconds: gracePeriodMilliseconds,
            forceWaitMilliseconds: forceWaitMilliseconds
        ))
        var terminatedCount = containerShims.count

        // A failed or quarantined container may still depend on shared storage.
        // Uninstall remains best-effort; an upgrade must leave infrastructure up
        // until every container's ownership and termination are resolved.
        if requireCompleteShutdown, !failures.isEmpty {
            throw EngineError(
                .internalError,
                "could not stop all cengine VM shims: \(failures.joined(separator: "; "))"
            )
        }

        if let infrastructure = try rootDirectory.openDirectoryIfPresent(named: "infrastructure"),
           let data = try infrastructure.readRegularFile(named: "shim.json", required: false) {
            let specification = try JSONDecoder().decode(
                VMShimProtocol.Specification.self, from: data
            )
            guard specification.kind == .storage,
                  specification.containerID == "cengine-storage",
                  VMShimClient.launchPathsMatch(
                      VMShimClient.specificationURL(for: specification).path,
                      infrastructure.url.appending(path: "shim.json").path
                  ) else {
                throw EngineError(.conflict, "infrastructure VM shim ownership is invalid")
            }

            try storeLock.validateRetainedOwnership()
            let lifecycle = try rootDirectory.entryMetadata(named: ManagedStorageLifecycleCheckpoint.directoryName) != nil
                || rootDirectory.entryMetadata(named: "managed-storage") != nil
                || rootDirectory.entryMetadata(named: ManagedStorageInitialization.directoryName) != nil
            if lifecycle {
                // Never fall back to token shutdown, signals, or backend recovery.
                try await ManagedLifecycleAdministrativeShutdown.stop(root: .init(storeLock: storeLock),
                    infrastructure: infrastructure, specification: specification,
                    expectedExecutable: expectedExecutable, exitWaitMilliseconds: forceWaitMilliseconds)
                guard failures.isEmpty else {
                    throw EngineError(.internalError,
                        "could not stop all cengine VM shims: \(failures.joined(separator: "; "))")
                }
                return terminatedCount + 1
            }

            let socketExists = FileManager.default.fileExists(
                atPath: specification.socketPath
            )
            let statusExists = FileManager.default.fileExists(
                atPath: specification.socketPath + ".status"
            )
            if socketExists || statusExists {
                let client = VMShimClient(specification: specification)
                do {
                    try await client.requestAdministrativeShutdown(
                        timeoutMilliseconds: gracePeriodMilliseconds,
                        waitForExit: requireCompleteShutdown,
                        exitWaitMilliseconds: forceWaitMilliseconds,
                        expectedExecutable: expectedExecutable
                    )
                    terminatedCount += 1
                } catch {
                    let shutdownError = error
                    do {
                        // The raw specification passed the ownership check above.
                        // A failed RPC is not proof of life, but disappearing socket
                        // artifacts alone are not proof of exit after a rejected peer.
                        guard requireCompleteShutdown,
                              FileManager.default.fileExists(
                                  atPath: specification.socketPath + ".status"
                              ) else { throw shutdownError }
                        try InfrastructureRecovery.requireExited(specification)
                        guard FileManager.default.fileExists(
                            atPath: specification.socketPath + ".status"
                        ) else { throw shutdownError }
                        terminatedCount += 1
                    } catch {
                        failures.append(
                            "infrastructure: \(EngineError.message(for: shutdownError))"
                        )
                    }
                }
            }
        }

        guard failures.isEmpty else {
            throw EngineError(
                .internalError,
                "could not stop all cengine VM shims: \(failures.joined(separator: "; "))"
            )
        }
        return terminatedCount
    }

    private static func terminate(
        _ clients: [VMShimClient],
        gracePeriodMilliseconds: Int32,
        forceWaitMilliseconds: Int32
    ) async -> [String] {
        await withTaskGroup(of: String?.self, returning: [String].self) { group in
            for client in clients {
                group.addTask {
                    do {
                        try await client.terminate(
                            gracePeriodMilliseconds: gracePeriodMilliseconds,
                            forceWaitMilliseconds: forceWaitMilliseconds
                        )
                        return nil
                    } catch {
                        return "\(client.specification.containerID): \(EngineError.message(for: error))"
                    }
                }
            }
            var failures: [String] = []
            for await failure in group {
                if let failure { failures.append(failure) }
            }
            return failures.sorted()
        }
    }
}

#if os(macOS)
/// Deliberately excludes takeover, boot, workload recovery, seal and reclaim.
@MainActor protocol ManagedLifecycleAdministrativeShutdownSteps: AnyObject {
    func validate() throws
    func adopt() async throws
    func connect() async throws
    func stop() async throws
    func requireExit() async throws
    func close() async
}

@MainActor enum ManagedLifecycleAdministrativeShutdown {
    static func run(_ steps: any ManagedLifecycleAdministrativeShutdownSteps) async throws {
        do {
            try steps.validate()
            try await steps.adopt()
            try steps.validate()
            try await steps.connect()
            try steps.validate()
            try await steps.stop()
            try steps.validate()
            try await steps.requireExit()
            try steps.validate()
            await steps.close()
        } catch {
            await steps.close()
            throw error
        }
    }

    static func stop(root: ManagedLifecycleStartupRoot, infrastructure: PersistentStateDirectory,
                     specification: VMShimProtocol.Specification, expectedExecutable: URL,
                     exitWaitMilliseconds: Int32) async throws {
        let steps = try Production(root: root, infrastructure: infrastructure, specification: specification,
            expectedExecutable: expectedExecutable, exitWaitMilliseconds: exitWaitMilliseconds)
        do {
            try steps.validate()
            if RawStorageShimRecovery.liveness(steps.published.record.process,
                observation: RawStorageShimRecovery.observe(steps.published.record.process.pid)) == .dead {
                await steps.close()
                return
            }
        } catch {
            await steps.close()
            throw error
        }
        try await run(steps)
    }

    /// Only positive kernel death evidence counts; socket loss and a successful
    /// stop response do not. Kept separate from RPC so stop gets its own budget.
    static func requireExit(_ process: RawStorageShimRecovery.ProcessIdentity,
                            milliseconds: Int32,
                            observe: (Int32) -> RawStorageShimRecovery.Observation = RawStorageShimRecovery.observe) async throws {
        let deadline = ContinuousClock.now + .milliseconds(max(0, milliseconds))
        while true {
            if RawStorageShimRecovery.liveness(process, observation: observe(process.pid)) == .dead { return }
            guard ContinuousClock.now < deadline else {
                throw EngineError(.conflict, "lifecycle storage shim did not positively exit after administrative shutdown")
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    /// Historical launch bytes stay immutable. Only the held-disk proposal uses
    /// today's device, and recovery permits that difference only after positive death.
    struct GenerationEvidence {
        let proposal: VMShimProtocol.Specification
        let published: RawStorageShimRecovery.Generation

        init(specification: VMShimProtocol.Specification, backingDescriptor: Int32, expectedSize: UInt64,
             observe: (Int32) -> RawStorageShimRecovery.Observation = RawStorageShimRecovery.observe) throws {
            var proposal = specification
            proposal.rootDiskIdentity = try PersistentFileIdentity.capture(descriptor: backingDescriptor).shimIdentity
            guard specification.rootDiskSize == expectedSize,
                  let published = try RawStorageShimRecovery.publishedGeneration(for: proposal, observe: observe),
                  published.specification == specification else { throw ManagedLifecycleStartupError.existingStore() }
            self.proposal = proposal
            self.published = published
        }

        func validate(backingDescriptor: Int32,
                      observe: (Int32) -> RawStorageShimRecovery.Observation = RawStorageShimRecovery.observe) throws {
            // Do not recalculate the proposal: a later live-FD change must fail,
            // even if its UUID/inode still match the retained historical record.
            guard try PersistentFileIdentity.capture(descriptor: backingDescriptor).shimIdentity == proposal.rootDiskIdentity,
                  let current = try RawStorageShimRecovery.publishedGeneration(for: proposal, observe: observe),
                  current.data == published.data, current.record == published.record else {
                throw ManagedLifecycleStartupError.existingStore()
            }
        }
    }

    private final class Production: ManagedLifecycleAdministrativeShutdownSteps {
        let root: ManagedLifecycleStartupRoot
        let infrastructure: PersistentStateDirectory
        let specification: VMShimProtocol.Specification
        let expectedExecutable: URL
        let exitWaitMilliseconds: Int32
        let backing: FileHandle
        let manifest: ManagedStorageLifecycleCheckpoint.Manifest
        let generation: GenerationEvidence
        var published: RawStorageShimRecovery.Generation { generation.published }
        let binding: StorageIdentity.StoreBinding
        var owner: ManagedStorageLifecycleOwner?
        var adopted: ManagedStorageLifecycleOwner.AdoptedShim?
        var connection: StorageLifecycleShimConnection?

        init(root: ManagedLifecycleStartupRoot, infrastructure: PersistentStateDirectory,
             specification: VMShimProtocol.Specification, expectedExecutable: URL, exitWaitMilliseconds: Int32) throws {
            try root.validate(infrastructure: infrastructure)
            guard try ManagedStorageLifecycleOwner.classify(root: root.directory) == .existingV2 else {
                throw ManagedLifecycleStartupError.existingStore()
            }
            let disk = try infrastructure.openRegularFile(named: "volumes.ext4", access: .readOnly)
            let manifest = try ManagedStorageLifecycleCheckpoint.inspect(in: root.directory, backingDescriptor: disk.handle.fileDescriptor)
            guard VMShimClient.launchPathsMatch(specification.rootDiskPath, infrastructure.url.appending(path: "volumes.ext4").path),
                  case .journal(let record) = try RawDiskInitialization.inspectExisting(in: infrastructure,
                    named: "volumes.ext4", expectedSize: manifest.bytes, heldDiskDescriptor: disk.handle.fileDescriptor, createLock: false),
                  record.state == .initialized, record.ext4UUID == manifest.ext4UUID else {
                throw ManagedLifecycleStartupError.existingStore()
            }
            let generation = try GenerationEvidence(specification: specification,
                backingDescriptor: disk.handle.fileDescriptor, expectedSize: manifest.bytes)
            func identity(_ value: PersistentFileIdentity) throws -> StorageIdentity.RootIdentity {
                guard let volume = value.volumeUUID else { throw ManagedLifecycleStartupError.existingStore() }
                return try .init(volumeUUID: .init(volume.uuidString.lowercased()), inode: value.inode)
            }
            binding = try .init(storeID: .init(manifest.identity.store), root: identity(manifest.root),
                backing: .init(identity: identity(manifest.backing), size: manifest.bytes), expectedExt4UUID: .init(manifest.ext4UUID))
            self.root = root; self.infrastructure = infrastructure; self.specification = specification
            self.expectedExecutable = expectedExecutable; self.exitWaitMilliseconds = exitWaitMilliseconds
            backing = disk.handle; self.manifest = manifest; self.generation = generation
        }

        func validate() throws {
            try root.validate(infrastructure: infrastructure)
            guard try infrastructure.regularFileIdentity(named: "volumes.ext4", expectedSize: manifest.bytes) == manifest.backing,
                  try ManagedStorageLifecycleCheckpoint.inspect(in: root.directory, backingDescriptor: backing.fileDescriptor) == manifest else {
                throw ManagedLifecycleStartupError.existingStore()
            }
            try generation.validate(backingDescriptor: backing.fileDescriptor)
        }
        func adopt() async throws {
            // Reject a foreign executable or edited generation before ROOT IO.
            let process = published.record.process
            let peer = VMShimClient.ProcessIdentity(processIdentifier: process.pid,
                startTime: process.startSeconds * 1_000_000 + process.startMicroseconds)
            guard let inspection = VMShimClient.inspectProcess(process.pid, identityProvider: { pid in
                guard case .process(let value) = VMShimClient.observeProcess(pid) else { return nil }
                return value
            }), VMShimClient.administrativeInspectionMatches(inspection, peerIdentity: peer,
                specification: specification, expectedExecutable: expectedExecutable) else {
                throw EngineError(.conflict, "lifecycle shim does not match exact executable generation")
            }
            let policy = try StorageLifecycleNativePolicy.current(role: .engine)
            let team = try policy.currentIdentity(role: .engine).teamIdentifier
            let client = try StorageLifecycleRootClient(installedHelperTeam: team, policy: policy)
            let store = binding.storeID, directory = root.directory
            try await Task.detached { try client.bindScope(store: store, rootFD: directory.descriptor) }.value
            try validate()
            let owner = try ManagedStorageLifecycleOwner(existingStoreRootClient: client, installedHelperTeam: team,
                root: directory, backingDescriptor: backing.fileDescriptor, binding: binding, policy: policy)
            self.owner = owner
            // Initializes the native candidate only: no grant or Guest takeover.
            _ = try await owner.prepareTakeover()
            try validate()
            let adopted = try await owner.adoptSurvivingShim(storeLock: root.storeLock)
            try ManagedLifecycleProductionStartup.validateSurvivingGeneration(published, status: adopted.status)
            self.adopted = adopted
        }
        func connect() async throws {
            guard let authorization = adopted?.connectionAuthorization else { throw ManagedLifecycleStartupError.existingStore() }
            connection = try await StorageLifecycleShimConnection.connectAdopted(socketPath: specification.socketPath,
                authorization: authorization)
        }
        func stop() async throws {
            guard let connection else { throw ManagedLifecycleStartupError.existingStore() }
            try await connection.stop()
        }
        func requireExit() async throws {
            try await ManagedLifecycleAdministrativeShutdown.requireExit(published.record.process, milliseconds: exitWaitMilliseconds)
        }
        func close() async { connection?.cancel(); await owner?.close(); try? backing.close() }
    }
}
#endif
