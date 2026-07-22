import CEngineCore
import Foundation

/// Stops every VM shim whose durable ownership records belong to one engine root.
/// Uninstall uses this before removing the privileged helper or moving engine data.
public enum VMShimTeardown {
    public static func terminateAll(
        in root: URL,
        expectedExecutable: URL = Bundle.main.executableURL
            ?? URL(filePath: CommandLine.arguments[0]),
        gracePeriodMilliseconds: Int32 = 5_000,
        forceWaitMilliseconds: Int32 = 1_000
    ) async throws -> Int {
        guard let rootDirectory = try PersistentStateDirectory.openIfPresent(root) else {
            return 0
        }

        var containerShims: [VMShimClient] = []
        if let containers = try rootDirectory.openDirectoryIfPresent(named: "containers") {
            for name in try containers.reconciledEntryNames() {
                let directory = try containers.openDirectory(named: name)
                let launches = try VMShimClient.persistedLaunches(
                    in: directory,
                    expectedContainerID: name,
                    expectedExecutable: expectedExecutable
                )
                guard launches.quarantined.isEmpty else {
                    let details = launches.quarantined.map {
                        "\($0.name): \($0.reason)"
                    }.joined(separator: "; ")
                    throw EngineError(
                        .conflict,
                        "cannot safely stop VM shims for container \(name): \(details)"
                    )
                }
                containerShims.append(contentsOf: launches.map(\.client))
            }
        }

        var failures = await terminate(
            containerShims,
            gracePeriodMilliseconds: gracePeriodMilliseconds,
            forceWaitMilliseconds: forceWaitMilliseconds
        )
        var terminatedCount = containerShims.count

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

            let socketExists = FileManager.default.fileExists(
                atPath: specification.socketPath
            )
            let statusExists = FileManager.default.fileExists(
                atPath: specification.socketPath + ".status"
            )
            if socketExists || statusExists {
                let client = VMShimClient(specification: specification)
                do {
                    try await client.terminate(
                        gracePeriodMilliseconds: gracePeriodMilliseconds,
                        forceWaitMilliseconds: forceWaitMilliseconds
                    )
                    terminatedCount += 1
                } catch {
                    failures.append(
                        "infrastructure: \(EngineError.message(for: error))"
                    )
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
