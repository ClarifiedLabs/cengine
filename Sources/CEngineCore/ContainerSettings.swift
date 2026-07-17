import Foundation

public struct ContainerSettings: Codable, Equatable, Sendable {
    public static let `default` = ContainerSettings(cpus: 4, memoryGiB: 1)
    public static let fileName = "container-settings.json"

    public var cpus: Int
    public var memoryGiB: Int

    public init(cpus: Int, memoryGiB: Int) {
        self.cpus = cpus
        self.memoryGiB = memoryGiB
    }

    public var memoryBytes: UInt64 { UInt64(memoryGiB) * 1_024 * 1_024 * 1_024 }

    public func validate(
        maximumCPUs: Int = ProcessInfo.processInfo.activeProcessorCount,
        maximumMemoryGiB: Int = VirtualMachineMemory.maximumHardLimitGiB(
            maximumCapacityBytes: ProcessInfo.processInfo.physicalMemory
        )
    ) throws {
        guard (1...maximumCPUs).contains(cpus) else {
            throw EngineError(.badRequest, "container CPUs must be between 1 and \(maximumCPUs)")
        }
        guard (1...maximumMemoryGiB).contains(memoryGiB) else {
            throw EngineError(.badRequest, "container memory must be between 1 and \(maximumMemoryGiB) GiB")
        }
    }

    public static func load(from url: URL) throws -> ContainerSettings {
        guard FileManager.default.fileExists(atPath: url.path) else { return .default }
        let settings = try JSONDecoder().decode(ContainerSettings.self, from: Data(contentsOf: url))
        try settings.validate()
        return settings
    }

    public func save(to url: URL) throws {
        try validate()
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: url, options: .atomic)
    }
}

public struct ContainerResourceOverride: Codable, Equatable, Sendable {
    public var cpus: Int?
    public var memoryGiB: Int?

    public init(cpus: Int? = nil, memoryGiB: Int? = nil) {
        self.cpus = cpus
        self.memoryGiB = memoryGiB
    }

    public var memoryBytes: UInt64? {
        memoryGiB.map { UInt64($0) * 1_024 * 1_024 * 1_024 }
    }

    public func validate(
        maximumCPUs: Int = ProcessInfo.processInfo.activeProcessorCount,
        maximumMemoryGiB: Int = VirtualMachineMemory.maximumHardLimitGiB(
            maximumCapacityBytes: ProcessInfo.processInfo.physicalMemory
        )
    ) throws {
        guard cpus != nil || memoryGiB != nil else {
            throw EngineError(.badRequest, "at least one container resource override is required")
        }
        if let cpus, !(1...maximumCPUs).contains(cpus) {
            throw EngineError(.badRequest, "container CPUs must be between 1 and \(maximumCPUs)")
        }
        if let memoryGiB, !(1...maximumMemoryGiB).contains(memoryGiB) {
            throw EngineError(.badRequest, "container memory must be between 1 and \(maximumMemoryGiB) GiB")
        }
    }
}
