import Foundation

public struct BuilderSettings: Codable, Equatable, Sendable {
    public static var `default`: BuilderSettings {
        recommended(
            hostCPUs: ProcessInfo.processInfo.activeProcessorCount,
            hostMemoryBytes: ProcessInfo.processInfo.physicalMemory
        )
    }

    public var cpus: Int
    public var memoryGiB: Int

    public init(cpus: Int, memoryGiB: Int) {
        self.cpus = cpus
        self.memoryGiB = memoryGiB
    }

    public var memoryBytes: UInt64 { UInt64(memoryGiB) * 1_024 * 1_024 * 1_024 }

    public static func recommended(hostCPUs: Int, hostMemoryBytes: UInt64) -> BuilderSettings {
        let cpus = min(max(hostCPUs, 1), min(8, max(4, hostCPUs / 2)))
        let hostMemoryGiB = Int(hostMemoryBytes / VirtualMachineMemory.gibibyte)
        let desiredMemoryGiB = hostMemoryGiB >= 24 ? 8 : (hostMemoryGiB >= 16 ? 6 : 4)
        let maximumMemoryGiB = VirtualMachineMemory.maximumHardLimitGiB(
            maximumCapacityBytes: hostMemoryBytes
        )
        return BuilderSettings(cpus: cpus, memoryGiB: min(desiredMemoryGiB, maximumMemoryGiB))
    }

    public func validate(
        maximumCPUs: Int = ProcessInfo.processInfo.activeProcessorCount,
        maximumMemoryGiB: Int = VirtualMachineMemory.maximumHardLimitGiB(
            maximumCapacityBytes: ProcessInfo.processInfo.physicalMemory
        )
    ) throws {
        guard (1...maximumCPUs).contains(cpus) else {
            throw EngineError(.badRequest, "builder CPUs must be between 1 and \(maximumCPUs)")
        }
        guard (1...maximumMemoryGiB).contains(memoryGiB) else {
            throw EngineError(.badRequest, "builder memory must be between 1 and \(maximumMemoryGiB) GiB")
        }
    }

    public static func load(from url: URL) throws -> BuilderSettings {
        guard FileManager.default.fileExists(atPath: url.path) else { return .default }
        let settings = try JSONDecoder().decode(BuilderSettings.self, from: Data(contentsOf: url))
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
