import Foundation

public enum DockerCPUResources {
    public static let defaultPeriod: Int64 = 100_000
    public static let nanoCPUsPerCPU: Int64 = 1_000_000_000

    public static func resolvedNanoCPUs(
        nanoCPUs: Int64?,
        period: Int64?,
        quota: Int64?
    ) throws -> Int64? {
        if let nanoCPUs, nanoCPUs < 0 {
            throw EngineError(.badRequest, "NanoCpus must not be negative")
        }
        if let period, period < 0 {
            throw EngineError(.badRequest, "CpuPeriod must not be negative")
        }
        if let quota, quota < -1 {
            throw EngineError(.badRequest, "CpuQuota is invalid")
        }
        if let period, period != 0, !(1_000...1_000_000).contains(period) {
            throw EngineError(
                .badRequest,
                "CpuPeriod must be between 1000 and 1000000 microseconds"
            )
        }
        if let quota, quota > 0, quota < 1_000 {
            throw EngineError(.badRequest, "CpuQuota must be at least 1000 microseconds")
        }
        if quota == -1 {
            throw EngineError(.unsupported, "unlimited CpuQuota is not supported")
        }
        if let nanoCPUs, nanoCPUs > 0,
           (period.map { $0 > 0 } ?? false) || (quota.map { $0 > 0 } ?? false) {
            throw EngineError(
                .badRequest,
                "NanoCpus cannot be combined with CpuPeriod or CpuQuota"
            )
        }
        if let period, period > 0, !(quota.map { $0 > 0 } ?? false) {
            throw EngineError(
                .unsupported,
                "CpuPeriod without a positive CpuQuota is not supported"
            )
        }
        if let nanoCPUs, nanoCPUs > 0 { return nanoCPUs }
        guard let quota, quota > 0 else { return nil }
        let selectedPeriod = max(period ?? defaultPeriod, 1)
        do {
            let scaled = try CheckedArithmetic.multiply(quota, nanoCPUsPerCPU)
            return try CheckedArithmetic.ceilingDivide(scaled, by: selectedPeriod)
        } catch {
            throw EngineError(.badRequest, "CPU quota is too large")
        }
    }

    public static func cpuCount(
        nanoCPUs: Int64,
        maximumCPUs: Int = ProcessInfo.processInfo.activeProcessorCount
    ) throws -> Int {
        guard nanoCPUs > 0 else {
            throw EngineError(.badRequest, "NanoCpus must be positive")
        }
        let count: Int
        do {
            let rounded: Int64 = try CheckedArithmetic.ceilingDivide(
                nanoCPUs, by: nanoCPUsPerCPU
            )
            count = try CheckedArithmetic.exact(rounded, as: Int.self)
        } catch {
            throw EngineError(.badRequest, "NanoCpus is too large")
        }
        guard count <= max(maximumCPUs, 1) else {
            throw EngineError(
                .badRequest,
                "requested CPU capacity exceeds the runtime maximum"
            )
        }
        return max(count, 1)
    }

    public static func nanoCPUs(cpuCount: Int) throws -> Int64 {
        guard cpuCount > 0, let count = Int64(exactly: cpuCount) else {
            throw EngineError(.internalError, "persisted CPU count is invalid")
        }
        do { return try CheckedArithmetic.multiply(count, nanoCPUsPerCPU) }
        catch { throw EngineError(.internalError, "persisted CPU count overflows NanoCpus") }
    }

    public static func quota(
        cpuCount: Int,
        period: Int64 = defaultPeriod
    ) throws -> Int64 {
        guard cpuCount > 0, period > 0, let count = Int64(exactly: cpuCount) else {
            throw EngineError(.internalError, "persisted CPU quota inputs are invalid")
        }
        do { return try CheckedArithmetic.multiply(count, period) }
        catch { throw EngineError(.internalError, "persisted CPU quota overflows") }
    }
}
