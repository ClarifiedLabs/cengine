import Foundation

public enum VirtualMachineMemory {
    public static let mebibyte: UInt64 = 1_024 * 1_024
    public static let gibibyte: UInt64 = 1_024 * mebibyte
    public static let minimumContainerCapacityBytes: UInt64 = 256 * mebibyte
    public static let fixedGuestReserveBytes: UInt64 = 64 * mebibyte

    /// Returns the VM capacity required to preserve a Docker hard memory limit
    /// while leaving room for the guest kernel and cengine supervisor.
    public static func capacity(forHardLimit hardLimit: UInt64) throws -> UInt64 {
        let proportional = try roundedUpToMiB(ceilDivide(hardLimit, by: 20))
        let (reserve, reserveOverflow) = fixedGuestReserveBytes.addingReportingOverflow(proportional)
        guard !reserveOverflow else { throw capacityOverflow() }
        let (total, totalOverflow) = hardLimit.addingReportingOverflow(reserve)
        guard !totalOverflow else { throw capacityOverflow() }
        return max(try roundedUpToMiB(total), minimumContainerCapacityBytes)
    }

    /// Largest whole-GiB Docker hard limit whose VM capacity fits within the
    /// supplied host or Virtualization.framework ceiling.
    public static func maximumHardLimitGiB(maximumCapacityBytes: UInt64) -> Int {
        var lower: UInt64 = 0
        var upper = min(maximumCapacityBytes / gibibyte, UInt64(Int.max))
        while lower < upper {
            let value = lower + (upper - lower + 1) / 2
            let hardLimit = value * gibibyte
            if let capacity = try? capacity(forHardLimit: hardLimit), capacity <= maximumCapacityBytes {
                lower = value
            } else {
                upper = value - 1
            }
        }
        return max(1, Int(lower))
    }

    private static func ceilDivide(_ value: UInt64, by divisor: UInt64) -> UInt64 {
        value / divisor + (value % divisor == 0 ? 0 : 1)
    }

    private static func roundedUpToMiB(_ value: UInt64) throws -> UInt64 {
        let remainder = value % mebibyte
        guard remainder != 0 else { return value }
        let (rounded, overflow) = value.addingReportingOverflow(mebibyte - remainder)
        guard !overflow else { throw capacityOverflow() }
        return rounded
    }

    private static func capacityOverflow() -> EngineError {
        EngineError(.badRequest, "container memory limit is too large to provision guest overhead")
    }
}
