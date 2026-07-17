public struct MemoryBalloonPressureState: Sendable, Equatable {
    public enum Action: Sendable, Equatable {
        case none
        case reclaim(generation: UInt64)
        case restore(generation: UInt64)
    }

    public private(set) var isConstrained = false
    public private(set) var generation: UInt64 = 0

    public init() {}

    public mutating func transition(toConstrained constrained: Bool) -> Action {
        guard constrained != isConstrained else { return .none }
        isConstrained = constrained
        generation &+= 1
        return constrained ? .reclaim(generation: generation) : .restore(generation: generation)
    }

    public func isCurrent(generation: UInt64, constrained: Bool) -> Bool {
        self.generation == generation && isConstrained == constrained
    }
}

public enum MemoryBalloonPolicy {
    public static let minimumCushionBytes: UInt64 = 512 * VirtualMachineMemory.mebibyte
    public static let maximumCushionBytes: UInt64 = VirtualMachineMemory.gibibyte

    public static func targetBytes(
        maximumBytes: UInt64,
        availableBytes: UInt64,
        minimumBytes: UInt64
    ) -> UInt64 {
        let proportionalCushion = maximumBytes / 4
        let cushion = min(maximumCushionBytes, max(minimumCushionBytes, proportionalCushion))
        let reclaimable = availableBytes > cushion ? availableBytes - cushion : 0
        let boundedReclaimable = min(reclaimable, maximumBytes)
        let floor = min(minimumBytes, maximumBytes)
        let unrounded = max(floor, maximumBytes - boundedReclaimable)
        let remainder = unrounded % VirtualMachineMemory.mebibyte
        guard remainder != 0 else { return unrounded }
        let increment = VirtualMachineMemory.mebibyte - remainder
        let (rounded, overflow) = unrounded.addingReportingOverflow(increment)
        return overflow ? maximumBytes : min(rounded, maximumBytes)
    }
}
