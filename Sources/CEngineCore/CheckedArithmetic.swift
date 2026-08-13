import Foundation

public enum CheckedArithmeticError: Error, Equatable, LocalizedError, Sendable {
    case conversion
    case addition
    case multiplication
    case invalidDivisor
    case invalidAlignment

    public var errorDescription: String? {
        switch self {
        case .conversion: "integer conversion is out of range"
        case .addition: "integer addition overflowed"
        case .multiplication: "integer multiplication overflowed"
        case .invalidDivisor: "ceiling division requires a nonnegative value and a positive divisor"
        case .invalidAlignment: "alignment requires a nonnegative value and a positive alignment"
        }
    }
}

/// Exact integer operations for values that cross Docker, OCI, archive, or
/// persisted-state trust boundaries. Callers map failures to their protocol's
/// error class instead of relying on traps, wrapping arithmetic, or clamping.
public enum CheckedArithmetic {
    public static func exact<Source: BinaryInteger, Destination: FixedWidthInteger>(
        _ value: Source,
        as: Destination.Type = Destination.self
    ) throws -> Destination {
        guard let result = Destination(exactly: value) else {
            throw CheckedArithmeticError.conversion
        }
        return result
    }

    public static func add<Value: FixedWidthInteger>(_ lhs: Value, _ rhs: Value) throws -> Value {
        let (result, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow else { throw CheckedArithmeticError.addition }
        return result
    }

    public static func multiply<Value: FixedWidthInteger>(_ lhs: Value, _ rhs: Value) throws -> Value {
        let (result, overflow) = lhs.multipliedReportingOverflow(by: rhs)
        guard !overflow else { throw CheckedArithmeticError.multiplication }
        return result
    }

    /// Addition-free ceiling division. Negative dividends are rejected so the
    /// operation has one unambiguous quota/accounting meaning for signed and
    /// unsigned integers.
    public static func ceilingDivide<Value: FixedWidthInteger>(
        _ value: Value,
        by divisor: Value
    ) throws -> Value {
        guard value >= 0, divisor > 0 else { throw CheckedArithmeticError.invalidDivisor }
        let quotient = value / divisor
        guard value % divisor != 0 else { return quotient }
        return try add(quotient, 1)
    }

    public static func alignedUp<Value: FixedWidthInteger>(
        _ value: Value,
        to alignment: Value
    ) throws -> Value {
        guard value >= 0, alignment > 0 else { throw CheckedArithmeticError.invalidAlignment }
        let remainder = value % alignment
        guard remainder != 0 else { return value }
        return try add(value, alignment - remainder)
    }

    public static func alignedToTarBlock(_ value: UInt64) throws -> UInt64 {
        try alignedUp(value, to: 512)
    }
}
