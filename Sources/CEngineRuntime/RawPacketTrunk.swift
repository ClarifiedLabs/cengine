#if os(macOS)
import Darwin
import Foundation

public final class RawPacketTrunk: @unchecked Sendable {
    public let virtualMachineFileHandle: FileHandle
    public let fabricFileHandle: FileHandle

    public init() throws {
        var descriptors: [Int32] = [-1, -1]
        guard Darwin.socketpair(AF_UNIX, SOCK_DGRAM, 0, &descriptors) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        virtualMachineFileHandle = FileHandle(fileDescriptor: descriptors[0], closeOnDealloc: true)
        fabricFileHandle = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: true)
    }
}
#endif
