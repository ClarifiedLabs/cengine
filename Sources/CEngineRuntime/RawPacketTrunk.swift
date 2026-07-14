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
        do {
            for descriptor in descriptors {
                var bufferSize: CInt = 4 * 1024 * 1024
                guard setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &bufferSize, socklen_t(MemoryLayout.size(ofValue: bufferSize))) == 0,
                      setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &bufferSize, socklen_t(MemoryLayout.size(ofValue: bufferSize))) == 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
            }
        } catch {
            descriptors.forEach { Darwin.close($0) }
            throw error
        }
        virtualMachineFileHandle = FileHandle(fileDescriptor: descriptors[0], closeOnDealloc: true)
        fabricFileHandle = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: true)
    }
}
#endif
