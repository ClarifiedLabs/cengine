#if os(macOS)
import Foundation
import MachO

/// The identity of the code actually mapped into this process. Reading the app's
/// path or Info.plist after an installer replaces it describes the *new* bundle,
/// not a surviving shim. LC_UUID remains part of the old process's mapping.
enum RunningExecutableIdentity {
    static let uuid: UUID? = {
        guard let header = _dyld_get_image_header(0), header.pointee.magic == MH_MAGIC_64 else {
            return nil
        }
        let raw = UnsafeRawPointer(header)
        let imageHeader = raw.load(as: mach_header_64.self)
        let commands = UnsafeRawBufferPointer(
            start: raw.advanced(by: MemoryLayout<mach_header_64>.size),
            count: Int(imageHeader.sizeofcmds)
        )
        return uuid(in: commands, commandCount: imageHeader.ncmds)
    }()

    static func uuid(in commands: UnsafeRawBufferPointer, commandCount: UInt32) -> UUID? {
        var offset = 0
        for _ in 0..<commandCount {
            guard commands.count - offset >= MemoryLayout<load_command>.size else { return nil }
            let command = commands.loadUnaligned(fromByteOffset: offset, as: load_command.self)
            let size = Int(command.cmdsize)
            guard size >= MemoryLayout<load_command>.size, size <= commands.count - offset else {
                return nil
            }
            if command.cmd == LC_UUID {
                guard size == MemoryLayout<uuid_command>.size else { return nil }
                return UUID(uuid: commands.loadUnaligned(fromByteOffset: offset, as: uuid_command.self).uuid)
            }
            offset += size
        }
        return nil
    }
}
#endif
