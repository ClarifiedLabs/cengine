#if os(macOS)
import CEngineCore
import Foundation
import Virtualization

public struct RootFSContentStreamer: Sendable {
    private let store: OCIContentStore

    public init(store: OCIContentStore) { self.store = store }

    @MainActor public func prepare(
        machine: RawContainerVirtualMachine,
        image: OCIStoredImage,
        rootDevice: String = "/dev/vda"
    ) async throws {
        try await prepare(machine: machine, layers: image.manifest.layers, rootDevice: rootDevice)
    }

    @MainActor public func prepare(
        machine: RawContainerVirtualMachine,
        layers: [OCIDescriptor],
        rootDevice: String = "/dev/vda"
    ) async throws {
        let connection = try await machine.connect(toPort: GuestProtocol.rootFSContentPort)
        let file = FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false)
        defer { connection.close() }
        let request = GuestProtocol.RootFSRequest(
            rootDevice: rootDevice,
            layers: layers.map { .init(mediaType: $0.mediaType, digest: $0.digest, size: $0.size) }
        )
        let payload = try JSONEncoder().encode(request)
        let envelope = GuestProtocol.Envelope(operation: "prepare-rootfs", payload: payload)
        try file.write(contentsOf: GuestProtocol.encode(envelope))
        for descriptor in layers {
            let data = try await store.data(for: descriptor.digest)
            guard data.count == descriptor.size else {
                throw EngineError(.internalError, "OCI layer \(descriptor.digest) size mismatch")
            }
            try file.write(contentsOf: data)
        }
        let reply = try GuestProtocol.decode(try readFrame(file))
        guard reply.id == envelope.id else { throw EngineError(.internalError, "rootfs response id does not match request") }
        if let failure = reply.error { throw EngineError(.internalError, "rootfs \(failure.code): \(failure.message)") }
    }

    private func readFrame(_ file: FileHandle) throws -> Data {
        let prefix = try readExactly(file, count: 4)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= GuestProtocol.maximumControlFrameSize else {
            throw EngineError(.badRequest, "invalid rootfs response frame size \(size)")
        }
        return prefix + (try readExactly(file, count: Int(size)))
    }

    private func readExactly(_ file: FileHandle, count: Int) throws -> Data {
        var result = Data()
        while result.count < count {
            guard let data = try file.read(upToCount: count - result.count), !data.isEmpty else {
                throw EngineError(.internalError, "rootfs content connection closed")
            }
            result.append(data)
        }
        return result
    }
}
#endif
