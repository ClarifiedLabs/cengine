#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Synchronization
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
        // Ownership is registered before the first suspension after connect. A
        // concurrent stop fences admission, closes this connection, and refuses it.
        try await machine.rootFSContentTransfers.prepare(store: store, layers: layers,
            rootDevice: rootDevice, descriptor: connection.fileDescriptor,
            closeConnection: { connection.close() })
    }
}

/// Machine-owned rootfs operations. Cancellation joins actual local I/O workers;
/// it is never a guest drain receipt or proof that VZ has stopped.
@MainActor final class RootFSContentTransfers {
    private var closed = false
    private var active: [UUID: RootFSContentTransfer] = [:]

    var activeCount: Int { active.count }

    func prepare(store: OCIContentStore, layers: [OCIDescriptor], rootDevice: String = "/dev/vda",
                 descriptor: Int32, closeConnection: @escaping @MainActor () -> Void) async throws {
        guard !closed else { closeConnection(); throw CancellationError() }
        let transfer: RootFSContentTransfer
        do {
            transfer = try RootFSContentTransfer(store: store, layers: layers,
                rootDevice: rootDevice, descriptor: descriptor, closeConnection: closeConnection)
        } catch { closeConnection(); throw error }
        let id = UUID()
        active[id] = transfer
        defer { active.removeValue(forKey: id) }
        try await transfer.value()
    }

    func cancel() {
        closed = true
        for transfer in active.values { transfer.cancel() }
    }

    func cancelAndJoin() async {
        cancel()
        // Snapshot across awaits: prepare's continuation may remove its entry.
        let pending = Array(active.values)
        for transfer in pending { await transfer.join() }
        active.removeAll()
    }
}

@MainActor private final class RootFSContentTransfer {
    private let socket: RootFSContentSocket
    private let worker: Task<Void, Error>
    private var closeConnection: (@MainActor () -> Void)?

    init(store: OCIContentStore, layers: [OCIDescriptor], rootDevice: String,
         descriptor: Int32, closeConnection: @escaping @MainActor () -> Void) throws {
        let socket = try RootFSContentSocket(descriptor: descriptor)
        self.socket = socket
        self.closeConnection = closeConnection
        worker = Task.detached {
            defer { socket.close() }
            try Task.checkCancellation()
            let request = GuestProtocol.RootFSRequest(rootDevice: rootDevice,
                layers: layers.map { .init(mediaType: $0.mediaType, digest: $0.digest, size: $0.size) })
            let envelope = GuestProtocol.Envelope(operation: "prepare-rootfs", payload: try JSONEncoder().encode(request))
            try await socket.blocking { try socket.file.write(contentsOf: GuestProtocol.encode(envelope)) }
            for descriptor in layers {
                try Task.checkCancellation()
                _ = try descriptor.validated(errorCode: .internalError)
                // OCIContentStore is its own actor. Its existing streaming digest
                // verification is preserved; shutdown wakes any blocked output.
                try await store.copyBlob(descriptor, to: socket.file)
            }
            try await socket.blocking {
                let reply = try GuestProtocol.decode(socket.readFrame())
                guard reply.id == envelope.id else {
                    throw EngineError(.internalError, "rootfs response id does not match request")
                }
                if let failure = reply.error {
                    throw EngineError(.internalError, "rootfs \(failure.code): \(failure.message)")
                }
            }
            try Task.checkCancellation()
        }
    }

    func cancel() { socket.cancel(); worker.cancel() }

    func value() async throws {
        let socket = socket, worker = worker
        do {
            try await withTaskCancellationHandler {
                try await worker.value
                try Task.checkCancellation()
            } onCancel: { socket.cancel(); worker.cancel() }
            await join()
        } catch {
            await join()
            throw error
        }
    }

    func join() async {
        _ = await worker.result
        let close = closeConnection
        closeConnection = nil
        close?()
    }
}

/// The duplicate is created synchronously, before dispatch, and closed only by
/// the joined worker. The mutex prevents cancellation from touching a reused FD.
private final class RootFSContentSocket: @unchecked Sendable {
    let file: FileHandle
    private let descriptor: Int32
    private let closed = Mutex(false)

    init(descriptor: Int32) throws {
        let owned = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard owned >= 0 else { throw EngineError(.internalError, "rootfs connection duplication failed") }
        var enabled: Int32 = 1
        guard setsockopt(owned, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                         socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            Darwin.close(owned)
            throw EngineError(.internalError, "rootfs connection configuration failed")
        }
        self.descriptor = owned
        file = FileHandle(fileDescriptor: owned, closeOnDealloc: false)
    }

    deinit { close() }

    func cancel() {
        closed.withLock { if !$0 { _ = Darwin.shutdown(descriptor, SHUT_RDWR) } }
    }

    func close() {
        closed.withLock {
            guard !$0 else { return }
            $0 = true
            try? file.close()
        }
    }

    func blocking(_ operation: @escaping @Sendable () throws -> Void) async throws {
        try await withCheckedThrowingContinuation { continuation in
            Thread.detachNewThread {
                do { try operation(); continuation.resume() }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    func readFrame() throws -> Data {
        let prefix = try readExactly(count: 4)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= GuestProtocol.maximumControlFrameSize else {
            throw EngineError(.badRequest, "invalid rootfs response frame size \(size)")
        }
        return prefix + (try readExactly(count: Int(size)))
    }

    private func readExactly(count: Int) throws -> Data {
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
