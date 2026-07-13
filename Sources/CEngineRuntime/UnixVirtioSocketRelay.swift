#if os(macOS)
import Darwin
import Foundation
@preconcurrency import Virtualization

@MainActor final class UnixVirtioSocketRelay: NSObject, @preconcurrency VZVirtioSocketListenerDelegate {
    private let socketPath: String
    private var active: [UUID: BidirectionalDescriptorRelay] = [:]
    let listener = VZVirtioSocketListener()

    init(socketPath: String) {
        self.socketPath = socketPath
        super.init()
        listener.delegate = self
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        let id = UUID()
        let accepted = SendableVirtioSocketConnection(connection)
        do {
            let descriptor = try UnixSocket.connect(path: socketPath)
            let target = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            let relay = BidirectionalDescriptorRelay(
                left: FileHandle(fileDescriptor: accepted.connection.fileDescriptor, closeOnDealloc: false),
                right: target,
                close: { accepted.connection.close(); try? target.close() },
                completion: { [weak self] in Task { @MainActor in self?.active.removeValue(forKey: id) } }
            )
            active[id] = relay
            relay.start()
            return true
        } catch {
            connection.close()
            return false
        }
    }
}

final class SendableVirtioSocketConnection: @unchecked Sendable {
    let connection: VZVirtioSocketConnection

    init(_ connection: VZVirtioSocketConnection) {
        self.connection = connection
    }
}

final class BidirectionalDescriptorRelay: @unchecked Sendable {
    private let left: FileHandle
    private let right: FileHandle
    private let closeAction: @Sendable () -> Void
    private let completion: @Sendable () -> Void
    private let lock = NSLock()
    private var finished = false

    init(left: FileHandle, right: FileHandle, close: @escaping @Sendable () -> Void, completion: @escaping @Sendable () -> Void) {
        self.left = left
        self.right = right
        closeAction = close
        self.completion = completion
    }

    func start() {
        left.readabilityHandler = { [weak self] in self?.forward(from: $0, to: self?.right) }
        right.readabilityHandler = { [weak self] in self?.forward(from: $0, to: self?.left) }
    }

    private func forward(from source: FileHandle, to target: FileHandle?) {
        guard let target else { finish(); return }
        let data = source.availableData
        guard !data.isEmpty else { finish(); return }
        do { try target.write(contentsOf: data) } catch { finish() }
    }

    private func finish() {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        left.readabilityHandler = nil
        right.readabilityHandler = nil
        closeAction()
        lock.unlock()
        completion()
    }
}
#endif
