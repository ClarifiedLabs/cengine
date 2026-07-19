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
    private var leftInputClosed = false
    private var rightInputClosed = false

    init(left: FileHandle, right: FileHandle, close: @escaping @Sendable () -> Void, completion: @escaping @Sendable () -> Void) {
        self.left = left
        self.right = right
        closeAction = close
        self.completion = completion
    }

    func start() {
        startLeftToRight()
        startRightToLeft()
    }

    func start(afterActivationByte expected: UInt8) {
        left.readabilityHandler = { [weak self] source in
            self?.consumeActivation(from: source, expected: expected)
        }
    }

    func startLeftToRight() {
        left.readabilityHandler = { [weak self] in self?.forward(from: $0, to: self?.right, leftToRight: true) }
    }

    func startRightToLeft() {
        right.readabilityHandler = { [weak self] in self?.forward(from: $0, to: self?.left, leftToRight: false) }
    }

    func cancel() { finish() }

    private func consumeActivation(from source: FileHandle, expected: UInt8) {
        var actual: UInt8 = 0
        let count = Darwin.read(source.fileDescriptor, &actual, 1)
        if count < 0, errno == EINTR || errno == EAGAIN { return }
        guard count == 1, actual == expected else { finish(); return }
        source.readabilityHandler = nil
        start()
    }

    private func forward(from source: FileHandle, to target: FileHandle?, leftToRight: Bool) {
        guard let target else { finish(); return }
        let data = source.availableData
        guard !data.isEmpty else {
            halfClose(source: source, target: target, leftToRight: leftToRight)
            return
        }
        do { try target.write(contentsOf: data) } catch { finish() }
    }

    private func halfClose(source: FileHandle, target: FileHandle, leftToRight: Bool) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        if leftToRight {
            guard !leftInputClosed else { lock.unlock(); return }
            leftInputClosed = true
        } else {
            guard !rightInputClosed else { lock.unlock(); return }
            rightInputClosed = true
        }
        source.readabilityHandler = nil
        let bothClosed = leftInputClosed && rightInputClosed
        lock.unlock()

        _ = Darwin.shutdown(target.fileDescriptor, SHUT_WR)
        if bothClosed { finish() }
    }

    private func finish() {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        left.readabilityHandler = nil
        right.readabilityHandler = nil
        lock.unlock()
        closeAction()
        completion()
    }
}
#endif
