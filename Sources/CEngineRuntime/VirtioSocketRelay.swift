#if os(macOS)
import Foundation
@preconcurrency import Virtualization

@MainActor public final class VirtioSocketRelay: NSObject, @preconcurrency VZVirtioSocketListenerDelegate {
    public typealias TargetConnector = @MainActor () async throws -> VZVirtioSocketConnection

    public let listener: VZVirtioSocketListener
    private let connectTarget: TargetConnector
    private var active: [UUID: DescriptorRelay] = [:]

    public init(connectTarget: @escaping TargetConnector) {
        self.connectTarget = connectTarget
        listener = VZVirtioSocketListener()
        super.init()
        listener.delegate = self
    }

    public func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        let identifier = UUID()
        let accepted = RelayVirtioSocketConnection(connection)
        Task { @MainActor [weak self] in
            guard let self else { accepted.connection.close(); return }
            do {
                let target = try await connectTarget()
                let relay = DescriptorRelay(source: accepted.connection, target: target) { [weak self] in
                    Task { @MainActor in self?.active.removeValue(forKey: identifier) }
                }
                active[identifier] = relay
                relay.start()
            } catch {
                accepted.connection.close()
            }
        }
        return true
    }
}

private final class RelayVirtioSocketConnection: @unchecked Sendable {
    let connection: VZVirtioSocketConnection

    init(_ connection: VZVirtioSocketConnection) {
        self.connection = connection
    }
}

private final class DescriptorRelay: @unchecked Sendable {
    private let sourceConnection: VZVirtioSocketConnection
    private let targetConnection: VZVirtioSocketConnection
    private let source: FileHandle
    private let target: FileHandle
    private let completion: @Sendable () -> Void
    private let lock = NSLock()
    private var finished = false

    init(
        source: VZVirtioSocketConnection,
        target: VZVirtioSocketConnection,
        completion: @escaping @Sendable () -> Void
    ) {
        sourceConnection = source
        targetConnection = target
        self.source = FileHandle(fileDescriptor: source.fileDescriptor, closeOnDealloc: false)
        self.target = FileHandle(fileDescriptor: target.fileDescriptor, closeOnDealloc: false)
        self.completion = completion
    }

    func start() {
        source.readabilityHandler = { [weak self] handle in self?.forward(from: handle, to: self?.target) }
        target.readabilityHandler = { [weak self] handle in self?.forward(from: handle, to: self?.source) }
    }

    private func forward(from source: FileHandle, to target: FileHandle?) {
        guard let target else { finish(); return }
        let data = source.availableData
        guard !data.isEmpty else { finish(); return }
        do { try target.write(contentsOf: data) }
        catch { finish() }
    }

    private func finish() {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        source.readabilityHandler = nil
        target.readabilityHandler = nil
        sourceConnection.close()
        targetConnection.close()
        lock.unlock()
        completion()
    }
}
#endif
