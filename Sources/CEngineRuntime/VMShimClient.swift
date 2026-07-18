#if os(macOS)
import CEngineCore
import Darwin
import Foundation

public final class VMShimClient: @unchecked Sendable {
    private struct ProcessIdentity: Equatable, Sendable {
        let processIdentifier: CInt
        let startTime: UInt64
    }

    public struct FabricPort: Codable, Hashable, Sendable { public var proto: String; public var externalPort: UInt16; public var internalAddress: String; public var internalPort: UInt16 }
    public struct FabricNetwork: Codable, Hashable, Sendable { public var id: String; public var vlan: UInt16; public var subnet: String; public var gateway: String; public var ipv6Subnet: String; public var internalNetwork: Bool; public var isolated: Bool; public var ports: [FabricPort] }
    public struct GuestCall: Codable, Sendable { public var operation: String; public var payload: Data }
    public struct RootFSRequest: Codable, Sendable { public var contentStorePath: String; public var layers: [OCIDescriptor] }
    public struct ExecStreamRequest: Codable, Sendable { public var id: String }
    public struct PortStreamRequest: Codable, Sendable {
        public var transport: String
        public var port: UInt16
        public var ipv6: Bool

        public init(transport: String, port: UInt16, ipv6: Bool) {
            self.transport = transport
            self.port = port
            self.ipv6 = ipv6
        }
    }

    public let specification: VMShimProtocol.Specification
    private let stateLock = NSLock()
    private let descriptorInvalidationHook: (@Sendable (CInt) -> Void)?
    private let descriptorReleaseHook: (@Sendable (CInt) -> Void)?
    private var acceptsRequests = true
    private var activeDescriptors = Set<CInt>()
    private var processIdentity: ProcessIdentity?

    public init(specification: VMShimProtocol.Specification, processIdentifier: CInt? = nil) {
        self.specification = specification
        descriptorInvalidationHook = nil
        descriptorReleaseHook = nil
        processIdentity = processIdentifier.flatMap(Self.identity(for:))
    }

    init(
        specification: VMShimProtocol.Specification,
        processIdentifier: CInt? = nil,
        descriptorInvalidationHook: @escaping @Sendable (CInt) -> Void,
        descriptorReleaseHook: @escaping @Sendable (CInt) -> Void
    ) {
        self.specification = specification
        self.descriptorInvalidationHook = descriptorInvalidationHook
        self.descriptorReleaseHook = descriptorReleaseHook
        processIdentity = processIdentifier.flatMap(Self.identity(for:))
    }

    public static func launch(specification: VMShimProtocol.Specification, executable: URL = Bundle.main.executableURL ?? URL(filePath: CommandLine.arguments[0])) async throws -> VMShimClient {
        let specURL = specificationURL(for: specification)
        try FileManager.default.createDirectory(at: specURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(specification)
        try data.write(to: specURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: specURL.path)
        let process = Process()
        process.executableURL = executable
        process.arguments = ["vm-shim", "--spec", specURL.path]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = try logHandle(specification.logPath)
        process.standardError = process.standardOutput
        try process.run()
        let client = VMShimClient(
            specification: specification, processIdentifier: process.processIdentifier
        )
        for _ in 0..<200 {
            if (try? await client.status()) != nil { return client }
            try await Task.sleep(for: .milliseconds(25))
        }
        throw EngineError(.internalError, "VM shim did not become ready at \(specification.socketPath)")
    }

    static func specificationURL(for specification: VMShimProtocol.Specification) -> URL {
        URL(filePath: specification.logPath).deletingLastPathComponent().appending(path: "shim.json")
    }

    public func status() async throws -> VMShimProtocol.Status {
        let status = try await request(.status, response: VMShimProtocol.Status.self)
        remember(status)
        return status
    }
    public func boot() async throws -> VMShimProtocol.Status { try await request(.boot, response: VMShimProtocol.Status.self) }
    public func pause() async throws -> VMShimProtocol.Status { try await request(.pause, response: VMShimProtocol.Status.self) }
    public func resume() async throws -> VMShimProtocol.Status { try await request(.resume, response: VMShimProtocol.Status.self) }
    public func stop() async throws -> VMShimProtocol.Status { try await request(.stop, response: VMShimProtocol.Status.self) }
    public func shutdown() async throws -> VMShimProtocol.Status { try await request(.shutdown, response: VMShimProtocol.Status.self) }

    /// Permanently invalidates this client and terminates its exact shim generation.
    /// Existing request sockets are shut down before the bounded shutdown request,
    /// so a timed-out guest call cannot complete after a replacement shim starts.
    func terminate(
        gracePeriodMilliseconds: Int32 = 5_000,
        forceWaitMilliseconds: Int32 = 1_000
    ) async throws {
        let identity = recordedProcessIdentity()
        invalidateRequests()

        let deadline = Self.deadline(afterMilliseconds: gracePeriodMilliseconds)
        let graceful: Bool = await (try? runBlocking { [self] in
            let payload = try requestData(
                .shutdown,
                payloadData: nil,
                allowInvalidated: true,
                deadlineNanoseconds: deadline
            )
            _ = try JSONDecoder().decode(VMShimProtocol.Status.self, from: payload)
            return true
        }) ?? false

        if let identity, graceful,
           Self.waitForExit(identity, timeoutMilliseconds: forceWaitMilliseconds) {
            removeStaleControlFiles()
            return
        }
        guard let identity else {
            guard graceful else {
                throw EngineError(
                    .internalError,
                    "could not identify unresponsive VM shim for container \(specification.containerID)"
                )
            }
            removeStaleControlFiles()
            return
        }
        // Revalidate as close to the destructive syscall as Darwin permits. If
        // the PID now belongs to another process, the original shim is already
        // gone and the replacement must not receive our signal.
        guard Self.identity(for: identity.processIdentifier) == identity else {
            removeStaleControlFiles()
            return
        }
        if Darwin.kill(identity.processIdentifier, SIGKILL) != 0, errno != ESRCH {
            throw EngineError(
                .internalError,
                "could not terminate VM shim \(identity.processIdentifier): \(String(cString: strerror(errno)))"
            )
        }
        guard Self.waitForExit(identity, timeoutMilliseconds: forceWaitMilliseconds) else {
            throw EngineError(
                .internalError,
                "VM shim \(identity.processIdentifier) did not exit after SIGKILL"
            )
        }
        removeStaleControlFiles()
    }

    public func startExecStream(id: String) async throws -> CInt {
        try await upgradedStream(.startExecStream, payload: ExecStreamRequest(id: id))
    }

    public func startPortStream(transport: String, port: UInt16, ipv6: Bool) async throws -> CInt {
        try await upgradedStream(
            .startPortStream,
            payload: PortStreamRequest(transport: transport, port: port, ipv6: ipv6)
        )
    }

    public func guest<Payload: Encodable, Response: Decodable>(operation: String, payload: Payload, response: Response.Type) async throws -> Response {
        let call = GuestCall(operation: operation, payload: try JSONEncoder().encode(payload))
        return try await request(.guest, payload: call, response: response)
    }

    public func prepareRootFS(contentStorePath: String, layers: [OCIDescriptor]) async throws {
        struct Empty: Decodable {}
        _ = try await request(.prepareRootFS, payload: RootFSRequest(contentStorePath: contentStorePath, layers: layers), response: Empty.self)
    }

    public func configureNetwork(vlans: [UInt16]) async throws -> VMShimProtocol.Status {
        struct Configuration: Encodable { let vlans: [UInt16] }
        return try await request(.configureNetwork, payload: Configuration(vlans: vlans), response: VMShimProtocol.Status.self)
    }

    public func configureFabric(networks: [FabricNetwork]) async throws -> VMShimProtocol.Status {
        struct Configuration: Encodable { let networks: [FabricNetwork] }
        return try await request(.configureFabric, payload: Configuration(networks: networks), response: VMShimProtocol.Status.self)
    }

    private func request<Response: Decodable>(_ operation: VMShimProtocol.Operation, response: Response.Type) async throws -> Response {
        try await request(operation, payloadData: nil, response: response)
    }

    private func request<Payload: Encodable, Response: Decodable>(_ operation: VMShimProtocol.Operation, payload: Payload, response: Response.Type) async throws -> Response {
        try await request(operation, payloadData: try JSONEncoder().encode(payload), response: response)
    }

    private func request<Response: Decodable>(_ operation: VMShimProtocol.Operation, payloadData: Data?, response: Response.Type) async throws -> Response {
        let payload = try await runBlocking { [self] in try requestData(operation, payloadData: payloadData) }
        return try JSONDecoder().decode(response, from: payload)
    }

    // Container wait requests can remain blocked for the workload's lifetime. Keep
    // their synchronous socket reads off Swift's cooperative executor so a group
    // of running containers cannot starve unrelated shim operations.
    private func runBlocking<Result: Sendable>(
        _ operation: @escaping @Sendable () throws -> Result
    ) async throws -> Result {
        try await withCheckedThrowingContinuation { continuation in
            Thread.detachNewThread {
                do { continuation.resume(returning: try operation()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    private func requestData(
        _ operation: VMShimProtocol.Operation,
        payloadData: Data?,
        allowInvalidated: Bool = false,
        deadlineNanoseconds: UInt64? = nil
    ) throws -> Data {
        let envelope = VMShimProtocol.Envelope(token: specification.token, operation: operation, payload: payloadData)
        let timeout = deadlineNanoseconds.map { Self.remainingMilliseconds(until: $0) }
        let descriptor = try UnixSocket.connect(
            path: specification.socketPath, timeoutMilliseconds: timeout
        )
        do {
            try register(descriptor, allowInvalidated: allowInvalidated)
        } catch {
            Darwin.close(descriptor)
            throw error
        }
        defer { unregisterAndClose(descriptor) }
        let frame: Data
        if let deadlineNanoseconds {
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                throw EngineError(.internalError, "could not configure VM shim request deadline")
            }
            try Self.writeExactly(
                VMShimProtocol.encode(envelope), to: descriptor, deadlineNanoseconds: deadlineNanoseconds
            )
            frame = try Self.readFrame(from: descriptor, deadlineNanoseconds: deadlineNanoseconds)
        } else {
            let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
            try file.write(contentsOf: VMShimProtocol.encode(envelope))
            frame = try readFrame(file)
        }
        let reply = try VMShimProtocol.decode(frame)
        guard reply.id == envelope.id else { throw EngineError(.internalError, "VM shim response id mismatch") }
        if let failure = reply.error { throw EngineError(.internalError, "VM shim \(failure.code): \(failure.message)") }
        guard let payload = reply.payload else { throw EngineError(.internalError, "VM shim response has no payload") }
        return payload
    }

    private func upgradedStream<Payload: Encodable & Sendable>(
        _ operation: VMShimProtocol.Operation,
        payload: Payload
    ) async throws -> CInt {
        let payloadData = try JSONEncoder().encode(payload)
        return try await runBlocking { [self] in
            try requestUpgradedStream(operation, payloadData: payloadData)
        }
    }

    private func requestUpgradedStream(
        _ operation: VMShimProtocol.Operation,
        payloadData: Data
    ) throws -> CInt {
        let descriptor = try UnixSocket.connect(path: specification.socketPath)
        do {
            try register(descriptor, allowInvalidated: false)
            defer { unregister(descriptor) }
            let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
            let envelope = VMShimProtocol.Envelope(
                token: specification.token,
                operation: operation,
                payload: payloadData
            )
            try file.write(contentsOf: VMShimProtocol.encode(envelope))
            let reply = try VMShimProtocol.decode(try readFrame(file))
            guard reply.id == envelope.id else {
                throw EngineError(.internalError, "VM shim response id mismatch")
            }
            if let failure = reply.error {
                throw EngineError(.internalError, "VM shim \(failure.code): \(failure.message)")
            }
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private func readFrame(_ file: FileHandle) throws -> Data {
        let prefix = try readExactly(file, count: 4)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= VMShimProtocol.maximumFrameSize else { throw EngineError(.badRequest, "invalid VM shim frame") }
        return prefix + (try readExactly(file, count: Int(size)))
    }

    private func readExactly(_ file: FileHandle, count: Int) throws -> Data {
        var data = Data()
        while data.count < count {
            guard let next = try file.read(upToCount: count - data.count), !next.isEmpty else { throw EngineError(.internalError, "VM shim closed connection") }
            data.append(next)
        }
        return data
    }

    private func register(_ descriptor: CInt, allowInvalidated: Bool) throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard acceptsRequests || allowInvalidated else {
            throw EngineError(.conflict, "VM shim client is being terminated")
        }
        activeDescriptors.insert(descriptor)
    }

    private func unregister(_ descriptor: CInt) {
        stateLock.lock()
        activeDescriptors.remove(descriptor)
        stateLock.unlock()
    }

    private func unregisterAndClose(_ descriptor: CInt) {
        descriptorReleaseHook?(descriptor)
        stateLock.lock()
        activeDescriptors.remove(descriptor)
        Darwin.close(descriptor)
        stateLock.unlock()
    }

    /// Stops new requests and shuts down every descriptor while the registry
    /// lock still owns its lifetime. Request cleanup must unregister before its
    /// FileHandle can close the descriptor, so the integer cannot be recycled
    /// between selection and shutdown.
    func invalidateRequests() {
        stateLock.lock()
        acceptsRequests = false
        for descriptor in activeDescriptors {
            descriptorInvalidationHook?(descriptor)
            _ = Darwin.shutdown(descriptor, SHUT_RDWR)
        }
        stateLock.unlock()
    }

    private func remember(_ status: VMShimProtocol.Status) {
        guard status.containerID == specification.containerID,
              status.generation == specification.generation,
              let startTime = status.processStartTime else { return }
        let identity = ProcessIdentity(
            processIdentifier: status.processIdentifier,
            startTime: startTime
        )
        guard Self.identity(for: status.processIdentifier) == identity else { return }
        stateLock.lock()
        processIdentity = identity
        stateLock.unlock()
    }

    private func recordedProcessIdentity() -> ProcessIdentity? {
        stateLock.lock()
        let knownIdentity = processIdentity
        stateLock.unlock()
        if let knownIdentity, Self.identity(for: knownIdentity.processIdentifier) == knownIdentity {
            return knownIdentity
        }

        let statusURL = URL(filePath: specification.socketPath + ".status")
        if let data = try? Data(contentsOf: statusURL),
           let status = try? JSONDecoder().decode(VMShimProtocol.Status.self, from: data),
           status.containerID == specification.containerID,
           status.generation == specification.generation,
           status.processIdentifier > 1,
           status.processStartTime != nil {
            remember(status)
        }
        stateLock.lock()
        let identity = processIdentity
        stateLock.unlock()
        guard let identity, Self.identity(for: identity.processIdentifier) == identity else { return nil }
        return identity
    }

    private func removeStaleControlFiles() {
        try? FileManager.default.removeItem(atPath: specification.socketPath)
        try? FileManager.default.removeItem(atPath: specification.socketPath + ".status")
    }

    private static func deadline(afterMilliseconds milliseconds: Int32) -> UInt64 {
        DispatchTime.now().uptimeNanoseconds
            &+ UInt64(max(0, milliseconds)) * 1_000_000
    }

    private static func remainingMilliseconds(until deadline: UInt64) -> Int32 {
        let now = DispatchTime.now().uptimeNanoseconds
        guard deadline > now else { return 0 }
        let roundedUp = (deadline - now + 999_999) / 1_000_000
        return Int32(min(roundedUp, UInt64(Int32.max)))
    }

    private static func waitForExit(
        _ identity: ProcessIdentity,
        timeoutMilliseconds: Int32
    ) -> Bool {
        let deadline = deadline(afterMilliseconds: timeoutMilliseconds)
        while Self.identity(for: identity.processIdentifier) == identity {
            if remainingMilliseconds(until: deadline) == 0 { return false }
            usleep(10_000)
        }
        return true
    }

    static func processStartTime(for processIdentifier: CInt) -> UInt64? {
        identity(for: processIdentifier)?.startTime
    }

    private static func identity(for processIdentifier: CInt) -> ProcessIdentity? {
        guard processIdentifier > 1 else { return nil }
        var information = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(
            processIdentifier,
            PROC_PIDTBSDINFO,
            0,
            &information,
            size
        ) == size,
        information.pbi_start_tvsec >= 0,
        information.pbi_start_tvusec >= 0 else { return nil }
        let seconds = UInt64(information.pbi_start_tvsec)
        let microseconds = UInt64(information.pbi_start_tvusec)
        return ProcessIdentity(
            processIdentifier: processIdentifier,
            startTime: seconds &* 1_000_000 &+ microseconds
        )
    }

    private static func wait(
        for events: Int16, descriptor: CInt, deadlineNanoseconds: UInt64
    ) throws {
        var event = pollfd(fd: descriptor, events: events, revents: 0)
        while true {
            let timeout = remainingMilliseconds(until: deadlineNanoseconds)
            guard timeout > 0 else { throw AsyncTimeout.TimeoutError() }
            let result = Darwin.poll(&event, 1, timeout)
            if result > 0 { return }
            if result == 0 { throw AsyncTimeout.TimeoutError() }
            if errno != EINTR {
                throw EngineError(
                    .internalError, "VM shim socket poll failed: \(String(cString: strerror(errno)))"
                )
            }
        }
    }

    private static func writeExactly(
        _ data: Data, to descriptor: CInt, deadlineNanoseconds: UInt64
    ) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                try wait(for: Int16(POLLOUT), descriptor: descriptor, deadlineNanoseconds: deadlineNanoseconds)
                let count = Darwin.write(descriptor, base.advanced(by: offset), raw.count - offset)
                if count > 0 { offset += count; continue }
                if count < 0, errno == EINTR || errno == EAGAIN { continue }
                throw EngineError(.internalError, "VM shim socket write failed")
            }
        }
    }

    private static func readExactly(
        from descriptor: CInt, count: Int, deadlineNanoseconds: UInt64
    ) throws -> Data {
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < count {
                try wait(for: Int16(POLLIN), descriptor: descriptor, deadlineNanoseconds: deadlineNanoseconds)
                let received = Darwin.read(descriptor, base.advanced(by: offset), count - offset)
                if received > 0 { offset += received; continue }
                if received < 0, errno == EINTR || errno == EAGAIN { continue }
                throw EngineError(.internalError, "VM shim closed connection")
            }
        }
        return data
    }

    private static func readFrame(from descriptor: CInt, deadlineNanoseconds: UInt64) throws -> Data {
        let prefix = try readExactly(from: descriptor, count: 4, deadlineNanoseconds: deadlineNanoseconds)
        let size = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0, size <= VMShimProtocol.maximumFrameSize else {
            throw EngineError(.badRequest, "invalid VM shim frame")
        }
        return prefix + (try readExactly(
            from: descriptor, count: Int(size), deadlineNanoseconds: deadlineNanoseconds
        ))
    }

    private static func logHandle(_ path: String) throws -> FileHandle {
        FileManager.default.createFile(atPath: path, contents: nil)
        let handle = try FileHandle(forWritingTo: URL(filePath: path))
        try handle.seekToEnd()
        return handle
    }
}
#endif
