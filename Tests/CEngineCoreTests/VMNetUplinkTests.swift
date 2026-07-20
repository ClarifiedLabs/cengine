#if os(macOS)
import CEngineCore
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import CEngineRuntime

@Suite struct VMNetUplinkTests {
    private final class EventState: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0

        var count: Int { lock.withLock { value } }
        func record() { lock.withLock { value += 1 } }
    }

    private final class CompletionTime: @unchecked Sendable {
        private let lock = NSLock()
        private var value: UInt64?

        func record() { lock.withLock { value = DispatchTime.now().uptimeNanoseconds } }
        func load() -> UInt64? { lock.withLock { value } }
    }

    private final class ReplyBox: @unchecked Sendable {
        private let lock = NSLock()
        private var value: VMNetUplinkReply?

        func store(_ reply: VMNetUplinkReply?) { lock.withLock { value = reply } }
        func load() -> VMNetUplinkReply? { lock.withLock { value } }
    }

    private final class WeakReplyBox: @unchecked Sendable {
        private let lock = NSLock()
        private weak var value: VMNetUplinkReply?

        func store(_ reply: VMNetUplinkReply) { lock.withLock { value = reply } }
        func isReleased() -> Bool { lock.withLock { value == nil } }
    }

    private final class AsyncSignal: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Void, Never>?
        private var isSignalled = false

        func signal() {
            let continuation = lock.withLock { () -> CheckedContinuation<Void, Never>? in
                guard !isSignalled else { return nil }
                isSignalled = true
                let continuation = self.continuation
                self.continuation = nil
                return continuation
            }
            continuation?.resume()
        }

        func wait() async {
            await withCheckedContinuation { continuation in
                let resume = lock.withLock { () -> Bool in
                    if isSignalled { return true }
                    self.continuation = continuation
                    return false
                }
                if resume { continuation.resume() }
            }
        }
    }

    private static func transport(
        connection: xpc_connection_t
    ) throws -> (transport: VMNetUplinkTransport, peer: CInt) {
        var descriptors: [CInt] = [-1, -1]
        guard socketpair(AF_UNIX, CInt(SOCK_DGRAM), 0, &descriptors) == 0 else {
            throw EngineError(.internalError, "could not create VMNet uplink test socket pair")
        }
        return (
            VMNetUplinkTransport(
                descriptor: descriptors[0],
                connection: connection,
                events: VMNetUplinkEvents()
            ),
            descriptors[1]
        )
    }

    private static func connection() -> xpc_connection_t {
        let connection = xpc_connection_create(nil, nil)
        xpc_connection_set_event_handler(connection) { _ in }
        xpc_connection_activate(connection)
        return connection
    }

    private static func waitUntil(
        timeoutNanoseconds: UInt64 = 1_000_000_000,
        _ predicate: () -> Bool
    ) -> Bool {
        let deadline = DispatchTime.now().uptimeNanoseconds + timeoutNanoseconds
        repeat {
            if predicate() { return true }
            usleep(1_000)
        } while DispatchTime.now().uptimeNanoseconds < deadline
        return predicate()
    }

    @Test func vlanTagRoundTripsWithoutChangingEthernetFrame() {
        let frame = Data([0,1,2,3,4,5,6,7,8,9,10,11,0x08,0x00,0x45,0,0,20])
        let tagged = VMNetUplink.tag(frame, vlan: 4094)
        #expect(tagged.count == frame.count + 4)
        #expect(tagged[12] == 0x81)
        #expect(tagged[13] == 0)
        #expect(VMNetUplink.untag(tagged, vlan: 4094) == frame)
        #expect(VMNetUplink.untag(tagged, vlan: 1) == nil)
    }

    @Test func privilegedVMNetRequestRoundTripsAcrossXPCPayload() throws {
        let request = PrivilegedVMNetRequest(
            id: "bridge", vlan: 42, subnet: "172.24.0.0/16", gateway: "172.24.0.1", ipv6Subnet: "fd00:24::/64",
            internalNetwork: false,
            dhcpEnabled: false,
            ports: [.init(proto: "tcp", externalPort: 8080, internalAddress: "172.24.0.2", internalPort: 80)]
        )
        #expect(PrivilegedPortProtocol.version == 4)
        let decoded = try JSONDecoder().decode(PrivilegedVMNetRequest.self, from: JSONEncoder().encode(request))
        #expect(decoded == request)
        #expect(decoded.dhcpEnabled == false)
    }

    @Test func automaticDockerNetworksUseVMNetSupportedPrivateRange() {
        let first = RawVirtualizationBackend.automaticIPv4Network(vlan: 1)
        #expect(first.subnet == "10.240.1.0/24")
        #expect(first.gateway == "10.240.1.1")

        let boundary = RawVirtualizationBackend.automaticIPv4Network(vlan: 256)
        #expect(boundary.subnet == "10.241.0.0/24")
        #expect(boundary.gateway == "10.241.0.1")

        let last = RawVirtualizationBackend.automaticIPv4Network(vlan: 4093)
        #expect(last.subnet == "10.255.253.0/24")
        #expect(last.gateway == "10.255.253.1")
        #expect(RawVirtualizationBackend.nextAvailableVLAN(used: Set(1...4093)) == nil)
    }

    @Test func failedNetworkCreateRollsBackRecordAndVLAN() {
        let network = NetworkRecord(
            id: "network-1",
            name: "rollback",
            subnet: "10.70.0.0/24",
            gateway: "10.70.0.1"
        )
        var networks: [String: NetworkRecord] = [:]
        var vlans: [String: UInt16] = [:]
        let transaction = RawNetworkStateTransaction(
            adding: network,
            vlan: 70,
            networks: networks,
            networkVLANs: vlans
        )

        transaction.apply(networks: &networks, networkVLANs: &vlans)
        #expect(networks[network.id]?.name == "rollback")
        #expect(vlans[network.id] == 70)

        // This is the state restoration used when fabric synchronization or
        // persistence throws during RawVirtualizationBackend.createNetwork.
        transaction.rollback(networks: &networks, networkVLANs: &vlans)
        #expect(networks[network.id] == nil)
        #expect(vlans[network.id] == nil)
    }

    @Test func uplinkDisconnectBeforeHandlerIsDeliveredExactlyOnce() {
        let events = VMNetUplinkEvents()
        let state = EventState()

        events.disconnect()
        events.setDisconnectHandler { state.record() }
        events.setDisconnectHandler { state.record() }
        events.disconnect()

        #expect(state.count == 1)
    }

    @Test func intentionalUplinkCancellationSuppressesDisconnect() {
        let events = VMNetUplinkEvents()
        let state = EventState()

        events.setDisconnectHandler { state.record() }
        events.cancel()
        events.disconnect()

        #expect(state.count == 0)
    }

    @Test func unavailablePrivilegedNetworkingHelperHasBoundedDeadline() async throws {
        let started = DispatchTime.now().uptimeNanoseconds
        let completionTime = CompletionTime()
        let completionCount = EventState()
        let cancellationCount = EventState()
        let replyBox = ReplyBox()
        let connection = Self.connection()
        let late = try Self.transport(connection: connection)
        defer { close(late.peer) }
        var timeoutError: EngineError?

        do {
            _ = try await VMNetUplink.awaitUplinkReply(
                timeout: .milliseconds(25),
                completionHook: {
                    completionTime.record()
                    completionCount.record()
                },
                connectionCancellation: {
                    cancellationCount.record()
                    xpc_connection_cancel($0)
                }
            ) { reply in
                replyBox.store(reply)
                reply.attach(connection)
            }
        } catch let error as EngineError {
            timeoutError = error
        } catch {
            Issue.record("unexpected privileged networking timeout error: \(error)")
        }

        let error = try #require(timeoutError)
        #expect(error.code == .unsupported)
        #expect(error.message.contains("timed out waiting for privileged networking helper"))
        let completed = try #require(completionTime.load())
        #expect(completed >= started)
        if completed >= started {
            #expect(completed - started < 1_000_000_000)
        }
        #expect(completionCount.count == 1)
        #expect(cancellationCount.count == 1)

        let reply = try #require(replyBox.load())
        reply.finish(.success(late.transport))
        errno = 0
        #expect(fcntl(late.transport.descriptor, F_GETFD) == -1)
        #expect(errno == EBADF)
        #expect(cancellationCount.count == 1)
        #expect(completionCount.count == 1)
    }

    @Test func successfulUplinkReplyCancelsTimeoutAndWinsConcurrentCancellation() async throws {
        let completionCount = EventState()
        let completionStarted = AsyncSignal()
        let allowCompletion = DispatchSemaphore(value: 0)
        let weakReply = WeakReplyBox()
        let connection = Self.connection()
        let successful = try Self.transport(connection: connection)
        defer {
            close(successful.peer)
            xpc_connection_cancel(connection)
        }

        let task = Task {
            try await VMNetUplink.awaitUplinkReply(
                timeout: .seconds(5),
                completionHook: {
                    completionCount.record()
                    completionStarted.signal()
                    allowCompletion.wait()
                }
            ) { reply in
                weakReply.store(reply)
                reply.attach(connection)
                reply.finish(.success(successful.transport))
            }
        }

        await completionStarted.wait()
        task.cancel()
        allowCompletion.signal()
        let result = try await task.value

        #expect(result.descriptor == successful.transport.descriptor)
        #expect(fcntl(result.descriptor, F_GETFD) >= 0)
        #expect(completionCount.count == 1)
        #expect(Self.waitUntil { weakReply.isReleased() })
        close(result.descriptor)
    }

    @Test func callerCancellationWinsAndDiscardsLateUplinkSuccess() async throws {
        let completionCount = EventState()
        let cancellationCount = EventState()
        let completionTime = CompletionTime()
        let replyBox = ReplyBox()
        let startReached = AsyncSignal()
        let connection = Self.connection()
        let late = try Self.transport(connection: connection)
        defer { close(late.peer) }

        let task = Task {
            try await VMNetUplink.awaitUplinkReply(
                timeout: .seconds(5),
                completionHook: {
                    completionTime.record()
                    completionCount.record()
                },
                connectionCancellation: {
                    cancellationCount.record()
                    xpc_connection_cancel($0)
                }
            ) { reply in
                replyBox.store(reply)
                reply.attach(connection)
                startReached.signal()
            }
        }

        await startReached.wait()
        let cancelledAt = DispatchTime.now().uptimeNanoseconds
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("cancelled privileged networking request unexpectedly succeeded")
        } catch is CancellationError {
        } catch {
            Issue.record("unexpected privileged networking cancellation error: \(error)")
        }

        let completed = try #require(completionTime.load())
        #expect(completed >= cancelledAt)
        if completed >= cancelledAt {
            #expect(completed - cancelledAt < 1_000_000_000)
        }
        #expect(completionCount.count == 1)
        #expect(cancellationCount.count == 1)

        let reply = try #require(replyBox.load())
        reply.finish(.success(late.transport))
        errno = 0
        #expect(fcntl(late.transport.descriptor, F_GETFD) == -1)
        #expect(errno == EBADF)
        #expect(cancellationCount.count == 1)
        #expect(completionCount.count == 1)
    }

    @Test func cancellationBeforeReplyInstallationCompletesExactlyOnce() async throws {
        let ready = AsyncSignal()
        let proceed = AsyncSignal()
        let completionCount = EventState()
        let startCount = EventState()
        let task = Task.detached {
            ready.signal()
            await proceed.wait()
            return try await VMNetUplink.awaitUplinkReply(
                timeout: .seconds(5),
                completionHook: { completionCount.record() }
            ) { _ in
                startCount.record()
            }
        }

        await ready.wait()
        task.cancel()
        proceed.signal()
        do {
            _ = try await task.value
            Issue.record("pre-cancelled privileged networking request unexpectedly succeeded")
        } catch is CancellationError {
        } catch {
            Issue.record("unexpected pre-install cancellation error: \(error)")
        }

        #expect(startCount.count == 0)
        #expect(completionCount.count == 1)
    }
}
#endif
