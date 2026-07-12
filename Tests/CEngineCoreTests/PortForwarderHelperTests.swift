import CEngineCore
import Darwin
import Foundation
import NIOCore
import Testing
@testable import CEngineRuntime

@Suite struct PortForwarderHelperTests {
    private struct ChannelFactoryFailure: Error {}

    @Test func helperDescriptorIsNotClosedWhenChannelFactoryFails() async throws {
        let forwarder = PortForwarder()
        var pair: [CInt] = [-1, -1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        let descriptor = pair[0]
        defer { close(pair[0]); close(pair[1]) }
        let binding = PortBinding(hostIP: "127.0.0.1", hostPort: 80, containerPort: 8080, proto: "tcp")

        await #expect(throws: ChannelFactoryFailure.self) {
            _ = try await forwarder.helperBoundChannel(
                binding: binding, transport: .tcp,
                ioError: IOError(errnoCode: EACCES, reason: "bind"),
                bind: { _ in descriptor }
            ) { _ in throw ChannelFactoryFailure() }
        }
        // The channel factory (NIO) owns the descriptor once invoked and closes it on
        // its own failure paths; a second close here could kill an unrelated, reused fd.
        #expect(fcntl(descriptor, F_GETFD) != -1)
    }

    @Test func unrelatedBindErrorsRethrowWithoutContactingHelper() async throws {
        let forwarder = PortForwarder()
        let binding = PortBinding(hostIP: "127.0.0.1", hostPort: 80, containerPort: 8080, proto: "tcp")

        do {
            _ = try await forwarder.helperBoundChannel(
                binding: binding, transport: .udp,
                ioError: IOError(errnoCode: EADDRINUSE, reason: "bind"),
                bind: { _ in
                    Issue.record("helper must not be contacted for non-permission errors")
                    throw ChannelFactoryFailure()
                }
            ) { _ in throw ChannelFactoryFailure() }
            Issue.record("expected the original bind error to be rethrown")
        } catch let error as IOError {
            #expect(error.errnoCode == EADDRINUSE)
        }
    }
}
