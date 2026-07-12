import CEngineCore
import Darwin
import Testing

@Suite struct PrivilegedPortProtocolTests {
    @Test func acceptsDistinctSpecificLowPortAddresses() throws {
        let first = try PrivilegedPortRequest(address: "127.0.0.1", port: 80, transport: .tcp)
        let second = try PrivilegedPortRequest(address: "127.0.0.2", port: 80, transport: .tcp)
        #expect(first != second)
        #expect(first.port == second.port)
    }

    @Test func acceptsIPv6AndUDP() throws {
        let value = try PrivilegedPortRequest(address: "::1", port: 443, transport: .udp)
        #expect(value.address == "::1")
        #expect(value.transport == .udp)
    }

    @Test(arguments: ["", "0.0.0.0", "::", "0:0:0:0:0:0:0:0", "::0"])
    func rejectsWildcardAddresses(_ address: String) {
        #expect(throws: EngineError.self) {
            _ = try PrivilegedPortRequest(address: address, port: 80, transport: .tcp)
        }
    }

    @Test(arguments: [
        ("2001:DB8::1", "2001:db8::1"),
        ("0:0:0:0:0:0:0:1", "::1"),
        ("2001:db8:0:0:0:0:2:1", "2001:db8::2:1"),
        ("fe80:0000:0000:0000:0000:0000:0000:0001", "fe80::1"),
        ("127.0.0.1", "127.0.0.1"),
    ])
    func canonicalizesHostAddresses(_ raw: String, _ canonical: String) throws {
        let request = try PrivilegedPortRequest(address: raw, port: 80, transport: .tcp)
        #expect(request.address == canonical)
        #expect(PrivilegedPortRequest.canonicalized(raw) == canonical)
    }

    @Test(arguments: ["localhost", "2001:db8::g", "256.0.0.1", "127.0.0.1:80"])
    func canonicalizedRejectsNonAddresses(_ value: String) {
        #expect(PrivilegedPortRequest.canonicalized(value) == nil)
    }

    @Test(arguments: [UInt16(0), 1024, 65_535])
    func rejectsNonPrivilegedPorts(_ port: UInt16) {
        #expect(throws: EngineError.self) {
            _ = try PrivilegedPortRequest(address: "127.0.0.1", port: port, transport: .tcp)
        }
    }

    @Test func rejectsHostnames() {
        #expect(throws: EngineError.self) {
            _ = try PrivilegedPortRequest(address: "localhost", port: 80, transport: .tcp)
        }
    }

    @Test func exactLowPortPermissionErrorsUseHelper() {
        #expect(PrivilegedPortRequest.shouldUseHelper(errnoCode: EPERM, address: "127.0.0.1", port: 80))
        #expect(PrivilegedPortRequest.shouldUseHelper(errnoCode: EACCES, address: "127.0.0.2", port: 443))
    }

    @Test func unrelatedBindFailuresDoNotUseHelper() {
        #expect(!PrivilegedPortRequest.shouldUseHelper(errnoCode: EADDRINUSE, address: "127.0.0.1", port: 80))
        #expect(!PrivilegedPortRequest.shouldUseHelper(errnoCode: EPERM, address: "0.0.0.0", port: 80))
        #expect(!PrivilegedPortRequest.shouldUseHelper(errnoCode: EPERM, address: "127.0.0.1", port: 1024))
    }
}
