import Foundation
import Testing
@testable import CEngineCore

@Suite struct GuestProtocolTests {
    @Test func execPayloadUsesCurrentIdentitySecurityContextAndRlimits() throws {
        #expect(GuestProtocol.version == 12)

        let value = GuestProtocol.Exec(
            id: "exec-1", arguments: ["id"], environment: ["A=1"],
            workingDirectory: "/work",
            user: .init(uid: 1_000, gid: 2_000, additionalGroups: [3_000]),
            terminal: false, attachStdin: false, attachStdout: true, attachStderr: true,
            noNewPrivileges: true,
            rlimits: [.init(type: "nofile", soft: 1_024, hard: UInt64.max)],
            ioClaim: "exec-claim"
        )

        let data = try JSONEncoder().encode(value)
        #expect(try JSONDecoder().decode(GuestProtocol.Exec.self, from: data) == value)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let user = try #require(object["user"] as? [String: Any])
        #expect(user["uid"] as? Int == 1_000)
        #expect(object["noNewPrivileges"] as? Bool == true)
        #expect(object["ioClaim"] as? String == "exec-claim")
        let limits = try #require(object["rlimits"] as? [[String: Any]])
        #expect(limits.first?["type"] as? String == "nofile")
        #expect(limits.first?["soft"] as? UInt64 == 1_024)
    }

    @Test func endpointSysctlsRemainAvailableInCurrentGuestProtocol() throws {
        #expect(GuestProtocol.version == 12)
        let endpoint = GuestProtocol.NetworkEndpoint(
            networkID: "network-1",
            vlan: 42,
            name: "eth0",
            macAddress: "02:42:ac:11:00:02",
            addresses: ["192.0.2.2/24"],
            gateways: ["192.0.2.1"],
            dns: ["192.0.2.1"],
            aliases: ["client"],
            sysctls: ["net.ipv4.conf.IFNAME.forwarding=1"]
        )
        let endpointData = try JSONEncoder().encode(endpoint)
        let endpointObject = try #require(
            try JSONSerialization.jsonObject(with: endpointData) as? [String: Any]
        )
        #expect(endpointObject["sysctls"] as? [String] == ["net.ipv4.conf.IFNAME.forwarding=1"])
    }

    @Test func bindMountPayloadCarriesRecursionAndReadOnlyModes() throws {
        let value = GuestProtocol.Mount(
            kind: "bind", source: "bind-0", destination: "/data", readOnly: true,
            propagation: "private", nonRecursive: true, readOnlyNonRecursive: true
        )
        let data = try JSONEncoder().encode(value)

        #expect(try JSONDecoder().decode(GuestProtocol.Mount.self, from: data) == value)
        let object = try #require(
            try JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        #expect(object["nonRecursive"] as? Bool == true)
        #expect(object["readOnlyNonRecursive"] as? Bool == true)
        #expect(object["readOnlyForceRecursive"] as? Bool == false)
    }

    @Test func blockIOThrottleResourcesRoundTripInCurrentProtocol() throws {
        let resources = GuestProtocol.Resources(
            memoryBytes: 64 * 1_024 * 1_024, cpuQuota: 100_000, cpuPeriod: 100_000, pids: 32,
            blockIOReadBps: [.init(path: "/dev/vda", rate: UInt64(Int64.max) + 1)],
            blockIOWriteBps: [.init(path: "/dev/vda", rate: UInt64.max)],
            blockIOReadIOps: [.init(path: "/dev/vda", rate: 100)],
            blockIOWriteIOps: [.init(path: "/dev/vda", rate: 200)]
        )
        let data = try JSONEncoder().encode(resources)
        #expect(try JSONDecoder().decode(GuestProtocol.Resources.self, from: data) == resources)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let readBps = try #require(object["blockIOReadBps"] as? [[String: Any]])
        #expect(readBps.first?["path"] as? String == "/dev/vda")
        #expect((readBps.first?["rate"] as? NSNumber)?.uint64Value == UInt64(Int64.max) + 1)
        let writeBps = try #require(object["blockIOWriteBps"] as? [[String: Any]])
        #expect((writeBps.first?["rate"] as? NSNumber)?.uint64Value == UInt64.max)

        let update = GuestProtocol.ResourceUpdate(
            resources: resources, compatibilityFailureAfterWrites: 4
        )
        let updateData = try JSONEncoder().encode(update)
        #expect(try JSONDecoder().decode(GuestProtocol.ResourceUpdate.self, from: updateData) == update)
    }

    @Test func workloadPayloadCarriesRuntimeAnnotations() throws {
        let value = GuestProtocol.Workload(
            id: "container-1", rootDevice: "/dev/vda", arguments: ["true"],
            environment: [], workingDirectory: "/", hostname: "container-1", user: .init(),
            terminal: false, readOnlyRoot: false,
            maskedPaths: ["/proc/kcore"], readonlyPaths: ["/proc/sys"],
            stopSignal: "SIGTERM", mounts: [], networks: [],
            resources: .init(memoryBytes: 64 * 1_024 * 1_024, cpuQuota: 100_000, cpuPeriod: 100_000, pids: 0),
            annotations: ["io.example.owner": "runtime"],
            capabilityAdd: ["CAP_NET_ADMIN"], capabilityDrop: ["CAP_CHOWN"],
            rlimits: [.init(type: "core", soft: 0, hard: UInt64.max)],
            ipcMode: "none",
            ioClaim: "container-claim"
        )

        let data = try JSONEncoder().encode(value)
        #expect(try JSONDecoder().decode(GuestProtocol.Workload.self, from: data) == value)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["annotations"] as? [String: String] == ["io.example.owner": "runtime"])
        #expect(object["capabilityAdd"] as? [String] == ["CAP_NET_ADMIN"])
        #expect(object["capabilityDrop"] as? [String] == ["CAP_CHOWN"])
        #expect((object["rlimits"] as? [[String: Any]])?.first?["type"] as? String == "core")
        #expect(object["ipcMode"] as? String == "none")
        #expect(object["maskedPaths"] as? [String] == ["/proc/kcore"])
        #expect(object["readonlyPaths"] as? [String] == ["/proc/sys"])
        #expect(object["ioClaim"] as? String == "container-claim")
    }

    @Test func controlEnvelopeRoundTripsWithLengthPrefix() throws {
        let envelope = GuestProtocol.Envelope(id: "request-1", operation: "ping")

        let encoded = try GuestProtocol.encode(envelope)
        let decoded = try GuestProtocol.decode(encoded)

        #expect(decoded == envelope)
    }

    @Test func controlEnvelopeEncodesPayloadAsRawJSONForTheGoGuest() throws {
        let payload = Data(#"{"status":"ready","pid":42}"#.utf8)
        let encoded = try GuestProtocol.encode(.init(id: "request-1", operation: "status", payload: payload))
        let body = try #require(try JSONSerialization.jsonObject(with: encoded.dropFirst(4)) as? [String: Any])
        let embedded = try #require(body["payload"] as? [String: Any])

        #expect(embedded["status"] as? String == "ready")
        #expect(embedded["pid"] as? Int == 42)
        let decoded = try GuestProtocol.decode(encoded)
        let decodedPayload = try #require(decoded.payload)
        let decodedObject = try #require(try JSONSerialization.jsonObject(with: decodedPayload) as? [String: Any])
        #expect(decodedObject["status"] as? String == "ready")
        #expect(decodedObject["pid"] as? Int == 42)
    }

    @Test func controlEnvelopeRejectsUnsupportedVersion() throws {
        let encoded = try GuestProtocol.encode(.init(version: GuestProtocol.version + 1, id: "request-1", operation: "ping"))

        #expect(throws: EngineError.self) {
            try GuestProtocol.decode(encoded)
        }
    }

    @Test func controlEnvelopeRejectsTruncatedFrame() {
        #expect(throws: EngineError.self) {
            try GuestProtocol.decode(Data([0, 0, 0, 2, 0]))
        }
    }
}
