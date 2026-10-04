import Foundation
import Testing
@testable import CEngineCore

@Suite struct DiskInitializationProtocolTests {
    private let nonce = "11111111-1111-4111-8111-111111111111"
    private let launch = "22222222-2222-4222-8222-222222222222"
    private let ext4 = "33333333-3333-4333-8333-333333333333"
    private let operation = "44444444-4444-4444-8444-444444444444"
    private let size: UInt64 = 32 * 1_024 * 1_024
    private typealias Wire = DiskInitializationProtocol

    private var hello: Wire.Hello {
        .init(kind: "container", guestBootNonce: nonce, disks: [
            .init(ordinal: 0, blockIdentifier: "root", bytes: size),
            .init(ordinal: 1, blockIdentifier: "volume0", bytes: size),
        ])
    }

    private var manifest: Wire.Manifest {
        .init(kind: "container", shimLaunchUUID: launch, guestBootNonce: nonce, disks: [
            .init(ordinal: 0, role: "container-root", action: "initialize-ext4", expectedBytes: size,
                  ext4UUID: ext4, operationUUID: operation),
            .init(ordinal: 1, role: "direct-volume", action: "mount-existing-ext4", expectedBytes: size,
                  volumeName: "example"),
        ])
    }

    private func roundTrip<T: Codable & Equatable>(_ value: T) throws {
        let frame = try Wire.encode(value)
        let count = frame.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        #expect(Int(count) == frame.count - 4)
        #expect(try Wire.decode(T.self, from: Data(frame.dropFirst(4))) == value)
    }

    @Test func exactMessagesRoundTrip() throws {
        try roundTrip(hello)
        try roundTrip(manifest)
        try roundTrip(Wire.Synced(shimLaunchUUID: launch, guestBootNonce: nonce, disks: [
            .init(ordinal: 0, bytes: size, ext4UUID: ext4, operationUUID: operation),
            .init(ordinal: 1, bytes: size, ext4UUID: launch),
        ]))
        try roundTrip(Wire.Commit(shimLaunchUUID: launch, guestBootNonce: nonce))
        for code in ["invalid-peer", "invalid-frame", "invalid-manifest", "disk-mismatch", "disk-operation", "sync", "commit"] {
            try roundTrip(Wire.ErrorFrame(code: code))
            try roundTrip(Wire.ErrorFrame(code: code, ordinal: 0))
        }
        let body = String(decoding: try Wire.encode(manifest).dropFirst(4), as: UTF8.self)
        #expect(!body.contains("null"))
        #expect(Wire.version == 1 && Wire.port == 4_105 && Wire.maxFrame == 65_536)
    }

    @Test func closedJSONRejectsAmbiguousAndMalformedTokens() throws {
        let valid = "{\"version\":1,\"type\":\"hello\",\"kind\":\"container\",\"guestBootNonce\":\"\(nonce)\",\"disks\":[{\"ordinal\":0,\"blockIdentifier\":\"root\",\"bytes\":33554432}]}"
        let invalid = [
            valid + "{}", valid + "null", valid + "x",
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1"),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"ver\\u0073ion\":1"),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"extra\":1"),
            valid.replacingOccurrences(of: "\"ordinal\":0", with: "\"ordinal\":0,\"ordinal\":0"),
            valid.replacingOccurrences(of: "\"ordinal\":0", with: "\"ordinal\":0,\"extra\":0"),
            valid.replacingOccurrences(of: "\"container\"", with: "null"),
            valid.replacingOccurrences(of: "\"container\"", with: "\"\\ud800\""),
            valid.replacingOccurrences(of: "33554432", with: "true"),
            valid.replacingOccurrences(of: "33554432", with: "null"),
            valid.replacingOccurrences(of: "33554432", with: "\"33554432\""),
            valid.replacingOccurrences(of: "33554432", with: "33554432,"),
            String(valid.dropLast()),
        ] + ["-0", "+0", "00", "01", "1.0", "1e0", "1E+0", "NaN", "Infinity", "9223372036854775808", "18446744073709551616"]
            .map { valid.replacingOccurrences(of: "33554432", with: $0) }
        for body in invalid {
            #expect(throws: Wire.ValidationError.self) { try Wire.decode(Wire.Hello.self, from: Data(body.utf8)) }
        }
        var invalidUTF8 = Data(valid.utf8)
        invalidUTF8[invalidUTF8.count - 3] = 0xff
        #expect(throws: Wire.ValidationError.self) { try Wire.decode(Wire.Hello.self, from: invalidUTF8) }
        #expect(try Wire.decode(Wire.Hello.self, from: Data((" \n" + valid + "\t\r").utf8)).disks.count == 1)
    }

    @Test func frameLimitsAndWrongMessageTypeFailClosed() throws {
        let frame = try Wire.encode(hello)
        #expect(throws: Wire.ValidationError.self) { try Wire.decode(Wire.Hello.self, from: frame) }
        #expect(throws: Wire.ValidationError.self) { try Wire.decode(Wire.Manifest.self, from: Data(frame.dropFirst(4))) }
        #expect(throws: Wire.ValidationError.self) { try Wire.decode(Wire.Hello.self, from: Data()) }
        var body = Data(frame.dropFirst(4))
        body.append(Data(repeating: 32, count: Wire.maxFrame - body.count))
        #expect(try Wire.decode(Wire.Hello.self, from: body) == hello)
        body.append(32)
        #expect(throws: Wire.ValidationError.self) { try Wire.decode(Wire.Hello.self, from: body) }
        var wrongVersion = hello
        wrongVersion.version = 2
        #expect(throws: Wire.ValidationError.self) { try Wire.encode(wrongVersion) }
        #expect(throws: Wire.ValidationError.self) { try Wire.encode(Wire.ErrorFrame(code: "raw request content")) }
        #expect(throws: Wire.ValidationError.self) { try Wire.encode(Wire.ErrorFrame(code: "sync", ordinal: 26)) }
    }

    @Test func diskSetAndInitializationPolicyAreClosed() throws {
        var variants: [Wire.Manifest] = []
        func changed(_ mutate: (inout Wire.Manifest) -> Void) {
            var value = manifest
            mutate(&value)
            variants.append(value)
        }
        changed { $0.disks[0].operationUUID = nil }
        changed { $0.disks[0].ext4UUID = nil }
        changed { $0.disks[0].expectedBytes = 4_096 }
        changed { $0.disks[0].expectedBytes += 1 }
        changed { $0.disks[0].expectedBytes = UInt64(Int64.max) + 1 }
        changed { $0.disks[1].operationUUID = operation }
        changed { $0.disks[1].volumeName = nil }
        changed { $0.disks[1].volumeName = "../escape" }
        changed { $0.disks[1].volumeName = "." }
        changed { $0.disks[1].volumeName = "nul\0name" }
        changed { $0.disks[0].volumeName = "forbidden" }
        changed { $0.disks[0].role = "storage-root" }
        changed { $0.disks[0].action = "format" }
        changed { $0.kind = "storage" }
        changed { $0.disks.swapAt(0, 1) }
        changed { $0.disks[1].ordinal = 0 }
        changed { $0.disks = [] }
        changed { $0.disks.append(.init(ordinal: 2, role: "direct-volume", action: "mount-existing-ext4", expectedBytes: size, volumeName: "example")) }
        changed { $0.disks = Array(repeating: $0.disks[0], count: 27) }
        for value in variants {
            #expect(throws: Wire.ValidationError.self) { try Wire.encode(value) }
        }
        var journaled = manifest
        journaled.disks[1].ext4UUID = launch
        try roundTrip(journaled)
        var storage = manifest
        storage.kind = "storage"
        storage.disks = [storage.disks[0]]
        storage.disks[0].role = "storage-root"
        try roundTrip(storage)
    }

    @Test func readOnlyProbeIsStorageOnlyAndCannotClaimFormattingOrSync() throws {
        let disk = Wire.ManifestDisk(ordinal: 0, role: "storage-root", action: "probe-read-only",
            expectedBytes: size, ext4UUID: ext4)
        let probe = Wire.Manifest(kind: "storage", shimLaunchUUID: launch, guestBootNonce: nonce, disks: [disk])
        try roundTrip(probe)
        var invalid = probe
        invalid.disks[0].ext4UUID = nil
        #expect(throws: Wire.ValidationError.self) { try Wire.encode(invalid) }
        invalid = probe; invalid.disks[0].operationUUID = operation
        #expect(throws: Wire.ValidationError.self) { try Wire.encode(invalid) }
        invalid = probe; invalid.kind = "container"; invalid.disks[0].role = "container-root"
        #expect(throws: Wire.ValidationError.self) { try Wire.encode(invalid) }
        var reply = Wire.Synced(shimLaunchUUID: launch, guestBootNonce: nonce, sync: "read-only-no-replay",
            disks: [.init(ordinal: 0, bytes: size, ext4UUID: ext4)])
        try roundTrip(reply)
        reply.disks[0].operationUUID = operation
        #expect(throws: Wire.ValidationError.self) { try Wire.encode(reply) }
        reply.disks[0].operationUUID = nil
        reply.disks.append(.init(ordinal: 1, bytes: size, ext4UUID: launch))
        #expect(throws: Wire.ValidationError.self) { try Wire.encode(reply) }
    }

    @Test func UUIDsAreCanonicalNonzeroAndNullOptionalsAreRejected() throws {
        #expect(Wire.validUUID(nonce))
        for value in ["00000000-0000-0000-0000-000000000000", "ABCDEFAB-1111-4111-8111-111111111111", nonce + " ", "{" + nonce + "}", "", "11111111111141118111111111111111"] {
            #expect(!Wire.validUUID(value))
        }
        let body = String(decoding: try Wire.encode(Wire.ErrorFrame(code: "sync")).dropFirst(4), as: UTF8.self)
        let null = body.replacingOccurrences(of: "\"code\":", with: "\"ordinal\":null,\"code\":")
        #expect(throws: Wire.ValidationError.self) { try Wire.decode(Wire.ErrorFrame.self, from: Data(null.utf8)) }
    }
}
