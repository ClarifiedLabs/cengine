import CEngineCore
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageBootstrapHelper

@Suite struct StorageOwnerStatusTests {
    private func directory(_ body: (URL, Int32) throws -> Void) throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(chmod(url.path, 0o755) == 0)
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        try #require(fd >= 0)
        defer { close(fd) }
        try body(url, fd)
    }
    private func request() -> xpc_object_t {
        let value = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(value, "operation", StorageOwnerStatusProtocol.operation)
        xpc_dictionary_set_int64(value, "version", StorageOwnerStatusProtocol.version)
        return value
    }
    private func reply(_ state: StorageOwnerStatus) throws -> xpc_object_t {
        let value = xpc_dictionary_create(nil, nil, 0)
        try StorageOwnerStatusProtocol.encode(state, into: value)
        return value
    }
    @Test func allStatesAreReadOnlySnapshots() throws {
        try directory { (url, fd) throws in
            func snapshot() throws -> [String: Data] {
                try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(atPath: url.path).map {
                    ($0, try Data(contentsOf: url.appendingPathComponent($0)))
                })
            }
            #expect(try StorageLifecycleOwnerEnrollment.status(parent: fd, owner: geteuid()) == .absent)
            #expect(try snapshot().isEmpty)
            for state in [StorageOwnerStatus.enrolled(501), .disabled, .enrolled(502)] {
                switch state {
                case .enrolled(let uid): try StorageLifecycleOwnerEnrollment.enroll(uid, parent: fd, owner: geteuid(), sync: { _ in })
                default: try StorageLifecycleOwnerEnrollment.unenroll(parent: fd, owner: geteuid(), sync: { _ in })
                }
                let before = try snapshot()
                for _ in 0..<3 { #expect(try StorageLifecycleOwnerEnrollment.status(parent: fd, owner: geteuid()) == state) }
                #expect(try snapshot() == before)
            }
            #expect(StorageBootstrapLifecycleRouter.existingProductionRouter == nil)
        }
    }
    @Test func missingLockExistingRecordAndMalformedUnsafeStateRefuse() throws {
        for bytes in [StorageLifecycleOwnerEnrollment.encode(501), StorageLifecycleOwnerEnrollment.tombstone, Data("broken".utf8)] {
            try directory { (url, fd) throws in
                let file = url.appendingPathComponent("storage-owner")
                try bytes.write(to: file); #expect(chmod(file.path, 0o600) == 0)
                #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.status(parent: fd, owner: geteuid()) }
                #expect(try Data(contentsOf: file) == bytes)
                #expect(try FileManager.default.contentsOfDirectory(atPath: url.path) == ["storage-owner"])
            }
        }
        for target in ["storage-owner", "storage-owner.lock"] {
            for unsafe in ["symlink", "mode", "hardlink", "malformed", "acl"] {
                try directory { (url, fd) throws in
                    try StorageLifecycleOwnerEnrollment.enroll(501, parent: fd, owner: geteuid(), sync: { _ in })
                    let path = url.appendingPathComponent(target).path
                    switch unsafe {
                    case "symlink": #expect(unlink(path) == 0); #expect(symlink("/nonexistent", path) == 0)
                    case "mode": #expect(chmod(path, 0o666) == 0)
                    case "hardlink": #expect(link(path, url.appendingPathComponent("alias").path) == 0)
                    case "acl":
                        let chmod = Process()
                        chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
                        chmod.arguments = ["+a", "everyone allow read", path]
                        try chmod.run(); chmod.waitUntilExit()
                        try #require(chmod.terminationStatus == 0)
                    default:
                        if target == "storage-owner.lock" { return }
                        try Data("broken".utf8).write(to: URL(fileURLWithPath: path))
                    }
                    #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.status(parent: fd, owner: geteuid()) }
                }
            }
        }
    }
    @Test func ancestorsAndOwnerAreValidatedAndOnlyENOENTIsAbsent() throws {
        try directory { (url, fd) throws in
            #expect(try StorageLifecycleOwnerEnrollment.statusParent(root: fd, components: ["missing"], owner: geteuid()) == nil)
            #expect(symlink("/nonexistent", url.appendingPathComponent("linked").path) == 0)
            #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.statusParent(root: fd, components: ["linked"], owner: geteuid()) }
            #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.status(parent: fd, owner: geteuid() + 1) }
            #expect(chmod(url.path, 0o777) == 0)
            #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.statusParent(root: fd, components: ["missing"], owner: geteuid()) }
            #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.status(parent: fd, owner: geteuid()) }
        }
    }
    @Test func busyAdministrativeLockIsBounded() throws {
        try directory { (url, fd) throws in
            try StorageLifecycleOwnerEnrollment.enroll(501, parent: fd, owner: geteuid(), sync: { _ in })
            let lock = open(url.appendingPathComponent("storage-owner.lock").path, O_RDONLY)
            try #require(lock >= 0); defer { close(lock) }
            #expect(flock(lock, LOCK_EX | LOCK_NB) == 0)
            #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.status(parent: fd, owner: geteuid()) }
        }
    }
    @Test func strictRequestAndReplyShapes() throws {
        try StorageOwnerStatusProtocol.validateRequest(request())
        for key in ["owner-uid", "path", "namespace", "authentication-token", "profile"] {
            let value = request(); xpc_dictionary_set_string(value, key, "assertion")
            #expect(throws: (any Error).self) { try StorageOwnerStatusProtocol.validateRequest(value) }
        }
        for key in ["operation", "version"] {
            let value = request(); xpc_dictionary_set_bool(value, key, true)
            #expect(throws: (any Error).self) { try StorageOwnerStatusProtocol.validateRequest(value) }
        }
        for state in [StorageOwnerStatus.absent, .disabled, .enrolled(501)] {
            #expect(try StorageOwnerStatusProtocol.decode(reply(state)) == state)
            for key in ["ok", "version", "state", "owner-uid", "namespace"] {
                let value = try reply(state); xpc_dictionary_set_int64(value, key, -1)
                #expect(throws: (any Error).self) { try StorageOwnerStatusProtocol.decode(value) }
            }
        }
        for uid in [UInt64(0), UInt64(UInt32.max) + 1] {
            let value = try reply(.enrolled(501)); xpc_dictionary_set_uint64(value, "owner-uid", uid)
            #expect(throws: (any Error).self) { try StorageOwnerStatusProtocol.decode(value) }
        }
        let value = try reply(.absent); xpc_dictionary_set_string(value, "state", "unavailable")
        #expect(throws: (any Error).self) { try StorageOwnerStatusProtocol.decode(value) }
    }
    @Test func unsignedCallerAndUnsignedHelperCannotReadStatus() throws {
        var token = audit_token_t()
        token.val.1 = geteuid(); token.val.3 = geteuid(); token.val.5 = UInt32(getpid())
        #expect(throws: (any Error).self) { try StorageLifecycleOwnerStatus.authenticate(token: token, team: "ABCDEFGHIJ") }
        let result = xpc_dictionary_create(nil, nil, 0)
        #expect(throws: (any Error).self) { try StorageLifecycleOwnerStatus.handle(request(), reply: result) }
        #expect(xpc_dictionary_get_count(result) == 0)
    }
}
