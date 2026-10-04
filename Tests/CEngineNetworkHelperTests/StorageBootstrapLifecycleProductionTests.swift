import CEngineCore
import Darwin
import Foundation
import Testing
@testable import StorageBootstrapHelper

private final class ProductionTempDirectory {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let fd: Int32
    init(mode: mode_t = 0o700) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        guard chmod(url.path, mode) == 0 else { throw POSIXError(.EPERM) }
        fd = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw POSIXError(.EIO) }
    }
    deinit { close(fd); try? FileManager.default.removeItem(at: url) }
    func path(_ name: String) -> String { url.appendingPathComponent(name).path }
}

private let noSync: @Sendable (Int32) throws -> Void = { _ in }

@Suite struct StorageBootstrapLifecycleProductionTests {
    @Test func ordinaryRouterRecognizesOnlyV2Envelopes() {
        let v2 = [StorageLifecycleRootProtocol.xpcOperation, StorageBootstrapLifecycleRouter.scopeBindOperation,
                  "storage-lifecycle-child", "storage-lifecycle-fresh-shim", "storage-lifecycle-service-shim"]
        for operation in v2 {
            #expect(StorageBootstrapLifecycleRouter.recognizes(operation))
        }
        // The engine can no longer self-enroll: there is no XPC enrollment route.
        for operation in ["enroll-storage-owner", "unenroll-storage-owner", "storage-bootstrap", "storage-child", "storage-child-confirm", "status", "bind", "start-vmnet", "restart"] {
            #expect(!StorageBootstrapLifecycleRouter.recognizes(operation))
        }
    }

    @Test func unsignedHelperCannotSelectAnOrdinaryOrQualificationRouter() {
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleRouter.ordinaryRouter() }
        #expect(StorageBootstrapLifecycleRouter.existingCompatibilityRouter == nil)
        #expect(StorageBootstrapLifecycleRouter.existingProductionRouter == nil)
        #if CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
        #expect(StorageBootstrapLifecycleQualification.installed == nil)
        #endif
    }

    @Test func namespaceAndOwnerSelectionNeverFallsBack() throws {
        #expect(StorageLifecycleScopeNamespace(.production) == .production)
        #expect(StorageLifecycleScopeNamespace(.compatibility) == .compatibility)
        let key = PrivilegedPortProtocol.ownerUIDEnvironmentKey
        var productionReads = 0
        var enrolled: uid_t = 501
        let readOwner: () throws -> uid_t = { productionReads += 1; return enrolled }
        #expect(try StorageLifecycleScopeNamespace.production.configuredOwner(environment: [key: "502"], productionOwner: readOwner) == 501)
        enrolled = 503
        #expect(try StorageLifecycleScopeNamespace.production.configuredOwner(environment: [:], productionOwner: readOwner) == 503)
        #expect(productionReads == 2)
        #expect(try StorageLifecycleScopeNamespace.compatibility.configuredOwner(environment: [key: "502"], productionOwner: readOwner) == 502)
        for text in [nil, "", "0", "-1", "0502", "+502", "4294967296", "502\n"] as [String?] {
            let environment = text.map { [key: $0] } ?? [:]
            #expect(throws: (any Error).self) {
                try StorageLifecycleScopeNamespace.compatibility.configuredOwner(environment: environment, productionOwner: readOwner)
            }
        }
        #expect(productionReads == 2) // Missing compatibility owner never reads enrollment.
        #expect(throws: (any Error).self) {
            try StorageLifecycleScopeNamespace.production.configuredOwner(environment: [key: "502"],
                productionOwner: { throw BootstrapFailure(.unavailable) })
        }
    }

    @Test func productionListenerAdmitsExactEngineAndControllerRolesOnly() throws {
        let text = try StorageBootstrapLifecycleRouter.productionListenerRequirement(team: "ABCDEFGHIJ")
        #expect(text.contains("\"dev.cengine.engine\""))
        #expect(text.contains("\"dev.cengine.storage-control\""))
        #expect(!text.contains("test-compat") && !text.contains("network-helper"))
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleRouter.productionListenerRequirement(team: "bad") }
    }

    @Test func compatibilityListenerNeverAdmitsProductionRoles() throws {
        let text = try StorageBootstrapAdmission.listenerRequirement(namespace: .compatibility, team: "ABCDEFGHIJ")
        #expect(text.contains("\"dev.cengine.engine.test-compat\""))
        #expect(text.contains("\"dev.cengine.storage-control.test-compat\""))
        #expect(!text.contains("\"dev.cengine.engine\"") && !text.contains("\"dev.cengine.storage-control\""))
        #expect(!text.contains("network-helper"))
        #expect(throws: (any Error).self) { try StorageBootstrapAdmission.listenerRequirement(namespace: .compatibility, team: "bad") }
    }

    @Test func productionAndCompatibilityNamespacesAreIsolated() {
        let production = StorageLifecycleScopeNamespace.production.components
        let compatibility = StorageLifecycleScopeNamespace.compatibility.components
        #expect(production == ["Library", "Application Support", "cengine", "storage-bootstrap"])
        #expect(compatibility == ["Library", "Application Support", "cengine", "compat",
            "dev.cengine.network-helper.test-compat", "storage-lifecycle-v2"])
        #expect(compatibility.contains("compat") && !production.contains("compat"))
        // No versioned production sibling that could bypass an existing authority.
        #expect(!production.contains("v1") && !production.contains("v2") && !production.contains("storage-lifecycle-v2"))
        #expect(!compatibility.starts(with: production) && !production.starts(with: compatibility))
    }

    @Test func bothNamespacesRefuseOldAuthorityBeforeCreatingAnyNewFiles() throws {
        for namespace in [StorageLifecycleScopeNamespace.production, .compatibility] {
            for marker in [nil, "cengine.storage.lifecycle.production.v2\n", "cengine.storage.lifecycle.compatibility.v2\n"] as [String?] {
                let directory = try ProductionTempDirectory()
                let oldScope = String(repeating: "b", count: 64)
                #expect(mkdirat(directory.fd, oldScope, 0o700) == 0)
                let bytes = Data("old scope authority must remain untouched".utf8)
                try bytes.write(to: directory.url.appendingPathComponent(oldScope + "/scope"))
                if let marker {
                    try StorageLifecycleQualificationFiles.write(Data(marker.utf8), parent: directory.fd, name: "format", owner: geteuid(), sync: noSync)
                }
                let before = try StorageLifecycleProductionFormat.entries(directory.fd)
                #expect(throws: (any Error).self) {
                    try StorageLifecycleProductionFormat.require(directory.fd, owner: geteuid(), namespace: namespace, sync: noSync)
                }
                #expect(try StorageLifecycleProductionFormat.entries(directory.fd) == before)
                #expect(try Data(contentsOf: directory.url.appendingPathComponent(oldScope + "/scope")) == bytes)
                #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path(oldScope)) == ["scope"])
            }
            let empty = try ProductionTempDirectory()
            try StorageLifecycleProductionFormat.require(empty.fd, owner: geteuid(), namespace: namespace, sync: noSync)
            try StorageLifecycleProductionFormat.require(empty.fd, owner: geteuid(), namespace: namespace, sync: noSync)
            let other: StorageLifecycleScopeNamespace = namespace == .production ? .compatibility : .production
            #expect(throws: (any Error).self) {
                try StorageLifecycleProductionFormat.require(empty.fd, owner: geteuid(), namespace: other, sync: noSync)
            }
        }
    }

    @Test func emptyProductionNamespaceInitializesFormatThenAcceptsScopes() throws {
        let directory = try ProductionTempDirectory()
        try StorageLifecycleProductionFormat.require(directory.fd, owner: geteuid(), sync: noSync)
        #expect(try StorageLifecycleQualificationFiles.read(directory.fd, "format", owner: geteuid()) == StorageLifecycleProductionFormat.bytes)
        try StorageLifecycleProductionFormat.require(directory.fd, owner: geteuid(), sync: noSync)
        #expect(mkdirat(directory.fd, String(repeating: "a", count: 64), 0o700) == 0)
        try StorageLifecycleProductionFormat.require(directory.fd, owner: geteuid(), sync: noSync)
    }

    @Test func existingV1OrUnknownProductionAuthorityRefusesAndPreservesBytes() throws {
        let legacy = Data("CEBSJ001 legacy v1 production authority bytes".utf8)
        for (name, isDirectory) in [("authority.journal", false), ("authority.lock", false), ("v1", true), ("unexpected", false)] {
            let directory = try ProductionTempDirectory()
            if isDirectory { #expect(mkdirat(directory.fd, name, 0o700) == 0) }
            else { try legacy.write(to: URL(fileURLWithPath: directory.path(name))) }
            #expect(throws: StorageLifecycleUnsupportedFormat(entry: name)) {
                try StorageLifecycleProductionFormat.require(directory.fd, owner: geteuid(), sync: noSync)
            }
            #expect(!FileManager.default.fileExists(atPath: directory.path("format")))
            if !isDirectory { #expect(try Data(contentsOf: URL(fileURLWithPath: directory.path(name))) == legacy) }
            #expect(StorageLifecycleUnsupportedFormat(entry: name).description.contains("unsupported"))
        }
        // A valid marker never legitimizes a coexisting v1 authority.
        let mixed = try ProductionTempDirectory()
        try StorageLifecycleProductionFormat.require(mixed.fd, owner: geteuid(), sync: noSync)
        #expect(mkdirat(mixed.fd, "v1", 0o700) == 0)
        #expect(throws: StorageLifecycleUnsupportedFormat(entry: "v1")) {
            try StorageLifecycleProductionFormat.require(mixed.fd, owner: geteuid(), sync: noSync)
        }
        // A different marker is refused unchanged.
        let wrong = try ProductionTempDirectory()
        let other = Data("cengine.storage.lifecycle.production.v1\n".utf8)
        try StorageLifecycleQualificationFiles.write(other, parent: wrong.fd, name: "format", owner: geteuid(), sync: noSync)
        #expect(throws: StorageLifecycleUnsupportedFormat(entry: "format")) {
            try StorageLifecycleProductionFormat.require(wrong.fd, owner: geteuid(), sync: noSync)
        }
        #expect(try StorageLifecycleQualificationFiles.read(wrong.fd, "format", owner: geteuid()) == other)
    }

    @Test func ownerEnrollsOnceAndRefusesMismatchUntilUnenrolled() throws {
        let directory = try ProductionTempDirectory(mode: 0o755)
        let owner = geteuid()
        #expect(try StorageLifecycleOwnerEnrollment.load(parent: directory.fd, owner: owner) == nil)
        #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.enroll(0, parent: directory.fd, owner: owner, sync: noSync) }
        try StorageLifecycleOwnerEnrollment.enroll(501, parent: directory.fd, owner: owner, sync: noSync)
        try StorageLifecycleOwnerEnrollment.enroll(501, parent: directory.fd, owner: owner, sync: noSync) // idempotent
        #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.enroll(502, parent: directory.fd, owner: owner, sync: noSync) }
        #expect(try StorageLifecycleOwnerEnrollment.load(parent: directory.fd, owner: owner) == 501)
        let attributes = try FileManager.default.attributesOfItem(atPath: directory.path("storage-owner"))
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect(try Data(contentsOf: URL(fileURLWithPath: directory.path("storage-owner"))) == StorageLifecycleOwnerEnrollment.encode(501))
        #expect(try StorageLifecycleOwnerEnrollment.unenroll(parent: directory.fd, owner: owner, sync: noSync))
        #expect(try !StorageLifecycleOwnerEnrollment.unenroll(parent: directory.fd, owner: owner, sync: noSync))
        // Durable tombstone, not a bare unlink.
        #expect(try StorageLifecycleOwnerEnrollment.state(parent: directory.fd, owner: owner) == .disabled)
        #expect(try Data(contentsOf: URL(fileURLWithPath: directory.path("storage-owner"))) == StorageLifecycleOwnerEnrollment.tombstone)
        // Tampered/malformed enrollment refuses instead of being reinterpreted.
        try StorageLifecycleOwnerEnrollment.enroll(502, parent: directory.fd, owner: owner, sync: noSync)
        #expect(try StorageLifecycleOwnerEnrollment.load(parent: directory.fd, owner: owner) == 502)
        let bad = try ProductionTempDirectory(mode: 0o755)
        try StorageLifecycleQualificationFiles.write(Data("cengine.storage.owner.v1\n0\n".utf8), parent: bad.fd,
            name: "storage-owner", owner: owner, sync: noSync)
        #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.load(parent: bad.fd, owner: owner) }
        #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.enroll(501, parent: bad.fd, owner: owner, sync: noSync) }
    }
}

private func adminRun(_ arguments: [String], directory: ProductionTempDirectory, euid: uid_t = 0,
                      userExists: (uid_t) -> Bool = { $0 == 501 || $0 == 502 }) -> StorageLifecycleOwnerAdministration.Outcome {
    StorageLifecycleOwnerAdministration.run(["cengine-helper"] + arguments, euid: euid, userExists: userExists,
        owner: geteuid(), openParent: { dup(directory.fd) }, sync: noSync)
}

/// Root-only administrative enrollment: flock-serialized, tombstoned, never via XPC.
@Suite struct StorageBootstrapLifecycleOwnerAdministrationTests {
    @Test func nonRootAndInvalidUIDsAreRefusedWithoutWrites() throws {
        let directory = try ProductionTempDirectory(mode: 0o755)
        #expect(StorageLifecycleOwnerAdministration.handles(["h", "enroll-storage-owner", "--uid", "501"]))
        #expect(StorageLifecycleOwnerAdministration.handles(["h", "unenroll-storage-owner"]))
        #expect(!StorageLifecycleOwnerAdministration.handles(["h"]) && !StorageLifecycleOwnerAdministration.handles(["h", "status"]))
        #expect(adminRun(["enroll-storage-owner", "--uid", "501"], directory: directory, euid: 501).status == 1)
        #expect(adminRun(["unenroll-storage-owner"], directory: directory, euid: 501).status == 1)
        for bad in ["0", "-1", "+501", "0501", "abc", "", "4294967296", "503"] {
            #expect(adminRun(["enroll-storage-owner", "--uid", bad], directory: directory).status == 1)
        }
        #expect(adminRun(["enroll-storage-owner", "501"], directory: directory).status == 2)
        #expect(adminRun(["enroll-storage-owner", "--uid", "501", "x"], directory: directory).status == 2)
        #expect(adminRun(["unenroll-storage-owner", "--uid", "501"], directory: directory).status == 2)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.url.path).isEmpty)
    }

    @Test func enrollIsIdempotentConflictsAndTombstoneBlocksUntilEnroll() throws {
        let directory = try ProductionTempDirectory(mode: 0o755)
        let owner = geteuid()
        // Helper read before any enrollment: no lock file, refuses without creating state.
        #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.enrolledOwner(parent: directory.fd, owner: owner) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.url.path).isEmpty)
        #expect(adminRun(["enroll-storage-owner", "--uid", "501"], directory: directory) == .init(status: 0, message: "storage owner enrolled: uid 501"))
        #expect(adminRun(["enroll-storage-owner", "--uid", "501"], directory: directory).status == 0)
        let conflict = adminRun(["enroll-storage-owner", "--uid", "502"], directory: directory)
        #expect(conflict.status == 1 && conflict.message.contains("unenroll-storage-owner first"))
        #expect(try StorageLifecycleOwnerEnrollment.enrolledOwner(parent: directory.fd, owner: owner) == 501)
        let lock = try FileManager.default.attributesOfItem(atPath: directory.path("storage-owner.lock"))
        #expect((lock[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect(adminRun(["unenroll-storage-owner"], directory: directory).status == 0)
        // Tombstone: the helper refuses (not cached) until an explicit enroll clears it.
        #expect(throws: (any Error).self) { try StorageLifecycleOwnerEnrollment.enrolledOwner(parent: directory.fd, owner: owner) }
        #expect(adminRun(["unenroll-storage-owner"], directory: directory).status == 0)
        #expect(try StorageLifecycleOwnerEnrollment.state(parent: directory.fd, owner: owner) == .disabled)
        #expect(adminRun(["enroll-storage-owner", "--uid", "502"], directory: directory).status == 0)
        #expect(try StorageLifecycleOwnerEnrollment.enrolledOwner(parent: directory.fd, owner: owner) == 502)
        #expect(!FileManager.default.fileExists(atPath: directory.path("storage-owner.tmp")))
        // A symlinked lock file is refused (O_NOFOLLOW).
        let linked = try ProductionTempDirectory(mode: 0o755)
        #expect(symlink(directory.path("storage-owner.lock"), linked.path("storage-owner.lock")) == 0)
        #expect(adminRun(["enroll-storage-owner", "--uid", "501"], directory: linked).status == 1)
        #expect(!FileManager.default.fileExists(atPath: linked.path("storage-owner")))
    }

    @Test func concurrentAdministrationAndHelperReadsSerializeOnFlock() throws {
        let directory = try ProductionTempDirectory(mode: 0o755)
        let owner = geteuid()
        try StorageLifecycleOwnerEnrollment.enroll(501, parent: directory.fd, owner: owner, sync: noSync)
        // A holder on a SEPARATE open file description blocks enroll and helper reads.
        let held = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = DispatchGroup()
        let fd = directory.fd
        DispatchQueue.global().async {
            _ = try? StorageLifecycleOwnerEnrollment.withLock(parent: fd, owner: owner, exclusive: true) {
                held.signal(); release.wait()
            }
        }
        held.wait()
        let order = NSLock(); nonisolated(unsafe) var events: [String] = []
        for name in ["read", "unenroll"] {
            done.enter()
            DispatchQueue.global().async {
                if name == "read" { _ = try? StorageLifecycleOwnerEnrollment.enrolledOwner(parent: fd, owner: owner) }
                else { _ = try? StorageLifecycleOwnerEnrollment.unenroll(parent: fd, owner: owner, sync: noSync) }
                order.withLock { events.append(name) }
                done.leave()
            }
        }
        Thread.sleep(forTimeInterval: 0.2)
        #expect(order.withLock { events.isEmpty })
        order.withLock { events.append("released") }
        release.signal()
        #expect(done.wait(timeout: .now() + 5) == .success)
        #expect(order.withLock { events.first } == "released")
        // Many racing enroll/unenroll writers never tear or corrupt the record.
        let group = DispatchGroup()
        for index in 0..<32 {
            group.enter()
            DispatchQueue.global().async {
                if index % 2 == 0 { _ = try? StorageLifecycleOwnerEnrollment.enroll(501, parent: fd, owner: owner, sync: noSync) }
                else { _ = try? StorageLifecycleOwnerEnrollment.unenroll(parent: fd, owner: owner, sync: noSync) }
                group.leave()
            }
        }
        #expect(group.wait(timeout: .now() + 10) == .success)
        let final = try StorageLifecycleOwnerEnrollment.state(parent: fd, owner: owner)
        #expect(final == .disabled || final == .enrolled(501))
        #expect(!FileManager.default.fileExists(atPath: directory.path("storage-owner.tmp")))
    }

    @Test func unenrolledOrRefusedProductionNamespaceIsNeverWritten() throws {
        let namespace = try ProductionTempDirectory()
        var baseCalls = 0
        for _ in 0..<3 {
            #expect(throws: (any Error).self) {
                try StorageBootstrapLifecycleRouter.productionRouter(owner: { throw BootstrapFailure(.unavailable) },
                    base: { baseCalls += 1; return dup(namespace.fd) }, team: "ABCDEFGHIJ")
            }
        }
        #expect(baseCalls == 0)
        #expect(try FileManager.default.contentsOfDirectory(atPath: namespace.url.path).isEmpty)
        // An enrolled owner with a v1 namespace keeps refusing and is never modified.
        let legacy = Data("CEBSJ001 legacy".utf8)
        try legacy.write(to: URL(fileURLWithPath: namespace.path("authority.journal")))
        #expect(mkdirat(namespace.fd, "v1", 0o700) == 0)
        for _ in 0..<3 {
            #expect(throws: (any Error).self) {
                try StorageBootstrapLifecycleRouter.productionRouter(owner: { 501 }, base: {
                    try StorageLifecycleProductionFormat.require(namespace.fd, owner: geteuid(), sync: noSync)
                    return dup(namespace.fd)
                }, team: "ABCDEFGHIJ")
            }
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: namespace.url.path).sorted() == ["authority.journal", "v1"])
        #expect(try Data(contentsOf: URL(fileURLWithPath: namespace.path("authority.journal"))) == legacy)
        // Disconnect/quiesce paths observe no router and therefore create no state.
        #expect(StorageBootstrapLifecycleRouter.existingProductionRouter == nil)
    }
}

/// Scope bind is a production contract: admitted in every build, closed to
/// qualification-only fields, and namespace selection stays in the helper.
@Suite struct StorageBootstrapLifecycleProductionScopeBindTests {
    private func bindMessage(_ payload: Data, fd: Int32, extra: String? = nil) -> xpc_object_t {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, "operation", StorageLifecycleScopeProtocol.xpcOperation)
        payload.withUnsafeBytes { xpc_dictionary_set_data(message, "request", $0.baseAddress, $0.count) }
        xpc_dictionary_set_fd(message, "store-root", fd)
        if let extra { xpc_dictionary_set_string(message, extra, "x") }
        return message
    }

    @Test func productionScopeBindIsAdmittedAndDecoded() throws {
        let root = try ProductionTempDirectory()
        let request = StorageLifecycleScopeProtocol.Request(store: try .init("11111111-1111-4111-8111-111111111111"))
        let message = bindMessage(try StorageLifecycleScopeProtocol.encode(request), fd: root.fd)
        // Previously refused `unavailable` without the qualification compile flag.
        #expect(try StorageBootstrapLifecycleRouter.validateAdmission(message) == StorageBootstrapLifecycleRouter.scopeBindOperation)
        #expect(try StorageBootstrapLifecycleRouter.decodeBind(message) == request)
        #expect(StorageBootstrapLifecycleRouter.scopeBindOperation == "storage-lifecycle-scope-bind")
    }

    @Test func productionScopeBindRejectsQualificationOnlyFields() throws {
        let root = try ProductionTempDirectory()
        let data = try StorageLifecycleScopeProtocol.encode(.init(store: try .init("11111111-1111-4111-8111-111111111111")))
        let text = String(decoding: data, as: UTF8.self)
        for field in ["\"sourcePin\":\"abc\"", "\"assetsSHA256\":\"00\"", "\"fault\":\"drop-reply\"",
                      "\"policy\":\"qualification\"", "\"namespace\":\"compatibility\"", "\"path\":\"/tmp/x\""] {
            let tampered = Data(text.replacingOccurrences(of: "{", with: "{\(field),").utf8)
            #expect(throws: (any Error).self) { try StorageLifecycleScopeProtocol.decode(tampered) }
            #expect(throws: (any Error).self) { try StorageBootstrapLifecycleRouter.validateAdmission(bindMessage(tampered, fd: root.fd)) }
        }
        let version = Data(text.replacingOccurrences(of: "storage-lifecycle-scope.v2", with: "storage-lifecycle-qualification.v1").utf8)
        #expect(throws: (any Error).self) { try StorageLifecycleScopeProtocol.decode(version) }
        for key in ["source-pin", "fault", "namespace", "store-backing"] {
            #expect(throws: (any Error).self) { try StorageBootstrapLifecycleRouter.validateAdmission(bindMessage(data, fd: root.fd, extra: key)) }
        }
        let missingRoot = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(missingRoot, "operation", StorageLifecycleScopeProtocol.xpcOperation)
        data.withUnsafeBytes { xpc_dictionary_set_data(missingRoot, "request", $0.baseAddress, $0.count) }
        #expect(throws: (any Error).self) { try StorageBootstrapLifecycleRouter.validateAdmission(missingRoot) }
    }

    @Test func productionScopeJournalRootIsHelperSelectedAndIsolated() {
        // The DTO carries no namespace; the router's compiled policy selects the base.
        #expect(StorageLifecycleNativePolicy.production.namespace == .production)
        let production = StorageLifecycleScopeNamespace.production.components
        let compatibility = StorageLifecycleScopeNamespace.compatibility.components
        #expect(production != compatibility && !production.contains("compat"))
    }
}
