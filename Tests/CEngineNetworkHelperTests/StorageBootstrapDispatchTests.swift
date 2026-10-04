import CEngineCore
import Darwin
import Testing
@preconcurrency import XPC
@testable import StorageBootstrapHelper

@Suite struct StorageBootstrapDispatchTests {
    @Test func removedOperationsNeverReachNetworkingEvenWithToken() {
        for operation in ["storage-bootstrap", "storage-child", "storage-child-confirm", "storage-unknown"] {
            let message = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(message, "operation", operation)
            xpc_dictionary_set_string(message, "authentication-token", "known-token")
            xpc_dictionary_set_int64(message, "version", PrivilegedPortProtocol.version)
            #expect(!StorageBootstrapLifecycleRouter.recognizes(operation))
            #expect(throws: (any Error).self) { try StorageBootstrapAdmission.requireNetworkingOperation(message) }
        }
    }
    @Test func networkingVocabularyIsClosed() throws {
        for operation in ["status", "restart", "bind", "start-vmnet", "stop-vmnet"] {
            let message = xpc_dictionary_create(nil, nil, 0)
            xpc_dictionary_set_string(message, "operation", operation)
            try StorageBootstrapAdmission.requireNetworkingOperation(message)
        }
        let message = xpc_dictionary_create(nil, nil, 0)
        #expect(throws: (any Error).self) { try StorageBootstrapAdmission.requireNetworkingOperation(message) }
        xpc_dictionary_set_uint64(message, "operation", 1)
        #expect(throws: (any Error).self) { try StorageBootstrapAdmission.requireNetworkingOperation(message) }
    }
    @Test func exactLifecyclePairNeverMixesNamespacesOrAcceptsUnsignedTeam() throws {
        for team in ["", "short", "ABCDEFGHI\"", "abcdefghij"] {
            #expect(throws: (any Error).self) {
                try StorageBootstrapAdmission.listenerRequirement(namespace: .production, team: team)
            }
        }
        for namespace in [SignedStorageIdentity.Namespace.production, .compatibility] {
            let requirement = try StorageBootstrapAdmission.listenerRequirement(namespace: namespace, team: "ABCDEFGHIJ")
            #expect(requirement.contains("anchor apple generic"))
            #expect(requirement.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"))
            #expect(requirement.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"))
            #expect(requirement.contains("identifier \"\(namespace.engineIdentifier)\" or identifier \"\(namespace.controllerIdentifier)\""))
            #expect(requirement.contains("test-compat") == (namespace == .compatibility))
        }
    }
    @Test func networkingRequiresNativeEngineRatherThanControllerOrToken() {
        let admission = StorageBootstrapAdmission(policy: .production, team: "ABCDEFGHIJ")
        var token = audit_token_t()
        token.val.1 = geteuid(); token.val.3 = getuid(); token.val.5 = UInt32(getpid())
        token.val.7 = BootstrapKernelIdentity.read(getpid())?.pidVersion ?? 0
        // The test process cannot mint an ENGINE identity, regardless of its UID.
        #expect(throws: (any Error).self) { try admission.authenticateNetworking(token: token) }
        #expect(throws: (any Error).self) { try StorageBootstrapAdmission.current() }
    }
    @Test func bootstrapCapabilityIsNeitherRequestedNorDecodedAsAlias() {
        #expect(NetworkHelperCapabilities.Requirement(rawValue: "bootstrap-v1") == nil)
        #expect(NetworkHelperCapabilities.StorageContract(rawValue: "bootstrap-v1") == nil)
    }
}
