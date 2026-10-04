import CEngineCore
import Darwin
import Foundation
import Testing
@preconcurrency import XPC
@testable import StorageControllerRuntime

@Suite struct RootPublicKeyTests {
    @Test func helperReplyKernelIdentityMatchesActualTaskAuditToken() throws {
        var token = audit_token_t(), count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        #expect(result == KERN_SUCCESS)
        #expect(Int32(bitPattern: token.val.5) == getpid())
        let first = try #require(RuntimeProcessIdentity.processIdentity(pid: getpid(), pidVersion: token.val.7))
        #expect(RuntimeProcessIdentity.processIdentity(pid: getpid(), pidVersion: token.val.7) == first)
        #expect(RuntimeProcessIdentity.processIdentity(pid: getpid(), pidVersion: token.val.7 &+ 1) == nil)
        #expect(RuntimeProcessIdentity.processIdentity(pid: -1, pidVersion: token.val.7) == nil)
        // Kernel ABI coverage is not a signed installed-helper authentication test.
    }
}
