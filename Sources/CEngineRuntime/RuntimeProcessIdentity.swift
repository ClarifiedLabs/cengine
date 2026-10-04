#if os(macOS)
import Darwin
import Foundation

nonisolated enum RuntimeProcessIdentity {
    /// XNU private ABI, not PROC_PIDT_SHORTBSDINFO: proc_info_private.h defines
    /// PROC_PIDUNIQIDENTIFIERINFO=17 and proc_uniqidentifierinfo (56 bytes), with
    /// p_uniqueid at 16 and p_idversion at 32. Keep the exact size/version checks.
    /// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info_private.h
    /// Exercised against the real task audit token by the isolated Runtime tests.
    static func processIdentity(pid: Int32, pidVersion: UInt32) -> Data? {
        guard pid > 0 else { return nil }
        var bytes = Data(count: 56)
        guard bytes.withUnsafeMutableBytes({ proc_pidinfo(pid, 17, 0, $0.baseAddress, 56) }) == 56,
              bytes.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 16, as: UInt64.self) }) != 0,
              bytes.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 32, as: UInt32.self) }) == pidVersion else { return nil }
        return bytes
    }
}
#endif
