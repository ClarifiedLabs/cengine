import Foundation

public struct BackendStatistics: Sendable {
    public struct Network: Sendable {
        public let name: String
        public let rxBytes: UInt64; public let rxPackets: UInt64; public let rxErrors: UInt64
        public let txBytes: UInt64; public let txPackets: UInt64; public let txErrors: UInt64
    }
    public struct BlockIO: Sendable {
        public let major: Int
        public let minor: Int
        public let readBytes: UInt64
        public let writeBytes: UInt64

        public init(major: Int, minor: Int, readBytes: UInt64, writeBytes: UInt64) {
            self.major = major; self.minor = minor
            self.readBytes = readBytes; self.writeBytes = writeBytes
        }
    }
    public let read: Date
    public let cpuTotalNanoseconds: UInt64
    public let cpuUserNanoseconds: UInt64
    public let cpuSystemNanoseconds: UInt64
    public let memoryUsage: UInt64
    public let memoryPeak: UInt64
    public let memoryLimit: UInt64
    public let memoryCache: UInt64
    public let pids: UInt64
    public let blockReadBytes: UInt64
    public let blockWriteBytes: UInt64
    public let blockIO: [BlockIO]
    public let cpuPeriods: UInt64
    public let cpuThrottledPeriods: UInt64
    public let cpuThrottledNanoseconds: UInt64
    public let networks: [Network]

    public init(read: Date = Date(), cpuTotalNanoseconds: UInt64, cpuUserNanoseconds: UInt64,
                cpuSystemNanoseconds: UInt64, memoryUsage: UInt64, memoryLimit: UInt64,
                memoryCache: UInt64, pids: UInt64, blockReadBytes: UInt64,
                blockWriteBytes: UInt64, networks: [Network], memoryPeak: UInt64? = nil,
                blockIO: [BlockIO] = [], cpuPeriods: UInt64 = 0,
                cpuThrottledPeriods: UInt64 = 0, cpuThrottledNanoseconds: UInt64 = 0) {
        self.read = read; self.cpuTotalNanoseconds = cpuTotalNanoseconds
        self.cpuUserNanoseconds = cpuUserNanoseconds; self.cpuSystemNanoseconds = cpuSystemNanoseconds
        self.memoryUsage = memoryUsage; self.memoryPeak = memoryPeak ?? memoryUsage
        self.memoryLimit = memoryLimit; self.memoryCache = memoryCache
        self.pids = pids; self.blockReadBytes = blockReadBytes; self.blockWriteBytes = blockWriteBytes
        self.blockIO = blockIO
        self.cpuPeriods = cpuPeriods; self.cpuThrottledPeriods = cpuThrottledPeriods
        self.cpuThrottledNanoseconds = cpuThrottledNanoseconds
        self.networks = networks
    }
}
