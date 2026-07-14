#if os(macOS)
import CEngineCore
import Foundation
import Virtualization

public struct RawVirtualMachineConfiguration: Sendable {
    public struct BindShare: Sendable {
        public let tag: String
        public let source: URL
        public let readOnly: Bool

        public init(tag: String, source: URL, readOnly: Bool) {
            self.tag = tag
            self.source = source
            self.readOnly = readOnly
        }
    }

    public struct BlockDisk: Sendable {
        public let identifier: String
        public let source: URL
        public let readOnly: Bool

        public init(identifier: String, source: URL, readOnly: Bool = false) {
            self.identifier = identifier
            self.source = source
            self.readOnly = readOnly
        }
    }

    public let id: String
    public let kernel: URL
    public let initialRamdisk: URL
    public let rootDisk: URL
    public let rootDiskReadOnly: Bool
    public let additionalDisks: [BlockDisk]
    public let cpus: Int
    public let memoryBytes: UInt64
    public let networkFileHandle: FileHandle?
    public let macAddress: String
    public let bindShares: [BindShare]
    public let kernelArguments: [String]

    public init(
        id: String,
        kernel: URL,
        initialRamdisk: URL,
        rootDisk: URL,
        rootDiskReadOnly: Bool = false,
        additionalDisks: [BlockDisk] = [],
        cpus: Int,
        memoryBytes: UInt64,
        networkFileHandle: FileHandle? = nil,
        macAddress: String,
        bindShares: [BindShare] = [],
        kernelArguments: [String] = []
    ) {
        self.id = id
        self.kernel = kernel
        self.initialRamdisk = initialRamdisk
        self.rootDisk = rootDisk
        self.rootDiskReadOnly = rootDiskReadOnly
        self.additionalDisks = additionalDisks
        self.cpus = cpus
        self.memoryBytes = memoryBytes
        self.networkFileHandle = networkFileHandle
        self.macAddress = macAddress
        self.bindShares = bindShares
        self.kernelArguments = kernelArguments
    }

    @MainActor public func makeVirtualizationConfiguration() throws -> VZVirtualMachineConfiguration {
        let configuration = VZVirtualMachineConfiguration()
        let bootLoader = VZLinuxBootLoader(kernelURL: kernel)
        bootLoader.initialRamdiskURL = initialRamdisk
        bootLoader.commandLine = Self.kernelCommandLine(id: id, kernelArguments: kernelArguments)
        configuration.bootLoader = bootLoader
        configuration.cpuCount = max(cpus, VZVirtualMachineConfiguration.minimumAllowedCPUCount)
        configuration.memorySize = max(memoryBytes, VZVirtualMachineConfiguration.minimumAllowedMemorySize)

        let rootAttachment = try VZDiskImageStorageDeviceAttachment(
            url: rootDisk,
            readOnly: rootDiskReadOnly,
            cachingMode: .cached,
            synchronizationMode: .full
        )
        let rootDevice = VZVirtioBlockDeviceConfiguration(attachment: rootAttachment)
        rootDevice.blockDeviceIdentifier = "root"
        let volumeDevices = try additionalDisks.map { disk in
            let attachment = try VZDiskImageStorageDeviceAttachment(
                url: disk.source,
                readOnly: disk.readOnly,
                cachingMode: .cached,
                synchronizationMode: .full
            )
            let device = VZVirtioBlockDeviceConfiguration(attachment: attachment)
            device.blockDeviceIdentifier = disk.identifier
            return device
        }
        configuration.storageDevices = [rootDevice] + volumeDevices
        configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        configuration.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]
        configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = try Self.makeConsoleAttachment()
        configuration.serialPorts = [console]

        guard let networkFileHandle else {
            throw EngineError(.badRequest, "VM configuration requires a network file handle")
        }
        let networkAttachment = VZFileHandleNetworkDeviceAttachment(fileHandle: networkFileHandle)
        let network = VZVirtioNetworkDeviceConfiguration()
        network.attachment = networkAttachment
        guard let address = VZMACAddress(string: macAddress) else {
            throw EngineError(.badRequest, "invalid VM MAC address \(macAddress)")
        }
        network.macAddress = address
        configuration.networkDevices = [network]

        configuration.directorySharingDevices = bindShares.map { share in
            let directory = VZSharedDirectory(url: share.source, readOnly: share.readOnly)
            let device = VZVirtioFileSystemDeviceConfiguration(tag: share.tag)
            device.share = VZSingleDirectoryShare(directory: directory)
            return device
        }
        try configuration.validate()
        return configuration
    }

    static func kernelCommandLine(id: String, kernelArguments: [String]) -> String {
        (["console=hvc0", "panic=1", "cengine.id=\(id)"] + kernelArguments).joined(separator: " ")
    }

    @MainActor static func makeConsoleAttachment() throws -> VZFileHandleSerialPortAttachment {
        let input = try FileHandle(forReadingFrom: URL(fileURLWithPath: "/dev/null"))
        return VZFileHandleSerialPortAttachment(
            fileHandleForReading: input,
            fileHandleForWriting: .standardError
        )
    }
}
#endif
