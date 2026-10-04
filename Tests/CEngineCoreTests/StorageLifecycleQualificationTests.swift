#if os(macOS) && CENGINE_STORAGE_LIFECYCLE_QUALIFICATION
import CEngineCore
import CryptoKit
@testable import CEngineRuntime
import Foundation
import Testing

@Suite struct StorageLifecycleQualificationTests {
    @Test func onlyExactQualificationSelectionsAreAccepted() throws {
        for value in ["fresh", "lost-completion", "live-proof-loss"] {
            let options = try StorageLifecycleQualification.Options(["--root", "/tmp/root", "--assets", "/tmp/assets", "--case", value])
            #expect(options.selection.rawValue == value)
        }
        for arguments in [[], ["--root", "/tmp/root", "--assets", "/tmp/assets", "--case", "takeover"],
                          ["--root", "relative", "--assets", "/tmp/assets", "--case", "fresh"],
                          ["--root", "/tmp/root", "--assets", "/tmp/assets", "--case", "fresh", "--reset"],
                          ["--root", "/tmp/root", "--root", "/tmp/assets", "--case", "fresh"]] {
            #expect(throws: (any Error).self) { try StorageLifecycleQualification.Options(arguments) }
        }
    }
    @Test func assetReceiptMustMatchSignedPinAndExactMetadataBytes() throws {
        func digest(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
        let metadata = Data("metadata".utf8)
        let names = ["vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz", "disk-bootstrap.json"]
        let receipt = Data(names.map { "\(digest($0 == "disk-bootstrap.json" ? metadata : Data($0.utf8)))  \($0)\n" }.joined().utf8)
        let pin = digest(receipt)
        #expect(try StorageLifecycleShimBootstrap.assetHashes(receipt, metadata: metadata, expected: pin).count == 4)
        for (bytes, data, expected) in [(receipt + Data([10]), metadata, Optional(pin)),
                                       (receipt, metadata + Data([10]), Optional(pin)),
                                       (receipt, metadata, Optional(String(repeating: "0", count: 64))),
                                       (receipt, metadata, nil)] {
            #expect(throws: (any Error).self) { try StorageLifecycleShimBootstrap.assetHashes(bytes, metadata: data, expected: expected) }
        }
        let duplicate = receipt + receipt
        #expect(throws: (any Error).self) { try StorageLifecycleShimBootstrap.assetHashes(duplicate, metadata: metadata, expected: digest(duplicate)) }
    }
    @Test func unsignedDriverRefusesBeforeRootCreation() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "cengine-compat-\(UUID().uuidString)/root")
        await #expect(throws: (any Error).self) {
            try await StorageLifecycleQualification.run(arguments: ["--root", root.path, "--assets", "/absent/assets", "--case", "fresh"])
        }
        #expect(!FileManager.default.fileExists(atPath: root.deletingLastPathComponent().path))
    }
}
#endif
