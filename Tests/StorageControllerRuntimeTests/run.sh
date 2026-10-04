#!/bin/bash
# Compile only the scoped Runtime sources and selected actual Core contracts.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/cengine-controller-tests.XXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/Sources/CEngineCore" "$work/Sources/StorageControllerRuntime" "$work/Tests/StorageControllerRuntimeTests"
cp "$root/Sources/CEngineCore/StorageServiceTypes.swift" "$root/Sources/CEngineCore/SignedCompatibilityIdentity.swift" "$root/Sources/CEngineCore/SignedStorageIdentity.swift" "$root/Sources/CEngineCore/StorageIdentity.swift" "$root/Sources/CEngineCore/PrivilegedPortProtocol.swift" "$root/Sources/CEngineCore/EngineError.swift" "$work/Sources/CEngineCore/"
# Closed boot command/reply unions depend on these actual Core DTOs, even when
# this suite only exercises controller transport. Do not replace them with mocks.
cp "$root/Sources/CEngineCore/ManagedPrepareCompatibilityProtocol.swift" "$root/Sources/CEngineCore/ManagedPrepareStorageProtocol.swift" "$root/Sources/CEngineCore/WorkloadStorageProtocol.swift" "$work/Sources/CEngineCore/"
cp "$root/Sources/CEngineCore/ConsumerObservationProtocol.swift" "$root/Sources/CEngineCore/OriginalConsumerObservationProtocol.swift" "$root/Sources/CEngineCore/OriginalConsumerRootObservation.swift" "$root/Sources/CEngineCore/ManagedPrepareWorkerCheckpointProtocol.swift" "$root/Sources/CEngineCore/DiskInitializationProtocol.swift" "$work/Sources/CEngineCore/"
cp "$root/Sources/CEngineCore/StorageLifecycleScopeProtocol.swift" "$root/Sources/CEngineCore/StorageLifecycleNativePolicy.swift" "$root/Sources/CEngineCore/StorageLifecycleRootProtocol.swift" "$root/Sources/CEngineCore/StorageLifecycleProtocol.swift" "$root/Sources/CEngineCore/StorageLifecycleBootTrust.swift" "$root/Sources/CEngineCore/StorageLifecycleStoreBinding.swift" "$work/Sources/CEngineCore/"
cp "$root/Sources/CEngineRuntime/StorageLifecycleRootScope.swift" "$root/Sources/CEngineRuntime/StorageLifecycleRootClient.swift" "$root/Sources/CEngineRuntime/ManagedStorageControlProtocol.swift" "$root/Sources/CEngineRuntime/ManagedStorageControlDiagnostics.swift" "$root/Sources/CEngineRuntime/RuntimeProcessIdentity.swift" "$work/Sources/StorageControllerRuntime/"
cp "$root/Sources/CEngineCore/CanonicalDataStoreLock.swift" "$root/Sources/CEngineCore/StorageLifecycleAdoptionRootProtocol.swift" "$root/Sources/CEngineCore/StorageLifecycleAdoptionProtocol.swift" "$work/Sources/CEngineCore/"
cp "$root/Sources/CEngineRuntime/StorageLifecycleRootAdoptionClient.swift" "$root/Sources/CEngineRuntime/StorageLifecycleRootColdClient.swift" "$work/Sources/StorageControllerRuntime/"
# Adoption replies include the real handoff status/completion contracts.
cp "$root/Sources/CEngineCore/StorageLifecycleHandoffProtocol.swift" "$root/Sources/CEngineCore/StorageLifecycleHandoffRootProtocol.swift" "$work/Sources/CEngineCore/"
cp "$root"/Sources/CEngineCore/StorageLifecycleCold*Protocol.swift "$root"/Sources/CEngineCore/StorageLifecycleResume*Protocol.swift "$work/Sources/CEngineCore/"
cp "$root"/Tests/StorageControllerRuntimeTests/*Tests.swift "$work/Tests/StorageControllerRuntimeTests/"
mkdir -p "$work/Tests/StorageControllerRuntimeTests/Fixtures"
cat > "$work/Package.swift" <<'SWIFT'
// swift-tools-version: 6.2
import PackageDescription
let package = Package(name: "StorageControllerRuntime", platforms: [.macOS(.v26)], targets: [
    .target(name: "CEngineCore"),
    .target(name: "StorageControllerRuntime", dependencies: ["CEngineCore"], swiftSettings: [.defaultIsolation(MainActor.self)]),
    .testTarget(name: "StorageControllerRuntimeTests", dependencies: ["StorageControllerRuntime", "CEngineCore"], resources: [.copy("Fixtures")])
])
SWIFT
# Socket framing tests do not authenticate a shim. These nonconstructible type
# shells compile the transport's sealed entry point without copying VM ownership.
# Full Xcode VMShim tests remain responsible for actual proof construction.
cat > "$work/Sources/StorageControllerRuntime/ReplacementProofTypes.swift" <<'SWIFT'
import CEngineCore
// Close diagnostics only inspect these out-of-scope error types. They cannot be
// constructed here; full Xcode tests cover the actual owner's error categories.
struct ManagedStorageFailure: Error { private init() {} }
struct StorageControlStreamRefused: Error { private init() {} }

SWIFT
swift test --package-path "$work" "$@"
