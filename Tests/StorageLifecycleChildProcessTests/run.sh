#!/bin/bash
# Isolated native socket/negative identity tests. No install, VM or rollout.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/cengine-lifecycle-child-tests.XXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/Sources/CEngineCore" "$work/Sources/LifecycleChildRuntime" "$work/Tests/LifecycleChildTests"
for name in StorageLifecycleNativePolicy StorageServiceTypes SignedCompatibilityIdentity SignedStorageIdentity StorageIdentity PrivilegedPortProtocol EngineError ManagedPrepareCompatibilityProtocol ManagedPrepareStorageProtocol WorkloadStorageProtocol ConsumerObservationProtocol OriginalConsumerObservationProtocol OriginalConsumerRootObservation ManagedPrepareWorkerCheckpointProtocol DiskInitializationProtocol StorageLifecycleProtocol StorageLifecycleBootTrust StorageLifecycleStoreBinding StorageLifecycleAdoptionProtocol StorageLifecycleChildProtocol; do
    cp "$root/Sources/CEngineCore/$name.swift" "$work/Sources/CEngineCore/"
done
cp "$root/Sources/CEngineRuntime/StorageLifecycleChildProcess.swift" "$root/Sources/CEngineRuntime/ManagedStorageControlProtocol.swift" "$root/Sources/CEngineRuntime/ManagedStorageControlClient.swift" "$work/Sources/LifecycleChildRuntime/"
cp "$root"/Tests/StorageLifecycleChildProcessTests/*Tests.swift "$work/Tests/LifecycleChildTests/"
cat > "$work/Package.swift" <<'SWIFT'
// swift-tools-version: 6.2
import PackageDescription
let package = Package(name: "LifecycleChild", platforms: [.macOS(.v26)], targets: [
    .target(name: "CEngineCore"),
    .target(name: "LifecycleChildRuntime", dependencies: ["CEngineCore"], swiftSettings: [.defaultIsolation(MainActor.self)]),
    .testTarget(name: "LifecycleChildTests", dependencies: ["LifecycleChildRuntime", "CEngineCore"])
])
SWIFT
# Compile the actual value-only workload wire contract without the legacy
# controller process or shells for its unrelated boot/diagnostic dependencies.
swift test --package-path "$work" "$@"
