#!/bin/bash
# Isolated SwiftPM tests exercise the actual helper sources without installing/elevating.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/cengine-bootstrap-tests.XXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/Sources/CEngineHelperSupport" "$work/Sources/StorageBootstrapHelper" "$work/Tests/StorageBootstrapHelperTests"
while IFS= read -r source; do
    cp "$root/$source" "$work/Sources/CEngineHelperSupport/"
done < "$root/Configuration/helper-support-sources.txt"
# Preserve engine-only protocol and socket-lock coverage without widening the
# actual helper module's closed dependency set. These compile only in tests.
for source in DaemonSocketLock StorageLifecycleServiceBootProtocol; do
    { printf 'import CEngineHelperSupport\n'; cat "$root/Sources/CEngineCore/$source.swift"; } > "$work/Tests/StorageBootstrapHelperTests/$source.swift"
done
# CanonicalDataStoreLockTests also compiles its own raw-source child process.
mkdir -p "$work/Tests/Fixtures/lock-owner"
for source in EngineError CanonicalDataStoreLock DaemonSocketLock; do
    cp "$root/Sources/CEngineCore/$source.swift" "$work/Tests/Fixtures/lock-owner/"
done
cp "$root/Tests/CEngineCoreTests/CanonicalDataStoreLockTests.swift" "$work/Tests/StorageBootstrapHelperTests/"
cp "$root"/Tests/CEngineCoreTests/StorageLifecycleCold*ProtocolTests.swift "$root"/Tests/CEngineCoreTests/StorageLifecycleResume*ProtocolTests.swift "$work/Tests/StorageBootstrapHelperTests/"
# Includes the paired native StorageBootstrapLifecycleAdoptionXPC transport.
cp "$root"/Sources/CEngineNetworkHelper/StorageBootstrap*.swift "$work/Sources/StorageBootstrapHelper/"
cp "$root"/Tests/CEngineNetworkHelperTests/*Tests.swift "$root/Tests/CEngineCoreTests/SignedCompatibilityIdentityTests.swift" "$root/Tests/CEngineCoreTests/SignedStorageIdentityTests.swift" "$work/Tests/StorageBootstrapHelperTests/"
cp "$root/Tests/CEngineCoreTests/StorageLifecycleNativePolicyTests.swift" "$root/Tests/CEngineCoreTests/StorageLifecycleServiceProofProtocolTests.swift" "$root/Tests/CEngineCoreTests/StorageLifecycleProtocolTests.swift" "$root/Tests/CEngineCoreTests/StorageLifecycleChildProtocolTests.swift" "$root/Tests/CEngineCoreTests/StorageLifecycleFreshProtocolTests.swift" "$work/Tests/StorageBootstrapHelperTests/"
cp "$root/Tests/CEngineCoreTests/StorageLifecycleAdoptionRootProtocolTests.swift" "$root/Tests/CEngineCoreTests/StorageLifecycleAdoptionProtocolTests.swift" "$work/Tests/StorageBootstrapHelperTests/"
cp "$root/Tests/CEngineCoreTests/StorageLifecycleServiceChangeProtocolTests.swift" "$work/Tests/StorageBootstrapHelperTests/"
cp "$root/Tests/CEngineCoreTests/StorageLifecycleChildIdentityTests.swift" "$work/Tests/StorageBootstrapHelperTests/"
mkdir -p "$work/Tests/Fixtures/storage-bootstrap"
cp "$root/Tests/Fixtures/storage-bootstrap/lifecycle-service-boot-v2.json" "$work/Tests/Fixtures/storage-bootstrap/"
cp "$root/Tests/Fixtures/storage-bootstrap/lifecycle-handoff-v1.json" "$work/Tests/Fixtures/storage-bootstrap/"
cp "$root/Tests/Fixtures/storage-bootstrap/lifecycle-cold-open-v1.json" "$root/Tests/Fixtures/storage-bootstrap/lifecycle-resume-open-v1.json" "$work/Tests/Fixtures/storage-bootstrap/"
cp "$root/Tests/Fixtures/storage-bootstrap/lifecycle-child-identity-v1.json" "$work/Tests/Fixtures/storage-bootstrap/"
cp "$root/Tests/Fixtures/storage-bootstrap/lifecycle-v2.json" "$root/Tests/Fixtures/storage-bootstrap/lifecycle-child-v2.json" "$work/Tests/Fixtures/storage-bootstrap/"
cp "$root/Tests/Fixtures/storage-bootstrap/lifecycle-service-result-v2.json" "$root/Tests/Fixtures/storage-bootstrap/lifecycle-service-change-v2.json" "$work/Tests/Fixtures/storage-bootstrap/"
# Only generated test copies change imports: production engine tests stay on Core.
python3 - "$work/Tests/StorageBootstrapHelperTests" <<'PYTHON'
from pathlib import Path
import sys
for path in Path(sys.argv[1]).glob("*Tests.swift"):
    text = path.read_text().replace("import CEngineCore", "import CEngineHelperSupport")
    if path.name == "CanonicalDataStoreLockTests.swift":
        text = text.replace("Sources/CEngineCore/", "Tests/Fixtures/lock-owner/")
    path.write_text(text)
PYTHON
cat > "$work/Package.swift" <<'SWIFT'
// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "StorageBootstrapHelper", platforms: [.macOS(.v15)], targets: [
    .target(name: "CEngineHelperSupport"),
    .target(name: "StorageBootstrapHelper", dependencies: ["CEngineHelperSupport"]),
    .testTarget(name: "StorageBootstrapHelperTests", dependencies: ["StorageBootstrapHelper", "CEngineHelperSupport"])
])
SWIFT
swift test --package-path "$work" "$@"
