# Isolated lifecycle ROOT Runtime tests

Run `bash Tests/StorageControllerRuntimeTests/run.sh` on macOS 26+ with Swift 6.2+.
The runner copies actual Runtime sources and Core contracts into a temporary
SwiftPM package with MainActor default isolation. It does not install a helper,
launch a VM, or authenticate a signed production peer.

Coverage includes lifecycle ROOT envelope closure, descriptor requirements,
request/reply correlation, cold/resume/adoption requests, canonical JSON and
UInt64 handling, neutral diagnostics, and kernel process identity.

Child socket framing, ownership, workload request limits, and replay coverage
live in [StorageLifecycleChildProcessTests](../StorageLifecycleChildProcessTests/README.md).
Owner retry, lost-reply, and generation fencing coverage lives in the lifecycle
owner suites under `Tests/CEngineCoreTests` and requires the Xcode test target.
