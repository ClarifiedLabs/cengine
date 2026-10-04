# Storage ownership cross-language integration tests

Run from the repository root on Apple silicon/macOS:

```sh
python3 Tests/StorageLifecycleIntegrationTests/run.py
```

This separate harness does not modify production routes, install helpers, request
sudo, boot VMs, or mint `ControllerRecovery`/native-proof capabilities.

## What is connected

1. An isolated SwiftPM test compiles the **actual** ROOT lifecycle authority and
   physical checkpoint journal. A private mode-0700 test directory holds its
   ephemeral signing key (mode-0600 files). The journal uses real fsync/rename;
   this does **not** qualify macOS power-loss durability/F_FULLFSYNC.
2. ROOT signs initialization, takeover and retirement grants. Its private child
   process is a Go **test binary**, compiled only with the dedicated
   `cengine_lifecycle_integration` build tag, selected by an environment gate and
   exact `-test.run=^TestLifecycleIntegrationBridge$`. A missing gate fails, never
   skips; ordinary Go tests do not compile this worker. Bounded NDJSON stdin/stdout
   carry those same grants to actual `InitializeLifecycle`, `TakeoverLifecycle`,
   `RetireLifecycle`, `LifecycleResult` and `LifecycleServiceResult`; signatures and
   durable registry IO are real. ROOT supplies independent fresh receipt/service
   nonces and performs actual complete/reclaim. Stable receipts retain the applied
   grant's original E; live results carry the actual authority E/open revision.
3. The producer writes only public grant/recipient/result metadata into a bounded
   trace under a unique `.build/storage-lifecycle-integration-*` directory.
   Its canonical header pins the SHA-256 of the complete source manifest, built
   worker hash and local Go version. The manifest includes every vendored regular
   file and this README. The focused Xcode test checks those inputs and runs the
   **actual** `ManagedStorageLifecycleCheckpoint.baseline`,
   `applying`, `encode` and `decode` with actual `HostStorageIntents.State`.
   This is sequential trace composition, **not** host transport authentication or
   physical HOST checkpoint persistence qualification.

The first datastore completes 4,098 takeovers (controller epoch 4,099), then
retires/reclaims. Another 129 fresh datastores each complete one takeover and
retire/reclaim. Store UUID reuse specifically exercises generation boundaries.
All 4,487 ROOT grants flow through Go and into HOST. No independent loops or
pre-recorded mock results substitute for this chain. The tests report per-layer
peak/current checkpoint byte counts and aggregates of retained terminal metadata.

Failures covered include stale ROOT epoch/generation/operation ID, old signed
Go grants, changed generation/ID/serial, invalid signatures, seal reply loss,
nonce mismatch/private proof refusal, and reply loss after ROOT has persisted its
seal. Completion also rejects absent fresh service proof, a mismatched service
nonce, and boot/result E inconsistency. Reclamation remains fenced until a fresh
direct Go result succeeds.

## Deliberate authentication boundary

ROOT process identities/liveness/fresh binding checking are **unsigned test
seams**. Each candidate has a fresh ephemeral Ed25519 public key, but this harness
makes **no key possession/nonexportability claim**. The Go worker uses explicit
package-internal principal construction rather than TLS. No arbitrary executable
can access this as a production API: the worker exists only in `_test.go`, and its
private inherited pipes are owned by the producer. Its Config resource barrier
fails if called; these are fresh empty stores with no volume/attachment owners.
Boot trust uses explicit deterministic **test-only** CA/server fingerprints bound
to actual Guest identity/E/bootstrap-key metadata; no production defaults, real
certificates, TLS, or native boot authentication are exercised. Service results
come unchanged from Go, never synthesized from receipts in Swift. Service-change
requests/confirmations fail explicitly: this lane has no reopen or staged-client
promotion support. Thus this is not retained-resource drain coverage or native
RTM acceptance.

The host test is compiled only with `CENGINE_STORAGE_LIFECYCLE_INTEGRATION`;
normal `make test` gains no skipped test. When compiled, a missing trace is an
error, not a silent success. `--producer-only` is diagnostic and explicitly does
not claim completion of the host chain.

The runner audits source hashes before and after execution. Go compilation uses
`GOFLAGS=-mod=vendor`, `GOWORK=off`, `GOENV=off`, `GOTOOLCHAIN=local`,
`GOPROXY=off`, `GOSUMDB=off`, and `CGO_ENABLED=0`; inherited Go/cgo/compiler
flags are removed. `build-info.json` records this environment, the Go version,
manifest digest and built worker digest. No downloaded toolchain/module fallback
is permitted.

The runner has subprocess deadlines and kills timed-out/interrupted owned process
groups **before** joining their leader. It never signals a process-group ID after
reaping the leader; normal Swift teardown joins its Go worker. Producer calls have
30-second nonblocking write/read deadlines; the Go helper has a 12-minute timeout,
64-KiB messages, and a 50,000-request ceiling. Private temporary files remain under
the runner-owned tree so abnormal termination still permits bounded cleanup.

Trace creation is exclusive (existing paths are never truncated or deleted).
HOST opens trace/manifest once with `O_NOFOLLOW|O_NONBLOCK`, requires private,
singly-linked regular files owned by the effective UID, bounds reads to 32 MiB,
and rechecks descriptor and pathname metadata after reading. Each NDJSON record
must be nonempty, at most 64 KiB, closed/canonical Codable, and newline-terminated.
The large vendor manifest is canonical JSON whose digest is pinned by the header;
it does not inflate the header past the wire limit.

Run the small file-type/size/race/framing/canonical-input regressions separately:

```sh
python3 -m unittest discover -s Tests/StorageLifecycleIntegrationTests -p 'test_*.py'
python3 Tests/StorageLifecycleIntegrationTests/run.py --negative-only
```

These negative tests do not repeat the lifecycle campaign. Public traces, source
hashes and build information remain in `.build` for review; do not commit them.
