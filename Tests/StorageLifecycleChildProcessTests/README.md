# Lifecycle-v2 child transport checks

Run `bash Tests/StorageLifecycleChildProcessTests/run.sh` on Apple silicon/macOS 26+.
The isolated Swift 6.2+ package compiles the actual native launcher and
`ManagedStorageControlProtocol` request DTOs under MainActor default isolation.
Tests cover socket framing, strict reply decoding, UInt64 exhaustion, deadlines,
one SCM_RIGHTS transfer, rejection and cleanup of unexpected descriptors,
descriptor borrowing, public replay envelopes, and unsigned process rejection.
They do not install helpers, start VMs, or verify an installed signed engine/helper pair.

Darwin/cgo builds enter the controller through `RunLifecycleChild`. It accepts no
argument or exactly `--lifecycle-v2`; `ManagedStorageLifecycleOwner` launches it
with that argument.

`StorageLifecycleChildProcess.launch(installedHelperTeam:policy:)` authenticates
the engine and fixed sibling controller under the selected native policy
(production by default). It starts the child suspended with an empty environment,
FD 3 as its private channel and standard streams redirected to `/dev/null`, then
checks the running executable before resuming and independently checking hello. The caller must use the nonserialized `processIdentity` for its
external ROOT enrollment before `initialize(_:)`, within the child's 5s startup
budget. Initialization takes only store/binding/incarnation/expected epoch/ROOT
public key. ROOT key lookup/enrollment is deliberately not implemented here.

Closed operations cover grant binding, boot/workload connection, staged service
rebind, attachment certificates, workload commands, public replay diagnostics,
takeover and retirement. Boot inputs carry certificate/TLS public material and
the signed grant; they are not boot provenance. The child owns its controller
private key and opens its own native ROOT channel; the parent cannot supply either.
`close()` shuts down the private socket, kills only an owned unreaped child and
bounds synchronous reap waiting. No proof/signature/result-receipt export exists.

Workload connection transfers exactly one borrowed socket duplicate without a body;
the child retains its audited boot trust. Commands use the neutral closed typed
workload request union, excluding takeover, nested as JSON with `id:0` (not base64).
Workload-only bounds are 256 KiB for the whole request frame and 4 MiB for raw
reply data, within a base64 reply frame capped at `4 MiB * 4 / 3 + 1024` bytes.
Other operations retain 64 KiB framing. Tests cover every allowed typed command,
Go-compatible escaping, exact/oversized bounds, canonical envelope rejection,
fresh outer sequences and incoming-right cleanup on both reply paths.
