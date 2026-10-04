// Package storageauthority implements the disabled durable generation authority.
// This core is deliberately not wired to a listener or the legacy storage service.
// The selected future data path is stateful managed FUSE backed by ext4; there is
// no data reconnection, request replay, NFS tunnel, or syncfs-only drain fence.
//
// Integration order:
//  1. Verify exclusive backing-disk ownership and predecessor service/VM teardown;
//     disable every legacy mutation path. Open the independently verified backing
//     root, with an existing volumes/ directory. Initialize once, Open thereafter.
//  2. Provide mutually verified TLS 1.3 connections without session resumption,
//     separate workload/controller keys and an offline bootstrap public key.
//     AuthenticateData/AuthenticateController/AuthenticateSuccessor are the only
//     principal constructors. Successor possession alone grants no control rights.
//  3. Admit every complete request (reads and both operands of namespace operations
//     included) before ANY identity/namespace queue or descriptor lookup. Retain its
//     Guard through all IO, sync, callback joins and request-resource closes. Socket
//     cancellation/response delivery must never release ownership. A Guard is not
//     a handle confinement implementation: runtime must root all handles in V.
//  4. Supply Barrier using retained root/attachment FDs, serialized namespace access,
//     sticky filesystem writeback errors, and attachment-handle teardown. It must
//     cover all resources, not merely invoke syncfs. Retirement owns its completion;
//     a canceled control wait cannot cancel it. Hung IO may prevent success forever.
//  5. Journal host intent before reservation/credential delivery; attest PREPARE only
//     after guest success and clean copy-up, drain all prepare A, then complete or
//     replace. Replace workloads after storage restart; never reuse A/key/mount.
//
// Managed-server root setup uses DataPrincipal.Binding (metadata only), Admit,
// then Guard.DupVolumeRoot. DupVolumeRoot duplicates the exact retained V root;
// it never reopens a pathname and serializes descriptor creation with Release.
// Already-admitted requests may obtain that root while A is RETIRING. Close each
// request-owned duplicate and join its users before Release. A server may retain
// a duplicate or derived node/handle only after transferring it into its exact
// attachment's resource registry covered by Barrier, before releasing the guard.
// That registry must fence further use and close retained descriptors before the
// barrier succeeds. Release does not close duplicates or revoke kernel FDs; the
// caller must coordinate resource ownership/transfer, including concurrent calls.
// Relative traversal, both namespace operands and handle confinement remain the
// server's responsibility; possessing a root FD alone does not enforce them.
//
// Binding.Container is the host's 64-character lowercase hexadecimal container
// ID. Binding.Launch is a separate lowercase UUIDv4 assigned and journaled for the
// exact shim launch. Existing VMShimProtocol.Specification.generation and
// VMShimProtocol.Status process identity fields are not one UUID; integration
// must durably bind that composite identity to Launch, not coerce it into a UUID.
//
// Journal IO or barrier failures are sticky for the whole open instance. A
// known-IO quarantine marker, a data-plane (data-uncertain) obligation, any generic
// "uncertain" marker or a barrier without exact completion or root-only PREPARE
// retry evidence blocks Open.
// There is deliberately no online repair/clear-fault API for them. A versioned metadata commit or completed retirement certificate can be
// resolved only where it proves the exact durable outcome. Retirement completion
// is certified after the entire retained-resource barrier returns nil, bound to
// the current predecessor and its one-receipt successor. Startup validates both
// certificates together before cleanup; it never rewrites state.json or mints
// a receipt. One complete retirement candidate beside the exact generic barrier
// may prove the RETIRING predecessor only, with no metadata proof: candidate bytes
// are created only after full barrier success. Other temporaries remain inert.
// The distinct v2 root-only PREPARE proof asserts no dirty ownership, not completed
// IO: sole audited bootstrap-only session, all other owners drained, no obligations,
// and exact canonical predecessor. Startup preserves RETIRING/PENDING without a
// receipt; only a new real barrier supplies one. Empty replacement registries and
// legacy bare markers gain no such proof. See DURABILITY.md for the closed scope.
// A proven RETIRING predecessor still requires ordinary Retire retry. Offline
// repair must establish actual data durability and cannot manufacture a receipt. A failure to record evidence on a failed device cannot
// be repaired by this package; verified storage recovery remains an integration
// prerequisite.
// A clean, complete registry can reopen: every old RESERVED/ACTIVE A is durably
// RETIRING under a fresh E and requires the retained-resource barrier, never automatic
// activation. Records, keys, operation IDs and grants are never evicted; capacity
// exhaustion blocks growth. Space and operation slots for each attachment's first
// retirement are reserved before granting authority, including both required
// journal revisions. Limits cannot be changed on an open Authority. A redundant
// Retire with a new operation ID may exhaust its unreserved budget: clean pre-IO
// rejection leaves the existing durable fence/receipt intact and the original ID
// remains retryable. A first-retirement capacity failure instead violates the
// reservation invariant (ErrCapacityInvariant); it remains conservatively fenced
// and quarantined, without claiming a storage EIO/ENOSPC. Local flock does not
// provide cross-VM disk fencing.
//
// Schema 2 adds controller-only CreateVolume/DeleteVolume and durable lifecycle
// intents. The authority mutex serializes lifecycle namespace IO with all control
// transactions/admission. Delete rejects pending PREPARE and every undrained A;
// it never waits for resource owners while holding that mutex. Incomplete volume
// intents require offline repair, never implicit adoption of a pathname. Deleted
// V/root/key/operation evidence remains terminal; only a fresh V can reuse a name.
// See LIFECYCLE.md for typed transport contracts, completion-capacity reservations,
// legacy AddVolume restrictions and descriptor-relative namespace prerequisites.
//
// Exported JSON DTOs are control-framing building blocks, not a wire protocol.
// Future framing must bound handshakes/frames/connections, reserve control capacity,
// negotiate schema/roles, and enforce controller/workload certificate trust roots.
// Fault tests inject IO errors and abruptly exit test subprocesses before/after
// real journal operations and during the mock barrier. Those process exits bypass
// deferred cleanup; they do not crash a device or VM. This package's tests do not
// establish live FUSE/ext4 or physical-power-loss behavior.
package storageauthority
