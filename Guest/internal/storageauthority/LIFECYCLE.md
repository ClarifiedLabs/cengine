# Managed volume lifecycle contract

The storage service uses these volume operations through authenticated
workload CONTROL. The registry envelope is schema **4**; workload receipts and
DATA journal records use schema **3**. There is no migration path.

## Typed control API

- `CreateVolume(*ControllerPrincipal, CreateVolumeRequest) (VolumeReceipt, error)`
  takes `{operation, store, volume, name}`. Host journals fresh lowercase UUIDv4
  `volume` and `operation` before sending; `store` must match exactly. Name follows
  the existing policy: valid UTF-8, 1–255 bytes, neither `.` nor `..`, no slash/NUL.
- `DeleteVolume(*ControllerPrincipal, DeleteVolumeRequest) (VolumeReceipt, error)`
  takes `{operation, store, volume}`; never resolve deletion by name.
- `VolumeReceipt` contains `{schema, operation, store, volume: {id,name,root},
  phase, revision}`. Create returns immutable `READY`; delete returns immutable
  `DELETED`. These are lifecycle results, **not attachment drain receipts**.
- `Query` includes `volume_lifecycles`, keyed by V, alongside all `volumes`,
  including tombstones. Each lifecycle records phase, original create/delete
  operation IDs and completion revisions. Legacy registered roots have no create
  operation/revision.

Every invocation rechecks the authenticated controller's exact owner/key/epoch,
including duplicate calls. TLS workload/successor identities cannot substitute for
controller authority. An operation ID is immutable across all control kinds and
arguments. Only an exact completed duplicate returns its original result; changing
arguments conflicts. An old create result remains retryable after deletion and
same-name recreation, but grants no authority. A new delete operation for an already
deleted V conflicts; retry its original operation instead.

## Durable transitions and exclusion

`CREATING -> READY -> DELETING -> DELETED`. All lifecycle namespace IO holds the
same authority mutex as every control transaction/admission; the control transport
bounds admission independently. Deletion never waits for owners:
it returns `ErrBusy` for unresolved PREPARE, any non-DRAINED attachment (including
RESERVED/RETIRING), or in-flight ownership. Attachment drain barriers must already
have synchronized/closed all retained resources. No role bypass. Long/hung local
filesystem IO may block all control operations; no control latency or
cancellation guarantee is provided.

Create records CREATING intent before exclusive descriptor-relative mkdir, opens
and binds the new root, syncs root and export parent, then durably publishes READY.
An existing leaf is never adopted. Delete records DELETING intent before recursively
unlinking through retained directory descriptors, never follows symlinks, rejects
cross-device directories, rewinds the shared root directory offset, syncs each
mutated directory and the export parent, closes the root, then publishes DELETED.
Linux directory opens use `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV)`
to reject mount transitions, including same-device bind mounts, without a weaker
fallback. Darwin is a native-test-only fallback, not production mount-confinement
proof. External namespace writers remain forbidden by the exclusive
owned-backing-root prerequisite; this is not cross-VM fencing.

Lifecycle open rejects unresolved volume lifecycle intent with `ErrRepairRequired`,
even if a leaf exists or is absent. No inference from an unrecorded inode, automatic resume, or
online repair. Before-intent crashes can retry; after terminal durable publication,
a lost reply can retry exactly after lifecycle open. Ordinary journal uncertainty
remains a hard repair fence. Lifecycle open never reopens a terminal-deleted root;
its name must be absent unless an independently recorded newer V owns it, whose exact root is then
verified. Unexpected replacements fail closed.

All V records, attachment/key history, operations and receipts are retained forever.
The same name can later use a fresh V only through CreateVolume. `AddVolume` remains
explicit registration of an already-created, explicitly identified root; it cannot
register managed/deleted identities or reuse a tombstoned name/root. The current
controller may delete an explicitly registered legacy V under the same drain and
PREPARE gates; legacy registration is not a preservation/retention policy.

Each intent reserves bytes and a revision for its terminal completion and reuses
its operation slot. A new operation can fail `ErrLimit` cleanly before intent;
there is no promise of unlimited future creates/deletes. Physical EIO/ENOSPC,
short writes, sync/close failures poison the open instance and quarantine reopening.
A completion capacity invariant violation is also fail-closed. No automatic GC.
Every outstanding PENDING PREPARE also reserves one resolution operation slot,
encoded terminal state/operation bytes, and one journal revision at reservation.
Each planned attachment independently reserves its first retirement operation,
intent/receipt bytes and both revisions, even if never registered. Unrelated growth
(including create/delete) cannot spend these reservations. After every exact drained
receipt and the successful, clean-copy-up attestation, CompletePrepare can commit
within the admitted logical budget. Only a committed exact terminal transition
reclaims the reservation; timeout, failed drain, invalid receipts/attestation and
failed persistence never release PENDING. Logical reservation invariant violations
quarantine the instance just like retirement/completion failures; no false receipt.

ReplacePrepare spends the predecessor's resolution reservation atomically, but
must additionally fund the fresh successor's records, operation and all retirement
and resolution reservations. It may return ErrLimit without changing the pending
predecessor. Finite retained history cannot promise unlimited recovery generations,
registrations, service restarts or controller takeovers. No successful attestation
may be invented to work around exhausted replacement capacity. Exact completed
replay uses no new capacity; changed operation arguments still conflict. Reservations
are derived from persisted phases. Lifecycle open rechecks the full budget and
refuses underfunded state; it never drops pending evidence to fit reduced limits. Physical storage failures and
hung IO remain outside this logical completion-capacity guarantee.

## Verification boundary

Native Go subprocesses abruptly exit around lifecycle boundaries without cleanup;
fault tests inject EIO, ENOSPC and short writes. Native race tests/vet and Linux
arm64 test cross-compilation do not establish VM/ext4/power-loss correctness.
The transport and host additionally enforce bounded framing, controller-role
trust separation, operation correlation, and independently reconciled intent.
