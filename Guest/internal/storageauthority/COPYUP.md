# Private durable PREPARE copy intent

The copy intent does not change FUSE identity, normal `ObjectID`, or the
public receipt schema. Exported `Ext4ObjectV1`, `CopyRootV1`, and `CopyIntent` DTOs
avoid an authority-to-wire import cycle. The private journal has an independent
`copy.version = 2` schema and one fixed-size intent per volume. `Query` does not
export that ledger. Only a SHA-256 digest and size are retained, not manifest bytes.

## Trusted server contract

All copy controls require an exact live, active **RW PREPARE** guard. `CopyDeviceID`
returns the configured independently verified backing device UUID. The server
must compare it with the actual UUID read from the authority-derived root
**descriptor**, and derive ext4 identities from pinned real descriptors, never
from request-provided identities. The authority checks S/V, root inode, supported
FILEID_INO32_GEN handle consistency, directory type, and nonzero backing UUID.

Under the service namespace gate:

1. Check `CopyFence` for **every dispatch**, including reads and queued work.
   A nil channel permits ordinary dispatch. For a nonnil channel, release the
   namespace gate, wait, reacquire, and check again. A notification is not access.
2. `BeginCopy(root)` durably records a fresh intent/fence before any transaction
   mutation. Same-owner/root/epoch retries return the existing unfinished intent.
3. `ProvisionCopyTransaction(id, identify)` captures `Initial` root metadata and
   `InitialCaptured` durably, then creates `.cengine-storage-authority/copy-<id>`
   privately (0700) on the same filesystem. After synchronizing that directory and
   its parent, it binds the real descriptor identity durably and atomically renames
   it NOREPLACE into the volume's `.cengine-copyup-transaction`, syncing both
   parents. A process crash before bind resumes only the deterministic private
   name owned by that durable live intent. A public entry in BEGUN is never adopted;
   a public entry in BOUND must match an already privately provisioned identity.
   `InitialCaptured` distinguishes an authentic all-zero snapshot from no snapshot.
   The original direct `BindCopyTransaction` API remains supported, but does not
   establish private-provisioning provenance.
4. `SealCopyManifest(id, transaction, bytes)` binds the exact nonempty bytes, at most
   `MaxCopyManifestBytes` (64 MiB), **before publication**. Repeated seals must match.
5. Recovery calls `AuthenticateCopyManifest` before touching root metadata or
   deleting anything. It then preflights the entire manifest and checks full
   durable identities at deletion under the still-held fence. `nil` bytes may
   authenticate only a **BOUND** pre-manifest transaction; empty nonnil bytes are
   invalid, and nil cannot bypass a **SEALED** record.
6. Before removing cleanup evidence or the transaction, call
   `StartCopyCleanup(id, transaction, cleanup)` to durably enter **CLEANING** with
   exact target root UID/GID/mode/atime/mtime and real manifest/staging identities.
   BOUND prepublication cleanup needs no digest and must not interpret unsealed
   instructions. SEALED cleanup requires the manifest identity. CLEANING can be
   inspected or replayed with exactly the same cleanup metadata, never replaced.
   For unsealed CLEANING, authenticate with `InspectCopy` and exact
   `StartCopyCleanup` replay—not the BOUND-only nil manifest proof.
   Missing evidence in CLEANING is recoverable only under this durable record;
   existing objects must still match their recorded identities. The server joins
   work, verifies/removes evidence, restores root metadata, and synchronizes it.
   `Initial` provides exact pre-manifest rollback metadata, including timestamps
   captured before transaction publication changed the root.
7. `FinishCopy(id)` is called only after joined transaction work, identity-verified
   cleanup, and successful synchronization. This verification and sync belong to
   the trusted server, not this authority API. A fenced nonempty-volume no-op can
   finish directly from pristine **BEGUN**. Privately provisioned intents must
   enter CLEANING before Finish; original direct-Bind callers retain the existing
   trusted-server completion assertion contract. Completion is durable before the
   fence wakes.

`SealCopyManifestDigest` and `AuthenticateCopyManifestDigest` accept a trusted
server's streaming SHA-256 and size, without storing manifest bytes. The byte-slice
APIs delegate to them. A zero digest/size proof is allowed only in BOUND; CLEANING
can authenticate the stored nonzero sealed digest but cannot be resealed. Metadata
nanoseconds must be below 1e9, mode at most 07777, and optional cleanup objects must
have consistent ext4 handles, correct types, and distinct non-root/non-transaction
inodes. Completed records may retain cleanup; pre-cleanup records may not.

The authority never blanket-rejects `ReservePrepare` for an existing runtime RW
attachment. Such attachments instead wait at dispatch. Unrelated volumes proceed.

## Failure and replacement

Retirement never clears or completes an unfinished intent. It rotates notification
channels so a fenced retiring nonowner request can return `ErrUnauthorized` and
release its guard instead of deadlocking the drain. Already-admitted retiring
owner work, and retiring work without a fence, may drain normally; private copy
controls still fail after retirement. Closure and quarantine wake notifications.

Only `ReplacePrepare`, after validating every predecessor drain receipt, transfers
an unfinished intent to the exact successor binding and current service epoch.
Physical root, transaction, manifest digest, size, intent ID, and phase remain
unchanged. A RO successor cannot acquire an unfinished RW copy. `CompletePrepare`
cannot accept a clean-copy attestation while an unfinished intent exists.

Reopen retains the intent and reconstructs fresh notification channels before
returning authority to DATA service. Ordinary epoch fencing and drain rules still
apply. Completed IDs fail closed, including repeated `FinishCopy` after a lost
reply. A later Begin may replace the completed per-volume tombstone with a fresh
random ID; the older ID remains unusable.

Copy transitions use the existing durable state/uncertainty protocol. IO failure
quarantines the authority and wakes waiters into an error, never access. Capacity
reserves the maximum fixed DTO encoding and all remaining metadata/bind/seal/
cleanup/completion revisions before exposing a new fence. No manifest-size bytes
are reserved in the authority journal. A clean pre-IO capacity rejection does not create an intent.

## Closed DATA recovery actions

`copy-operation` v1 also carries `rollback-sealed` and `prepare-directory-tail`.
Unlike ordinary DATA uncertainty, these describe independently authenticated,
operation-specific whole-intent undo/nonmutating domains. Unknown actions already
make old readers reject physical markers and persisted replay state; no permissive
schema migration is introduced. Complete records are published atomically before
execution. See `DURABILITY.md` for the exact classifier and error-history limits.

The shared `copycontract` v4 manifest preserves the original JSON byte-name/xattr
encoding and bounds. Startup requires trusted read-only physical preflight before
any recovery writes. The successor performs private RollbackCopy or
ResumeCopyDirectory while unrelated private actions and ordinary DATA remain
fenced. Normal SEALED recovery also uses that server-owned rollback, rather than
issuing unjournaled ordinary FUSE undo operations. Cache invalidations cover the
known affected volume objects and manifest dentries under the same namespace gate.

COMPLETED plus an unresolved directory tail is a narrow exception to the completed
ID tombstone rule: only its exact replay and auxiliary Begin remain actionable.
CompletePrepare refuses it; ReplacePrepare transfers it only after all real drains;
a new Begin cannot replace it until the exact tail is discharged. No old reply or
receipt is synthesized. A later fresh Begin then returns a new intent normally.

## Format compatibility

Lifecycle open rejects absent or unknown private copy schemas. Copy schema 1
is rejected; there is no migration API or automatic adoption of old pending
authority state. Uncertain journals remain fail-closed.

## Verification boundary

Host authority tests use synthetic descriptor identity DTOs and real private
journal fsync/rename IO. Continuation tests also kill subprocesses after real
private creation/binding/publication and cleanup boundaries, reopen, drain and
transfer to a fresh PREPARE, and check exact identity and nanosecond metadata.
They do not prove ext4 identity acquisition, dispatcher
coverage, native FUSE behavior, VM/Docker compatibility, or host lifecycle qualification.
Those integrations require their own scoped checks.
