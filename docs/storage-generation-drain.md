# Generation-fenced shared-volume drain

This is the DATA/PREPARE safety contract for production managed FUSE backed by
storage-VM ext4. For deployment guidance see [Managed storage](storage-adoption.md);
for ROOT/HOST/Guest lifecycle authority see
[Lifecycle checkpoints](storage-production-checkpoints.md).

## Required invariant

After storage acknowledges `DRAINED(S,V,A)`, no request from attachment `A` can
mutate volume instance `V`, including after reconnection or restart. Every admitted
operation has released its mutation resources and passed the required durability
barrier. A drain is not rollback or proof that PREPARE succeeded; it does not
certify physical power-loss behavior.

A failed connection, cancelled task, expired deadline or dead workload does not
prove that its mutations stopped. Requests can still be queued or executing in the
kernel, transport, identity handler or filesystem.

## Identity and authenticated transport

| Identity | Meaning |
| --- | --- |
| `S` | Persistent store UUID bound to the owned backing disk. |
| `V` | Volume instance UUID bound to its name and verified root; recreation uses a new identity. |
| `A` | Fresh attachment UUID/keypair bound to `S,V`, workload launch, role and access mode. |
| `P` | Durable PREPARE attempt naming its complete, deduplicated `(V,A)` set. |
| `E` | Storage-service incarnation bound into every connection and request. |

Names, network addresses, PIDs and numeric node/handle tokens are not attachment
authority. Trusted guest init owns a private FUSE client/mount per attachment.
DATA uses mutually authenticated TLS 1.3, separate control/data credentials,
explicit versions/roles, pinned keys and immutable per-request authority.
Early data and session resumption are disabled. A workload credential grants only
its registered attachment, not registration, deletion or controller takeover.

The guest-owned TLS trust root is distinct from ROOT's installation-owned signing
key. Initial pins arrive through private VM channels bound to the held disk/ext4
UUID, exact shim/boot, pinned assets and `S,E`. Public host metadata supports exact
reconciliation; it cannot select a replacement service or reconstruct authority.
Private keys remain outside workload mounts, argv, environment and logs.

There is no transparent DATA reconnect, handle recovery or replay. Transport loss
makes the attachment terminal. Retire/drain it before issuing fresh authority to
a replacement workload VM; never relabel queued work with a new attachment key.

### Trust boundary

Trusted components are the enrolled helper, accepted signed daemon/controller/shim,
pinned guest assets, guest init/kernel and storage service. Workloads, network
traffic and stale controller connections are untrusted. Host/root compromise,
arbitrary-code compromise of the daemon or storage kernel/service, and malicious
same-account filesystem edits are outside this contract.

Signed identity accepts the configured team/identifier lineage, not one immutable
build hash. Native predecessor death and current-key proofs still gate takeover;
a signed stale controller cannot replace frozen pins or bypass the epoch CAS.
Controller takeover does not transfer a backing-disk lease.

## Filesystem and request authority

Every operation is confined to its bound `V`, including both operands of LINK and
RENAME and all handle-based operations. Retained descriptors preserve open/unlink
semantics, real link counts and inode identity. Session-local node/handle numbers
are not global capabilities; see [RTM-103 isolation](rtm103-original-consumer-isolation.md).

Lookup/FORGET, open/RELEASE and in-flight references are bounded. Kernel-live nodes
are not evicted. Data descriptors retain their open-time grants; node identity
alone grants no data access. Raw-byte names, bounded readdir, no-follow xattrs and
explicit attribute masks preserve Linux semantics. Invalidation carries
volume/inode identity translated to each client's local node IDs.

Request-time credentials use the required kernel credential ABI, including the
immutable supplementary-group snapshot. `/proc/<pid>` lookup, header-only
credentials and silent root substitution are not acceptable authority. Lifecycle
and open-descriptor operations have explicit policies; unsupported identity fails
closed. See [Kernel patch contracts](../Configuration/kernel-patches/README.md).

The client uses write-through caching, zero entry/attribute TTLs and close-to-open
data invalidation, not writeback cache or blanket direct IO. mmap is supported;
cross-VM concurrent mmap coherence and distributed locking are not promised.
Locks are client-local. These limits are not application-level serialization.

## Storage protocol and admission

Control operations are authenticated, bounded, request-ID correlated and
idempotent. Reusing an operation ID with different arguments fails. Query is
side-effect-free. Reserved control capacity prevents DATA saturation from consuming
all fencing capacity.

- **Reserve PREPARE:** atomically reserve all `V,A` pairs or none, with no clock-based
  expiry. Overlapping attempts conflict. RESERVED attachments have no DATA authority.
- **Register:** persist the exact attachment/key/role/mode binding before access.
  Nonterminal PREPARE reservations admit only their planned attachments or a
  CAS-authorized successor's; explicitly recorded active runtime peers may continue.
  Retired attachments cannot reactivate or reuse keys.
- **Retire and drain:** permanently close admission, finish admitted work and persist
  the receipt. Caller disconnect does not cancel retirement. RESERVED attachments
  also retire, fencing delayed registrations.
- **Complete or replace PREPARE:** CAS only after every preparing attachment drains.
  Completion additionally requires host attestation of successful Guest PREPARE and
  clean copy-up, bound to `P`. Replacement leaves staging for confined recovery.
  Neither operation silently deletes staging.

Every request atomically checks ACTIVE attachment, current authority, role,
reservation and access mode and increments its in-flight count **before** queues or
filesystem access. Reads, setup, flush and fsync use the same gate. Read-only
attachments reject mutations on storage regardless of guest mount flags. Count
requests, not connections; a rejected request cannot acquire authority later.

```text
RESERVED -> ACTIVE -> RETIRING -> DRAINED
RESERVED ----------> RETIRING
RETIRING -- I/O/persistence error --> RETIRING (blocked and fenced)
```

Retirement has four ordered steps:

1. Close admission under its lock and persist retirement intent. Previously received
   but unadmitted requests are rejected on every connection.
2. Wait for admitted operations, including queued work, synchronization and
   descriptor cleanup. No detached callback may outlive its count; do not hold a
   lock those operations need.
3. After the count reaches zero, run the serialized retained-resource durability
   barrier. Writeback errors remain sticky. `syncfs` after fencing is a barrier,
   not the fence itself.
4. Persist DRAINED and the exact versioned `S,V,A,P`/revision receipt, including
   required directory synchronization, before replying. Lost replies return the
   same durable result; unknown identity is never treated as drained.

Response delivery need not block drain after mutation resources are gone. Closing
a socket never decrements executing work. A filesystem call may hang: bounded API
failure is possible, but bounded successful drain is not guaranteed. Capacity
exhaustion refuses new work rather than discarding retirement evidence.

## Durable host quarantine and PREPARE lifecycle

`Sources/CEngineRuntime/HostStorageIntents.swift` persists exact store, volume,
attachment, launch and attempt context before registration, credential delivery or
PREPARE. The storage registry and host intents are outside workload-writable paths.
An incomplete durable intent is itself a fence.

Successful PREPARE stops its preparation clients and drains every preparing
attachment before completion and fresh runtime attachment issuance. It never
promotes a live preparation connection with queued writes into runtime authority.
On error, cancellation or reply loss, quarantine every potentially used attachment;
if saving quarantine fails, preserve the original intent and block in memory too.

Persist verified receipts locally before resolving quarantine. Ambiguous attempts
transfer to a fresh recovery attempt only after predecessor drain, then use the
locked, descriptor-confined copy-up recovery path. Session-local FUSE handles are
not durable cross-attachment copy-up identity. Publish terminal host state before
releasing the local reservation. Never clear staging, recreate a volume or switch
to direct-block mode merely because a VM died.

Runtime setup failure, ordinary stop and abrupt workload exit also require runtime
attachment retirement. A completed workload is not private-channel failure:
collect its actual exit result and final output, retire exact attachments, then
tear down the VM. Healthy runtime peers are not automatically retired because a
new initializer fails.

## Restart and failure policy

- **Daemon replacement:** reconcile durable intents and exact retained generations
  before starts, removal, mode changes or auto-cleanup. Stale receipts cannot clear
  a successor's quarantine.
- **Service/VM replacement:** hold the registry lock for the service lifetime and
  independently prove predecessor exit and exclusive backing ownership. Guest
  `flock` is not cross-VM disk fencing. Establish fresh `E` and finish nonterminal
  retirement before admission; zero in-memory requests is not a drain receipt.
  Old DATA mounts are not revived under new credentials.
- **Persistence/I/O faults:** malformed/missing state, identity mismatch and known
  EIO/ENOSPC/fsync failures preserve fences. A later successful sync cannot prove
  earlier uncertain IO. Only operation-specific, validated durable recovery proofs
  permit forward progress; see [Write-ahead obligations](../Guest/internal/storageauthority/DURABILITY.md).
- **Recreation and versions:** new volume instances never inherit old credentials.
  Unsupported store formats and incompatible protocols are rejected without
  modifying stored data. cengine does not migrate or automatically reset these
  stores. Production data is never implicitly disposable.

## Contract and verification boundaries

Applicable contracts are Docker [empty-volume population](https://docs.docker.com/engine/storage/volumes/#mounting-a-volume-over-existing-data),
OCI [mounts](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#mounts),
TLS [client authentication](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2.2),
and Linux [fsync](https://man7.org/linux/man-pages/man2/fsync.2.html),
[syncfs](https://man7.org/linux/man-pages/man2/syncfs.2.html) and
[rename](https://man7.org/linux/man-pages/man2/rename.2.html).
This private safety protocol adds no Docker or OCI field.

[Docker compatibility](docker-compatibility.md) owns the focused RTM/ORC coverage.
Host/component tests, mounted native DATA, API restart, worker replacement, VM death
and actual host reboot are distinct checks. A software drain, finite stress run or
VM kill does not certify physical power-loss behavior.
