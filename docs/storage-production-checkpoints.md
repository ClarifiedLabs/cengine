# Production storage lifecycle checkpoints

The privileged helper (ROOT), host runtime (HOST) and storage VM (Guest) coordinate
shared-storage authorization and recovery. [Managed storage](storage-adoption.md)
covers setup and delivery; [Generation-fenced drain](storage-generation-drain.md)
defines DATA/PREPARE safety.
This document defines lifecycle authority and recovery, not a second DATA protocol.

## Authority and version boundary

A ROOT registration represents the datastore backing `infrastructure/volumes.ext4`,
not one Docker named volume. Production enrollment is explicitly administrator
approved; ordinary startup cannot claim an owner. Production and compatibility
identities, namespaces and fault controls remain separate.

Every boot, proof and grant agrees on the ROOT verifier, store generation, binding,
controller epoch and closed protocol version. `storage-lifecycle.v2` uses distinct
signing domains and bounded canonical messages. Guest schema-4 lifecycle state and
HOST checkpoints participate in that same binding. Unsupported store formats are
rejected without modifying their data. cengine does not migrate or automatically
reset them. A separate authority namespace cannot bypass this check.

- ROOT durably preserves monotonic store-generation and grant-serial high-water
  counters and rejects overflow.
- Each live datastore retains its binding/generation, current controller/key and
  principals, latest exact completed retry, and bounded pending/fenced state.
  Limits apply to active or unresolved registrations, not cumulative completed use.
- ROOT permits at most 128 active/unresolved bindings. The per-store checkpoint is
  bounded to 96 KiB with a 16-KiB completion reservation; aggregate publication
  limits remain independent.
- Exact pending/current retries are idempotent only for the independently proven
  original recipient. Superseded epochs/generations are not re-signed from history.
- Fold completed state only after durable authenticated confirmation. Pending
  grants survive channel loss, expiry and recipient death; those events alone
  cannot supersede or delete a fence.
- Exclude aliases of active, provisioning, retiring and unresolved roots/backings.
  Retired generations never resume, even after their active ROOT entry is reclaimed.

Fresh nonexporting child keys and current/live-role separation avoid an unbounded
historical-key registry. This is not global historical key-membership attestation.
HOST preserves every old controller/service context still referenced by physical
`HostStorageIntents`. A capacity cap never authorizes losing recovery evidence.
Persisted public metadata cannot construct a `ControllerRecovery` capability.

## Native proof and private channels

ROOT independently authenticates accepted signed native processes and their exact
birth identities, private child channels and shim/service proofs. Challenges include
fresh ROOT nonces, channel incarnations and bounded monotonic counters. Native
sender/process checks bracket replies; closed endpoints revoke pending work.
Proofs are not recreated from a journal, cached daemon receipt or caller assertion.

The child owns its private key. Candidate challenge, ROOT checkpoint/signing,
exact grant binding, private Guest configuration and actual TLS result proof occur
in order. An unsigned candidate is neither an applied result nor boot permission.
Every result proof performs fresh authenticated IO.

Lifecycle TLS permits only its typed authenticated operations. Terminal result
queries do not reopen ordinary admission. Current/successor policy and reserved
capacity prevent current idle sessions from consuming all takeover capacity;
pre-TLS slots and deadlines remain bounded. Unauthenticated denial-of-service is
not claimed solved.

Durable host identity is filesystem UUID plus inode. Live descriptor device/inode
checks still apply, alongside backing size, ext4 UUID and full binding. A historical
shim specification's old device number is usable only after positive predecessor
death; it cannot bypass exact checks on the current held backing.

## Live adoption and cold recovery

**Daemon-only replacement** preserves the live storage and workload VMs. ROOT
requires exact native predecessor/controller proofs, authenticates the replacement
controller and rotates adoption authority. Fresh service proof, full Guest Query
and the physical HOST intent census gate reconciliation. Healthy DATA sessions
continue; a new daemon does not restart their containers merely to regain control.

**Cold recovery** is a separate mount-existing transaction. It requires positive
native predecessor death and exclusive backing ownership before configuring a VM.
ROOT authorization, signed-open identity, actual Guest completion, adoption rotation
and native enrollment must agree before normal issuance resumes. The completed
store uses normal journaled ext4 mounting, not formatting or the unused-store
clean-only probe. An attempted boot is not retried by substituting a new process
or key into its frozen transaction.

**First-initialization resume** requires its own protected authorization and an
unused-store census. It probes read-only before promotion to journaled ext4 without
reformatting. Clean abort retains the backing lease through worker reap, sync,
plain unmount and positive Guest shutdown. Partial or uncertain initialization
is not permission to reset the disk.

Cold work shares one absolute 120-second default/maximum deadline through nested
proofs/retries. Adoption and resume retain 30-second budgets. Expiry cancels and
joins owned work; it does not prove death, drain, or safe retry.

### Interrupted committed-cold recovery

The closed `resolve-dead` operation is the limited forward-recovery exception for
one failed cold edge whose L2 completion is already durable. It requires the frozen
store, original operation, signed-open digest and exact resolution retry ID. ROOT
independently proves native exit of every original and failed-successor daemon,
controller and shim participant. Alive, unknown, PID-reused or mismatched identities
remain blocked; transport loss is never proof of death.

ROOT persists resolution intent D1, finishes the exact original A1 adoption rotation
idempotently, then publishes distinct dead history D2. ROOT and HOST retain the
last committed controller; ordinary publication/adoption/issuance remains fenced.
Only fresh cold status/prepare may select the protected dead successor as the next
predecessor. HOST retains the original `bootAttempted=true` and exact signatures
and never configures that attempted boot again.

Recovery uses a new operation, key, native births and service epoch for a new cold
transaction. Genuine L3 completion and L4 native enrollment clear the ordinary
fence. Its authenticated completion carries one bounded historical bridge, not a
standalone permission: this owner's fresh ROOT service proof, full schema-4 Query
and exact physical HOST intent census must all pass before historical settlement.
Workload credentials remain current-controller-only. Unreferenced audit context
folds through the existing census rather than accumulating forever.

This exception does **not** resolve missing L2, uncertain Guest journal commits, a
failed recovery edge already containing a bridge, live pre-enrollment orphans, or
ordinary L3/L4 uncertainty. Those states preserve data and remain fenced. No reset,
formatting, fsck or checkpoint surgery is authorized. A normal host reboot can
establish native death, but does not itself prove transaction recovery. Helper
admission requires `lifecycle-v2-cold-dead-resolution-v1`.

## Explicit datastore retirement

Datastore retirement is not Docker volume removal or test-directory cleanup:

1. Authenticate the current owner and exact binding/generation. Refuse outstanding
   grants, operations or uncertainty; a daemon assertion is not drain proof.
2. Close Guest admission, drain owners and complete retained-resource barriers.
   Publish the irreversible terminal seal for this generation.
3. Obtain a fresh direct authenticated child result bound to ROOT's challenge,
   binding/generation, controller/service and actual durable seal.
4. ROOT persists the terminal result before reclaiming the active alias/count entry.
   Lost replies retain the fence until independently re-proven; no timeout reclaims it.

Guest refuses to reopen a sealed generation for work. Fresh provisioning needs a
fresh generation and fresh-store proof, not adoption of sealed bytes. Sealing
revokes authority; it does not prove VM/process exit or permit disk deletion,
reformatting or reuse. Those require independent host writer-exclusion proofs and
explicit disposition of user data.

## Physical checkpoint publication

`Sources/CEngineNetworkHelper/StorageBootstrapCheckpointJournal.swift` publishes
complete authenticated snapshots through owned descriptors. Its typed signer
accepts validated lifecycle grants, not arbitrary messages or pruning instructions.

- Permanent `authority.lock` (`CEBSL001`) binds the configured owner and ROOT public
  verifier. Ownership, mode, ACL, local filesystem, held/named identity and contents
  are checked; its exclusive lock survives snapshot replacement.
- `authority.journal` (`CEBSC001`) includes owner, private ROOT seed, sequence and
  snapshot. Never copy it into ordinary logs. One 32-MiB snapshot, one bounded
  `authority.next`, lock and marker bound publication to 64 MiB + 84 bytes. This
  bounds file sizes, not allocation or available space.
- Persist the publication marker and directory before candidate creation; fully
  synchronize the candidate, rename it, synchronize the namespace, remove the
  marker and synchronize again. Failed publication releases no signature/result
  and poisons the instance while preserving refusal artifacts.
- Reopen refuses marker/candidate residue, missing state, wrong owner/key, bad
  authentication, incompatible schema and malformed namespace. It never chooses
  an older snapshot, truncates, regenerates keys or automatically repairs state.
- Fresh creation requires an empty protected directory in the fixed authority
  namespace. A versioned sibling path cannot bypass existing authority.

Sequence numbers are not an independent anti-rollback anchor against root
compromise. An intact checkpoint is not fresh liveness proof, and a terminal seal
is not permission to dispose of the backing.

## Verification boundaries

[Docker compatibility](docker-compatibility.md) owns the runtime contract inventory.
Cross-language sustained checkpoint tests establish bounded logical state, not
thousands of native VM lifecycles. Native fresh/retry/refusal, live daemon adoption,
service/VM replacement, interrupted-cold recovery and host reboot have distinct
contracts. Installed production reboot acceptance does not certify arbitrary
power-loss or repair of uncertain disk writes.

Publication relies on Linux [fsync](https://man7.org/linux/man-pages/man2/fsync.2.html)
and [rename](https://man7.org/linux/man-pages/man2/rename.2.html); native death relies
on observed process lifecycle, not EOF or a timeout. Known/ambiguous I/O fences
remain governed by [Write-ahead obligations](../Guest/internal/storageauthority/DURABILITY.md).
