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
  bounded to 192 KiB with a 16-KiB completion reservation; aggregate publication
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

Cold bootstrap work shares one absolute 120-second default/maximum deadline
through nested proofs/retries; resume bootstrap retains its 30-second budget.
Native fresh adoption has 30 seconds, cold/resume enrollment has 90 seconds, and
adoption reconnect has 5 seconds, inside the daemon/shim channel's 110-second
request budget. The RTM-135/136 successful-recovery readiness wait is separately
bounded at 240 seconds to cover bootstrap, enrollment and fresh service proofs;
other fixture starts keep their 60-second default. A harness wait never extends
runtime authority or protocol deadlines. Expiry cancels and joins owned work;
it does not prove death, drain, or safe retry.

Failed **unenrolled cold launches** use the same bounded, single-flight shutdown
as failed initialization/resume. Initial-channel EOF starts cleanup; it is not exit
evidence. The shim exits only after joined teardown positively stops the VM and
releases its machine/disk ownership. An enrollment ACK published by ROOT wins
atomically over detachment, including when the daemon never receives its reply;
that enrolled VM survives. RTM-135 covers failed cold configure, natural native
exit and unchanged observed recovery; RTM-136 covers Guest application without
helper completion and applied observed recovery. Both passed locally with paired
current Guest assets and a separately built managed kernel.
RTM-132 no longer uses test-side SIGKILL to mask missing cleanup.

Cold startup failures emit secret-free phase, public operation ID, concrete error
type and closed error code breadcrumbs. These do not wrap the underlying error or
change retry/authorization decisions. They distinguish Guest configure/transport
failure from controller authentication and protected ROOT completion failure.

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

This L2-only exception does **not** resolve a missing L2; that case has the separate
observed path below. Uncertain Guest application-journal commits, failed recovery
edges already containing a bridge, live pre-enrollment orphans and ordinary L3/L4
uncertainty preserve data and remain fenced. No reset, formatting, fsck or checkpoint
surgery is authorized. A normal host reboot can establish native death, but does not
itself prove transaction recovery. Dead-resolution helper admission requires
`lifecycle-v2-cold-dead-resolution-v1`.

### Observed pre-L2 cold recovery

A frozen attempted cold edge without protected helper L2 completion can now recover
only through an exact read-only Guest registry observation. ROOT independently
proves positive native exit of all original and failed-successor daemon, controller
and shim participants, and verifies that the original adoption snapshot is still
committed. HOST retains the exact abandoned request, signatures and
`bootAttempted=true`; it never reruns that boot or invents its completion.

1. **O1 — protected intent.** HOST records the exact observation request before ROOT
   IO. ROOT durably retains the failed transaction and signed observation
   authorization before release. It binds a distinct observation ID, the canonical
   original signed-open bytes and a fresh observer launch on the same store/backing.
2. **Native observer proof.** ROOT challenges the independently authenticated native
   observer shim over its private channel, with exact daemon/shim births, fresh
   nonce, counter, expiry and held-backing verification. Guest verifies ROOT's
   authorization, opens only existing application-journal files read-only and takes
   the real exclusive registry `flock`. It validates schema-4 identity, roots,
   lifecycle state, volume roots and clean artifact namespace. This is not a HOST
   checkpoint inference or a caller-supplied projection.
3. **Exact projection only.** `unchanged` equals the original signed predecessor in
   full. `applied` requires the exact original takeover grant/key at C+1, a new
   service epoch, increased open revision and unchanged bootstrap key, plus the
   matching durable `ColdApplied` request digest/grant/service/revision marker.
   Any other registry state or uncertain publication/artifact residue refuses.
4. **O2 — protected result.** ROOT durably records the concrete projection and its
   original committed anchor after repeated native observation/death/adoption
   checks; HOST persists the returned history before child selection/configure.
   Cached O2 is not fresh proof: this owner must freshly observe it again. The new
   Guest takeover repeats projection admission under its actual journal `flock`,
   before startup cleanup, recovery or publication writes.
5. **Genuine new cold transaction.** Select the observed predecessor with a new
   operation ID, nonexporting child key and higher grant serial, fresh native births
   and service epoch. `unchanged` advances Guest C once from the original predecessor;
   `applied` advances once from its observed C+1. ROOT/HOST keep the original committed
   receipt/service/controller anchor until real new completion. Adoption rotates
   directly from the original committed snapshot to the new successor: there is no
   synthetic failed enrollment, failed-edge receipt or intermediate adoption rotation.
   Actual new L2/A1/L3 completion and L4 native enrollment, this owner's fresh ROOT
   service proof, full authenticated schema-4 Guest Query and exact physical HOST
   intent census gate reconciliation, historical settlement and normal admission.

Observation/history is never a `Receipt`, `ServiceState`, TLS trust, enrollment or
standalone recovery authority. There is one bounded observed bridge, not recursive
recovery: a failed new observed recovery edge or uncertain nested state remains
fenced with data/evidence preserved. This path does not repair application journals,
remove uncertain artifacts, format, reset or authorize fsck/checkpoint surgery.

The observer and subsequent configure use the **same mounted ordinary cold ext4**
store. Normal kernel ext4 journal replay on mount is allowed; read-only application
journal loading does not mean a read-only filesystem or a no-replay mount. This is
not unused-store initialization resume or its clean-only/no-replay probe. Kernel
replay is not proof that an uncertain application publication completed.

Admission requires helper capability `lifecycle-v2-cold-observed-recovery-v1` and
paired Guest metadata `storageColdObservationVersion: 1` in `disk-bootstrap.json`.
Older helpers or assets missing this explicit version fail closed, with no fallback
to replaying the abandoned attempt.

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
contracts. RTM-135/136 in `Tests/Compatibility/test_storage_lifecycle_v2_runtime.py`
passed local native verification with the managed kernel: their harness requires
automatic retained `always` peers,
unchanged store/disk/manifest/volume identity, saved seeds and new bidirectional shared
DATA. It does not directly capture Query evidence; the runtime Query/census gates
have unit coverage, while actual shared DATA demonstrates end-to-end admission only.
These cases do not establish actual OS reboot acceptance, power-loss durability or
a full VM-suite pass. Attended installed-production reboot acceptance remains a
separate gate, not certification of arbitrary power loss or uncertain disk repair.

Publication relies on Linux [fsync](https://man7.org/linux/man-pages/man2/fsync.2.html)
(including directory synchronization for namespace durability),
[syncfs](https://man7.org/linux/man-pages/man2/syncfs.2.html),
[rename](https://man7.org/linux/man-pages/man2/rename.2.html) and
[ext4 journal recovery](https://docs.kernel.org/filesystems/ext4/journal.html).
Ordinary ext4 kernel replay is distinct from application-journal repair; neither
observation nor a later sync erases an uncertain application commit. Native death
relies on observed process lifecycle, not EOF or a timeout. Known/ambiguous I/O fences
remain governed by [Write-ahead obligations](../Guest/internal/storageauthority/DURABILITY.md).
