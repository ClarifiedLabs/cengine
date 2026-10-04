# Managed data write-ahead obligations

The private authority disk format requires `durability: 1`, independently of
lifecycle registry schema 4 and workload receipt/DATA journal schema 3. Lifecycle
open rejects older/missing/newer durability
formats; there is no automatic upgrade, state adoption, or online repair path.
Old versions also reject this added field through their closed JSON decoder.

`Guard.BeginDurability(sequence)` binds one live authenticated request to its
complete attachment binding, current service epoch, current controller, and exact
uint64 stream sequence. Before any mutation or flush/close barrier, it exclusively
creates `data-uncertain`, writes its bounded canonical record (maximum 2048 bytes),
fsyncs it, closes it, and fsyncs the journal directory. A single service-global
namespace gate permits one outstanding record; no per-read journal or unbounded
per-operation history is introduced. Control commits and final retirement use
separate markers and cannot erase this obligation. Volume create/delete already
have durable pre-mutation lifecycle records.

The managed dispatcher performs the mutation, ordered syncfs (including namespace
and metadata), and reply/event validation before completing the obligation. EIO
or ENOSPC from the operation itself is sticky even if a subsequent sync succeeds.
Flush/fsync/fdatasync/release errors, partial namespace bookkeeping, panic, and
pre-completion persistence failures retain the fence. Completion requires unlink
plus parent fsync before reply publication. Failed/abandoned obligations poison
this Authority; guard release, cancellation, timeout, and later successful sync
cannot clear mutation uncertainty. The retirement barrier has its existing independent write-ahead fence.
A successful syscall returning an ordinary policy/path errno, with successful
ordered synchronization and no sticky error, does not permanently quarantine.

A fresh process refuses any `data-uncertain` entry *before* rotating E or issuing
credentials/receipts. Neither valid successor credentials nor ROOT grants bypass
this check. Exact earlier receipts are left untouched on disk. A crash after
successful ordered IO and obligation unlink may recover even if the acknowledgement
was lost; no new receipt is inferred from this. Any crash earlier in the operation
is conservatively repair-required, including a crash before the syscall after
recording intent. There is no promise of repairing a genuinely ambiguous fault.

**Post-completion cleanup boundary:** marker unlink is attempted only after the
mutation and ordered synchronization are known successful. A subsequent marker
cleanup error suppresses the reply and poisons the live authority; quarantine is
best-effort. If unlink became visible and the process dies before quarantine can
persist, restart may proceed with the already-completed data. Marker absence does
not prove that cleanup returned success or that a reply was delivered. Preserving
every observed cleanup error across immediate crash cannot be guaranteed on the
same faulting filesystem: a completion witness has the same visible-write/error
ambiguity. That stronger error-history contract needs an independent witness or
conservatively blocking successful crash windows; it is not claimed here.

Poison is terminal for the whole service. The trusted parent must stop/join the
process or VM; teardown releases resources but is not a drain receipt and does
not clear uncertainty. Service.Close intentionally rejects retained resources.
Every data fault does not itself automatically exit PID1; the parent must perform
the existing terminal-service containment path.

## Certified retirement completion

The generic `barrier-uncertain` fence is still durable before the configured
retirement barrier runs. Only after the **entire** barrier returns nil and the
live authority passes its concurrent-fault check may it atomically replace that
fence with a bounded version-1 completion certificate. The certificate binds the
complete store/volume roots, bootstrap, epoch/controller, attachment binding,
retirement operation, next revision and exact predecessor/successor state digests.
The predecessor is captured after the barrier, so unrelated control commits or a
legitimate takeover during drain cannot be mistaken for an older state.

On startup, a certificate is usable only after ordinary state/root/operation and
`ExpectedStartup` validation, including agreement with any metadata commit proof.
The exact predecessor stays RETIRING without a receipt; a normal retry must run
its real barrier again. The exact durable successor retains its existing receipt.
Startup does not invoke the barrier or mint a receipt. Metadata recovery completes
before the certified fence is discharged; both cleanups are retryable across death,
and normal epoch rotation happens afterward. Pending/legacy barriers, DATA
uncertainty, known-error quarantine, malformed proofs and mismatched bindings
remain fail-closed. Metadata `proof-*.tmp` and `state-*.tmp` never authorize recovery.

**Conditional retirement candidate:** the complete canonical retirement candidate
is different: its first byte can only be written after the entire barrier has
already succeeded. Beside the securely read, byte-exact generic fence, exactly
one private, owned, single-link `barrier-<Attempt>.tmp` may therefore witness that
earlier completion even before its own fsync. The directory census is bounded to
256 entries. This path requires the exact RETIRING predecessor, no selected receipt
and no metadata proof; the full tuple, both digests and all startup guards still
apply. Malformed/multiple/stale candidates or a corrupt published certificate
refuse unchanged. Candidate absence or partial bytes never imply completion.

Recovery syncs and closes the validated candidate, renames it over the generic
fence, then performs ordinary certificate cleanup. The new sync makes that cleanup
retryable; it does not prove an earlier uncertain barrier succeeded. No receipt
is created and the ordinary retirement retry still needs its full barrier.
Persisted known-error fences always dominate. A candidate without the generic
fence stays inert; published certificates retain their existing independent rules.

A failed barrier cannot certify completion. Later observed persistence errors
still poison the live authority and persist quarantine best-effort. As with the
metadata protocol, death before that quarantine can leave a proven durable
predecessor recoverable after a candidate-write/cleanup error. This does not claim
universal preservation of error history on the same failing filesystem, nor does
it infer that an earlier uncertain barrier succeeded from a new sync.

## Root-only PREPARE retirement retry

A separate version-2 `prepare-root-only-retry` record may replace the generic
barrier fence **before** the barrier only when both the trusted live registry and
authority prove an already-durable baseline with no dirty owner. It is not a
barrier-completion certificate. It carries full store/volume/root, epoch/controller,
bootstrap, binding, retirement operation, exact predecessor revision and digest;
it has no successor digest, receipt or assertion that a close/sync succeeded.

Only successful fresh PREPARE/RW session initialization with no inherited sessions,
objects or sticky faults may establish eligibility. The only subsequent requests
allowed are exact root GETATTR without a handle and harmless read-only root OPENDIR.
Every other request, private action, error or failed validation permanently clears
eligibility before execution. READDIR/READ/LOOKUP/RELEASE/FORGET and successful
writes followed by sync/cleanup are not exceptions. The registry requires the sole
live session, exact linked-root node/object references and read-only directory
handles, matching mount identities, no orphan/foreign pins and no sticky error.
It holds the namespace gate through synchronous, at-most-once publication.

The authority separately requires the selected RETIRING/PENDING owner, zero
inflight work, every other attachment genuinely DRAINED, no DATA/copy/replay or
metadata uncertainty, and all roots plus canonical state bytes unchanged. Any
historical copy intent must be COMPLETED under a different drained owner. The
marker is atomically written/fsynced/closed/published before the unchanged full
barrier; there is no intermediate generic marker on this eligible path. Inspection
or publication errors poison; only clean ineligibility takes the old generic path.
After real barrier success, normal v1 completion certification and receipt commit
still apply. Dedicated `prepare-retire-*` temporaries stay inert and never enter
the generic completed-candidate census. Like other inert journal temporaries they
are retained, not silently collected; the existing 256-entry candidate census
remains a conservative bound, not an unbounded crash-loop liveness guarantee.

Startup checks ExpectedStartup, every retained root, exact predecessor/proof and
all eligibility relationships before clearing just this marker durably. Metadata
proof overlap or any unknown/known-error obligation refuses. The owner remains
RETIRING without a receipt and its PREPARE remains PENDING. Normal fresh-epoch
Retire retry must perform a real barrier before supplying a receipt; an empty
replacement registry cannot manufacture another root-only certificate. Older
binaries reject the new closed record, and retained bare barriers cannot be
retroactively classified. A later sync never proves earlier errseq/close success.
The same best-effort error-history limitation on a failing filesystem applies.

RTM-110 selects five exact names: helper negatives, parent and published,
inside-real-barrier, and completed process-death controls. Earlier real ACK/drain,
owned pidfd SIGKILL/sole Wait, repeated guarded opens, no fabricated receipt and
actual ordinary-barrier retry/readback are required. Native acceptance is recorded
in `docs/docker-compatibility.md`; RTM-107's bare-marker refusals are unchanged.

## Operation-specific PREPARE DATA recovery

Plain `data-uncertain` v1 is unchanged and always refuses. A trusted dispatcher
may instead record a closed `copy-operation` v1 action after authenticating the
entire exact recovery domain under the namespace gate:

- `rollback-sealed`: same-name NOREPLACE publication of an authenticated top-level
  staged entry into the exact root, or root-only owner/mode/time/xattr changes
  without truncation/open semantics, during the owned SEALED intent.
- `prepare-directory-tail`: fsync/release of an exact read-only directory grant
  for root/transaction/staging during SEALED/CLEANING/COMPLETED. No file writes,
  file releases, foreign objects, runtime-role DATA or unsupported mutation class
  gains this exception.

The canonical record binds current controller/epoch, full PREPARE binding, exact
root, sequence and entire Before intent (including authenticated manifest and
cleanup identities). It describes a whole-intent recovery domain, not permission
to replay arbitrary operands or old FD numbers. Record write/fsync/close precede
atomic publication and parent sync; execution starts only afterward. Incomplete
prepublication temporaries are inert. Old binaries reject the new closed actions
in both physical records and persisted replay ledgers before startup mutations.

Startup checks ExpectedStartup, all state/roots and every replay, then performs
mandatory read-only physical preflight before any evidence cleanup or epoch
rotation. Missing preflight, substituted manifests/private objects or any generic
uncertainty/quarantine refuses. It persists pending recovery, retains the DATA
fence, and requires ordinary genuine drains and all-volume ownership transfer.
Even COMPLETED plus pending tail stays fenced; Begin cannot discard that record.

Private RollbackCopy reauthenticates and preflights the complete bounded manifest,
public ancestor chains, staged/private identities and root xattrs before mutation.
It restores original ownership/mode/xattrs, removes only matching owned public
objects child-first, restores Initial times, syncs, then enters durable CLEANING.
Replaced public ancestors and unknown children are preserved. CLEANING never
rolls back public data again. FinishCopy owns evidence cleanup. ResumeCopyDirectory
only performs a fresh synchronization; it does not claim the old close succeeded,
replay an old grant, or mint a receipt. Classified syscall/sync/close/persistence
errors still poison; persisted quarantine dominates. The same best-effort
error-history limitations described above apply; this is not general uncertain
DATA repair or power-loss certification.

## Verification boundary

Portable authority subprocess tests exercise every write-ahead/clear boundary,
EIO/ENOSPC persistence failure, guard abandonment, independent commits, max-uint64
binding, clean reopen, retained receipts, and an externally observed ACK prefix.
The synthetic authority fixture barrier is not an ext4 drain proof.

`storagemanaged.TestManagedDurabilityFaultCrashFencesRestart` exercises the real
Linux dispatcher and authority with actual filesystem mutations, separate
subprocess death, private EIO/ENOSPC hooks at syncfs/fsync/namespace/metadata, and
external ACK capture. It requires the matching managed kernel, root capabilities,
and ext4 TMPDIR as the existing package suite. Hooks are test-private, bounded,
and never fill or damage a host disk. Native Darwin testing and cross-compilation
are not execution of these Linux tests, VM crash acceptance, or physical-power-loss
acceptance. No production fault-injection API or activation switch is provided.

### Separate native process-death policy lane (RTM-107)

`storagemanaged.TestNativeDurabilityPolicyProcessDeath` uses actual ext4 and the
real dispatcher/Registry.Barrier. It holds after successful real syncfs, before
the DATA obligation or retirement barrier is discharged. An owned parent records
an earlier actual ACK and drained receipt before authorizing the selected
operation, then uses pidfd SIGKILL and the child's sole actual Wait. Repeated
Lifecycle open and exact-predecessor reopen must return nil plus typed
`ErrRepairRequired`, with every bounded regular-file registry entry byte-identical,
no epoch/controller/revision advancement, no new selected receipt, and the earlier
ACK prefix/receipts preserved. Releasing the same holds before death provides
completed-operation controls that must reopen successfully with fresh epochs.

The separate RTM-107 native selector requires those four leaves, their three
parents and helper negatives (eight exact names, zero skips). Execution/acceptance
status is recorded in `docs/docker-compatibility.md`. This tests process death
while the Linux kernel and filesystem remain alive—not VM death, journal replay,
power loss, PREPARE NORMAL/A6 reproduction, or authenticated host bootstrap.
Nil authority proves no admission through the failed construction path; it is not
proof that the host exercised every replacement route. RTM-098/099 successful
recovery aggregates are unchanged. No pending marker is cleared or uncertain store repaired.

### Certified retirement process-death lane (RTM-108)

`storagemanaged.TestNativeRetirementRecoveryProcessDeath` complements RTM-107.
The tagged, test-private adapter observes only real completed journal boundaries,
with no injected successful IO or caller-supplied filesystem descriptor. Real
Registry.Barrier resource closure and syncfs must complete before the bound hold.
The parent fsyncs an earlier ACK/receipt manifest, validates exact disk evidence,
then pidfd-SIGKILLs and genuinely Waits its child. Cuts cover the completed retirement candidate before fsync, certificate publication,
A6's unpublished receipt candidate/Ready temporary, durable successor publication,
and completed Retire. Repeated lifecycle open/reopen must preserve the exact
predecessor or successor, prior ACK/receipts and inert temporaries while rotating E;
no new receipt, admission or barrier call is permitted during recovery.

The selector requires seven exact names (parent, five leaves, helper negatives),
zero skips and the existing bounded ext4 fixture. Execution status lives in
`docs/docker-compatibility.md`. This is process death with kernel/filesystem alive,
not VM death/remount/power-loss, nor RTM-099's integrated acceptance. RTM-107's
hold remains **inside** the configured syncfs barrier, before it returns, so its
legacy pending marker continues to refuse; no certificate is published there.

### PREPARE DATA process-death lane (RTM-109)

`storagemanaged.TestNativeCopyDataRecoveryProcessDeath` selects five actual-ext4
cuts: rename, root metadata, and SEALED/CLEANING/COMPLETED directory tails. Real
syscall and fsync/syncfs precede the owned hold; parent-fsynced ACK/receipt evidence,
pidfd SIGKILL and sole Wait precede repeated lifecycle open/reopen, genuine drains,
fresh-owner private recovery and a populated retry. Helpers reject altered
manifests, foreign staging and known EIO/ENOSPC, and preserve public replacements
and matching hardlinks beneath replaced ancestors. Seven exact names, zero skips
and bounded owned cleanup are required. Native execution status is maintained in
`docs/docker-compatibility.md`; cross-compilation is not acceptance.
