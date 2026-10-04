# Full-profile PREPARE IO faults (RTM-100)

The fault catalog covers authority persistence and server cleanup boundaries.
`InstallPrepareCompatibility` is privileged boot wiring:
its caller must authenticate the signed
full-profile plan before installation. No principal/control command installs a
fault. `prepareCompatibilityEnabled` enables installation only with
`cengine_prepare_full_compat` and neither older PREPARE profile tag. The native
fault-test tag alone is inert.

## Carrier contract

Use the existing `PrepareCompatibilityPlan` unchanged, with `Stage` exactly
`io-eio-<point>` or `io-enospc-<point>`. Existing epoch, controller, exact target
binding, all PREPARE bindings, and reserved runtime-attachment validation remain
mandatory. The binding includes store, volume, attachment, prepare, container,
launch, key, role and mode. No operation, request sequence, path, journal name,
errno number, or occurrence selector is accepted by this plan.

`PrepareCompatibilitySnapshot.IO *PrepareCompatibilityIO` is nil for older
cases. For IO cases it is initialized to `{Point, Errno: "EIO"|"ENOSPC"}`.
At the first exact owned boundary, it becomes:

- `Fired: true`, `Occurrence: 1` (fixed FIRST, not configurable).
- `Sequence`: actual accepted copy request sequence, or zero for retirement.
- `Operation`: actual retirement operation UUID, or empty for copy.
- Snapshot `State: "observed"`; copy cases also have `Admitted: true` and the
  actual snapshot `Sequence`. Retirement also sets snapshot `RetireOperation`.

Snapshots copy the IO record; callers cannot mutate witness state. Observation
is error-injection evidence, **not successful drain, receipt, or recovery proof**.
IO cases do not use Release/ClaimWorkerExit and never enter a success state.
The plan itself contains no requested sequence or operation. An unmatched case
remains armed rather than faulting unrelated work.

## Closed points and actual operations

| Point | Actual owned operation / failed journal boundary |
|---|---|
| `copy-operation-write` | FIRST owned `BeginCopyOperation` with action `CopyOperationBegin` / `copy-op-write` |
| `copy-operation-sync` | FIRST owned `BeginCopyOperation` with action `CopyOperationBegin` / `copy-op-sync` |
| `seal-persist` | exact live guard's seal obligation and `SealCopyManifestDigest` commit / `state-sync` |
| `cleaning-persist` | exact live guard's cleanup obligation and `StartCopyCleanup` commit / `state-sync` |
| `finish-persist` | exact live guard's finish obligation and `FinishCopy` commit / `state-sync` |
| `retire-intent-persist` | exact target retirement intent commit / `state-sync` |
| `retire-barrier-persist` | exact target retirement's barrier marker / `marker-sync` |
| `retire-receipt-persist` | exact target retirement receipt commit after actual barrier / `state-sync` |
| `retire-barrier-clear-persist` | exact target retirement barrier-marker clear / `barrier-clear-sync` |

The private journal hook is scoped while `authority.mu` is held, removed on
return, and never spans the unlocked backing-store barrier. Existing `j.fault`
and `j.afterStep` are preserved. Their ordinary error/ordering behavior remains;
an earlier existing-hook failure does not claim that this IO fault fired.
There is no generic next-fsync selector. Invalid or unrelated ownership and
legacy copy commits without the exact live obligation cannot consume a point.

## Authority fault classification and verification

All eighteen EIO/ENOSPC cases are **sticky / offline repair required** in the
real returned-error path: errors retain the unix errno and `ErrBlocked`, later
Query/Admit are blocked, and Close/Open returns `ErrRepairRequired`. Existing
poison/quarantine behavior is unchanged. No recoverable case is claimed.

`retire-barrier-clear-persist` is deliberately different from an uncommitted
receipt: the receipt has already committed and the attachment is internally
DRAINED, but the failed clear poisons the authority, returns no successful
receipt, and cannot permit reopening. Intent/barrier/receipt failures do not
manufacture successful completion. These are returned-error tests, not crash
replay tests or claims that a genuinely failing disk can always write quarantine.

`prepare_io_test.go` covers all eighteen cases through production authority
methods and real host journal IO, preceding unrelated commits, real root sync
barriers, sticky reopen, copied snapshots, owner-component mismatches, the closed
catalog, and unowned/idempotent seals. Host copy identity uses the existing
synthetic ext4-handle adapter; no Linux/ext4 runtime or VM coverage is claimed.
Default/older/conflicting/native-only profiles are checked as inert. Host race
tests and Linux cross-compilation do not establish signed-carrier, VM or
end-to-end RTM-100 behavior.

## Provision and server cleanup faults

The same signed-full-only installation supports six provision/cleanup points,
each with EIO and ENOSPC and fixed FIRST occurrence, using the same plan and
snapshot fields.

| Point | Actual owned operation / failed boundary |
|---|---|
| `provision-rename` | `Guard.ProvisionCopyTransaction`, exact live PROVISION obligation / `copy-private-publish`, before private-to-public no-replace rename |
| `provision-parent-sync` | same obligation / `copy-public-parent-sync`, after rename and before public parent fsync (not private creation/source-parent sync) |
| `child-unlink-parent-sync` | `Session.finishCopyCleanup` under exact live FINISH / first non-manifest child's successful unlink, before its parent fsync |
| `manifest-unlink-parent-sync` | same FINISH / successful `manifest.json` unlink, before transaction-directory fsync |
| `transaction-unlink-parent-sync` | same FINISH / successful transaction-directory unlink, before public root-directory fsync |
| `root-restoration-syncfs` | same FINISH / exact root timestamp restoration, before final backing-root syncfs |

`PrepareCompatibilityCleanupIO` is a narrow trusted-server bridge, not a public
fault installation API: only those four cleanup points are accepted, and a live
`BeginCopyOperation` FINISH token supplies the actual sequence. It validates the
exact guard, intent, current epoch/controller, target binding and CLEANING phase.
No plan/request may choose a path, errno number, ordinal or operation token. The
private server hook latches the registry error; normal Dispatch completion
poisons authority and retains the durable obligation. An absent child/manifest
cannot consume its point, nor can preflight, legacy calls or another guard.

Transaction removal requires an explicit root-directory fsync before restoration,
separate from the final root-restoration syncfs. This applies to ordinary builds
too; no phase completes until final syncfs and `FinishCopy` commit succeed.

All twelve provision/cleanup cases retain the **sticky / offline repair required**
expectation. Host authority regressions execute both provision syscalls, check
private/public object placement, fail-closed Query/Admit/Retire and reopen, and
exercise cleanup hook ownership. Host managed regressions execute real Dispatch,
FINISH obligation and durable poison with a substituted Linux filesystem body.
The Linux-only `TestPrepareIOPhase2ActualLinuxCleanup` exercises actual ext4
cleanup, verifies removed objects, exact sync counts/root restoration, retained
obligation and sticky reopen. Linux arm64 cross-compilation alone is **not** a
runtime pass. Scoped native RTM-100 coverage is recorded in
[`docs/docker-compatibility.md`](../../../docs/docker-compatibility.md).
