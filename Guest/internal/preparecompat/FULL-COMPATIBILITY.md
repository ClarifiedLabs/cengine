# Full-nine v3 Guest carrier API

Profile `rtm096-full-nine-v3`, Arm version 3, explicit tag
`cengine_prepare_full_compat`. Both binaries require this tag. `CurrentProfile()` returns empty for zero or conflicting profile
tags. `SupportsArm` and `SupportsStorageArm` refuse mismatches; the closed codecs
may recognize a profile without enabling it. V1/v2 schemas/vectors/test bytes are
unchanged.

## Shared storage DTOs

Defined in `storage.go`:

- `StorageArm { Arm Arm; WorkerUUID string }`
- `StorageQuery { Version uint32; Profile, RequestID, ArmDigest, WorkerUUID string }`
- `StorageRelease { Query StorageQuery; Stage, Token string }`
- `AdmissionCut { RequestSequence uint64; Admitted bool; ReleaseToken string }`
- `BoundCut { RequestSequence uint64; Intent storageauthority.CopyIntent }`
- `DrainCut { RetireOperation string; Receipt storageauthority.Receipt }`
- `StorageObservation`: common version/profile/request/digest/worker/stage/count/
  targetAttachment plus exactly one stage-selected Admission/Bound/Drain pointer.
- `StorageStatus`: Query, State, RetirementStarted, AcceptedInFlight,
  LateAdmissionRejected, ReceiptReplayCount, optional Observation.

All public keys are the fixed contract's lowerCamelCase. APIs:

- `ValidateStorageArm`, `ValidateStorageQuery`, `ValidateStorageRelease`,
  `ValidateStorageObservation`, `ValidateStorageStatus`
- `DecodeStorageArm`, `DecodeStorageQuery`, `DecodeStorageRelease`,
  `DecodeStorageObservation`, `DecodeStorageStatus`
- `StorageQueryForArm`, `CanonicalStorageArmData`, `SupportsStorageArm`
- `ValidateStorageObservationForArm(observation, storageArm)`
- `ValidateStorageStatusForArm(status, storageArm)`

Arm digest remains `ArmDigest(storageArm.Arm)`, not the wrapper's digest. The
wrapper has a 65536-byte bound; storageboot must independently reject the complete
wrapped envelope exceeding its unchanged 65536-byte frame limit. Observations
remain bounded to 8192 bytes. These validators do not grant authority: service
installation must compare real worker/S/E/controller and every issued PREPARE
credential against actual authority state.

### Strict authority projection

`storage_authority_json.go` implements BoundCut/DrainCut JSON adapters while
retaining real authority types in the Go API. Authority journals and DATA/ioctl
representations are unchanged. Storageboot's closed reflection walker must route
its entire StorageArm/Query/Release/Status subtree through the appropriate
`DecodeStorage*` helper; reflection on the untagged authority types is not a
substitute for these strict adapters.

All of these keys are required, including zero BOUND fields:

- Intent: `id, owner, epoch, root, transaction, manifest_digest, manifest_size,
  phase, initial, cleanup, initial_captured`.
- Root: `store, volume, backing_uuid, root`.
- Object: `inode, generation, file_type, handle_type, handle_size, handle`.
- Cleanup: `uid, gid, mode, atime_seconds, mtime_seconds, atime_nanos, mtime_nanos,
  manifest, staging`.
- Owner: existing authority Binding lower-case keys; PREPARE requires `prepare`.
- Receipt: `schema, store, volume, attachment, launch, prepare, revision`.

`backing_uuid`, `handle`, `manifest_digest` are lowercase hex strings of exactly
32, 16, 64 characters. Signed seconds are canonical signed-decimal **strings**
within Int64; no plus sign, leading zero, negative zero, exponent or numeric JSON
substitute. Nanos are UInt32 less than 1e9. Other authority numbers retain their
exact UInt32/UInt64 ranges. Actual zero cleanup objects/BOUND digest are preserved;
root and transaction require genuine supported nonzero ext4 directory identities.
No fake SEALED identity/digest is invented.

## Actual guest behavior

The existing Session installation still checks actual installed full PREPARE
credentials and the complete mount/slot set before mount/DATA.

- V3 normal/A8 follow the existing real source-atime capture, sealed/authenticated
  manifest and first-rename observation hook. Normal/A8 join the independent
  observer write before successful PREPARE, then close normally. A8's actual
  Retire cut/retry is owned by the storage service, not a guest fake receipt.
- V3 A7 uses the same physical hook and remains indefinitely held after one event.
- V3 A1/A2/A3 reuse the existing before-send/accepted/actual TLS partial-frame seams
  with version-3 counters. A3 sends the actual internally sequenced DATA frame's
  first five bytes and joins observer write before closing DATA with failure.
- A4/A5/A6 start **no guest observer**. Their actual storage-owned hooks execute
  before the guest can reach physical publication. If a hook is missed, the guest
  initializer and Session success guard fail closed instead of waiting for a
  nonexistent guest event or reporting successful PREPARE.

No new release mechanism, timer, cleanup shortcut, authority callback, synthetic
principal, global native fault tag, or durability operation is introduced here.

## Shared vectors

`testdata/full-vectors.json` is generated by the actual Go canonical codecs and
verified byte-for-byte by tests. It contains nine rows:

- Every row: `name, arm, canonical, sha256, observation, observationCanonical,
  observationSHA256`.
- A4/A5/A6/A8 also: `storageArm, storageQuery, storageStatus, storageObservation,
  storageObservationCanonical, storageObservationSHA256`.
- A4/A5 also: `storageRelease`.
- A8 also: `physicalObservation, physicalObservationCanonical,
  physicalObservationSHA256` for the pre-Retire guest physical event.

The generic `observation` aliases the storage observation on storage-owned cases.
These vectors are codec fixtures, not physical execution or RTM acceptance proof.
