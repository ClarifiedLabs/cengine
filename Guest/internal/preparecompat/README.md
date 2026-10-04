# RTM096 normal+A7 Guest carrier

Explicit compile tag: `cengine_prepare_compat`. Profile: `rtm096-normal-a7-v1`.
Ordinary builds select `profile_inert.go`, advertise an empty hello, reject arm,
and cannot construct a live witness. No environment activation or native-fault
compile tag is used.

## Carrier interface

- Shared DTOs: `Arm`, `Credential`, `Observation`, `ObjectIdentity`, `BootBinding`,
  `Scope`, `MountBinding`, `Slot`, `SourceAtimes`. Exact frozen lowerCamel JSON keys.
- Required observation `sourceAtimes: {root, a, z}` contains unsigned nanoseconds
  in `0...Int64.max`. Missing/null/unknown fields and overflow are rejected.
- `CanonicalArmData`, `ArmDigest`, `DecodeArm`, `DecodeObservation` enforce the
  closed bounded contract. `testdata/vectors.json` is the shared Swift/Go vector
  source; includes UInt64.max, reordered arrays and Unicode/escape controls.
- workloadstorage retains local **defined types**, not aliases, for its existing
  four DTOs. Underlying shared structures are identical, and conversions are
  explicit.
- Arm command: `command/prepare-compatibility-arm`, data `{compatibilityArm}`.
  Positive reply data `{compatibilityDigest}`. Ordinary error/code unchanged.
- Enabled hello data `{compatibilityProfile}`. Checkpoint operation
  `prepare-checkpoint`, no kind/sequence, exact binding/scope, data
  `{compatibilityObservation}`. This travels on the existing authenticated guest
  connection to the host's independent frame reader, **not** through the host's
  serial PREPARE command lock. The host owns the separate VMShim
  `workloadStoragePrepareObservation` request/response route and validation.

## Actual path and ownership

`Session.armPrepareCompatibility` compares the complete live mount+prepare/runtime
slot sets and all currently installed PREPARE keys and actual leaf DER hashes. It
requires certificates-installed/prepare, no mount, no runtime key entry and no
previous arm. It constructs a `Witness` only after all comparisons, then installs
through private `supervisorWorkload.installPrepareCompatibility` into the actual
PID1 `Supervisor.InstallPrepareCompatibility` before mount/DATA.

Only the selected attachment passes the witness into
`initializeManagedVolumeWitnessedAt`. Every returned CopyIntent is compared to
the full actual S/E/P/V/A/container/launch/key/RW tuple. The source must contain
exactly regular a/z. Each selected attempt records source root/a/z atimes via
confined `fstat`/`fstatat` before staging reads. These are PID1 read-only source
observations, not earlier destination timestamps or manifest Root metadata, and
are not a claim that the source snapshot itself is sealed. Capture never uses
O_NOATIME, enumeration, metadata mutation or modified copy behavior. The existing
authenticated sealed-manifest check enforces the complete two-entry vocabulary.
Missing/non-directory source, nonempty destination and nocopy cannot silently
complete an armed initializer.

After genuine sealing and authentication of the exact persisted manifest, the
hook executes immediately after the first real exclusive rename returns. It uses
real IdentityAt controls for root, transaction, published a, and staged z, checking
full ext4 handles against the root/transaction and authenticated manifest. There
is no added fsync, synthetic transaction, principal, DATA reply, drain or receipt.

Both normal and A7 emit exactly one observation at the genuine publication hook.
Normal waits for the private bounded `Witness.ObservationWritten(error)` result:
the Session worker calls it only after `s.write` has returned, released writeMu,
and completed worker accounting. Only a successful ACK lets `PublishAndHold`
return; error or owner cancellation fails closed. `Session.command` additionally
requires `NormalObservationWritten()` before constructing a successful PREPARE
reply. Therefore the full normal checkpoint frame always precedes its PREPARE
reply; the host frame reader may keep its strict expected-kind=prepare gate.

A7 sends its observation and then `select {}` forever. It never reads the write
ACK and has no context, EOF, timer, resume or release input. Observation failure
cannot cancel or release the owner. The actual supervisor initializer retains
lifecycle ownership, so teardown cannot turn it into completed PREPARE/join
evidence. Actual VM/process death remains the only A7 hold exit.

## Verification boundary

Host tests exercise codecs, real Session credential issuance/arm admission and
DTO observation transport/concurrency. Synthetic observation DTOs are not physical
copy-up evidence. This profile covers NORMAL and A7; the full nine-boundary
profile is documented in [FULL-COMPATIBILITY.md](FULL-COMPATIBILITY.md). Native
acceptance is scoped in [docs/docker-compatibility.md](../../../docs/docker-compatibility.md).
