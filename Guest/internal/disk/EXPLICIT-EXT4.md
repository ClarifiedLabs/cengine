# Explicit ext4 and the mandatory paired disk bootstrap

`MountExistingExt4(device, destination string) error`,
`InitializeExt4(device, destination, label, expectedUUID string, expectedBytes uint64) error`
and `ProbeExt4ReadOnly(device, destination, expectedUUID string, expectedBytes uint64) (Ext4ReadOnlyLease, error)`
are Linux-only entry points. Diskbootstrap's storage-only `probe-read-only`
action retains the opaque probe lease and reports `read-only-no-replay`,
without an operation UUID or filesystem/block sync. That result cannot supply
an ordinary storage root or fresh-initialization permission. PID1's lifecycle
launcher alone can consume `PromoteResume`: it binds the signed ROOT request to
the observed launch/disk, runs `AdmitLifecycleResumeReadOnly` under the still-RO
lease, and then replaces the RO mount with a journaled RW mount without releasing
its block FD/flock. The launcher must close **all** external RO root descriptors
before `Promote` and obtain a new `Root()` only after success. Admission binds the
continuously held locked device and disk content, not an old mount DTO. The worker
receives the new root via FD4 only after successful admission and promotion.
Ordinary RW boot cannot resume; a probe boot cannot initialize or open before its
admitted resume. Later authorized worker replacement may reopen the promoted root.
Ordinary storage, rootfs, PREPARE and stopped-root
inspection callers are mount-only. Stage 2 verifies its already-mounted inherited
root without opening the block device for data. There is no auto-format fallback.
The sole production initialization caller is `diskbootstrap.linuxOperations.initialize`,
behind PID1's mandatory one-shot gate immediately after kernel filesystem mounts.
New guests fail closed without a matching bootstrap-capable host; no normal guest
listener starts until an authenticated manifest is synchronized and committed.

The private port is 4105; only a concrete kernel-derived `vsock.Addr` with CID 2
is accepted. PID1 generates one cryptographic boot nonce, closes the listener before
hello on the first authenticated connection, and never reopens/replays the session.
Frames are uint32-big-endian length plus UTF-8 JSON, at most 65536 bytes, with
closed shapes and no unknown/duplicate keys, nulls, or trailing JSON. Whole-batch
validation precedes every operation; devices, mountpoints and labels are derived
from ordinals/roles rather than request paths. Inventory verifies all attached
whole virtio block devices (at most 26), kernel capacities, unique major/minor and
`/sys/class/block/vdX/serial`: `root`, then `volume0` through `volume24`.
Partitions, gaps, extra physical disks, aliases and configured loop devices fail
closed; inert virtual loop/ram devices are not attachments. Initialization is serial,
and each result contains the observed identity after filesystem and block sync.
Only a matching launch UUID and boot nonce in commit lets normal boot continue.

## Authority and ownership contract

`InitializeExt4` is an explicitly destructive capability, not a freshness detector.
Before calling, the host must durably consume one-shot authorization bound to the
exact exclusively owned block disk, VM launch, canonical UUID and byte capacity.
The caller must exclude other users of that disk (including other mount namespaces,
partitions/overlapping devices, other VMs, swap and raw writers) and privileged
mount-namespace/path mutation throughout the transition. The guest cannot establish
those host properties. EINVAL, ENODEV, zero headers, missing sidecars, matching size
or an unmounted disk **never establish freshness or authority**.

A failure may occur after destruction or mounting: **never retry initialization**
with that authorization, and do not guess cleanup/unmount targets. Report the
failure to the paired host recovery protocol. There is deliberately no fallback,
repair, fsck, relabel or automatic recovery. An existing normal mount preserves
UUID and label; ordinary ext4 journal replay remains normal kernel mount behavior.

## Local guards

- A process-local lock serializes all explicit entry points; per-instance private ops
  allow pure tests without mutable global syscall hooks. All production mount and
  initialization callers use these explicit operations.
- Device and destination are clean absolute paths. Destination must already exist.
  Every directory component is held/opened with no symlink traversal. All ancestors
  remain root-owned and not group/other writable (even sticky `/tmp` is rejected).
  Only after proving the actual visible exact ext4 device root and policy may the
  destination leaf retain arbitrary owner/mode/ACLs (including uid 1000, mode 000
  or 0777). An unmounted leaf still requires root ownership and no group/other
  write permission. Pinning a leaf alone never grants this exception; hidden mounts
  and untrusted intermediate directories still fail. No chmod/chown/ACL mutation.
  Device is pinned once, no-follow, checked as root-owned block special, and flocked.
- The actual visible mount ID comes from `/proc/self/fdinfo` for a freshly held
  directory and is matched against `/proc/self/mountinfo`, not line ordering.
  Destination replacement, hidden/stacked ancestor or destination mounts, nested
  mounts, foreign device/fs, bind subtrees, and missing `nodev,nosuid` or ext4
  `errors=remount-ro` policy fail closed. EBUSY is never success.
- Initialization rejects that major/minor mounted **anywhere** in the process mount
  namespace, including hidden records and another destination. It checks twice,
  including immediately before destruction. This is not an atomic interlock against
  privileged concurrent mounts; host/caller exclusivity remains mandatory.
- `BLKGETSIZE64` uses an actual `uint64` output buffer (not `int`), checking current
  capacity twice against the expected size. Policy accepts 4KiB-aligned sizes from
  16MiB through signed-64-bit capacity; labels are 1–16 printable ASCII bytes and
  UUIDs are nonzero canonical lowercase 128-bit hexadecimal with hyphens.
- Exactly one `/sbin/mke2fs` invocation receives the held descriptor in `ExtraFiles`
  and formats `/proc/self/fd/3`, with explicit `-U` UUID, not the original device
  path. No `blkid` dependency. A small direct superblock read checks magic/UUID for
  identity only before and after mounting; it never authorizes destruction.
- Mount names the pinned device by its own path after re-checking that the path
  still names the pinned root-owned block special (the kernel records that string
  verbatim as the mount source, and per-device consumers such as cAdvisor need
  `/dev/vdX`, not one shared `/proc/self/fd/N` spelling), uses the held destination
  descriptor, then verifies the visible exact ext4 device root and flags. Filesystem integrity remains the kernel's decision. The read-only probe and its journaled promotion are the
  exceptions: it names the pinned device descriptor itself (`/proc/self/fd/N`) as
  the mount source, never re-resolving a pathname, because it feeds no
  per-device consumers.
- `VerifyInheritedMountedExt4(device, destination) error` is stage 2's verification-only
  path after PID1 mount/verification and namespace cloning. The workload's device
  cgroup already forbids raw VM-disk access: the device node and mount root are
  pinned with `O_PATH`, never opened for reading/writing. No mount, formatting,
  ioctl, flock, root metadata change or policy relaxation occurs. Root-owned safe
  ancestors remain required; arbitrary verified root-leaf metadata remains intact.
  Two exact visible mount snapshots bracket `fstat`/`fstatfs` checks for ext4 and
  matching device major/minor. All existing mount-root, hidden/stacked/nested mount
  and safety-flag checks apply. Missing/foreign mounts fail, never trigger mounting.
  It does not observe UUID/capacity or authorize initialization; PID1's paired
  verification and caller exclusion of privileged mutation remain prerequisites.
- `InspectExt4Identity(device, destination) (Ext4Identity, error)` is read-only:
  `{UUID, Bytes}` comes from the pinned device only after verifying the exact
  visible mount, with another mount verification before returning. It never mounts,
  formats, repairs, or authorizes destruction. Host acknowledgement must still bind
  this observation to its own durable consumed authorization and launch.
- `ProbeExt4ReadOnly` mounts an existing ext4 filesystem strictly read-only for
  authenticated fresh-init resume. It holds the same transition lock, pins the device
  once `O_RDONLY`, and requires the expected UUID and 4KiB-aligned byte capacity
  to match exactly. A direct superblock preflight (magic, `s_state` VALID_FS with
  no ERROR_FS, no `EXT4_FEATURE_INCOMPAT_RECOVER` recovery-pending bit, a zero
  `s_last_orphan` at superblock offset `0xe8`, no
  `EXT4_FEATURE_RO_COMPAT_ORPHAN_PRESENT` (`0x10000` — orphan cleanup writes
  even to a `ro,noload` mount, so it is rejected outright, not merely absent
  from an allowlist), and only supported compat/incompat/ro_compat feature
  bits, per Linux `fs/ext4/ext4.h`) runs strictly before any mount; unclean,
  error-marked, recovery-needed, orphan-listed or identity-mismatched disks
  fail closed with no mount. The destination must be unmounted, trusted and
  free of hidden mounts, and the device must be mounted nowhere in the
  namespace. The mount itself is `MS_RDONLY|MS_NODEV|MS_NOSUID` with exactly
  the `noload` data option from the pinned device descriptor, so the journal
  is never replayed; the visible mount (ext4, exact device major/minor, root
  `/`, `ro,nodev,nosuid`, and `noload` or its kernel alias `norecovery` in the
  super options, no `rw`) is reverified from the held directory afterwards. It
  never formats, fscks, syncs, replays or remounts read-write. Even a mount
  syscall errno requires a fresh complete device-absence census before releasing
  the flock; an uncertain or present mount returns a cleanup-only lease with
  mount ID zero and must never be detached as if owned. A successful initial
  post-mount proof records the original mount ID. Later proof failures may roll
  back only that exact ID after a fresh snapshot; rollback cannot adopt a new ID
  from the current pathname. After a successful detach, another complete census
  must prove device absence before the flock is released. Changed/foreign mounts,
  snapshot failures, and mounts remaining elsewhere retain the cleanup lease —
  never a zero lease with every pin closed while a mount may remain. The returned `Ext4ReadOnlyLease` is an opaque
  pointer lease: for its whole lifetime it retains the pinned device FD
  (keeping the exclusive flock) and a POST-mount pinned mounted-root FD whose
  observed mount ID was proved to be the exact verified one — a pre-mount pin
  still references the underlying directory's old mount and is never
  retained. `Identity`, `Device` and `Destination` expose the verified
  record; `Root` is available only on a successfully verified (owned) lease,
  revalidates the mount and disk, and returns a readable `O_RDONLY`
  directory descriptor opened relative to the pin (the `O_PATH` pin alone
  cannot serve directory reads) — the caller must close it before `Close`, or
  the unmount fails with `EBUSY`. Idempotent `Close` revalidates and
  unmounts only the exact owned mount before releasing the pins; a failed
  unmount keeps the device lock held and leaves the lease `closePending`, so
  a retry safely repins and reproves before re-attempting the detach.
  Copies of the lease value share this state; there is nothing
  serializable. PID1 exclusive device and mount-namespace ownership is assumed
  throughout.
- `Ext4ReadOnlyLease.Promote(authorize func(*os.File) error) error` is a one-shot
  authorization boundary. The trusted callback authenticates signed host resume
  authority and performs its disk census using a borrowed readable root while the
  exact mount is proved `ro,noload`. It must not retain/close the descriptor, call
  lease methods, or mutate namespace/device state. This package does not verify
  signatures itself. Admission is bound to the continuously held locked block
  device, UUID/capacity and checked contents, **not** the old mount identity.
  All external RO root descriptors must already be closed before calling Promote.
  The borrowed callback FD closes even on panic. Fresh RO proofs follow admission;
  then the old root pin closes and a **plain, non-lazy unmount** removes the RO
  mount. `EBUSY` is terminal for promotion, not a retry or remount fallback.

  With the SAME O_RDONLY block FD/exclusive flock still held, promotion repins
  the underlying destination, proves no mount of the device anywhere in this
  namespace (including hidden records), requires a trusted unmounted destination,
  and rechecks UUID/capacity, clean VALID_FS/no ERROR_FS, no recovery, no orphans,
  supported features, no readonly feature, and **HAS_JOURNAL** with an internal
  journal (`s_journal_dev == 0`, nonzero `s_journal_inum`). External journals are
  rejected: a second device is outside the held FD/flock authority. Only then does a
  normal ext4 mount use `/proc/self/fd/<held-block-FD>` and the pinned destination
  FD with `MS_NODEV|MS_NOSUID`, `errors=remount-ro,data=ordered`. It never calls
  the ordinary pathname-source `mount()` adapter, reopens the device, formats,
  fscks, repairs, or mounts a dirty disk to replay it. There is no `MS_REMOUNT`,
  `noload`/`norecovery`, or unjournaled fallback. Linux loads the existing journal
  on this new mount; the clean-state proof means recovery is not needed.

  The ACTUAL new mounted root is repinned and verified for exact device/ext4 root,
  a nonzero mount ID, inode/device identity and unchanged UID/GID/mode, visibility,
  `rw,nodev,nosuid`, `errors=remount-ro`, and no `noload`/`norecovery` or alternate
  data mode. The mount explicitly requests `data=ordered`; Linux `ext4_show_options`
  omits it from mountinfo when it matches the on-disk default, which is accepted.
  UID/GID/ACL/xattrs are not rewritten; the inode/device and UID/GID/mode comparison is
  not a complete independent ACL/xattr attestation. `Root()` is available again
  only after success and reproves the new journaled mount. `IsPromoted()` reports
  successful open owned state, not a fresh proof. Old root descriptors are not
  transferable across this boundary. Linux may reuse numeric mount IDs after unmount
  (`proc_pid_mountinfo(5)`): equality with the old ID neither proves nor refuses
  ownership. The owned unmount, namespace-wide absence, continuously held block
  FD/flock, successful new mount and complete fresh-root postproof establish it.

  Every failure consumes promotion and leaves a cleanup-only lease retaining the
  block lock. The old mount ID is cleared immediately after successful RO unmount.
  Only a successful RW mount syscall plus complete postproof publishes the new
  ownership ID. An uncertain syscall/proof outcome leaves mount ID zero: `Close`
  MUST NOT detach whatever mount is visible, even a matching device/path/policy.
  Known ownership allows plain detach; lock release still requires a complete
  snapshot proving device absence. Snapshot errors, foreign/hidden/moved mounts
  and `EBUSY` retain exclusion. Cleanup may need external operator intervention;
  no automatic foreign-mount adoption or detach is permitted. Caller exclusion of
  other namespaces, VMs, raw writers and privileged namespace mutation remains
  mandatory throughout: `/proc/self/mountinfo` cannot prove host-wide absence.

  Linux [`fs/ext4/super.c` (v6.12)](https://github.com/torvalds/linux/blob/v6.12/fs/ext4/super.c)
  initializes no journal with `noload`; its reconfigure path cannot load that
  omitted journal. Therefore remounting the probe RW is deliberately forbidden.
  Dirty/recovery-needed disks remain refused and require separately authorized
  offline recovery; this transition never relaxes that policy.
- `SyncExt4Identity(device, destination)` holds the same transition lock, verifies
  the pinned visible exact ext4 root, opens a real directory FD relative to the
  held O_PATH pin, checks `syncfs` on that real FD and `fsync` on the pinned block
  FD, reverifies visibility, then observes UUID/capacity and verifies again. Any
  synchronization or identity error prevents a successful acknowledgement. Root
  owner/mode/ACL/xattrs are never rewritten by mount, inspection or synchronization.

Linux contracts: `mount(2)` (`MS_NODEV`, `MS_NOSUID`, errors),
`proc_pid_mountinfo(5)` (mount IDs, device/root and stacked mounts),
`proc_pid_fdinfo(5)` (`mnt_id`), `open(2)`/`openat(2)` (`O_NOFOLLOW`),
`ioctl_blk(2)`/Linux `BLKGETSIZE64` (`__u64`), `syncfs(2)` (checked real filesystem
FD), `fsync(2)` (checked block FD), and `mke2fs(8)` (`-U`). Actual paired host/guest
VZ transport, serial/CID evidence and runtime coverage require RTM-074 integration.

## Verification (no VM/Xcode/Docker needed)

From `Guest/`:

```sh
go test -race ./internal/disk ./internal/diskbootstrap
go vet ./internal/disk ./internal/diskbootstrap
GOOS=linux GOARCH=arm64 go test -c -o /tmp/cengine-disk-linux-arm64.test ./internal/disk
GOOS=linux GOARCH=amd64 go test -c -o /tmp/cengine-disk-linux-amd64.test ./internal/disk
GOOS=linux GOARCH=386 go test -c -o /tmp/cengine-disk-linux-386.test ./internal/disk
GOOS=linux GOARCH=arm64 go vet ./internal/disk
```

Pure state-machine tests run natively on macOS without any Linux side effects.
Linux native tests also validate descriptor handoff after path replacement, typed
ioctl rejection of regular files, superblock identity and visible mount ID reads,
and the file-backed superblock adapter (including `s_last_orphan` surfacing);
they never call mount or a formatter.

Only on a **disposable root Linux test machine**, explicitly opt into the real test:

```sh
sudo env CENGINE_EXT4_OWNED_LOOP_TEST=1 go test -run '^TestExplicitExt4OwnedLoopRuntime$' -v ./internal/disk
```

The runner must provide `CONFIG_BLK_DEV_LOOP=y` (at least 8 loop minors), ext4
and POSIX ACL support, `/sbin/mke2fs` with its config, and writable private `/run`
tmpfs that permits device-node opens (not `nodev`). No `losetup` or pre-existing
`/dev/loop*` nodes are needed. Missing opt-in
prerequisites fail instead of silently skipping. **No arbitrary device is accepted.**

The exec-created private mount-namespace child creates a fresh 32MiB image and
private root-owned character node (10:237), proves it with `LOOP_CTL_GET_FREE`,
then creates only the returned loop block node (7:minor). `LOOP_CONFIGURE` atomically
claims a new binding with `AUTOCLEAR`; EBUSY never means ownership or adoption.
At most 8 free-device queries/configuration candidates are tried, with no candidate
configured twice; repeated candidates after transient contention may exhaust the
bound and fail closed rather than reusing a previously raced candidate. The held loop FD and `LOOP_GET_STATUS64` prove exact backing
device/inode, offset, size limit, flags, loop number and actual block capacity.
No global device node is changed and no unknown loop is detached.

Runtime controls cover nonzero corrupt-superblock `MountExistingExt4` refusal
without formatting, explicit initialization, live-device refusal, synced data/UUID
preservation, uid 1000/mode 000/0777 and POSIX root ACL idempotence/persistence,
unsafe intermediates/symlinks, foreign-mount refusal, and the read-only probe
(success identity, `Root` dup, lease `Close` unmount), promotion (`EBUSY` with an
external RO root, same FD/flock across new journaled mount, nonzero mount ID, root
metadata/ACL preservation, and writable data persistence after clean close), plus superblock-dirty
rejections with a full-image byte-equality proof (including non-empty orphan
list and orphan-present feature). Cleanup validates the
new lease before unmounting and detaching; unexpected mounts or failed unmounts
preserve artifacts instead of calling `RemoveAll` through a mount. The parent
authenticates the child's distinct namespace against its actual parent and an
inherited namespace FD (ambient child markers are insufficient), streams logs,
uses a bounded context/process-group deadline, and separately bounds
Wait after SIGKILL (including uninterruptible kernel sleep). On an unreaped child,
preserve its artifacts and terminate the disposable VM; never blindly detach.
Never run this opt-in test on the macOS host.
