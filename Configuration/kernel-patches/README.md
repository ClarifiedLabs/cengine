# Downstream kernel patches

Base: Linux **6.18.44**, commit
`1efe5d048a391de3ead2804b2e7f86376c356cc5`, from
<https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git>.
These are cengine changes, not upstream backports. They retain upstream copyright
and license terms; modifications are GPL-2.0-only. See the pinned source's
`COPYING` and `LICENSES/preferred/GPL-2.0` for license text.

## Build and artifact boundaries

- **`series` contains only `0001-virtiofs-host-close-to-open.patch`.**
  `make kernel-build` runs `Scripts/build-kernel.sh`: export the pinned commit to
  a disposable tree, apply `series` with `git apply --no-index --check` and
  `--whitespace=error-all`, then use Docker Buildx through
  `Scripts/build-kernel-linux.sh`. `Scripts/compile-kernel-in-guest.sh` merges and
  checks `Configuration/cengine-kernel.fragment`, builds arm64 `Image`, and exports
  it as `vmlinux`. Source caches are never reset, cleaned or patched. The patch
  helper requires a disposable-export marker.
- `Scripts/kernel-input-sha256.sh` hashes the pin, build configuration/scripts,
  `series` order/content and **listed** patches. It does not include 0002.
  `Scripts/check-guest-kernel.sh` checks this stamp and image presence, not managed
  ABI support, runtime behavior or canonical release origin.
- **Managed kernels additionally apply
  `0002-fuse-request-credentials-experimental.patch` after 0001**, separately from
  `series`; the historical `experimental` filename is not an activation status.
  Use the isolated source procedure below when building this profile. Do not add
  0002 to `series` or mistake an ordinary `make kernel-build` result for it.
- `make kernel` defaults to release fetching through `Scripts/fetch-kernel.sh`;
  `CENGINE_KERNEL_MODE=build` selects the series-only source build.
  `CENGINE_LOCAL_KERNEL=/absolute/path/to/Image make guest-assets` installs a
  separately built managed kernel and builds guest assets. The fetcher records
  local/custom/canonical origin separately; a matching input stamp does not
  promote local bytes to canonical origin.
- Local signed **production sole-v2 works with the local managed kernel**.
  Canonical managed-kernel release publication is distinct and remains unverified;
  local operation does not establish what a published release contains. Source
  interfaces and local probe results alone are not production authorization proof.
- `tools/build-managed-fuse-artifact.py` is a **Go test-fixture compiler, not a
  kernel builder**. It requires the direct parent's original compatibility lock,
  an explicit local daemon endpoint and approved cached builder image. It builds
  arm64/amd64 tests without executing them, exports arm64 test/setup binaries plus
  the pinned formatter and provenance, and removes its owned build container.
  It neither applies kernel patches nor boots a VM nor validates a kernel ABI.

Offline build-script regression check:
`python3 tools/tests/test_guest_build_scripts.py`. Kernel compilation, probe
execution, and compatibility tests are separate checks; source application or
cross-compilation alone is not runtime evidence.

## Host-bind close-to-open policy

0001 adds the explicit virtiofs mount flag `host_close_to_open`. Only supervisor
host bind shares opt in (RO and RW), not Rosetta, cengine-io or ordinary FUSE.
The policy declines `FUSE_WRITEBACK_CACHE`, rejects DAX and conflicting reuse of
one virtiofs tag, and keeps buffered read, splice and mmap (no forced DIRECT_IO).

Regular-file opens flush guest buffered writes, force size/modification GETATTR,
and invalidate cached data even with KEEP_CACHE or same-size/same-timestamp host
rewrites. Failures release the new handle synchronously before I/O setup.
Server-atomic O_TRUNC does not flush old data into the truncated file: local size
and page-cache truncation precede fallible GETATTR, preventing old-data rebirth.

This is **close-to-open**, not continuous coherence of retained FDs/mappings or
multi-writer serialization. Reopen can fail if cache cannot safely be invalidated.
A dirty guest mapping may flush over a concurrent host edit; writers must coordinate
ownership, including msync/close. `RTM-071` covers fresh read/splice/mmap opens across
same-inode rewrites, growth/shrink/regrowth and RO/RW binds; `CMP-043` covers the
Compose lifecycle. See [compatibility contracts](../../docs/docker-compatibility.md).

## Request credential ABI3

0002 supplies the native FUSE `request_cred` and `managed_close_to_open` options
and the separate storage-session API. These are private downstream interfaces,
not an upstream FUSE feature bit or wire-protocol extension.

### Opt-in and identity contract

Mounting ordinary `fuse` with `request_cred` and querying it both require
init-user-namespace `CAP_SYS_ADMIN`. The daemon must hold the delivering `/dev/fuse`
file. Reused connections must agree on the option; there is no late enablement.
This is a **trusted daemon interface**, not authentication for an untrusted server.

`fuse_get_req()` pins the task's immutable `get_current_cred()` at allocation;
`fuse_request_free()` releases it. Fsuid, fsgid, the complete supplementary group
list and `cred->cap_effective.val` come from that same snapshot, unaffected by
later credential changes or task exit. Groups retain kernel order and duplicates;
fsgid is separate. This is not the header identity or `FUSE_CREATE_SUPP_GROUP`'s
single parent-relevant group. No PID/`/proc` lookup or historical credential registry
is used.

**ABI3 only:** `FUSE_DEV_IOC_REQUEST_CRED`, private command 240,
`0xc040e5f0`, uses this fixed 64-byte layout (including compat ioctl):

| Offset | Field |
| --- | --- |
| 0 / 4 | u32 `version` = 3 / u32 `flags` = 0 |
| 8 / 16 | u64 exact `unique` / aligned u64 userspace `groups` pointer |
| 24 / 28 / 32 / 36 | u32 `group_count` / `fsuid` / `fsgid` / `state` |
| 40 / 48 / 56 | u64 `semantics` / `cap_effective` / `cap_valid` |

1. Zero the structure, set version and exact received unique; query with zero
   pointer/count for required size. Require success **and PRESENT**.
2. Allocate `group_count` native u32s, set pointer/capacity and query again **before
   replying**. Reset input `semantics` to zero on every query. Require success and
   PRESENT again; the second query independently rechecks liveness.
3. Validate `cap_valid` against the supported vocabulary and reject unknown
   effective bits. Install exactly the fsuid/fsgid/full groups/effective mask;
   install capabilities after identity transitions and verify them before I/O.
   Validate managed metadata semantics too. Never infer privilege from UID 0,
   discard supported nonroot capabilities, truncate groups, or fall back to the
   header, PID, server credentials, an earlier request or ABI1/2 snapshots.

PRESENT returns the running kernel's `CAP_VALID_MASK`; a capability-empty root
identity is valid PRESENT with zero effective mask. NONE instead has fsuid/fsgid
`UINT32_MAX`, zero groups and **both capability masks zero**; it is never an
identity. Version 1/2 with the v3 command fails `EINVAL`; the old size-48 command
fails `ENOTTY`. Nonzero flags/input semantics, unknown versions, capacity above
`NGROUPS_MAX` (65536), or capacity without a pointer fail `EINVAL`. A short buffer
returns required metadata and `ENOSPC` without copying groups. Ignore partial
output on other allocation/user-copy failures.

Lookup is only on the **delivering `fuse_dev`'s processing queue** under `pq.lock`:
read by the daemon and awaiting reply (`FR_SENT`), not pre-delivery `FR_PENDING`.
Unread/completed/aborted/reply-copy requests, unknown/interrupt IDs and requests
delivered on another device return `ENOENT`. A clone is a different device; dup
of the same open file is not. IDs are connection-local. Only a cred reference
escapes the lock. A reply can complete while an already-pinned snapshot is copied;
serialize query against reply/abort/resend. Resend may change both unique and
delivering device; the old query grants no extended lifetime.

### Deliberate exclusions and no-credential requests

- Native init user namespace and `SB_I_NOIDMAP` only; unsupported namespaces and
  kernel/workqueue/`PF_IO_WORKER`/`PF_USER_WORKER` origins fail `EOPNOTSUPP`.
  Invalid IDs fail `EOVERFLOW`, not overflow-ID munging. Idmapped binds are denied.
- No VirtioFS, CUSE, fuseblk, FUSE-over-io_uring or passthrough. INIT rejects idmap,
  writeback-cache, io_uring and passthrough selection. `fuse_uring_cmd()` also
  rejects noncancellation commands **before** registration mutates queues, even
  when global `enable_uring` is on; cancellation retains its cleanup path.
  Ordinary-task native AIO remains supported. Worker exclusion is not a claim
  that Linux io_uring credentials are generally wrong; inline ordinary-task
  requests snapshot their subjective credentials.
- Forced/nocreds requests, INIT, DESTROY, RELEASE/RELEASEDIR, notify replies and
  forced FLUSH have NONE when queryable. Synthesized writeback remains NONE,
  including `FUSE_WRITE_CACHE`; disabling writeback-cache negotiation does not
  eliminate mmap/reclaim writes. A backend needs explicit retained-handle policy.
  FORGET/BATCH_FORGET have no reply-bearing request and query returns `ENOENT`.
- No permitted/inheritable/bounding/ambient capability sets, LSM labels, securebits,
  root-squash/export policy, idmap or open-handle authority are transported.
  Replaying this tuple does not reproduce every Linux permission decision.

## Native managed checked-close-to-open profile

`managed_close_to_open` requires **both** `request_cred` and `default_permissions`
(`EINVAL` otherwise, independent of option order). It is native-FUSE-only,
displayed in mount options, and rejects conflicting connection reuse. Native
FUSE has no DAX device/mount mode here. Ordinary FUSE and VirtioFS are unchanged.

The managed regular-file open uses 0001's checked sequence: flush dirty
buffered/mmap data with `filemap_write_and_wait()`, force authoritative GETATTR,
then invalidate pages even with KEEP_CACHE and unchanged size/mtime. Errors
propagate with synchronous new-handle release. It skips stock FUSE's redundant,
unchecked final invalidation without forcing DIRECT_IO.

Managed INIT rejects `FUSE_ATOMIC_O_TRUNC` and both `FUSE_HANDLE_KILLPRIV` versions.
Managed truncation is non-atomic: checked OPEN precedes typed SETATTR carrying
actual FILE/OPEN/FH intent. For a nonexclusive CREATE collision, the backing service
returns EEXIST, never an existing-file CreateReply. Managed `fuse_atomic_open`
drops the negative dentry, LOOKUPs and returns `finish_no_open`, so normal
permission/type checks, OPEN and truncation run. O_EXCL retains EEXIST; a second
negative lookup becomes ENOENT. There is no manufactured CREATE success/replay.

This remains checked close-to-open, not continuous coherence, distributed write
serialization or a general parity claim. Authoritative server data, coordinated
writers and retained-handle writeback authorization are required. See the
[stateful fixture](../../Tests/Fixtures/fuse-stateful/README.md) for buffered/mmap,
truncate and error assertions; credential-probe DIRECT_IO is not cache coverage.

## Managed metadata semantics

ABI3 offset 40 is output-only `semantics`; input must be zero on **each** query.
Only managed `fuse_do_setattr()` supplies the original kernel metadata intent.
NONE and nonmetadata requests return zero. Unknown bits fail closed.

| Bit | UAPI name | Meaning |
| --- | --- | --- |
| 0 | `FUSE_REQUEST_META_VALID` | Kernel-captured managed SETATTR metadata |
| 1 | `FUSE_REQUEST_META_KILL_SUID` | Original `ATTR_KILL_SUID` |
| 2 | `FUSE_REQUEST_META_KILL_SGID` | Original `ATTR_KILL_SGID` |
| 3 | `FUSE_REQUEST_META_KILL_PRIV` | Original `ATTR_KILL_PRIV` |
| 4 | `FUSE_REQUEST_META_FORCE` | Original `ATTR_FORCE`, not server privilege |
| 5 | `FUSE_REQUEST_META_CTIME` | Update backing ctime now, not delegated merge |
| 6 | `FUSE_REQUEST_META_TIMES_SET` | Explicit timestamp intent |
| 7 | `FUSE_REQUEST_META_TOUCH` | Current-identity touch authorization |
| 8 | `FUSE_REQUEST_META_FILE` | Original `ATTR_FILE`; exact backing FD required |
| 9 | `FUSE_REQUEST_META_OPEN` | Original `ATTR_OPEN`; size must be zero |

Mask: **1023**. The frontend retains `setattr_prepare()` checks with only KILL_PRIV
deferred, preserves original kill flags, omits synthetic MODE generated by them,
and carries CTIME and truncate mtime/NOW. Unsupported original iattr flags,
including ATTR_DELEG/ATTR_CTIME_SET, fail `EOPNOTSUPP`. These are not opcode/xattr
heuristics: implicit killpriv must use the typed action below, not corrective
chmod, explicit removexattr (which has different CAP_SETFCAP checks), or dummy
truncate. Writing and chown have distinct SGID/CAP_FSETID rules; preserve intent.

## Storage-session ABI1

This is **separate from source ABI3**. Removed command 241 returns `ENOTTY`, with
no retry/fallback. The storage API has no source unique, pointer, PID, credential
or serialized `CredentialKey`; it does not independently attest remote identity.

1. Trusted startup opens `/dev/fuse` with `O_RDWR|O_CLOEXEC` and calls
   `FUSE_DEV_IOC_STORAGE_SESSION`, command 242, `_IO(229, 242)` = **`0x0000e5f2`**,
   argument zero. The return value is a new CLOEXEC anonymous session FD.
   Minting requires **CURRENT init-user-namespace CAP_SYS_ADMIN**, even on a
   root-opened device. Nonzero argument is EINVAL. No mount, initialized connection
   or source request is needed; close the device afterward.
2. Keep this transferable FD capability inside the trusted service. It is not
   task-bound or per-inode authority; possession permits internal FORCE/killpriv
   intent. Never leak it through workload inheritance, plugins, SCM_RIGHTS or
   proc/pidfd access. CLOEXEC does not prevent fork inheritance.
3. The client still proves the live source request through ABI3, validates complete
   identity/semantics and sends a typed operation over authenticated trusted wire.
   The server validates bounds/field consistency/opcode, resolves its own exact
   backing FD under lifetime locks, installs full captured credentials through
   `storageidentity.Worker.Do`, and invokes apply **inside that callback**.
4. On the session FD, `FUSE_STORAGE_IOC_APPLY_ATTR`, command 243,
   `_IOW(229, 243, struct fuse_storage_attr)` = **`0x4050e5f3`**, returns zero on
   success, with no output/FD replacement. Apply has **no CAP_SYS_ADMIN check**, no
   `override_creds`, saved root/session `f_cred` or corrective mutation. Actual
   `notify_change`, ext4 `setattr_prepare` and LSM checks run under the **CURRENT
   worker** in the init user namespace.

### Fixed 80-byte storage layout

| Offset | Field | Type / contract |
| --- | --- | --- |
| 0 / 4 | `version` / `flags` | u32 = **1** / u32 = 0 |
| 8 / 12 | `fd` / `valid` | s32 local backing FD, never wire FD / u32 typed mask |
| 16 | `semantics` | aligned u64 sanitized source bits; VALID required |
| 24 | `mode` | u32 permission/special bits, `0..07777`, no file type |
| 28 / 32 | `uid` / `gid` | u32 requested owner/group, not caller; UINT32_MAX invalid |
| 36 | `reserved` | u32 = 0 |
| 40 | `size` | s64 nonnegative actual requested size |
| 48 / 56 | `atime` / `mtime` | s64 seconds; signed Linux wire bit pattern |
| 64 / 68 | `atime_nsec` / `mtime_nsec` | u32, 0..999999999 |
| 72 | `reserved2[2]` | two u32 = 0 |

`FUSE_STORAGE_ATTR_*`: **MODE=1, UID=2, GID=4, SIZE=8, ATIME=16, MTIME=32,
ATIME_NOW=64, MTIME_NOW=128; mask=255**. Translate explicitly, not by copying
Linux ATTR or FUSE FATTR bits. NOW requires the matching time-present bit; without
NOW, present time means explicit SET. Unselected values must be zero. NOW values
may carry source wire time, but backing `current_time` is used. There is no ctime
value: CTIME requests ordinary update, not delegated monotonic merge.

Unknown versions/bits, nonzero reserved fields, bad ns/IDs/size, MODE with
KILL_S*ID, FORCE with chmod/chown/explicit-time/TIMES_SET/TOUCH, or OPEN without
zero SIZE return EINVAL. ATTR_DELEG/ATTR_CTIME_SET cannot be requested. No source
fh, lock_owner or ctime value is serialized into this local structure.

### Backing object, authorization and lifetime rules

- `fdget_raw` pins the exact file, including O_PATH and O_PATH|O_NOFOLLOW symlinks;
  no pathname or `/proc` reopen. Regular files/directories/symlinks are accepted
  where `notify_change` allows; symlink chmod is EOPNOTSUPP. SIZE is regular-only.
  Devices/FIFOs/sockets, non-ext4 (including ext2/ext3 sharing the magic),
  non-init-userns superblocks and idmapped mounts fail EOPNOTSUPP.
- SIZE chooses retained-file authority **only for source FILE plus that exact
  FD's FMODE_WRITE**: append check, `security_file_truncate` (including open-time
  Landlock rights), then `fsnotify_truncate_perm`. It does not recheck DAC after
  chmod of an already-open file. Otherwise current `inode_permission(MAY_WRITE)`
  precedes fsnotify, exact-mount `mnt_want_write`, append check, `get_write_access`,
  `break_lease(O_WRONLY)` and `security_path_truncate`. Write access precedes lease
  breaking; permission watchers run **outside the inode lock**. Mount-write checks
  include retained and read-only O_PATH binds; `notify_change` retains
  immutable/append/LSM checks. Never substitute a privileged handle for source
  pathname authority or recompute remote intent via a dummy truncate.
- UID/GID/MODE/explicit times retain ext4 current-owner/group/capability checks.
  FORCE/killpriv is trusted internal VFS intent, **not an untrusted syscall API**.
  Kill-only FORCE requires current MAY_WRITE unless source FILE binds the exact
  retained writable descriptor. A token, O_PATH or read-only FD is insufficient.
  No-op chown can update ctime as Linux allows; do not invent extra ownership checks.
- The session pins no inode between calls and has no replay registry. Service
  locks own node/FH association, close/reuse, mutation order and completion.
  Each call pins the exact inode across rename/unlink. Never retry ambiguous apply
  completion. Closing the last session FD destroys the capability.
- Remote rlimits, LSM domains/labels, securebits and full task context are not
  transported. Worker limits/context and local open-time security blobs apply;
  replaying credentials does not install remote Landlock. Other metadata does not
  replay every source path hook. `__remove_privs` can emit FORCE without FILE:
  the service cannot borrow writable-FD authority and must pass current MAY_WRITE
  or fail closed. Write-side killpriv after source-FD permissions were revoked is
  therefore not full remote parity without trustworthy source handle intent.

## Isolated build and regression probe

On a Linux build host, export committed source into a **new disposable tree**,
never a source cache. Native arm64 example (set CROSS_COMPILE if needed):

```sh
repo=$PWD
LINUX=/path/to/linux-stable-git
scratch=$(mktemp -d)
mkdir "$scratch/source"
git -C "$LINUX" archive 1efe5d048a391de3ead2804b2e7f86376c356cc5 |
  tar -x -C "$scratch/source"
for patch in 0001-virtiofs-host-close-to-open.patch \
             0002-fuse-request-credentials-experimental.patch; do
  git -C "$scratch/source" apply --no-index --check --whitespace=error-all \
    "$repo/Configuration/kernel-patches/$patch"
  git -C "$scratch/source" apply --no-index --whitespace=error-all \
    "$repo/Configuration/kernel-patches/$patch"
done
make -C "$scratch/source" O="$scratch/out" ARCH=arm64 defconfig
"$scratch/source/scripts/kconfig/merge_config.sh" -m -O "$scratch/out" \
  "$scratch/out/.config" "$repo/Configuration/cengine-kernel.fragment"
"$scratch/source/scripts/config" --file "$scratch/out/.config" \
  -e FUSE_FS -e VIRTIO_FS -e IO_URING -e FUSE_IO_URING -e FUSE_PASSTHROUGH
make -C "$scratch/source" O="$scratch/out" ARCH=arm64 olddefconfig
make -C "$scratch/source" O="$scratch/out" ARCH=arm64 -j"$(nproc)" Image
# Sanitized UAPI; unlike headers_install, this needs no rsync.
make -C "$scratch/source" O="$scratch/out" ARCH=arm64 headers
cc -std=gnu11 -Wall -Wextra -Werror -O2 -I"$scratch/out/usr/include" \
  "$repo/Tests/Fixtures/fuse-credentials/probe.c" -o "$scratch/probe"
```

These build commands do not boot or run anything. For runtime probes, separately
boot the resulting kernel in an **authorized disposable Linux VM**, with native
init-namespace root, CAP_SYS_ADMIN/SETUID/SETGID, CAP_DAC_OVERRIDE available for the
nonroot-capability case, normal unlocked set-ID securebits and io_uring unblocked.
Enable global FUSE io_uring so its off-switch cannot hide the registration bug:

```sh
# Alternatively boot with fuse.enable_uring=1.
printf 'Y\n' | sudo tee /sys/module/fuse/parameters/enable_uring
sudo "$scratch/probe" 65536
sudo "$scratch/probe" 0
for feature in writeback idmap uring passthrough killpriv killpriv-v2 atomic-trunc; do
  sudo env FUSE_CRED_REJECT_INIT="$feature" "$scratch/probe" 0
done
for missing in missing-creds missing-permissions; do
  sudo env FUSE_CRED_BAD_MOUNT="$missing" "$scratch/probe" 0
done
sudo "$scratch/probe" --storage-session /path/to/disposable/ext4/directory
sudo "$scratch/probe" --killpriv /path/to/disposable/ext4/directory
```

The raw credential probe needs no libfuse/liburing. Normal runs check native-AIO
READ/WRITE snapshots despite subsequent identity changes, CAPGET-derived masks,
root with zero capabilities, nonroot with CAP_DAC_OVERRIDE, a different fsync
caller's identity, short buffers, obsolete ABI rejection, completed IDs and cloned
device isolation. Forced io-wq fails EOPNOTSUPP and the client receives EACCES;
raw io_uring REGISTER fails EOPNOTSUPP before buffer validation. The probe fails if
global io_uring gating cannot be exercised. INIT negatives require ECONNREFUSED,
not success or skip. FORGET ENOENT is checked if observed, not required for PASS.

`--storage-session` exercises the local API **without mounting FUSE/source
requests**: mint privilege, current-identity chmod/chown/truncate/FORCE denial,
owned regular/directory/symlink pins, malformed fields, read-only/unsupported
objects, removed command and missing session. It distinguishes O_PATH/read-only
from retained writable FILE authority after chmod. Lease, Landlock ABI >= 3 and
fanotify pre-content cases check real truncate hooks and watcher reentrancy outside
the inode lock. Feature absence prints explicit **SKIP**, never PASS; unexpected
privilege errors and timeouts fail. Full feature coverage needs CONFIG_FILE_LOCKING,
CONFIG_SECURITY_LANDLOCK with `landlock` active, CONFIG_FANOTIFY and
CONFIG_FANOTIFY_ACCESS_PERMISSIONS.

`--killpriv` adds actual managed FUSE source queries and nonroot operations on real
ext4 fixtures: no-op chown/write/ftruncate, SGID/group/CAP_FSETID rules, explicit
removexattr denial, exact unlinked pins, and CREATE-collision OPEN|FILE|FH truncate.
Metadata is applied through the session under current-identity workers, with
workload session/backing FDs closed; no elevated corrective mutation. This is a
local two-half probe, not independent remote attestation or cross-VM execution.

The [stateful fixture](../../Tests/Fixtures/fuse-stateful/README.md) separately
checks held-unlink lifetime, buffered/mmap/fsync, close-to-open rewrites and checked
flush/GETATTR errors. Genuine deterministic page-cache invalidation failure is not
covered. Neither probe proves every namespace/LSM/task-context combination,
concurrent query/reply/abort/resend or FD-reuse race, compat-ioctl execution, or
complete remote filesystem parity. Report actual kernel/config/case results;
compilation and older ABI runs cannot substitute for those executions.

Relevant pinned contracts: `Documentation/security/credentials.rst`,
`include/linux/cred.h`, `kernel/groups.c`, `include/linux/capability.h`,
`security/commoncap.c`, `fs/fuse/{dev.c,dev_uring.c,file.c,dir.c,inode.c}`,
`fs/{open.c,attr.c,namei.c}`, `mm/{filemap.c,truncate.c}` and
`include/uapi/linux/fuse.h`. These references mean the pinned source plus patches,
not arbitrary host headers.
