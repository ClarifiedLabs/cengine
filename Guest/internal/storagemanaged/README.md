# Managed ext4 session core

The storage service uses this dispatcher behind `storageserver`.
`storagewire/README.md` defines the DATA contract. Kernel capture and FUSE mount
policy belong to `storageclient` and `storagefuse`, not this dispatcher.

## Ownership and admission

Create one `Registry` with the **service-global namespace mutex**, and share one
`storageidentity.Worker`. The same gate must cover **every writer** of these ext4
exports; external path replacement/mount mutation is outside this trust model.
After authentication and admission, call:

```go
session, rootEntry, err := storagemanaged.New(
    guard, principal, binding, namespaceGate, identityWorker, registry,
)
```

The constructor obtains its own canonical `Guard.DupVolumeRoot()` duplicate;
callers cannot substitute a same-inode alternate bind/idmapped mount descriptor.
Success transfers that duplicate to registry barrier ownership; failure closes it.
The constructor verifies exact guard/principal, binding, directory type, and ext4.
It does not reopen a volume name. Before any identity worker, it opens
`/dev/fuse` and mints command 242 (`0xe5f2`) under CURRENT init-userns
CAP_SYS_ADMIN, then closes the device. Each session privately owns the returned
CLOEXEC anonymous metadata capability; constructor failure joins its close error,
and Barrier closes it before final syncfs even after a fault. Never expose this
FD to workloads, plugins, SCM_RIGHTS peers, fork children, or proc/pidfd access.
Missing ioctl/device/capability fails setup closed: there is no old-ABI fallback. Configure authority's `Barrier` callback as
`registry.Barrier`. Both modes require authoritative `statmount(MNT_BASIC)` on
the attached canonical mount, matched to its `STATX_MNT_ID_UNIQUE`, proving a NOP
idmap; missing support/results (including ENOENT) fail closed. ReadOnly performs
this check immediately before `open_tree(CLONE|AT_EMPTY_PATH|CLOEXEC)` on the exact
canonical duplicate, under the namespace gate. Linux clones inherit the source
idmap; the sole `mount_setattr(RDONLY|NOATIME, attr_clr=_ATIME)` call does not request
IDMAP and therefore cannot change it. Setup checks the exact clone FD for ext4,
identical inode/device, a distinct unique mount ID, and read-only/noatime flags
before interning any operation pin. **The detached clone's NOP idmap is proven by
inheritance, not queried.** No newer statmount-by-FD ABI is required or guessed.
The clone FD stays service-private: never publish it through SCM_RIGHTS, fork
children, proc/pidfd access, or a mountpoint. External mount mutation and malicious
same-UID/root descriptor access are outside this gate-owned trust model.
Failure closes the clone and canonical duplicate; no fallback mount or elevated
O_NOATIME open is substituted. The canonical real descriptor remains separate
syncfs/barrier ownership.

Each `Dispatch(guard, request)` first calls `guard.ValidateFor(sessionPrincipal)`
before either mutex, identity queue, or descriptor lookup. Requests are validated
and deeply copied through the sealed codec. The transport must call in
stream order and hold the particular guard until Dispatch returns; there is no
cancellation/replay/reconnect API. Wrong-session and released guards fail before
queueing. The authority, not this package, fences admission and joins guards.

## Filesystem semantics

- Session node IDs intern real device/inode identity; lookup and open references
  are independent. FORGET checks the whole batch for underflow before changing it.
  No live lookup/open reference is evicted. O_PATH fstat reports real zero nlink
  after final unlink, including GETATTR without a file handle.
- The bounded service registry pins inode identities for the lifetime of all
  sessions on a volume. This keeps ObjectIDs stable across sessions, events,
  FORGET/relookup, and inode-number reuse. These global pins are **identity-only**:
  every session node owns a separate operational pin from its own mount view.
  Neither RW-first nor RO-first interning can substitute an operational descriptor
  from another view. Session pins/records are reclaimed at zero lookup/open refs;
  global identity pins are reclaimed by the final volume barrier.
  Limits return ENFILE/EMFILE rather than evicting authority or wrapping tokens.
  Long-lived volumes touching 65,536 distinct objects require retirement; this
  conservative availability limit is deliberate, not an unbounded cache.
- Namespace and metadata syscalls run synchronously under the complete caller
  snapshot. UID zero adds no capabilities. Ancestor traversal/default-permission
  and ACL checks are trusted kernel/client preconditions; the node pin itself
  never supplies data-open authority. Child names are nofollow, descriptor-confined,
  and mount-crossing lookups are rejected.
- OPEN checks inode type **before** reopening its exact descriptor under the
  caller. Only regular data files and OPENDIR directories get real open grants;
  device/FIFO/socket opens never run. Immutable handles cannot cross sessions,
  nodes, access modes, or directory/file kinds.
- LINK uses the session's exact O_PATH pin through a trusted procfs magiclink and
  `linkat(AT_SYMLINK_FOLLOW)`, under current credentials, not privileged
  AT_EMPTY_PATH. Only the magiclink is followed: its kernel pure jump selects even
  a symlink inode without traversing that inode's target text. This needs no alias
  witnesses or directory scans, including after the last observed name is removed.
  The kernel still enforces protected_hardlinks, destination permissions, mount
  equality, and ENOENT for zero-nlink resurrection.
- Regular/directory xattrs prefer exact f*xattr. When data-open permission differs
  from metadata permission (e.g. mode 000), actual Get/List/Set/RemoveXattr syscalls
  use the retained O_PATH pin's trusted procfs magiclink under the **same caller**.
  No service data-open permission is borrowed. Linux xattrat(AT_EMPTY_PATH) rejects
  O_PATH even in 6.18 and is **not** used. Symlink xattrs use the same exact-pin
  pure jump with ordinary xattr syscalls; l*xattr on the procfd path would instead
  touch the procfs link. Retained-unlinked symlinks need no name witness.
  Unknown errors are never rewritten as empty.
- Creation passes the unmasked mode to the kernel with the worker's isolated
  umask, preserving default ACL inheritance. Every SETATTR, including empty
  chown/ctime/kill-only intent, calls storage-session command 243 (`0x4050e5f3`)
  exactly once inside `Worker.Do`. The fixed 80-byte ABI1 payload explicitly
  translates valid mask 255, preserves source ABI3 `MetadataSemantics` mask 1023,
  signed timestamps/NOW, and zeroes reserved/unselected fields. One kernel
  `notify_change` retains authorization, implicit killpriv and metadata ordering;
  no elevated chmod/removexattr retry or userspace multi-syscall emulation.
  `MetadataFile` selects only the exact matching session handle; SIZE additionally
  requires its immutable writable grant and actual writable FD. Without FILE,
  use the session's O_PATH view pin, never a borrowed data-open grant. The kernel
  enforces exact ext4/mount/current-caller checks, including symlink and RO rules.
- OPEN rejects TRUNC and all legacy kill flags. CREATE preserves wire TRUNC but
  always uses backing O_EXCL and suppresses backing TRUNC. Every collision,
  including a device inode, returns EEXIST without opening or granting a handle.
  The managed source kernel resolves nonexclusive collisions with LOOKUP and
  normal non-created OPEN; regular-file truncation then uses source-semantic
  SETATTR. Device OPEN remains EPERM. No backing atomic-truncate shortcut is negotiated.
- FD I/O is bounded and offset-addressed. APPEND is not installed on the backing
  open description, avoiding Linux's pwrite/O_APPEND offset override. Data-open
  status flags are translated from frozen generic bits to architecture constants.
  Per-I/O F_SETFL applies mutable DIRECT/NOATIME/NONBLOCK/ASYNC, including clearing
  original flags; buffer alignment follows the request, not the opener. Access
  rights remain immutable. Caller-authenticated NOATIME enables run the kernel's
  current owner/CAP_FOWNER check. Identity-less grants may preserve or clear an
  existing NOATIME authorization, but cannot newly enable it using service UID.
  Cache/OpenGrant writes execute on disposable zero-effective-capability threads,
  never under opener capabilities; real writes perform kernel killpriv.
- READDIR uses one bounded getdents buffer and real d_off cookies, with response
  byte/entry limits; it never reads a whole directory. Mutating requests, including
  partial failures, run actual syncfs on the retained ext4 root before returning.
  This includes directory durability. Every fsync/fdatasync/syncfs failure latches
  a **sticky per-volume terminal fault**, shared by all current/future sessions.
  No later successful sync or new attachment clears that evidence. Barrier closes
  attachment handles/root/node ownership (and final-volume global pins) **before
  the final syncfs on the authority's borrowed root**, covering orphan reclamation.
  Cleanup/final sync still run after failure; a faulted volume cannot mint a fresh
  successful drain receipt.
- Results contain validated wire replies and invalidation events carrying global
  ObjectIDs, not session NodeIDs. The bounded server event writer distributes
  events to matching-volume sessions; recipients translate IDs. Events are
  retained on syscall/sync failures when mutations may already have occurred.
  If a namespace syscall succeeds but pin/ref/event bookkeeping fails,
  the whole volume becomes terminal rather than fabricating a child ObjectID.
  `Dispatch` can return a truthful partial `Result` **alongside ErrVolumeFault**;
  the transport must stop and request retirement for every volume peer on that
  error, not turn it into an ordinary recoverable reply. No further filesystem dispatch is allowed.

## Kernel and integration requirements

1. Frozen source ABI3 and the storage-session ABI1 kernel extension are mandatory.
   All legacy `SetKillSUIDGID`, `KillSUIDGID`, `FuseOpenKillSUIDGID`, and
   `WriteKillSUIDGID` inputs are rejected at the wire boundary, not translated.
   Source semantics must come from the authenticated client's captured snapshot;
   this trusted consumer does not independently attest a remote kernel request.
2. Cache/OpenGrant writes retain root UID with zero effective capabilities on a
   disposable thread. Actual backing writes still perform kernel killpriv; this
   must remain coupled to the source profile's preceding semantic SETATTR flags,
   not interpreted as permission to borrow a data open for metadata replay.
3. Host tests and cross-compilation cannot prove Linux credentials, ACLs, killpriv,
   mounted FUSE/mmap coherency, durability under power loss, or the credential ABI.
4. Transport FIFO/writer, TLS authentication, event distribution and receive
   deadlines belong to `storageserver`; client abort and checked close-to-open
   belong to `storageclient`/`storagefuse`. The lifecycle owner coordinates retirement.
   None of these responsibilities has an implicit fallback.

## Linux source contract

The Linux **6.18** contracts below govern the implementation, rather than
assumptions about `/proc` symlink text:

- `Configuration/kernel-patches/README.md`: frozen source ABI3 and storage-session
  ABI1, `fuse_do_setattr` captured semantics and exact `notify_change` replay.
  The matching managed kernel is mandatory; a stock kernel is not a fallback.
- Managed `fs/fuse/dir.c:fuse_atomic_open` handles nonexclusive CREATE EEXIST by
  clearing FMODE_CREATED, dropping the negative dentry, and returning a fresh
  lookup through `finish_no_open`. `fs/namei.c:do_open` otherwise suppresses
  permission/truncate checks for FMODE_CREATED. The backend must never return an
  existing-inode CreateReply; O_EXCL collisions still return EEXIST.
- `Guest/internal/storageauthority/authority.go:Authority.Admit` rejects mutation
  admission on RO attachments. An admissible read-only guard independently tests
  `Session.Dispatch` returning wire EROFS; direct storage-session metadata replay
  still checks `fs/fuse/dev.c`'s `mnt_want_write(target->f_path.mnt)` on the exact
  detached RO pin. Neither layer upgrades the authenticated binding or mount.
- `fs/open.c:do_ftruncate` returns EINVAL for a valid nonwritable file descriptor;
  `do_sys_ftruncate` returns EBADF for a missing descriptor. Managed SETATTR size
  preserves this distinction without upgrading a read-only grant.
- `fs/open.c:chown_common` supplies ATTR_KILL_SUID/ATTR_KILL_PRIV and
  `fs/attr.c:setattr_should_drop_sgid` retains non-executable SGID when group or
  CAP_FSETID authorizes it; chmod is not a substitute.
- Also checked directly against upstream [Linux v6.18 `fs/namespace.c`](https://github.com/torvalds/linux/blob/v6.18/fs/namespace.c):
  `vfs_open_tree` → `open_detached_copy` → `get_detached_copy` → `__do_loopback`
  → `clone_mnt` copies `mnt_idmap_get(mnt_idmap(&old->mnt))`. `can_idmap_mount`
  rejects idmap changes on attached mounts. `build_mount_idmapped` does nothing
  without explicit IDMAP in attr_set/attr_clr, and `do_idmap_mount` returns without
  changing the map when `kattr->mnt_idmap` is NULL. Ordinary `mount_setattr`
  initializes that field to NULL; RO/NOATIME alone cannot set it. `build_mount_kattr`
  requires clearing the whole atime enum. `statmount_mnt_basic`/`mnt_to_attr_flags`
  report the canonical idmap authoritatively. The v6.18 `include/uapi/linux/mount.h`
  supplies the 24-byte request and 512-byte result layouts used here.
  `fs/inode.c:atime_needs_update` and `touch_atime` enforce noatime/read-only semantics.
- `fs/proc/fd.c:proc_fd_link` returns the exact pinned `file.f_path`;
  `fs/proc/base.c:proc_pid_get_link` calls `nd_jump_link`.
  `fs/namei.c:pick_link` returns NULL for this pure jump and `path_lookupat`
  terminates rather than following the pinned symlink's text. `do_linkat`,
  `may_linkat`, and `vfs_link` retain current-caller checks and zero-nlink ENOENT.

## Checks

```sh
cd Guest
go test -race ./internal/storagemanaged
go vet ./internal/storagemanaged
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/storagemanaged-arm64.test ./internal/storagemanaged
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/storagemanaged-amd64.test ./internal/storagemanaged
# Matching ABI3/storage-session kernel, Linux root with identity-setup
# capabilities plus CAP_SYS_ADMIN, ext4 and ACL support;
# the isolated runner must configure fs.protected_hardlinks=1 before testing.
TMPDIR=/path/on/ext4 go test -race -count=1 ./internal/storagemanaged
```

Linux tests skip only nonroot execution. Root with a non-ext4 TMPDIR, unsupported
identity setup, missing capabilities, or unsupported required syscalls fails.
Fixtures authenticate over in-memory TLS pipes; no listener or external service
is started. Tests exercise every operation family, retained-unlinked metadata/data,
identity groups/UID-zero, ACL/umask, killpriv and offset-addressed cache grants,
symlink xattrs, exact-pin hardlinks/exchange, bounded cookies, exact admission,
atomic FORGET underflow, queued retirement, and descriptor cleanup. Review
regressions compare xattrs to direct ext4 syscalls for root/nonroot/mode-000 and
unlinked inodes, check symlink target protection and mutable I/O flags, inject
one-shot sync EIO and post-namespace EMFILE failures, verify RO nonowner file,
directory and symlink reads preserve atime in both RO-first/RW-first identity
orders, compare chown SGID decisions to native syscalls, recover unknown aliases
without enumeration, and assert final orphan-owner closes precede syncfs. Fault injection is private and
per-registry; no host filesystem is filled or damaged.

ABI1 metadata regressions include real-ioctl current-caller root/nonroot denial,
empty chown and force kill before data write, exact retained FILE vs pathname
truncate, symlink target protection, NOW/explicit timestamps, RO view enforcement,
CREATE truncate deferral, apply/durability failure invalidations, and metadata FD
counts/close-before-sync ordering. Native tests cover layout and conversion only;
Linux ioctl/runtime tests require the matching managed kernel; Darwin checks do
not execute them. Idmap regressions cover both canonical modes, exact clone
identity/unique IDs/CLOEXEC/RO/noatime, unchanged canonical flags, and a real
idmapped mount whose clone retains its map through flag-only mount_setattr
(queried only after a test-only attachment in a private namespace).
No production fallback or public mutable test injection exists.

Managed mutation and flush/close dispatch obtains a durable authority-owned
write-ahead obligation before entering any potentially faulting syscall. See
[`storageauthority/DURABILITY.md`](../storageauthority/DURABILITY.md) for the
bounded format, fail-closed schema rule, restart behavior, and process-crash ACK
matrix. Ordinary reads allocate no obligation. Faults cannot be erased by a fresh
in-memory Registry after restart; no production fault hook is provided.
