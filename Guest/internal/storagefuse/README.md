# Managed FUSE adapter and native mount owner

`Mount` creates the managed FUSE client on Linux arm64/amd64. There is no replay
or reconnect, and local mount closure is not an
authority drain receipt. Unit tests and cross-compilation are not mounted, VM or
Docker verification; see the scoped compatibility coverage in
[`docs/docker-compatibility.md`](../../../docs/docker-compatibility.md).

## Implemented

- Filesystem wire operations and private PREPARE controls, including local-only
  FORGET; exact local node/FH
  remapping; Linux arm64/amd64 flags (not host Darwin constants), setattr NOW and
  ABI3 metadata intent (legacy create/open/write killpriv fields rejected), raw byte names, errno, xattr probes/ERANGE,
  partial counts, directory cookies, signed timestamps and rdev encoding.
- Every admitted raw RPC captures its exact header Unique before validation, wire
  admission and response. The private **real `clientBridge`** delegates to
  `storageclient.Client.Capture` and uses read-only `Snapshot.Kind()` only. It
  cannot construct caller credentials or turn errors into NONE. Header UID/GID/PID
  are not authority; `Client.Do` still validates the capturing client and grants.
- NONE requires explicit lifecycle release, live-node-only getattr without FH, or
  an existing matching open grant. CACHE writes require NONE open-grant provenance,
  retain the exact offset, and never borrow opener credentials.
- Bounded raw admission and go-fuse inflight bytes; admitted wire RPCs retain the
  client's fixed deadline/FIFO behavior, without cancellation or retry afterward.
  Cleanup capacity stays reserved by the client. No live IDs are evicted/reused.
- Zero entry/negative/attr TTLs and zero OpenOut cache flags. No blanket DIRECT_IO,
  KEEP_CACHE, directory/symlink caching, readdirplus, writeback, passthrough, idmap,
  io_uring, legacy killpriv, extended-xattr ABI or distributed lock forwarding.
- Invalidation translates recipient-local node/parent IDs on the client's separate
  serial bounded event worker. Terminal, delivery failure and OnUnmount abort and
  request retirement exactly once. Normal FORGET/BATCH_FORGET/NOTIFY_REPLY
  suppression is not mistaken for a discarded grant. Advisory kernel INTERRUPT
  requests do not cancel admitted DATA operations. Their normal matched suppression,
  or unmatched EAGAIN reply (including its ENOENT completion race), is not retirement.

## PREPARE initializer process isolation

Authenticated PREPARE mounts additionally own a kernel-local process gate. Before
BeginCopy, only root bootstrap metadata/open and trusted lifecycle cleanup are
admitted; no pre-owner mutation or data-open can straddle pinning. The first
BeginCopy pins its live initializer **before** sending DATA and keeps that owner
through errors, FinishCopy, subsequent BeginCopy, and mount teardown. There is no
timeout, owner reset, or process adoption. All subsequent filesystem callbacks
require PRESENT exact-Unique credential capture plus membership of the pinned
TGID; NONE metadata/open-grant I/O is rejected. Forget/release remain trusted
kernel bookkeeping. Runtime mounts retain their previous routing and provenance.

Linux `fs/fuse/dev.c:fuse_get_req` puts **TID**, not TGID, in the header. The gate
resolves that TID through verified procfs in the mount creator's PID namespace,
retains the TGID directory and pidfd, and checks live task membership and process
starttime using descriptor-relative procfs access. No PID-only/starttime-only
fallback exists. Thread changes within the same live process are allowed; other
processes, dead/reused owners, unprovable/zero identity, and unsupported hosts are
rejected. Header PID is only this extra local constraint, never caller credentials.
`storageclient.Client.Do` still requires captured credentials, live root grants,
and `Request.ValidateBinding` (PREPARE + RW for every control action).

Initial acquisition relies on the synchronous ioctl request remaining unreplied:
Linux 6.18 `fs/fuse/dev.c:request_wait_answer` waits uninterruptibly once a request
is in userspace, even after a fatal signal. Therefore the BeginCopy caller cannot
exit/recycle its TID while the gate pins it. This is not assumed for background
I/O; later membership checks use the already pinned process lifetime. Privileged
procfs/mount/PID-namespace replacement is outside the existing trusted mount-owner
threat model. The boundary is a process, not an individual thread: initializer
code must still serialize its own identity-check/unlink sequence. Unit tests and
cross-compilation are not evidence of real mounted-kernel execution.

## Controlled fork — these are NOT assumed upstream APIs

`Guest/go.mod` replaces pinned `github.com/hanwen/go-fuse/v2 v2.11.0` with
`Guest/third_party/go-fuse`. Provenance, retained license and the minimal patch list
are in `Guest/third_party/go-fuse/CENGINE-FORK.md`; vendor is generated, not patched.

- `MountOptions.ValidateInit` checks a **value-copy of the actual negotiated
  InitOut before its reply**. Errors/panics serialize EINVAL, never INIT success;
  native server construction then fails and closes the owned device. The callback
  cannot modify output or send asynchronous responses. Offered KernelSettings is
  not profile proof.
- `MountOptions.ObserveReply` receives exact Unique/opcode, filesystem status,
  written/expected bytes, syscall/short-write error, interruption and suppression
  after each native send and before request reuse. It forces non-splice counted
  writes. ProtocolServer cannot claim native delivery and does not call this hook.
  The adapter aborts/retires on failed or discarded grant delivery, including
  ENOENT on an original operation reply. An interrupted flag alone is advisory:
  a complete native send still supplies delivery proof. An operation's EINTR
  result, short write, suppression or transport failure remains terminal.
  Contract: Linux FUSE documentation, **Interrupting filesystem operations**
  (https://www.kernel.org/doc/html/latest/filesystems/fuse/fuse.html), and Linux
  6.18 `fs/fuse/dev.c:fuse_dev_do_write` for the interrupt-reply ENOENT race.
- `ManagedProtocol` narrowly opts Linux into FUSE **7.33**, retained as the fixed protocol layout ceiling; upstream's default is 7.28. Both hooks are required. The mode
  clears 7.36 INIT_EXT/flags2, rejects non-Linux, and disables the internal poll-hack
  namespace shortcut. Nil/default options retain upstream behavior.

`checkNegotiated` requires 7.33, DONT_MASK/ACL, bounded I/O and an
explicit allowed flag set. Both HANDLE_KILLPRIV versions and atomic O_TRUNC
are forbidden. CTIME raw FATTR is accepted only as kernel snapshot intent, never
as direct ctime assignment; legacy FATTR_KILL_SUIDGID is invalid. ATIME_NOW and
MTIME_NOW require the corresponding present bit and retain source timestamps. Serializer tests test actual output and missing bits;
Linux tests are cross-compiled on Darwin, not represented as executed Linux proof.

## Private mount lifecycle and ownership

1. Claim the canonical mountpoint for this generation (process-wide exclusion
   through teardown), then validate a **new** absolute leaf. Walk **every ancestor
   from `/`** with NOFOLLOW directory descriptors: each must be root-owned and not
   group/world-writable; retain and revalidate each descriptor's identity. A root
   0700 parent nested under a user-owned ancestor is rejected. Require a private
   (not shared or slave) mount and reject unknown kernel capability masks:
   `/proc/sys/kernel/cap_last_cap` must equal compiled CAP_LAST_CAP and the
   configured supported mask. Preflight rejection leaves TLS with the caller.
2. Thereafter own the already-handshaken TLS connection, call `storageclient.New`
   with exact version/profile/pins, obtain and validate the pinned directory root.
   Setup failure closes the connection and requests retirement; it does not prove
   remote admitted work has drained.
3. Create the leaf with mkdirat against its pinned parent; pin the new directory.
   Native mount uses `/proc/self/fd/<leaf-fd>`, not a path that an ancestor rename
   could redirect. Open/verify native `/dev/fuse`, retain that descriptor
   for capture, and use `F_DUPFD_CLOEXEC` to give go-fuse a separately owned fd via
   `/dev/fd/N`. Both refer to the **same open description**. Never IOC_CLONE or use a
   peer connection. Mount natively with `request_cred,managed_close_to_open,
   default_permissions,allow_other`, NOSUID/NODEV and bounded max_read. allow_other
   permits non-root workload IDs; default_permissions plus captured identity still
   enforce access. No helper process or fallback mount is invoked.
4. Successful request_cred mount is the experimental kernel's init-user-namespace
   enforcement point. Open the mounted root O_PATH through the pinned parent
   (without an INIT-blocking GETATTR); bind its fdinfo mount ID to the exact canonical
   mountinfo path and device minor. Both ID and connection must be absent from the
   pre-mount snapshot. Retain that mount descriptor and **never rebind**. Only then
   pin the connection's fusectl abort file, verifying FUSE_CTL filesystem type.
   Bind the actual INIT/delivery hooks and apply a fixed INIT deadline.
5. Start one terminal watcher and one bounded abort worker. Raw/delivery callbacks
   only signal that worker; they never wait for device I/O. Abort the pinned
   connection, synchronizing against both capture ioctls. On abort-write failure,
   only force-unmount through the pinned mounted-root descriptor after matching
   its original mount ID **and connection minor**. Join server/client workers outside
   callbacks; close the capture fd under the same lock. Never use a global unmount.
   Unknown/zero identity after partial setup permits **no unmount or fusectl abort**;
   close owned device descriptors and report failure instead. Cleanup uses
   identity-checked unlinkat against the pinned parent, preserves replacement and
   nonempty leaves, and never recurses. Release the generation claim only after
   successful cleanup; uncertain/failed teardown permanently poisons that path.

An external privileged process deliberately remounting, moving mounts, or changing
trusted ancestors is outside this private-helper threat model. Unprivileged ancestor
renames are excluded by the entire-chain checks; descriptor anchoring prevents path
redirection regardless. Our own concurrent generations cannot mount, adopt an abort
control file, or clean up the same destination while its predecessor holds the claim.
A replacement detected at teardown is preserved and reported, never adopted.

The retirement callback must be nonblocking and must not wait for the current raw
request. The mount owner must call `Close` to join local teardown. Kernel abort is
what unblocks go-fuse notification writes; the notification API itself is not
context-aware. Authority drain always remains a separate owner-side protocol.

## Real-kernel verification

`native_mounted_linux_test.go:TestNativeMountedManagedV3` is an **actual mounted
integration test**, not an injected raw/credential/backend test. It calls private
`newMount`, real `storageclient`, `storageserver.Server.Serve(ctx, authority, raw)`,
managed ext4 dispatch, native ABI-3 credential ioctls, and the real authority barrier.
Kernel build status and cross-compilation alone do not prove these behaviors.

### Disposable Linux mounted fixture

Requirements: root in the kernel-0002 Linux **6.18** init user namespace, native
`/dev/fuse`, mounted fusectl at `/sys/fs/fuse/connections`, procfs, identity-worker
and mount capabilities, an up loopback interface, and executable ext4 `/scratch`
with root-owned 0755 trusted ancestors on a private (not shared/slave) mount. Set `TMPDIR=/scratch`. The test
skips only nonroot execution (the separate child entry point skips unless invoked
by its parent). Root with an old/stock kernel, missing device/capabilities/ACLs,
wrong filesystem or unsafe path **fails**, rather than hiding the missing gate.

The fixture creates one ephemeral `127.0.0.1` TCP connection pair each for DATA and
controller authentication, closes each listener after acceptance, generates private
TLS 1.3 certificates in memory, registers an immutable RW runtime attachment, and
uses the real authenticated controller to obtain a retirement/drain receipt.
`storageserver.Config.ClientRoots` receives the matching DER CA; Serve owns the raw
socket and its server-side TLS settings. No external address, fake Caller/Snapshot,
raw executor seam, environment/argv credential, or production activation is used.

Coverage includes exact negotiated profile/root/mount-ID/connection/options;
create/pwrite/read/unlink; fstat nlink=0 with data FH and O_PATH/no FH; shared mmap,
msync/fsync and actual backing-file readback; root/directory/file and mode-000
xattrs, probes and ERANGE; real nonroot exec credentials with/without supplementary
groups; checked reopen denial; owner ACL mutation without data-open authority;
default ACL inheritance under umask 0077; unprivileged executable-SGID write
killpriv and empty-mask chown(-1,-1); explicit timestamp, NOW/OMIT, TOUCH, FILE
ftruncate and non-atomic OPEN truncate transport; and exact
mount Close/retirement/barrier/descriptor cleanup. Credential children execute a
copy of the test binary on `/scratch`, never credentials or a guest command.
Read-only attachment setup has separate coverage; this fixture does not substitute
for that coverage.

### Mmap self-mount deadlock and bounded diagnostics

Touching a FUSE mapping in the same Go process that serves the mount can deadlock:
`Guest/third_party/go-fuse/fs/api.go` ("Deadlocks", item 3) and
`Guest/third_party/go-fuse/fuse/test/cachecontrol_test.go` (`assertMmapRead`,
upstream issue 261) describe the hazard. A page fault blocks an OS thread without
a Go syscall transition. With one P, or a stop-the-world GC waiting for that
thread, the server cannot satisfy the fault and a Go timeout may not produce a stack.

`nativeExecMmap` execs `TestNativeMountedMmapChild` from a root-owned copy on
actual `/scratch` ext4, with its cwd there, no ExtraFiles, and no inherited transport
material. The child retains real root credentials and uses `GOMAXPROCS=1`; only the
client touches the mapping, so its runtime cannot stop the server's runtime. The
probe still uses MAP_SHARED, a real faulting store, MS_SYNC, fsync, and both mounted
and ext4 offset/count readback. No direct I/O, prefault/mlock workaround, disabled
GC, mount-profile change, or simulated credential capture is used.

Every syscall/memory-access phase logs begin/done, including munmap/close. The
parent relays at most 64 KiB through a bounded drop-on-backpressure queue and retains
a 64 KiB tail; a stalled receipt writer cannot block the deadline/abort controller.
The executable source is pinned through `/proc/self/exe`, and the destination is
created exclusively. Readback uses the payload's actual length. A 20-second child deadline
collects the exact connection's `waiting` and parent/child task `wchan`, `syscall`,
`stack` (at most 32 threads per process, 2 KiB/file, about 16 KiB/process, one
second total), requests a
SIGQUIT child stack, then signals only the already-owned mount's normal abort path
and kills the child if needed. SIGQUIT has one second and reaping three seconds;
unreaped children cause real test failure and preserve the fixture directory.
A failed mmap subtest does not continue into more mounted operations. The existing
exact-mount join/authority-retirement cleanup remains in force.

Reply and invalidation ordering must avoid kernel writeback deadlocks:
`storageserver.(*Server).publish` queues the origin reply before its events;
`storageclient.(*Client).receive` waits for grant application, not invalidation;
`(*Client).notify` drops the client mutex before calling the separate event worker;
`storagefuse.invalidate` does not run on a raw RPC callback; and go-fuse's
`(*fuseFD).withFD`/`writevFD` allow notification/reply writes concurrently rather than
holding a common write mutex. Do not add a synchronous invalidate-before-reply
barrier: invalidation can wait for kernel writeback/page locks that need that reply.
Subprocess isolation is not proof of coherence; msync/fsync stalls require
real-kernel notification/writeback diagnostics.

For a bounded outer fallback inside the authorized fixture (with its `timeout`
utility), use:

```sh
TMPDIR=/scratch timeout -s QUIT -k 5s 140s /scratch/storagefuse-mounted.test \
  -test.count=1 -test.timeout=120s -test.v -test.run='^TestNativeMountedManagedV3$' \
  > /scratch/storagefuse-mounted.log 2>&1
```

The internal child deadline records `/proc/<parent-or-child>/task/<tid>/{wchan,syscall,stack}`
and `/sys/fs/fuse/connections/<owned-connection>/waiting` **before** abort. Inspect
those exact paths/phase markers in the receipt; permission-denied diagnostics must
be reported, not fixed by weakening the credential/trust fixture. The outer timeout
owns only the launched test; the fixture owner must still perform its existing
bounded exact-container cleanup after a forced exit. A full mounted PASS remains a
separate real-kernel gate, not a claim from native compile/race/vet.

Run **inside the disposable authorized Linux fixture only**, from Guest:

```sh
TMPDIR=/scratch go test -count=1 -timeout=180s -v ./internal/storagefuse -run '^TestNativeMountedManagedV3$'
# Or run the cross-compiled binary already copied into that fixture:
TMPDIR=/scratch /scratch/storagefuse-mounted.test -test.count=1 -test.timeout=180s -test.v -test.run='^TestNativeMountedManagedV3$'
```

Teardown requests exact mount abort, joins local/server workers, then retires the
attachment using the actual controller principal and real managed barrier. Unknown
mounts or failed joins/drains preserve the private fixture directory for diagnosis;
cleanup never globally unmounts or recursively removes a surviving mount.
Forced grant-delivery loss, interruption, crash/power-loss durability and multi-
attachment mmap coherence are not established by this one mounted fixture.

## Verification

From Guest:

```sh
go test -race ./internal/storagefuse ./internal/storageclient ./internal/storagewire
go vet ./internal/storagefuse ./internal/storageclient ./internal/storagewire
GOOS=linux GOARCH=arm64 go test -c -o /tmp/storagefuse-linux-arm64.test ./internal/storagefuse
GOOS=linux GOARCH=amd64 go test -c -o /tmp/storagefuse-linux-amd64.test ./internal/storagefuse
```

From Guest/third_party/go-fuse:

```sh
go test -race ./fuse -run TestManaged
go vet ./fuse
GOOS=linux GOARCH=arm64 go test -c -o /tmp/go-fuse-managed-linux-arm64.test ./fuse
```

The full upstream `go test -race ./fuse` is not a clean Darwin check: the existing
buffer-pool integration test needs a FUSE mount utility, and the existing print
flags test expects a Linux-only flag. Do not install/mount anything to hide this.
