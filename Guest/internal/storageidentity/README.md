# Managed storage identity worker

The managed ext4 service shares a zero-value `Worker` and calls
`Do(storagewire.Caller, umask, func() error)`. The service must authenticate caller
provenance and apply `storagewire.PolicyFor`/admission before entering this scope.
It does not implement grants, confinement, descriptor lifetime, or operation policy.

Identities contain the complete supplementary group multiset
(up to 65,536, including duplicates) and a literal uint64 effective capability set.
UID 0 with zero capabilities gets zero capabilities; nonroot callers can retain
explicitly captured capabilities. Unsupported kernel bits and Linux's `-1` ID
sentinels fail closed. Missing (`nil`) groups are invalid, matching wire validation.
The group slice is copied before waiting or dispatch; callers must not race the
initial copy. Only that private copy is sorted, never deduplicated or truncated.

Each call uses a locked, disposable **non-leader** OS thread with raw Linux
syscalls. If dispatch selects the process leader, it holds that clean thread
locked until a second goroutine has locked a different thread, then unlocks only
the untouched leader before permitting installation. No credentialed thread is
unlocked, reused, or used to spawn that handoff. The existing semaphore covers
both dispatch and callback; the handoff needs at most one extra goroutine per
admitted call. The installer independently rejects `TID == PID` before mutation.
`CLONE_FS` is
unshared **before** setting umask, isolating cwd/root/umask from other threads.
Groups and all real/effective/saved IDs are replaced. `PR_SET_KEEPCAPS` preserves
permitted capabilities across a nonroot UID transition when requested; capset then
installs exactly effective = permitted = captured, inheritable = ambient = zero.
Keepcaps is cleared, and all IDs, groups and capability sets are verified before
running the callback. The service must already hold requested capabilities plus
identity-setup authority; UID 0 is not a fallback for missing authority.

The synchronous callback must not spawn goroutines, exec, unlock its thread, or
use process-wide credential wrappers. This is a trusted-code boundary, not a
sandbox against a malicious callback. Exiting without `UnlockOSThread` retires the
thread on success, syscall/setup failure, panic, or `runtime.Goexit`; there is no
fallible restoration path. The 64-slot semaphore lasts through callback completion.
There is deliberately no cancellation-return API. Goroutine/thread creation failure
is a Go runtime fatal error, not a recoverable request error.

### Why the leader is excluded

`/proc/self/status` reports the thread-group leader, whereas raw credential
syscalls and `/proc/thread-self/status` report the executing thread. In
[Go 1.25.14 `runtime.mexit`](https://github.com/golang/go/blob/go1.25.14/src/runtime/proc.go#L1988-L2010),
`m0` is permanently parked instead of terminated. A request on it would leave
its changed credentials and isolated fs state visible through `/proc/self` even
though Go never scheduled another goroutine on that contaminated thread.
`runtime.LockOSThread`'s clean template protects newly created runtime threads,
but does not exclude `m0`. The leader must stay clean and usable, including for
canonical process inspection and procfs descriptor operations; see Linux
[`proc_pid_fd(5)`](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html).
Regression coverage forces the leader handoff and separately checks leader state,
raw executing-thread IDs, all concurrently active clean threads, and procfs opens.

Contracts: Linux `credentials(7)`, `capabilities(7)`, `setgroups(2)` (sorted group
multisets), `setresuid(2)`, `setfsuid(2)`, `unshare(2)` (`CLONE_FS`), and Go
`runtime.LockOSThread`. Linux arm64/amd64 are supported; other targets return ENOSYS.

Checks:

```sh
cd Guest
go test -race ./internal/storageidentity
go vet ./internal/storageidentity
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/storageidentity.test ./internal/storageidentity
# On real Linux root with setup capabilities and ext4 (ACL enabled):
TMPDIR=/path/on/ext4 go test -race -count=1 ./internal/storageidentity
```

Linux syscall tests skip when not root; they are not emulated on Darwin. Root
without the required capabilities, CLONE_FS permission, or ACL support fails the
Linux checks rather than silently substituting a mock.
