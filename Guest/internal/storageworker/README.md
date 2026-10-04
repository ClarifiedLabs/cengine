# Linux owned lifecycle storage worker

`storageboot` uses this transport for the PID1-owned lifecycle worker. Transport
readiness alone never authorizes opening storage.

## Trusted parent API

- `StartLifecycle(root *os.File) (*Owner, error)`: root UID/GID, real/effective, PID1 only.
  Borrows a caller-verified directory FD; never takes a path or boot-result
  constructor. The caller retains its FD. The child receives its own duplicate.
- Launch is exactly `/proc/self/exe --managed-lifecycle-worker`, empty environment, working
  directory `/`, `/dev/null` on 0–2, private Unix `SOCK_SEQPACKET` FD3, root FD4.
  Both socket ends have `SO_PASSCRED` before spawn. Other parent FDs must remain
  CLOEXEC: StartLifecycle rejects ambient inheritable FDs, and trusted callers must not
  race that check by introducing new non-CLOEXEC FDs. Accept also rejects any
  unexpected non-CLOEXEC inherited FD before readiness; the worker dispatch
  MUST exit on Accept failure. This is not a sandbox against arbitrary code
  running inside the trusted process.
- `Owner.PID()`, `Send([]byte) error`, `Receive() ([]byte,error)`,
  `SetDeadline(time.Time) error`: nonempty packets up to `MaxPayload=65536`, one
  reader and one writer concurrently. No ancillary-send or FD-exposure API.
- StartLifecycle consumes an internal credential-ready packet (five-second deadline).
  Success grants **transport readiness only**, never permission to open an
  authority. Caller must send its explicit application start gate later.
- **A nonnil owner on error remains owned**: StartLifecycle requests pidfd SIGKILL and
  closes IPC after startup failure, but does not wait for actual reap. Retain it,
  observe `Done`, inspect `Result().Reaped`, then `Close`. No automatic restart.
- `Kill()` uses only the kernel birth pidfd (`SysProcAttr.PidFD`); there is no
  numeric PID signal fallback, nor a post-spawn pidfd_open identity lookup.
- `Done() <-chan struct{}` closes on the final wait observation, including a wait
  system error. `Result() (WaitResult,bool)` reports whether that observation
  exists. `WaitResult{Reaped,State,Err}` distinguishes actual wait from failure.
- `Close()` interrupts IPC immediately; it does not kill/wait. `ErrUnreaped`
  means retain the owner and retry later. Only actual reaping permits closing
  the pidfd. EOF, cancellation via Close, deadline, pidfd readiness and signal
  delivery never constitute a reap observation.

## Worker entry API

The trusted executable must dispatch only its fixed `--managed-lifecycle-worker` branch
into `Accept() (*Child,error)` before opening any storage authority. Accept owns
FD3/FD4 even on failure, makes them CLOEXEC, checks root UID/GID and actual
`Getppid()==1`, sets `PR_SET_PDEATHSIG=SIGKILL`, rechecks parentage, validates
FD3's connected Unix seqpacket type and pre-enabled PASSCRED, and checks FD4 is a
directory. `Child` exposes `*Channel` and `Root *os.File`; `Child.Close()` closes
both. The integration layer MUST verify ext4 and provenance of `Root` and await
its explicit authenticated application start gate before opening authority.
Neither channel creation nor the internal ready packet authorizes data/service
calls. There is no production environment, argument, expected-parent or root-path
configuration override. Private argument/parent/wait-gate seams exist only for
same-package tests and are not exported.

## Ownership and identity invariants

The same goroutine locks its OS thread before `cmd.Start` and remains locked
through its sole actual `cmd.Wait`, because Linux PDEATHSIG tracks the creating
thread. The initial wait gate prevents reaping before readiness credentials are
checked. Thereafter `waitid(P_PIDFD, WEXITED|WNOWAIT)` observes exit without
reaping; it closes/joins all transport operations and credential checks before
`cmd.Wait` can permit numeric PID reuse. Queued packets may be discarded at exit;
this is intentionally fail-closed, not a final-response delivery guarantee.
Only a nonnil ProcessState with nil error or `*exec.ExitError` is reaped. Other
wait failures retain the birth pidfd and locked thread indefinitely (fail-stop,
not a retry/restart policy). The trusted executable must not install a competing
reaper for this child. Close does not synchronously wait for child exit.

Each recvmsg uses `MSG_CMSG_CLOEXEC` and checks exactly one `SCM_CREDENTIALS`
with root UID/GID and the exact launched child PID (parent side) or PID1 (child
side). `SO_PEERCRED` is deliberately unused: a pre-spawn socketpair pins its
creator, not the sender. Missing/duplicate/wrong credentials, unknown cmsgs,
SCM_RIGHTS, empty packets, data or ancillary truncation are rejected; every
received right is closed even on credential rejection. No claim is made that
this isolates hostile root/CAP_SYS_ADMIN code able to forge Linux credentials;
the executable, PID1 and passed root descriptor are trusted.

## Verification scope

Tests are Linux-only subprocess tests using their own source test executable.
Root uid/gid, /proc, pidfds, SO_PASSCRED and subreaper support are required and
fail rather than skip when unavailable. They cover actual exit/nonzero/signaled
waits, early child death, parent death with explicitly reaped orphan, gated
wait, deadlines/EOF/Close without invented reaping, received-rights cleanup,
credential validation, bounds, stdio/environment, and swapped/malformed FDs.

On macOS, cross-compile only (do not claim execution):

```
cd Guest
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c ./internal/storageworker -o /tmp/storageworker-arm64.test
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c ./internal/storageworker -o /tmp/storageworker-amd64.test
```

Run on an authorized Linux fixture:
`go test -count=1 -timeout=90s ./internal/storageworker` (and race-enabled where
supported). Cross-compilation is not execution of these Linux ownership checks.
