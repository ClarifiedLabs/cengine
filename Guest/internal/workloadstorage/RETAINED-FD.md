# Retained writable file observer

## Integration contract

Both retained-FD routes are wired through the full compatibility profile. See
[docs/docker-compatibility.md](../../../docs/docker-compatibility.md) for scoped
RTM-103 native coverage.

The owner keeps its acquisition root until its sole syscall worker exits to
exclude asynchronous FUSE RELEASEDIR from the READ window.
A Linux close that returns exact ENOTCONN **after the exact mount already joined**
still relinquishes the descriptor: see [close(2)](https://man7.org/linux/man-pages/man2/close.2.html).
Only that error is classified as a disconnected FLUSH result, retained privately
for diagnosis. EBADF, other errors, joined error aggregates, cancellation and
unjoined mounts/workers cannot yield released ACKs. Close is never retried.

Same-E guest v7 / worker v8 observes the actual retained pwrite's first denied
RPC: CallerAuth GETXATTR of exactly `security.capability`, on the positive WRITE's
node and at a later sequence. Linux 6.18 calls kiocb_modified / cap_inode_need_killpriv
before WRITE. This is a denied prewrite prerequisite, **not fabricated WRITE
admission**. Actual pwrite and fsync must both fail on the same retained descriptor;
worker Admit must reject that exact original binding/sequence, and independent
backing must remain unchanged. Worker v7 requires strict actual WRITE evidence; v8 accepts the exact denied
prewrite prerequisite described above.

## Descriptor acquisition and operations

`retained_fd_unix.go:openRetainedFD` borrows an owner-pinned original mount
root descriptor and opens only the existing fixture `a` (the `a`/`z` tree used by
`Tests/Compatibility/fixtures/managed-prepare-faults.go`). No path, payload,
credentials, authority, wire version, or selector is exposed. It never creates,
truncates, unlinks, or reopens the target file. The caller must exclusively own
the trusted fixture/root during acquisition and preserve the original mount.

Linux uses `openat2` with BENEATH, NO_SYMLINKS, NO_MAGICLINKS and NO_XDEV;
unsupported kernels fail closed. Root/file statx mount IDs and devices must
match. The target must be a regular, singly linked, writable-mode file of 1–4096
bytes. `O_NONBLOCK` prevents a substituted FIFO from blocking open; it does NOT
make regular-file/FUSE operations cancellable. Darwin's implementation exists
only for host tests and makes no Linux mount-ID/FUSE attestation claim.

The retained `O_RDWR|O_CLOEXEC` file performs an actual one-byte `WriteAt(0)` plus
file `Sync`, first with `0xa5`, then with `0x5a`. Only a completed, successful first
pair permits the second; each actual attempt is single-use. Both pairs use the
same original file descriptor, even if its path is renamed/replaced. The helper
returns actual write count/write error/sync error, with no success-as-denial or
authority-denial predicate. A write error is not substituted for fsync; both
outcomes are retained when context still permits the sync. A failed positive
consumes the helper. Closing before the attempt is invalid, not an EBADF negative.

## Ownership and evidence limits

- Directory FSYNCDIR behavior is not a writable-file prerequisite or accepted
  writable retained-FD case result.
- A context with at most the existing ten-second budget is required and checked
  before/after operations. This bounds scheduling/evidence acceptance, **not a
  blocked kernel syscall**. No detached goroutine or timed-out syscall is called
  complete. Concurrent calls/close fail busy rather than closing an active FD;
  busy close retains ownership and requires a real join before retry.
- `retained_fd_owner_unix.go` serializes acquisition, write, fsync and close
  on one owned worker. Cancellation signals the exact mount's existing abort
  worker; syscall and native mount joins are separately required. A failed join
  preserves the owner and failed cause and cannot authorize generation release.
  Native acquisition duplicates the original O_PATH mount pin and verifies exact
  statx mount ID, rather than reopening an overmountable pathname. These are
  ownership requirements, not a proven native syscall timing bound.
- The native owner must attest this is the exact live original FUSE attachment
  and mount, preserve its lifetime, correlate the real retirement receipt and
  unchanged/replaced service binding as applicable, and enforce cancellation
  through the existing containment/finalization owner. A root FD alone is not
  authenticated attachment identity. No caller boolean can stand in for Retire.
- A separate fresh owner must verify exact backing bytes and metadata, with its
  baseline taken **after the intentional positive mutation**. The second fixed
  byte makes any erroneously accepted write distinguishable. There is no local
  readback-as-persistence proof, restore-after-negative, or unchanged-backing
  claim. Retirement does not itself prove writeback is blocked.
- Host tests exercise real file writes/fsync, descriptor retention across path
  replacement, fixed-path rejection, bounds, cancellation-before-dispatch and
  ownership. They do not simulate retirement by chmod, local close, invalid FD,
  timeout, or manufactured syscall failure. They do not substitute for real
  retired negatives, Linux mount-crossing execution or native end-to-end coverage.
