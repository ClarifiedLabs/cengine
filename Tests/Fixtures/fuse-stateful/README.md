# Stateful raw FUSE / ext4 proof fixture

**Disposable Linux VM only; this fixture is not a product filesystem.** No libfuse,
liburing, VM launcher or Docker invocation. `build.sh` only compiles; kernel boot
and probe execution are separate operator actions. This local single-root probe
does not establish cross-VM or full filesystem conformance.

## Required kernel and build

Use Linux **6.18.44**, commit
`1efe5d048a391de3ead2804b2e7f86376c356cc5`, with
`Configuration/kernel-patches/0001-virtiofs-host-close-to-open.patch` **then**
`Configuration/kernel-patches/0002-fuse-request-credentials-experimental.patch`.
`series` contains **0001 only**; managed kernels apply 0002 separately afterward.
Its historical `experimental` filename is not an activation status. Ordinary
`make kernel-build` does not include it. Local signed production sole-v2 works
with a local managed kernel; canonical release publication is a separate,
unverified boundary. See the
[kernel build and ABI contracts](../../../Configuration/kernel-patches/README.md).
Build against **that patched** `include/uapi/linux/fuse.h` (prefer the generated
`out/usr/include` tree). No copied private ABI definitions or stock fallback.

From the repository root, on a Linux build host:

```sh
sh Tests/Fixtures/fuse-stateful/build.sh \
  /path/to/experimental-kernel/out/usr/include \
  Tests/Fixtures/fuse-stateful/probe-linux
```

Optional host-only arm64 cross-build using installed Zig/Clang and musl
(use `ZIG_TARGET=x86_64-linux-musl` and the matching output name for amd64):

```sh
ZIG_TARGET=aarch64-linux-musl sh Tests/Fixtures/fuse-stateful/build.sh \
  /path/to/patched-uapi \
  Tests/Fixtures/fuse-stateful/probe-aarch64-linux-musl
file Tests/Fixtures/fuse-stateful/probe-aarch64-linux-musl
```

`CC` selects a native compiler executable; `ZIG` selects the Zig executable.
Compilation uses GNU C11, `-Wall -Wextra -Werror -O2`. This fixture has no Swift or
Xcode dependency. A successful cross-build is **not runtime evidence**.

For compile-only work with a cached patched source (no kernel/header build), use
an isolated include overlay containing its **unchanged** `linux/fuse.h`; Zig
supplies its normal target Linux support headers, including `asm/types.h`. Do not
pass the entire unexported `source/include/uapi` tree: it contains kernel-only
annotations such as `__user`. No credential structs, ioctl numbers or request
headers are redefined locally. Compile-time checks pin the 64-byte ABI3 snapshot,
semantics/capability offsets, `0xc040e5f0`, storage ABI1, Linux 6.18's 40-byte input
header/extension field and raw WRITE framing.

Example using a cached patched source, without mutating it:

```sh
uapi=$(mktemp -d Tests/Fixtures/fuse-stateful/probe-uapi.XXXXXX)
trap 'rm -rf "$uapi"' EXIT
mkdir "$uapi/linux"
cp /path/to/experimental-kernel/source/include/uapi/linux/fuse.h "$uapi/linux/fuse.h"
for target in aarch64-linux-musl x86_64-linux-musl; do
  ZIG_TARGET="$target" sh Tests/Fixtures/fuse-stateful/build.sh "$uapi" \
    "Tests/Fixtures/fuse-stateful/probe-$target"
done
```

## Wrapper expectations

Keep the `stateful` case name and runner binary path
`Tests/Fixtures/fuse-stateful/probe-aarch64-linux-musl`. One normal run requires
**every** assertion below; do not substitute synthetic counts, match only an old
PASS string or drop cases when valid bits differ. ABI2 runs and 0001's atomic
truncate behavior do not validate the managed ABI3 non-atomic truncate contract.

The separate credential probe supplies `groups65536`, `groups0`, INIT negatives
(`writeback`, `idmap`, `uring`, `passthrough`, `killpriv`, `killpriv-v2`,
`atomic-trunc`), mount prerequisites (`missing-creds`, `missing-permissions`),
`--storage-session` and `--killpriv`. This fixture does not replace those checks;
see [probe commands](../../../Configuration/kernel-patches/README.md#isolated-build-and-regression-probe).
`tools/build-managed-fuse-artifact.py` compiles separate Go native-test fixtures,
not this C probe or its kernel.

## Separate execution gate

**Only after booting the patched managed kernel in an authorized disposable VM:**

```sh
sudo /path/to/probe-linux --disposable-vm /absolute/path/on/ext4
```

The argument is an existing writable scratch **parent**, not a preexisting mount
or file to reuse. Init-user-namespace root, root primary IDs, native capabilities,
`/dev/fuse`, mounted `/proc`, and ordinary 4K/16K Linux pages are required. Other
page sizes fail the bounded-buffer prerequisite. The flag is an explicit operator
acknowledgment, not VM detection or permission to use a nondisposable machine.

The probe creates its own mode-0700 random subtree with separate `backing/` and
`mount/`, checks both ext4 superblock magic **and** exact `ext4` mount type, unshares
a mount namespace, and makes propagation recursively private. It mounts with all
three mandatory options:

```
request_cred,default_permissions,managed_close_to_open
```

It neither retries with stock options nor skips a failed prerequisite. The sole
root client has an explicitly empty supplementary group list. Ordinary request
credentials must match that driver's exact effective capability snapshot. NONE
is allowed only for lifecycle requests and `FUSE_WRITE_CACHE` on an existing
writable handle; it is never treated as a root authorization identity. NONE and
nonmetadata requests must have zero semantics. SETATTR requires ABI3 VALID and
only known semantics; FILE requires the exact live OPEN FH, and OPEN additionally
requires FILE and zero SIZE. Unknown valid-mask bits fail, never skip.

The server also requires the patched **storage-session ABI1**: mint command
`0x0000e5f2`, apply command `0x4050e5f3` with its 80-byte typed input. It translates
FATTR fields explicitly and applies captured metadata/killpriv intent to the
actual backing FD through the kernel session, not corrective chmod/removexattr
or a dummy truncate. The session is CLOEXEC, closed in the workload child, and
closed on parent teardown. Real GETXATTR uses backing `fgetxattr`, including its
actual ENODATA, so implicit killpriv checks do not receive fabricated answers.
This is a single-root-driver test policy with the same validated credentials in
both processes, **not** production credential replay/delegation or cross-VM proof.
FORGET/BATCH_FORGET have no reply-bearing `fuse_req`: this fixture balances their
references without querying credentials or replying. The separate
`Tests/Fixtures/fuse-credentials/probe.c` checks their credential-ioctl `ENOENT`
contract; this fixture does not claim duplicate coverage of that negative.

Control exchanges have 10-second deadlines, the child has a 90-second alarm,
and the server has a 95-second monotonic loop deadline. The server checks child
exit nonblockingly and drains all opened-handle RELEASEs before passing. Failure
cleanup disconnects FUSE, kills/reaps the child with a bounded wait, detaches only
its own mount, and removes only its own scratch entries. The child clears all
inherited cleanup paths (including the mountpoint), using a separate path copy
for its test operations rather than relying on `rmdir` failing with EBUSY.
A hard kernel/storage
hang can still require destroying the disposable VM; no userspace test can make
uninterruptible kernel I/O terminate. Abnormal termination may leave the owned
scratch directory, never a reason to prune unrelated resources.

## Mandatory assertions

Every listed assertion is required in one normal run. There are no optional
modes, skips, errno normalization, or simulated inode/link counts.

| Area | Exact assertion |
| --- | --- |
| ORC-020 held-unlink subcase | Mode 0600, uid/gid 0, 12 exact bytes; open real backing ext4 inode; link a second name; both handles retain identical inode identity with nlink 2, then 1, then **0** after real `unlinkat`. Read and overwrite all 12 bytes through retained handles, real backing `fsync`, and exact visible namespace excluding both names and **any** `.nfs*` entry. |
| No-FH retained GETATTR | `statx(AT_STATX_FORCE_SYNC, /proc/self/fd/N)` follows the still-held dentry without passing a FUSE FH. The daemon requires and counts real `FUSE_GETATTR` **without** `FUSE_GETATTR_FH` after unlink; returned attributes come from `fstat(object.fd)`, then client `fstat` must agree. `/proc` is used only to address the client's own retained dentry, never to recover credentials. |
| Object/FH lifetime | Node IDs map to pinned real inode descriptors; hardlink lookup deduplicates by authoritative inode number within the one ext4 backing filesystem. Kernel lookup/FORGET and OPEN/RELEASE references are balanced separately. Final removal of a name does not remove the object; its pin closes only once lookup and open references both reach zero (or fixture teardown). IDs are never reused. Each FH is an actual duplicated descriptor, not an invented data buffer. |
| Buffered/mmap/fsync | No `FOPEN_DIRECT_IO` and no negotiated writeback cache. Real `MAP_SHARED` writes plus `msync(MS_SYNC)`/`fsync`, then ordinary `pwrite`/`fsync`, must match direct backing reads exactly. Both ordinary and synthesized `FUSE_WRITE_CACHE` requests must be observed. The latter uses retained writable-FH authority, not flusher credentials. |
| Checked reopen/cache | Every open returns `FOPEN_KEEP_CACHE`; attribute and entry TTLs are one hour. Keep an old FD alive to prevent inode/cache eviction. Directly rewrite the **same backing inode**, restore its exact nanosecond mtime, and `fsync`. Reopen must issue checked post-OPEN GETATTR and expose exact bytes/EOF/size/mtime through buffered read and mmap: same size, growth across three pages, shrink to 31 bytes, empty, then regrowth. |
| GETATTR failure | Inject one real post-OPEN GETATTR `EIO`. `open` must return `EIO`, and the exact new FH must have been synchronously RELEASEd before the caller inspects counters. No pre-OPEN failure can satisfy this assertion. |
| FSYNC failure | Inject a FUSE FSYNC service `EIO`; client `fsync` must fail with that errno, then a new retry must perform a successful real backing `fsync`. |
| Checked-flush failure | Record the original writable FH from OPEN of the known `failure` pathname. Dirty a real mmap page, then inject `EIO` only for `FUSE_WRITE_CACHE` on that exact retained FH/node, offset 0, size exactly one page, after a distinct new FH has been opened on the same node. Open must fail **before** post-OPEN GETATTR and RELEASE its new FH. Backing bytes remain unchanged; the original FD must report writeback errseq at `fsync`, then recover after consuming the error. A fresh successful write/sync/reopen must preserve new bytes. |
| Non-atomic truncate open failure | ABI3 must **not** offer/negotiate `FUSE_ATOMIC_O_TRUNC` or either userspace killpriv flag. Dirty an existing mapping, then `open(O_TRUNC)` reaches checked OPEN/GETATTR before truncate SETATTR. Inject GETATTR `EIO`: dirty data has been flushed, new FH is RELEASEd, the SETATTR counter must not advance, and local/backing size remains unchanged. Original-FD fsync and a normal reopen preserve the flushed bytes. The managed profile is non-atomic; 0001's host-bind policy remains distinct. |
| Successful non-atomic truncate / no rebirth | Dirty the retained mapping again. Successful `open(O_TRUNC)` must flush the exact old page to backing and complete checked GETATTR before SETATTR with captured FILE/OPEN semantics, the actual new checked writable FH, and SIZE 0. Apply real ext4 metadata; inspect local size with DONT_SYNC before any GETATTR can repair it. Backing size/EOF remain zero through old-mapping msync, both real FDs' fsync, and fresh/retained-FD reads. Never access the old mapping beyond the new EOF. |

The raw operation subset is INIT, LOOKUP, GETATTR, GETXATTR, SETATTR,
OPEN/OPENDIR, READ, WRITE, FSYNC, FLUSH, RELEASE/RELEASEDIR, LINK, UNLINK,
READDIR and FORGET/BATCH_FORGET. SETATTR is a typed local metadata adapter for
these cases, not a general metadata conformance claim. Files are seeded directly
in the owned ext4 backing directory. Unknown operations return **EOPNOTSUPP**,
not ENOSYS success/fallback. No CREATE/rename, locks, xattr mutation, symlinks,
sockets or general filesystem interface is promised.
READDIR enumerates the actual backing directory; it never filters `.nfs*` names.

## Explicitly unproved edges

- **Pinned-page/invalidation-error propagation is not proved.** A simple
  `mlock`, splice/vmsplice or extra page reference is not a valid failure injector:
  pinned `mm/truncate.c::folio_unmap_invalidate()` deliberately ignores the
  folio reference count and unmaps mappings. Redirtying between checked flush and
  GETATTR is also not a deterministic EBUSY reproducer:
  `fs/fuse/file.c::fuse_launder_folio()` launders dirty pages during invalidation.
  This fixture does **not** fake an invalidation failure by returning EBUSY from
  GETATTR. A genuine deterministic kernel-side reproducer remains separate work.
- Injected EIOs model service failures. They are not ext4 device faults,
  disk-full/power-loss proof, or proof of allocation-error handling. The checked
  flush case exercises real dirty-page/writeback/error propagation, not the later
  `invalidate_inode_pages2()` failure branch.
- Atomic truncate is intentionally excluded by ABI3 (the credential probe
  separately tests INIT rejection). Successful non-atomic truncate is a mandatory
  assertion, not implied by compilation. General chmod/chown/timestamp/killpriv
  permutations belong to the credential/session fixture. Continuous
  coherence of retained mappings, multi-writer serialization, inode-number reuse,
  daemon restart/recovery, remote storage, credential transitions, distributed
  locks, export policy and production handle authorization are not covered.
- This tests the **exact Linux open-unlink property** exercised by ORC-020, not
  the entire saved oracle replay, Docker API parity, a production backend, TLS,
  or a complete POSIX profile. Consult [current compatibility status](../../../docs/docker-compatibility.md)
  rather than inferring it from this fixture. See
  `Tests/Compatibility/fixtures/volume-probe.go::server.snapshot` for the oracle's
  unnormalized nlink/identity/namespace/data observations.

Relevant pinned contracts: `fs/fuse/file.c::fuse_finish_open`, `fuse_open`,
`fuse_sync_release`, `fuse_fsync`, `fuse_writepage_end`, `fuse_launder_folio`;
`fs/fuse/dir.c::fuse_do_getattr`, `fuse_revalidate_file`, `fuse_do_setattr`;
`fs/fuse/dev.c::fuse_storage_apply_attr`; `fs/open.c::do_truncate`;
`mm/filemap.c::filemap_write_and_wait_range`, `file_check_and_advance_wb_err`;
`mm/truncate.c::folio_unmap_invalidate`, `invalidate_inode_pages2_range`;
`include/uapi/linux/fuse.h` for raw messages and the private ABI3 ioctl. These
symbols refer to the pinned kernel plus the two patches above, not arbitrary host
headers. Source reasoning and cross-compilation never substitute for the separate
patched-kernel execution gate.
