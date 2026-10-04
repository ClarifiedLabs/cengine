# Bounded upstream filesystem corpus pilot

This is **actual upstream C fsx and pjdfstest**, not a Go imitation or import of
an upstream harness. `test_volume_corpus.py` owns one shared executor for direct
cengine and explicit Docker-reference controls. Backend proof combines the host's
volume placement and lifecycle state with raw `/proc/self/mountinfo` for each
consumer: ext4 for direct volumes, exact `fuse.managed-v3` for shared volumes.
Both shared consumers are created before either starts.
There are no binds, devices, scratch disks, mounts, formatting, fill tests, daemon
restarts, global pruning, or privileged containers.

## Immutable inputs and licenses

* fsx: linux-test-project/ltp commit
  `dd2d61ac1a1e09797a6165f478abd4a9f4f43035` (20230127),
  `testcases/kernel/fs/fsx-linux/fsx-linux.c`, **APSL-1.1**. Its original header is
  retained; full license in `APSL-1.1.txt` (https://spdx.org/licenses/APSL-1.1.txt).
  This predates the LTP-harness-dependent rewrite. Source is unmodified.
* pjdfstest: pjd/pjdfstest commit
  `85a8aea9e685999ef0540392fd80535f873d7ff7`, `pjdfstest.c`,
  `configure.ac`, `tests/{rename,unlink,chmod}/00.t`, **BSD-2-Clause**;
  original notices retained and `PJDFSTEST-COPYING` included. Source is unmodified.
  The `.t` files are provenance, not executed: only their regular-file branches
  are transcribed into `PJD_CASES`. Local `config.h` replaces configure for the
  fixed Linux/glibc toolchain (no ACL extensions).
* Existing builder: `golang@sha256:2c4c60ef415fbfa5e90300722293bef36c5e63fae17570ce18f580af933dbd73`,
  linux/arm64. Uses its existing gcc/glibc with `-O2 -static -Wl,--build-id=none`.
  fsx additionally uses `-include libgen.h` for modern GCC's basename declaration.
  No packages downloaded or installed. No fixture binary is checked in.
* `provenance.json` records source/license/build-input SHA-256 values. Fixture
  metadata retains this manifest, builder digest, compiler version, archive hash.
  Build and fixture loading validate current inputs with explicit exceptions (also
  under `python -O`). Only manifest-listed regular, nonsymlink files enter the
  build context and image; each is at most 1 MiB, at most 128 entries / 8 MiB total.
  Parent-directory symlinks and unlisted include-file shadows are excluded.
  `build.py` itself is hashed; `provenance.json` excludes itself to avoid circular
  hashing. Refresh manifest hashes only after final source/script edits, then build.

## Selected and deferred

* fsx seed **1**, **1000** operations, `-l 4194304 -o 65536 -d`:
  read/write/truncate/mapread/mapwrite, size and data-integrity checks enabled.
  No `-L`, `-W`, `-R`, `-n` or simulated-operation suppression.
* pjdfstest `rename/00.t` lines 20–35 (regular branch): rename with a hard link,
  disappearance of old names and link count preservation.
* `unlink/00.t` lines 19–27 and 95–102: regular/symlink removal, missing-name
  errno, and unprivileged EACCES (ctime sleeps intentionally omitted).
* `chmod/00.t` lines 23–41 and 87–100: chmod follows symlink but does not chmod
  the link; numeric mode and unprivileged EPERM. No special files or lchmod.
* Local peer-visibility extension: pjdfstest publishes a short sentinel through
  open/write, process-exit close, then rename after the selected workload. The shared peer then opens
  fresh descriptors to check final content, mode, size, link count, and absence of
  removed/old/denied names. These are **post-workload visibility** observations,
  not interleaved semantics or concurrent-cache-coherence coverage.
* Optional `CENGINE_CORPUS_PROFILE=soak`: pinned LTP fsstress from the same revision
  as fsx. Its `fsstress.c`, `global.h`, `xfscompat.h`, `Makefile`, and
  `include/tst_common.h` retain original notices; `upstream/fsstress/COPYING` retains
  GPL v2. fsstress/global.h are GPL-2.0-only; Makefile and tst_common.h carry their
  own GPL notices. Compile directly with upstream `NO_XFS`, `_LARGEFILE64_SOURCE`,
  `_GNU_SOURCE` flags; no configure or host execution of upstream code.
  The native launcher requires exactly `-X -c -p 1 -l 1 -n 128 -s NONZERO -v -z`,
  then creat=4, mkdir=2, rename=2, link=1, symlink=1, unlink=2, rmdir=1, stat=1,
  getdents=1, readlink=1 via `-f`. **`-c` bypasses upstream's system rm-rf cleanup.**
  Native exec appends fixed `-d .` only after entering the validated worker
  directory, satisfying upstream's required directory argument without exposing
  path selection. No fsstress offset writes/truncates: fsx owns bounded data/mmap coverage.
* Additional pjdfstest rename/{10,13,14,18,20}.t files are read-only provenance.
  RTM-075 tests directory topology/atomic failures; RTM-076 tests sticky overwrite
  regular-file branches. No upstream shell harness or special files are run.
* Deferred: whole pjdfstest shell harness, ACLs, devices, timestamps, disk fills,
  long fuzz runs, power loss. This is a bounded pilot, not full
  POSIX, pjdfstest, LTP, or xfstests certification.

Bounds: the local (not upstream) `limit.c` launcher sets one independent SIGKILL
watchdog by executable: **150 s for `/fsx`**, **30 s for pjdfstest/fsstress**.
Host exec deadlines are **165 s for fsx**, **45 s otherwise**, identically on
Docker, block and shared backends, including soak. No external budget knob,
rearming or automatic retry; diagnostics consume, never extend, the same budget.
All children retain **30 s CPU**, **4 MiB/file RLIMIT_FSIZE**, no core dump.
fsx uses one data file and at most two diagnostic files (each <=4 MiB); pjdfstest
adds at most three names plus one denied target that must never be created. The peer extension adds one short sentinel name
(renamed once). There are exactly **23 writer pjdfstest invocations** (21 selected
upstream cases plus write and publication), **8 additional shared-peer invocations**, one
fsx invocation per backend, and no unbounded generation. Combined Docker-framed
stdout/stderr is capped at **1 MiB per exec**. Host socket closure is synchronous;
no background exec thread can race owned-resource cleanup. Keeper does no I/O and
is force-removed in owned cleanup. Failed upstream calls preserve raw stdout,
stderr, exit and errno in `.build/volume-hunt/corpus-*/<endpoint>-<backend>.jsonl`.
No xfail: failures remain failures; syscall mismatches do not suppress later
selected cases. Docker local volumes are controls, not proof of cengine backend.

## Optional bounded soak (not a backend pass claim)

Default `pilot` remains fsx seed 1 / 1000 operations / 4 MiB plus 23 writer and
8 shared-peer pjdfstest invocations. `soak` instead runs eight epochs, seeds
101,202,303,404,505,606,707,808, with two independent worker directories, each with
fsx 1000/4 MiB/64 KiB and fsstress 128 namespace operations. Direct uses one
consumer; shared uses two. Each worker owns an independent SDK client; all workers
join and hijacked streams close before exact-name + owner-token cleanup, including
ambiguous create responses. Each epoch uses a fresh owned volume, so leftovers
never accumulate across epochs. Filesystem observations are not filtered.

Bounds per epoch: <=512 entries, <=64 MiB data (two fsx data+diagnostic sets and
empty fsstress files). Containers: 16 pids, 256 MiB, one CPU, read-only root,
16 MiB /tmp. Launcher: fsx 150 s wall, others 30 s wall; all retain 30 s CPU,
256 MiB address space and process-group kill. Each command's host deadline is
capped by the remaining backend work budget (fsx at most 165 s, others 45 s).
Per backend: 60-minute deadline including a three-minute cleanup reserve;
all SDK requests use the remaining absolute budget and late replies fail, never
pass. Each active HTTP send has one joined watchdog that registers its fresh,
request-owned Unix socket before connect and uses shutdown+close at the absolute
deadline, including while headers drip. At most two watchdogs run during the two
workers; none survives its send or races cleanup. Bodies retain per-underlying-read
deadlines and a 16 MiB response limit; `stream=True` is required. Unsupported
transports and redirects fail closed. Cleanup failure retains exact-name/owner-token
reconciliation evidence for the lifecycle runner.
Journal cap: 128 MiB/pass, 512 MiB/campaign directory, with cleanup reserve.
Artifacts retain source hashes, owner plan, explicit schedule, mount identity,
raw stderr/stdout/errno, and cleanup. fsstress tolerates some syscall failures by
design: exit zero means workload completed, not per-operation POSIX certification.
The runner additionally requires all 128 numbered namespace-operation records.
RTM-075/076 provide focused asserted errno contracts. No automatic reducer.

`CENGINE_CORPUS_SHARED_FS`, when set, must equal `fuse.managed-v3`; NFS and generic
FUSE overrides are rejected. Raw identity is checked for every consumer alongside
the lifecycle proof, not inferred from placement metadata alone. Execute through
the standard compatibility runner. Fixture construction is not a runtime pass.

## Build only, then use the standard runner

From the repository root, with the authorized Colima **build-only** socket
(explicit `CENGINE_CORPUS_BUILD_HOST` is the user opt-in authority; there is no
ambient context fallback or machine-specific allowlist). Only absolute Unix
socket URLs are accepted, and the server version must identify Linux arm64 and
must not identify cengine:

```sh
CENGINE_CORPUS_BUILD_HOST="unix://$HOME/.colima/default/docker.sock" \
  python3 Tests/Compatibility/fixtures/volume-corpus/build.py
```

The build container has no network, no bind mounts, no capabilities, a read-only
root and size-bounded tmpfs. It compiles and checks ELF architecture/static
linking only; **it never runs corpus scenarios**. Artifacts go to
`.build/volume-corpus/fixture.{tar,json}`. Tests load the exact same archive on each
endpoint and retain replay/evidence outside the disposable daemon. Images use
full content-derived tags and are intentionally retained as reusable image cache,
like the existing volume probe. Cleanup removes only owned containers and volumes;
it never deletes a pre-existing/reused cache image or globally prunes. Re-run this
command after fixture source changes. Only the standard compatibility runner
may execute `RTM-067` / `ORC-023`; ORC-023 is individually marked oracle and
explicitly skips without `DOCKER_REFERENCE_HOST`. RTM-067 never inherits that skip.

Compatibility ledger entries (registered in `docs/docker-compatibility.md`):

| RTM-067 | Bounded upstream fsx and pjdfstest corpus on block/shared named volumes | `test_volume_corpus.py::test_bounded_upstream_filesystem_corpus` |
| ORC-023 | Bounded upstream filesystem corpus matches explicit Docker reference | `test_volume_corpus.py::test_bounded_upstream_filesystem_corpus_matches_reference` |

Applicable contracts: Linux read(2), write(2), truncate(2), mmap(2), rename(2),
link(2), unlink(2), chmod(2), stat(2); OCI filesystem mounts provide the mounted
filesystem, not a waiver of these Linux contracts. No new OCI lifecycle surface.
