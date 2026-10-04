# Offline volume application campaign (VOL-023)

`wheels.py` creates deterministic repo-owned `volume-workflow` 1.0/2.0 wheels using
only `zipfile`. No index, dependency, build backend, executable build hook, or host
installation is involved. The console script reads an installed package resource;
v2 removes a v1-only file. Wheel RECORD entries carry URL-safe SHA-256 and byte sizes.
The pinned base image is verified against `Tests/Fixtures/compose/developer-loop/Dockerfile`;
that fixture's requirements are empty, so it does not test an actual package change.

One campaign runs direct (`block`) and pre-created two-consumer (`shared`) modes
serially. A root-only initializer owns each fresh volume for UID:GID 10001:10001,
then is removed before the nonroot application is created. Every phase's consumers
are removed before the next phase; shared consumers are both registered before
startup. Source and fresh restore use the same absolute `/work/tree` prefix, needed
by venv scripts. A read-only source tar preserves the entire venv/config/data tree,
including literal symlinks, numeric owner/mode/mtime and within-filesystem hardlink
relations. There is no cross-engine inode-number assertion or `.nfs*` filtering.

Bounds: two modes, three volumes per mode, at most two simultaneous containers,
16 processes/container, 256 MiB memory/container, 90 seconds/guest phase, 35 seconds/
child command plus at most 5 seconds kill/reap, 120 seconds/host phase, and
1800 seconds/campaign plus bounded cleanup (at most 27 exact-name get/remove
pairs, each pair at most 5 seconds). Every SDK operation uses the shared
`test_volume_corpus.api_deadline` Unix transport: an owned pre-connect/header
watchdog, per-raw-read body deadlines, `stream=True`, a 16 MiB response limit before
JSON decoding, and redirect rejection. Requests require identity encoding and
reject compressed responses before decompression, so compressed expansion cannot
bypass the wire-byte/deadline limits. Header watchdogs are joined before body
ownership transfers; log generators and all owned responses (including ignored
DELETE bodies) close before cleanup. One response-close failure does not prevent
closing the rest. The shared transport's source hash is captured with the fixture.
Socket inactivity
timeouts alone are not treated as wall-clock bounds. Failed commands retain preceding
version/command observations, and failure/cleanup records have reserved space.
Each tree is at most 256 entries/4 MiB (including duplicate hardlink sizes); archive
at most 16 MiB; two trees plus archive at most 24 MiB mutable named-volume data.
Only `/tmp` is writable tmpfs (2 MiB/container); rootfs is read-only. Guest commands
have CPU, file-size, descriptor and output limits. Host artifacts are at most 8 MiB.
This is a fixed tiny fixture, not a quota/ENOSPC, randomized stress, power-loss, or
package supply-chain test. No device, mount, bind, prune, or host filesystem mutation
is used; the only host writes are bounded campaign evidence under `.build/volume-hunt`.

The runner never pulls/builds images. Seed the exact digest through the authorized
compatibility lifecycle before running. The test records image inspection, source
and wheel hashes, Python/pip versions, raw guest mountinfo and lifecycle backend
proof. Direct mounts require ext4; shared mounts require `fuse.managed-v3`.
Missing image/backend proof and cleanup failures are failures, not skipped claims.
All names and the unique owner token are journaled before creation. Cleanup
reconciles exact names and requires the exact owner label, including ambiguous
create outcomes. It never deletes an image or any unowned resource.

Engine-free verification (does not execute wheels):

```sh
python3 -B tools/tests/test-volume-workflows.py
.build/compat-venv/bin/python -B tools/tests/test-volume-workflows.py
```

The existing compatibility Python environment additionally runs real local Unix
HTTP header/body drip, creation, log, cleanup and independent-client regressions;
these are local test peers, not Docker/VM execution. Plain stdlib Python explicitly
skips only those SDK-dependent transport checks if Docker SDK/pytest are absent.
The lazy shared-helper import defines fixtures but never requests corpus fixtures
or builds/runs a workload.

VM verification uses the serialized compatibility runner after seeding the pinned
image. VOL-023 is registered in the [compatibility ledger](../../../../docs/docker-compatibility.md):

```sh
make test-compat COMPAT_ARGS='Tests/Compatibility/test_volume_workflows.py'
```

Contracts: Docker Engine API v1.45 ContainerCreate `User`, `ReadonlyRootfs`, mount
`ReadOnly`, and named-volume lifecycle; Linux `link(2)`, `symlink(2)`, `stat(2)` and
`chmod(2)`; Python venv and pip offline wheel upgrade behavior; tar hardlink metadata.
VOL-023 is campaign coverage only. Promote minimized failures to RTM separately.
