# Private storage for a disposable Docker reference

The reference harness needs a spacious, trusted local filesystem; creating an
APFS volume is not a prerequisite. Use [volume_reference.py](volume_reference.py)
with a new run root whose existing ancestors are canonical, owned by root or the
invoking UID, and not group/other-writable. Symlink components and extra-write ACLs
are outside the supported trust policy. Do not repair a shared tree with recursive
ownership or permission changes.

## Reference harness

Requires Python 3.11+, macOS 26+ on Apple silicon, installed Lima 2.2.0, Docker CLI,
and a local SHA-256-pinned aarch64 image containing the requested Docker Engine,
systemd/cloud-init/SSH/sudo and Lima guest dependencies. The image must have an
empty Docker data root and no automatic update jobs. Provisioning downloads no
image or packages and does not use ambient Docker contexts or Lima templates.

After explicitly authorizing a disposable VM, substitute reviewed, absolute,
canonical paths and the independently verified image digest:

```sh
python3 tools/volume_reference.py provision --allow-disposable-vm \
  --root /absolute/private/new-run \
  --image /absolute/private/docker.raw --image-sha256 '<reviewed SHA-256>' \
  --engine-version '<exact Engine version>' \
  --limactl /absolute/canonical/limactl --docker /absolute/canonical/docker
python3 tools/volume_reference.py status --root /absolute/private/new-run
```

Provision prints the run UUID and explicit Unix endpoint. `crash`, `restart` and
`destroy` each require `--root` and that exact `--run-id`. Crash force-stops only
the owned instance; restart is limited to eight attempts and requires a verified
crash. Failed/interrupted attempts are terminal, not resumable. Destroy removes
only the Lima instance; receipts, logs and fixtures remain. There is no automatic
cleanup, adoption or global prune. Optional owned fixture mounts are not a
qualified bind-mount oracle. See the script's module documentation for the full
image and trust requirements.

## Machine-pinned APFS helper

[volume_reference_apfs.py](volume_reference_apfs.py) is **not a portable storage
provisioner**. Its `HOME`, UID/GID, container/store/data UUIDs, data path and capacity
are hard-coded. The `--expect-*-uuid` arguments confirm those constants; they do
not select another disk. Likewise, `volume_reference_build.py` pins local paths
and tool/source digests. Neither helper is a generic prerequisite for the
reference harness. Do not reuse old run IDs, observed free-space values or device
numbers as current authorization.

Using the APFS helper requires separate review of the exact source bytes and
current machine topology. Never execute its `prepare` action directly from a
shared checkout: self-hashing happens too late. The hash-before-execution bootstrap
below treats source as data and executes only bytes matching an independently
reviewed digest. It creates a private setup copy and receipt, not an APFS volume.
Run from the repository root; the script still performs its hard-coded host checks.

```sh
SHA='<independently reviewed script SHA-256>'
RUN='<new canonical lowercase UUID>'
python3 -I -B - "$SHA" "$RUN" <<'PY'
import hashlib, os, pathlib, sys
expected, run_id = sys.argv[1:]
source = pathlib.Path('tools/volume_reference_apfs.py').absolute()
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, 'rb') as stream:
    data = stream.read(1024 * 1024 + 1)
if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit('reviewed source SHA mismatch; nothing executed')
sys.argv = [str(source), 'prepare', '--allow-private-copy', '--run-id', run_id,
            '--setup-sha256', expected]
exec(compile(data, str(source), 'exec'), {'__name__': '__main__', '__file__': str(source)})
PY
```

Review the printed private copy and receipt before separately authorizing
`create`. It requires `--allow-new-apfs-volume`, the same run ID/source digest and
all three exact UUID pins. Never sudo Python. Privileged Apple commands use
`sudo -n`; the helper never prompts, refreshes credentials or retries.

Creation adds exactly one 48-GiB-quota, zero-reserve volume, requiring at least
72 GiB free. It verifies topology, mounts under a new private parent, enables
native ownership, and changes only the new volume root to the pinned UID/GID and
mode `0700`. No resize, deletion, unmount, mount adoption or automatic cleanup is
implemented. The locked, fsynced `0600` receipt stays outside the new volume.

On any failure, retain the receipt, directories and volume for manual
reconciliation; do not rerun or automatically clean up. A timed-out disk command
may finish later, even before the new UUID was recorded. Private parents and inode
checks do not contain malicious same-UID/root actors or physical unplug races.

## Disk-free checks

```sh
python3 -I -B tools/tests/test-volume-reference-apfs.py
```

Diskutil and sudo operations are fakes; these checks create only small private
temporary directories. They do not establish real APFS mutation or VM acceptance.
