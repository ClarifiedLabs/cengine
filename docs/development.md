# Development

Development requires Apple silicon, macOS 26 or newer, and Xcode. The supported
entry points are:

```sh
make build                 # debug app and CLI
make guest-assets          # kernel and paired guest initramfs assets
make kernel-build          # explicit kernel source build
make test                  # compatibility-harness checks and Swift/Xcode tests
make test-guest             # Linux guest tests
make test-compat            # isolated Docker/Compose compatibility tests
make test-release          # release-tooling regression checks
make dist-cli              # tests and staged CLI/assets
make package               # local unsigned package
```

The hosted Linux CI job runs general guest tests without root, then runs the
storageworker and supervisor component suites as root for credential, ownership,
and direct-ext4 xattr coverage. The managed symlink-capability test requires the
patched guest kernel and runs with `make test-guest`; it is excluded from the
hosted-kernel job. The two root component suites are excluded from its
unprivileged pass and run in the root pass instead.

## Guest assets and kernels

`make guest-assets` fetches the checksum-verified kernel release selected by
`Configuration/kernel-release`, builds the static Go guest services and `mke2fs`,
and packs deterministic initramfs files with boot-asset checksums.

Local kernels are supported for development and testing:

```sh
CENGINE_LOCAL_KERNEL=/absolute/path/to/Image make guest-assets
# Or build the configured Linux source and assets together:
CENGINE_KERNEL_MODE=build make guest-assets
# Or reuse an explicit source build:
make kernel-build
CENGINE_LOCAL_KERNEL="$PWD/.build/guest/vmlinux" make guest-assets
```

`make kernel-build` uses the exact Linux commit, configuration and patches under
`Configuration/`. It runs through Docker Buildx on Linux or macOS using the
selected Docker context and builder. Configure those first; kernel builds never
install a privileged helper or request administrator access. Use
`CENGINE_TOOLCHAIN_DOCKER_CONTEXT` for an explicit context. The default parallelism
is the container's visible CPU count; `CENGINE_KERNEL_BUILD_JOBS` overrides it.
To constrain builder resources:

```sh
CENGINE_KERNEL_BUILD_CPUS=8 CENGINE_KERNEL_BUILD_MEMORY=16g make kernel-build
```

Local builds and custom kernel URLs do not establish canonical release origin.
Application releases require the configured immutable kernel release to be
published and fetched through the canonical path; see [Release](release.md).
The ordinary kernel series currently includes only the host-bind patch. Shared
managed storage also requires the request-credential patch and matching ABI; a
plain source build alone is not sufficient. See
[Kernel patches](../Configuration/kernel-patches/README.md) for the managed-kernel
build procedure and required compatibility checks.

## Tests

`make test` checks harness isolation, then runs `CEngineCoreTests`,
`CEngineAPITests`, and `CEngineAppTests` through the shared `cengine` scheme.
Hosted macOS test and release jobs use the `xcode-27` preview runner image
and explicitly select Xcode 27.1. Use Xcode 27.1 locally to match CI.
The jobs also select that Xcode globally and resolve its `SDKROOT` for native
subprocess fixtures. Hosted tests run serially to avoid contention in deadline
and subprocess tests on the smaller CI machines.
The host regression checks also require Go on `PATH`. To use the same pinned
toolchain as macOS CI, run `export PATH="$(dirname "$(sh Scripts/ensure-go-toolchain.sh)"):$PATH"`
before `make test`.
Run focused checks first, then `make test` before review. VM-backed changes also
require `make test-compat` locally; GitHub-hosted runners cannot run that suite.
To retain an Xcode result bundle:

```sh
make test XCODE_RESULT_BUNDLE="/path/to/fresh/test-results.xcresult"
```

For serial test execution, keep the standard build tool and pass test flags:

```sh
make test XCODE_RESULT_BUNDLE_FLAGS='-resultBundlePath /path/to/fresh/test-results.xcresult -parallel-testing-enabled NO'
```

Use a fresh result-bundle path each time. If an app test host stalls with products
on an external volume, set `XCODE_DERIVED_DATA` to an internal path such as
`$HOME/Library/Caches/cengine-tests`, after checking free space. Do not disable
permissions or tests to work around a stalled host.

Use Swift Testing (`@Suite`, `@Test`, `#expect`) for unit tests. Bug fixes need
regression coverage. Each non-oracle compatibility test needs a unique
`@pytest.mark.compat("AREA-NNN")` entry in the
[compatibility ledger](docker-compatibility.md).

Runtime-semantic changes must cite Docker API v1.55, OCI Runtime Spec v1.3.0 or
the applicable Linux contract in that ledger, update its OCI applicability table,
and add a focused `RTM-*` test before relying on kind or application-level tests.
Reference Docker/Moby behavior only where those specifications are silent.

## Compatibility setup

Provision the dedicated compatibility helper once with
`make test-compat-helper-install` (an attended administrator action), then run
`make test-compat-doctor`. Normal suite, soak, oracle and isolated-tool runs do
not request authorization or repair/replace the helper. Guest-only and engine-only
updates do not ordinarily require reinstalling it: compatibility uses authenticated
capabilities and a security floor, not an exact local binary. Deliberately update
it when testing changed helper behavior or an incompatible protocol.
Qualification and fault campaigns require an exact signed pair.

The helper is shared across worktrees. Before replacing it, have every consumer's
owner quiesce their work or explicitly authorize interruption. Never stop foreign
shims, replace the production helper, or downgrade the test helper to run old tests.
See [Compatibility testing](compatibility-testing.md) for signing, lifecycle,
asset overrides, network pools, cleanup and exact-helper requirements.

```sh
make test-compat COMPAT_ARGS='Tests/Compatibility/test_kind.py -x -vv'
make test-compat-soak
make test-compat-oracle DOCKER_REFERENCE_HOST=unix:///path/to/authorized/docker.sock
```

Include `Tests/Compatibility` or specific test paths when overriding `COMPAT_ARGS`;
flags alone can collect unrelated tool tests. Never invoke the VM-backed pytest
suite directly or infer a reference endpoint from the active Docker context.

## Storage setup and recovery

Shared volumes use FUSE backed by ext4 in the storage VM. Unsupported store formats
are rejected without modifying their data; cengine does not migrate or automatically
reset them. Preserve the store and its recovery metadata.

Production owner enrollment is explicit and one-time: use app onboarding,
**Enable**/**Restart**, or `cengine helper setup-storage-owner` as your normal user
with administrator approval. `cengine helper check-storage-owner` and background
startup only check ownership; the first XPC caller cannot enroll itself.
The compatibility helper install target provisions its separate test owner
without manual root-helper enrollment.

Daemon-only restart reconnects control without stopping workloads. Recovery also
supports controlled first-start retry and installed-system reboot. These are
separate from arbitrary helper, VM or disk failure guarantees. See
[Managed storage](storage-adoption.md) for the lifecycle and recovery contract.

## Volume campaign workflow

Run one serialized compatibility runner at a time. Begin with engine-free helper
checks, then focused VM-backed contracts before the broader compatibility suite:

```sh
python3 tools/tests/test-compat-harness.py
python3 tools/tests/test-volume-invalid-copy.py
make test-compat COMPAT_ARGS='Tests/Compatibility/test_volume_concurrency.py'
make test-compat COMPAT_ARGS='Tests/Compatibility --tb=short'
```

For corpus and application fixtures, follow the build/provenance instructions in
[volume-corpus](../Tests/Compatibility/fixtures/volume-corpus/README.md),
[volume-workflows](../Tests/Compatibility/fixtures/volume-workflows/README.md), and
[Compose upstream volumes](../Tests/Fixtures/compose/upstream-volumes/README.md).
Fixture builds, cross-compilation and skipped tests are not runtime proof.

Volume oracles require an explicitly authorized Linux/arm64 Docker Engine. They
remove only run-owned resources; a normal reference is not permission for global
prune or crash testing. Destructive campaigns require a separately provisioned,
explicitly authorized disposable engine.

To replay a trusted local plan:

```sh
CENGINE_VOLUME_PROBE_PLAN=/absolute/path/to/plan.json \
  make test-compat-oracle DOCKER_REFERENCE_HOST=unix:///path/to/authorized/docker.sock \
  COMPAT_ARGS='Tests/Compatibility/test_volume_oracle.py -k serial_volume'
```

Keep `plan.json`, `fixture.tar` and `fixture.json` together. The archive executes
code on both endpoints; its hash checks only the archive/manifest pair, not the
plan or provenance. Replay only trusted archives. Preserve failed roots and
uncertainty markers until investigated; a timeout, process-census error or failed
transport is not evidence of drain or process exit. Never signal an unverified
process, delete lifecycle journals, or use global prune to clear a failed run.

## Build identities

Metadata-only local CLI builds are ad-hoc signed with
`Configuration/cengine.entitlements`. VM-backed lifecycle startup requires matching
Developer ID engine/helper/controller identities; set
`CENGINE_DEVELOPER_ID_APPLICATION` for compatibility builds. Engines and VM shims
require `com.apple.security.virtualization`. The root-owned helper does not claim
`com.apple.vm.networking`: that restricted entitlement requires a provisioning
profile for non-root vmnet access.

The Xcode workspace owns Swift package resolution. Commit
`cengine.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved` when
changing dependency versions.

## Local installation and metadata-only development

The signed app registers the per-user `dev.cengine.engine` LaunchAgent and the
privileged `dev.cengine.network-helper` LaunchDaemon. The helper authorizes storage
ownership, owns vmnet uplinks and binds privileged ports through authenticated XPC.
The app manages service approval, bundled guest assets, Docker context and Buildx.

To develop API metadata without downloading a kernel or starting VMs:

```sh
cengine daemon --metadata-only
DOCKER_HOST=unix://$HOME/.cengine/run/docker.sock docker info
```

A concurrent daemon needs both a distinct `--socket` and a distinct `--root`;
metadata-only mode still writes store metadata. Store leases in
`/private/var/tmp/dev.cengine.store-locks-<uid>` are persistent: do not remove them
to clear a lock. Stop the daemon before administratively moving or replacing its
root; ownership leases do not descriptor-pin path I/O or fence storage-VM writers.

State is under `~/Library/Application Support/cengine`, runtime sockets under
`~/.cengine/run`, and daemon logs under `~/Library/Logs/cengine`. See
[Raw runtime architecture](raw-runtime.md) for implementation details and
[Release](release.md) for signed, notarized package requirements.
