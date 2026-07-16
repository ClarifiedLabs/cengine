# Development

`cengine` is an Xcode project targeting arm64 macOS 26. The supported build
entrypoints are:

```bash
make build
make guest-assets
make kernel-build
make test
make test-guest
make test-compat
make test-compat-soak
make test-compat-oracle DOCKER_REFERENCE_HOST=unix:///path/to/docker.sock
make test-compat-reset
make dist-cli
make package
make test-release
```

`make test` first checks compatibility-harness environment isolation, then runs
`CEngineCoreTests` and `CEngineAPITests` through the shared `cengine` scheme.
`make guest-assets` fetches the checksum-verified kernel release named by
`Configuration/kernel-release`, builds the static Go guest services and static
`mke2fs`, packs both deterministic initramfs files, and writes boot-asset
checksums. Set `CENGINE_LOCAL_KERNEL=/path/to/Image` to prepare guest assets with
a local ARM64 kernel instead.

`make kernel-build` is the explicit source-build path for kernel development. It
builds the exact Linux commit and cengine config recorded under `Configuration/`
and leaves the result in `.build/guest/vmlinux`; a following `make guest-assets`
reuses it because its kernel input stamp is current. Use
`CENGINE_KERNEL_MODE=build make guest-assets` to combine those steps. On Linux
ARM64, including kernel release CI, the kernel and `mke2fs` toolchains run through
Docker Buildx. The builder uses
`CENGINE_TOOLCHAIN_DOCKER_CONTEXT` (default: `default`). On macOS, the source
build runs inside an isolated cengine container using an installed or explicitly
configured `CENGINE_BOOTSTRAP_KERNEL`. Normal builds do not need that bootstrap
because they fetch the dedicated kernel release.
`make dist-cli` runs the tests and stages `dist/cengine` plus `dist/share/cengine`.
`make package` creates `dist/cengine-<marketing-version>.pkg` for local
release-artifact testing, using `MARKETING_VERSION` from the Xcode project.

`make test-compat` builds and signs the debug daemon, terminates orphaned
compatibility daemons and VM shims owned by this worktree, removes their
`cengine-compat-*` temporary roots, creates a cached Python virtual environment
under `.build`, and runs the Docker API and Docker Compose 5.3.1 compatibility
suites. Every test gets a new daemon, temporary root, Unix socket, engine state,
and VM set. Fixture images are fetched once into a versioned immutable seed
content store under `.build` and APFS-cloned into each root, avoiding external registry state without
sharing mutable engine metadata. Pytest stops all VM shims owned by that root before removing it,
including when a test fails; it does not reuse a daemon or repair resources
left by a preceding test. The command uses
the guest assets installed by the managed service or `cengine system install`;
override them with `CENGINE_KERNEL`, `CENGINE_CONTAINER_INITRAMFS`, and
`CENGINE_STORAGE_INITRAMFS`, or override the daemon and fixture image with
`CENGINE_BINARY` and `CENGINE_TEST_IMAGE`.
Set `CENGINE_TEST_IMAGE_SOURCE` when the fixture tag should be seeded from a
private or internal mirror; the default `alpine:latest` fixture is seeded from
`mirror.gcr.io/library/alpine:latest` to avoid Docker Hub's anonymous rate limit.
The suite requires Docker Compose
5.3.1 and kind (v0.32.0 is the reference version); install the checksum-pinned
Compose plugin with `Scripts/install-compose-compat.sh`. GitHub-hosted runners
cannot execute the VM-backed suite, so compatibility tests are currently a
local gate rather than part of `.github/workflows/test.yml`.

The harness removes ambient Docker endpoint overrides from every subprocess,
checks that each daemon reports the expected Git commit, and verifies Docker CLI
access to a sentinel resource on each isolated socket before running a scenario.
Set `CENGINE_EXPECTED_GIT_COMMIT` when testing a custom `CENGINE_BINARY`.

Use `make test-compat-reset` to perform the worktree-scoped cleanup without
running the suite. It deliberately does not touch `/Applications/cengine.app`,
the installed engine service, or processes from another checkout. If a network
helper crash left an idle reservation inside macOS `NetworkSharing`, use
`make test-compat-reset-system` once. That exceptional recovery command requests
administrator authorization and restarts cengine's helper and the system
NetworkSharing daemon; normal compatibility runs do not restart system services.

Use `make test-compat-soak` to run three fresh-daemon passes with shuffled test
ordering. To compare normalized behavior with a real Docker Engine, run
`make test-compat-oracle DOCKER_REFERENCE_HOST=unix:///path/to/docker.sock`;
the reference host is always explicit and is never inferred from the active
Docker context.

The CLI target is ad-hoc signed for local development with
`Configuration/cengine.entitlements`. The engine and its VM shims require
`com.apple.security.virtualization`. The root-owned network helper deliberately
does not claim `com.apple.vm.networking`; that restricted entitlement is for
using vmnet without root privilege and requires a provisioning profile.

The Xcode workspace owns Swift package resolution. Update and commit
`cengine.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`
when dependency versions change.

## Architecture

```text
docker / compose / buildx
          |
          | negotiated HTTP v1.44-v1.55 over ~/.cengine/run/docker.sock
          v
  SwiftNIO API router
          |
          v
 persisted EngineRuntime actor
          |
          v
 RawVirtualizationBackend actor
          |
          +------ authenticated Unix control ------+
          |                                         |
          v                                         v
 per-container VM shim                       infrastructure shim
          |                                  /               \
          v                                 v                 v
 Virtualization.framework VM       ext4 storage VM     VLAN/vmnet fabric
          |
          v
 cengine-init (workload is PID 1 in isolated Linux namespaces)
```

State is JSON with an explicit schema envelope and atomic rename/fsync
persistence under `~/Library/Application Support/cengine`. VM shims, rather
than the API daemon, own every `VZVirtualMachine`, so daemon replacement only
reconnects control sockets and does not stop workloads. Runtime sockets
remain under `~/.cengine/run`, and daemon logs are under
`~/Library/Logs/cengine`.

## Implementation scope

This repository is an experimental engine rather than a complete
implementation of every Docker API. Its focused runtime surface covers
interactive Docker CLI use, Compose application lifecycle, Buildx container
builds, networking, observability, and daemon recovery.

Implemented API groups include server ping/version/info and filtered live events;
authenticated, platform-aware image pull with live progress,
import/list/inspect/history/delete and pruning; container lifecycle, health,
stats, top, logs, attach, exec, archive copy, mounts, networking, ports, and
pruning; and Docker-shaped network and volume lifecycle APIs. Direct
`docker build` intentionally directs clients to Buildx. The managed Buildx
builder pins BuildKit, stores its state on a 512 GiB sparse block-backed ext4
volume, and uses the overlayfs snapshotter as part of cengine's tested Buildx
contract.

See [`docker-compatibility.md`](docker-compatibility.md) for the detailed
compatibility ledger and test provenance.

## Local installation and metadata-only development

The signed app registers its bundled `dev.cengine.engine` LaunchAgent with
`SMAppService`. The agent installs the bundled cengine guest assets, creates the
cengine Docker context, starts the daemon, and configures the Buildx builder. The
privileged `dev.cengine.network-helper` LaunchDaemon owns raw vmnet uplinks and
binds privileged published ports, returning descriptors to the engine over
authenticated XPC. The app guides the user through approving this required
networking service during onboarding.

To develop without downloading a kernel or starting VMs:

```sh
cengine daemon --metadata-only
DOCKER_HOST=unix://$HOME/.cengine/run/docker.sock docker info
```

## Releases

Public releases use one Developer ID signed, notarized, stapled `.pkg` for
direct download and the Homebrew Cask. See
[`release.md`](release.md) for the release process.
