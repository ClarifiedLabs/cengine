# Development

`cengine` is an Xcode project targeting arm64 macOS 26. The supported build
entrypoints are:

```bash
make build
make test
make test-compat
make dist-cli
make package
```

`make test` runs `CEngineCoreTests` and `CEngineAPITests` through the shared
`cengine` scheme. `make dist-cli` runs the tests and stages `dist/cengine`.
`make package` creates `dist/cengine-0.0.1.pkg` for local release-artifact testing.

`make test-compat` builds the debug daemon, creates a cached Python virtual
environment under `.build`, and runs the Docker API and Docker Compose 5.3.1
compatibility suites against a temporary root and Unix socket. The command uses
the kernel installed by the managed service or `cengine system install`; override it with
`CENGINE_KERNEL`, or override the daemon and fixture image with
`CENGINE_BINARY` and `CENGINE_TEST_IMAGE`. The suite requires Docker Compose
5.3.1 and kind (v0.32.0 is the reference version); install the checksum-pinned
Compose plugin with `Scripts/install-compose-compat.sh`. GitHub-hosted runners
cannot execute the VM-backed suite, so compatibility tests are currently a
local gate rather than part of `.github/workflows/test.yml`.

Use `make test-compat-soak` to run three fresh-daemon passes with shuffled test
ordering. To compare normalized behavior with a real Docker Engine, run
`make test-compat-oracle DOCKER_REFERENCE_HOST=unix:///path/to/docker.sock`;
the reference host is always explicit and is never inferred from the active
Docker context.

The CLI target is ad-hoc signed for local development with
`Configuration/cengine.entitlements`. That file intentionally contains only
`com.apple.security.virtualization`; the build rejects either vmnet entitlement.

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
 AppleContainerBackend actor
          |
          v
 Apple Containerization + Virtualization.framework
   (one lightweight VM per running container)
```

State is JSON with an explicit schema envelope and atomic rename/fsync
persistence under `~/Library/Application Support/cengine`. Runtime sockets
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
builder pins BuildKit and uses its native snapshotter because overlayfs upper
layers are incompatible with the VirtioFS-backed builder volume.

See [`docker-compatibility.md`](docker-compatibility.md) for the detailed
compatibility ledger and test provenance.

## Local installation and metadata-only development

The signed app registers its bundled `dev.cengine.engine` LaunchAgent with
`SMAppService`. The agent downloads the pinned Kata kernel, creates the cengine
Docker context, starts the daemon, and configures the Buildx builder. The
optional `dev.cengine.network-helper` LaunchDaemon binds exact specific-IP
ports below 1024 and returns descriptors to the engine over authenticated XPC.

To develop without downloading a kernel or starting VMs:

```sh
cengine daemon --metadata-only
DOCKER_HOST=unix://$HOME/.cengine/run/docker.sock docker info
```

## Releases

Public releases use one Developer ID signed, notarized, stapled `.pkg` for
direct download and the Homebrew Cask. See
[`release.md`](release.md) for the release process.

Note: this project was created as part of testing gpt-5.6-sol. Planning used
`xhigh` effort and implementation used `low` effort through commit
`f78d30dcb6eae948fbdd271f08e5c82d1656457a`.
