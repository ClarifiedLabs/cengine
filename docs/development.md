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
`make package` creates `dist/cengine-0.0.1.pkg` and
`dist/cengine-0.0.1.dmg` for local release-artifact testing.

`make test-compat` builds the debug daemon, creates a cached Python virtual
environment under `.build`, and runs the Docker API and Docker Compose 5.3.1
compatibility suites against a temporary root and Unix socket. The command uses
the kernel installed by `cengine system install`; override it with
`CENGINE_KERNEL`, or override the daemon and fixture image with
`CENGINE_BINARY` and `CENGINE_TEST_IMAGE`. The suite requires Docker Compose
5.3.1; install the checksum-pinned plugin with
`Scripts/install-compose-compat.sh`. GitHub-hosted runners cannot execute the
VM-backed suite, so compatibility tests are currently a local gate rather than
part of `.github/workflows/test.yml`.

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

Implemented API groups include server ping/version/info and live events;
authenticated, platform-aware image pull with live progress,
import/list/inspect/history/delete and pruning; container lifecycle, health,
stats, top, logs, attach, exec, archive copy, mounts, networking, ports, and
pruning; and Docker-shaped network and volume lifecycle APIs. Direct
`docker build` intentionally directs clients to Buildx. The VM-backed Buildx
contract is tracked in the compatibility ledger and currently records a strict
known failure while copying into a non-scratch image.

See [`docker-compatibility.md`](docker-compatibility.md) for the detailed
compatibility ledger and test provenance.

## Local installation and metadata-only development

`cengine system install` downloads the pinned Kata kernel and verifies its
SHA-256 digest, installs the `dev.cengine.engine` LaunchAgent, creates the
`cengine` Docker context, and attempts to create the `cengine-builder` Buildx
builder. It does not change the active Docker context.

To develop without downloading a kernel or starting VMs:

```sh
cengine daemon --metadata-only
DOCKER_HOST=unix://$HOME/.cengine/run/docker.sock docker info
```

## Releases

Public releases include Developer ID signed, notarized, stapled `.pkg`
installers for direct download and `.dmg` images used by Homebrew without
administrator access. They are published through GitHub Releases and
`ClarifiedLabs/homebrew-tap`. See
[`release.md`](release.md) for the release process.

Note: this project was created as part of testing gpt-5.6-sol. Planning used
`xhigh` effort and implementation used `low` effort through commit
`f78d30dcb6eae948fbdd271f08e5c82d1656457a`.
