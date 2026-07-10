# cengine

`cengine` is an experimental, lightweight Docker Engine-compatible daemon for Apple silicon. It accepts Docker Engine API v1.44 requests on a user-owned Unix socket and runs Linux containers as lightweight virtual machines through Apple's [Containerization](https://github.com/apple/containerization) package.

This repository is an early functional MVP, not yet a replacement for Docker Desktop. The daemon can pull and manage images, create/start/stop/remove containers, and persist container, volume, and network metadata. The API surface required for interactive attach, logs, exec, archive copy, health checks, port forwarding, and a Buildx container is still being implemented.

## Requirements

- Apple silicon
- macOS 26 or newer
- Swift 6.2 or newer
- Docker CLI (optional, but required to use the Docker context and Buildx)

## Build and test

```sh
make test
make release
```

The release target ad-hoc signs the executable with Apple's required
`com.apple.security.virtualization` entitlement. Running `swift build -c release`
directly produces a binary that cannot create the VM network.

The project deliberately limits direct SwiftPM dependencies to Apple Containerization, SwiftNIO, and Swift System. `make test` enforces that allowlist. Transitive packages required by Containerization are not duplicated as direct dependencies.

Some developer machines have an old Homebrew or source-installed `/usr/local/include/zlib.h` that shadows the macOS SDK header. `Scripts/swift.sh` applies a narrow VFS overlay in that case; it does not alter system files.

## Install for the current user

Place the release binary at a stable path, then run:

```sh
.build/release/cengine system install
docker --context cengine info
```

Installation downloads a pinned Kata kernel and verifies its SHA-256 digest, installs a `dev.cengine.engine` LaunchAgent, and creates the `cengine` Docker context. It never changes the active Docker context. If the daemon exposes all endpoints Buildx needs, installation also attempts to create the `cengine-builder` builder; failure is non-fatal during this MVP phase.

To remove the service and context while preserving images and container data:

```sh
cengine system uninstall
```

For development without downloading a kernel or starting VMs:

```sh
cengine daemon --metadata-only
DOCKER_HOST=unix://$HOME/.cengine/run/docker.sock docker info
```

## Architecture

```text
docker / compose / buildx
          |
          | HTTP v1.44 over ~/.cengine/run/docker.sock
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

State is JSON with an explicit schema envelope and atomic rename/fsync persistence under `~/Library/Application Support/cengine`. Runtime sockets remain under `~/.cengine/run`, and daemon logs are under `~/Library/Logs/cengine`.

## Current compatibility

Implemented API groups include server ping/version/info; image pull/list/inspect/delete with Docker short-name normalization and automatic pull-on-run; container create/start/stop/kill/wait/remove/list/inspect; automatic exit reconciliation and auto-remove; interactive and non-interactive attach with stdin, TTY resize, and Docker stream framing; exec create/start/inspect with attached, detached, TTY, stdin, resize, and exit-code handling; durable non-following container logs; safe archive upload before and after container start; bind, volume, and tmpfs mounts; Docker-shaped network and volume create/list/inspect/remove lifecycle; and a working managed Buildx container driver for local and pushed outputs. Direct `docker build` intentionally returns a message directing clients to Buildx.

Known gaps:

- Restart policies and recovery after daemon or process failure
- Following logs and post-start/multi-client attach
- `GET /containers/{id}/archive` for container-to-host copy
- Host port publishing, shared user-defined networks, network aliases, and Compose service DNS
- Network connect/disconnect, prune, and anonymous-volume lifecycle
- Health checks, events, stats, top, restart, pause/unpause, update, and resource pruning
- Complete image metadata/store synchronization, registry authentication, history, and real pull progress
- Docker image import/load for Buildx's default `--load` behavior and Compose compatibility validation
- Full `linux/amd64` image selection; the VM enables Rosetta, but the current Apple `ContainerManager` convenience pull path selects the host platform
- Recovery or cleanup of live VM handles after daemon restart (persisted running containers are conservatively marked exited)

These gaps are reported as unsupported or absent rather than silently emulated.
