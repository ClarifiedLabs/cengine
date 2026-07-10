# cengine

`cengine` is an experimental, lightweight Docker Engine-compatible daemon for Apple silicon. It accepts Docker Engine API v1.44 requests on a user-owned Unix socket and runs Linux containers as lightweight virtual machines through Apple's [Containerization](https://github.com/apple/containerization) package.

This repository is an early functional MVP, not yet a replacement for Docker Desktop. It supports interactive containers, exec, logs, archive copy, image import, and a managed Buildx container, but substantial networking, observability, recovery, and Compose work remains.

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

Implemented API groups include server ping/version/info and live events; authenticated, platform-aware image pull with live progress, import/list/inspect/history/delete and pruning with Docker short-name normalization and automatic pull-on-run; container create/start/stop/kill/wait/remove/list/inspect, restart, pause, resource update, health checks, stats, top, and pruning; automatic exit reconciliation and auto-remove; reusable multi-client attach with stdin, TTY resize, and Docker stream framing; exec create/start/inspect with attached, detached, TTY, stdin, resize, and exit-code handling; durable and following container logs; safe bidirectional archive copy before and after container start; bind, named/anonymous volume, and tmpfs mounts; shared vmnet networking with live alias updates, TCP and UDP port publishing, and Docker-shaped network and volume lifecycle APIs; and a working managed Buildx container driver with local, pushed, and Docker `--load` outputs. Direct `docker build` intentionally returns a message directing clients to Buildx.
