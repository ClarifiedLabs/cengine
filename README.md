# cengine

`cengine` is an experimental, lightweight Docker Engine-compatible daemon for
Apple silicon. It runs Linux containers as lightweight virtual machines using
Apple's [Containerization](https://github.com/apple/containerization) package.

Note: this project was created as an experiment when testing out gpt-5.6-sol for the first time. As of commit 224624b705e9a94428316c9c33a96b70d77f08b1 all planning used `xhigh` effort and implementation used `low`.

## Requirements

- Apple silicon
- macOS 26 or newer
- Docker CLI

## Install

Install the signed cengine app and CLI with Homebrew:

```sh
brew install --cask clarifiedlabs/tap/cengine
```

Open `/Applications/cengine.app`. On first launch, cengine enables its per-user
engine service, downloads and verifies the Linux kernel, initializes its runtime,
and configures the Docker context and Buildx builder when Docker CLI is available.
The optional Privileged Ports helper is disabled by default and can be enabled
during onboarding or later in Settings.

```sh
open /Applications/cengine.app
```

Check that the engine is ready:

```sh
cengine system status
cengine system doctor
docker --context cengine info
```

Each Docker network is backed by a separate dual-stack macOS vmnet network.
Cengine allocates IPv4 `/24`s from documented RFC 1918 pools and assigns every
network an RFC 4193 ULA `/64`. Override the IPv4 pools with
`~/Library/Application Support/cengine/config.json`:

```json
{
  "network": {
    "ipv4Pools": ["192.168.224.0/20", "172.29.0.0/16", "10.240.0.0/16"]
  }
}
```

Pool entries must be unique RFC 1918 ranges containing complete `/24`s. Cengine
asks vmnet to reserve each candidate directly; it does not pre-screen the host
routing table. Networks are always dual-stack because vmnet supplies IPv6 even
when Docker clients send `EnableIPv6: false`. Cengine persists vmnet's opaque
network serialization so an abruptly restarted daemon can reclaim the same
reservation before falling back to subnet remapping.

## Usage

Run Docker commands against `cengine` by selecting its context:

```sh
docker --context cengine run --rm hello-world
docker --context cengine ps
docker --context cengine images
docker --context cengine compose up
docker --context cengine buildx build --builder cengine-builder --load .
```

Buildx is the intended build path. The managed `cengine-builder` uses BuildKit's
native snapshotter so non-scratch builds work with cengine-backed volumes. Its
builder VM defaults to 4 CPUs, 4 GiB of memory, and a 16 GiB root filesystem.
View or change the CPU and memory settings from the app's Settings window or
with the CLI:

```sh
cengine builder resources
cengine builder resources --cpus 6 --memory 8g
```

Applying new resources recreates the managed builder while preserving its
BuildKit cache.

Ordinary containers default to 4 CPUs and 1 GiB of memory. Change those defaults
for newly created containers from **Container Defaults** in the app's Settings
window or with the CLI:

```sh
cengine container resources
cengine container resources --cpus 2 --memory 2g
```

Explicit Docker or Compose CPU and memory limits take precedence over these
defaults. Existing containers are not changed.

To make `cengine` the default engine for subsequent Docker commands, activate
its Docker context:

```sh
docker context use cengine
docker info
```

Switch back to Docker's standard context with:

```sh
docker context use default
```

Use **Uninstall cengine…** in the app to remove services, Docker integration,
the app, and CLI while preserving images and container data by default. Homebrew
users can instead run:

```sh
brew uninstall --cask cengine
```

which also unregisters the background services and removes the `cengine` Docker
context and `cengine-builder` Buildx builder. Add `--zap` to delete images,
containers, and logs as well. Dragging only the app to Trash is not a complete
uninstall because macOS does not invoke package or `SMAppService` cleanup hooks
for ordinary app bundles.

The initial service start can take several minutes while the Kata kernel and
Apple `vminit` image are downloaded. The app reports service state and daemon
errors; transient provisioning failures are retried twice. The daemon logs to
`~/Library/Logs/cengine/daemon.log`.

For architecture, development, testing, and implementation details, see
[`docs/development.md`](docs/development.md). Docker API and Compose support is
tracked in [`docs/docker-compatibility.md`](docs/docker-compatibility.md).
