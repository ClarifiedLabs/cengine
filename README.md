# cengine

`cengine` is an experimental, lightweight Docker Engine-compatible daemon for
Apple silicon. It runs Linux containers as lightweight virtual machines using
Virtualization.framework directly, with one independently supervised VM per
container.

## Requirements

- Apple silicon
- macOS 26 or newer
- Docker CLI with the Buildx plugin
- Docker Compose plugin when using Compose

## Install

Install the signed cengine app and CLI with Homebrew:

```sh
brew install --cask clarifiedlabs/tap/cengine
```

After a fresh install, open cengine to begin setup:

```sh
open /Applications/cengine.app
```

The installer does not show the app, request networking approval, or start the
engine until you open it. Upgrades and standard reinstalls resume an engine that
was previously enabled. On first user launch, cengine registers its required VM
networking service for administrator approval. Once approved, it enables the
per-user engine service, installs the bundled cengine kernel and guest initramfs
assets, initializes its runtime, and configures the Docker context and Buildx
builder when Docker CLI is available.

Check that the engine is ready:

```sh
cengine system status
cengine system doctor
docker --context cengine info
```

Every container VM has one 802.1Q trunk. Docker networks are persistent VLAN and
IP assignments switched by the infrastructure shim. Normal bridge VLANs receive
a raw vmnet shared-mode uplink for host access, DNS, NAT, and published ports;
internal networks use host-only mode, and isolated networks have no uplink.

Network access follows Docker's bridge modes:

| Configuration | Network peers | macOS host services | Internet |
|---|---:|---:|---:|
| Default bridge | Yes | Yes | Yes |
| `docker network create --internal` | Yes | Yes | No |
| Internal bridge with gateway mode `isolated` | Yes | No | No |
| `docker run --network none` | No (loopback only) | No | No |

Use `--internal` with
`com.docker.network.bridge.gateway_mode_ipv4=isolated` and/or
`com.docker.network.bridge.gateway_mode_ipv6=isolated` when containers must not
reach macOS host services. VLAN membership is enforced outside the workload VM,
so a privileged container
cannot bypass isolation by adding its own route or opening the trunk parent.

## Usage

Run Docker commands against `cengine` by selecting its context:

```sh
docker --context cengine run --rm hello-world
docker --context cengine ps
docker --context cengine images
docker --context cengine compose up
docker --context cengine buildx build --builder cengine-builder --load .
```

Builds are supported through cengine's managed Buildx builder. Use
`docker buildx build`; cengine does not implement Docker Engine's legacy
`/build` API. The managed `cengine-builder` uses BuildKit's overlayfs
snapshotter on a directly attached ext4 volume. On first use, its resources are
selected from the host: half the CPUs (minimum 4 where available, maximum 8)
and 4 GiB, 6 GiB, or 8 GiB of memory on hosts with less than 16 GiB, 16–23 GiB,
or at least 24 GiB, respectively. Saved settings remain explicit overrides.
The builder also has a 64 GiB root filesystem and a separate 512 GiB sparse
BuildKit state volume. View or change the CPU and memory settings from the app's
Settings page or with the CLI:

```sh
cengine builder resources
cengine builder resources --cpus 6 --memory 8g
```

Applying new resources recreates the managed builder while preserving its
BuildKit cache. Upgrading a builder that used the older native snapshotter
recreates its cache once so it can use overlayfs.

Ordinary containers default to 4 CPUs and 1 GiB of memory. Change those defaults
for newly created containers from **Container Defaults** on the app's Settings
page or with the CLI:

```sh
cengine container resources
cengine container resources --cpus 2 --memory 2g
```

Explicit Docker or Compose CPU and memory limits take precedence over these
defaults. Existing containers are not changed. A memory value is the workload's
hard cgroup limit, matching Docker semantics; cengine adds a small, separate VM
allowance for its guest kernel and supervisor.

For tools that create containers without exposing resource flags, run the tool
through a temporary cengine resource scope:

```sh
cengine run --cpus 2 --memory 2g -- kind create cluster
```

The selected values override CPU or memory settings supplied by the wrapped
tool and apply to each container it creates. Flags omitted from `cengine run`
continue to use the tool's value or the ordinary container default. The scope
exists only while the command runs, so concurrent Docker clients continue to
use the normal defaults; containers created by the command remain afterward.
The wrapped tool must honor `DOCKER_HOST` and must not select another Docker
host or context explicitly.

## Volumes

cengine chooses a volume's storage mode from the container topology known
before its first use:

- A volume with one known consumer uses a directly attached ext4 block device.
  This supports filesystem behavior required by workloads such as BuildKit and
  kind.
- A volume with multiple known consumers is exported over NFS by cengine's
  storage VM so the containers can mount it concurrently.

The selected mode is persistent. Once a block-backed volume has been used,
cengine cannot later attach it to a second container as a shared volume. Declare
the complete sharing topology before first use; Compose does this automatically
because cengine receives the project topology before starting its containers.
See [Raw runtime architecture](docs/raw-runtime.md) for the detailed storage
design.

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
provides the same non-destructive uninstall:

```sh
brew uninstall --cask cengine
```

It unregisters the background services and removes the `cengine` Docker context
and `cengine-builder` Buildx builder, but preserves all VM disks and engine data
for a later reinstall. If `cengine` was the active Docker context, a standard
reinstall restores it on the next managed engine start. To uninstall **and**
remove containers, images, volumes, downloaded guest assets, runtime files,
logs, app preferences, and the saved context selection, use the explicit
destructive form:

```sh
brew uninstall --cask --zap cengine
```

Homebrew moves the user data to Trash; empty Trash to reclaim its disk space.
For a direct PKG install, the app's uninstall confirmation provides the same
full cleanup with **Delete all cengine data**; the in-app option deletes the data
permanently rather than moving it to Trash. Dragging only the app to Trash is
not a complete uninstall because macOS does not invoke package or `SMAppService`
cleanup hooks for ordinary app bundles.

The app reports service state and daemon errors; transient provisioning failures
are retried twice. The daemon logs to
`~/Library/Logs/cengine/daemon.log`.

See [Development](docs/development.md) for build and test commands. Architecture
and implementation details are documented in
[Raw runtime architecture](docs/raw-runtime.md). Docker API and Compose support
is tracked in [Docker compatibility](docs/docker-compatibility.md), and current
priorities are tracked in the [Roadmap](docs/roadmap.md).
