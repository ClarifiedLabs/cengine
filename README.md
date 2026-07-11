# cengine

`cengine` is an experimental, lightweight Docker Engine-compatible daemon for
Apple silicon. It runs Linux containers as lightweight virtual machines using
Apple's [Containerization](https://github.com/apple/containerization) package.

Note: this project was created as part of testing out gpt-5.6-sol for the first time. As of commit 224624b705e9a94428316c9c33a96b70d77f08b1 all planning used `xhigh` effort and implementation used `low`.

## Requirements

- Apple silicon
- macOS 26 or newer
- Docker CLI

## Install

Install `cengine` with Homebrew:

```sh
brew install clarifiedlabs/tap/cengine
```

If upgrading from the former cask package, first run
`brew uninstall --cask cengine`.

Start the per-user service. On its first start, cengine downloads and verifies
the Linux kernel, initializes its runtime, and configures the Docker context and
Buildx builder when the Docker CLI is available:

```sh
brew services start cengine
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
native snapshotter so non-scratch builds work with cengine-backed volumes.

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

To stop the service and remove the Homebrew package while preserving images,
container data, the kernel, and Docker integration:

```sh
brew services stop cengine
brew uninstall cengine
```

Run `cengine system uninstall` before `brew uninstall cengine` if the Docker
context and Buildx builder should also be removed.

The initial service start can take several minutes while the Kata kernel and
Apple `vminit` image are downloaded. Inspect progress in
`$(brew --prefix)/var/log/cengine.log`. Transient provisioning failures are
retried twice; after three failed attempts, correct the reported problem and
run `brew services restart cengine`.

For architecture, development, testing, and implementation details, see
[`docs/development.md`](docs/development.md). Docker API and Compose support is
tracked in [`docs/docker-compatibility.md`](docs/docker-compatibility.md).
