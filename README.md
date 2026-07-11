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
brew install --cask clarifiedlabs/tap/cengine
```

Then install the per-user service, Linux kernel, Docker context, and Buildx
builder:

```sh
cengine system install
```

Check that the engine is ready:

```sh
cengine system status
cengine system doctor
docker --context cengine info
```

## Usage

Run Docker commands against `cengine` by selecting its context:

```sh
docker --context cengine run --rm hello-world
docker --context cengine ps
docker --context cengine images
docker --context cengine compose up
docker buildx build --builder cengine-builder .
```

Buildx is the intended build path, but non-scratch builds currently have a
strict known compatibility failure; see `BLD-001` in the compatibility ledger.

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

To remove the service and Docker context while preserving images and container
data:

```sh
cengine system uninstall
```

For architecture, development, testing, and implementation details, see
[`docs/development.md`](docs/development.md). Docker API and Compose support is
tracked in [`docs/docker-compatibility.md`](docs/docker-compatibility.md).
