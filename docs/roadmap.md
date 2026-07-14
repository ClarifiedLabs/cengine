# Roadmap

This document tracks cengine's remaining project-level work. The detailed
Docker API and test backlog remains in
[Docker compatibility](docker-compatibility.md), while architectural contracts
and limitations remain in [Raw runtime architecture](raw-runtime.md). Items are
listed here only when they require a cross-cutting decision or sustained work.

## Current state

cengine runs each workload container in its own Virtualization.framework VM.
The daemon, per-container VM shims, infrastructure shim, ext4 container roots,
hybrid block/NFS volume storage, Docker networking, Compose lifecycle, managed
Buildx builder, and daemon recovery path are implemented. The raw virtualization
migration is complete; there is no remaining Apple Containerization migration
phase.

## Priorities

### 1. Add a VM-backed compatibility CI gate

The complete compatibility suite is currently a local gate because GitHub-hosted
runners cannot execute its Virtualization.framework scenarios. Add a maintained
self-hosted Apple-silicon runner for pull requests and release commits.

Completion criteria:

- `make test-compat` runs from a clean lifecycle on every gated commit.
- Failure artifacts include daemon, VM-shim, and pytest diagnostics.
- Release packaging requires a successful VM-backed run for the same commit.

### 2. Define the supported client-version envelope

Docker-py and Compose are pinned for the compatibility suite, and the managed
BuildKit image is pinned. The host Docker CLI and Buildx plugin are recorded but
not pinned. Define minimum and tested Docker CLI and Buildx versions, then run a
small version matrix or install a pinned reference Buildx plugin in the harness.

Completion criteria:

- Documentation names minimum and reference client versions.
- Compatibility runs fail clearly outside the supported envelope.
- At least the minimum and reference Buildx versions exercise `BLD-001` and
  `BLD-002`.

### 3. Prioritize API-version gaps by client demand

The API v1.46-v1.55 assessment table in
[Docker compatibility](docker-compatibility.md#api-version-envelope) is the
endpoint-level backlog. Implement gaps when required by supported Docker,
Compose, Buildx, or kind behavior rather than pursuing unused fields solely for
nominal API completeness. Decide whether registry search (`IMG-004`) belongs in
the supported surface.

Completion criteria for each accepted gap:

- The compatibility ledger records the intended behavior.
- A unique compatibility contract covers the behavior when black-box testing is
  practical.
- The implementation matches a reference Docker Engine or documented Docker API
  semantics.

### 4. Expand stress and protocol coverage

Current black-box gaps include higher-volume concurrent container lifecycle
stress, broader differential-oracle sampling, and an explicit decision on SCTP
networking support.

Completion criteria:

- Repeated concurrent lifecycle tests leave no VM, shim, vmnet, or temporary
  state behind.
- The differential oracle covers the deterministic contracts most likely to
  diverge from Docker Engine.
- SCTP is either implemented and tested or recorded as an intentional gap.

## Accepted constraints and non-goals

These are deliberate boundaries, not open implementation tasks:

- Preserve the one-workload-container-per-VM model. Do not delegate execution to
  Docker Engine inside a generic Linux VM.
- Use the managed Buildx builder for image builds. Docker Engine's legacy
  `/build` API is intentionally unsupported.
- Select named-volume storage mode before first use. An already-used block-backed
  volume is not promoted live to shared NFS storage when a later container adds a
  second reference; callers must declare the sharing topology up front.
- Do not add migration or backward-compatibility machinery while cengine remains
  an unused experiment unless a concrete compatibility requirement is adopted.

## Keeping this roadmap current

Update this file when priorities or architectural boundaries change. Update
[Docker compatibility](docker-compatibility.md) in the same change whenever an
API status or compatibility-test disposition changes. Do not duplicate the
endpoint inventory here.
