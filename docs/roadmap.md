# Roadmap

This page contains project-level priorities, not a development log or an endpoint
inventory. [Docker compatibility](docker-compatibility.md) owns supported behavior
and explicit gaps; [Raw runtime architecture](raw-runtime.md) owns runtime design.

## Current state and delivery

cengine runs one workload container per Virtualization.framework VM, with durable
host shims, private ext4 roots, direct-block single-consumer volumes and FUSE shared
volumes backed by ext4 in the storage VM. Containers survive API-daemon restarts.
Storage recovery supports controlled first-start retry and system reboot.

Release preparation requires canonical asset publication, signing and distribution
acceptance. Local assets are usable for development but do not satisfy these
[release requirements](release.md).
[Managed storage](storage-adoption.md) documents owner enrollment and recovery limits.

## Compatibility priorities

1. **Maintain focused Docker/OCI/Linux contracts.** Classify runtime behavior against
   the [OCI applicability table](docker-compatibility.md#runtime-semantics-and-oci-applicability).
   Apply supported inputs and reject active gaps before mutation. Add a focused
   `RTM-*` regression before relying on kind or another nested-runtime integration.
2. **Close deliberately adopted client gaps.** Use the
   [API assessment](docker-compatibility.md#api-version-envelope), observed Docker,
   Compose, Buildx, kind and Testcontainers demand to prioritize work. Unsupported
   behavior must remain explicit rather than silently accepted.
3. **Keep sustained-use validation bounded.** Expand concurrency and differential
   coverage where a concrete missing contract warrants it. Require owned cleanup,
   fixed resource budgets and strict comparisons; a finite pass is not universal
   filesystem or crash certification.

Every runtime change names its Docker, OCI, Linux or observed-Moby contract, updates
the compatibility inventory and adds focused regression coverage. Intentional
architecture gaps are not a queue of promised implementations.

## Deferred validation and automation

- **VM-backed CI:** native compatibility remains a local gate. A maintained
  self-hosted Apple-silicon runner would allow same-commit VM-backed release checks;
  GitHub-hosted runners cannot execute these Virtualization.framework scenarios.
- **Client-version matrix:** Docker-py, Compose and managed BuildKit are pinned;
  the host Docker CLI and Buildx are recorded rather than pinned. Define minimum
  and reference versions before promising a supported client envelope.
- **Curated upstream tests:** bounded Moby/runc ports can extend focused contracts.
  A test-only OCI adapter is a possible validation tool, not a public runtime CLI
  or a prerequisite for current Docker support.

## Accepted constraints and non-goals

- Preserve one workload container per VM; do not delegate to Docker Engine inside
  a shared Linux VM. Cross-container Linux namespace sharing cannot span kernels.
- Use the managed Buildx builder. Docker Engine's legacy `/build` API is unsupported.
- Select volume placement before first use. Used block-backed volumes are not
  promoted live when a later container adds a second reference; declare the sharing
  topology up front.
- Shared-volume locks are client-local; distributed locking and cross-VM concurrent
  mmap coherence are not promised.
- Unsupported store formats are rejected without modifying their data. cengine
  does not migrate or automatically reset them.
- Physical power-loss certification is separate from software drain, VM/process
  death and host reboot coverage.

Update this page when priorities or boundaries change, not after each local run.
