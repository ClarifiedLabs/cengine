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

## Recently completed

### Runtime compatibility foundation

Runtime compatibility now has a normative source hierarchy beneath the Docker
API: OCI Runtime Spec v1.3.0 for applicable execution semantics, Linux
documentation for implementation mechanisms, and Docker/Moby behavior where the
specifications are silent. Focused `RTM-*` contracts cover init/exec namespace,
root, identity, security-context and descriptor parity; read-only-root behavior;
and pinned Docker-in-Docker exec and healthchecks without kind.

Default exec and healthcheck context now resolves image and container cwd, user,
groups, and environment consistently. The guest protocol carries structured
identity and `no_new_privs` policy for exec. Compatibility tests normally use the
installed, pre-approved networking helper without interactive authorization.

### Multi-platform and OCI image behavior

The image store now preserves OCI graph roots and all locally available
platform manifests instead of flattening an index to one variant. Docker API
v1.47-v1.55 behavior includes versioned manifest/descriptor responses, platform
selection for inspect, history, load, save, push, and delete, selected container
manifest descriptors, trusted pull/push origin identity, and attached in-toto
attestations. Identity intentionally omits build and signature claims because
cengine does not have verified evidence for either.

The VM-backed compatibility suite covers successful and missing platform
selection, multi-platform archive round trips, selective deletion, identity,
attestations, and optional differential response-shape comparison.

### Client-visible metadata and image events

Container annotations now persist from create through inspect and daemon
recovery, with list responses exposing them from API v1.46. Successful pulls
and archive loads emit Docker-shaped image events with historical type, action,
and image filtering. System information counts the actual image store and
versions discovered-device output; containerd, Moby's Linux firewall backend,
and NRI remain omitted because cengine does not implement those subsystems.

## Compatibility priorities

### 1. Establish and expand OCI/Linux runtime-semantic conformance

Treat the OCI applicability table in
[Docker compatibility](docker-compatibility.md#runtime-semantics-and-oci-applicability)
as the first runtime backlog. Preserve the one-container-per-VM architecture and
adopt only semantics that support cengine's Docker compatibility surface; do not
claim an OCI runtime CLI merely because its execution rules are used as a
reference.

Work in this order:

1. Find supported Docker inputs that are accepted but ignored or insufficiently
   tested. Apply them, reject them explicitly, or classify them in the ledger.
2. Close mount propagation, namespace, cgroup-v2, capability, device, rlimit,
   seccomp/security-option, and masked-path gaps for functionality cengine
   already exposes.
3. Add curated Moby/runc test ports and an OCI-runtime test adapter after focused
   cengine contracts have stabilized the expected behavior.
4. Implement otherwise unexposed OCI features only when cengine adopts them as
   explicit compatibility requirements.

Completion criteria:

- Each runtime change names its Docker, OCI, Linux, or observed-Moby source.
- A focused `RTM-*` contract fails strictly for every adopted black-box semantic.
- The applicability table classifies new discoveries as covered, partial,
  intentional gap, undecided, or architecturally not applicable.
- Nested-runtime regressions are reproducible without kind before kind is used as
  the integration gate.

Generated API differentials, broad upstream test imports, and self-hosted VM CI
remain later validation work rather than prerequisites for this priority.

### 2. Complete modern network endpoint and IPAM semantics

Close the remaining network behavior gaps that affect how clients create and
inspect endpoints. The following sub-items are complete:

- Endpoint MAC address application: an explicit `MacAddress` is decoded,
  validated, applied in the guest, inspected, and preserved across recovery
  (`NET-014`, `NET-015`).
- Endpoint gateway priority: `GwPriority` is decoded on create and connect,
  used to select the single default-gateway endpoint for multi-network
  containers, inspected, and preserved across recovery (`NET-016`).
- SCTP has an explicit support decision: publishing an `sctp` port is rejected
  with 400 and recorded as an intentional gap because the vmnet port forwarder
  bridges only TCP and UDP (`NET-017`).

The remaining gaps are endpoint sysctls, explicit IPv4 controls (`EnableIPv4`
and endpoint IPv4 enable/disable), and IPAM status.

Completion criteria:

- Accepted endpoint settings are applied in the guest and survive inspect and
  daemon recovery. *(Done for MAC address and gateway priority.)*
- Invalid or unsupported settings fail explicitly instead of being ignored.
  *(Done for MAC address and SCTP publishing.)*
- Multi-network containers select routes according to gateway priority. *(Done:
  `NET-016`.)*
- SCTP is either implemented and tested end to end or recorded as an intentional
  compatibility gap. *(Done: recorded as an intentional gap, `NET-017`.)*
- Endpoint sysctls, explicit IPv4 controls, and IPAM status are still
  outstanding.

### 3. Close remaining client-visible API gaps

Use the API v1.46-v1.55 assessment table in
[Docker compatibility](docker-compatibility.md#api-version-envelope) as the
endpoint-level backlog. After image and networking behavior, address the
remaining registry search (`IMG-004`) and per-device blkio update fields.
Container annotations, pull/load image events, accurate image counts, and
versioned native-engine information are complete. Direct-build image `create`
events remain part of the intentional direct-builder gap. Implement accepted
gaps in observed Docker, Compose, Buildx, kind, and Testcontainers demand order.

Completion criteria for each accepted gap:

- The compatibility ledger records the intended behavior.
- A unique compatibility contract covers the behavior when black-box testing is
  practical.
- The implementation matches a reference Docker Engine or documented Docker API
  semantics.
- A deliberately unsupported behavior returns a clear error and is recorded as
  an intentional gap rather than being silently accepted.

### 4. Harden compatibility under sustained use

Current black-box gaps include higher-volume concurrent container lifecycle
stress and broader differential-oracle sampling. Use these tests to find and fix
observable lifecycle, recovery, cleanup, and response-shape incompatibilities
after the functional API gaps above.

Completion criteria:

- Repeated concurrent lifecycle tests leave no VM, shim, vmnet, or temporary
  state behind.
- The differential oracle covers deterministic image, network, inspect, event,
  and error-response contracts that are likely to diverge from Docker Engine.
- Any discovered divergence is fixed or recorded in the compatibility ledger.

## Deferred validation and automation

These improve repeatability and release confidence but do not expand Docker
compatibility. Continue to use the local compatibility suite while functional
compatibility work is prioritized.

### Add a VM-backed compatibility CI gate

The complete compatibility suite is currently a local gate because GitHub-hosted
runners cannot execute its Virtualization.framework scenarios. When CI
automation becomes a priority, add a maintained self-hosted Apple-silicon runner
for pull requests and release commits.

Completion criteria:

- `make test-compat` runs from a clean lifecycle on every gated commit.
- Failure artifacts include daemon, VM-shim, and pytest diagnostics.
- Release packaging requires a successful VM-backed run for the same commit.

### Define the supported client-version envelope

Docker-py and Compose are pinned for the compatibility suite, and the managed
BuildKit image is pinned. The host Docker CLI and Buildx plugin are recorded but
not pinned. Later, define minimum and tested Docker CLI and Buildx versions, then
run a small version matrix or install a pinned reference Buildx plugin in the
harness.

Completion criteria:

- Documentation names minimum and reference client versions.
- Compatibility runs fail clearly outside the supported envelope.
- At least the minimum and reference Buildx versions exercise `BLD-001` and
  `BLD-002`.

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
