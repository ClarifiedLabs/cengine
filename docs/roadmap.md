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

Docker PID limits now persist across recovery and drive cgroup-v2 `pids.max` on
create and live update. Bind mounts apply private isolation; shared/slave modes
are rejected because virtiofs cannot form the required host/container peer or
master mount. Unprivileged containers use Docker's default Linux capability set with
`CapAdd`/`CapDrop` parity between init and exec. Filtered container pruning now
fails closed on unknown inputs instead of widening deletion scope. Focused
`RTM-004`–`RTM-008` contracts cover enforcement and recovery, explicit
propagation gaps, capability masks, prune selection, and exec stage signal and
status behavior. Security options, configurable devices, container
sysctls, masked paths, non-recursive bind variants, health start intervals, and
custom exec detach keys are decoded and rejected explicitly instead of being
silently ignored.

Docker create-time ulimits now persist and apply to container init, exec, and
healthcheck processes through capability introduced in guest protocol v7 and
carried by the current guest protocol v10. The final exec command receives
limits after namespace and root setup without constraining the guest supervisor
or its signal/status proxies. `RTM-014` covers inspect, validation without
side effects, daemon recovery, and container stop/start. Live ulimit updates
remain an explicit gap.

Supported namespace selections now persist, inspect, and survive daemon
recovery. Docker IPC `none` uses a private IPC namespace without mounting
`/dev/shm`; the default/private cgroup and IPC selections plus the host userns
selection reflect guest behavior through guest protocol v10 (`RTM-016`).
Docker-host and cross-container cgroup, IPC, PID, UTS, and network sharing are
explicit architecture gaps: separate per-container VM kernels cannot join one
Linux namespace. OCI namespace paths are likewise not exposed through the
Docker API or an OCI runtime CLI. These requests fail before container or volume
mutation (`RTM-017`).

The four Docker per-device block-I/O throttle arrays now persist and apply to
the VM root disk `/dev/vda` through cgroup-v2 `io.max`. API v1.55 live updates
independently replace or clear each BPS/IOPS limit while older update APIs keep
their historical ignore behavior. `RTM-015` covers inspect, kernel control-state
readback, direct-I/O enforcement, rollback after a compatibility-injected guest
failure following successful scalar and IO writes, daemon recovery, and an
actual stop/start cycle. Updates durably journal the complete old and desired
resource selections before backend mutation, serialize journal and metadata
writes, and atomically publish the desired record only when the journal is
removed. Recovery reapplies the durable old selection before accepting a live
or stopped execution. Stopped recovery reconstructs a missing in-memory shim
from the persisted spec and writable root, while failed replacements restore
the original shim without deleting that root. Partially launched candidates
are durably owned by immutable per-generation specs and PID/start identities.
A pre-spawn intent, child-first identity publication, and argv-based recovery
close the crash boundary immediately after process creation; every generation
is independently enumerated until process, socket, spec, and capacity cleanup
has succeeded. Preparation failures retain the writable root when termination
cannot be proven, and recovered stopped preparations seed the exact old CPU,
memory, PID, block-I/O, and VM-capacity selection before replacement. An
unresolved journal reserves the container's stable
ID/name/creation identity, fences lifecycle, restart-policy, and auto-remove
work, and is removed atomically with a definitive container deletion.
Compatibility fault markers are claimed by rename before validation so a
replacement path cannot be consumed accidentally. Blkio weights and additional
devices remain explicit gaps.

The API v1.55 runtime-input baseline audit is complete (`RTM-013`). Container
create and update resources, namespace and process configuration, structured and
legacy mounts, healthchecks, and exec terminal sizing now distinguish inert
defaults from active requests. Recognized active gaps fail before container,
volume, or exec state is mutated; malformed and contradictory values return a
client error. Unknown extension keys remain forward-compatible rather than
triggering whole-object rejection.

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
recovery, enter the versioned guest runtime specification, and appear in list
responses from API v1.46. Successful pulls
and archive loads emit Docker-shaped image events with historical type, action,
and image filtering; container events apply the same filter to their creating
image reference. Default prune requests preserve tagged images and named
volumes, while Docker's explicit widening selectors remove all unused records.
System information counts the actual image store and
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

1. Maintain the completed API v1.55 runtime-input baseline audit as Docker's
   request schema evolves. Apply newly supported fields, reject active gaps
   explicitly, or classify them in the ledger (`RTM-013`).
2. Close cgroup-v2 IO/device, device,
   seccomp/security-option, masked-path, and remaining mount-matrix gaps for
   functionality cengine already exposes. Namespace inputs, PID limits, private
   bind isolation, and capability add/drop have explicit supported or
   architectural-gap decisions; shared/slave bind propagation is also an
   explicit architecture gap.
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

The modern network endpoint and IPAM behavior that affects how clients create,
configure, and inspect endpoints is complete:

- Endpoint MAC address application: an explicit `MacAddress` is decoded,
  validated, applied in the guest, inspected, and preserved across recovery
  (`NET-014`, `NET-015`).
- Endpoint gateway priority: `GwPriority` is decoded on create and connect,
  used to select IPv4 and IPv6 default-gateway endpoints independently for
  multi-network containers, inspected, and preserved across recovery
  (`NET-016`, `RTM-012`).
- SCTP has an explicit support decision: publishing an `sctp` port is rejected
  with 400 and recorded as an intentional gap because the vmnet port forwarder
  bridges only TCP and UDP (`NET-017`).
- Explicit address-family controls are persisted and applied: `EnableIPv4=false`
  suppresses IPv4 IPAM and endpoint allocation, `EnableIPv6` controls IPv6 IPAM,
  and both flags survive inspect and daemon recovery (`NET-018`).
- Endpoint sysctls use the API v1.46 `DriverOpts` field, validate Docker's
  `IFNAME` grammar, and apply through the guest network namespace. Create and
  connect accept the current request DTO for older negotiated APIs, while the
  field round-trips only through v1.46+ inspect and remains omitted from older
  responses. Recovery support shipped in guest protocol v7 and is carried by
  the current guest protocol v10 (`NET-019`).
- API v1.52+ network inspect reports per-subnet IPAM allocation status while
  older API responses omit it; IPv4 `/31` status and allocation follow RFC 3021
  semantics through privileged-helper gateway validation and subnet-derived
  default gateways, and pending creates reserve static IP and explicit MAC
  endpoints before persistence (`NET-020`).
- IPAM and address-family configurations cengine cannot faithfully express are
  rejected before persistence: auxiliary reservations, multiple same-family
  subnets, asymmetric dual-stack isolation, both families disabled, and custom
  IPv6 gateways (`NET-022`).

Completion criteria:

- Accepted endpoint settings are applied in the guest and survive inspect and
  daemon recovery. *(Done for MAC address and gateway priority.)*
- Invalid or unsupported settings fail explicitly instead of being ignored.
  *(Done for MAC address, SCTP publishing, IPAM, and family/fabric limits.)*
- Multi-network containers select each address family's route according to
  gateway priority. *(Done: `NET-016`, `RTM-012`.)*
- SCTP is either implemented and tested end to end or recorded as an intentional
  compatibility gap. *(Done: recorded as an intentional gap, `NET-017`.)*
- Endpoint sysctls, explicit IPv4 controls, IPAM status, and IPAM validation are
  covered by `NET-018`–`NET-020` and `NET-022`.

### 3. Close remaining client-visible API gaps

Use the API v1.44-v1.55 assessment table in
[Docker compatibility](docker-compatibility.md#api-version-envelope) as the
endpoint-level backlog. Registry search (`IMG-004`) is complete for Docker Hub
and legacy-v1 custom registries, including authentication, filters, limits, and
the versioned Docker response shape. Per-device block-I/O updates are complete
for the VM root disk under API v1.55, with the additional-device limitation
recorded as an intentional gap.
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
