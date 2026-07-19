# Docker and Compose compatibility

This cengine-owned ledger combines Docker API contracts with real Docker Compose
lifecycle tests. Its seed inventory came from the docker-py compatibility tests
maintained by Podman, pinned to commit
[`ac46410007edf94c9c5482c5d83c1471cfd23b00`](https://github.com/containers/podman/tree/ac46410007edf94c9c5482c5d83c1471cfd23b00/test/python/docker/compat),
with assertions adapted to Docker Engine semantics where Podman tests its own
quirks. The active suite uses docker-py 7.2.0, negotiates Docker API v1.55,
and retains an explicit v1.44 minimum-version smoke test.

Run the complete suite with `make test-compat`, repeat it across three isolated
shuffled runs with `make test-compat-soak`, or compare deterministic behavior
with `make test-compat-oracle DOCKER_REFERENCE_HOST=...`. Known failures
are strict expected failures: a new failure or an unexpected pass fails the
command until this ledger and the test disposition are updated.

The VM-backed suite is a local gate today. GitHub-hosted runners do not provide
the environment needed to run it; a self-hosted Apple-silicon gate remains a
future task. Test output records the installed Docker CLI, Compose, and Buildx
versions. Docker-py and Compose are pinned by the repository, BuildKit is pinned
by the Buildx contract, and external Compose/Buildx fixture images use manifest
digests.

## Normative source hierarchy

Compatibility decisions use the narrowest authoritative source that defines the
observable behavior:

1. [Docker Engine API v1.55](https://docs.docker.com/reference/api/engine/version/v1.55/)
   defines request, response, error, and version-negotiation behavior.
2. [OCI Runtime Specification v1.3.0](https://github.com/opencontainers/runtime-spec/tree/v1.3.0)
   defines execution semantics that apply to cengine's Docker-facing runtime,
   especially process identity, cwd, environment, rootfs, mounts, namespaces,
   resources, and Linux security state.
3. Linux syscall documentation defines the mechanism used to realize those
   semantics, including [`setns(2)`](https://man7.org/linux/man-pages/man2/setns.2.html),
   [`mount(2)`](https://man7.org/linux/man-pages/man2/mount.2.html), and
   [`PR_SET_NO_NEW_PRIVS`](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html).
   Per-interface network settings additionally follow Linux's
   [`/proc/sys/net` sysctl interface](https://docs.kernel.org/admin-guide/sysctl/net.html).
4. Reference Docker Engine/Moby behavior resolves details the API and OCI specs
   leave unspecified. Such behavior should become a deterministic differential
   oracle or a focused cengine-owned contract.

This hierarchy does not claim that cengine exposes the OCI runtime command-line
interface or accepts an OCI `config.json`. It uses applicable OCI semantics as a
reference beneath the Docker API.

## Black-box coverage map

| Exposed family | VM-backed coverage | Remaining black-box gaps |
|---|---|---|
| Negotiation, version, info | `SYS-001`–`SYS-004`, `CLI-001` | Counts and optional native-engine fields are versioned; operational shape sampling is concentrated at v1.44 and v1.55. |
| Container lifecycle and inspect | `CTR-001`–`CTR-048`, `EVT-001`–`EVT-005`, `CLI-002`–`CLI-004`, `CLI-008` | Concurrent VM creation/start is covered at twelve containers; lifecycle event filters include the creating image and accept both Docker filter encodings; longer-running high-volume churn is not assessed. |
| Archive, exec, observability, update | `CTR-015`, `CTR-024`–`CTR-033`, `CTR-036`, `CTR-038`–`CTR-047`, `CLI-006` | Disk usage, filtered logs, historical events, and multi-container stats have black-box coverage. |
| Networks, ports, and volumes | `CTR-002`, `CTR-004`, `CTR-034`–`CTR-035`, `NET-001`–`NET-022`, `VOL-001`–`VOL-006`, `CLI-005`, `KND-001` | Address-family control, endpoint sysctls, IPAM validation/status and filtered pruning, MAC application, and gateway priority are covered. SCTP publishing is an intentional gap (`NET-017`). |
| Images and build | `IMG-001`–`IMG-023`, `BLD-001`–`BLD-003`, `EVT-003` | Multi-platform graph selection, archives, descriptors, identity, attestations, authenticated registry round trips, and pull/load events are covered. |
| Compose and recovery | `CMP-001`–`CMP-007`, `REC-001`–`REC-006` | Recovery covers live workloads, log and stats streams, active networking, restart-policy semantics, and vmnet reservation release. |
| Testcontainers | `TST-001`–`TST-004` | Ryuk is exercised with default and privileged container configurations against the bound cengine Docker socket, including shell-less exec probing and concurrent control connections. |
| Differential behavior | `ORC-001`–`ORC-002` | Optional lifecycle and multi-platform image response-shape comparisons require an explicit reference Docker Engine. |
| Runtime semantics | `RTM-001`–`RTM-014`, `KND-001` | PID limits, process rlimits, private bind isolation, configurable capability add/drop, filter-safe container pruning, paused lifecycle control, attached/detached exec status behavior, independent IPv4/IPv6 default-route selection, and fail-closed API v1.55 runtime-input handling are covered. Shared/slave bind propagation, configurable devices/seccomp/security options, masked paths, and broader cgroup-v2 IO/device behavior remain gaps with explicit rejection where decoded. |

## Runtime semantics and OCI applicability

The applicability table is the runtime-semantic backlog. **Covered** means a
strict `RTM-*` or equivalent compatibility contract exercises the behavior;
**Partial** means cengine implements a constrained Docker-facing subset; **Gap**
means an exposed or planned behavior needs a decision; and **Not applicable**
means the one-container-per-VM architecture does not expose that OCI surface.

| OCI Runtime v1.3 area | Applicability | Current evidence | Remaining work |
|---|---|---|---|
| Process args, environment, cwd, user and groups | Covered | `RTM-001` checks init/default-exec parity and named supplementary groups; `RTM-009` verifies attached exec PID and terminal-state publication; `RTM-011` terminalizes attached and detached execs when their parent stops or restarts; focused Swift tests cover image/container/exec precedence. | Expand differentials for invalid named identities and explicit exec overrides as clients demand them. |
| Root filesystem and mount-namespace root | Covered | `RTM-001` compares namespace/root identity; `RTM-003` exercises nested Docker reopening process roots. | Continue porting nested-runtime regressions as distinct contracts. |
| Read-only root and writable mounts | Partial | `RTM-002` requires exec writes to fail on the root while an explicit tmpfs remains writable; private and recursive-private bind modes are applied. | Shared/slave propagation cannot cross the macOS virtiofs boundary and is explicitly rejected by `RTM-005`; expand bind/volume remount matrices. |
| PID, mount, UTS, IPC, network and cgroup namespaces | Partial | `RTM-001` requires init/default exec to share all six namespace identities; `RTM-012` requires independent IPv4 and IPv6 default-route selection across mixed-family endpoints; `RTM-013` rejects active namespace-sharing modes rather than silently selecting the private default. | Docker namespace-sharing modes and configurable namespace paths are not implemented. |
| Process security state | Partial | `RTM-001` compares capability masks, checks `NoNewPrivs`, verifies privileged-exec override, and rejects leaked stage descriptors. `RTM-006` verifies Docker-default capability policy plus `CapAdd`/`CapDrop` parity for init and exec. `RTM-014` verifies OCI-style process rlimits for init, exec, and healthchecks across recovery and restart. | Ambient capabilities, seccomp, AppArmor/SELinux-shaped security options, masked/readonly paths, and device policy remain intentional gaps and are explicitly rejected when requested. |
| Linux resources and cgroup v2 | Partial | `CTR-028`, `CTR-042`, and `CTR-047` cover CPU/memory limits and live updates; `RTM-004` covers persisted create/update PID limits, enforcement, and recovery; `RTM-008` places each final exec target in its own leaf beneath the container workload cgroup while staging processes remain outside its PID budget, and uses recursive cgroup kill for timed-out healthchecks; `RTM-013` requires active unsupported resource fields to fail before mutation. | IO/device controls, per-device blkio, and broader cgroup-v2 delegation/accounting remain gaps. |
| Linux devices and filesystems | Partial | `CTR-035`, `CTR-045`, `VOL-002`–`VOL-006`, and `RTM-002` cover ext4, standard devices, volumes, tmpfs, and private bind mounts; `NET-019` covers endpoint-scoped network sysctls; `RTM-013` covers fail-closed structured mount options without anonymous-volume leakage. | Configurable devices, device cgroup rules, container-wide sysctls, shared/slave propagation, non-recursive bind variants, and additional filesystem options remain intentional gaps and are explicitly rejected when requested. |
| Configuration annotations | Covered | `CTR-048` starts an annotated workload; focused Swift and Go protocol tests require the persisted values to enter the versioned guest workload specification. | Annotations remain runtime metadata and are not injected into the container process environment. |
| OCI lifecycle operations and hooks | Not applicable | Docker lifecycle maps directly to cengine shims and guest control; no OCI runtime CLI is exposed. | Reassess only if cengine adopts an OCI runtime adapter or hook surface. |

Every runtime divergence discovered during implementation is classified as
covered, partial, intentional gap, or undecided. Supported Docker inputs must not
be silently ignored; either apply them, reject them clearly, or record and
prioritize the gap.

Docker-facing lifecycle mutations are serialized per container. Pause, unpause,
rename, network connect/disconnect, explicit start/stop, and policy-driven restart do not
commit through collection positions captured before a backend suspension, and a
stop request that overlaps an in-flight start returns a conflict instead of
reporting a false successful stop. Focused Swift race tests cover these ownership
rules against the [Docker container API](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Container)
and [Docker network API](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Network)
operation contracts.

## API version envelope

Cengine advertises API v1.55 and accepts versioned operational requests from
v1.44 through v1.55. Unversioned requests are limited to `/_ping` and
`/version`. Supporting this negotiation envelope does not imply that cengine
implements every endpoint in Docker's API; the tables below remain the source
of truth for its focused runtime surface.

The following assessment tracks changes from Docker's
[API version history](https://docs.docker.com/reference/api/engine/version-history/)
that affect endpoint families cengine exposes. **Supported** means the versioned
behavior is implemented and tested, **Partial** means the base operation works
but the newer option does not, and **Gap** identifies future work. This table is
an assessment backlog rather than part of the pytest compatibility-ID inventory.

| API | Change affecting cengine's surface | Status | Notes |
|---|---|---|---|
| 1.42 | Volume prune defaults to anonymous volumes | Supported | All accepted cengine API versions inherit the safe anonymous-only default; `all=true` explicitly widens pruning to every unused local volume. |
| 1.45 | Container network alias response semantics | Supported | v1.44 retains the short ID in `Aliases`; v1.45+ returns submitted aliases and uses `DNSNames` for runtime names. |
| 1.45 | Named-volume mount `VolumeOptions.Subpath` | Supported | Existing subdirectories are safely resolved beneath the named-volume root. |
| 1.45 | Image-inspect removal of `Container` and `ContainerConfig` | Supported | Cengine does not emit the removed legacy fields. |
| 1.46 | Containerd info, container annotations, endpoint sysctls, tmpfs options, push platform, and image-create events | Partial | Annotations persist from create/inspect, appear in list responses from v1.46, and enter the versioned guest runtime specification. Endpoint `DriverOpts` sysctls are validated, persisted, applied to the resolved guest interface, inspected only for v1.46+, and recovered (`NET-019`); current request DTOs remain accepted for older negotiated APIs. Pull/load events, tmpfs size/mode, and platform-selective push are supported. `Containerd` is omitted because cengine does not use containerd, and the builder-only image `create` event is inapplicable while direct build remains intentionally unsupported. |
| 1.47 | Image-list manifest summaries | Supported | `manifests=true` returns available, missing, image, and attestation manifest summaries. |
| 1.48 | Platform-aware history/load/save/push, image mounts, OCI descriptors/manifests, image-manifest descriptors, IPv4 network control, and gateway priority | Partial | Image operations, descriptor responses, endpoint gateway priority (`NET-016`, `RTM-012`), and explicit network IPv4 enable/disable (`NET-018`) are supported; pre-v1.48 requests retain legacy IPv4-enabled behavior. Image mounts remain a gap. |
| 1.49 | Platform-specific image inspect and firewall backend info | Supported | JSON-encoded OCI platform selection and `manifests` conflicts are enforced. `FirewallBackend` is correctly omitted because cengine does not use Moby's Linux iptables/nftables backend. |
| 1.50 | Platform-selective image deletion and discovered-device info | Supported | Repeated JSON platform deletion preserves unselected variants; `DiscoveredDevices` is an empty array because cengine has no device-discovery drivers. |
| 1.50 | Removal of deprecated image-config fields | Supported | Cengine's image configuration already omits the removed runtime-only fields. |
| 1.51 | Image summary container usage count | Supported | v1.44-v1.50 report `-1`; v1.51+ calculate the number of containers using each image. |
| 1.52 | Event legacy-field removal and container/image response omissions | Supported | Responses branch at v1.52 while older API requests retain their legacy shape. |
| 1.52 | Container summary health and stats OS type | Supported | v1.52+ responses include `Health` and `os_type`. |
| 1.52 | Multi-platform image load/save, network IPAM status, event content negotiation, and verbose system disk usage | Supported | Repeated image selectors, versioned subnet allocation status (`NET-020`), event negotiation, and disk usage are supported. |
| 1.53 | NRI info, JSONL event negotiation, and image identity | Supported | Event streams and trusted pull/push origin identity are supported. `NRI` is correctly omitted because cengine has no Node Resource Interface integration. |
| 1.54 | Image-list identity and endpoint MAC application | Supported | `identity=true` implies manifest summaries and returns trusted origin data; explicit endpoint `MacAddress` is decoded, validated, applied in the guest, and inspected (`NET-014`, `NET-015`). Endpoint sysctls (`NET-019`) and gateway priority (`NET-016`, API 1.48) are also supported. |
| 1.55 | Image attestations and per-device blkio updates | Partial | Attached in-toto statements support platform/type filters and statement opt-in; the five blkio device arrays remain an intentional gap and active create/update requests return HTTP 501 (`RTM-013`). |

Status values are **✅ Pass**, **❌ Known fail**, and **⬜ Not assessed**. Intent
values are **Support**, **Intentional gap**, and **Undecided**.

Rows inherited from the original inventory retain the pinned Podman commit as
their origin. Rows identified as cengine-owned below are contracts added from
Docker Engine semantics or observed Docker Compose 5.3.1 behavior.

## Runtime semantics

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `RTM-001` | `test_init_and_default_exec_share_runtime_context` | ✅ Pass | Support | **cengine-owned.** Init and default exec share mount, PID, UTS, IPC, network, and cgroup namespaces; root identity; hostname; cwd; user and supplementary groups; environment; capability masks; and `NoNewPrivs`. Exec stage descriptors do not leak, an explicitly privileged exec clears the no-new-privileges request, and default exec inherits a privileged container's effective privilege. |
| `RTM-002` | `test_read_only_root_applies_to_exec_but_tmpfs_stays_writable` | ✅ Pass | Support | **cengine-owned.** Start does not report success before the workload root is ready for an immediate exec. Exec cannot write through a read-only workload root while an explicitly writable tmpfs remains writable. |
| `RTM-003` | `test_nested_docker_exec_and_healthcheck_without_kind` | ✅ Pass | Support | **cengine-owned.** Pinned Docker 29.6.2 DinD loads the cached pinned Alpine archive, starts a nested container at `/data`, executes into it, and reaches `healthy` without kind or another registry pull. |
| `RTM-004` | `test_pids_limit_enforces_live_updates_and_survives_recovery` | ✅ Pass | Support | **cengine-owned.** Docker `PidsLimit` create/inspect/update semantics drive cgroup-v2 `pids.max`; lowering to the live process count prevents exec, raising the limit restores exec, and the configured limit survives daemon recovery. Docker API `0` and `-1` unlimited values map to Linux `max`. See the [Docker API update contract](https://docs.docker.com/reference/api/engine/version-history/#v140-api-changes) and [OCI Linux PID resources](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#control-groups). |
| `RTM-005` | `test_unrealizable_bind_mount_propagation_is_rejected` | ✅ Pass | Intentional gap | **cengine-owned.** Private and recursive-private bind modes remain supported. Shared/slave modes require a real peer/master mount across the host/container boundary, which macOS virtiofs cannot provide, so `shared`, `rshared`, `slave`, and `rslave` return HTTP 501 instead of exposing a marker-only mount. See [Docker bind propagation](https://docs.docker.com/engine/storage/bind-mounts/#configure-bind-propagation) and [`mount(2)` shared-subtree operations](https://man7.org/linux/man-pages/man2/mount.2.html). |
| `RTM-006` | `test_capability_add_drop_apply_to_init_and_exec` | ✅ Pass | Support | **cengine-owned.** Docker's default Linux capability set is used for unprivileged root workloads; case-insensitive `CapAdd`/`CapDrop`, optional `CAP_` prefixes, and `ALL` are normalized, drops are applied before additions, and the result is applied to bounding/permitted/effective sets for init and default exec. Privileged workloads and privileged exec retain all capabilities. See [Docker Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities) and [OCI process capabilities](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#process). |
| `RTM-007` | `test_container_prune_honors_filters_and_rejects_unknown_keys` | ✅ Pass | Support | **cengine-owned.** Container prune applies one Docker `until` cutoff, conjunctive positive-label filters, and negated-label filters before deletion. Legacy map-shaped filter keys remain active regardless of their boolean payload. Unknown, malformed, or ambiguous filters fail without deleting any container instead of silently broadening prune scope. See the [Docker container prune API](https://docs.docker.com/reference/api/engine/version/v1.52/#tag/Container/operation/ContainerPrune). |
| `RTM-008` | `test_exec_stage_proxies_preserve_status_and_kill_timed_out_healthchecks` | ✅ Pass | Support | **cengine-owned.** Exec staging processes preserve target exit codes and proxy catchable signals. Exec inspect publishes the final target's workload-namespace PID rather than a staging proxy's outer PID. Each exec target receives a dedicated cgroup-v2 leaf, and timed-out healthchecks write `1` to that leaf's `cgroup.kill`, recursively terminating both the target and descendants without affecting sibling execs. See the [Linux cgroup-v2 `cgroup.kill` contract](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files) and [OCI Linux control groups](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#control-groups). |
| `RTM-009` | `test_attached_exec_inspect_publishes_pid_and_terminal_status` | ✅ Pass | Support | **cengine-owned.** An attached exec remains pending while its guest state is `starting` or `running`, publishes its final target PID before the HTTP upgrade completes, and transitions inspect to the terminal exit code without losing that PID, including when the target exits before its PID publication is committed. A launch failure after stream upgrade becomes terminal instead of reverting to a permanently created host record. See the [Docker exec inspect API](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Exec/operation/ExecInspect) and [OCI process lifecycle](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/runtime.md#lifecycle). |
| `RTM-010` | `test_paused_stop_restart_and_force_remove_complete` | ✅ Pass | Support | **cengine-owned.** Stop, restart, and forced removal resume a paused VM before sending guest process signals, then use a bounded forced-shutdown fallback so lifecycle requests cannot wait forever on a suspended guest. Restart returns the workload to a responsive running state. |
| `RTM-011` | `test_parent_stop_and_restart_terminalize_attached_and_detached_execs` | ✅ Pass | Support | **cengine-owned.** Parent stop and restart reconcile every attached and detached child exec from the old execution generation to a terminal inspect state before a replacement generation is published, preserving its PID and using exit code 137 when VM teardown makes the final guest status unavailable. The restarted parent is responsive to a new exec while the old exec records remain terminal. See the [Docker exec inspect API](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Exec/operation/ExecInspect) and [OCI process lifecycle](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/runtime.md#lifecycle). |
| `RTM-012` | `test_default_routes_are_selected_per_address_family` | ✅ Pass | Support | **cengine-owned.** A container attached to separate IPv4-only and IPv6-only networks retains one default route for each family even when the endpoint priorities differ. This matches [Moby's independent IPv4 and IPv6 gateway endpoint selection](https://github.com/moby/moby/blob/docker-v29.0.0/integration/network/network_linux_test.go#L446-L541). |
| `RTM-013` | `test_active_unsupported_runtime_inputs_fail_closed` | ✅ Pass | Intentional gap | **cengine-owned.** Runtime-bearing API v1.55 fields are decoded across container create/update, Linux resources and namespaces, mounts, healthchecks, and exec create/start. Inert zero/default forms remain accepted, while recognized active gaps return HTTP 501 before container, anonymous-volume, resource, or exec mutation. Malformed or contradictory recognized values return HTTP 400, and unknown extension keys remain tolerated. See Moby's [container config](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/container/config.go), [host resources/config](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/container/hostconfig.go), [mount request](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/mount/mount.go), and [exec create](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/container/exec_create_request.go) and [start](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/container/exec_start_request.go) definitions. |
| `RTM-014` | `test_ulimits_apply_to_init_exec_healthchecks_and_survive_recovery` | ✅ Pass | Support | **cengine-owned.** Create-time Docker ulimits are normalized, inspected, persisted, and applied with Linux `setrlimit` to init, exec, and healthcheck processes. Limits survive daemon recovery and container stop/start without constraining the guest supervisor or exec signal/status proxies. Invalid values fail before container or anonymous-volume mutation; non-empty update-time ulimits remain an explicit HTTP 501 gap. See [Docker `--ulimit`](https://docs.docker.com/reference/cli/docker/container/run/#set-ulimits-in-container---ulimit), [OCI process rlimits](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#posix-process), and [`getrlimit(2)`/`setrlimit(2)`](https://man7.org/linux/man-pages/man2/ugetrlimit.2.html). |

### Explicit runtime input decisions

| Docker input | Intent | Behavior |
|---|---|---|
| create config `Domainname`, `ArgsEscaped`, `NetworkDisabled`, and `Shell` | Intentional gap | Active values that differ from cengine's fixed runtime behavior return HTTP 501; empty/default values are accepted. |
| create attachment routing flags | Support | `AttachStdout`, `AttachStderr`, and `StdinOnce` are accepted in both boolean forms. They configure client attachment behavior rather than the container's OCI/Linux runtime contract; cengine's attach endpoint and input-close handling remain authoritative. |
| `HostConfig.Init` | Support | Both boolean forms are accepted and reflected by inspect. cengine owns the fixed workload launch stage rather than selecting Docker's host-side init binary. |
| unsupported create/update resource fields | Intentional gap | Active CPU shares/cpuset/realtime, custom cgroup-parent, blkio, memory reservation/swap/swappiness, OOM-killer override, device requests, and Windows resource fields return HTTP 501. Docker's `MemorySwappiness=-1` and Buildx's `/docker/buildx` cgroup-parent defaults are accepted as inert in cengine's one-container-per-VM model. Supported memory, CPU quota/NanoCPUs, and PID-limit fields retain their existing behavior. |
| namespace, cgroup, runtime, process-group, OOM-score, shared-memory, and isolation overrides | Intentional gap | Private/default modes and inert values are accepted. Active namespace/cgroup sharing, custom runtime/groups/storage options, non-default OOM score, non-default shared-memory size, and non-default isolation return HTTP 501; invalid modes and out-of-range values return HTTP 400. |
| `HostConfig.SecurityOpt` | Partial | Privileged containers accept kind's inert `seccomp=unconfined` and `apparmor=unconfined` defaults. Other non-empty requests return HTTP 501; seccomp and LSM-shaped settings are not silently accepted. |
| `HostConfig.Ulimits` | Partial | Create accepts Docker's Linux limit names except deprecated `as`, canonicalizes names, validates soft/hard values, persists and inspects the request, and applies it to init, exec, and healthchecks. Empty updates are inert; non-empty update requests return HTTP 501 because live process-limit mutation is not implemented. |
| `HostConfig.Devices`, `HostConfig.DeviceCgroupRules` | Intentional gap | Non-empty requests return HTTP 501; the fixed one-container VM device surface is unchanged. |
| `HostConfig.Sysctls` | Intentional gap | Non-empty requests return HTTP 501 until container namespace sysctls are applied in the guest. |
| `HostConfig.MaskedPaths`, `HostConfig.ReadonlyPaths` | Intentional gap | Non-empty requests return HTTP 501 until path masking/read-only bind policy is implemented. |
| bind propagation `shared`, `rshared`, `slave`, `rslave` | Intentional gap | Requests return HTTP 501 because virtiofs cannot establish the required host/container peer or master mount; `private` and `rprivate` remain supported. |
| `Mount.BindOptions.NonRecursive`, `ReadOnlyNonRecursive`, `ReadOnlyForceRecursive` | Intentional gap | Enabled requests return HTTP 501; ordinary recursive bind mounts remain supported. |
| image/cluster/npipe mounts, mount consistency, volume labels, SELinux/nocopy legacy options, and structured tmpfs options | Intentional gap | Recognized active requests return HTTP 501. Unknown mount types/options, mismatched option families, and malformed size/mode values return HTTP 400. |
| `Healthcheck.StartInterval` | Intentional gap | Non-zero requests return HTTP 501 until start-period scheduling supports a distinct interval. |
| empty healthcheck test inheritance | Intentional gap | An explicitly empty `Test` returns HTTP 501 because cengine cannot inherit an image healthcheck through the create request; invalid test forms and sub-millisecond durations return HTTP 400. |
| container `AttachStdin` | Support | The requested attach configuration is persisted and returned by inspect; `OpenStdin` continues to control whether the guest input remains open. |
| exec `DetachKeys` | Intentional gap | Non-empty custom detach-key requests return HTTP 501. |
| create/exec `ConsoleSize` | Intentional gap | `[0,0]` is accepted as the inert default; a non-zero terminal size returns HTTP 501, while malformed shapes return HTTP 400. |
| exec-start `Tty` | Support | When supplied, the value must match the TTY mode selected when the exec was created; mismatches return HTTP 400. |

## Containers

| ID | Upstream test | Status | Intent | Notes |
|---|---|---|---|---|
| `CTR-001` | `test_create_container` | ✅ Pass | Support | Create and list through docker-py. |
| `CTR-002` | `test_create_network` | ✅ Pass | Support | Bridge network creation. |
| `CTR-003` | `test_start_container` | ✅ Pass | Support | Start through docker-py and verify running state. |
| `CTR-004` | `test_start_container_with_random_port_bind` | ✅ Pass | Support | Strengthened to require a nonzero assigned host port after start. |
| `CTR-005` | `test_stop_container` | ✅ Pass | Support | State becomes exited. |
| `CTR-006` | `test_kill_container` | ✅ Pass | Support | SIGKILL is reconciled before the response completes. |
| `CTR-007` | `test_restart_container` | ✅ Pass | Support | Restart after stop. |
| `CTR-008` | `test_remove_container` | ✅ Pass | Support | Force removal of a running container. |
| `CTR-009` | `test_remove_container_without_force` | ✅ Pass | Support | Uses Docker's HTTP 409 conflict rather than Podman's HTTP 500 assertion. |
| `CTR-010` | `test_pause_container` | ✅ Pass | Support | Pause and inspect. |
| `CTR-011` | `test_pause_stopped_container` | ✅ Pass | Support | Uses Docker's HTTP 409 conflict. |
| `CTR-012` | `test_unpause_container` | ✅ Pass | Support | Resume and inspect. |
| `CTR-013` | `test_list_container` | ✅ Pass | Support | List all containers. |
| `CTR-014` | `test_filters` | ✅ Pass | Support | Enabled even though Podman currently skips it. |
| `CTR-015` | `test_copy_to_container` | ✅ Pass | Support | Content, mode, and numeric tar UID/GID are preserved inside the guest. |
| `CTR-016` | `test_mount_preexisting_dir` | ❌ Known fail | Intentional gap | Requires direct `docker build`; cengine requires Buildx. |
| `CTR-017` | `test_non_existent_workdir` | ❌ Known fail | Intentional gap | Requires direct `docker build`; cengine requires Buildx. |
| `CTR-018` | `test_build_pull` | ❌ Known fail | Intentional gap | Requires direct `docker build`; cengine requires Buildx. |
| `CTR-019` | `test_mount_options_by_default` | ✅ Pass | Support | Checks normalized `HostConfig.Binds` and top-level `Mounts`. |
| `CTR-020` | `test_wait_next_exit` | ✅ Pass | Support | Blocks until the next start and exit, including from the created state. |
| `CTR-021` | `test_container_inspect_compatibility` | ✅ Pass | Support | Includes stable container, mount, network, logging, and host-config fields consumed by docker-py. |
| `CTR-022` | `test_rename_container` | ✅ Pass | Support | **cengine-owned.** Rename is persisted and addressable by the new name. |
| `CTR-023` | `test_rename_container_name_conflict` | ✅ Pass | Support | **cengine-owned.** Duplicate names return HTTP 409. |
| `CTR-024` | `test_exec_attached_output_and_exit_code` | ✅ Pass | Support | **cengine-owned.** Attached exec preserves multiplexed stdout/stderr and exit status. |
| `CTR-025` | `test_copy_from_container_round_trip` | ✅ Pass | Support | **cengine-owned.** Archive download returns file contents and path metadata. |
| `CTR-026` | `test_container_configuration_round_trip` | ✅ Pass | Support | **cengine-owned.** Environment, user, workdir, read-only root, labels, restart policy, and default resources survive create/inspect. |
| `CTR-027` | `test_container_stats_complete` | ✅ Pass | Support | **cengine-owned.** VM-backed `docker stats --no-stream` returns a container sample. |
| `CTR-028` | `test_top_and_update` | ✅ Pass | Support | **cengine-owned.** Process listing and live cgroup resource-policy updates preserve the running VM. |
| `CTR-029` | `test_follow_logs_streams_output_and_closes` | ✅ Pass | Support | **cengine-owned.** Follow mode streams multiplexed output and closes at container exit. |
| `CTR-030` | `test_streaming_stats_produces_multiple_samples` | ✅ Pass | Support | **cengine-owned.** Streaming stats returns successive Docker-shaped samples. |
| `CTR-031` | `test_container_and_exec_tty_resize` | ✅ Pass | Support | **cengine-owned.** Running container and exec terminals accept resize requests. |
| `CTR-032` | `test_log_time_tail_stream_and_timestamp_filters` | ✅ Pass | Support | **cengine-owned.** Snapshot and follow logs honor stream, time, tail, and timestamp options. |
| `CTR-033` | `test_multiple_containers_stream_stats_concurrently` | ✅ Pass | Support | **cengine-owned.** Multiple simultaneous stats streams produce independent samples. |
| `CTR-034` | `test_network_none_has_only_loopback` | ✅ Pass | Support | **cengine-owned.** Network mode `none` persists across inspect and exposes only loopback in the guest. |
| `CTR-035` | `test_debian_package_install_uses_ext4_rootfs` | ✅ Pass | Support | **cengine-owned.** Debian package installation creates `/etc/ssl` on the guest ext4 root without host-filesystem permission failures. |
| `CTR-036` | `test_exec_hijack_closes_after_process_exit` | ✅ Pass | Support | **cengine-owned.** Attached exec closes its hijacked HTTP stream promptly when the guest process exits. |
| `CTR-037` | `test_short_lived_container_reaches_exited_state` | ✅ Pass | Support | **cengine-owned.** A naturally exiting guest process is reconciled without requiring an explicit stop request. |
| `CTR-038` | `test_attached_exec_streams_stdin_before_eof` | ✅ Pass | Support | **cengine-owned.** Attached exec stdin remains open for streamed data and receives EOF when the client half-closes. |
| `CTR-039` | `test_attached_exec_preserves_multiline_stdin_bytes` | ✅ Pass | Support | **cengine-owned.** Attached exec preserves structured multi-line stdin byte-for-byte. |
| `CTR-040` | `test_exec_inherits_and_overrides_container_environment` | ✅ Pass | Support | **cengine-owned.** Exec inherits image and container environment before applying exec-specific overrides. |
| `CTR-041` | `test_restart_policy_update_preserves_running_vm` | ✅ Pass | Support | **cengine-owned.** Updating only restart-policy metadata preserves the running VM, container start time, and guest boot identity. |
| `CTR-042` | `test_live_resource_update_rejects_limits_above_vm_capacity` | ✅ Pass | Support | **cengine-owned.** Live resource increases above fixed VM capacity return HTTP 409 without changing container state. |
| `CTR-043` | `test_attached_exec_streams_large_stdin_without_filesystem_polling` | ✅ Pass | Support | **cengine-owned.** A 128 MiB attached exec stream is lossless and completes without filesystem-polling throughput limits. |
| `CTR-044` | `test_attached_exec_flushes_short_output_before_eof` | ✅ Pass | Support | **cengine-owned.** Short attached exec output is flushed before EOF, including rapid consecutive execs and clients that keep attached stdin open. |
| `CTR-045` | `test_unprivileged_standard_devices_are_world_accessible` | ✅ Pass | Support | **cengine-owned.** Standard character devices retain mode `0666` and are usable after the workload drops root privileges. |
| `CTR-046` | `test_concurrent_vm_starts_remain_responsive` | ✅ Pass | Support | **cengine-owned.** Twelve concurrent container creates and starts leave every running guest responsive to exec without starving shim control I/O. |
| `CTR-047` | `test_container_memory_limit_is_separate_from_vm_capacity` | ✅ Pass | Support | **cengine-owned.** The Docker memory value remains the workload cgroup hard limit while the per-container VM includes separate guest overhead. |
| `CTR-048` | `test_container_annotations_are_versioned_and_persisted` | ✅ Pass | Support | **cengine-owned.** Create-time annotations enter the guest workload specification, survive daemon recovery and inspect, while list responses expose them only from API v1.46. |

## Testcontainers

| ID | Test | Status | Intent | Notes |
|---|---|---|---|---|
| `TST-001` | `test_ryuk_reaps_through_bound_cengine_socket` | ✅ Pass | Support | **cengine-owned.** Default Ryuk reaches the cengine Docker API through an exact Unix-socket bind and reaps a labeled container. |
| `TST-002` | `test_privileged_ryuk_reaps_through_bound_cengine_socket` | ✅ Pass | Support | **cengine-owned.** Privileged Ryuk uses the same socket relay without requiring a rootful cengine daemon. |
| `TST-003` | `test_shellless_ryuk_exec_reports_command_not_found` | ✅ Pass | Support | **cengine-owned.** Exec against Ryuk's shell-less image returns Docker-compatible command-not-found status instead of retryable application failure. |
| `TST-004` | `test_ryuk_keeps_multiple_control_connections_open` | ✅ Pass | Support | **cengine-owned.** Closing one Ryuk control connection leaves cleanup suppressed while sibling connections remain open. |

## Images

| ID | Upstream test | Status | Intent | Notes |
|---|---|---|---|---|
| `IMG-001` | `test_tag_valid_image` | ✅ Pass | Support | Image tagging persists through the backend store. |
| `IMG-002` | `test_retag_valid_image` | ✅ Pass | Support | Additional tags resolve to the same image. |
| `IMG-003` | `test_list_images` | ✅ Pass | Support | Reference filtering excludes nonmatching images. |
| `IMG-004` | `test_search_image` | ❌ Known fail | Undecided | Registry search is not implemented; upstream currently skips this case. |
| `IMG-005` | `test_search_bogus_image` | ✅ Pass | Support | Unsupported search is surfaced as an API error. |
| `IMG-006` | `test_remove_image` | ✅ Pass | Support | Missing-image and successful removal behavior. |
| `IMG-007` | `test_image_history` | ✅ Pass | Support | History includes the image identifier. |
| `IMG-008` | `test_get_image_exists_not` | ✅ Pass | Support | Missing images return NotFound. |
| `IMG-009` | `test_save_image` | ✅ Pass | Support | Docker archive export from the backend OCI store. |
| `IMG-010` | `test_load_image` | ✅ Pass | Support | Docker save/load round trips. |
| `IMG-011` | `test_load_corrupt_image` | ✅ Pass | Support | Corrupt archives are rejected. |
| `IMG-012` | `test_build_image` | ❌ Known fail | Intentional gap | Direct build is intentionally unsupported. |
| `IMG-013` | `test_build_image_via_api_client` | ❌ Known fail | Intentional gap | Direct build is intentionally unsupported. |
| `IMG-014` | `test_push_error` | ✅ Pass | Support | Push streams registry failures in Docker's response shape. |
| `IMG-015` | `test_authenticated_push_round_trip` | ✅ Pass | Support | **cengine-owned.** Basic-auth push, removal, pull-back, and execution use a pinned local registry. |
| `IMG-016` | `test_multi_platform_manifest_summary_preserves_local_variants` | ✅ Pass | Support | **cengine-owned.** OCI index targets expose locally available arm64 and amd64 manifest summaries without flattening the graph. |
| `IMG-017` | `test_platform_specific_inspect_and_missing_platform` | ✅ Pass | Support | **cengine-owned.** JSON OCI platform selection returns the requested variant and a missing platform returns NotFound. |
| `IMG-018` | `test_multi_platform_save_and_load_round_trip` | ✅ Pass | Support | **cengine-owned.** Repeated save/load platform selectors preserve both selected variants in the OCI archive round trip. |
| `IMG-019` | `test_platform_selective_delete_retains_other_variant` | ✅ Pass | Support | **cengine-owned.** Forced platform deletion removes selected content while the other variant remains inspectable. |
| `IMG-020` | `test_container_reports_selected_image_manifest_descriptor` | ✅ Pass | Support | **cengine-owned.** Container list and inspect identify the graph root and selected platform manifest. |
| `IMG-021` | `test_image_identity_records_trusted_pull_origin` | ✅ Pass | Support | **cengine-owned.** Inspect and identity-enabled list responses report daemon-recorded pull origins. |
| `IMG-022` | `test_image_attestations_support_filters_and_statement_opt_in` | ✅ Pass | Support | **cengine-owned.** Attestation metadata avoids reading statements until opted in and supports predicate filtering. |
| `IMG-023` | `test_manifest_options_reject_conflicts_and_preserve_identity_after_retag` | ✅ Pass | Support | **cengine-owned.** Inspect rejects conflicting selectors, and retagging cannot manufacture trusted identity origins. |

## System

| ID | Upstream test | Status | Intent | Notes |
|---|---|---|---|---|
| `SYS-001` | `test_info` | ✅ Pass | Support | Adapted from Podman registry configuration to cengine driver, platform, and root invariants. |
| `SYS-002` | `test_info_container_details` | ✅ Pass | Support | Container totals update after create. |
| `SYS-003` | `test_version` | ✅ Pass | Support | Platform name and negotiated API version. |
| `SYS-004` | `test_info_reports_images_and_versioned_native_engine_details` | ✅ Pass | Support | **cengine-owned.** Image totals reflect the local store, discovered devices are reported as an empty list from v1.50, and inapplicable containerd, Linux firewall, and NRI details are not fabricated. |

## Events

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `EVT-001` | `test_filtered_container_events` | ✅ Pass | Support | **cengine-owned.** Type, container, and label filters isolate live create, start, die, and destroy events. |
| `EVT-002` | `test_historical_events_honor_time_window_and_jsonl` | ✅ Pass | Support | **cengine-owned.** A bounded history honors time windows and API v1.53+ JSONL negotiation. |
| `EVT-003` | `test_historical_image_pull_and_load_events_honor_filters` | ✅ Pass | Support | **cengine-owned.** Successful pulls and archive loads emit Docker-shaped image events that replay through type, action, and image filters. |
| `EVT-004` | `test_container_events_match_image_filter_with_tag_stripping` | ✅ Pass | Support | **cengine-owned.** Container lifecycle events match the `image` actor attribute by tagged reference or its tag-stripped familiar name, as defined by Moby event filtering. |
| `EVT-005` | `test_event_filters_accept_boolean_maps_and_ignore_false_entries` | ✅ Pass | Support | **cengine-owned.** The event stream accepts modern nested boolean-map filters, activates true selectors, and ignores false selectors without widening to unrelated event types. |

## Resources

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `NET-001` | `test_network_list_filters_labels` | ✅ Pass | Support | **cengine-owned.** Compose project label isolation. |
| `NET-002` | `test_network_connect_disconnect` | ✅ Pass | Support | **cengine-owned.** Containers can be connected to and disconnected from additional networks. |
| `NET-003` | `test_create_container_on_network` | ✅ Pass | Support | **cengine-owned.** docker-py's nullable endpoint configuration selects a network during create. |
| `NET-004` | `test_udp_port_forwarding` | ✅ Pass | Support | **cengine-owned.** Dynamically assigned UDP bindings forward request and response datagrams. |
| `NET-005` | `test_occupied_host_port_returns_server_error` | ✅ Pass | Support | **cengine-owned.** Occupied host ports fail container start without stealing the listener. |
| `NET-006` | `test_concurrent_random_port_allocation_is_unique` | ✅ Pass | Support | **cengine-owned.** Concurrent ephemeral TCP bindings remain unique. |
| `NET-007` | `test_sequential_network_deletion_releases_vmnet_reservations` | ✅ Pass | Support | **cengine-owned.** More than 119 sequential networks reuse a released vmnet reservation instead of exhausting host resources. |
| `NET-008` | `test_bridge_network_allows_peers_host_and_internet` | ✅ Pass | Support | **cengine-owned.** A normal bridge reaches peers, macOS host services, and the internet. |
| `NET-009` | `test_internal_network_allows_peers_and_host_but_not_internet` | ✅ Pass | Support | **cengine-owned.** Docker internal mode retains peer and host access while removing external connectivity. |
| `NET-010` | `test_isolated_gateway_allows_only_network_peers` | ✅ Pass | Support | **cengine-owned.** Isolated gateway mode permits peer traffic and blocks host and internet traffic. |
| `NET-011` | `test_isolated_gateway_options_round_trip_and_require_internal` | ✅ Pass | Support | **cengine-owned.** Docker bridge gateway options round-trip and isolated mode requires an internal network. |
| `NET-012` | `test_isolated_gateway_filter_cannot_be_bypassed_by_adding_a_route` | ✅ Pass | Support | **cengine-owned.** The external frame filter remains effective when a privileged guest adds a default route. |
| `NET-013` | `test_creating_container_preserves_existing_network_connectivity` | ✅ Pass | Support | **cengine-owned.** Replacing a running container's fabric bridge preserves its gateway, DNS, and Internet path. |
| `NET-014` | `test_explicit_endpoint_mac_address_is_applied_and_survives_recovery` | ✅ Pass | Support | **cengine-owned.** An explicit endpoint `MacAddress` is applied to the guest interface, returned by inspect, and preserved across daemon recovery. |
| `NET-015` | `test_invalid_and_duplicate_endpoint_mac_addresses_are_rejected` | ✅ Pass | Support | **cengine-owned.** Malformed or multicast MAC addresses fail with 400 and duplicate effective MACs on the same network fail with 409, including an explicit address that collides with a container's deterministic automatic address. Pending creates reserve effective MACs before persistence so concurrent creates cannot claim the same address. |
| `NET-016` | `test_gateway_priority_selects_default_route_and_survives_recovery` | ✅ Pass | Support | **cengine-owned.** A multi-network container installs its default route from the highest-priority endpoint (`GwPriority`), reports the value in inspect, and preserves the selection across daemon recovery. |
| `NET-017` | `test_publishing_sctp_port_is_rejected_as_intentional_gap` | ✅ Pass | Intentional gap | **cengine-owned.** Publishing an `sctp` port fails with 400 because the vmnet port forwarder bridges only TCP and UDP; TCP and UDP publishing on the same request still succeed. |
| `NET-018` | `test_explicit_network_address_families_apply_and_survive_recovery` | ✅ Pass | Support | **cengine-owned.** `EnableIPv4=false` suppresses IPv4 IPAM and endpoint addressing while enabled IPv6 remains usable; inspect and daemon recovery preserve both family flags. Empty backend address sentinels are normalized to absent addresses before persistence, so start and recovery do not misclassify IPv6-only endpoints as IPv4-capable or suppress IPv6 peer-host entries. This follows Docker's network `EnableIPv4`/`EnableIPv6` contract and [Moby's network-level enable labels](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/libnetwork/netlabel/labels.go). |
| `NET-019` | `test_endpoint_sysctls_apply_validate_and_survive_recovery` | ✅ Pass | Support | **cengine-owned.** Endpoint `DriverOpts` accepts `com.docker.network.endpoint.sysctls` with `IFNAME`, rejects malformed or unsupported settings, applies the values through the guest's `/proc/sys/net` namespace, and preserves them across recovery. Create and connect decode and apply the current DTO even with a pre-v1.46 negotiated API, matching Moby; inspect emits `DriverOpts` only for v1.46+. Semantics follow [Moby #47686](https://github.com/moby/moby/pull/47686). |
| `NET-020` | `test_network_ipam_status_tracks_allocations_and_api_version` | ✅ Pass | Support | **cengine-owned.** API v1.52+ network inspect reports per-subnet `IPsInUse` and `DynamicIPsAvailable`, including bridge reservations and endpoint allocations; API v1.51 omits `Status`. Explicit CIDRs are canonicalized before persistence, so a request such as `10.55.0.2/29` is stored and reported as `10.55.0.0/29` without double-counting the first allocated endpoint. IPv4 `/31` pools reserve neither endpoint as network/broadcast, including in privileged-helper gateway validation, matching [Moby's RFC 3021 allocator exception](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/libnetwork/ipams/defaultipam/allocator.go). When a gateway is omitted, the runtime derives the canonical first address from the masked subnet for both IPv4 and IPv6 before invoking any backend, keeping metadata-only and vmnet-backed inspect, allocation, and status accounting consistent. Pending creates and connects reserve endpoints before persistence; network deletion, prune, container start, and container removal respect those reservations until the operation commits or rolls back. Shape and accounting otherwise follow [Moby #50917](https://github.com/moby/moby/pull/50917). |
| `NET-021` | `test_network_prune_filters_limit_deleted_networks` | ✅ Pass | Support | **cengine-owned.** Network prune applies positive and negative label filters plus `until` before deleting unused networks, and rejects empty label keys before indexing or deleting anything. |
| `NET-022` | `test_network_ipam_and_family_validation_is_explicit` | ✅ Pass | Support | **cengine-owned.** The official `AuxiliaryAddresses` field is decoded and rejected explicitly, as are multiple same-family subnets, both families disabled, custom IPv6 gateways, and asymmetric dual-stack isolation. Network creation centrally validates CIDR syntax, prefix widths, and address families before backend persistence; canonicalizes subnet and gateway spellings; derives omitted gateways; requires gateways to belong to the pool; and rejects IPv4 network/broadcast and IPv6 network boundaries. Static endpoint addresses receive the same family, pool, canonicalization, and reservation checks before conflict checks and persistence, so equivalent IPv6 spellings cannot bypass duplicate allocation checks. Older negotiated APIs ignore `EnableIPv4` and keep legacy IPv4 behavior. The field spelling follows [Moby's IPAM API type](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/network/ipam.go), and reserved-address behavior follows [Moby's default IPAM allocator](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/libnetwork/ipams/defaultipam/allocator.go); custom IPv6 gateways are unsupported because Apple's vmnet configuration API exposes an [IPv6 prefix setter](https://developer.apple.com/documentation/vmnet/vmnet_network_configuration_set_ipv6_prefix(_:_:_:)) but no gateway-address setter in its [configuration function surface](https://developer.apple.com/documentation/vmnet/vmnet_functions). |
| `VOL-001` | `test_volume_list_filters_labels` | ✅ Pass | Support | **cengine-owned.** Compose project label isolation. |
| `VOL-002` | `test_empty_named_volume_copies_image_directory` | ✅ Pass | Support | **cengine-owned.** Empty named volumes receive image directory contents. |
| `VOL-003` | `test_volume_nocopy_leaves_empty_volume_empty` | ✅ Pass | Support | **cengine-owned.** `VolumeOptions.NoCopy` disables initialization. |
| `VOL-004` | `test_volume_subpath_mounts_existing_directory` | ✅ Pass | Support | **cengine-owned.** Existing volume subdirectories mount safely and traversal is rejected. |
| `VOL-005` | `test_tmpfs_size_and_mode_options` | ✅ Pass | Support | **cengine-owned.** Structured tmpfs size and mode options are applied in the guest. |
| `VOL-006` | `test_volume_preserves_inodes_across_link_and_rename` | ✅ Pass | Support | **cengine-owned.** Stable NFS file handles preserve hard-link identity across directory rename. |

## Docker Compose 5.3.1

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `CMP-001` | `test_compose_application_lifecycle` | ✅ Pass | Support | Pull, create, start, DNS, exit status, published-port HTTP, list, and teardown. |
| `CMP-002` | `test_compose_repeated_up_is_idempotent` | ✅ Pass | Support | Reconciliation preserves unchanged containers. |
| `CMP-003` | `test_compose_force_recreate_renames_replacement` | ✅ Pass | Support | Replacement containers receive canonical Compose names. |
| `CMP-004` | `test_compose_scale_and_reconcile` | ✅ Pass | Support | Scaling creates the requested replicas, preserves them on repeated up, and removes excess replicas. |
| `CMP-005` | `test_compose_exec_stop_start_and_restart` | ✅ Pass | Support | Compose exec and service lifecycle commands work without replacing the container. |
| `CMP-006` | `test_compose_named_volume_down_semantics` | ✅ Pass | Support | Named data survives ordinary down and is deleted by `down --volumes`. |
| `CMP-007` | `test_compose_waits_for_healthy_dependency` | ✅ Pass | Support | Health-conditioned dependencies start only after the prerequisite reports healthy. |

## Docker Buildx and BuildKit 0.27.1

The Buildx plugin is supplied by the host Docker CLI and its version is recorded
in compatibility-test output rather than pinned by this repository. The managed
builder and compatibility fixtures pin `moby/buildkit:v0.27.1`.

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `BLD-001` | `test_buildx_load_run_cache_and_volume_copy` | ✅ Pass | Support | The managed overlayfs builder supports non-scratch `COPY`, `RUN`, load, cache reuse, and volume initialization. |
| `BLD-002` | `test_buildx_pull_succeeds_after_daemon_restart` | ✅ Pass | Support | **cengine-owned.** A recovered BuildKit VM regains carrier, DNS, and registry access for a fresh pull. |
| `BLD-003` | `test_buildx_overlay_worker_has_large_state_volume` | ✅ Pass | Support | **cengine-owned.** Parallel stages use overlayfs on a 512 GiB sparse block-backed state volume. |
| `BLD-004` | `test_buildx_relaunches_missing_stopped_container_shim` | ✅ Pass | Support | **cengine-owned.** A stopped BuildKit container relaunches its missing VM shim after a daemon replacement without losing its writable root. |
| `BLD-005` | `test_buildx_recovers_uplink_after_network_helper_restart` | ✅ Pass | Support | **cengine-owned.** A running BuildKit VM automatically recreates its vmnet uplink after the privileged networking helper restarts. |

## Daemon recovery

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `REC-001` | `test_daemon_restart_recovers_resources_and_restart_policy` | ✅ Pass | Support | **cengine-owned.** An abrupt daemon restart preserves resources and restarts an `always` container. |
| `REC-002` | `test_daemon_restart_during_active_io_and_stats` | ✅ Pass | Support | **cengine-owned.** Recovery remains correct while log and stats streams are active. |
| `REC-003` | `test_daemon_restart_recreates_usable_network_interfaces` | ✅ Pass | Support | **cengine-owned.** Logical vmnet restoration recreates a carrier-up interface with working DNS and internet access. |
| `REC-004` | `test_running_workload_survives_daemon_process_replacement` | ✅ Pass | Support | **cengine-owned.** A daemon process replacement reconnects to the existing VM shim without changing container start time. |
| `REC-005` | `test_vmnet_reservation_is_released_when_infrastructure_shim_exits` | ✅ Pass | Support | **cengine-owned.** Infrastructure shim termination releases its privileged vmnet reservations before recovery. |
| `REC-006` | `test_daemon_restart_honors_manually_stopped_restart_policies` | ✅ Pass | Support | **cengine-owned.** Manual stops suppress immediate policy restarts; daemon restart starts `always` containers but leaves `unless-stopped` containers stopped. |

## Docker CLI

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `CLI-001` | `test_cli_system_and_image_commands` | ✅ Pass | Support | Version, info, pull, and image listing through the Docker CLI. |
| `CLI-002` | `test_cli_container_lifecycle` | ✅ Pass | Support | Create, start, inspect, list, stop, and remove through the Docker CLI. |
| `CLI-003` | `test_cli_run_attached_output` | ✅ Pass | Support | Attached `docker run` output and automatic removal. |
| `CLI-004` | `test_cli_run_attached_stdin` | ✅ Pass | Support | Interactive stdin over the hijacked attach connection. |
| `CLI-005` | `test_cli_network_and_volume_lifecycle` | ✅ Pass | Support | Network and volume create, list, and remove commands. |
| `CLI-006` | `test_cli_system_disk_usage` | ✅ Pass | Support | Base and verbose `docker system df` render engine-owned usage. |
| `CLI-007` | `test_cli_detached_kind_shaped_run` | ✅ Pass | Support | Detached runs acknowledge next-exit waits before start and preserve kind-style network and mount configuration. |
| `CLI-008` | `test_cengine_run_scopes_container_resources_and_process_behavior` | ✅ Pass | Support | The cengine wrapper preserves process behavior, isolates its Docker endpoint, and overrides create-time CPU and memory without changing ordinary defaults. |

## kind 0.32.0

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `KND-001` | `test_kind_create_cluster` | ✅ Pass | Support | A real kind control-plane cluster created through a scoped cengine resource wrapper receives the requested limits, reaches readiness, starts ordinary CoreDNS pods over CNI networking, executes a command inside a running pod, reaches the Kubernetes service VIP, resolves `host.docker.internal` through cluster DNS to its cengine network gateway, and is deleted through the isolated daemon. |

## Optional Docker differential oracle

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `ORC-001` | `test_container_lifecycle_matches_reference_docker` | ✅ Pass | Support | With `DOCKER_REFERENCE_HOST`, compares normalized create/inspect/filter/conflict/stop behavior to a real Docker Engine. |
| `ORC-002` | `test_image_metadata_matches_reference_docker` | ✅ Pass | Support | With a multi-platform reference image store, compares descriptor, manifest-summary, identity, and selected-platform response shapes. |
