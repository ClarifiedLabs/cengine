# Docker and Compose compatibility

Current support, behavioral contracts and test inventory for cengine's Docker-facing
runtime. API negotiation is **v1.44–v1.55**; the suite uses docker-py 7.2.0,
Compose 5.5.0 and BuildKit 0.32.2. Supporting this envelope does not implement every
Docker endpoint. The pinned [Podman seed inventory](https://github.com/containers/podman/tree/ac46410007edf94c9c5482c5d83c1471cfd23b00/test/python/docker/compat)
is adapted to Docker semantics, not Podman-specific behavior.

## Current storage and recovery contract

- **Direct volumes use ext4; shared volumes use FUSE backed by ext4 in the storage
  VM.** Unsupported store and ROOT authority formats are rejected without modifying
  their data. cengine does not migrate or automatically reset them; preserve the
  store and its recovery metadata. Owner enrollment requires explicit
  administrative approval; metadata-only startup needs neither helper enrollment
  nor guest assets.
- **Daemon-only restart preserves live VMs.** Graceful exit and daemon crashes
  retain storage/workload native identities, zero container restarts, shared DATA
  and original open-unlinked FD progress, including while the daemon is absent.
  The storage shim's independent process group prevents launchd job cleanup from
  killing it. Reattachment requires authenticated authority, not public receipts.
- **Normal macOS reboot recovery is qualified by attended installed-production
  acceptance.** The same store, backing/ext4
  identity and manifest survive; fresh storage/workload births and the next
  controller generation restore retained `always` peers automatically, with synced
  seed bytes and new bidirectional shared DATA. This is not same-VM survival across
  reboot, abrupt power-loss durability or arbitrary disk repair.
- Durable host identity is filesystem UUID plus inode, store/ext4 UUID and size;
  `st_dev` is a live observation, not a reboot-stable identifier. Live descriptors,
  leases and attachments remain exact-device checked. Historical specs are not
  rewritten. Stable bracketed `kern.bootsessionuuid` evidence proves prior-boot
  death even if a reused PID's BSD query returns EPERM; same-boot query failure
  does not prove death. A complete differing native birth is also death-only:
  missing/changing boot evidence or unknown/equal births never authorize a signal
  or peer.
  Duplicated-UUID offline cloning/rollback is not authenticated media provenance.
- Cold/interrupted handoff recovery requires exact protected history, positive
  native exit where required, and fresh authenticated proof/enrollment. Pending
  uncertainty remains contained; EOF, timeout and cancellation do not prove death
  or DRAINED. A committed-but-unenrolled cold owner needs a genuine fresh cold
  successor, not a synthetic ACK. PREPARE has no timeout-as-drain shortcut.

See [supported storage](storage-adoption.md#supported-storage),
[lifecycle checkpoints](storage-production-checkpoints.md),
[generation fencing and drain](storage-generation-drain.md), and
[raw disk initialization](../Guest/internal/disk/EXPLICIT-EXT4.md).
Canonical release assets and provenance are defined by [release policy](release.md);
local validation/preview artifacts do not establish canonical-release provenance,
notarization or distribution status.

## Verification scope

`make test-compat` runs the isolated VM suite; `make test-compat-soak` repeats it
with shuffled order. `make test-compat-oracle DOCKER_REFERENCE_HOST=...` requires an
explicit independent Docker endpoint. VM testing requires Apple silicon/macOS;
it is a local gate, not a GitHub-hosted-runner claim. See the
[compatibility harness](compatibility-testing.md) for fixture/profile requirements.

Run `make test-compat-images` to prepare verified digest-pinned local OCI fixtures
for CMP-008–010 and BLD-001/003/004/006/007. These use real Compose/Buildx builds,
the unmodified managed default builder and named OCI contexts with RUN networking
disabled; missing/invalid fixtures fail before daemon setup. BLD-002/005 retain
remote-pull/uplink tests. The whole suite is **not** offline.

Inventory status **Covered** means the stated contract has runtime coverage, not
complete upstream certification. **Intentional gap** rows verify rejection or a
bounded divergence, not feature support. **Expected failure** marks only the
existing strict legacy-build exclusions; unexpected passes fail. Native component,
qualification-only and parent-owned campaign scopes are not interchangeable.
Rows retain exact registered IDs and Python test names; conftest checks IDs at
collection. Optional oracle coverage requires its reference fixture.

## Normative source hierarchy

1. [Docker Engine API v1.55](https://docs.docker.com/reference/api/engine/version/v1.55/)
   defines request/response/error/version behavior.
2. [OCI Runtime v1.3.0](https://github.com/opencontainers/runtime-spec/tree/v1.3.0)
   defines applicable process/root/mount/namespace/resource/security semantics.
3. Linux syscall/kernel contracts define mechanisms. Storage uses
   [fsync](https://man7.org/linux/man-pages/man2/fsync.2.html),
   [syncfs](https://man7.org/linux/man-pages/man2/syncfs.2.html),
   [rename](https://man7.org/linux/man-pages/man2/rename.2.html),
   [ext4](https://docs.kernel.org/admin-guide/ext4.html) and
   [FUSE interruption](https://www.kernel.org/doc/html/latest/filesystems/fuse/fuse.html#interrupting-filesystem-operations).
4. Pinned Moby/reference Docker behavior resolves unspecified details through focused
   contracts or deterministic differentials. cengine exposes no OCI CLI/config.json.

Docker [volume population/lifetime](https://docs.docker.com/engine/storage/volumes/),
[restart policies](https://docs.docker.com/engine/containers/start-containers-automatically/)
and [live restore](https://docs.docker.com/engine/daemon/live-restore/) govern the
storage/recovery surface beneath OCI [mounts](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#mounts).
Linux [open](https://man7.org/linux/man-pages/man2/open.2.html),
[unlink](https://man7.org/linux/man-pages/man2/unlink.2.html) and
[waitpid](https://man7.org/linux/man-pages/man2/waitpid.2.html) distinguish retained
FD/process lifetime from names, transport status and daemon lifetime.

## Runtime semantics and OCI applicability

Covered denotes the stated subset; Partial records real limits. Host/storage
protocols implement Docker behavior beneath OCI mounts, not new OCI fields.

| OCI Runtime v1.3 area | Applicability / contracts | Limits |
|---|---|---|
| Process args, user/groups, cwd, environment, exec status | Covered: RTM-001/008/009/011/029/038–043/072/106/112, ORC-003/004 | Explicit exec overrides preserve namespace/root identity; no GroupAdd/ambient-set or per-probe health-log claim. |
| Terminal | Covered: CTR-031, RTM-030, CLI-009 | Docker height/width only; pixel dimensions stay zero. |
| Guest architecture | Partial: RTM-045 | Rosetta x86-64 ELF run/exec only, not i386 or cross-architecture build. |
| Root, read-only composition, mount ordering/confinement | Covered: RTM-002/003/020/022/023/031/046/048/049/056/105 | Source symlinks fail closed; confined intermediate workload links are distinct. |
| Host bind consistency | Partial: RTM-036/037/064–066/071, CMP-009 | Eventual coherence and completed-write fresh opens/content polling; no retained-FD atomicity, event-only watcher, host UID remapping or macOS differential claim. |
| Namespaces | Partial: RTM-001/012/016/017/033/044 | Separate VM kernels cannot share Docker-host/peer namespaces. Private/default and IPC none supported; no OCI namespace-path interface. |
| Capabilities, no-new-privileges, seccomp and path policy | Partial: RTM-006/014/018/021/024/025/028 | Built-in/unconfined seccomp only; custom JSON, AppArmor/SELinux and driver DeviceRequests unsupported. |
| Cgroup v2/resources | Partial: CTR-028/042/047, RTM-004/015/019/025–027/050 | CPU/memory/PIDs and real guest-device throttles/accounting; no cross-VM shares/weights, realtime, Docker cpuset inputs or live ulimit updates. Nested cpuset delegation is separate. |
| Wall clock | Covered: RTM-032 | Host wall-clock synchronization across start/resume/adoption; monotonic clocks remain VM-local. |
| Devices, sysctls, tmpfs and shm | Partial: RTM-022/024/025/033/034, NET-019 | Standard/attached guest devices only, not macOS passthrough; namespaced sysctls only. |
| Volume copy-up, identity, namespace and sync | Partial: RTM-053/054/058–070/075/076/078, VOL-020–023, CMP-040–045, ORC-020–025 | Direct/shared tests state their topology; VOL-006 is direct-only. Client-local locks are not distributed application locks. Invalid-copy/missing-subpath status classes intentionally differ. |
| Volume metadata/xattrs and execution | Partial: RTM-073/080/086/088/091/092 | Binary/empty user.*, valid ACL/capability and no-follow symlink subset; no arbitrary LSM/trusted namespace guarantee. |
| FUSE native request, write, sparse mmap and fsx | Scoped components: RTM-081–083/085/087/089/090 | Exact native completion/cleanup; not exhaustive POSIX, cross-VM corpus or general fault certification. |
| PREPARE initializer/identity/snapshot/liveness | Scoped components: RTM-093–095/101/102/104 | Initializer/direct-session proofs do not substitute deployed Session/Supervisor recovery; some component retirement callbacks are no-op. |
| Integrated PREPARE ambiguity/restart/error handling | Scoped deployed matrices: RTM-096–100 | API, worker and storage-VM death are separate selections; sticky errors prove containment, not liveness. Extra active-ACK/two-volume cuts are not matrix aggregates. |
| Original consumer retirement/isolation | Scoped RTM-103 campaign | Same-/cross-E original connections, retained FDs, registration and root-grant rejection; private fixture routes require authenticated observations, not diagnostics as authority. |
| DATA/retirement process-death recovery | Scoped components: RTM-107–110 | Kernel-alive ext4 components; no remount, VM-death or power-loss inference. Generic uncertainty remains refused. |
| Disk initialization and failed start | Partial: RTM-074/077 | Explicit initialization then mount-only; corrupt initialized disk refuses. Failed-start test does not check in-place userdata corruption. |
| Fresh lifecycle checkpoint/retirement | Scoped Guest RTM-113 and signed qualification RTM-114–116 | Fresh stores, actual physical HOST/ROOT only where stated; not DATA/drain or thousands of native VM cycles. |
| Ordinary shared DATA, live restore and worker replacement | Covered: RTM-117–125/127 | Positive births/exits and exact generation authority; original VMs survive daemon exit, not worker/storage replacement. |
| Host identity and cold recovery | Covered: RTM-126/128–133; normal installed OS reboot qualified separately | Fresh births and saved/new DATA, immutable store/history. No same-VM reboot survival, cloned-media provenance, power loss or fabricated ACK/death. |
| Annotations | Covered: CTR-048 | Runtime metadata, not injected environment variables. |
| OCI lifecycle CLI/hooks | Not applicable | Docker lifecycle uses cengine shim/guest control. Logs/admission/events (RTM-047/051/052/055), upgrade/fabric recovery (RTM-056/057) and Darwin host admission add no OCI configuration fields. |

## Volume contract and provenance

Existing data is authoritative; only an empty real ext4 `lost+found` is exempt from
copy-up emptiness checks. PREPARE serialization protects initialization, not
application locking. Volume removal is incarnation-bound and fail-closed: referenced
volumes refuse deletion, uncertain cleanup retains its fence/quarantine, and each
successful prune deletion commits separately. Recreating a name cannot restore old
contents. Completed-write synchronization, API live restore, kernel-alive process
death, storage-VM replacement and OS reboot are distinct durability boundaries.

Managed FUSE suppresses only origin-attachment DATA invalidations for a validated,
correlated successful full WRITE (including FUSE_WRITE_CACHE) or size SETATTR.
Linux updates its own cache for these operations; reverse-invalidation echo could
induce writeback loops. Payloads, volume identities and global sequences validate
before filtering; origin ATTR/ENTRY and all same-volume remote events remain
ordered. Errors, short/missing/mismatched replies and other operations never gain
this suppression. Authentication and durability are unchanged. See pinned Linux
[fuse_write_update_attr](https://github.com/gregkh/linux/blob/1efe5d048a391de3ead2804b2e7f86376c356cc5/fs/fuse/file.c),
[fuse_do_setattr](https://github.com/gregkh/linux/blob/1efe5d048a391de3ead2804b2e7f86376c356cc5/fs/fuse/dir.c)
and [fuse_reverse_inval_inode](https://github.com/gregkh/linux/blob/1efe5d048a391de3ead2804b2e7f86376c356cc5/fs/fuse/inode.c).

Curated upstream adaptations are **not wholesale suite ports**. Immutable source pins:

| Source | Immutable revision | Inventoried paths |
|---|---|---|
| Moby | [`fce9664cc153ea3da5a3057957a65be9bda30de8`](https://github.com/moby/moby/tree/fce9664cc153ea3da5a3057957a65be9bda30de8) | `integration-cli/docker_cli_run_test.go`, `integration-cli/docker_cli_volume_test.go`, `integration/volume/mount_test.go`, `integration/volume/volume_test.go` |
| Compose | [`e9491499f116984e00b89a39b53a8b28d33ad4c7`](https://github.com/docker/compose/tree/e9491499f116984e00b89a39b53a8b28d33ad4c7) | `pkg/e2e/volumes_test.go`, `pkg/e2e/recreate_no_deps_test.go` |
| Podman | [`e967db5f23d65df653790547ec6146fe8ccabd9f`](https://github.com/containers/podman/tree/e967db5f23d65df653790547ec6146fe8ccabd9f) | `test/e2e/run_volume_test.go`, `test/system/160-volumes.bats` |
| Rancher Desktop | [`a65e92ed4524e5be57be0c7fd16c999041fc239f`](https://github.com/rancher-sandbox/rancher-desktop/tree/a65e92ed4524e5be57be0c7fd16c999041fc239f) | `bats/tests/containers/volumes.bats` |

Actual corpus C sources, source/license hashes, selected cases, build inputs and
resource limits: [volume-corpus README](../Tests/Compatibility/fixtures/volume-corpus/README.md)
and [provenance manifest](../Tests/Compatibility/fixtures/volume-corpus/provenance.json).
Compose adaptations: [upstream-volume fixtures](../Tests/Fixtures/compose/upstream-volumes/README.md).
Offline application fixtures: [volume workflows](../Tests/Compatibility/fixtures/volume-workflows/README.md).
Moby/runc process ports retain the revision/path attribution in RTM-040–043.

Unported/unsupported scope remains explicit: exhaustive path normalization,
duplicate mount/precedence and CLI-format/filter/error matrices; generated `/etc`
interactions; combined copy-up/subpath sequencing; host-bind ownership/Unicode/case;
Compose config/secret adapters and exact build-volume fixtures; broad fsstress,
long-duration concurrency and arbitrary package managers. `VolumesFrom`, image/
cluster mounts, local-driver host mounts/options and cross-host propagation are not
substituted by ordinary named-volume tests. Podman `:O`, `:U`, `keep-id`, `nocreate`,
marker files and management CLI extensions are not Docker contracts. No upstream
factory reset, global prune or ambient reference-engine cleanup is imported.

The named `:copy` rejection follows pinned Moby
[copyModes](https://github.com/moby/moby/blob/fce9664cc153ea3da5a3057957a65be9bda30de8/daemon/volume/mounts/volume_copy.go)
and [mount parsing](https://github.com/moby/moby/blob/fce9664cc153ea3da5a3057957a65be9bda30de8/daemon/volume/mounts/linux_parser.go),
not Podman's copy extension. ORC-021 keeps exact parity assertions separate from
Docker 500/cengine 400 validation diagnostics.

`RTM-103` is a parent-owned original-consumer isolation campaign rather than a
pytest inventory row; see [its contract](rtm103-original-consumer-isolation.md).
`DGN-001`, `DGN-002` and `DGN-003` are diagnostic/calibration identifiers, not
compatibility passes; corpus/concurrency contracts require their formal tests.

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
but the newer option does not, and **Gap** identifies future work. This version assessment is separate from the pytest compatibility-ID inventory.

| API | Change affecting cengine's surface | Status | Notes |
|---|---|---|---|
| 1.42 | Volume prune defaults to anonymous volumes | Supported | All accepted cengine API versions inherit the safe anonymous-only default; `all=true` explicitly widens pruning to every unused local volume. |
| 1.44 | Registry login and image search automation deprecation | Supported | `POST /auth` validates credentials through the registry-v2 Basic or Bearer challenge flow, obtains an identity token when offered, and is covered against the pinned authenticated-registry fixture. `GET /images/search` follows Docker's legacy registry-v1 search contract across API v1.44–v1.55, including Docker Hub short-name normalization, HTTPS-first loopback custom registries, padded base64url registry credentials, scoped identity-token exchange, metadata headers, the default/validated result limit, and `is-official`/`stars` filtering. Responses are bounded, disconnected clients cancel the upstream request, and bypass-read pipelined input is capped at 1 MiB while a response is outstanding. The deprecated `is_automated` response is always false and `is-automated=true` returns no results. |
| 1.45 | Container network alias response semantics | Supported | v1.44 retains the short ID in `Aliases`; v1.45+ returns submitted aliases and uses `DNSNames` for runtime names. |
| 1.45 | Named-volume mount `VolumeOptions.Subpath` | Supported | Existing regular-file/directory subpaths are resolved beneath a retained named-volume descriptor. Intermediate and final symlinks fail before launch by design (`RTM-046`). |
| 1.45 | Image-inspect removal of `Container` and `ContainerConfig` | Supported | Cengine does not emit the removed legacy fields. |
| 1.46 | Containerd info, container annotations, endpoint sysctls, tmpfs options, push platform, and image-create events | Partial | Annotations persist from create/inspect, appear in list responses from v1.46, and enter the versioned guest runtime specification. Endpoint `DriverOpts` sysctls are validated, persisted, applied to the resolved guest interface, inspected only for v1.46+, and recovered (`NET-019`); current request DTOs remain accepted for older negotiated APIs. Pull/load events, tmpfs size/mode plus structured `exec`/`noexec` flags (`RTM-022`), and platform-selective push are supported. `Containerd` is omitted because cengine does not use containerd, and the builder-only image `create` event is inapplicable while direct build remains intentionally unsupported. |
| 1.47 | Image-list manifest summaries | Supported | `manifests=true` returns available, missing, image, and attestation manifest summaries. |
| 1.48 | Platform-aware history/load/save/push, image mounts, OCI descriptors/manifests, image-manifest descriptors, IPv4 network control, and gateway priority | Partial — intentional gap | Image operations, descriptor responses, endpoint gateway priority (`NET-016`, `RTM-012`), and explicit network IPv4 enable/disable (`NET-018`) are supported; pre-v1.48 requests retain legacy IPv4-enabled behavior. Image mounts remain explicitly rejected and require a separate demand-backed adoption decision. |
| 1.49 | Platform-specific image inspect and firewall backend info | Supported | JSON-encoded OCI platform selection and `manifests` conflicts are enforced. `FirewallBackend` is correctly omitted because cengine does not use Moby's Linux iptables/nftables backend. |
| 1.50 | Platform-selective image deletion and discovered-device info | Supported | Repeated JSON platform deletion preserves unselected variants; `DiscoveredDevices` is an empty array because cengine has no device-discovery drivers. |
| 1.50 | Removal of deprecated image-config fields | Supported | Cengine's image configuration already omits the removed runtime-only fields. |
| 1.51 | Image summary container usage count | Supported | v1.44-v1.50 report `-1`; v1.51+ calculate the number of containers using each image. |
| 1.52 | Event legacy-field removal and container/image response omissions | Supported | Responses branch at v1.52 while older API requests retain their legacy shape. |
| 1.52 | Container summary health and stats OS type | Supported | v1.52+ responses include `Health` and `os_type`. |
| 1.52 | Multi-platform image load/save, network IPAM status, event content negotiation, and verbose system disk usage | Supported | Repeated image selectors, versioned subnet allocation status (`NET-020`), event negotiation, and disk usage are supported. |
| 1.53 | NRI info, JSONL event negotiation, and image identity | Supported | Event streams and trusted pull/push origin identity are supported. `NRI` is correctly omitted because cengine has no Node Resource Interface integration. |
| 1.54 | Image-list identity and endpoint MAC application | Supported | `identity=true` implies manifest summaries and returns trusted origin data; explicit endpoint `MacAddress` is decoded, validated, applied in the guest, and inspected (`NET-014`, `NET-015`). Endpoint sysctls (`NET-019`) and gateway priority (`NET-016`, API 1.48) are also supported. |
| 1.55 | Image attestations and per-device blkio updates | Partial — intentional architecture gap | Attached in-toto statements support platform/type filters and statement opt-in. The four throttle arrays support any real guest block-device path: create applies them across API v1.44–v1.55, while v1.55 update treats omitted or null fields as unchanged and empty arrays as independent clears (reported as `max` by cgroup-v2 `io.max`); earlier update APIs strip these fields before typed decoding and ignore even malformed values (`RTM-015`, `RTM-025`). `BlkioWeightDevice` update has the same pre-v1.55 ignore behavior, but active create and v1.55 update requests return HTTP 501 because relative I/O scheduling cannot cross cengine's per-container VMs (`RTM-019`). |

### Explicit runtime input decisions

| Docker input | Intent | Behavior |
|---|---|---|
| create config `Domainname` | Support | The configured value persists and inspects exactly. A non-empty value enters the workload UTS namespace through the existing `kernel.domainname` sysctl path, while an explicit dot- or slash-spelled `HostConfig.Sysctls` assignment wins and remains independently visible in inspect (`RTM-044`). Omitted and empty values inspect as `""` and add no implicit sysctl. Non-DNS syntax and values longer than 64 bytes are accepted without host rewriting; Linux determines the effective runtime value. NUL, LF, and CR return HTTP 400 before mutation as a deliberate cengine sysctl-safety hardening. Docker's additional `/etc/hosts` FQDN formatting remains outside this bounded contract. |
| create config `ArgsEscaped`, `NetworkDisabled`, and `Shell` | Intentional gap | Active values that differ from cengine's fixed runtime behavior return HTTP 501; empty/default values are accepted. |
| create attachment routing flags | Support | `AttachStdout`, `AttachStderr`, and `StdinOnce` are accepted in both boolean forms. They configure client attachment behavior rather than the container's OCI/Linux runtime contract; cengine's attach endpoint and input-close handling remain authoritative. |
| `HostConfig.Init` | Support | Both boolean forms are accepted and reflected by inspect. cengine owns the fixed workload launch stage rather than selecting Docker's host-side init binary. |
| Docker `CpusetCpus`, `CpusetMems` | Intentional gap | Active create/update requests return pre-mutation HTTP 501: guest-vCPU IDs do not define host-CPU pinning and memory-node semantics are not adopted. `RTM-027` covers nested cpuset delegation inside one guest, not Docker cpuset inputs. |
| other unsupported create/update resource fields | Intentional gap | Active CPU shares/realtime, custom cgroup-parent, memory reservation/swap/swappiness, OOM-killer override, driver device requests, and Windows resource fields return HTTP 501. Docker's `MemorySwappiness=-1` and Buildx's `/docker/buildx` cgroup-parent defaults are accepted as inert in cengine's one-container-per-VM model. Supported memory, CPU quota/NanoCPUs, PID limits, and real guest-device block-I/O throttles retain their documented behavior. |
| `BlkioWeight`, `BlkioWeightDevice` | Intentional gap | Docker-relative weights require sibling containers to share one kernel block scheduler. Guest-only weights would not coordinate cengine's separate VM disks, and Virtualization.framework has no host-side equivalent, so active requests return HTTP 501 with an architecture-specific error (`RTM-019`). API v1.44–v1.54 updates ignore `BlkioWeightDevice` per Docker's historical version behavior; zero, empty, and inspect defaults remain inert. |
| `CgroupnsMode`, `IpcMode`, `PidMode`, `UTSMode`, and `UsernsMode` | Partial | Private/default cgroup, IPC, PID, and UTS selections plus host userns are persisted and inspected. IPC `none` creates a private IPC namespace without a generated `/dev/shm` mount and survives recovery; an explicit mount at that target still applies (`RTM-016`, `RTM-033`). IPC `shareable`, every Docker-host/cross-container sharing mode, and arbitrary namespace-path-shaped mode values fail before mutation (`RTM-017`). |
| `NetworkMode=host`, `NetworkMode=container:*`, and `HostConfig.Cgroup=container:*` | Intentional gap | A container cannot join a Docker-host or peer namespace across cengine's separate per-container VM kernels, so these requests return HTTP 501 before persistence (`RTM-017`). Malformed container references return HTTP 400. |
| runtime, process-group, OOM-score, and isolation overrides | Intentional gap | Inert values are accepted. Custom runtime/groups/storage options, non-default OOM score, and non-default isolation return HTTP 501; invalid values return HTTP 400. |
| `HostConfig.SecurityOpt` | Partial | Bare and boolean `no-new-privileges` selections persist, inspect, and apply to init, exec, and healthchecks across restart and recovery (`RTM-021`). Unprivileged containers use the built-in seccomp profile by default; `seccomp=builtin` and `seccomp=unconfined` persist, inspect, and select it explicitly, while privileged containers remain unconfined by default (`RTM-028`). Privileged `apparmor=unconfined` remains accepted for kind compatibility. Custom seccomp JSON is an **intentional gap**: well-formed custom profiles return HTTP 501 rather than being approximated. AppArmor and SELinux remain separate LSM gaps. |
| `HostConfig.Ulimits` | Partial | Create preserves submitted names/order and soft/hard values; supported limits apply case-insensitively to init, exec and healthchecks. Unsupported/duplicate/runtime-invalid limits fail at start with HTTP 500, leaving the container created (`RTM-014`, `ORC-004`). Empty updates are inert; non-empty live updates return pre-mutation HTTP 501. |
| `HostConfig.Devices`, `HostConfig.DeviceCgroupRules` | Support | Standard or attached virtio devices already present in the per-container Linux VM can be mapped to normalized `/dev` destinations with `rwm` permissions. Additive exact or wildcard custom rules extend the cgroup-v2 BPF policy. Create and live update persist and inspect the selection; updates atomically restore policy and nodes on failure (`RTM-025`). Arbitrary macOS device passthrough and driver `DeviceRequests` remain architecture gaps. |
| `HostConfig.ShmSize` | Support | Every nonnegative byte count is accepted; omitted or zero values select Docker's 64 MiB default. The effective value persists, inspects, and sizes a `nosuid,nodev,noexec` private/default IPC `/dev/shm` across restart and recovery. An explicit `/dev/shm` mount takes precedence; otherwise IPC `none` omits the generated mount while retaining the inspect value (`RTM-033`). |
| `HostConfig.Sysctls` | Partial | Docker/runc's namespaced `net.*`, `fs.mqueue.*`, selected IPC `kernel.*`, and `kernel.domainname` settings persist, inspect, and apply in the workload namespaces after endpoint sysctls (`RTM-034`). An explicit dot- or slash-spelled domain-name sysctl also takes precedence over the implicit `Config.Domainname` translation (`RTM-044`). Nonnamespaced and malformed names return HTTP 400 before mutation; cengine does not modify guest-global kernel settings. |
| `HostConfig.MaskedPaths`, `HostConfig.ReadonlyPaths` | Support | Absolute paths persist and inspect. Nil selects Docker's defaults, explicit empty lists disable them, and privileged mode clears them. Missing targets are ignored; file and directory masks plus recursive read-only binds are applied in the guest mount namespace and survive restart/recovery (`RTM-018`). Relative paths return HTTP 400. |
| bind propagation `shared`, `rshared`, `slave`, `rslave` | Intentional gap | Requests return HTTP 501 because virtiofs cannot establish the required host/container peer or master mount; `private` and `rprivate` remain supported. |
| `Mount.BindOptions.NonRecursive`, `ReadOnlyNonRecursive`, `ReadOnlyForceRecursive` | Support | Structured bind requests persist and apply source recursion plus top-level or recursive read-only behavior. Read-only mounts are recursively read-only by default; `ReadOnlyNonRecursive` selects a top-level-only remount and `ReadOnlyForceRecursive` forbids fallback. Conflicting read-only selections return HTTP 400 before mutation (`RTM-020`). |
| `Mount.TmpfsOptions.Options` | Support | API v1.46's structured `exec` and `noexec` flags persist, inspect only on v1.46+, and apply in the guest; omitted options select Docker's default `noexec` behavior, and the last submitted execution flag wins (`RTM-022`). Unknown options and non-flag-shaped arrays return HTTP 400 before mutation. |
| image/cluster/npipe mounts, mount consistency, volume labels, and SELinux/nocopy legacy options | Intentional gap | Recognized active requests return HTTP 501. Unknown mount types/options, mismatched option families, and malformed size/mode values return HTTP 400. |
| `Healthcheck.StartInterval` | Support | Effective values persist and inspect. While health is `starting` within `StartPeriod`, probes use `StartInterval`; after a successful probe or grace expiry they use `Interval`. Failures during the starting grace period do not increment the streak (`RTM-035`). |
| image healthcheck inheritance | Support | Omitted or empty container tests inherit the image command, scalar fields merge independently, and remaining zero/missing values receive Docker defaults. `Test=["NONE"]` disables inherited checks. The effective configuration persists across restart and daemon recovery (`RTM-035`). Invalid test forms and sub-millisecond durations return HTTP 400. |
| container `AttachStdin` | Support | The requested attach configuration is persisted and returned by inspect; `OpenStdin` continues to control whether the guest input remains open. |
| exec `DetachKeys` | Intentional gap | Non-empty custom detach-key requests return HTTP 501. |
| create/exec `ConsoleSize` | Support | Two-element `[height,width]` values are accepted for container create, exec create, and exec start. Container create persists the submitted size for inspect even when `Tty=false`; terminal workloads apply non-zero sizes, exec start overrides exec create, and omitted or `[0,0]` values use the prior configured size or the 24x80 PTY default. Malformed, negative, and values above 65535 return HTTP 400 before mutation (`RTM-030`, `CLI-009`). |
| exec-start `Tty` | Support | When supplied, the value must match the TTY mode selected when the exec was created; mismatches return HTTP 400. |

## Runtime semantics

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `RTM-001` | `test_init_and_default_exec_share_runtime_context` | Covered | Support | Init and default exec share mount, PID, UTS, IPC, network, and cgroup namespaces; root identity; hostname; cwd; user and supplementary groups; environment; capability masks; and `NoNewPrivs`. Exec stage descriptors do not leak, Docker's default leaves `NoNewPrivs=0`, an explicitly privileged exec retains an unprivileged container's default seccomp profile, and default exec inherits a privileged container's unconfined effective privilege. |
| `RTM-002` | `test_read_only_root_applies_to_exec_but_tmpfs_stays_writable` | Covered | Support | Start does not report success before the workload root is ready for an immediate exec. Exec cannot write through a read-only workload root while an explicitly writable tmpfs remains writable. |
| `RTM-003` | `test_nested_docker_exec_and_healthcheck_without_kind` | Covered | Support | Pinned Docker 29.6.2 DinD loads the cached pinned Alpine archive, starts a nested container at `/data`, executes into it, and reaches `healthy` without kind or another registry pull. |
| `RTM-004` | `test_pids_limit_enforces_live_updates_and_survives_recovery` | Covered | Support | Docker `PidsLimit` create/inspect/update semantics drive cgroup-v2 `pids.max`; lowering to the live process count prevents exec, raising the limit restores exec, and the configured limit survives daemon recovery. Docker API `0` and `-1` unlimited values map to Linux `max`. See the [Docker API update contract](https://docs.docker.com/reference/api/engine/version-history/#v140-api-changes) and [OCI Linux PID resources](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#control-groups). |
| `RTM-005` | `test_unrealizable_bind_mount_propagation_is_rejected` | Covered | Intentional gap | Private and recursive-private bind modes remain supported. Shared/slave modes require a real peer/master mount across the host/container boundary, which macOS virtiofs cannot provide, so `shared`, `rshared`, `slave`, and `rslave` return HTTP 501 instead of exposing a marker-only mount. See [Docker bind propagation](https://docs.docker.com/engine/storage/bind-mounts/#configure-bind-propagation) and [`mount(2)` shared-subtree operations](https://man7.org/linux/man-pages/man2/mount.2.html). |
| `RTM-006` | `test_capability_add_drop_apply_to_init_and_exec` | Covered | Support | Docker's default Linux capability set is used for unprivileged root workloads; case-insensitive `CapAdd`/`CapDrop`, optional `CAP_` prefixes, and `ALL` are normalized, drops are applied before additions, and the result is applied to bounding/permitted/effective sets for init and default exec. Privileged workloads and privileged exec retain all capabilities. See [Docker Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities) and [OCI process capabilities](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#process). |
| `RTM-007` | `test_container_prune_honors_filters_and_rejects_unknown_keys` | Covered | Support | Container prune applies one Docker `until` cutoff, conjunctive positive-label filters, and negated-label filters before deletion. Legacy map-shaped filter keys remain active regardless of their boolean payload. Unknown, malformed, or ambiguous filters fail without deleting any container instead of silently broadening prune scope. See the [Docker container prune API](https://docs.docker.com/reference/api/engine/version/v1.52/#tag/Container/operation/ContainerPrune). |
| `RTM-008` | `test_exec_stage_proxies_preserve_status_and_kill_timed_out_healthchecks` | Covered | Support | Exec staging processes preserve target exit codes and proxy catchable signals. Exec inspect publishes the final target's workload-namespace PID rather than a staging proxy's outer PID. Each exec target receives a dedicated cgroup-v2 leaf, and timed-out healthchecks write `1` to that leaf's `cgroup.kill`, recursively terminating both the target and descendants without affecting sibling execs. See the [Linux cgroup-v2 `cgroup.kill` contract](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files) and [OCI Linux control groups](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#control-groups). |
| `RTM-009` | `test_attached_exec_inspect_publishes_pid_and_terminal_status` | Covered | Support | An attached exec remains pending while its guest state is `starting` or `running`, publishes its final target PID asynchronously without blocking HTTP stream activation, and transitions inspect to the terminal exit code without losing that PID, including when the target exits before its PID publication is committed. A launch failure after stream upgrade becomes terminal instead of reverting to a permanently created host record. See the [Docker exec inspect API](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Exec/operation/ExecInspect) and [OCI process lifecycle](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/runtime.md#lifecycle). |
| `RTM-010` | `test_paused_stop_restart_and_force_remove_complete` | Covered | Support | Stop, restart, and forced removal resume a paused VM before sending guest process signals, then use a bounded forced-shutdown fallback so lifecycle requests cannot wait forever on a suspended guest. Restart returns the workload to a responsive running state. |
| `RTM-011` | `test_parent_stop_and_restart_terminalize_attached_and_detached_execs` | Covered | Support | Parent stop and restart close attached streams and reconcile every attached and detached child exec from the old execution generation to a bounded-eventual terminal inspect state, preserving its PID and using exit code 137 when VM teardown makes the final guest status unavailable. Detached exec inspect publication may briefly trail parent control completion. The restarted parent is responsive to a new exec after the old exec records become terminal. See the [Docker exec inspect API](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Exec/operation/ExecInspect) and [OCI process lifecycle](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/runtime.md#lifecycle). |
| `RTM-012` | `test_default_routes_are_selected_per_address_family` | Covered | Support | A container attached to separate IPv4-only and IPv6-only networks retains one default route for each family even when the endpoint priorities differ. This matches [Moby's independent IPv4 and IPv6 gateway endpoint selection](https://github.com/moby/moby/blob/docker-v29.0.0/integration/network/network_linux_test.go#L446-L541). |
| `RTM-013` | `test_active_unsupported_runtime_inputs_fail_closed` | Covered | Intentional gap | Runtime-bearing API v1.55 fields are decoded across container create/update, Linux resources and namespaces, mounts, healthchecks, and exec create/start. Inert zero/default forms remain accepted, while recognized active gaps return HTTP 501 before container, anonymous-volume, resource, or exec mutation. Malformed or contradictory recognized values return HTTP 400, and unknown extension keys remain tolerated. See Moby's [container config](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/container/config.go), [host resources/config](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/container/hostconfig.go), [mount request](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/mount/mount.go), and [exec create](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/container/exec_create_request.go) and [start](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/container/exec_start_request.go) definitions. |
| `RTM-014` | `test_ulimits_apply_to_init_exec_healthchecks_and_survive_recovery` | Covered | Support | Create-time Docker ulimits are preserved in request order and original name casing, inspected, persisted, and applied case-insensitively with Linux `setrlimit` to init, exec, and healthcheck processes. Limits survive daemon recovery and container stop/start without constraining the guest supervisor or exec signal/status proxies. As Docker does, unsupported names, duplicates, and runtime-invalid signed values or soft/hard relationships still create the container and anonymous volumes; Linux/runtime validation then makes start return HTTP 500 while the container remains created (`ORC-004`). Non-empty update-time ulimits remain an explicit HTTP 501 gap. See [Docker `--ulimit`](https://docs.docker.com/reference/cli/docker/container/run/#set-ulimits-in-container---ulimit), [OCI process rlimits](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#posix-process), and [`getrlimit(2)`/`setrlimit(2)`](https://man7.org/linux/man-pages/man2/ugetrlimit.2.html). |
| `RTM-015` | `test_block_io_throttles_apply_update_enforce_and_survive_recovery` | Covered | Support | Four real-guest-device BPS/IOPS arrays enforce cgroup-v2 io.max and survive restart/recovery. v1.55 omitted/null is unchanged, empty independently clears to max; v1.44–54 ignores fields before typed decoding. Invalid paths/rates/duplicates return 400. Durable old/desired journal plus generation-owned shim identity make scalar/device updates transactional: prove restoration or remain fenced/rollback-incomplete. Recovery reapplies the durable old selection; uncertain termination preserves writable roots and blocks reuse. RTM-025 adds nonroot attached-volume coverage. |
| `RTM-016` | `test_ipc_none_omits_shared_memory_and_survives_recovery` | Covered | Support | Accepted private/default cgroup, IPC, PID, and UTS selections plus host userns persist and inspect. Docker IPC `none` creates a private IPC namespace without generating a `/dev/shm` mount; an explicit mount at that target remains available. See Docker's [`--ipc` modes](https://docs.docker.com/reference/cli/docker/container/run/#ipc-settings---ipc) and [OCI Linux namespace creation](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#namespaces). |
| `RTM-017` | `test_same_kernel_namespace_sharing_fails_closed` | Covered | Intentional gap | Docker-host and cross-container cgroup, IPC, PID, UTS, and network sharing return HTTP 501 before container or anonymous-volume mutation because separate per-container VM kernels cannot join the same Linux namespace. Arbitrary path-shaped Docker mode values return HTTP 400. OCI namespace paths are not exposed through the Docker API or an OCI runtime CLI. See Docker's [namespace mode semantics](https://docs.docker.com/reference/cli/docker/container/run/) and [OCI namespace paths](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#namespaces). |
| `RTM-018` | `test_masked_and_readonly_paths_apply_restart_and_survive_recovery` | Covered | Support | MaskedPaths/ReadonlyPaths persist across restart/recovery: nil selects defaults, empty disables, privileged clears, missing targets ignore, relative paths return 400. Files use a verified /dev/null descriptor, directories read-only tmpfs; read-only paths preserve nosuid/nodev/noexec. Named identities resolve before masking; passwd/group snapshots preserve later exec resolution. |
| `RTM-019` | `test_block_io_weights_are_an_architecture_gap_with_versioned_update_semantics` | Covered | Intentional gap | Cross-VM relative block scheduling is unavailable. Active BlkioWeight create/update and BlkioWeightDevice create/v1.55 update return 501 before mutation; v1.44–54 update ignores BlkioWeightDevice before decoding. Inert defaults remain inspectable; malformed recognized values return 400. |
| `RTM-020` | `test_bind_recursion_and_readonly_modes_apply_restart_and_survive_recovery` | Covered | Support | Structured bind mounts persist Docker's `NonRecursive`, `ReadOnlyNonRecursive`, and `ReadOnlyForceRecursive` selections and apply them. Bind creation uses `MS_BIND` or `MS_BIND|MS_REC`; read-only binds default to recursive `mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY)`, the non-recursive option remounts only the bind root, and the force option forbids compatibility fallback. The applied read-only/writable state survives container restart and daemon recovery. Contradictory read-only modes return HTTP 400 before container or anonymous-volume mutation. See Moby v29.6.2's [bind option definitions](https://github.com/moby/moby/blob/docker-v29.6.2/api/types/mount/mount.go) and [OCI mount option selection](https://github.com/moby/moby/blob/docker-v29.6.2/daemon/oci_linux.go#L595-L618), plus Linux [`mount_setattr(2)`](https://man7.org/linux/man-pages/man2/mount_setattr.2.html). |
| `RTM-021` | `test_no_new_privileges_security_option_applies_restart_and_survives_recovery` | Covered | Support | Bare/boolean no-new-privileges persists and applies to init/default/privileged exec and healthchecks across restart/recovery; omitted defaults to disabled. Seccomp selection is independent, including explicit false with builtin. Invalid boolean returns 400; unsupported profiles return 501. |
| `RTM-022` | `test_structured_tmpfs_execution_options_apply_restart_and_survive_recovery` | Covered | Support | Structured tmpfs mounts are writable but `noexec,nosuid,nodev` by default. API v1.46's `TmpfsOptions.Options` accepts the Docker/Moby `exec` and `noexec` flags, persists and inspects their submitted order, applies the last execution flag in the guest, and survives container restart and daemon recovery. API v1.45 inspect omits the later `Options` field. Unknown options and non-flag-shaped arrays return HTTP 400 before container or anonymous-volume mutation. See Moby v29.0.0's [tmpfs option API shape](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/mount/mount.go#L116-L151), [accepted execution flags](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/volume/mounts/linux_parser.go#L230-L249), and [Docker default tmpfs flags](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/oci_linux.go#L521-L534), plus Linux [`mount(2)`](https://man7.org/linux/man-pages/man2/mount.2.html). |
| `RTM-023` | `test_volume_readonly_matrix_orders_nested_mounts_and_survives_recovery` | Covered | Support | User mounts are applied parent-before-child regardless of request order so a parent cannot hide a nested mount. A read-only root remains immutable while explicitly writable named volumes stay writable; read-only volumes are recursively read-only, and a later writable child mount remains writable beneath a read-only parent. The matrix covers both direct ext4 block volumes and managed shared FUSE volumes for init and exec across container restart and daemon recovery. See Moby v29.6.2's [mount depth ordering and recursive read-only selection](https://github.com/moby/moby/blob/docker-v29.6.2/daemon/oci_linux.go#L479-L638), OCI Runtime Spec v1.3.0 [read-only root](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#root) and [ordered mount](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#mounts) requirements, and Linux [`mount_setattr(2)` recursive read-only semantics](https://man7.org/linux/man-pages/man2/mount_setattr.2.html). |
| `RTM-024` | `test_default_device_policy_blocks_vm_disks_and_survives_recovery` | Covered | Support | Unprivileged cgroups enforce Docker/runc device BPF policy before process placement: standard devices/PTYs allow rwm, arbitrary nodes allow mknod but not opening VM disks (EPERM). Exec/restart/recovery preserve policy; transient verifier EAGAIN retries. Privileged remains unrestricted. |
| `RTM-025` | `test_configured_devices_custom_rules_nonroot_io_and_stats_survive_recovery` | Covered | Support | Devices/DeviceCgroupRules resolve descriptor-safely inside the guest VM, not macOS. Exact/wildcard additive rwm policy, node clear/restore and nonroot volume io.max/accounting persist across restart/recovery. Failed live update restores nodes/policy/resources/durable records or fails closed. No arbitrary host passthrough/DeviceRequests. |
| `RTM-026` | `test_privileged_cgroup_delegation_and_workload_wide_accounting` | Covered | Support | The container cgroup becomes the cgroup-namespace root before init moves to `.cengine-init`, leaving the namespace root process-free with `cpu`, `io`, `memory`, and `pids` delegated. Privileged workloads can create a nested child, set controller limits, and place a process there; unprivileged workloads retain a read-only cgroup mount. Docker stats aggregate the workload root and all init/exec/nested descendants through `cpu.stat`, `memory.current`, `memory.peak`, `memory.stat`, `pids.current`, and per-device `io.stat`. Delegation remains usable after restart and daemon recovery. See Linux's [cgroup-v2 delegation and no-internal-process rules](https://docs.kernel.org/admin-guide/cgroup-v2.html#delegation) and OCI Runtime Spec v1.3.0 [control groups](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#control-groups). |
| `RTM-027` | `test_privileged_cpuset_delegation_reaches_private_cgroup_namespace` | Covered | Support | When the kernel exposes `cpuset`, cengine enables it at the unified root, the process-free `cengine` parent, and the process-free workload namespace root. The privileged container sees `cpuset` in both `cgroup.controllers` and `cgroup.subtree_control`, inherits non-empty effective CPU and memory-node masks, and can create a child with `cpuset.cpus` and `cpuset.mems`, configure those masks, and move a process into it. This supplies the cpuset files expected by nested kubelet Node Allocatable cgroups without hard-coding VM topology. See Linux's [cgroup-v2 controller enabling, top-down constraint, and cpuset inheritance](https://docs.kernel.org/admin-guide/cgroup-v2.html#controllers). |
| `RTM-028` | `test_default_seccomp_applies_to_init_exec_healthcheck_restart_and_recovery` | Covered | Support | Arm64 Docker builtin seccomp applies to init/exec/healthchecks across restart/recovery; privileged defaults unconfined, explicit builtin/unconfined persists. EPERM default, capability rules, clone masking, clone3 ENOSYS and architecture refusal remain. AArch32 and custom JSON unsupported; custom JSON returns 501. |
| `RTM-029` | `test_exec_create_racing_init_exit_reports_container_not_running` | Covered | Support | Backend completion is published before its VM shim is stopped, so an exec-create request racing init exit receives HTTP 409 with Docker's container-not-running error instead of an internal guest-control or VM-shim failure. Final container and exec output is drained before teardown. See Docker's [`docker container exec` lifecycle contract](https://docs.docker.com/reference/cli/docker/container/exec/) and the [OCI process lifecycle](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/runtime.md#lifecycle). |
| `RTM-030` | `test_console_size_applies_to_container_and_exec_ptys` | Covered | Support | Container/exec ConsoleSize is [height,width]; nonzero exec-start overrides create, omitted/[0,0] retains configured or 24x80 default. Live resize uses TIOCSWINSZ/SIGWINCH. Malformed/negative/>65535 returns 400 before mutation; pixel dimensions are not exposed. |
| `RTM-031` | `test_image_label_filters_isolate_testcontainers_cleanup_sessions` | Covered | Support | Image-list `label=key` and `label=key=value` filters match the selected image configuration and return those labels in summary responses. A nonexistent Testcontainers session selects no cached image, so Ryuk cannot delete unrelated shared images. In parallel, explicit forced removal and image pruning treat a pending container create as an active consumer until backend rootfs preparation finishes, preventing content-store pruning from invalidating an in-flight layer stream. See Docker API v1.55 [image list filters](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Image/operation/ImageList) and the OCI Runtime Spec [root filesystem contract](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#root). |
| `RTM-032` | `test_guest_wall_clock_is_synchronized_across_vm_lifecycle` | Covered | Support | Each container VM receives the host wall clock before startup returns, immediately after resume, and every 30 seconds while running. Startup synchronization failure tears down the VM. Resume synchronization failure first re-pauses the VM; if re-pause also fails, cengine durably quarantines that exact shim generation before verified teardown. Each update uses a fresh virtio-socket connection with a one-second absolute I/O deadline. The black-box contract brackets Linux file mtimes with the host clock across four fresh VMs, pause/resume, abrupt daemon restart with adoption of the same shim generation, and post-recovery pause/resume. See Linux [`settimeofday(2)`](https://man7.org/linux/man-pages/man2/settimeofday.2.html), [`gettimeofday(2)`](https://man7.org/linux/man-pages/man2/gettimeofday.2.html), and [`stat(2)` timestamp semantics](https://man7.org/linux/man-pages/man2/stat.2.html). |
| `RTM-033` | `test_shared_memory_size_applies_restart_and_survives_recovery` | Covered | Support | Docker `HostConfig.ShmSize` accepts every nonnegative byte count, with omitted or zero values selecting Docker's 64 MiB default. The effective value persists and inspects, sizes the private IPC namespace's `nosuid,nodev,noexec` `/dev/shm` tmpfs across stop/start and daemon recovery. An explicit mount at `/dev/shm` takes precedence, including under IPC `none`; without that override, IPC `none` retains the configured inspect value but intentionally omits the generated mount (`RTM-016`). Negative values return HTTP 400 before container or anonymous-volume mutation. See Docker's [`--shm-size`](https://docs.docker.com/engine/containers/run/#runtime-constraints-on-resources) and the OCI Runtime Spec [mount contract](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#mounts). |
| `RTM-034` | `test_namespaced_sysctls_apply_after_endpoint_settings_and_survive_recovery` | Covered | Support | Namespaced runc-allowlisted sysctls persist and apply after endpoint IFNAME settings, before path policy/privilege drop, surviving restart/recovery. Dot/slash paths select proc components without a shell. Nonnamespaced, malformed/traversal/NUL/newline inputs return 400 before mutation. |
| `RTM-035` | `test_health_start_interval_image_inheritance_restart_and_recovery` | Covered | Support | Docker/OCI image `Healthcheck` metadata is ingested and merged field-by-field with container-create overrides; an empty or omitted test inherits the image command, while `Test=["NONE"]` disables it. Effective interval, timeout, retries, start period, and start interval persist and inspect. While a new execution remains `starting` inside its start period, `StartInterval` schedules probes and failures do not increment the streak; a success or grace expiry selects the regular interval. Explicit restart resets health to `starting`, and daemon recovery resumes monitoring the adopted execution without losing effective configuration. See Docker's [healthcheck image metadata](https://github.com/moby/moby/blob/docker-v29.6.2/api/types/container/health.go) and [`HEALTHCHECK` command](https://docs.docker.com/reference/dockerfile/#healthcheck). |
| `RTM-036` | `test_bind_directory_mutations_stay_coherent_across_restart_and_recovery` | Covered | Support | Directory binds reflect final contents/create/modify/atomic replace/rename/delete both ways across restart/adoption; RO views reject writes. Host readers see whole guest replacements, but racing guest reads may see partial host-originated generations: use stable-content polling. No single-file inode retargeting, shared propagation, Unicode/case, source-link, ownership or arbitrary metadata-fidelity claim; RTM-071 covers completed-write fresh opens. |
| `RTM-037` | `test_bind_content_polling_watcher_observes_edits_across_recovery` | Covered | Support | Content-hash polling debounces two equal reads at 200ms, observes distinct host in-place/atomic edits within 10s, and survives restart/adoption. Functional bound, not performance SLA or inotify/FSEvents mask/order/event-only watcher guarantee. RTM-071 covers fresh opens. |
| `RTM-038` | `test_invalid_init_and_exec_identities_fail_without_leaking_stages` | Covered | Support | Numeric and named users/groups resolve from the workload identity files even after those files are masked. Missing init identities fail at start with Docker's server-error class and leave the container created but not running; missing exec identities are rejected during exec creation with HTTP 400. `ORC-003` compares that failure phase and status directly against the selected Docker reference. Rejected exec creation leaves no per-exec artifacts. See OCI Runtime Spec v1.3.0 [`process.user`](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#posix-process) and Moby docker-v29.6.2 `integration/container/exec_test.go::TestExecUser`. |
| `RTM-039` | `test_explicit_exec_context_overrides_and_omitted_values_inherit` | Covered | Support | Omitted exec user/group, cwd, environment, capabilities, and no-new-privileges state inherit the container context. Explicit user/group, cwd, environment, TTY, and privileged selections override only their Docker-defined fields while preserving the workload namespace and root identities. Stage descriptors remain closed and exec inspect retains the authoritative final target PID and exit 23. See Docker's [exec-create API](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Exec/operation/ExecCreate) and OCI Runtime Spec v1.3.0 [process properties](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config.md#process). |
| `RTM-040` | `test_moby_exec_identity_exit_and_close_stdin_ports` | Covered | Support | Pinned upstream adaptation. Ports Moby docker-v29.6.2 `integration/container/exec_test.go::{TestExec,TestExecWithCloseStdin,TestExecUser}` and `integration/container/exec_linux_test.go::TestFailedExecExitCode` through cengine's Docker API. It checks inspect identity, cwd/environment overrides, image-defined supplementary groups, stdin EOF, and exit 127 versus 126 without importing daemon internals. `TestExecWithGroupAdd` is excluded because Docker `GroupAdd` remains an explicit pre-mutation gap. |
| `RTM-041` | `test_runc_capability_and_rlimit_ports` | Covered | Support | Pinned upstream adaptation. Ports the applicable runc v1.3.3 `tests/integration/capabilities.bats` “runc run with some capabilities” and `tests/integration/rlimits.bats` smaller-than-system-hard-limit run/exec cases. Docker `CapDrop=ALL` plus `CapAdd=SYS_ADMIN`, no-new-privileges, and NOFILE soft/hard limits produce the expected init and exec process state. Arbitrary ambient sets are excluded because the Docker surface does not expose them. |
| `RTM-042` | `test_runc_masked_path_and_readonly_bind_ports` | Covered | Support | Pinned upstream adaptation. Ports runc v1.3.3 `tests/integration/mask.bats::{mask paths [file],mask paths [directory]}` and the Docker-representable request shapes from `tests/integration/mounts_recursive.bats`. Masked files/directories deny access, a top-level-only read-only bind leaves a later explicit child mount writable, and a force-recursive request makes the supplied top level read-only. This bounded port does not claim recursive enforcement over a pre-existing Linux nested mount because that source topology cannot be fabricated across macOS virtiofs. Shared propagation remains a pre-mutation HTTP 501 architecture gap. |
| `RTM-043` | `test_moby_ipc_shm_health_ports` | Covered | Support | Pinned upstream adaptation. Ports distinct observations from Moby docker-v29.6.2 `integration/container/run_linux_test.go::TestContainerShmSize` and `integration/container/health_test.go::TestHealthCheckWorkdir`. The configured private `/dev/shm` enforces capacity and healthchecks inherit the container cwd. `TestHealthCheckProcessKilled` remains excluded because cengine does not yet retain Docker's per-probe health log. |
| `RTM-044` | `test_domainname_persists_applies_precedence_restart_and_recovery` | Covered | Support | Domainname persists exactly and applies through kernel.domainname in UTS; explicit dot/slash Sysctls wins while inspect fields stay distinct. Empty adds nothing, Linux controls effective length/syntax, NUL/LF/CR return 400. Survives restart/adoption; no additional /etc/hosts FQDN formatting claim. |
| `RTM-045` | `test_amd64_containers_run_and_exec_via_rosetta` | Covered | Support | Docker linux/amd64 run and exec use Rosetta for Linux with x86-64 ELF binfmt OCF flags. Missing host Rosetta fails start with an actionable error. No i386/other architecture or cross-architecture build claim. |
| `RTM-046` | `test_volume_copyup_and_subpaths_reject_symlink_escape_across_recovery` | Covered | Support | Copy-up/subpath/destination lookup stays descriptor-rooted. Volume sources reject final/intermediate symlinks via openat2/no-follow fallback; workload targets allow confined intermediate links. Identity/file-handle journals, fsync and RENAME_NOREPLACE protect copy-up/recovery; files, directories, literal symlinks, hardlinks and supported metadata remain supported, special nodes refuse. |
| `RTM-047` | `test_retained_logs_stay_bounded_and_recover` | Covered | Support | Container Docker-log history and the shim-owned stdout/stderr downtime spool are each capped at a 64 MiB suffix, individual records/chunks at 1 MiB, and follower pending writes at 4 MiB. The shim durably publishes its cursor before filesystem-block-aligned source hole punching; shim and daemon serialize segment mutation across processes, and the daemon commits spool bytes to the checksummed immutable journal before deleting acknowledged segments. Journal checkpoints preserve current source-session offsets, oversized/corrupt persisted files fail boundedly, and restart returns the same retained suffix without replay. TTY bytes and Docker multiplex framing/filter semantics are unchanged. See Docker's [`logs` API](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Container/operation/ContainerLogs). |
| `RTM-048` | `test_registry_streams_valid_blob_and_rejects_descriptor_size_mismatch` | Covered | Support | Registry manifests/configs, tokens, and error bodies have independent response bounds. Blob bytes stream into owner-only CAS-local temporary files and are counted and SHA-256 hashed before fsync/rename; exact descriptor size and digest, strict present `Content-Length`, cache identity, graph depth/count/aggregate limits, cycles, and conflicting repeated descriptors are checked before a tag is published. See OCI Image Spec [descriptors](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md). |
| `RTM-049` | `test_archive_copy_roundtrip_rejects_link_traversal_and_expansion` | Covered | Support | Docker copy/load extraction uses one bounded ustar/GNU/PAX pass rooted at a retained destination descriptor. Checksums, octal/base-256 numerics, paths, links, entry/metadata/file/expanded/wire quotas, duplicate/type conflicts, special nodes, symlink parents, and forward/escaping hard links are rejected before backend mutation; ordinary ownership, links, and copy round trips remain supported. See Docker [archive APIs](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Container/operation/PutContainerArchive) and OCI [image layout](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md). |
| `RTM-050` | `test_extreme_cpu_values_fail_without_mutation` | Covered | Support | Central exact arithmetic handles signed/unsigned conversion, add/multiply, addition-free ceiling division, and tar alignment. Docker NanoCPU/period/quota conflicts and overflows return HTTP 400 before container/update mutation; representable fractional values retain integer-vCPU ceiling semantics and inspect safely. See Docker [resource update](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Container/operation/ContainerUpdate) and OCI [CPU resources](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#cpu). |
| `RTM-051` | `test_global_connection_and_upload_admission_recovers_capacity` | Covered | Support | Primary and scoped Unix listeners share limits for connections, active requests, retained body bytes, uploads/downloads, expensive operations, and long-lived streams. Content lengths are canonical and pre-admitted, chunked bodies reserve before retention, and admitted image/archive uploads spool owner-only. Transient excess uploads wait with socket backpressure without allocating a spool file, while oversized requests and other saturated classes retain their 413/429/503 responses. Idempotent leases and canceled upload waiters return capacity on completion/disconnect. This is Docker HTTP transport behavior, not an OCI runtime field. |
| `RTM-052` | `test_scoped_socket_authenticates_owner_descendants_and_cleans_on_exit` | Covered | Support | Scope ownership comes from Darwin `getpeereid`/`LOCAL_PEERPID` plus `proc_pidinfo` PID/start/UID identity; a legacy body PID must exactly match. Scoped sockets authorize the stable owner or a bounded proven descendant chain, enforce global/UID/owner/child quotas, and are removed when the exact owner exits. Unrelated same-UID processes receive 403. See Darwin [`getpeereid(3)`](https://keith.github.io/xcode-man-pages/getpeereid.3.html) and [`proc_pidinfo(3)`](https://keith.github.io/xcode-man-pages/proc_pidinfo.3.html); OCI is not applicable. |
| `RTM-053` | `test_named_volume_copyup_preserves_root_metadata_and_existing_data` | Covered | Support | Direct/shared copy-up preserves empty/populated image-root UID/GID and special modes; nonroot creation works. NoCopy and existing nonempty data preserve root metadata/content. |
| `RTM-054` | `test_shared_volume_enforces_caller_ownership_permissions_and_groups` | Covered | Support | Shared consumers enforce caller UID/GID, supplementary groups and setgid inheritance; denied read/write/truncate/chmod/chown, close/reopen, restart and concurrent caller isolation are checked. |
| `RTM-055` | `test_default_events_do_not_replay_deleted_containers` | Covered | Support | Default event subscriptions are live-only: deleted-container history is not replayed. Explicit since/until history remains supported. |
| `RTM-056` | `test_same_path_upgrade_refuses_old_writer_then_preserves_data_and_egress` | Covered | Support | Same-path executable upgrade rejects old live infrastructure without mutation; strict native retirement/recreation preserves writable-root/shared-volume data, network identity, restart policy and carrier/DNS/TCP egress. Replacement signing must preserve the paired helper identity contract. |
| `RTM-057` | `test_identical_failed_fabric_retries_reach_helper_then_restore_real_egress` | Covered | Support | Identical invalid-gateway requests each reach the helper and fail without changing persisted network metadata. Valid retry preserves infrastructure identity and restores existing/new endpoint egress. |
| `RTM-058` | `test_volume_lost_found_data_remains_authoritative` | Covered | Support | Existing lost+found data, or a non-directory entry of that name, prevents copy-up and root metadata replacement. Only an empty real ext4 lost+found directory is ignored. |
| `RTM-059` | `test_shared_volume_sync_and_cross_consumer_readback` | Covered | Support | Synced external acknowledgments precede API-daemon SIGKILL/adoption; adopted peers read saved bytes and exchange new writes. Storage/workload VMs remain alive: not storage-VM crash or power-loss proof. |
| `RTM-060` | `test_empty_nocopy_volume_is_populated_by_later_copy` | Covered | Support | Structured NoCopy leaves an empty volume; a later copy-enabled consumer populates it. Direct consumers are removed before replacement; no late live promotion claim. |
| `RTM-061` | `test_same_volume_alias_destinations_share_mutations` | Covered | Support | Two destinations for the same direct/shared volume observe the same writes and renames. Mount aliasing is distinct from retained-handle identity. |
| `RTM-062` | `test_volume_file_subpath_over_new_and_existing_targets` | Covered | Support | Existing regular-file subpaths mount read-only over new and existing targets on direct/shared volumes. |
| `RTM-063` | `test_missing_volume_subpath_fails_at_start` | Covered | Support, status difference | Missing subpath fails at start before workload output. A root-mounted consumer confirms absence, creates it, and the identical workload then starts. Managed shared refusal is HTTP 409, not Docker's 404/500 class; only the exact closed refusal is accepted. |
| `RTM-064` | `test_missing_bind_source_legacy_creates_but_mount_rejects` | Covered | Support | Legacy Docker Binds creates a missing host directory; structured Mounts rejects it before workload I/O and leaves it absent. The distinction is between Docker request formats. |
| `RTM-065` | `test_bind_paths_with_spaces_and_nonascii` | Covered | Support | Host bind paths with spaces/non-ASCII support guest writes and host readback without shell interpolation. No general Unicode-normalization or case-equivalence claim. |
| `RTM-066` | `test_single_file_bind_preserves_writes_and_chmod` | Covered | Support | A single-file bind preserves seed, guest writes and ordinary chmod on host readback. Host UID/GID mapping and inode-replacement retargeting are outside scope. |
| `RTM-067` | `test_bounded_upstream_filesystem_corpus` | Covered | Support | Pinned, unchanged fsx/pjdfstest and bounded seeded fsstress exercise direct/shared backends with exact completion and owned cleanup. Bounded multiworker stress is not exhaustive POSIX certification; see Volume contract and provenance for sources, licenses and limits. |
| `RTM-068` | `test_shared_volume_locking_is_client_local` | Covered | Intentional gap | Direct/same-client controls and independent shared peers establish client-local flock/fcntl scope. Cross-VM distributed application locking is intentionally unsupported. |
| `RTM-069` | `test_shared_volume_simultaneous_initialization` | Covered | Support | Simultaneous shared initialization serializes PREPARE; both consumers see every seed file and metadata without staging names. This is copy-up coordination, not application locking. |
| `RTM-070` | `test_named_volume_same_name_recreation_has_no_old_data` | Covered | Support | Referenced volumes refuse removal even with force; deleting and recreating the same name does not restore old data. Direct/shared backends are checked. |
| `RTM-071` | `test_completed_host_bind_rewrites_do_not_retain_cached_eof` | Covered | Support | Opted-in VirtioFS host_close_to_open refreshes size/mtime and invalidates cache on fresh opens. cat/splice/mmap check completed host growth, same-size rewrite, shrink, empty/regrow and fsync controls on directory/file RW/RO binds. Retained FDs, concurrent-write atomicity and macOS-reference parity are not claimed. |
| `RTM-072` | `test_attached_exec_immediate_output_activates_without_metadata_deadlock` | Covered | Support | Attached exec activates independently of PID publication; exact immediate stdout/stderr at 8191/8192/8193/32768 bytes and concurrent inspect remain responsive. Instance guards reject stale descriptors. |
| `RTM-073` | `test_direct_ext4_named_volume_copyup_preserves_source_xattrs` | Covered | Support | Direct-ext4 OCI-source copy-up preserves root/directory/file binary and empty user.* xattrs, valid ACLs/capabilities, and no-follow live/dangling symlink controls with nonroot denials. Bounded root metadata supports rollback; arbitrary LSM/trusted namespaces are outside scope. |
| `RTM-074` | `test_disk_bootstrap_preserves_identity_and_refuses_corrupt_owned_disk` | Covered | Support | Real VZ root/direct/storage initialization preserves ext4 UUID, capacity, root ownership/special modes and journals across mount-only boots/cold restart. A corrupt owned INITIALIZED direct disk refuses without rewriting bytes/journals. No bootstrap fault-boundary, simultaneous three-disk initialization or storage-root metadata claim. |
| `RTM-075` | `test_directory_rename_topology_and_atomic_failures` | Covered | Support | Pinned pjdfstest rename/{00,13,14,18,20} subset checks directory inode/topology/link counts, ENOTDIR/EISDIR, cycle EINVAL, nonempty EEXIST/ENOTEMPTY, failure atomicity and shared-peer observations. |
| `RTM-076` | `test_sticky_rename_overwrite_ownership` | Covered | Support | Pinned pjdfstest rename/10 regular-file subset checks sticky-directory nonowner denial without mutation; destination-owner and directory-owner overwrite succeeds and reaches the shared peer. |
| `RTM-077` | `test_failed_start_preserves_writable_root_and_metadata` | Covered | Support | Two failed starts and cold reloads preserve writable-root inode/size, ext4 UUID and initialization journals; explicit exact-ID removal deletes it. Quiescence/exclusive disk claims are mandatory. Does not detect in-place post-failure userdata/metadata corruption. |
| `RTM-078` | `test_initial_managed_storage` | Covered | Support | Two pre-created shared consumers prove FUSE topology, copy-up bytes/ownership/mode/mtime, open-unlink with zero nlink/no hidden names, retained writes and PREPARE/runtime drains. Not a fault-matrix claim. |
| `RTM-079` | `test_owned_managed_storage_crash_recovery` | Covered | Support | Synced acknowledgments, stopped consumers, durable drains and positive workload exit precede exact storage-VM death. Same-store recovery requires new E/authorized controller, preserved data and fresh shared attachments/writes. Completed-and-drained boundary only, not active PREPARE failure. |
| `RTM-080` | `test_shared_managed_volume_source_xattrs` | Covered | Support | Shared FUSE source/two-consumer probes cover root/directory/file user.*, valid ACL/capability metadata, cross-client updates/restoration, nonroot denials and no-follow target controls. Source OCI preflight and exact backend proof are required; no arbitrary xattr namespace claim. |
| `RTM-081` | `test_native_managed_fuse_interrupt` | Covered | Support | A gated real TLS DATA reply receives an actual kernel FUSE INTERRUPT while its thread is signaled. Advisory interruption may complete the original request; short/lost replies, canceled transport or uncertain drains are not success. Native component requires graceful receipt, FD and loop cleanup, not general cancellation certification. |
| `RTM-082` | `test_native_managed_fuse_write_burst` | Covered | Support | Native ABI-v3 Mount/DATA/authority component checks 1,000 writes, truncations, exact mounted/backing syscall readback and graceful cleanup. Linux pwrite(2), ftruncate(2), fsync(2) apply; not the unchanged cross-VM fsx corpus or crash proof. |
| `RTM-083` | `test_native_managed_fuse_sparse_mmap` | Covered | Support | Native sparse-prefix component checks mmap(2), msync(2), ftruncate(2), stat(2), lseek(2) and graceful cleanup. msync flags 0 are legal on Linux but do not promise synchronous durability. Not unchanged fsx or crash proof. |
| `RTM-084` | `test_live_managed_storage_worker_replacement` | Covered | Support | Production worker-only replacement keeps daemon/controller, storage VM and backing while changing E/worker/TLS. Old workloads must positively exit; new consumers retain metadata/data, write and drain. QUERY observes same-controller Ready without a mutating reconciliation. |
| `RTM-085` | `test_native_managed_fuse_full_fsx` | Covered | Support | Unchanged pinned static LTP fsx runs seed 1, 1,000 operations on native managed FUSE with capabilities dropped. Exact completion/exit zero and graceful barrier/drain/unmount required; no mmap suppression or added sync. Component scope, not RTM-067 cross-VM or exhaustive crash certification. |
| `RTM-086` | `test_volume_direct_exec_shebang_and_elf` | Covered | Support | Nonroot capability-dropped direct execution of volume shebang and ELF files works on direct/shared volumes and both shared peers. Non-executable controls require exact EACCES; no interpreter-prefix bypass. |
| `RTM-087` | `test_native_managed_data_stale_credentials` | Covered | Support | Native component uses real issued credentials/control/CSR/DATA TLS: same-E retired connection/reconnect must return ErrBlocked without mutation; after Reopen, the server rejects the old certificate despite client trust in the new server. Fresh credentials work. TLS 1.3 and fsync(2) apply. Owned 128-MiB ext4 fixture; 90s Go, 95s wrapper, 240s campaign bounds. Not RTM-084 VM-consumer/worker-crash or mounted-workload proof. |
| `RTM-088` | `test_shared_volume_empty_xattr_symlink_copyup_and_nocopy` | Covered | Support | Source-OCI/direct-ext4 preflight plus two shared consumers checks empty-xattr live/dangling literal symlink copy-up and NoCopy, ownership/mtime, unchanged outside targets and empty nocopy roots. Unsupported metadata restoration fails closed. |
| `RTM-089` | `test_native_service_faults` | Covered | Support | Closed native service plan injects durability/identity errors at selected stages; exact barrier-completion certificate, quarantine, no fabricated receipt and byte-preserving refusal are required. Scoped component, not integrated VM/PREPARE recovery. |
| `RTM-090` | `test_native_fault_tuple_regression` | Covered | Support | Native final-sync namespace-gate component crosses other-volume/other-attachment/mutation tuples with EIO/ENOSPC. Valid requests retain exact identity/error behavior; not deployed VM recovery. |
| `RTM-091` | `test_native_symlink_root_rollback` | Covered | Support | Native supervisor components check target safety, pinned rename/unlink, capability and CHOWN/FOWNER-denial rollback, and partial root-xattr rollback. Direct-ext4 component paths, not cross-VM copy-up proof. |
| `RTM-092` | `test_native_managed_valid_capability` | Covered | Support | Native managed/direct-ext4 comparison covers valid live/dangling symlink capability xattrs for three identities and get/list/set/remove. Component scope; RTM-073/080/088 separately exercise copy-up. |
| `RTM-093` | `test_native_issued_prepare_initializer_preflight` | Covered | Support | Issued PREPARE with actual mounted FUSE initializer covers flock/copy/journal/rollback/metadata and fresh-attachment replay. Initializer-only composition, not full Session/Supervisor boot or storage-VM death. |
| `RTM-094` | `test_native_pending_prepare_fresh_mount_replay` | Covered | Support | Fresh child-mounted FUSE replays authenticated pending provision through reopen/drain/ReplacePrepare, root ioctl and blocked/released DATA. Lower-authority crash setup, not natural in-flight DATA-server death or full Supervisor boot. |
| `RTM-095` | `test_native_prepare_ext4_identity_and_cleanup` | Covered | Support | Real-ext4 direct-session components check physical identity, intermediate-symlink containment, fresh-session pending bootstrap and sealed/unsealed cleanup crash recovery. Retirement callback is a no-op: not deployed DATA/FUSE retirement or forced inode-reuse proof. |
| `RTM-096` | `test_managed_prepare_ambiguity_full_acceptance` | Covered | Support | Parent-owned NORMAL/A1–A8 integrated PREPARE campaign traverses Docker start, Session/Supervisor/FUSE/ext4 publication, exact-launch arm, fsynced external evidence, positive native exit, quarantine/drain/ReplacePrepare and fresh-credential retry with exact tree/root metadata. Aggregate requires live outcomes from unique owned roots; ordinary pytest refuses before setup. Does not substitute for API/worker/VM matrices. |
| `RTM-097` | `test_managed_prepare_api_restart_recovery` | Covered | Support | Parent-owned NORMAL/A1–A8 API restart matrix requires exact daemon death, unchanged live storage identity, authenticated controller takeover/reconciliation, actual drain and fresh-credential retry. Ordinary pytest refuses; initial A7 alone is not the full matrix. Public receipts are evidence, not recovery authority. |
| `RTM-098` | `test_managed_prepare_worker_restart_recovery` | Covered | Support | Parent-owned worker NORMAL/A1–A8 cells require exact one-shot worker exit and PID1 Wait, same daemon/storage VM/C/key, fresh worker/E/TLS, containment, drain and retry. Per-cell coverage has no aggregate schema. Separate worker-a5-active-ack requires independent fsynced ACK and fresh-E readback before rewriting. EOF/timeout is not death or drain. |
| `RTM-099` | `test_managed_prepare_storage_vm_recovery` | Covered | Support | Parent-owned storage-VM NORMAL/A1–A8 matrix requires native death, preserved backing/ROOT, fresh VM/E/worker/TLS and authenticated recovery/drain/retry. Separate private/root/CLEANING, active-ACK and two-volume drain-reply-gap cuts retain exact metadata, read ACKs before rewriting, and replay original receipts/CompletePrepare without fabrication. Matrix aggregate and these extra selections are distinct. |
| `RTM-100` | `test_managed_prepare_io_failures` | Covered | Support | Parent-owned returned-error matrix covers 23 operations × EIO/ENOSPC: recoverable workload errors require actual failed start/drain/fresh NORMAL retry; authority uncertainty remains sticky, with no runtime/receipt/successor and byte-preserving retry refusal. Complete coverage requires unique live outcomes, not serialized receipts. No timeout-as-drain or power-loss claim. |
| `RTM-101` | `test_native_prepare_snapshot_fence` | Covered | Support | Mounted snapshot fence checks foreign TGID, retained writable FD, dirty MAP_SHARED writeback, read/readdir atime, pre-Begin namespace admission, runtime queue capacity, initializer death and hung accepted guard. READ requires real read prerequisite; hung guards retain RETIRING/no DRAINED. Tagged observation cannot manufacture guards or substitute dispatch. |
| `RTM-102` | `test_native_prepare_ext4_identity_authenticity` | Covered | Support | Real-ext4 direct-session identity/authenticity component requires actual inode reuse with new generation/full handle, cross-filesystem UUID/openat2 refusal, same-A FORGET/relookup, altered manifests, late children, registered-root reuse, same-name volume stale-TLS refusal and large-journal replay. Copy-recovery retirement callback is a no-op; not deployed FUSE or exhaustive fault proof. |
| `RTM-104` | `test_native_prepare_process_poll_eintr` | Covered | Support | Retained pidfd zero-timeout poll retries EINTR at most 16 attempts, then fails closed. Readiness, changed birth, foreign thread, closed owner and non-EINTR errors deny authority; live procfs checks remain mandatory. Native component, not signal-storm/full PREPARE proof. |
| `RTM-105` | `test_disk_mount_sources_name_distinct_block_devices` | Covered | Support | Root and direct-volume mountinfo name distinct /dev/vdX devices; the pinned descriptor is rechecked against the path and post-mount major/minor. Supports per-device consumers such as cAdvisor without weakening descriptor identity. |
| `RTM-106` | `test_kill_cancellation_survives_daemon_crash_before_exit` | Covered | Support | An instance-bound manual-stop checkpoint precedes kill signal delivery. After daemon/workload death, unless-stopped stays exited while always restarts; explicit start/removal clears the marker. Failed checkpoint sends no signal; foreign-instance markers refuse. |
| `RTM-107` | `test_native_durability_fail_closed_policy` | Covered | Support | Actual-ext4 process-death component retains DATA/retirement obligations after real syncfs/barrier holds. Repeated anchored opens return typed repair-required without changing registry bytes or earlier ACK/receipts; completed controls reopen. Kernel remains alive: not VM death/remount/power loss or successful integrated recovery. |
| `RTM-108` | `test_native_retirement_completion_recovery` | Covered | Support | Real completed barrier plus exact completion certificate recovers RETIRING predecessor or durable DRAINED successor across process-death cuts, without minting receipts/replaying the barrier. Unanchored opens, generic barriers, DATA and known-error fences refuse. Not VM/power-loss or RTM-099 aggregate proof. |
| `RTM-109` | `test_native_copy_data_recovery` | Covered | Support | Operation-specific version-2 PREPARE DATA recovery uses bounded manifest/physical preflight, real drains, fresh-owner rollback/tail replay and populated retry after process-death cuts. Generic/version-1 DATA and known errors still refuse, even with matching hash. Not VM/power-loss proof. |
| `RTM-110` | `test_native_prepare_retirement_recovery` | Covered | Support | Root-bootstrap-only PREPARE retry requires exact predecessor certificate, all older owners drained and actual barrier/retry/readback. Dirty/runtime/no-session/foreign/pinned/error cases refuse; no fabricated completed receipt. Process-death component only. |
| `RTM-111` | `test_managed_volume_short_lived_concurrent_starts` | Covered | Support | Shared-volume short-lived concurrent readers preserve a seeded marker, exact start/wait status and empty stderr across bounded rounds. At most two concurrent starts; no deterministic overlap or crash claim. |
| `RTM-112` | `test_managed_shared_normal_exit_preserves_status_output_and_contains_execs` | Covered | Support | Shared-volume PID1 normal exit preserves exit 23 and exact final stdout/stderr, terminalizes observed execs, and rejects new exec with HTTP 409. Process completion is not authority failure; no crash/kernel-PID absence claim. |
| `RTM-113` | `test_native_storage_lifecycle_checkpoint` | Covered | Guest component | Guest TLS/checkpoint component checks bounded takeover state, stale identity/key/epoch/serial and v1 refusal, fresh-nonce results, terminal seal and mutation-free sealed reopen refusal. Fresh empty store only; no DATA/drain, physical HOST checkpoint, installed ROOT or VM-death proof. |
| `RTM-114` | `test_native_storage_lifecycle_fresh` | Covered | Qualification only | Signed qualification-only fresh lifecycle uses real ROOT/VZ/Guest and physical HOST reopen, terminal retirement and actual shim/controller reap. Not ordinary daemon DATA/drain coverage; EOF cannot authorize VM-exit/deletion. |
| `RTM-115` | `test_native_storage_lifecycle_lost_completion` | Covered | Qualification only | Signed qualification-only lost-completion retry retains the grant and requires fresh proof/terminal result plus physical HOST reopen and actual reap. Not broader crash acceptance or relabeled RTM-113 component proof. |
| `RTM-116` | `test_native_storage_lifecycle_live_proof_loss` | Covered | Qualification only | Signed qualification-only live-proof loss refuses while preserving pending state and terminal=false, without reclaim. Actual controller/shim reap precedes owned cleanup; no naked-shim signal authority or DATA/drain proof. |
| `RTM-117` | `test_lifecycle_v2_fresh_shared_fuse_data` | Covered | Ordinary lifecycle gate | Two pre-created consumers prove shared FUSE topology/native identities and exchange fresh bidirectional DATA. Missing selected helper/assets/signing fails, never falls back. |
| `RTM-118` | `test_lifecycle_v2_daemon_restart_preserves_live_data` | Covered | Ordinary lifecycle gate | Only the owned daemon is killed. Original workloads advance peer read/write and unlinked-FD counters while it is absent; storage/workload native births, launches and restart counts survive reattachment, new DATA and fresh shared attachment. Not helper restart or VM death. |
| `RTM-119` | `test_lifecycle_v2_first_initialization_failure_resumes` | Covered | Controlled initialization gate | Compile-sealed genuine-hello/pre-configure failure requires positive guestDidStop; same binary resumes while preserving backing inode, ext4 UUID/creation time and initialization manifest. Genuine enrollment/shared DATA required. Markers do not authorize formatting or deletion; not power-loss repair. |
| `RTM-120` | `test_lifecycle_v2_same_daemon_worker_replacement` | Covered | Ordinary lifecycle replacement gate | Ordinary owned production queue replaces only the worker: same daemon/storage VM/ROOT/store/G/C/key/backing, fresh E/worker/TLS, positive old-workload exits and Docker 137. Fresh peers retain seeds and exchange DATA; no manual worker kill/private owner shortcut. |
| `RTM-121` | `test_lifecycle_v2_daemon_death_during_worker_replacement` | Covered | Controlled replacement-crash gate | Sealed post-native/pre-completion daemon death preserves frozen pending operation and immutable observed successor. Normal authenticated recovery replays exactly one E/worker/TLS successor, advances C/key, preserves backing/storage VM, requires old-workload exit/137 and fresh DATA. Departed queue task is not synthetically succeeded; diagnostics are not authority. |
| `RTM-122` | `test_lifecycle_v2_repairs_owned_root_permissions` | Covered | Host startup regression | Locked, owned, ACL-free 0755 root is tightened to 0700 at fresh/populated startup without inode/content replacement; shared DATA and live VMs survive. Other-writable/special-bit/ACL/unsupported/replaced roots refuse. Permission repair does not authorize store-format changes, resets or recovery. |
| `RTM-123` | `test_lifecycle_v2_storage_shim_owns_process_group` | Covered | Host process lifetime regression | Storage shim leads a process group distinct from daemon/launchd job cleanup. Graceful daemon exit preserves native storage/workload identities, zero restart counts and new shared DATA after reattachment. |
| `RTM-124` | `test_lifecycle_v2_live_restart_after_two_cold_recoveries` | Covered | Post-cold live-restart regression | Two cold recoveries followed by two live daemon restarts retain seed data and original live VM identities. Cold audit history remains validated metadata; only current/referenced contexts demand fresh recovery authority. |
| `RTM-125` | `test_lifecycle_v2_interrupted_live_takeover_recovers` | Covered | Controlled live-takeover crash gate | Sealed before/after-takeover-apply profiles kill only the daemon. Authenticated handoff resolution selects the exact predecessor/successor outcome, fences the abandoned grant and consumes serials without reuse; original VMs/worker/E/TLS/unlinked FDs continue DATA. No public diagnostic authority or helper/VM-death claim. |
| `RTM-126` | `test_lifecycle_v2_offline_apfs_remount` | Covered | Host stable-identity regression | Offline owned APFS remount must actually change st_dev while preserving filesystem UUID/inodes, backing/ext4/store/ROOT/manifest and saved/new shared DATA. Historical specs remain immutable; exact live descriptor checks still apply. No live-remount or physical-media cloning guarantee. |
| `RTM-127` | `test_lifecycle_v2_ready_graceful_restarts` | Covered | Host graceful-shutdown regression | Immediate-ready SIGTERM cycles exit normally without forced fallback; original storage/workload native identities, restart counts and shared DATA survive. Deterministic service-task cancellation is separately unit-tested. |
| `RTM-128` | `test_lifecycle_v2_two_strict_cold_restarts_with_live_peers` | Covered | Strict cold-start regression | Supported strict shutdown/start cycles positively retire predecessors, retain store/ROOT/manifest/disk, advance C once with new E/worker/key/native births, automatically start retained always-policy peers and preserve synced seeds/new DATA. This test is not an actual OS reboot or power-loss simulation. |
| `RTM-129` | `test_lifecycle_v2_interrupted_cold_l2_recovers` | Covered | Interrupted committed-cold recovery | Sealed ROOT L2/pre-A1 failure preserves the exact frozen attempt. Positive participant exit, real protected dead-history bridge and fresh C+2/key/E/birth recover automatic peers and saved/new DATA. HOST pending metadata alone is not L2 proof; no reset/fabricated authority. |
| `RTM-130` | `test_lifecycle_v2_guest_initramfs_update_cold_recovery` | Covered | Guest artifact update regression | Timestamp-only compressed guest-image update changes digest but not decompressed code/provenance. After positive native exit, protected interrupted-cold recovery preserves launch records/store/seeds and fresh DATA. Artifact admission regression; does not establish guest-protocol compatibility or store-format conversion. |
| `RTM-131` | `test_lifecycle_v2_cold_enrollment_survives_live_reattachment` | Covered | Cold enrollment regression | Strict cold recovery then live reattachment preserves new VM births/E/worker/restart counts, advances C once, and retains seeds/new DATA. Recovery enrollment budget and late-ACK refusal are unit-tested; native case injects no delay or reboot. |
| `RTM-132` | `test_lifecycle_v2_committed_unenrolled_cold_recovery` | Covered | Committed cold enrollment failure | ROOT/HOST-committed but unenrolled cold successor recovers only after all exact native participants exit and adoption rotates. Fresh cold operation keeps publication fenced until real enrollment, preserving original peers/seeds/new DATA. No synthetic ACK, old boot replay, L2 bridge or reset. |
| `RTM-133` | `test_lifecycle_v2_retained_history_allows_live_storage_control` | Covered | Retained storage history | Repeated cold cycles preserve immutable old launch history; authenticated storage-control/network CRUD and live reattachment retain automatic peers/seeds/new DATA. Prior-boot inaccessible-PID classification and death-only differing-birth fallback are unit-covered; native test neither forges boot IDs nor injects EPERM/reboot. |

## Containers

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `CTR-001` | `test_create_container` | Covered | Support | Create and list through docker-py. |
| `CTR-002` | `test_create_network` | Covered | Support | Bridge network creation. |
| `CTR-003` | `test_start_container` | Covered | Support | Start through docker-py and verify running state. |
| `CTR-004` | `test_start_container_with_random_port_bind` | Covered | Support | Strengthened to require a nonzero assigned host port after start. |
| `CTR-005` | `test_stop_container` | Covered | Support | State becomes exited. |
| `CTR-006` | `test_kill_container` | Covered | Support | SIGKILL is reconciled before the response completes. |
| `CTR-007` | `test_restart_container` | Covered | Support | Restart after stop. |
| `CTR-008` | `test_remove_container` | Covered | Support | Force removal of a running container. |
| `CTR-009` | `test_remove_container_without_force` | Covered | Support | Uses Docker's HTTP 409 conflict rather than Podman's HTTP 500 assertion. |
| `CTR-010` | `test_pause_container` | Covered | Support | Pause and inspect. |
| `CTR-011` | `test_pause_stopped_container` | Covered | Support | Uses Docker's HTTP 409 conflict. |
| `CTR-012` | `test_unpause_container` | Covered | Support | Resume and inspect. |
| `CTR-013` | `test_list_container` | Covered | Support | List all containers. |
| `CTR-014` | `test_filters` | Covered | Support | Enabled even though Podman currently skips it. |
| `CTR-015` | `test_copy_to_container` | Covered | Support | Content, mode, and numeric tar UID/GID are preserved inside the guest; repeated uploads replace regular files and symlinks without following link targets, existing directories merge, and the default archive endpoint replaces directory/non-directory type changes. |
| `CTR-016` | `test_mount_preexisting_dir` | Expected failure | Intentional gap | Requires direct `docker build`; cengine requires Buildx. |
| `CTR-017` | `test_non_existent_workdir` | Expected failure | Intentional gap | Requires direct `docker build`; cengine requires Buildx. |
| `CTR-018` | `test_build_pull` | Expected failure | Intentional gap | Requires direct `docker build`; cengine requires Buildx. |
| `CTR-019` | `test_mount_options_by_default` | Covered | Support | Checks normalized `HostConfig.Binds` and top-level `Mounts`. |
| `CTR-020` | `test_wait_next_exit` | Covered | Support | Blocks until the next start and exit, including from the created state. |
| `CTR-021` | `test_container_inspect_compatibility` | Covered | Support | Includes stable container, mount, network, logging, and host-config fields consumed by docker-py. |
| `CTR-022` | `test_rename_container` | Covered | Support | Rename is persisted and addressable by the new name. |
| `CTR-023` | `test_rename_container_name_conflict` | Covered | Support | Duplicate names return HTTP 409. |
| `CTR-024` | `test_exec_attached_output_and_exit_code` | Covered | Support | Attached exec preserves multiplexed stdout/stderr and exit status. |
| `CTR-025` | `test_copy_from_container_round_trip` | Covered | Support | Archive download returns file contents and path metadata. |
| `CTR-026` | `test_container_configuration_round_trip` | Covered | Support | Environment, user, workdir, read-only root, labels, restart policy, and default resources survive create/inspect. |
| `CTR-027` | `test_container_stats_complete` | Covered | Support | VM-backed `docker stats --no-stream` returns a container sample. |
| `CTR-028` | `test_top_and_update` | Covered | Support | Process listing and live cgroup resource-policy updates preserve the running VM. |
| `CTR-029` | `test_follow_logs_streams_output_and_closes` | Covered | Support | Follow mode streams multiplexed output and closes at container exit. |
| `CTR-030` | `test_streaming_stats_produces_multiple_samples` | Covered | Support | Streaming stats returns successive Docker-shaped samples. |
| `CTR-031` | `test_container_and_exec_tty_resize` | Covered | Support | Running container and exec resize requests change the PTY size observed by `stty`, including the resulting `SIGWINCH` update path. |
| `CTR-032` | `test_log_time_tail_stream_and_timestamp_filters` | Covered | Support | Snapshot and follow logs honor stream, time, tail, and timestamp options. |
| `CTR-033` | `test_multiple_containers_stream_stats_concurrently` | Covered | Support | Multiple simultaneous stats streams produce independent samples. |
| `CTR-034` | `test_network_none_has_only_loopback` | Covered | Support | Network mode `none` persists across inspect and exposes only loopback in the guest. |
| `CTR-035` | `test_debian_package_install_uses_ext4_rootfs` | Covered | Support | Debian package installation creates `/etc/ssl` on the guest ext4 root without host-filesystem permission failures. |
| `CTR-036` | `test_exec_hijack_closes_after_process_exit` | Covered | Support | Attached exec closes its hijacked HTTP stream promptly when the guest process exits. |
| `CTR-037` | `test_short_lived_container_reaches_exited_state` | Covered | Support | A naturally exiting guest process is reconciled without requiring an explicit stop request. |
| `CTR-038` | `test_attached_exec_streams_stdin_before_eof` | Covered | Support | Attached exec stdin remains open for streamed data and receives EOF when the client half-closes. |
| `CTR-039` | `test_attached_exec_preserves_multiline_stdin_bytes` | Covered | Support | Attached exec preserves structured multi-line stdin byte-for-byte. |
| `CTR-040` | `test_exec_inherits_and_overrides_container_environment` | Covered | Support | Exec inherits image and container environment before applying exec-specific overrides. |
| `CTR-041` | `test_restart_policy_update_preserves_running_vm` | Covered | Support | Updating only restart-policy metadata preserves the running VM, container start time, and guest boot identity. |
| `CTR-042` | `test_live_resource_update_rejects_limits_above_vm_capacity` | Covered | Support | Live resource increases above fixed VM capacity return HTTP 409 without changing container state. |
| `CTR-043` | `test_attached_exec_streams_large_stdin_without_filesystem_polling` | Covered | Support | A 128 MiB attached exec stream is lossless and completes without filesystem-polling throughput limits. |
| `CTR-044` | `test_attached_exec_flushes_short_output_before_eof` | Covered | Support | Short attached exec output is flushed before EOF, including rapid consecutive execs and clients that keep attached stdin open. |
| `CTR-045` | `test_unprivileged_standard_devices_are_world_accessible` | Covered | Support | Standard character devices retain mode `0666` and are usable after the workload drops root privileges. |
| `CTR-046` | `test_concurrent_vm_starts_remain_responsive` | Covered | Support | Twelve concurrent container creates and starts leave every running guest responsive to exec without starving shim control I/O. |
| `CTR-047` | `test_container_memory_limit_is_separate_from_vm_capacity` | Covered | Support | The Docker memory value remains the workload cgroup hard limit while the per-container VM includes separate guest overhead. |
| `CTR-048` | `test_container_annotations_are_versioned_and_persisted` | Covered | Support | Create-time annotations enter the guest workload specification, survive daemon recovery and inspect, while list responses expose them only from API v1.46. |
| `CTR-049` | `test_kill_cancels_restart_policy_until_next_start` | Covered | Support | SIGKILL/configured stop signal is a manual stop that suppresses immediate policy restart; explicit start reenables normal exit policy. Other delivered signals leave policy active. |

## Testcontainers

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `TST-001` | `test_ryuk_reaps_through_bound_cengine_socket` | Covered | Support | Default Ryuk reaches the cengine Docker API through an exact Unix-socket bind and reaps a labeled container. |
| `TST-002` | `test_privileged_ryuk_reaps_through_bound_cengine_socket` | Covered | Support | Privileged Ryuk uses the same socket relay without requiring a rootful cengine daemon. |
| `TST-003` | `test_shellless_ryuk_exec_reports_command_not_found` | Covered | Support | Exec against Ryuk's shell-less image returns Docker-compatible command-not-found status instead of retryable application failure. |
| `TST-004` | `test_ryuk_keeps_multiple_control_connections_open` | Covered | Support | Closing one Ryuk control connection leaves cleanup suppressed while sibling connections remain open. |

## Images

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `IMG-001` | `test_tag_valid_image` | Covered | Support | Image tagging persists through the backend store. |
| `IMG-002` | `test_retag_valid_image` | Covered | Support | Additional tags resolve to the same image. |
| `IMG-003` | `test_list_images` | Covered | Support | Reference filtering excludes nonmatching images. |
| `IMG-004` | `test_search_image` | Covered | Support | Docker Hub search applies limits and official/star filters, strips the familiar `library/` prefix, bounds upstream responses, and returns the Docker result shape with deprecated automation state forced false. |
| `IMG-005` | `test_search_bogus_image` | Covered | Support | Search terms containing a URL scheme are rejected deterministically as invalid repository names. |
| `IMG-006` | `test_remove_image` | Covered | Support | Missing-image and successful removal behavior. |
| `IMG-007` | `test_image_history` | Covered | Support | History includes the image identifier. |
| `IMG-008` | `test_get_image_exists_not` | Covered | Support | Missing images return NotFound. |
| `IMG-009` | `test_save_image` | Covered | Support | Per-image Docker archive export from the backend OCI store. |
| `IMG-010` | `test_load_image` | Covered | Support | Docker save/load round trips. |
| `IMG-011` | `test_load_corrupt_image` | Covered | Support | Corrupt archives are rejected. |
| `IMG-012` | `test_build_image` | Expected failure | Intentional gap | Direct build is intentionally unsupported. |
| `IMG-013` | `test_build_image_via_api_client` | Expected failure | Intentional gap | Direct build is intentionally unsupported. |
| `IMG-014` | `test_push_error` | Covered | Support | Push streams registry failures in Docker's response shape. |
| `IMG-015` | `test_authenticated_push_round_trip` | Covered | Support | Bad credentials are rejected and valid credentials succeed through Docker's registry-login API before Basic-auth push, removal, pull-back, and execution use a pinned local registry. |
| `IMG-016` | `test_multi_platform_manifest_summary_preserves_local_variants` | Covered | Support | OCI index targets expose locally available arm64 and amd64 manifest summaries without flattening the graph. |
| `IMG-017` | `test_platform_specific_inspect_and_missing_platform` | Covered | Support | JSON OCI platform selection returns the requested variant and a missing platform returns NotFound. |
| `IMG-018` | `test_multi_platform_save_and_load_round_trip` | Covered | Support | Repeated save/load platform selectors preserve both selected variants in the OCI archive round trip. |
| `IMG-019` | `test_platform_selective_delete_retains_other_variant` | Covered | Support | Forced platform deletion removes selected content while the other variant remains inspectable. |
| `IMG-020` | `test_container_reports_selected_image_manifest_descriptor` | Covered | Support | Container list and inspect identify the graph root and selected platform manifest. |
| `IMG-021` | `test_image_identity_records_trusted_pull_origin` | Covered | Support | Inspect and identity-enabled list responses report daemon-recorded pull origins. |
| `IMG-022` | `test_image_attestations_support_filters_and_statement_opt_in` | Covered | Support | Attestation metadata avoids reading statements until opted in and supports predicate filtering. |
| `IMG-023` | `test_manifest_options_reject_conflicts_and_preserve_identity_after_retag` | Covered | Support | Inspect rejects conflicting selectors, and retagging cannot manufacture trusted identity origins. |
| `IMG-024` | `test_docker_cli_saves_multiple_images` | Covered | Support | Docker CLI collection export preserves every requested image and its repository tags in one archive, as required by `GET /images/get` and consumed by kind image loading. |
| `IMG-025` | `test_load_layerless_buildkit_archive_uses_docker_tag` | Covered | Support | `POST /images/load` accepts BuildKit's layerless Docker archive encoding (`Layers=[]` and `rootfs.diff_ids=null`), restores the explicit Docker `RepoTags` name, and does not invent a `local:latest` tag from the generic OCI annotation. See Docker API v1.55 [`POST /images/load`](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Image/operation/ImageLoad). |

## System

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `SYS-001` | `test_info` | Covered | Support | Adapted from Podman registry configuration to cengine driver, platform, and root invariants. |
| `SYS-002` | `test_info_container_details` | Covered | Support | Container totals update after create. |
| `SYS-003` | `test_version` | Covered | Support | Platform name and negotiated API version. |
| `SYS-004` | `test_info_reports_images_and_versioned_native_engine_details` | Covered | Support | Image totals reflect the local store, discovered devices are reported as an empty list from v1.50, and inapplicable containerd, Linux firewall, and NRI details are not fabricated. |

## Events

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `EVT-001` | `test_filtered_container_events` | Covered | Support | Type, container, and label filters isolate live create, start, die, and destroy events. |
| `EVT-002` | `test_historical_events_honor_time_window_and_jsonl` | Covered | Support | A bounded history honors time windows and API v1.53+ JSONL negotiation. |
| `EVT-003` | `test_historical_image_pull_and_load_events_honor_filters` | Covered | Support | Successful pulls and archive loads emit Docker-shaped image events that replay through type, action, and image filters. |
| `EVT-004` | `test_container_events_match_image_filter_with_tag_stripping` | Covered | Support | Container lifecycle events match the `image` actor attribute by tagged reference or its tag-stripped familiar name, as defined by Moby event filtering. |
| `EVT-005` | `test_event_filters_accept_boolean_maps_and_ignore_false_entries` | Covered | Support | The event stream accepts modern nested boolean-map filters, activates true selectors, and ignores false selectors without widening to unrelated event types. |

## Networks

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `NET-001` | `test_network_list_filters_labels` | Covered | Support | Compose project label isolation. |
| `NET-002` | `test_network_connect_disconnect` | Covered | Support | Containers can be connected to and disconnected from additional networks. |
| `NET-003` | `test_create_container_on_network` | Covered | Support | docker-py's nullable endpoint configuration selects a network during create. |
| `NET-004` | `test_udp_port_forwarding` | Covered | Support | Dynamically assigned UDP bindings forward request and response datagrams. |
| `NET-005` | `test_occupied_host_port_returns_server_error` | Covered | Support | Occupied host ports fail container start without stealing the listener. |
| `NET-006` | `test_concurrent_random_port_allocation_is_unique` | Covered | Support | Concurrent ephemeral TCP bindings remain unique. |
| `NET-007` | `test_sequential_network_deletion_releases_vmnet_reservations` | Covered | Support | More than 119 sequential networks reuse a released vmnet reservation instead of exhausting host resources. |
| `NET-008` | `test_bridge_network_allows_peers_host_and_internet` | Covered | Support | A normal bridge reaches peers, macOS host services, and the internet. |
| `NET-009` | `test_internal_network_allows_peers_and_host_but_not_internet` | Covered | Support | Docker internal mode retains peer and host access while removing external connectivity. |
| `NET-010` | `test_isolated_gateway_allows_only_network_peers` | Covered | Support | Isolated gateway mode permits peer traffic and blocks host and internet traffic. |
| `NET-011` | `test_isolated_gateway_options_round_trip_and_require_internal` | Covered | Support | Docker bridge gateway options round-trip and isolated mode requires an internal network. |
| `NET-012` | `test_isolated_gateway_filter_cannot_be_bypassed_by_adding_a_route` | Covered | Support | The external frame filter remains effective when a privileged guest adds a default route. |
| `NET-013` | `test_creating_container_preserves_existing_network_connectivity` | Covered | Support | Replacing a running container's fabric bridge preserves its gateway, DNS, and Internet path. |
| `NET-014` | `test_explicit_endpoint_mac_address_is_applied_and_survives_recovery` | Covered | Support | An explicit endpoint `MacAddress` is applied to the guest interface, returned by inspect, and preserved across daemon recovery. |
| `NET-015` | `test_invalid_and_duplicate_endpoint_mac_addresses_are_rejected` | Covered | Support | Malformed or multicast MAC addresses fail with 400 and duplicate effective MACs on the same network fail with 409, including an explicit address that collides with a container's deterministic automatic address. Pending creates reserve effective MACs before persistence so concurrent creates cannot claim the same address. |
| `NET-016` | `test_gateway_priority_selects_default_route_and_survives_recovery` | Covered | Support | A multi-network container installs its default route from the highest-priority endpoint (`GwPriority`), reports the value in inspect, and preserves the selection across daemon recovery. |
| `NET-017` | `test_publishing_sctp_port_is_rejected_as_intentional_gap` | Covered | Intentional gap | Publishing an `sctp` port fails with 400 because the vmnet port forwarder bridges only TCP and UDP; TCP and UDP publishing on the same request still succeed. |
| `NET-018` | `test_explicit_network_address_families_apply_and_survive_recovery` | Covered | Support | `EnableIPv4=false` suppresses IPv4 IPAM and endpoint addressing while enabled IPv6 remains usable; inspect and daemon recovery preserve both family flags. Empty backend address sentinels are normalized to absent addresses before persistence, so start and recovery do not misclassify IPv6-only endpoints as IPv4-capable or suppress IPv6 peer-host entries. This follows Docker's network `EnableIPv4`/`EnableIPv6` contract and [Moby's network-level enable labels](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/libnetwork/netlabel/labels.go). |
| `NET-019` | `test_endpoint_sysctls_apply_validate_and_survive_recovery` | Covered | Support | Endpoint `DriverOpts` accepts `com.docker.network.endpoint.sysctls` with `IFNAME`, rejects malformed or unsupported settings, applies the values through the guest's `/proc/sys/net` namespace, and preserves them across recovery. Create and connect decode and apply the current DTO even with a pre-v1.46 negotiated API, matching Moby; inspect emits `DriverOpts` only for v1.46+. Semantics follow [Moby #47686](https://github.com/moby/moby/pull/47686). |
| `NET-020` | `test_network_ipam_status_tracks_allocations_and_api_version` | Covered | Support | API v1.52+ network inspect reports per-subnet `IPsInUse` and `DynamicIPsAvailable`, including bridge reservations and endpoint allocations; API v1.51 omits `Status`. Explicit CIDRs are canonicalized before persistence, so a request such as `10.55.0.2/29` is stored and reported as `10.55.0.0/29` without double-counting the first allocated endpoint. IPv4 `/31` pools reserve neither endpoint as network/broadcast, including in privileged-helper gateway validation, matching [Moby's RFC 3021 allocator exception](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/libnetwork/ipams/defaultipam/allocator.go). When a gateway is omitted, the runtime derives the canonical first address from the masked subnet for both IPv4 and IPv6 before invoking any backend, keeping metadata-only and vmnet-backed inspect, allocation, and status accounting consistent. Pending creates and connects reserve endpoints before persistence; network deletion, prune, container start, and container removal respect those reservations until the operation commits or rolls back. Shape and accounting otherwise follow [Moby #50917](https://github.com/moby/moby/pull/50917). |
| `NET-021` | `test_network_prune_filters_limit_deleted_networks` | Covered | Support | Network prune applies positive and negative label filters plus `until` before deleting unused networks, and rejects empty label keys before indexing or deleting anything. |
| `NET-022` | `test_network_ipam_and_family_validation_is_explicit` | Covered | Support | The official `AuxiliaryAddresses` field is decoded and rejected explicitly, as are multiple same-family subnets, both families disabled, custom IPv6 gateways, and asymmetric dual-stack isolation. Network creation centrally validates CIDR syntax, prefix widths, and address families before backend persistence; canonicalizes subnet and gateway spellings; derives omitted gateways; requires gateways to belong to the pool; and rejects IPv4 network/broadcast and IPv6 network boundaries. Static endpoint addresses receive the same family, pool, canonicalization, and reservation checks before conflict checks and persistence, so equivalent IPv6 spellings cannot bypass duplicate allocation checks. Older negotiated APIs ignore `EnableIPv4` and keep legacy IPv4 behavior. The field spelling follows [Moby's IPAM API type](https://github.com/moby/moby/blob/docker-v29.0.0/api/types/network/ipam.go), and reserved-address behavior follows [Moby's default IPAM allocator](https://github.com/moby/moby/blob/docker-v29.0.0/daemon/libnetwork/ipams/defaultipam/allocator.go); custom IPv6 gateways are unsupported because Apple's vmnet configuration API exposes an [IPv6 prefix setter](https://developer.apple.com/documentation/vmnet/vmnet_network_configuration_set_ipv6_prefix(_:_:_:)) but no gateway-address setter in its [configuration function surface](https://developer.apple.com/documentation/vmnet/vmnet_functions). |

## Volumes

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `VOL-001` | `test_volume_list_filters_labels` | Covered | Support | Compose project label isolation. |
| `VOL-002` | `test_empty_named_volume_copies_image_directory` | Covered | Support | Empty named volumes receive image directory contents. |
| `VOL-003` | `test_volume_nocopy_leaves_empty_volume_empty` | Covered | Support | `VolumeOptions.NoCopy` disables initialization. |
| `VOL-004` | `test_volume_subpath_mounts_existing_directory` | Covered | Support | Existing volume subdirectories mount safely and traversal is rejected. |
| `VOL-005` | `test_tmpfs_size_and_mode_options` | Covered | Support | Structured tmpfs size and mode options are applied in the guest; `RTM-022` covers its default and explicit execution policy. |
| `VOL-006` | `test_volume_preserves_inodes_across_link_and_rename` | Covered | Support | Single-consumer direct ext4 only: hardlink preserves inode/payload after parent rename. Does not prove shared-FUSE retained-handle or restart identity. |
| `VOL-020` | `test_invalid_copy_modes_reject_container_creation` | Covered | Support / intentional API validation-class difference | Named :copy and bind :copy/:nocopy return HTTP 400 before creation. Structured NoCopy is supported; ORC-021 documents Docker's different validation status class. |
| `VOL-021` | `test_volume_remove_rejects_stopped_container_reference` | Covered | Support | A created/nonrunning consumer protects a named volume with HTTP 409; deletion succeeds after consumer removal. No complete force/prune equivalence claim. |
| `VOL-022` | `test_rm_v_removes_anonymous_but_retains_named_volume` | Covered | Support | Create-only rm -v deletes a structured anonymous mount while retaining a named volume. Not all run/auto-remove transitions. |
| `VOL-023` | `test_offline_package_nonroot_multifile_backup_restore` | Covered | Support | Offline pip wheel upgrade and nonroot multifile tar backup/restore on direct/shared volumes check command/resource output, obsolete-file removal, exact bytes/metadata, literal symlinks and within-filesystem hardlinks. Bounded fixture, not general package-manager certification. |

## Docker Compose 5.x

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `CMP-001` | `test_compose_application_lifecycle` | Covered | Support | Pull, create, start, DNS, exit status, published-port HTTP, list, and teardown. |
| `CMP-002` | `test_compose_repeated_up_is_idempotent` | Covered | Support | Reconciliation preserves unchanged containers. |
| `CMP-003` | `test_compose_force_recreate_renames_replacement` | Covered | Support | Replacement containers receive canonical Compose names. |
| `CMP-004` | `test_compose_scale_and_reconcile` | Covered | Support | Scaling creates the requested replicas, preserves them on repeated up, and removes excess replicas. |
| `CMP-005` | `test_compose_exec_stop_start_and_restart` | Covered | Support | Compose exec and service lifecycle commands work without replacing the container. |
| `CMP-006` | `test_compose_named_volume_down_semantics` | Covered | Support | Named data survives ordinary down and is deleted by `down --volumes`. |
| `CMP-007` | `test_compose_waits_for_healthy_dependency` | Covered | Support | Health-conditioned dependencies start only after the prerequisite reports healthy. |
| `CMP-008` | `test_developer_compose_build_uses_context_default_builder` | Covered | Support | Bare context-qualified Compose 5.5.0 `build` and `up --build` select `cengine-builder`, create only `buildx_buildkit_cengine-builder0`, load the arm64 image, and run it. Managed setup registers the builder default under both the `cengine` context and its resolved Unix endpoint because Compose passes both to its standalone Buildx child. No `BUILDX_BUILDER`, `--builder`, temporary builder, legacy `/build` fallback, or emulated platform is involved. |
| `CMP-009` | `test_developer_compose_source_edits_hot_reload_without_replacement` | Covered | Support | Repeated host in-place and atomic-save edits plus a guest-originated atomic edit are observed through a 150 ms Python stable-content polling reloader without changing the service container or server process. The line-oriented reloader requires a complete newline-terminated payload and two consecutive matching reads before publication, matching and strengthening the `RTM-037` baseline. Compose Watch and event-only watchers remain out of scope. |
| `CMP-010` | `test_developer_compose_rebuild_restart_recovery_and_teardown` | Covered | Support | A changed image input rebuilds and recreates the service, an unchanged rebuild is idempotent, Compose restart preserves container identity, abrupt daemon recovery adopts the same service and builder, post-recovery source reload remains usable, and final teardown removes project resources. Recovery means adoption, not VM migration or cross-VM namespace sharing. |
| `CMP-040` | `test_compose_anonymous_volume_inheritance_and_renewal` | Covered | Support | Force recreation retains anonymous volume identity/data; --renew-anon-volumes replaces identity and removes the old sentinel. Pinned Compose subset. |
| `CMP-041` | `test_compose_external_volume_switches_identity_and_content` | Covered | Support | Switching external volume names recreates the service and isolates data; switch-back restores the first sentinel. down --volumes retains external volumes. |
| `CMP-042` | `test_compose_approved_volume_definition_change_recreates_data` | Covered | Support | Approved volume-label definition change recreates the managed volume under the same name, replaces its consumer and discards old contents. |
| `CMP-043` | `test_compose_unchanged_bind_does_not_recreate_container` | Covered | Support | Unchanged bind definition retains container ID/start time while the service reads the full completed host rewrite through host_close_to_open. |
| `CMP-044` | `test_compose_no_deps_recreates_only_selected_service` | Covered | Support | --force-recreate --no-deps app replaces only app despite changed dependency definition; dependency ID/start time/boot ID/health/label/sentinel stay unchanged. |
| `CMP-045` | `test_compose_redis_volume_backup_and_replacement` | Covered | Support | Nonroot Redis snapshot/restore uses read-only backup sidecar and named/external volume retention; ORC-024 supplies the optional reference comparison. |

## Docker Buildx and BuildKit 0.32.2

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `BLD-001` | `test_buildx_load_run_cache_and_volume_copy` | Covered | Support | The managed overlayfs builder supports non-scratch `COPY`, `RUN`, load, cache reuse, and volume initialization. |
| `BLD-002` | `test_buildx_pull_succeeds_after_daemon_restart` | Covered | Support | A recovered BuildKit VM regains carrier, DNS, and registry access for a fresh pull. |
| `BLD-003` | `test_buildx_overlay_worker_has_large_state_volume` | Covered | Support | Parallel stages use overlayfs on a 512 GiB sparse block-backed state volume. |
| `BLD-004` | `test_buildx_relaunches_missing_stopped_container_shim` | Covered | Support | A stopped BuildKit container relaunches its missing VM shim after a daemon replacement without losing its writable root. |
| `BLD-005` | `test_buildx_recovers_uplink_after_network_helper_restart` | Covered | Support | A running BuildKit VM automatically recreates its vmnet uplink after the dedicated compatibility helper performs an authenticated, launchd-managed restart without another administrator session. |
| `BLD-006` | `test_managed_docker_context_and_default_builder` | Covered | Support | The shipped synchronous `cengine system configure-docker` command creates the exact `cengine` context and `cengine-builder` in fresh isolated client state without activating the context globally. It persists exactly the context and resolved Unix-endpoint Buildx default keys while leaving ordinary Docker defaults untouched. A bare context-qualified Buildx build/load/run uses the pinned BuildKit image, overlayfs, and configured resources; repeated reconciliation preserves context endpoint, BuildKit container, and state volume. No builder override, temporary builder, legacy `POST /build`, or cross-architecture execution is involved. |
| `BLD-007` | `test_buildx_bake_load_immediately_publishes_every_target` | Covered | Support | A two-target Bake creates distinct images and loads both through concurrent Docker exporters; every explicit tag is inspectable as soon as Bake returns, while BuildKit's shared `org.opencontainers.image.ref.name=local` metadata does not become a Docker tag. This locks down the synchronous visibility promised by Docker API v1.55 [`POST /images/load`](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Image/operation/ImageLoad). |

## Daemon recovery

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `REC-001` | `test_daemon_restart_recovers_resources_and_restart_policy` | Covered | Support | An abrupt daemon restart preserves resources and restarts an `always` container. |
| `REC-002` | `test_daemon_restart_during_active_io_and_stats` | Covered | Support | Recovery remains correct while log and stats streams are active. |
| `REC-003` | `test_daemon_restart_recreates_usable_network_interfaces` | Covered | Support | Logical vmnet restoration recreates a carrier-up interface with working DNS and internet access. |
| `REC-004` | `test_running_workload_survives_daemon_process_replacement` | Covered | Support | A daemon process replacement reconnects to the existing VM shim without changing container start time. Same-boot daemon replacements reuse the owner-only random runtime namespace only when its persisted directory identity still matches; focused Swift tests cover next-boot namespace rotation, same-boot replacement rejection, and safe retirement of pre-boot publications without mutating a replacement directory. |
| `REC-005` | `test_vmnet_reservation_is_released_when_infrastructure_shim_exits` | Covered | Support | Exact infrastructure-shim incarnation exit releases privileged vmnet reservations before recovery. Owned process census and immutable generation spec select the target, not PID/name patterns. |
| `REC-006` | `test_daemon_restart_honors_manually_stopped_restart_policies` | Covered | Support | Manual stop is durably published before reply. Daemon recovery restarts always but leaves unless-stopped exited; stop/kill joins canonical persistence rather than racing completion. |

## Docker CLI

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `CLI-001` | `test_cli_system_and_image_commands` | Covered | Support | Version, info, pull, and image listing through the Docker CLI. |
| `CLI-002` | `test_cli_container_lifecycle` | Covered | Support | Create, start, inspect, list, stop, and remove through the Docker CLI. |
| `CLI-003` | `test_cli_run_attached_output` | Covered | Support | Attached `docker run` output and automatic removal. |
| `CLI-004` | `test_cli_run_attached_stdin` | Covered | Support | Interactive stdin over the hijacked attach connection. |
| `CLI-005` | `test_cli_network_and_volume_lifecycle` | Covered | Support | Network and volume create, list, and remove commands. |
| `CLI-006` | `test_cli_system_disk_usage` | Covered | Support | Base and verbose `docker system df` render engine-owned usage. |
| `CLI-007` | `test_cli_detached_kind_shaped_run` | Covered | Support | Detached runs acknowledge next-exit waits before start and preserve kind-style network and mount configuration. |
| `CLI-008` | `test_cengine_run_scopes_container_resources_and_process_behavior` | Covered | Support | The cengine wrapper preserves process behavior, isolates its Docker endpoint, and overrides create-time CPU and memory without changing ordinary defaults. |
| `CLI-009` | `test_cli_run_interactive_tty_uses_client_console_size` | Covered | Support | A real pseudoterminal drives `docker run --rm -it`; Docker CLI 29.6.2's create-time `ConsoleSize` reaches the guest PTY and is observed by `stty size`. |

## kind 0.32.0

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `KND-001` | `test_kind_create_cluster` | Covered | Support | Real kind control-plane readiness, resource limits, CoreDNS/CNI, pod exec, service VIP and host.docker.internal resolution through cluster DNS. Scoped creation/deletion; focused RTM contracts remain the runtime authority. |

## Optional Docker differential oracle

| ID | Test function | Status | Intent | Contract / limits |
|---|---|---|---|---|
| `ORC-001` | `test_container_lifecycle_matches_reference_docker` | Covered | Support | With `DOCKER_REFERENCE_HOST`, compares normalized create/inspect/filter/conflict/stop behavior to a real Docker Engine. |
| `ORC-002` | `test_image_metadata_matches_reference_docker` | Covered | Support | With a multi-platform reference image store, compares descriptor, manifest-summary, identity, and selected-platform response shapes. |
| `ORC-003` | `test_runtime_process_context_matches_reference_docker` | Covered | Support | With `DOCKER_REFERENCE_HOST`, compares omitted/explicit exec context under an explicitly enabled no-new-privileges policy, Docker's default and explicit-false `NoNewPrivs=0`, exact missing init identity behavior, and the HTTP 400 exec-create phase for missing exec identities. Host bind paths, unstable IDs, PIDs, timestamps, and engine-specific error strings are excluded. |
| `ORC-004` | `test_runtime_error_contract_against_reference_docker` | Covered | Support | With `DOCKER_REFERENCE_HOST`, compares the exact invalid-user failure phase plus invalid cwd, command, and mount outcomes. It also directly compares Docker's `soft > hard` ulimit lifecycle: successful create and anonymous-volume mutation followed by an HTTP 500 start failure that leaves the container created. |
| `ORC-020` | `test_serial_volume_filesystem_matches_reference` | Covered | Support | Exact Docker/direct/shared filesystem observations include open-unlink and retained nlink/data, with explicit FUSE backend proof. Seeded serial plans and bounded mismatch-preserving reduction are not exhaustive POSIX certification. |
| `ORC-021` | `test_curated_volume_primitives_match_reference` | Covered | Support / intentional API validation-class difference | Six curated parity assertions plus separate invalid-copy diagnostic: named :copy and bind :copy/:nocopy fail at create without resources. Docker HTTP 500 versus deliberate cengine 400 is a documented difference, not normalized parity. |
| `ORC-022` | `test_curated_compose_volumes_match_reference` | Covered | Support | Reference/cengine Compose comparison covers external switching, approved definition change, anonymous inheritance/renewal and no-deps. Owned resources only; no host-bind oracle. |
| `ORC-023` | `test_bounded_upstream_filesystem_corpus_matches_reference` | Covered | Support | Exact reference/direct/shared bounded pinned filesystem corpus. Requires actual unchanged binary/case completion, not normalized errors or exhaustive POSIX parity. |
| `ORC-024` | `test_compose_redis_volume_matches_reference` | Covered | Support | Reference/cengine nonroot Redis snapshot/restore, read-only backup sidecar and named/external volume retention. |
| `ORC-025` | `test_volume_lock_scope_against_reference` | Covered | Intentional gap / Support | Reference distributed contention is contrasted with intentional cengine client-local shared locks; simultaneous initialization is separately verified. Passing this diagnostic does not implement distributed application locking. |

## Additional normative references

These define the runtime mechanisms and API subcontracts above; a link does not
expand the supported surface or the test scope.

- [stat(2)](https://keith.github.io/xcode-man-pages/stat.2.html)
- [container wait](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Container/operation/ContainerWait)
- [syncfs(2)](https://man7.org/linux/man-pages/man2/sync.2.html)
- [umount(2)](https://man7.org/linux/man-pages/man2/umount.2.html)
- [reboot(2)](https://man7.org/linux/man-pages/man2/reboot.2.html)
- [FUSE background requests and interruption](https://docs.kernel.org/filesystems/fuse/fuse.html)
- [`setns(2)`](https://man7.org/linux/man-pages/man2/setns.2.html)
- [`/proc/sys/net` sysctl interface](https://docs.kernel.org/admin-guide/sysctl/net.html)
- [launchd.plist](https://keith.github.io/xcode-man-pages/launchd.plist.5.html)
- [pwrite(2)](https://man7.org/linux/man-pages/man2/pwrite.2.html)
- [ftruncate(2)](https://man7.org/linux/man-pages/man2/truncate.2.html)
- [mmap(2)](https://man7.org/linux/man-pages/man2/mmap.2.html)
- [msync(2)](https://man7.org/linux/man-pages/man2/msync.2.html)
- [lseek(2)](https://man7.org/linux/man-pages/man2/lseek.2.html)
- [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
- [TLS 1.3 client certificate validation](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2.2)
- [pread(2)](https://man7.org/linux/man-pages/man2/pread.2.html)
- [flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html)
- [empty-volume population](https://docs.docker.com/engine/storage/volumes/#mounting-a-volume-over-existing-data)
- [name_to_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html)
- [poll/ppoll EINTR](https://man7.org/linux/man-pages/man2/poll.2.html)
- [pidfd_open readiness](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
- [atime](https://man7.org/linux/man-pages/man7/inode.7.html)
- [credentials](https://man7.org/linux/man-pages/man7/credentials.7.html)
- [ioctl](https://man7.org/linux/man-pages/man2/ioctl.2.html)
- [ContainerWait](https://docs.docker.com/reference/api/engine/version/v1.47/#tag/Container/operation/ContainerWait)
- [ContainerLogs](https://docs.docker.com/reference/api/engine/version/v1.47/#tag/Container/operation/ContainerLogs)
- [ContainerStart](https://docs.docker.com/reference/api/engine/version/v1.47/#tag/Container/operation/ContainerStart)
- [Linux capabilities](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#capabilities)
- [xattr(7)](https://man7.org/linux/man-pages/man7/xattr.7.html)
- [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [symlink(7)](https://man7.org/linux/man-pages/man7/symlink.7.html)
- [chown(2)](https://man7.org/linux/man-pages/man2/chown.2.html)
- [utimensat(2)](https://man7.org/linux/man-pages/man2/utimensat.2.html)
- [network API](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Network)
- [bridge networking](https://docs.docker.com/engine/network/drivers/bridge/)
- [events API](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/System/operation/SystemEvents)
- [close(2)](https://man7.org/linux/man-pages/man2/close.2.html)
- [getdents(2)](https://man7.org/linux/man-pages/man2/getdents.2.html)
- [`/proc/pid/stat` field 22](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html)
- [container start](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Container/operation/ContainerStart)
- [image-layer file attributes](https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md#file-attributes)
- [errseq](https://docs.kernel.org/core-api/errseq.html)
- [Linux FUSE I/O contract](https://docs.kernel.org/filesystems/fuse/fuse-io.html)
- [`mkdir(2)`](https://man7.org/linux/man-pages/man2/mkdir.2.html)
- [`exports(5)`](https://man7.org/linux/man-pages/man5/exports.5.html)
- [volume removal](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Volume/operation/VolumeDelete)
- [`link(2)`](https://man7.org/linux/man-pages/man2/link.2.html)
- [`acl(5)`](https://man7.org/linux/man-pages/man5/acl.5.html)
- [`proc_pid_mountinfo(5)`](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html)
- [`mke2fs(8)` `-U`](https://man7.org/linux/man-pages/man8/mke2fs.8.html)
- [ExecStart](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Exec/operation/ExecStart)
- [symlink(2)](https://man7.org/linux/man-pages/man2/symlink.2.html)
- [ContainerKill](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Container/operation/ContainerKill)
- [chmod(2)](https://man7.org/linux/man-pages/man2/chmod.2.html)
- [ContainerStop](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Container/operation/ContainerStop)
- [restart policy](https://docs.docker.com/reference/cli/docker/container/run/#restart)
- [API v1.55 update semantics](https://docs.docker.com/reference/api/engine/version-history/#v155-api-changes)
- [Linux cgroup-v2 `io.max` contract](https://docs.kernel.org/admin-guide/cgroup-v2.html#io)
- [OCI block-I/O resources](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#block-io)
- [default OCI paths](https://github.com/moby/moby/blob/docker-v29.6.2/daemon/pkg/oci/defaults.go)
- [masked paths and read-only paths](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#masked-paths)
- [`readonlyPath` and `maskPaths`](https://github.com/opencontainers/runc/blob/v1.3.3/libcontainer/rootfs_linux.go)
- [GHSA-9493-h29p-rfm2](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [block-I/O weight contract](https://docs.docker.com/reference/cli/docker/container/run/#block-io-bandwidth-blkio-constraint)
- [cgroup-v2 weight distribution model](https://docs.kernel.org/admin-guide/cgroup-v2.html#weights)
- [disk-image storage attachment API](https://developer.apple.com/documentation/virtualization/vzdiskimagestoragedeviceattachment)
- [`--security-opt no-new-privileges`](https://docs.docker.com/reference/cli/docker/container/run/#optional-security-options---security-opt)
- [security-option parsing and boolean override contract](https://github.com/moby/moby/blob/docker-v29.1.5/daemon/daemon_unix.go)
- [`PR_SET_NO_NEW_PRIVS`](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html)
- [default allowed-device rules](https://github.com/opencontainers/runc/blob/v1.3.3/libcontainer/specconv/spec_linux.go#L776-L922)
- [default devices and allowed device list](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#devices)
- [cgroup-v2 BPF device controller](https://docs.kernel.org/admin-guide/cgroup-v2.html#device-controller)
- [`bpf(2)` `EAGAIN` handling](https://man7.org/linux/man-pages/man2/bpf.2.html#ERRORS)
- [pinned built-in default seccomp profile](https://github.com/moby/profiles/blob/f9bc03ec19b2dc4c091449b08e88f85c0caa9f0b/seccomp/default.json)
- [default seccomp documentation](https://docs.docker.com/engine/security/seccomp/)
- [`linux.seccomp`](https://github.com/opencontainers/runtime-spec/blob/v1.3.0/config-linux.md#seccomp)
- [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [seccomp filter documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [container create](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Container/operation/ContainerCreate)
- [container resize](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Container/operation/ContainerResize)
- [exec resize](https://docs.docker.com/reference/api/engine/version/v1.55/#tag/Exec/operation/ExecResize)
- [`TIOCSWINSZ`](https://man7.org/linux/man-pages/man2/TIOCSWINSZ.2const.html)
- [namespaced sysctl contract](https://docs.docker.com/engine/containers/run/#configure-namespaced-kernel-parameters-sysctls-at-runtime)
- [sysctl validation](https://github.com/opencontainers/runc/blob/v1.3.3/libcontainer/configs/validate/validator.go)
- [`setLinuxDomainname`](https://github.com/moby/moby/blob/docker-v29.6.2/daemon/oci_utils.go)
- [`TestNISDomainname`](https://github.com/moby/moby/blob/docker-v29.6.2/integration/container/run_linux_test.go)
- [`uts_namespaces(7)`](https://man7.org/linux/man-pages/man7/uts_namespaces.7.html)
- [volume subpath](https://docs.docker.com/engine/storage/volumes/#options-for---mount)
- [`openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html)
