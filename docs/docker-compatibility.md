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

## Black-box coverage map

| Exposed family | VM-backed coverage | Remaining black-box gaps |
|---|---|---|
| Negotiation, version, info | `SYS-001`–`SYS-003`, `CLI-001` | Operational shape sampling is concentrated at v1.44 and v1.55. |
| Container lifecycle and inspect | `CTR-001`–`CTR-014`, `CTR-019`–`CTR-024`, `CTR-026`, `CTR-029`, `CTR-031`–`CTR-034`, `EVT-001`–`EVT-002`, `CLI-002`–`CLI-004` | Higher-volume concurrent lifecycle stress is not assessed. |
| Archive, exec, observability, update | `CTR-015`, `CTR-025`, `CTR-027`, `CTR-028`, `CTR-030`, `CLI-006` | Disk usage, filtered logs, historical events, and multi-container stats have black-box coverage. |
| Networks, ports, and volumes | `CTR-002`, `CTR-004`, `NET-001`–`NET-012`, `VOL-001`–`VOL-005`, `CLI-005` | SCTP is not assessed. |
| Images and build | `IMG-001`–`IMG-015`, `BLD-001`–`BLD-002` | Authenticated push and pull-back use a pinned local registry. |
| Compose and recovery | `CMP-001`–`CMP-007`, `REC-001`–`REC-003` | Recovery is covered during log following, stats streaming, and active network use. |
| Differential behavior | `ORC-001` | Optional and limited to deterministic container lifecycle behavior. |

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
| 1.45 | Container network alias response semantics | Supported | v1.44 retains the short ID in `Aliases`; v1.45+ returns submitted aliases and uses `DNSNames` for runtime names. |
| 1.45 | Named-volume mount `VolumeOptions.Subpath` | Supported | Existing subdirectories are safely resolved beneath the named-volume root. |
| 1.45 | Image-inspect removal of `Container` and `ContainerConfig` | Supported | Cengine does not emit the removed legacy fields. |
| 1.46 | Containerd info, container annotations, endpoint sysctls, tmpfs options, push platform, and image-create events | Partial | Tmpfs size and mode are applied; the other additions remain gaps. |
| 1.47 | Image-list manifest summaries | Gap | The `manifests` option and `Manifests` response are not implemented. |
| 1.48 | Platform-aware history/load/save/push, image mounts, OCI descriptors/manifests, image-manifest descriptors, IPv4 network control, and gateway priority | Gap | These optional parameters and response fields are not implemented. |
| 1.49 | Platform-specific image inspect and firewall backend info | Gap | Image inspect uses the stored image platform; `FirewallBackend` is absent. |
| 1.50 | Platform-selective image deletion and discovered-device info | Gap | Deletion applies to the stored image and `DiscoveredDevices` is absent. |
| 1.50 | Removal of deprecated image-config fields | Supported | Cengine's image configuration already omits the removed runtime-only fields. |
| 1.51 | Image summary container usage count | Supported | v1.44-v1.50 report `-1`; v1.51+ calculate the number of containers using each image. |
| 1.52 | Event legacy-field removal and container/image response omissions | Supported | Responses branch at v1.52 while older API requests retain their legacy shape. |
| 1.52 | Container summary health and stats OS type | Supported | v1.52+ responses include `Health` and `os_type`. |
| 1.52 | Multi-platform image load/save, network IPAM status, event content negotiation, and verbose system disk usage | Partial | Base and verbose `/system/df` are implemented; multi-platform image and IPAM additions remain gaps. |
| 1.53 | NRI info, JSONL event negotiation, and image identity | Partial | Event streams negotiate `application/jsonl`; `NRI` and image `Identity` remain gaps. |
| 1.54 | Image-list identity and endpoint MAC application | Gap | The `identity` option and endpoint `MacAddress` are ignored. |
| 1.55 | Image attestations and per-device blkio updates | Gap | `GET /images/{name}/attestations` and the five blkio device arrays are not implemented. |

Status values are **✅ Pass**, **❌ Known fail**, and **⬜ Not assessed**. Intent
values are **Support**, **Intentional gap**, and **Undecided**.

Rows inherited from the original inventory retain the pinned Podman commit as
their origin. Rows identified as cengine-owned below are contracts added from
Docker Engine semantics or observed Docker Compose 5.3.1 behavior.

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
| `CTR-028` | `test_top_and_update` | ✅ Pass | Support | **cengine-owned.** Process listing and live resource-policy updates use Docker schemas. |
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

## System

| ID | Upstream test | Status | Intent | Notes |
|---|---|---|---|---|
| `SYS-001` | `test_info` | ✅ Pass | Support | Adapted from Podman registry configuration to cengine driver, platform, and root invariants. |
| `SYS-002` | `test_info_container_details` | ✅ Pass | Support | Container totals update after create. |
| `SYS-003` | `test_version` | ✅ Pass | Support | Platform name and negotiated API version. |

## Events

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `EVT-001` | `test_filtered_container_events` | ✅ Pass | Support | **cengine-owned.** Type, container, and label filters isolate live create, start, die, and destroy events. |
| `EVT-002` | `test_historical_events_honor_time_window_and_jsonl` | ✅ Pass | Support | **cengine-owned.** A bounded history honors time windows and API v1.53+ JSONL negotiation. |

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

## Docker Buildx 0.35

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `BLD-001` | `test_buildx_load_run_cache_and_volume_copy` | ✅ Pass | Support | The managed native-snapshotter builder supports non-scratch `COPY`, `RUN`, load, cache reuse, and volume initialization. |
| `BLD-002` | `test_buildx_pull_succeeds_after_daemon_restart` | ✅ Pass | Support | **cengine-owned.** A recovered BuildKit VM regains carrier, DNS, and registry access for a fresh pull. |

## Daemon recovery

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `REC-001` | `test_daemon_restart_recovers_resources_and_restart_policy` | ✅ Pass | Support | **cengine-owned.** An abrupt daemon restart preserves resources and restarts an `always` container. |
| `REC-002` | `test_daemon_restart_during_active_io_and_stats` | ✅ Pass | Support | **cengine-owned.** Recovery remains correct while log and stats streams are active. |
| `REC-003` | `test_daemon_restart_recreates_usable_network_interfaces` | ✅ Pass | Support | **cengine-owned.** Logical vmnet restoration recreates a carrier-up interface with working DNS and internet access. |
| `REC-004` | `test_running_workload_survives_daemon_process_replacement` | ✅ Pass | Support | **cengine-owned.** A daemon process replacement reconnects to the existing VM shim without changing container start time. |
| `REC-005` | `test_vmnet_reservation_is_released_when_infrastructure_shim_exits` | ✅ Pass | Support | **cengine-owned.** Infrastructure shim termination releases its privileged vmnet reservations before recovery. |

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

## kind 0.32.0

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `KND-001` | `test_kind_create_cluster` | ✅ Pass | Support | A real kind control-plane cluster creates a fresh dedicated network, reaches readiness, and is deleted through the isolated cengine daemon. |

## Optional Docker differential oracle

| ID | Contract | Status | Intent | Notes |
|---|---|---|---|---|
| `ORC-001` | `test_container_lifecycle_matches_reference_docker` | ✅ Pass | Support | With `DOCKER_REFERENCE_HOST`, compares normalized create/inspect/filter/conflict/stop behavior to a real Docker Engine. |
