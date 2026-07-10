# Docker SDK compatibility

This ledger tracks cengine against the docker-py compatibility tests maintained
by Podman. The source inventory is pinned to Podman commit
[`ac46410007edf94c9c5482c5d83c1471cfd23b00`](https://github.com/containers/podman/tree/ac46410007edf94c9c5482c5d83c1471cfd23b00/test/python/docker/compat),
with assertions adapted to Docker Engine semantics where Podman tests its own
quirks. The active suite uses docker-py 7.2.0 and Docker API v1.44.

Run the current container tranche with `make test-docker-py`. Known failures
are strict expected failures: a new failure or an unexpected pass fails the
command until this ledger and the test disposition are updated.

Status values are **Pass**, **Known fail**, and **Not assessed**. Intent values
are **Support**, **Intentional gap**, and **Undecided**.

## Containers

| ID | Upstream test | Status | Intent | Notes |
|---|---|---|---|---|
| `CTR-001` | `test_create_container` | Pass | Support | Create and list through docker-py. |
| `CTR-002` | `test_create_network` | Pass | Support | Bridge network creation. |
| `CTR-003` | `test_start_container` | Pass | Support | Created-container accounting. |
| `CTR-004` | `test_start_container_with_random_port_bind` | Pass | Support | Strengthened to require a nonzero assigned host port after start. |
| `CTR-005` | `test_stop_container` | Pass | Support | State becomes exited. |
| `CTR-006` | `test_kill_container` | Pass | Support | SIGKILL is reconciled before the response completes. |
| `CTR-007` | `test_restart_container` | Pass | Support | Restart after stop. |
| `CTR-008` | `test_remove_container` | Pass | Support | Force removal of a running container. |
| `CTR-009` | `test_remove_container_without_force` | Pass | Support | Uses Docker's HTTP 409 conflict rather than Podman's HTTP 500 assertion. |
| `CTR-010` | `test_pause_container` | Pass | Support | Pause and inspect. |
| `CTR-011` | `test_pause_stopped_container` | Pass | Support | Uses Docker's HTTP 409 conflict. |
| `CTR-012` | `test_unpause_container` | Pass | Support | Resume and inspect. |
| `CTR-013` | `test_list_container` | Pass | Support | List all containers. |
| `CTR-014` | `test_filters` | Pass | Support | Enabled even though Podman currently skips it. |
| `CTR-015` | `test_copy_to_container` | Pass | Support | Content, mode, and numeric tar UID/GID are preserved inside the guest. |
| `CTR-016` | `test_mount_preexisting_dir` | Known fail | Intentional gap | Requires direct `docker build`; cengine requires Buildx. |
| `CTR-017` | `test_non_existent_workdir` | Known fail | Intentional gap | Requires direct `docker build`; cengine requires Buildx. |
| `CTR-018` | `test_build_pull` | Known fail | Intentional gap | Requires direct `docker build`; cengine requires Buildx. |
| `CTR-019` | `test_mount_options_by_default` | Pass | Support | Checks normalized `HostConfig.Binds` and top-level `Mounts`. |
| `CTR-020` | `test_wait_next_exit` | Pass | Support | Blocks until the next start and exit, including from the created state. |
| `CTR-021` | `test_container_inspect_compatibility` | Pass | Support | Includes stable container, mount, network, logging, and host-config fields consumed by docker-py. |

## Images

| ID | Upstream test | Status | Intent | Notes |
|---|---|---|---|---|
| `IMG-001` | `test_tag_valid_image` | Known fail | Undecided | Image tagging endpoint is missing. |
| `IMG-002` | `test_retag_valid_image` | Known fail | Undecided | Image retagging endpoint is missing. |
| `IMG-003` | `test_list_images` | Known fail | Support | Listing works; reference filters are missing. |
| `IMG-004` | `test_search_image` | Known fail | Undecided | Registry search is not implemented; upstream currently skips this case. |
| `IMG-005` | `test_search_bogus_image` | Pass | Support | Unsupported search is surfaced as an API error. |
| `IMG-006` | `test_remove_image` | Pass | Support | Missing-image and successful removal behavior. |
| `IMG-007` | `test_image_history` | Pass | Support | History includes the image identifier. |
| `IMG-008` | `test_get_image_exists_not` | Pass | Support | Missing images return NotFound. |
| `IMG-009` | `test_save_image` | Known fail | Undecided | Docker archive export endpoint is missing. |
| `IMG-010` | `test_load_image` | Known fail | Undecided | Load exists, but save/load round trips cannot yet run. |
| `IMG-011` | `test_load_corrupt_image` | Pass | Support | Corrupt archives are rejected. |
| `IMG-012` | `test_build_image` | Known fail | Intentional gap | Direct build is intentionally unsupported. |
| `IMG-013` | `test_build_image_via_api_client` | Known fail | Intentional gap | Direct build is intentionally unsupported. |
| `IMG-014` | `test_push_error` | Known fail | Undecided | Image push endpoint is missing. |

## System

| ID | Upstream test | Status | Intent | Notes |
|---|---|---|---|---|
| `SYS-001` | `test_info` | Not assessed | Undecided | Podman's registry-mirror assertion must be adapted to Docker semantics. |
| `SYS-002` | `test_info_container_details` | Not assessed | Undecided | System tranche backlog. |
| `SYS-003` | `test_version` | Not assessed | Undecided | System tranche backlog. |
