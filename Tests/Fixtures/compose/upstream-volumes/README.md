# Curated Compose volume scenarios

These small cengine-owned fixtures adapt observable scenarios from Docker Compose
at commit `e9491499f116984e00b89a39b53a8b28d33ad4c7`. They do not vendor upstream
fixtures, the Go scenario runner, or upstream implementation code.

Source: [pkg/e2e/volumes_test.go](https://github.com/docker/compose/blob/e9491499f116984e00b89a39b53a8b28d33ad4c7/pkg/e2e/volumes_test.go)

| Compatibility ID | Upstream scenario | Local assertion |
| --- | --- | --- |
| CMP-040 | `TestLocalComposeVolume`, anonymous inheritance and renewal subtests | Force recreation changes the container but retains the anonymous mount name and sentinel; renewal changes the mount name and starts without the sentinel. |
| CMP-041 | `TestUpSwitchVolumes` | Switching external names recreates the service, exposes independent contents, and switching back restores the first sentinel; Compose teardown leaves both external volumes intact. |
| CMP-042 | `TestUpRecreateVolumes` | An approved (`up --yes`) label-definition change recreates a managed volume under the same name, changes its label, replaces its consumer, and discards old contents. |
| CMP-043 | `TestUpRecreateVolumesIgnoreBinds` | An unchanged bind declaration preserves container identity and start time even when host file contents change. |

Source: [pkg/e2e/recreate_no_deps_test.go](https://github.com/docker/compose/blob/e9491499f116984e00b89a39b53a8b28d33ad4c7/pkg/e2e/recreate_no_deps_test.go)

| Compatibility ID | Upstream scenario | Local assertion |
| --- | --- | --- |
| CMP-044 | `TestRecreateWithNoDeps` | `up --force-recreate --no-deps app` replaces only the selected service; its healthy dependency retains ID, start time, guest boot ID, label, and sentinel despite a pending dependency-only label change. |

## Scope and contracts

- [Compose up](https://docs.docker.com/reference/cli/docker/compose/up/) defines
  recreation, anonymous-volume renewal, `--no-deps`, and noninteractive approval.
- [Compose volumes](https://docs.docker.com/reference/compose-file/volumes/) defines
  external ownership, name selection, and labels. The approved label-change
  reconciliation policy is additionally pinned to `TestUpRecreateVolumes` above.
- These are Compose/Engine reconciliation contracts, not new OCI runtime
  requirements. Ordinary volume and bind mounts apply on cengine's per-container
  VMs; no cross-container namespaces, Linux-host bind paths, volume drivers,
  image mounts, build operations, or upstream fixture images are required.
- CMP-040 strengthens upstream's command-exit checks with explicit mount identity
  and positive/negative sentinel assertions. CMP-041 checks data, not only inspect.
  CMP-044 changes the dependency definition so accidentally ignoring `--no-deps`
  cannot pass merely because that dependency was already up to date.
- Existing CMP-002/CMP-003 cover generic unchanged-up/replacement identity,
  CMP-006 covers ordinary named-volume down semantics, and CMP-007 covers healthy
  dependency startup. Those generic cases are not copied; the selected pilot
  adds mount-specific reconciliation and the distinct no-deps mutation boundary.

Every image uses the Alpine digest already seeded by `conftest.py`. Tests copy
fixtures into a unique daemon-owned project directory and use an explicit daemon
endpoint, runner-owned Docker state, cleared ambient Compose options, and an empty
env file. Teardown removes only that project's resources and explicitly tracks
external and orphaned anonymous volumes; no global prune or upstream runner is used.

Runtime verification is intentionally performed by the serialized compatibility
runner, not by fixture creation or syntax checks.
