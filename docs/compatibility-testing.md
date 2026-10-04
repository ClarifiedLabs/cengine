# Deterministic compatibility test lifecycle

Use `make test-compat` as the only entry point for Docker compatibility tests. Do not
start the daemon manually or invoke the compatibility `pytest` suite directly. The
runner owns the complete lifecycle so every run begins from a known state.

The suite requires Apple silicon, macOS 26+, Docker CLI/Buildx, Docker Compose 5.x,
and kind (v0.32.0 is the reference version). Compose 5.x minor/patch updates are
accepted; `bash Scripts/install-compose-compat.sh` installs a checksum-pinned
reference release. Use `CENGINE_DEVELOPER_ID_APPLICATION` for matching signed
engine, controller and helper identities. VM-backed tests are a local gate, not
part of the GitHub-hosted test workflow.

## Normal lifecycle

`make test-compat` performs these phases in order:

1. Acquire a host-wide compatibility lock. Concurrent runs fail rather than sharing
   VM, vmnet, Docker, or temporary state.
2. Remove Docker and Buildx environment overrides inherited from the caller.
3. Stop compatibility daemons and VM shims owned by this cengine binary, remove their
   temporary engine roots, and assert that both processes and roots are gone.
4. Fingerprint the helper's sources and toolchain, build and Developer-ID-sign the isolated
   `test-compat` daemon and helper identities, then authenticate to the preprovisioned
   `dev.cengine.network-helper.test-compat` LaunchDaemon. Validate its owner, files,
   manifest checksum, signature, launchd state, identity, and protocol without changing
   the installation or requesting administrator authorization.
5. Rebuild the Linux guest assets (or validate an explicitly supplied paired asset
   directory), validate the kernel/provenance contract, and reject
   compatibility address pools that overlap an active host interface or specific route.
6. Delete and recreate the Python virtual environment from the pinned requirements.
7. Let the pytest harness create a unique engine root and Docker configuration for the
   run, then execute the requested tests.
8. On success, failure, or interruption, stop all owned processes, remove temporary
   roots, assert the state is clean, and release the lock. The test helper remains
   installed for later runs.

Before **each new ordinary pytest daemon fixture root** (including manual first start),
the harness performs one authenticated test-helper process restart. It is never part of
`Daemon.start()`, daemon restart, or recovery, and collection/skipped fixtures do not
restart it. This bounds process-local helper registrations without increasing capacity,
reinstalling the helper, or deleting protected lifecycle journals. The image cache only
caches content; it does not start a daemon.

All three supported launchers (`run-compat-tests.sh`, `run-isolated-cengine.sh`, and
`managed-prepare-matrix.sh`) use `/private/tmp/cengine-compat-run-UID.lock`, created
owner-private. `CENGINE_COMPAT_LOCK` may only name that exact path; `TMPDIR` must resolve
to the macOS user's standard temporary directory, and `HOME` must be the UID's canonical
home (so retained matrix roots cannot move out of the census). There is no stale-lock stealing.
Each launcher pins its own PID/kernel process generation, lock device/inode, and PID-file device/inode/change time
immediately after publishing ownership. Cleanup revalidates that receipt before reset,
client-state deletion, and claim release; a replaced/forged claim refuses without signalling
or deleting evidence. Claim release removes only the verified PID file and empty directory,
never recursively deleting unexpected entries. Interrupted/failed acquisition leaves the
claim for explicit investigation rather than guessing that stale ownership authorizes deletion.
The fixture checks the claim, requires the previous fixture's final cleanup to have
completed (including expected call-phase xfails), refuses any leftover/unknown root in
the standard user temp, `/private/tmp`, or matrix work cache, and performs a conservative
read-only current-UID kernel process census. Active daemon/shim/private-controller
clients or inspection uncertainty refuse; no client is signalled by this guard.
The installed fingerprint exported by preflight, exact test namespace, current UID,
protocol and signed `--require-managed lifecycle-v2` status must match. One bounded
restart must produce a different PID, followed by authenticated status with unchanged
identity and capabilities. The read-only root/client census runs again after that final
status, before any new root can be created. Failure/timeout poisons the fixture boundary: no retry and
no new root. Retained roots require explicit investigation, never automatic disposal.
These guards cover supported launchers; unsynchronized direct/private launchers are
unsupported. Historical roots placed in arbitrary nonstandard directories are not
inventoried automatically.

Compiler intermediates and the pinned kernel build are caches, not runtime state. They
remain between runs; Xcode dependency tracking rebuilds changed sources, guest assets
are repacked on every run, and the kernel hash/version check prevents a stale or
unapproved kernel from entering a VM.

## Managed compatibility helper

The **Privileged Helper** (`cengine-helper`) handles both privileged networking and
storage ownership/authorization. Its CLI is `cengine helper status|restart`; storage
preflight uses `cengine helper status --require-managed lifecycle-v2` (or
`lifecycle-qualification` for the closed qualification lane). Shared volumes use
FUSE backed by ext4 in the storage VM. Unsupported store formats are rejected
without modifying their data; cengine does not migrate or automatically reset them.
Preserve the store and its recovery metadata.

The helper uses `dev.cengine.network-helper[.test-compat]` service/signing identifiers
and `CENGINE_NETWORK_HELPER_*` environment keys. Installation must preserve its
protected storage directories and authority.

Provision the dedicated test helper once before running compatibility tests:

```sh
make test-compat-helper-install   # attended administrator action
make test-compat-doctor
make test-compat                  # unattended thereafter
```

The helper is shared across worktrees: replacing it stops its VMNet uplinks. Have
all consumers' owners quiesce their work, or explicitly approve interruption, before
an update. A separate DerivedData directory does not make the helper private. Never
stop foreign shims or downgrade the helper to run old tests.

The install target acquires the compatibility lock, performs the worktree-scoped reset,
builds and signs the local `test-compat` products, and installs or updates the helper
under `/Library/Application Support/cengine/compat/` in one administrator transaction.
It automatically provisions the test owner and exits before building guest assets
or running pytest. No installed cengine app or manual root-helper
`enroll-storage-owner` command is required for tests. Production ownership is a
separate explicit one-time action: app onboarding/Enable/Restart or
`cengine helper setup-storage-owner` as the normal user with administrator approval.
Normal production startup checks only; the first XPC caller cannot enroll itself.

Normal suite, soak, oracle, and isolated-tool runs never request administrator
authorization and never repair or replace the helper. They fail with the install command
when the service is missing, damaged, unloaded, provisioned for another macOS UID, or
protocol-incompatible. The helper fingerprint is provenance rather than a compatibility
gate: daemon/API/test changes and Swift, Xcode, SDK, or compatible helper-source drift do
not require reinstalling it. Such runs report fingerprint drift and export the installed
fingerprint to the tests. Ordinary signed managed runs additionally authenticate the
actual root helper's audit token, process generation, Developer ID/team, namespace and
profile, then require its bounded versioned capabilities and compiled minimum security
revision. Missing capabilities, stale security revisions or incompatible contracts refuse;
there is no fallback to a weaker status check. The installed executable must still match
its root-owned installation manifest and pass signature/integrity checks.

Lifecycle qualification, PREPARE-profile assets and lifecycle fault campaigns still require
an exact local source fingerprint **and full signed CodeDirectory digest**. For explicit
helper/security/release qualification, set `CENGINE_COMPAT_REQUIRE_EXACT_HELPER=1`;
this is a stricter-only option, not a bypass. Unknown or contradictory selections refuse.
Ordinary compatibility results describe the installed compatible helper, not qualification
of an uninstalled local helper change.

Use `tools/managed-prepare-matrix.sh` for the full PREPARE campaign. It supplies
`PREPARE_COMPATIBILITY_PROFILE` and `CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY`
as `rtm096-full-nine-v3` plus exact-helper qualification. Build its paired assets
with `Scripts/build-guest-assets.sh
--prepare-compatibility=rtm096-full-nine-v3` into a dedicated `CENGINE_GUEST_OUTPUT`.
They must advertise `storageLifecycleVersion: 2` and match the current source pin;
partial/mismatched profiles or mixed qualification/fault selections refuse.
Ordinary lifecycle builds remain fault-free.

The test helper has a distinct service name, executable identity, client identity,
authentication token, and per-engine-root vmnet resource namespace. Its automatic
IPv4 and IPv6 pools also differ from the production defaults. An installed cengine
helper service `dev.cengine.network-helper` is never changed. The fixture's conservative
current-UID census may refuse while a production daemon is running; it never stops it.

Run `make test-compat-helper-install` deliberately after changing helper behavior that
must be exercised by live VM-backed tests or after an incompatible protocol change.
Until then, VM-backed tests continue to exercise the installed helper even though normal
build and unit checks compile the local `Sources/CEngineNetworkHelper` source. Incompatible
networking wire or required semantic changes must bump `PrivilegedPortProtocol.version`.
Managed storage incompatibilities require a new capability contract. Both lifecycle
requirements (`lifecycle-v2` and `lifecycle-qualification`) enforce the complete
contract set compiled into `NetworkHelperCapabilities.validate(_:for:)` in
`Sources/CEngineCore/NetworkHelperCapabilities.swift`. A helper missing any required
contract must be updated through the attended install target before starting VMs.
Guest-only or engine-only changes do not ordinarily require repeated helper
updates; exact-pair campaigns enforce their stricter match. Only required security
fixes must raise `NetworkHelperCapabilities.minimumSecurityRevision` and the
implementing helper's `securityRevision`. Status has a closed schema: new top-level
fields also require protocol version discipline, not silent same-version extension.

The helper links only `CEngineHelperSupport`, whose explicit shared-source closure is
`Configuration/helper-support-sources.txt`, rather than the general engine core. Engine-only
edits therefore cannot change its executable. Source files are shared, not forked; the
fingerprint covers every selected helper/support input. Updates preserve the protected
`storage-lifecycle-v2` directory by rename, including rollback; unknown layouts or interrupted
installation backups refuse rather than deleting authority. Explicit uninstall remains a
separate destructive administrative action.

Inspect the setup before a long run, update it deliberately, or remove it explicitly:

```sh
make test-compat-doctor
make test-compat-helper-install
make test-compat-helper-uninstall
```

Uninstall affects only `dev.cengine.network-helper.test-compat`; it does not stop or
modify the production helper.

The runner defaults to `10.192.0.0/12` and `fdcc::/16` for automatically allocated
test networks, with `10.208.0.0/12` and `fdcd::/16` reserved for explicit fixtures.
Override these with `CENGINE_COMPAT_IPV4_AUTO_POOL`,
`CENGINE_COMPAT_IPV6_AUTO_PREFIX`, `CENGINE_COMPAT_IPV4_FIXTURE_POOL`, and
`CENGINE_COMPAT_IPV6_FIXTURE_PREFIX` when a host VPN or LAN uses those ranges.

## Local guest assets

Ordinary runs build `.build/guest`. Use
`CENGINE_COMPAT_MANAGED_ASSET_DIR=/absolute/path` to supply a complete paired asset
set matching the current source. The runner derives kernel and both initramfs
paths from that directory. Set `CENGINE_LOCAL_KERNEL=/path/to/Image` or
`CENGINE_KERNEL_MODE=build` when building assets with a local kernel. Local
provenance is valid for development/testing, not canonical release qualification.
Use a matching `CENGINE_DEVELOPER_ID_APPLICATION` signing identity for the daemon,
controller and test helper. See [Development](development.md) for kernel commands.

Fixture images are fetched into a versioned immutable seed content store and
APFS-cloned into each fresh root; mutable engine metadata is never shared. Override
the fixture image with `CENGINE_TEST_IMAGE` and its source mirror with
`CENGINE_TEST_IMAGE_SOURCE`. The default Alpine fixture uses
`mirror.gcr.io/library/alpine:latest` to avoid anonymous Docker Hub rate limits.
Use `CENGINE_BINARY` for a custom daemon and `CENGINE_EXPECTED_GIT_COMMIT` for its
expected source revision. The harness checks daemon identity and Docker CLI access
to a sentinel on each isolated socket before running scenarios.

## Focused and repeated runs

Pass pytest arguments through `COMPAT_ARGS` without bypassing the lifecycle. Include
`Tests/Compatibility` or specific test paths when overriding it; flags alone can
collect unrelated tool tests:

```sh
make test-compat COMPAT_ARGS='Tests/Compatibility/test_kind.py -x -vv'
make test-compat-soak
```

Each soak seed receives another runtime reset. The binary and immutable guest inputs
are shared within that one locked invocation because they cannot change during it.
Use `make test-compat-reset` for worktree-scoped cleanup without running tests;
it never stops an installed engine or processes from another checkout.

For oracle tests, supply `DOCKER_REFERENCE_HOST` explicitly to
`make test-compat-oracle`; the active Docker context is never the reference.
Destructive tests require an explicitly authorized disposable reference engine.

## Exceptional macOS networking recovery

Normal process teardown releases vmnet state. If macOS retains a reservation after a
helper or OS crash, perform the explicit privileged recovery and then start a normal
run:

```sh
make test-compat-reset-system
make test-compat
```

The system recovery is intentionally not part of every run: it restarts macOS
NetworkSharing and the compatibility helper, affects host-global networking, and
requires administrator authorization. It refuses to run while the production cengine
service is loaded unless `CENGINE_COMPAT_ALLOW_GLOBAL_NETWORK_RESET=1` is explicitly
set. A normal run never silently depends on it.
