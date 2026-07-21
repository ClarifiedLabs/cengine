# Deterministic compatibility test lifecycle

Use `make test-compat` as the only entry point for Docker compatibility tests. Do not
start the daemon manually or invoke the compatibility `pytest` suite directly. The
runner owns the complete lifecycle so every run begins from a known state.

## Normal lifecycle

`make test-compat` performs these phases in order:

1. Acquire a host-wide compatibility lock. Concurrent runs fail rather than sharing
   VM, vmnet, Docker, or temporary state.
2. Remove Docker and Buildx environment overrides inherited from the caller.
3. Stop compatibility daemons and VM shims owned by this cengine binary, remove their
   temporary engine roots, and assert that both processes and roots are gone.
4. Fingerprint the helper's sources and toolchain, build and ad-hoc sign the isolated
   `test-compat` daemon and helper identities, and check the dedicated persistent
   `dev.cengine.network-helper.test-compat` LaunchDaemon. If it is missing or stale,
   replace it in one administrator-authorized transaction and perform an authenticated
   health check. This happens before guest assets are built, so any authorization
   prompt appears near the beginning of the run.
5. Rebuild the Linux guest initramfs, validate the exact pinned guest kernel, and reject
   compatibility address pools that overlap an active host interface or specific route.
6. Delete and recreate the Python virtual environment from the pinned requirements.
7. Let the pytest harness create a unique engine root and Docker configuration for the
   run, then execute the requested tests.
8. On success, failure, or interruption, stop all owned processes, remove temporary
   roots, assert the state is clean, and release the lock. The test helper remains
   installed for later runs.

Compiler intermediates and the pinned kernel build are caches, not runtime state. They
remain between runs; Xcode dependency tracking rebuilds changed sources, guest assets
are repacked on every run, and the kernel hash/version check prevents a stale or
unapproved kernel from entering a VM.

## Managed compatibility helper

The first compatibility run requests administrator authorization to install the test
helper under `/Library/Application Support/cengine/compat/`. Later runs do not prompt
unless the helper fingerprint changes, the helper is damaged, or a different macOS
user takes ownership of the test service. No installed cengine app is required.

The test helper has a distinct service name, executable identity, client identity,
authentication token, and per-engine-root vmnet resource namespace. Its automatic
IPv4 and IPv6 pools also differ from the production defaults. An installed cengine
daemon and its `dev.cengine.network-helper` service may remain running while the suite
executes.

Inspect the setup before a long run, or remove it explicitly:

```sh
make test-compat-doctor
make test-compat-helper-uninstall
```

Uninstall affects only `dev.cengine.network-helper.test-compat`; it does not stop or
modify the production helper.

The runner defaults to `10.192.0.0/12` and `fdcc::/16` for automatically allocated
test networks, with `10.208.0.0/12` and `fdcd::/16` reserved for explicit fixtures.
Override these with `CENGINE_COMPAT_IPV4_AUTO_POOL`,
`CENGINE_COMPAT_IPV6_AUTO_PREFIX`, `CENGINE_COMPAT_IPV4_FIXTURE_POOL`, and
`CENGINE_COMPAT_IPV6_FIXTURE_PREFIX` when a host VPN or LAN uses those ranges.

## Focused and repeated runs

Pass pytest arguments through `COMPAT_ARGS` without bypassing the lifecycle:

```sh
make test-compat COMPAT_ARGS='Tests/Compatibility/test_kind.py -x -vv'
make test-compat-soak
```

Each soak seed receives another runtime reset. The binary and immutable guest inputs
are shared within that one locked invocation because they cannot change during it.

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
