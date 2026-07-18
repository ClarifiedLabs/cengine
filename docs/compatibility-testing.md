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
4. Rebuild the macOS runtime and Linux guest initramfs from the current checkout.
5. Validate the exact pinned guest kernel, build the `test-compat` Xcode scheme,
   sign the test binary, and use the installed, already-approved
   `dev.cengine.network-helper` service. Normal runs never request administrator
   authorization. Set `CENGINE_COMPAT_NETWORK_HELPER=local` only while changing
   the helper itself; that explicit mode signs the local helper and requests
   authorization to bootstrap a temporary root-owned LaunchDaemon.
6. Delete and recreate the Python virtual environment from the pinned requirements.
7. Let the pytest harness create a unique engine root and Docker configuration for the
   run, then execute the requested tests.
8. On success, failure, or interruption, stop all owned processes, remove temporary
   roots, remove any temporary local networking helper, assert the state is clean,
   and release the lock.

Compiler intermediates and the pinned kernel build are caches, not runtime state. They
remain between runs; Xcode dependency tracking rebuilds changed sources, guest assets
are repacked on every run, and the kernel hash/version check prevents a stale or
unapproved kernel from entering a VM.

## One-time non-interactive host setup

Install cengine, open the app once, and approve Networking. The privileged helper
can remain registered while the per-user engine is disabled in Settings, allowing
the isolated compatibility daemon to own all engine state without authentication
prompts or interference from the installed daemon.

Verify that setup before a long run:

```sh
/bin/launchctl print system/dev.cengine.network-helper >/dev/null
! /bin/launchctl print "gui/$(id -u)/dev.cengine.engine" >/dev/null 2>&1
```

Automatic helper selection requires this installed helper and does not fall back
to a privileged local bootstrap. This is the normal setup for compatibility and
guest tests. `CENGINE_COMPAT_NETWORK_HELPER=local` is an explicit, interactive
developer path for networking-helper changes only.

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
NetworkSharing and the installed cengine helper, affects host-global networking, and
requires administrator authorization. A normal run must never silently depend on it.
