#!/usr/bin/env python3
from __future__ import annotations

import ast
import io
import json
import pathlib
import re
import runpy
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "Tests" / "Compatibility"))

import harness  # noqa: E402
from harness import (  # noqa: E402
    DOCKER_AMBIENT_CONFIG_VARIABLES,
    DOCKER_ENDPOINT_VARIABLES,
    COMPATIBILITY_OWNER_FILE,
    COMPATIBILITY_EXECUTABLES_FILE,
    VMNET_TEARDOWN_SETTLE_SECONDS,
    compatibility_environment,
    compatibility_image_cache_key,
    compatibility_registered_executables,
    compatibility_root_owned_by,
    compatibility_runtime_processes,
    control_plane_status_is_ready,
    docker_environment,
    managed_docker_environment,
    persisted_container_record,
    register_compatibility_executable,
    terminate_compatibility_runtime,
)


def test_original_executable_cleanup() -> None:
    binary = pathlib.Path("/build/cengine")
    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = pathlib.Path(temporary)
        work = temporary_root / "cengine-compat-owned"
        work.mkdir()
        root = work / "root"
        root.mkdir()
        unowned = temporary_root / "cengine-compat-unowned"
        unowned.mkdir()
        foreign = temporary_root / "cengine-compat-foreign"
        foreign.mkdir()
        (foreign / COMPATIBILITY_OWNER_FILE).write_text("/other/cengine\n")
        manual = pathlib.Path("/tmp/manual-cengine/root")
        commands = {
            101: f"{binary} daemon --root {root} --socket /tmp/owned.sock",
            102: f"{binary} vm-shim --spec {root}/infrastructure/shim.json",
            103: f"{binary} vm-shim --spec {manual}/infrastructure/shim.json",
            104: f"{binary} daemon --root {manual}",
            105: f"/other/cengine daemon --root {root}",
            106: f"{binary} daemon --root {unowned}/root",
            107: f"{binary} vm-shim --spec {foreign}/root/infrastructure/shim.json",
            108: f"{binary} daemon --root /production/root --root {root}",
            109: f"{binary} daemon --root {root} --root /production/root",
            110: f"{binary} daemon --root {root} --root {root}",
            111: f"{binary} daemon --root=/production/root --root {root}",
            112: f"{binary} vm-shim --spec {root}/infrastructure/shim.json --spec /production/shim.json",
            113: f"{binary} vm-shim --spec /production/shim.json --spec {root}/infrastructure/shim.json",
            114: f"{binary} vm-shim --spec {root}/infrastructure/shim.json --spec={root}/other.json",
            115: f"{binary} daemon --socket {root}/docker.sock",
            116: f"{binary} daemon --root /production/root --socket {root}/docker.sock",
            117: f"{binary} vm-shim --spec {root}-other/infrastructure/shim.json",
            118: f"{binary} vm-shim --spec {root}/../other/shim.json",
            119: f"{binary} system shutdown --root {root}",
            120: "/build/cengine daemon --root /production/root --root /tmp/cengine-compat-owned/root",
            121: "/build/cengine vm-shim --spec /production/infrastructure/shim.json --label cengine-compat-decoy",
            122: f"{binary} daemon --root /production/root --label cengine-compat-decoy",
        }
        process_table = "\n".join(f"{pid} {command}" for pid, command in commands.items())
        with patch.object(harness.tempfile, "gettempdir", return_value=temporary):
            assert not compatibility_runtime_processes(binary, process_table=process_table)
            assert [value.pid for value in compatibility_runtime_processes(
                binary, roots=(manual,), process_table=process_table,
            )] == [103, 104]
            # Explicit roots authorize cleanup even before their owner marker is written.
            assert [value.pid for value in compatibility_runtime_processes(
                binary, roots=(root,), process_table=process_table,
            )] == [101, 102]
            (work / COMPATIBILITY_OWNER_FILE).write_text(f"{binary}\n")
            for roots in ((), (root,)):
                assert [value.pid for value in compatibility_runtime_processes(
                    binary, roots=roots, process_table=process_table,
                )] == [101, 102]
            assert not compatibility_runtime_processes(
                binary, roots=(pathlib.Path("/tmp/cengine-compat-owned/root"),),
                process_table=process_table,
            )


def test_reset_rechecks_removed_roots() -> None:
    reset_main = runpy.run_path(str(REPO_ROOT / "Scripts/reset-compat-runtime.py"))["main"]
    binary = pathlib.Path("/build/cengine")
    for extra_arguments in ([], ["--root", "/tmp/manual-cengine/root"]):
        with tempfile.TemporaryDirectory() as temporary:
            work = pathlib.Path(temporary) / "cengine-compat-reset"
            root = work / "root"
            root.mkdir(parents=True)
            (work / COMPATIBILITY_OWNER_FILE).write_text(f"{binary}\n")
            staged = work / "upgrade-bin" / "cengine"
            staged.parent.mkdir()
            staged.write_text("staged executable")
            register_compatibility_executable(work, binary, staged)
            commands = [
                f"{binary} daemon --root {root}",
                f"{staged.resolve()} vm-shim --spec {root}/infrastructure/shim.json",
            ]
            process_table = "\n".join(f"{pid} {command}" for pid, command in enumerate(commands, 401))
            # Simulate processes reappearing after termination and removal of owner markers.
            with patch.object(harness.tempfile, "gettempdir", return_value=temporary), \
                    patch.dict(reset_main.__globals__, {"terminate_compatibility_runtime": lambda *a, **k: []}), \
                    patch.object(harness.subprocess, "run", return_value=SimpleNamespace(stdout=process_table)), \
                    patch.object(harness.os, "kill") as signal_process, \
                    patch.object(sys, "argv", ["reset-compat-runtime.py", "--binary", str(binary), *extra_arguments]), \
                    patch.object(sys, "stderr", io.StringIO()) as stderr:
                try:
                    reset_main()
                except SystemExit as error:
                    assert str(error) == "compatibility runtime reset did not reach a clean state"
                else:
                    raise AssertionError("reset forgot owned runtime paths after removing their markers")
                signal_process.assert_not_called()
                for command in commands:
                    assert command in stderr.getvalue()
            assert not work.exists()


def test_staged_executable_cleanup() -> None:
    binary = REPO_ROOT / ".build/test-compat/cengine"
    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = pathlib.Path(temporary)
        work = temporary_root / "cengine-compat-upgrade"
        work.mkdir()
        root = work / "root"
        root.mkdir()
        owner = work / COMPATIBILITY_OWNER_FILE
        original_owner = f"{binary.resolve()}\n"
        owner.write_text(original_owner)
        staged = work / "upgrade-bin" / "cengine"
        staged.parent.mkdir()
        staged.write_text("staged executable")
        staged = staged.resolve()
        register_compatibility_executable(work, binary, staged)
        register_compatibility_executable(work, binary, staged)  # Idempotent.
        assert owner.read_text() == original_owner
        assert compatibility_root_owned_by(work, binary)
        assert not compatibility_root_owned_by(work, staged)
        assert compatibility_registered_executables(work, binary) == (staged,)
        assert compatibility_registered_executables(work, pathlib.Path("/other/cengine")) == ()
        registry = work / COMPATIBILITY_EXECUTABLES_FILE
        registration = registry.read_bytes()
        for owner_binary, executable in ((staged, staged), (binary, binary)):
            try:
                register_compatibility_executable(work, owner_binary, executable)
            except ValueError:
                pass
            else:
                raise AssertionError("accepted unowned directory or external executable")
            assert registry.read_bytes() == registration

        commands = {
            301: f"{binary.resolve()} daemon --root {root} --socket /tmp/owned.sock",
            302: f"{staged} daemon --root {root.resolve()} --socket /tmp/staged.sock",
            303: f"{staged} vm-shim --spec {root}/infrastructure/shim.json",
            304: f"{staged} vm-shim --spec {root}/vms/container/shim.json",
            305: f"{staged}.other daemon --root {root}",
            306: f"{staged} daemon --root {root}-other",
            307: f"{staged} vm-shim --spec {root}-other/infrastructure/shim.json",
            308: f"{staged} daemon --root /production/root --socket {root}/docker.sock",
            309: f"{staged} system shutdown --root {root}",
            310: f"{staged} vm-shim --spec {root}/../other/shim.json",
            311: f"/other/cengine daemon --root {root}",
            312: f"{staged} daemon --root /tmp/cengine-compat-other/root",
            313: f"{staged} daemon --root /production/root --root {root}",
            314: f"{staged} daemon --root {root} --root /production/root",
            315: f"{staged} vm-shim --spec {root}/infrastructure/shim.json --spec /production/shim.json",
            316: f"{staged} vm-shim --spec /production/shim.json --spec {root}/infrastructure/shim.json",
            317: f"{binary.resolve()} daemon --root /production/root --label cengine-compat-decoy",
            318: f"{binary.resolve()} vm-shim --spec /production/infrastructure/shim.json --label cengine-compat-decoy",
            319: f"{binary.resolve()} daemon --root /production/root --root {root}",
        }
        process_table = "\n".join(f"{pid} {command}" for pid, command in commands.items())
        with patch.object(harness.tempfile, "gettempdir", return_value=temporary):
            for roots in ((), (root,)):
                assert [process.pid for process in compatibility_runtime_processes(
                    binary, roots=roots, process_table=process_table,
                )] == [301, 302, 303, 304]
            assert not compatibility_runtime_processes(
                binary, roots=(work / "other",), process_table=process_table,
            )
            # Foundation's child argv uses /var even when the staged parent was
            # launched through /private/var; ownership and root checks still apply.
            if str(staged).startswith("/private/var/"):
                alias = str(staged).removeprefix("/private")
                alias_table = "\n".join([
                    f"801 {alias} vm-shim --spec {root}/infrastructure/shim.json",
                    f"802 {alias} vm-shim --spec /production/infrastructure/shim.json",
                    f"803 {alias}.other vm-shim --spec {root}/infrastructure/shim.json",
                ])
                for owner_binary, roots in ((binary, ()), (binary, (root,)), (staged, (root,))):
                    assert [process.pid for process in compatibility_runtime_processes(
                        owner_binary, roots=roots, process_table=alias_table,
                    )] == [801]
            # Simulate killed pytest: only the durable marker/registry and original binary remain.
            live = commands.copy()
            def snapshot(*args, **kwargs):
                return SimpleNamespace(stdout="\n".join(
                    f"{pid} {command}" for pid, command in live.items()
                ))
            def kill(pid, signal):
                del live[pid]
            with patch.object(harness.subprocess, "run", side_effect=snapshot), \
                    patch.object(harness.os, "kill", side_effect=kill), \
                    patch.object(harness.time, "sleep"):
                stopped = terminate_compatibility_runtime(binary, timeout=0)
            assert [process.pid for process in stopped] == [301, 302, 303, 304]
            assert set(live) == set(commands) - {301, 302, 303, 304}

            # Invalid registrations fail closed before signaling anything or deleting the root.
            for invalid in (["../external/cengine"], [str(binary)], ["."], [7], {}):
                registry.write_text(json.dumps(invalid))
                with patch.object(harness.os, "kill") as signal_process:
                    try:
                        terminate_compatibility_runtime(binary, timeout=0)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError(f"accepted invalid registry: {invalid}")
                    signal_process.assert_not_called()
                assert work.is_dir()
            registry.write_bytes(registration)
            staged.unlink()
            staged.symlink_to(binary)
            try:
                compatibility_registered_executables(work, binary)
            except ValueError:
                pass
            else:
                raise AssertionError("accepted escaped executable symlink")
            staged.unlink()
            staged.write_text("replacement executable")

            # Exercise the actual reset entry point with all process operations mocked.
            reset_main = runpy.run_path(str(REPO_ROOT / "Scripts/reset-compat-runtime.py"))["main"]
            live = commands.copy()
            with patch.object(sys, "argv", ["reset-compat-runtime.py", "--binary", str(binary)]), \
                    patch.object(harness.subprocess, "run", side_effect=snapshot), \
                    patch.object(harness.os, "kill", side_effect=PermissionError("stop failed")):
                try:
                    reset_main()
                except PermissionError:
                    pass
                else:
                    raise AssertionError("reset ignored failed process termination")
            assert owner.read_text() == original_owner
            assert registry.read_bytes() == registration
            assert live == commands
            with patch.object(sys, "argv", ["reset-compat-runtime.py", "--binary", str(binary)]), \
                    patch.object(harness.subprocess, "run", side_effect=snapshot), \
                    patch.object(harness.os, "kill", side_effect=kill), \
                    patch.object(harness.time, "sleep"):
                reset_main()
            assert not work.exists()
            assert set(live) == set(commands) - {301, 302, 303, 304}


def test_upgrade_finally_cleanup() -> None:
    # Load only the cleanup helper: regression checks need neither pytest/docker nor VMs.
    path = REPO_ROOT / "Tests/Compatibility/test_upgrade_recovery.py"
    source = ast.parse(path.read_text())
    function = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_restore_upgrade_daemon")
    namespace: dict = {"pathlib": pathlib}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    original = pathlib.Path("/build/cengine")
    staged = pathlib.Path("/tmp/cengine-compat-upgrade/upgrade-bin/cengine")
    for failures in ((), ("stop",), ("shutdown",), ("stop", "shutdown"),
                     ("terminate",), ("stop", "shutdown", "terminate"), ("start",)):
        events = []
        def action(name):
            events.append(name)
            if name in failures:
                raise RuntimeError(name)
        def start():
            assert daemon.binary == original
            action("start")
        daemon = SimpleNamespace(
            binary=staged, root=pathlib.Path("/tmp/cengine-compat-upgrade/root"),
            stop=lambda: action("stop"), start=start,
        )
        def terminate(binary, *, roots):
            assert binary == original and roots == (daemon.root,)
            action("terminate")
        namespace["_strict_shutdown"] = lambda value: action("shutdown")
        namespace["terminate_compatibility_runtime"] = terminate
        try:
            namespace["_restore_upgrade_daemon"](daemon, original)
        except RuntimeError:
            assert failures
        else:
            assert not failures
        assert daemon.binary == original
        assert events == ["stop", "shutdown", "terminate"] + (
            [] if "terminate" in failures else ["start"]
        )


def main() -> None:
    test_original_executable_cleanup()
    test_staged_executable_cleanup()
    test_reset_rechecks_removed_roots()
    test_upgrade_finally_cleanup()
    ambient = {
        "PATH": "/test/bin",
        "DOCKER_CONFIG": "/isolated/docker",
        "BUILDX_CONFIG": "/isolated/buildx",
        **{key: f"ambient-{key.lower()}" for key in DOCKER_ENDPOINT_VARIABLES},
        **{key: f"ambient-{key.lower()}" for key in DOCKER_AMBIENT_CONFIG_VARIABLES},
    }
    compatible = compatibility_environment(base=ambient)
    managed = managed_docker_environment(base=ambient)
    environment = docker_environment(pathlib.Path("/tmp/cengine/docker.sock"), base=ambient)

    for value in (compatible, managed, environment):
        assert value["PATH"] == ambient["PATH"]
        assert value["DOCKER_CONFIG"] == ambient["DOCKER_CONFIG"]
        assert value["BUILDX_CONFIG"] == ambient["BUILDX_CONFIG"]
        for key in DOCKER_AMBIENT_CONFIG_VARIABLES:
            assert key not in value
    assert "DOCKER_HOST" not in compatible
    assert "DOCKER_HOST" not in managed
    assert environment["DOCKER_HOST"] == "unix:///tmp/cengine/docker.sock"
    for key in DOCKER_ENDPOINT_VARIABLES:
        assert key not in compatible
        assert key not in managed
        if key != "DOCKER_HOST":
            assert key not in environment

    explicit = docker_environment("tcp://127.0.0.1:2375", base={})
    assert explicit == {"DOCKER_HOST": "tcp://127.0.0.1:2375"}
    assert VMNET_TEARDOWN_SETTLE_SECONDS >= 2.0
    assert not control_plane_status_is_ready(0, b"")
    assert not control_plane_status_is_ready(1, b"True")
    assert not control_plane_status_is_ready(0, b"True False")
    assert control_plane_status_is_ready(0, b"True")
    assert control_plane_status_is_ready(0, "True True")
    assert persisted_container_record(
        {
            "schemaVersion": 1,
            "value": {
                "containers": [
                    {"id": "other", "name": "unrelated"},
                    {"id": "target", "name": "persisted-target"},
                ]
            },
        },
        "target",
    )["name"] == "persisted-target"

    cache_key = compatibility_image_cache_key([("alpine:latest", "mirror/alpine:latest")])
    assert cache_key == compatibility_image_cache_key([("alpine:latest", "mirror/alpine:latest")])
    assert cache_key != compatibility_image_cache_key([("alpine:latest", "alpine:latest")])
    assert cache_key != compatibility_image_cache_key([
        ("alpine:latest", "mirror/alpine:latest"),
        ("busybox:latest", "mirror/busybox:latest"),
    ])

    binary = REPO_ROOT / ".build/xcode-derived/Build/Products/Debug/cengine"
    with tempfile.TemporaryDirectory() as temporary:
        owned_root = pathlib.Path(temporary)
        (owned_root / COMPATIBILITY_OWNER_FILE).write_text(f"{binary.resolve()}\n")
        assert compatibility_root_owned_by(owned_root, binary)
        assert not compatibility_root_owned_by(owned_root, pathlib.Path("/other/cengine"))

        fake_home_config = owned_root / "home" / ".docker" / "config.json"
        fake_home_config.parent.mkdir(parents=True)
        sentinel = '{"credsStore":"do-not-read-or-change"}\n'
        fake_home_config.write_text(sentinel)
        isolated = managed_docker_environment(base={
            "HOME": str(fake_home_config.parents[1]),
            "DOCKER_CONFIG": str(owned_root / "client" / "docker"),
            "BUILDX_CONFIG": str(owned_root / "client" / "buildx"),
            "DOCKER_HOST": "unix:///developer.sock",
            "DOCKER_CONTEXT": "developer",
            "BUILDX_BUILDER": "developer-builder",
            "DOCKER_AUTH_CONFIG": "developer-credentials",
        })
        assert isolated["DOCKER_CONFIG"].endswith("/client/docker")
        assert isolated["BUILDX_CONFIG"].endswith("/client/buildx")
        assert fake_home_config.read_text() == sentinel

    makefile = (REPO_ROOT / "Makefile").read_text()
    assert 'XCODE_COMPAT_SCHEME ?= test-compat' in makefile
    assert 'XCODE_COMPAT_CONFIGURATION ?= test-compat' in makefile
    assert 'XCODEBUILD="$(XCODEBUILD)"' in makefile
    assert 'XCODE_DERIVED_DATA="$(XCODE_DERIVED_DATA)"' in makefile
    assert 'CENGINE_KERNEL="$(CENGINE_GUEST_OUTPUT)/vmlinux"' in makefile
    assert 'CENGINE_CONTAINER_INITRAMFS="$(CENGINE_GUEST_OUTPUT)/container-initramfs.cpio.gz"' in makefile
    assert 'CENGINE_STORAGE_INITRAMFS="$(CENGINE_GUEST_OUTPUT)/storage-initramfs.cpio.gz"' in makefile
    assert makefile.count("$(CENGINE_COMPAT_ENV)") == 5
    assert "test-compat-reset-system:" in makefile
    assert "test-compat-doctor:" in makefile
    assert "test-compat-helper-install:" in makefile
    assert "test-compat-helper-uninstall:" in makefile
    assert "Scripts/run-compat-tests.sh suite $(COMPAT_ARGS)" in makefile
    assert "CENGINE_HOST_OS ?= $(shell uname -s)" in makefile
    assert "kernel-build: build" not in makefile
    assert "ifeq ($(CENGINE_HOST_OS),Darwin)\ntest-guest: build guest-initramfs\nendif" in makefile

    linux_guest_dry_run = subprocess.run(
        ["make", "--no-print-directory", "-n", "CENGINE_HOST_OS=Linux", "test-guest"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "xcodebuild" not in linux_guest_dry_run
    assert "build-guest-assets.sh" not in linux_guest_dry_run
    assert "./Scripts/test-guest.sh" in linux_guest_dry_run

    linux_guest_assets_dry_run = subprocess.run(
        ["make", "--no-print-directory", "-n", "CENGINE_HOST_OS=Linux", "guest-assets"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "xcodebuild" not in linux_guest_assets_dry_run
    assert "./Scripts/fetch-kernel.sh" in linux_guest_assets_dry_run
    assert "./Scripts/build-kernel.sh" not in linux_guest_assets_dry_run
    assert "./Scripts/build-guest-assets.sh" in linux_guest_assets_dry_run

    linux_local_kernel_dry_run = subprocess.run(
        ["make", "--no-print-directory", "-n", "CENGINE_HOST_OS=Linux", "CENGINE_KERNEL_MODE=build", "kernel"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "./Scripts/build-kernel.sh" in linux_local_kernel_dry_run
    assert "./Scripts/fetch-kernel.sh" not in linux_local_kernel_dry_run

    darwin_local_kernel_dry_run = subprocess.run(
        ["make", "--no-print-directory", "-n", "CENGINE_HOST_OS=Darwin", "kernel-build"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "xcodebuild" not in darwin_local_kernel_dry_run
    assert "./Scripts/build-kernel.sh" in darwin_local_kernel_dry_run

    runner = (REPO_ROOT / "Scripts" / "run-compat-tests.sh").read_text()
    assert runner.index("$RESET") < runner.index("make -C")
    assert "trap cleanup EXIT HUP INT TERM" in runner
    assert "rm -rf \"$ROOT/.build/compat-venv\"" in runner
    assert '"$ROOT/Scripts/check-guest-kernel.sh"' in runner
    assert 'LOCK=${CENGINE_COMPAT_LOCK:-"${TMPDIR:-/tmp}/cengine-compat-run.lock"}' in runner
    assert "unset DOCKER_API_VERSION DOCKER_AUTH_CONFIG DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_HOST" in runner
    assert 'CENGINE_COMPAT_CLIENT_STATE_ROOT="$LOCK/client-state"' in runner
    assert 'DOCKER_CONFIG="$CENGINE_COMPAT_CLIENT_STATE_ROOT/docker"' in runner
    assert 'BUILDX_CONFIG="$CENGINE_COMPAT_CLIENT_STATE_ROOT/buildx"' in runner
    assert 'AMBIENT_DOCKER_CONFIG=${DOCKER_CONFIG:-"$HOME/.docker"}' in runner
    assert 'mkdir -p "$DOCKER_CONFIG/cli-plugins" "$BUILDX_CONFIG"' in runner
    assert '"$ROOT/Scripts/find-docker-plugin.sh" "$plugin" "$AMBIENT_DOCKER_CONFIG"' in runner
    assert 'ln -s "$plugin_path" "$DOCKER_CONFIG/cli-plugins/docker-$plugin"' in runner
    plugin_finder = REPO_ROOT / "Scripts" / "find-docker-plugin.sh"
    with tempfile.TemporaryDirectory() as directory:
        plugin_root = pathlib.Path(directory)
        plugin = plugin_root / ".docker-ci/cli-plugins/docker-buildx"
        plugin.parent.mkdir(parents=True)
        plugin.write_text("#!/bin/sh\nexit 0\n")
        plugin.chmod(0o755)
        discovered = subprocess.run(
            ["/bin/sh", str(plugin_finder), "buildx", ".docker-ci"],
            cwd=plugin_root, env={"HOME": str(plugin_root), "PATH": "/usr/bin:/bin"},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True,
        ).stdout.strip()
        assert discovered == str(plugin.resolve())
    assert "secrets.token_hex(32)" in runner
    assert 'CENGINE_COMPAT_OWNER_PID=$$' in runner
    assert 'printf \'%s %s\\n\' "$CENGINE_COMPAT_RUN_ID" "$CENGINE_COMPAT_OWNER_PID"' in runner
    assert 'export CENGINE_COMPAT_CLIENT_STATE_ROOT CENGINE_COMPAT_RUN_ID CENGINE_COMPAT_OWNER_PID' in runner
    conftest = (REPO_ROOT / "Tests" / "Compatibility" / "conftest.py").read_text()
    assert 'docker_config != root / "docker"' in conftest
    assert 'buildx_config != root / "buildx"' in conftest
    assert 'owner_file.stat(follow_symlinks=False)' in conftest
    assert 'owner_file.read_text() == expected_owner' in conftest
    assert 'os.kill(int(owner_pid), 0)' in conftest
    assert 'rm -rf "$CENGINE_COMPAT_CLIENT_STATE_ROOT"' in runner
    plugin_finder_source = plugin_finder.read_text()
    assert 'command -v "docker-$plugin"' in plugin_finder_source
    assert '"/Applications/Docker.app/Contents/Resources/cli-plugins"' in plugin_finder_source
    assert 'candidate_directory=$(CDPATH= cd -- "$(dirname -- "$candidate")" && pwd)' in plugin_finder_source
    assert 'stage "preflight reset"' in runner
    assert 'BUILD_STAGE="build and validate compatibility runtime"' in runner
    assert 'BUILD_STAGE="build and provision compatibility runtime"' in runner
    assert 'XCODE_COMPAT_SCHEME=${XCODE_COMPAT_SCHEME:-test-compat}' in runner
    assert '-scheme "$XCODE_COMPAT_SCHEME"' in runner
    assert '-configuration "$XCODE_COMPAT_CONFIGURATION"' in runner
    assert 'stage "recreate test environment"' in runner
    assert 'HELPER_FINGERPRINT=$("$ROOT/Scripts/network-helper-fingerprint.sh")' in runner
    assert 'if [ "$MODE" = helper-install ]; then' in runner
    assert 'compat_network_helper_provision "$HELPER" "$BINARY" "$HELPER_FINGERPRINT"' in runner
    assert 'compat_network_helper_require "$BINARY" "$HELPER_FINGERPRINT"' in runner
    assert runner.count("compat_network_helper_provision") == 1
    assert "compat_network_helper_ensure" not in runner
    assert "compat_network_helper_install" not in runner
    assert "/usr/bin/osascript" not in runner
    assert "/usr/bin/sudo" not in runner
    assert 'compat_network_helper_cleanup_local' not in runner
    assert 'CENGINE_COMPAT_IPV4_AUTO_POOL' in runner
    assert '"$ROOT/Scripts/check-compat-network-pools.py"' in runner

    helper_lifecycle = (REPO_ROOT / "Scripts" / "compat-network-helper.sh").read_text()
    assert 'compat_network_helper_support_root="/Library/Application Support/cengine"' in helper_lifecycle
    assert 'compat_network_helper_parent="$compat_network_helper_support_root/compat"' in helper_lifecycle
    assert 'compat_network_helper_root="/Library/Application Support/cengine/compat/' in helper_lifecycle
    assert 'compat_network_helper_token_path=' in helper_lifecycle
    assert 'compat_network_helper_manifest_path=' in helper_lifecycle
    assert 'compat_network_helper_service_name="dev.cengine.network-helper.test-compat"' in helper_lifecycle
    assert 'cengine-network-helper\\n' in helper_lifecycle
    assert 'CENGINE_NETWORK_HELPER_SERVICE_NAME' in helper_lifecycle
    assert 'CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE' in helper_lifecycle
    assert 'compat_network_helper_validate_installation()' in helper_lifecycle
    assert 'compat_network_helper_require()' in helper_lifecycle
    assert 'compat_network_helper_provision()' in helper_lifecycle
    assert 'compat_network_helper_ensure' not in helper_lifecycle
    assert 'compat_network_helper_uninstall()' in helper_lifecycle
    assert 'launchctl bootstrap system' in helper_lifecycle
    assert 'launchctl bootout "system/$label"' in helper_lifecycle
    assert 'launchctl kickstart "system/$label"' in helper_lifecycle
    assert 'launchctl kickstart -k "system/$label"' not in helper_lifecycle
    assert "/usr/bin/osascript" not in helper_lifecycle
    assert "with administrator privileges" not in helper_lifecycle
    assert "/Applications/cengine.app" not in helper_lifecycle
    assert helper_lifecycle.count("/usr/bin/sudo") == 1
    assert helper_lifecycle.count("compat_network_helper_run_as_administrator") == 3
    assert '[ ! -L "$_cnh_controlled_path" ]' in helper_lifecycle
    assert '[ ! -L "$compat_network_helper_token_path" ]' in helper_lifecycle
    install_body = helper_lifecycle.split("compat_network_helper_install() {", 1)[1].split(
        "compat_network_helper_print_install_instruction() {", 1
    )[0]
    assert 'validate_controlled_directory "$support_parent"' in install_body
    assert 'refusing to overwrite stale helper backup' in install_body
    assert 'binary=${12}' not in install_body
    assert 'network-helper status' not in install_body
    swift_protocol = (REPO_ROOT / "Sources/CEngineCore/PrivilegedPortProtocol.swift").read_text()
    shell_version = re.search(r"^compat_network_helper_protocol_version=(\d+)$", helper_lifecycle, re.MULTILINE)
    swift_version = re.search(r"public static let version: Int64 = (\d+)", swift_protocol)
    assert shell_version is not None
    assert swift_version is not None
    assert shell_version.group(1) == swift_version.group(1)
    require_body = helper_lifecycle.split("compat_network_helper_require() {", 1)[1].split(
        "compat_network_helper_provision() {", 1
    )[0]
    for forbidden in (
        "compat_network_helper_install \\",
        "compat_network_helper_provision ",
        "compat_network_helper_run_as_administrator ",
        "/usr/bin/osascript",
        "/usr/bin/sudo",
    ):
        assert forbidden not in require_body
    assert 'compat_network_helper_export_environment "$_cnh_installed_fingerprint"' in require_body
    assert "protocolVersion" in require_body
    assert "make test-compat-helper-install" in require_body
    provision_body = helper_lifecycle.split("compat_network_helper_provision() {", 1)[1].split(
        "compat_network_helper_uninstall() {", 1
    )[0]
    assert provision_body.index("compat_network_helper_require") < provision_body.index(
        "compat_network_helper_install"
    )
    assert provision_body.index("compat_network_helper_install") < provision_body.rindex(
        "compat_network_helper_require"
    )
    assert "reinstalling the matching local helper because its health check failed" in provision_body

    with tempfile.TemporaryDirectory() as temporary:
        fake_binary = pathlib.Path(temporary) / "cengine"
        installed_fingerprint = "a" * 64
        local_fingerprint = "b" * 64
        fake_binary.write_text(
            "#!/bin/sh\n"
            "cat <<EOF\n"
            f'{{"buildFingerprint":"{installed_fingerprint}",'
            '"serviceName":"dev.cengine.network-helper.test-compat",'
            '"ownerUID":$(id -u),"processIdentifier":1,"protocolVersion":5}\n'
            "EOF\n"
        )
        fake_binary.chmod(0o755)
        mismatch = subprocess.run(
            [
                "/bin/sh",
                "-c",
                f'. {shlex.quote(str(REPO_ROOT / "Scripts/compat-network-helper.sh"))}; '
                "compat_network_helper_validate_installation() { :; }; "
                f"compat_network_helper_installed_fingerprint() {{ echo {installed_fingerprint}; }}; "
                f'compat_network_helper_require {shlex.quote(str(fake_binary))} {local_fingerprint}; '
                'printf "%s\\n" "$CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT"',
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert mismatch.returncode == 0, mismatch.stderr
        assert mismatch.stdout.strip() == installed_fingerprint
        assert "compatible provisioned helper differs from the local build" in mismatch.stderr

        fake_binary.write_text(fake_binary.read_text().replace('"protocolVersion":5', '"protocolVersion":4'))
        incompatible = subprocess.run(
            [
                "/bin/sh",
                "-c",
                f'. {shlex.quote(str(REPO_ROOT / "Scripts/compat-network-helper.sh"))}; '
                "compat_network_helper_validate_installation() { :; }; "
                f"compat_network_helper_installed_fingerprint() {{ echo {installed_fingerprint}; }}; "
                f'compat_network_helper_require {shlex.quote(str(fake_binary))} {local_fingerprint}; '
                'status=$?; printf "%s\\n" "$CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT"; exit "$status"',
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert incompatible.returncode != 0
        assert incompatible.stdout.strip() == installed_fingerprint
        assert "make test-compat-helper-install" in incompatible.stderr

        target = pathlib.Path(temporary) / "target"
        link = pathlib.Path(temporary) / "link"
        target.write_text("target")
        link.symlink_to(target)
        symlink_check = subprocess.run(
            [
                "/bin/sh",
                "-c",
                f'. {shlex.quote(str(REPO_ROOT / "Scripts/compat-network-helper.sh"))}; '
                f'compat_network_helper_validate_root_controlled {shlex.quote(str(link))}',
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert symlink_check.returncode != 0
        assert "must not be a symbolic link" in symlink_check.stderr

    buildx_test = (REPO_ROOT / "Tests" / "Compatibility" / "test_buildx.py").read_text()
    assert '"network-helper", "restart"' in buildx_test
    assert "CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT" in buildx_test
    assert "CENGINE_COMPAT_NETWORK_HELPER_CONTROL_ROOT" not in buildx_test
    assert "/usr/bin/osascript" not in buildx_test
    assert "with administrator privileges" not in buildx_test
    assert "/usr/bin/sudo" not in buildx_test

    reset = (REPO_ROOT / "Scripts" / "reset-compat-runtime.py").read_text()
    assert "binary.is_file()" not in reset
    assert "compatibility_runtime_processes" in reset
    assert "compatibility runtime reset did not reach a clean state" in reset
    assert "system/dev.cengine.network-helper.test-compat" in reset
    assert "system/dev.cengine.network-helper 2" not in reset
    assert "CENGINE_COMPAT_ALLOW_GLOBAL_NETWORK_RESET" in reset

    isolated = (REPO_ROOT / "Scripts" / "run-isolated-cengine.sh").read_text()
    assert 'mktemp -d "${TMPDIR:-/tmp}/cengine-compat-tool.XXXXXX"' in isolated
    assert "unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY" in isolated
    assert 'trap cleanup EXIT' in isolated
    assert 'compat_network_helper_require "$BINARY" "$HELPER_FINGERPRINT"' in isolated
    assert "compat_network_helper_ensure" not in isolated
    assert "compat_network_helper_provision" not in isolated
    assert "compat_network_helper_install" not in isolated
    assert "/usr/bin/osascript" not in isolated
    assert "/usr/bin/sudo" not in isolated
    assert 'compat_network_helper_cleanup_local' not in isolated
    assert '--binary "$BINARY" --root "$ENGINE_ROOT"' in isolated
    assert isolated.index('--binary "$BINARY" --root "$ENGINE_ROOT"') < isolated.index('> "$WORK/.cengine-compat-owner"')
    assert 'CENGINE_ISOLATED_IMAGE_CACHE' in isolated
    assert '/bin/cp -cR "$IMAGE_CACHE/content" "$ENGINE_ROOT/content"' in isolated

    doctor = (REPO_ROOT / "Scripts" / "compat-doctor.sh").read_text()
    assert "local fingerprint:" in doctor
    assert "installed fingerprint:" in doctor
    assert 'compat_network_helper_require "$BINARY" "$LOCAL_FINGERPRINT"' in doctor
    assert "compat_network_helper_provision" not in doctor
    assert 'compat_network_helper_install "' not in doctor
    assert "compat_network_helper_run_as_administrator" not in doctor
    assert "/usr/bin/osascript" not in doctor
    assert "/usr/bin/sudo" not in doctor

    kernel_fetcher = (REPO_ROOT / "Scripts" / "fetch-kernel.sh").read_text()
    kernel_builder = (REPO_ROOT / "Scripts" / "build-kernel.sh").read_text()
    linux_kernel_builder = (REPO_ROOT / "Scripts" / "build-kernel-linux.sh").read_text()
    guest_tests = (REPO_ROOT / "Scripts" / "test-guest.sh").read_text()
    assert 'Configuration/kernel-release' in kernel_fetcher
    assert 'CENGINE_KERNEL_RELEASE_TAG' not in kernel_fetcher
    assert 'CENGINE_LOCAL_KERNEL' in kernel_fetcher
    assert 'shasum -a 256 -c SHA256SUMS' in kernel_fetcher
    assert 'kernel-input-sha256.sh' in kernel_fetcher
    assert "docker buildx" not in kernel_builder
    assert "docker buildx" not in guest_tests
    assert '"$ROOT/Scripts/build-kernel-linux.sh"' in kernel_builder
    assert 'docker_cli "$@"' in linux_kernel_builder
    assert 'docker --context "$DOCKER_CONTEXT" "$@"' in linux_kernel_builder
    assert 'CENGINE_KERNEL_BUILD_CPUS' in linux_kernel_builder
    assert 'CENGINE_KERNEL_BUILD_MEMORY' in linux_kernel_builder
    assert '--resource "cpu-quota=$((CPUS * 100000))"' in linux_kernel_builder
    assert '--resource "memory=$MEMORY"' in linux_kernel_builder
    assert '"$ROOT/Scripts/run-isolated-cengine.sh"' not in linux_kernel_builder
    assert "compile-kernel-in-guest.sh" in linux_kernel_builder
    assert 'Linux|Darwin)' in kernel_builder
    assert '"$ROOT/Scripts/run-isolated-cengine.sh"' not in kernel_builder
    assert 'CENGINE_BOOTSTRAP_KERNEL' not in kernel_builder
    assert '"$ROOT/Scripts/run-isolated-cengine.sh"' in guest_tests
    assert "command -v go" in guest_tests
    assert 'cd "$ROOT/Guest"' in guest_tests
    assert 'go test ./...' in guest_tests

    kernel_check = (REPO_ROOT / "Scripts" / "check-guest-kernel.sh").read_text()
    assert '"$ROOT/Scripts/kernel-input-sha256.sh"' in kernel_check
    assert '"$ROOT/Scripts/build-kernel.sh"' not in kernel_check

    conftest = (REPO_ROOT / "Tests" / "Compatibility" / "conftest.py").read_text()
    assert "terminate_compatibility_runtime(value.binary, roots=(value.root,))" in conftest
    assert "try:\n        value.start()\n        yield value\n    finally:" in conftest
    assert '@pytest.fixture\ndef daemon(request: pytest.FixtureRequest, image_cache: pathlib.Path)' in conftest
    assert '@pytest.fixture(scope="session")\ndef image_cache()' in conftest
    assert '@pytest.fixture\ndef client(daemon: Daemon, image_cache: pathlib.Path)' in conftest
    assert 'mirror.gcr.io/library/alpine:latest' in conftest
    assert '["/bin/cp", "-cR"' in conftest
    assert 'def clean_resources(' not in conftest

    kind_test = (REPO_ROOT / "Tests" / "Compatibility" / "test_kind.py").read_text()
    assert 'if state.get("Running"):' in kind_test
    assert "container stopped before live diagnostics" in kind_test

    compatibility_tests = REPO_ROOT / "Tests" / "Compatibility"
    for path in compatibility_tests.glob("*.py"):
        if path.name == "harness.py":
            continue
        source = path.read_text()
        assert "DOCKER_HOST" not in source, f"{path} bypasses docker_environment"
        assert "os.environ.copy()" not in source, f"{path} copies an unsanitized environment"


if __name__ == "__main__":
    main()
