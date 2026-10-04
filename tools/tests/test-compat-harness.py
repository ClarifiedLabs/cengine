#!/usr/bin/env python3
from __future__ import annotations

import ast
import configparser
import io
import json
import pathlib
import re
import runpy
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import os
import selectors
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import time
import uuid
from unittest.mock import patch


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "Tests" / "Compatibility"))

import harness  # noqa: E402
from harness import (  # noqa: E402
    DOCKER_AMBIENT_CONFIG_VARIABLES,
    DOCKER_ENDPOINT_VARIABLES,
    COMPATIBILITY_OWNER_FILE,
    COMPATIBILITY_EXECUTABLES_FILE,
    RuntimeProcess,
    VMNET_TEARDOWN_SETTLE_SECONDS,
    compatibility_environment,
    compatibility_image_cache_key,
    compatibility_registered_executables,
    compatibility_root_owned_by,
    compatibility_root_retained,
    retain_compatibility_root,
    remove_compatibility_root,
    _compatibility_root_claim,
    compatibility_runtime_processes,
    compatibility_disk_holder_diagnostics,
    _kernel_process,
    _kernel_process_argv_excludes_runtime,
    _runtime_matches,
    _signal_runtime_process,
    _signal_pid_incarnation,
    control_plane_status_is_ready,
    docker_environment,
    managed_docker_environment,
    persisted_container_record,
    register_compatibility_executable,
    terminate_compatibility_runtime,
)


@contextmanager
def mock_runtime_process_table(commands):
    def snapshot(*args, **kwargs):
        return SimpleNamespace(stdout="\n".join(f"{pid} {os.getuid()}" for pid in commands))

    def inspect(pid, binary=None):
        command = commands.get(pid)
        if command is None:
            return None
        args = tuple(shlex.split(command))
        if binary is not None and pathlib.Path(args[0]).resolve() != binary.resolve():
            return None
        return RuntimeProcess(pid, executable=args[0], arguments=args,
                              identity=(100, 0, pid), pidversion=1)

    with patch.object(harness.subprocess, "run", side_effect=snapshot), \
            patch.object(harness, "_kernel_process", side_effect=inspect):
        yield


def test_original_executable_cleanup() -> None:
    binary = pathlib.Path("/build/cengine")
    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = pathlib.Path(temporary)
        work = temporary_root / "cengine-compat-owned"
        work.mkdir(mode=0o700)
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
            work.chmod(0o700)
            (work / COMPATIBILITY_OWNER_FILE).write_text(f"{binary}\n")
            staged = work / "upgrade-bin" / "cengine"
            staged.parent.mkdir()
            staged.write_text("staged executable")
            register_compatibility_executable(work, binary, staged)
            commands = [
                f"{binary} daemon --root {root}",
                f"{staged.resolve()} vm-shim --spec {root}/infrastructure/shim.json",
            ]
            processes = dict(enumerate(commands, 401))
            # Simulate processes reappearing after termination and removal of owner markers.
            with patch.object(harness.tempfile, "gettempdir", return_value=temporary), \
                    patch.dict(reset_main.__globals__, {"terminate_compatibility_runtime": lambda *a, **k: []}), \
                    mock_runtime_process_table(processes), \
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
                for pid in processes:
                    assert f"PID {pid}" in stderr.getvalue()
            assert not work.exists()


def test_staged_executable_cleanup() -> None:
    binary = REPO_ROOT / ".build/test-compat/cengine"
    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = pathlib.Path(temporary)
        work = temporary_root / "cengine-compat-upgrade"
        work.mkdir(mode=0o700)
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
            def kill(pid, pidversion, selected_signal):
                del live[pid]
            with mock_runtime_process_table(live), \
                    patch.object(harness, "_signal_pid_incarnation", side_effect=kill), \
                    patch.object(harness.time, "sleep"):
                stopped = terminate_compatibility_runtime(binary, timeout=0)
            assert [process.pid for process in stopped] == [301, 302, 303, 304]
            assert set(live) == set(commands) - {301, 302, 303, 304}

            # Invalid registrations fail closed before signaling anything or deleting the root.
            for invalid in (["../external/cengine"], [str(binary)], ["."], [7], {}):
                registry.write_text(json.dumps(invalid))
                with patch.object(harness, "_signal_pid_incarnation") as signal_process:
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
                    mock_runtime_process_table(live), \
                    patch.object(harness, "_signal_pid_incarnation", side_effect=PermissionError("stop failed")):
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
                    mock_runtime_process_table(live), \
                    patch.object(harness, "_signal_pid_incarnation", side_effect=kill), \
                    patch.object(harness.time, "sleep"):
                reset_main()
            assert not work.exists()
            assert set(live) == set(commands) - {301, 302, 303, 304}


def test_upgrade_staging_preserves_managed_pair() -> None:
    path = REPO_ROOT / "Tests/Compatibility/test_upgrade_recovery.py"
    source = ast.parse(path.read_text())
    function = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_stage_upgrade_runtime")
    namespace = dict(pathlib=pathlib, shutil=shutil, os=os)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary).resolve()
        original = root / "original"
        original.mkdir()
        binary = original / "cengine"
        binary.write_bytes(b"original signed engine")
        binary.chmod(0o755)
        controller = original / "cengine-storage-controller"
        controller.write_bytes(b"original signed controller")
        controller.chmod(0o755)
        frameworks = original / "PackageFrameworks"
        frameworks.mkdir()
        destination = root / "staged"
        with patch.dict(os.environ, {}, clear=True):
            staged = namespace["_stage_upgrade_runtime"](binary, destination)
        assert staged == destination / "cengine"
        assert staged.read_bytes() == binary.read_bytes()
        assert (destination / "PackageFrameworks").resolve() == frameworks
        copy = destination / controller.name
        assert copy.read_bytes() == controller.read_bytes()
        assert copy.stat().st_mode & 0o777 == 0o755
        assert not copy.is_symlink() and copy.stat().st_ino != controller.stat().st_ino
        controller.unlink()
        with patch.dict(os.environ, {}, clear=True):
            try:
                namespace["_stage_upgrade_runtime"](binary, root / "missing-pair")
            except FileNotFoundError:
                pass
            else:
                raise AssertionError("missing lifecycle controller accepted")


def test_upgrade_expected_refusal_preserves_old_runtime() -> None:
    path = REPO_ROOT / "Tests/Compatibility/test_upgrade_recovery.py"
    source = ast.parse(path.read_text())
    function = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_assert_replacement_refuses_old_writer")
    mismatch = "infrastructure VM belongs to a different or older cengine build"
    environment = {"PATH": "/fixture"}
    namespace = dict(subprocess=subprocess, BUILD_MISMATCH=mismatch,
                     compatibility_environment=lambda: environment)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        command = [str(root / "cengine"), "daemon", "--root", str(root / "root"),
                   "--kernel", "/fixture/kernel"]
        previous = SimpleNamespace(args=command, poll=lambda: 0)
        daemon = SimpleNamespace(binary=root / "cengine", log_path=root / "daemon.log", process=previous)
        cases = [(1, mismatch.encode(), True), (0, mismatch.encode(), False),
                 (1, b"unrelated error: secret fixture", False), (1, b"", False),
                 (1, mismatch.encode() + b"x" * 65536, False)]
        for returncode, output, accepted in cases:
            # An old matching error must never satisfy a later unrelated refusal.
            daemon.log_path.write_bytes(mismatch.encode() + b"\nold secret fixture\n")
            def run(actual, **options):
                assert actual == command
                assert options["env"] == environment and options["timeout"] == 30
                assert options["stdin"] == subprocess.DEVNULL
                assert options["stderr"] == subprocess.STDOUT
                options["stdout"].write(output)
                return SimpleNamespace(returncode=returncode)
            with patch.object(subprocess, "run", side_effect=run) as invoked:
                try:
                    namespace["_assert_replacement_refuses_old_writer"](daemon)
                except AssertionError as error:
                    assert not accepted
                    assert "secret fixture" not in str(error)
                else:
                    assert accepted
                assert invoked.call_count == 1
            assert daemon.process is previous  # No start/stop/cleanup capability was supplied.
            assert daemon.log_path.read_bytes().endswith(output)
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired(command, 30)):
            try:
                namespace["_assert_replacement_refuses_old_writer"](daemon)
            except subprocess.TimeoutExpired:
                pass
            else:
                raise AssertionError("timeout counted as a build refusal")
        previous.poll = lambda: None
        with patch.object(subprocess, "run") as invoked:
            try:
                namespace["_assert_replacement_refuses_old_writer"](daemon)
            except AssertionError:
                pass
            else:
                raise AssertionError("probe launched alongside live API")
            invoked.assert_not_called()


def test_upgrade_replacement_preserves_signing_mode() -> None:
    # Execute the real UUID/signing helper on a synthetic Mach-O, without
    # importing Docker/pytest or invoking codesign, a daemon, or a VM.
    path = REPO_ROOT / "Tests/Compatibility/test_upgrade_recovery.py"
    source = ast.parse(path.read_text())
    function = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_replacement_with_new_uuid")
    namespace: dict = dict(pathlib=pathlib, shutil=shutil, struct=struct, uuid=uuid,
                           os=os, subprocess=subprocess, REPO_ROOT=REPO_ROOT)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    original = uuid.uuid4()
    contents = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    contents += struct.pack("<II", 0x1B, 24) + original.bytes
    identity = "Developer ID Application: Fixture (ABCDEFGHIJ)"
    with tempfile.TemporaryDirectory() as temporary:
        binary = pathlib.Path(temporary) / "cengine"
        binary.write_bytes(contents)
        for configured in (identity,):
            environment = {"CENGINE_DEVELOPER_ID_APPLICATION": configured}
            with patch.dict(os.environ, environment, clear=True), patch.object(subprocess, "run") as run:
                replacement, before, after = namespace["_replacement_with_new_uuid"](binary)
            assert before == original and after != before
            assert binary.read_bytes() == contents
            assert replacement.read_bytes() == contents[:40] + after.bytes
            assert run.call_count == 2
            sign, verify = run.call_args_list
            command = sign.args[0]
            assert command[command.index("--sign") + 1] == identity
            assert command[command.index("--options") + 1] == "runtime"
            assert command[-1] == str(replacement)
            assert verify.args[0] == ["/usr/bin/codesign", "--verify", "--strict", str(replacement)]
            assert sign.kwargs["check"] and verify.kwargs["check"]
        # A signing failure must propagate, not silently fall back to ad-hoc.
        failure = subprocess.CalledProcessError(1, "codesign")
        with patch.dict(os.environ, {"CENGINE_DEVELOPER_ID_APPLICATION": identity}), \
                patch.object(subprocess, "run", side_effect=failure) as run:
            try:
                namespace["_replacement_with_new_uuid"](binary)
            except subprocess.CalledProcessError as error:
                assert error is failure
            else:
                raise AssertionError("signing failure was hidden")
            assert run.call_count == 1
            assert binary.read_bytes() == contents


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
    # Failure before the staged switch must still clean up the original runtime.
    for selected in (original, staged):
        for failures in ((), ("stop",), ("shutdown",), ("stop", "shutdown"),
                         ("terminate",), ("stop", "shutdown", "terminate"), ("start",)):
            events = []
            def action(name):
                events.append(name)
                if name in failures:
                    raise RuntimeError(name)
            def start():
                assert daemon.binary == selected
                action("start")
            daemon = SimpleNamespace(
                binary=selected, root=pathlib.Path("/tmp/cengine-compat-upgrade/root"),
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
            assert daemon.binary == selected
            assert events == ["stop", "shutdown", "terminate"] + (
                [] if "terminate" in failures else ["start"]
            )


def test_daemon_lifecycle_fault_callbacks() -> None:
    # Execute the real start/stop/retention paths without importing Docker/pytest,
    # launching native processes, or contacting the helper.
    from dataclasses import dataclass, field
    from unittest.mock import Mock

    path = REPO_ROOT / "Tests/Compatibility/conftest.py"
    tree = ast.parse(path.read_text())
    definitions: list[ast.stmt] = [node for node in tree.body
                   if isinstance(node, (ast.ClassDef, ast.FunctionDef))
                   and node.name in ("Daemon", "managed_storage_arguments")]
    code = compile(ast.Module(body=definitions, type_ignores=[]), str(path), "exec")

    class StartupFailure(Exception):
        pass

    def fail(message, **kwargs):
        assert kwargs == {"pytrace": False}
        raise StartupFailure(message)

    fresh = "before-configure-v1"
    cold = "after-cold-l2-before-a1-v1"
    profiles = ("before-takeover-apply-v1", "after-takeover-apply-v1")
    cases: list[tuple[str, int | None, object, str, str]] = [
             (fresh, 71, True, "fresh", "accepted"),
             (fresh, -9, True, "fresh", "failed"),
             (fresh, 0, True, "fresh", "failed"),
             (fresh, 71, False, "fresh", "failed"),
             (fresh, 71, True, "restart", "refused")]
    cases.append((cold, 71, True, "restart", "accepted"))
    for returncode in (-9, -15, 0):
        cases.append((cold, returncode, True, "restart", "failed"))
    for result in (False, None, 1):
        cases.append((cold, 71, result, "restart", "failed"))
    for mode in ("fresh", "unowned", "unretained", "latched", "no-root", "no-fixture"):
        cases.append((cold, 71, True, mode, "refused"))
    for mode in ("swapped-child", "swapped-child-error", "callback-error", "mutated-binary", "mutated-owner", "mutated-retention", "mutated-returncode", "mutated-owner-binary", "mutated-root"):
        cases.append((cold, 71, True, mode, "failed"))
    for profile in profiles:
        cases.append((profile, -9, True, "restart", "accepted"))
        for returncode in (-15, 0, 71, None):
            cases.append((profile, returncode, True, "restart", "failed"))
        for result in (False, None, 1):
            cases.append((profile, -9, result, "restart", "failed"))
        for mode in ("fresh", "unowned", "unretained", "latched", "no-root", "no-fixture"):
            cases.append((profile, -9, True, mode, "refused"))
        for mode in ("dead-child", "swapped-child", "swapped-child-error", "callback-error"):
            cases.append((profile, -9, True, mode, "failed"))
    for profile in ("arbitrary", "", "after-replacement-before-completion-v1"):
        cases.append((profile, -9, True, "restart", "refused"))

    for profile, exit_code, result, mode, expected in cases:
        with tempfile.TemporaryDirectory(prefix="cengine-compat-callback-") as temporary:
            events = []
            unrelated = SimpleNamespace(poll=lambda: None, terminate=Mock(), kill=Mock())
            child = SimpleNamespace(returncode=None)
            child.poll = lambda: child.returncode
            def wait(*, timeout):
                events.append("wait")
                if profile in (fresh, cold):
                    child.returncode = exit_code
                return child.returncode
            child.wait = Mock(side_effect=wait)
            child.kill = Mock(side_effect=lambda: setattr(child, "returncode", -9))
            child.terminate = Mock(side_effect=lambda: setattr(child, "returncode", -15))
            process_api = SimpleNamespace(Popen=Mock(return_value=child), run=Mock(),
                DEVNULL=subprocess.DEVNULL, STDOUT=subprocess.STDOUT, PIPE=subprocess.PIPE,
                TimeoutExpired=subprocess.TimeoutExpired)
            cleanup = Mock()
            namespace: dict = dict(__name__="__main__", dataclass=dataclass, field=field,
                pathlib=pathlib, os=SimpleNamespace(environ={"CENGINE_COMPAT_LIFECYCLE_FAULT": profile}),
                subprocess=process_api, time=time, compatibility_environment=lambda: {},
                COMPATIBILITY_OWNER_FILE=COMPATIBILITY_OWNER_FILE,
                compatibility_root_retained=compatibility_root_retained,
                retain_compatibility_root=retain_compatibility_root,
                terminate_compatibility_runtime=cleanup, pytest=SimpleNamespace(fail=fail))
            exec(code, namespace)
            work = pathlib.Path(temporary)
            binary = work / "cengine"
            daemon = namespace["Daemon"](binary=binary, kernel=work / "kernel",
                container_initramfs=work / "container", storage_initramfs=work / "storage", work=work)
            harness.preretain_compatibility_root(work, daemon.owner_binary)
            daemon._managed_fixture_retention = mode != "no-fixture"
            daemon._manual_lifecycle_start = mode == "fresh"
            if mode != "fresh":
                daemon.process = SimpleNamespace(poll=lambda: -9)
            if mode == "unowned":
                (work / COMPATIBILITY_OWNER_FILE).write_text("/other/cengine\n")
            elif mode == "unretained":
                namespace["compatibility_root_retained"] = lambda directory: False
            elif mode == "latched":
                daemon._retain_root = True
            elif mode == "no-root":
                daemon.root.rmdir()
            elif mode == "dead-child":
                child.returncode = -9

            def qualify(actual):
                events.append("callback")
                assert actual is daemon and actual.process is child
                assert child.poll() == (exit_code if profile in (fresh, cold) else None)
                if profile not in (fresh, cold):
                    if mode == "callback-error":
                        raise RuntimeError("secret callback diagnostic")
                    if exit_code == -9:
                        actual.stop(kill=True)
                        assert actual._log is None
                    else:
                        child.returncode = exit_code
                    if mode in ("swapped-child", "swapped-child-error"):
                        actual.process = unrelated
                        if mode == "swapped-child-error":
                            raise RuntimeError("secret swapped-child diagnostic")
                if profile == cold:
                    if mode in ("swapped-child", "swapped-child-error"):
                        actual.process = unrelated
                    if mode in ("callback-error", "swapped-child-error"):
                        raise RuntimeError("secret callback diagnostic")
                    if mode == "mutated-binary": actual.binary = work / "other"
                    if mode == "mutated-owner": (work / COMPATIBILITY_OWNER_FILE).write_text("/other/cengine\n")
                    if mode == "mutated-retention": actual._managed_fixture_retention = False
                    if mode == "mutated-returncode": child.returncode = 0
                    if mode == "mutated-owner-binary": actual.owner_binary = work / "other"
                    if mode == "mutated-root": actual.root = work
                return result

            callback = Mock(side_effect=qualify)
            backend = SimpleNamespace(capture_backend_root=Mock())
            with patch.dict(sys.modules, storage_backend_proof=backend):
                try:
                    daemon.start(qualify_lifecycle_fault=callback)
                except ValueError:
                    assert expected == "refused", (profile, exit_code, result, mode)
                    process_api.Popen.assert_not_called()
                    callback.assert_not_called()
                    cleanup.assert_not_called()
                except StartupFailure as error:
                    assert expected == "failed", (profile, exit_code, result, mode)
                    assert "secret" not in str(error)
                    assert daemon._retain_root and compatibility_root_retained(work)
                    cleanup.assert_called_once_with(daemon.owner_binary, roots=(daemon.root,))
                else:
                    assert expected == "accepted", (profile, exit_code, result, mode)
                    callback.assert_called_once_with(daemon)
                    assert daemon.process is child and child.poll() == exit_code
                    assert daemon._log is None and not daemon._retain_root
                    assert compatibility_root_retained(work)
                    cleanup.assert_not_called()
                    if profile in (fresh, cold):
                        assert events == ["wait", "callback"]
                        child.kill.assert_not_called()
                    else:
                        assert events == ["callback", "wait"]
                        child.kill.assert_called_once_with()
                    child.terminate.assert_not_called()
                process_api.run.assert_not_called()  # No API ping before the callback.
                unrelated.terminate.assert_not_called()
                unrelated.kill.assert_not_called()
                if mode in ("swapped-child", "swapped-child-error"):
                    assert daemon.process is child
                assert daemon._log is None


def check_disk_observation() -> None:
    # Exercise the actual compatibility observation without importing its
    # Docker/pytest dependencies or invoking a daemon, VM, or guest command.
    path = REPO_ROOT / "Tests/Compatibility/test_disk_initialization.py"
    tree = ast.parse(path.read_text(), filename=str(path))
    names = {"_mounts", "_observe", "_persistent_observation"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in functions} == names
    values: dict = {"uuid": uuid}
    exec(compile(ast.Module(body=[*functions], type_ignores=[]), str(path), "exec"), values)
    disk_uuid = uuid.UUID("bfa34f84-14eb-4c71-83fe-dc6a1287f46a")
    journal = {"expectedSize": 16 * 1024 * 1024, "ext4UUID": str(disk_uuid)}
    baseline = None
    for source in ("/dev/vda", "/proc/self/fd/5", "/proc/self/fd/12"):
        def command(_container, *args):
            if args == ("cat", "/proc/self/mountinfo"):
                return f"41 34 254:0 / / rw - ext4 {source} rw\n".encode()
            assert args[:2] == ("sh", "-ec")
            assert "test -b /dev/vda" in args[2]
            assert "stat -c '%t:%T' /dev/vda" in args[2]
            # virtio-blk's serial sysfs attribute has no trailing newline. Execute
            # the real observation's shell prefix with that kernel byte contract;
            # canned newline-delimited output concealed a field-shift regression.
            prefix = args[2].split("test -b /dev/vda", 1)[0]
            with tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / "serial").write_bytes(b"root")
                (root / "size").write_bytes(b"32768\n")
                prefix = prefix.replace("/sys/class/block/vda", shlex.quote(directory))
                observed = subprocess.check_output(["/bin/sh", "-ec", prefix])
            assert observed == b"root\n32768\n", observed
            return observed + (f"fe:0\n254:0\n1000:1100:3777:2\n{disk_uuid.bytes.hex(' ')}\n").encode()
        values["_exec"] = command
        result = values["_observe"](None, {"/": journal})
        assert result["/"]["mountSource"] == source
        identity = values["_persistent_observation"](result)
        assert identity["/"]["device"] == "254:0"
        if baseline is not None:
            assert identity == baseline
        baseline = identity

    # A cosmetic source match must not conceal a different mounted device,
    # sysfs identity, serial, capacity, UUID, filesystem, or subdirectory mount.
    for original, replacement in (
        (b"41 34 254:0", b"41 34 254:16"),
        (b"fe:0", b"fe:10"),
        (b"\n254:0\n", b"\n254:16\n"),
        (b"root\n", b"volume0\n"),
        (b"32768\n", b"32769\n"),
        (disk_uuid.bytes.hex(' ').encode(), bytes(16).hex(' ').encode()),
        (b"- ext4", b"- xfs"),
        (b" / / rw", b" /subdir / rw"),
    ):
        values["_exec"] = lambda *args: command(*args).replace(original, replacement)
        try:
            values["_observe"](None, {"/": journal})
        except AssertionError:
            pass
        else:
            raise AssertionError(f"accepted changed guest identity: {original!r}")


def check_owned_disk_claims() -> None:
    path = REPO_ROOT / "Tests/Compatibility/test_disk_initialization.py"
    tree = ast.parse(path.read_text(), filename=str(path))
    names = {"_matched_pids", "_quiesce", "_disk_holders", "_DiskClaimTimeout", "_record_disk_event",
             "_owned_disk", "_host_uuid", "_stable_file_identity", "_journal"}
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    assert {node.name for node in nodes} == names
    from storage_backend_proof import _file_identity
    values = {"_file_identity": _file_identity, "PHASES": ("created", "spent", "initialized"),
              "contextmanager": contextmanager, "errno": errno, "fcntl": fcntl, "json": json,
              "os": os, "stat": stat, "time": time, "uuid": uuid, "selectors": selectors,
              "subprocess": subprocess, "compatibility_root_owned_by": compatibility_root_owned_by,
              "compatibility_disk_holder_diagnostics": lambda records, binary: []}
    exec(compile(ast.Module(body=[*nodes], type_ignores=[]), str(path), "exec"), values)

    @contextmanager
    def rejects(kind):
        try:
            yield
        except kind:
            pass
        else:
            raise AssertionError(f"expected {kind}")

    with tempfile.TemporaryDirectory() as directory:
        work = pathlib.Path(directory)
        root = work / "root"
        root.mkdir()
        disk = root / "disk.ext4"
        disk_uuid = uuid.UUID("8096e57f-840b-4f26-a46d-056d6f2b8486")
        content = bytearray(4096)
        content[1080:1082] = b"\x53\xef"
        content[1128:1144] = disk_uuid.bytes
        disk.write_bytes(content)
        info = disk.stat()
        with disk.open("rb") as stream:
            stable = values["_stable_file_identity"](stream.fileno())
        journal = {"diskIdentity": stable,
                   "expectedSize": info.st_size, "ext4UUID": str(disk_uuid)}
        lock = disk.with_name(f".raw-init-{disk.name}.lock")
        lock.touch()
        parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            parent_identity = values["_stable_file_identity"](parent_fd)
        finally:
            os.close(parent_fd)
        with lock.open("rb") as stream:
            lock_identity = values["_stable_file_identity"](stream.fileno())
        initial = dict(journal, schemaVersion=2, state="created", diskName=disk.name,
                       parentIdentity=parent_identity, lockIdentity=lock_identity, operationUUID=str(uuid.uuid4()))
        binding = dict(shimLaunchUUID=str(uuid.uuid4()), guestBootNonce=str(uuid.uuid4()))
        records = {phase: dict(initial, state=phase, **({"binding": binding} if phase != "created" else {}))
                   for phase in values["PHASES"]}
        def publish_records():
            for phase, value in records.items():
                disk.with_name(f".raw-init-{disk.name}.{phase}.json").write_text(json.dumps(value))
        publish_records()
        assert values["_journal"](disk)[0] == records["initialized"]
        for field in ("diskIdentity", "parentIdentity", "lockIdentity"):
            for invalid in ("device", "inode", "volumeUUID"):
                original = records["created"][field]
                records["created"][field] = dict(original, **{invalid:
                    str(uuid.uuid4()).upper() if invalid == "volumeUUID" else original.get(invalid, 0) + 1})
                publish_records()
                with rejects(AssertionError):
                    values["_journal"](disk)
                records["created"][field] = original
        records["created"]["schemaVersion"] = 1
        publish_records()
        with rejects(AssertionError):
            values["_journal"](disk)
        records["created"]["schemaVersion"] = 2
        publish_records()
        binary = work / "unique-cengine"
        (work / COMPATIBILITY_OWNER_FILE).write_text(str(binary.resolve()))
        calls, events = [], []
        daemon = SimpleNamespace(work=work, root=root, binary=binary, stop=lambda: calls.append("stop"))
        values["terminate_compatibility_runtime"] = lambda *a, **k: [RuntimeProcess(123, "not logged")]
        values["compatibility_runtime_processes"] = lambda *a, **k: []
        record = lambda phase, **details: events.append({"phase": phase, **details})
        quiescence = values["_quiesce"](daemon, record=record)
        assert calls == ["stop"] and quiescence == {
            "cleanup_matched_pids": [123], "remaining_matched_pids": []}
        assert events == [{"phase": "quiesced", **quiescence}]
        values["compatibility_runtime_processes"] = lambda *a, **k: [RuntimeProcess(456, "secret argv")]
        with rejects(AssertionError):
            values["_quiesce"](daemon, record=record)
        assert events[-1]["remaining_matched_pids"] == [456] and "secret" not in json.dumps(events)
        values["compatibility_runtime_processes"] = lambda *a, **k: []
        values["_disk_holders"] = lambda actual: {"records": "p456\ncVirtualization\nf5u\nn" + str(actual)}
        options = {"quiescence": quiescence, "role": "storage", "record": record}

        # The first rejection is an ACTUAL separate-open-file-description flock.
        # Release only from the sleep hook, and verify every raw byte read happens
        # while the fixture (not the old holder) excludes an independent claim.
        holder = os.open(disk, os.O_RDONLY)
        real_flock, real_pread = fcntl.flock, os.pread
        real_flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        reads, sleeps = [], []

        def release_holder(delay):
            assert not reads
            sleeps.append(delay)
            real_flock(holder, fcntl.LOCK_UN)

        def checked_read(fd, size, offset):
            with rejects(BlockingIOError):
                real_flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            reads.append((size, offset))
            return real_pread(fd, size, offset)

        try:
            events.clear()
            with patch.object(time, "sleep", side_effect=release_holder), \
                    patch.object(os, "pread", side_effect=checked_read):
                assert values["_host_uuid"](daemon, disk, journal, **options) == str(disk_uuid)
            assert len(sleeps) == 1 and reads == [(2, 1080), (16, 1128)]
            assert [item["phase"] for item in events] == ["disk-claim-contention", "disk-claim-acquired"]
            assert events[0]["disk"] == "disk.ext4" and events[0]["role"] == "storage"
            assert events[0]["cleanup_matched_pids"] == [123] and events[0]["remaining_matched_pids"] == []
            # Closing the claim really releases the kernel lock.
            real_flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            real_flock(holder, fcntl.LOCK_UN)
        finally:
            os.close(holder)

        # EINTR and EAGAIN are retryable; all other errno fail immediately.
        for code in (errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK):
            events.clear()
            attempts = []

            def interrupted(fd, flags):
                attempts.append(flags)
                if len(attempts) == 1:
                    raise OSError(code, "injected contention")
                real_flock(fd, flags)

            with patch.object(fcntl, "flock", side_effect=interrupted), patch.object(time, "sleep"):
                with values["_owned_disk"](daemon, disk, journal, **options):
                    pass
            assert attempts == [fcntl.LOCK_EX | fcntl.LOCK_NB] * 2
        for code in (errno.EBADF, errno.EACCES, errno.EIO, errno.ENOTSUP):
            events.clear()
            with patch.object(fcntl, "flock", side_effect=OSError(code, "injected fatal errno")) as claim, \
                    patch.object(time, "sleep") as sleep, patch.object(os, "pread") as read:
                with rejects(OSError):
                    with values["_owned_disk"](daemon, disk, journal, **options):
                        raise AssertionError("must not yield")
                claim.assert_called_once()
                sleep.assert_not_called()
                read.assert_not_called()
            assert events == []

        # A deterministic deadline is a failure, not a license to read or write.
        events.clear()
        clock = [0.0]
        def advance(delay):
            clock[0] += delay
        with patch.object(time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(time, "sleep", side_effect=advance), \
                patch.object(fcntl, "flock", side_effect=BlockingIOError(errno.EWOULDBLOCK, "held")), \
                patch.object(os, "pread") as read, patch.object(os, "pwrite") as write:
            with rejects(values["_DiskClaimTimeout"]):
                with values["_owned_disk"](daemon, disk, journal, writable=True, **options):
                    raise AssertionError("must not yield")
            read.assert_not_called()
            write.assert_not_called()
        assert [item["phase"] for item in events] == ["disk-claim-contention", "disk-claim-timeout"]
        assert events[-1]["duration_seconds"] == 10.0 and disk.read_bytes() == content

        # Broken evidence/lsof must not replace the primary timeout exception.
        def broken_evidence(*args, **kwargs):
            raise OSError(errno.ENOSPC, "sentinel must not leak")
        saved_holders = values["_disk_holders"]
        values["_disk_holders"] = broken_evidence
        clock[0] = 0.0
        with patch.object(time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(time, "sleep", side_effect=advance), \
                patch.object(fcntl, "flock", side_effect=BlockingIOError(errno.EWOULDBLOCK, "held")):
            try:
                with values["_owned_disk"](daemon, disk, journal, **{**options, "record": broken_evidence}):
                    raise AssertionError("must not yield")
            except values["_DiskClaimTimeout"] as error:
                assert "evidence_error" in str(error) and "sentinel" not in str(error)
            else:
                raise AssertionError("expected primary timeout")
        values["_disk_holders"] = saved_holders
        attempts = []
        code = errno.EINTR
        with patch.object(fcntl, "flock", side_effect=interrupted), patch.object(time, "sleep"):
            with values["_owned_disk"](daemon, disk, journal, **{**options, "record": broken_evidence}):
                pass  # Even the successful-acquisition event is non-authoritative.
        assert len(attempts) == 2

        # Safety assertions can never be bypassed with python -O/--assert=plain:
        # the real helpers explicitly refuse optimized execution before any IO.
        optimized = dict(values)
        exec(compile(ast.Module(body=[*nodes], type_ignores=[]), str(path), "exec", optimize=1), optimized)
        with patch.object(os, "open") as opened:
            with rejects(RuntimeError):
                optimized["_quiesce"](None)
            with rejects(RuntimeError):
                with optimized["_owned_disk"](None, None, None, quiescence={}, role="storage"):
                    raise AssertionError("must not yield")
            opened.assert_not_called()

        # Validate the already-open FD before the first attempt; wrong owner,
        # journal inode, and an unsafe pathname cannot reach flock or raw IO.
        for invalid in ("owner", "inode", "volumeUUID", "legacy-device", "marker", "symlink", "live-process"):
            changed = {**journal, "diskIdentity": {**journal["diskIdentity"]}}
            if invalid == "inode":
                changed["diskIdentity"]["inode"] += 1
            if invalid == "volumeUUID":
                changed["diskIdentity"]["volumeUUID"] = str(uuid.uuid4()).upper()
            if invalid == "legacy-device":
                changed["diskIdentity"]["device"] = info.st_dev
            if invalid == "marker":
                (work / COMPATIBILITY_OWNER_FILE).write_text("/foreign/binary")
            if invalid == "symlink":
                disk.rename(root / "saved.ext4")
                disk.symlink_to(root / "saved.ext4")
            values["compatibility_runtime_processes"] = lambda *a, **k: (
                [RuntimeProcess(123, "secret must not be logged")] if invalid == "live-process" else [])
            actual_uid = os.getuid()
            with patch.object(os, "getuid", return_value=actual_uid + (invalid == "owner")), \
                    patch.object(fcntl, "flock") as claim, patch.object(os, "pread") as read:
                with rejects(AssertionError):
                    with values["_owned_disk"](daemon, disk, changed, **options):
                        raise AssertionError("must not yield")
                claim.assert_not_called()
                read.assert_not_called()
            (work / COMPATIBILITY_OWNER_FILE).write_text(str(binary.resolve()))
            if invalid == "symlink":
                disk.unlink()
                (root / "saved.ext4").rename(disk)
        values["compatibility_runtime_processes"] = lambda *a, **k: []

        # A rename while contended must not let the old pinned FD authorize the
        # new pathname, even if the replacement has identical bytes and length.
        def replace_disk(_delay):
            disk.rename(root / "saved.ext4")
            disk.write_bytes(content)
        yielded = []
        with patch.object(fcntl, "flock", side_effect=BlockingIOError(errno.EWOULDBLOCK, "held")) as claim, \
                patch.object(time, "sleep", side_effect=replace_disk), patch.object(os, "pread") as read:
            with rejects(AssertionError):
                with values["_owned_disk"](daemon, disk, journal, **options):
                    yielded.append(True)
            assert not yielded
            claim.assert_called_once()
            read.assert_not_called()
        assert disk.read_bytes() == (root / "saved.ext4").read_bytes() == content
        disk.unlink()
        (root / "saved.ext4").rename(disk)

        # Also replace immediately after successful flock: only the post-claim
        # path/FD comparison catches this, even though all preflight checks passed.
        def claim_then_replace(fd, flags):
            real_flock(fd, flags)
            replace_disk(0)
        with patch.object(fcntl, "flock", side_effect=claim_then_replace), patch.object(os, "pread") as read:
            with rejects(AssertionError):
                with values["_owned_disk"](daemon, disk, journal, **options):
                    yielded.append(True)
            assert not yielded
            read.assert_not_called()
        assert disk.read_bytes() == (root / "saved.ext4").read_bytes() == content

    # Exercise the ACTUAL fixture finally block with an active primary error.
    # Once a raw-disk phase starts, every failure type suppresses boot/removal,
    # even if writing both failure and cleanup evidence also fails.
    fixture = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name.startswith("test_disk_bootstrap_"))
    operation = next(node for node in fixture.body if isinstance(node, ast.Try))
    cleanup = compile(ast.Module(body=[*operation.finalbody], type_ignores=[]), str(path), "exec")
    for failure in (values["_DiskClaimTimeout"]("timeout"), OSError(errno.EIO, "IO"), AssertionError("identity")):
        actions = []
        cleanup_values = {**values, "sys": sys, "preserve_disks": True,
                          "daemon": SimpleNamespace(process=None, start=lambda: actions.append("start")),
                          "client": SimpleNamespace(api=SimpleNamespace(timeout=5)),
                          "previous_timeout": 180, "record": broken_evidence,
                          "print": lambda *a, **k: None}
        try:
            raise failure
        except BaseException:
            exec(cleanup, cleanup_values)
            assert sys.exc_info()[1] is failure
        assert actions == [] and cleanup_values["client"].api.timeout == 180
    # Every quiescence call must be preceded by the phase-preservation latch.
    guarded_calls = 0
    for parent in ast.walk(fixture):
        for _, children in ast.iter_fields(parent):
            if not isinstance(children, list):
                continue
            for index, node in enumerate(children):
                if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Name) and node.value.func.id == "_quiesce"):
                    previous = children[index - 1]
                    assert isinstance(previous, ast.Assign) and isinstance(previous.targets[0], ast.Name)
                    assert previous.targets[0].id == "preserve_disks" and previous.value.value is True
                    guarded_calls += 1
    assert guarded_calls == 3

    # Real, harmless owned subprocesses exercise output cap and timeout teardown
    # without running lsof or inspecting/signalling any ambient process.
    exec(compile(ast.Module(body=[node for node in nodes if isinstance(node, ast.FunctionDef)
                                 and node.name == "_disk_holders"], type_ignores=[]), str(path), "exec"), values)
    real_popen = subprocess.Popen
    for mode in ("large", "hang", "done"):
        children = []
        def spawn(command, **kwargs):
            assert command == ["/usr/sbin/lsof", "-nP", "-Fpcfn", "--", "/owned/exact.ext4"]
            script = {"large": "import os; os.write(1, b'n' * 10000)",
                      "hang": "import time; time.sleep(30)",
                      "done": "print('p321\\ncowned\\nf5u\\nn/owned/exact.ext4')"}[mode]
            child = real_popen([sys.executable, "-c", script], **kwargs)
            children.append(child)
            return child
        started = time.monotonic()
        with patch.object(subprocess, "Popen", side_effect=spawn):
            diagnostic = values["_disk_holders"](pathlib.Path("/owned/exact.ext4"))
        assert len(diagnostic["records"].encode()) <= 8192 and children[0].poll() is not None
        assert time.monotonic() - started < 5.0
        assert diagnostic["end"] == {"large": "output-limit", "hang": "timeout", "done": "eof"}[mode]
    with patch.object(subprocess, "Popen", side_effect=OSError(errno.ENOENT, "missing")):
        assert values["_disk_holders"](pathlib.Path("/owned/exact.ext4")) == {"error_errno": errno.ENOENT}


def check_kernel_process_exit_recheck() -> None:
    # Fully scripted libproc: no ambient process inspection or signals. Neither
    # initial ENOENT (including an unlinked live executable) nor any other error
    # licenses absence without a fresh authoritative ESRCH.
    live = bytearray(56)
    live[16:24] = (300).to_bytes(8, sys.byteorder)
    live[32:36] = (7).to_bytes(4, sys.byteorder)
    reused = bytearray(live)
    reused[16:24] = (301).to_bytes(8, sys.byteorder)
    reused[32:36] = (8).to_bytes(4, sys.byteorder)
    probes = (
        ("absent", 0, errno.ESRCH, bytes(56), True),
        ("negative-absent", -1, errno.ESRCH, bytes(56), True),
        ("live", 56, 0, bytes(live), False),
        ("reused-live", 56, errno.ESRCH, bytes(reused), False),
        ("malformed-full", 56, errno.ESRCH, bytes(56), False),
        ("short", 8, errno.ESRCH, bytes(56), False),
        ("unknown", 0, 0, bytes(56), False),
        ("stale-errno", 0, None, bytes(56), False),
        ("enoent", 0, errno.ENOENT, bytes(56), False),
        ("permission", 0, errno.EPERM, bytes(56), False),
        ("io", 0, errno.EIO, bytes(56), False),
    )
    for initial_errno in (errno.ENOENT, errno.EPERM, errno.EIO):
        for label, count, probe_errno, contents, absent in probes:
            calls = []
            def failed_path(pid, buffer, size):
                assert pid == 123 and size == 4096
                calls.append("path")
                ctypes.set_errno(initial_errno)
                return 0
            def recheck(pid, flavor, argument, buffer, size):
                assert (pid, flavor, argument.value, size) == (123, 17, 0, 56)
                assert ctypes.get_errno() == 0  # Never consume stale first-call errno.
                calls.append("recheck")
                ctypes.memmove(buffer, contents, len(contents))
                if probe_errno is not None:
                    ctypes.set_errno(probe_errno)
                return count
            native = SimpleNamespace(proc_pidpath=failed_path, proc_pidinfo=recheck)
            with patch("harness.sys.platform", "darwin"), patch("harness.ctypes.CDLL", return_value=native):
                try:
                    result = _kernel_process(123)
                except RuntimeError as error:
                    assert not absent, (initial_errno, label)
                    assert str(error) == f"kernel process inspection failed for PID 123, errno {initial_errno}"
                else:
                    assert absent and result is None, (initial_errno, label)
            assert calls == ["path", "recheck"], (initial_errno, label)
    # Existing direct ESRCH handling remains immediate: no second query/retry.
    def absent_path(*_):
        ctypes.set_errno(errno.ESRCH)
        return 0
    with patch("harness.sys.platform", "darwin"), patch("harness.ctypes.CDLL", return_value=SimpleNamespace(
            proc_pidpath=absent_path)):
        assert _kernel_process(123) is None


def check_kernel_runtime_ownership() -> None:
    binary = pathlib.Path("/bin/bash")
    with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
        work = pathlib.Path(temporary)
        root = work / "root"
        root.mkdir()
        (work / COMPATIBILITY_OWNER_FILE).write_text(str(binary.resolve()))
        (work / "vm-shim").write_text("printf 'ready\\n'; IFS= read -r token\n")
        specification = root / "infrastructure/storage-shim-generations/generation/spec.json"
        for argv0 in (str(binary), "cengine", str(work / "binary-alias")):
            # A real native process with storage-shaped argv and no daemon/VM.
            # Its harmless shell script blocks on owned stdin until we close it.
            args = [argv0, "vm-shim", "--spec", str(specification),
                    "--spec-sha256", "a" * 64, "--storage-disk-fd", "3"]
            child = subprocess.Popen(args, executable=str(binary), cwd=work,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            try:
                assert child.stdout is not None
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    assert selector.select(3), "owned process did not become ready"
                assert child.stdout.readline() == b"ready\n"
                observed = _kernel_process(child.pid)
                assert observed is not None and observed.arguments == tuple(args), observed
                assert observed.identity is not None and observed.identity[0] > 0
                assert pathlib.Path(observed.executable).resolve() == binary.resolve()
                assert _runtime_matches(observed, binary, (root,))
                assert _runtime_matches(observed, binary, ())
                if argv0 == "cengine":
                    assert not " ".join(args).startswith(str(binary.resolve()) + " ")
                # Actual native enumeration must find this owned child despite
                # abbreviated argv[0], not just a fabricated process-table row.
                with patch("harness.subprocess.run", return_value=SimpleNamespace(
                        stdout=f"{child.pid} {os.getuid()}\n")):
                    assert compatibility_runtime_processes(binary, roots=(root,)) == [observed]
            finally:
                child.communicate(input=b"done\n", timeout=3)
            assert child.returncode == 0

        valid = RuntimeProcess(123, executable=str(binary), arguments=("alias", "vm-shim", "--spec", str(specification)),
                               identity=(100, 2, 300), pidversion=7)
        for arguments in (
            ("alias", "daemon", "--root", str(root) + "-foreign"),
            ("alias", "daemon", "--root", "/foreign", "--socket", str(root / "socket")),
            ("alias", "vm-shim", "--spec", str(root) + "-foreign/spec.json"),
            ("alias", "vm-shim", "--spec", "/foreign/spec.json", "--note", str(root)),
            ("alias", "vm-shim", "--spec", str(specification), "--spec", "/foreign/spec.json"),
            ("alias", "other", "--note", "vm-shim", "--spec", str(specification)),
        ):
            assert not _runtime_matches(RuntimeProcess(123, executable=str(binary), arguments=arguments), binary, (root,))
        assert not _runtime_matches(RuntimeProcess(123, executable="/foreign/cengine", arguments=valid.arguments), binary, (root,))
        with patch("harness._kernel_process", return_value=valid), patch("harness._signal_pid_incarnation") as kill:
            _signal_runtime_process(valid, signal.SIGTERM)
            kill.assert_called_once_with(123, 7, signal.SIGTERM)
        for changed in (
            RuntimeProcess(123, executable=valid.executable, arguments=valid.arguments, identity=(101, 2, 301)),
            RuntimeProcess(123, executable="/foreign/cengine", arguments=valid.arguments, identity=valid.identity),
            RuntimeProcess(123, executable=valid.executable, arguments=("foreign",), identity=valid.identity),
        ):
            with patch("harness._kernel_process", return_value=changed), patch("harness._signal_pid_incarnation") as kill:
                try:
                    _signal_runtime_process(valid, signal.SIGTERM)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("changed process must not be signalled")
                kill.assert_not_called()
        with patch("harness._kernel_process", side_effect=RuntimeError("unknown permission")), patch("harness._signal_pid_incarnation") as kill:
            try:
                _signal_runtime_process(valid, signal.SIGTERM)
            except RuntimeError:
                pass
            else:
                raise AssertionError("unknown process must not be signalled")
            kill.assert_not_called()

        assert not compatibility_root_retained(work)
        with _compatibility_root_claim(work, binary):
            for operation in (lambda: remove_compatibility_root(work, binary),
                              lambda: retain_compatibility_root(work, binary, reason="unsafe-disk-phase")):
                try:
                    operation()
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError("retention/removal must share the directory inode lock")
            assert work.is_dir()
        retain_compatibility_root(work, binary, reason="unsafe-disk-phase")
        marker = work / ".cengine-compat-retain"
        assert compatibility_root_retained(work) and json.loads(marker.read_text())["reason"] == "unsafe-disk-phase"
        # Existing marker bytes are immutable, including incomplete publication.
        marker.write_bytes(b"")
        retain_compatibility_root(work, binary, reason="cleanup-incomplete")
        assert compatibility_root_retained(work) and marker.read_bytes() == b""
        marker.unlink()
        marker.symlink_to(work / "absent")
        assert compatibility_root_retained(work)

    # Reset must still attempt owned process cleanup, but never delete a retained
    # root or report success. Exercise the actual reset entry point with all
    # process actions mocked, including empty/dangling retention markers.
    reset = runpy.run_path(str(REPO_ROOT / "Scripts/reset-compat-runtime.py"))
    with tempfile.TemporaryDirectory(prefix="cengine-compat-") as temporary:
        work = pathlib.Path(temporary)
        (work / COMPATIBILITY_OWNER_FILE).write_text(str(binary.resolve()))
        marker = work / ".cengine-compat-retain"
        for kind in ("valid", "empty", "symlink"):
            if os.path.lexists(marker):
                marker.unlink()
            if kind == "symlink":
                marker.symlink_to(work / "absent")
            else:
                marker.write_text("" if kind == "empty" else '{"schemaVersion":1}')
            with patch.dict(reset["main"].__globals__, {
                    "terminate_compatibility_runtime": lambda *a, **k: [],
                    "compatibility_runtime_processes": lambda *a, **k: []}), \
                    patch.object(tempfile, "gettempdir", return_value=str(work.parent)), \
                    patch.object(sys, "argv", ["reset-compat-runtime.py", "--binary", str(binary)]), \
                    patch("shutil.rmtree") as remove:
                try:
                    reset["main"]()
                except SystemExit as error:
                    assert "did not reach a clean state" in str(error)
                else:
                    raise AssertionError("retained reset must fail closed")
                remove.assert_not_called()
            assert work.is_dir() and os.path.lexists(marker)

    # Permanent coverage of the actual generic fixture teardown deletion guard.
    conftest_path = REPO_ROOT / "Tests/Compatibility/conftest.py"
    conftest = ast.parse(conftest_path.read_text(), filename=str(conftest_path))
    daemon_fixture = next(node for node in conftest.body if isinstance(node, ast.FunctionDef) and node.name == "daemon")
    teardown = next(node.finalbody for node in daemon_fixture.body if isinstance(node, ast.Try) and node.finalbody)
    for retained in (False, True):
        actions = []
        value = SimpleNamespace(root_retained=retained, stop=lambda: actions.append("stop"), process=None,
                                binary=binary, owner_binary=binary, root=pathlib.Path("/owned/root"), logs=lambda: "no secrets")
        namespace = {"value": value, "work": pathlib.Path("/owned"), "receipt": None,
                     "request": SimpleNamespace(node=SimpleNamespace(report_call=SimpleNamespace(failed=True))),
                     "terminate_compatibility_runtime": lambda *a, **k: actions.append("terminate"),
                     "remove_compatibility_root": lambda *a, **k: actions.append("remove"),
                     "print": lambda *a, **k: None}
        exec(compile(ast.Module(body=[*teardown], type_ignores=[]), str(conftest_path), "exec"), namespace)
        assert actions == (["stop", "terminate"] if retained else ["stop", "terminate", "remove"])

    # Inspecting a process that exits at the final path query is absence, not
    # fabricated EIO. All other native reads use this test process only.
    native = ctypes.CDLL(None, use_errno=True)
    queries = []
    def exit_at_final_path(pid, buffer, size):
        queries.append(pid)
        if len(queries) == 2:
            ctypes.set_errno(errno.ESRCH)
            return 0
        return native.proc_pidpath(pid, buffer, size)
    with patch("harness.ctypes.CDLL", return_value=SimpleNamespace(
            proc_pidpath=exit_at_final_path, proc_pidinfo=native.proc_pidinfo, sysctl=native.sysctl)):
        assert _kernel_process(os.getpid()) is None
    assert len(queries) == 2
    # The only signalling primitive carries PID incarnation atomically; no real
    # signal is issued. Check native token layout and errno-return semantics.
    for status in (0, errno.ESRCH, errno.EPERM):
        def signal_token(pointer, sig):
            words = list(ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32 * 8)).contents)
            assert words == [0, 0, 0, 0, 0, 123, 0, 7] and sig == signal.SIGTERM
            return status
        with patch("harness.ctypes.CDLL", return_value=SimpleNamespace(proc_signal_with_audittoken=signal_token)):
            try:
                _signal_pid_incarnation(123, 7, signal.SIGTERM)
            except RuntimeError:
                assert status == errno.EPERM
            else:
                assert status in (0, errno.ESRCH)

    observed_pids = []
    with patch("harness.compatibility_process_diagnostic", side_effect=lambda pid, _: observed_pids.append(pid) or {"pid": pid}):
        result = compatibility_disk_holder_diagnostics("\n".join(f"p{pid}" for pid in range(20)) + "\np0", binary)
        assert observed_pids == list(range(16)) and len(result) == 16


def check_kernel_argv_excludes_runtime() -> None:
    # Scripted libproc: executable-path resolution fails (hardened reporter)
    # while kernel argv stays readable, plus vanishing and hostile shapes.
    # No ambient process inspection; argv never comes from ps output.
    identifier = bytearray(56)
    identifier[16:24] = (300).to_bytes(8, sys.byteorder)
    identifier[32:36] = (7).to_bytes(4, sys.byteorder)
    bsd = bytearray(136)
    struct.pack_into("=I", bsd, 12, 123)
    struct.pack_into("=QQ", bsd, 120, 100, 2)
    def argv_blob(words):
        blob = struct.pack("=i", len(words)) + b"/exe\0"
        # Pad the exec-path region past the argc word, as KERN_PROCARGS2 does.
        blob += b"\0" * ((-(len(blob) - 4)) % struct.calcsize("P"))
        for word in words:
            blob += word.encode() + b"\0"
        return bytes(blob)
    swapped_identifier = bytearray(identifier)
    swapped_identifier[16:24] = (301).to_bytes(8, sys.byteorder)
    def native_for(words=None, argv_errno=0, responses=None, probe=(56, 0), blob_override=None):
        calls = []
        if blob_override is not None:
            blob = blob_override
        else:
            blob = argv_blob(words) if words is not None else b""
        # Queued birth reads; once exhausted the PID is gone or live per probe.
        pending = list(responses) if responses is not None else [bytes(identifier), bytes(bsd), bytes(identifier)] * 2
        def pidinfo(pid, flavor, argument, buffer, size):
            assert (pid, argument.value) == (123, 0) and flavor in (17, 3)
            calls.append(("pidinfo", flavor))
            if not pending:
                count, re_errno = probe
                if re_errno is not None:
                    ctypes.set_errno(re_errno)
                return count
            contents = pending.pop(0)
            ctypes.memmove(buffer, contents, len(contents))
            return size
        def sysctl(mib, namelen, oldp, oldlenp, newp, newlen):
            assert tuple(mib[i] for i in range(3)) == (1, 49, 123)
            calls.append("sysctl")
            if argv_errno != 0:
                ctypes.set_errno(argv_errno)
                return -1
            if oldp is None:
                ctypes.cast(oldlenp, ctypes.POINTER(ctypes.c_size_t)).contents.value = len(blob)
                return 0
            ctypes.memmove(oldp, blob, len(blob))
            return 0
        def recheck(pid, flavor, argument, buffer, size):
            assert (pid, flavor, argument.value, size) == (123, 17, 0, 56)
            calls.append("recheck")
            count, re_errno = probe
            if re_errno is not None:
                ctypes.set_errno(re_errno)
            return count
        return SimpleNamespace(proc_pidinfo=pidinfo, sysctl=sysctl), calls
    scripted = [
        (["codex", "-c", "features", "yes"], 0, True, "hardened-reporter"),
        (["cengine", "other", "--root", "/r"], 0, True, "non-launcher-second-word"),
        (["cengine", "vm-shim"], 0, True, "short-argv"),
        (["/b/cengine", "daemon", "--root", "/r"], 0, False, "daemon-shape-uncertain"),
        (["/b/cengine", "vm-shim", "--spec", "/s"], 0, False, "shim-shape-uncertain"),
    ]
    for words, argv_errno, expected, label in scripted:
        native, calls = native_for(words, argv_errno)
        with patch("harness.sys.platform", "darwin"), patch("harness.ctypes.CDLL", return_value=native):
            assert _kernel_process_argv_excludes_runtime(123) is expected, label
    # Vanishing argv is absence, not uncertainty; anything else stays fatal.
    for argv_errno, probe, expected, label in (
        (errno.ESRCH, (56, 0), True, "vanished"),
        (errno.EPERM, (56, 0), "error", "permission"),
        (errno.EIO, (0, errno.ESRCH), True, "io-then-absent"),
        (errno.EIO, (56, 0), "error", "io-live"),
    ):
        # One birth queued; the recheck after the argv failure uses the probe.
        native, _ = native_for(["codex", "-c", "x", "y"], argv_errno,
                                responses=[bytes(identifier), bytes(bsd), bytes(identifier)], probe=probe)
        with patch("harness.sys.platform", "darwin"), patch("harness.ctypes.CDLL", return_value=native):
            try:
                result = _kernel_process_argv_excludes_runtime(123)
            except RuntimeError as error:
                assert expected == "error", (label, error)
                assert str(error) == f"kernel process argv inspection failed for PID 123, errno {argv_errno}", label
            else:
                assert expected is True and result is True, label
    # PID reuse across the argv read preserves uncertainty even for a benign
    # shape; malformed argv is malformed, not exonerating.
    native, _ = native_for(["codex", "-c", "x", "y"], 0,
                            responses=[bytes(identifier), bytes(bsd), bytes(identifier),
                                       bytes(swapped_identifier), bytes(bsd), bytes(identifier)])
    with patch("harness.sys.platform", "darwin"), patch("harness.ctypes.CDLL", return_value=native):
        try:
            _kernel_process_argv_excludes_runtime(123)
        except RuntimeError as error:
            assert "argv inspection failed" in str(error)
        else:
            raise AssertionError("reused PID must stay uncertain")
    # No NUL anywhere: length/count reads succeed, then parsing fails.
    native, _ = native_for(blob_override=struct.pack("=i", 1) + b"xxxxxxxx")
    with patch("harness.sys.platform", "darwin"), patch("harness.ctypes.CDLL", return_value=native):
        try:
            _kernel_process_argv_excludes_runtime(123)
        except RuntimeError as error:
            assert "malformed" in str(error)
        else:
            raise AssertionError("malformed argv must stay uncertain")
    # Scan wiring: an exonerated PID is skipped, a possible launcher re-raises
    # the original inspection error instead of being silently dropped.
    binary = pathlib.Path("/bin/bash")
    table = f"123 {os.getuid()}\n"
    with patch("harness.subprocess.run", return_value=SimpleNamespace(stdout=table)), \
            patch("harness._kernel_process", side_effect=RuntimeError("no path")), \
            patch("harness._kernel_process_argv_excludes_runtime", return_value=True):
        assert compatibility_runtime_processes(binary) == []
    with patch("harness.subprocess.run", return_value=SimpleNamespace(stdout=table)), \
            patch("harness._kernel_process", side_effect=RuntimeError("no path")), \
            patch("harness._kernel_process_argv_excludes_runtime", return_value=False):
        try:
            compatibility_runtime_processes(binary)
        except RuntimeError as error:
            assert str(error) == "no path"
        else:
            raise AssertionError("possible launcher must preserve uncertainty")


def test_pytest_default_collection() -> None:
    config = configparser.ConfigParser()
    config.read(REPO_ROOT / "Tests/Compatibility/pytest.ini")
    options = shlex.split(config["pytest"]["addopts"])
    # pytest ignores testpaths if invocation_dir != rootpath. With -c pointing
    # below the repo root, testpaths alone does not fix options-only invocations.
    assert not any(option.startswith("--rootdir") for option in options)
    assert shlex.split(config["pytest"]["testpaths"]) == ["Tests/Compatibility"]
    assert "--strict-markers" in options
    assert (REPO_ROOT / "Tests/Compatibility").is_dir()


def test_pytest_selection_forwarding() -> None:
    # Execute only the runner's selection/dispatch tail, replacing Python with
    # an argv recorder: no pytest, builds, helper installation, daemon, or VM.
    runner = (REPO_ROOT / "Scripts/run-compat-tests.sh").read_text()
    tail = runner[runner.index('if [ "$#" -eq 0 ]; then'):]
    invocation = '"$ROOT/.build/compat-venv/bin/python" -m pytest'
    assert tail.count(invocation) == 1
    script = '''
set -eu
ROOT=$1; MODE=$2; shift 2
RESET=:
stage() { :; }
capture_pytest() { printf '%s\\n' "${CENGINE_TEST_SEED:-}" "$@" '---'; }
''' + tail.replace(invocation, "capture_pytest -m pytest")
    node = "Tests/Compatibility/test_api.py::test_selected"
    for mode, seeds in (("suite", [""]), ("soak", ["101", "202", "303"]), ("oracle", [""])):
        for arguments in ([], ["-x", "-q"], ["-x", "-q", node]):
            result = subprocess.run(
                ["/bin/sh", "-c", script, "selection-test", str(REPO_ROOT), mode, *arguments],
                cwd=REPO_ROOT, env={"DOCKER_REFERENCE_HOST": "unix:///unused-reference.sock"},
                check=True, capture_output=True, text=True,
            )
            selected = arguments or [str(REPO_ROOT / "Tests/Compatibility")]
            expected = []
            for seed in seeds:
                expected.extend([seed, "-m", "pytest", f"--rootdir={REPO_ROOT}",
                                 "-c", str(REPO_ROOT / "Tests/Compatibility/pytest.ini")])
                if mode == "oracle":
                    expected.extend(["-m", "oracle"])
                expected.extend([*selected, "---"])
            assert result.stdout.splitlines() == expected, (mode, arguments, result.stdout)


def test_pytest_collection_integration() -> None:
    python = REPO_ROOT / ".build/compat-venv/bin/python"
    if not python.is_file():
        print("SKIP pytest collection integration: compatibility venv is not installed")
        return
    runner = (REPO_ROOT / "Scripts/run-compat-tests.sh").read_text()
    tail = runner[runner.index('if [ "$#" -eq 0 ]; then'):]
    script = 'set -eu\nROOT=$1; MODE=$2; shift 2\nRESET=:\nstage() { :; }\n' + tail.replace(
        '"$ROOT/.build/compat-venv/bin/python"', shlex.quote(str(python)),
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary).resolve()
        suite = root / "Tests/Compatibility"
        suite.mkdir(parents=True)
        shutil.copyfile(REPO_ROOT / "Tests/Compatibility/pytest.ini", suite / "pytest.ini")
        (suite / "test_selection.py").write_text(
            'import pytest\ndef test_regular():\n    raise AssertionError("must only collect")\n'
            '@pytest.mark.oracle\ndef test_oracle():\n    raise AssertionError("must only collect")\n'
        )
        outside = root / "Tests/StorageLifecycleIntegrationTests"
        outside.mkdir()
        (outside / "test_runner.py").write_text('raise AssertionError("collected outside Compatibility")\n')
        (suite / "conftest.py").write_text(
            'import json\nimport pathlib\n'
            'def pytest_sessionfinish(session):\n'
            '    with pathlib.Path("collection.jsonl").open("a") as output:\n'
            '        output.write(json.dumps({"rootpath": str(session.config.rootpath), '
            '"nodes": [item.nodeid for item in session.items]}) + "\\n")\n'
        )
        regular = "Tests/Compatibility/test_selection.py::test_regular"
        oracle = "Tests/Compatibility/test_selection.py::test_oracle"
        for mode in ("suite", "soak", "oracle"):
            for selection in ([], [oracle]):
                evidence = root / "collection.jsonl"
                evidence.unlink(missing_ok=True)
                result = subprocess.run(
                    ["/bin/sh", "-c", script, "collection-test", str(root), mode,
                     "--collect-only", "-x", "-q", *selection],
                    cwd=root, env={"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                                   "DOCKER_REFERENCE_HOST": "unix:///unused-reference.sock"},
                    capture_output=True, text=True, timeout=30,
                )
                assert result.returncode == 0, result.stdout + result.stderr
                records = [json.loads(line) for line in evidence.read_text().splitlines()]
                assert len(records) == (3 if mode == "soak" else 1)
                for record in records:
                    assert record["rootpath"] == str(root), record
                    assert set(record["nodes"]) == ({oracle} if selection or mode == "oracle" else {regular, oracle})


def test_oracle_early_applicability() -> None:
    python = REPO_ROOT / ".build/compat-venv/bin/python"
    if not python.is_file():
        print("SKIP oracle applicability integration: compatibility venv is not installed")
        return
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        # Copy the real tests, but never load the production daemon/helper fixtures.
        shutil.copyfile(REPO_ROOT / "Tests/Compatibility/test_oracle.py", root / "test_oracle.py")
        (root / "pytest.ini").write_text(
            "[pytest]\naddopts = --strict-markers\nmarkers =\n"
            "    oracle: Docker reference contracts\n    compat(id): compatibility ID\n"
        )
        (root / "conftest.py").write_text('''
import json
import os
from pathlib import Path
from unittest.mock import patch
import docker
import pytest

reports = []
fixtures = []

@pytest.fixture
def daemon(request):
    fixtures.append(request.node.name)
    if request.node.get_closest_marker("oracle") and not os.environ.get("DOCKER_REFERENCE_HOST"):
        raise AssertionError("oracle reached bomb daemon fixture before applicability skip")
    return object()

@pytest.fixture
def client(daemon):
    return daemon

@pytest.fixture(autouse=True)
def seeded_images(client):
    pass

@pytest.fixture(autouse=True)
def daemon_survived(daemon):
    pass

@pytest.fixture(autouse=True)
def invalid_reference():
    # A configured but unusable reference must fail, not become an applicability skip.
    with patch.object(docker, "DockerClient", side_effect=RuntimeError("invalid reference sentinel")):
        yield

def pytest_runtest_logreport(report):
    reports.append([report.nodeid, report.when, report.outcome])

def pytest_sessionfinish(session):
    Path("evidence.json").write_text(json.dumps({"reports": reports, "fixtures": fixtures}))
''')
        (root / "test_following.py").write_text("def test_ordinary_following(client):\n    assert client is not None\n")
        for host in (None, "", "invalid://reference"):
            environment = {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
            if host is not None:
                environment["DOCKER_REFERENCE_HOST"] = host
            result = subprocess.run(
                [str(python), "-m", "pytest", "-q", "test_oracle.py", "test_following.py"],
                cwd=root, env=environment, capture_output=True, text=True, timeout=30,
            )
            output = result.stdout + result.stderr
            assert result.returncode == (1 if host else 0), output
            evidence = json.loads((root / "evidence.json").read_text())
            oracle = [report for report in evidence["reports"] if report[0].startswith("test_oracle.py::")]
            ordinary = [report for report in evidence["reports"] if report[0].startswith("test_following.py::")]
            assert ordinary == [["test_following.py::test_ordinary_following", phase, "passed"]
                                for phase in ("setup", "call", "teardown")], evidence
            assert evidence["reports"][-3:] == ordinary, evidence
            assert len({report[0] for report in oracle}) == 4, evidence
            if host:
                assert [report[2] for report in oracle if report[1] == "call"] == ["failed"] * 4, output
                assert not any(report[2] == "skipped" for report in oracle), output
                assert "invalid reference sentinel" in output, output
                assert len(evidence["fixtures"]) == 5, evidence
            else:
                assert [report[2] for report in oracle if report[1] == "setup"] == ["skipped"] * 4, output
                assert not any(report[1] == "call" for report in oracle), evidence
                assert evidence["fixtures"] == ["test_ordinary_following"], evidence


def main() -> None:
    test_oracle_early_applicability()
    test_pytest_collection_integration()
    test_pytest_default_collection()
    test_pytest_selection_forwarding()
    test_original_executable_cleanup()
    test_staged_executable_cleanup()
    test_reset_rechecks_removed_roots()
    test_upgrade_staging_preserves_managed_pair()
    test_upgrade_expected_refusal_preserves_old_runtime()
    test_upgrade_replacement_preserves_signing_mode()
    test_upgrade_finally_cleanup()
    test_daemon_lifecycle_fault_callbacks()
    check_disk_observation()
    check_owned_disk_claims()
    check_kernel_process_exit_recheck()
    check_kernel_argv_excludes_runtime()
    check_kernel_runtime_ownership()
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
    compatibility_root = pathlib.Path("/private/var/folders/test/T/cengine-compat-owned/root")
    process_table = "\n".join([
        f"101 {binary.resolve()} daemon --root {compatibility_root} --socket /tmp/owned.sock",
        f"102 {binary.resolve()} vm-shim --spec {compatibility_root}/infrastructure/shim.json",
        f"106 {binary.resolve()} vm-shim --spec {compatibility_root}/infrastructure/storage-shim-generations/launch/spec.json --spec-sha256 {'a' * 64} --storage-disk-fd 3",
        f"103 {binary.resolve()} vm-shim --spec /tmp/manual-cengine/root/infrastructure/shim.json",
        "104 /Applications/cengine.app/Contents/MacOS/cengine vm-shim --spec /tmp/installed/shim.json",
        f"105 /other/worktree/.build/xcode-derived/Build/Products/Debug/cengine vm-shim --spec {compatibility_root}/shim.json",
    ])
    with patch("harness.compatibility_root_owned_by", side_effect=lambda directory, _: directory == compatibility_root.parent):
        automatic = compatibility_runtime_processes(binary, process_table=process_table)
    assert [value.pid for value in automatic] == [101, 102, 106]
    assert [value.pid for value in compatibility_runtime_processes(
        binary, roots=(compatibility_root,), process_table=process_table,
    )] == [101, 102, 106]
    # Immediate storage-shim death must still run the existing post-exit settle;
    # immutable generation argv paths must not bypass owned runtime cleanup.
    owned = [RuntimeProcess(106, executable=str(binary), arguments=(str(binary), "vm-shim"), identity=(123, 4, 567), pidversion=7)]
    with patch("harness.compatibility_runtime_processes", side_effect=[owned, [], []]), \
            patch("harness._kernel_process", return_value=owned[0]), \
            patch("harness._signal_pid_incarnation") as kill, patch("harness.time.sleep") as sleep:
        assert terminate_compatibility_runtime(binary, roots=(compatibility_root,)) == owned
        kill.assert_called_once_with(106, 7, signal.SIGTERM)
        sleep.assert_called_once_with(VMNET_TEARDOWN_SETTLE_SECONDS)
    explicit_root = compatibility_runtime_processes(
        binary,
        roots=(pathlib.Path("/tmp/manual-cengine/root"),),
        process_table=process_table,
    )
    assert [value.pid for value in explicit_root] == [103]

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
    assert runner.index("$RESET") < runner.index('stage "validate paired lifecycle guest assets')
    assert "trap cleanup EXIT HUP INT TERM" in runner
    assert "rm -rf \"$ROOT/.build/compat-venv\"" in runner
    assert '"$ROOT/Scripts/check-managed-guest-assets.py"' in runner
    assert 'LOCK=$(python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py")' in runner
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
    assert 'cengine-helper\\n' in helper_lifecycle
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
    assert 'refusing interrupted helper installation' in install_body
    assert 'for backup in "$root".rollback.* "$plist_target".rollback.*' in install_body
    assert '/bin/mv "$backup_root/storage-lifecycle-v2" "$root/storage-lifecycle-v2"' in install_body
    assert '/bin/rm -rf "$root"' not in install_body
    assert 'binary=${12}' not in install_body
    assert 'helper status' not in install_body
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
            '[ "$*" = "helper status --require-managed lifecycle-v2" ] || exit 64\n'
            "cat <<EOF\n"
            f'{{"buildFingerprint":"{installed_fingerprint}",'
            '"serviceName":"dev.cengine.network-helper.test-compat",'
            '"ownerUID":$(id -u),"processIdentifier":1,"protocolVersion":5,'
            '"capabilities":{"schemaVersion":1,"securityRevision":1,"profile":"ordinary",'
            '"storageContracts":["lifecycle-v2","lifecycle-v2-adopted-service-change-v1","lifecycle-v2-stable-host-identity-v1"]}}\n'
            "EOF\n"
        )
        fake_binary.chmod(0o755)
        assets = pathlib.Path(temporary) / "assets"
        assets.mkdir()
        (assets / "disk-bootstrap.json").write_text(json.dumps({"storageLifecycleVersion": 2}))
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("CENGINE_", "PREPARE_"))}
        environment["CENGINE_COMPAT_MANAGED_ASSET_DIR"] = str(assets)
        mismatch = subprocess.run(
            [
                "/bin/sh",
                "-c",
                f'. {shlex.quote(str(REPO_ROOT / "Scripts/compat-network-helper.sh"))}; '
                f"ROOT={shlex.quote(str(REPO_ROOT))}; "
                "compat_network_helper_validate_installation() { :; }; "
                "compat_network_helper_validate_managed_signatures() { :; }; "
                f"compat_network_helper_installed_fingerprint() {{ echo {installed_fingerprint}; }}; "
                f'compat_network_helper_require {shlex.quote(str(fake_binary))} {local_fingerprint}; '
                'printf "%s\\n" "$CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT"',
            ],
            cwd=REPO_ROOT, env=environment,
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
                f"ROOT={shlex.quote(str(REPO_ROOT))}; "
                "compat_network_helper_validate_installation() { :; }; "
                "compat_network_helper_validate_managed_signatures() { :; }; "
                f"compat_network_helper_installed_fingerprint() {{ echo {installed_fingerprint}; }}; "
                f'compat_network_helper_require {shlex.quote(str(fake_binary))} {local_fingerprint}; '
                'status=$?; printf "%s\\n" "$CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT"; exit "$status"',
            ],
            cwd=REPO_ROOT, env=environment,
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
    assert '"helper", "restart"' in buildx_test
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
    assert 'reset-compat-runtime.py' not in isolated
    assert 'terminate_compatibility_runtime(binary, roots=(engine_root,))' in isolated
    assert 'compatibility_runtime_processes(binary, roots=(engine_root,))' in isolated
    assert 'remove_compatibility_root(work, binary)' in isolated
    assert 'preretain_compatibility_root(work, binary)' in isolated
    assert isolated.index('> "$WORK/.cengine-compat-owner"') < isolated.index('"$BINARY" daemon')
    assert 'sign-compat-binary.sh" --sign "$CENGINE_DEVELOPER_ID_APPLICATION" "$BINARY"' in isolated
    assert 'LOCK=$(python3 "$ROOT/Tests/Compatibility/helper_fixture_lifetime.py")' in isolated
    assert 'tail -n' not in isolated
    assert 'CENGINE_ISOLATED_IMAGE_CACHE' in isolated
    assert '/bin/cp -cR "$IMAGE_CACHE/content" "$ENGINE_ROOT/content"' in isolated

    doctor = (REPO_ROOT / "Scripts" / "compat-doctor.sh").read_text()
    assert "compatibility Privileged Helper is healthy" in doctor
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
    assert "terminate_compatibility_runtime(value.owner_binary, roots=(value.root,))" in conftest
    assert "        yield value\n        fixture_completed = True\n    finally:" in conftest
    assert "        if not manual:\n            value.start()" in conftest
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
