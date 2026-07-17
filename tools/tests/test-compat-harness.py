#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "Tests" / "Compatibility"))

from harness import (  # noqa: E402
    DOCKER_ENDPOINT_VARIABLES,
    COMPATIBILITY_OWNER_FILE,
    VMNET_TEARDOWN_SETTLE_SECONDS,
    compatibility_image_cache_key,
    compatibility_root_owned_by,
    compatibility_runtime_processes,
    control_plane_status_is_ready,
    docker_environment,
)


def main() -> None:
    ambient = {
        "PATH": "/test/bin",
        "DOCKER_HOST": "tcp://ambient.example:2376",
        **{key: f"ambient-{key.lower()}" for key in DOCKER_ENDPOINT_VARIABLES},
    }
    environment = docker_environment(pathlib.Path("/tmp/cengine/docker.sock"), base=ambient)

    assert environment["PATH"] == ambient["PATH"]
    assert environment["DOCKER_HOST"] == "unix:///tmp/cengine/docker.sock"
    for key in DOCKER_ENDPOINT_VARIABLES:
        assert key not in environment

    explicit = docker_environment("tcp://127.0.0.1:2375", base={})
    assert explicit == {"DOCKER_HOST": "tcp://127.0.0.1:2375"}
    assert VMNET_TEARDOWN_SETTLE_SECONDS >= 2.0
    assert not control_plane_status_is_ready(0, b"")
    assert not control_plane_status_is_ready(1, b"True")
    assert not control_plane_status_is_ready(0, b"True False")
    assert control_plane_status_is_ready(0, b"True")
    assert control_plane_status_is_ready(0, "True True")

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
        f"103 {binary.resolve()} vm-shim --spec /tmp/manual-cengine/root/infrastructure/shim.json",
        "104 /Applications/cengine.app/Contents/MacOS/cengine vm-shim --spec /tmp/installed/shim.json",
        f"105 /other/worktree/.build/xcode-derived/Build/Products/Debug/cengine vm-shim --spec {compatibility_root}/shim.json",
    ])
    automatic = compatibility_runtime_processes(binary, process_table=process_table)
    assert [value.pid for value in automatic] == [101, 102]
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

    makefile = (REPO_ROOT / "Makefile").read_text()
    assert 'XCODE_COMPAT_SCHEME ?= test-compat' in makefile
    assert 'XCODE_COMPAT_CONFIGURATION ?= test-compat' in makefile
    assert 'XCODEBUILD="$(XCODEBUILD)"' in makefile
    assert 'XCODE_DERIVED_DATA="$(XCODE_DERIVED_DATA)"' in makefile
    assert 'CENGINE_KERNEL="$(CENGINE_GUEST_OUTPUT)/vmlinux"' in makefile
    assert 'CENGINE_CONTAINER_INITRAMFS="$(CENGINE_GUEST_OUTPUT)/container-initramfs.cpio.gz"' in makefile
    assert 'CENGINE_STORAGE_INITRAMFS="$(CENGINE_GUEST_OUTPUT)/storage-initramfs.cpio.gz"' in makefile
    assert makefile.count("$(CENGINE_COMPAT_ENV)") == 3
    assert "test-compat-reset-system:" in makefile
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
    assert "unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY" in runner
    assert 'stage "preflight reset"' in runner
    assert 'stage "rebuild runtime and guest assets"' in runner
    assert 'XCODE_COMPAT_SCHEME=${XCODE_COMPAT_SCHEME:-test-compat}' in runner
    assert '-scheme "$XCODE_COMPAT_SCHEME"' in runner
    assert '-configuration "$XCODE_COMPAT_CONFIGURATION"' in runner
    assert 'stage "recreate test environment"' in runner
    assert 'compat_network_helper_bootstrap_local "$HELPER"' in runner
    assert 'compat_network_helper_cleanup_local || status=$?' in runner
    assert 'CENGINE_NETWORK_HELPER_SERVICE_NAME=$compat_network_helper_default_service_name' in runner

    helper_lifecycle = (REPO_ROOT / "Scripts" / "compat-network-helper.sh").read_text()
    assert 'compat_network_helper_installed_path="/Applications/cengine.app/Contents/MacOS/cengine-network-helper"' in helper_lifecycle
    assert 'CENGINE_COMPAT_NETWORK_HELPER:-auto' in helper_lifecycle
    assert 'compat_network_helper_test_compat_service_name="dev.cengine.network-helper.test-compat"' in helper_lifecycle
    assert 'cengine-network-helper\\n' in helper_lifecycle
    assert 'CENGINE_NETWORK_HELPER_SERVICE_NAME' in helper_lifecycle
    assert 'launchctl bootstrap system' in helper_lifecycle
    assert 'launchctl bootout "system/$label"' in helper_lifecycle
    assert 'launchctl kill SIGTERM "system/$label"' in helper_lifecycle
    assert 'launchctl kickstart "system/$label"' in helper_lifecycle
    assert 'launchctl kickstart -k "system/$label"' not in helper_lifecycle
    assert helper_lifecycle.count("/usr/bin/osascript -") == 1
    assert helper_lifecycle.count("with administrator privileges") == 1
    assert '"$request_root"/restart-*' in helper_lifecycle
    assert ': > "$_cnh_control_root/requests/stop"' in helper_lifecycle
    assert "/usr/bin/sudo" not in helper_lifecycle

    buildx_test = (REPO_ROOT / "Tests" / "Compatibility" / "test_buildx.py").read_text()
    assert "CENGINE_COMPAT_NETWORK_HELPER_CONTROL_ROOT" in buildx_test
    assert 'f"restart-{request_id}"' in buildx_test
    assert "/usr/bin/osascript" not in buildx_test
    assert "with administrator privileges" not in buildx_test
    assert "/usr/bin/sudo" not in buildx_test

    reset = (REPO_ROOT / "Scripts" / "reset-compat-runtime.py").read_text()
    assert "binary.is_file()" not in reset
    assert "compatibility_runtime_processes" in reset
    assert "compatibility runtime reset did not reach a clean state" in reset

    isolated = (REPO_ROOT / "Scripts" / "run-isolated-cengine.sh").read_text()
    assert 'mktemp -d "${TMPDIR:-/tmp}/cengine-compat-tool.XXXXXX"' in isolated
    assert "unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY" in isolated
    assert 'trap cleanup EXIT' in isolated
    assert 'compat_network_helper_bootstrap_local "$HELPER" "$COMPAT_HELPER_SERVICE" 1' in isolated
    assert 'compat_network_helper_cleanup_local || status=$?' in isolated
    assert '--binary "$BINARY" --root "$ENGINE_ROOT"' in isolated
    assert isolated.index('--binary "$BINARY" --root "$ENGINE_ROOT"') < isolated.index('> "$WORK/.cengine-compat-owner"')
    assert 'CENGINE_ISOLATED_IMAGE_CACHE' in isolated
    assert '/bin/cp -cR "$IMAGE_CACHE/content" "$ENGINE_ROOT/content"' in isolated

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
