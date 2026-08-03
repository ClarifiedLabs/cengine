#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import shlex
import subprocess
import sys
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "Tests" / "Compatibility"))

from harness import (  # noqa: E402
    DOCKER_AMBIENT_CONFIG_VARIABLES,
    DOCKER_ENDPOINT_VARIABLES,
    COMPATIBILITY_OWNER_FILE,
    VMNET_TEARDOWN_SETTLE_SECONDS,
    compatibility_environment,
    compatibility_image_cache_key,
    compatibility_root_owned_by,
    compatibility_runtime_processes,
    control_plane_status_is_ready,
    docker_environment,
    managed_docker_environment,
    persisted_container_record,
)


def main() -> None:
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
    assert helper_lifecycle.count("/usr/bin/osascript -") == 1
    assert helper_lifecycle.count("with administrator privileges") == 1
    assert "/Applications/cengine.app" not in helper_lifecycle
    assert "/usr/bin/sudo" not in helper_lifecycle
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
