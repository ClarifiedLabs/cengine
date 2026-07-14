#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "Tests" / "Compatibility"))

from harness import (  # noqa: E402
    DOCKER_ENDPOINT_VARIABLES,
    COMPATIBILITY_OWNER_FILE,
    VMNET_TEARDOWN_SETTLE_SECONDS,
    compatibility_root_owned_by,
    compatibility_runtime_processes,
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
    assert 'CENGINE_KERNEL="$(CENGINE_GUEST_OUTPUT)/vmlinux"' in makefile
    assert 'CENGINE_CONTAINER_INITRAMFS="$(CENGINE_GUEST_OUTPUT)/container-initramfs.cpio.gz"' in makefile
    assert 'CENGINE_STORAGE_INITRAMFS="$(CENGINE_GUEST_OUTPUT)/storage-initramfs.cpio.gz"' in makefile
    assert makefile.count("$(CENGINE_COMPAT_ENV)") == 3
    assert "test-compat-reset-system:" in makefile
    assert "Scripts/run-compat-tests.sh suite $(COMPAT_ARGS)" in makefile
    assert "kernel: build" in makefile
    assert "test-guest: build guest-initramfs" in makefile

    runner = (REPO_ROOT / "Scripts" / "run-compat-tests.sh").read_text()
    assert runner.index("$RESET") < runner.index("make -C")
    assert "trap cleanup EXIT HUP INT TERM" in runner
    assert "rm -rf \"$ROOT/.build/compat-venv\"" in runner
    assert '"$ROOT/Scripts/check-guest-kernel.sh"' in runner
    assert 'LOCK=${CENGINE_COMPAT_LOCK:-"${TMPDIR:-/tmp}/cengine-compat-run.lock"}' in runner
    assert "unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY" in runner
    assert 'stage "preflight reset"' in runner
    assert 'stage "rebuild runtime and guest assets"' in runner
    assert 'stage "recreate test environment"' in runner

    reset = (REPO_ROOT / "Scripts" / "reset-compat-runtime.py").read_text()
    assert "binary.is_file()" not in reset
    assert "compatibility_runtime_processes" in reset
    assert "compatibility runtime reset did not reach a clean state" in reset

    isolated = (REPO_ROOT / "Scripts" / "run-isolated-cengine.sh").read_text()
    assert 'mktemp -d "${TMPDIR:-/tmp}/cengine-compat-tool.XXXXXX"' in isolated
    assert "unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY" in isolated
    assert 'trap cleanup EXIT' in isolated
    assert '--binary "$BINARY" --root "$ENGINE_ROOT"' in isolated
    assert isolated.index('--binary "$BINARY" --root "$ENGINE_ROOT"') < isolated.index('> "$WORK/.cengine-compat-owner"')
    assert 'CENGINE_ISOLATED_IMAGE_CACHE' in isolated
    assert '/bin/cp -cR "$IMAGE_CACHE/content" "$ENGINE_ROOT/content"' in isolated

    kernel_builder = (REPO_ROOT / "Scripts" / "build-kernel.sh").read_text()
    guest_tests = (REPO_ROOT / "Scripts" / "test-guest.sh").read_text()
    assert "docker buildx" not in kernel_builder
    assert "docker buildx" not in guest_tests
    assert "CENGINE_KERNEL_BUILD_CPUS" in kernel_builder
    assert "CENGINE_KERNEL_BUILD_MEMORY" in kernel_builder
    assert '"$ROOT/Scripts/run-isolated-cengine.sh"' in kernel_builder
    assert '"$ROOT/Scripts/run-isolated-cengine.sh"' in guest_tests
    assert 'go test ./...' in guest_tests

    kernel_check = (REPO_ROOT / "Scripts" / "check-guest-kernel.sh").read_text()
    assert '"$ROOT/Configuration/kernel-commit"' in kernel_check
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
