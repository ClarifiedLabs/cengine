"""End-to-end contracts for the supported Buildx build path."""

from __future__ import annotations

import json
import os
import pathlib
import signal
import subprocess
import time
import uuid

import docker
import pytest
from docker.types import Mount

from harness import compatibility_environment, docker_environment


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD_CONTEXT = REPO_ROOT / "Tests/Fixtures/buildx"
BUILDKIT_CONFIG = BUILD_CONTEXT / "buildkitd.toml"
BUILDKIT_IMAGE = "moby/buildkit:v0.27.1"


def buildx(*arguments: str, docker_host: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", "buildx", *arguments], cwd=REPO_ROOT,
        env=docker_environment(docker_host), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
    )
    assert result.returncode == 0, f"docker buildx {' '.join(arguments)} failed:\n{result.stdout}"
    return result


def restart_compatibility_network_helper() -> None:
    binary = os.environ.get("CENGINE_BINARY")
    assert binary, "CENGINE_BINARY is required to restart the compatibility helper"
    result = subprocess.run(
        [binary, "network-helper", "restart"], env=compatibility_environment(), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
    )
    assert result.returncode == 0, f"could not restart compatibility networking helper:\n{result.stdout}"
    status = json.loads(result.stdout)
    assert status["serviceName"] == "dev.cengine.network-helper.test-compat"
    assert status["buildFingerprint"] == os.environ["CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT"]


@pytest.mark.compat("BLD-001")
def test_buildx_load_run_cache_and_volume_copy(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    builder = f"compat-builder-{suffix}"
    tag = f"compat-buildx:{suffix}"
    docker_host = f"unix://{daemon.socket}"
    try:
        buildx(
            "create", "--name", builder, "--driver", "docker-container",
            "--driver-opt", f"image={BUILDKIT_IMAGE}",
            "--driver-opt", "memory=4294967296",
            "--driver-opt", "cpu-period=100000",
            "--driver-opt", "cpu-quota=400000",
            "--buildkitd-config", str(BUILDKIT_CONFIG),
            "--buildkitd-flags", "--oci-worker-snapshotter=overlayfs",
            docker_host, docker_host=docker_host,
        )
        first = buildx(
            "build", "--builder", builder, "--load", "--tag", tag, str(BUILD_CONTEXT),
            docker_host=docker_host,
        )
        assert "ERROR" not in first.stdout
        builder_container = client.containers.get(f"buildx_buildkit_{builder}0")
        assert builder_container.attrs["HostConfig"]["Memory"] == 4_294_967_296
        assert builder_container.attrs["HostConfig"]["NanoCpus"] == 4_000_000_000
        try:
            image = client.images.get(tag)
        except docker.errors.ImageNotFound:
            visible = sorted(tag for value in client.images.list(all=True) for tag in value.tags)
            pytest.fail(
                f"loaded image {tag} is not visible; images={visible}\n"
                f"buildx output:\n{first.stdout}"
            )
        assert tag in image.tags
        assert client.containers.run(tag, remove=True).strip() == b"cengine-buildx-ok"

        volume = client.volumes.create(
            f"compat-buildx-{suffix}", labels={"dev.cengine.compat": "true"}
        )
        container = client.containers.create(
            tag, command=["test", "-f", "/workspace/seed"],
            mounts=[Mount(target="/workspace", source=volume.name, type="volume")],
        )
        container.start()
        assert container.wait(timeout=60)["StatusCode"] == 0

        second = buildx(
            "build", "--builder", builder, "--load", "--tag", tag, str(BUILD_CONTEXT),
            docker_host=docker_host,
        )
        assert "ERROR" not in second.stdout
    finally:
        subprocess.run(
            ["docker", "buildx", "rm", "--force", builder], cwd=REPO_ROOT,
            env=docker_environment(docker_host), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=60,
        )


@pytest.mark.compat("BLD-002")
def test_buildx_pull_succeeds_after_daemon_restart(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    builder = f"compat-recovery-builder-{suffix}"
    tag = f"compat-recovery-buildx:{suffix}"
    docker_host = f"unix://{daemon.socket}"
    try:
        buildx(
            "create", "--name", builder, "--driver", "docker-container",
            "--driver-opt", f"image={BUILDKIT_IMAGE}",
            "--driver-opt", "memory=4294967296",
            "--buildkitd-config", str(BUILDKIT_CONFIG),
            "--buildkitd-flags", "--oci-worker-snapshotter=overlayfs",
            docker_host, docker_host=docker_host,
        )
        buildx("inspect", "--builder", builder, "--bootstrap", docker_host=docker_host)
        daemon.restart(kill=True)

        deadline = time.monotonic() + 30
        while True:
            buildkit = client.containers.get(f"buildx_buildkit_{builder}0")
            buildkit.reload()
            if buildkit.status == "running":
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"buildkit did not recover after daemon restart: {buildkit.attrs['State']}")
            time.sleep(0.2)

        result = buildx(
            "build", "--builder", builder, "--pull", "--no-cache", "--load",
            "--tag", tag, str(BUILD_CONTEXT), docker_host=docker_host,
        )
        assert "ERROR" not in result.stdout
        assert client.containers.run(tag, remove=True).strip() == b"cengine-buildx-ok"
    finally:
        subprocess.run(
            ["docker", "buildx", "rm", "--force", builder], cwd=REPO_ROOT,
            env=docker_environment(docker_host), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=60,
        )


@pytest.mark.compat("BLD-005")
def test_buildx_recovers_uplink_after_network_helper_restart(
    daemon, client: docker.DockerClient
):
    suffix = uuid.uuid4().hex[:8]
    builder = f"compat-helper-recovery-builder-{suffix}"
    tag = f"compat-helper-recovery-buildx:{suffix}"
    docker_host = f"unix://{daemon.socket}"
    try:
        buildx(
            "create", "--name", builder, "--driver", "docker-container",
            "--driver-opt", f"image={BUILDKIT_IMAGE}",
            "--driver-opt", "memory=4294967296",
            "--buildkitd-config", str(BUILDKIT_CONFIG),
            "--buildkitd-flags", "--oci-worker-snapshotter=overlayfs",
            docker_host, docker_host=docker_host,
        )
        buildx("inspect", "--builder", builder, "--bootstrap", docker_host=docker_host)
        buildkit = client.containers.get(f"buildx_buildkit_{builder}0")
        initial = buildkit.exec_run(["nslookup", "mirror.gcr.io"])
        assert initial.exit_code == 0, initial.output.decode(errors="replace")

        restart_compatibility_network_helper()

        deadline = time.monotonic() + 30
        output = b"uplink did not recover"
        while time.monotonic() < deadline:
            probe = buildkit.exec_run(["nslookup", "mirror.gcr.io"])
            output = probe.output
            if probe.exit_code == 0:
                break
            time.sleep(0.2)
        else:
            shim_log = daemon.root / "infrastructure" / "shim.log"
            shim_output = shim_log.read_text(errors="replace") if shim_log.is_file() else "unavailable"
            pytest.fail(
                "BuildKit DNS did not recover after helper restart:\n"
                f"{output.decode(errors='replace')}\n"
                f"Infrastructure shim log:\n{shim_output}"
            )

        result = buildx(
            "build", "--builder", builder, "--pull", "--no-cache", "--load",
            "--tag", tag, str(BUILD_CONTEXT), docker_host=docker_host,
        )
        assert "ERROR" not in result.stdout
        assert client.containers.run(tag, remove=True).strip() == b"cengine-buildx-ok"
    finally:
        subprocess.run(
            ["docker", "buildx", "rm", "--force", builder], cwd=REPO_ROOT,
            env=docker_environment(docker_host), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=60,
        )


@pytest.mark.compat("BLD-003")
def test_buildx_overlay_worker_has_large_state_volume(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    builder = f"compat-storage-builder-{suffix}"
    tag = f"compat-storage-buildx:{suffix}"
    docker_host = f"unix://{daemon.socket}"
    try:
        buildx(
            "create", "--name", builder, "--driver", "docker-container",
            "--driver-opt", f"image={BUILDKIT_IMAGE}",
            "--driver-opt", "memory=4294967296",
            "--buildkitd-config", str(BUILDKIT_CONFIG),
            "--buildkitd-flags", "--oci-worker-snapshotter=overlayfs",
            docker_host, docker_host=docker_host,
        )
        buildx(
            "build", "--builder", builder, "--load", "--tag", tag,
            "--file", str(BUILD_CONTEXT / "Dockerfile.parallel"), str(BUILD_CONTEXT),
            docker_host=docker_host,
        )

        inspection = buildx("inspect", "--builder", builder, docker_host=docker_host)
        assert "--oci-worker-snapshotter=overlayfs" in inspection.stdout
        buildkit = client.containers.get(f"buildx_buildkit_{builder}0")
        disk = buildkit.exec_run(["df", "-Pk", "/var/lib/buildkit"])
        assert disk.exit_code == 0, disk.output.decode(errors="replace")
        size_kib = int(disk.output.decode().splitlines()[-1].split()[1])
        assert size_kib >= 500_000_000, f"BuildKit state volume is only {size_kib} KiB"
    finally:
        subprocess.run(
            ["docker", "buildx", "rm", "--force", builder], cwd=REPO_ROOT,
            env=docker_environment(docker_host), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=60,
        )


@pytest.mark.compat("BLD-004")
def test_buildx_relaunches_missing_stopped_container_shim(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    builder = f"compat-shim-recovery-builder-{suffix}"
    tag = f"compat-shim-recovery-buildx:{suffix}"
    docker_host = f"unix://{daemon.socket}"
    try:
        buildx(
            "create", "--name", builder, "--driver", "docker-container",
            "--driver-opt", f"image={BUILDKIT_IMAGE}",
            "--buildkitd-config", str(BUILDKIT_CONFIG),
            "--buildkitd-flags", "--oci-worker-snapshotter=overlayfs",
            docker_host, docker_host=docker_host,
        )
        buildx("inspect", "--builder", builder, "--bootstrap", docker_host=docker_host)
        buildkit = client.containers.get(f"buildx_buildkit_{builder}0")
        marker = buildkit.exec_run(["sh", "-c", "printf retained >/shim-recovery-marker; sync"])
        assert marker.exit_code == 0, marker.output.decode(errors="replace")

        generations = daemon.root / "containers" / buildkit.id / "shim-generations"
        def running_generation():
            running = []
            for specification_path in generations.glob("*/spec.json"):
                specification = json.loads(specification_path.read_text())
                status_path = pathlib.Path(specification["socketPath"] + ".status")
                if not status_path.exists():
                    continue
                status = json.loads(status_path.read_text())
                if status["state"] == "running":
                    running.append((specification_path, specification, status))
            assert len(running) == 1, f"running VM shim generations: {running}"
            return running[0]

        _, specification, status = running_generation()
        shim_pid = status["processIdentifier"]

        daemon.stop(kill=True)
        os.kill(shim_pid, signal.SIGKILL)
        deadline = time.monotonic() + 5
        while True:
            try:
                os.kill(shim_pid, 0)
            except ProcessLookupError:
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"container VM shim {shim_pid} did not exit")
            time.sleep(0.05)

        state_path = daemon.root / "engine.json"
        state = json.loads(state_path.read_text())
        matches = [value for value in state["value"]["containers"] if value["id"] == buildkit.id]
        assert len(matches) == 1
        matches[0]["phase"] = "exited"
        matches[0]["exitCode"] = 137
        state_path.write_text(json.dumps(state, sort_keys=True))
        daemon.start()

        buildkit = client.containers.get(buildkit.id)
        assert buildkit.status == "exited"

        result = buildx(
            "build", "--builder", builder, "--load", "--tag", tag, str(BUILD_CONTEXT),
            docker_host=docker_host,
        )
        assert "ERROR" not in result.stdout
        _, relaunched, _ = running_generation()
        assert relaunched["generation"] == specification["generation"] + 1
        buildkit = client.containers.get(f"buildx_buildkit_{builder}0")
        marker = buildkit.exec_run(["cat", "/shim-recovery-marker"])
        assert (marker.exit_code, marker.output) == (0, b"retained")
    finally:
        subprocess.run(
            ["docker", "buildx", "rm", "--force", builder], cwd=REPO_ROOT,
            env=docker_environment(docker_host), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=60,
        )
