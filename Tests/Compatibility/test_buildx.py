"""End-to-end contracts for the supported Buildx build path."""

from __future__ import annotations

import pathlib
import subprocess
import time
import uuid

import docker
import pytest
from docker.types import Mount

from harness import docker_environment


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD_CONTEXT = REPO_ROOT / "Tests/Fixtures/buildx"
BUILDKIT_IMAGE = "moby/buildkit:v0.27.1"


def buildx(*arguments: str, docker_host: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", "buildx", *arguments], cwd=REPO_ROOT,
        env=docker_environment(docker_host), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
    )
    assert result.returncode == 0, f"docker buildx {' '.join(arguments)} failed:\n{result.stdout}"
    return result


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
            "--buildkitd-flags", "--oci-worker-snapshotter=native",
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
        image = client.images.get(tag)
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
            "--buildkitd-flags", "--oci-worker-snapshotter=native",
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
