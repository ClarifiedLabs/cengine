"""End-to-end contracts for the supported Buildx build path."""

from __future__ import annotations

import os
import pathlib
import subprocess
import uuid

import docker
import pytest
from docker.types import Mount


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD_CONTEXT = REPO_ROOT / "Tests/Fixtures/buildx"
BUILDKIT_IMAGE = "moby/buildkit:v0.27.1"
KNOWN_GAP = pytest.mark.xfail(strict=True)


def buildx(*arguments: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", "buildx", *arguments], cwd=REPO_ROOT, env=os.environ.copy(), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
    )
    assert result.returncode == 0, f"docker buildx {' '.join(arguments)} failed:\n{result.stdout}"
    return result


@KNOWN_GAP(reason="BLD-001: BuildKit COPY into an Alpine rootfs fails with a read-only filesystem")
@pytest.mark.compat("BLD-001")
def test_buildx_load_run_cache_and_volume_copy(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    builder = f"compat-builder-{suffix}"
    tag = f"compat-buildx:{suffix}"
    try:
        buildx(
            "create", "--name", builder, "--driver", "docker-container",
            "--driver-opt", f"image={BUILDKIT_IMAGE}", f"unix://{daemon.socket}",
        )
        first = buildx("build", "--builder", builder, "--load", "--tag", tag, str(BUILD_CONTEXT))
        assert "ERROR" not in first.stdout
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

        second = buildx("build", "--builder", builder, "--load", "--tag", tag, str(BUILD_CONTEXT))
        assert "ERROR" not in second.stdout
    finally:
        subprocess.run(
            ["docker", "buildx", "rm", "--force", builder], cwd=REPO_ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60,
        )
