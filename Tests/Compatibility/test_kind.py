"""End-to-end compatibility contract for kind cluster creation."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import uuid

import docker
import pytest


def kind(daemon, *arguments: str, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("kind")
    if executable is None:
        pytest.fail("kind is required for the compatibility suite; install kind v0.32.0")
    socket = daemon["socket"]
    assert isinstance(socket, pathlib.Path)
    environment = os.environ.copy()
    environment["DOCKER_HOST"] = f"unix://{socket}"
    return subprocess.run(
        [executable, *arguments], env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
    )


@pytest.mark.compat("KND-001")
def test_kind_create_cluster(daemon, client: docker.DockerClient):
    name = f"cengine-{uuid.uuid4().hex[:8]}"
    kubeconfig = daemon["work"] / f"{name}.kubeconfig"
    assert isinstance(kubeconfig, pathlib.Path)
    created = False
    try:
        result = kind(
            daemon, "create", "cluster", "--name", name,
            "--kubeconfig", str(kubeconfig), "--wait", "5m",
        )
        assert result.returncode == 0, f"kind create cluster failed:\n{result.stdout}"
        created = True
        clusters = kind(daemon, "get", "clusters", timeout=60)
        assert clusters.returncode == 0, clusters.stdout
        assert name in clusters.stdout.splitlines()
    finally:
        deleted = kind(
            daemon, "delete", "cluster", "--name", name,
            "--kubeconfig", str(kubeconfig), timeout=180,
        )
        for container in client.containers.list(all=True):
            if (
                container.name == f"{name}-control-plane"
                or container.name.startswith(f"{name}-worker")
            ):
                container.remove(force=True)
        for network in client.networks.list(names=["kind"]):
            try:
                network.remove()
            except docker.errors.NotFound:
                pass
        kubeconfig.unlink(missing_ok=True)
        if created:
            assert deleted.returncode == 0, f"kind delete cluster failed:\n{deleted.stdout}"
