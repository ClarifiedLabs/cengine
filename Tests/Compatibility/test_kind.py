"""End-to-end compatibility contract for kind cluster creation."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import time
import uuid

import docker
import pytest

from harness import control_plane_status_is_ready, docker_environment


KIND_NODE_IMAGE = (
    "mirror.gcr.io/kindest/node@"
    "sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)


def kind(
    daemon, *arguments: str, network: str, timeout: int = 600,
    resources: tuple[int, int] | None = None,
) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("kind")
    if executable is None:
        pytest.fail("kind is required for the compatibility suite; install kind v0.32.0")
    socket = daemon["socket"]
    assert isinstance(socket, pathlib.Path)
    environment = docker_environment(socket)
    environment["KIND_EXPERIMENTAL_PROVIDER"] = "docker"
    environment["KIND_EXPERIMENTAL_DOCKER_NETWORK"] = network
    command = [executable, *arguments]
    if resources is not None:
        cpus, memory_gib = resources
        command = [
            str(daemon.binary), "run", "--socket", str(socket),
            "--cpus", str(cpus), "--memory", f"{memory_gib}g", "--", *command,
        ]
    return subprocess.run(
        command, env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
    )


def wait_for_control_plane_ready(
    client: docker.DockerClient, name: str, timeout: int = 300,
) -> str | None:
    node = client.containers.get(f"{name}-control-plane")
    deadline = time.monotonic() + timeout
    last_result = "readiness command has not run"
    command = [
        "kubectl",
        "--kubeconfig=/etc/kubernetes/admin.conf",
        "get",
        "nodes",
        "--selector=node-role.kubernetes.io/control-plane",
        "-o=jsonpath={.items..status.conditions[-1:].status}",
    ]
    while time.monotonic() < deadline:
        try:
            exit_code, output = node.exec_run(command)
            if control_plane_status_is_ready(exit_code, output):
                return None
            rendered_output = (
                output.decode(errors="replace") if isinstance(output, bytes) else str(output)
            )
            last_result = f"exit {exit_code}: {rendered_output}"
        except docker.errors.APIError as error:
            last_result = f"Docker API error: {error}"
        time.sleep(0.2)
    return f"control-plane did not become Ready within {timeout}s; last result: {last_result}"


@pytest.mark.compat("KND-001")
def test_kind_create_cluster(daemon, client: docker.DockerClient):
    name = f"cengine-{uuid.uuid4().hex[:8]}"
    network = f"compat-kind-{uuid.uuid4().hex[:8]}"
    kubeconfig = daemon["work"] / f"{name}.kubeconfig"
    assert isinstance(kubeconfig, pathlib.Path)
    assert all(value.name != network for value in client.networks.list(names=[network]))
    created = False
    try:
        result = kind(
            daemon, "create", "cluster", "--name", name,
            "--image", KIND_NODE_IMAGE, "--retain",
            "--kubeconfig", str(kubeconfig),
            network=network, resources=(2, 2),
        )
        failure = None
        if result.returncode != 0:
            failure = f"kind create cluster failed:\n{result.stdout}"
        else:
            failure = wait_for_control_plane_ready(client, name)
        if failure is not None:
            diagnostics = []
            for container in client.containers.list(all=True):
                if container.name.startswith(f"{name}-"):
                    container.reload()
                    state = container.attrs["State"]
                    inspection_output = "container stopped before live diagnostics"
                    if state.get("Running"):
                        try:
                            inspection = container.exec_run([
                                "sh", "-c",
                                "systemctl is-system-running 2>&1 || true; "
                                "systemctl --failed --no-pager 2>&1 || true; "
                                "printf '\nPROCESSES\n'; ps auxww; "
                                "printf '\nMOUNTS\n'; mount; "
                                "printf '\nCONTAINERD STATUS\n'; "
                                "systemctl status containerd --no-pager 2>&1 || true; "
                                "printf '\nCONTAINERD JOURNAL\n'; "
                                "journalctl -b -u containerd --no-pager 2>&1 || true; "
                                "printf '\nCONTAINERD PLUGINS\n'; "
                                "ctr plugins ls 2>&1 || true; "
                                "printf '\nCONTAINERD CONFIG\n'; "
                                "cat /etc/containerd/config.toml 2>&1 || true; "
                                "printf '\nJOURNAL\n'; "
                                "journalctl -b --no-pager -n 200 2>&1 || true",
                            ])
                            inspection_output = inspection.output.decode(errors="replace")
                        except docker.errors.APIError as error:
                            inspection_output = f"live diagnostics failed: {error}"
                    diagnostics.append(
                        f"{container.name} state: {state}\n"
                        f"{container.logs().decode(errors='replace')}\n"
                        f"{inspection_output}"
                    )
            pytest.fail(
                f"{failure}\n"
                f"node diagnostics:\n{'\n'.join(diagnostics)}"
            )
        created = True
        node = client.containers.get(f"{name}-control-plane")
        assert node.attrs["HostConfig"]["NanoCpus"] == 2_000_000_000
        assert node.attrs["HostConfig"]["Memory"] == 2 * 1024 * 1024 * 1024
        kind_network = client.networks.get(network)
        assert kind_network.attrs["Options"][
            "com.docker.network.bridge.enable_ip_masquerade"
        ] == "true"
        clusters = kind(daemon, "get", "clusters", network=network, timeout=60)
        assert clusters.returncode == 0, clusters.stdout
        assert name in clusters.stdout.splitlines()
    finally:
        deleted = kind(
            daemon, "delete", "cluster", "--name", name,
            "--kubeconfig", str(kubeconfig), network=network, timeout=180,
        )
        for container in client.containers.list(all=True):
            if (
                container.name == f"{name}-control-plane"
                or container.name.startswith(f"{name}-worker")
            ):
                container.remove(force=True)
        for value in client.networks.list(names=[network]):
            try:
                if value.name == network:
                    value.remove()
            except docker.errors.NotFound:
                pass
        kubeconfig.unlink(missing_ok=True)
        if created:
            assert deleted.returncode == 0, f"kind delete cluster failed:\n{deleted.stdout}"
