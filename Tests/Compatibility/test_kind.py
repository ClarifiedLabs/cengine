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
DNS_A_QUERY = r"""
use strict;
use warnings;
my ($server, $name) = @ARGV;
my $id = 0x4345;
my $encoded = join('', map { pack('C', length($_)) . $_ } split(/\./, $name)) . "\0";
my $query = pack('n6', $id, 0x0100, 1, 0, 0, 0) . $encoded . pack('n2', 1, 1);
socket(my $socket, AF_INET, SOCK_DGRAM, getprotobyname('udp')) or die "socket: $!";
send($socket, $query, 0, sockaddr_in(53, inet_aton($server))) or die "send: $!";
my $reply = '';
eval {
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm 5;
    defined recv($socket, $reply, 512, 0) or die "recv: $!";
    alarm 0;
};
die $@ if $@;
my ($reply_id, $flags, $questions, $answers) = unpack('n4', $reply);
die sprintf("invalid DNS response: flags=%04x answers=%d\n", $flags, $answers)
    unless $reply_id == $id && ($flags & 0x8000) && ($flags & 0x000f) == 0
        && $questions == 1 && $answers > 0;
print join('.', unpack('C4', substr($reply, -4))), "\n";
"""


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


def wait_for_cluster_network_ready(
    client: docker.DockerClient, name: str, timeout: int = 180,
) -> str | None:
    node = client.containers.get(f"{name}-control-plane")
    deadline = time.monotonic() + timeout
    last_result = "network readiness command has not run"
    command = [
        "sh", "-c",
        "ready=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf -n kube-system "
        "get pods -l k8s-app=kube-dns "
        "-o=jsonpath='{.items[*].status.conditions[?(@.type==\"Ready\")].status}'); "
        "case \"$ready\" in '') exit 1;; *False*) exit 1;; esac; "
        "service_ip=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf "
        "get service kubernetes -o=jsonpath='{.spec.clusterIP}'); "
        "status=$(curl --connect-timeout 2 --max-time 3 -ksS -o /dev/null "
        "-w '%{http_code}' https://$service_ip:443/livez) || exit 1; "
        "test \"$status\" != 000",
    ]
    while time.monotonic() < deadline:
        try:
            exit_code, output = node.exec_run(command)
            if exit_code == 0:
                return None
            rendered_output = (
                output.decode(errors="replace") if isinstance(output, bytes) else str(output)
            )
            last_result = f"exit {exit_code}: {rendered_output}"
        except docker.errors.APIError as error:
            last_result = f"Docker API error: {error}"
        time.sleep(0.5)
    return (
        f"pod and service networking did not become ready within {timeout}s; "
        f"last result: {last_result}"
    )


def verify_cluster_pod_exec(client: docker.DockerClient, name: str) -> str | None:
    node = client.containers.get(f"{name}-control-plane")
    selected = node.exec_run([
        "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "-n", "kube-system",
        "get", "pods", "-l", "k8s-app=kube-dns",
        "-o=jsonpath={.items[0].metadata.name}",
    ])
    if selected.exit_code != 0:
        return f"could not select a CoreDNS pod for exec: {selected.output!r}"
    pod = selected.output.decode(errors="replace").strip()
    if not pod:
        return "could not select a CoreDNS pod for exec: no pods returned"
    executed = node.exec_run([
        "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "-n", "kube-system",
        "exec", pod, "--", "/coredns", "-version",
    ])
    if executed.exit_code != 0:
        return f"exec into CoreDNS pod {pod} failed: {executed.output!r}"
    return None


def verify_docker_host_resolution(
    client: docker.DockerClient, name: str, network: str, timeout: int = 60,
) -> str | None:
    node = client.containers.get(f"{name}-control-plane")
    service = node.exec_run([
        "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "-n", "kube-system",
        "get", "service", "kube-dns", "-o=jsonpath={.spec.clusterIP}",
    ])
    if service.exit_code != 0:
        return f"could not read cluster DNS service address: {service.output!r}"
    server = service.output.decode(errors="replace").strip()
    deadline = time.monotonic() + timeout
    last_output = b"lookup has not run"
    while time.monotonic() < deadline:
        lookup = node.exec_run([
            "perl", "-MSocket", "-e", DNS_A_QUERY, server, "host.docker.internal",
        ])
        if lookup.exit_code == 0:
            node.reload()
            expected = node.attrs["NetworkSettings"]["Networks"][network]["Gateway"]
            resolved = lookup.output.decode(errors="replace").strip()
            if resolved != expected:
                return (
                    f"host.docker.internal resolved to {resolved}, "
                    f"expected network gateway {expected}"
                )
            return None
        last_output = lookup.output
        time.sleep(0.5)
    return (
        f"cluster DNS could not resolve host.docker.internal within {timeout}s: "
        f"{last_output!r}"
    )


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
            if failure is None:
                failure = wait_for_cluster_network_ready(client, name)
            if failure is None:
                failure = verify_cluster_pod_exec(client, name)
            if failure is None:
                failure = verify_docker_host_resolution(client, name, network)
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
                                "printf '\nKUBERNETES WORKLOADS\n'; "
                                "kubectl --kubeconfig=/etc/kubernetes/admin.conf "
                                "get pods -A -o wide 2>&1 || true; "
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
