"""OCI/Linux runtime-semantic contracts below the Docker API surface."""

from __future__ import annotations

import io
import pathlib
import tarfile
import time

import docker
import pytest
from docker.types import Mount


DIND_IMAGE = "docker:29.6.2-dind"
ALPINE_IMAGE = "alpine:latest"
SNAPSHOT_SCRIPT = r"""
snapshot() {
    for namespace in mnt pid uts ipc net cgroup; do
        value=$(readlink "/proc/$$/ns/$namespace")
        printf 'namespace_%s=%s\n' "$namespace" "$value"
    done
    printf 'root_stat=%s\n' "$(stat -c '%d:%i' /)"
    awk '$5 == "/" { print "root_mount=" $1 ":" $3 ":" $4 ":" $6; exit }' /proc/self/mountinfo
    printf 'hostname=%s\n' "$(hostname)"
    printf 'working_directory=%s\n' "$(pwd)"
    printf 'uid=%s\n' "$(id -u)"
    printf 'gid=%s\n' "$(id -g)"
    printf 'groups=%s\n' "$(id -G | tr ' ' ',')"
    printf 'environment=%s\n' "$CONTEXT"
    awk '/^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):/ {
        key=$1; sub(":", "", key); print "status_" key "=" $2
    }' /proc/self/status
    for descriptor in 3 4 5; do
        if test -e "/proc/$$/fd/$descriptor"; then
            printf 'fd_%s=open\n' "$descriptor"
        else
            printf 'fd_%s=closed\n' "$descriptor"
        fi
    done
    printf 'snapshot_complete=1\n'
}
snapshot
"""


def parse_snapshot(output: bytes) -> dict[str, str]:
    values = {}
    for raw_line in output.decode(errors="replace").splitlines():
        key, separator, value = raw_line.partition("=")
        if separator:
            values[key] = value
    assert values.get("snapshot_complete") == "1", output.decode(errors="replace")
    return values


def wait_for_init_snapshot(container: docker.models.containers.Container) -> dict[str, str]:
    deadline = time.monotonic() + 30
    output = b""
    while time.monotonic() < deadline:
        output = container.logs()
        if b"snapshot_complete=1" in output:
            return parse_snapshot(output)
        container.reload()
        if container.status == "exited":
            break
        time.sleep(0.1)
    pytest.fail(f"init context snapshot did not complete:\n{output.decode(errors='replace')}")


@pytest.mark.compat("RTM-001")
def test_init_and_default_exec_share_runtime_context(
    client: docker.DockerClient, tmp_path: pathlib.Path,
):
    group_file = tmp_path / "group"
    group_file.write_text("root:x:0:\nnobody:x:65534:\ncompat:x:2345:nobody\n")
    privileged_container = None
    container = client.containers.create(
        ALPINE_IMAGE,
        ["sh", "-ec", SNAPSHOT_SCRIPT + "while :; do sleep 1; done"],
        hostname="runtime-context",
        user="nobody",
        working_dir="/tmp",
        environment={"CONTEXT": "container"},
        mounts=[Mount("/etc/group", str(group_file), type="bind", read_only=True)],
    )
    try:
        container.start()
        init_context = wait_for_init_snapshot(container)
        result = container.exec_run(["sh", "-ec", SNAPSHOT_SCRIPT])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        exec_context = parse_snapshot(result.output)

        semantic_keys = set(exec_context) - {"fd_3", "fd_4", "fd_5"}
        assert {key: exec_context[key] for key in semantic_keys} == {
            key: init_context[key] for key in semantic_keys
        }
        assert exec_context["working_directory"] == "/tmp"
        assert exec_context["uid"] == "65534"
        assert exec_context["gid"] == "65534"
        assert "2345" in exec_context["groups"].split(",")
        assert exec_context["status_NoNewPrivs"] == "1"
        assert all(exec_context[f"fd_{descriptor}"] == "closed" for descriptor in (3, 4, 5))

        privileged = container.exec_run(
            ["sh", "-ec", "awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status"],
            privileged=True,
        )
        assert privileged.exit_code == 0, privileged.output.decode(errors="replace")
        assert privileged.output.strip() == b"0"

        privileged_container = client.containers.run(
            ALPINE_IMAGE, ["tail", "-f", "/dev/null"], detach=True, privileged=True,
        )
        inherited = privileged_container.exec_run([
            "sh", "-ec",
            "awk '/^CapEff:/ { print $2 } /^NoNewPrivs:/ { print $2 }' /proc/self/status",
        ])
        assert inherited.exit_code == 0, inherited.output.decode(errors="replace")
        capability_mask, no_new_privileges = inherited.output.splitlines()
        assert int(capability_mask, 16) & (1 << 21), "default exec lost container CAP_SYS_ADMIN"
        assert no_new_privileges == b"0"
    finally:
        container.remove(force=True)
        if privileged_container is not None:
            privileged_container.remove(force=True)


@pytest.mark.compat("RTM-002")
def test_read_only_root_applies_to_exec_but_tmpfs_stays_writable(
    client: docker.DockerClient,
):
    container = client.containers.run(
        ALPINE_IMAGE,
        ["sh", "-c", "while :; do sleep 1; done"],
        detach=True,
        read_only=True,
        tmpfs={"/writable": "rw,nosuid,nodev,mode=1777"},
    )
    try:
        result = container.exec_run([
            "sh", "-ec",
            "if touch /root-write 2>/dev/null; then exit 20; fi; "
            "touch /writable/exec-write; test -f /writable/exec-write; printf readonly-ok",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output == b"readonly-ok"
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-004")
def test_pids_limit_enforces_live_updates_and_survives_recovery(
    daemon, client: docker.DockerClient,
):
    container = client.containers.run(
        ALPINE_IMAGE, ["tail", "-f", "/dev/null"], detach=True, pids_limit=8,
    )
    try:
        container.reload()
        assert container.attrs["HostConfig"]["PidsLimit"] == 8
        result = container.exec_run(["cat", "/sys/fs/cgroup/pids.max"])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output.strip() == b"8"

        response = client.api._post_json(
            client.api._url("/containers/{0}/update", container.id),
            data={"PidsLimit": 1},
        )
        client.api._result(response, True)
        try:
            constrained = container.exec_run(["true"])
        except docker.errors.APIError:
            pass
        else:
            assert constrained.exit_code != 0, "pids.max=1 unexpectedly allowed an exec process"

        response = client.api._post_json(
            client.api._url("/containers/{0}/update", container.id),
            data={"PidsLimit": 12},
        )
        client.api._result(response, True)
        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        try:
            value = recovered.containers.get(container.id)
            value.reload()
            assert value.attrs["HostConfig"]["PidsLimit"] == 12
            result = value.exec_run(["cat", "/sys/fs/cgroup/pids.max"])
            assert result.exit_code == 0, result.output.decode(errors="replace")
            assert result.output.strip() == b"12"
        finally:
            recovered.close()
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-005")
def test_unrealizable_bind_mount_propagation_is_rejected(
    client: docker.DockerClient, tmp_path: pathlib.Path,
):
    with pytest.raises(docker.errors.APIError) as error:
        client.containers.create(
            ALPINE_IMAGE,
            ["tail", "-f", "/dev/null"],
            mounts=[Mount(
                target="/propagated", source=str(tmp_path), type="bind", propagation="rshared",
            )],
        )
    assert error.value.status_code == 501


@pytest.mark.compat("RTM-006")
def test_capability_add_drop_apply_to_init_and_exec(client: docker.DockerClient):
    container = client.containers.run(
        ALPINE_IMAGE,
        [
            "sh", "-ec",
            "awk '/^CapEff:/ { print $2 }' /proc/self/status >/tmp/init-cap; "
            "while :; do sleep 1; done",
        ],
        detach=True,
        cap_drop=["ALL", "CHOWN"],
        cap_add=["CHOWN", "NET_ADMIN"],
    )
    try:
        result = container.exec_run([
            "sh", "-ec",
            "cat /tmp/init-cap; awk '/^CapEff:/ { print $2 }' /proc/self/status",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        init_mask, exec_mask = (int(value, 16) for value in result.output.splitlines())
        expected = (1 << 0) | (1 << 12)  # CAP_CHOWN | CAP_NET_ADMIN
        assert init_mask == expected
        assert exec_mask == expected
        container.reload()
        assert container.attrs["HostConfig"]["CapDrop"] == ["ALL", "CAP_CHOWN"]
        assert container.attrs["HostConfig"]["CapAdd"] == ["CAP_CHOWN", "CAP_NET_ADMIN"]
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-007")
def test_container_prune_honors_filters_and_rejects_unknown_keys(client: docker.DockerClient):
    selected = client.containers.create(ALPINE_IMAGE, ["true"], labels={"prune": "yes"})
    preserved = client.containers.create(ALPINE_IMAGE, ["true"], labels={"prune": "no"})
    try:
        with pytest.raises(docker.errors.APIError) as error:
            client.containers.prune(filters={"name": [selected.name]})
        assert error.value.status_code == 400
        client.containers.get(selected.id)
        client.containers.get(preserved.id)

        response = client.containers.prune(filters={"label": ["prune=yes"]})
        assert response["ContainersDeleted"] == [selected.id]
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(selected.id)
        client.containers.get(preserved.id)
    finally:
        for container in (selected, preserved):
            try:
                container.remove(force=True)
            except docker.errors.NotFound:
                pass


@pytest.mark.compat("RTM-008")
def test_exec_stage_proxies_preserve_status_and_kill_timed_out_healthchecks(
    client: docker.DockerClient,
):
    healthcheck = """
        mkdir -p /tmp/healthcheck-pids
        for marker in /tmp/healthcheck-pids/*; do
            [ -f "$marker" ] || continue
            for pid in $(cat "$marker"); do
                state=$(awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null || true)
                if [ -n "$state" ] && [ "$state" != Z ]; then
                    touch /tmp/orphaned-healthcheck
                    exit 42
                fi
            done
        done
        sleep 30 &
        child=$!
        printf '%s %s' "$$" "$child" > "/tmp/healthcheck-pids/$$"
        wait "$child"
    """
    container = client.containers.run(
        ALPINE_IMAGE,
        ["tail", "-f", "/dev/null"],
        detach=True,
        healthcheck={
            "test": ["CMD-SHELL", healthcheck],
            "interval": 1_000_000_000,
            "timeout": 1_000_000_000,
            "retries": 2,
        },
    )
    try:
        failed = container.exec_run(["sh", "-c", "exit 23"])
        assert failed.exit_code == 23

        inspected_exec = client.api.exec_create(
            container.id,
            [
                "sh",
                "-c",
                "awk '/^NSpid:/{print $2}' /proc/self/status > /tmp/exec-target-pid; sleep 30",
            ],
        )["Id"]
        client.api.exec_start(inspected_exec, detach=True)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            observed = container.exec_run(["cat", "/tmp/exec-target-pid"])
            if observed.exit_code == 0 and observed.output.strip():
                break
            time.sleep(0.1)
        else:
            pytest.fail("exec target did not publish its outer-namespace PID")
        inspect = client.api.exec_inspect(inspected_exec)
        assert inspect["Running"] is True
        assert inspect["Pid"] == int(observed.output.strip())

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            container.reload()
            if container.attrs["State"]["Health"]["FailingStreak"] >= 2:
                break
            time.sleep(0.2)
        else:
            pytest.fail(f"healthcheck did not time out twice: {container.attrs['State']['Health']}")

        surviving_exec = client.api.exec_inspect(inspected_exec)
        assert surviving_exec["Running"] is True, "healthcheck cgroup kill reached a sibling exec"
        assert surviving_exec["Pid"] == inspect["Pid"]
        orphan = container.exec_run(["test", "-e", "/tmp/orphaned-healthcheck"])
        assert orphan.exit_code == 1, "a timed-out healthcheck target or descendant survived its exec cgroup"
    finally:
        container.remove(force=True)


def archive_file(name: str, contents: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        info = tarfile.TarInfo(name)
        info.mode = 0o600
        info.size = len(contents)
        archive.addfile(info, io.BytesIO(contents))
    return output.getvalue()


def outer_exec(
    container: docker.models.containers.Container, command: list[str],
) -> tuple[int, str]:
    result = container.exec_run(command)
    output = result.output.decode(errors="replace")
    return result.exit_code, output


def dind_diagnostics(container: docker.models.containers.Container) -> str:
    sections = [f"outer logs:\n{container.logs().decode(errors='replace')}"]
    for name, command in [
        ("docker info", ["docker", "info"]),
        ("docker ps -a", ["docker", "ps", "-a", "--no-trunc"]),
        ("nested inspect", ["docker", "inspect", "runtime-nested"]),
    ]:
        try:
            code, output = outer_exec(container, command)
            sections.append(f"{name} (exit {code}):\n{output}")
        except docker.errors.DockerException as error:
            sections.append(f"{name}: {error}")
    return "\n\n".join(sections)


@pytest.mark.compat("RTM-003")
def test_nested_docker_exec_and_healthcheck_without_kind(client: docker.DockerClient):
    container = client.containers.create(
        DIND_IMAGE,
        ["--host=unix:///var/run/docker.sock", "--storage-driver=overlay2"],
        privileged=True,
        environment={"DOCKER_TLS_CERTDIR": ""},
        tmpfs={
            "/run": "rw,nosuid,nodev,mode=755",
            "/tmp": "rw,nosuid,nodev,mode=1777",
        },
        mem_limit=2 * 1024 * 1024 * 1024,
        nano_cpus=2_000_000_000,
    )
    try:
        container.start()
        deadline = time.monotonic() + 120
        last_info = "nested daemon readiness has not run"
        while time.monotonic() < deadline:
            code, last_info = outer_exec(container, ["docker", "info", "--format", "{{.Driver}}"])
            if code == 0 and last_info.strip() == "overlay2":
                break
            time.sleep(0.2)
        else:
            pytest.fail(
                f"nested Docker daemon did not become ready; last result: {last_info}\n\n"
                + dind_diagnostics(container)
            )

        alpine_archive = b"".join(client.images.get(ALPINE_IMAGE).save(named=True))
        assert container.put_archive("/tmp", archive_file("alpine.tar", alpine_archive))
        code, output = outer_exec(container, ["docker", "load", "--input", "/tmp/alpine.tar"])
        assert code == 0, output + "\n\n" + dind_diagnostics(container)

        code, output = outer_exec(container, [
            "docker", "run", "--detach", "--name", "runtime-nested",
            "--workdir", "/data",
            "--health-cmd", "test \"$(pwd)\" = /data",
            "--health-interval", "1s", "--health-timeout", "2s", "--health-retries", "5",
            ALPINE_IMAGE, "sh", "-c", "while :; do sleep 1; done",
        ])
        assert code == 0, output + "\n\n" + dind_diagnostics(container)

        code, output = outer_exec(container, [
            "docker", "exec", "runtime-nested", "sh", "-ec",
            "test \"$(pwd)\" = /data; printf nested-exec-ok",
        ])
        assert code == 0, output + "\n\n" + dind_diagnostics(container)
        assert output == "nested-exec-ok"

        deadline = time.monotonic() + 30
        health = "healthcheck has not run"
        while time.monotonic() < deadline:
            code, health = outer_exec(container, [
                "docker", "inspect", "--format", "{{.State.Health.Status}}", "runtime-nested",
            ])
            if code == 0 and health.strip() == "healthy":
                break
            time.sleep(0.2)
        else:
            pytest.fail(
                f"nested container did not become healthy; last result: {health}\n\n"
                + dind_diagnostics(container)
            )
    finally:
        container.remove(force=True)
