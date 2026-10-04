"""Real Docker Compose compatibility scenarios owned by cengine."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
import pathlib
import json
import os
import shutil
import subprocess
import time
import urllib.request
import uuid

import pytest
from docker import errors

from harness import docker_environment, managed_docker_environment, wait_for_value


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "Tests/Fixtures/compose/compose.yaml"
COMPOSE_VOLUMES_FILE = REPO_ROOT / "Tests/Fixtures/compose/compose-volumes.yaml"
COMPOSE_HEALTH_FILE = REPO_ROOT / "Tests/Fixtures/compose/compose-health.yaml"
DEVELOPER_FIXTURE = REPO_ROOT / "Tests/Fixtures/compose/developer-loop"
COMPOSE_MAJOR_VERSION = "5"
UPSTREAM_VOLUMES_FIXTURE = REPO_ROOT / "Tests/Fixtures/compose/upstream-volumes"


def compose(daemon, project: str, *arguments: str, compose_file=COMPOSE_FILE) -> subprocess.CompletedProcess[str]:
    socket = daemon["socket"]
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "--project-name", project, *arguments],
        cwd=REPO_ROOT,
        env=docker_environment(socket),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
    )
    if result.returncode != 0:
        pytest.fail(f"Docker Compose {' '.join(arguments)} failed:\n{result.stdout}")
    return result


def compose_json(daemon, project: str, *arguments: str) -> list[dict]:
    output = compose(daemon, project, *arguments).stdout
    return [json.loads(line) for line in output.splitlines() if line.strip()]


def developer_compose(managed, project: dict, *arguments: str, check: bool = True):
    return managed.run(
        "--context", "cengine", "compose", "-f", str(project["compose_file"]),
        "--project-name", project["name"], *arguments,
        cwd=project["root"], check=check,
    )


def developer_container_id(managed, project: dict) -> str:
    return developer_compose(managed, project, "ps", "-q", "developer").stdout.strip()


def developer_http_state(managed, project: dict, *, timeout: float = 30, predicate=None) -> dict:
    published = developer_compose(managed, project, "port", "developer", "8000").stdout.strip()
    port = int(published.rsplit(":", 1)[1])

    def probe() -> dict:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as response:
            return json.loads(response.read())

    try:
        return wait_for_value(
            probe, predicate or (lambda value: bool(value.get("message"))),
            timeout=timeout, description="developer-loop HTTP state",
        )
    except TimeoutError as error:
        pytest.fail(f"{error}\n\n{managed.diagnostics()}")


def atomic_replace(path: pathlib.Path, payload: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def container_boot_id(container) -> str:
    result = container.exec_run(["cat", "/proc/sys/kernel/random/boot_id"])
    assert result.exit_code == 0, result.output.decode(errors="replace")
    return result.output.decode().strip()


def managed_buildkit_identity(client) -> tuple[str, str]:
    try:
        container = client.containers.get("buildx_buildkit_cengine-builder0")
    except errors.NotFound:
        observed = sorted(
            value.name for value in client.containers.list(all=True)
            if value.name.startswith("buildx_buildkit_")
        )
        raise AssertionError(
            f"Compose {COMPOSE_MAJOR_VERSION}.x did not use the cengine context's default "
            f"cengine-builder; observed BuildKit containers: {observed}"
        ) from None
    state_volumes = [
        mount["Name"] for mount in container.attrs["Mounts"]
        if mount.get("Type") == "volume" and mount.get("Destination") == "/var/lib/buildkit"
    ]
    assert len(state_volumes) == 1, container.attrs["Mounts"]
    return container.id, state_volumes[0]


def assert_developer_project_removed(client, project: dict) -> None:
    containers = client.containers.list(
        all=True, filters={"label": f"com.docker.compose.project={project['name']}"},
    )
    networks = client.networks.list(
        filters={"label": f"com.docker.compose.project={project['name']}"},
    )
    assert not containers, [value.name for value in containers]
    assert not networks, [value.name for value in networks]


@pytest.fixture(scope="session", autouse=True)
def require_compose_version():
    result = subprocess.run(
        ["docker", "compose", "version", "--short"], env=managed_docker_environment(), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True,
    )
    version = result.stdout.strip()
    assert version.split(".", 1)[0] == COMPOSE_MAJOR_VERSION, (
        f"Docker Compose {COMPOSE_MAJOR_VERSION}.x is required; found {version}"
    )


@pytest.fixture
def developer_project(daemon, client, managed_docker_integration, request):
    root = daemon.work / "developer-loop"
    shutil.copytree(DEVELOPER_FIXTURE, root)
    project = {
        "name": f"cenginedeveloper{uuid.uuid4().hex[:8]}",
        "root": root,
        "compose_file": root / "compose.yaml",
        "source": root / "source/message.txt",
        "image_input": root / "image-version.txt",
        "image": f"compat-developer-loop:{uuid.uuid4().hex[:8]}",
    }
    # The named OCI context is transferred through the normal Buildx session;
    # it does not replace the shipped default builder or add a registry.
    import compat_image_fixtures
    managed_docker_integration.environment.update({
        "DEVELOPER_IMAGE": project["image"],
        "DEVELOPER_PYTHON_LAYOUT": str(daemon.local_images["python"]),
        "DEVELOPER_PYTHON_MANIFEST": compat_image_fixtures.manifest_digest("python"),
    })
    managed_docker_integration.register_image(project["image"])
    try:
        yield project
    finally:
        down = developer_compose(
            managed_docker_integration, project, "down", "--volumes", "--remove-orphans",
            check=False,
        )
        errors = []
        if down.returncode != 0:
            errors.append(f"Compose down failed: {down.stdout}")
        try:
            assert_developer_project_removed(client, project)
        except AssertionError as error:
            errors.append(f"Compose project resources leaked: {error}")
        shutil.rmtree(root, ignore_errors=True)
        if root.exists():
            errors.append(f"developer-loop fixture leaked at {root}")
        if errors:
            diagnostics = managed_docker_integration.diagnostics()
            report = getattr(request.node, "report_call", None)
            message = "\n".join(errors)
            if report is not None and report.failed:
                print(f"\ndeveloper-loop cleanup failed:\n{message}\n\n{diagnostics}")
            else:
                pytest.fail(f"developer-loop cleanup failed:\n{message}\n\n{diagnostics}")


@pytest.fixture
def compose_project(daemon):
    project = f"cenginecompat{uuid.uuid4().hex[:8]}"
    yield project
    compose(daemon, project, "down", "--volumes", "--remove-orphans")
    compose(
        daemon, project, "down", "--volumes", "--remove-orphans",
        compose_file=COMPOSE_VOLUMES_FILE,
    )


@pytest.mark.compat("CMP-008")
def test_developer_compose_build_uses_context_default_builder(
    managed_docker_integration, developer_project, client,
):
    managed = managed_docker_integration
    project = developer_project
    try:
        build = developer_compose(managed, project, "build", "--progress", "plain")
        assert "ERROR" not in build.stdout
        assert "cengine-builder" in managed.run(
            "--context", "cengine", "buildx", "inspect",
        ).stdout

        developer_compose(managed, project, "up", "-d", "--build")
        state = developer_http_state(
            managed, project, predicate=lambda value: value.get("message") == "source-v1",
        )
        assert state["imageVersion"] == "image-v1"
        image = client.images.get(project["image"])
        assert image.attrs["Os"] == "linux"
        assert image.attrs["Architecture"] == "arm64"
        container = client.containers.get(developer_container_id(managed, project))
        assert container.status == "running"
        assert managed_buildkit_identity(client)[0]
    except Exception:
        print("\ndeveloper Compose build diagnostics:\n" + managed.diagnostics())
        raise


@pytest.mark.compat("CMP-009")
def test_developer_compose_source_edits_hot_reload_without_replacement(
    managed_docker_integration, developer_project,
):
    managed = managed_docker_integration
    project = developer_project
    developer_compose(managed, project, "up", "-d", "--build")
    managed_buildkit_identity(managed.client)
    container_id = developer_container_id(managed, project)
    state = developer_http_state(
        managed, project, predicate=lambda value: value.get("message") == "source-v1",
    )
    server_pid = state["pid"]

    previous_generation = state["generation"]
    project["source"].write_text("incomplete-frame")
    time.sleep(0.75)
    incomplete = developer_http_state(managed, project)
    assert incomplete["generation"] == previous_generation
    assert incomplete["message"] == "source-v1"
    assert incomplete["pid"] == server_pid

    project["source"].write_text("host-in-place\n")
    state = developer_http_state(
        managed, project,
        predicate=lambda value: value.get("message") == "host-in-place"
        and value.get("generation", 0) > previous_generation,
    )
    assert state["generation"] == previous_generation + 1
    assert state["pid"] == server_pid
    previous_generation = state["generation"]
    atomic_replace(project["source"], "host-atomic\n")
    state = developer_http_state(
        managed, project,
        predicate=lambda value: value.get("message") == "host-atomic"
        and value.get("generation", 0) > previous_generation,
    )
    assert state["generation"] == previous_generation + 1
    assert state["pid"] == server_pid

    previous_generation = state["generation"]
    developer_compose(
        managed, project, "exec", "-T", "developer", "sh", "-c",
        "printf 'container-atomic\\n' > /workspace/.message.tmp && "
        "sync /workspace/.message.tmp && mv /workspace/.message.tmp /workspace/message.txt",
    )
    try:
        wait_for_value(
            project["source"].read_text,
            lambda value: value == "container-atomic\n",
            timeout=10, description="container-originated source edit on macOS",
        )
    except TimeoutError as error:
        pytest.fail(str(error))
    state = developer_http_state(
        managed, project,
        predicate=lambda value: value.get("message") == "container-atomic"
        and value.get("generation", 0) > previous_generation,
    )
    assert state["generation"] == previous_generation + 1
    assert developer_container_id(managed, project) == container_id
    assert state["pid"] == server_pid


@pytest.mark.compat("CMP-010")
def test_developer_compose_rebuild_restart_recovery_and_teardown(
    daemon, managed_docker_integration, developer_project, client,
):
    managed = managed_docker_integration
    project = developer_project
    developer_compose(managed, project, "up", "-d", "--build")
    initial = developer_http_state(
        managed, project, predicate=lambda value: value.get("imageVersion") == "image-v1",
    )
    initial_container = developer_container_id(managed, project)
    initial_image = client.images.get(project["image"]).id
    builder_identity = managed_buildkit_identity(client)

    atomic_replace(project["image_input"], "image-v2\n")
    developer_compose(managed, project, "up", "-d", "--build")
    replaced_container = developer_container_id(managed, project)
    assert replaced_container != initial_container
    assert client.images.get(project["image"]).id != initial_image
    replaced = developer_http_state(
        managed, project, predicate=lambda value: value.get("imageVersion") == "image-v2",
    )
    assert replaced["pid"]
    assert managed_buildkit_identity(client) == builder_identity

    developer_compose(managed, project, "up", "-d", "--build")
    assert developer_container_id(managed, project) == replaced_container
    assert managed_buildkit_identity(client) == builder_identity

    developer_compose(managed, project, "restart", "developer")
    assert developer_container_id(managed, project) == replaced_container
    before_recovery = developer_http_state(
        managed, project,
        predicate=lambda value: value.get("imageVersion") == "image-v2"
        and value.get("generation", 0) > 0,
    )
    service = client.containers.get(replaced_container)
    service.reload()
    service_started_at = service.attrs["State"]["StartedAt"]
    service_boot_id = container_boot_id(service)
    buildkit = client.containers.get("buildx_buildkit_cengine-builder0")
    buildkit.reload()
    buildkit_started_at = buildkit.attrs["State"]["StartedAt"]
    buildkit_boot_id = container_boot_id(buildkit)

    daemon.restart(kill=True)
    assert developer_container_id(managed, project) == replaced_container
    assert managed_buildkit_identity(client) == builder_identity
    recovered_service = client.containers.get(replaced_container)
    recovered_service.reload()
    assert recovered_service.attrs["State"]["StartedAt"] == service_started_at
    assert container_boot_id(recovered_service) == service_boot_id
    recovered_buildkit = client.containers.get("buildx_buildkit_cengine-builder0")
    recovered_buildkit.reload()
    assert recovered_buildkit.attrs["State"]["StartedAt"] == buildkit_started_at
    assert container_boot_id(recovered_buildkit) == buildkit_boot_id
    atomic_replace(project["source"], "post-recovery\n")
    recovered = developer_http_state(
        managed, project,
        predicate=lambda value: value.get("message") == "post-recovery",
    )
    assert recovered["generation"] == before_recovery["generation"] + 1
    assert recovered["pid"] == before_recovery["pid"]

    developer_compose(managed, project, "down", "--volumes", "--remove-orphans")
    assert_developer_project_removed(client, project)


@pytest.mark.compat("CMP-001")
def test_compose_application_lifecycle(daemon, compose_project):
    compose(daemon, compose_project, "up", "-d")
    deadline = time.monotonic() + 30
    while True:
        rows = compose_json(daemon, compose_project, "ps", "-a", "--format", "json")
        by_service = {row["Service"]: row for row in rows}
        if by_service.get("client", {}).get("State") == "exited":
            break
        if time.monotonic() >= deadline:
            pytest.fail(f"Compose client did not exit: {rows}")
        time.sleep(0.2)
    assert by_service["client"]["ExitCode"] == 0
    assert by_service["web"]["State"] == "running"
    published = compose(daemon, compose_project, "port", "web", "80").stdout.strip()
    with urllib.request.urlopen(f"http://{published}", timeout=5) as response:
        assert b"Welcome to nginx" in response.read()


@pytest.mark.compat("CMP-002")
def test_compose_repeated_up_is_idempotent(daemon, compose_project):
    compose(daemon, compose_project, "up", "-d")
    before = compose(daemon, compose_project, "ps", "-q", "web").stdout.strip()
    compose(daemon, compose_project, "up", "-d")
    after = compose(daemon, compose_project, "ps", "-q", "web").stdout.strip()
    assert before == after


@pytest.mark.compat("CMP-003")
def test_compose_force_recreate_renames_replacement(daemon, compose_project):
    compose(daemon, compose_project, "up", "-d")
    before = compose(daemon, compose_project, "ps", "-q", "web").stdout.strip()
    compose(daemon, compose_project, "up", "-d", "--force-recreate")
    after = compose(daemon, compose_project, "ps", "-q", "web").stdout.strip()
    assert before != after
    ps = compose(daemon, compose_project, "ps", "-a")
    assert f"{compose_project}-web-1" in ps.stdout


@pytest.mark.compat("CMP-004")
def test_compose_scale_and_reconcile(daemon, compose_project):
    compose(daemon, compose_project, "up", "-d", "--scale", "web=2")
    before = set(compose(daemon, compose_project, "ps", "-q", "web").stdout.split())
    assert len(before) == 2
    compose(daemon, compose_project, "up", "-d", "--scale", "web=2")
    after = set(compose(daemon, compose_project, "ps", "-q", "web").stdout.split())
    assert after == before
    compose(daemon, compose_project, "up", "-d", "--scale", "web=1")
    assert len(compose(daemon, compose_project, "ps", "-q", "web").stdout.split()) == 1


@pytest.mark.compat("CMP-005")
def test_compose_exec_stop_start_and_restart(daemon, compose_project):
    compose(daemon, compose_project, "up", "-d")
    version = compose(daemon, compose_project, "exec", "-T", "web", "nginx", "-v")
    assert "nginx version" in version.stdout
    compose(
        daemon,
        compose_project,
        "exec",
        "-T",
        "web",
        "sh",
        "-c",
        "printf retained >/tmp/cengine-stop-start-marker",
    )
    compose(daemon, compose_project, "stop", "web")
    stopped = compose_json(daemon, compose_project, "ps", "-a", "--format", "json", "web")
    assert stopped[0]["State"] == "exited"
    compose(daemon, compose_project, "start", "web")
    compose(
        daemon,
        compose_project,
        "exec",
        "-T",
        "web",
        "test",
        "-f",
        "/tmp/cengine-stop-start-marker",
    )
    started_id = compose(daemon, compose_project, "ps", "-q", "web").stdout.strip()
    compose(daemon, compose_project, "restart", "web")
    assert compose(daemon, compose_project, "ps", "-q", "web").stdout.strip() == started_id


@pytest.mark.compat("CMP-006")
def test_compose_named_volume_down_semantics(daemon, compose_project, client):
    compose(daemon, compose_project, "up", "-d", compose_file=COMPOSE_VOLUMES_FILE)
    first = compose(
        daemon, compose_project, "run", "--rm", "reader", compose_file=COMPOSE_VOLUMES_FILE,
    )
    assert first.stdout.rstrip().endswith("persistent")
    compose(daemon, compose_project, "down", compose_file=COMPOSE_VOLUMES_FILE)
    second = compose(
        daemon, compose_project, "run", "--rm", "reader", compose_file=COMPOSE_VOLUMES_FILE,
    )
    assert second.stdout.rstrip().endswith("persistent")
    compose(daemon, compose_project, "down", "--volumes", compose_file=COMPOSE_VOLUMES_FILE)
    with pytest.raises(errors.NotFound):
        client.volumes.get(f"{compose_project}_data")


@pytest.mark.compat("CMP-007")
def test_compose_waits_for_healthy_dependency(daemon, compose_project, client):
    try:
        compose(daemon, compose_project, "up", "-d", compose_file=COMPOSE_HEALTH_FILE)
        gate = client.containers.get(f"{compose_project}-gate-1")
        gate.reload()
        assert gate.attrs["State"]["Health"]["Status"] == "healthy"
        dependent = client.containers.get(f"{compose_project}-dependent-1")
        assert dependent.wait(timeout=60)["StatusCode"] == 0
    finally:
        compose(
            daemon, compose_project, "down", "--volumes", "--remove-orphans",
            compose_file=COMPOSE_HEALTH_FILE,
        )


@dataclass(frozen=True)
class VolumeComposeEndpoint:
    """Explicit oracle endpoint; environment and work paths belong to the runner.

    daemon=None is Docker's local-volume control, not block/shared proof.
    A cengine endpoint must carry its real daemon for backend assertions.
    """

    host: str
    work: pathlib.Path
    environment: dict[str, str]
    daemon: Any | None


def volume_compose(daemon, project: dict, *arguments: str, check: bool = True):
    if isinstance(daemon, VolumeComposeEndpoint):
        host = daemon.host
        environment = docker_environment(host, base=daemon.environment)
    else:
        host = f"unix://{daemon['socket']}"
        environment = docker_environment(host)
    for key in tuple(environment):
        if key.startswith("COMPOSE_"):
            environment.pop(key)
    environment.update(project["environment"])
    result = subprocess.run(
        [
            "docker", "--host", host, "compose",
            "--env-file", os.devnull, "-f", str(project["root"] / project["file"]),
            "--project-name", project["name"], *arguments,
        ],
        cwd=project["root"], env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300,
    )
    if check and result.returncode != 0:
        pytest.fail(f"Volume pilot Compose {' '.join(arguments)} failed:\n{result.stdout}")
    return result


def volume_service(daemon, project: dict, client, service: str = "app"):
    ids = volume_compose(daemon, project, "ps", "-q", service).stdout.split()
    assert len(ids) == 1, ids
    container = client.containers.get(ids[0])
    assert container.status == "running", container.attrs["State"]
    if isinstance(daemon, VolumeComposeEndpoint) and daemon.daemon is not None:
        modes = json.loads((daemon.daemon.root / "volume-storage.json").read_text())
        # Curated volume services each have one active consumer, hence block.
        for mount in container.attrs["Mounts"]:
            if mount["Type"] == "volume":
                assert modes[mount["Name"]] == "block", (mount, modes)
    return container


def volume_mount(project: dict, container) -> dict:
    mounts = [mount for mount in container.attrs["Mounts"] if mount["Destination"] == "/data"]
    assert len(mounts) == 1, container.attrs["Mounts"]
    mount = mounts[0]
    assert mount["Type"] == "volume", mount
    assert mount["Name"], mount
    project["volumes"].add(mount["Name"])
    return mount


def volume_exec(container, *arguments: str) -> str:
    result = container.exec_run(list(arguments))
    assert result.exit_code == 0, result.output.decode(errors="replace")
    return result.output.decode()


@pytest.fixture
def upstream_volume_project(daemon, client, request):
    with upstream_volume_project_context(daemon, client, request) as project:
        yield project


@contextmanager
def upstream_volume_project_context(daemon, client, request):
    """Reuse the same owned project lifecycle, without invoking pytest fixtures."""
    name = f"cenginevolumes{uuid.uuid4().hex}"
    root = daemon.work / name
    shutil.copytree(UPSTREAM_VOLUMES_FIXTURE, root)
    (root / "bind-data").mkdir()
    project = {
        "name": name, "root": root, "file": "anonymous.yaml", "volumes": set(),
        "owned_external": {},
        "environment": {
            "CENGINE_CMP_EXTERNAL_VOLUME": f"{name}-external-first",
            "CENGINE_CMP_VOLUME_LABEL": "first",
            "CENGINE_CMP_DEPENDENCY_LABEL": "first",
        },
    }
    try:
        yield project
    finally:
        failures = []
        try:
            # Include any mount created before a test assertion failed. Explicitly
            # tracked names also cover anonymous volumes orphaned by renewal.
            for container in client.containers.list(
                all=True, filters={"label": f"com.docker.compose.project={name}"},
            ):
                try:
                    container.reload()
                except errors.NotFound:
                    continue
                project["volumes"].update(
                    mount["Name"] for mount in container.attrs["Mounts"]
                    if mount["Type"] == "volume"
                )
        except Exception as error:
            failures.append(f"volume discovery failed: {error}")
        try:
            down = volume_compose(
                daemon, project, "down", "--volumes", "--remove-orphans", check=False,
            )
            if down.returncode != 0:
                failures.append(f"Compose down failed: {down.stdout}")
        except Exception as error:
            failures.append(f"Compose down failed: {error}")
        try:
            assert_developer_project_removed(client, project)
        except Exception as error:
            failures.append(f"project cleanup failed: {error}")
        for name in sorted(project["volumes"]):
            try:
                volume = client.volumes.get(name)
                if name in project["owned_external"]:
                    assert volume.attrs.get("Labels", {}).get("dev.cengine.compat.owner") == project["owned_external"][name]
                volume.remove()
            except errors.NotFound:
                pass
            except Exception as error:
                failures.append(f"volume {name} cleanup failed: {error}")
        shutil.rmtree(root, ignore_errors=True)
        if failures:
            message = "\n".join(failures)
            report = getattr(request.node, "report_call", None)
            if report is not None and report.failed:
                print(f"\nVolume pilot cleanup failed:\n{message}")
            else:
                pytest.fail(message)


# Observable scenarios selected from docker/compose at
# e9491499f116984e00b89a39b53a8b28d33ad4c7; see the fixture README for provenance.
@pytest.mark.compat("CMP-040")
def test_compose_anonymous_volume_inheritance_and_renewal(daemon, upstream_volume_project, client):
    project = upstream_volume_project
    volume_compose(daemon, project, "up", "-d")
    first = volume_service(daemon, project, client)
    original_volume = volume_mount(project, first)["Name"]
    volume_exec(first, "sh", "-c", "printf inherited >/data/sentinel")

    volume_compose(daemon, project, "up", "-d", "--force-recreate")
    inherited = volume_service(daemon, project, client)
    assert inherited.id != first.id
    assert volume_mount(project, inherited)["Name"] == original_volume
    assert volume_exec(inherited, "cat", "/data/sentinel") == "inherited"

    volume_compose(daemon, project, "up", "-d", "--force-recreate", "--renew-anon-volumes")
    renewed = volume_service(daemon, project, client)
    assert renewed.id not in {first.id, inherited.id}
    assert volume_mount(project, renewed)["Name"] != original_volume
    volume_exec(renewed, "test", "!", "-e", "/data/sentinel")
    volume_exec(renewed, "sh", "-c", "printf renewed >/data/sentinel")
    assert volume_exec(renewed, "cat", "/data/sentinel") == "renewed"


@pytest.mark.compat("CMP-041")
def test_compose_external_volume_switches_identity_and_content(daemon, upstream_volume_project, client):
    project = upstream_volume_project
    project["file"] = "external.yaml"
    first_name = project["environment"]["CENGINE_CMP_EXTERNAL_VOLUME"]
    second_name = f"{project['name']}-external-second"
    for name in (first_name, second_name):
        token = uuid.uuid4().hex
        volume = client.volumes.create(name, labels={"dev.cengine.compat.owner": token})
        assert volume.attrs.get("Labels", {}).get("dev.cengine.compat.owner") == token
        project["owned_external"][name] = token
        project["volumes"].add(name)

    volume_compose(daemon, project, "up", "-d")
    first = volume_service(daemon, project, client)
    assert volume_mount(project, first)["Name"] == first_name
    volume_exec(first, "sh", "-c", "printf first-volume >/data/sentinel")

    project["environment"]["CENGINE_CMP_EXTERNAL_VOLUME"] = second_name
    volume_compose(daemon, project, "up", "-d")
    second = volume_service(daemon, project, client)
    assert second.id != first.id
    assert volume_mount(project, second)["Name"] == second_name
    volume_exec(second, "test", "!", "-e", "/data/sentinel")
    volume_exec(second, "sh", "-c", "printf second-volume >/data/sentinel")
    assert volume_exec(second, "cat", "/data/sentinel") == "second-volume"

    project["environment"]["CENGINE_CMP_EXTERNAL_VOLUME"] = first_name
    volume_compose(daemon, project, "up", "-d")
    returned = volume_service(daemon, project, client)
    assert returned.id not in {first.id, second.id}
    assert volume_mount(project, returned)["Name"] == first_name
    assert volume_exec(returned, "cat", "/data/sentinel") == "first-volume"
    volume_compose(daemon, project, "down", "--volumes")
    # External volumes remain caller-owned even when Compose removes its volumes.
    assert client.volumes.get(first_name).name == first_name
    assert client.volumes.get(second_name).name == second_name


@pytest.mark.compat("CMP-042")
def test_compose_approved_volume_definition_change_recreates_data(daemon, upstream_volume_project, client):
    project = upstream_volume_project
    project["file"] = "definition.yaml"
    volume_compose(daemon, project, "up", "-d")
    first = volume_service(daemon, project, client)
    name = volume_mount(project, first)["Name"]
    label = "dev.cengine.compat.definition"
    assert client.volumes.get(name).attrs["Labels"][label] == "first"
    volume_exec(first, "sh", "-c", "printf obsolete >/data/sentinel")

    project["environment"]["CENGINE_CMP_VOLUME_LABEL"] = "second"
    volume_compose(daemon, project, "up", "-d", "--yes")
    recreated = volume_service(daemon, project, client)
    assert recreated.id != first.id
    assert volume_mount(project, recreated)["Name"] == name
    assert client.volumes.get(name).attrs["Labels"][label] == "second"
    volume_exec(recreated, "test", "!", "-e", "/data/sentinel")
    volume_exec(recreated, "sh", "-c", "printf replacement >/data/sentinel")
    assert volume_exec(recreated, "cat", "/data/sentinel") == "replacement"


@pytest.mark.compat("CMP-043")
def test_compose_unchanged_bind_does_not_recreate_container(daemon, upstream_volume_project, client):
    project = upstream_volume_project
    project["file"] = "bind.yaml"
    source = project["root"] / "bind-data"
    (source / "sentinel").write_text("before-up")
    volume_compose(daemon, project, "up", "-d")
    first = volume_service(daemon, project, client)
    mount = [value for value in first.attrs["Mounts"] if value["Destination"] == "/data"]
    assert len(mount) == 1, first.attrs["Mounts"]
    assert mount[0]["Type"] == "bind"
    assert pathlib.Path(mount[0]["Source"]).resolve() == source.resolve()
    assert volume_exec(first, "cat", "/data/sentinel") == "before-up"
    started = first.attrs["State"]["StartedAt"]

    (source / "sentinel").write_text("changed-content-not-definition")
    volume_compose(daemon, project, "up", "-d")
    unchanged = volume_service(daemon, project, client)
    assert unchanged.id == first.id
    assert unchanged.attrs["State"]["StartedAt"] == started
    assert volume_exec(unchanged, "cat", "/data/sentinel") == "changed-content-not-definition"


@pytest.mark.compat("CMP-044")
def test_compose_no_deps_recreates_only_selected_service(daemon, upstream_volume_project, client):
    project = upstream_volume_project
    project["file"] = "no-deps.yaml"
    volume_compose(daemon, project, "up", "-d", "--wait", "--wait-timeout", "60")
    first = volume_service(daemon, project, client)
    dependency = volume_service(daemon, project, client, "dependency")
    assert dependency.attrs["State"]["Health"]["Status"] == "healthy"
    label = "dev.cengine.compat.dependency"
    assert dependency.attrs["Config"]["Labels"][label] == "first"
    started = dependency.attrs["State"]["StartedAt"]
    boot_id = container_boot_id(dependency)
    volume_exec(dependency, "sh", "-c", "printf untouched >/tmp/sentinel")

    # Make dependency reconciliation observable: ignoring --no-deps would now
    # apply this changed definition and replace the otherwise healthy dependency.
    project["environment"]["CENGINE_CMP_DEPENDENCY_LABEL"] = "second"
    volume_compose(daemon, project, "up", "-d", "--force-recreate", "--no-deps", "app")
    assert volume_service(daemon, project, client).id != first.id
    untouched = volume_service(daemon, project, client, "dependency")
    assert untouched.id == dependency.id
    assert untouched.attrs["Config"]["Labels"][label] == "first"
    assert untouched.attrs["State"]["StartedAt"] == started
    assert untouched.attrs["State"]["Health"]["Status"] == "healthy"
    assert container_boot_id(untouched) == boot_id
    assert volume_exec(untouched, "cat", "/tmp/sentinel") == "untouched"
