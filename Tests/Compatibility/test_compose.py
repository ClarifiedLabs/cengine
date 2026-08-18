"""Real Docker Compose compatibility scenarios owned by cengine."""

from __future__ import annotations

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
COMPOSE_VERSION = "5.5.0"


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
            f"Compose {COMPOSE_VERSION} did not use the cengine context's default "
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
    assert result.stdout.strip() == COMPOSE_VERSION, (
        f"Docker Compose {COMPOSE_VERSION} is required; found {result.stdout.strip()}"
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
    managed_docker_integration.environment["DEVELOPER_IMAGE"] = project["image"]
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
