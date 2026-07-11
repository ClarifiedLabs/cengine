"""Real Docker Compose compatibility scenarios owned by cengine."""

from __future__ import annotations

import os
import pathlib
import json
import subprocess
import time
import urllib.request
import uuid

import pytest
from docker import errors


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "Tests/Fixtures/compose/compose.yaml"
COMPOSE_VOLUMES_FILE = REPO_ROOT / "Tests/Fixtures/compose/compose-volumes.yaml"
COMPOSE_HEALTH_FILE = REPO_ROOT / "Tests/Fixtures/compose/compose-health.yaml"
COMPOSE_VERSION = "5.3.1"


def compose(daemon, project: str, *arguments: str, compose_file=COMPOSE_FILE) -> subprocess.CompletedProcess[str]:
    socket = daemon["socket"]
    environment = os.environ.copy()
    environment["DOCKER_HOST"] = f"unix://{socket}"
    return subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "--project-name", project, *arguments],
        cwd=REPO_ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=True,
    )


def compose_json(daemon, project: str, *arguments: str) -> list[dict]:
    output = compose(daemon, project, *arguments).stdout
    return [json.loads(line) for line in output.splitlines() if line.strip()]


@pytest.fixture(scope="session", autouse=True)
def require_compose_version():
    result = subprocess.run(
        ["docker", "compose", "version", "--short"], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True,
    )
    assert result.stdout.strip() == COMPOSE_VERSION, (
        f"Docker Compose {COMPOSE_VERSION} is required; found {result.stdout.strip()}"
    )


@pytest.fixture
def compose_project(daemon):
    project = f"cenginecompat{uuid.uuid4().hex[:8]}"
    yield project
    try:
        compose(daemon, project, "down", "--volumes", "--remove-orphans")
        compose(
            daemon, project, "down", "--volumes", "--remove-orphans",
            compose_file=COMPOSE_VOLUMES_FILE,
        )
    except subprocess.CalledProcessError as error:
        pytest.fail(f"Compose cleanup failed:\n{error.stdout}")


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
    compose(daemon, compose_project, "stop", "web")
    stopped = compose_json(daemon, compose_project, "ps", "-a", "--format", "json", "web")
    assert stopped[0]["State"] == "exited"
    compose(daemon, compose_project, "start", "web")
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
