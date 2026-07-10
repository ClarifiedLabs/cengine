"""Real Docker Compose compatibility scenarios owned by cengine."""

from __future__ import annotations

import os
import pathlib
import subprocess
import uuid

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "Tests/Fixtures/compose/compose.yaml"
COMPOSE_VERSION = "5.3.1"


def compose(daemon, project: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    socket = daemon["socket"]
    environment = os.environ.copy()
    environment["DOCKER_HOST"] = f"unix://{socket}"
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "--project-name", project, *arguments],
        cwd=REPO_ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=True,
    )


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
    except subprocess.CalledProcessError as error:
        pytest.fail(f"Compose cleanup failed:\n{error.stdout}")


@pytest.mark.compat("CMP-001")
def test_compose_application_lifecycle(daemon, compose_project):
    compose(daemon, compose_project, "up", "-d")
    ps = compose(daemon, compose_project, "ps", "-a")
    assert f"{compose_project}-web-1" in ps.stdout
    assert f"{compose_project}-client-1" in ps.stdout
    logs = compose(daemon, compose_project, "logs", "--no-color")
    assert "Welcome" not in logs.stdout  # wget is quiet; successful exit is asserted by ps
    assert "Exited" in ps.stdout


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
