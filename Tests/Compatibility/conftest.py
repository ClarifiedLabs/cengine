from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import uuid

import docker
import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_BINARY = REPO_ROOT / ".build/xcode-derived/Build/Products/Debug/cengine"
DEFAULT_KERNEL = pathlib.Path.home() / "Library/Application Support/cengine/assets/vmlinux"
DEFAULT_IMAGE = "alpine:latest"


def pytest_collection_finish(session: pytest.Session) -> None:
    ledger = (REPO_ROOT / "docs/docker-compatibility.md").read_text()
    seen: set[str] = set()
    for item in session.items:
        marker = item.get_closest_marker("compat")
        if marker is None or len(marker.args) != 1:
            raise pytest.UsageError(f"{item.nodeid} is missing one @pytest.mark.compat ID")
        compat_id = str(marker.args[0])
        if compat_id in seen:
            raise pytest.UsageError(f"duplicate compatibility ID: {compat_id}")
        if f"`{compat_id}`" not in ledger:
            raise pytest.UsageError(f"{compat_id} is missing from docs/docker-compatibility.md")
        seen.add(compat_id)
    documented = set(re.findall(r"^\| `([A-Z]+-[0-9]+)` \|", ledger, flags=re.MULTILINE))
    requested = [pathlib.Path(str(value).split("::", 1)[0]).resolve() for value in session.config.args]
    full_suite = requested == [pathlib.Path(__file__).parent.resolve()]
    missing = documented - seen
    if full_suite and missing:
        raise pytest.UsageError(f"compatibility ledger IDs have no tests: {', '.join(sorted(missing))}")


@pytest.fixture(scope="session")
def daemon() -> dict[str, pathlib.Path | subprocess.Popen[bytes]]:
    binary = pathlib.Path(os.environ.get("CENGINE_BINARY", DEFAULT_BINARY))
    kernel = pathlib.Path(os.environ.get("CENGINE_KERNEL", DEFAULT_KERNEL))
    if not binary.is_file():
        pytest.fail(f"cengine binary not found at {binary}; run make build or set CENGINE_BINARY")
    if not kernel.is_file():
        pytest.fail(
            f"Linux kernel not found at {kernel}; run cengine system install or set CENGINE_KERNEL"
        )

    work = pathlib.Path(tempfile.mkdtemp(prefix="cengine-compat-"))
    root, runtime = work / "root", work / "run"
    root.mkdir(); runtime.mkdir()
    socket = runtime / "docker.sock"
    log_path = work / "daemon.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(binary), "daemon", "--root", str(root), "--socket", str(socket), "--kernel", str(kernel)],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not socket.exists() and process.poll() is None:
        time.sleep(0.1)
    if not socket.exists():
        process.terminate(); process.wait(timeout=5); log.close()
        output = log_path.read_text(errors="replace")
        shutil.rmtree(work, ignore_errors=True)
        pytest.fail(f"cengine daemon did not create its socket:\n{output}")

    state = {"work": work, "socket": socket, "log": log_path, "process": process}
    yield state

    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=5)
    log.close()
    if process.returncode not in (-15, 0):
        print("\ncengine daemon log:\n" + log_path.read_text(errors="replace"))
    shutil.rmtree(work, ignore_errors=True)


@pytest.fixture(scope="session")
def client(daemon: dict[str, pathlib.Path | subprocess.Popen[bytes]]) -> docker.DockerClient:
    socket = daemon["socket"]
    assert isinstance(socket, pathlib.Path)
    value = docker.DockerClient(base_url=f"unix://{socket}", timeout=180, version="auto")
    value.ping()
    value.images.pull(os.environ.get("CENGINE_TEST_IMAGE", DEFAULT_IMAGE))
    yield value
    value.close()


@pytest.fixture(autouse=True)
def clean_resources(client: docker.DockerClient):
    image = os.environ.get("CENGINE_TEST_IMAGE", DEFAULT_IMAGE)
    try:
        client.images.get(image)
    except docker.errors.NotFound:
        client.images.pull(image)
    yield
    errors: list[str] = []
    for container in client.containers.list(all=True):
        try:
            container.reload()
            if container.status == "paused":
                container.unpause()
                container.reload()
            if container.status == "running":
                container.stop(timeout=1)
            container.remove(force=True)
        except Exception as error:  # cleanup should preserve the original test failure
            errors.append(f"container {container.name}: {error}")
    for volume in client.volumes.list():
        if volume.attrs.get("Labels", {}).get("dev.cengine.compat") != "true":
            continue
        try:
            volume.remove(force=True)
        except Exception as error:
            errors.append(f"volume {volume.name}: {error}")
    for network in client.networks.list():
        if not network.name.startswith("compat-"):
            continue
        try:
            network.remove()
        except Exception as error:
            errors.append(f"network {network.name}: {error}")
    for value in client.images.list():
        if any("alpine" in tag for tag in value.tags):
            continue
        try:
            client.images.remove(value.id, force=True)
        except Exception as error:
            errors.append(f"image {value.id}: {error}")
    if errors:
        pytest.fail("resource cleanup failed:\n" + "\n".join(errors))


@pytest.fixture
def top(client: docker.DockerClient):
    image = os.environ.get("CENGINE_TEST_IMAGE", DEFAULT_IMAGE)
    container = client.containers.create(
        image=image, command="top", detach=True, tty=True, name=f"top-{uuid.uuid4().hex[:8]}"
    )
    container.start()
    return container
