from __future__ import annotations

import os
import pathlib
import random
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field

import docker
import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_BINARY = REPO_ROOT / ".build/xcode-derived/Build/Products/Debug/cengine"
DEFAULT_KERNEL = pathlib.Path.home() / "Library/Application Support/cengine/assets/vmlinux"
DEFAULT_IMAGE = "alpine:latest"


@dataclass
class Daemon:
    binary: pathlib.Path
    kernel: pathlib.Path
    work: pathlib.Path
    root: pathlib.Path = field(init=False)
    runtime: pathlib.Path = field(init=False)
    socket: pathlib.Path = field(init=False)
    log_path: pathlib.Path = field(init=False)
    process: subprocess.Popen[bytes] | None = field(default=None, init=False)
    _log: object | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.root = self.work / "root"
        self.runtime = self.work / "run"
        self.socket = self.runtime / "docker.sock"
        self.log_path = self.work / "daemon.log"
        self.root.mkdir()
        self.runtime.mkdir()

    def __getitem__(self, key: str):
        return {
            "work": self.work, "socket": self.socket, "log": self.log_path,
            "process": self.process,
        }[key]

    def start(self) -> None:
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("cengine daemon is already running")
        self.socket.unlink(missing_ok=True)
        self._log = self.log_path.open("ab")
        self.process = subprocess.Popen(
            [str(self.binary), "daemon", "--root", str(self.root), "--socket", str(self.socket),
             "--kernel", str(self.kernel)],
            stdin=subprocess.DEVNULL, stdout=self._log, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 60
        last_error = "socket not created"
        while time.monotonic() < deadline and self.process.poll() is None:
            if self.socket.exists():
                result = subprocess.run(
                    ["curl", "--silent", "--show-error", "--unix-socket", str(self.socket),
                     "http://localhost/_ping"],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                if result.returncode == 0 and result.stdout == "OK":
                    return
                last_error = result.stderr or result.stdout
            time.sleep(0.1)
        self.stop()
        pytest.fail(f"cengine daemon did not become ready ({last_error}):\n{self.logs()}")

    def stop(self, *, kill: bool = False) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.kill() if kill else self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self._log is not None:
            self._log.close()
            self._log = None

    def restart(self, *, kill: bool = False) -> None:
        self.stop(kill=kill)
        self.start()

    def logs(self) -> str:
        return self.log_path.read_text(errors="replace") if self.log_path.exists() else ""


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    seed = os.environ.get("CENGINE_TEST_SEED")
    if seed is not None:
        random.Random(int(seed)).shuffle(items)
        print(f"compatibility test order seed: {seed}")


def pytest_report_header() -> list[str]:
    commands = {
        "Docker CLI": ["docker", "--version"],
        "Docker Compose": ["docker", "compose", "version", "--short"],
        "Docker Buildx": ["docker", "buildx", "version"],
        "kind": ["kind", "version"],
    }
    versions = []
    for name, command in commands.items():
        try:
            result = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
            )
            versions.append(f"{name}: {result.stdout.strip() or 'unavailable'}")
        except (OSError, subprocess.TimeoutExpired):
            versions.append(f"{name}: unavailable")
    return versions


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
    full_suite = requested == [pathlib.Path(__file__).parent.resolve()] and not session.config.option.markexpr
    missing = documented - seen
    if full_suite and missing:
        raise pytest.UsageError(f"compatibility ledger IDs have no tests: {', '.join(sorted(missing))}")


@pytest.fixture(scope="session")
def daemon() -> Daemon:
    binary = pathlib.Path(os.environ.get("CENGINE_BINARY", DEFAULT_BINARY))
    kernel = pathlib.Path(os.environ.get("CENGINE_KERNEL", DEFAULT_KERNEL))
    if not binary.is_file():
        pytest.fail(f"cengine binary not found at {binary}; run make build or set CENGINE_BINARY")
    if not kernel.is_file():
        pytest.fail(
            f"Linux kernel not found at {kernel}; run cengine system install or set CENGINE_KERNEL"
        )

    work = pathlib.Path(tempfile.mkdtemp(prefix="cengine-compat-"))
    value = Daemon(binary=binary, kernel=kernel, work=work)
    value.start()
    yield value
    value.stop()
    if value.process is not None and value.process.returncode not in (-15, -9, 0):
        print("\ncengine daemon log:\n" + value.logs())
    shutil.rmtree(work, ignore_errors=True)


@pytest.fixture(scope="session")
def client(daemon: Daemon) -> docker.DockerClient:
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


@pytest.fixture(autouse=True)
def daemon_survived(daemon: Daemon):
    yield
    assert daemon.process is not None and daemon.process.poll() is None, (
        "cengine daemon exited during the test:\n" + daemon.logs()
    )


@pytest.fixture
def top(client: docker.DockerClient):
    image = os.environ.get("CENGINE_TEST_IMAGE", DEFAULT_IMAGE)
    container = client.containers.create(
        image=image, command="top", detach=True, tty=True, name=f"top-{uuid.uuid4().hex[:8]}"
    )
    container.start()
    return container
