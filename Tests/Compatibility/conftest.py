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

from harness import (
    COMPATIBILITY_OWNER_FILE,
    compatibility_image_cache_key,
    docker_environment,
    terminate_compatibility_runtime,
)


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_BINARY = REPO_ROOT / ".build/xcode-derived/Build/Products/Debug/cengine"
DEFAULT_KERNEL = pathlib.Path.home() / "Library/Application Support/cengine/assets/vmlinux"
DEFAULT_CONTAINER_INITRAMFS = pathlib.Path.home() / "Library/Application Support/cengine/assets/container-initramfs.cpio.gz"
DEFAULT_STORAGE_INITRAMFS = pathlib.Path.home() / "Library/Application Support/cengine/assets/storage-initramfs.cpio.gz"
DEFAULT_IMAGE = "alpine:latest"
DEFAULT_IMAGE_SOURCE = "mirror.gcr.io/library/alpine:latest"
FIXTURE_IMAGES = [
    (
        "alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
        "mirror.gcr.io/library/alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
    ),
    (
        "nginx@sha256:54f2a904c251d5a34adf545a72d32515a15e08418dae0266e23be2e18c66fefa",
        "mirror.gcr.io/library/nginx@sha256:54f2a904c251d5a34adf545a72d32515a15e08418dae0266e23be2e18c66fefa",
    ),
    ("busybox:latest", "mirror.gcr.io/library/busybox:latest"),
    ("debian:trixie-slim", "mirror.gcr.io/library/debian:trixie-slim"),
    (
        "registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373",
        "mirror.gcr.io/library/registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373",
    ),
    (
        "mirror.gcr.io/kindest/node@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
        "mirror.gcr.io/kindest/node@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
    ),
]


def fixture_image_seeds() -> list[tuple[str, str]]:
    image = os.environ.get("CENGINE_TEST_IMAGE", DEFAULT_IMAGE)
    source = os.environ.get(
        "CENGINE_TEST_IMAGE_SOURCE",
        DEFAULT_IMAGE_SOURCE if image == DEFAULT_IMAGE else image,
    )
    return [(image, source)] + FIXTURE_IMAGES


def expected_git_commit(binary: pathlib.Path) -> str:
    configured = (
        os.environ.get("CENGINE_EXPECTED_GIT_COMMIT")
        or os.environ.get("CENGINE_GIT_COMMIT")
    )
    if configured:
        return configured
    if binary.resolve() != DEFAULT_BINARY.resolve():
        pytest.fail(
            "CENGINE_EXPECTED_GIT_COMMIT is required when CENGINE_BINARY selects a custom binary"
        )
    result = subprocess.run(
        ["git", "rev-parse", "--short=7", "HEAD"], cwd=REPO_ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    if result.returncode != 0:
        pytest.fail(f"could not determine expected cengine commit: {result.stderr.strip()}")
    return result.stdout.strip()


def clone_tree(source: pathlib.Path, destination: pathlib.Path) -> None:
    subprocess.run(["/bin/cp", "-cR", str(source), str(destination)], check=True)


@dataclass
class Daemon:
    binary: pathlib.Path
    kernel: pathlib.Path
    container_initramfs: pathlib.Path
    storage_initramfs: pathlib.Path
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
        (self.work / COMPATIBILITY_OWNER_FILE).write_text(f"{self.binary.resolve()}\n")
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
             "--kernel", str(self.kernel), "--container-initramfs", str(self.container_initramfs),
             "--storage-initramfs", str(self.storage_initramfs)],
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


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    outcome = yield
    setattr(item, f"report_{call.when}", outcome.get_result())


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


@pytest.fixture
def daemon(request: pytest.FixtureRequest, image_cache: pathlib.Path) -> Daemon:
    binary = pathlib.Path(os.environ.get("CENGINE_BINARY", DEFAULT_BINARY))
    kernel = pathlib.Path(os.environ.get("CENGINE_KERNEL", DEFAULT_KERNEL))
    container_initramfs = pathlib.Path(os.environ.get("CENGINE_CONTAINER_INITRAMFS", DEFAULT_CONTAINER_INITRAMFS))
    storage_initramfs = pathlib.Path(os.environ.get("CENGINE_STORAGE_INITRAMFS", DEFAULT_STORAGE_INITRAMFS))
    if not binary.is_file():
        pytest.fail(f"cengine binary not found at {binary}; run make build or set CENGINE_BINARY")
    if not kernel.is_file():
        pytest.fail(
            f"Linux kernel not found at {kernel}; run cengine system install or set CENGINE_KERNEL"
        )
    for name, asset in [("container initramfs", container_initramfs), ("storage initramfs", storage_initramfs)]:
        if not asset.is_file():
            pytest.fail(f"cengine {name} not found at {asset}; run make guest-assets or set its CENGINE_* path")

    work = pathlib.Path(tempfile.mkdtemp(prefix="cengine-compat-"))
    value = Daemon(binary=binary, kernel=kernel, container_initramfs=container_initramfs,
                   storage_initramfs=storage_initramfs, work=work)
    cached_content = image_cache / "content"
    if cached_content.is_dir():
        clone_tree(cached_content, value.root / "content")
    try:
        value.start()
        yield value
    finally:
        value.stop()
        failed = any(
            getattr(request.node, f"report_{phase}", None) is not None
            and getattr(request.node, f"report_{phase}").failed
            for phase in ("setup", "call", "teardown")
        )
        if failed:
            lines = value.logs().splitlines()
            print("\ncengine daemon log (last 200 lines):\n" + "\n".join(lines[-200:]))
        if value.process is not None and value.process.returncode not in (-15, -9, 0):
            print("\ncengine daemon log:\n" + value.logs())
        terminate_compatibility_runtime(value.binary, roots=(value.root,))
        shutil.rmtree(work, ignore_errors=True)


@pytest.fixture(scope="session")
def image_cache():
    key = compatibility_image_cache_key(fixture_image_seeds())
    root = REPO_ROOT / ".build" / f"compat-image-cache-{key}"
    root.mkdir(parents=True, exist_ok=True)
    yield root


@pytest.fixture
def client(daemon: Daemon, image_cache: pathlib.Path) -> docker.DockerClient:
    socket = daemon["socket"]
    assert isinstance(socket, pathlib.Path)
    value = docker.DockerClient(base_url=f"unix://{socket}", timeout=180, version="auto")
    value.ping()
    expected = expected_git_commit(daemon.binary)
    actual = value.version().get("GitCommit")
    if actual != expected:
        pytest.fail(
            f"cengine binary identity mismatch: expected GitCommit {expected}, daemon reports {actual} "
            f"(binary: {daemon.binary}, socket: {socket})"
        )
    for target, seed_source in fixture_image_seeds():
        try:
            value.images.get(target)
            continue
        except docker.errors.ImageNotFound:
            pass
        pulled = value.images.pull(seed_source)
        if seed_source != target:
            value.api.tag(pulled.id, repository=target)
        value.images.get(target)
    cached_content = image_cache / "content"
    if not cached_content.exists():
        temporary = image_cache / "content.tmp"
        shutil.rmtree(temporary, ignore_errors=True)
        clone_tree(daemon.root / "content", temporary)
        temporary.rename(cached_content)
    yield value
    value.close()


@pytest.fixture(autouse=True)
def verify_docker_cli_target(daemon: Daemon, client: docker.DockerClient):
    name = f"compat-target-{uuid.uuid4().hex[:8]}"
    network = client.networks.create(name, labels={"dev.cengine.compat": "true"})
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", name, "--format", "{{.Name}}"],
            env=docker_environment(daemon.socket), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )
        if result.returncode != 0 or result.stdout.strip() != name:
            pytest.fail(
                "Docker CLI did not reach the isolated cengine daemon "
                f"(binary: {daemon.binary}, socket: {daemon.socket}):\n{result.stdout}"
            )
    finally:
        try:
            network.remove()
        except docker.errors.NotFound:
            pass


@pytest.fixture(autouse=True)
def daemon_survived(daemon: Daemon, request: pytest.FixtureRequest):
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
