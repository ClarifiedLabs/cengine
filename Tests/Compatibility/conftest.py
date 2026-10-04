from __future__ import annotations

import fcntl
import io
import json
import os
import pathlib
import random
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass, field

import docker
import pytest

from helper_fixture_lifetime import FixtureBoundary

from harness import (
    COMPATIBILITY_OWNER_FILE,
    compatibility_environment,
    compatibility_image_cache_key,
    compatibility_root_retained,
    remove_compatibility_root,
    docker_environment,
    managed_docker_environment,
    retain_compatibility_root,
    preretain_compatibility_root,
    release_compatibility_root,
    terminate_compatibility_runtime,
)


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))
import compat_image_fixtures

LOCAL_COMPOSE_IDS = {"CMP-008", "CMP-009", "CMP-010"}
LOCAL_BUILDX_IDS = {"BLD-001", "BLD-003", "BLD-004", "BLD-006", "BLD-007"}
DEFAULT_BINARY = REPO_ROOT / ".build/xcode-derived/Build/Products/test-compat/cengine"
DEFAULT_KERNEL = REPO_ROOT / ".build/guest/vmlinux"
DEFAULT_CONTAINER_INITRAMFS = REPO_ROOT / ".build/guest/container-initramfs.cpio.gz"
DEFAULT_STORAGE_INITRAMFS = REPO_ROOT / ".build/guest/storage-initramfs.cpio.gz"
HELPER_FIXTURE_BOUNDARY = FixtureBoundary()
DEFAULT_IMAGE = "alpine:latest"
DEFAULT_IMAGE_SOURCE = "mirror.gcr.io/library/alpine:latest"
MULTI_PLATFORM_IMAGE_SOURCE = "mirror.gcr.io/library/alpine:latest"
MULTI_PLATFORM_FIXTURES = ["linux/arm64", "linux/amd64"]
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
    (
        "docker:29.6.2-dind",
        "mirror.gcr.io/library/docker@sha256:bfec1f5159c63a81ca6fdedbd81404d2c0e16378ed0feec3bb3fbf3998847659",
    ),
    (
        "testcontainers/ryuk:0.13.0",
        "testcontainers/ryuk@sha256:2a5038e0424aee30b8e1ecaf3889eb18b1496baca035b5cbdfeb79faa06e867a",
    ),
    # RTM-086/VOL-023 pin this image and never pull; seed it with the fixtures.
    (
        "mirror.gcr.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0",
        "mirror.gcr.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0",
    ),
]


def local_build_image_preflight(request) -> dict[str, pathlib.Path]:
    """Build tests use local fixtures; pull/uplink contracts remain online."""
    marker = request.node.get_closest_marker("compat")
    compat_id = marker.args[0] if marker and marker.args else None
    if compat_id in LOCAL_COMPOSE_IDS:
        names = ("python", "buildkit")
    elif compat_id in LOCAL_BUILDX_IDS:
        names = ("alpine", "buildkit")
    else:
        return {}
    # No helper action, daemon root, or fallback download on a missing/bad cache.
    return {name: compat_image_fixtures.verify(name) for name in names}


def seed_local_build_images(client, work: pathlib.Path) -> None:
    """Load BuildKit's shipped alias; base images travel via the build session."""
    reference = compat_image_fixtures.FIXTURES["buildkit"].removeprefix("docker.io/")
    # archive() fully verifies the root pin and selected manifest graph offline.
    # OCIContentStore.importLayout uses io.containerd.image.name as a reference,
    # including digest aliases. Do not mutate the verified cache's import index.
    with tempfile.TemporaryDirectory(prefix="compose-images-", dir=work) as temporary:
        source = pathlib.Path(temporary) / "buildkit.oci.tar"
        named = pathlib.Path(temporary) / "buildkit-named.oci.tar"
        compat_image_fixtures.archive("buildkit", source)
        with tarfile.open(source, "r:") as incoming, tarfile.open(named, "w") as outgoing:
            for member in incoming:
                if member.name == "index.json":
                    index = json.load(incoming.extractfile(member))
                    descriptor, = index["manifests"]
                    descriptor.setdefault("annotations", {})["io.containerd.image.name"] = reference
                    payload = json.dumps(index, separators=(",", ":")).encode()
                    member.size = len(payload)
                    outgoing.addfile(member, io.BytesIO(payload))
                else:
                    # Preserve every verified blob, including the upstream root-index proof.
                    outgoing.addfile(member, incoming.extractfile(member) if member.isfile() else None)
        with named.open("rb") as stream:
            for result in client.api.load_image(stream, quiet=False):
                if result.get("error") or result.get("errorDetail"):
                    raise RuntimeError(f"could not load local BuildKit fixture: {result}")
        # Fail closed before configure-docker/buildx can attempt a bootstrap pull.
        client.images.get(reference)


def fixture_image_seeds() -> list[tuple[str, str]]:
    image = os.environ.get("CENGINE_TEST_IMAGE", DEFAULT_IMAGE)
    source = os.environ.get(
        "CENGINE_TEST_IMAGE_SOURCE",
        DEFAULT_IMAGE_SOURCE if image == DEFAULT_IMAGE else image,
    )
    return [(image, source)] + FIXTURE_IMAGES


def image_cache_seeds() -> list[tuple[str, str]]:
    return fixture_image_seeds() + [
        (f"{MULTI_PLATFORM_IMAGE_SOURCE}#{platform}", MULTI_PLATFORM_IMAGE_SOURCE)
        for platform in MULTI_PLATFORM_FIXTURES
    ]


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
class ManagedDockerIntegration:
    daemon: "Daemon"
    client: docker.DockerClient
    home: pathlib.Path
    environment: dict[str, str]
    loaded_images: set[str] = field(default_factory=set)

    def run(
        self, *arguments: str, timeout: int = 300, check: bool = True,
        cwd: pathlib.Path = REPO_ROOT,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["docker", *arguments], cwd=cwd, env=self.environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
        )
        if check and result.returncode != 0:
            pytest.fail(f"docker {' '.join(arguments)} failed:\n{result.stdout}")
        return result

    def configure(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.daemon.binary.resolve()), "system", "configure-docker",
                "--socket", str(self.daemon.socket), "--home", str(self.home),
            ],
            cwd=REPO_ROOT, env=self.environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300,
        )

    def register_image(self, tag: str) -> None:
        self.loaded_images.add(tag)

    def diagnostics(self) -> str:
        commands = [
            ("context ls", ["context", "ls"]),
            ("context inspect", ["context", "inspect", "cengine"]),
            ("buildx ls", ["buildx", "ls"]),
            ("buildx inspect", ["buildx", "inspect", "cengine-builder"]),
            ("buildx du", ["--context", "cengine", "buildx", "du"]),
        ]
        sections = []
        for title, arguments in commands:
            try:
                result = self.run(*arguments, timeout=30, check=False)
                sections.append(f"{title} (exit {result.returncode}):\n{result.stdout[-8000:]}")
            except Exception as error:
                sections.append(f"{title}: {error!r}")
        buildkit = [
            value for value in self.client.containers.list(all=True)
            if value.name.startswith("buildx_buildkit_")
        ]
        for container in buildkit:
            try:
                sections.append(
                    f"{container.name} inspect:\n"
                    + json.dumps(container.attrs, sort_keys=True)[-8000:]
                )
                sections.append(
                    f"{container.name} logs:\n"
                    + container.logs(tail=200).decode(errors="replace")[-8000:]
                )
            except Exception as error:
                sections.append(f"{container.name}: {error!r}")
        sections.append(
            "sanitized client environment keys: "
            + ", ".join(sorted(self.environment))
        )
        sections.append("daemon log:\n" + self.daemon.logs()[-16000:])
        return "\n\n".join(sections)


def managed_storage_arguments(environment) -> list[str]:
    for key in ("CENGINE_COMPAT_SHARED_STORAGE", "CENGINE_COMPAT_MANAGED_STORAGE"):
        if key in environment:
            raise ValueError(f"{key} is retired; lifecycle is the default")
    if environment.get("CENGINE_STORAGE_LIFECYCLE_QUALIFICATION"):
        raise ValueError("ordinary daemon cannot use lifecycle qualification assets")
    controller = environment.get("CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY", "")
    prepare = environment.get("PREPARE_COMPATIBILITY_PROFILE", "")
    if controller or prepare:
        if controller != "rtm096-full-nine-v3" or prepare != controller or environment.get("CENGINE_COMPAT_LIFECYCLE_FAULT"):
            raise ValueError("lifecycle PREPARE requires both full-profile selections and no runtime fault")
    return []


@dataclass
class Daemon:
    binary: pathlib.Path
    owner_binary: pathlib.Path = field(init=False)
    kernel: pathlib.Path
    container_initramfs: pathlib.Path
    storage_initramfs: pathlib.Path
    work: pathlib.Path
    root: pathlib.Path = field(init=False)
    runtime: pathlib.Path = field(init=False)
    socket: pathlib.Path = field(init=False)
    log_path: pathlib.Path = field(init=False)
    resource_update_failure_file: pathlib.Path = field(init=False)
    process: subprocess.Popen[bytes] | None = field(default=None, init=False)
    _log: object | None = field(default=None, init=False)
    _retain_root: bool = field(default=False, init=False)
    _managed_fixture_retention: bool = field(default=False, init=False)
    _manual_lifecycle_start: bool = field(default=False, init=False)
    _qualify_root_permissions: bool = field(default=False, init=False)
    local_images: dict[str, pathlib.Path] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        # Runtime replacement may change binary, never the root's original
        # cleanup owner or its registered-executable authority.
        self.owner_binary = self.binary.resolve()
        self.root = self.work / "root"
        self.runtime = self.work / "run"
        self.socket = self.runtime / "docker.sock"
        self.log_path = self.work / "daemon.log"
        self.resource_update_failure_file = self.work / "resource-update-failure"
        (self.work / COMPATIBILITY_OWNER_FILE).write_text(f"{self.owner_binary}\n")
        # The helper requires a private root; create it that way, never repair
        # permissions on an existing (possibly retained) store.
        self.root.mkdir(mode=0o700)
        self.runtime.mkdir()

    def __getitem__(self, key: str):
        return {
            "work": self.work, "socket": self.socket, "log": self.log_path,
            "process": self.process,
        }[key]

    def start(self, *, on_spawn=None, qualify_lifecycle_fault=None) -> None:
        # pytest_sessionstart verifies runner ownership before any daemon fixture.
        # Validate before opening logs or removing a socket, including on restart.
        storage_arguments = managed_storage_arguments(os.environ)
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("cengine daemon is already running")
        takeover_fault = False
        cold_fault = False
        if qualify_lifecycle_fault is not None:
            from harness import compatibility_root_owned_by
            profile = os.environ.get("CENGINE_COMPAT_LIFECYCLE_FAULT")
            takeover_fault = profile in ("before-takeover-apply-v1", "after-takeover-apply-v1")
            cold_fault = profile in ("after-cold-l2-before-a1-v1", "after-first-cold-completion-v1")
            if takeover_fault or cold_fault:
                if not (
                    not self._manual_lifecycle_start and self.process is not None
                    and self._managed_fixture_retention and not self._retain_root
                    and self.root.is_dir() and not self.root.is_symlink()
                    and (not cold_fault or self.binary.resolve() == self.owner_binary)
                    and compatibility_root_owned_by(self.work, self.owner_binary)
                    and compatibility_root_retained(self.work)
                ):
                    raise ValueError("intentional restart fault requires the owned retained restart")
                root_info = self.root.stat()
                retained_identity = (self.binary, self.owner_binary, self.root, self.work, root_info.st_dev, root_info.st_ino)
            elif not (
                self._manual_lifecycle_start and self.process is None
                and self._managed_fixture_retention and not self._retain_root
                and profile == "before-configure-v1"
            ):
                raise ValueError("intentional lifecycle fault requires the owned manual first start")
        spawned_process = None
        try:
            from storage_backend_proof import capture_backend_root
            capture_backend_root(self.root, "lifecycle")
            if self._qualify_root_permissions:
                if not self._managed_fixture_retention or self._retain_root:
                    raise ValueError("root permission fault requires the owned active fixture")
                # Pin the private directory first, then inject the regression on
                # each RTM-122 start. Only the engine may tighten it again.
                self.root.chmod(0o755)
                assert self.root.stat().st_mode & 0o7777 == 0o755
            self.socket.unlink(missing_ok=True)
            self._log = self.log_path.open("ab")
            environment = compatibility_environment()
            environment["CENGINE_COMPAT_RESOURCE_UPDATE_FAILURE_FILE"] = str(
                self.resource_update_failure_file
            )
            self.process = subprocess.Popen(
                [str(self.binary), "daemon", "--root", str(self.root), "--socket", str(self.socket),
                 "--kernel", str(self.kernel), "--container-initramfs", str(self.container_initramfs),
                 "--storage-initramfs", str(self.storage_initramfs),
                 "--automatic-ipv4-pool", environment.get(
                     "CENGINE_COMPAT_IPV4_AUTO_POOL", "10.192.0.0/12"
                 ),
                 "--automatic-ipv6-prefix", environment.get(
                     "CENGINE_COMPAT_IPV6_AUTO_PREFIX", "fdcc::/16"
                 ), *storage_arguments],
                stdin=subprocess.DEVNULL, stdout=self._log, stderr=subprocess.STDOUT,
                env=environment,
            )
            spawned_process = self.process
            # Passive fault-fixture observation of this actual child, before
            # readiness/reconciliation can hide the birth-versus-exit ordering.
            if on_spawn is not None:
                on_spawn()
            if qualify_lifecycle_fault is not None:
                if takeover_fault:
                    # The sealed pause is before API readiness. The callback must
                    # observe it alive and kill only this owned child via stop().
                    if self.process is not spawned_process or spawned_process.poll() is not None:
                        raise RuntimeError("intentional takeover fault child is not alive")
                    qualified = qualify_lifecycle_fault(self)
                    if (qualified is not True or self.process is not spawned_process
                            or spawned_process.poll() != -9):
                        raise RuntimeError("intentional takeover fault was not qualified")
                else:
                    # Observe natural exit BEFORE generic failure cleanup can signal
                    # any process. A timeout, signal, success, or unqualified fault
                    # follows the ordinary permanent-retention failure path below.
                    if self.process is not spawned_process:
                        raise RuntimeError("intentional fault child was replaced")
                    returncode = spawned_process.wait(timeout=60)
                    if (returncode <= 0 or qualify_lifecycle_fault(self) is not True
                            or self.process is not spawned_process or spawned_process.poll() != returncode):
                        raise RuntimeError("intentional lifecycle startup fault was not qualified")
                if cold_fault:
                    info = self.root.stat()
                    if (retained_identity != (self.binary, self.owner_binary, self.root, self.work, info.st_dev, info.st_ino)
                            or self.root.is_symlink() or self._manual_lifecycle_start
                            or not self._managed_fixture_retention or self._retain_root
                            or not compatibility_root_owned_by(self.work, self.owner_binary)
                            or not compatibility_root_retained(self.work)):
                        raise RuntimeError("intentional cold fault changed retained ownership")
                # A takeover callback's stop(kill=True) already closed this log.
                if self._log is not None:
                    self._log.close()
                    self._log = None
                return
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
            raise RuntimeError("cengine daemon did not become ready")
        except BaseException:
            # A rejected callback must never redirect stop() at another process,
            # even when it replaced self.process before raising an exception.
            if qualify_lifecycle_fault is not None and spawned_process is not None:
                self.process = spawned_process
            if cold_fault and spawned_process is not None:
                # Never let a rejected callback redirect cleanup ownership.
                self.binary, self.owner_binary, self.root, self.work = retained_identity[:4]
            # Every daemon is lifecycle-backed. Latch before any fallible cleanup.
            try:
                self.retain_root(reason="unsafe-disk-phase")
            except Exception:
                pass  # retain_root already latched, including on marker ENOSPC.
            cleanup_failed = False
            try:
                try:
                    self.stop()
                finally:
                    terminate_compatibility_runtime(self.owner_binary, roots=(self.root,))
            except Exception:
                cleanup_failed = True
            # Logs, readiness responses, and exception text can contain boot secrets.
            # Keep the evidence on disk; report only metadata, even on cleanup faults.
            message = f"cengine daemon startup failed; root retained: {self.work}"
            if cleanup_failed:
                message += "; process cleanup incomplete"
            pytest.fail(message, pytrace=False)

    def stop(self, *, kill: bool = False) -> None:
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.kill() if kill else self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            if self._log is not None:
                self._log.close()
                self._log = None

    def restart(self, *, kill: bool = False) -> None:
        self.stop(kill=kill)
        self.start()

    def publish_resource_update_failure(
        self, *, container_id: str, failure_after_writes: int,
    ) -> None:
        if not container_id or failure_after_writes <= 0:
            raise ValueError("container_id and a positive failure_after_writes are required")
        temporary = self.resource_update_failure_file.with_name(
            f".{self.resource_update_failure_file.name}.{uuid.uuid4().hex}.tmp"
        )
        lock_path = self.resource_update_failure_file.with_suffix(
            self.resource_update_failure_file.suffix + ".lock"
        )
        try:
            temporary.write_text(json.dumps({
                "containerID": container_id,
                "failureAfterWrites": failure_after_writes,
            }, separators=(",", ":")))
            temporary.chmod(0o600)
            with lock_path.open("a+b") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                os.replace(temporary, self.resource_update_failure_file)
                fcntl.flock(lock, fcntl.LOCK_UN)
        finally:
            temporary.unlink(missing_ok=True)

    @property
    def root_retained(self) -> bool:
        return (self._retain_root or self._managed_fixture_retention
                or compatibility_root_retained(self.work))

    def retain_root(self, *, reason: str) -> None:
        # Latch first: even ENOSPC writing the durable marker must not let this
        # fixture delete forensic disks and logs during generic teardown.
        self._retain_root = True
        retain_compatibility_root(self.work, self.owner_binary, reason=reason)

    def logs(self) -> str:
        return self.log_path.read_text(errors="replace") if self.log_path.exists() else ""


def pytest_sessionstart(session: pytest.Session) -> None:
    root_value = os.environ.get("CENGINE_COMPAT_CLIENT_STATE_ROOT")
    run_id = os.environ.get("CENGINE_COMPAT_RUN_ID")
    owner_pid = os.environ.get("CENGINE_COMPAT_OWNER_PID")
    docker_value = os.environ.get("DOCKER_CONFIG")
    buildx_value = os.environ.get("BUILDX_CONFIG")
    if not all((root_value, run_id, owner_pid, docker_value, buildx_value)):
        pytest.exit(
            "compatibility tests require runner-owned DOCKER_CONFIG and BUILDX_CONFIG; "
            "use make test-compat",
            returncode=2,
        )

    root = pathlib.Path(root_value).absolute()
    docker_config = pathlib.Path(docker_value).absolute()
    buildx_config = pathlib.Path(buildx_value).absolute()
    owner_file = root / ".owner-pid"
    expected_owner = f"{run_id} {owner_pid}\n"
    try:
        owner_mode = owner_file.stat(follow_symlinks=False).st_mode
        owner_matches = stat.S_ISREG(owner_mode) and owner_file.read_text() == expected_owner
        os.kill(int(owner_pid), 0)
    except (OSError, ValueError):
        owner_matches = False
    if (
        not re.fullmatch(r"[0-9a-f]{64}", run_id)
        or root.is_symlink()
        or not root.is_dir()
        or docker_config != root / "docker"
        or buildx_config != root / "buildx"
        or docker_config.is_symlink()
        or buildx_config.is_symlink()
        or not docker_config.is_dir()
        or not buildx_config.is_dir()
        or not owner_matches
    ):
        pytest.exit(
            "compatibility Docker/Buildx state is not owned by the invoking runner",
            returncode=2,
        )


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    seed = os.environ.get("CENGINE_TEST_SEED")
    if seed is not None:
        random.Random(int(seed)).shuffle(items)
        print(f"compatibility test order seed: {seed}")


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    outcome = yield
    setattr(item, f"report_{call.when}", outcome.get_result())
    pending = getattr(item, "_managed_root_cleanup", None)
    remount = getattr(item, "_managed_remount_cleanup", None)
    if call.when != "teardown" or (pending is None and remount is None):
        return
    # Fixture finally runs before the teardown report (and other finalizers).
    # Run outside pytest's xfail wrapper so these are the final outcomes. Only a
    # call-phase expected XFAIL may substitute for a pass; skips, setup/teardown
    # xfails, XPASS (including non-strict), and missing reports retain evidence.
    if remount is not None:
        from storage_lifecycle_v2_remount import OfflineRemount
        if type(remount) is not OfflineRemount or pending is not None:
            return  # Never fall through to recursive generic cleanup.
        value, receipt = remount.value, remount.retention
    else:
        value, receipt = pending
    call_report = getattr(item, "report_call", None)
    call_completed = (
        getattr(call_report, "passed", False) and not hasattr(call_report, "wasxfail")
    ) or (
        getattr(call_report, "skipped", False)
        and isinstance(getattr(call_report, "wasxfail", None), str)
    )
    if value._retain_root or not call_completed or not all(
        getattr(getattr(item, f"report_{phase}", None), "passed", False)
        and not hasattr(getattr(item, f"report_{phase}", None), "wasxfail")
        for phase in ("setup", "teardown")
    ):
        return
    try:
        if remount is not None:
            # RTM-126 has no expected-failure contract: all three phases must pass.
            if getattr(call_report, "passed", False) and not hasattr(call_report, "wasxfail"):
                remount.final_cleanup()
            return
        if release_compatibility_root(value.work, value.owner_binary, receipt):
            if remove_compatibility_root(value.work, value.owner_binary):
                value._managed_fixture_retention = False
    except Exception:
        # Unknown marker/root state is not cleanup authority.
        if remount is not None:
            value._retain_root = True
        print(f"\ncengine compatibility root cleanup refused: {value.work}")


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
                command, env=compatibility_environment(), text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
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
    local_images = local_build_image_preflight(request)
    start_mode = getattr(request, "param", "automatic")
    if start_mode not in ("automatic", "lifecycle-first-start", "lifecycle-root-permissions"):
        raise ValueError("unknown daemon fixture start mode")
    repair_root = start_mode == "lifecycle-root-permissions"
    if repair_root and request.node.get_closest_marker("compat").args != ("RTM-122",):
        raise ValueError("root permission fixture is restricted to RTM-122")
    manual = start_mode == "lifecycle-first-start"
    if manual and not (
        request.node.get_closest_marker("compat").args == ("RTM-119",)
        and managed_storage_arguments(os.environ) == []
        and os.environ.get("CENGINE_COMPAT_LIFECYCLE_FAULT") == "before-configure-v1"
    ):
        raise ValueError("manual lifecycle startup is restricted to RTM-119")
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

    managed_storage_arguments(os.environ)
    try:
        HELPER_FIXTURE_BOUNDARY.prepare(binary)
    except Exception:
        # No root exists yet. Never retry an ambiguous helper restart or expose
        # status/argv/token-bearing subprocess diagnostics.
        pytest.fail("test helper fixture isolation refused; no root created", pytrace=False)
    work = pathlib.Path(tempfile.mkdtemp(prefix="cengine-compat-"))
    value = Daemon(binary=binary, kernel=kernel, container_initramfs=container_initramfs,
                   storage_initramfs=storage_initramfs, work=work)
    value.local_images = local_images
    HELPER_FIXTURE_BOUNDARY.created(value)
    receipt = None
    managed_storage_arguments(os.environ)
    try:
        receipt = preretain_compatibility_root(work, value.owner_binary)
        value._managed_fixture_retention = True
    except Exception:
        # No engine, clone/build, or runtime-cleanup call is allowed before
        # durable publication. An empty newly-created root may remain.
        pytest.fail(f"could not pre-retain managed compatibility root: {work}", pytrace=False)
    fixture_completed = False
    try:
        cached_content = image_cache / "content"
        if not local_images and cached_content.is_dir():
            clone_tree(cached_content, value.root / "content")
        value._manual_lifecycle_start = manual
        value._qualify_root_permissions = repair_root
        if not manual:
            value.start()
        yield value
        fixture_completed = True
    finally:
        cleanup_failed = False
        try:
            value.stop()
        except Exception:
            if receipt is None and not value.root_retained:
                raise
            value._retain_root = True
            cleanup_failed = True
        failed = any(
            getattr(request.node, f"report_{phase}", None) is not None
            and getattr(request.node, f"report_{phase}").failed
            for phase in ("setup", "call", "teardown")
        )
        retained = receipt is not None or value.root_retained
        if retained:
            # Legacy boot arguments may contain secrets; keep logs on disk only.
            print(f"\ncengine compatibility root retained: {work}")
        else:
            if failed:
                lines = value.logs().splitlines()
                print("\ncengine daemon log (last 200 lines):\n" + "\n".join(lines[-200:]))
            if value.process is not None and value.process.returncode not in (-15, -9, 0):
                print("\ncengine daemon log:\n" + value.logs())
        try:
            terminate_compatibility_runtime(value.owner_binary, roots=(value.root,))
        except Exception:
            if receipt is None and not value.root_retained:
                raise
            value._retain_root = True
            cleanup_failed = True
        if cleanup_failed:
            pytest.fail(
                f"cengine process cleanup incomplete; root retained: {work}", pytrace=False,
            )
        if (receipt is not None and fixture_completed and not value._retain_root
                and value.process is not None and value.process.poll() is not None):
            # Both stop and owned runtime termination succeeded. Keep the marker
            # until pytest has observed every setup/call/teardown finalizer.
            request.node._managed_root_cleanup = (value, receipt)
        if receipt is None and not value.root_retained:
            remove_compatibility_root(work, value.owner_binary)


@pytest.fixture
def managed_docker_integration(
    daemon: Daemon, client: docker.DockerClient, request: pytest.FixtureRequest,
) -> ManagedDockerIntegration:
    home = daemon.work / "managed-home"
    settings = home / "Library/Application Support/cengine/builder-settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"cpus":2,"memoryGiB":2}\n')
    environment = managed_docker_environment()
    value = ManagedDockerIntegration(
        daemon=daemon, client=client, home=home, environment=environment,
    )
    assert value.run("context", "show").stdout.strip() == "default"
    try:
        configured = value.configure()
        if configured.returncode != 0:
            pytest.fail(
                "the shipped configure-docker command failed:\n"
                f"{configured.stdout}\n\n{value.diagnostics()}"
            )
        yield value
    finally:
        errors: list[str] = []
        for tag in value.loaded_images:
            try:
                client.images.remove(tag, force=True)
            except docker.errors.ImageNotFound:
                pass
            except Exception as error:
                errors.append(f"could not remove image {tag}: {error}")
        builder_removals = {
            builder: value.run(
                "buildx", "rm", "--force", builder, timeout=60, check=False,
            )
            for builder in ("cengine-builder", "default")
        }
        leaked_containers = sorted(
            container.name for container in client.containers.list(all=True)
            if container.name.startswith("buildx_buildkit_")
        )
        leaked_volumes = sorted(
            volume.name for volume in client.volumes.list()
            if volume.name.startswith("buildx_buildkit_")
        )
        instances = pathlib.Path(value.environment["BUILDX_CONFIG"]) / "instances"
        leaked_builders = [
            builder for builder in ("cengine-builder", "default")
            if (instances / builder).exists()
        ]
        context_removal = value.run(
            "context", "rm", "-f", "cengine", timeout=60, check=False,
        )
        context_leaked = (
            value.run("context", "inspect", "cengine", check=False).returncode == 0
        )
        if leaked_containers:
            errors.append(f"managed BuildKit containers leaked: {leaked_containers}")
        if leaked_volumes:
            errors.append(f"managed BuildKit volumes leaked: {leaked_volumes}")
        if leaked_builders:
            errors.append(f"managed Buildx records leaked: {leaked_builders}")
        if context_leaked:
            errors.append("cengine Docker context record leaked")
        if leaked_containers or leaked_volumes or leaked_builders:
            for builder, removal in builder_removals.items():
                if removal.returncode != 0:
                    errors.append(
                        f"docker buildx rm --force {builder} failed: {removal.stdout}"
                    )
        if context_removal.returncode != 0 and context_leaked:
            errors.append(
                f"docker context rm -f cengine failed: {context_removal.stdout}"
            )
        shutil.rmtree(home, ignore_errors=True)
        if home.exists():
            errors.append(f"managed cengine home leaked at {home}")
        if errors:
            diagnostics = value.diagnostics()
            message = "managed Docker integration cleanup failed:\n" + "\n".join(errors)
            report = getattr(request.node, "report_call", None)
            if report is not None and report.failed:
                print(f"\n{message}\n\n{diagnostics}")
            else:
                pytest.fail(f"{message}\n\n{diagnostics}")


@pytest.fixture(scope="session")
def image_cache():
    key = compatibility_image_cache_key(image_cache_seeds())
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
    if daemon.local_images:
        try:
            seed_local_build_images(value, daemon.work)
            yield value
        finally:
            value.close()
        return
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
    for platform in MULTI_PLATFORM_FIXTURES:
        encoded = {"os": platform.split("/")[0], "architecture": platform.split("/")[1]}
        response = value.api._get(
            value.api._url("/images/{0}/json", MULTI_PLATFORM_IMAGE_SOURCE),
            params={"platform": json.dumps(encoded, separators=(",", ":"))},
        )
        if response.status_code == 200:
            continue
        messages = list(value.api.pull(
            MULTI_PLATFORM_IMAGE_SOURCE, platform=platform, stream=True, decode=True,
        ))
        errors = [message for message in messages if message.get("error")]
        if errors:
            pytest.fail(f"could not seed {MULTI_PLATFORM_IMAGE_SOURCE} for {platform}: {errors}")
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
    if daemon.process is not None and daemon.process.poll() is None:
        return
    if daemon.root_retained:
        message = f"cengine daemon exited during the test; root retained: {daemon.work}"
        report = getattr(request.node, "report_call", None)
        if report is not None and report.failed:
            # The failed raw-disk phase deliberately leaves the daemon stopped.
            print("\n" + message)
            return
        pytest.fail(message)
    pytest.fail("cengine daemon exited during the test:\n" + daemon.logs())


@pytest.fixture
def top(client: docker.DockerClient):
    image = os.environ.get("CENGINE_TEST_IMAGE", DEFAULT_IMAGE)
    container = client.containers.create(
        image=image, command="top", detach=True, tty=True, name=f"top-{uuid.uuid4().hex[:8]}"
    )
    container.start()
    return container
