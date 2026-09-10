from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TypeVar


DOCKER_ENDPOINT_VARIABLES = (
    "DOCKER_API_VERSION",
    "DOCKER_CERT_PATH",
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
    "BUILDX_BUILDER",
    "CONTAINER_HOST",
)
DOCKER_AMBIENT_CONFIG_VARIABLES = ("DOCKER_AUTH_CONFIG",)
T = TypeVar("T")


def compatibility_fixture_ipv4(
    subnet: int, host: int = 0, *, prefix: int | None = 24,
) -> str:
    pool = ipaddress.ip_network(
        os.environ.get("CENGINE_COMPAT_IPV4_FIXTURE_POOL", "10.208.0.0/12"),
        strict=True,
    )
    if pool.version != 4 or pool.prefixlen != 12 or not 0 <= subnet < 4096:
        raise ValueError("the compatibility IPv4 fixture pool must be a /12")
    address = pool.network_address + subnet * 256 + host
    return str(address) if prefix is None else f"{address}/{prefix}"


def compatibility_fixture_ipv6(
    subnet: int, host: int = 0, *, prefix: int | None = 64,
) -> str:
    pool = ipaddress.ip_network(
        os.environ.get("CENGINE_COMPAT_IPV6_FIXTURE_PREFIX", "fdcd::/16"),
        strict=True,
    )
    if pool.version != 6 or pool.prefixlen != 16 or not 0 <= subnet <= 0xFFFF:
        raise ValueError("the compatibility IPv6 fixture pool must be a /16")
    address = pool.network_address + (subnet << 96) + host
    return str(address) if prefix is None else f"{address}/{prefix}"


def compatibility_image_cache_key(seeds: list[tuple[str, str]]) -> str:
    encoded = json.dumps(seeds, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]


def wait_for_value(
    probe: Callable[[], T],
    predicate: Callable[[T], bool],
    *,
    timeout: float,
    interval: float = 0.2,
    description: str = "condition",
) -> T:
    deadline = time.monotonic() + timeout
    last_value: T | None = None
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            last_value = probe()
            last_error = None
            if predicate(last_value):
                return last_value
        except Exception as error:  # The caller receives the last bounded diagnostic.
            last_error = error
        time.sleep(interval)
    detail = f"last value: {last_value!r}"
    if last_error is not None:
        detail = f"last exception: {last_error!r}"
    raise TimeoutError(f"timed out waiting for {description} ({detail})")


def control_plane_status_is_ready(exit_code: int, output: bytes | str) -> bool:
    if exit_code != 0:
        return False
    if isinstance(output, bytes):
        output = output.decode(errors="replace")
    statuses = output.split()
    return bool(statuses) and all(status == "True" for status in statuses)


def persisted_container_record(state: Mapping[str, object], container_id: str) -> dict:
    """Read a container from AtomicStore's `{schemaVersion,value}` envelope."""
    value = state.get("value")
    if not isinstance(value, Mapping):
        raise AssertionError("engine state is missing the AtomicStore value envelope")
    containers = value.get("containers")
    if not isinstance(containers, list):
        raise AssertionError("engine state value has no container list")
    return next(
        item for item in containers
        if isinstance(item, dict) and item.get("id") == container_id
    )


COMPATIBILITY_OWNER_FILE = ".cengine-compat-owner"
COMPATIBILITY_EXECUTABLES_FILE = ".cengine-compat-executables.json"
VMNET_TEARDOWN_SETTLE_SECONDS = 2.0


@dataclass(frozen=True)
class RuntimeProcess:
    pid: int
    command: str


def compatibility_root_owned_by(directory: pathlib.Path, binary: pathlib.Path) -> bool:
    try:
        owner = (directory / COMPATIBILITY_OWNER_FILE).read_text().strip()
    except OSError:
        return False
    return pathlib.Path(owner).resolve() == binary.resolve()


def compatibility_registered_executables(
    directory: pathlib.Path, binary: pathlib.Path,
) -> tuple[pathlib.Path, ...]:
    """Read staged executables without transferring the original root ownership."""
    if not compatibility_root_owned_by(directory, binary):
        return ()
    registry = directory / COMPATIBILITY_EXECUTABLES_FILE
    if registry.is_symlink():
        raise ValueError(f"compatibility executable registry must not be a symlink: {registry}")
    try:
        entries = json.loads(registry.read_text())
    except FileNotFoundError:
        return ()
    if not isinstance(entries, list) or not all(isinstance(entry, str) for entry in entries):
        raise ValueError(f"invalid compatibility executable registry: {registry}")
    directory = directory.resolve()
    if (directory / "root").resolve() != directory / "root":
        raise ValueError(f"compatibility engine root escapes owned directory: {directory}")
    executables = []
    for entry in entries:
        relative = pathlib.Path(entry)
        executable = directory / relative
        if (relative.is_absolute() or ".." in relative.parts or not relative.parts
                or executable.resolve() != executable):
            raise ValueError(f"staged executable escapes owned directory: {entry}")
        executables.append(executable)
    return tuple(executables)


def register_compatibility_executable(
    directory: pathlib.Path, binary: pathlib.Path, executable: pathlib.Path,
) -> None:
    """Atomically register before launch; keep registration until the root is removed."""
    if not compatibility_root_owned_by(directory, binary):
        raise ValueError(f"compatibility directory is not owned by {binary}: {directory}")
    registered = compatibility_registered_executables(directory, binary)
    directory = directory.resolve()
    executable = executable.resolve()
    relative = executable.relative_to(directory)
    if not relative.parts or not executable.is_file():
        raise ValueError(f"staged executable must be a file under {directory}: {executable}")
    entries = [str(value.relative_to(directory)) for value in registered]
    if str(relative) in entries:
        return
    entries.append(str(relative))
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=directory, delete=False) as stream:
            temporary = pathlib.Path(stream.name)
            json.dump(entries, stream)
        os.replace(temporary, directory / COMPATIBILITY_EXECUTABLES_FILE)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _runtime_command_has_root(command: str, root_markers: tuple[str, ...]) -> bool:
    # The CLI consumes the first flag. Never let a later decoy establish ownership.
    for flag in ("--root", "--spec"):
        if len(re.findall(r"(?:^|\s)" + flag + r"(?=\s|=|$)", command)) > 1:
            return False
    for marker in root_markers:
        if command.startswith("daemon "):
            if re.search(r"(?:^| )--root " + re.escape(marker) + r"(?: |$)", command):
                return True
        elif command.startswith(f"vm-shim --spec {marker}/"):
            suffix = command[len(f"vm-shim --spec {marker}/"):].split(" ", 1)[0]
            if suffix and ".." not in pathlib.Path(suffix).parts:
                return True
    return False


def _runtime_executable_spellings(executable: pathlib.Path) -> tuple[str, ...]:
    canonical = str(executable.resolve())
    # Foundation launches shims using /var even when Python launched their
    # parent via /private/var. Accept only this verified macOS filesystem alias.
    if (canonical.startswith("/private/var/")
            and pathlib.Path("/var").resolve() == pathlib.Path("/private/var")):
        return canonical, canonical.removeprefix("/private")
    return (canonical,)


def compatibility_runtime_processes(
    binary: pathlib.Path,
    *,
    roots: tuple[pathlib.Path, ...] = (),
    process_table: str | None = None,
) -> list[RuntimeProcess]:
    candidates = (
        {root.parent for root in roots if root.name == "root"}
        if roots else pathlib.Path(tempfile.gettempdir()).glob("cengine-compat-*")
    )
    directories = [
        directory for directory in candidates
        if directory.is_dir() and compatibility_root_owned_by(directory, binary)
    ]
    targets = [(binary, roots or tuple(directory / "root" for directory in directories))]
    for directory in directories:
        for executable in compatibility_registered_executables(directory, binary):
            targets.append((executable, (directory / "root",)))
    prefixes = [
        (f"{spelling} ", tuple(dict.fromkeys(
            marker
            for root in target_roots
            for marker in (str(root.absolute()), str(root.resolve()))
        )))
        for executable, target_roots in targets
        for spelling in _runtime_executable_spellings(executable)
    ]
    if process_table is None:
        process_table = subprocess.run(
            ["ps", "-axo", "pid=,command="],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout

    matches: list[RuntimeProcess] = []
    for line in process_table.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2 or not fields[0].isdigit():
            continue
        command = fields[1]
        for binary_prefix, root_markers in prefixes:
            if not command.startswith(binary_prefix):
                continue
            arguments = command[len(binary_prefix):]
            if not arguments.startswith(("daemon ", "vm-shim ")):
                continue
            if not _runtime_command_has_root(arguments, root_markers):
                continue
            matches.append(RuntimeProcess(pid=int(fields[0]), command=command))
            break
    return matches


def terminate_compatibility_runtime(
    binary: pathlib.Path,
    *,
    roots: tuple[pathlib.Path, ...] = (),
    timeout: float = 5.0,
) -> list[RuntimeProcess]:
    processes = compatibility_runtime_processes(binary, roots=roots)
    for process in processes:
        try:
            os.kill(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    deadline = time.monotonic() + timeout
    remaining = compatibility_runtime_processes(binary, roots=roots)
    while remaining and time.monotonic() < deadline:
        time.sleep(0.05)
        remaining = compatibility_runtime_processes(binary, roots=roots)
    for process in remaining:
        try:
            os.kill(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    deadline = time.monotonic() + timeout
    remaining = compatibility_runtime_processes(binary, roots=roots)
    while remaining and time.monotonic() < deadline:
        time.sleep(0.05)
        remaining = compatibility_runtime_processes(binary, roots=roots)
    if remaining:
        detail = "\n".join(f"  {value.pid} {value.command}" for value in remaining)
        raise RuntimeError(f"could not terminate compatibility runtime processes:\n{detail}")
    if processes:
        # The shim can exit before vmnet and InternetSharing finish releasing the
        # network reservation owned by its now-closed XPC session.
        time.sleep(VMNET_TEARDOWN_SETTLE_SECONDS)
    return processes


def compatibility_environment(*, base: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ if base is None else base)
    for key in DOCKER_ENDPOINT_VARIABLES + DOCKER_AMBIENT_CONFIG_VARIABLES:
        environment.pop(key, None)
    return environment


def managed_docker_environment(
    *, base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return isolated client state without selecting a Docker endpoint or builder."""
    return compatibility_environment(base=base)


def docker_environment(
    host: str | pathlib.Path, *, base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = compatibility_environment(base=base)
    value = str(host)
    environment["DOCKER_HOST"] = value if "://" in value else f"unix://{value}"
    return environment
