from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import signal
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass


DOCKER_ENDPOINT_VARIABLES = (
    "DOCKER_API_VERSION",
    "DOCKER_CERT_PATH",
    "DOCKER_CONTEXT",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
)


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


def compatibility_runtime_processes(
    binary: pathlib.Path,
    *,
    roots: tuple[pathlib.Path, ...] = (),
    process_table: str | None = None,
) -> list[RuntimeProcess]:
    binary_prefix = f"{binary.resolve()} "
    root_markers = tuple(dict.fromkeys(
        marker
        for root in roots
        for marker in (str(root.absolute()), str(root.resolve()))
    ))
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
        if not command.startswith(binary_prefix):
            continue
        if " daemon " not in f" {command} " and " vm-shim " not in f" {command} ":
            continue
        if root_markers:
            if not any(marker in command for marker in root_markers):
                continue
        elif "cengine-compat-" not in command:
            continue
        matches.append(RuntimeProcess(pid=int(fields[0]), command=command))
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
    for key in DOCKER_ENDPOINT_VARIABLES:
        environment.pop(key, None)
    return environment


def docker_environment(
    host: str | pathlib.Path, *, base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = compatibility_environment(base=base)
    value = str(host)
    environment["DOCKER_HOST"] = value if "://" in value else f"unix://{value}"
    return environment
