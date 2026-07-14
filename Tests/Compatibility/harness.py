from __future__ import annotations

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


def control_plane_status_is_ready(exit_code: int, output: bytes | str) -> bool:
    if exit_code != 0:
        return False
    if isinstance(output, bytes):
        output = output.decode(errors="replace")
    statuses = output.split()
    return bool(statuses) and all(status == "True" for status in statuses)


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


def docker_environment(
    host: str | pathlib.Path, *, base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = dict(os.environ if base is None else base)
    for key in DOCKER_ENDPOINT_VARIABLES:
        environment.pop(key, None)
    value = str(host)
    environment["DOCKER_HOST"] = value if "://" in value else f"unix://{value}"
    return environment
