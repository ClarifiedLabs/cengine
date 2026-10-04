from __future__ import annotations

from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import stat
import struct
import sys
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
COMPATIBILITY_RETAIN_FILE = ".cengine-compat-retain"
VMNET_TEARDOWN_SETTLE_SECONDS = 2.0


@dataclass(frozen=True)
class RuntimeProcess:
    pid: int
    command: str = ""  # Synthetic process-table tests only; never print argv.
    executable: str = ""
    arguments: tuple[str, ...] = ()
    identity: tuple[int, int, int] | None = None  # start sec/usec + kernel uniqueid
    pidversion: int | None = None
    parent_pid: int | None = None  # Kernel lineage, bracketed by the birth snapshots.


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


def compatibility_root_retained(directory: pathlib.Path) -> bool:
    # Even a malformed or symlink marker must prevent automatic deletion.
    try:
        (directory / COMPATIBILITY_RETAIN_FILE).lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True  # Unknown marker state is never permission to delete.
    return True


@contextmanager
def _compatibility_root_claim(directory: pathlib.Path, binary: pathlib.Path):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("unsafe compatibility root")
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        # Lock the directory inode itself: no removable lock sidecar/generation.
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pinned, visible = os.fstat(parent), directory.lstat()
        if (pinned.st_dev, pinned.st_ino) != (visible.st_dev, visible.st_ino):
            raise RuntimeError("compatibility root changed during cleanup claim")
        if not compatibility_root_owned_by(directory, binary):
            raise RuntimeError("unowned compatibility root")
        yield parent
    finally:
        os.close(parent)


def retain_compatibility_root(directory: pathlib.Path, binary: pathlib.Path, *, reason: str) -> None:
    if reason not in ("unsafe-disk-phase", "cleanup-incomplete"):
        raise ValueError("unknown compatibility retention reason")
    with _compatibility_root_claim(directory, binary) as parent:
        try:
            fd = os.open(COMPATIBILITY_RETAIN_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        except FileExistsError:
            # An explicit retention request from another process must also
            # invalidate the creating fixture's receipt, without allocating a
            # second file or changing existing forensic marker contents.
            fd = os.open(COMPATIBILITY_RETAIN_FILE, os.O_RDONLY | os.O_NOFOLLOW
                         | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            try:
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    os.fchmod(fd, 0o400)
                    os.fsync(fd)
            finally:
                os.close(fd)
            return
        try:
            data = json.dumps({"schemaVersion": 1, "reason": reason}).encode() + b"\n"
            if os.write(fd, data) != len(data):
                raise OSError(errno.EIO, "short retention marker write")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)


@dataclass(frozen=True)
class CompatibilityRootRetention:
    root_identity: tuple[int, int]
    marker_identity: tuple[int, int, int]
    contents: bytes


def preretain_compatibility_root(
    directory: pathlib.Path, binary: pathlib.Path,
) -> CompatibilityRootRetention:
    """Publish before any managed fixture side effects; never adopt an old marker."""
    contents = b'{"schemaVersion":1,"reason":"managed-fixture-active"}\n'
    with _compatibility_root_claim(directory, binary) as parent:
        root = os.fstat(parent)
        fd = os.open(COMPATIBILITY_RETAIN_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            if os.write(fd, contents) != len(contents):
                raise OSError(errno.EIO, "short retention marker write")
            os.fsync(fd)
            marker = os.fstat(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
        return CompatibilityRootRetention(
            (root.st_dev, root.st_ino),
            (marker.st_dev, marker.st_ino, marker.st_ctime_ns), contents,
        )


def release_compatibility_root(
    directory: pathlib.Path, binary: pathlib.Path, receipt: CompatibilityRootRetention,
) -> bool:
    """Only the creating fixture can release its unchanged pre-retention marker."""
    with _compatibility_root_claim(directory, binary) as parent:
        root = os.fstat(parent)
        if (root.st_dev, root.st_ino) != receipt.root_identity:
            return False
        fd = os.open(COMPATIBILITY_RETAIN_FILE, os.O_RDONLY | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            marker = os.fstat(fd)
            if (not stat.S_ISREG(marker.st_mode) or marker.st_uid != os.getuid()
                    or stat.S_IMODE(marker.st_mode) != 0o600 or marker.st_nlink != 1
                    or (marker.st_dev, marker.st_ino, marker.st_ctime_ns) != receipt.marker_identity
                    or os.read(fd, len(receipt.contents) + 1) != receipt.contents):
                return False
            visible = os.stat(COMPATIBILITY_RETAIN_FILE, dir_fd=parent, follow_symlinks=False)
            if (visible.st_dev, visible.st_ino, visible.st_ctime_ns) != receipt.marker_identity:
                return False
            # Release is the final marker operation, authorized only after a
            # clean fixture and proven runtime exit. Do not require a fallible
            # post-unlink fsync: a crash restoring the marker safely over-retains.
            os.unlink(COMPATIBILITY_RETAIN_FILE, dir_fd=parent)
            return True
        finally:
            os.close(fd)


def remove_compatibility_root(directory: pathlib.Path, binary: pathlib.Path) -> bool:
    with _compatibility_root_claim(directory, binary):
        if compatibility_root_retained(directory):
            return False
        shutil.rmtree(directory)
        return True


def _kernel_process(pid: int, binary: pathlib.Path | None = None) -> RuntimeProcess | None:
    """Darwin kernel executable/argv, bracketed by complete birth snapshots."""
    if sys.platform != "darwin":
        raise RuntimeError("compatibility runtime ownership requires Darwin process identity")
    native = ctypes.CDLL(None, use_errno=True)
    def pidinfo(flavor, size):
        buffer = ctypes.create_string_buffer(size)
        count = native.proc_pidinfo(pid, flavor, ctypes.c_uint64(0), buffer, size)
        if count != size:
            code = ctypes.get_errno() if count <= 0 else errno.EIO
            raise OSError(code, "kernel process identity unavailable")
        return buffer.raw
    def birth():
        before = pidinfo(17, 56)  # PROC_PIDUNIQIDENTIFIERINFO, uniqueid at 16.
        bsd = pidinfo(3, 136)  # proc_bsdinfo: pid at 12, uid at 20, start at 120.
        after = pidinfo(17, 56)
        unique = struct.unpack_from("=Q", before, 16)[0]
        seconds, micros = struct.unpack_from("=QQ", bsd, 120)
        if (unique == 0 or unique != struct.unpack_from("=Q", after, 16)[0]
                or struct.unpack_from("=I", bsd, 12)[0] != pid or seconds == 0 or micros >= 1_000_000):
            raise OSError(errno.EIO, "inconsistent kernel process identity")
        version = struct.unpack_from("=I", before, 32)[0]
        if version == 0 or version != struct.unpack_from("=I", after, 32)[0]:
            raise OSError(errno.EIO, "inconsistent kernel PID version")
        return (seconds, micros, unique, version, struct.unpack_from("=I", bsd, 16)[0])
    try:
        path = ctypes.create_string_buffer(4096)
        length = native.proc_pidpath(pid, path, len(path))
        if length <= 0:
            raise OSError(ctypes.get_errno(), "kernel executable unavailable")
        executable = os.fsdecode(path.value)
        if not pathlib.Path(executable).is_absolute():
            raise OSError(errno.EIO, "invalid kernel executable")
        if binary is not None and pathlib.Path(executable).resolve() != binary.resolve():
            return None
        before = birth()
        mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2.
        size = ctypes.c_size_t()
        if native.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), "kernel argv unavailable")
        if not 4 < size.value <= 1024 * 1024:
            raise OSError(errno.EIO, "invalid kernel argv length")
        data = ctypes.create_string_buffer(size.value)
        if native.sysctl(mib, 3, data, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), "kernel argv unavailable")
        raw = data.raw[:size.value]
        count = struct.unpack_from("=i", raw)[0]
        if not 1 <= count <= 4096:
            raise OSError(errno.EIO, "invalid kernel argv count")
        end = raw.index(b"\0", 4)
        index = end + 1 + (-(end - 4 + 1) % struct.calcsize("P"))
        arguments = []
        for _ in range(count):
            end = raw.index(b"\0", index)
            arguments.append(raw[index:end].decode("utf-8"))
            index = end + 1
        # Never decode or retain the environment after the counted argv.
        final_path = ctypes.create_string_buffer(4096)
        final_length = native.proc_pidpath(pid, final_path, len(final_path))
        if final_length <= 0:
            raise OSError(ctypes.get_errno(), "final kernel executable unavailable")
        if final_path.value != path.value or birth() != before:
            raise OSError(errno.EIO, "process identity changed during inspection")
        return RuntimeProcess(pid, executable=executable, arguments=tuple(arguments),
                              identity=before[:3], pidversion=before[3], parent_pid=before[4])
    except OSError as error:
        if error.errno == errno.ESRCH:
            return None
        # A process can disappear between enumeration and any inspection read.
        # ENOENT alone is not exit (a live executable may have been unlinked).
        # One fresh libproc failure with ESRCH proves absence; a live/reused PID,
        # short reply, or any other uncertainty must preserve the original error.
        probe = ctypes.create_string_buffer(56)  # PROC_PIDUNIQIDENTIFIERINFO.
        ctypes.set_errno(0)
        count = native.proc_pidinfo(pid, 17, ctypes.c_uint64(0), probe, len(probe))
        if count <= 0 and ctypes.get_errno() == errno.ESRCH:
            return None
        raise RuntimeError(f"kernel process inspection failed for PID {pid}, errno {error.errno}") from None
    except (ValueError, UnicodeError):
        raise RuntimeError(f"malformed kernel process arguments for PID {pid}") from None


def _kernel_process_argv_excludes_runtime(pid: int) -> bool:
    """True only when kernel argv proves the PID cannot be a runtime launcher.

    Fallback for PIDs whose executable path resists kernel resolution (for
    example hardened reporter processes) while KERN_PROCARGS2 argv remains
    readable. The argv comes from the same kernel authority the inspector
    itself uses, bracketed by the same birth snapshots against PID reuse; a
    launcher shape it cannot match decides _runtime_matches independently of
    the executable, so skipping is exactly equivalent to a completed match.
    Vanished PIDs also return True. Every other uncertainty raises
    RuntimeError and preserves the caller's fail-closed behavior.
    """
    if sys.platform != "darwin":
        raise RuntimeError("compatibility runtime ownership requires Darwin process identity")
    native = ctypes.CDLL(None, use_errno=True)
    def pidinfo(flavor, size):
        buffer = ctypes.create_string_buffer(size)
        count = native.proc_pidinfo(pid, flavor, ctypes.c_uint64(0), buffer, size)
        if count != size:
            code = ctypes.get_errno() if count <= 0 else errno.EIO
            raise OSError(code, "kernel process identity unavailable")
        return buffer.raw
    def birth():
        before = pidinfo(17, 56)  # PROC_PIDUNIQIDENTIFIERINFO, uniqueid at 16.
        bsd = pidinfo(3, 136)  # proc_bsdinfo: pid at 12, uid at 20, start at 120.
        after = pidinfo(17, 56)
        unique = struct.unpack_from("=Q", before, 16)[0]
        seconds, micros = struct.unpack_from("=QQ", bsd, 120)
        if (unique == 0 or unique != struct.unpack_from("=Q", after, 16)[0]
                or struct.unpack_from("=I", bsd, 12)[0] != pid or seconds == 0 or micros >= 1_000_000):
            raise OSError(errno.EIO, "inconsistent kernel process identity")
        version = struct.unpack_from("=I", before, 32)[0]
        if version == 0 or version != struct.unpack_from("=I", after, 32)[0]:
            raise OSError(errno.EIO, "inconsistent kernel PID version")
        return (seconds, micros, unique, version)
    try:
        before = birth()
        mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2.
        size = ctypes.c_size_t()
        if native.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), "kernel argv unavailable")
        if not 4 < size.value <= 1024 * 1024:
            raise OSError(errno.EIO, "invalid kernel argv length")
        data = ctypes.create_string_buffer(size.value)
        if native.sysctl(mib, 3, data, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), "kernel argv unavailable")
        raw = data.raw[:size.value]
        count = struct.unpack_from("=i", raw)[0]
        if not 1 <= count <= 4096:
            raise OSError(errno.EIO, "invalid kernel argv count")
        end = raw.index(b"\0", 4)
        index = end + 1 + (-(end - 4 + 1) % struct.calcsize("P"))
        arguments = []
        for _ in range(count):
            end = raw.index(b"\0", index)
            arguments.append(raw[index:end].decode("utf-8"))
            index = end + 1
        if birth() != before:
            raise OSError(errno.EIO, "process identity changed during inspection")
        # Include qualification-only shapes in the uncertainty gate. The private
        # FD3 shim/controller have no root argv and are NEVER generic kill targets.
        return not (
            len(arguments) >= 4 and arguments[1] in ("daemon", "vm-shim", "storage-lifecycle-qualification")
            or len(arguments) == 2 and arguments[1] in ("--storage-lifecycle-qualification-shim", "--lifecycle-v2")
        )
    except OSError as error:
        if error.errno == errno.ESRCH:
            return True
        # A process can disappear between enumeration and any inspection read.
        # One fresh libproc failure with ESRCH proves absence; a live/reused PID
        # or any other uncertainty must preserve the original error.
        probe = ctypes.create_string_buffer(56)  # PROC_PIDUNIQIDENTIFIERINFO.
        ctypes.set_errno(0)
        count = native.proc_pidinfo(pid, 17, ctypes.c_uint64(0), probe, len(probe))
        if count <= 0 and ctypes.get_errno() == errno.ESRCH:
            return True
        raise RuntimeError(f"kernel process argv inspection failed for PID {pid}, errno {error.errno}") from None
    except (ValueError, UnicodeError):
        raise RuntimeError(f"malformed kernel process arguments for PID {pid}") from None


def _runtime_root(process: RuntimeProcess) -> pathlib.Path | None:
    args = process.arguments
    if len(args) < 4 or args[1] not in ("daemon", "vm-shim", "storage-lifecycle-qualification"):
        return None
    for flag in ("--root", "--spec"):
        if sum(value == flag or value.startswith(flag + "=") for value in args) > 1:
            return None
    option = "--spec" if args[1] == "vm-shim" else "--root"
    if args.count(option) != 1:
        return None
    index = args.index(option)
    if index < 2 or index + 1 >= len(args) or not pathlib.Path(args[index + 1]).is_absolute():
        return None
    return pathlib.Path(args[index + 1]).resolve()


def _runtime_matches(process: RuntimeProcess, binary: pathlib.Path, roots: tuple[pathlib.Path, ...]) -> bool:
    if pathlib.Path(process.executable).resolve() != binary.resolve():
        return False
    path = _runtime_root(process)
    if path is None:
        return False
    if roots:
        return any(path == root.resolve() if process.arguments[1] != "vm-shim"
                   else path.is_relative_to(root.resolve()) for root in roots)
    # Automatic cleanup requires the actual owner marker, not a root-shaped
    # substring in a socket path or an unrelated argument. Missing roots require
    # explicitly authorized --root receipts instead of orphan guessing.
    candidates = (path,) if process.arguments[1] != "vm-shim" else path.parents
    return any(root.name == "root" and root.parent.name.startswith("cengine-compat-")
               and compatibility_root_owned_by(root.parent, binary) for root in candidates)


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
    targets = [(binary, roots)]
    for directory in directories:
        for executable in compatibility_registered_executables(directory, binary):
            targets.append((executable, (directory / "root",)))
    candidates = []
    if process_table is not None:
        # Pure matcher fixtures only. Real cleanup never treats a ps line as
        # executable, argv or process-birth authority.
        for line in process_table.splitlines():
            fields = line.strip().split(maxsplit=1)
            if len(fields) != 2 or not fields[0].isdigit():
                continue
            try:
                args = tuple(shlex.split(fields[1]))
            except ValueError:
                continue
            if args:
                candidates.append(RuntimeProcess(int(fields[0]), fields[1], args[0], args))
    else:
        table = subprocess.run(["ps", "-axo", "pid=,uid="], check=True, text=True,
                               stdout=subprocess.PIPE, timeout=5).stdout
        for line in table.splitlines():
            fields = line.split()
            if len(fields) == 2 and all(value.isdigit() for value in fields) and int(fields[1]) == os.getuid():
                try:
                    process = None
                    for executable, _ in targets:
                        process = _kernel_process(int(fields[0]), executable)
                        if process is not None:
                            break
                except RuntimeError:
                    # A live hardened process can refuse executable-path
                    # resolution while kernel argv remains available. Kernel
                    # argv is the same authority the inspector itself uses; a
                    # launcher shape it cannot match decides _runtime_matches
                    # independently of the executable. Anything else preserves
                    # the original uncertainty instead of skipping blindly.
                    if _kernel_process_argv_excludes_runtime(int(fields[0])):
                        continue
                    raise
                if process is not None:
                    candidates.append(process)
    return [process for process in candidates
            if any(_runtime_matches(process, executable, target_roots)
                   for executable, target_roots in targets)]


def compatibility_process_diagnostic(pid: int, binary: pathlib.Path) -> dict:
    """Exact lsof-reported PIDs only; never emit environment or arbitrary argv."""
    process = _kernel_process(pid)
    if process is None:
        return {"pid": pid, "state": "absent"}
    result = {"pid": pid, "executable": process.executable, "birth": process.identity,
              "pidversion": process.pidversion}
    if pathlib.Path(process.executable).resolve() == binary.resolve():
        args = process.arguments
        result["argv0"] = args[0][:1024] if args else ""
        result["role"] = args[1] if len(args) > 1 and args[1] in ("daemon", "vm-shim", "storage-lifecycle-qualification") else "other"
        allowed = {"--root", "--spec", "--spec-sha256", "--storage-disk-fd", "--launch-intent"}
        result["arguments"] = {key: args[index + 1][:1024] for index, key in enumerate(args[:-1])
                               if key in allowed and args.count(key) == 1}
    return result


def compatibility_disk_holder_diagnostics(records: str, binary: pathlib.Path) -> list[dict]:
    pids = list(dict.fromkeys(int(line[1:]) for line in records.splitlines()
                             if line.startswith("p") and line[1:].isdigit()))[:16]
    result = []
    for pid in pids:
        try:
            result.append(compatibility_process_diagnostic(pid, binary))
        except Exception as error:
            result.append({"pid": pid, "error_type": type(error).__name__})
    return result


def _signal_runtime_process(process: RuntimeProcess, selected_signal: int) -> None:
    if process.identity is None or process.pidversion is None:
        raise RuntimeError(f"missing process birth identity for PID {process.pid}")
    current = _kernel_process(process.pid)
    if current is None:
        return
    if (current.identity, current.pidversion, current.executable, current.arguments) != (
            process.identity, process.pidversion, process.executable, process.arguments):
        raise RuntimeError(f"process ownership changed for PID {process.pid}")
    _signal_pid_incarnation(process.pid, process.pidversion, selected_signal)


def _signal_pid_incarnation(pid: int, pidversion: int, selected_signal: int) -> None:
    # XNU validates token slots 5/7 atomically; never fall back to kill(pid).
    # libproc returns an errno value (not -1) on failure.
    token = (ctypes.c_uint32 * 8)(0, 0, 0, 0, 0, pid, 0, pidversion)
    native = ctypes.CDLL(None, use_errno=True)
    result = native.proc_signal_with_audittoken(ctypes.byref(token), selected_signal)
    if result not in (0, errno.ESRCH):
        raise RuntimeError(f"incarnation signal failed for PID {pid}, errno {result}")


def terminate_compatibility_runtime(
    binary: pathlib.Path,
    *,
    roots: tuple[pathlib.Path, ...] = (),
    timeout: float = 5.0,
) -> list[RuntimeProcess]:
    processes = compatibility_runtime_processes(binary, roots=roots)
    for process in processes:
        _signal_runtime_process(process, signal.SIGTERM)

    deadline = time.monotonic() + timeout
    remaining = compatibility_runtime_processes(binary, roots=roots)
    while remaining and time.monotonic() < deadline:
        time.sleep(0.05)
        remaining = compatibility_runtime_processes(binary, roots=roots)
    for process in remaining:
        original = next((value for value in processes if value.pid == process.pid), None)
        if original is None or original.identity != process.identity:
            raise RuntimeError(f"new runtime appeared during cleanup: PID {process.pid}")
        _signal_runtime_process(original, signal.SIGKILL)

    deadline = time.monotonic() + timeout
    remaining = compatibility_runtime_processes(binary, roots=roots)
    while remaining and time.monotonic() < deadline:
        time.sleep(0.05)
        remaining = compatibility_runtime_processes(binary, roots=roots)
    if remaining:
        detail = ", ".join(str(value.pid) for value in remaining)
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
