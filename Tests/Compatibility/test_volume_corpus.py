"""Bounded upstream fsx/pjdfstest pilot; engine work only via compatibility runner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import struct
import socket
import threading
import time
import uuid

import docker
from docker.types import Mount
from docker.transport.unixconn import UnixHTTPAdapter, UnixHTTPConnection, UnixHTTPConnectionPool
import pytest

from volume_probe import ARTIFACT_ROOT, REPO_ROOT, close_exec_stream, encode, fixture_identity, read_bounded, same_unix_endpoint
from storage_backend_proof import daemon_startup_mode, verify_backend

FIXTURE = REPO_ROOT / ".build/volume-corpus"
SOURCE = Path(__file__).parent / "fixtures/volume-corpus"
_spec = importlib.util.spec_from_file_location("volume_corpus_build", SOURCE / "build.py")
_builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_builder)
PEER_CONTENT = "corpus-peer-final-data"
# Selected regular-file branches of pinned pjdfstest tests; not the shell harness.
PJD_CASES = [
    ("create", ["create", "a", "0644"], "0"),
    ("rename", ["rename", "a", "b"], "0"),
    ("rename-missing-source", ["lstat", "a", "type"], "ENOENT"),
    ("link", ["link", "b", "a"], "0"),
    ("link-count", ["lstat", "a", "type,mode,nlink"], "regular,0644,2"),
    ("rename-linked", ["rename", "b", "c"], "0"),
    ("linked-survivor", ["lstat", "a", "type,mode,nlink"], "regular,0644,2"),
    ("unlink-link", ["unlink", "c"], "0"),
    ("unlink-count", ["lstat", "a", "nlink"], "1"),
    ("chmod", ["chmod", "a", "0111"], "0"),
    ("chmod-mode", ["stat", "a", "mode"], "0111"),
    ("symlink", ["symlink", "a", "s"], "0"),
    ("chmod-follows-symlink", ["chmod", "s", "0222"], "0"),
    ("chmod-target", ["stat", "a", "mode"], "0222"),
    ("chmod-not-symlink", ["lstat", "s", "type,mode"], "symlink,0777"),
    ("chmod-nonowner", ["-u", "65534", "chmod", "a", "0111"], "EPERM"),
    ("rename-nonowner", ["-u", "65534", "rename", "a", "denied"], "EACCES"),
    ("unlink-nonowner", ["-u", "65534", "unlink", "a"], "EACCES"),
    ("unlink-symlink", ["unlink", "s"], "0"),
    ("unlink-regular", ["unlink", "a"], "0"),
    ("unlink-missing", ["lstat", "a", "type"], "ENOENT"),
    # The pinned pjdfstest has no close command; process exit closes the writer.
    ("peer-write", ["open", "peer-before", "O_CREAT,O_WRONLY", "0644", ":",
                    "write", "0", PEER_CONTENT], "0\n0"),
    ("peer-publish", ["rename", "peer-before", "peer-final"], "0"),
]
PEER_CASES = [("peer-missing-" + name, ["lstat", name, "type"], "ENOENT")
              for name in ("a", "b", "c", "s", "denied", "peer-before")] + [
    ("peer-final-stat", ["lstat", "peer-final", "type,mode,nlink,size"],
     f"regular,0644,1,{len(PEER_CONTENT)}"),
    ("peer-final-content", ["open", "peer-final", "O_RDONLY", ":", "pread", "0",
                            str(len(PEER_CONTENT)), "0"], "0\n" + PEER_CONTENT),
]


def corpus_fixture_directory():
    """Select a trusted local build, not an authenticated external replay bundle.

    CENGINE_CORPUS_FIXTURE is an explicit absolute directory containing
    fixture.{tar,json}; unset preserves FIXTURE. No expansion or fallback on an
    invalid override. Hash checks detect corruption/staleness, not authenticity.
    """
    value = os.environ.get("CENGINE_CORPUS_FIXTURE")
    if value is None:
        return FIXTURE
    if (not value or value != value.strip() or len(os.fsencode(value)) > 4096
            or not value.startswith("/")
            or any(part in ("", ".", "..") for part in value[1:].split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError("CENGINE_CORPUS_FIXTURE must be a bounded absolute directory path")
    return Path(value)


@pytest.fixture(scope="module")
def corpus_fixture():
    directory = corpus_fixture_directory()
    if not (directory / "fixture.tar").is_file():
        pytest.fail("corpus fixture missing: explicitly run fixtures/volume-corpus/build.py with CENGINE_CORPUS_BUILD_HOST (build only)")
    metadata = json.loads(read_bounded(directory / "fixture.json", 1024 * 1024))
    archive = read_bounded(directory / "fixture.tar", 16 * 1024 * 1024)
    if hashlib.sha256(archive).hexdigest() != metadata["archive_sha256"]:
        raise ValueError("corpus archive digest mismatch")
    fixture_identity(archive, metadata["image"])
    current, _ = _builder.validated_sources(SOURCE)
    if metadata["provenance"] != current:
        raise ValueError("rebuild stale corpus fixture")
    return archive, metadata


def _exec(container, command, *, seconds=45, maximum=1024 * 1024, binary=False):
    """Bound synchronous HTTP calls and hijacked output; no background exec threads."""
    api = container.client.api
    deadline = time.monotonic() + seconds
    previous_timeout = api.timeout
    stream = None

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("corpus exec deadline exceeded")
        return value

    try:
        api.timeout = remaining()
        exec_id = api.exec_create(container.id, ["/limit", *command],
                                  stdout=True, stderr=True)["Id"]
        api.timeout = remaining()
        stream = api.exec_start(exec_id, socket=True)
        raw_socket = getattr(stream, "_sock", stream)
        data = bytearray()
        while True:
            raw_socket.settimeout(remaining())
            chunk = raw_socket.recv(min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum:
                raise ValueError("corpus exec output exceeds size bound")
        output = {1: bytearray(), 2: bytearray()}
        offset = 0
        while offset < len(data):
            if len(data) - offset < 8:
                raise ValueError("truncated corpus exec frame header")
            header = data[offset:offset + 8]
            channel, length = struct.unpack(">BxxxI", header)
            offset += 8
            if channel not in output or header[1:4] != b"\0\0\0" or length > len(data) - offset:
                raise ValueError("invalid corpus exec frame")
            output[channel].extend(data[offset:offset + length])
            offset += length
        finished_stream, stream = stream, None
        close_exec_stream(finished_stream)
        api.timeout = remaining()
        status = api.exec_inspect(exec_id)
        remaining()
        if status.get("Running") or status.get("ExitCode") is None:
            raise RuntimeError("corpus exec ended without an exit status")
        values = [bytes(output[channel]) for channel in (1, 2)]
        return status["ExitCode"], *(values if binary else [value.decode(errors="replace") for value in values])
    finally:
        try:
            if stream is not None:
                close_exec_stream(stream)
        finally:
            api.timeout = previous_timeout


FSX_EVIDENCE_BYTES = 32 * 1024


def _exec_fsx(container, command, directory, record, *, seconds=165):
    """Keep fsx's result/argv intact; diagnostics share, never renew, its budget.

    The launcher owns the direct child and the only proc descriptors. Retrieval
    addresses an unpredictable private file token, NOT a PID or arbitrary path.
    Raw kernel evidence goes only to a 0600 exclusive file, never the journal.
    Denials/collection failures are data and cannot replace the original result.
    """
    deadline = time.monotonic() + seconds
    token = uuid.uuid4().hex
    try:
        return _exec(container, ["--fsx-diagnostics", token, *command],
                     seconds=max(0, deadline - time.monotonic()))
    finally:
        summary = {"phase": "fsx-diagnostics", "status": "unavailable", "bytes": 0, "sha256": None}
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                summary["status"] = "deadline-exhausted"
            else:
                code, data, stderr = _exec(container, ["fsx-evidence", token], seconds=remaining,
                                           maximum=FSX_EVIDENCE_BYTES + 8192, binary=True)
                if code == 2:
                    summary["status"] = "absent"
                elif code == 0 and not stderr and len(data) <= FSX_EVIDENCE_BYTES:
                    # Pin the artifact directory, reject preexisting/symlink outputs.
                    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        fd = os.open(f"fsx-{token}.wait", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                     os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
                        with os.fdopen(fd, "wb") as output:
                            output.write(data)
                    finally:
                        os.close(parent)
                    summary.update(status="saved", bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                   artifact=f"fsx-{token}.wait")
        except Exception:
            # Do not publish raw response/exception strings (may contain proc data).
            pass
        try:
            record(summary)
        except Exception:
            pass  # Diagnostic persistence must not hide the original fsx result.


OWNER_LABEL = "dev.cengine.compat.owner"
FSSTRESS_WEIGHTS = (("creat", 4), ("mkdir", 2), ("rename", 2), ("link", 1),
                    ("symlink", 1), ("unlink", 2), ("rmdir", 1), ("stat", 1),
                    ("getdents", 1), ("readlink", 1))
SOAK_SEEDS = tuple(range(101, 809, 101))
BACKEND_SECONDS = 60 * 60  # Calibrated 2026-09-19: 8 epochs x (fsx 150 s + fsstress) need > 20 min.
PASS_BYTES = 128 * 1024 * 1024
CAMPAIGN_BYTES = 512 * 1024 * 1024
_JOURNAL_LOCK = threading.Lock()


def fsstress_command(seed):
    if type(seed) is not int or not 0 < seed <= 1000000:
        raise ValueError("explicit nonzero bounded integer seed required")
    return ["/fsstress", "-X", "-c", "-p", "1", "-l", "1", "-n", "128",
            "-s", str(seed), "-v", "-z", *[arg for name, weight in FSSTRESS_WEIGHTS
                                          for arg in ("-f", f"{name}={weight}")]]


def stress_completed(code, stdout):
    # Exit zero alone does not prove the upstream operation loop actually ran.
    records = re.findall(r"^0/(\d+): ([a-z]+)\b", stdout, re.MULTILINE)
    return (code == 0 and len(records) == 128 and
            {int(index) for index, _ in records} == set(range(128)) and
            all(name in dict(FSSTRESS_WEIGHTS) for _, name in records))


def soak_schedule():
    return [{"epoch": epoch, "worker": worker, "seed": seed,
             "directory": f"e{epoch}-w{worker}", "commands": [
                 ["/fsx", "-d", "-S", str(seed), "-N", "1000", "-l", "4194304",
                  "-o", "65536", "fsx-file"], fsstress_command(seed)]}
            for epoch, seed in enumerate(SOAK_SEEDS, 1) for worker in range(2)]


def journal_writer(directory, name):
    path = directory / (name + ".jsonl")
    def record(value):
        data = encode(value) + b"\n"
        # Reserve 4 MiB for failure/cleanup evidence; never silently truncate logs.
        reserve = 0 if value.get("phase") in ("error", "cleanup", "cleanup-error") else 4 * 1024 * 1024
        with _JOURNAL_LOCK:
            used = path.stat().st_size if path.exists() else 0
            total = sum(item.stat().st_size for item in directory.iterdir() if item.is_file())
            if used + len(data) > PASS_BYTES - reserve or total + len(data) > CAMPAIGN_BYTES - reserve:
                raise ValueError("corpus artifact budget exceeded")
            with path.open("ab") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
    return record


def mount_identity(text):
    matches = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) > 6 and fields[4] == "/data":
            separator = fields.index("-")
            matches.append({"device": fields[2], "root": fields[3],
                            "filesystem": fields[separator + 1], "source": fields[separator + 2],
                            "raw": line})
    if len(matches) != 1:
        raise ValueError("expected one exact /data mountinfo record")
    return matches[0]


def bound_response_body(response, deadline):
    """Bound every underlying socket read, including SDK image-load generators.

    The authorized local Unix transport uses socket.SocketIO. Fail closed if an
    unsupported transport cannot expose that boundary; never fall back to an
    unbounded generator. Also bound metadata/import-response bytes.
    """
    try:
        raw = response.raw._fp.fp.raw
        sock = raw._sock
        readinto = raw.readinto
    except AttributeError:
        response.close()
        raise ValueError("corpus requires a deadline-capable socket transport")
    total = 0
    def bounded_readinto(buffer):
        nonlocal total
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            response.close()
            raise TimeoutError("corpus response body deadline exceeded")
        sock.settimeout(min(45, remaining))
        count = readinto(memoryview(buffer)[:65536])
        total += count or 0
        if time.monotonic() > deadline or total > 16 * 1024 * 1024:
            response.close()
            raise ValueError("corpus response body exceeded time/size budget")
        return count
    raw.readinto = bounded_readinto


class HeaderDeadline:
    """One joined watchdog per active send, owning sockets before connect().

    Session.close() cannot interrupt an in-flight HTTP header read. Shutdown on
    the exact registered socket does, including when a makefile retains its fd.
    No global socket hooks, descriptor-number lookups, or shared SDK clients.
    """
    def __init__(self, deadline):
        self.deadline = deadline
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._socket = None
        self.expired = False
        self.thread = threading.Thread(target=self._watch, name="corpus-http-deadline")
        self.thread.start()

    @staticmethod
    def _shutdown(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def register(self, sock):
        with self._lock:
            if self.expired or self._stop.is_set() or time.monotonic() >= self.deadline:
                self._shutdown(sock)
                raise TimeoutError("corpus HTTP header deadline exceeded before connect")
            if self._socket is not None:
                self._shutdown(sock)
                raise ValueError("corpus request attempted more than one connection")
            self._socket = sock

    def _watch(self):
        if not self._stop.wait(max(0, self.deadline - time.monotonic())):
            with self._lock:
                if not self._stop.is_set():
                    self.expired = True
                    if self._socket is not None:
                        self._shutdown(self._socket)

    def finish(self):
        with self._lock:
            self._stop.set()
        self.thread.join()
        # Never close a successful response's socket: body/hijack owns it now.
        self._socket = None


class DeadlineUnixConnection(UnixHTTPConnection):
    def __init__(self, *args, watchdog, **kwargs):
        super().__init__(*args, **kwargs)
        self.watchdog = watchdog

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.watchdog.register(sock)  # Before any blocking socket operation.
            sock.settimeout(max(0.001, min(45, self.watchdog.deadline - time.monotonic())))
            sock.connect(self.unix_socket)
            self.sock = sock
        except BaseException:
            sock.close()
            raise


class DeadlineUnixPool(UnixHTTPConnectionPool):
    def __init__(self, *args, watchdog, **kwargs):
        super().__init__(*args, **kwargs)
        self.watchdog = watchdog

    def _new_conn(self):
        return DeadlineUnixConnection(self.base_url, self.socket_path, self.timeout,
                                      watchdog=self.watchdog)


class DeadlineUnixAdapter(UnixHTTPAdapter):
    def __init__(self, socket_path, watchdog):
        super().__init__("http+unix://" + socket_path, pool_connections=1, max_pool_size=1)
        self.watchdog = watchdog

    def build_response(self, req, resp):
        response = super().build_response(req, resp)
        # Session.send consumes redirect bodies even with allow_redirects=False
        # while preparing Response.next. Reject before control returns to it.
        if 300 <= response.status_code < 400:
            response.close()
            raise ValueError("corpus API redirects are forbidden")
        return response

    def get_connection(self, url, proxies=None):
        with self.pools.lock:
            pool = self.pools.get(url)
            if pool is None:
                pool = DeadlineUnixPool(url, self.socket_path, self.timeout, maxsize=1,
                                        watchdog=self.watchdog)
                self.pools[url] = pool
            return pool


@contextmanager
def api_deadline(client, deadline):
    """Recompute the remaining budget for EVERY SDK HTTP request, not just calls.

    SDK create/get helpers can issue multiple requests. Restore the transport on
    exit; workers never share this client. Late responses always fail the pass.
    """
    send = client.api.send
    prefix = "http+docker://"
    original_adapter = client.api.adapters.get(prefix)
    if not isinstance(original_adapter, UnixHTTPAdapter):
        raise ValueError("corpus requires an explicit local Unix SDK transport")
    def bounded_send(request, **kwargs):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("corpus API deadline exceeded")
        requested = kwargs.get("timeout", 45)
        if isinstance(requested, tuple):
            requested = min((value for value in requested if value is not None), default=45)
        kwargs["timeout"] = min(45, remaining, requested if requested is not None else 45)
        request_deadline = min(deadline, time.monotonic() + kwargs["timeout"])
        # Fresh request-local connection: never register or shutdown a cached,
        # borrowed connection. No redirect can open an unregistered transport.
        kwargs["stream"] = True
        kwargs["allow_redirects"] = False
        watchdog = HeaderDeadline(request_deadline)
        adapter = response = None
        try:
            adapter = DeadlineUnixAdapter(original_adapter.socket_path, watchdog)
            client.api.mount(prefix, adapter)
            response = send(request, **kwargs)
            # Retire/join the header owner BEFORE checking and transferring the
            # response to the body guard; it cannot close a transferred socket.
            watchdog.finish()
            if watchdog.expired or time.monotonic() >= request_deadline:
                raise TimeoutError("corpus API response exceeded deadline")
            if 300 <= response.status_code < 400:
                raise ValueError("corpus API redirects are forbidden")
            bound_response_body(response, request_deadline)
            return response
        except BaseException as error:
            if response is not None:
                response.close()
            if watchdog.expired:
                raise TimeoutError("corpus HTTP header deadline exceeded") from error
            raise
        finally:
            watchdog.finish()  # No watchdog can race later cleanup requests.
            client.api.mount(prefix, original_adapter)
            if adapter is not None:
                adapter.close()
    client.api.send = bounded_send
    try:
        yield
    finally:
        client.api.send = send


def cleanup_owned(client, names, volume_name, token, record):
    errors = []
    def log(value):
        try:
            record(value)
        except Exception as error:
            errors.append("cleanup evidence: " + str(error))
    # Exact names plus owner token, including ambiguous create replies. No prune.
    for kind, name in [("container", name) for name in reversed(names)] + [("volume", volume_name)]:
        try:
            resource = (client.containers if kind == "container" else client.volumes).get(name)
            labels = resource.attrs.get("Config", {}).get("Labels", {}) if kind == "container" else resource.attrs.get("Labels", {})
            if (labels or {}).get(OWNER_LABEL) != token:
                raise ValueError(f"refusing unowned {kind}: {name}")
            if kind == "container":
                if resource.name != name:
                    raise ValueError("container name mismatch")
                resource.remove(force=True)
            else:
                if resource.name != name:
                    raise ValueError("volume name mismatch")
                resource.remove()
            log({"phase": "cleanup", "kind": kind, "name": name, "status": "removed"})
        except docker.errors.NotFound:
            log({"phase": "cleanup", "kind": kind, "name": name, "status": "absent"})
        except Exception as error:
            errors.append(str(error))
            log({"phase": "cleanup-error", "kind": kind, "name": name, "error": str(error)})
    if errors:
        raise RuntimeError("owned corpus cleanup failed: " + "; ".join(errors))


@contextmanager
def corpus_resources(client, fixture, storage, record, daemon=None, *, deadline=None, cleanup_deadline=None):
    if storage not in ("block", "shared"):
        raise ValueError("invalid storage mode")
    archive, metadata = fixture
    token = uuid.uuid4().hex
    volume_name = f"corpus-{storage}-{token}"
    names = [f"{volume_name}-{index}" for index in range(2 if storage == "shared" else 1)]
    containers = []
    previous = client.api.timeout
    client.api.timeout = 45
    deadline = deadline if deadline is not None else time.monotonic() + BACKEND_SECONDS - 180
    cleanup_deadline = cleanup_deadline if cleanup_deadline is not None else deadline + 180
    transport = api_deadline(client, deadline)
    transport.__enter__()
    try:
        record({"phase": "plan", "owner": token, "volume": volume_name, "containers": names,
                "provenance": metadata["provenance"]})
        tag, config, digest = fixture_identity(archive, metadata["image"])
        client.images.load(archive)  # Content-addressed cache is deliberately retained.
        inspected = client.images.get(tag).attrs
        record({"phase": "image", "config_sha256": digest, "inspect": inspected, "version": client.version()})
        assert inspected["Architecture"] == "arm64" and inspected["Os"] == "linux"
        assert inspected["RootFS"]["Layers"] == config["rootfs"]["diff_ids"]
        assert inspected["Config"]["Cmd"] == config["config"]["Cmd"]
        client.volumes.create(volume_name, labels={OWNER_LABEL: token})
        for name in names:
            containers.append(client.containers.create(
                tag, name=name, network_mode="none", read_only=True, mem_limit="256m",
                pids_limit=16, nano_cpus=1000000000, tmpfs={"/tmp": "rw,nosuid,nodev,noexec,size=16m"},
                security_opt=["no-new-privileges"],
                mounts=[Mount("/data", volume_name, type="volume", no_copy=True)],
                labels={OWNER_LABEL: token}))
        # Register both shared consumers BEFORE either starts.
        for container in containers:
            container.start()
        modes = None if daemon is None else json.loads(read_bounded(daemon.root / "volume-storage.json", 1024 * 1024))
        record({"phase": "backend", "expected": storage, "storage": modes,
                "reference": "Docker local-volume control" if daemon is None else None})
        if daemon is not None:
            assert modes[volume_name] == storage, modes
        for container in containers:
            code, stdout, stderr = _exec(container, ["mountinfo"])
            record({"phase": "mountinfo", "container": container.id, "exit": code,
                    "stdout": stdout, "stderr": stderr})
            assert code == 0, (code, stderr)
            identity = mount_identity(stdout)
            record({"phase": "mount-identity", **identity})
            if daemon is not None:
                proof = verify_backend(daemon.root, storage, stdout,
                                       startup_mode=daemon_startup_mode(daemon))
                record({"phase": "backend-proof", "container": container.id, "proof": proof})
        yield containers
    except BaseException as error:
        record({"phase": "error", "error": f"{type(error).__name__}: {error}"})
        raise
    finally:
        try:
            transport.__exit__(None, None, None)
            with api_deadline(client, cleanup_deadline):
                cleanup_owned(client, names, volume_name, token, record)
        finally:
            client.api.timeout = previous


def _execute_soak(client, fixture, storage, directory, label, daemon=None):
    record = journal_writer(directory, f"{label}-{storage}")
    schedule = soak_schedule()
    record({"phase": "schedule", "profile": "soak", "schedule": schedule,
            "ordering": "epoch barriers; two independent concurrent worker directories",
            "backend_seconds": BACKEND_SECONDS, "max_epoch_entries": 512,
            "max_epoch_data_bytes": 64 * 1024 * 1024})
    started = time.monotonic()
    deadline = started + BACKEND_SECONDS - 180  # Leave a bounded cleanup reserve.
    endpoint = f"unix://{daemon.socket}" if daemon is not None else os.environ["DOCKER_REFERENCE_HOST"]
    _builder.validate_build_host(endpoint)  # Validate before any SDK transport construction.
    results = []
    for epoch in range(1, 9):
        if time.monotonic() >= deadline:
            raise TimeoutError("corpus backend budget exhausted")
        with corpus_resources(client, fixture, storage, record, daemon,
                              deadline=deadline, cleanup_deadline=started + BACKEND_SECONDS) as containers:
            def worker(item):
                # Each worker owns its SDK connection and hijacked exec stream.
                sdk = docker.DockerClient(base_url=endpoint, timeout=45, version=client.api._version)
                transport = api_deadline(sdk, deadline)
                transport.__enter__()
                try:
                    container = sdk.containers.get(containers[item["worker"] if storage == "shared" else 0].id)
                    observations = []
                    for command in item["commands"]:
                        seconds = min(165 if command[0] == "/fsx" else 45,
                                      deadline - time.monotonic())
                        if seconds <= 0:
                            raise TimeoutError("corpus worker budget exhausted")
                        args = ["--work", item["directory"], *command]
                        record({"phase": "before", **item, "argv": args})
                        if command[0] == "/fsx":
                            # TESTONLY: same workload/budget; correlate private wait evidence.
                            def record_fsx(value):
                                record({**value, "epoch": item["epoch"], "worker": item["worker"],
                                        "seed": item["seed"], "work": item["directory"]})
                            code, stdout, stderr = _exec_fsx(container, args, directory, record_fsx,
                                                             seconds=seconds)
                        else:
                            code, stdout, stderr = _exec(container, args, seconds=seconds)
                        record({"phase": "after", "epoch": epoch, "worker": item["worker"],
                                "argv": args, "exit": code, "stdout": stdout, "stderr": stderr})
                        passed = (code == 0 and "All operations completed A-OK!" in stdout) if command[0] == "/fsx" else stress_completed(code, stdout)
                        observations.append({"case": f"e{epoch}-w{item['worker']}-{command[0]}", "passed": passed})
                        if not passed:
                            break
                    return observations
                finally:
                    transport.__exit__(None, None, None)
                    sdk.close()
            # __exit__ joins both workers BEFORE container/volume cleanup, even on error.
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(worker, item) for item in schedule if item["epoch"] == epoch]
                for future in futures:
                    results.extend(future.result())
        if time.monotonic() - started > BACKEND_SECONDS:
            raise TimeoutError("corpus backend wall budget exceeded")
        if not all(item["passed"] for item in results):
            break
    return results


def _execute_corpus(client, fixture, storage, directory, label, daemon=None):
    profile = os.environ.get("CENGINE_CORPUS_PROFILE", "pilot")
    if profile not in ("pilot", "soak"):
        raise ValueError("CENGINE_CORPUS_PROFILE must be pilot or soak")
    runner = _execute_pilot if profile == "pilot" else _execute_soak
    return runner(client, fixture, storage, directory, label, daemon)


def _execute_pilot(client, fixture, storage, directory, label, daemon=None):
    """One executor and exact archive for both endpoints. Keep raw errno/log evidence."""
    archive, metadata = fixture
    record = journal_writer(directory, f"{label}-{storage}")
    outcomes = []
    with corpus_resources(client, fixture, storage, record, daemon) as containers:
        workload = [(0, "fsx-seed-1", ["/fsx", "-d", "-S", "1", "-N", "1000", "-l", "4194304", "-o", "65536", "fsx-file"], None)]
        workload.extend((0, name, ["/pjdfstest", *args], expected) for name, args, expected in PJD_CASES)
        if storage == "shared":
            # Fresh peer descriptors AFTER publication, not interleaved/coherence coverage.
            workload.extend((1, name, ["/pjdfstest", *args], expected)
                            for name, args, expected in PEER_CASES)
        for consumer, name, args, expected in workload:
            record({"phase": "before", "case": name, "argv": args, "consumer": consumer})
            if args[0] == "/fsx":
                exit_code, stdout, stderr = _exec_fsx(containers[consumer], args, directory, record)
            else:
                exit_code, stdout, stderr = _exec(containers[consumer], args)
            observation = {"case": name, "exit": exit_code, "stdout": stdout, "stderr": stderr}
            record({"phase": "after", **observation})
            # Continue after syscall mismatch so one fsx gap cannot hide namespace errno.
            if expected is None:
                passed = exit_code == 0 and "All operations completed A-OK!" in stdout
                outcomes.append({"case": name, "passed": passed})
            else:
                passed = stdout.strip() == expected and exit_code == (1 if expected in ("ENOENT", "EPERM", "EACCES") else 0)
                outcomes.append({"case": name, "passed": passed, "stdout": stdout.strip(), "exit": exit_code})
        return outcomes


def _artifacts(fixture):
    directory = ARTIFACT_ROOT / ("corpus-" + uuid.uuid4().hex)
    directory.mkdir(parents=True)
    archive, metadata = fixture
    (directory / "fixture.tar").write_bytes(archive)
    (directory / "fixture.json").write_bytes(encode(metadata) + b"\n")
    sources = {}
    for name in ("test_volume_corpus.py", "test_volume_namespace.py"):
        data = read_bounded(Path(__file__).parent / name, 1024 * 1024)
        (directory / name).write_bytes(data)
        sources[name] = hashlib.sha256(data).hexdigest()
    (directory / "runner.json").write_bytes(encode({"sha256": sources,
        "profile": os.environ.get("CENGINE_CORPUS_PROFILE", "pilot"),
        "shared_filesystem_required": "private lifecycle-v2 checkpoint and fuse.managed-v3",
        "backend_proof_source_sha256": hashlib.sha256(read_bounded(
            Path(__file__).parent / "storage_backend_proof.py", 1024 * 1024)).hexdigest()}) + b"\n")
    print(f"volume corpus artifacts: {directory}")
    return directory


@pytest.mark.compat("RTM-067")
def test_bounded_upstream_filesystem_corpus(daemon, client, corpus_fixture):
    directory = _artifacts(corpus_fixture)
    results = {storage: _execute_corpus(client, corpus_fixture, storage, directory, "cengine", daemon)
               for storage in ("block", "shared")}
    assert all(item["passed"] for values in results.values() for item in values), (results, str(directory))


@pytest.mark.oracle
@pytest.mark.skipif(not os.environ.get("DOCKER_REFERENCE_HOST"), reason="requires explicit DOCKER_REFERENCE_HOST")
@pytest.mark.compat("ORC-023")
def test_bounded_upstream_filesystem_corpus_matches_reference(daemon, client, corpus_fixture):
    host = os.environ["DOCKER_REFERENCE_HOST"]
    _builder.validate_build_host(host)  # Reject SSH/TCP before constructor side effects.
    assert not same_unix_endpoint(host, daemon.socket), "reference and cengine must differ"
    # Pin the API needed by this fixture, not cengine's advertised maximum:
    # a supported Docker reference can advertise an older maximum. Avoid
    # unbounded constructor-time auto-negotiation.
    reference = docker.DockerClient(base_url=host, timeout=45, version="1.45")
    try:
        with api_deadline(reference, time.monotonic() + 45):
            version = reference.version()
        assert version.get("Platform", {}).get("Name", "").lower() != "cengine", version
        assert version.get("Os") == "linux" and version.get("Arch") in ("arm64", "aarch64"), version
        directory = _artifacts(corpus_fixture)
        results = []
        for storage in ("block", "shared"):
            expected = _execute_corpus(reference, corpus_fixture, storage, directory, "docker")
            actual = _execute_corpus(client, corpus_fixture, storage, directory, "cengine", daemon)
            results.append((storage, expected, actual))
        assert all(expected == actual and all(item["passed"] for item in expected)
                   for _, expected, actual in results), (results, str(directory))
    finally:
        reference.close()
