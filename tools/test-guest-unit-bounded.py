#!/usr/bin/env python3
"""Parent-owned Linux/arm64 units ONLY; no VM management, pull, build or mounts.

The direct parent must already own the original compatibility mkdir lock. This
runner never claims, adopts or removes it. --destination must be a NEW private
receipt directory. Only two fixed suites exist; no command, environment or
capability overrides exist.
"""
from __future__ import annotations
import argparse
import io
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import tarfile
import time
import uuid
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import helper_fixture_lifetime as claims
import managed_fuse_artifact as inputs

OWNER = "dev.cengine.guest-unit-bounded"
POLICY = "tools/guest-unit-seccomp-arm64.json"
POLICY_SHA256 = "115d4719c16b4bd613cf57bb705d8e425c7d3468fbe9e510dd1ae33036019b84"
SUPERVISOR_SHA256 = "b1ba7b7675a78f00972e327b54ee53275b8de7ded2a953fd252780c4a1e01433"
TOOL = "tools/test-guest-unit-bounded.py"
SUPERVISOR = "Guest/internal/supervisor/seccomp_linux_arm64.go"
FIXTURES = ("Guest/internal/workloadstorage/testdata/vectors.json",
            "Guest/internal/preparecompat/testdata/vectors.json",
            "Guest/internal/preparecompat/testdata/full-vectors.json",
            "Tests/Fixtures/storage-bootstrap/lifecycle-v2.json",
            "Tests/Fixtures/storage-bootstrap/lifecycle-service-result-v2.json",
            "Tests/Fixtures/storage-bootstrap/lifecycle-resume-open-v1.json",
            "Tests/Fixtures/storage-bootstrap/lifecycle-cold-open-v1.json",
            "Tests/Fixtures/storage-bootstrap/lifecycle-handoff-v1.json",
            "Tests/Fixtures/storage-bootstrap/lifecycle-worker-unreaped-v2.json",
            "Tests/Fixtures/storage-bootstrap/lifecycle-service-boot-v2.json")
# Fixed package groups keep the default suite bounded.
GROUPS = ("storageauthority", "storageidentity", "storagefuse")
SUITES = {"default": GROUPS, "storage-worker": ("storageworker", "storageboot")}
NATIVE = {"TestNativeChildOwner" + n for n in ("GateAndActualWait", "StartupFailure", "LiveCreatingThread")}
NATIVE_PATTERN = "^TestNativeChildOwner(GateAndActualWait|StartupFailure|LiveCreatingThread)$"
CAPS = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETUID", "SETGID", "MKNOD"]
TMPFS = {"/work": "rw,exec,nosuid,nodev,size=768m", "/tmp": "rw,nosuid,nodev,size=128m,mode=1777"}
ENV = ["PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
       "HOME=/tmp", "LANG=C", "LC_ALL=C", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64",
       "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off", "GOFLAGS=",
       "GOCACHE=/work/cache", "GOTMPDIR=/work/tmp", "TMPDIR=/tmp", "GOMAXPROCS=2", "GOMEMLIMIT=512MiB"]
MAX_SOURCE, MAX_ARCHIVE, MAX_OUTPUT = 128 << 20, 140 << 20, 40 << 20
MAX_ENTRIES = 50000
require, digest, encode = inputs.require, inputs.digest, inputs.encode

def suite_groups(suite):
    require(isinstance(suite, str) and suite in SUITES, "unknown fixed suite")
    return SUITES[suite]


def export_bounds(suite="default"):
    # Leave tar overhead inside MAX_OUTPUT even if every diagnostic hits its cap.
    count = len(suite_groups(suite))
    return {**{"group-" + str(i) + ".jsonl": 5 << 20 for i in range(count)},
            **{"group-" + str(i) + ".stderr": 128 << 10 for i in range(count)},
            **{"group-" + str(i) + ".status": 32 for i in range(count)},
            **{n: 4 << 20 for n in ("source.before", "source.after", "toolchain.before", "toolchain.after")},
            "run.status": 32}


EXPORT_BOUNDS = export_bounds()
STATUS_SCRIPT = r'''
write_status() {
    # Overwrite the already allocated page: O_TRUNC could lose it on full tmpfs.
    printf '%s\n' "$1" | dd of="$2" conv=notrunc 2>/dev/null || return 1
    truncate -s "$((${#1} + 1))" "$2"
}
'''
INVENTORY_SCRIPT = STATUS_SCRIPT + r'''
inventory() {
    test -z "$(find "$1" -type l -print -quit)" || return 1
    (cd "$1"; find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum --zero)
}
toolchain_inventory() {
    # The entire immutable distribution, not just the compiler/version.
    test -z "$(find /usr/local/go -type l -print -quit)" || return 1
    find /usr/local/go -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum --zero
}
'''
WORK_PREFIX = "set -eu\n" + INVENTORY_SCRIPT + r'''
tar -xf - -C /work/src
inventory /work/src > /work/out/source.before
toolchain_inventory > /work/out/toolchain.before
cd /work/src/Guest
# Go's linker honors umask. Kernel credential subprocesses must execute the
# pinned test binary as nonroot, so use the normal compiler/test mask. Export
# files and extracted source were already created privately by the outer shell.
umask 022
'''
def suite_scripts(suite="default"):
    groups, bounds = suite_groups(suite), export_bounds(suite)
    work = WORK_PREFIX
    # New groups get 60s each for tests; compilation shares the unchanged 210s
    # total work budget. Remaining default groups retain their original limits.
    test_timeout = "60s" if suite == "storage-worker" else "180s"
    for index, group in enumerate(groups):
        prefix = "/work/out/group-" + str(index)
        work += ("write_status running " + prefix + ".status\nstatus=0\n"
                 + "go test -json -mod=vendor -count=1 -p=1 -parallel=1 -trimpath -buildvcs=false -timeout=" + test_timeout + " "
                 + ("-tags=cengine_prepare_full_compat " if suite == "storage-worker" else "")
                 + "./internal/" + group
                 + (" -run '" + NATIVE_PATTERN + "'" if group == "storagefuse" else "")
                 + " > " + prefix + ".jsonl 2> " + prefix + ".stderr || status=$?\n"
                 + "write_status \"$status\" " + prefix + ".status\n"
                 + "test \"$status\" -eq 0 || exit \"$status\"\n")
    # The inner timeout leaves an export window within the original 270s hard limit.
    # No exec/cp recovery command is needed; the same fixed process exports failures.
    script = "set -eu\numask 077\n" + INVENTORY_SCRIPT + "mkdir -p /work/src /work/out /work/cache /work/tmp\n"
    for name in bounds:
        script += ": > /work/out/" + name + "\n"
    # Reserve a status data page before the worker can fill the shared tmpfs.
    script += "printf 'incomplete\\n' > /work/out/run.status\n"
    for index in range(len(groups)):
        script += "printf 'not-run\\n' > /work/out/group-" + str(index) + ".status\n"
    script += "status=0\ntimeout -k 2 210 sh -ec " + shlex.quote(work) + " || status=$?\n"
    script += r'''
failed() { if test "$status" -eq 0; then status=1; fi; }
for f in /work/out/group-*.status; do
    if test "$(cat "$f")" = running; then write_status interrupted "$f" || failed; failed; fi
done
inventory /work/src > /work/out/source.after || failed
toolchain_inventory > /work/out/toolchain.after || failed
cmp /work/out/source.before /work/out/source.after >&2 || failed
cmp /work/out/toolchain.before /work/out/toolchain.after >&2 || failed
'''
    for name, bound in bounds.items():
        if name == "run.status": continue
        file = "/work/out/" + name
        script += ("if test \"$(stat -c %s " + file + ")\" -gt " + str(bound) + "; then\n"
                   + "    truncate -s " + str(bound) + " " + file + "; failed\nfi\n")
    script += "write_status \"$status\" /work/out/run.status\n"
    script += "tar -cf - -C /work/out " + " ".join(bounds) + '\nexit "$status"\n'
    return work, script


def suite_command(suite="default"):
    return ["-i", *ENV, "timeout", "-k", "2", "270", "sh", "-ec", suite_scripts(suite)[1]]


WORK_SCRIPT, SCRIPT = suite_scripts()
CMD = suite_command()


def loads(raw):
    return json.loads(raw, object_pairs_hook=inputs.object_pairs,
                      parse_constant=lambda s: require(False, "nonfinite JSON"))


def bounded_file(root, name, maximum=8 << 20):
    # Component-by-component O_NOFOLLOW plus single-link check before and after.
    path = Path(root) / name
    before = path.lstat()
    require(before.st_nlink == 1 and stat.S_ISREG(before.st_mode), "regular single-link source required")
    raw = inputs.read_file(root, name, maximum, allow_empty=True)
    require(inputs.stamp(before) == inputs.stamp(path.lstat()), "source changed during snapshot")
    return raw


def snapshot(root, guard=lambda: None):
    names = [POLICY, TOOL, "Tests/Compatibility/managed_fuse_artifact.py",
             "Tests/Compatibility/helper_fixture_lifetime.py", "Tests/Compatibility/harness.py", *FIXTURES]
    pending, entries = [(Path(root) / "Guest", 0)], 0
    while pending:
        directory, depth = pending.pop()
        guard(); require(depth <= 32 and not directory.is_symlink(), "source directory depth/link")
        with os.scandir(directory) as listing:
            for entry in listing:
                guard(); entries += 1
                require(entries <= MAX_ENTRIES and len(os.fsencode(entry.path)) <= 4096, "source traversal bound")
                require(not entry.is_symlink(), "source link")
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1)); continue
                require(entry.is_file(follow_symlinks=False), "regular source required")
                require(path.suffix != ".syso", "unrecorded Go object")
                if path.suffix in {".go", ".s", ".S", ".h", ".c", ".mod", ".sum"} or entry.name == "modules.txt":
                    names.append(str(path.relative_to(root)))
    names = sorted(set(names))
    require(0 < len(names) <= 20000, "source count bound")
    result, used = {}, 0
    for name in names:
        guard()
        raw = bounded_file(root, name)
        require(not name.endswith(".go") or b"//go:embed" not in raw, "unrecorded embed forbidden")
        used += len(raw); require(used <= MAX_SOURCE, "source bytes bound")
        result[name] = raw
    return result


def expected_tests(source, suite="default"):
    """Exact names from frozen Go declarations; closed known Linux build tags.

    Strip Go comments/literals first, so a test name in a comment is not evidence.
    Unknown future build constraints fail closed rather than hiding coverage.
    """
    expected = {g: set() for g in suite_groups(suite)}
    tags = {"linux", "linux && (amd64 || arm64)", "linux && (arm64 || amd64)", "linux || darwin"}
    full = {"cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat",
            "(linux || darwin) && cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat"}
    inert = {"!cengine_prepare_full_compat || cengine_prepare_compat || cengine_prepare_early_compat"}
    # Match the fixed compile profile: only storage-worker enables full compat.
    tags |= full if suite == "storage-worker" else inert
    inactive = {"!linux || (!amd64 && !arm64)", "!linux || (!arm64 && !amd64)",
                "cengine_native_faulttest", "cengine_native_faulttest && linux && (arm64 || amd64)",
                "cengine_lifecycle_integration"}
    inactive |= inert if suite == "storage-worker" else full
    lexical = re.compile(r'//[^\n]*|/\*.*?\*/|`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
    for name, raw in source.items():
        parts = name.split("/")
        if len(parts) != 4 or parts[:2] != ["Guest", "internal"] or parts[2] not in expected or not name.endswith("_test.go"):
            continue
        text = raw.decode("utf-8")
        constraints = re.findall(r"(?m)^//go:build (.+)$", text)
        require(not constraints or len(constraints) == 1 and constraints[0] in tags | inactive,
                "unknown test build constraint")
        # Known inactive files remain frozen in the source inventory.
        if constraints and constraints[0] in inactive:
            continue
        require(not re.search(r"_(?:darwin|windows|amd64)_test\.go$", name), "unexpected platform test")
        clean = lexical.sub(lambda m: "\n" * m.group().count("\n") + " ", text)
        names = re.findall(r"(?m)^func\s+(Test\w+)\s*\(\s*\w+\s+\*testing\.T\s*\)\s*\{", clean)
        if parts[2] == "storagefuse":
            names = [n for n in names if n in NATIVE]
        for test in names:
            require(test not in expected[parts[2]], "duplicate test declaration")
            expected[parts[2]].add(test)
    require(all(expected.values()), "frozen test coverage empty")
    if suite == "default":
        require(expected["storagefuse"] == NATIVE
                and "TestStorageSchemaVersions" in expected["storageauthority"],
                "frozen test coverage empty")
    return expected


def validate_policy(raw, supervisor):
    # The checked-in profile is frozen; derive only a comparison, never broaden it.
    require(digest(raw) == POLICY_SHA256 and digest(supervisor) == SUPERVISOR_SHA256, "frozen seccomp policy/source pin")
    block = supervisor.decode().split("var dockerDefaultSeccompSyscalls = []uint32{", 1)[1].split("}", 1)[0]
    names = sorted(set(n.lower() for n in re.findall(r"unix\.SYS_(\w+)", block)))
    rules = [{"names": names, "action": "SCMP_ACT_ALLOW"}]
    def allow(name, args):
        rules.append({"names": [name], "action": "SCMP_ACT_ALLOW", "args": args})
    allow("clone", [{"index": 0, "value": 2114060288, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}])
    rules.append({"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38})
    for value, op in ((38, "SCMP_CMP_LT"), (39, "SCMP_CMP_EQ"), (40, "SCMP_CMP_GT")):
        allow("socket", [{"index": 0, "value": value, "op": op}])
    for value in (0, 8, 131072, 131080, 4294967295):
        allow("personality", [{"index": 0, "value": value, "op": "SCMP_CMP_EQ"}])
    allow("unshare", [{"index": 0, "value": 512, "op": "SCMP_CMP_EQ"}])
    expected = {"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 1, "architectures": ["SCMP_ARCH_AARCH64"], "syscalls": rules}
    value = loads(raw)
    require(value == expected, "frozen supervisor-derived seccomp policy mismatch")
    return value


class OriginalLock:
    def __init__(self, path, pid):
        require(pid == os.getppid() and pid > 1, "original lock must belong to direct parent")
        approved = claims.launcher_lock()
        require(Path(path).absolute() == approved.absolute(), "original global lock path required")
        self.path, self.pid = Path(path), pid
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.identity = inputs.stamp(os.fstat(self.fd))[:2]
        try:
            self.check()
        except BaseException:
            self.close(); raise
    def check(self):
        info = self.path.lstat()
        require(os.getppid() == self.pid and stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
                not info.st_mode & 0o022 and inputs.stamp(info)[:2] == self.identity, "original parent lock lost/replaced")
        require(inputs.read_file(self.path, "pid", 32, private=True) == (str(self.pid) + "\n").encode(), "original lock PID mismatch")
    def close(self):
        os.close(self.fd)


class CommandFailure(ValueError):
    """Bounded transport evidence, including partial output on deadline/guard loss."""
    def __init__(self, message, output, errors, returncode):
        super().__init__(message)
        self.output, self.errors, self.returncode = output, errors, returncode


def run_bounded(command, deadline, *, env, input_file=None, maximum=1 << 20, guard=lambda: None):
    guard(); require(time.monotonic() < deadline, "command deadline")
    process = subprocess.Popen(command, env=env, stdin=input_file or subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    assert process.stdout is not None and process.stderr is not None
    output, errors = bytearray(), bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            for pipe, target, limit in ((process.stdout, output, maximum), (process.stderr, errors, 128 << 10)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, (target, limit))
            while selector.get_map() or process.poll() is None:
                guard(); require(time.monotonic() < deadline, "command deadline")
                for key, _ in selector.select(min(.05, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj); continue
                    target, limit = key.data
                    exceeded = len(target) + len(chunk) > limit
                    target.extend(chunk[:limit - len(target)])
                    require(not exceeded, "CLI output bound")
            guard()
        require(process.returncode == 0, "CLI failed: " + errors[:2048].decode(errors="replace"))
        return bytes(output)
    except Exception as error:
        raise CommandFailure(str(error), bytes(output), bytes(errors), process.poll()) from error
    finally:
        # Even a successful wrapper may leave pipe-closed descendants behind.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            if process.poll() is None:
                try:
                    process.wait(timeout=max(.01, min(1, deadline - time.monotonic())))
                except subprocess.TimeoutExpired as error:
                    raise CommandFailure("CLI reap deadline", bytes(output), bytes(errors), process.poll()) from error
        finally:
            process.stdout.close(); process.stderr.close()


def archive(files, guard=lambda: None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, raw in sorted(files.items()):
            guard()
            member = tarfile.TarInfo(name); member.size = len(raw); member.mode = 0o600
            tar.addfile(member, io.BytesIO(raw))
    guard(); require(stream.tell() <= MAX_ARCHIVE, "source archive bound")
    return stream.getvalue()


def unpack(raw, guard=lambda: None, *, suite="default"):
    require(0 < len(raw) <= MAX_OUTPUT, "export output bound")
    bounds = export_bounds(suite)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for member in tar:
            guard()
            require(member.name in bounds and member.name not in files and member.isreg() and
                    0 <= member.size <= bounds[member.name], "export member/type/size")
            stream = tar.extractfile(member)
            require(stream is not None, "export file required")
            files[member.name] = stream.read(member.size + 1)
            require(len(files[member.name]) == member.size, "truncated export")
    require(set(files) == set(bounds), "missing export")
    return files


def coverage(raw, group, expected, guard=lambda: None):
    active, results, started, finished = set(), {}, False, False
    package = None
    for line in io.BytesIO(raw):
        guard()
        require(0 < len(line) <= 256 << 10, "JSON event bound")
        row = loads(line); require(isinstance(row, dict), "JSON event object")
        action, test = row.get("Action"), row.get("Test")
        require(row.get("Package") == "dev.cengine/guest/internal/" + group, "unexpected package")
        if package is None: package = row["Package"]
        require(package == row["Package"] and not finished, "package event ordering")
        require(action in {"start", "run", "pause", "cont", "output", "pass", "skip"}, "failed/unknown JSON action")
        if test is not None:
            require(isinstance(test, str) and test.split("/")[0] in expected, "unlisted test")
            if action == "run":
                require(started and test not in active and test not in results, "duplicate/unstarted test")
                active.add(test)
            elif action in {"pass", "skip"}:
                require(test in active, "test completion without run")
                require(action != "skip", "unlisted test skip")
                active.remove(test); results[test] = action
            else:
                require(action in {"output", "pause", "cont"} and test in active, "test event ordering")
        elif action == "start":
            require(not started, "duplicate package start"); started = True
        elif action == "pass":
            require(started and not active, "incomplete package"); finished = True
        else:
            require(action == "output" and started, "package failure/skip")
    require(finished and not active and {n for n in results if "/" not in n} == expected, "missing frozen test coverage")
    return results


def container_policy(value, image, policy, name, token, suite="default"):
    c, h = value["Config"], value["HostConfig"]
    require(value["Image"] == image["Id"] and c["Image"] == image["Id"] and c["User"] == "0:0" and
            c["Entrypoint"] == ["/usr/bin/env"] and c["Cmd"] == suite_command(suite) and c["WorkingDir"] == "/work" and
            c.get("Env") == image["Config"].get("Env") and c.get("Labels") == {OWNER: token} and
            c.get("Healthcheck") == {"Test": ["NONE"]} and c.get("OpenStdin") is True and
            c.get("Tty") is False and not c.get("ExposedPorts") and not c.get("Volumes"), "exact container command/config")
    expected = {"Memory": 1 << 30, "MemorySwap": 1 << 30, "NanoCpus": 2000000000, "PidsLimit": 128,
                "ReadonlyRootfs": True, "NetworkMode": "none", "Privileged": False, "CapDrop": ["ALL"],
                "CapAdd": sorted("CAP_" + cap for cap in CAPS), "Tmpfs": TMPFS, "ShmSize": 16 << 20, "LogConfig": {"Type": "none", "Config": {}}}
    limits = h.get("Ulimits", [])
    require(len(limits) == 2 and {v["Name"]: (v["Soft"], v["Hard"]) for v in limits} ==
            {"nofile": (4096, 4096), "core": (0, 0)}, "exact FD/core limits")
    for key, expected_value in expected.items():
        require(h.get(key) == expected_value, "container policy: " + key)
    for key in ("Binds", "Mounts", "VolumesFrom", "Devices", "DeviceRequests", "DeviceCgroupRules", "PortBindings",
                "Links", "ExtraHosts", "Sysctls", "GroupAdd", "StorageOpt", "Dns", "DnsSearch", "DnsOptions"):
        require(not h.get(key), "forbidden container policy: " + key)
    for key in ("PidMode", "UTSMode", "UsernsMode", "CgroupParent", "ContainerIDFile"):
        require(h.get(key, "") == "", "host namespace/authority: " + key)
    require(h.get("IpcMode") == "private" and h.get("CgroupnsMode") == "private" and
            h.get("PublishAllPorts") is False and h.get("AutoRemove") is False and
            h.get("RestartPolicy") == {"Name": "no", "MaximumRetryCount": 0} and not value.get("Mounts"), "private isolated container")
    opts = h.get("SecurityOpt", [])
    require(len(opts) == 2 and any(o in ("no-new-privileges", "no-new-privileges:true") for o in opts), "no-new-privileges required")
    seccomp = [o[8:] for o in opts if o.startswith("seccomp=")]
    require(len(seccomp) == 1 and loads(seccomp[0]) == policy, "inspected seccomp differs")
    owned(value, name, token)
    require(value["State"]["Status"] == "created" and value["State"]["Running"] is False, "must inspect before start")


def owned(value, name, token, identifier=None):
    require(value.get("Name") == "/" + name and value.get("Config", {}).get("Labels", {}).get(OWNER) == token and
            (identifier is None or value.get("Id") == identifier), "exact owned container identity required")
    return inputs.sha(value["Id"])


def write_new(directory, name, raw):
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def endpoint_stamp(path):
    info = os.stat(path, follow_symlinks=False)
    require(stat.S_ISSOCK(info.st_mode), "explicit Unix socket required")
    return inputs.stamp(info)


def run(args):
    deadline = time.monotonic() + 300  # Cleanup is INSIDE this deadline.
    suite = args.suite
    groups, command = suite_groups(suite), suite_command(suite)
    selection = {"suite": suite, "groups": list(groups)}
    url = urlsplit(args.host)
    require(url.scheme == "unix" and not url.netloc and url.path.startswith("/") and url.path != "/" and
            not url.query and not url.fragment and not any(ord(c) < 33 for c in args.host), "explicit Unix endpoint required")
    inputs.approved_daemon_id(args.daemon_id)
    require(args.image_id.startswith("sha256:"), "local image ID required")
    inputs.sha(args.image_id[7:])
    # Validate Id and RepoDigests independently below. Containerd image stores
    # may report the manifest digest as Id; equality is not a missing pin.
    pinned_endpoint = endpoint_stamp(url.path)
    def endpoint_guard():
        require(endpoint_stamp(url.path) == pinned_endpoint, "original daemon endpoint changed; cleanup unproven")
    lock = OriginalLock(args.lock, args.lock_pid)
    attempted, removed, identifier, success = False, False, None, False
    start_failure, cleanup_inspected = None, None
    captured_raw, captured_files, inspected_after = None, {}, None
    destination = Path(args.destination).absolute()
    try:
        parent = destination.parent.lstat()
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o022, "private output parent required")
        destination.mkdir(mode=0o700)  # Never adopt an existing receipt directory.
        dest_identity = inputs.stamp(destination.lstat())[:2]
        config = destination / "docker-config"; config.mkdir(mode=0o700)
    except BaseException:
        lock.close(); raise
    token = uuid.uuid4().hex; name = "guest-unit-" + token
    base = [args.docker, "--config", str(config), "--host", args.host]
    cli_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(config), "LANG": "C", "LC_ALL": "C"}
    def output_guard():
        info = destination.lstat()
        require(inputs.stamp(info)[:2] == dest_identity and stat.S_ISDIR(info.st_mode) and
                info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, "receipt directory changed")
        require(time.monotonic() < deadline, "parent deadline")
    def guard():
        output_guard(); lock.check(); endpoint_guard()
        require(time.monotonic() < deadline - 25, "cleanup/publication reserve deadline")
    def save(filename, raw):
        guard(); write_new(destination, filename, raw); guard()
    def call(*values, cleanup=False, maximum=1 << 20, input_file=None):
        require(not cleanup or values[:2] in (("container", "inspect"), ("container", "ls")) or values[0] in ("rm", "info"), "cleanup-only command")
        # Leave 20s for cleanup and a separate 5s publication window.
        return run_bounded(base + list(values), min(deadline - (5 if cleanup else 25), time.monotonic() + (275 if values[0] == "start" else 5)),
                           env=cli_env, input_file=input_file, maximum=maximum, guard=endpoint_guard if cleanup else guard)
    def inspect(target, cleanup=False):
        rows = loads(call("container", "inspect", target, cleanup=cleanup))
        require(isinstance(rows, list) and len(rows) == 1, "exact container inspect")
        owned(rows[0], name, token, identifier)
        return rows[0]
    def listing(kind, value):
        raw = call("container", "ls", "-a", "--no-trunc", "--filter", kind + "=" + value, "--format", "{{json .}}", cleanup=True)
        return [loads(line) for line in raw.splitlines()]
    def cleanup_identity():
        identity = loads(call("info", "--format", "{{json .}}", cleanup=True))
        require(identity.get("ID") == args.daemon_id, "cleanup daemon identity changed; absence unproven")
    previous_signals = {}
    def interrupted(signum, frame):
        raise RuntimeError("runner interrupted")
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous_signals[sig] = signal.signal(sig, interrupted)
    try:
        source = snapshot(ROOT, guard)
        hashes = {n: digest(b) for n, b in source.items()}
        policy = validate_policy(source[POLICY], source[SUPERVISOR])
        expected = expected_tests(source, suite)
        selection["group_sources"] = {g: {n: h for n, h in hashes.items() if n.startswith("Guest/internal/" + g + "/")}
                                      for g in groups}
        save("seccomp.json", source[POLICY])
        payload = archive(source, guard); save("source.tar", payload)
        plan = {**selection, "schema": "guest-unit-bounded-v1", "name": name, "owner": token, "daemon_id": args.daemon_id,
                "reference": inputs.BUILDER, "image_id": args.image_id, "sources": hashes,
                "archive_sha256": digest(payload), "policy_sha256": digest(source[POLICY]),
                "expected_tests": {g: sorted(t) for g, t in expected.items()}, "command": command}
        save("plan.json", encode(plan))
        info = loads(call("info", "--format", "{{json .}}"))
        require(info.get("ID") == args.daemon_id and info.get("OSType") == "linux" and
                info.get("Architecture") in ("arm64", "aarch64") and info.get("CgroupVersion") == "2", "daemon identity mismatch")
        images = loads(call("image", "inspect", inputs.BUILDER))
        require(isinstance(images, list) and len(images) == 1, "exact cached image")
        image = images[0]
        require(image["Id"] == args.image_id and isinstance(image["RepoDigests"], list) and inputs.BUILDER in image["RepoDigests"] and image["Os"] == "linux" and
                image["Architecture"] == "arm64" and not image["Config"].get("Volumes") and
                not image["Config"].get("ExposedPorts"), "cached image ID/digest/platform mismatch")
        create = ["create", "--pull=never", "--name", name, "--label", OWNER + "=" + token,
                  "--platform", "linux/arm64", "--user", "0:0", "--network", "none", "--read-only", "--cap-drop", "ALL"]
        for cap in CAPS: create += ["--cap-add", cap]
        create += ["--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + str(destination / "seccomp.json"),
                   "--memory", "1g", "--memory-swap", "1g", "--cpus", "2", "--pids-limit", "128",
                   "--ulimit", "nofile=4096:4096", "--ulimit", "core=0:0", "--shm-size", "16m", "--log-driver", "none",
                   "--ipc", "private", "--cgroupns", "private", "--restart", "no", "--no-healthcheck", "--workdir", "/work",
                   "--entrypoint", "/usr/bin/env"]
        for path, options in TMPFS.items(): create += ["--tmpfs", path + ":" + options]
        guard(); attempted = True
        identifier = inputs.sha(call(*create, "-i", args.image_id, *command).decode().strip())
        inspected = inspect(identifier); container_policy(inspected, image, policy, name, token, suite)
        save("inspect.before.json", encode(inspected))
        # Refuse a late start rather than let the parent cut off the worker's
        # 212s maximum before its bounded export window. Cleanup keeps 20s.
        require(time.monotonic() + 250 < deadline - 25, "insufficient failure-export budget")
        with open(destination / "source.tar", "rb") as stream:
            require(digest(stream.read()) == digest(payload), "source archive changed")
            stream.seek(0)
            try:
                raw = call("start", "-ai", identifier, input_file=stream, maximum=MAX_OUTPUT)
            except CommandFailure as error:
                # Retain already-exported bytes in memory through exact-owner
                # cleanup. Failure publication/fsync must not spend its reserve.
                start_failure = error
                raise
        captured_raw = raw
        files = unpack(raw, guard, suite=suite); captured_files = files
        state = inspect(identifier)["State"]
        inspected_after = encode(state)
        require(state["Running"] is False and type(state["ExitCode"]) is int and state["ExitCode"] == 0 and
                state["OOMKilled"] is False and state.get("Error", "") == "", "unit exit/OOM failure")
        require(files["run.status"] == b"0\n" and all(files["group-" + str(i) + ".status"] == b"0\n"
                for i in range(len(groups))), "incomplete/failed group status")
        inventory = b"".join((hashes[n] + "  ./" + n).encode() + b"\0" for n in sorted(source))
        require(files["source.before"] == files["source.after"] == inventory, "container source bytes changed")
        require(files["toolchain.before"] == files["toolchain.after"], "toolchain changed")
        guard(); toolchain = inputs.toolchain_proof(files["toolchain.before"]); guard()
        results = {g: coverage(files["group-" + str(i) + ".jsonl"], g, expected[g], guard) for i, g in enumerate(groups)}
        success = True
    finally:
        # Once normal authority is lost or execution finishes, ONLY exact-owner
        # inspect/list/removal can touch the engine. Never remove by name alone.
        for sig in previous_signals: signal.signal(sig, signal.SIG_IGN)
        try:
            if attempted:
                cleanup_identity()
                queries = [("name", "^/" + name + "$"), ("label", OWNER + "=" + token)]
                if identifier is not None: queries.append(("id", identifier))
                candidates = {inputs.sha(row["ID"]) for kind, match in queries for row in listing(kind, match)}
                require(len(candidates) <= 1, "ambiguous owned create")
                if candidates:
                    value = inspect(candidates.pop(), cleanup=True)
                    identifier = owned(value, name, token, identifier)
                    cleanup_inspected = encode(value)
                    call("rm", "-f", identifier, cleanup=True)
                if identifier is not None and ("id", identifier) not in queries: queries.append(("id", identifier))
                require(all(not listing(kind, match) for kind, match in queries), "owned cleanup absence unproven")
                cleanup_identity()
                removed = True
        finally:
            try:
                output_guard()
                write_new(destination, "cleanup.json", encode({**selection, "container": identifier, "removed": removed, "execution_complete": success}))
                if start_failure is not None:
                    write_new(destination, "output.tar", start_failure.output)
                    write_new(destination, "start.stderr", start_failure.errors)
                    write_new(destination, "start.failure.json", encode({**selection, "error": str(start_failure)[:2048],
                              "returncode": start_failure.returncode, "complete": False}))
                if captured_raw is not None:
                    write_new(destination, "output.tar", captured_raw)
                    for filename, data in captured_files.items():
                        output_guard(); write_new(destination, filename, data)
                if inspected_after is not None:
                    output_guard(); write_new(destination, "inspect.after.json", inspected_after)
                if cleanup_inspected is not None:
                    output_guard(); write_new(destination, "inspect.cleanup.json", cleanup_inspected)
                if success and removed:
                    # Keep the ORIGINAL pinned lock FD through publication.
                    def final_guard():
                        lock.check(); output_guard(); endpoint_guard()
                    require({n: digest(b) for n, b in snapshot(ROOT, final_guard).items()} == hashes,
                            "source/policy/runner changed before pass")
                    final_guard()
                    receipt = {**plan, "container": identifier, "toolchain": toolchain, "results": results,
                               "output_sha256": digest(raw), "exit": 0, "oom": False, "removed": True}
                    write_new(destination, "receipt.json", encode(receipt))
            finally:
                lock.close()
                for sig, handler in previous_signals.items(): signal.signal(sig, handler)
    require(success and removed, "completed owned units required")
    print(json.dumps({"suite": suite, "groups": list(groups), "receipt": str(destination / "receipt.json"), "sha256": digest(encode(receipt))}))


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "daemon-id", "image-id", "lock", "destination"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--suite", choices=tuple(SUITES), default="default", help="closed group selection; default preserves the original four groups")
    parser.add_argument("--lock-pid", type=int, required=True)
    parser.add_argument("--docker", default="docker", help="CLI executable; no engine action except this fixed protocol")
    return parser


if __name__ == "__main__":
    run(argument_parser().parse_args())
