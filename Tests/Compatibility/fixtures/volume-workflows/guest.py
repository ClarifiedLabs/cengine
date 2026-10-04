"""Fixed guest-only actions. Importing this module is safe; main requires Linux VM paths.

No shell, index, build backend, hooks, device operations, mount commands or binds.
The venv has no pip copy: the pinned base image's pip manages it with --python.
"""
from __future__ import annotations

import base64
from decimal import Decimal
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile

UID = 10001
TREE = Path("/work/tree")
VENV = str(TREE / "venv")
PYTHON = "/usr/local/bin/python"
MAX_TREE = 4 * 1024 * 1024
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_FILES = 256
MAX_OUTPUT = 256 * 1024
ACTIONS = {"initialize", "install", "backup", "restore", "verify", "identity"}
CONFIG = b"[application]\nowner=10001\nsecret=offline-fixture-only\n"
PAYLOAD = b"user-owned hardlink data\x00\n"


def commands():
    result = {
        "python-version": [PYTHON, "--version"],
        "pip-version": [PYTHON, "-m", "pip", "--version"],
        "venv": [PYTHON, "-m", "venv", "--without-pip", VENV],
        "entrypoint": [VENV + "/bin/volume-workflow"],
    }
    for version in ("1.0", "2.0"):
        result["install-" + version] = [
            PYTHON, "-m", "pip", "--python", VENV + "/bin/python",
            "--isolated", "--disable-pip-version-check", "install", "--no-index",
            "--no-deps", "--no-compile", "--no-cache-dir", "--upgrade",
            f"/tmp/volume_workflow-{version}-py3-none-any.whl",
        ]
    return result


def run_command(name, observations):
    if name not in commands():
        raise ValueError("command is not allowlisted")
    argv = commands()[name]
    # Temporary output is physically tmpfs-bounded; each child has a smaller
    # file-size ceiling. No unbounded PIPE/communicate buffer or shell execution.
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True,
                                   preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536)))
        failure = None
        try:
            process.wait(timeout=35)
        except BaseException as error:
            failure = error
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        output.seek(0)
        data = output.read(65537)
    if len(data) > 65536:
        raise ValueError("command output bound exceeded")
    text = data.decode("utf-8", errors="strict")
    observations.append({"argv": argv, "exit": process.returncode, "output": text})
    if failure is not None:
        raise failure
    if process.returncode != 0:
        raise RuntimeError(f"{name} exited {process.returncode}: {text}")
    return text


def inventory(root=TREE):
    """Raw nlink plus within-filesystem equivalence classes, never cross-engine inode IDs."""
    entries, groups, total = {}, {}, 0
    paths = [root]
    # Explicit bounded walk does not follow symlinks and never filters .nfs names.
    for path in paths:
        if len(paths) > MAX_FILES:
            raise ValueError("tree entry bound exceeded")
        info = path.lstat()
        name = "." if path == root else path.relative_to(root).as_posix()
        entry: dict = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
                 "gid": info.st_gid, "mtime_ns": info.st_mtime_ns, "nlink": info.st_nlink}
        if stat.S_ISDIR(info.st_mode):
            entry["type"] = "directory"
            with os.scandir(path) as children:
                for child in children:
                    paths.append(Path(child.path))
                    if len(paths) > MAX_FILES:
                        raise ValueError("tree entry bound exceeded")
        elif stat.S_ISLNK(info.st_mode):
            entry.update(type="symlink", target=os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            total += info.st_size
            if total > MAX_TREE:
                raise ValueError("tree byte bound exceeded")
            entry.update(type="file", size=info.st_size,
                         sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            groups.setdefault((info.st_dev, info.st_ino), []).append(name)
        else:
            raise ValueError("unexpected non-file tree entry")
        entries[name] = entry
    for names in groups.values():
        for name in names:
            entries[name]["links"] = sorted(names)
    return {"entries": dict(sorted(entries.items())), "bytes": total}


def validate_members(members):
    """Reject traversal/devices/duplicates/links through directories before any write."""
    if not 1 <= len(members) <= MAX_FILES:
        raise ValueError("archive entry bound exceeded")
    seen, total = {}, 0
    for member in members:
        name = member.name
        path = PurePosixPath(name)
        if (not name or path.is_absolute() or ".." in path.parts or str(path) != name
                or name in seen or (name != "tree" and not name.startswith("tree/"))):
            raise ValueError("unsafe archive name")
        if member.uid != UID or member.gid != UID or member.mode & ~0o777:
            raise ValueError("unsafe archive metadata")
        if name != "tree" and (str(path.parent) not in seen or not seen[str(path.parent)].isdir()):
            raise ValueError("archive parent must precede children and be a directory")
        if member.isfile():
            if member.size < 0:
                raise ValueError("negative archive member size")
            total += member.size
        elif member.isdir():
            pass
        elif member.issym():
            target = PurePosixPath(member.linkname)
            # venv's base interpreter is the only permitted out-of-tree link.
            if target.is_absolute():
                interpreters = {"python", "python3", f"python3.{sys.version_info.minor}"}
                if (path.parent != PurePosixPath("tree/venv/bin") or path.name not in interpreters
                        or target.parent != PurePosixPath("/usr/local/bin") or target.name not in interpreters
                        or not os.path.samefile(member.linkname, PYTHON)):
                    raise ValueError("unsafe absolute symlink")
            elif not member.linkname or ".." in target.parts:
                raise ValueError("unsafe relative symlink")
        elif member.islnk():
            if member.linkname not in seen or not seen[member.linkname].isfile():
                raise ValueError("hardlink must name preceding regular file")
        else:
            raise ValueError("archive special entry forbidden")
        if total > MAX_TREE:
            raise ValueError("archive expanded size bound exceeded")
        seen[name] = member
    if not seen["tree"].isdir():
        raise ValueError("archive root must be a directory")
    return members


def verify_app(observations, version="2.0"):
    expected = "first resource" if version == "1.0" else "upgraded resource"
    assert run_command("entrypoint", observations) == f"volume-workflow {version}: {expected}\n"
    packages = list((TREE / "venv/lib").glob("python*/site-packages/volume_workflow"))
    assert len(packages) == 1
    package = packages[0]
    assert (package / "message.txt").read_text() == expected + "\n"
    assert (package / ("v1_only.txt" if version == "1.0" else "v2_only.txt")).read_text() == version
    if version == "2.0":
        assert not (package / "v1_only.txt").exists()
        assert not (package.parent / "volume_workflow-1.0.dist-info").exists()
    config = TREE / "config/app.ini"
    assert config.read_bytes() == CONFIG
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert os.readlink(TREE / "current") == "config/app.ini"
    a, b = (TREE / "data/primary").stat(), (TREE / "data/alias").stat()
    assert (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and a.st_nlink == b.st_nlink == 2
    assert (TREE / "data/primary").read_bytes() == (TREE / "data/alias").read_bytes() == PAYLOAD
    result = inventory()
    assert all(item["uid"] == UID and item["gid"] == UID for item in result["entries"].values())
    return result


def execute(action, wheels, result):
    observations = result["commands"]
    with open("/proc/self/mountinfo") as mounts:
        for line in mounts:
            if len(line) > 8192:
                raise ValueError("mountinfo line bound exceeded")
            fields = line.split()
            if fields[4] in ("/work", "/backup", "/"):
                result["mountinfo"].append(line.rstrip())
    assert any(line.split()[4] == "/work" for line in result["mountinfo"])
    run_command("python-version", observations)
    run_command("pip-version", observations)
    if action == "initialize":
        assert os.getuid() == 0
        # Only fresh owned mount's root; no recursive chown/delete.
        os.chown("/work", UID, UID)
        os.chmod("/work", 0o700)
    else:
        assert os.getuid() == os.getgid() == UID
    if action == "install":
        TREE.mkdir(mode=0o700)
        (TREE / "config").mkdir(mode=0o700)
        (TREE / "data").mkdir(mode=0o700)
        (TREE / "config/app.ini").write_bytes(CONFIG)
        (TREE / "config/app.ini").chmod(0o600)
        (TREE / "data/primary").write_bytes(PAYLOAD)
        os.link(TREE / "data/primary", TREE / "data/alias")
        os.symlink("config/app.ini", TREE / "current")
        for name, encoded in wheels.items():
            (Path("/tmp") / name).write_bytes(base64.b64decode(encoded, validate=True))
        run_command("venv", observations)
        for version in ("1.0", "2.0"):
            run_command("install-" + version, observations)
            result["installed-" + version] = verify_app(observations, version)
    elif action == "backup":
        # Prove source protection, rather than trusting just HostConfig.
        try:
            descriptor = os.open(TREE / "must-not-write", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as error:
            assert error.errno == errno.EROFS, error
        else:
            os.close(descriptor)
            raise AssertionError("backup source unexpectedly writable")
        result["inventory"] = inventory()
        archive_path = Path("/backup/tree.tar")
        with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT, dereference=False) as archive:
            for name, entry in result["inventory"]["entries"].items():
                path = TREE if name == "." else TREE / name
                arcname = "tree" if name == "." else "tree/" + name
                info = archive.gettarinfo(str(path), arcname)
                info.pax_headers = {**info.pax_headers, "mtime": str(Decimal(entry["mtime_ns"]) / 1000000000)}
                if info.isfile():
                    with path.open("rb") as content:
                        archive.addfile(info, content)
                else:
                    archive.addfile(info)
        assert archive_path.stat().st_size <= MAX_ARCHIVE
        result["archive"] = {"bytes": archive_path.stat().st_size,
                             "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()}
    elif action == "restore":
        archive_path = Path("/backup/tree.tar")
        assert archive_path.stat().st_size <= MAX_ARCHIVE
        assert not TREE.exists() and not TREE.is_symlink()
        result["archive"] = {"bytes": archive_path.stat().st_size,
                             "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()}
        with tarfile.open(archive_path, "r:") as archive:
            members = []
            for member in archive:
                members.append(member)
                if len(members) > MAX_FILES:
                    raise ValueError("archive entry bound exceeded")
            validate_members(members)
            # Manual extraction: never follows archive-created symlinks, never
            # creates special files, never asks a root extractor to trust a tar.
            for member in members:
                path = Path("/work") / member.name
                if member.isdir():
                    path.mkdir(mode=0o700)
                elif member.issym():
                    os.symlink(member.linkname, path)
                elif member.islnk():
                    os.link(Path("/work") / member.linkname, path)
                else:
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError("missing regular archive content")
                    with source, path.open("xb") as destination:
                        remaining = member.size
                        while remaining:
                            chunk = source.read(min(65536, remaining))
                            if not chunk:
                                raise ValueError("truncated archive content")
                            destination.write(chunk)
                            remaining -= len(chunk)
            for member in reversed(members):
                path = Path("/work") / member.name
                if not member.issym():
                    path.chmod(member.mode)
                ns = int(Decimal(member.pax_headers.get("mtime", str(member.mtime))) * 1000000000)
                os.utime(path, ns=(ns, ns), follow_symlinks=False)
        result["inventory"] = verify_app(observations)
    elif action == "verify":
        result["inventory"] = verify_app(observations)
    return result


def validate_request(request):
    if not isinstance(request, dict) or set(request) != {"action", "wheels"}:
        raise ValueError("invalid request schema")
    if not isinstance(request["action"], str) or request["action"] not in ACTIONS:
        raise ValueError("invalid action")
    wheels = request["wheels"]
    expected = {f"volume_workflow-{v}-py3-none-any.whl" for v in ("1.0", "2.0")}
    if not isinstance(wheels, dict) or set(wheels) != (expected if request["action"] == "install" else set()):
        raise ValueError("invalid wheel inputs")
    for value in wheels.values():
        if not isinstance(value, str) or len(value) > 45000 or len(base64.b64decode(value, validate=True)) > 32768:
            raise ValueError("invalid wheel size")
    return request


def run_request(request):
    result = {"schema": 1, "action": request["action"], "uid": os.getuid(), "gid": os.getgid(),
              "commands": [], "mountinfo": []}
    status = 0
    try:
        execute(request["action"], request["wheels"], result)
    except BaseException as error:
        status = 1
        result["error"] = {"type": type(error).__name__, "message": str(error)[:4096]}
    return result, status


def main():
    if len(sys.argv) != 2 or len(sys.argv[1]) > 100000:
        raise ValueError("invalid request size")
    request = validate_request(json.loads(sys.argv[1]))
    signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
    signal.alarm(90)  # PID1 exit kills its guest PID namespace, including stuck children.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARCHIVE, MAX_ARCHIVE))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    os.umask(0o077)
    result, status = run_request(request)
    encoded = json.dumps(result, sort_keys=True)
    if len(encoded.encode()) > MAX_OUTPUT:
        raise ValueError("result bound exceeded")
    print(encoded, flush=True)
    raise SystemExit(status)


if __name__ == "__main__":
    main()
