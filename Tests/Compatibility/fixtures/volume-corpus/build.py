#!/usr/bin/env python3
"""Build only on an explicitly authorized socket. Never runs filesystem scenarios."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
from volume_probe import encode, tar_bytes

BUILDER = "golang@sha256:2c4c60ef415fbfa5e90300722293bef36c5e63fae17570ce18f580af933dbd73"
HERE = Path(__file__).resolve().parent


MAX_SOURCE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * MAX_SOURCE_BYTES
REQUIRED_SOURCES = {"build.py", "config.h", "limit.c", "upstream/fsx-linux.c",
                    "upstream/pjdfstest/pjdfstest.c", "upstream/fsstress/fsstress.c",
                    "upstream/fsstress/global.h", "upstream/fsstress/xfscompat.h",
                    "upstream/fsstress/include/tst_common.h", "upstream/fsstress/Makefile",
                    "upstream/fsstress/COPYING"}


def read_source(root, name):
    """Read bounded regular inputs without following any source-path symlinks."""
    if (not isinstance(name, str) or not name or
            PurePosixPath(name).is_absolute() or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("unsafe corpus source path")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                             dir_fd=directory)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
                raise ValueError("corpus input must be a bounded regular file")
            data = source.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES:
                raise ValueError("corpus input exceeds size bound")
            return data
    finally:
        os.close(directory)


def validated_sources(root=HERE):
    provenance = json.loads(read_source(root, "provenance.json"))
    hashes = provenance.get("sha256")
    if (not isinstance(hashes, dict) or not REQUIRED_SOURCES <= hashes.keys()
            or len(hashes) > 128 or "provenance.json" in hashes):
        raise ValueError("invalid corpus source manifest")
    sources = {}
    total = 0
    for name, digest in sorted(hashes.items()):
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid corpus source digest")
        data = read_source(root, name)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("corpus source digest mismatch: " + name)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("corpus sources exceed total size bound")
        sources[name] = data
    return provenance, sources


def validate_build_host(host):
    endpoint = urlsplit(host)
    if (endpoint.scheme != "unix" or endpoint.netloc or not endpoint.path.startswith("/")
            or endpoint.path == "/" or endpoint.query or endpoint.fragment):
        raise ValueError("explicit absolute local build-only unix socket required")


def validate_build_version(version):
    names = [version.get("Platform", {}).get("Name", "")]
    names.extend(item.get("Name", "") for item in version.get("Components", []))
    if any("cengine" in name.lower() for name in names):
        raise ValueError("cengine is not an authorized corpus build endpoint")
    if version.get("Os") != "linux" or version.get("Arch") not in ("arm64", "aarch64"):
        raise ValueError("corpus builder requires a Linux arm64 server")


def build(host, destination):
    validate_build_host(host)
    provenance, sources = validated_sources(HERE)
    destination.mkdir(parents=True, exist_ok=True)
    owner = "volume-corpus-build-" + uuid.uuid4().hex
    docker = ["docker", "--host", host]
    def run(*args, **kwargs):
        result = subprocess.run(docker + list(args), timeout=120,
                                capture_output=True, **kwargs)
        if result.returncode:
            (destination / "build.log").write_bytes(result.stderr)
            print(result.stderr.decode(errors="replace"), file=sys.stderr)
            result.check_returncode()
        return result
    script = """set -eu
mkdir -p /src /out
tar -xf - -C /src
cd /src
gcc -O2 -static -include libgen.h -Wl,--build-id=none -o /out/fsx upstream/fsx-linux.c
gcc -O2 -static -Wl,--build-id=none -I. -o /out/pjdfstest upstream/pjdfstest/pjdfstest.c
gcc -O2 -static -Wl,--build-id=none -DNO_XFS -D_LARGEFILE64_SOURCE -D_GNU_SOURCE -I. -Iupstream/fsstress -Iupstream/fsstress/include -o /out/fsstress upstream/fsstress/fsstress.c
gcc -O2 -static -Wl,--build-id=none -o /out/limit limit.c
for file in /out/*; do
  readelf -h "$file" | grep -q AArch64
  if readelf -l "$file" | grep -q INTERP; then exit 1; fi
done
gcc --version > /out/compiler.txt
tar -cf - -C /out .
"""
    validate_build_version(json.loads(run("version", "--format", "{{json .Server}}").stdout))
    created = False
    try:
        run("create", "--name", owner, "--label", "dev.cengine.compat.corpus-build=" + owner,
            "--platform", "linux/arm64", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--memory", "512m", "--pids-limit", "64",
            "--read-only", "--tmpfs", "/src:rw,size=16m", "--tmpfs", "/out:rw,size=16m",
            "--tmpfs", "/tmp:rw,size=32m", "-i", BUILDER, "sh", "-ec", script)
        created = True
        # Archive the validated snapshot only: unlisted includes cannot shadow config.h.
        source = tar_bytes([(name, data, 0o644) for name, data in sources.items()])
        result = run("start", "-ai", owner, input=source)
        (destination / "build.log").write_bytes(result.stderr)
        state = json.loads(run("inspect", owner).stdout)[0]["State"]
        if state["ExitCode"] != 0:
            raise RuntimeError("corpus compilation failed; see " + str(destination / "build.log"))
        # tmpfs disappears on stop: binaries are emitted as a tar stream instead.
        import io
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as saved:
            binaries = {name: saved.extractfile("./" + name).read()
                        for name in ("fsx", "pjdfstest", "fsstress", "limit", "compiler.txt")}
        layer = tar_bytes([(name, binaries[name], 0o755) for name in ("fsx", "pjdfstest", "fsstress", "limit")]
                          + [("data", None, 0o755)]
                          + [("corpus-source/" + name, data, 0o644)
                             for name, data in sources.items()])
        config = encode({"architecture": "arm64", "os": "linux",
                         "config": {"Cmd": ["/limit", "keeper"]},
                         "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}})
        digest = hashlib.sha256(config).hexdigest()
        tag = "compat-volume-probe:" + digest
        archive = tar_bytes([(digest + ".json", config, 0o644), ("layer.tar", layer, 0o644),
                             ("manifest.json", encode([{"Config": digest + ".json", "RepoTags": [tag], "Layers": ["layer.tar"]}]), 0o644)])
        (destination / "fixture.tar").write_bytes(archive)
        (destination / "fixture.json").write_bytes(encode({"image": tag, "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "provenance": provenance, "builder": BUILDER, "compiler": binaries["compiler.txt"].decode()}) + b"\n")
        print(destination / "fixture.tar")
    finally:
        if created:
            run("rm", "-f", owner)


if __name__ == "__main__":
    # No ambient DOCKER_HOST/context fallback and no automatically installed packages.
    build(os.environ["CENGINE_CORPUS_BUILD_HOST"], ROOT / ".build/volume-corpus")
