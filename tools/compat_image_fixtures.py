#!/usr/bin/env python3
"""Explicit, stdlib-only preparation of the Compose/Buildx OCI fixtures.

prepare() is the only network entry point. verify() and archive() are offline.
The pinned upstream index is retained as proof; index.json references ONLY the
selected linux/arm64 manifest, whose entire import graph is present locally.
"""
import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_CACHE = Path(__file__).resolve().parents[1] / ".build/compat-image-fixtures-v1"
FIXTURES = {
    "python": "docker.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0",
    "buildkit": "docker.io/moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8",
    "alpine": "docker.io/library/alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
}
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
CONFIG_TYPES = {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}
LAYER_TYPES = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar.gzip"}
MAX_METADATA = 4 * 1024 * 1024
MAX_BLOB = 2 * 1024 * 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024 * 1024
MAX_DESCRIPTORS = 256
MAX_REQUESTS = 1024
MAX_SECONDS = 900
SOCKET_TIMEOUT = 30
CHUNK = 64 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class FixtureError(ValueError):
    """Unusable or unavailable fixture; never a reason to download implicitly."""


def require(condition, message):
    if not condition:
        raise FixtureError(message)


def source(name):
    require(name in FIXTURES, f"unknown fixture: {name!r}")
    return FIXTURES[name]


def digest(value):
    require(isinstance(value, str) and DIGEST.fullmatch(value), "invalid sha256 digest")
    return value


def blob_path(layout, value):
    return layout / "blobs/sha256" / digest(value).split(":")[1]


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise FixtureError(f"invalid JSON: {error}") from error
    require(isinstance(value, dict), "expected JSON object")
    return value


class Budget:
    def __init__(self):
        self.deadline = time.monotonic() + MAX_SECONDS
        self.total = 0
        self.requests = 0

    def check(self, amount=0):
        self.total += amount
        require(self.total <= MAX_TOTAL, "fixture exceeds total byte bound")
        require(time.monotonic() < self.deadline, "fixture exceeded time bound")


def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode), f"not a regular file (symlinks forbidden): {path}")


def directory(path):
    require(stat.S_ISDIR(path.lstat().st_mode), f"not a directory (symlinks forbidden): {path}")


def entries(path, limit):
    result = []
    with os.scandir(path) as iterator:
        for entry in iterator:
            require(len(result) < limit, f"directory entry count bound: {path}")
            result.append(Path(entry.path))
    return result


def read_metadata(path):
    regular(path)
    require(path.stat().st_size <= MAX_METADATA, f"metadata exceeds byte bound: {path}")
    with path.open("rb") as stream:
        data = stream.read(MAX_METADATA + 1)
    require(len(data) <= MAX_METADATA, "metadata exceeds byte bound")
    return parse_json(data)


def descriptor(value, types, limit=MAX_BLOB):
    require(isinstance(value, dict), "invalid descriptor")
    digest(value.get("digest"))
    size = value.get("size")
    require(type(size) is int and 0 <= size <= limit, "descriptor exceeds size bound or has invalid size")
    require(value.get("mediaType") in types, "unsupported descriptor media type")
    require(not value.get("urls") and "data" not in value, "external/inline descriptor forbidden")
    return value


def arm64(platform):
    return isinstance(platform, dict) and platform.get("os") == "linux" and platform.get("architecture") == "arm64" and platform.get("variant", "v8") == "v8"


def select(root):
    require(root.get("schemaVersion") == 2 and root.get("mediaType") in INDEX_TYPES, "pin must identify an image index")
    entries = root.get("manifests")
    require(isinstance(entries, list) and 0 < len(entries) <= MAX_DESCRIPTORS, "index descriptor count bound")
    selected = [entry for entry in entries if isinstance(entry, dict) and arm64(entry.get("platform"))]
    require(len(selected) == 1, "index must contain exactly one linux/arm64 manifest")
    entry = descriptor(selected[0], MANIFEST_TYPES, MAX_METADATA)
    return {"mediaType": entry["mediaType"], "digest": entry["digest"], "size": entry["size"], "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}}


def graph(manifest):
    require(manifest.get("schemaVersion") == 2 and manifest.get("mediaType") in MANIFEST_TYPES, "invalid image manifest")
    config = descriptor(manifest.get("config"), CONFIG_TYPES, MAX_METADATA)
    layers = manifest.get("layers")
    require(isinstance(layers, list) and len(layers) <= MAX_DESCRIPTORS, "layer count bound")
    return config, [descriptor(layer, LAYER_TYPES) for layer in layers]


def check_config(config, layers):
    require(arm64(config), "image config must be linux/arm64/v8")
    rootfs = config.get("rootfs")
    require(isinstance(rootfs, dict) and rootfs.get("type") == "layers", "invalid config rootfs")
    ids = rootfs.get("diff_ids")
    if not isinstance(ids, list) or len(ids) != len(layers):
        raise FixtureError("config/layer count mismatch")
    for value in ids:
        digest(value)


def hash_file(path, expected, size, budget):
    regular(path)
    require(path.stat().st_size == size, f"blob size mismatch: {path.name}")
    actual = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK):
            budget.check(len(chunk))
            count += len(chunk)
            require(count <= size, "blob exceeds expected size")
            actual.update(chunk)
    require(count == size and "sha256:" + actual.hexdigest() == expected, f"blob digest mismatch: {path.name}")


def _verify(name, layout, budget):
    pin = source(name).split("@", 1)[1]
    directory(layout)
    directory(layout / "blobs")
    directory(layout / "blobs/sha256")
    require({p.name for p in entries(layout, 4)} == {"oci-layout", "index.json", "provenance.json", "blobs"}, "unexpected layout entries")
    require({p.name for p in entries(layout / "blobs", 1)} == {"sha256"}, "unexpected blob algorithms")
    require(read_metadata(layout / "oci-layout") == {"imageLayoutVersion": "1.0.0"}, "invalid OCI layout version")
    root_path = blob_path(layout, pin)
    regular(root_path)
    size = root_path.stat().st_size
    require(size <= MAX_METADATA, "root index exceeds metadata bound")
    hash_file(root_path, pin, size, budget)
    selected = select(read_metadata(root_path))
    require(read_metadata(layout / "provenance.json") == {"version": 1, "source": source(name), "manifest_digest": selected["digest"]}, "provenance does not match checked-in pin/selected manifest")
    require(read_metadata(layout / "index.json") == {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [selected]}, "import index must contain only the selected manifest")
    seen = {pin: size}

    def check(entry):
        value, length = entry["digest"], entry["size"]
        if value in seen:
            require(seen[value] == length, "conflicting blob sizes")
        else:
            hash_file(blob_path(layout, value), value, length, budget)
            seen[value] = length

    check(selected)
    manifest = read_metadata(blob_path(layout, selected["digest"]))
    require(manifest.get("mediaType") == selected["mediaType"], "manifest media type mismatch")
    config, layers = graph(manifest)
    for entry in [config, *layers]:
        check(entry)
    check_config(read_metadata(blob_path(layout, config["digest"])), layers)
    actual = set()
    for path in entries(layout / "blobs/sha256", MAX_DESCRIPTORS + 3):
        regular(path)
        actual.add("sha256:" + path.name)
    require(actual == set(seen), "unexpected or missing blobs")
    return selected["digest"]


def verify(name, cache=DEFAULT_CACHE):
    """Fully hash and validate a fixture offline; return its OCI layout Path."""
    source(name)
    layout = Path(cache) / name
    try:
        directory(Path(cache))
        _verify(name, layout, Budget())
    except (OSError, FixtureError) as error:
        raise FixtureError(f"fixture {name}: {error}. Run make test-compat-images to prepare missing fixtures; existing invalid caches must be inspected/removed explicitly.") from error
    return layout


def manifest_digest(name, cache=DEFAULT_CACHE):
    """Return the verified selected linux/arm64 manifest digest, never the index pin."""
    layout = verify(name, cache)
    return read_metadata(layout / "provenance.json")["manifest_digest"]


def https(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment, "only credential-free HTTPS URLs are permitted")
    return parsed


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        https(newurl)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            # Never forward registry bearer credentials to a CDN or token redirect.
            redirected.remove_header("Authorization")
        return redirected


class Registry:
    def __init__(self, repository, budget, opener=None):
        self.repository = repository
        self.budget = budget
        self.opener = opener or urllib.request.build_opener(HTTPSRedirect())
        self.token = None

    def request(self, url, authorized=False):
        https(url)
        self.budget.check()
        self.budget.requests += 1
        require(self.budget.requests <= MAX_REQUESTS, "request count bound")
        headers = {"Accept": ", ".join(sorted(INDEX_TYPES | MANIFEST_TYPES)), "Accept-Encoding": "identity"}
        if authorized and self.token:
            headers["Authorization"] = "Bearer " + self.token
        return self.opener.open(urllib.request.Request(url, headers=headers), timeout=min(SOCKET_TIMEOUT, max(0.1, self.budget.deadline - time.monotonic())))

    def chunks(self, response, limit):
        require(response.status == 200, "registry did not return HTTP 200")
        require(response.headers.get("Content-Encoding", "identity") == "identity", "encoded registry response forbidden")
        length = response.headers.get("Content-Length")
        if length is not None:
            require(length.isdigit() and int(length) <= limit, "response exceeds size bound")
        count = 0
        while True:
            self.budget.check()
            chunk = response.read1(min(CHUNK, limit - count + 1))
            if not chunk:
                break
            count += len(chunk)
            self.budget.check(len(chunk))
            require(count <= limit, "response exceeds size bound")
            yield chunk
        require(length is None or count == int(length), "truncated registry response")

    def authenticate(self, challenge):
        require(challenge and challenge.startswith("Bearer "), "registry requires unsupported authentication")
        fields = urllib.request.parse_keqv_list(urllib.request.parse_http_list(challenge[7:]))
        realm = fields.get("realm")
        require(realm == "https://auth.docker.io/token", "untrusted bearer token realm")
        require(fields.get("service") == "registry.docker.io", "unexpected bearer service")
        scope = f"repository:{self.repository}:pull"
        require(fields.get("scope") == scope, "unexpected bearer scope")
        url = "https://auth.docker.io/token?" + urllib.parse.urlencode({"service": "registry.docker.io", "scope": scope})
        with self.request(url) as response:
            data = parse_json(b"".join(self.chunks(response, MAX_METADATA)))
        token = data.get("token", data.get("access_token"))
        require(isinstance(token, str) and 0 < len(token) <= 16384 and all(32 < ord(c) < 127 for c in token), "invalid bearer token")
        self.token = token

    def download(self, layout, value, kind, size=None):
        digest(value)
        path = blob_path(layout, value)
        if path.exists():
            hash_file(path, value, path.stat().st_size if size is None else size, self.budget)
            return
        limit = MAX_METADATA if kind == "manifests" else MAX_BLOB
        if size is not None:
            require(0 <= size <= limit, "download size bound")
            limit = size
        url = f"https://registry-1.docker.io/v2/{self.repository}/{kind}/{value}"
        try:
            response = self.request(url, authorized=True)
        except urllib.error.HTTPError as error:
            challenge = error.headers.get("WWW-Authenticate")
            error.close()
            if error.code != 401:
                raise
            self.authenticate(challenge)
            response = self.request(url, authorized=True)
        actual = hashlib.sha256()
        count = 0
        with response, path.open("xb") as output:
            for chunk in self.chunks(response, limit):
                output.write(chunk)
                actual.update(chunk)
                count += len(chunk)
        require(size is None or count == size, "download size mismatch")
        require("sha256:" + actual.hexdigest() == value, "download digest mismatch")


def publish(staging, target):
    """Atomic directory rename with exclusive creation, including empty targets."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = libc.renamex_np
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        result = rename(os.fsencode(staging), os.fsencode(target), 0x4)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        rename = libc.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        result = rename(-100, os.fsencode(staging), -100, os.fsencode(target), 1)  # RENAME_NOREPLACE
    else:
        raise FixtureError("atomic exclusive directory publication requires macOS or Linux")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(target))


@contextlib.contextmanager
def download_deadline():
    """Interrupt even DNS/header reads: socket idle timeouts alone allow drips.

    Explicit downloads run on the main thread (the CLI path). Refuse to alter
    another caller's active process timer rather than silently weakening bounds.
    Offline verification has no signal/thread restrictions.
    """
    require(threading.current_thread() is threading.main_thread(), "prepare downloads require the main thread; use the prepare CLI")
    require(MAX_SECONDS > 0, "fixture exceeded time bound")
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "prepare cannot run with an existing process timer")
    previous = signal.getsignal(signal.SIGALRM)

    def expired(signum, frame):
        raise FixtureError("fixture exceeded time bound")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, MAX_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def prepare(name, cache=DEFAULT_CACHE, *, opener=None):
    """Explicit HTTPS download; atomically publish only a verified private layout.

    opener is an injectable urllib-compatible transport for offline unit tests.
    A cache-directory flock serializes cooperating preparers. Existing invalid
    entries are never repaired or removed; only this call's staging is cleaned.
    """
    reference = source(name)
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    directory(cache)
    with contextlib.ExitStack() as stack:
        fd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise FixtureError("another fixture preparation holds the cache lock; retry after it finishes") from error
        target = cache / name
        if os.path.lexists(target):
            return verify(name, cache)
        stack.enter_context(download_deadline())
        staging = Path(tempfile.mkdtemp(prefix=f".{name}-", dir=cache))
        stack.callback(shutil.rmtree, staging, True)
        (staging / "blobs/sha256").mkdir(parents=True)
        budget = Budget()
        repository, pin = reference.removeprefix("docker.io/").split("@", 1)
        registry = Registry(repository, budget, opener)
        registry.download(staging, pin, "manifests")
        selected = select(read_metadata(blob_path(staging, pin)))
        registry.download(staging, selected["digest"], "manifests", selected["size"])
        config, layers = graph(read_metadata(blob_path(staging, selected["digest"])))
        for entry in [config, *layers]:
            registry.download(staging, entry["digest"], "blobs", entry["size"])
        for filename, value in {
            "oci-layout": {"imageLayoutVersion": "1.0.0"},
            "index.json": {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [selected]},
            "provenance.json": {"version": 1, "source": reference, "manifest_digest": selected["digest"]},
        }.items():
            (staging / filename).write_bytes(json_bytes(value))
        # Separate byte budget for the full offline hash pass; shared deadline.
        validation = Budget()
        validation.deadline = budget.deadline
        _verify(name, staging, validation)
        require(not os.path.lexists(target), "cache appeared during preparation; refusing replacement")
        publish(staging, target)
        return target


def archive(name, output, cache=DEFAULT_CACHE):
    """Write a standard OCI tar from a verified layout (no provenance file)."""
    layout = verify(name, cache)
    output = Path(output)
    require(not os.path.lexists(output), f"archive output already exists: {output}")
    require(not output.resolve().is_relative_to(layout.resolve()), "archive output must be outside layout")
    fd, temporary = tempfile.mkstemp(prefix=".oci-archive-", dir=output.parent)
    os.close(fd)
    try:
        with tarfile.open(temporary, "w", format=tarfile.USTAR_FORMAT) as tar:
            for name in ("blobs", "blobs/sha256"):
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
            paths = [layout / "oci-layout", layout / "index.json", *sorted(entries(layout / "blobs/sha256", MAX_DESCRIPTORS + 3))]
            for path in paths:
                regular(path)
                info = tarfile.TarInfo(path.relative_to(layout).as_posix())
                info.size = path.stat().st_size
                info.mode = 0o644
                with path.open("rb") as stream:
                    tar.addfile(info, stream)
        os.link(temporary, output)  # Atomic no-replace publication.
    finally:
        os.unlink(temporary)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "check"):
        subparser = commands.add_parser(command)
        subparser.add_argument("names", nargs="+", choices=tuple(FIXTURES))
    subparser = commands.add_parser("archive")
    subparser.add_argument("name", choices=tuple(FIXTURES))
    subparser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "archive":
            print(archive(args.name, args.output, args.cache))
        else:
            action = prepare if args.command == "prepare" else verify
            for name in args.names:
                print(action(name, args.cache))
    except (OSError, FixtureError, urllib.error.URLError, http.client.HTTPException) as error:
        print(f"compat image fixtures: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
