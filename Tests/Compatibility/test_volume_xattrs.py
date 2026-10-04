"""RTM-073: direct-ext4 copyup of actual OCI-source xattrs, not tmpfs/NFS.

Linux contracts: xattr(7), acl(5), capabilities(7), lsetxattr(2).
The source preflight is intentional: an importer that drops PAX xattrs must fail
before this test can claim copyup coverage. Never seed the mounted destination.

Empty SCHILY.xattr values must survive OCI import as present zero-length attrs.
The mandatory source preflight prevents archive/tar's empty-value omission from
being mistaken for successful copyup.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import uuid

import docker
from docker.types import Mount
import pytest


# Linux errno values, not host errno (this test runner normally runs on Darwin).
EPERM, EACCES, EINVAL, ENODATA, EOPNOTSUPP = 1, 13, 22, 61, 95
USER = "user.cengine-fixture"
EMPTY = "user.cengine-empty"
ACCESS = "system.posix_acl_access"
DEFAULT = "system.posix_acl_default"
CAP = "security.capability"
NAMES = (USER, EMPTY, ACCESS, DEFAULT, CAP)
PAYLOAD = b"image-xattr-seed\n"
SENTINEL = b"symlink-target-must-not-change\n"


def _acl():
    # v2: root rwx, named UID 10001 r-x, group ---, mask r-x, other ---.
    entries = ((1, 7, 0xffffffff), (2, 5, 10001), (4, 0, 0xffffffff),
               (16, 5, 0xffffffff), (32, 0, 0xffffffff))
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *e) for e in entries)


ACL = _acl()
# VFS_CAP_REVISION_2 | EFFECTIVE; permitted CAP_NET_BIND_SERVICE only.
CAPABILITY = struct.pack("<IIIII", 0x02000001, 1 << 10, 0, 0, 0)
# Raw Linux security.capability xattrs are also storable on directories; they
# have no executable-capability meaning there, but must survive root copyup.
DIRECTORY_ATTRS = {USER: b"directory\x00value\xff", EMPTY: b"", ACCESS: ACL,
                   DEFAULT: ACL, CAP: CAPABILITY}
FILE_ATTRS = {USER: b"file\x00value\xff", EMPTY: b"", ACCESS: ACL, CAP: CAPABILITY}
SENTINEL_ATTRS = {USER: b"outside-sentinel"}
LINK_TIME = 1700000001
CAP_CHANGED = struct.pack("<IIIII", 0x02000001, 1, 0, 0, 0)
SYMLINKS = {
    "/populated/link": ("/sentinel", 0, 0, 0, {}),
    "/populated/cap-live": ("/sentinel", 10001, 10002, LINK_TIME, {CAP: CAPABILITY}),
    "/populated/cap-dangling": ("/missing-sentinel", 10001, 10002, LINK_TIME, {CAP: CAPABILITY}),
    "/links/live": ("/sentinel", 10001, 10002, LINK_TIME, {}),
    "/links/dangling": ("/missing-sentinel", 10001, 10002, LINK_TIME, {}),
}
EXPECTED = {
    "/empty": DIRECTORY_ATTRS,
    "/populated": DIRECTORY_ATTRS,
    "/populated/child": DIRECTORY_ATTRS,
    "/populated/file": FILE_ATTRS,
    "/populated/child/file": FILE_ATTRS,
    "/sentinel": SENTINEL_ATTRS,
}


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _tar(entries):
    """name, payload (None = directory), mode, attrs, optional symlink target."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT,
                      encoding="utf-8", errors="surrogateescape") as archive:
        for name, data, mode, attrs, target in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.uid = info.gid = info.mtime = 0
            if "/" + name in SYMLINKS:
                _, info.uid, info.gid, info.mtime, _ = SYMLINKS["/" + name]
            # Binary PAX values are raw bytes, NOT base64 or a UTF-8 conversion.
            info.pax_headers = {"SCHILY.xattr." + key: value.decode("utf-8", "surrogateescape")
                                for key, value in sorted(attrs.items())}
            if target is not None:
                info.type, info.linkname = tarfile.SYMTYPE, target
            elif data is None:
                info.type = tarfile.DIRTYPE
            else:
                info.size = len(data)
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return output.getvalue()


def _image_archive(binary):
    layer = _tar([
        ("probe", binary, 0o755, {}, None),
        ("empty", None, 0o750, DIRECTORY_ATTRS, None),
        ("populated", None, 0o750, DIRECTORY_ATTRS, None),
        ("populated/child", None, 0o750, DIRECTORY_ATTRS, None),
        ("populated/file", PAYLOAD, 0o750, FILE_ATTRS, None),
        ("populated/child/file", PAYLOAD, 0o750, FILE_ATTRS, None),
        ("populated/link", None, 0o777, {}, "/sentinel"),
        ("populated/cap-live", None, 0o777, {CAP: CAPABILITY}, "/sentinel"),
        ("populated/cap-dangling", None, 0o777, {CAP: CAPABILITY}, "/missing-sentinel"),
        ("links", None, 0o755, {}, None),
        ("links/live", None, 0o777, {}, "/sentinel"),
        ("links/dangling", None, 0o777, {}, "/missing-sentinel"),
        ("sentinel", SENTINEL, 0o644, SENTINEL_ATTRS, None),
    ])
    config = {"architecture": "arm64", "os": "linux",
              "config": {"Cmd": ["/probe", "serve"], "User": "0:0"},
              "rootfs": {"type": "layers", "diff_ids": [_digest(layer)]}}
    config_data = _encode(config)

    def descriptor(data, media):
        return {"mediaType": "application/vnd.oci." + media,
                "digest": _digest(data), "size": len(data)}

    manifest = _encode({"schemaVersion": 2,
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": descriptor(config_data, "image.config.v1+json"),
                        "layers": [descriptor(layer, "image.layer.v1.tar")]})
    # Content-addressed identity; no timestamp, UUID, registry lookup or build VM.
    tag = "compat-volume-xattrs:" + _digest(manifest).split(":")[1]
    entry = descriptor(manifest, "image.manifest.v1+json")
    entry["annotations"] = {"io.containerd.image.name": tag,
                            "org.opencontainers.image.ref.name": tag}
    index = _encode({"schemaVersion": 2,
                     "mediaType": "application/vnd.oci.image.index.v1+json",
                     "manifests": [entry]})
    files = [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'), ("index.json", index)]
    files += [("blobs/sha256/" + _digest(data).split(":")[1], data)
              for data in (config_data, manifest, layer)]
    return _tar([(name, data, 0o644, {}, None) for name, data in files]), tag, config


@pytest.fixture
def client(daemon):
    """Local override: this scratch-only test must not seed network images."""
    from conftest import expected_git_commit

    value = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=180, version="auto")
    try:
        value.ping()
        assert value.version().get("GitCommit") == expected_git_commit(daemon.binary)
        yield value
    finally:
        value.close()


@pytest.fixture
def xattrs_image(client, tmp_path):
    binary = tmp_path / "probe"
    subprocess.run(
        ["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=",
         "-o", str(binary), str(Path(__file__).parent / "fixtures/volume-xattrs.go")],
        env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64",
             "GOWORK": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off",
             "GOSUMDB": "off", "GOFLAGS": ""},
        check=True, capture_output=True, text=True, timeout=120,
    )
    archive, tag, config = _image_archive(binary.read_bytes())
    owned_id = None
    try:
        # Check both Docker config IDs and CEngine manifest IDs before loading:
        # an absent tag alone does not imply ownership of deduplicated content.
        image = None
        for reference in (tag, "sha256:" + tag.split(":")[1], _digest(_encode(config))):
            try:
                image = client.images.get(reference)
                break
            except docker.errors.ImageNotFound:
                pass
        if image is None:
            loaded = client.images.load(archive)
            assert len(loaded) == 1, loaded
            image = loaded[0]
            owned_id = image.id
        assert image.attrs["Architecture"] == config["architecture"]
        assert image.attrs["Os"] == config["os"]
        assert image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"]
        assert image.attrs["Config"]["Cmd"] == config["config"]["Cmd"]
        assert image.attrs["Config"]["User"] == "0:0"
        yield image.id
    finally:
        if owned_id is not None:
            client.images.remove(owned_id, force=False)


def _probe(container, *args, user="0:0"):
    result = container.exec_run(["/probe", *args], user=user)
    assert result.exit_code == 0, (args, result.output.decode(errors="replace"))
    value = json.loads(result.output)
    uid, gid = map(int, user.split(":"))
    assert (value["uid"], value["gid"]) == (uid, gid), value
    return value


def _get(container, path, name, expected, *, follow=False, user="0:0"):
    result = _probe(container, "get-follow" if follow else "get", path, name, user=user)
    assert result["errno"] == 0, ("source/import or copyup xattr missing", path, name, result)
    assert result["value"] == expected.hex(), (path, name, result, expected.hex())


def _assert_outside(value):
    assert (value["mode"], value["owner"], value["group"], value["mtime_ns"]) == (0o100644, 0, 0, 0), value
    assert value["list_errno"] == 0 and value["attrs"] == {USER: SENTINEL_ATTRS[USER].hex()}, value
    assert value["value"] == SENTINEL.hex(), value


def _assert_link(value, path, *, capability=CAPABILITY, legacy=False):
    target, uid, gid, mtime, attrs = SYMLINKS[path]
    assert (value["mode"], value["target"], value["owner"], value["group"], value["mtime_ns"]) == (
        0o120777, target, uid, gid, mtime * 1000000000), (path, value)
    expected = {name: (capability if name == CAP else data).hex() for name, data in attrs.items()}
    assert value["list_errno"] in ((0, EOPNOTSUPP) if legacy and not attrs else (0,)), (path, value)
    assert value["attrs"] == expected, (path, value, expected)


def _assert_symlinks(container, selector="populated", *, legacy=False):
    value = _probe(container, "symlink-proof", selector)
    paths = {path for path in SYMLINKS if path.startswith("/populated/" if selector == "populated" else "/links/")}
    assert set(value["links"]) == paths, value
    for path, link in value["links"].items():
        _assert_link(link, path, legacy=legacy)
    _assert_outside(value["outside"])
    return value


def _assert_symlink_capability_controls(container):
    # Source/consumer preflight has already proved imported/copied bytes. These
    # fixed-path controls must never manufacture a missing source/dest attribute.
    for user in ("0:0", "10001:10001"):
        result = _probe(container, "capability-controls", "populated", user=user)
        phases = ("caller", "uid-zero-no-caps") if user == "0:0" else ("caller",)
        rows = result["controls"]
        assert [(row["phase"], row["path"]) for row in rows] == [
            (phase, path) for phase in phases for path in ("/populated/cap-live", "/populated/cap-dangling")], rows
        for row in rows:
            permitted = user == "0:0" and row["phase"] == "caller"
            assert type(row["caps"]) is int and (bool(row["caps"] & (1 << 31)) if permitted else row["caps"] == 0), row
            assert row["errno"] == (0 if permitted else EPERM), row
            _assert_link(row["link"], row["path"], capability=CAP_CHANGED if permitted else CAPABILITY)
            _assert_outside(row["outside_before"])
            assert row["outside_before"] == row["outside_after"], row
            if permitted:
                assert row["restore_errno"] == 0, row
                _assert_link(row["restored"], row["path"])
                assert row["outside_before"] == row["outside_restored"], row


def _assert_metadata(container):
    for path, attrs in EXPECTED.items():
        stat = _probe(container, "stat", path)
        directory = path in ("/empty", "/populated", "/populated/child")
        expected_mode = (0o40000 if directory else 0o100000) | (0o644 if path == "/sentinel" else 0o750)
        assert (stat["owner"], stat["group"], stat["mode"]) == (0, 0, expected_mode), (path, stat)
        for name in NAMES:
            if name in attrs:
                _get(container, path, name, attrs[name])
            else:
                result = _probe(container, "get", path, name)
                assert result["errno"] == ENODATA, (path, name, result)
    _assert_symlinks(container)
    for path, data in (("/populated/file", PAYLOAD), ("/populated/child/file", PAYLOAD),
                       ("/sentinel", SENTINEL)):
        result = _probe(container, "read", path)
        assert (result["errno"], result["value"]) == (0, data.hex()), (path, result)


def _assert_denials_and_nofollow(container):
    # ACL is operational, not merely stored: named reader allowed, other denied.
    allowed = _probe(container, "read", "/populated/child/file", user="10001:10001")
    assert (allowed["errno"], allowed["value"]) == (0, PAYLOAD.hex()), allowed
    denied = _probe(container, "read", "/populated/child/file", user="10002:10002")
    assert denied["errno"] == EACCES, denied
    for path, attrs in EXPECTED.items():
        for name, value in attrs.items():
            result = _probe(container, "set", path, name, value.hex(), user="10001:10001")
            assert result["errno"] in (EACCES, EPERM), (path, name, result)
    # cap_convert_nscap rejects malformed values regardless of inode type.
    # Do NOT infer that Linux refuses valid capability xattrs on directories.
    for path in ("/empty", "/populated", "/populated/child", "/populated/file",
                 "/populated/child/file"):
        result = _probe(container, "set", path, CAP, "01")
        assert result["errno"] == EINVAL, (path, result)
    result = _probe(container, "set", "/populated/child/file", DEFAULT, ACL.hex())
    assert result["errno"] == EACCES, result

    # ext4 refuses user.* and POSIX ACLs on symlinks. Capability rejection here
    # concerns a malformed value, NOT refusal of the security.* namespace.
    # The original empty-attr link remains the malformed-value negative control;
    # separate live/dangling links carry valid OCI-source capability bytes.
    _assert_symlink_capability_controls(container)
    for name, value in ((USER, b"must-not-reach-target"), (ACCESS, ACL),
                        (DEFAULT, ACL), (CAP, b"\x01")):
        result = _probe(container, "get", "/populated/link", name)
        assert result["errno"] in (ENODATA, EOPNOTSUPP), (name, result)
        for user in ("0:0", "10001:10001"):
            result = _probe(container, "set", "/populated/link", name, value.hex(), user=user)
            expected = (EPERM,) if name == USER else ((EINVAL,) if name == CAP else (EOPNOTSUPP,))
            assert result["errno"] in expected, (name, user, result)
            # Observe the external target after EACH attempted mutation.
            for target_name in NAMES:
                result = _probe(container, "get", "/sentinel", target_name)
                if target_name == USER:
                    assert (result["errno"], result["value"]) == (0, SENTINEL_ATTRS[USER].hex()), result
                else:
                    assert result["errno"] == ENODATA, (target_name, result)
    _assert_metadata(container)


def _assert_ext4(container, path, *, mounted):
    def require(condition, *evidence):
        # Device proof remains fail-closed when the harness is run with -O.
        if not condition:
            raise AssertionError((path, *evidence))

    def device_number(value):
        require(type(value) is int and 0 <= value < 1 << 64, "invalid Linux dev_t", value)
        # Linux gnu_dev_major/minor, not the Darwin runner's os.major/os.minor.
        major = ((value >> 8) & 0xfff) | ((value >> 32) & 0xfffff000)
        minor = (value & 0xff) | ((value >> 12) & 0xffffff00)
        require(major != 0, "direct block device required", value)
        return f"{major}:{minor}"

    def directory_device(target):
        value = _probe(container, "stat", target)  # Existing Lstat, no following links.
        mode = value.get("mode")
        require(type(mode) is int and mode & 0o170000 == 0o40000,
                "mountpoint must be a directory", target, value)
        require(type(value.get("rdev")) is int and value["rdev"] == 0,
                "directory must not report a special-device rdev", target, value)
        return device_number(value.get("dev"))

    result = _probe(container, "fs", path)
    require(result.get("magic") == 0xEF53,
            "DIRECT-EXT4 required; tmpfs is not equivalent", result)
    require(isinstance(result.get("mountinfo"), str), "missing mountinfo", result)
    records = [line.split() for line in result["mountinfo"].splitlines()]
    for fields in records:
        require(len(fields) >= 10 and "-" in fields[6:], "malformed mountinfo", fields)
        require(len(fields) == fields.index("-", 6) + 4, "malformed mountinfo tail", fields)

    def mount_device(target):
        matches = [fields for fields in records if fields[4] == target]
        require(len(matches) == 1, "expected one exact mount", target, records)
        fields = matches[0]
        separator = fields.index("-", 6)
        require(fields[separator + 1] == "ext4" and fields[3] == "/",
                "whole-root ext4 mount required", fields)
        pair = fields[2].split(":")
        require(len(pair) == 2 and all(part.isascii() and part.isdecimal() for part in pair),
                "invalid mount device", fields)
        major, minor = map(int, pair)
        require(0 < major < 1 << 32 and 0 <= minor < 1 << 32, "invalid mount device", fields)
        # mount(2)'s source label may be /proc/self/fd/5 on EVERY direct disk.
        # It is cosmetic, never identity. Compare the actual Linux stat device.
        identity = f"{major}:{minor}"
        require(directory_device(target) == identity, "mountinfo/stat device mismatch", fields)
        return identity

    root = mount_device("/")
    require(not any(fields[4].startswith(path.rstrip("/") + "/") for fields in records),
            "nested mount could substitute tested metadata", records)
    if mounted:
        identity = mount_device(path)
        require(identity != root, "named volume shares root's underlying disk", identity, root)
    else:
        identity = directory_device(path)
        require(identity == root, "source control must inherit the root device", identity, root)
        require(not any(fields[4] != "/" and
                        (path == fields[4] or path.startswith(fields[4].rstrip("/") + "/"))
                        for fields in records), "source control has an unexpected mount", records)

    for device in sorted({root, identity}):
        # Unprivileged scratch containers need not expose block nodes or sysfs.
        # If visible, the kernel block-class entry must independently agree.
        sysfs = _probe(container, "read", f"/sys/dev/block/{device}/dev")
        require(type(sysfs.get("errno")) is int, "missing sysfs errno", sysfs)
        if sysfs["errno"] == 0:
            try:
                observed = bytes.fromhex(sysfs["value"]).decode("ascii").strip()
            except (KeyError, TypeError, ValueError, UnicodeError) as error:
                raise AssertionError((path, "invalid sysfs device proof", sysfs)) from error
            require(observed == device, "sysfs block device mismatch", device, sysfs)
        else:
            require(sysfs["errno"] in (2, EPERM, EACCES),
                    "unexpected sysfs block-device failure", device, sysfs)
    return identity


@pytest.mark.compat("RTM-073")
def test_direct_ext4_named_volume_copyup_preserves_source_xattrs(daemon, client, xattrs_image):
    containers, volumes = [], []
    try:
        # Independent no-mount control proves the image importer supplied attrs.
        source = client.containers.create(xattrs_image, network_mode="none")
        containers.append(source)
        source.start()
        _assert_ext4(source, "/populated", mounted=False)
        _assert_metadata(source)
        _assert_denials_and_nofollow(source)
        source.remove(force=True)
        containers.remove(source)
        for role in ("empty", "populated"):
            volumes.append(client.volumes.create(
                f"rtm073-{role}-{uuid.uuid4().hex}", labels={"dev.cengine.compat": "true"},
            ))
        # Only one known consumer: never trigger the shared/NFS backend.
        target = client.containers.create(
            xattrs_image, network_mode="none",
            mounts=[Mount(target="/" + role, source=volume.name, type="volume", no_copy=False)
                    for role, volume in zip(("empty", "populated"), volumes)],
        )
        containers.append(target)
        target.start()
        modes = json.loads((daemon.root / "volume-storage.json").read_text())
        devices = []
        for role, volume in zip(("empty", "populated"), volumes):
            assert modes[volume.name] == "block", (volume.name, modes)
            devices.append(_assert_ext4(target, "/" + role, mounted=True))
        assert len(set(devices)) == len(volumes), devices
        _assert_metadata(target)
        _assert_denials_and_nofollow(target)
    finally:
        # No pruning, name searches, or daemon-wide cleanup; only returned IDs.
        errors = []
        for resource in [*reversed(containers), *reversed(volumes)]:
            try:
                resource.remove(force=True)
            except Exception as error:
                errors.append(error)
        assert not errors, ("test-owned resource cleanup failed", errors)


@pytest.mark.compat("RTM-088")
def test_shared_volume_empty_xattr_symlink_copyup_and_nocopy(daemon, client, xattrs_image):
    # One ledger ID names the whole contract, not two parametrized pytest items.
    for no_copy in (False, True):
        _shared_empty_symlink_case(daemon, client, xattrs_image, no_copy)


def _shared_empty_symlink_case(daemon, client, xattrs_image, no_copy):
    """Prove empty-volume symlink semantics under the default managed FUSE lifecycle."""
    from storage_backend_proof import daemon_startup_mode, verify_backend

    containers, volumes = [], []
    try:
        source = client.containers.create(xattrs_image, network_mode="none")
        containers.append(source)
        source.start()
        _assert_ext4(source, "/links", mounted=False)
        _assert_symlinks(source, "empty")
        source.remove(force=True)
        containers.remove(source)
        volume = client.volumes.create(f"rtm088-{uuid.uuid4().hex}", labels={"dev.cengine.compat": "true"})
        volumes.append(volume)
        # Both consumers exist before either starts, so actual shared copy-up is
        # exercised rather than promoting a previously populated block volume.
        for _ in range(2):
            containers.append(client.containers.create(
                xattrs_image, network_mode="none",
                mounts=[Mount(target="/links", source=volume.name, type="volume", no_copy=no_copy)],
            ))
        for container in containers:
            container.start()
        modes = json.loads((daemon.root / "volume-storage.json").read_text())
        assert modes[volume.name] == "shared", modes
        for container in containers:
            mounts = _probe(container, "fs", "/links")["mountinfo"]
            proof = verify_backend(daemon.root, "shared", mounts, "/links",
                                   startup_mode=daemon_startup_mode(daemon))
            assert not any(line.split()[4].startswith("/links/") for line in mounts.splitlines()), mounts
            if no_copy:
                value = _probe(container, "empty-directory", "links")
                assert value["entries"] == [], value
                _assert_outside(value["outside"])
            else:
                _assert_symlinks(container, "empty", legacy=proof["mode"] == "legacy")
    finally:
        errors = []
        for resource in [*reversed(containers), *reversed(volumes)]:
            try:
                resource.remove(force=True)
            except Exception as error:
                errors.append(error)
        assert not errors, ("test-owned RTM-088 cleanup failed", errors)
