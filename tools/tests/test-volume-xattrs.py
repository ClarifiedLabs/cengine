#!/usr/bin/env python3
"""Engine-free RTM-073 fixture and assertion regression checks (no subprocesses)."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, call, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
SPEC = importlib.util.spec_from_file_location(
    "volume_xattrs", ROOT / "Tests/Compatibility/test_volume_xattrs.py",
)
assert SPEC is not None and SPEC.loader is not None
xattrs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(xattrs)


class VolumeXattrFixtureTests(unittest.TestCase):
    def test_deterministic_oci_descriptors_and_binary_pax(self):
        result = xattrs._image_archive(b"deterministic-probe-placeholder")
        self.assertEqual(result, xattrs._image_archive(b"deterministic-probe-placeholder"))
        archive, tag, config = result
        with tarfile.open(fileobj=io.BytesIO(archive)) as outer:
            files = {info.name: outer.extractfile(info).read() for info in outer}
        index = json.loads(files["index.json"])

        def blob(descriptor):
            value = files["blobs/sha256/" + descriptor["digest"].split(":")[1]]
            self.assertEqual(len(value), descriptor["size"])
            self.assertEqual(xattrs._digest(value), descriptor["digest"])
            return value

        descriptor = index["manifests"][0]
        self.assertEqual(tag, "compat-volume-xattrs:" + descriptor["digest"].split(":")[1])
        self.assertEqual(descriptor["annotations"]["io.containerd.image.name"], tag)
        manifest = json.loads(blob(descriptor))
        self.assertEqual(json.loads(blob(manifest["config"])), config)
        self.assertEqual(config["config"], {"Cmd": ["/probe", "serve"], "User": "0:0"})
        self.assertEqual(config["rootfs"]["diff_ids"], [manifest["layers"][0]["digest"]])
        with tarfile.open(fileobj=io.BytesIO(blob(manifest["layers"][0])),
                          encoding="utf-8", errors="surrogateescape") as layer:
            for path, expected in xattrs.EXPECTED.items():
                info = layer.getmember(path.lstrip("/"))
                attrs = {key.removeprefix("SCHILY.xattr."): value.encode("utf-8", "surrogateescape")
                         for key, value in info.pax_headers.items() if key.startswith("SCHILY.xattr.")}
                self.assertEqual(attrs, expected, path)
                self.assertEqual((info.uid, info.gid, info.mtime), (0, 0, 0))
            link = layer.getmember("populated/link")
            self.assertTrue(link.issym())
            self.assertEqual(link.linkname, "/sentinel")
            self.assertEqual(link.pax_headers, {})
            self.assertEqual(layer.extractfile("populated/child/file").read(), xattrs.PAYLOAD)
            for path, (target, uid, gid, mtime, attrs) in xattrs.SYMLINKS.items():
                info = layer.getmember(path.lstrip("/"))
                self.assertTrue(info.issym())
                self.assertEqual((info.linkname, info.uid, info.gid, info.mtime), (target, uid, gid, mtime))
                self.assertEqual({key.removeprefix("SCHILY.xattr."): value.encode("utf-8", "surrogateescape")
                                  for key, value in info.pax_headers.items() if key.startswith("SCHILY.xattr.")}, attrs)
            self.assertFalse(layer.getmember("links").pax_headers)
            self.assertEqual(layer.getmember("populated/cap-live").pax_headers["SCHILY.xattr." + xattrs.CAP].encode("utf-8", "surrogateescape"), xattrs.CAPABILITY)
        # Independent literal layouts catch accidentally testing our own encoder.
        self.assertEqual(xattrs.CAPABILITY.hex(), "0100000200040000000000000000000000000000")
        self.assertEqual(len(xattrs.ACL), 44)
        self.assertEqual(struct.unpack_from("<I", xattrs.ACL), (2,))
        self.assertEqual(struct.unpack_from("<HHI", xattrs.ACL, 12), (2, 5, 10001))
        self.assertIn(b"\x00", xattrs.DIRECTORY_ATTRS[xattrs.USER])
        self.assertIn(b"\xff", xattrs.DIRECTORY_ATTRS[xattrs.USER])
        self.assertEqual(xattrs.DIRECTORY_ATTRS[xattrs.EMPTY], b"")

    def test_missing_or_corrupt_source_xattrs_cannot_pass(self):
        for result in ({"errno": xattrs.ENODATA, "value": ""},
                       {"errno": xattrs.EOPNOTSUPP, "value": ""},
                       {"errno": 0, "value": b"changed".hex()}):
            with self.subTest(result=result), patch.object(xattrs, "_probe", return_value=result):
                with self.assertRaises(AssertionError):
                    xattrs._get(None, "/empty", xattrs.USER, b"expected")

    def test_empty_value_is_not_missing(self):
        with patch.object(xattrs, "_probe", return_value={"errno": 0, "value": ""}):
            xattrs._get(None, "/empty", xattrs.EMPTY, b"")

    def test_unexpected_permission_success_fails(self):
        # Reach the first denied read; a probe's exit status alone cannot pass it.
        with patch.object(xattrs, "_probe", return_value={"errno": 0, "value": xattrs.PAYLOAD.hex()}):
            with self.assertRaises(AssertionError):
                xattrs._assert_denials_and_nofollow(None)

    def test_actual_runtime_case_rejects_duplicate_direct_volume_roles(self):
        proof = Ext4DeviceIdentityTests()
        mounts = proof.ROOT_MOUNT + proof.VOLUME_MOUNT
        mounts += proof.VOLUME_MOUNT.replace("/empty", "/populated").replace("254:1", "0254:0001")
        devices = [proof.observe(mountinfo=mounts, path=path,
                                 stats={"/populated": {"dev": 0xfe01}})
                   for path in ("/empty", "/populated")]
        source, target = Mock(), Mock()
        volumes = [SimpleNamespace(name=name, remove=Mock()) for name in ("v0", "v1")]
        client = SimpleNamespace(containers=SimpleNamespace(create=Mock(side_effect=[source, target])),
                                 volumes=SimpleNamespace(create=Mock(side_effect=volumes)))
        daemon = SimpleNamespace(root=MagicMock())
        daemon.root.__truediv__.return_value.read_text.return_value = json.dumps({"v0": "block", "v1": "block"})
        with patch.object(xattrs, "_assert_ext4", side_effect=["254:0", *devices]), \
                patch.object(xattrs, "_assert_metadata"), patch.object(xattrs, "_assert_denials_and_nofollow"):
            with self.assertRaises(AssertionError) as failure:
                xattrs.test_direct_ext4_named_volume_copyup_preserves_source_xattrs(daemon, client, "image")
        self.assertEqual(failure.exception.args, (devices,))
        target.remove.assert_called_once_with(force=True)
        for volume in volumes:
            volume.remove.assert_called_once_with(force=True)

    def test_shared_empty_symlink_case_precreates_peers_and_honors_nocopy(self):
        for no_copy in (False, True):
            for mode in ("lifecycle",):
                events = []
                source, first, second = [Mock(id=name) for name in ("source", "first", "second")]
                peers = [source, first, second]
                creates = []
                def create(image, **kw):
                    value = peers[len(creates)]
                    creates.append(kw)
                    events.append(("create", value.id))
                    value.start.side_effect = lambda: events.append(("start", value.id))
                    return value
                volume = SimpleNamespace(name="owned-volume", remove=Mock())
                client = SimpleNamespace(containers=SimpleNamespace(create=create),
                                         volumes=SimpleNamespace(create=Mock(return_value=volume)))
                daemon = SimpleNamespace(root=MagicMock())
                daemon.root.__truediv__.return_value.read_text.return_value = '{"owned-volume":"shared"}'
                mounts = "30 20 0:30 / /links rw - fuse.managed-v3 managed-v3 rw\n"
                with patch.object(xattrs, "_assert_ext4"), patch.object(xattrs, "_assert_symlinks") as links, \
                        patch.object(xattrs, "_assert_outside") as outside, \
                        patch.object(xattrs, "_probe", return_value={"mountinfo": mounts, "entries": [], "outside": {}}), \
                        patch("storage_backend_proof.daemon_startup_mode", return_value=mode), \
                        patch("storage_backend_proof.verify_backend", return_value={"mode": mode}) as backend:
                    xattrs._shared_empty_symlink_case(daemon, client, "image", no_copy)
                self.assertNotIn("mounts", creates[0])
                for peer in (first, second):
                    self.assertLess(events.index(("create", first.id)), events.index(("start", peer.id)))
                    self.assertLess(events.index(("create", second.id)), events.index(("start", peer.id)))
                self.assertEqual([kw["mounts"][0].get("VolumeOptions", {}).get("NoCopy", False) for kw in creates[1:]], [no_copy, no_copy])
                self.assertEqual(backend.call_count, 2)
                self.assertEqual(links.call_count, 1 if no_copy else 3)
                self.assertEqual(outside.call_count, 2 if no_copy else 0)
                if not no_copy: self.assertEqual(links.call_args.kwargs, {"legacy": mode == "legacy"})
                for value in peers: value.remove.assert_called_once_with(force=True)
                volume.remove.assert_called_once_with(force=True)
        test = xattrs.test_shared_volume_empty_xattr_symlink_copyup_and_nocopy
        self.assertEqual([mark.args for mark in test.pytestmark if mark.name == "compat"], [("RTM-088",)])
        self.assertFalse(any(mark.name == "parametrize" for mark in test.pytestmark))
        with patch.object(xattrs, "_shared_empty_symlink_case") as run:
            test("daemon", "client", "image")
        self.assertEqual(run.call_args_list, [
            call("daemon", "client", "image", False),
            call("daemon", "client", "image", True),
        ])
        with patch.object(xattrs, "_shared_empty_symlink_case", side_effect=RuntimeError("failed")) as run:
            with self.assertRaises(RuntimeError):
                test("daemon", "client", "image")
        run.assert_called_once_with("daemon", "client", "image", False)

    def test_empty_symlink_metadata_and_nfs_attr_downgrade_are_exact(self):
        path = "/links/live"
        good = dict(mode=0o120777, target="/sentinel", owner=10001, group=10002,
                    mtime_ns=xattrs.LINK_TIME * 1000000000, attrs={}, list_errno=xattrs.EOPNOTSUPP)
        xattrs._assert_link(good, path, legacy=True)
        with self.assertRaises(AssertionError): xattrs._assert_link(good, path)
        for key, value in (("owner", 0), ("group", 0), ("mtime_ns", 0), ("target", "/other"), ("attrs", {xattrs.CAP: "01"})):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                xattrs._assert_link({**good, key: value}, path, legacy=True)
        capable = {**good, "target": "/sentinel", "attrs": {xattrs.CAP: xattrs.CAPABILITY.hex()}}
        with self.assertRaises(AssertionError): xattrs._assert_link(capable, "/populated/cap-live", legacy=True)

    def test_one_runtime_ledger_id(self):
        test = xattrs.test_direct_ext4_named_volume_copyup_preserves_source_xattrs
        self.assertEqual([mark.args for mark in test.pytestmark if mark.name == "compat"], [("RTM-073",)])


class Ext4DeviceIdentityTests(unittest.TestCase):
    ROOT_MOUNT = "20 1 254:0 / / rw - ext4 /proc/self/fd/5 rw\n"
    VOLUME_MOUNT = "25 20 254:1 / /empty rw - ext4 /proc/self/fd/5 rw\n"

    def observe(self, *, mountinfo=None, magic=0xEF53, stats=None, sysfs=None,
                path="/empty", mounted=True):
        if mountinfo is None:
            mountinfo = self.ROOT_MOUNT + self.VOLUME_MOUNT
        values = {target: {"dev": device, "rdev": 0, "mode": 0o40755}
                  for target, device in (("/", 0xfe00), ("/empty", 0xfe01),
                                         ("/populated", 0xfe02))}
        for target, changes in (stats or {}).items():
            values[target].update(changes)
        def probe(container, operation, target):
            if operation == "fs":
                return {"magic": magic, "mountinfo": mountinfo}
            if operation == "stat":
                return values[target]
            self.assertEqual(operation, "read")
            self.assertTrue(target.startswith("/sys/dev/block/"))
            self.assertTrue(target.endswith("/dev"))
            return {"errno": 2, "value": ""} if sysfs is None else sysfs(target)
        with patch.object(xattrs, "_probe", side_effect=probe):
            return xattrs._assert_ext4(None, path, mounted=mounted)

    def test_legacy_and_descriptor_sources_use_kernel_identity(self):
        for source in ("/dev/vdc", "/proc/self/fd/5", "none"):
            mounts = self.ROOT_MOUNT + self.VOLUME_MOUNT.replace("/proc/self/fd/5", source)
            with self.subTest(source=source):
                self.assertEqual(self.observe(mountinfo=mounts), "254:1")

    def test_wrong_filesystem_subdirectory_and_mount_metadata_rejected(self):
        good = self.ROOT_MOUNT + self.VOLUME_MOUNT
        bad = (good.replace("ext4", "tmpfs"), good.replace("ext4", "nfs"),
               good.replace("ext4", "fuse.managed-v3"),
               good.replace("/empty rw", "/different rw"),
               good.replace("254:1 / /empty", "254:1 /subdir /empty"),
               good.replace("254:0 / /", "254:0 /subdir /"),
               good.replace("254:1", "254:2"), good.replace("254:0", "254:3"),
               good + self.VOLUME_MOUNT, self.VOLUME_MOUNT,
               good.replace("254:1", "invalid"), good.replace(" - ", " "))
        for mountinfo in bad:
            with self.subTest(mountinfo=mountinfo), self.assertRaises(AssertionError):
                self.observe(mountinfo=mountinfo)
        with self.assertRaises(AssertionError):
            self.observe(magic=0x01021994)

    def test_same_underlying_root_disk_rejected_despite_different_source(self):
        mounts = self.ROOT_MOUNT + self.VOLUME_MOUNT.replace("254:1", "254:0").replace("/proc/self/fd/5", "/dev/vdz")
        with self.assertRaisesRegex(AssertionError, "shares root"):
            self.observe(mountinfo=mounts, stats={"/empty": {"dev": 0xfe00}})

    def test_control_inherits_verified_whole_ext4_root(self):
        self.assertEqual(self.observe(mountinfo=self.ROOT_MOUNT,
                                      stats={"/populated": {"dev": 0xfe00}},
                                      path="/populated", mounted=False), "254:0")
        for mountinfo, stats in ((self.ROOT_MOUNT, {}),
                                (self.ROOT_MOUNT.replace("ext4", "tmpfs"), {"/populated": {"dev": 0xfe00}}),
                                (self.ROOT_MOUNT.replace("/ / rw", "/subdir / rw"), {"/populated": {"dev": 0xfe00}}),
                                (self.ROOT_MOUNT, {"/": {"dev": 0xfe01}, "/populated": {"dev": 0xfe00}})):
            with self.subTest(mountinfo=mountinfo, stats=stats), self.assertRaises(AssertionError):
                self.observe(mountinfo=mountinfo, stats=stats, path="/populated", mounted=False)
        mounted_control = self.ROOT_MOUNT + self.VOLUME_MOUNT.replace("/empty", "/populated").replace("254:1", "254:0")
        with self.assertRaisesRegex(AssertionError, "unexpected mount"):
            self.observe(mountinfo=mounted_control, stats={"/populated": {"dev": 0xfe00}},
                         path="/populated", mounted=False)

    def test_nested_mounts_cannot_substitute_source_or_copyup_metadata(self):
        child = "30 25 254:3 / /populated/child rw - ext4 /proc/self/fd/5 rw\n"
        for mounted in (False, True):
            mounts = self.ROOT_MOUNT + child
            if mounted:
                mounts += self.VOLUME_MOUNT.replace("/empty", "/populated").replace("254:1", "254:2")
            stats = {} if mounted else {"/populated": {"dev": 0xfe00}}
            with self.subTest(mounted=mounted), self.assertRaisesRegex(AssertionError, "nested mount"):
                self.observe(mountinfo=mounts, stats=stats, path="/populated", mounted=mounted)

    def test_stat_identity_and_directory_type_are_required(self):
        for field, value in (("dev", None), ("dev", True), ("dev", "65025"),
                             ("dev", -1), ("dev", 1 << 64), ("dev", 0),
                             ("rdev", 1), ("rdev", None), ("mode", 0o120777)):
            for target in ("/", "/empty"):
                with self.subTest(field=field, value=value, target=target), self.assertRaises(AssertionError):
                    self.observe(stats={target: {field: value}})

    def test_linux_extended_device_bits_and_exact_json_integer(self):
        # Literal Linux dev_t vectors; do not use Darwin os.makedev/major/minor.
        for major, minor, raw in ((4096, 256, 0x100000100000),
                                  (305419896, 2596069104, 0x123459abcde678f0)):
            value = json.loads(json.dumps({"dev": raw}))["dev"]
            self.assertEqual(value, raw)
            mounts = self.ROOT_MOUNT + self.VOLUME_MOUNT.replace("254:1", f"{major}:{minor}")
            self.assertEqual(self.observe(mountinfo=mounts, stats={"/empty": {"dev": value}}),
                             f"{major}:{minor}")

    def test_visible_sysfs_block_identity_must_agree(self):
        def visible(path):
            return {"errno": 0, "value": (path.split("/")[-2] + "\n").encode().hex()}
        self.assertEqual(self.observe(sysfs=visible), "254:1")
        for errno in (2, xattrs.EPERM, xattrs.EACCES):
            self.assertEqual(self.observe(sysfs=lambda path: {"errno": errno}), "254:1")
        for result in ({"errno": 0, "value": b"254:7\n".hex()},
                       {"errno": 0, "value": "not hex"}, {"errno": 5}, {}):
            with self.subTest(result=result), self.assertRaises(AssertionError):
                self.observe(sysfs=lambda path: result)

    def test_distinct_roles_use_canonical_device_not_repeated_fd_label(self):
        other = self.VOLUME_MOUNT.replace("/empty", "/populated").replace("254:1", "254:2")
        mounts = self.ROOT_MOUNT + self.VOLUME_MOUNT + other
        devices = [self.observe(mountinfo=mounts, path=path) for path in ("/empty", "/populated")]
        self.assertEqual(devices, ["254:1", "254:2"])
        self.assertEqual(len(set(devices)), 2)
        duplicate = mounts.replace("254:2", "0254:0001")
        devices = [self.observe(mountinfo=duplicate, path=path,
                               stats={"/populated": {"dev": 0xfe01}})
                   for path in ("/empty", "/populated")]
        # The existing caller's set comparison must see a duplicate, not two
        # cosmetically different labels or differently formatted numbers.
        self.assertEqual(devices, ["254:1", "254:1"])
        self.assertNotEqual(len(set(devices)), 2)


if __name__ == "__main__":
    unittest.main()
