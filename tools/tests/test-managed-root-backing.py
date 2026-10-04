#!/usr/bin/env python3
"""Engine-free root backing/owned stream regressions; no Docker/helper execution."""
import copy
import io
from pathlib import Path
import runpy
import stat
import sys
import tarfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p
import managed_root_backing as b
STREAM = runpy.run_path(str(ROOT / "tools/tests/test-managed-retained-reader.py"))


def uid(n): return f"{n:08x}-1111-4111-8111-111111111111"


def snapshot():
    def metadata(regular, raw):
        value = dict(mode=(stat.S_IFREG | 0o640) if regular else (stat.S_IFDIR | 0o750), uid=10001, gid=10002,
            atimeNS=1, mtimeNS=p.MTIME * 10**9, ctimeNS=2, xattrs={})
        if regular: value.update(size=32, sha256=p.digest(raw), nlink=1)
        return value
    return dict(command="root-snapshot", completed=True,
        roots={path: dict(entries=[b.NAME], root=metadata(False, raw), object=metadata(True, raw)) for path, raw in b.CONTENTS.items()},
        mountinfo="\n".join(f"{i+10} 1 0:{i+10} / {path} rw,nosuid - fuse.managed-v3 managed-v3 rw" for i, path in enumerate(b.CONTENTS)))


def fixture():
    original = dict(id=uid(1), container="a"*64, launch=uid(2), store=uid(3), serviceEpoch=uid(4), controllerEpoch=1,
        controllerKey="b"*64, slots=[], mounts=[])
    reader = {**copy.deepcopy(original), "id": uid(5), "container": "c"*64, "launch": uid(6), "phase": "running", "prepareCompleted": True}
    for i, path in enumerate(b.CONTENTS):
        slot = dict(role="runtime", volume=uid(10+i), attachment=uid(20+i), key=str(i+1)*64, mode="read-write")
        original["slots"].append(slot)
        reader["slots"].append({**slot, "attachment": uid(30+i), "key": str(i+3)*64})
        for intent in (original, reader): intent["mounts"].append(dict(volume=slot["volume"], destination=path))
    binding = dict(caseName=b.ROOT_CASES[0], scope=dict(intent=original["id"]), targetAttachment=uid(20))
    value = snapshot(); marker = b.baseline_marker(binding, original, reader, value)
    positive = dict(roots={name: dict(read=dict(authority=dict(binding=dict(volume=item["volume"])), contentSHA256=item["contentSHA256"]))
        for name, item in zip(("source", "target"), marker["rootPair"])})
    return original, reader, marker, dict(binding=binding, baseline=copy.deepcopy(marker), positive=positive)


class RootBackingTests(unittest.TestCase):
    def test_actual_stream_prestarts_before_one_trigger_and_joins(self):
        frame, API = STREAM["frame"], STREAM["API"]
        api = API(frame(STREAM["READY"]) + frame(STREAM["joined"](snapshot())))
        reader = b.RootBackingReader(api, SimpleNamespace(id="independent"), lambda: 10)
        self.assertEqual(api.calls[0][1], ["/probe", "root-wait"])
        self.assertEqual(api.sock.sent, [])
        self.assertEqual(reader.baseline(snapshot()), snapshot())
        self.assertEqual(api.sock.sent, [b'\x01']); self.assertTrue(api.sock.closed)
        with self.assertRaises(ValueError): reader.baseline(snapshot())

    def test_two_fixed_image_objects_are_not_created_by_observer(self):
        plan = dict(owner="owned", image="root-proof:test")
        archive, _ = p.image_archive(b"not-executed", plan, second_mount=True, root_objects=True)
        with tarfile.open(fileobj=io.BytesIO(archive)) as outer:
            with tarfile.open(fileobj=io.BytesIO(outer.extractfile("layer.tar").read())) as layer:
                self.assertEqual(set(layer.getnames()), {"probe", "data", "other", "data/"+b.NAME, "other/"+b.NAME})
                for path, raw in b.CONTENTS.items():
                    self.assertEqual(layer.extractfile(path[1:]+"/"+b.NAME).read(), raw)
        with self.assertRaises(ValueError): p.image_archive(b"probe", plan, root_objects=True)

    def test_metadata_namespace_and_distinct_contents_all_preserved(self):
        self.assertEqual(b.unchanged(snapshot(), snapshot()), snapshot())
        for path in b.CONTENTS:
            for entry in ("root", "object"):
                for field in ("mode", "uid", "gid", "atimeNS", "mtimeNS", "ctimeNS"):
                    bad = snapshot(); bad["roots"][path][entry][field] += 1
                    with self.subTest(path=path, entry=entry, field=field), self.assertRaises(ValueError): b.unchanged(bad, snapshot())
            bad = snapshot(); bad["roots"][path]["entries"].append("extra")
            with self.assertRaises(ValueError): b.snapshot(bad)
        bad = snapshot(); bad["roots"]["/other"]["object"]["sha256"] = p.digest(b.CONTENTS["/data"])
        with self.assertRaises(ValueError): b.snapshot(bad)

    def test_every_present_schema_field_missing_null_unknown_or_numeric_alias_rejects(self):
        original = snapshot()
        def walk(obj, path=()):
            if not isinstance(obj, dict): return
            variants = [{**obj, "unknown": 1}]
            for key, value in obj.items():
                missing = copy.deepcopy(obj); del missing[key]; variants.append(missing)
                variants.append({**obj, key: None})
                if type(value) is int: variants.extend(({**obj, key: float(value)}, {**obj, key: True}))
            for variant in variants:
                bad = copy.deepcopy(original); parent = bad
                for key in path[:-1]: parent = parent[key]
                if path: parent[path[-1]] = variant
                else: bad = variant
                with self.subTest(path=path, variant=variant), self.assertRaises(ValueError): b.snapshot(bad)
            for key, value in obj.items(): walk(value, path+(key,))
        walk(original)

    def test_mount_alias_or_missing_or_readonly_rejected(self):
        for change in (lambda s:s.splitlines()[0], lambda s:s+'\n'+s.splitlines()[0],
                       lambda s:s.replace('/other', '/data'), lambda s:s.replace('rw,nosuid', 'ro,nosuid'),
                       lambda s:s.replace('fuse.managed-v3', 'ext4')):
            bad = snapshot(); bad["mountinfo"] = change(bad["mountinfo"])
            with self.assertRaises(ValueError): b.snapshot(bad)

    def test_reader_identity_and_positive_content_join(self):
        original, reader, marker, result = fixture()
        self.assertEqual(b.project_backing(result, marker, snapshot(), snapshot(), original, reader)["snapshotSHA256"], marker["snapshotSHA256"])
        for field in ("id", "container", "launch"):
            bad = copy.deepcopy(reader); bad[field] = original[field]
            with self.assertRaises(ValueError): b.baseline_marker(marker["binding"], original, bad, snapshot())
        for field in ("store", "serviceEpoch", "controllerEpoch", "controllerKey"):
            bad = copy.deepcopy(reader); bad[field] = "foreign"
            with self.assertRaises(ValueError): b.baseline_marker(marker["binding"], original, bad, snapshot())
        for index in range(2):
            for field in ("attachment", "key"):
                bad = copy.deepcopy(reader); bad["slots"][index][field] = original["slots"][index][field]
                with self.assertRaises(ValueError): b.baseline_marker(marker["binding"], original, bad, snapshot())
        bad = copy.deepcopy(result); bad["positive"]["roots"]["target"]["read"]["contentSHA256"] = marker["rootPair"][0]["contentSHA256"]
        with self.assertRaises(ValueError): b.project_backing(bad, marker, snapshot(), snapshot(), original, reader)
        bad = copy.deepcopy(marker); bad["version"] = 2.0
        with self.assertRaises(ValueError): b.baseline_accepted(bad, marker)


if __name__ == '__main__': unittest.main()
