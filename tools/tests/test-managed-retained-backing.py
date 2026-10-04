#!/usr/bin/env python3
"""Engine-free retained backing checks. Not guest/native acceptance evidence."""
import copy
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p
import managed_retained_backing as s

BASE = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-faults.py"))["snapshot"]


def original():
    value = BASE()
    value["command"] = "retained-snapshot"
    for entry in (value["root"], *value["files"].values()):
        entry["ctimeNS"] = 1700000001000000000
    return value


def positive():
    value = original()
    value["files"]["a"].update(sha256=p.digest(b"\xa5" + p.FILES["a"][1:]),
        mtimeNS=1700000002000000000, ctimeNS=1700000002000000000)
    return value


def written():
    value = positive()
    value.update(command="retained-write", written=1, completed=True)
    value["files"]["a"].update(sha256=p.digest(b"\x5a" + p.FILES["a"][1:]),
        mtimeNS=1700000003000000000, ctimeNS=1700000003000000000)
    return value


def marker():
    return s.baseline_marker(dict(testBinding="opaque-not-authority"), str(uuid.uuid4()),
        str(uuid.uuid4()), "a" * 64, positive())


class RetainedTests(unittest.TestCase):
    def test_finite_cases_and_required_versions_are_explicit(self):
        self.assertEqual(s.FD_CASES, ("same-e-retained-fd", "cross-e-retained-fd"))
        self.assertEqual((s.FD_GUEST_VERSION, s.FD_SAME_E_GUEST_VERSION, s.FD_WORKER_VERSION), (5, 7, 8))

    def test_baseline_exact_a5_and_other_bytes_unchanged(self):
        self.assertEqual(s.retained_baseline(positive(), original()), positive())
        for digest in (p.digest(p.FILES["a"]), p.digest(b"\xa5" + p.FILES["a"][1:-1]),
                       p.digest(b"\xa5" + b"x" + p.FILES["a"][2:])):
            bad = positive(); bad["files"]["a"]["sha256"] = digest
            with self.assertRaises(ValueError): s.retained_baseline(bad, original())
        bad = positive(); bad["files"]["z"]["sha256"] = "f" * 64
        with self.assertRaises(ValueError): s.retained_baseline(bad, original())
        with self.assertRaises(ValueError): s.retained_baseline(positive(), positive())
        with self.assertRaises(ValueError): s.retained_baseline(positive(), BASE())

    def test_baseline_cannot_hide_unrelated_metadata_changes(self):
        for name, field, value in (("root", "ctimeNS", 0), ("z", "atimeNS", 0),
                                   ("z", "mtimeNS", 0), ("a", "atimeNS", 0),
                                   ("a", "nlink", 2), ("a", "size", 1)):
            bad = positive()
            (bad["root"] if name == "root" else bad["files"][name])[field] = value
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                s.retained_baseline(bad, original())

    def test_fresh_requires_exact_postpositive_bytes_and_all_metadata(self):
        self.assertEqual(s.fresh_retained_snapshot(positive(), positive()), positive())
        with self.assertRaises(ValueError): s.fresh_retained_snapshot(original(), positive())
        for name in ("root", "a", "z"):
            for field in ("atimeNS", "mtimeNS", "ctimeNS"):
                bad = positive()
                entry = bad["root"] if name == "root" else bad["files"][name]
                entry[field] += 1
                with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                    s.fresh_retained_snapshot(bad, positive())

    def test_fresh_write_actual_fixed_witness_and_distinct_5a(self):
        self.assertEqual(s.fresh_retained_write(written(), positive()), written())
        for field, value in (("written", True), ("written", 0), ("written", 2),
                             ("completed", False), ("completed", 1), ("parentFsynced", True),
                             ("command", "retained-snapshot")):
            bad = written(); bad[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                s.fresh_retained_write(bad, positive())
        bad = written(); bad["files"]["a"]["sha256"] = positive()["files"]["a"]["sha256"]
        with self.assertRaises(ValueError): s.fresh_retained_write(bad, positive())
        bad = written(); bad["files"]["z"]["ctimeNS"] += 1
        with self.assertRaises(ValueError): s.fresh_retained_write(bad, positive())

    def test_closed_helper_fields_owner_bounds_and_managed_rw_mount(self):
        for base, command in ((positive(), "retained-snapshot"), (written(), "retained-write")):
            for field in base:
                bad = copy.deepcopy(base); del bad[field]
                with self.subTest(field=field), self.assertRaises(ValueError): s.retained_snapshot(bad, command)
            bad = copy.deepcopy(base); bad["extra"] = True
            with self.assertRaises(ValueError): s.retained_snapshot(bad, command)
        for name, value in (("uid", True), ("gid", 0), ("mode", 0o100666), ("nlink", True),
                            ("size", 4097), ("ctimeNS", True), ("ctimeNS", 2**63),
                            ("mtimeNS", -(2**63)-1), ("xattrs", {"user.changed": "eA=="})):
            bad = positive(); bad["files"]["a"][name] = value
            with self.subTest(field=name), self.assertRaises(ValueError): s.retained_snapshot(bad)
        for mountinfo in ("", "x" * 65537, positive()["mountinfo"] * 2,
                          positive()["mountinfo"].replace("/data rw", "/data ro"),
                          positive()["mountinfo"].replace("fuse.managed-v3", "ext4")):
            bad = positive(); bad["mountinfo"] = mountinfo
            with self.assertRaises(ValueError): s.retained_snapshot(bad)

    def test_snapshot_schema_is_not_silently_accepted_as_normal(self):
        p.snapshot(BASE())
        with self.assertRaises(ValueError): p.snapshot(positive())
        with self.assertRaises(ValueError): s.retained_snapshot(BASE())

    def test_prewrite_mismatch_prevents_any_fresh_write(self):
        calls, owner = [], object()
        def observe(command, actual_owner):
            self.assertIs(actual_owner, owner); calls.append(command)
            return original()
        with self.assertRaises(ValueError): s.observe_fresh_retained(observe, owner, positive())
        self.assertEqual(calls, ["retained-snapshot"])
        calls.clear()
        def good(command, actual_owner):
            self.assertIs(actual_owner, owner); calls.append(command)
            return positive() if command == "retained-snapshot" else written()
        self.assertEqual(s.observe_fresh_retained(good, owner, positive()), (positive(), written()))
        self.assertEqual(calls, ["retained-snapshot", "retained-write"])

    def test_baseline_echo_is_exact_and_hashes_the_recorded_report(self):
        value = marker()
        report = {k: v for k, v in positive().items() if k != "mountinfo"}
        self.assertEqual(value["snapshotSHA256"], p.digest(p.canonical(report)))
        self.assertEqual(s.baseline_accepted(copy.deepcopy(value), value), value)
        for field, changed in (("version", True), ("binding", {}), ("readerIntent", str(uuid.uuid4())),
                               ("readerAttachment", str(uuid.uuid4())), ("readerKey", "b" * 64),
                               ("snapshotSHA256", "0" * 64)):
            bad = copy.deepcopy(value); bad[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError): s.baseline_accepted(bad, value)
        for field in value:
            bad = copy.deepcopy(value); del bad[field]
            with self.assertRaises(ValueError): s.baseline_accepted(bad, value)
        bad = copy.deepcopy(value); bad["extra"] = 1
        with self.assertRaises(ValueError): s.baseline_accepted(bad, value)
        for field, changed in (("version", True), ("binding", {}), ("readerIntent", "not-uuid"),
                               ("readerAttachment", "not-uuid"), ("readerKey", "a"),
                               ("snapshotSHA256", "A" * 64)):
            bad = copy.deepcopy(value); bad[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError): s.baseline_accepted(bad, bad)

    def test_public_marker_roundtrip_uses_exclusive_fsynced_directory_api(self):
        # Only this tiny descriptor fixture uses trusted internal ancestry.
        # Build caches remain external; production must still reject mode0775.
        with tempfile.TemporaryDirectory(prefix="retained-backing-", dir="/private/tmp") as temporary:
            with p.Directory(Path(temporary).resolve()) as directory:
                value = marker()
                directory.publish(".original-consumer.baseline.json", value)
                raw, stamp = directory.read(".original-consumer.baseline.json", pin_file=True)
                self.assertEqual(p.decode(raw), value)
                self.assertEqual(stamp[-1], p.digest(raw))
                with self.assertRaises(OSError): directory.publish(".original-consumer.baseline.json", value)
                directory.publish(".baseline-accepted.json", value)
                self.assertEqual(s.baseline_accepted(p.decode(directory.read(".baseline-accepted.json")[0]), value), value)

    def test_helper_source_keeps_real_write_sync_and_independent_reader(self):
        source = (ROOT / "Tests/Compatibility/fixtures/managed-prepare-faults.go").read_text()
        retained = source[source.index("func retained(command"):source.index("func main()")]
        self.assertIn('retainedOpen(root, "a", command == "retained-write")', retained)
        self.assertEqual(retained.count(".WriteAt("), 1)
        write = retained.index("a.WriteAt([]byte{0x5a}, 0)")
        sync = retained.index("must(a.Sync())")
        read = retained.index('retained("retained-snapshot")')
        self.assertLess(write, sync); self.assertLess(sync, read)
        self.assertIn('result["written"], result["completed"] = written, true', retained)
        self.assertNotIn("O_CREAT", retained); self.assertNotIn("O_TRUNC", retained)
        self.assertLess(retained.index("retainedMountinfo()"), write)
        self.assertIn('result["ctimeNS"] = st.Ctim.Sec*1e9 + st.Ctim.Nsec', source)
        opened = source[source.index("func retainedOpen"):source.index("func retainedMountinfo")]
        self.assertIn("syscall.O_NOATIME", opened)
        self.assertIn("syscall.O_NOFOLLOW", opened)
        self.assertIn("syscall.O_NONBLOCK", opened)
        self.assertIn("syscall.Openat(int(root.Fd()), name, flags, 0)", opened)
        self.assertNotIn("O_CREAT", opened); self.assertNotIn("O_TRUNC", opened)


if __name__ == "__main__": unittest.main()
