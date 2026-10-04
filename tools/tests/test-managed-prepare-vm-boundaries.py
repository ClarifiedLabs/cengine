#!/usr/bin/env python3
"""Engine-free selectors only. Not physical crash/recovery acceptance."""
from pathlib import Path
import copy
import runpy
import sys
import unittest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p
import managed_prepare_vm_boundaries as vm

class VMSelectors(unittest.TestCase):
    def test_closed_three_without_changing_nine(self):
        self.assertEqual(len(p.FULL_CASES), 9)
        for case in vm.CASES:
            self.assertFalse(vm.selection(p.FULL_PROFILE, vm.CASES, case)["fullAcceptance"])
            with self.assertRaises(ValueError): p.full_selection(p.FULL_PROFILE, p.FULL_CASES, case)
        for profile, cases, case in [(p.PROFILE,vm.CASES,vm.CASES[0]), (p.FULL_PROFILE,vm.CASES[::-1],vm.CASES[0]), (p.FULL_PROFILE,vm.CASES,"first-child-published")]:
            with self.assertRaises(ValueError): vm.selection(profile,cases,case)
    def test_complete_tree_never_normal_republication(self):
        for case in vm.CASES[1:]:
            self.assertEqual(vm.selection(p.FULL_PROFILE, vm.CASES, case)["recovery"], "complete-tree-readback")
    def test_early_root_checkpoint_rejected(self):
        with self.assertRaises(ValueError): vm.root_observation(dict(stage="first-child-published"),dict(caseName=vm.CASES[1]))
FULL = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-full.py"))


def fixture(stage):
    arm = FULL["arm_for"]("transaction-published-bind-reply-lost")
    worker = FULL["uid"]()
    value = FULL["storage"](arm, worker)
    arm["caseName"] = stage
    value.update(**vm.storage_query(arm, worker), stage=stage)
    if stage == vm.CASES[2]:
        intent = value["bound"]["intent"]
        metadata = FULL["cleanup"]()
        metadata.update(uid=10001, gid=10002, mode=0o750, atime_seconds="1700000001", mtime_seconds="2", atime_nanos=7, mtime_nanos=9,
                        manifest=FULL["object_for"](3), staging=FULL["object_for"](4))
        metadata["manifest"]["file_type"] = 32768
        intent.update(phase="CLEANING", manifest_size=100, manifest_digest="a" * 64, cleanup=metadata)
    return arm, worker, value


def physical_identity(inode, kind):
    obj = FULL["object_for"](inode)
    return dict(inode=obj["inode"], generation=obj["generation"], fileType=kind, handle=obj["handle"])


def source_witness_for(arm, checkpoint):
    """Real first-a DTO bound to the later CLEANING intent, not a root-cut DTO."""
    intent = checkpoint["bound"]["intent"]
    value = FULL["V1"]["observed"](arm)
    value.update(version=3, profile=p.FULL_PROFILE, copyIntent=intent["id"],
        filesystemUUID=intent["root"]["backing_uuid"], manifestDigest=intent["manifest_digest"],
        manifestSize=intent["manifest_size"], published=physical_identity(5, 32768),
        staged=physical_identity(6, 32768))
    for name, obj in (("root", intent["root"]["root"]), ("transaction", intent["transaction"])):
        value[name] = dict(inode=obj["inode"], generation=obj["generation"],
            fileType=obj["file_type"], handle=obj["handle"])
    cleanup = intent["cleanup"]
    value["sourceAtimes"]["root"] = int(cleanup["atime_seconds"]) * 10**9 + cleanup["atime_nanos"]
    return value


def invalid_source_witnesses(arm, checkpoint):
    value = source_witness_for(arm, checkpoint)
    yield "missing", None
    for key in value:
        bad = copy.deepcopy(value); del bad[key]
        yield "missing-" + key, bad
    for index, (key, wrong) in enumerate((("version", 1), ("version", True), ("profile", p.PROFILE),
            ("stage", vm.CASES[2]), ("requestID", FULL["uid"]()), ("armDigest", "0" * 64),
            ("targetAttachment", FULL["uid"]()), ("copyIntent", FULL["uid"]()),
            ("filesystemUUID", "7" * 32), ("manifestDigest", "b" * 64), ("manifestSize", 101),
            ("count", 2), ("count", True), ("extra", 1))):
        bad = copy.deepcopy(value); bad[key] = wrong
        yield f"wrong-{key}-{index}", bad
    bad = copy.deepcopy(value)
    bad["root"], bad["transaction"] = bad["transaction"], bad["root"]
    yield "swapped-root-transaction", bad
    for name in ("root", "transaction"):
        bad = copy.deepcopy(value); bad[name] = physical_identity(99, 16384)
        yield "foreign-" + name, bad
    for name in ("published", "staged"):
        for other in ("root", "transaction", "published", "staged", "manifest", "staging"):
            if name == other: continue
            obj = value[other] if other in value else checkpoint["bound"]["intent"]["cleanup"][other]
            bad = copy.deepcopy(value)
            # Keep valid file types/handles so inode aliasing is the only defect.
            for key in ("inode", "generation", "handle"): bad[name][key] = obj[key]
            yield f"alias-{name}-{other}", bad
    for key, wrong in (("root", value["sourceAtimes"]["root"] + 1), ("a", True), ("z", -1), ("extra", 1)):
        bad = copy.deepcopy(value); bad["sourceAtimes"][key] = wrong
        yield "invalid-atime-" + key, bad
    bad = copy.deepcopy(value); bad["root"]["extra"] = 1
    yield "extra-object-field", bad


class CleaningSourceProof(unittest.TestCase):
    def test_exact_joint_witness_preserves_both_independent_observations(self):
        arm, worker, checkpoint = fixture(vm.CASES[2])
        value = source_witness_for(arm, checkpoint)
        original = copy.deepcopy((value, arm, checkpoint))
        self.assertEqual([value[k]["inode"] for k in ("root", "transaction", "published", "staged")], [1, 2, 5, 6])
        self.assertEqual([checkpoint["bound"]["intent"]["cleanup"][k]["inode"] for k in ("manifest", "staging")], [3, 4])
        self.assertEqual(value["stage"], "first-child-published")
        self.assertIs(vm.cleaning_source_observation(value, arm, checkpoint, worker), value)
        self.assertEqual((value, arm, checkpoint), original)

    def test_missing_stale_foreign_unbound_duplicate_alias_and_root_atime_fail(self):
        arm, worker, checkpoint = fixture(vm.CASES[2])
        original = copy.deepcopy((arm, checkpoint))
        for label, value in invalid_source_witnesses(arm, checkpoint):
            before = copy.deepcopy(value)
            with self.subTest(label=label), self.assertRaises(ValueError):
                vm.cleaning_source_observation(value, arm, checkpoint, worker)
            self.assertEqual(value, before)
            self.assertEqual((arm, checkpoint), original)

    def test_cleanup_root_atime_cannot_replace_retained_source_timestamp(self):
        arm, worker, checkpoint = fixture(vm.CASES[2])
        value = source_witness_for(arm, checkpoint)
        # Establish an independent earlier source timestamp, then separately
        # model its later capture by CLEANING. Never repair either proof at validation.
        retained_root_atime = FULL["V1"]["observed"](arm)["sourceAtimes"]["root"] + 29
        value["sourceAtimes"]["root"] = retained_root_atime
        seconds, nanos = divmod(retained_root_atime, 10**9)
        cleanup = checkpoint["bound"]["intent"]["cleanup"]
        cleanup.update(atime_seconds=str(seconds), atime_nanos=nanos)
        original = copy.deepcopy((value, checkpoint))
        self.assertIs(vm.cleaning_source_observation(value, arm, checkpoint, worker), value)
        self.assertEqual((value, checkpoint), original)
        cleanup["atime_nanos"] += 1
        vm.cleaning_observation(checkpoint, arm, worker)  # Independently valid later metadata.
        changed = copy.deepcopy(checkpoint)
        with self.assertRaisesRegex(ValueError, "pre-read source witness"):
            vm.cleaning_source_observation(value, arm, checkpoint, worker)
        self.assertEqual(value, original[0])
        self.assertEqual(checkpoint, changed)

    def test_individually_valid_witnesses_cannot_be_swapped_between_attempts(self):
        arm, worker, checkpoint = fixture(vm.CASES[2])
        other_arm, other_worker, other_checkpoint = fixture(vm.CASES[2])
        value = source_witness_for(arm, checkpoint)
        other = source_witness_for(other_arm, other_checkpoint)
        vm.cleaning_source_observation(other, other_arm, other_checkpoint, other_worker)
        for physical, storage, owner in ((other, checkpoint, worker), (value, other_checkpoint, other_worker),
                                        (value, checkpoint, other_worker)):
            with self.assertRaises(ValueError): vm.cleaning_source_observation(physical, arm, storage, owner)
        for stage in vm.CASES[:2]:
            bad_arm = dict(arm, caseName=stage)
            with self.assertRaises(ValueError): vm.cleaning_source_observation(value, bad_arm, checkpoint, worker)
        bad = copy.deepcopy(checkpoint); bad["bound"]["intent"]["phase"] = "BOUND"
        with self.assertRaises(ValueError): vm.cleaning_source_observation(value, arm, bad, worker)


class VMStorageProof(unittest.TestCase):
    def test_actual_cleaning_fields_preserved_and_private_bound_only(self):
        for stage in (vm.CASES[0], vm.CASES[2]):
            arm, worker, value = fixture(stage)
            original = copy.deepcopy(value)
            self.assertIs(vm.storage_observation(value, arm, worker), value)
            self.assertEqual(value, original)
            bad = copy.deepcopy(value)
            bad["bound"]["intent"]["phase"] = "BOUND" if stage == vm.CASES[2] else "CLEANING"
            with self.assertRaises(ValueError): vm.storage_observation(bad, arm, worker)

    def test_exact_current_worker_request_digest_and_full_owner(self):
        for stage in (vm.CASES[0], vm.CASES[2]):
            arm, worker, value = fixture(stage)
            mutations = [lambda v: v.update(workerUUID=FULL["uid"]()), lambda v: v.update(requestID=FULL["uid"]()),
                lambda v: v.update(armDigest="0" * 64), lambda v: v.update(count=True), lambda v: v.update(count=2),
                lambda v: v.update(version=True), lambda v: v.update(extra=1), lambda v: v.update(targetAttachment=FULL["uid"]()),
                lambda v: v["bound"].update(requestSequence=0), lambda v: v["bound"].update(requestSequence=True),
                lambda v: v["bound"]["intent"].update(epoch=FULL["uid"]())]
            for key in value["bound"]["intent"]["owner"]:
                mutations.append(lambda v, key=key: v["bound"]["intent"]["owner"].update({key: "wrong"}))
            for mutate in mutations:
                bad = copy.deepcopy(value); mutate(bad)
                with self.assertRaises(ValueError): vm.storage_observation(bad, arm, worker)
            for key in value:
                bad = copy.deepcopy(value); del bad[key]
                with self.assertRaises(ValueError): vm.storage_observation(bad, arm, worker)

    def test_cleaning_metadata_negative_matrix(self):
        arm, worker, value = fixture(vm.CASES[2])
        changes = [("uid", True), ("uid", 2**32-1), ("gid", -1), ("mode", 0o10000), ("atime_nanos", 10**9),
                   ("mtime_nanos", True), ("atime_seconds", "-0"), ("mtime_seconds", str(2**63)), ("mtime_seconds", 1)]
        for key, wrong in changes:
            bad = copy.deepcopy(value); bad["bound"]["intent"]["cleanup"][key] = wrong
            with self.subTest(key=key, wrong=wrong), self.assertRaises(ValueError): vm.cleaning_observation(bad, arm, worker)
        for key, wrong in (("manifest_size", 0), ("manifest_size", True), ("manifest_digest", "0" * 64), ("initial_captured", False)):
            bad = copy.deepcopy(value); bad["bound"]["intent"][key] = wrong
            with self.assertRaises(ValueError): vm.cleaning_observation(bad, arm, worker)
        for obj in ("manifest", "staging"):
            for key, wrong in (("inode", 0), ("file_type", True), ("handle_type", 2), ("handle_size", 0), ("handle", "0" * 16)):
                bad = copy.deepcopy(value); bad["bound"]["intent"]["cleanup"][obj][key] = wrong
                with self.assertRaises(ValueError): vm.cleaning_observation(bad, arm, worker)

    def test_cleaning_four_distinct_provenance_inodes(self):
        arm, worker, value = fixture(vm.CASES[2])
        def objects(intent):
            return [intent["root"]["root"], intent["transaction"],
                    intent["cleanup"]["manifest"], intent["cleanup"]["staging"]]
        self.assertEqual([obj["inode"] for obj in objects(value["bound"]["intent"])], [1, 2, 3, 4])
        for source in range(4):
            for target in range(source + 1, 4):
                bad = copy.deepcopy(value)
                rows = objects(bad["bound"]["intent"])
                # Keep each object's expected type and internally coherent handle;
                # only provenance distinctness should reject these aliases.
                for key in ("inode", "generation", "handle"):
                    rows[target][key] = rows[source][key]
                with self.subTest(source=source, target=target), self.assertRaisesRegex(ValueError, "distinct cleanup provenance"):
                    vm.cleaning_observation(bad, arm, worker)

    def test_status_never_promotes_hold_or_changed_checkpoint_to_drain(self):
        for stage in (vm.CASES[0], vm.CASES[2]):
            arm, worker, checkpoint = fixture(stage)
            value = dict(query=vm.storage_query(arm, worker), state="observed", observation=checkpoint,
                         retirementStarted=False, acceptedInFlight=1, lateAdmissionRejected=False, receiptReplayCount=0)
            vm.storage_status(value, arm, worker, checkpoint=checkpoint)
            for key, wrong in (("state", "finished"), ("state", "released"), ("retirementStarted", True),
                               ("acceptedInFlight", 0), ("acceptedInFlight", True), ("receiptReplayCount", 1), ("lateAdmissionRejected", True)):
                bad = copy.deepcopy(value); bad[key] = wrong
                with self.assertRaises(ValueError): vm.storage_status(bad, arm, worker, checkpoint=checkpoint)
            bad = copy.deepcopy(value); bad["observation"]["bound"]["requestSequence"] += 1
            with self.assertRaises(ValueError): vm.storage_status(bad, arm, worker, checkpoint=checkpoint)
            with self.assertRaises(ValueError): vm.storage_status(value, arm, worker, phase="finished")
            armed = {k: v for k, v in value.items() if k != "observation"}
            armed.update(state="armed", acceptedInFlight=0)
            vm.storage_status(armed, arm, worker, phase="armed")

    def test_root_scope_duplicate_and_handles(self):
        arm = FULL["arm_for"]("first-child-published"); arm["caseName"] = vm.CASES[1]
        value = FULL["V1"]["observed"](arm)
        value.update(version=3, profile=p.FULL_PROFILE, stage=vm.CASES[1])
        vm.root_observation(value, arm)
        for key, wrong in (("count", 2), ("count", True), ("requestID", FULL["uid"]()), ("armDigest", "0" * 64),
                           ("targetAttachment", FULL["uid"]()), ("stage", "first-child-published")):
            bad = copy.deepcopy(value); bad[key] = wrong
            with self.assertRaises(ValueError): vm.root_observation(bad, arm)
        bad = copy.deepcopy(value); bad["staged"] = bad["published"]
        with self.assertRaises(ValueError): vm.root_observation(bad, arm)


if __name__ == "__main__": unittest.main()
