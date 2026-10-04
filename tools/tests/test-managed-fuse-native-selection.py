#!/usr/bin/env python3
"""Engine-free fixed native plan and exact subcase proof; no Linux execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_fuse_artifact as artifact


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


builder = module("native_builder", ROOT / "tools/build-managed-fuse-artifact.py")
proofs = module("native_proofs", ROOT / "tools/tests/test-managed-fuse-interrupt.py")
bundles = module("native_bundles", ROOT / "tools/tests/test-managed-fuse-artifact.py")


def declaration(source, signature):
    start = source.index(signature)
    return source[start:source.index("\n}", start) + 2]


class NativeSelectionTests(unittest.TestCase):
    def test_fixed_packages_tags_and_each_expected_subcase(self):
        counts = {"RTM-089": ("storagefuse", 15, 13), "RTM-090": ("storagemanaged", 7, 6),
                  "RTM-091": ("supervisor", 19, 14), "RTM-092": ("storagemanaged", 25, 24),
                  "RTM-093": ("supervisor", 3, 2), "RTM-094": ("supervisor", 1, 0),
                  "RTM-095": ("storagemanaged", 14, 10), "RTM-101": ("supervisor", 8, 0), "RTM-102": ("storagemanaged", 48, 38),
                  "RTM-104": ("storagefuse", 13, 10), "RTM-107": ("storagemanaged", 8, 6),
                  "RTM-108": ("storagemanaged", 7, 5), "RTM-109": ("storagemanaged", 7, 5),
                  "RTM-110": ("storagemanaged", 5, 3), "RTM-113": ("storageauthority", 1, 0)}
        for case_id, (package, total, children) in counts.items():
            selected = artifact.selection(case_id)
            self.assertEqual(selected["package"], "./internal/" + package)
            self.assertEqual(selected["binary"], "native.test")
            self.assertEqual(selected["tags"], ["cengine_native_faulttest"] if case_id in ("RTM-089", "RTM-090", "RTM-093", "RTM-094", "RTM-101", "RTM-102", "RTM-108", "RTM-109", "RTM-110") else [])
            names = selected["expected"]
            self.assertEqual(len(names), total)
            self.assertEqual(sum("/" in name for name in names), children)
            self.assertEqual(names, sorted(set(names)))
            self.assertEqual(set(selected["test"].split("|")), {name for name in names if "/" not in name})
            script = builder.build_script(case_id)
            self.assertEqual(script.count(" " + selected["package"] + "\n"), 2)
            self.assertEqual(script.count("-tags=cengine_native_faulttest"), 2 if selected["tags"] else 0)
            self.assertNotIn("__PACKAGE__", script)
            self.assertNotIn("go test -run", script)
            self.assertIn("cmp /work/toolchain.before /work/out/toolchain.sha256", script)
            self.assertIn("GOPROXY=off GOSUMDB=off", script)
            self.assertEqual(set(artifact.BOUNDS), {"native.test", "setup", "mke2fs", "toolchain.sha256"})
            value = proofs.proof(case_id)
            proofs.case.native_proof(json.dumps(value).encode(), proofs.STATE, "a" * 64, "c" * 64, case_id)
            for name in names:
                missing = copy.deepcopy(value)
                missing["passed_tests"].remove(name)  # unchanged generic pass count is not proof
                with self.subTest(case=case_id, missing=name), self.assertRaises(ValueError):
                    proofs.case.native_proof(json.dumps(missing).encode(), proofs.STATE, "a" * 64, "c" * 64, case_id)
            wrong_sets = [names + [names[0]], names[:-1] + ["TestForeign"], [], None]
            if len(names) > 1:
                wrong_sets.append(list(reversed(names)))
            for wrong in wrong_sets:
                with self.assertRaises(ValueError):
                    proofs.case.native_proof(json.dumps(dict(value, passed_tests=wrong)).encode(), proofs.STATE, "a" * 64, "c" * 64, case_id)
            with self.assertRaises(ValueError):
                proofs.case.native_proof(json.dumps(dict(value, skips=1)).encode(), proofs.STATE, "a" * 64, "c" * 64, case_id)
        for bad in ("RTM-088", "RTM-084", "RTM-089 ", ".*", "../supervisor", "/native.test", "123", None, {}, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.build_script(bad)

    def test_durability_process_death_exact_component_plan(self):
        helper = "TestDurabilityPolicyHelpers"
        name = "TestNativeDurabilityPolicyProcessDeath"
        self.assertEqual(artifact.selection("RTM-107"), {
            "case": "RTM-107", "binary": "native.test", "package": "./internal/storagemanaged",
            "tags": [], "test": helper + "|" + name,
            "expected": [helper, name, name + "/barrier", name + "/barrier/completed",
                         name + "/barrier/uncertain", name + "/data", name + "/data/completed",
                         name + "/data/uncertain"]})
        for bad in ("RTM-107 ", "RTM-111", helper, helper + "|" + name,
                    name, name + "/data", "^" + name + "$", ".*"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.build_script(bad)

    def test_retirement_recovery_exact_component_plan(self):
        helper = "TestNativeRetirementRecoveryHelpers"
        name = "TestNativeRetirementRecoveryProcessDeath"
        self.assertEqual(artifact.selection("RTM-108"), {
            "case": "RTM-108", "binary": "native.test", "package": "./internal/storagemanaged",
            "tags": ["cengine_native_faulttest"], "test": helper + "|" + name,
            "expected": [helper, name, name + "/candidate", name + "/certified", name + "/completed",
                         name + "/prepared", name + "/published"]})
        for bad in ("RTM-108 ", "RTM-111", "rtm-108", helper, helper + "|" + name,
                    name, name + "/certified", "^(" + helper + "|" + name + ")$", ".*"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.build_script(bad)

    def test_copy_data_recovery_exact_component_plan(self):
        helper = "TestNativeCopyDataRecoveryHelpers"
        name = "TestNativeCopyDataRecoveryProcessDeath"
        worker = "TestNativeCopyDataRecoveryWorker"
        self.assertEqual(artifact.selection("RTM-109"), {
            "case": "RTM-109", "binary": "native.test", "package": "./internal/storagemanaged",
            "tags": ["cengine_native_faulttest"], "test": helper + "|" + name,
            "expected": [helper, name, name + "/cleaning-tail", name + "/completed-tail",
                         name + "/rename", name + "/root-metadata", name + "/sealed-tail"]})
        self.assertNotIn(worker, artifact.selection("RTM-109")["expected"])
        for bad in ("RTM-109 ", "RTM-111", "rtm-109", helper, helper + "|" + name,
                    name, name + "/rename", worker, "^(" + helper + "|" + name + ")$", ".*"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.build_script(bad)

    def test_prepare_retirement_exact_component_plan(self):
        helper = "TestNativePrepareRetirementHelpers"
        name = "TestNativePrepareRetirementProcessDeath"
        worker = "TestNativePrepareRetirementWorker"
        self.assertEqual(artifact.selection("RTM-110"), {
            "case": "RTM-110", "binary": "native.test", "package": "./internal/storagemanaged",
            "tags": ["cengine_native_faulttest"], "test": helper + "|" + name,
            "expected": [helper, name, name + "/completed", name + "/inside-barrier", name + "/published"]})
        self.assertNotIn(worker, artifact.selection("RTM-110")["expected"])
        for bad in ("RTM-110 ", "RTM-111", "rtm-110", helper, helper + "|" + name,
                    name, name + "/inside-barrier", worker, "^(" + helper + "|" + name + ")$", ".*"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.build_script(bad)

    def test_lifecycle_checkpoint_exact_inactive_component_plan(self):
        name = "TestNativeLifecycleCheckpointAndTerminalSeal"
        self.assertEqual(artifact.selection("RTM-113"), {
            "case": "RTM-113", "binary": "native.test", "package": "./internal/storageauthority",
            "tags": [], "test": name, "expected": [name]})
        for bad in ("RTM-113 ", "rtm-113", name, "^" + name + "$", name + "/child", ".*"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.build_script(bad)
        source = ROOT / "Guest/internal/storageauthority/lifecycle_native_linux_test.go"
        self.assertEqual(artifact.inventory(ROOT)[str(source.relative_to(ROOT))], artifact.digest(source.read_bytes()))

    def test_prepare_process_eintr_exact_plan_and_private_child_rejection(self):
        parents = ['TestPrepareProcessLinuxPollEINTR', 'TestPrepareProcessLinuxThreadMembership',
                   'TestPrepareProcessLinuxDeathRetainsDeadOwner']
        children = ['first', 'final', 'last-attempt', 'exhausted-first', 'exhausted-final',
                    'error-after-interrupt', 'ready-after-interrupt', 'starttime-after-interrupt',
                    'foreign-thread', 'closed-owner']
        self.assertEqual(artifact.selection("RTM-104"), {
            "case": "RTM-104", "binary": "native.test", "package": "./internal/storagefuse",
            "tags": [], "test": "|".join(parents),
            "expected": sorted(parents + [parents[0] + "/" + child for child in children])})
        for bad in ("RTM-104 ", "TestPrepareProcessLinuxChild", "|".join(parents), ".*"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.build_script(bad)

    def test_snapshot_exact_eight_component_cases_no_private_children(self):
        names = ['TestNativeSnapshot101DeadInitializerConsumers', 'TestNativeSnapshot101DirtyMmapWriteback', 'TestNativeSnapshot101HungAcceptedGuard', 'TestNativeSnapshot101PreBeginRenameUnlink', 'TestNativeSnapshot101ReadReaddirAtime', 'TestNativeSnapshot101RetainedWritableFD', 'TestNativeSnapshot101RuntimePoolSaturation', 'TestNativeSnapshot101SameUIDForeignTGID']
        self.assertEqual(artifact.selection("RTM-101"), {
            "case": "RTM-101", "binary": "native.test", "package": "./internal/supervisor",
            "tags": ["cengine_native_faulttest"], "test": "|".join(names), "expected": names})
        for child in ("TestNativeSnapshot101ForeignProcess", "TestNativeSnapshot101ConsumerProcess", "TestNativePrepareInitializerChildV4"):
            self.assertNotIn(child, artifact.selection("RTM-101")["expected"])
        self.assertEqual(len(names), 8)
        self.assertEqual(len(set(names)), 8)

    def test_prepare_preflight_exact_initializer_only_plan(self):
        name = "TestNativeIssuedPrepareInitializerPreflightV4"
        self.assertEqual(artifact.selection("RTM-093"), {
            "case": "RTM-093", "binary": "native.test", "package": "./internal/supervisor",
            "tags": ["cengine_native_faulttest"], "test": name,
            "expected": [name, name + "/first-publication-fresh-attachment", name + "/positive"]})
        for bad in ("RTM-093 ", name, "TestNativePrepareInitializerChild", "^" + name + "$", "PREPARE-PREFLIGHT"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.build_script(bad)

    def test_prepare_pending_and_ext4_cleanup_exact_closed_plans(self):
        pending = "TestNativePendingProvisionFreshMountReplayV4"
        self.assertEqual(artifact.selection("RTM-094"), {
            "case": "RTM-094", "binary": "native.test", "package": "./internal/supervisor",
            "tags": ["cengine_native_faulttest"], "test": pending, "expected": [pending]})
        cleanup = "TestCopyCleanupServerCrashRestoresExactRoot"
        parents = [cleanup, "TestCopyPendingReplayFreshSessionRootBootstrap",
                   "TestPrepareExt4IdentityRealFilesystem", "TestPrepareIdentityAtRejectsIntermediateSymlink"]
        boundaries = ["after-child-unlink", "after-finish-before-reply", "after-manifest-sync",
                      "after-root-sync", "after-transaction-unlink"]
        expected = sorted(parents + [cleanup + "/" + prefix + boundary
                                    for prefix in ("", "sealed/") for boundary in boundaries])
        self.assertEqual(artifact.selection("RTM-095"), {
            "case": "RTM-095", "binary": "native.test", "package": "./internal/storagemanaged",
            "tags": [], "test": "|".join(parents), "expected": expected})
        for bad in ("RTM-094 ", "RTM-095 ", "RTM-096", pending, "|".join(parents),
                    "TestNativePendingProvisionMarkerWorkerV4", "TestNativePrepareInitializerChildV4",
                    "TestCopyCleanupServerCrashWorker", "TestCopyBootstrapCrashWorker"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.build_script(bad)
        # The existing source-pinned manifest cannot be relabelled across packages,
        # tags or cases, including a superficially plausible empty test subset.
        for case_id in ("RTM-094", "RTM-095", "RTM-102", "RTM-107", "RTM-108", "RTM-109", "RTM-110", "RTM-113"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                value, _ = bundles.fixture(root)
                value["selection"] = artifact.selection(case_id)
                with patch.object(artifact, "inventory", return_value=value["sources"]):
                    for field, wrong in (("case", "RTM-093"), ("package", "./internal/storagefuse"),
                                         ("tags", [] if case_id in ("RTM-094", "RTM-102", "RTM-108", "RTM-109", "RTM-110") else ["cengine_native_faulttest"]),
                                         ("test", ".*"), ("expected", [])):
                        bad = copy.deepcopy(value)
                        bad["selection"][field] = wrong
                        raw = artifact.encode(bad)
                        (root / "fixture.json").write_bytes(raw)
                        with self.subTest(case=case_id, field=field), self.assertRaises(ValueError):
                            artifact.load_fixture(root, artifact.digest(raw), ROOT, case_id)

    def test_case_manifest_rejects_wrong_binary_package_tags_or_subcases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            value, _ = bundles.fixture(root)
            value["selection"] = artifact.selection("RTM-089")
            def load(v, case_id="RTM-089"):
                raw = artifact.encode(v)
                (root / "fixture.json").write_bytes(raw)
                return artifact.load_fixture(root, artifact.digest(raw), ROOT, case_id)
            with patch.object(artifact, "inventory", return_value=value["sources"]):
                load(value)
                for case_id in artifact.SELECTIONS:
                    if case_id != "RTM-089":
                        with self.assertRaises(ValueError): load(value, case_id)
                for field, wrong in (("case", "RTM-090"), ("binary", "other.test"), ("package", "./internal/supervisor"),
                                     ("tags", []), ("test", ".*"), ("expected", [])):
                    bad = copy.deepcopy(value)
                    bad["selection"][field] = wrong
                    with self.subTest(field=field), self.assertRaises(ValueError): load(bad)
                for name in value["selection"]["expected"]:
                    bad = copy.deepcopy(value)
                    bad["selection"]["expected"].remove(name)
                    with self.assertRaises(ValueError): load(bad)
        with patch.object(builder, "OriginalLock") as lock, patch.object(builder, "run_bounded") as engine:
            for bad in ("RTM-088", ".*", "--native-service-fault-child", "/tmp/evil", "123"):
                with self.assertRaises(ValueError): builder.build(type("Args", (), {"case": bad})())
            lock.assert_not_called()
            engine.assert_not_called()

    def test_actual_go_parser_every_missing_duplicate_foreign_skip_and_selector(self):
        source = (ROOT / "Tests/Compatibility/fixtures/managed-fuse-native.go").read_text()
        pieces = [declaration(source, "func " + name + "(") for name in
                  ("selectedTest", "selectedCaseBudget", "expectedNativeTests", "nativePassProof")]
        expected = json.dumps({key: value["expected"] for key, value in artifact.SELECTIONS.items()})
        go = '''package main
import("errors";"regexp";"strings";"encoding/json";"testing";"time")
''' + "\n\n".join(pieces) + '''
func TestExactNativeProof(t *testing.T) {
 var plans map[string][]string
 if err := json.Unmarshal([]byte(`''' + expected + '''`), &plans); err != nil {t.Fatal(err)}
 for id, names := range plans {
  selected, err := selectedTest(id); if err != nil {t.Fatal(err)}
  budget, outer, err := selectedCaseBudget(id); if err != nil {t.Fatal(err)}
  if (id == "RTM-093" || id == "RTM-094" || id == "RTM-095" || id == "RTM-101" || id == "RTM-102" || id == "RTM-107" || id == "RTM-108" || id == "RTM-109" || id == "RTM-110" || id == "RTM-113") && (budget != "-test.timeout=180s" || outer != 190*time.Second) {t.Fatal("preflight budget",budget,outer)}
  if id == "RTM-104" && (budget != "-test.timeout=90s" || outer != 95*time.Second) {t.Fatal("EINTR budget",budget,outer)}
  pattern := regexp.MustCompile("^("+selected+")$")
  for _, name := range names { if !strings.Contains(name,"/") && !pattern.MatchString(name) {t.Fatal(name)} }
  for _, forbidden := range []string{"TestPrepareProcessLinuxChild", "TestForeign", "TestNativeIssuedPrepareInitializerPreflight", "TestNativePrepareInitializerChild", "TestNativePrepareInitializerChildV4", "TestNativePendingProvisionMarkerWorkerV4", "TestCopyCleanupServerCrashWorker", "TestCopyBootstrapCrashWorker", "TestNativeCopyDataRecoveryWorker", "TestNativePrepareRetirementWorker", selected+"Extra"} {
   if pattern.MatchString(forbidden) {t.Fatal("open selector", forbidden)}
  }
  var lines []string
  for _, name := range names {lines=append(lines,"=== RUN   "+name,"    --- PASS: "+name+" (0.00s)")}
  lines=append(lines,"PASS")
  raw:=strings.Join(lines,"\\n")
  got,err:=nativePassProof([]byte(raw),id)
  if err!=nil || strings.Join(got,"\\n")!=strings.Join(names,"\\n") {t.Fatalf("%s: %v",id,err)}
  reject:=func(raw string) { t.Helper(); if _,err:=nativePassProof([]byte(raw),id);err==nil {t.Fatalf("accepted incomplete/foreign/duplicate/skip for %s",id)} }
  for i:=range lines {
   missing:=append([]string{},lines[:i]...);missing=append(missing,lines[i+1:]...);reject(strings.Join(missing,"\\n"))
   reject(raw+"\\n"+lines[i])
  }
  for _,extra:=range []string{"=== RUN   TestForeign","--- PASS: TestForeign (0.00s)","    --- SKIP: hidden (0.00s)","SKIP","FAIL","--- FAIL: hidden (0.00s)","=== RUN   TestNativePrepareInitializerChild","--- PASS: TestNativePrepareInitializerChild (0.00s)","=== RUN   TestNativeCopyDataRecoveryWorker","--- PASS: TestNativeCopyDataRecoveryWorker (0.00s)","=== RUN   TestNativePrepareRetirementWorker","--- PASS: TestNativePrepareRetirementWorker (0.00s)"} {reject(raw+"\\n"+extra)}
  reject("PASS")
 }
 for _,id:=range []string{"RTM-088","RTM-084",".*","/native.test","123","RTM-089 ","RTM-107 ","RTM-108 ","RTM-109 ","RTM-111","rtm-108","rtm-109","RTM-110 ","rtm-110","RTM-113 ","rtm-113","TestNativeLifecycleCheckpointAndTerminalSeal","TestNativeLifecycleCheckpointAndTerminalSeal/child","TestNativePrepareRetirementHelpers","TestNativePrepareRetirementHelpers|TestNativePrepareRetirementProcessDeath","TestNativePrepareRetirementProcessDeath","TestNativePrepareRetirementProcessDeath/inside-barrier","TestNativePrepareRetirementWorker","TestDurabilityPolicyHelpers","TestDurabilityPolicyHelpers|TestNativeDurabilityPolicyProcessDeath","TestNativeDurabilityPolicyProcessDeath","TestNativeRetirementRecoveryHelpers","TestNativeRetirementRecoveryHelpers|TestNativeRetirementRecoveryProcessDeath","TestNativeRetirementRecoveryProcessDeath","TestNativeRetirementRecoveryProcessDeath/certified","TestNativeCopyDataRecoveryHelpers","TestNativeCopyDataRecoveryHelpers|TestNativeCopyDataRecoveryProcessDeath","TestNativeCopyDataRecoveryProcessDeath","TestNativeCopyDataRecoveryProcessDeath/rename","TestNativeCopyDataRecoveryWorker"} {
  if _,err:=selectedTest(id);err==nil {t.Fatal(id)}
  if _,_,err:=selectedCaseBudget(id);err==nil {t.Fatal(id)}
  if _,err:=nativePassProof([]byte("PASS"),id);err==nil {t.Fatal(id)}
 }
}
'''
        # Portable pure parser only; never compile/run the Linux helper here.
        with tempfile.TemporaryDirectory(prefix="native-proof-", dir=ROOT.parent) as temp:
            root = Path(temp)
            (root / "proof_test.go").write_text(go)
            for name in ("cache", "tmp", "modcache"): (root / name).mkdir()
            env = dict(os.environ, CGO_ENABLED="1", GOOS="darwin", GOARCH="arm64", GOMAXPROCS="2",
                       GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOWORK="off", GOENV="off", GOFLAGS="",
                       GOCACHE=str(root / "cache"), GOTMPDIR=str(root / "tmp"), TMPDIR=str(root / "tmp"),
                       GOMODCACHE=str(root / "modcache"))
            subprocess.run(["go", "test", "-race", "-v", "proof_test.go"], cwd=root, env=env, check=True, timeout=120)


if __name__ == "__main__":
    unittest.main()
