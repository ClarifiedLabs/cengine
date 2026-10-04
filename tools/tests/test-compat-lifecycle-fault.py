#!/usr/bin/env python3
"""Closed selector and target-scoped fault build wiring regression tests."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Scripts"))
import compat_lifecycle_fault as fault


class LifecycleFaultTests(unittest.TestCase):
    def selected(self, **updates):
        value = {fault.ENV: fault.PROFILE, "CENGINE_DEVELOPER_ID_APPLICATION": "Developer ID Application: Example (ABC1234567)"}
        value.update(updates)
        return value

    def test_normal_and_exact_profile(self):
        self.assertEqual(fault.selection({}), "")
        self.assertEqual(fault.selection(self.selected()), fault.PROFILE)
        self.assertEqual(fault.build_settings({}), [fault.ENV + "=", fault.CONDITION_SETTING + "=",
                                                   fault.HELPER_CONDITION_SETTING + "=", fault.COLD_L2_SETTING + "="])
        for profile in (fault.PROFILE, fault.REPLACEMENT_PROFILE, *fault.TAKEOVER_PROFILES, fault.FIRST_COLD_COMPLETION_PROFILE):
            self.assertEqual(fault.build_settings(self.selected(**{fault.ENV: profile})),
                             [fault.ENV + "=" + profile, fault.CONDITION_SETTING + "=" + fault.CONDITION,
                              fault.HELPER_CONDITION_SETTING + "=", fault.COLD_L2_SETTING + "="])
        self.assertEqual(fault.selection(self.selected(**{fault.ENV: fault.REPLACEMENT_PROFILE})), fault.REPLACEMENT_PROFILE)
        for value in ("unknown", " before-configure-v1", "before-configure-v1 ", "1",
                      "after-replacement-before-completion-v2", "after-replacement-before-completion-v1 "):
            with self.subTest(value=value), self.assertRaises(ValueError):
                fault.selection(self.selected(**{fault.ENV: value}))

    def test_first_cold_completion_is_engine_only_and_closed(self):
        profile = fault.FIRST_COLD_COMPLETION_PROFILE
        for bad in (profile + ' ', ' ' + profile, profile.replace('v1', 'v2'), profile + ',' + fault.COLD_L2_PROFILE):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                fault.selection(self.selected(**{fault.ENV: bad}))
        source = (ROOT / 'Sources/CEngineRuntime/ManagedStorageLifecycleOwner.swift').read_text()
        body = source[source.index('private func finishColdBoot('):source.index('func bootResume(')]
        points = ['checkedColdRequest(', 'try result.validate(prepared: prepared)',
                  'try Self.match(result.successor, boot: successor)', 'try persist(.completeCold(result))',
                  '#if CENGINE_COMPAT_LIFECYCLE_FAULT',
                  'try StorageLifecycleCompatibilityFaultPolicy.afterFirstColdCompletion(result)',
                  '#endif', 'freshColdCompletion =']
        offsets = [body.index(point) for point in points]
        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(source.count('StorageLifecycleCompatibilityFaultPolicy.afterFirstColdCompletion('), 1)
        policy = (ROOT / 'Sources/CEngineRuntime/StorageLifecycleCompatibilityFaultPolicy.swift').read_text()
        hook = policy[policy.index('static func afterFirstColdCompletion('):policy.index('/// Only a successfully')]
        self.assertIn('StorageLifecycleColdRootProtocol.Completed', hook)
        self.assertIn('try currentProfile() == .afterFirstColdCompletion', hook)
        self.assertIn('completion.receipt.grant.expectedEpoch', hook)
        self.assertIn('expectedEpoch == 1', policy)
        self.assertIn('cengine.compat.lifecycle.after-first-cold-completion-v1.injected\\n', hook)
        self.assertIn('throw EngineError', hook)
        for forbidden in ('ProcessInfo', 'UserDefaults', 'createFile', 'persist(', 'Task.sleep', 'write(to:'):
            self.assertNotIn(forbidden, hook)

    def test_cold_l2_profile_is_helper_only_and_closed(self):
        self.assertEqual(fault.build_settings(self.selected(**{fault.ENV: fault.COLD_L2_PROFILE})),
                         [fault.ENV + "=" + fault.COLD_L2_PROFILE, fault.CONDITION_SETTING + "=",
                          fault.HELPER_CONDITION_SETTING + "=" + fault.HELPER_CONDITION,
                          fault.COLD_L2_SETTING + "=" + fault.COLD_L2_PROFILE])
        for bad in (fault.COLD_L2_PROFILE + " ", " " + fault.COLD_L2_PROFILE,
                    fault.COLD_L2_PROFILE.replace("v1", "v2"),
                    fault.COLD_L2_PROFILE + "," + fault.PROFILE):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                fault.selection(self.selected(**{fault.ENV: bad}))

    def test_takeover_profiles_and_closed_spelling(self):
        for profile in fault.TAKEOVER_PROFILES:
            self.assertEqual(fault.selection(self.selected(**{fault.ENV: profile})), profile)
            for bad in (profile + " ", " " + profile, profile.replace("v1", "v2")):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    fault.selection(self.selected(**{fault.ENV: bad}))

    def test_takeover_cuts_bracket_apply_and_only_authenticated_recovery_bypasses(self):
        source = (ROOT / "Sources/CEngineRuntime/ManagedStorageLifecycleOwner.swift").read_text()
        before = source.index("StorageLifecycleCompatibilityFaultPolicy.takeoverApply(.beforeTakeoverApply")
        apply = source.index("try await worker.takeover()", before)
        after = source.index("StorageLifecycleCompatibilityFaultPolicy.takeoverApply(.afterTakeoverApply", apply)
        reconcile = source.index("command(.reconcileController", after)
        self.assertLess(before, apply)
        self.assertLess(apply, after)
        self.assertLess(after, reconcile)
        self.assertEqual(source.count("recoveredHandoff = true"), 1)
        self.assertIn("try persist(.recoverHandoff(value))\n        recoveredHandoff = true", source)
        self.assertIn("#endif", source[before:apply])
        self.assertIn("#if CENGINE_COMPAT_LIFECYCLE_FAULT", source[apply:after])
        self.assertIn("#endif", source[after:reconcile])

    def test_ambient_output_settings_refused_even_empty_or_without_profile(self):
        for profile in ("", *fault.PROFILES):
            for key in (fault.CONDITION_SETTING, fault.HELPER_CONDITION_SETTING, fault.COLD_L2_SETTING):
                for value in ("", fault.CONDITION, fault.HELPER_CONDITION, fault.COLD_L2_PROFILE):
                    with self.subTest(profile=profile, key=key, value=value), self.assertRaises(ValueError):
                        fault.selection(self.selected(**{fault.ENV: profile, key: value}))

    def test_conflicting_or_unsigned_selections_refused(self):
        for key, value in {"CENGINE_COMPAT_SHARED_STORAGE": "", "CENGINE_COMPAT_MANAGED_STORAGE": "0",
                           "CENGINE_DEVELOPER_ID_APPLICATION": "-", "CENGINE_STORAGE_LIFECYCLE_QUALIFICATION": "lifecycle-v2-native-v1",
                           "CENGINE_STORAGE_LIFECYCLE_SOURCE_PIN": "a" * 64,
                           "CENGINE_STORAGE_LIFECYCLE_ASSETS_SHA256": "a" * 64,
                           "CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY": "rtm096-full-nine-v3",
                           "PREPARE_COMPATIBILITY_PROFILE": "profile", "CONFIGURATION": "Release",
                           "XCODE_COMPAT_CONFIGURATION": "Debug", "XCODE_COMPAT_SCHEME": "cengine",
                           "CENGINE_SIGN_RELEASE": "1", "CENGINE_NOTARIZE": "1",
                           "CODE_SIGNING_ALLOWED": "NO", "CODE_SIGNING_REQUIRED": "NO", "CODE_SIGN_IDENTITY": "-"}.items():
            for profile in fault.PROFILES:
                with self.subTest(profile=profile, key=key), self.assertRaises(ValueError):
                    fault.selection(self.selected(**{fault.ENV: profile, key: value}))

    def test_runner_passes_target_scoped_settings_for_install_and_suite(self):
        source = (ROOT / "Scripts/run-compat-tests.sh").read_text()
        # Execute the real selection/build argv, not lock/reset/install/VM code.
        script = source[:source.index("LOCK=")] + '\nBUILD_STAGE=test\nstage() { :; }\n' + source[
            source.index('stage "$BUILD_STAGE"'):source.index('HELPER=$(compat_network_helper_local_for_binary')]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "Scripts", root / "Scripts")
            (root / "Scripts/check-managed-guest-assets.py").write_text("# Asset validation is covered separately.\n")
            (root / "assets").mkdir()
            (root / "assets/disk-bootstrap.json").write_text(json.dumps({"storageLifecycleVersion": 2}))
            log = root / "calls.jsonl"
            for name in ("network-helper-fingerprint.sh", "xcodebuild", "build-storage-controller.sh", "sign-compat-binary.sh"):
                command = root / "Scripts" / name
                command.write_text(f'#!{sys.executable}\nimport json,os,pathlib,sys\n'
                    'with open(os.environ["CALLS"],"a") as output:\n'
                    ' output.write(json.dumps([pathlib.Path(sys.argv[0]).name,*sys.argv[1:]])+"\\n")\n'
                    'if pathlib.Path(sys.argv[0]).name == "network-helper-fingerprint.sh": print("a"*64)\n')
                command.chmod(0o755)
            base = {key: value for key, value in os.environ.items()
                    if not key.startswith(("CENGINE_", "XCODE", "PREPARE_", "CODE_SIGN", "CONFIGURATION"))}
            base.update(self.selected(), CALLS=str(log), XCODEBUILD=str(root / "Scripts/xcodebuild"),
                        CENGINE_COMPAT_MANAGED_ASSET_DIR=str(root / "assets"))
            for profile in ("", *fault.PROFILES):
                for mode in ("helper-install", "suite"):
                    with self.subTest(profile=profile, mode=mode):
                        log.write_text("")
                        result = subprocess.run(["/bin/sh", "-eu", "-c", script,
                            str(root / "Scripts/run-compat-tests.sh"), mode],
                            env={**base, fault.ENV: profile}, text=True, capture_output=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        calls = [json.loads(line) for line in log.read_text().splitlines()]
                        xcode = next(call for call in calls if call[0] == "xcodebuild")
                        expected = fault.build_settings(self.selected(**{fault.ENV: profile}))
                        actual = [item for item in xcode if item.split("=", 1)[0] in
                                  (fault.ENV, fault.CONDITION_SETTING, fault.HELPER_CONDITION_SETTING, fault.COLD_L2_SETTING)]
                        self.assertEqual(actual, expected)
                        self.assertFalse(any(item.startswith(("OTHER_SWIFT_FLAGS=", "SWIFT_ACTIVE_COMPILATION_CONDITIONS=")) for item in xcode))
                        controller = next(call for call in calls if call[0] == "build-storage-controller.sh")
                        self.assertEqual(controller[1:4], ["--sign", base["CENGINE_DEVELOPER_ID_APPLICATION"], "--compat"])
                        self.assertFalse(any("FAULT" in item for item in controller))
            for overrides in ({"XCODE_COMMON_FLAGS": "OTHER_SWIFT_FLAGS=-D BAD"},
                              {"CENGINE_BINARY": str(root / "unpaired")},
                              {fault.CONDITION_SETTING: fault.CONDITION},
                              {fault.HELPER_CONDITION_SETTING: fault.HELPER_CONDITION},
                              {fault.COLD_L2_SETTING: fault.COLD_L2_PROFILE}):
                log.write_text("")
                result = subprocess.run(["/bin/sh", "-eu", "-c", script,
                    str(root / "Scripts/run-compat-tests.sh"), "suite"],
                    env={**base, **overrides}, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(log.read_text(), "")

    def test_replacement_pause_only_after_actual_native_success(self):
        source = (ROOT / "Sources/CEngineRuntime/ManagedStorageLifecycleOwner.swift").read_text()
        call = source.index("try await StorageLifecycleCompatibilityFaultPolicy.afterReplacementBeforeCompletion(")
        success = source.rindex("try await self.pollReplacement", 0, call)
        rebind = source.index("try await self.worker.stageServiceRebind", call)
        self.assertLess(success, call)
        self.assertLess(call, rebind)
        self.assertIn("#if CENGINE_COMPAT_LIFECYCLE_FAULT", source[success:call])
        self.assertIn("#endif", source[call:rebind])
        self.assertEqual(source.count("StorageLifecycleCompatibilityFaultPolicy.afterReplacementBeforeCompletion("), 1)
        policy = (ROOT / "Sources/CEngineRuntime/StorageLifecycleCompatibilityFaultPolicy.swift").read_text()
        self.assertIn("try await Task.sleep(for: .seconds(30))", policy)
        self.assertIn("controlled compatibility replacement pause expired", policy)

    def test_metadata_fault_keys_are_target_scoped(self):
        with (ROOT / "Configuration/cengine-Info.plist").open("rb") as source:
            engine = plistlib.load(source)
        self.assertEqual(engine["CEngineCompatLifecycleFault"], "$(CENGINE_COMPAT_LIFECYCLE_FAULT)")
        self.assertNotIn("CEngineCompatColdL2Fault", engine)
        with (ROOT / "Configuration/network-helper-Info.plist").open("rb") as source:
            helper = plistlib.load(source)
        self.assertNotIn("CEngineCompatLifecycleFault", helper)
        self.assertEqual(helper["CEngineCompatColdL2Fault"], "$(CENGINE_COMPAT_COLD_L2_FAULT)")

    def test_target_setting_not_global(self):
        project = json.loads(subprocess.check_output(["plutil", "-convert", "json", "-o", "-",
                                                     str(ROOT / "cengine.xcodeproj/project.pbxproj")]))
        objects = project["objects"]
        consumers = {fault.CONDITION_SETTING: [], fault.HELPER_CONDITION_SETTING: []}
        for obj in objects.values():
            if obj.get("isa") != "PBXNativeTarget":
                continue
            for config_id in objects[obj["buildConfigurationList"]]["buildConfigurations"]:
                config = objects[config_id]
                condition = config["buildSettings"].get("SWIFT_ACTIVE_COMPILATION_CONDITIONS", "")
                for setting in consumers:
                    if setting in condition:
                        consumers[setting].append((obj["name"], config["name"]))
        self.assertEqual(consumers, {fault.CONDITION_SETTING: [("CEngineRuntime", "test-compat")],
                                    fault.HELPER_CONDITION_SETTING: [("CEngineHelper", "test-compat")]})
        # Neither switch leaks into another target or a Debug/Release configuration.
        source = (ROOT / "cengine.xcodeproj/project.pbxproj").read_text()
        for setting in consumers:
            self.assertEqual(source.count(setting), 1)

    def test_validated_hello_before_fault_before_configure(self):
        source = (ROOT / "Sources/CEngineRuntime/PrivateStorageLifecycleBootCoordinator.swift").read_text()
        hello = source.index("guard hello.operation == .hello")
        fault_call = source.index("try StorageLifecycleCompatibilityFaultPolicy.beforeConfigure")
        configure = source.index("try io.write(Wire.encode(.init(operation: .configure")
        self.assertLess(hello, fault_call)
        self.assertLess(fault_call, configure)
        self.assertIn("#if CENGINE_COMPAT_LIFECYCLE_FAULT", source[hello:fault_call])
        self.assertIn("#endif", source[fault_call:configure])
        policy = (ROOT / "Sources/CEngineRuntime/StorageLifecycleCompatibilityFaultPolicy.swift").read_text()
        self.assertNotIn("ProcessInfo", policy)
        self.assertNotIn("Bundle.main", policy)
        self.assertIn("StorageLifecycleNativePolicy.current(role: .engine)", policy)
        self.assertIn("kSecCodeInfoPList", policy)


if __name__ == "__main__":
    unittest.main()
