#!/usr/bin/env python3
"""Engine-free fingerprint and build-boundary regression coverage."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path('Configuration/helper-support-sources.txt')


def support_sources():
    return (ROOT / MANIFEST).read_text().splitlines()


class HelperFingerprintTests(unittest.TestCase):
    def test_closed_manifest_is_explicit_unique_and_complete(self):
        sources = support_sources()
        self.assertEqual(sources, sorted(set(sources)))
        self.assertEqual(len(sources), 37)  # Includes the three closed interrupted-handoff value protocols.
        for source in sources:
            self.assertRegex(source, r'^Sources/CEngineCore/[A-Za-z][A-Za-z0-9]*\.swift$')
            self.assertTrue((ROOT / source).is_file(), source)
        for name in ('NetworkHelperCapabilities', 'StorageLifecycleAdoptionProtocol',
                     'StorageLifecycleResumeProtocol', 'StorageLifecycleColdProtocol',
                     'StorageLifecycleHandoffProtocol', 'StorageLifecycleHandoffRootProtocol',
                     'StorageLifecycleHandoffShimProtocol',
                     'CanonicalDataStoreLock', 'VMNetIPv4Configuration',
                     'StorageIdentity', 'StorageServiceTypes', 'StorageOwnerStatusProtocol'):
            self.assertIn(f'Sources/CEngineCore/{name}.swift', sources)
        self.assertNotIn('Sources/CEngineCore/Paths.swift', sources)
        self.assertNotIn('Sources/CEngineCore/DaemonSocketLock.swift', sources)
        self.assertNotIn('Sources/CEngineCore/StorageLifecycleServiceBootProtocol.swift', sources)

    def test_every_support_and_helper_input_changes_fingerprint(self):
        # Execute the real hashing logic with deterministic toolchain fixtures;
        # never invoke Xcode or depend on installed developer-tool versions.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / 'Scripts/network-helper-fingerprint.sh'
            script.parent.mkdir()
            text = (ROOT / 'Scripts/network-helper-fingerprint.sh').read_text()
            for command in ('/usr/bin/xcrun swiftc --version', '/usr/bin/xcodebuild -version',
                            '/usr/bin/xcrun --sdk macosx --show-sdk-build-version'):
                text = text.replace(command, "printf 'fixture-toolchain\\n'")
            script.write_text(text)
            (script.parent / 'storage_lifecycle_qualification.py').write_text("print('')\n")
            inputs = support_sources() + [str(MANIFEST), 'Configuration/network-helper-Info.plist']
            inputs += [str(path.relative_to(ROOT)) for path in
                       sorted((ROOT / 'Sources/CEngineNetworkHelper').glob('*.swift'))]
            for source in inputs:
                path = root / source
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / source, path)
            env = dict(os.environ, TMPDIR=directory)
            def fingerprint():
                return subprocess.check_output(['/bin/sh', str(script)], env=env, text=True).strip()
            baseline = fingerprint()
            self.assertRegex(baseline, r'^[0-9a-f]{64}$')
            for source in inputs:
                if source == str(MANIFEST):
                    continue  # Membership is exercised by the added source below.
                with self.subTest(source=source):
                    path = root / source
                    original = path.read_bytes()
                    path.write_bytes(original + b'\n// fingerprint mutation\n')
                    self.assertNotEqual(baseline, fingerprint())
                    path.write_bytes(original)
            for source in ('Sources/CEngineCore/Paths.swift', 'Sources/CEngineRuntime/EngineRuntime.swift'):
                path = root / source
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('// unrelated engine edit\n')
            self.assertEqual(baseline, fingerprint())
            with (root / MANIFEST).open('a') as manifest:
                manifest.write('Sources/CEngineCore/Paths.swift\n')
            self.assertNotEqual(baseline, fingerprint())

    def test_qualification_retains_broad_source_and_asset_pins(self):
        script = (ROOT / 'Scripts/network-helper-fingerprint.sh').read_text()
        self.assertIn('storage_lifecycle_qualification.py" source-pin "$ROOT"', script)
        self.assertIn('storage_lifecycle_qualification.py" assets-sha256 "$ROOT"', script)
        self.assertIn('lifecycle-source:%s', script)
        self.assertIn('lifecycle-assets:%s', script)

    def test_xcode_helper_links_only_explicit_support(self):
        project = json.loads(subprocess.check_output([
            'plutil', '-convert', 'json', '-o', '-', str(ROOT / 'cengine.xcodeproj/project.pbxproj')]))
        objects = project['objects']
        targets = {obj['name']: obj for obj in objects.values() if obj.get('isa') == 'PBXNativeTarget'}
        self.assertNotIn('CEngineNetworkHelper', targets)
        helper = targets['CEngineHelper']
        support = targets['CEngineHelperSupport']
        self.assertEqual(helper['productName'], 'cengine-helper')
        self.assertEqual(objects[helper['productReference']]['path'], 'cengine-helper')
        dependencies = [objects[objects[key]['target']]['name'] for key in helper['dependencies']]
        self.assertEqual(dependencies, ['CEngineHelperSupport'])
        self.assertEqual(support['dependencies'], [])
        self.assertFalse(support.get('fileSystemSynchronizedGroups'))
        self.assertFalse(support.get('packageProductDependencies'))
        phases = [objects[key] for key in support['buildPhases']]
        files = [objects[objects[key]['fileRef']]['path'] for phase in phases
                 if phase['isa'] == 'PBXSourcesBuildPhase' for key in phase['files']]
        self.assertEqual(sorted(files), support_sources())
        frameworks = [objects[objects[key]['fileRef']]['path'] for phase_key in helper['buildPhases']
                      for phase in [objects[phase_key]] if phase['isa'] == 'PBXFrameworksBuildPhase'
                      for key in phase['files']]
        self.assertEqual(frameworks, ['libCEngineHelperSupport.a'])
        core_groups = [objects[key] for key in targets['CEngineCore']['fileSystemSynchronizedGroups']]
        self.assertEqual([group['path'] for group in core_groups], ['Sources/CEngineCore'])
        self.assertFalse(core_groups[0].get('exceptions'))
        for config_key in objects[helper['buildConfigurationList']]['buildConfigurations']:
            settings = objects[config_key]['buildSettings']
            self.assertEqual(settings['PRODUCT_NAME'], 'cengine-helper')
            self.assertEqual(settings['INFOPLIST_FILE'], 'Configuration/network-helper-Info.plist')
            self.assertTrue(settings['PRODUCT_BUNDLE_IDENTIFIER'].startswith('dev.cengine.network-helper'))
        for path in (ROOT / 'cengine.xcodeproj/xcshareddata/xcschemes').glob('*.xcscheme'):
            refs = [ref for ref in ET.parse(path).iter('BuildableReference')
                    if ref.get('BlueprintIdentifier') == 'CE0000000000000000000037']
            self.assertTrue(refs)
            for ref in refs:
                self.assertEqual(ref.get('BlueprintName'), 'CEngineHelper')
                self.assertEqual(ref.get('BuildableName'), 'cengine-helper')

    def test_helper_imports_never_fall_back_to_engine(self):
        for path in (ROOT / 'Sources/CEngineNetworkHelper').glob('*.swift'):
            with self.subTest(source=path.name):
                text = path.read_text()
                imports = re.findall(r'\bimport (\w+)', text)
                self.assertIn('CEngineHelperSupport', imports)
                self.assertFalse({'CEngineCore', 'CEngineRuntime', 'CEngineAPI'} & set(imports))
        for runner in ('Tests/CEngineNetworkHelperTests/run.sh', 'Tests/StorageLifecycleIntegrationTests/run.py'):
            text = (ROOT / runner).read_text()
            self.assertIn('helper-support-sources.txt', text)
            self.assertIn('.target(name: "CEngineHelperSupport")', text)
            self.assertNotIn('.target(name: "CEngineCore")', text)


if __name__ == '__main__':
    unittest.main()
