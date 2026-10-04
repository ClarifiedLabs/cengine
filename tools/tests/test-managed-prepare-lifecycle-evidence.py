#!/usr/bin/env python3
"""Standard-library v2 PREPARE comparison tests; no native/engine authority."""
import base64
import copy
from dataclasses import replace
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import managed_prepare_lifecycle_evidence as e
import managed_prepare_service_faults as api
import managed_prepare_storage_vm_faults as vm
import managed_prepare_restart_matrix as matrix
from harness import RuntimeProcess


def uid(): return str(uuid.uuid4())
def encoded(value): return base64.b64encode(value).decode()


def owner():
    rootkey, child = encoded(b'r' * 32), encoded(b'c' * 32)
    identity = dict(store=uid(), generation=1, binding='a' * 64)
    context = dict(serviceEpoch=uid(), controllerEpoch=1, controllerKey=e.fingerprint(child))
    grant = dict(operation='initialize', id=uid(), identity=identity, serial=1, expected_epoch=0, new_key=context['controllerKey'])
    service = dict(grant=grant, context=dict(service_epoch=context['serviceEpoch'], controller_epoch=1, controller_key=context['controllerKey']),
        boot=dict(identity=identity, service_epoch=context['serviceEpoch'], tls_root_sha256='b'*64, server_spki='c'*64,
                  bootstrap_key=e.fingerprint(rootkey)), open_revision=10)
    current = dict(original=dict(signed=dict(grant=grant, signature=encoded(b's'*64)), requestID=uid(),
        recipient=dict(publicKey=child, incarnation=uid(), daemonUniqueID=10, childUniqueID=20, childPID=100)),
        directResult=dict(grant=grant, nonce=encoded(b'n'*32), service_epoch=context['serviceEpoch'], revision=12))
    state = dict(version=e.VERSION, identity=identity, rootPublicKey=rootkey, provenanceReference='d'*64,
        revision=10, contexts=[dict(context=context, controller=current)], serviceLinks=[], references=[], intentRevision=1, current=current, currentContext=context, currentService=service, pendingCold=None, latestCold=None,
        observedWorker=dict(context=context, workerUUID=uid()))
    file = dict(device=3, inode=40, volumeUUID=uid())
    manifest = dict(version=e.MANIFEST_VERSION, identity=identity, rootPublicKey=rootkey, provenanceReference='d'*64,
        root={**file, 'inode':4}, backing=file, directory={**file, 'inode':5}, lease={**file, 'inode':6}, bytes=4096, ext4UUID=uid())
    identity["binding"] = e.p.digest(b"cengine.storageauthority.binding.v3\0" + e.p.canonical(e.manifest_binding(manifest)))
    return dict(format=e.VERSION, checkpoint=state, manifest=manifest)


def successor(before, storage=False):
    after = copy.deepcopy(before)
    a, b = before['checkpoint'], after['checkpoint']
    b['revision'] += 10
    child = encoded(b'z'*32)
    context = b['currentContext']
    context.update(controllerEpoch=2, controllerKey=e.fingerprint(child))
    if storage:
        context['serviceEpoch'] = uid()
        b['observedWorker']['workerUUID'] = uid()
    b['currentService']['context'] = dict(service_epoch=context['serviceEpoch'], controller_epoch=2, controller_key=context['controllerKey'])
    grant = b['currentService']['grant']
    grant.update(operation='takeover', id=uid(), serial=2, expected_epoch=1, new_key=context['controllerKey'])
    b['current']['original']['recipient'].update(publicKey=child, incarnation=uid(), daemonUniqueID=30, childUniqueID=40, childPID=200)
    b['current']['original'].update(requestID=uid(), serviceEpoch=context['serviceEpoch'])
    b['current']['directResult'].update(revision=20, service_epoch=context['serviceEpoch'])
    if storage:
        b['currentService']['open_revision'] = 20
        b['currentService']['boot'].update(service_epoch=context['serviceEpoch'], tls_root_sha256='1'*64, server_spki='2'*64)
        binding = e.manifest_binding(after['manifest'])
        origin = dict(shimLaunchUUID=uid(), specSHA256='3'*64, rootPublicKey=b['rootPublicKey'],
            binding=dict(version=e.BINDING_VERSION,store=b['identity']['store'],root=binding['root'],backing=binding['backing']['identity'],bytes=4096,ext4_uuid=after['manifest']['ext4UUID']))
        b['latestCold'] = dict(predecessor=dict(controller=copy.deepcopy(a['current']), context=copy.deepcopy(a['currentContext'])),
            predecessorService=copy.deepcopy(a['currentService']),
            completion=dict(receipt=b['current']['directResult'], successor=b['currentService'], successorOrigin=origin),
            prepared=dict(signedOpen=dict(request=dict(takeover=b['current']['original']['signed'])), successorOrigin=origin),
            request=dict(prepareRequestID=uid(), recipient=b['current']['original']['recipient'], completionRequestID=b['current']['original']['requestID']))
        cold = b['latestCold']
        launch = dict(shim_launch_uuid=origin['shimLaunchUUID'], spec_sha256='3'*64, initramfs_sha256='4'*64,
            ext4_uuid=after['manifest']['ext4UUID'], bytes=4096)
        cold['request']['prepare'] = dict(operationID=grant['id'], expectedAllocatedEpoch=1, mountedGreeting=dict(launch=launch,version='storage-lifecycle-cold-shim.v2',purpose='cold',
            channelID=uid(),daemonUniqueID=b['current']['original']['recipient']['daemonUniqueID'],rootPublicKey=b['rootPublicKey'],
            binding=origin['binding'],heldBackingIdentity=dict(device=after['manifest']['backing']['device'], **origin['binding']['backing']),
            bootBinding=dict(shimLaunchUUID=origin['shimLaunchUUID'],guestBootNonce=uid(),ext4UUID=after['manifest']['ext4UUID'],bytes=4096)))
        signed = cold['prepared']['signedOpen']
        signed['signature'] = encoded(b'o'*64)
        predecessor = dict(current_grant=a['currentService']['grant'],service_epoch=a['currentContext']['serviceEpoch'],
            controller_epoch=a['currentContext']['controllerEpoch'],controller_key=a['currentContext']['controllerKey'],
            open_revision=a['currentService']['open_revision'],bootstrap_key=a['currentService']['boot']['bootstrap_key'])
        cold['request']['prepare'].update(identity=b['identity'],expectedPredecessor=predecessor,
            expectedOrigin={**origin,'shimLaunchUUID':uid()},candidate=dict(spki=encoded(bytes.fromhex('302a300506032b6570032100')+b'z'*32),pid=200,
            incarnation=b['current']['original']['recipient']['incarnation']),nowUnixSeconds=100,lifetimeSeconds=60)
        signed['request'].update(operation_id=grant['id'], launch=launch,predecessor=predecessor,
            now_unix_seconds=100,lifetime_seconds=60)
        cold['prepared']['baseEpoch'] = 2
        cold['completion'].update(operationID=grant['id'], baseEpoch=2,
            signedOpenSHA256=e.p.digest(b'cengine.storage-lifecycle-cold-root.signed-open.v1\0'+e.p.canonical(signed)))
    b['contexts'] = [copy.deepcopy(a['contexts'][0]), dict(context=b['currentContext'], controller=b['current'])]
    return after


class LifecycleEvidenceTests(unittest.TestCase):
    def test_stable_binding_digest_and_old_format_rejection(self):
        value = owner()
        binding = e.manifest_binding(value['manifest'])
        self.assertEqual(set(binding['root']), {'inode', 'volume_uuid'})
        self.assertEqual(set(binding['backing']['identity']), {'inode', 'volume_uuid'})
        for field in ('root', 'backing', 'directory', 'lease'):
            value['manifest'][field]['device'] += 99
        self.assertEqual(e.manifest_binding(value['manifest']), binding)
        e.owner_context(value)
        for version in (e.VERSION, 'storage-host-owner.v2'):
            bad = copy.deepcopy(value); bad['manifest']['version'] = version
            with self.subTest(version=version), self.assertRaises(ValueError): e.owner_context(bad)
        for field in ('root', 'backing'):
            for part in ('inode', 'volumeUUID'):
                bad = copy.deepcopy(value)
                bad['manifest'][field][part] = uid() if part == 'volumeUUID' else 999
                with self.subTest(field=field, part=part), self.assertRaises(ValueError): e.owner_context(bad)
        before = owner(); after = successor(before, storage=True)
        cold = after['checkpoint']['latestCold']
        cold['request']['prepare']['mountedGreeting']['heldBackingIdentity']['device'] += 101
        arm = dict(scope=e.owner_context(before)[1])
        e.transition(before, after, arm, storage=True)
        for mutation in ('missing-version', 'old-version', 'legacy-device', 'missing-live-device'):
            bad = copy.deepcopy(after)
            binding = bad['checkpoint']['latestCold']['completion']['successorOrigin']['binding']
            if mutation == 'missing-version': del binding['version']
            elif mutation == 'old-version': binding['version'] = 'storage-host-binding.v1'
            elif mutation == 'legacy-device': binding['backing']['device'] = 3
            else: del bad['checkpoint']['latestCold']['request']['prepare']['mountedGreeting']['heldBackingIdentity']['device']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): e.transition(before, bad, arm, storage=True)

    def test_read_path_selects_explicit_v2_without_fabricating_legacy_boot(self):
        value = owner(); reader = Mock(side_effect=[(value['checkpoint'], 'a'*64), (value['manifest'], 'b'*64)])
        actual, digest = e.read_owner(Path('/owned'), reader)
        self.assertEqual(actual, value); self.assertEqual(len(digest), 64)
        self.assertNotIn('transitions', actual); self.assertNotIn('boot', actual)
        self.assertEqual(reader.call_args_list[1].args[0], Path('/owned/managed-storage-owner/manifest.json'))
        projection, context = api.owner_context(actual)
        self.assertEqual(projection['confirmedRevision'], 12)
        self.assertEqual(vm.public_boot(vm.current_boot(actual))['revision'], 12)
        self.assertEqual(context['controllerEpoch'], 1)
        with self.assertRaises(ValueError):
            e.read_owner(Path('/owned'), Mock(return_value=({'version':'unknown'}, 'a'*64)))

    def test_unchanged_vm_owner_accepts_explicit_v2_nulls(self):
        value = owner()
        def read():
            return e.read_owner(Path('/owned'), Mock(side_effect=[
                (copy.deepcopy(value['checkpoint']), 'a'*64),
                (copy.deepcopy(value['manifest']), 'b'*64)]))
        before, before_hash = read(); current, current_hash = read()
        expected = api.owner_context(before)
        self.assertIsNone(current['checkpoint']['pendingCold'])
        self.assertIsNone(current['checkpoint']['latestCold'])
        self.assertEqual(vm.unchanged_owner_at_signal(before, before_hash, current, current_hash), expected)
        # The legacy/wire canonicalizer remains deliberately null/float-free.
        for invalid in (current, {'value': None}, {'value': 1.0}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError): e.p.canonical(invalid)

    def test_unchanged_vm_owner_rejects_record_mutation_and_either_file_hash_change(self):
        before = owner(); api.owner_context(before)
        def read(value, state_hash='a'*64, manifest_hash='b'*64):
            return e.read_owner(Path('/owned'), Mock(side_effect=[
                (value['checkpoint'], state_hash), (value['manifest'], manifest_hash)]))
        _, before_hash = read(before)
        changed = copy.deepcopy(before); changed['checkpoint']['revision'] += 1
        current, current_hash = read(changed)
        self.assertEqual(current_hash, before_hash)
        with self.assertRaisesRegex(ValueError, 'unchanged current VM owner at signal'):
            vm.unchanged_owner_at_signal(before, before_hash, current, current_hash)
        for hashes in (('c'*64, 'b'*64), ('a'*64, 'c'*64)):
            current, current_hash = read(copy.deepcopy(before), *hashes)
            self.assertEqual(current, before)
            with self.subTest(hashes=hashes), self.assertRaisesRegex(ValueError, 'unchanged current VM owner at signal'):
                vm.unchanged_owner_at_signal(before, before_hash, current, current_hash)

    def test_unchanged_vm_owner_still_requires_closed_validated_v2(self):
        for mutate in (lambda v: v['checkpoint'].update(unknown=None),
                       lambda v: v['checkpoint'].update(pendingCold={})):
            value = owner(); mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                vm.unchanged_owner_at_signal(value, 'a'*64, copy.deepcopy(value), 'a'*64)

    def test_api_c_plus_one_same_e_and_storage_fresh_e_are_distinct(self):
        before = owner(); arm = dict(scope=api.owner_context(before)[1]); saved = copy.deepcopy(before)
        after = successor(before)
        self.assertEqual(api.api_owner_transition(before, after, arm)['serviceEpoch'], arm['scope']['serviceEpoch'])
        with self.assertRaises(ValueError): vm.storage_owner_transition(before, after, arm)
        cold = successor(before, True)
        self.assertNotEqual(vm.storage_owner_transition(before, cold, arm)['serviceEpoch'], arm['scope']['serviceEpoch'])
        with self.assertRaises(ValueError): api.api_owner_transition(before, cold, arm)
        self.assertEqual(before, saved)

    def test_rejects_mismatched_exact_root_results_and_physical_manifest(self):
        before = owner(); arm = dict(scope=api.owner_context(before)[1])
        mutations = [lambda b:b['checkpoint'].update(pendingCold={}),
            lambda b:b['checkpoint'].update(unknown=None),
            lambda b:b['checkpoint']['serviceLinks'].append({'transitions':[{'confirmed':'minted'}]}),
            lambda b:b['checkpoint']['references'].append({'boot':{'ready':'minted'}}),
            lambda b:b['checkpoint']['contexts'][0].update(controller={'transitions':[],'boot':{}}),
            lambda b:b['manifest'].update(unknown=None),
            lambda b:b['checkpoint']['contexts'].append(copy.deepcopy(b['checkpoint']['contexts'][-1])),
            lambda b:b['checkpoint']['current']['original'].pop('serviceEpoch'),
            lambda b:b['checkpoint'].pop('contexts'),
            lambda b:b['checkpoint']['current']['directResult'].update(service_epoch=uid()),
            lambda b:b['checkpoint']['current']['directResult'].update(revision=10),
            lambda b:b['checkpoint']['current']['original']['recipient'].update(publicKey=encoded(b'x'*32)),
            lambda b:b['checkpoint']['observedWorker'].update(workerUUID=uid()),
            lambda b:b['manifest']['backing'].update(inode=41),
            lambda b:b['checkpoint']['currentService']['boot'].update(tls_root_sha256='f'*64),
            lambda b:b['checkpoint'].update(latestServiceChange={}),
            lambda b:b['checkpoint']['current']['directResult'].update(nonce=encoded(b'n'*31)),
            lambda b:b['checkpoint']['currentContext'].update(controllerEpoch=True)]
        for i, mutate in enumerate(mutations):
            after = successor(before); mutate(after)
            with self.subTest(mutation=i), self.assertRaises((ValueError, KeyError)):
                api.api_owner_transition(before, after, arm)

    def test_cold_requires_exact_predecessor_and_confirmed_successor(self):
        before = owner(); arm = dict(scope=api.owner_context(before)[1])
        for path, value in [(('predecessorService','open_revision'), 9),
                            (('predecessor','context','controllerEpoch'), 2),
                            (('completion','receipt','revision'), 21),
                            (('request','completionRequestID'), uid()),
                            (('request','prepare','candidate','pid'), 999),
                            (('request','prepare','identity','generation'), 2),
                            (('request','prepare','mountedGreeting','bootBinding','shimLaunchUUID'), uid()),
                            (('request','prepare','mountedGreeting','heldBackingIdentity','inode'), 999),
                            (('completion','successorOrigin','specSHA256'), 'f'*64)]:
            after = successor(before, True)
            # Break fixture aliases before mutating one side of a correlation.
            import json
            after = json.loads(json.dumps(after))
            node = after['checkpoint']['latestCold']
            for key in path[:-1]: node = node[key]
            node[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError): vm.storage_owner_transition(before, after, arm)

    def test_cold_greeting_requires_v2_without_version_fallback(self):
        before = owner(); after = successor(before, True)
        arm = dict(scope=e.owner_context(before)[1])
        greeting = after['checkpoint']['latestCold']['request']['prepare']['mountedGreeting']
        self.assertEqual(greeting['version'], 'storage-lifecycle-cold-shim.v2')
        vm.storage_owner_transition(before, after, arm)
        for version in ('storage-lifecycle-cold-shim.v1', 'storage-lifecycle-cold-shim.v999', 'unknown'):
            changed = copy.deepcopy(after)
            changed['checkpoint']['latestCold']['request']['prepare']['mountedGreeting']['version'] = version
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'exact mounted physical/native greeting'):
                vm.storage_owner_transition(before, changed, arm)

    def test_cold_v2_held_backing_remains_closed_and_stably_bound(self):
        before = owner(); after = successor(before, True)
        arm = dict(scope=e.owner_context(before)[1])
        greeting = after['checkpoint']['latestCold']['request']['prepare']['mountedGreeting']
        greeting['heldBackingIdentity']['device'] += 101
        vm.storage_owner_transition(before, after, arm)
        mutations = [dict(inode=999), dict(volume_uuid=uid()), dict(device=True),
            dict(device=-1), dict(extra=1)]
        for fields in mutations:
            changed = copy.deepcopy(after)
            changed['checkpoint']['latestCold']['request']['prepare']['mountedGreeting']['heldBackingIdentity'].update(fields)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                vm.storage_owner_transition(before, changed, arm)
        for field in ('device', 'inode', 'volume_uuid'):
            changed = copy.deepcopy(after)
            del changed['checkpoint']['latestCold']['request']['prepare']['mountedGreeting']['heldBackingIdentity'][field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                vm.storage_owner_transition(before, changed, arm)
        for fields in (dict(purpose='resumeReadOnly'), dict(extra=1)):
            changed = copy.deepcopy(after)
            changed['checkpoint']['latestCold']['request']['prepare']['mountedGreeting'].update(fields)
            with self.subTest(greeting=fields), self.assertRaises(ValueError):
                vm.storage_owner_transition(before, changed, arm)

    def test_cold_candidate_requires_exact_canonical_ed25519_spki_not_raw_key(self):
        before = owner(); arm = dict(scope=api.owner_context(before)[1])
        after = successor(before, True)
        key = base64.b64decode(after['checkpoint']['current']['original']['recipient']['publicKey'])
        spki = bytes.fromhex('302a300506032b6570032100') + key
        self.assertEqual(after['checkpoint']['latestCold']['request']['prepare']['candidate']['spki'], encoded(spki))
        vm.storage_owner_transition(before, after, arm)
        for invalid in (encoded(key), encoded(spki[:-1]), encoded(spki+b'\x00'),
                        encoded(bytes.fromhex('302a300506032b6571032100')+key),
                        encoded(spki[:-32]+b'x'*32), encoded(spki)+'\n'):
            changed = copy.deepcopy(after)
            changed['checkpoint']['latestCold']['request']['prepare']['candidate']['spki'] = invalid
            with self.subTest(spki=invalid), self.assertRaisesRegex(ValueError, 'exact cold native candidate'):
                vm.storage_owner_transition(before, changed, arm)

    def native_values(self):
        record = owner(); projected, _ = api.owner_context(record)
        daemon = SimpleNamespace(root=Path('/owned/root'), binary=Path('/owned/cengine'), storage_initramfs=Path('/owned/initramfs'), kernel=Path('/owned/kernel'))
        launch_id = uid(); path = daemon.root/'infrastructure/storage-shim-generations'/launch_id/'spec.json'
        digest = 'a'*64
        proc = RuntimeProcess(55, executable=str(daemon.binary), identity=(100,2,300), pidversion=8,
            arguments=(str(daemon.binary),'vm-shim','--spec',str(path),'--spec-sha256',digest,'--storage-disk-fd','3','--storage-lifecycle-fd','4'))
        spec = dict(kernelPath=str(daemon.kernel), diskBootstrapVersion=1, kind='storage',containerID='cengine-storage',shimLaunchUUID=launch_id,
            rootDiskPath=str(daemon.root/'infrastructure/volumes.ext4'),rootDiskIdentity=dict(projected['backing']),rootDiskSize=4096,
            rootDiskReadOnly=False,volumeDisks=[],bindShares=[],initialRamdiskPath=str(daemon.storage_initramfs),expectedInitramfsSHA256='b'*64)
        launch = dict(intent=dict(schemaVersion=1,protocolVersion=7,specificationSHA256=digest,launchUUID=launch_id,
            storeIdentity={**projected['root'],'inode':50},generationIdentity={**projected['root'],'inode':51}),
            process=dict(pid=55,startSeconds=100,startMicroseconds=2,uniqueID=300,bootUUID=uid()))
        disk = SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_dev=3,st_ino=40,st_size=4096)
        return dict(daemon=daemon, owner=projected, proc=proc, spec=spec, digest=digest, launch=launch, disk=disk, boot=launch['process']['bootUUID'])

    def select_native(self, v):
        with patch.object(api, 'read_public', side_effect=[(v['spec'],v['digest']),(v['launch'],'c'*64),(v['launch']['intent'],'d'*64)]), \
                patch.object(e, 'asset_digest', return_value='b'*64), patch.object(e,'host_boot_uuid',return_value=v['boot']), \
                patch.object(Path,'lstat',autospec=True,side_effect=lambda path: v['disk'] if path.name == 'volumes.ext4' else
                    SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_dev=3,st_ino=50 if path.name == 'infrastructure' else 51)):
            return api.storage_target(v['daemon'],v['owner'],[v['proc']])

    def test_native_selection_ignores_persistent_manifest_device_diagnostic(self):
        value = self.native_values()
        value['owner']['backing']['device'] += 100
        self.assertEqual(self.select_native(value), value['proc'])

    def test_native_lifecycle_launch_not_rewritten_to_managed(self):
        v = self.native_values(); self.assertEqual(self.select_native(v),v['proc'])
        mutations = [lambda v:v['spec'].update(storageStartupMode='managed'),
            lambda v:v['spec'].update(storageStartupMode='lifecycle'),
            lambda v:v['spec'].update(storageStartupMode=None),
            lambda v:v['launch']['intent'].update(protocolVersion=6),
            lambda v:v['launch']['intent'].update(protocolVersion=True),
            lambda v:v['launch']['intent'].update(schemaVersion=2),
            lambda v:v['launch']['intent']['storeIdentity'].update(inode=999),
            lambda v:v['launch']['intent']['generationIdentity'].update(inode=999),
            lambda v:v['launch']['intent'].update(unexpected=None),
            lambda v:v['owner'].update(specSHA256='f'*64),
            lambda v:v['spec'].update(kernelPath='/other/kernel'),
            lambda v:v['spec'].update(diskBootstrapVersion=True),
            lambda v:v['spec'].update(expectedInitramfsSHA256='f'*64),
            lambda v:v['launch']['process'].update(uniqueID=301),
            lambda v:v['launch']['process'].update(bootUUID=uid()),
            lambda v:v['launch']['process'].update(startMicroseconds=True),
            lambda v:v.update(proc=replace(v['proc'],arguments=v['proc'].arguments[:-1]+('5',))),
            lambda v:v.update(proc=replace(v['proc'],arguments=v['proc'].arguments[:-2])),
            lambda v:v.update(proc=replace(v['proc'],identity=None)),
            lambda v:v['spec'].update(shimLaunchUUID=uid()),
            lambda v:setattr(v['disk'],'st_mode',stat.S_IFLNK|0o777)]
        for i, mutate in enumerate(mutations):
            v = self.native_values(); mutate(v)
            with self.subTest(mutation=i), self.assertRaises(ValueError): self.select_native(v)

    def test_native_selection_requires_exact_census_and_all_backing_correlations(self):
        for mutate in (lambda v:v['spec'].update(kind='container'),
                       lambda v:v['spec'].update(containerID='foreign'),
                       lambda v:v['spec'].update(rootDiskPath='/foreign/disk'),
                       lambda v:v['spec'].update(rootDiskIdentity={**v['owner']['backing'], 'inode':999}),
                       lambda v:v['spec'].update(rootDiskSize=8192),
                       lambda v:v['spec'].update(rootDiskReadOnly=True),
                       lambda v:v['spec'].update(volumeDisks=[{}]),
                       lambda v:v['spec'].update(bindShares=[{}]),
                       lambda v:v['launch']['intent'].update(specificationSHA256='f'*64),
                       lambda v:v['launch']['intent'].update(launchUUID=uid()),
                       lambda v:v['launch']['process'].update(pid=56),
                       lambda v:v.update(proc=replace(v['proc'], executable='/foreign/cengine')),
                       lambda v:setattr(v['disk'], 'st_dev', 4),
                       lambda v:setattr(v['disk'], 'st_ino', 41),
                       lambda v:setattr(v['disk'], 'st_size', 8192)):
            v = self.native_values(); mutate(v)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError): self.select_native(v)
        v = self.native_values()
        for census in ([], [v['proc'], v['proc']]):
            with patch.object(e, 'host_boot_uuid', return_value=v['boot']), self.assertRaises(ValueError):
                api.storage_target(v['daemon'], v['owner'], census)

    def test_api_target_pins_selected_lifecycle_cli_mode(self):
        daemon = SimpleNamespace(binary=Path('/owned/cengine'), root=Path('/owned/root'), socket=Path('/owned/socket'),
            kernel=Path('/owned/kernel'), container_initramfs=Path('/owned/container'), storage_initramfs=Path('/owned/storage'), process=Mock(pid=42))
        daemon.process.poll.return_value = None
        args = ('/owned/cengine', 'daemon', '--root', '/owned/root', '--socket', '/owned/socket', '--kernel', '/owned/kernel',
            '--container-initramfs', '/owned/container', '--storage-initramfs', '/owned/storage', '--automatic-ipv4-pool', '10.0.0.0/8',
            '--automatic-ipv6-prefix', 'fdcc::/16')
        proc = RuntimeProcess(42, executable='/owned/cengine', arguments=args, identity=(10,2,300), pidversion=8)
        self.assertEqual(api.api_target(daemon, proc), proc)
        for mode in ('managed', 'legacy', 'lifecycle', ''):
            with self.assertRaises(ValueError):
                api.api_target(daemon, replace(proc, arguments=args+('--shared-storage', mode)))

    def test_drain_threshold_is_root_confirmed_revision_not_open_revision(self):
        # Existing receipt regression suite exercises the same public_boot entry;
        # v2 deliberately exposes the stronger ROOT-confirmed lower bound.
        record = successor(owner(), True)
        self.assertEqual(vm.public_boot(vm.current_boot(record))['revision'], record['checkpoint']['current']['directResult']['revision'])
        self.assertIs(matrix.public_boot, vm.public_boot)


if __name__ == '__main__': unittest.main()
