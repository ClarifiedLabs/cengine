#!/usr/bin/env python3
"""Standard-library RTM103 v2 comparisons; no engine, natives or acceptance."""
import base64
import copy
import json
from contextlib import contextmanager
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import managed_takeover_lifecycle_evidence as e
import managed_takeover_original as original
import managed_takeover_replay as replay

fixtures = runpy.run_path(str(ROOT / 'tools/tests/test-managed-prepare-lifecycle-evidence.py'))


def uid(): return str(uuid.uuid4())
def encoded(value): return base64.b64encode(value).decode()


def successor(before, key):
    after = copy.deepcopy(before)
    a, b = before['checkpoint'], after['checkpoint']
    b['current'] = copy.deepcopy(a['current'])
    context = dict(a['currentContext'], controllerEpoch=a['currentContext']['controllerEpoch'] + 1,
        controllerKey=e.lifecycle.fingerprint(encoded(key * 32)))
    grant = dict(a['current']['original']['signed']['grant'], operation='takeover', id=uid(),
        serial=a['current']['original']['signed']['grant']['serial'] + 1,
        expected_epoch=a['currentContext']['controllerEpoch'], new_key=context['controllerKey'])
    b['revision'] += 10
    b['current']['original'].update(signed=dict(grant=grant, signature=encoded(key * 64)), requestID=uid(),
        serviceEpoch=context['serviceEpoch'], recipient=dict(publicKey=encoded(key * 32), incarnation=uid(),
        daemonUniqueID=100 + context['controllerEpoch'], childUniqueID=200 + context['controllerEpoch'], childPID=300))
    b['current']['directResult'].update(grant=grant, revision=a['current']['directResult']['revision'] + 1)
    b['currentContext'] = context
    b['observedWorker']['context'] = context
    b['currentService'].update(grant=grant, context=dict(service_epoch=context['serviceEpoch'],
        controller_epoch=context['controllerEpoch'], controller_key=context['controllerKey']))
    b['contexts'] = copy.deepcopy(a['contexts']) + [dict(context=context, controller=b['current'])]
    return after


def fixture():
    initial = fixtures['owner']()
    before = successor(initial, b'b')
    checkpoint = before['checkpoint']
    checkpoint['references'] = [dict(id=uid(), version=1, original=copy.deepcopy(checkpoint['currentContext']), superseded=[])]
    after = successor(before, b'c')
    request = uid()
    observation = dict(version=1, requestID=request, old=copy.deepcopy(checkpoint['current']['original']['signed']),
        pending=copy.deepcopy(after['checkpoint']['current']['original']['signed']),
        incarnationID=after['checkpoint']['current']['original']['recipient']['incarnation'], error='UNAUTHORIZED')
    return initial, before, after, request, observation


def publication(owner, snapshot):
    return dict(version=2, lifecycleIdentity=copy.deepcopy(owner['checkpoint']['identity']), registry=snapshot)


def control_fixture():
    initial, before, after, request, denied = fixture()
    proof = e.owner(before)
    capture = dict(version=replay.VERSION, requestID=request, store=proof['store'], epoch=proof['controllerEpoch'],
        serviceEpoch=proof['serviceEpoch'])
    begun = dict(version=2, **{key:copy.deepcopy(denied[key]) for key in ('requestID','old','pending','incarnationID')})
    confirmed = dict(version=2, completion=copy.deepcopy(after['checkpoint']['current']))
    return initial, before, after, capture, begun, denied, confirmed


def query(owner, intent):
    proof = e.owner(owner)
    slot = intent['slots'][0]
    return dict(schema=4, revision=40, store=dict(id=proof['store']), epoch=proof['serviceEpoch'],
        controller=dict(epoch=proof['controllerEpoch'], key=proof['controllerKey']),
        volumes={slot['volume']: dict(id=slot['volume'])}, volume_lifecycles={slot['volume']: dict(phase='READY')},
        attachments={slot['attachment']: dict(phase='ACTIVE', binding=dict(volume=slot['volume'], key=slot['key']))},
        prepares={uid(): dict(context=dict(service_epoch=proof['serviceEpoch'], controller_epoch=proof['controllerEpoch'],
            controller_key=proof['controllerKey']))})


class Tests(unittest.TestCase):
    def test_owner_ledger_projection_preserves_exact_nullable_v2_bytes_and_pins(self):
        _, before, _, _, _ = fixture()
        saved = copy.deepcopy(before)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            directory = root / 'managed-storage-owner'; directory.mkdir(mode=0o700)
            raw_files = {}
            for field, name in (('checkpoint', 'state.json'), ('manifest', 'manifest.json')):
                raw = (json.dumps(before[field], indent=2) + '\n').encode()
                raw_files[field] = raw
                (directory / name).write_bytes(raw)
            actual, stamp = e.read_owner(root)
            projected = e.owner_evidence(root, actual, stamp)
            self.assertEqual(projected['format'], e.VERSION)
            self.assertEqual(projected['ownerSHA256'], stamp)
            for field, raw in raw_files.items():
                self.assertEqual(base64.b64decode(projected[field]['base64'], validate=True), raw)
                self.assertEqual(projected[field]['sha256'], e.p.digest(raw))
            with e.p.Directory(root) as ledger:
                ledger.publish('first-confirmed.json', dict(phase='takeover-first-confirmed', owner=projected))
                self.assertEqual(e.p.decode(ledger.read('first-confirmed.json')[0])['owner'], projected)
            self.assertEqual(before, saved)
            self.assertIsNone(actual['checkpoint']['pendingCold'])
            self.assertIsNone(actual['checkpoint']['latestCold'])
            with self.assertRaisesRegex(ValueError, 'no null or float'): e.p.canonical(actual)
            # Same decoded DTO, different physical bytes must not replace the pin.
            (directory / 'state.json').write_bytes(raw_files['checkpoint'] + b' ')
            with self.assertRaisesRegex(ValueError, 'byte pins'): e.owner_evidence(root, actual, stamp)
            (directory / 'state.json').write_bytes(raw_files['checkpoint'])
            (directory / 'manifest.json').write_bytes(raw_files['manifest'] + b' ')
            with self.assertRaisesRegex(ValueError, 'byte pins'): e.owner_evidence(root, actual, stamp)
            for change in (lambda v:v.update(format='storage-lifecycle.v3'),
                           lambda v:v['checkpoint'].pop('pendingCold'),
                           lambda v:v['checkpoint'].update(extra=None)):
                bad = copy.deepcopy(actual); change(bad)
                with self.assertRaises((ValueError, KeyError)): e.owner_evidence(root, bad, stamp)

    def test_joined_original_route_publishes_every_event_to_real_canonical_ledger(self):
        joined = runpy.run_path(str(ROOT/'tools/tests/test-managed-takeover-original.py'))['Tests']()
        events = []
        try:
            with tempfile.TemporaryDirectory() as temporary, e.p.Directory(Path(temporary).resolve()) as ledger:
                def record(phase, **value):
                    event = dict(phase=phase, **value)
                    name = '%03d-%s.json' % (len(events), phase)
                    ledger.publish(name, event)
                    self.assertEqual(ledger.read(name)[0], e.p.canonical(event))
                    events.append(event)
                joined.joined(lifecycle_fixture=control_fixture(), record=record)
                self.assertEqual([event['phase'] for event in events], ['takeover-first-confirmed',
                    'takeover-original-armed', 'takeover-independent-unchanged', 'takeover-fresh-getattr', 'takeover-control-leg'])
                self.assertFalse(events[-1]['result']['nativeAcceptance'])
                self.assertFalse(events[-1]['result']['fullAcceptance'])
        finally: joined.doCleanups()

    def test_real_dto_two_successors_without_legacy_projection(self):
        initial, before, after, request, observation = fixture()
        replay.same_service_step(initial, before)
        saved = copy.deepcopy((before, after, observation))
        result = e.replay_observation(before, after, request, observation)
        self.assertTrue(result['controlLegVerified'])
        self.assertFalse(result['nativeAcceptance']); self.assertFalse(result['fullAcceptance'])
        self.assertEqual(saved, (before, after, observation))
        self.assertNotIn('transitions', before); self.assertNotIn('boot', before)

    def test_replay_requires_c2_old_before_c3_candidate(self):
        _, _, before, request, _ = fixture()
        after = successor(before,b'd')
        observation = dict(version=1,requestID=request,old=before['checkpoint']['current']['original']['signed'],
            pending=after['checkpoint']['current']['original']['signed'],
            incarnationID=after['checkpoint']['current']['original']['recipient']['incarnation'],error='UNAUTHORIZED')
        with self.assertRaisesRegex(ValueError,'C2 OLD takeover'):
            e.replay_observation(before,after,request,observation)

    def test_private_dto_rejects_malformed_mixed_scope_and_unsigned_pending(self):
        mutations = [lambda v:v.update(version=True), lambda v:v.update(version=1.0),
            lambda v:v.update(extra=1), lambda v:v.pop('old'), lambda v:v.update(error='CURRENT'),
            lambda v:v.update(requestID=uid()), lambda v:v.update(incarnationID=uid()),
            lambda v:v.update(pending=v['pending']['grant']), lambda v:v['old'].update(signature=encoded(b'x'*64)),
            lambda v:v['pending']['grant']['identity'].update(generation=2),
            lambda v:v['old']['grant']['identity'].update(binding='0'*64),
            lambda v:v['old']['grant']['identity'].update(store=uid()),
            lambda v:v['old']['grant'].update(serial=True), lambda v:v['old']['grant'].update(expected_epoch=1.0),
            lambda v:v['pending']['grant'].update(new_key='f'*64)]
        for mutate in mutations:
            _, before, after, request, observation = fixture(); mutate(observation)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, KeyError, TypeError)):
                e.replay_observation(before, after, request, observation)

    def test_no_lost_original_reference_or_retained_proof(self):
        for fault in ('reference', 'context', 'worker', 'boot', 'mixed'):
            _, before, after, request, observation = fixture()
            if fault == 'reference': after['checkpoint']['references'] = []
            elif fault == 'context': after['checkpoint']['contexts'] = after['checkpoint']['contexts'][-1:]
            elif fault == 'worker': after['checkpoint']['observedWorker']['workerUUID'] = uid()
            elif fault == 'boot': after['checkpoint']['currentService']['boot']['server_spki'] = 'f'*64
            else: after = {'transitions': []}
            with self.subTest(fault=fault), self.assertRaises((ValueError, KeyError, TypeError)):
                e.replay_observation(before, after, request, observation)

    def test_recovery_provenance_cannot_disappear(self):
        _, before, after, request, observation = fixture()
        prior = dict(before['checkpoint']['currentContext'], provenanceReference=before['checkpoint']['provenanceReference'])
        before['checkpoint']['references'][0]['recovery'] = prior
        with self.assertRaisesRegex(ValueError, 'retained recovery provenance'):
            e.replay_observation(before,after,request,observation)
        after['checkpoint']['references'][0]['recovery'] = copy.deepcopy(prior)
        e.replay_observation(before,after,request,observation)
        after['checkpoint']['references'][0].update(version=2, recovery=dict(after['checkpoint']['currentContext'],
            provenanceReference=prior['provenanceReference']))
        e.replay_observation(before,after,request,observation)

    def test_query_complete_maps_exact_c_plus_one_full_identity_contexts(self):
        _, before, after, _, _ = fixture()
        intent = dict(before['checkpoint']['currentContext'], store=before['checkpoint']['identity']['store'],
            slots=[dict(role='runtime', volume=uid(), attachment=uid(), key='a'*64)])
        old = query(before, intent); new = copy.deepcopy(old)
        new.update(revision=41, controller=query(after, intent)['controller'])
        identity = copy.deepcopy(before['checkpoint']['identity'])
        def check(a=old, b=new, ident=identity):
            return original.unchanged_registry(dict(version=2,lifecycleIdentity=ident,registry=a),
                dict(version=2,lifecycleIdentity=ident,registry=b), before, after, intent)
        self.assertTrue(check()['registryVerified'])
        for field in original.REGISTRY_FIELDS:
            bad = copy.deepcopy(new)
            if field == 'revision': bad[field] += 1
            elif field == 'schema': bad[field] = 3
            elif field == 'epoch': bad[field] = uid()
            else: bad[field] = {'changed': True}
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError, TypeError)):
                check(b=bad)
        for key, value in [('store', uid()), ('generation', 2), ('binding', 'f'*64), ('generation', True)]:
            with self.subTest(identity=key), self.assertRaises(ValueError): check(ident=dict(identity, **{key:value}))
        with self.assertRaises(ValueError): original.registry(old, before, intent)
        with self.assertRaisesRegex(ValueError, 'older than ROOT'):
            original.registry(publication(before,dict(old,revision=1)),before,intent)
        for field, value in [('store',uid()), ('controllerKey','f'*64), ('controllerEpoch',True)]:
            with self.subTest(intent=field), self.assertRaises(ValueError):
                original.registry(publication(before,old),before,dict(intent,**{field:value}))
        missing = copy.deepcopy(old)
        next(iter(missing['prepares'].values())).pop('context')
        with self.assertRaises(KeyError): original.registry(publication(before,missing), before, intent)
        bad = copy.deepcopy(old)
        next(iter(bad['prepares'].values()))['context']['controller_key'] = 'f'*64
        with self.assertRaises(ValueError): original.registry(publication(before,bad), before, intent)

    def test_isolation_actual_before_probe_after_and_hidden_digest(self):
        _, owner, _, _, _ = fixture(); proof = e.owner(owner)
        binding = dict(requestID=uid(), operationUUID=uid(), armDigest='a'*64, scope=proof)
        state = dict(request={k:binding[k] for k in ('requestID','operationUUID','armDigest')}, workerUUID=proof['workerUUID'],
            caseName='isolation-state', store=proof['store'], serviceEpoch=proof['serviceEpoch'], revision=40,
            registrySHA256='b'*64, result='registry-state')
        state['request']['challenge'] = uid()
        for case, result in [('legacy-connection','legacy-tls-header-rejected'), ('second-service-exclusivity','second-owner-locked')]:
            receipt = dict(before=copy.deepcopy(state), after=copy.deepcopy(state),
                observation=dict(copy.deepcopy(state), caseName=case, result=result))
            original.isolation_attestation(receipt, binding, {'revision':40}, case, owner)
            for phase in receipt:
                for field, value in [('registrySHA256','f'*64), ('revision',41), ('revision',40.0), ('workerUUID',uid()), ('workerUUID','invalid'), ('serviceEpoch',uid())]:
                    bad = copy.deepcopy(receipt); bad[phase][field] = value
                    with self.subTest(phase=phase,field=field), self.assertRaises(ValueError):
                        original.isolation_attestation(bad,binding,{'revision':40},case,owner)
            for phase in receipt:
                bad = copy.deepcopy(receipt); del bad[phase]
                with self.assertRaises(ValueError): original.isolation_attestation(bad,binding,{'revision':40},case,owner)

    def test_frozen_public_control_phases_and_malformed_or_mixed_publication(self):
        args = control_fixture()[1:]
        result = replay.control_result(*args)
        self.assertTrue(result['controlLegVerified']); self.assertFalse(result['nativeAcceptance'])
        self.assertFalse(result['fullAcceptance'])
        changes = [(2,lambda v:v.update(epoch=3)), (2,lambda v:v.update(serviceEpoch=uid())),
            (3,lambda v:v.update(version=True)), (3,lambda v:v.update(version=2.0)),
            (3,lambda v:v.update(extra=1)), (3,lambda v:v.pop('pending')),
            (3,lambda v:v.update(requestID=uid())), (3,lambda v:v.update(incarnationID=uid())),
            (3,lambda v:v['old'].update(signature=encoded(b'x'*64))),
            (3,lambda v:v['pending']['grant']['identity'].update(generation=2)),
            (4,lambda v:v.update(version=2)), (4,lambda v:v.update(error='CURRENT')),
            (5,lambda v:v.update(version=1)), (5,lambda v:v.update(extra=1)),
            (5,lambda v:v['completion']['directResult'].update(revision=1)),
            (5,lambda v:v['completion']['original']['recipient'].update(childPID=999))]
        for index, change in changes:
            bad = copy.deepcopy(args); change(bad[index])
            with self.subTest(index=index,change=change), self.assertRaises((ValueError,KeyError,TypeError)):
                replay.control_result(*bad)
        legacy = runpy.run_path(str(ROOT/'tools/tests/test-managed-takeover-replay.py'))['fixture']()[1:]
        for index in (0,1,3,4,5):
            bad = list(copy.deepcopy(args)); bad[index] = legacy[index]
            with self.subTest(mixed=index), self.assertRaises((ValueError,KeyError,TypeError)):
                replay.control_result(*bad)

    def test_registry_wrapper_closed_versioned_and_no_identity_inside_snapshot(self):
        _, owner, _, _, _ = fixture()
        intent = dict(owner['checkpoint']['currentContext'],store=owner['checkpoint']['identity']['store'],
            slots=[dict(role='runtime',volume=uid(),attachment=uid(),key='a'*64)])
        value = publication(owner,query(owner,intent))
        self.assertEqual(original.registry(value,owner,intent),value['registry'])
        changes = [lambda v:v.update(version=True), lambda v:v.update(version=2.0), lambda v:v.update(version=1),
            lambda v:v.update(extra=1),lambda v:v.pop('lifecycleIdentity'),
            lambda v:v['registry'].update(lifecycleIdentity=v['lifecycleIdentity']),
            lambda v:v['registry'].update(schema=3)]
        for change in changes:
            bad = copy.deepcopy(value); change(bad)
            with self.subTest(change=change), self.assertRaises((ValueError,KeyError,TypeError)):
                original.registry(bad,owner,intent)

    def test_joined_v2_live_route_and_failure_containment_without_native_execution(self):
        joined = runpy.run_path(str(ROOT/'tools/tests/test-managed-takeover-original.py'))['Tests']()
        self.addCleanup(joined.doCleanups)
        joined.joined(lifecycle_fixture=control_fixture())
        for fault in ('registry','cached','backing','fresh-release','budget','hidden','replay-binding','identity','pin'):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                joined.joined(fault,lifecycle_fixture=control_fixture())
            self.assertIn('stop-original',joined.events)
            self.assertNotIn('takeover-control-leg',joined.events)
            if fault == 'budget': self.assertEqual(joined.events.count('restart'),1)

    def isolation_joined(self, case, fault=None):
        import managed_prepare_worker_faults as worker
        helpers = runpy.run_path(str(ROOT/'tools/tests/test-managed-takeover-original.py'))
        _, owner, _, _, _ = fixture()
        proof = e.owner(owner)
        volume, instance, reader_instance = uid(), uid(), uid()
        files, intents, pending, events = {}, {}, {}, []
        self.isolation_events = events

        class Item:
            def __init__(self, identifier):
                self.id = identifier
                self.attrs = dict(State=dict(Status='created',Running=False))
            def reload(self): pass
            def start(self):
                events.append('start-' + self.id[0])
                request = pending.pop('request', None)
                candidate, armed, registry, intent = helpers['observation'](owner,self.id,
                    instance if self.id == 'a'*64 else reader_instance,volume,2,request)
                intents[self.id] = intent
                if request is None: return
                values = dict(candidate=candidate,armed=armed,registry=registry,released=dict(arm=armed['arm'],stage='released'))
                if request.get('isolationCase'):
                    state = dict(request={key:candidate['binding'][key] for key in ('requestID','operationUUID','armDigest')},
                        workerUUID=proof['workerUUID'],caseName='isolation-state',store=proof['store'],
                        serviceEpoch=proof['serviceEpoch'],revision=registry['registry']['revision'],
                        registrySHA256='b'*64,result='registry-state')
                    state['request']['challenge'] = uid()
                    result = 'legacy-tls-header-rejected' if case == 'legacy-connection' else 'second-owner-locked'
                    values['isolation'] = dict(before=copy.deepcopy(state),after=copy.deepcopy(state),
                        observation=dict(copy.deepcopy(state),caseName=case,result=result))
                    values['positive'] = helpers['recovered'](candidate['binding'],armed)
                    if fault == 'hidden': values['isolation']['after']['registrySHA256'] = 'f'*64
                    if fault == 'cached': values['positive']['positive'] = values['positive']['begun']
                    if fault == 'original-release': values['released']['stage'] = 'begun'
                    if fault == 'identity': values['registry']['lifecycleIdentity']['binding'] = 'f'*64
                elif fault == 'fresh-release': values['released']['stage'] = 'begun'
                for phase, value in values.items():
                    files[request['requestID']+'.public-takeover-arm.'+phase+'.json'] = value
            def stop(self, **kwargs): events.append('stop-' + self.id[0])
        container, reader = Item('a'*64), Item('b'*64)

        class Queue:
            def __init__(self,*args): pass
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def validate(self): pass
            def publish(self,name,value):
                pending['request'] = value
                events.append('arm-capture' if value.get('isolationCase') else 'fresh-capture')
            def read(self,name,*args,**kwargs):
                stamp = 'changed' if fault == 'pin' and not kwargs.get('pin_file') else 'pin'
                return e.p.canonical(files[name]),(stamp,name)
        @contextmanager
        def prepared(daemon,item,*args):
            yield None,dict(containerInstance=instance if item is container else reader_instance),lambda:None
        def live(fixture,item,plan):
            return intents[item.id],2,lambda:events.append('validate-'+item.id[0])
        def snapshot(fixture,item):
            events.append('snapshot-'+item.id[0])
            value = helpers['snap']()
            if fault == 'backing' and 'start-a' in events: value['files']['a']['sha256'] = 'f'*64
            return value
        daemon = SimpleNamespace(root=Path('/unused'))
        with patch.object(e,'read_owner',return_value=(owner,'stamp')),patch.object(original.p,'Directory',Queue),\
             patch.object(original.p,'owned'),patch.object(original.OriginalFixture,'state',return_value=({'root':{}},{})),\
             patch.object(original.OriginalFixture,'processes',return_value=[]),patch.object(worker,'prepared_peer_owner',prepared),\
             patch.object(original.OriginalFixture,'live',live),patch.object(original.OriginalFixture,'snapshot',snapshot):
            result = original.run_service_isolation(daemon,case=case,container=container,reader=reader,
                plan={'volume':volume},reader_plan={'volume':volume},remaining=lambda:500,
                record=lambda phase,**kwargs:events.append(phase))
        self.assertFalse(result['nativeAcceptance']); self.assertFalse(result['fullAcceptance'])
        for field in ('originalOperationVerified','registryVerified','backingVerified','freshGetattrVerified'):
            self.assertTrue(result[field])
        self.assertLess(events.index('snapshot-b'),events.index('start-a'))
        self.assertLess(events.index('service-isolation-unchanged'),events.index('fresh-capture'))
        self.assertEqual(events.count('start-a'),1); self.assertEqual(events.count('start-b'),2)
        self.assertIn('stop-a',events)

    def test_joined_v2_isolation_actual_phases_fresh_data_and_containment(self):
        for case in ('legacy-connection','second-service-exclusivity'):
            with self.subTest(case=case): self.isolation_joined(case)
            for fault in ('hidden','cached','identity','original-release','fresh-release','backing','pin'):
                with self.subTest(case=case,fault=fault), self.assertRaises(ValueError):
                    self.isolation_joined(case,fault)
                self.assertIn('stop-a',self.isolation_events)
                self.assertNotIn('service-isolation-fresh-getattr',self.isolation_events)


if __name__ == '__main__': unittest.main()
