#!/usr/bin/env python3
"""Host-only joined Python orchestration. Fake wire/native fixtures are not authority."""
import copy
import json
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path
import runpy
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import harness
import managed_takeover_original as o
import managed_takeover_replay as t
import managed_prepare_worker_faults as worker
base = runpy.run_path(str(ROOT / 'tools/tests/test-managed-takeover-replay.py'))
snap = runpy.run_path(str(ROOT / 'tools/tests/test-managed-prepare-faults.py'))['snapshot']
def uid(): return str(uuid.uuid4())

def observation(owner, container, instance, volume, generation, request=None):
    proof = t.lifecycle.owner(owner)
    key = proof['controllerKey'] if t.lifecycle.is_v2(owner) else t.transition(owner['transitions'][-1])[0]['grant']['new_key']
    intent = dict(id=uid(), store=proof['store'], serviceEpoch=proof['serviceEpoch'], controllerEpoch=proof['controllerEpoch'],
        controllerKey=key, container=container, containerInstance=instance, launch=uid(), prepare=uid(), specificationDigest='c'*64,
        phase='running', prepareCompleted=True, slots=[dict(role='runtime', volume=volume, attachment=uid(), key=t.p.digest(uid().encode()),mode='read-write')])
    request = request or dict(version=o.ARM_VERSION, requestID=uid(), operationUUID=uid(), store=proof['store'],
        epoch=proof['controllerEpoch'], serviceEpoch=proof['serviceEpoch'],container=container,containerInstance=instance)
    binding = dict(version=4,profile=t.p.FULL_PROFILE,requestID=request['requestID'],operationUUID=request['operationUUID'],
        caseName='same-e-existing-data',armDigest='0'*64,generation=generation,boot=dict(shimLaunchUUID=intent['launch'],guestBootNonce=uid()),
        scope={k:intent['id' if k=='intent' else k] for k in t.p.SCOPE},targetAttachment=intent['slots'][0]['attachment'],
        key=intent['slots'][0]['key'],certificateSHA256=t.p.digest(uid().encode()))
    candidate = dict(request=request,binding=binding)
    binding['armDigest']=t.p.digest(t.p.canonical(candidate))
    arm={k:binding[k] for k in ('version','profile','requestID','operationUUID','caseName','scope','targetAttachment')}
    arm.update(binding=binding['boot'],leafSHA256=binding['certificateSHA256'])
    armed=dict(arm=arm,stage='armed-mounted-positive',scope=binding['scope'],keySHA256=binding['key'],mountIdentitySHA256='a'*64,
        serverDERSHA256='',signCount=0,signInputSHA256='',bytesWrittenAfterSign=0,clientWrittenBytes=0,clientPrefixBytes=0,
        clientPrefixSHA256='',localError='',fdOperation='fsync-directory',fdSequence=1,rootRequest=dict(node=99,requestSequence=7),
        originalOperation=dict(kind='data-getattr-root',sequence=1,errorClass='ok'))
    registry=dict(schema=3,revision=40,store=dict(id=proof['store']),epoch=proof['serviceEpoch'],controller=dict(epoch=proof['controllerEpoch'],key=key),
        volumes={volume:dict(id=volume)},volume_lifecycles={volume:dict(phase='READY')},prepares={},
        attachments={binding['targetAttachment']:dict(phase='ACTIVE',binding=dict(key=binding['key'],volume=volume))})
    if t.lifecycle.is_v2(owner):
        registry['schema'] = 4
        registry = dict(version=2,lifecycleIdentity=copy.deepcopy(owner['checkpoint']['identity']),registry=registry)
    return candidate,armed,registry,intent

def recovered(binding,armed):
    begun=copy.deepcopy(armed);begun['stage']='begun'
    positive=copy.deepcopy(begun);positive['stage']='original-data-positive';positive['rootRequest']['requestSequence']+=1;positive['originalOperation']['sequence']=2
    return dict(binding=binding,resumed=armed,begun=begun,positive=positive,released=dict(arm=armed['arm'],stage='released'))

class Tests(unittest.TestCase):
    def test_candidate_and_registry_reject_mutations(self):
        _,before,after,*_=base['fixture']()
        c,a,r,i=observation(before,'a'*64,uid(),uid(),2)
        o.candidate(c,c['request'],i,2);o.positive_arm(c['binding'],a)
        new=copy.deepcopy(r);new['revision']+=1;new['controller']=dict(epoch=3,key=t.transition(after['transitions'][-1])[0]['grant']['new_key'])
        self.assertTrue(o.unchanged_registry(r,new,before,after,i)['registryVerified'])
        for field in o.REGISTRY_FIELDS:
            bad=copy.deepcopy(new)
            if field=='revision':bad[field]+=1
            elif field=='schema':bad[field]=1
            elif field=='epoch':bad[field]=uid()
            else:bad[field]={'changed':True}
            with self.subTest(field=field),self.assertRaises((ValueError,KeyError,TypeError)):
                o.unchanged_registry(r,bad,before,after,i)
        for field in ('armDigest','key','generation','certificateSHA256'):
            bad=copy.deepcopy(c);bad['binding'][field]=3 if field=='generation' else 'b'*64
            with self.subTest(field=field),self.assertRaises(ValueError):o.candidate(bad,c['request'],i,2)

    def joined(self, fault=None, *, lifecycle_fixture=None, record=None):
        initial,before,after,capture,begun,denied,confirmed=lifecycle_fixture or base['fixture']()
        events=[];self.events=events;files={};owner=[initial]
        v2 = t.lifecycle.is_v2(initial)
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        owner_directory = root / 'managed-storage-owner'; owner_directory.mkdir(mode=0o700)
        real_directory = t.p.Directory
        def write_owner():
            state = owner[0]['checkpoint'] if v2 else owner[0]
            (owner_directory / 'state.json').write_text(json.dumps(state, indent=2) + '\n')
            if v2: (owner_directory / 'manifest.json').write_text(json.dumps(owner[0]['manifest'], indent=2) + '\n')
        write_owner()
        def record_event(phase, **value):
            if record is not None: record(phase, **value)
            events.append(phase)
        volume=uid();instance=uid();reader_instance=uid();intents={};fixtures={}
        class Item:
            def __init__(self,ident):self.id=ident;self.attrs={'State':{'Status':'created','Running':False}}
            def reload(self):pass
            def start(self):
                events.append('start-original' if self.id=='a'*64 else 'start-reader')
                if 'pending' in fixtures:
                    request=fixtures.pop('pending')
                    c,a,r,i=observation(owner[0],self.id,instance if self.id=='a'*64 else reader_instance,volume,2 if owner[0] is before else 3,request)
                    intents[self.id]=i
                    for phase,v in dict(candidate=c,armed=a,registry=r).items():files[request['requestID']+'.public-takeover-arm.'+phase+'.json']=v
                    if request.get('positiveOnly'):files[request['requestID']+'.public-takeover-arm.released.json']=dict(arm=a['arm'],stage='begun' if fault=='fresh-release' else 'released')
                    if self.id=='a'*64:fixtures.update(binding=c['binding'],armed=a,registry=r)
                else:intents[self.id]=observation(owner[0],self.id,reader_instance,volume,2)[3]
            def stop(self,**kw):events.append('stop-original' if self.id=='a'*64 else 'stop-reader')
        original,reader=Item('a'*64),Item('b'*64)
        class Queue:
            def __init__(self,*a):pass
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def validate(self):pass
            def publish(self,name,v):
                if name=='public-takeover-arm.capture.json':fixtures['pending']=v;events.append('fresh-capture' if v.get('positiveOnly') else 'arm-capture')
                else:fixtures['capture']=v;events.append('replay-capture')
            def read(self,name,*a,**kw):
                stamp = 'changed' if fault == 'pin' and not kw.get('pin_file') else 'pin'
                return t.p.canonical(files[name]),(stamp,name)
        killed = []
        def process(pid):
            value = SimpleNamespace(pid=pid, returncode=None)
            value.poll = lambda: value.returncode
            return value
        def restart(**kw):
            self.assertEqual(kw, {'kill': True})
            events.append('restart')
            daemon.process.returncode = ({'death-live': None, 'death-zero': 0, 'death-term': -signal.SIGTERM}.get(fault, -signal.SIGKILL)
                if owner[0] is before else -signal.SIGKILL)
            killed.append(daemon.process)
            daemon.process = process(daemon.process.pid + 1)
            if owner[0] is initial:owner[0]=before;write_owner();return
            owner[0]=after;write_owner();req=fixtures['capture']
            denied['requestID' if v2 else 'request_id']=req['requestID']
            if v2: begun['requestID']=req['requestID']
            new=copy.deepcopy(fixtures['registry'])
            snapshot = new['registry'] if v2 else new
            snapshot['revision']+=2 if fault=='registry' else 1
            key = t.lifecycle.owner(after)['controllerKey'] if v2 else t.transition(after['transitions'][-1])[0]['grant']['new_key']
            snapshot['controller']=dict(epoch=3,key=key)
            if fault == 'identity': new['lifecycleIdentity']['generation'] += 1
            recovered_value=recovered(fixtures['binding'],fixtures['armed'])
            if fault=='cached':recovered_value['positive']=recovered_value['begun']
            state=dict(request=dict(requestID=req['requestID'],operationUUID=fixtures['binding']['operationUUID'],armDigest=fixtures['binding']['armDigest'],challenge=uid()),workerUUID=t.lifecycle.owner(before)['workerUUID'] if v2 else uid(),caseName='isolation-state',store=req['store'],serviceEpoch=req['serviceEpoch'],revision=(fixtures['registry']['registry'] if v2 else fixtures['registry'])['revision'],registrySHA256='a'*64,result='registry-state')
            attestation=dict(before=state,after=copy.deepcopy(state))
            if fault=='hidden':attestation['after']['registrySHA256']='b'*64
            if fault=='replay-binding':
                for item in attestation.values():item['request']['requestID']=uid()
            for phase,value in dict(begun=begun,denied=denied,attestation=attestation,confirmed=confirmed,resumed=fixtures['armed'],
                positive=recovered_value,registry=new).items():files[req['requestID']+'.public-takeover.'+phase+'.json']=value
        daemon=SimpleNamespace(root=root,process=process(100),restart=restart)
        @contextmanager
        def prepared(d,item,*args):yield None,dict(containerInstance=instance if item is original else reader_instance),lambda:None
        def live(self,item,plan):return intents[item.id],2 if owner[0] is before else 3,lambda:events.append('validate-original' if item is original else 'validate-reader')
        def snapshot(self,item):
            events.append('snapshot-original' if item is original else 'snapshot-reader')
            value=snap()
            if fault=='backing' and owner[0] is after:value['files']['a']['sha256']='f'*64
            return value
        api_restarted = o.OriginalFixture.api_restarted
        def refreshed(fixture, api):
            self.assertIs(api, killed[-1])
            self.assertIsNot(api, daemon.process)
            api_restarted(fixture, api)
            events.append('native-refresh')
        def directory(path, **kwargs):
            return real_directory(path, **kwargs) if Path(path) == owner_directory else Queue(path)
        with patch.object(t.p,'Directory',side_effect=directory),\
             patch.object(o.p,'owned'),patch.object(o.OriginalFixture,'state',return_value=({'root':{}},{})),\
             patch.object(o.OriginalFixture,'processes',return_value=[]),patch.object(worker,'prepared_peer_owner',prepared),\
             patch.object(o.OriginalFixture,'live',live),patch.object(o.OriginalFixture,'snapshot',snapshot),\
             patch.object(o.OriginalFixture,'api_restarted',refreshed):
            result=o.run_original_restarts(daemon,container=original,reader=reader,plan={'volume':'v'},reader_plan={'volume':'v'},
                remaining=lambda:194 if fault=='budget' and 'takeover-original-armed' in events else 500,record=record_event)
        self.assertEqual(events.count('restart'),2)
        for a,b in [('takeover-first-confirmed','arm-capture'),('arm-capture','takeover-original-armed'),
                    ('takeover-original-armed','replay-capture'),('replay-capture','native-refresh'),
                    ('native-refresh','takeover-independent-unchanged'),('takeover-independent-unchanged','fresh-capture'),('fresh-capture','takeover-fresh-getattr')]:
            self.assertLess(events.index(a),events.index(b))
        self.assertEqual(events.count('start-original'),1);self.assertEqual(events.count('start-reader'),2)
        for field in ('controlLegVerified','originalOperationVerified','registryVerified','backingVerified','freshGetattrVerified'):self.assertTrue(result[field])
        self.assertFalse(result['fullAcceptance']);self.assertFalse(result['nativeAcceptance'])
        self.assertIn('stop-original',events)

    def test_actual_adapter_joins_two_restarts_backing_and_fresh_arm(self):
        self.joined()

    def test_joined_failures_contain_without_acceptance(self):
        for fault in ('registry','cached','backing','fresh-release','budget','hidden','replay-binding'):
            with self.subTest(fault=fault),self.assertRaises(ValueError):self.joined(fault)
            self.assertIn('stop-original',self.events)
            self.assertNotIn('takeover-control-leg',self.events)
            if fault=='budget':self.assertEqual(self.events.count('restart'),1)

    def test_final_restart_requires_owned_sigkill_death_proof(self):
        for fault in ('death-live', 'death-zero', 'death-term'):
            with self.subTest(fault=fault):
                with self.assertRaisesRegex(ValueError, 'joined owned API SIGKILL'):
                    self.joined(fault)
                self.assertNotIn('native-refresh', self.events)
                self.assertNotIn('takeover-control-leg', self.events)
                self.assertIn('stop-original', self.events)

    def test_live_diagnostic_entry_routes_without_opening_selector(self):
        import ast
        source=ast.parse((ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
        entry=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='run_takeover_original_followup')
        namespace={'proof':t.p}
        exec(compile(ast.Module(body=[entry],type_ignores=[]),str(ROOT/'Tests/Compatibility/test_managed_prepare_faults.py'),'exec'),namespace)
        args=dict(cases=o.stale.CASES,container=object(),reader=object(),plan={},reader_plan={},remaining=lambda:500,record=lambda *a,**k:None)
        with patch.object(o,'run_original_restarts',return_value={'fullAcceptance':False}) as run:
            result=namespace[entry.name](object(),profile=t.p.FULL_PROFILE,**args)
            self.assertFalse(result['fullAcceptance']);self.assertEqual(run.call_count,1)
            with self.assertRaises(ValueError):namespace[entry.name](object(),profile='normal',**args)
            self.assertEqual(run.call_count,1)

    def test_source_route_is_distinct_from_replacement_shard_and_native(self):
        self.assertEqual(set(o.SOURCE_ENABLED_CASES), set(o.stale.CASES))
        self.assertEqual(len(o.SOURCE_ENABLED_CASES), 18)
        for case in o.FOLLOWUP_CASES:
            selected=o.followup_selection(t.p.FULL_PROFILE,o.stale.CASES,case)
            self.assertFalse(selected["nativeAcceptance"]);self.assertFalse(selected["fullAcceptance"])
            with self.assertRaises(ValueError):o.followup_selection(t.p.FULL_PROFILE,o.stale.CASES[:-1],case)
            with self.assertRaises(ValueError):o.stale.selection(t.p.FULL_PROFILE,o.stale.CASES,case)

class NativeOwnerTests(unittest.TestCase):
    def setUp(self):
        self.api = SimpleNamespace(pid=100, poll=lambda: -signal.SIGKILL)
        self.fixture = o.OriginalFixture.__new__(o.OriginalFixture)
        self.fixture.daemon = SimpleNamespace(process=object())
        self.fixture.stack = ExitStack(); self.addCleanup(self.fixture.stack.close)
        self.fixture.native_owners = {}
        self.intent = dict(id='intent', container='container', phase='running', launch=uid())
        generation = '00000000000000000002-' + self.intent['launch']
        self.process = harness.RuntimeProcess(pid=101, executable='/cengine',
            arguments=('/cengine', 'vm-shim', '--spec', '/' + generation + '/spec.json', '--launch-intent', '/intent.json'),
            identity=(10, 20, 30), pidversion=2, parent_pid=self.api.pid)
        self.fixture.state = lambda: ({'root': {}}, {'intents': {'intent': self.intent}})
        self.fixture.processes = lambda: [self.process]
        self.validate = Mock()
        @contextmanager
        def workload_owner(*args): yield {}, {}, self.validate
        self.enterContext(patch.object(o.p, 'workload_owner', workload_owner))
        self.enterContext(patch.object(o.p, 'running_receipts'))
        self.enterContext(patch.object(o.stale, 'fixture_mounts'))
        self.kernel = self.enterContext(patch.object(harness, '_kernel_process', return_value=self.process))
        _, _, self.check = self.fixture.live(SimpleNamespace(id='container'), {})

    def test_only_joined_api_child_reparent_refreshes_live_closure(self):
        reparented = replace(self.process, parent_pid=1)
        self.assertNotEqual(reparented, self.process)  # Global equality stays strict.
        self.kernel.return_value = reparented
        with self.assertRaises(ValueError): self.check()
        self.fixture.api_restarted(self.api)
        self.check()
        self.assertEqual(self.fixture.native_owners['container']['process'], reparented)
        self.validate.assert_called()
        self.kernel.return_value = self.process
        with self.assertRaises(ValueError): self.check()  # Closure uses refreshed pin.

    def test_unchanged_workload_is_allowed(self):
        self.fixture.api_restarted(self.api)
        self.check()

    def test_changed_native_identity_or_lineage_is_rejected_atomically(self):
        reparented = replace(self.process, parent_pid=1)
        mutations = [None, replace(reparented, pid=102), replace(reparented, identity=(11, 20, 30)),
            replace(reparented, identity=(10, 21, 30)), replace(reparented, identity=(10, 20, 31)),
            replace(reparented, arguments=('/other',)), replace(reparented, executable='/other'),
            replace(reparented, command='changed'), replace(reparented, pidversion=3),
            replace(reparented, parent_pid=102)]
        for changed in mutations:
            with self.subTest(changed=changed):
                self.kernel.return_value = changed
                with self.assertRaises(ValueError): self.fixture.api_restarted(self.api)
                self.assertEqual(self.fixture.native_owners['container']['process'], self.process)
        self.fixture.native_owners['container']['process'] = replace(self.process, parent_pid=99)
        self.kernel.return_value = reparented
        with self.assertRaises(ValueError): self.fixture.api_restarted(self.api)

    def test_bad_reader_does_not_partially_refresh_original(self):
        reader = replace(self.process, pid=102)
        self.fixture.native_owners['reader'] = {'process': reader}
        self.kernel.side_effect = [replace(self.process, parent_pid=1), replace(reader, parent_pid=1, pidversion=3)]
        with self.assertRaises(ValueError): self.fixture.api_restarted(self.api)
        self.assertEqual(self.fixture.native_owners['container']['process'], self.process)
        self.assertEqual(self.fixture.native_owners['reader']['process'], reader)

    def test_no_refresh_without_exact_owned_death_proof(self):
        self.kernel.return_value = replace(self.process, parent_pid=1)
        for code in (None, 0, -signal.SIGTERM, signal.SIGKILL):
            with self.subTest(code=code), self.assertRaises(ValueError):
                self.fixture.api_restarted(SimpleNamespace(pid=100, poll=lambda: code))
            self.assertEqual(self.fixture.native_owners['container']['process'], self.process)
        self.fixture.daemon.process = self.api
        with self.assertRaises(ValueError): self.fixture.api_restarted(self.api)

    def test_refresh_keeps_launch_and_intent_validation(self):
        self.kernel.return_value = replace(self.process, parent_pid=1)
        self.fixture.api_restarted(self.api)
        self.validate.side_effect = ValueError('launch changed')
        with self.assertRaisesRegex(ValueError, 'launch changed'): self.check()
        self.validate.side_effect = None
        self.fixture.state = lambda: ({}, {'intents': {'intent': dict(self.intent, phase='changed')}})
        with self.assertRaisesRegex(ValueError, 'unchanged live original intent'): self.check()


if __name__=='__main__':unittest.main()
