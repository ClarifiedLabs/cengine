#!/usr/bin/env python3
"""Host-only replay projection/ordering; fake fixtures are not ROOT authority."""
import base64
import copy
import json
from pathlib import Path
import runpy
import signal
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import uuid
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import managed_takeover_replay as t
ns = runpy.run_path(str(ROOT / 'tools/tests/test-managed-storage-recovery.py'))
def uid(): return str(uuid.uuid4())
def encoded(v): return base64.b64encode(t.p.canonical(v)).decode()
def fixture():
    initial, before = ns['owners']()
    before.pop('serviceTransitions'); before['boot'] = copy.deepcopy(initial['boot'])
    def fix(record):
        tr = record['transitions'][-1]
        issue = json.loads(base64.b64decode(tr['issue']))
        issue['body']['candidate'].update(child_pid_hint=123, incarnation_id=uid())
        tr['issue'] = encoded(issue)
    fix(before)
    after = copy.deepcopy(before); after['revision'] += 5
    tr = copy.deepcopy(before['transitions'][-1])
    issue, issued, confirm, confirmed = [json.loads(base64.b64decode(tr[k])) for k in ('issue','issued','confirm','confirmed')]
    public = b'new-public-test-key'; key = t.p.digest(public); grant = uid()
    issue['request_id'] = issued['request_id'] = uid()
    confirm['request_id'] = confirmed['request_id'] = uid()
    issue['body'].update(grant_id=grant, expected_epoch=2, candidate=dict(public_data=base64.b64encode(public).decode(), child_pid_hint=124, incarnation_id=uid()))
    issued['body']['grant'].update(id=grant, expected_epoch=2, new_key=key)
    issued['body']['signature'] = base64.b64encode(b'y'*64).decode()
    confirm['body'].update(grant_id=grant, controller=dict(epoch=3,key=key)); confirmed['body']['controller'] = dict(epoch=3,key=key)
    after['transitions'].append(dict(zip(('issue','issued','confirm','confirmed'), map(encoded,(issue,issued,confirm,confirmed)))))
    p = t.recovery.owner_proof(before)
    capture = dict(version=t.VERSION, requestID=uid(), store=p['store'], epoch=2, serviceEpoch=p['serviceEpoch'])
    old, _ = t.transition(before['transitions'][-1]); pending, candidate = t.transition(after['transitions'][-1])
    denied = dict(request_id=capture['requestID'], version=t.VERSION, store=p['store'], service_epoch=p['serviceEpoch'],
        incarnation_id=candidate['incarnation_id'], signed=old, pending=pending['grant'], denied=dict(id=1,error='UNAUTHORIZED'))
    return initial, before, after, capture, before['transitions'][-1], denied, after['transitions'][-1]
class Tests(unittest.TestCase):
    def test_exact_two_successors_and_nonacceptance(self):
        initial, before, *args = fixture()
        t.same_service_step(initial,before)
        result = t.control_result(before,*args)
        self.assertTrue(result['controlLegVerified']); self.assertFalse(result['fullAcceptance']); self.assertFalse(result['nativeAcceptance'])
    def test_denial_shape_and_identity_exhaustive(self):
        def nodes(v,path=()):
            if type(v) is dict:
                yield path,v
                for k,x in v.items(): yield from nodes(x,path+(k,))
        count=0
        for path,obj in nodes(fixture()[5]):
            for key in obj:
                for mode in ('missing','null','alias'):
                    args=list(fixture()[1:]); value=args[4]
                    for part in path:value=value[part]
                    if mode=='missing':del value[key]
                    elif mode=='null':value[key]=None
                    elif type(value[key]) is int:value[key]=float(value[key])
                    else:continue
                    with self.subTest(path=path,key=key,mode=mode),self.assertRaises((ValueError,KeyError,TypeError)):t.control_result(*args)
                    count+=1
            args=list(fixture()[1:]);value=args[4]
            for part in path:value=value[part]
            value['unknown']=True
            with self.assertRaises((ValueError,KeyError,TypeError)):t.control_result(*args)
        self.assertGreater(count,35)
    def test_no_current_preflight_new_service_or_unconfirmed(self):
        for fault in ('local','code','same-grant','service','signature','confirmed','history'):
            args=list(fixture()[1:]);before,after,capture,begun,denied,confirmed=args
            if fault=='local':denied['denied']['id']=0
            elif fault=='code':denied['denied']['error']='BLOCKED'
            elif fault=='same-grant':denied['signed']=dict(grant=denied['pending'],signature=denied['signed']['signature'])
            elif fault=='service':after['boot']['ready']['serviceEpoch']=uid()
            elif fault=='signature':denied['signed']['signature']=base64.b64encode(b'z'*64).decode()
            elif fault=='confirmed':args[5]=begun
            else:after['transitions']=[]
            with self.subTest(fault=fault),self.assertRaises((ValueError,KeyError,TypeError,IndexError)):t.control_result(*args)
    def test_recovered_operation_not_cached_positive(self):
        u, h = uid(), 'a'*64
        binding = dict(version=4, profile=t.p.FULL_PROFILE, requestID=u, operationUUID=u, caseName='same-e-existing-data',
            armDigest=h, generation=1, boot=dict(shimLaunchUUID=u,guestBootNonce=u), scope={}, targetAttachment=u, key=h, certificateSHA256=h)
        arm = {k: binding[k] for k in ('version','profile','requestID','operationUUID','caseName','scope','targetAttachment')}
        arm.update(binding=binding['boot'],leafSHA256=h)
        armed = dict(arm=arm,stage='armed-mounted-positive',scope={},keySHA256=h,mountIdentitySHA256=h,
            serverDERSHA256='',signCount=0,signInputSHA256='',bytesWrittenAfterSign=0,clientWrittenBytes=0,clientPrefixBytes=0,
            clientPrefixSHA256='',localError='',fdOperation='fsync-directory',fdSequence=1,
            rootRequest=dict(node=99,requestSequence=7),originalOperation=dict(kind='data-getattr-root',sequence=1,errorClass='ok'))
        begun=copy.deepcopy(armed);begun['stage']='begun'
        positive=copy.deepcopy(begun);positive['stage']='original-data-positive';positive['rootRequest']['requestSequence']=8;positive['originalOperation']['sequence']=2
        value=dict(binding=binding,resumed=armed,begun=begun,positive=positive,released=dict(arm=arm,stage='released'))
        self.assertTrue(t.recovered_original_positive(value,binding,armed)['originalOperationVerified'])
        for fault in ('cache','sequence','alias','node','denial','mount','extra','released','binding'):
            v=copy.deepcopy(value)
            if fault=='cache':v['positive']=copy.deepcopy(begun)
            elif fault=='sequence':v['positive']['rootRequest']['requestSequence']=7
            elif fault=='alias':v['positive']['rootRequest']['requestSequence']=8.0
            elif fault=='node':v['positive']['rootRequest']['node']=1
            elif fault=='denial':v['positive']['originalOperation']['errorClass']='transport-failed'
            elif fault=='mount':v['positive']['mountIdentitySHA256']='b'*64
            elif fault=='extra':v['positive']['newClient']=True
            elif fault=='released':v['released']['stage']='begun'
            else:v['binding']['generation']=2
            with self.subTest(fault=fault),self.assertRaises((ValueError,KeyError,TypeError)):
                t.recovered_original_positive(v,binding,armed)

    def test_actual_fixture_restart_order_without_running_processes(self):
        initial,before,after,capture,begun,denied,confirmed=fixture(); events=[]
        class Queue:
            def __init__(self,*a):pass
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def validate(self):pass
            def publish(self,name,value):
                events.append('capture');denied['request_id']=value['requestID']
            def read(self,name,*a,**k):
                phase=name.split('.')[-2]
                return t.p.canonical(dict(begun=begun,denied=denied,confirmed=confirmed)[phase]),None
        def process():
            value = SimpleNamespace(returncode=None)
            value.poll = lambda: value.returncode
            return value
        def restart(**kwargs):
            self.assertEqual(kwargs, {'kill': True})
            events.append('restart')
            d.process.returncode = -signal.SIGKILL
            d.process = process()
        d=SimpleNamespace(root=Path('/unused'),process=process(),restart=restart)
        with patch.object(t.recovery,'read_public',side_effect=[(v,'hash') for v in (initial,before,after)]),patch.object(t.p,'Directory',Queue):
            result=t.run_control_restarts(d,remaining=lambda:400,record=lambda name,**kw:events.append(name))
        self.assertEqual(events,['restart','takeover-first-confirmed','capture','restart','takeover-control-leg'])
        self.assertFalse(result['fullAcceptance'])
        events.clear()
        with patch.object(t.recovery,'read_public',return_value=(initial,'hash')),self.assertRaises(ValueError):
            t.run_control_restarts(d,remaining=lambda:194,record=lambda *a,**k:None)
        self.assertEqual(events,[])
if __name__=='__main__':unittest.main()
