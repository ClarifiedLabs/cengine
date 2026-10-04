#!/usr/bin/env python3
"""Joined host-only root v6 projection regressions; no native acceptance."""
import ast
import base64
import copy
from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import managed_stale_consumer as s
import managed_root_backing as b
import managed_root_projection as r
p = s.p
values = runpy.run_path(str(ROOT / 'tools/tests/test-managed-stale-consumer.py'))['values']
backing_fixtures = runpy.run_path(str(ROOT / 'tools/tests/test-managed-root-backing.py'))
uid = backing_fixtures['uid']


def lifecycle_projection(boot, authority):
    """Host-only independent owner comparison; never native acceptance."""
    boot.update(format=r.lifecycle.VERSION, lifecycleIdentity=dict(
        store=boot['ready']['storeUUID'], generation=1, binding='a'*64))
    for name in ('before', 'atProbe', 'after'):
        snapshot = authority[name]; snapshot['schema'] = 4
        for prepare in snapshot['prepares'].values():
            prepare['context'] = dict(service_epoch=snapshot['epoch'],
                controller_epoch=snapshot['controller']['epoch'], controller_key=snapshot['controller']['key'])


def fixture(retired=True, lifecycle=True):
    _, binding, _, boot = values('same-e-existing-data')
    original, reader, _, _ = backing_fixtures['fixture']()
    scope = binding['scope']; scope.update({k: original['id' if k == 'intent' else k] for k in ('intent', 'store', 'container', 'launch', 'serviceEpoch', 'controllerEpoch', 'controllerKey')})
    original.update({k: v for k, v in scope.items() if k != 'intent'})
    case = b.ROOT_CASES[int(retired)]
    binding.update(version=6, caseName=case, targetAttachment=original['slots'][0]['attachment'], key=original['slots'][0]['key'])
    binding['boot']['shimLaunchUUID'] = scope['launch']
    for index, slot in enumerate(original['slots']): slot['retireOperation'] = uid(60+index)
    ready = boot['ready']; ready.update(storeUUID=scope['store'], **{k:scope[k] for k in ('serviceEpoch', 'controllerEpoch', 'controllerKey')},
        tlsRootDER=base64.b64encode(b'root-public-DER').decode(), serverKey='9'*64)
    marker = b.baseline_marker(binding, original, reader, backing_fixtures['snapshot']())
    roots, issued = {}, []
    for index, name in enumerate(('source', 'target')):
        slot = original['slots'][index]
        authority = dict(epoch=scope['serviceEpoch'], binding=dict(store=scope['store'], container=scope['container'], launch=scope['launch'],
            role='runtime', **{k:slot[k] for k in ('volume', 'attachment', 'key', 'mode')}))
        issued.append(authority)
        roots[name] = dict(identitySHA256=str(index+4)*64, leafSHA256=binding['certificateSHA256'] if index == 0 else '6'*64,
            rootRequest=dict(node=1, requestSequence=1), read=dict(authority=authority, rootNode=1, node=2, handle=3, requestSequence=2,
                size=4096, ioFlags=0x48800, contentSHA256=marker['rootPair'][index]['contentSHA256']))
    arm = dict(version=6, profile=p.FULL_PROFILE, requestID=binding['requestID'], operationUUID=binding['operationUUID'], caseName=case,
        binding=binding['boot'], scope=scope, targetAttachment=binding['targetAttachment'], leafSHA256=binding['certificateSHA256'])
    positive = dict(arm=arm, stage='begun', scope=scope, keySHA256=binding['key'],
        mountIdentitySHA256=p.digest(p.canonical(dict(Source=roots['source']['identitySHA256'], Target=roots['target']['identitySHA256']))),
        serverDERSHA256='', signCount=0, signInputSHA256='', bytesWrittenAfterSign=0, clientWrittenBytes=0, clientPrefixBytes=0,
        clientPrefixSHA256='', localError='', fdOperation='read-file-root-grant', fdSequence=1,
        originalOperation=dict(kind='read-file-root-grant', sequence=1, errorClass='ok'), roots=roots, rootRequest=roots['source']['rootRequest'])
    attempted = copy.deepcopy(positive); attempted.update(stage='original-root-scope-replay', serverDERSHA256=p.digest(base64.b64decode(ready['serverDER'])),
        fdSequence=2, originalOperation=dict(kind='read-file-root-grant', sequence=2, errorClass='transport-failed' if retired else 'ok'), rootRequest=dict(node=1, requestSequence=3))
    attempted['roots']['replay'] = dict(source=issued[0], target=issued[1], rootNode=1, node=2, handle=3, rootSequence=3, readSequence=4, contentSHA256=roots['target']['read']['contentSHA256'])
    before = dict(schema=3, revision=10, store=dict(id=scope['store'], device_id='owned', root=dict(device=1,inode=1), exports=dict(device=1,inode=2)),
        epoch=scope['serviceEpoch'], controller=dict(epoch=scope['controllerEpoch'],key=scope['controllerKey']),
        volumes={slot['volume']:dict(id=slot['volume'], name='vol'+str(index), root=dict(device=1,inode=index+3)) for index, slot in enumerate(original['slots'])},
        volume_lifecycles={slot['volume']:dict(phase='READY',create=uid(70+index),created_revision=index+1) for index,slot in enumerate(original['slots'])},
        attachments={a['binding']['attachment']:dict(binding=a['binding'],phase='ACTIVE') for a in issued}, prepares={})
    # Include real-shaped completed PREPARE history, not a runtime-only registry.
    prepare_id = uid(80); prepare_bindings = []
    for index, a in enumerate(issued):
        pb = dict(a['binding'], role='prepare', prepare=prepare_id, attachment=uid(81+index), key=str(index+7)*64)
        prepare_bindings.append(pb)
        before['attachments'][pb['attachment']] = dict(binding=pb,phase='DRAINED',retirement=uid(83+index),
            receipt=dict(schema=3, **{k:pb[k] for k in ('store','volume','attachment','prepare','launch')}, revision=5))
    before['prepares'][prepare_id] = dict(id=prepare_id, attachments=prepare_bindings, phase='COMPLETED', attestation=dict(prepare=prepare_id,succeeded=True,clean_copy_up=True))
    at = copy.deepcopy(before); authority = dict(before=before,atProbe=at,after=copy.deepcopy(at))
    result = dict(version=1,binding=binding,service={k:ready[k] for k in ('storeUUID','serviceEpoch','workerUUID')},
        peer={**{k:ready[k] for k in ('tlsRootDER','serverDER','serverKey')},'dataAddress':'192.0.2.1:1234'},baseline=marker,positive=positive,original=attempted,authority=authority)
    if retired:
        slot = original['slots'][0]; receipt = dict(schema=3, **{k:issued[0]['binding'][k] for k in ('store','volume','attachment','launch')}, revision=11)
        remote = dict(binding=issued[0]['binding'],phase='DRAINED',receipt=receipt,retirement=slot['retireOperation'])
        at['revision']=12; at['attachments'][slot['attachment']]=remote; authority['after']=copy.deepcopy(at)
        authority['retirement']=dict(operation=slot['retireOperation'],receipt=receipt,queryRevision=12,epoch=scope['serviceEpoch'],controller=at['controller'],attachment=remote)
        query=dict(version=6,profile=p.FULL_PROFILE,requestID=binding['requestID'],armDigest=binding['armDigest'],operationUUID=binding['operationUUID'],caseName='same-e-existing-data',
            originalBootBinding=binding['boot'],original=issued[0],originalLeafSHA256=binding['certificateSHA256'],workerScope=result['service'])
        evidence=dict(stage='request-admit',errorClass='blocked',storeUUID=scope['store'],serviceEpoch=scope['serviceEpoch'],rejectedLeafSHA256=binding['certificateSHA256'],
            admission=dict(original=issued[0],node=1,requestSequence=3,operation='get_attr',authKind=3,noHandle=True))
        result.update(worker=dict(query=query,state='observed',selectedCount=1,evidence=evidence),finalized=dict(query=query,state='finalized',selectedCount=1,evidence=evidence))
    if lifecycle: lifecycle_projection(boot, authority)
    return tuple(copy.deepcopy(x) for x in (result,binding,original,boot,marker))


def walk(value,path=()):
    yield path,value
    for key,item in (value.items() if isinstance(value,dict) else enumerate(value) if isinstance(value,list) else ()):
        yield from walk(item,(*path,key))


class RootProjectionTests(unittest.TestCase):
    def check(self,args): return s.correlated_result(*args)
    def test_both_actual_shapes_preserve_legitimate_b_numeric_collisions(self):
        for retired in (False,True):
            args=fixture(retired); self.assertEqual(self.check(args),args[0])
            selected=s.selection(p.FULL_PROFILE,s.CASES,args[1]['caseName'])
            self.assertFalse(selected['fullAcceptance'])
            self.assertEqual(selected['coverage'],'1/18')
    def test_legacy_is_explicit_and_schema4_requires_independent_identity(self):
        for retired in (False, True):
            args = fixture(retired, lifecycle=False)
            self.assertEqual(self.check(args), args[0])
            for bad in (None, {}, dict(store=uid(199), generation=1, binding='a'*64),
                    dict(store=args[1]['scope']['store'], generation=True, binding='a'*64),
                    dict(store=args[1]['scope']['store'], generation=1, binding='not-a-pin')):
                args = fixture(retired)
                if bad is None: del args[3]['lifecycleIdentity']
                else: args[3]['lifecycleIdentity'] = bad
                with self.subTest(retired=retired, identity=bad), self.assertRaises((ValueError, KeyError)):
                    self.check(args)
            args = fixture(retired); del args[3]['format']
            with self.assertRaises(ValueError): self.check(args)
            args = fixture(retired); args[3].pop('lifecycleIdentity'); args[3].pop('format')
            with self.assertRaises(ValueError): self.check(args)
            args = fixture(retired); args[0]['authority']['before']['schema'] = 3
            with self.assertRaises(ValueError): self.check(args)

    def test_prepare_context_and_receipts_keep_distinct_contracts(self):
        args = fixture(); snap = args[0]['authority']['before']; scope = args[1]['scope']
        identity = args[3]['lifecycleIdentity']; ident = next(iter(snap['prepares']))
        for context in ({}, None, dict(service_epoch=uid(198), controller_epoch=True, controller_key=scope['controllerKey']),
                dict(service_epoch=uid(198), controller_epoch=2, controller_key=scope['controllerKey']),
                dict(service_epoch=uid(198), controller_epoch=1, controller_key='f'*64)):
            bad = copy.deepcopy(snap); bad['prepares'][ident]['context'] = context
            with self.subTest(context=context), self.assertRaises(ValueError): r.snapshot(bad, scope, identity)
        for phase in ('PENDING', 'COMPLETED'):
            good = copy.deepcopy(snap); good['prepares'][ident]['phase'] = phase
            if phase == 'PENDING': del good['prepares'][ident]['attestation']
            r.snapshot(good, scope, identity)
            del good['prepares'][ident]['context']
            with self.assertRaises(ValueError): r.snapshot(good, scope, identity)
        replaced = copy.deepcopy(snap); first = replaced['prepares'][ident]
        successor = copy.deepcopy(first); successor_id = uid(195)
        successor.update(id=successor_id, phase='PENDING'); del successor['attestation']
        for index, planned in enumerate(successor['attachments']):
            planned.update(prepare=successor_id, attachment=uid(196+index), key=('c' if index == 0 else 'd')*64)
            replaced['attachments'][planned['attachment']] = dict(binding=planned, phase='RESERVED')
        replaced['prepares'][successor_id] = successor
        first.update(phase='REPLACED', successor=successor_id); del first['attestation']
        r.snapshot(replaced, scope, identity)
        del first['context']
        with self.assertRaises(ValueError): r.snapshot(replaced, scope, identity)
        # Historical service epochs remain valid; contexts are not rewritten to CURRENT.
        historical = copy.deepcopy(snap)
        historical['prepares'][ident]['context']['service_epoch'] = uid(198)
        r.snapshot(historical, scope, identity)
        bad = copy.deepcopy(snap)
        next(item for item in bad['attachments'].values() if 'receipt' in item)['receipt']['schema'] = 4
        with self.assertRaises(ValueError): r.snapshot(bad, scope, identity)
        legacy = fixture(lifecycle=False)[0]['authority']['before']
        legacy['prepares'][ident]['context'] = snap['prepares'][ident]['context']
        with self.assertRaises(ValueError): r.snapshot(legacy, scope)

    def test_recursive_closed_schema_and_numeric_aliases(self):
        count=0
        for retired in (False,True):
            base=fixture(retired)
            for path,obj in walk(base[0]):
                mutations=[]
                if isinstance(obj,dict):
                    mutations.append({**obj,'unknown':1})
                    for key in obj:
                        bad=copy.deepcopy(obj); del bad[key]; mutations.extend((bad,{**obj,key:None}))
                elif isinstance(obj,list):
                    mutations.extend(([], [*obj, copy.deepcopy(obj[0])]))
                    for index in range(len(obj)):
                        bad=copy.deepcopy(obj); bad[index]=None; mutations.append(bad)
                        bad=copy.deepcopy(obj); del bad[index]; mutations.append(bad)
                elif type(obj) is int: mutations.extend((float(obj),bool(obj)))
                elif type(obj) is bool: mutations.append(int(obj))
                for mutation in mutations:
                    args=copy.deepcopy(base)
                    if path:
                        target=args[0]
                        for key in path[:-1]: target=target[key]
                        target[path[-1]]=mutation
                    else: args=(mutation,*args[1:])
                    with self.subTest(retired=retired,path=path,mutation=mutation), self.assertRaises((ValueError,KeyError)): self.check(args)
                    count+=1
        self.assertGreater(count,1500)
    def test_semantic_authority_content_and_fifo_substitutions_rejected(self):
        for retired in (False,True):
            for path,wrong in ((('service','workerUUID'),uid(90)),(('original','roots','replay','contentSHA256'),'f'*64),
                    (('original','roots','replay','readSequence'),3),(('original','rootRequest','requestSequence'),2),
                    (('positive','roots','source','read','ioFlags'),1),(('authority','after','revision'),13),
                    (('positive','roots','target','leafSHA256'),'b'*64)):
                args=fixture(retired); target=args[0]
                for key in path[:-1]: target=target[key]
                target[path[-1]]=wrong
                with self.subTest(retired=retired,path=path), self.assertRaises(ValueError): self.check(args)
        args=fixture(); args[0]['authority']['retirement']['receipt']['revision']=10
        with self.assertRaises(ValueError): self.check(args)
    def test_live_reader_order_requires_actual_fresh_wire_proof(self):
        text=(ROOT/'Tests/Compatibility/managed_stale_consumer.py').read_text(); ast.parse(text)
        for first,second in [('root_backing.RootBackingReader','queue.publish("original-consumer.capture.json"'),
                ('reader.snapshot()','queue.publish(request_id + ".original-consumer.baseline.json"'),
                ('root_backing.project_backing','proof = fresh_read('),
                ('proof = fresh_read(','record("original-consumer-fresh-wire-root-read"'),
                ('record("original-consumer-fresh-wire-root-read"','record("original-consumer-fresh-owner-positive"')]:
            self.assertLess(text.index(first),text.index(second))


def fresh_fixture(retired=True, reverse=False):
    previous, old, current, boot, _ = fixture(retired)
    current.update(id=uid(100),launch=uid(101),prepare=uid(102),serviceEpoch=uid(103),phase='running',prepareCompleted=True)
    scope={k:current['id' if k=='intent' else k] for k in old['scope']}
    slots=current['slots']; evidence=copy.deepcopy(previous['positive'])
    roots=[evidence['roots'][k] for k in ('source','target')]
    if reverse: slots.reverse(); roots.reverse()
    for index,(slot,item) in enumerate(zip(slots,roots)):
        slot.update(attachment=uid(110+index),key=('c' if index==0 else 'd')*64)
        item['leafSHA256']=('e' if index==0 else 'f')*64
        item['read']['authority']=dict(epoch=scope['serviceEpoch'],binding=dict(store=scope['store'],container=scope['container'],launch=scope['launch'],role='runtime',**{k:slot[k] for k in ('volume','attachment','key','mode')}))
    binding={**copy.deepcopy(old),'caseName':'cross-mount-root-grant','scope':scope,'generation':old['generation']+1,
        'boot':dict(shimLaunchUUID=scope['launch'],guestBootNonce=uid(120)), 'targetAttachment':slots[0]['attachment'],'key':slots[0]['key'],'certificateSHA256':roots[0]['leafSHA256']}
    evidence.update(arm=dict(version=6,profile=p.FULL_PROFILE,requestID=binding['requestID'],operationUUID=binding['operationUUID'],caseName=binding['caseName'],
        binding=binding['boot'],scope=scope,targetAttachment=binding['targetAttachment'],leafSHA256=binding['certificateSHA256']),scope=scope,keySHA256=binding['key'],stage='armed-mounted-positive',
        roots=dict(source=roots[0],target=roots[1]),rootRequest=roots[0]['rootRequest'],mountIdentitySHA256=p.digest(p.canonical(dict(Source=roots[0]['identitySHA256'],Target=roots[1]['identitySHA256']))))
    boot['ready'].update(serviceEpoch=scope['serviceEpoch'],workerUUID=uid(121))
    proof=dict(original=old,binding=binding,service={k:boot['ready'][k] for k in ('serviceEpoch','workerUUID')},serverDERSHA256=p.digest(base64.b64decode(boot['ready']['serverDER'])),evidence=evidence,released=True)
    return tuple(copy.deepcopy(x) for x in (proof,previous,current,boot,binding['generation']))


class FreshRootReadTests(unittest.TestCase):
    def check(self,args): return r.fresh_read(*args,s.EVIDENCE_FIELDS)
    def test_both_roots_and_fresh_order_swap(self):
        for retired in (False,True):
            for reverse in (False,True):
                args=fresh_fixture(retired,reverse); self.assertEqual(self.check(args),args[0])
    def test_every_fresh_field_closed_and_exact_numbers(self):
        base=fresh_fixture()
        for path,obj in walk(base[0]):
            mutations=[]
            if isinstance(obj,dict):
                mutations.append({**obj,'unknown':True})
                for key in obj:
                    bad=copy.deepcopy(obj); del bad[key]; mutations.extend((bad,{**obj,key:None}))
            elif type(obj) is int: mutations.extend((float(obj),bool(obj)))
            elif type(obj) is bool: mutations.append(int(obj))
            for mutation in mutations:
                args=copy.deepcopy(base)
                if path:
                    target=args[0]
                    for key in path[:-1]: target=target[key]
                    target[path[-1]]=mutation
                else: args=(mutation,*args[1:])
                with self.subTest(path=path), self.assertRaises((ValueError,KeyError)): self.check(args)
    def test_original_leaf_wrong_volume_or_content_and_unjoined_rejected(self):
        for field in ('leaf','volume','content','release','generation','worker','stat'):
            args=fresh_fixture(); proof=args[0]; item=proof['evidence']['roots']['target']
            if field=='leaf': item['leafSHA256']=args[1]['positive']['roots']['target']['leafSHA256']
            elif field=='volume': item['read']['authority']['binding']['volume']=uid(190)
            elif field=='content': item['read']['contentSHA256']='0'*64
            elif field=='release': proof['released']=False
            elif field=='generation': proof['binding']['generation']=proof['original']['generation']
            elif field=='worker': proof['service']['workerUUID']=args[1]['service']['workerUUID']
            else: proof['evidence']['fdOperation']='fsync-directory'
            with self.subTest(field=field), self.assertRaises(ValueError): self.check(args)


if __name__=='__main__': unittest.main()
