#!/usr/bin/env python3
"""Fresh actual wire positive projection; host fixtures are not native proof."""
import copy
import runpy
import unittest
import uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
ns = runpy.run_path(str(ROOT / 'tools/tests/test-managed-stale-consumer.py'))
s, values = ns['s'], ns['values']

def fixture(case='same-e-existing-data'):
    _, original, old, _ = values(case)
    v, b, current, boot = values('same-e-existing-data')
    for key in ('requestID', 'operationUUID', 'armDigest'): b[key] = original[key]
    b['generation'] = original['generation'] + 1
    b['key'] = '7'*64; b['certificateSHA256'] = '8'*64
    current.update(phase='running', prepareCompleted=True)
    for key in ('store', 'container', 'containerInstance'):
        current[key] = old[key]; b['scope'][key] = old[key]
    current['slots'][0].update(volume=old['slots'][0]['volume'], key=b['key'])
    boot['ready']['storeUUID'] = old['store']
    e = v['original']; e['arm'].update(requestID=b['requestID'], operationUUID=b['operationUUID'], leafSHA256=b['certificateSHA256'])
    e.update(scope=copy.deepcopy(b['scope']), stage='armed-mounted-positive', keySHA256=b['key'], serverDERSHA256='', signCount=0,
        signInputSHA256='', bytesWrittenAfterSign=0, clientWrittenBytes=0, clientPrefixBytes=0, clientPrefixSHA256='', localError='',
        originalOperation=dict(kind='data-getattr-root', sequence=1, errorClass='ok'))
    proof = dict(original=original, binding=b, service={k:boot['ready'][k] for k in ('serviceEpoch','workerUUID')},
        serverDERSHA256=s.p.digest(b'public-test-DER'), evidence=e, released=True)
    return tuple(copy.deepcopy(x) for x in (proof, original, current, boot, b['generation']))

class FreshTests(unittest.TestCase):
    def test_live_owner_order_and_no_second_negative_or_replacement(self):
        source = (ROOT / 'Sources/CEngineRuntime/RawManagedStorageBackend.swift').read_text()
        flow = source[source.index('    private func attestFreshGetattr('):source.index('    /// Containment ordering only.')]
        for before, after in (('shim.originalConsumerArm(', 'let evidence = armed.evidence'),
                ('let evidence = armed.evidence', 'armed.release()'),
                ('armed.release()', 'proof.validate('), ('proof.validate(', 'compatibility.originalPublish(')):
            self.assertLess(flow.index(before), flow.index(after))
        self.assertNotIn('.begin()', flow); self.assertNotIn('.probe(', flow)
        self.assertNotIn('retireOriginalConsumer', flow)
        self.assertIn('OriginalConsumerCleanup.run', flow)
        self.assertIn('contain: { _ = try await shim.stop() }', flow)
        live = (ROOT / 'Tests/Compatibility/managed_stale_consumer.py').read_text().split('def run_live(',1)[1]
        self.assertLess(live.index('joined_start(start_request())'), live.index('proof = fresh_getattr('))
        self.assertIn('if case in FRESH_GETATTR_CASES:', live)

    def test_actual_three_required_cases(self):
        for case in s.FRESH_GETATTR_CASES:
            args=fixture(case); self.assertEqual(s.fresh_getattr(*args), args[0])
    def test_every_observed_field_missing_null_unknown_and_type_alias(self):
        def nodes(o,path=()):
            if isinstance(o,dict):
                yield path,o
                for k,v in o.items(): yield from nodes(v,(*path,k))
        for path,obj in nodes(fixture()[0]):
            edits=[(k,op) for k in obj for op in ('missing','null')]+[('unknown','extra')]
            edits += [(k,'alias') for k,v in obj.items() if type(v) in (bool,int)]
            for field,op in edits:
                args=fixture(); target=args[0]
                for k in path:target=target[k]
                if op=='missing':del target[field]
                elif op=='null':target[field]=None
                elif op=='alias':target[field]=int(target[field]) if type(target[field]) is bool else float(target[field])
                else:target[field]='forbidden'
                with self.subTest(path=path,field=field,op=op),self.assertRaises((ValueError,KeyError)):s.fresh_getattr(*args)
    def test_old_owner_peer_failure_and_stat_cannot_substitute(self):
        mutations=[lambda v:v.update(released=False), lambda v:v['binding'].update(generation=4),
            lambda v:v.update(serverDERSHA256='0'*64),lambda v:v['evidence'].update(stage='begun'),
            lambda v:v['evidence']['originalOperation'].update(kind='fsync-directory'),
            lambda v:v['evidence']['originalOperation'].update(errorClass='eio'),
            lambda v:v['evidence']['rootRequest'].update(requestSequence=0),
            lambda v:v['service'].update(workerUUID=str(uuid.uuid4()))]
        for mutate in mutations:
            args=fixture();mutate(args[0])
            with self.assertRaises(ValueError):s.fresh_getattr(*args)

if __name__=='__main__':unittest.main()
