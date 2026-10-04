#!/usr/bin/env python3
"""Joined live adapter with host fixtures at engine/native boundaries, not native proof."""
import ast
import copy
from contextlib import contextmanager
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
b = runpy.run_path(str(ROOT / 'tools/tests/test-managed-takeover-original.py'))
o, t, worker, uid = (b[k] for k in ('o', 't', 'worker', 'uid'))

class Tests(unittest.TestCase):
    def joined(self, case, fault=None):
        _, owner, *_ = b['base']['fixture']()
        events, files, pending, intents = [], {}, {}, {}
        self.events = events
        volume, instance = uid(), uid()
        class Item:
            def __init__(self, identifier):
                self.id = identifier
                self.attrs = {'State': {'Status': 'created', 'Running': False}}
            def reload(self): pass
            def start(self):
                events.append('start-' + self.id[0])
                if pending:
                    request = pending.pop('request')
                    c, a, r, i = b['observation'](owner, self.id, instance, volume, 2, request)
                    values = dict(candidate=c, armed=a, registry=r, released=dict(arm=a['arm'], stage='released'))
                    if request.get('isolationCase'):
                        events.append('probe')
                        proof = dict(request=dict(requestID=request["requestID"], operationUUID=request["operationUUID"], armDigest=c["binding"]["armDigest"], challenge=uid()), workerUUID=uid(), caseName=case, store=request['store'], serviceEpoch=request['serviceEpoch'],
                            revision=r['revision'], registrySHA256='a'*64,
                            result='legacy-tls-header-rejected' if case == 'legacy-connection' else 'second-owner-locked')
                        positive = b['recovered'](c['binding'], a)
                        if fault == 'result': proof['result'] = 'eof'
                        if fault == 'revision': proof['revision'] += 1
                        if fault == 'cached': positive['positive'] = positive['begun']
                        if fault == 'release': values['released']['stage'] = 'begun'
                        state = dict(proof, caseName='isolation-state', result='registry-state')
                        receipt = dict(before=copy.deepcopy(state), observation=proof, after=copy.deepcopy(state))
                        if fault == 'hidden': receipt['after']['registrySHA256'] = 'b'*64
                        if fault == 'challenge': receipt['after']['request']['challenge'] = uid()
                        if fault == 'stale-receipt':
                            for item in receipt.values(): item['request']['requestID'] = uid()
                        if fault == 'arm':
                            for item in receipt.values(): item['request']['armDigest'] = 'c'*64
                        if fault == 'worker': receipt['observation']['workerUUID'] = uid()
                        values.update(isolation=receipt, positive=positive)
                    for phase, value in values.items():
                        files[request['requestID'] + '.public-takeover-arm.' + phase + '.json'] = value
                else:
                    i = b['observation'](owner, self.id, instance, volume, 2)[3]
                intents[self.id] = i
            def stop(self, **kw): events.append('stop-' + self.id[0])
        original, reader = Item('a'*64), Item('b'*64)
        class Queue:
            def __init__(self, *args): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def validate(self): pass
            def publish(self, name, value): pending['request'] = value
            def read(self, name, *args, **kwargs):
                return t.p.canonical(files[name]), ('pin', name)
        @contextmanager
        def prepared(*args): yield None, dict(containerInstance=instance), lambda: None
        def live(self, item, plan): return intents[item.id], 2, lambda: None
        def snapshot(self, item):
            events.append('snapshot-' + item.id[0])
            value = b['snap']()
            if fault == 'backing' and 'probe' in events: value['files']['a']['sha256'] = 'f'*64
            return value
        daemon = SimpleNamespace(root=Path('/unused'))
        with patch.object(t.recovery, 'read_public', return_value=(owner, 'hash')), patch.object(t.p, 'Directory', Queue), \
             patch.object(o.p, 'owned'), patch.object(o.OriginalFixture, 'state', return_value=({'root': {}}, {})), \
             patch.object(o.OriginalFixture, 'processes', return_value=[]), patch.object(worker, 'prepared_peer_owner', prepared), \
             patch.object(o.OriginalFixture, 'live', live), patch.object(o.OriginalFixture, 'snapshot', snapshot):
            result = o.run_service_isolation(daemon, case=case, container=original, reader=reader,
                plan={'volume': 'v'}, reader_plan={'volume': 'v'}, remaining=lambda: 100,
                record=lambda phase, **kw: events.append(phase))
        self.assertLess(events.index('snapshot-b'), events.index('probe'))
        self.assertLess(events.index('service-isolation-unchanged'), events.index('service-isolation-fresh-getattr'))
        self.assertEqual(events.count('start-a'), 1)
        self.assertEqual(events.count('start-b'), 2)
        self.assertFalse(result['nativeAcceptance']); self.assertFalse(result['fullAcceptance'])
        for key in ('originalOperationVerified', 'registryVerified', 'backingVerified', 'freshGetattrVerified'):
            self.assertTrue(result[key])
        self.assertIn('stop-a', events)

    def test_joined_both_cases(self):
        for case in ('legacy-connection', 'second-service-exclusivity'):
            with self.subTest(case=case): self.joined(case)

    def test_joined_rejections_and_cleanup(self):
        for fault in ('result', 'revision', 'cached', 'release', 'backing', 'hidden', 'challenge', 'arm', 'worker', 'stale-receipt'):
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.joined('legacy-connection', fault)
            self.assertIn('stop-a', self.events)
            self.assertNotIn('service-isolation-fresh-getattr', self.events)

    def test_live_entry_uses_distinct_source_selector_not_native_gate(self):
        tree = ast.parse((ROOT / 'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
        entry = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_service_isolation_followup')
        namespace = {'proof': t.p}
        exec(compile(ast.Module(body=[entry], type_ignores=[]), '<entry>', 'exec'), namespace)
        args = dict(cases=o.stale.CASES, case='legacy-connection', container=object(), reader=object(), plan={}, reader_plan={}, remaining=lambda: 100, record=lambda *a, **k: None)
        with patch.object(o, 'run_service_isolation', return_value={'fullAcceptance': False}) as run:
            namespace[entry.name](object(), profile=t.p.FULL_PROFILE, **args)
            self.assertEqual(run.call_count, 1)
            with self.assertRaises(ValueError): namespace[entry.name](object(), profile='normal', **args)
            self.assertEqual(run.call_count, 1)
        for case in ('legacy-connection', 'second-service-exclusivity'):
            selected = o.followup_selection(t.p.FULL_PROFILE, o.stale.CASES, case)
            self.assertEqual(selected['executionRoute'], 'service-isolation')
            self.assertFalse(selected['nativeAcceptance'])
            with self.assertRaises(ValueError): o.stale.selection(t.p.FULL_PROFILE, o.stale.CASES, case)

if __name__ == '__main__': unittest.main()
