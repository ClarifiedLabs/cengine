#!/usr/bin/env python3
"""Engine-free RTM103 follow-up parent wiring; no daemon, engine, VMs or natives."""
import ast
from contextlib import contextmanager
import copy
import runpy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import harness
import managed_original_followup_parent as parent
import managed_prepare_faults as proof
import managed_stale_consumer as stale
import managed_takeover_original as followup

RUNNER = ROOT / 'tools/managed_prepare_matrix.py'
LIFECYCLE = runpy.run_path(str(ROOT / 'tools/tests/test-managed-takeover-lifecycle-evidence.py'))


def replace_metadata(value, old, new):
    """Coherent test substitution, so the real checkpoint validator still runs."""
    if value == old:
        return copy.deepcopy(new)
    if type(value) is dict:
        return {key: replace_metadata(item, old, new) for key, item in value.items()}
    if type(value) is list:
        return [replace_metadata(item, old, new) for item in value]
    return value

REPLAYED_RESULT = dict(controlLegVerified=True, originalOperationVerified=True, registryVerified=True,
    backingVerified=True, freshGetattrVerified=True, fullAcceptance=False, nativeAcceptance=False)


def isolation_result(case):
    return dict(caseName=case, originalOperationVerified=True, registryVerified=True, backingVerified=True,
        freshGetattrVerified=True, nativeAcceptance=False, fullAcceptance=False)


class FakeDirectory:
    """Serves the route ledger and the managed-storage manifest by path."""
    events = []
    records = []
    def __init__(self, path, *, private=True):
        self.path = Path(path)
        self.published = {}
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def publish(self, name, value):
        FakeDirectory.events.append('record:' + value['phase'])
        FakeDirectory.records.append((value['phase'], value))
        self.published[name] = value
    def read(self, name, maximum=65536, *, pin_file=False):
        if self.path.name == 'managed-storage' and name == 'manifest.json':
            raw = json.dumps({"schema": 1, "mode": "managed", "store": STORE}).encode()
            return raw, ('pin', name)
        raise FileNotFoundError(name)


STORE = '3' * 32 + '4' * 32


class ParentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.work = base / 'work'
        (self.work / 'root').mkdir(parents=True)
        self.evidence = base / 'evidence'
        self.evidence.mkdir()
        self.probe = base / 'probe'
        self.probe.write_bytes(b'pinned-parent-probe')
        self.probe_sha256 = proof.digest(self.probe.read_bytes())
        self.events = []
        self.records = []
        self.daemon = SimpleNamespace(work=self.work, root=self.work / 'root', socket=self.work / 'run/docker.sock',
            process=SimpleNamespace(poll=lambda: None), _retain_root=False,
            restart=lambda **kw: self.events.append('daemon-restart'))

    def tearDown(self):
        self.tmp.cleanup()

    def record(self, phase, **value):
        self.events.append('record:' + phase)
        self.records.append((phase, value))

    def client(self):
        events, records = self.events, self.records
        archive_config = self.archive_config
        class Images:
            def load(self, archive):
                events.append('images-load')
            def get(self, name):
                # The loaded image carries the same owner label as the plan tag.
                item = SimpleNamespace(id='image-' + name, attrs={'RootFS': {'Layers': archive_config['rootfs']['diff_ids']},
                    'RepoTags': [name], 'Config': {'Labels': {proof.OWNER: name.rsplit(':', 1)[-1]}}})
                item.reload = lambda: events.append('image-reload')
                return item
            def remove(self, image_id):
                events.append('image-remove')
        class Volumes:
            def create(self, name, labels=None):
                volume = SimpleNamespace(name=name, attrs={'Labels': labels})
                volume.reload = lambda: events.append('volume-reload')
                volume.remove = lambda: events.append('volume-remove')
                events.append('volume-create')
                return volume
        client = SimpleNamespace(images=Images(), volumes=Volumes(),
            version=lambda: {'GitCommit': 'c0ffee0'},
            close=lambda: events.append('client-close'))
        return client

    def resources(self):
        events = self.events
        plan_box = {}
        def make_item(ident):
            item = SimpleNamespace(id=ident, name=None, attrs={'Config': {'Labels': {'ignored': True}}})
            item.reload = lambda: events.append('container-reload')
            item.remove = lambda: events.append('remove-' + ident[0])
            return item
        original, reader = make_item('a' * 64), make_item('b' * 64)
        def shared(client, image, volume, plan):
            plan_box['plan'] = plan
            reader_plan = {**plan, 'container': plan['container'] + '-peer'}
            for item in (original, reader):
                item.attrs['Config']['Labels'] = {proof.OWNER: plan['owner']}
            original.name = plan['container']
            reader.name = reader_plan['container']
            events.append('create-consumers')
            return original, reader, reader_plan
        return original, reader, shared, plan_box

    def run_route(self, case, dispatch_result, *, dispatch_error=None, owner_pair=None):
        original, reader, shared, plan_box = self.resources()
        archive, config = proof.image_archive(self.probe.read_bytes(), proof.names('f' * 32))
        self.archive_config = config
        fake_docker = SimpleNamespace(DockerClient=lambda **kw: self.client())
        # Reuse the real public transcript fixture; do not mock the successor
        # correlation that forbids a substituted storage VM or worker.
        takeover = runpy.run_path(str(ROOT / 'tools/tests/test-managed-takeover-replay.py'))
        initial, successor = owner_pair if owner_pair is not None else takeover['fixture']()[:2]
        if getattr(self, 'substitute_service', False):
            successor = copy.deepcopy(successor)
            successor['boot']['ready']['serviceEpoch'] = str(__import__('uuid').uuid4())
        wire = []
        for value, stamp in ((initial, 'h1'), (successor, 'h2')):
            if value.get('format') == parent.lifecycle.VERSION:
                wire.extend([('state.json',value['checkpoint'],stamp), ('manifest.json',value['manifest'],stamp+'m')])
            else:
                wire.append(('state.json',value,stamp))
        owner_records = iter(wire)
        self.owner_reads = []
        def read_public(path, maximum):
            name, value, stamp = next(owner_records)
            self.assertEqual(path,self.daemon.root/'managed-storage-owner'/name)
            self.assertEqual(maximum,262144)
            self.owner_reads.append(name)
            return copy.deepcopy(value), stamp
        dispatch = self.make_dispatch(case, dispatch_result, dispatch_error)
        FakeDirectory.events = self.events
        FakeDirectory.records = self.records
        # The lazy `import test_managed_prepare_faults` in the parent resolves
        # to this fake: same caller-side interface, no pytest module required.
        @contextmanager
        def bounded_parent(deadline):
            self.events.append('bound-enter')
            self.assertGreater(deadline, parent.time.monotonic())
            try:
                yield
            finally:
                self.events.append('bound-exit')
        fake_fixture = SimpleNamespace(create_shared_consumers=shared, bounded_parent=bounded_parent,
            run_takeover_original_followup=dispatch, run_service_isolation_followup=dispatch)
        with patch.dict(sys.modules, {'docker': fake_docker, 'test_managed_prepare_faults': fake_fixture}), \
             patch.object(harness, 'compatibility_root_retained', return_value=True), \
             patch.object(proof, 'Directory', FakeDirectory), \
             patch.object(parent.lifecycle.recovery, 'read_public', side_effect=read_public), \
             patch.dict(os.environ, {}):
            try:
                report = parent.run_followup_route(self.daemon, case=case, profile=proof.FULL_PROFILE,
                    cases=stale.CASES, probe=self.probe, probe_sha256=self.probe_sha256,
                    source_sha256='a' * 64, expected_commit='c0ffee0', evidence=self.evidence,
                    log=lambda message: self.events.append('log'))
                error = None
            except BaseException as raised:
                report, error = None, raised
        return report, error, plan_box

    def make_dispatch(self, case, result, error):
        def dispatch(daemon, **kwargs):
            self.events.append('dispatch-' + case)
            self.dispatch_kwargs = kwargs
            if error is not None:
                raise error
            kwargs['remaining']()
            return result
        return dispatch

    def test_replayed_takeover_parent_sequence_and_exact_report(self):
        report, error, plan_box = self.run_route('replayed-takeover', REPLAYED_RESULT)
        self.assertIsNone(error)
        plan = plan_box['plan']
        kwargs = self.dispatch_kwargs
        self.assertEqual(kwargs['container'].id, 'a' * 64)
        self.assertEqual(kwargs['reader'].id, 'b' * 64)
        self.assertEqual(kwargs['plan'], plan)
        self.assertEqual(kwargs['reader_plan']['volume'], plan['volume'])
        self.assertIsNot(kwargs['reader_plan'], plan)
        self.assertEqual(kwargs['profile'], proof.FULL_PROFILE)
        self.assertEqual(tuple(kwargs['cases']), stale.CASES)
        self.assertTrue(callable(kwargs['remaining']))
        remaining = kwargs['remaining']()
        self.assertTrue(0 < remaining <= parent.ROUTE_BUDGETS['replayed-takeover'])
        order = ['record:route-plan', 'volume-create', 'create-consumers', 'record:route-fixtures',
                 'dispatch-replayed-takeover', 'remove-a', 'remove-b',
                 'volume-reload', 'volume-remove', 'image-reload', 'image-remove',
                 'record:route-owned-cleanup', 'record:route-result']
        positions = [self.events.index(name) for name in order]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(self.events.count('container-reload'), 2)
        self.assertEqual(self.events.count('record:route-cleanup-intent'), 4)
        self.assertEqual(self.events.count('record:route-cleanup-completed'), 4)
        self.assertEqual(self.events[-2:], ['client-close', 'bound-exit'])
        self.assertLess(self.events.index('bound-enter'), self.events.index('images-load'))
        self.assertNotIn('daemon-restart', self.events)
        self.assertEqual(self.daemon._retain_root, False)
        self.assertEqual(report['rtm'], 'RTM-103')
        self.assertEqual(report['caseName'], 'replayed-takeover')
        self.assertEqual(report['result'], 'followup-route-passed')
        self.assertEqual(report['execution'], 'actual-docker-runtime')
        self.assertEqual(report['executionRoute'], 'two-api-restarts')
        self.assertIs(report['fullAcceptance'], False)
        self.assertIs(report['nativeAcceptance'], False)
        self.assertEqual(report['runID'], str(__import__('uuid').UUID(plan['owner'])))
        self.assertEqual(report['store'], STORE)
        self.assertRegex(report['evidenceSHA256'], r'^[0-9a-f]{64}$')
        self.assertEqual(self.records[-1][0], 'route-result')

    def test_isolation_confirms_c2_before_dispatch(self):
        for case in ('legacy-connection', 'second-service-exclusivity'):
            with self.subTest(case=case):
                self.events, self.records = [], []
                report, error, _ = self.run_route(case, isolation_result(case))
                self.assertIsNone(error)
                self.assertLess(self.events.index('daemon-restart'), self.events.index('dispatch-' + case))
                self.assertEqual(self.events.count('daemon-restart'), 1)
                self.assertIn('record:route-controller-successor', self.events)
                self.assertEqual(self.dispatch_kwargs['case'], case)
                self.assertEqual(report['caseName'], case)
                self.assertEqual(report['executionRoute'], 'service-isolation')
                self.assertEqual(report['result'], 'followup-route-passed')

    def test_isolation_rejects_substituted_service_before_dispatch(self):
        self.substitute_service = True
        report, error, _ = self.run_route('legacy-connection', isolation_result('legacy-connection'))
        self.assertIsNone(report)
        self.assertIsInstance(error, ValueError)
        self.assertTrue(self.daemon._retain_root)
        self.assertNotIn('dispatch-legacy-connection', self.events)
        self.assertNotIn('record:route-result', self.events)

    def test_lifecycle_isolation_reads_real_checkpoint_manifest_and_confirms_once(self):
        for case in ('legacy-connection', 'second-service-exclusivity'):
            with self.subTest(case=case):
                initial, successor, *_ = LIFECYCLE['control_fixture']()
                saved = copy.deepcopy((initial,successor))
                self.events, self.records = [], []
                report, error, _ = self.run_route(case,isolation_result(case),owner_pair=(initial,successor))
                self.assertIsNone(error)
                self.assertEqual(self.owner_reads,['state.json','manifest.json'] * 2)
                self.assertEqual(self.events.count('daemon-restart'),1)
                self.assertLess(self.events.index('daemon-restart'),self.events.index('dispatch-'+case))
                self.assertLess(self.events.index('record:route-controller-successor'),self.events.index('dispatch-'+case))
                self.assertIs(report['nativeAcceptance'],False); self.assertIs(report['fullAcceptance'],False)
                event = next(value for phase,value in self.records if phase == 'route-controller-successor')
                self.assertEqual((event['beforeEpoch'],event['afterEpoch']),(1,2))
                self.assertEqual(event['ownerSHA256'],proof.digest(proof.canonical(dict(state='h2',manifest='h2m'))))
                self.assertEqual((initial,successor),saved)
                self.assertNotIn('transitions',initial); self.assertNotIn('transitions',successor)

    def test_lifecycle_substitutions_never_dispatch_or_claim_acceptance(self):
        for fault in ('service','identity','store','physical','worker','nonadjacent','candidate','incarnation',
                      'pending','completion','mixed'):
            with self.subTest(fault=fault):
                initial, successor, third, *_ = LIFECYCLE['control_fixture']()
                successor = json.loads(json.dumps(successor))  # independent wire DTO fields, no aliases
                state = successor['checkpoint']
                if fault == 'service':
                    successor = replace_metadata(successor,state['currentContext']['serviceEpoch'],LIFECYCLE['uid']())
                elif fault == 'identity':
                    identity = state['identity']
                    successor = replace_metadata(successor,identity,dict(identity,generation=identity['generation']+1))
                elif fault in ('store','physical'):
                    if fault == 'store':
                        successor = replace_metadata(successor,state['identity']['store'],LIFECYCLE['uid']())
                    else:
                        successor['manifest']['backing']['inode'] += 1
                    identity = successor['checkpoint']['identity']
                    binding = proof.digest(b'cengine.storageauthority.binding.v3\0' +
                        proof.canonical(parent.lifecycle.lifecycle.manifest_binding(successor['manifest'])))
                    successor = replace_metadata(successor,identity,dict(identity,binding=binding))
                elif fault == 'worker': state['observedWorker']['workerUUID'] = LIFECYCLE['uid']()
                elif fault == 'nonadjacent': successor = third
                elif fault == 'candidate': state['current']['original']['recipient']['publicKey'] = LIFECYCLE['encoded'](b'x'*32)
                elif fault == 'incarnation':
                    old = state['current']['original']['recipient']['incarnation']
                    successor = replace_metadata(successor,old,initial['checkpoint']['current']['original']['recipient']['incarnation'])
                elif fault == 'pending': state['pendingTakeover'] = dict(uncompleted=True)
                elif fault == 'completion': state['current']['directResult']['grant']['new_key'] = 'f'*64
                else: successor = runpy.run_path(str(ROOT/'tools/tests/test-managed-takeover-replay.py'))['fixture']()[1]
                if fault in ('service','identity','store','physical','worker','nonadjacent','incarnation'):
                    parent.lifecycle.owner(successor)  # coherent but wrong successor, not merely malformed JSON
                self.events, self.records = [], []
                report, error, _ = self.run_route('legacy-connection',isolation_result('legacy-connection'),
                    owner_pair=(initial,successor))
                self.assertIsNone(report); self.assertIsInstance(error,ValueError)
                self.assertEqual(self.events.count('daemon-restart'),1)
                self.assertTrue(self.daemon._retain_root)
                self.assertNotIn('dispatch-legacy-connection',self.events)
                self.assertNotIn('record:route-controller-successor',self.events)
                self.assertNotIn('record:route-result',self.events)
                self.assertNotIn('remove-a',self.events)
                failure = next(value for phase,value in self.records if phase == 'failure')
                self.assertIs(failure['nativeAcceptance'],False); self.assertIs(failure['fullAcceptance'],False)

    def test_lifecycle_initial_owner_and_restart_preconditions_fail_before_restart(self):
        for fault in ('not-c1','pending','budget','dead-before','dead-after'):
            with self.subTest(fault=fault):
                initial, successor, *_ = LIFECYCLE['control_fixture']()
                if fault == 'not-c1': initial = successor
                if fault == 'pending': initial['checkpoint']['pendingTakeover'] = dict(uncompleted=True)
                records = iter([(initial['checkpoint'],'h1'),(initial['manifest'],'h1m'),
                    (successor['checkpoint'],'h2'),(successor['manifest'],'h2m')])
                calls, events = [], []
                def read_public(path, maximum):
                    calls.append(path)
                    return next(records)
                def poll(): return 1 if fault == 'dead-before' or (fault == 'dead-after' and events) else None
                daemon = SimpleNamespace(root=self.daemon.root,process=SimpleNamespace(poll=poll),
                    restart=lambda **kwargs: events.append(('restart',kwargs)))
                with patch.object(parent.lifecycle.recovery,'read_public',side_effect=read_public), self.assertRaises(ValueError):
                    parent.confirm_controller_successor(daemon,remaining=lambda:194 if fault == 'budget' else 195,
                        record=lambda *args,**kwargs:events.append(('record',kwargs)))
                self.assertEqual(events,[('restart',dict(kill=True))] if fault == 'dead-after' else [])
                if fault in ('budget','dead-before'): self.assertEqual(calls,[])

    def test_cleanup_remains_inside_route_deadline(self):
        clock = SimpleNamespace(now=1000.0)
        original_client = self.client
        def late_client():
            client = original_client()
            def remove(image):
                self.events.append('image-remove')
                clock.now += parent.ROUTE_BUDGETS['replayed-takeover'] + 1
            client.images.remove = remove
            return client
        self.client = late_client
        with patch.object(parent.time, 'monotonic', lambda: clock.now):
            report, error, _ = self.run_route('replayed-takeover', REPLAYED_RESULT)
        self.assertIsNone(report)
        self.assertIsInstance(error, ValueError)
        self.assertTrue(self.daemon._retain_root)
        self.assertNotIn('record:route-result', self.events)
        self.assertEqual(self.events[-1], 'bound-exit')

    def test_route_failure_retains_root_and_skips_cleanup(self):
        report, error, _ = self.run_route('replayed-takeover', None, dispatch_error=ValueError('route blew up'))
        self.assertIsNone(report)
        self.assertIsInstance(error, ValueError)
        self.assertEqual(self.daemon._retain_root, True)
        self.assertIn('record:failure', self.events)
        self.assertNotIn('remove-a', self.events)
        self.assertNotIn('record:route-result', self.events)
        phases = [phase for phase, _ in self.records]
        self.assertEqual(phases[-1], 'failure')

    def test_inexact_route_result_is_rejected_and_retained(self):
        bad = dict(REPLAYED_RESULT, backingVerified=False)
        report, error, _ = self.run_route('replayed-takeover', bad)
        self.assertIsNone(report)
        self.assertIsInstance(error, ValueError)
        self.assertEqual(self.daemon._retain_root, True)
        self.assertNotIn('record:route-result', self.events)

    def test_wrong_replayed_case_name_is_rejected(self):
        report, error, _ = self.run_route('replayed-takeover', dict(REPLAYED_RESULT, caseName='legacy-connection'))
        self.assertIsNone(report)
        self.assertIsInstance(error, ValueError)
        self.assertNotIn('remove-a', self.events)
        self.assertTrue(self.daemon._retain_root)

    def test_budget_exhaustion_propagates(self):
        clock = SimpleNamespace(now=1_000.0)
        def late_dispatch(daemon, **kwargs):
            self.events.append('dispatch-replayed-takeover')
            self.dispatch_kwargs = kwargs
            self.assertTrue(kwargs['remaining']() > 0)
            clock.now += parent.ROUTE_BUDGETS['replayed-takeover'] + 1
            with self.assertRaises(ValueError):
                kwargs['remaining']()
            raise LookupError('budget propagation sentinel')
        self.make_dispatch = lambda *a, **k: late_dispatch
        with patch.object(parent.time, 'monotonic', lambda: clock.now):
            report, error, _ = self.run_route('replayed-takeover', REPLAYED_RESULT)
        self.assertIsNone(report)
        self.assertIsInstance(error, LookupError)
        self.assertEqual(self.daemon._retain_root, True)

    def test_closed_selection_and_fixed_budgets(self):
        self.assertEqual(set(parent.ROUTE_BUDGETS), set(followup.FOLLOWUP_CASES))
        self.assertGreaterEqual(parent.ROUTE_BUDGETS['replayed-takeover'], 390)
        for case in ('legacy-connection', 'second-service-exclusivity'):
            self.assertGreaterEqual(parent.ROUTE_BUDGETS[case], parent.RESTART_BOUND)
        for case in followup.FOLLOWUP_CASES:
            self.assertEqual(parent.route_budget(case), parent.ROUTE_BUDGETS[case])
            fake_docker = SimpleNamespace(DockerClient=lambda **kw: None)
            with patch.dict(sys.modules, {'docker': fake_docker}), self.assertRaises(ValueError):
                parent.run_followup_route(self.daemon, case=case, profile='normal', cases=stale.CASES,
                    probe=self.probe, probe_sha256=self.probe_sha256, source_sha256='a' * 64,
                    expected_commit='c0ffee0', evidence=self.evidence)
        with self.assertRaises(ValueError):
            parent.route_budget('cross-e-existing-data')


class RunnerWiringTests(unittest.TestCase):
    def setUp(self):
        self.tree = ast.parse(RUNNER.read_text())

    def test_descriptor_budget_preserves_all_live_evidence_pins(self):
        function = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == 'prepare_descriptor_budget')
        for initial, expected, raises in [((256, 8192), (2048, 8192), False),
                ((4096, 8192), None, False), ((256, -1), (2048, -1), False),
                ((-1, -1), None, False), ((256, 1024), None, True)]:
            with self.subTest(initial=initial):
                current, changes = [initial], []
                def set_limit(kind, value):
                    self.assertEqual(kind, 7)
                    changes.append(value)
                    current[0] = value
                def require(condition, message):
                    if not condition: raise ValueError(message)
                namespace = dict(resource=SimpleNamespace(RLIMIT_NOFILE=7, RLIM_INFINITY=-1,
                    getrlimit=lambda kind: current[0], setrlimit=set_limit), require=require)
                exec(compile(ast.Module(body=[function], type_ignores=[]), str(RUNNER), 'exec'), namespace)
                if raises:
                    with self.assertRaises(ValueError): namespace['prepare_descriptor_budget']()
                else:
                    self.assertEqual(namespace['prepare_descriptor_budget'](), expected[0] if expected else initial[0])
                self.assertEqual(changes, [expected] if expected else [])
        main = ast.unparse(next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main'))
        self.assertLess(main.index('prepare_descriptor_budget()'), main.index('run_cell('))

    def test_campaign_unions_followup_routes_without_changing_implemented(self):
        namespace = {'followup_parent': followup, 'proof': __import__('managed_prepare_faults'),
            'matrix': __import__('managed_prepare_restart_matrix'), 'stale': stale}
        statements = [node for node in self.tree.body if isinstance(node, (ast.Assign, ast.AugAssign))
            and any((isinstance(target, ast.Name) and target.id == 'CAMPAIGNS')
                    or (isinstance(target, ast.Subscript) and ast.unparse(target.value) == 'CAMPAIGNS')
                    for target in (node.targets if isinstance(node, ast.Assign) else [node.target]))]
        self.assertTrue(statements)
        for node in statements:
            exec(compile(ast.Module(body=[node], type_ignores=[]), str(RUNNER), 'exec'), namespace)
        campaigns = namespace['CAMPAIGNS']
        implemented = list(stale.IMPLEMENTED_CASES)
        self.assertEqual(campaigns['RTM-103'][:len(implemented)], implemented)
        self.assertEqual(campaigns['RTM-103'][len(implemented):], list(followup.FOLLOWUP_CASES))
        self.assertEqual(len(campaigns['RTM-103']), len(set(campaigns['RTM-103'])))
        self.assertEqual(tuple(stale.IMPLEMENTED_CASES), tuple(implemented))  # constant itself unchanged
        # RTM-098 is dual-route: strict A4/A5 storage-release claims plus the
        # seven generic checkpoint-exit cuts, in the fixed FULL_CASES order.
        self.assertEqual([c for c in campaigns['RTM-098'] if c in set(namespace['proof'].HELD_STORAGE_CASES)],
            list(namespace['proof'].HELD_STORAGE_CASES))
        self.assertEqual(len(namespace['proof'].CHECKPOINT_EXIT_CASES), 7)
        self.assertEqual(campaigns['RTM-098'], ['normal', 'before-prepare-send', 'guest-accepted-before-prepare',
            'data-partial-frame', 'full-frame-before-admit', 'admitted-queued', 'transaction-published-bind-reply-lost',
            'first-child-published', 'drain-durable-reply-lost'])
        self.assertEqual(len(campaigns['RTM-098']), len(set(campaigns['RTM-098'])))

    def test_worker_campaign_dispatches_admission_and_checkpoint_routes(self):
        run_cell = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run_cell')
        branch = next(node for node in ast.walk(run_cell) if isinstance(node, ast.If) and ast.unparse(node.test) == "rtm == 'RTM-098'")
        text = ast.unparse(ast.Module(body=branch.body, type_ignores=[]))
        self.assertIn('fixture.run_checkpoint_exit_shard if case in proof.CHECKPOINT_EXIT_CASES else fixture.run_worker_admission_shard', text)
        self.assertIn("outcome.get('caseName') == case", text)
        self.assertIn("outcome.get('fullAcceptance') is False", text)
        self.assertIn("'initial-cut-passed'", text)

    def test_run_cell_dispatches_followup_routes_with_exact_report(self):
        run_cell = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run_cell')
        branches = [node for node in ast.walk(run_cell) if isinstance(node, ast.If)]
        followup_branch = next(node for node in branches if 'FOLLOWUP_CASES' in ast.unparse(node.test))
        shard_branch = next(node for node in branches if ast.unparse(node.test) == "rtm == 'RTM-103'")
        self.assertLess(followup_branch.lineno, shard_branch.lineno)
        guard = ast.unparse(followup_branch.test)
        self.assertIn('followup_parent.FOLLOWUP_CASES', guard)
        text = ast.unparse(ast.Module(body=followup_branch.body, type_ignores=[]))
        self.assertIn('followup_parent.run_followup_route(', text)
        self.assertIn("'followup-route-passed'", text)
        self.assertIn("outcome.get('nativeAcceptance') is False", text)
        self.assertNotIn("'case-passed'", text)
        # The existing shard branch keeps its own exact report untouched.
        shard_text = ast.unparse(ast.Module(body=shard_branch.body, type_ignores=[]))
        self.assertIn("'case-passed'", shard_text)
        self.assertNotIn('run_followup_route', shard_text)


if __name__ == '__main__':
    unittest.main()
