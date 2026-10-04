#!/usr/bin/env python3
"""Engine-free RTM097 API A7 checks; no signals, native probes or engines."""
import ast
import base64
import copy
from dataclasses import replace
import json
from pathlib import Path
import runpy
import signal
import stat
import sys
from contextlib import ExitStack
from types import MethodType, ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import managed_prepare_faults as p
import managed_prepare_service_faults as s
from harness import RuntimeProcess
V1 = runpy.run_path(str(ROOT / 'tools/tests/test-managed-prepare-faults.py'))
FIXTURE = ROOT / 'Tests/Compatibility/test_managed_prepare_faults.py'


def uid(): return str(uuid.uuid4())
def encode(value): return base64.b64encode(json.dumps(value).encode()).decode()
def envelope(operation, body, request=None):
    return dict(version='bootstrap.v1', operation=operation, request_id=request or uid(), body=body)


def owners():
    store=uid(); backing=dict(device=3,inode=40,volumeUUID=uid())
    boot=dict(binding=dict(shimLaunchUUID=uid(),guestBootNonce=uid(),ext4UUID=uid(),bytes=4096),
        ready=dict(storeUUID=store,serviceEpoch=uid(),revision=10),diskIdentity=backing)
    old=dict(schema=1,store=store,root=dict(device=3,inode=4,volumeUUID=uid()),backing=backing,bytes=4096,
        revision=10,rootPublicKey=encode('public-only'),journalExpected=True,bootAttempted=True,boot=boot,transitions=[],
        initialReply=encode(envelope('registerInitialController',dict(controller=dict(epoch=1,key='c'*64)))))
    new=copy.deepcopy(old);new['revision']=20
    public=b'public-spki';key=p.digest(public);grant=uid()
    issue=envelope('issueTakeoverGrant',dict(grant_id=grant,store=store,expected_epoch=1,candidate=dict(public_data=base64.b64encode(public).decode())))
    issued=envelope('issueTakeoverGrant',dict(grant=dict(id=grant,store=store,expected_epoch=1,new_key=key),signature=base64.b64encode(b'x'*64).decode()),issue['request_id'])
    confirm=envelope('confirmTakeover',dict(store=store,grant_id=grant,controller=dict(epoch=2,key=key)))
    confirmed=envelope('confirmTakeover',dict(controller=dict(epoch=2,key=key)),confirm['request_id'])
    new['transitions']=[dict(zip(('issue','issued','confirm','confirmed'),map(encode,(issue,issued,confirm,confirmed))))]
    arm=dict(scope=s.owner_context(old)[1])
    return old,new,arm


def production_daemon_start(**bindings):
    tree = ast.parse((ROOT / 'Tests/Compatibility/conftest.py').read_text())
    daemon = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Daemon')
    start = next(n for n in daemon.body if isinstance(n, ast.FunctionDef) and n.name == 'start')
    namespace = dict(bindings)
    exec(compile(ast.Module(body=[start], type_ignores=[]), 'actual-Daemon-start', 'exec'), namespace)
    return namespace['start']


def function(name, **bindings):
    tree=ast.parse(FIXTURE.read_text());nodes=[n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==name]
    assert len(nodes)==1
    constants=[n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NATURAL_FAILURE_CASES' for t in n.targets)]
    namespace=dict(proof=p,**bindings)
    exec(compile(ast.Module(body=[*constants,*nodes],type_ignores=[]),'fixture-only','exec'),namespace)
    return namespace[name]


class ServiceTests(unittest.TestCase):
    def test_registered_api_cut_refuses_ordinary_pytest_before_daemon_setup(self):
        tree = ast.parse(FIXTURE.read_text())
        entry = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                     and n.name == 'test_managed_prepare_api_restart_recovery')
        self.assertEqual(entry.args.args, [])
        self.assertEqual([ast.unparse(n) for n in entry.decorator_list], ["pytest.mark.compat('RTM-097')"])
        self.assertEqual(len(entry.body), 1)
        call = entry.body[0].value
        self.assertEqual(ast.unparse(call.func), 'pytest.fail')
        self.assertIn('initial A7 is not the full host matrix', call.args[0].value)
        self.assertIn('`RTM-097` | `test_managed_prepare_api_restart_recovery`',
                      (ROOT / 'docs/docker-compatibility.md').read_text())

    def test_real_root_history_same_service_fresh_controller(self):
        old,new,arm=owners();before=copy.deepcopy(old)
        context=s.api_owner_transition(old,new,arm)
        self.assertEqual(context['controllerEpoch'],2);self.assertNotEqual(context['controllerKey'],arm['scope']['controllerKey'])
        self.assertEqual(old,before)

    def test_owner_transition_rejects_service_worker_identity_and_history_changes(self):
        old,new,arm=owners()
        mutations=[lambda n:n.update(store=uid()),lambda n:n.update(revision=10),lambda n:n.update(transitions=[]),
            lambda n:n.update(workerReplacements=[{'changed':True}]),lambda n:n['boot']['ready'].update(serviceEpoch=uid()),
            lambda n:n['boot']['binding'].update(guestBootNonce=uid()),lambda n:n['backing'].update(inode=41),
            lambda n:n.update(pendingIssue='unknown')]
        for mutate in mutations:
            bad=copy.deepcopy(new);mutate(bad)
            with self.assertRaises((ValueError,KeyError)):s.api_owner_transition(old,bad,arm)
        arm['scope']['controllerKey']='0'*64
        with self.assertRaises(ValueError):s.api_owner_transition(old,new,arm)

    def test_retry_fresh_credentials_exact_controller_and_old_context_default_unchanged(self):
        old,_,_,capture,candidate=V1['values']();candidate.update(version=3,profile=p.FULL_PROFILE)
        context={k:old[k] for k in ('store','serviceEpoch','controllerEpoch','controllerKey')};context.update(controllerEpoch=2,controllerKey='2'*64)
        candidate['scope'].update(controllerEpoch=2,controllerKey='2'*64)
        with self.assertRaises(ValueError):p.full_arm_candidate(candidate,capture,old,'normal')
        arm=p.full_arm_candidate(candidate,capture,old,'normal',controller_recovery=context)
        self.assertEqual(arm['scope']['controllerEpoch'],2)
        for field,value in [('serviceEpoch',uid()),('store',uid()),('controllerEpoch',True),('controllerEpoch',3),('controllerKey',old['controllerKey'])]:
            bad={**context,field:value}
            with self.assertRaises(ValueError):p.full_arm_candidate(candidate,capture,old,'normal',controller_recovery=bad)
        with self.assertRaises(ValueError):p.full_arm_candidate(candidate,capture,old,'first-child-published',controller_recovery=context)
        candidate['credentials'][0]['key']=old['slots'][0]['key']
        with self.assertRaises(ValueError):p.full_arm_candidate(candidate,capture,old,'normal',controller_recovery=context)

    def test_closed_selector_never_dispatches_old_profiles(self):
        calls=[];run=function('run_api_a7_shard',_run_prepare_case=lambda *a,**k:calls.append(k))
        args=dict(probe=None,probe_sha256=None,source_sha256=None,expected_commit=None,evidence=None)
        for profile in (p.PROFILE,p.EARLY_PROFILE,None):
            with self.assertRaises(ValueError):run(None,profile=profile,**args)
        self.assertFalse(calls)
        run(None,profile=p.FULL_PROFILE,**args)
        self.assertTrue(calls[0]['api_restart']);self.assertFalse(calls[0]['staged']['fullAcceptance'])

    def test_only_exact_sdk_connection_loss_is_52_and_always_closes(self):
        docker=ModuleType('docker');requests=ModuleType('requests.exceptions')
        RequestLoss=type('ConnectionError',(Exception,),{'__module__':'requests.exceptions'})
        Lookalike=type('ConnectionError',(Exception,),{'__module__':'requests.exceptions'})
        requests.ConnectionError=RequestLoss;docker.errors=SimpleNamespace(APIError=type('APIError',(Exception,),{}))
        start=function('_docker_start')
        for kind in (RequestLoss,Lookalike,ConnectionError,TimeoutError,RuntimeError):
            client=Mock();client.api.start.side_effect=kind('secret');docker.DockerClient=Mock(return_value=client)
            with patch.dict(sys.modules,{'docker':docker,'requests.exceptions':requests}):
                if kind is RequestLoss:self.assertEqual(start('/socket','a'*64),52)
                else:
                    with self.assertRaises(kind):start('/socket','a'*64)
            client.close.assert_called_once_with()

    def test_exact_disconnect_join_never_accepts_http_error_or_arbitrary_failure(self):
        for failed in (False,True):
            for code in (0,1,49,50,51,52,255,-9):
                log=Mock();proc=Mock();proc.wait.return_value=code
                joined=function('joined_start',signal=signal,early=True,fault_case='first-child-published',io_case=None,remaining=lambda:1,record=log)
                if code==(52 if failed else 0):joined(proc,failed=failed,disconnected=True)
                else:
                    with self.assertRaises(ValueError):joined(proc,failed=failed,disconnected=True)
                log.assert_called_once_with('docker-start-joined',failed=failed,returncode=code, diagnostic="UNKNOWN")

    def test_api_target_requires_actual_unreaped_child_exact_role_paths_and_birth(self):
        d=SimpleNamespace(binary=Path('/owned/cengine'),root=Path('/owned/root'),socket=Path('/owned/run/socket'),
            kernel=Path('/assets/kernel'),container_initramfs=Path('/assets/init'),storage_initramfs=Path('/assets/storage'),process=Mock(pid=42))
        d.process.poll.return_value=None
        args=('/owned/cengine','daemon','--root','/owned/root','--socket','/owned/run/socket','--kernel','/assets/kernel','--container-initramfs','/assets/init','--storage-initramfs','/assets/storage','--automatic-ipv4-pool','10.0.0.0/8','--automatic-ipv6-prefix','fdcc::/16')
        proc=RuntimeProcess(42,executable='/owned/cengine',arguments=args,identity=(10,2,300),pidversion=8)
        self.assertEqual(s.api_target(d,proc),proc)
        for bad in (replace(proc,pid=43),replace(proc,identity=None),replace(proc,pidversion=0),replace(proc,arguments=args+('extra',)),replace(proc,arguments=tuple('wrong' if a=='/owned/root' else a for a in args))):
            with self.assertRaises(ValueError):s.api_target(d,bad)
        d.process.poll.return_value=-9
        with self.assertRaises(ValueError):s.api_target(d,proc)

    def storage_values(self, root=Path('/owned/root')):
        owner, _ = s.owner_context(owners()[0])
        daemon = SimpleNamespace(binary=Path('/owned/cengine'), root=root)
        root = s.runtime_root_path(root)
        generation = root / 'infrastructure/storage-shim-generations' / owner['shimLaunchUUID']
        digest = 'a' * 64
        proc = RuntimeProcess(55, executable=str(daemon.binary), identity=(100, 2, 300), pidversion=8,
            arguments=(str(daemon.binary), 'vm-shim', '--spec', str(generation / 'spec.json'), '--spec-sha256', digest, '--storage-disk-fd', '9'))
        spec = dict(kind='storage', containerID='cengine-storage', storageStartupMode='managed', shimLaunchUUID=owner['shimLaunchUUID'],
            rootDiskPath=str(root / 'infrastructure/volumes.ext4'), rootDiskIdentity=owner['backing'], rootDiskSize=owner['bytes'],
            rootDiskReadOnly=False, volumeDisks=[], bindShares=[])
        launch = dict(intent=dict(specificationSHA256=digest, launchUUID=owner['shimLaunchUUID']),
            process=dict(pid=55, startSeconds=100, startMicroseconds=2, uniqueID=300))
        disk = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_dev=3, st_ino=40, st_size=4096)
        return dict(daemon=daemon, owner=owner, root=root, generation=generation, proc=proc,
            spec=spec, digest=digest, launch=launch, disk=disk)

    def select_storage(self, value, census=None):
        v = value
        with patch.object(s, 'read_public') as reads, patch.object(Path, 'lstat') as lstat:
            with self.assertRaisesRegex(ValueError, 'lifecycle-v2 storage owner required'):
                s.storage_target(v['daemon'], v['owner'], [v['proc']] if census is None else census)
            reads.assert_not_called(); lstat.assert_not_called()

    def test_storage_target_rejects_legacy_owner_before_native_selection(self):
        for root in (Path('/owned/root'), Path('/private/tmp/owned/root')):
            self.select_storage(self.storage_values(root))

    def test_legacy_storage_target_cannot_gain_authority_from_census(self):
        v = self.storage_values()
        for census in ([], [v['proc']], [v['proc'], v['proc']]):
            self.select_storage(v, census)

    def test_legacy_storage_target_cannot_be_relabeled_as_current_spec(self):
        v = self.storage_values(); del v['spec']['storageStartupMode']
        self.select_storage(v)

    def test_sdk_versions_are_bounded_loaded_module_evidence(self):
        docker, requests = ModuleType('docker'), ModuleType('requests')
        docker.__version__, requests.__version__ = '7.1.0', '2.32.3'
        with patch.dict(sys.modules, {'docker':docker, 'requests':requests}):
            self.assertEqual(s.sdk_versions(), {'docker':'7.1.0', 'requests':'2.32.3'})
            for module in (docker, requests):
                original = module.__version__
                for value in (None, True, b'7.1.0', '', '7.1.0\nsecret', '7.1.0/'+('x'*10), '1.0'+'a'*62, '１.０'):
                    module.__version__ = value
                    with self.subTest(value=value), self.assertRaises(ValueError): s.sdk_versions()
                del module.__version__
                with self.assertRaises(ValueError): s.sdk_versions()
                module.__version__ = original

    def test_api_branch_does_not_signal_workload_or_mutate_journals(self):
        tree=ast.parse(FIXTURE.read_text());run=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_run_prepare_case')
        branches=[n for n in ast.walk(run) if isinstance(n,ast.If) and isinstance(n.test,ast.Name) and n.test.id=='api_restart']
        branch=next(n for n in branches if 'restart_api_at_a7' in ast.unparse(ast.Module(body=n.body,type_ignores=[])))
        text=ast.unparse(ast.Module(body=branch.body,type_ignores=[]))
        self.assertNotIn('SIGKILL',text);self.assertNotIn('publish(',text)
        self.assertIn('restart_api_at_a7',text)
        body=ast.parse((ROOT/'Tests/Compatibility/managed_prepare_service_faults.py').read_text())
        restart=next(n for n in body.body if isinstance(n,ast.FunctionDef) and n.name=='restart_api_at_a7')
        calls=[n for n in ast.walk(restart) if isinstance(n,ast.Call)]
        stops=[n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='stop']
        self.assertEqual(len(stops),1);self.assertEqual(ast.unparse(stops[0]),'daemon.stop(kill=True)')
        self.assertLess(next(n.lineno for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='verify_full_ledger'),stops[0].lineno)
        self.assertNotIn('write_text',ast.unparse(restart));self.assertNotIn('os.kill',ast.unparse(restart))
        self.assertIn('unchanged_processes(census, processes(), api)',ast.unparse(restart))


class RestartTests(unittest.TestCase):
    def run_restart(self, fault=None):
        """Whole restart helper + actual Daemon.start body; all OS/SDK edges doubled."""
        old, new, _ = owners()
        vector = next(v for v in json.loads((ROOT / 'Guest/internal/preparecompat/testdata/full-vectors.json').read_text()) if v['name'] == 'first-child-published')
        arm, checkpoint = copy.deepcopy(vector['arm']), copy.deepcopy(vector['observation'])
        arm['scope'].update(s.owner_context(old)[1])
        checkpoint['armDigest'] = p.digest(p.canonical(arm))
        intent = {('id' if k == 'intent' else k): v for k, v in arm['scope'].items()}
        intent.update(phase='prepareAdmitted', prepareCompleted=False, slots=arm['slots'])
        d = SimpleNamespace(binary=Path('/owned/cengine'), root=Path('/owned/root'), socket=Path('/owned/run/socket'),
            kernel=Path('/assets/kernel'), container_initramfs=Path('/assets/init'), storage_initramfs=Path('/assets/storage'),
            work=Path('/owned'), log_path=Mock(), resource_update_failure_file=Path('/owned/failure'), root_retained=True)
        args = ('/owned/cengine', 'daemon', '--root', '/owned/root', '--socket', '/owned/run/socket', '--kernel', '/assets/kernel',
            '--container-initramfs', '/assets/init', '--storage-initramfs', '/assets/storage', '--automatic-ipv4-pool', '10.192.0.0/12',
            '--automatic-ipv6-prefix', 'fdcc::/16')
        api = RuntimeProcess(42, executable='/owned/cengine', arguments=args, identity=(10, 2, 300), pidversion=8)
        fresh = replace(api, pid=43, identity=(11, 3, 301), pidversion=9)
        workload = RuntimeProcess(44, identity=(10, 4, 302), pidversion=10)
        storage = RuntimeProcess(45, identity=(10, 5, 303), pidversion=11)
        census = [api, workload, storage]; live = {v.pid: v for v in census}
        events, order, records = [], [], []
        waiter = Mock()
        def control(changes, maximum, timeout=None):
            if changes is not None:
                self.assertEqual(changes[0].ident, workload.pid)
                order.append('watch-installed'); return []
            if timeout == 0: order.append('watch-check')
            result = events[:maximum]; del events[:maximum]
            return result
        waiter.control.side_effect = control
        def workload_exit():
            live.pop(workload.pid, None)
            events.append(SimpleNamespace(ident=workload.pid, filter=s.select.KQ_FILTER_PROC, flags=0, fflags=s.select.KQ_NOTE_EXIT))
            order.append('workload-exit')
        old_handle = Mock(pid=api.pid, returncode=None); old_handle.poll.return_value = None
        fresh_handle = Mock(pid=fresh.pid, returncode=None); fresh_handle.poll.return_value = None
        d.process = old_handle
        def stop(*, kill=False):
            order.append('api-stop')
            live.pop(d.process.pid, None); d.process.returncode = -signal.SIGKILL if kill else -signal.SIGTERM
            d.process.poll.return_value = d.process.returncode
        d.stop = Mock(side_effect=stop); d.retain_root = Mock()
        def spawned(*args, **kwargs):
            if fault == 'exit-before-birth': workload_exit()
            order.append('api-spawn'); live[fresh.pid] = fresh
            return fresh_handle
        def ready(*args, **kwargs):
            order.append('api-readiness')
            self.assertIn('api-replacement-born', order)
            if fault == 'startup-failure': raise RuntimeError('startup failure')
            workload_exit()
            if fault == 'wrong-exit': events[0].ident += 10
            if fault == 'error-exit': events[0].flags = s.select.KQ_EV_ERROR
            if fault == 'storage-change': live[storage.pid] = replace(storage, identity=(12, 6, 400), pidversion=20)
            return SimpleNamespace(returncode=0, stdout='OK')
        subprocess = SimpleNamespace(Popen=Mock(side_effect=spawned), run=Mock(side_effect=ready), DEVNULL=-3, STDOUT=-2, PIPE=-1)
        capture = ModuleType('storage_backend_proof'); capture.capture_backend_root = Mock()
        docker, requests = ModuleType('docker'), ModuleType('requests')
        docker.__version__, requests.__version__ = '7.1.0', '2.32.3'
        def fail(*args, **kwargs): raise RuntimeError('retained startup failure')
        d._qualify_root_permissions = False
        d.start = MethodType(production_daemon_start(subprocess=subprocess, time=SimpleNamespace(monotonic=lambda:1, sleep=Mock()),
            os=SimpleNamespace(environ={}), managed_storage_arguments=lambda _:[],
            compatibility_environment=lambda:{}, pytest=SimpleNamespace(fail=fail), terminate_compatibility_runtime=Mock()), d)
        def record(phase, **value):
            order.append(phase); records.append((phase, value))
            if phase == 'api-only-death-joined' and fault == 'exit-before-start': workload_exit()
        def native(pid):
            value = live.get(pid)
            if pid == workload.pid and 'watch-check' in order and fault == 'exit-during-birth':
                workload_exit(); return None
            if pid == fresh.pid and fault == 'bad-api-birth': return replace(fresh, identity=None)
            if pid == fresh.pid and fault == 'exit-during-birth-lookup':
                # A same-identity zombie-like native result is not proof of life.
                events.append(SimpleNamespace(ident=workload.pid, filter=s.select.KQ_FILTER_PROC, flags=0, fflags=s.select.KQ_NOTE_EXIT))
            return value
        directory = Mock(); directory.__enter__ = Mock(return_value=directory); directory.__exit__ = Mock(return_value=False)
        directory.fd = 999; directory.read.return_value = (b'/owned/cengine\n', None)
        directories = Mock(return_value=directory); directories.stamp.return_value = (3, 4)
        state_reads = [(old, p.digest(p.canonical(old))), (new, p.digest(p.canonical(new)))]
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {'storage_backend_proof':capture, 'docker':docker, 'requests':requests}))
            stack.enter_context(patch.object(s.select, 'kqueue', return_value=waiter))
            stack.enter_context(patch.object(s.select, 'kevent', side_effect=lambda ident, **kw: SimpleNamespace(ident=ident, **kw)))
            stack.enter_context(patch.object(s.p, 'Directory', directories))
            stack.enter_context(patch.object(s.os, 'fstat', return_value=None))
            stack.enter_context(patch.object(s.p, 'verify_full_ledger', side_effect=lambda *_:order.append('ledger-verified')))
            stack.enter_context(patch.object(s, 'storage_target', return_value=storage))
            stack.enter_context(patch.object(s, 'read_public', side_effect=state_reads))
            stack.enter_context(patch('harness._kernel_process', side_effect=native))
            stack.enter_context(patch.object(Path, 'unlink'))
            stack.enter_context(patch.object(Path, 'exists', return_value=True))
            try:
                result = s.restart_api_at_a7(d, workload, census, intent, arm, checkpoint, None, {}, record,
                    lambda:list(live.values()), lambda:1)
            finally:
                waiter.close.assert_called_once_with()
        self.assertEqual(result[0], [fresh, workload, storage])
        self.assertEqual(result[1], s.owner_context(new)[1])
        self.assertEqual(result[2], (new, p.digest(p.canonical(new))))
        d.stop.assert_called_once_with(kill=True)
        self.assertEqual(dict(records)['api-SIGKILL-intent']['sdkVersions'], {'docker':'7.1.0', 'requests':'2.32.3'})
        self.assertLess(order.index('watch-installed'), order.index('api-stop'))
        self.assertLess(order.index('ledger-verified'), order.index('api-stop'))
        self.assertLess(order.index('api-spawn'), order.index('api-replacement-born'))
        self.assertLess(order.index('api-replacement-born'), order.index('workload-exit'))
        self.assertLess(order.index('workload-exit'), order.index('api-reconciled'))
        return result

    def test_complete_restart_with_actual_daemon_start_and_real_record_validators(self):
        self.run_restart()

    def test_exit_before_or_during_birth_observation_never_passes(self):
        for fault in ('exit-before-start', 'exit-before-birth', 'exit-during-birth', 'exit-during-birth-lookup'):
            with self.subTest(fault=fault), self.assertRaises(RuntimeError): self.run_restart(fault)

    def test_bad_birth_startup_and_exit_evidence_fail_closed(self):
        for fault in ('bad-api-birth', 'startup-failure', 'wrong-exit', 'error-exit', 'storage-change'):
            with self.subTest(fault=fault), self.assertRaises((ValueError, RuntimeError)): self.run_restart(fault)

    def test_final_owner_requires_exact_record_and_hash(self):
        _, new, _ = owners(); stamp = p.digest(p.canonical(new)); daemon = SimpleNamespace(root=Path('/owned/root'))
        with patch.object(s, 'read_public', return_value=(copy.deepcopy(new), stamp)):
            self.assertEqual(s.verify_api_owner_final(daemon, (new, stamp)), stamp)
        changes = [lambda n:n.update(revision=n['revision']+1), lambda n:n.update(workerReplacements=[{}]),
            lambda n:n.update(serviceTransitions=[{}]), lambda n:n['backing'].update(inode=41),
            lambda n:n.update(pendingIssue='unexpected')]
        for change in changes:
            current=copy.deepcopy(new);change(current)
            with patch.object(s, 'read_public', return_value=(current,p.digest(p.canonical(current)))):
                with self.assertRaises((ValueError, KeyError)):s.verify_api_owner_final(daemon,(new,stamp))
        with patch.object(s, 'read_public', return_value=(new, '0'*64)):
            with self.assertRaises(ValueError):s.verify_api_owner_final(daemon,(new,stamp))

    def test_final_owner_rejects_valid_extra_controller_takeover(self):
        old, new, arm = owners(); later=copy.deepcopy(new)
        public=b'next-public'; key=p.digest(public); grant=uid(); store=old['store']
        issue=envelope('issueTakeoverGrant',dict(grant_id=grant,store=store,expected_epoch=2,candidate=dict(public_data=base64.b64encode(public).decode())))
        issued=envelope('issueTakeoverGrant',dict(grant=dict(id=grant,store=store,expected_epoch=2,new_key=key),signature=base64.b64encode(b'y'*64).decode()),issue['request_id'])
        confirm=envelope('confirmTakeover',dict(store=store,grant_id=grant,controller=dict(epoch=3,key=key)))
        confirmed=envelope('confirmTakeover',dict(controller=dict(epoch=3,key=key)),confirm['request_id'])
        later['transitions'].append(dict(zip(('issue','issued','confirm','confirmed'),map(encode,(issue,issued,confirm,confirmed)))))
        later['revision']+=1
        self.assertEqual(s.owner_context(later)[1]['controllerEpoch'],3)
        s.api_owner_transition(old,new,arm)
        with patch.object(s,'read_public',return_value=(later,p.digest(p.canonical(later)))):
            with self.assertRaises(ValueError):s.verify_api_owner_final(SimpleNamespace(root=Path('/owned/root')),(new,p.digest(p.canonical(new))))

    def test_final_owner_recheck_follows_all_owned_cleanup_before_result(self):
        tree=ast.parse(FIXTURE.read_text())
        body=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_run_prepare_case')
        calls=[n for n in ast.walk(body) if isinstance(n,ast.Call)]
        recheck=next(n for n in calls if isinstance(n.func,ast.Name) and n.func.id=='verify_api_owner_final')
        cleanup=next(n for n in calls if isinstance(n.func,ast.Name) and n.func.id=='record' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='owned-cleanup')
        result=next(n for n in calls if isinstance(n.func,ast.Name) and n.func.id=='record' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='service-cut-result')
        self.assertLess(cleanup.lineno,recheck.lineno);self.assertLess(recheck.lineno,result.lineno)


if __name__=='__main__':unittest.main()
