#!/usr/bin/env python3
"""Native engine-free regression tests. No Docker/VM/network commands."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / 'volume_reference_probe.py'
spec = importlib.util.spec_from_file_location('probe',PATH)
assert spec is not None and spec.loader is not None
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
RUN='7ca0df3f-e945-4d97-b6ec-b787dbc2d730'
PROOF='24299546-784f-42d2-969b-179232199f62'
IMAGE='sha256:'+'a'*64
CID='b'*64


def backend(kind='ext4',boot=RUN):
    return {'statfs':{'ext4':'ef53','virtiofs':'65735546'}[kind], 'boot_id':boot,
            'kernel':'test-kernel','mountinfo':f'32 1 0:33 / /work rw - {kind} test rw\n'}


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='vrp-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.log=p.Ledger(self.root/'proof',{'phase':'new','mode':'bind','run_id':RUN,'proof_id':PROOF,'containers':[]})
        self.args=SimpleNamespace(run_id=RUN,proof_id=PROOF,expected_daemon_id='daemon',endpoint='unix:///owned')
        self.ref=Mock()
        self.ref.state={'phase':'ready','run_id':RUN,'daemon_id':'daemon','endpoint':'unix:///owned',
                        'engine_version':'29.2.1','same_path_fixture':True,'fixture':True}
        self.ref.socket=self.root/'owned.sock'
        self.parent=Mock()
        self.transport=Mock(return_value=(200,b'{}'))
        self.probe=p.Probe(self.ref,self.args,self.parent,self.log,self.transport)

    def test_parent_lock_requires_live_calling_owner_never_steals(self):
        lock=self.root/'cengine-compat-run.lock'; lock.mkdir(mode=0o700)
        (lock/'pid').write_text(str(os.getppid())+'\n')
        parent=p.ParentLock(lock,os.getppid()); parent.check()
        with self.assertRaises(p.ref.Refusal): p.ParentLock(lock,os.getpid())
        (lock/'pid').write_text('1\n')
        with self.assertRaises(p.ref.Refusal): parent.check()
        self.assertTrue(lock.exists())

    def test_parent_lock_replacement_refused(self):
        lock=self.root/'cengine-compat-run.lock'; lock.mkdir(mode=0o700)
        (lock/'pid').write_text(str(os.getppid()))
        parent=p.ParentLock(lock,os.getppid())
        (lock/'pid').rename(lock/'old'); (lock/'pid').write_text(str(os.getppid()))
        with self.assertRaises(p.ref.Refusal): parent.check()

    def test_ledger_reopen_and_event_tampering(self):
        self.log.event('test',n=1)
        reopened=p.Ledger(self.log.root)
        self.assertEqual(reopened.state,self.log.state)
        (self.log.root/'event-0000.json').write_bytes(b'{}')
        with self.assertRaises(p.ref.Refusal): p.Ledger(self.log.root)

    def test_ledger_artifact_tampering(self):
        self.log.file('probe',b'local binary')
        (self.log.root/'probe').write_bytes(b'altered')
        with self.assertRaises(p.ref.Refusal): p.Ledger(self.log.root)

    def test_ledger_refuses_symlink_artifact_and_existing_root(self):
        (self.log.root/'probe').symlink_to(self.root/'outside')
        with self.assertRaises((OSError,p.ref.Refusal)): self.log.file('probe',b'never follows')
        self.assertFalse((self.root/'outside').exists())
        with self.assertRaises(FileExistsError): p.Ledger(self.log.root,{'phase':'new'})

    def test_identity_failures_before_transport(self):
        for key,value in [('run_id','wrong'),('daemon_id','wrong'),('endpoint','unix:///foreign'),
                          ('engine_version','29.3.0'),('phase','crashed')]:
            with self.subTest(key=key), patch.dict(self.ref.state,{key:value}):
                with self.assertRaises(p.ref.Refusal): self.probe.api('GET','/info')
        self.transport.assert_not_called()

    def test_reference_tamper_guard_before_transport(self):
        self.ref.guard.side_effect=p.ref.Refusal('tamper')
        with self.assertRaises(p.ref.Refusal): self.probe.api('GET','/info')
        self.transport.assert_not_called()

    def test_ambient_context_cannot_select_target(self):
        with patch.dict(os.environ,{'DOCKER_HOST':'unix:///foreign','DOCKER_CONTEXT':'production',
                                    'HTTP_PROXY':'http://invalid','COLIMA_HOME':'/foreign'}):
            self.probe.api('GET','/info')
        args=self.transport.call_args.args
        self.assertEqual(args[:3],(self.ref.socket,'GET','/v1.52/info'))
        self.assertLessEqual(args[-1],60)

    def test_pull_build_prune_and_arbitrary_commands_refused(self):
        for method,path in [('POST','/images/create?fromImage=alpine'),('POST','/build'),
                            ('POST','/volumes/prune'),('POST','/containers/prune'),
                            ('DELETE','/containers/'+CID+'?force=1'),('GET','http://foreign/info')]:
            with self.assertRaises(p.ref.Refusal): self.probe.api(method,path)
        with self.assertRaises(p.ref.Refusal): self.probe.execute(CID,'sh','-c','bad')
        self.transport.assert_not_called()
        with self.assertRaises(p.ref.Refusal): p.container_config('alpine:latest',{}, {})

    def test_hard_container_bounds(self):
        config=p.container_config(IMAGE,{}, {'Type':'volume'})
        h=config['HostConfig']
        self.assertEqual(h['NanoCpus'],2_000_000_000)
        self.assertEqual(h['Memory'],768*p.MIB)
        self.assertEqual(h['MemorySwap'],h['Memory'])
        self.assertEqual(h['PidsLimit'],128)
        self.assertEqual(h['NetworkMode'],'none')
        self.assertTrue(h['ReadonlyRootfs'])
        self.assertEqual(h['CapDrop'],['ALL'])
        self.assertEqual(h['RestartPolicy'],{'Name':'no','MaximumRetryCount':0})

    def inspected_container(self, kind='bind', readonly=False):
        mount={'Type':kind,'Source':str(self.root/'fixture') if kind=='bind' else 'vrp-'+PROOF,
               'Target':'/work','ReadOnly':readonly}
        config=p.container_config(IMAGE,self.probe.labels,mount)
        actual={'Type':kind,'Destination':'/work','RW':not readonly}
        actual.update({'Source':mount['Source']} if kind=='bind' else {'Name':mount['Source'],'Driver':'local'})
        obj={'Id':CID,'Image':IMAGE,'Config':copy.deepcopy(config),'HostConfig':copy.deepcopy(config['HostConfig']),
             'State':{'Running':False},'NetworkSettings':{'Networks':{}},'Mounts':[actual]}
        return mount,config,obj

    def assert_capabilities_refused_before_start(self, kind, key, value):
        self.log.state.update(image=IMAGE,containers=[],running=None,phase='qualify-running' if kind=='bind' else 'seed-running')
        mount,_,obj=self.inspected_container(kind)
        obj['HostConfig'][key]=value
        self.transport.reset_mock()
        self.transport.side_effect=[(201,p.encoded({'Id':CID})),(200,p.encoded(obj))]
        with self.assertRaisesRegex(p.ref.Refusal,'capability allowance'):
            self.probe.container(mount)
        self.assertEqual([call.args[1] for call in self.transport.call_args_list],['POST','GET'])
        self.assertTrue(self.transport.call_args_list[0].args[2].startswith('/v1.52/containers/create?'))
        self.assertEqual(self.transport.call_args_list[1].args[2],'/v1.52/containers/'+CID+'/json')
        self.assertEqual(self.log.state['containers'],[CID])
        self.assertIsNone(self.log.state['running'])

    def test_bind_qualification_adds_only_dac_override(self):
        _,config,_=self.inspected_container()
        self.assertEqual(config['HostConfig']['CapAdd'],['DAC_OVERRIDE'])
        self.assertEqual(config['HostConfig']['CapDrop'],['ALL'])
        self.assertEqual(config['User'],'0:0')
        self.assertFalse(config['HostConfig']['Privileged'])

    def test_volume_seed_and_readonly_verify_add_no_capabilities(self):
        for readonly in (False,True):
            _,config,_=self.inspected_container('volume',readonly)
            self.assertEqual(config['HostConfig']['CapAdd'],[])
            self.assertEqual(config['HostConfig']['CapDrop'],['ALL'])

    def test_capability_config_refuses_unknown_mount_types(self):
        for mount in ({},{'Type':'tmpfs'},{'Type':'unknown'}):
            with self.assertRaises(p.ref.Refusal): p.container_config(IMAGE,{},mount)

    def test_inspect_accepts_only_bind_dac_override_spellings(self):
        mount,config,obj=self.inspected_container()
        for caps in (['DAC_OVERRIDE'],['CAP_DAC_OVERRIDE']):
            obj['HostConfig']['CapAdd']=caps
            p.validate_container(obj,config,mount,running=False)

    def test_inspect_accepts_volume_empty_null_or_absent_caps(self):
        mount,config,obj=self.inspected_container('volume')
        for caps in ([],None):
            obj['HostConfig']['CapAdd']=caps
            p.validate_container(obj,config,mount,running=False)
        del obj['HostConfig']['CapAdd']
        p.validate_container(obj,config,mount,running=False)

    def test_missing_bind_override_rejected_before_start(self):
        for caps in (None,[]):
            with self.subTest(caps=caps):
                self.assert_capabilities_refused_before_start('bind','CapAdd',caps)
        mount,config,obj=self.inspected_container()
        del obj['HostConfig']['CapAdd']
        with self.assertRaises(p.ref.Refusal): p.validate_container(obj,config,mount,running=False)

    def test_extra_or_wrong_caps_rejected_before_start(self):
        for kind in ('bind','volume'):
            for caps in (['ALL'],['SYS_ADMIN'],['DAC_READ_SEARCH'],['UNKNOWN'],
                         ['DAC_OVERRIDE','CHOWN'],['CAP_DAC_OVERRIDE','CAP_SYS_ADMIN'],
                         ['DAC_OVERRIDE','DAC_OVERRIDE']):
                with self.subTest(kind=kind,caps=caps):
                    self.assert_capabilities_refused_before_start(kind,'CapAdd',caps)
        for caps in (['DAC_OVERRIDE'],['CAP_DAC_OVERRIDE']):
            self.assert_capabilities_refused_before_start('volume','CapAdd',caps)

    def test_malformed_caps_rejected_before_start(self):
        for kind in ('bind','volume'):
            for caps in ('DAC_OVERRIDE','',{},False,0,[None]):
                with self.subTest(kind=kind,caps=caps):
                    self.assert_capabilities_refused_before_start(kind,'CapAdd',caps)

    def test_cap_drop_all_required_before_start(self):
        for kind in ('bind','volume'):
            for caps in (None,[],['CHOWN'],['ALL','NET_ADMIN']):
                with self.subTest(kind=kind,caps=caps):
                    self.assert_capabilities_refused_before_start(kind,'CapDrop',caps)

    def test_runtime_caps_and_unknown_mount_type_fail_closed(self):
        mount,config,obj=self.inspected_container()
        obj['State']['Running']=True
        obj['HostConfig']['CapAdd']=['DAC_OVERRIDE','SYS_ADMIN']
        with self.assertRaises(p.ref.Refusal): p.validate_container(obj,config,mount,running=True)
        obj['HostConfig']['CapAdd']=['DAC_OVERRIDE']
        mount['Type']='tmpfs'
        with self.assertRaises(p.ref.Refusal): p.validate_container(obj,config,mount,running=True)

    def test_owned_bind_fixture_permissions_remain_private(self):
        directory=self.root/'fixture'; p.ref.private_directory(directory)
        p.ref.write_new(directory/'host',b'private')
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE((directory/'host').stat().st_mode),0o600)
        self.assertEqual(directory.stat().st_uid,os.getuid())
        self.assertEqual((directory/'host').stat().st_uid,os.getuid())

    def test_api_bounds(self):
        self.probe.deadline=0
        with self.assertRaises(p.ref.Refusal): self.probe.api('GET','/info')
        self.transport.assert_not_called()
        self.probe.deadline=float('inf'); self.probe.calls=180
        with self.assertRaises(p.ref.Refusal): self.probe.api('GET','/info')
        self.probe.calls=0; self.transport.return_value=(200,b'x'*(p.MIB+1))
        with self.assertRaises(p.ref.Refusal): self.probe.api('GET','/info')

    def test_request_fsync_failure_prevents_api(self):
        with patch.object(p.ref,'sync_directory',side_effect=OSError('EIO')):
            with self.assertRaises(OSError): self.probe.api('POST','/volumes/create',{})
        self.transport.assert_not_called()

    def test_uncertain_create_records_intent_no_query_adopt(self):
        self.log.state['image']=IMAGE
        self.transport.side_effect=TimeoutError('uncertain response')
        with self.assertRaises(TimeoutError):
            self.probe.container({'Type':'volume','Source':'owned','ReadOnly':False})
        self.assertEqual(self.transport.call_count,1)
        self.assertEqual(self.log.state['containers'],[])
        self.assertEqual(json.loads((self.log.root/'event-0000.json').read_text())['kind'],'request')

    def seed_setup(self):
        self.log.state.update(image=IMAGE,containers=[CID],phase='seed-running')
        self.probe.volume=Mock(return_value='vrp-'+PROOF)
        self.probe.container=Mock(return_value=CID)
        self.probe.backend=Mock(return_value=backend())
        manifest={'files':{'x':{'size':5}},'root_xattrs':{'user.fixture':''}}
        ack={'ACK':True,'operation_bytes':5,'backend':backend(),'manifest':manifest}
        self.probe.execute=Mock(side_effect=[ack,{'verified':True,'manifest':manifest,'backend':backend()}])
        return ack

    def test_seed_ack_is_external_durable_and_no_lifecycle_calls(self):
        self.seed_setup()
        self.probe.seed()
        saved=p.Ledger(self.log.root)
        self.assertEqual(saved.state['phase'],'acknowledged')
        self.assertTrue(json.loads((self.log.root/'ack.json').read_text())['ack']['ACK'])
        self.ref.destructive.assert_not_called(); self.ref.restart.assert_not_called()
        self.assertEqual(self.probe.execute.call_args_list[-1].args,(CID,'verify','/work',PROOF))

    def test_no_ack_on_file_or_parent_fsync_failure(self):
        self.seed_setup()
        with patch.object(p.os,'fsync',side_effect=OSError('EIO')):
            with self.assertRaises(OSError): self.probe.seed()
        self.assertEqual(self.log.state['phase'],'seed-running')
        self.ref.destructive.assert_not_called()

    def test_no_ack_on_parent_directory_fsync_failure(self):
        self.seed_setup()
        with patch.object(p.ref,'sync_directory',side_effect=OSError('EIO')):
            with self.assertRaises(OSError): self.probe.seed()
        self.assertEqual(self.log.state['phase'],'seed-running')
        self.assertTrue((self.log.root/'ack.json').exists())
        saved=p.Ledger(self.log.root)
        self.assertNotEqual(saved.state['phase'],'acknowledged')

    def test_missing_guest_ack_preserves_resources(self):
        self.seed_setup(); self.probe.execute.side_effect=[{'ACK':False}]
        with self.assertRaises(p.ref.Refusal): self.probe.seed()
        self.assertFalse((self.log.root/'ack.json').exists())
        self.assertEqual(self.log.state['containers'],[CID])
        self.transport.assert_not_called()

    def test_verify_readonly_never_reseed_and_failure_preserves(self):
        ack=self.seed_setup(); self.log.state.update(ack=ack,restart_count=0,phase='verify-running')
        self.ref.state['restart_count']=1
        self.probe.owned_volume=Mock(return_value='vrp-'+PROOF)
        self.probe.owned_container=Mock(return_value={'State':{'Running':False}})
        self.probe.execute=Mock(return_value={'verified':True,'backend':backend(boot=PROOF),'manifest':{'wrong':True}})
        with self.assertRaises(p.ref.Refusal): self.probe.verify()
        mount=self.probe.container.call_args.args[0]
        self.assertTrue(mount['ReadOnly']); self.assertTrue(mount['VolumeOptions']['NoCopy'])
        self.probe.execute.assert_called_once_with(CID,'verify','/work',PROOF)
        self.assertEqual(self.log.state['containers'],[CID])
        self.assertEqual(self.log.state['phase'],'verify-running')

    def test_cleanup_stops_at_foreign_identity_or_failure(self):
        self.log.state.update(containers=[CID],image=IMAGE,phase='cleanup-running')
        self.probe.owned_container=Mock(side_effect=p.ref.Refusal('foreign label'))
        with self.assertRaises(p.ref.Refusal): self.probe.cleanup()
        self.transport.assert_not_called()
        self.probe.owned_container.return_value={'State':{'Running':False}}
        self.probe.owned_container.side_effect=None
        self.transport.side_effect=TimeoutError('uncertain delete')
        with self.assertRaises(TimeoutError): self.probe.cleanup()
        self.assertEqual(self.transport.call_count,1)
        self.assertEqual(self.log.state['containers'],[CID])

    def test_actual_backend_not_configuration_claim(self):
        p.validate_backend(backend(),'ext4'); p.validate_backend(backend('virtiofs'),'virtiofs')
        with self.assertRaises(p.ref.Refusal): p.validate_backend(backend(),'virtiofs')
        bad=backend(); bad['mountinfo']='32 1 0:33 / /elsewhere rw - ext4 test rw'
        with self.assertRaises(p.ref.Refusal): p.validate_backend(bad,'ext4')

    def test_stream_framing_and_stderr(self):
        frame=lambda channel,data:bytes([channel,0,0,0])+len(data).to_bytes(4,'big')+data
        self.assertEqual(p.decode_stream(frame(1,b'out')+frame(2,b'err')),(b'out',b'err'))
        for data in (b'x',frame(0,b'bad'),frame(1,b'ok')[:-1]):
            with self.assertRaises(p.ref.Refusal): p.decode_stream(data)

    def test_oci_encoder_digests_and_modes(self):
        archive,images=p.image_archive(b'fake local ELF',{p.LABEL:RUN})
        with tarfile.open(fileobj=io.BytesIO(archive)) as outer:
            contents={m.name:outer.extractfile(m).read() for m in outer.getmembers()}
        self.assertEqual(json.loads(contents['oci-layout']),{'imageLayoutVersion':'1.0.0'})
        desc=json.loads(contents['index.json'])['manifests'][0]
        def blob(desc):
            data=contents['blobs/sha256/'+desc['digest'].split(':')[1]]
            self.assertEqual(desc['digest'],'sha256:'+p.sha(data)); self.assertEqual(desc['size'],len(data))
            return data
        manifest=json.loads(blob(desc)); config=json.loads(blob(manifest['config']))
        layer=blob(manifest['layers'][0])
        self.assertEqual(images['config'],manifest['config']['digest'])
        self.assertEqual(images['manifest'],desc['digest'])
        self.assertEqual(config['rootfs']['diff_ids'],['sha256:'+p.sha(layer)])
        self.assertEqual(config['config']['Labels'],{p.LABEL:RUN})
        with tarfile.open(fileobj=io.BytesIO(layer)) as inner:
            self.assertEqual(inner.getnames(),['probe'])
            self.assertEqual(inner.getmember('probe').mode,0o755)
            self.assertEqual(inner.extractfile('probe').read(),b'fake local ELF')
        self.assertEqual(archive,p.image_archive(b'fake local ELF',{p.LABEL:RUN})[0])
        with self.assertRaises(p.ref.Refusal): p.image_archive(b'',{})

    def test_loaded_image_supports_exact_precomputed_store_ids_only(self):
        _,ids=p.image_archive(b'fake local ELF',{})
        for image in ids.values():
            for prefix in ('Loaded image ID: ','Loaded image: '):
                self.assertEqual(p.loaded_image(p.encoded({'stream':prefix+image+'\n'}),ids),image)
        for output in (b'{}',p.encoded({'error':'failed'}),
                       p.encoded({'stream':'Loaded image ID: '+IMAGE+'\n'}),
                       p.encoded({'stream':' '.join(ids.values())})):
            with self.assertRaises(p.ref.Refusal): p.loaded_image(output,ids)

    def test_realistic_inspect_is_checked_before_start(self):
        self.log.state['image']=IMAGE
        mount={'Type':'volume','Source':'vrp-'+PROOF,'Target':'/work','ReadOnly':True}
        config=p.container_config(IMAGE,self.probe.labels,mount)
        obj={'Id':CID,'Image':IMAGE,'Config':config,'HostConfig':config['HostConfig'],
             'State':{'Running':False},'NetworkSettings':{'Networks':{'none':{'IPAddress':''}}},
             'Mounts':[{'Type':'volume','Name':mount['Source'],'Driver':'local','Destination':'/work','RW':False}]}
        responses=[(201,p.encoded({'Id':CID})),(200,p.encoded(obj)),(204,b'')]
        obj_running=copy.deepcopy(obj); obj_running['State']['Running']=True
        responses.append((200,p.encoded(obj_running)))
        self.transport.side_effect=responses
        self.assertEqual(self.probe.container(mount),CID)
        self.assertEqual([c.args[1:3] for c in self.transport.call_args_list][1:],
            [('GET','/v1.52/containers/'+CID+'/json'),('POST','/v1.52/containers/'+CID+'/start'),
             ('GET','/v1.52/containers/'+CID+'/json')])
        for key,value in [('ReadonlyRootfs',False),('Privileged',True),('Memory',1024**3),
                          ('SecurityOpt',[]),('LogConfig',{'Type':'json-file'})]:
            bad=copy.deepcopy(obj); bad['HostConfig'][key]=value
            with self.assertRaises(p.ref.Refusal): p.validate_container(bad,config,mount,running=False)
        bad=copy.deepcopy(obj); bad['NetworkSettings']['Networks']={'bridge':{}}
        with self.assertRaises(p.ref.Refusal): p.validate_container(bad,config,mount,running=False)

    def test_bad_inspect_never_starts_container(self):
        self.log.state['image']=IMAGE
        self.probe.owned_container=Mock(side_effect=p.ref.Refusal('bad isolation'))
        self.transport.return_value=(201,p.encoded({'Id':CID}))
        with self.assertRaises(p.ref.Refusal):
            self.probe.container({'Type':'volume','Source':'owned','ReadOnly':False})
        self.assertEqual(self.transport.call_count,1)
        self.assertEqual(self.log.state['containers'],[CID])

    def test_verify_restart_gate_refuses_unchanged_or_multiple_reboots(self):
        self.log.state.update(restart_count=2,phase='verify-running')
        for count in (0,2,4):
            self.ref.state['restart_count']=count
            with self.assertRaises(p.ref.Refusal): self.probe.verify()
        self.transport.assert_not_called()

    def test_seed_readback_divergence_never_acknowledges(self):
        ack=self.seed_setup()
        self.probe.execute.side_effect=[ack,{'verified':True,'manifest':{'wrong':True}}]
        with self.assertRaises(p.ref.Refusal): self.probe.seed()
        self.assertFalse((self.log.root/'ack.json').exists())
        self.assertEqual(self.log.state['phase'],'seed-running')

    def test_canonical_boot_uuid_and_virtiofs_spellings(self):
        for token in ('virtiofs','fuse.virtiofs'):
            proof=backend('virtiofs'); proof['mountinfo']=f'32 1 0:33 / /work rw - {token} test rw'
            p.validate_backend(proof,'virtiofs')
        with self.assertRaises((ValueError,p.ref.Refusal)):
            p.validate_backend(backend(boot='-'*36),'ext4')

    def test_reviewed_fixture_pin_matches_repository_source(self):
        fixture=PATH.parents[1]/'Tests/Compatibility/fixtures/volume-reference-probe.go'
        self.assertEqual(p.sha(fixture.read_bytes()),p.FIXTURE_SHA)

    def test_offline_build_failure_has_no_fallback_or_ambient_environment(self):
        go=self.root/'go'; go.write_bytes(b'fake tool never executed'); go.chmod(0o700)
        source=PATH.parents[1]/'Tests/Compatibility/fixtures/volume-reference-probe.go'
        self.args.go=str(go); self.args.go_sha256=p.sha(go.read_bytes())
        self.args.source=str(source); self.args.source_sha256=p.FIXTURE_SHA
        with patch.object(p.ref,'run_bounded',return_value=SimpleNamespace(returncode=1)) as run, \
             patch.object(p.os,'statvfs',return_value=SimpleNamespace(f_bavail=4*1024**3,f_frsize=1)), \
             patch.dict(os.environ,{'GOTOOLCHAIN':'auto','GOPROXY':'https://foreign','DOCKER_HOST':'unix:///foreign'}):
            with self.assertRaises(p.ref.Refusal): self.probe.build()
        self.assertEqual(run.call_count,1)
        env=run.call_args.kwargs['env']
        self.assertEqual(env['GOTOOLCHAIN'],'local'); self.assertEqual(env['GOPROXY'],'off')
        self.assertEqual(env['GOSUMDB'],'off'); self.assertEqual(env['GOENV'],'off')
        self.assertEqual(env['GOWORK'],'off'); self.assertEqual(env['GO111MODULE'],'off')
        self.assertNotIn('DOCKER_HOST',env); self.assertLessEqual(run.call_args.kwargs['timeout'],60)
        self.transport.assert_not_called()

    def test_caller_cannot_repin_modified_fixture(self):
        go=self.root/'go'; go.write_bytes(b'fake'); go.chmod(0o700)
        source=self.root/'unreviewed.go'; source.write_bytes(b'package main // NOT the reviewed fixture')
        self.args.go=str(go); self.args.go_sha256=p.sha(go.read_bytes())
        self.args.source=str(source); self.args.source_sha256=p.sha(source.read_bytes())
        with patch.object(p.ref,'run_bounded') as run:
            with self.assertRaises(p.ref.Refusal): self.probe.build()
        run.assert_not_called(); self.transport.assert_not_called()

    def qualification_setup(self, fail=False):
        self.log.state['phase']='qualify-running'
        self.ref.root=self.root/'reference'; self.ref.root.mkdir(mode=0o700)
        (self.ref.root/'fixture').mkdir(mode=0o700)
        self.probe.build=Mock(side_effect=lambda:self.log.state.update(image=IMAGE))
        self.probe.container=Mock(return_value=CID)
        self.probe.backend=Mock(return_value=backend('virtiofs'))
        self.probe.stop=Mock()
        directory=self.ref.root/'fixture'/('probe-'+PROOF)
        seen=[]
        def execute(cid,mode,root,*args):
            seen.append((mode,args))
            if mode in ('read','splice','mmap'):
                data=(directory/args[0]).read_bytes()
                return {'size':len(data),'sha256':'wrong' if fail else p.sha(data)}
            if mode=='write':
                data=p.base64.b64decode(args[1]); p.ref.write_new(directory/args[0],data)
                return {'size':len(data),'sha256':p.sha(data)}
            if mode=='namespace':
                self.assertEqual(os.readlink(directory/'literal'),'./renamed')
                self.assertFalse((directory/'removed').exists())
                os.rename(directory/'renamed',directory/'guest-renamed')
                os.unlink(directory/'literal'); os.symlink('./guest-renamed',directory/'guest-literal')
                return {'namespace':True}
            self.fail('unexpected operation '+mode)
        self.probe.execute=Mock(side_effect=execute)
        return seen

    def test_qualification_first_reads_and_bidirectional_namespace(self):
        seen=self.qualification_setup()
        self.probe.qualify()
        self.assertEqual(self.log.state['phase'],'qualified')
        self.assertEqual([mode for mode,_ in seen],['read']*7+['splice']*7+['mmap']*7+['write','namespace'])
        events=[json.loads((self.log.root/e['name']).read_text()) for e in self.log.state['events']]
        self.assertEqual(sum(e['kind']=='first-reopen' for e in events),21)
        self.assertTrue(all(e['expected']==e['actual'] for e in events if e['kind']=='first-reopen'))
        self.probe.stop.assert_called_once_with(CID)

    def test_qualification_mismatch_is_first_read_terminal_no_retry(self):
        seen=self.qualification_setup(fail=True)
        self.log.state['phase']='qualify-running'
        with self.assertRaises(p.ref.Refusal): self.probe.qualify()
        self.assertEqual(len(seen),1)
        self.assertEqual(self.log.state['phase'],'qualify-running')
        self.probe.stop.assert_not_called()

    def local_setup(self):
        self.log=p.Ledger(self.root/'local-proof',{'phase':'new','mode':'local','run_id':RUN,
                                               'proof_id':PROOF,'containers':[]})
        self.probe=p.Probe(self.ref,self.args,self.parent,self.log,self.transport)
        self.ref.state.update(fixture=False,same_path_fixture=False)

    def test_local_prepare_without_fixture_builds_only_owned_image(self):
        self.local_setup()
        self.log.phase('prepare-local-running')
        self.probe.build=Mock(side_effect=lambda:self.log.state.update(image=IMAGE,image_created=True))
        self.probe.container=Mock()
        self.probe.prepare_local()
        saved=p.Ledger(self.log.root)
        self.assertEqual((saved.state['phase'],saved.mode),('local-ready','local'))
        self.assertTrue(saved.state['image_created'])
        self.assertNotIn('fixture',saved.state)
        self.assertNotIn('qualification_backend',saved.state)
        self.probe.build.assert_called_once_with()
        self.probe.container.assert_not_called()
        self.transport.assert_not_called()

    def test_local_prepare_failure_is_terminal_no_retry_or_cleanup(self):
        self.local_setup(); self.log.phase('prepare-local-running')
        self.probe.build=Mock(side_effect=p.ref.Refusal('failed offline build'))
        with self.assertRaises(p.ref.Refusal): self.probe.prepare_local()
        for phase in ('prepare-local-running','qualify-running','seed-running','cleanup-running'):
            with self.assertRaises(p.ref.Refusal): self.log.phase(phase)
        self.assertEqual(p.Ledger(self.log.root).state['phase'],'prepare-local-running')
        self.transport.assert_not_called()

    def test_seed_accepts_both_ready_modes_and_records_external_ack_mode(self):
        for mode in ('bind','local'):
            if mode=='local': self.local_setup()
            prepare,ready=('qualify-running','qualified') if mode=='bind' else ('prepare-local-running','local-ready')
            self.log.phase(prepare); self.log.phase(ready)
            self.log.phase('seed-running')
            self.seed_setup(); self.probe.seed()
            ack=json.loads((self.log.root/'ack.json').read_text())
            self.assertEqual(ack['mode'],mode)
            self.assertEqual(p.Ledger(self.log.root).state['phase'],'acknowledged')
            self.assertEqual(self.probe.container.call_args.args[0]['Type'],'volume')
            self.ref.destructive.assert_not_called(); self.ref.restart.assert_not_called()

    def test_proof_mode_changes_rejected_in_memory_and_on_reopen(self):
        self.local_setup()
        self.log.state['mode']='bind'
        with self.assertRaisesRegex(p.ref.Refusal,'mode is immutable'): self.log.save()
        with self.assertRaises(p.ref.Refusal): self.log.phase('qualify-running')
        # Accidental same-ID ledger edit cannot convert the pinned mode record.
        (self.log.root/'ledger.json').write_bytes(p.encoded(self.log.state))
        with self.assertRaisesRegex(p.ref.Refusal,'mode is immutable'): p.Ledger(self.log.root)

    def test_mode_record_tampering_and_legacy_missing_mode_fail_closed(self):
        self.local_setup()
        (self.log.root/'mode.json').write_bytes(p.encoded({'mode':'bind'}))
        with self.assertRaises(p.ref.Refusal): self.log.save()
        with self.assertRaises(p.ref.Refusal): p.Ledger(self.log.root)
        with self.assertRaises((KeyError,p.ref.Refusal)):
            p.Ledger(self.root/'legacy',{'phase':'new'})

    def test_local_mode_never_claims_qualified_or_macos_oracle(self):
        self.local_setup(); self.log.phase('prepare-local-running'); self.log.phase('local-ready')
        for phase in ('qualified','qualify-running','verified','cleanup-running'):
            with self.assertRaises(p.ref.Refusal): self.log.phase(phase)
        for key in ('fixture','qualification_backend'):
            with patch.dict(self.log.state,{key:{}}):
                with self.assertRaises(p.ref.Refusal): self.log.save()
        with patch.dict(self.log.state,phase='qualified'):
            with self.assertRaises(p.ref.Refusal): self.log.save()
        with self.assertRaises(p.ref.Refusal): self.probe.qualify()
        self.transport.assert_not_called()

    def test_every_mode_transition_rejects_out_of_order_and_repeat(self):
        for mode in ('bind','local'):
            log=p.Ledger(self.root/('transitions-'+mode),{'phase':'new','mode':mode})
            graph=p.transitions(mode)
            for before,after in graph.items():
                self.assertEqual(log.state['phase'],before)
                for wrong in (set(graph)|{'cleaned','qualified','local-ready'})-{after}:
                    with self.assertRaises(p.ref.Refusal): log.phase(wrong)
                log.phase(after)
            self.assertEqual(p.Ledger(log.root).state['phase'],'cleaned')

    def test_fixture_gate_is_bind_only_but_identity_and_parent_still_required(self):
        self.ref.state.update(fixture=False,same_path_fixture=False)
        self.probe.api('GET','/info')
        self.parent.check.assert_called_once_with(); self.ref.guard.assert_called_once_with()
        self.log.state['phase']='qualify-running'
        self.probe.build=Mock()
        with self.assertRaisesRegex(p.ref.Refusal,'same-path fixture'): self.probe.qualify()
        self.probe.build.assert_not_called()
        self.local_setup()
        for key,value in [('phase','crashed'),('daemon_id','foreign'),('endpoint','foreign'),('run_id','foreign')]:
            with patch.dict(self.ref.state,{key:value}):
                with self.assertRaises(p.ref.Refusal): self.probe.api('GET','/info')

    def test_local_mode_cannot_create_bind_container_even_with_fixture(self):
        self.local_setup(); self.ref.state.update(fixture=True,same_path_fixture=True)
        self.log.phase('prepare-local-running'); self.log.phase('local-ready'); self.log.phase('seed-running')
        self.log.state['image']=IMAGE
        with self.assertRaises(p.ref.Refusal):
            self.probe.container({'Type':'bind','Source':'/owned','ReadOnly':False})
        self.transport.assert_not_called()

    def test_fresh_proof_labels_produce_disjoint_source_image_candidates(self):
        labels=self.probe.labels
        local_labels={**labels,p.LABEL+'.mode':'local',p.LABEL+'.proof':RUN}
        self.assertNotEqual(labels[p.LABEL+'.proof'],local_labels[p.LABEL+'.proof'])
        _,old=p.image_archive(b'same pinned binary',labels)
        _,fresh=p.image_archive(b'same pinned binary',local_labels)
        self.assertFalse(set(old.values()) & set(fresh.values()))

    def cli_setup(self):
        self.ref.root=self.root/'reference'; self.ref.root.mkdir(mode=0o700)
        (self.ref.root/'artifacts').mkdir(mode=0o700)
        argv=['--root',str(self.ref.root),'--run-id',RUN,'--proof-id',PROOF,
              '--expected-daemon-id','daemon','--endpoint','unix:///owned',
              '--compat-lock',str(self.root/'cengine-compat-run.lock'),
              '--parent-lock-pid',str(os.getppid()),'--allow-disposable-reference']
        return argv

    def test_main_prepare_local_new_id_only_and_dispatches_seed_without_bind(self):
        argv=self.cli_setup(); self.ref.state.update(fixture=False,same_path_fixture=False)
        context=Mock(); context.__enter__=Mock(return_value=self.ref); context.__exit__=Mock(return_value=False)
        with patch.object(p,'ParentLock',return_value=self.parent), patch.object(p.ref,'Reference',return_value=context), \
             patch.object(p.Probe,'preflight'), patch.object(p.Probe,'build') as build, \
             patch.object(p.Probe,'seed') as seed, patch('sys.stdout',new_callable=io.StringIO) as output:
            p.main(['prepare-local',*argv])
            build.assert_called_once_with()
            self.assertEqual(json.loads(output.getvalue())['phase'],'local-ready')
            self.assertEqual(json.loads(output.getvalue())['mode'],'local')
            for phase in ('prepare-local','qualify'):
                with self.assertRaises(FileExistsError): p.main([phase,*argv])
            p.main(['seed',*argv]); seed.assert_called_once_with()
            with self.assertRaises(p.ref.Refusal): p.main(['seed',*argv])

    def test_failed_qualification_main_cannot_resume_convert_seed_or_cleanup(self):
        argv=self.cli_setup()
        path=self.ref.root/'artifacts'/('probe-'+PROOF)
        log=p.Ledger(path,{'phase':'new','mode':'bind','run_id':RUN,'proof_id':PROOF,
            'endpoint':self.args.endpoint,'daemon_id':'daemon','controller_sha256':p.sha(PATH.read_bytes())})
        log.phase('qualify-running'); log.event('first-reopen',actual={'size':30},expected={'size':4097},index=2)
        original={f.name:f.read_bytes() for f in path.iterdir()}
        context=Mock(); context.__enter__=Mock(return_value=self.ref); context.__exit__=Mock(return_value=False)
        with patch.object(p,'ParentLock',return_value=self.parent), patch.object(p.ref,'Reference',return_value=context), \
             patch.object(p.Probe,'preflight') as preflight:
            for phase in ('qualify','prepare-local','seed','verify','cleanup'):
                with self.assertRaises((FileExistsError,p.ref.Refusal)): p.main([phase,*argv])
            preflight.assert_not_called()
        self.assertEqual({f.name:f.read_bytes() for f in path.iterdir()},original)

    def test_stale_eof_after_host_growth_is_preserved_without_retry_or_stat(self):
        seen=self.qualification_setup()
        real=self.probe.execute.side_effect
        def stale(*args):
            result=real(*args)
            if len(seen)==3: return {'size':30,'sha256':p.sha(b'changed-content-not-definition')}
            return result
        self.probe.execute.side_effect=stale
        with self.assertRaisesRegex(p.ref.Refusal,'authoritative FIRST read failed'): self.probe.qualify()
        self.assertEqual([mode for mode,_ in seen],['read']*3)
        events=[json.loads((self.log.root/e['name']).read_text()) for e in self.log.state['events']]
        event=events[-1]
        self.assertEqual((event['index'],event['actual']['size'],event['expected']['size']),(2,30,4097))
        self.assertEqual(p.Ledger(self.log.root).state['phase'],'qualify-running')
        self.probe.stop.assert_not_called()

    def local_verify_setup(self):
        self.local_setup(); ack=self.seed_setup()
        self.log.state.update(ack=ack,restart_count=0,phase='verify-running',image_created=True)
        self.ref.state['restart_count']=1
        self.probe.owned_volume=Mock(return_value='vrp-'+PROOF)
        self.probe.owned_container=Mock(return_value={'State':{'Running':False}})
        self.probe.execute=Mock(return_value={'verified':True,'backend':backend(),'manifest':ack['manifest']})

    def test_local_verify_unchanged_boot_is_terminal(self):
        self.local_verify_setup()
        with self.assertRaisesRegex(p.ref.Refusal,'boot did not change'): self.probe.verify()
        with self.assertRaises(p.ref.Refusal): self.log.check_transition('verify-running')
        self.assertEqual(self.log.state['phase'],'verify-running')

    def test_local_success_verify_cleanup_retains_evidence(self):
        self.local_verify_setup()
        self.probe.execute.return_value['backend']=backend(boot=PROOF)
        self.probe.stop=Mock(); self.probe.verify()
        self.assertEqual(self.log.state['phase'],'verified')
        self.assertTrue(self.probe.container.call_args.args[0]['ReadOnly'])
        self.log.file('ack.json',b'preserved evidence')
        self.log.phase('cleanup-running')
        self.probe.api=Mock(return_value={'Id':IMAGE,'Config':{'Labels':self.probe.labels}})
        self.probe.cleanup()
        self.assertEqual(p.Ledger(self.log.root).state['phase'],'cleaned')
        self.assertEqual((self.log.root/'ack.json').read_bytes(),b'preserved evidence')
        self.assertTrue((self.log.root/'mode.json').exists())
        self.assertTrue(all('prune' not in c.args[1] or 'noprune=1' in c.args[1] for c in self.probe.api.call_args_list))
        self.ref.destructive.assert_not_called(); self.ref.restart.assert_not_called()

    def test_local_prepare_real_build_path_is_offline_and_imports_exact_owned_image(self):
        self.local_setup(); self.log.phase('prepare-local-running')
        go=self.root/'go'; go.write_bytes(b'pinned fake tool'); go.chmod(0o700)
        self.args.go=str(go); self.args.go_sha256=p.sha(go.read_bytes())
        self.args.source=str(PATH.parents[1]/'Tests/Compatibility/fixtures/volume-reference-probe.go')
        self.args.source_sha256=p.FIXTURE_SHA
        binary=b'fake ELF from mocked compiler'
        archive,ids=p.image_archive(binary,self.probe.labels)
        image=ids['manifest']
        self.transport.side_effect=[(404,b'{}'),(404,b'{}'),
            (200,p.encoded({'stream':'Loaded image ID: '+image+'\n'})),
            (200,p.encoded({'Id':image,'Config':{'Labels':self.probe.labels}}))]
        def compile(*args,**kwargs):
            (self.log.root/'probe').write_bytes(binary)
            return SimpleNamespace(returncode=0)
        with patch.object(p.ref,'run_bounded',side_effect=compile) as run, \
             patch.object(p.os,'statvfs',return_value=SimpleNamespace(f_bavail=4*1024**3,f_frsize=1)):
            self.probe.prepare_local()
        self.assertEqual(run.call_args.kwargs['env']['GOPROXY'],'off')
        self.assertEqual(run.call_args.kwargs['env']['GOTOOLCHAIN'],'local')
        self.assertEqual(self.log.state['image_candidates'],ids)
        self.assertEqual(self.log.state['image'],image)
        self.assertEqual((self.log.root/'image.tar').read_bytes(),archive)
        self.assertEqual(self.log.state['phase'],'local-ready')
        self.assertEqual([c.args[1:3] for c in self.transport.call_args_list],
            [('GET','/v1.52/images/'+ids['config']+'/json'),
             ('GET','/v1.52/images/'+ids['manifest']+'/json'),
             ('POST','/v1.52/images/load?quiet=1'),('GET','/v1.52/images/'+image+'/json')])
        self.assertEqual(self.log.state['containers'],[])
        self.assertNotIn('fixture',self.log.state)

    def test_main_preflight_failure_is_terminal_in_every_phase_and_mode(self):
        argv=self.cli_setup()
        context=Mock(); context.__enter__=Mock(return_value=self.ref); context.__exit__=Mock(return_value=False)
        for mode in ('bind','local'):
            for command in ('qualify' if mode=='bind' else 'prepare-local','seed','verify','cleanup'):
                proof=str(p.uuid.uuid4())
                args=list(argv); args[args.index('--proof-id')+1]=proof
                path=self.ref.root/'artifacts'/('probe-'+proof)
                if command not in p.PREPARATIONS:
                    log=p.Ledger(path,{'phase':'new','mode':mode,'run_id':RUN,'proof_id':proof,
                        'endpoint':self.args.endpoint,'daemon_id':'daemon','controller_sha256':p.sha(PATH.read_bytes())})
                    graph=p.transitions(mode)
                    while graph[log.state['phase']]!=command+'-running': log.phase(graph[log.state['phase']])
                with patch.object(p,'ParentLock',return_value=self.parent), \
                     patch.object(p.ref,'Reference',return_value=context), \
                     patch.object(p.Probe,'preflight',side_effect=p.ref.Refusal('preflight failure')) as preflight:
                    with self.assertRaisesRegex(p.ref.Refusal,'preflight failure'): p.main([command,*args])
                    self.assertEqual(p.Ledger(path).state['phase'],command+'-running')
                    preserved={f.name:f.read_bytes() for f in path.iterdir()}
                    with self.assertRaises((FileExistsError,p.ref.Refusal)): p.main([command,*args])
                    preflight.assert_called_once_with()
                    self.assertEqual({f.name:f.read_bytes() for f in path.iterdir()},preserved)

    def test_cli_has_no_crash_restart_prune_or_ambient_defaults(self):
        parser=p.parser()
        action=next(a for a in parser._actions if a.dest=='phase')
        self.assertEqual(set(action.choices),{'qualify','prepare-local','seed','verify','cleanup'})
        for name in ('root','run_id','expected_daemon_id','endpoint','proof_id','compat_lock','parent_lock_pid','allow_disposable_reference'):
            self.assertTrue(next(a for a in parser._actions if a.dest==name).required)


if __name__=='__main__':
    unittest.main()
