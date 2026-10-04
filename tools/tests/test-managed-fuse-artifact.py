#!/usr/bin/env python3
"""Engine-free bounded build/bundle tests. No Docker, compiler or VM execution."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import managed_fuse_artifact as artifact
spec = importlib.util.spec_from_file_location('builder', ROOT / 'tools/build-managed-fuse-artifact.py')
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)


def elf():
    data = bytearray(120); data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', data, 18, 183); struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<H', data, 54, 56); struct.pack_into('<H', data, 56, 1)
    struct.pack_into('<I', data, 64, 1)
    return bytes(data)


def toolchain():
    paths = ['bin/go', 'pkg/tool/linux_arm64/compile', 'pkg/tool/linux_arm64/asm', 'pkg/tool/linux_arm64/link']
    paths += ['src/file-%03d.go' % n for n in range(105)]
    paths += ['src/space name.go', 'src/ü.go']
    return b''.join(b'a' * 64 + b'  /usr/local/go/' + p.encode() + b'\0' for p in sorted(paths, key=lambda p:p.encode()))


def fixture(root):
    files = {'native.test': elf(), 'setup': elf(), 'mke2fs': elf(), 'toolchain.sha256': toolchain()}
    value = {'selection': artifact.selection('RTM-081'), 'schema': artifact.SCHEMA, 'sources': {'Guest/go.mod':'d'*64},
        'builder': {'reference':artifact.BUILDER,'image_id':'sha256:'+'a'*64,'daemon_id':'1af13675-8d46-4c32-8af5-e0c9b2b7fc69',
                    'container':'c'*64,'limits':artifact.LIMITS,'exit':0,'oom':False,'crosscompiled':['arm64','amd64']},
        'binaries':{n:{'sha256':artifact.digest(files[n]),'bytes':len(files[n])} for n in ('native.test','setup','mke2fs')},
        'toolchain':artifact.toolchain_proof(files['toolchain.sha256']), 'formatter_sha256':artifact.digest(files['mke2fs']),
        'cleanup':{'container':'c'*64,'removed':True}}
    for name, raw in files.items(): (root/name).write_bytes(raw)
    return value, files


class ArtifactTests(unittest.TestCase):
    def test_exact_bundle_pin_provenance_and_negative_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); value, files=fixture(root)
            def check(v):
                raw=artifact.encode(v); (root/'fixture.json').write_bytes(raw)
                return artifact.load_fixture(root, artifact.digest(raw), ROOT)
            with patch.object(artifact,'inventory',return_value=value['sources']):
                self.assertEqual(check(value),(value,files))
                mutations = [lambda v:v['builder'].update(reference='golang:latest'),
                    lambda v:v['builder'].update(image_id='sha256:'+'x'*64), lambda v:v['builder'].update(daemon_id='f'*64),
                    lambda v:v['builder'].update(daemon_id='1af13675-8d46-4c32-8af5-e0c9b2b7fc68'),
                    lambda v:v['builder'].update(daemon_id='1af13675'+'b'*56),
                    lambda v:v['builder']['limits'].update(memory=2<<30), lambda v:v['builder'].update(exit=True),
                    lambda v:v['builder'].update(oom=True), lambda v:v['builder'].update(crosscompiled=['arm64']),
                    lambda v:v['cleanup'].update(removed=False),
                    lambda v:v['sources'].update(extra='a'*64), lambda v:v['binaries']['setup'].update(sha256='b'*64),
                    lambda v:v.update(formatter_sha256='b'*64), lambda v:v['toolchain'].update(sha256='b'*64)]
                for mutation in mutations:
                    broken=copy.deepcopy(value); mutation(broken)
                    with self.subTest(mutation=mutation), self.assertRaises(ValueError): check(broken)
                check(value)
                with self.assertRaisesRegex(ValueError,'pin'): artifact.load_fixture(root,'e'*64,ROOT)
                (root/'setup').unlink(); (root/'setup').symlink_to(root/'native.test')
                with self.assertRaises(OSError): check(value)

    def test_fsx_input_is_exact_private_nofollow_static_binary(self):
        # Synthetic bytes only under test-scoped pins; production has no pin override.
        raw = elf()
        with tempfile.TemporaryDirectory() as temp, patch.object(artifact, 'FSX_BYTES', len(raw)), \
             patch.object(artifact, 'FSX_SHA256', artifact.digest(raw)):
            root = Path(temp).resolve(); path = root / 'fsx'; path.write_bytes(raw)
            path.chmod(0o600)
            self.assertEqual(artifact.load_fsx(str(path)), raw)
            for bad in (None, '', 'relative/fsx', str(root) + '//fsx', str(root) + '/./fsx',
                        str(root) + '/../fsx', str(path) + '\n'):
                with self.subTest(path=bad), self.assertRaises(ValueError): artifact.load_fsx(bad)
            path.write_bytes(raw[:-1])
            with self.assertRaises(ValueError): artifact.load_fsx(str(path))
            path.write_bytes(raw[:-1] + b'x')
            with self.assertRaisesRegex(ValueError, 'pinned'): artifact.load_fsx(str(path))
            path.write_bytes(raw); path.chmod(0o622)
            with self.assertRaisesRegex(ValueError, 'private'): artifact.load_fsx(str(path))
            path.chmod(0o600); os.link(path, root / 'hardlink')
            with self.assertRaisesRegex(ValueError, 'private'): artifact.load_fsx(str(path))
            (root / 'hardlink').unlink(); (root / 'link').symlink_to(path)
            with self.assertRaises(OSError): artifact.load_fsx(str(root / 'link'))
            (root / 'directory-link').symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError): artifact.load_fsx(str(root / 'directory-link' / 'fsx'))
            path.unlink(); os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, 'regular'): artifact.load_fsx(str(path))
            dynamic = bytearray(raw); struct.pack_into('<I', dynamic, 64, 3)
            with patch.object(artifact, 'FSX_SHA256', artifact.digest(dynamic)):
                with self.assertRaisesRegex(ValueError, 'static'): artifact.validate_fsx(bytes(dynamic))
        with self.assertRaises(ValueError): artifact.validate_fsx(raw)
        source = (ROOT / 'Guest/internal/storagefuse/native_fsx_protocol_test.go').read_text()
        self.assertIn(artifact.FSX_SHA256, source)
        self.assertRegex(source, rf'fsxBinaryBytes\s*=\s*{artifact.FSX_BYTES}')

    def test_source_snapshot_exact_hashes_rejects_links_embed_syso(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            names=[*artifact.SOURCES,'Guest/go.mod','Guest/go.sum','Guest/vendor/modules.txt','Guest/third_party/go-fuse/a.go']
            for name in names:
                p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(name.encode())
            (root/'Guest/go.sum').write_bytes(b'')
            result=artifact.inventory(root); self.assertEqual(set(result),set(names))
            self.assertEqual(result['Guest/go.sum'],artifact.digest(b''))
            self.assertEqual(result['Guest/go.mod'],artifact.digest(b'Guest/go.mod'))
            (root/'Guest/a.syso').write_bytes(b'object')
            with self.assertRaisesRegex(ValueError,'object'): artifact.inventory(root)
            (root/'Guest/a.syso').unlink(); (root/'Guest/a.go').write_bytes(b'package a\n//go:embed other\n')
            with self.assertRaisesRegex(ValueError,'embed'): artifact.inventory(root)
            (root/'Guest/a.go').unlink(); (root/'Guest/link').symlink_to(root/'Guest/vendor',target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'link'): artifact.inventory(root)

    def test_shared_native_cases_are_in_existing_exact_source_inventory(self):
        # No alternate fixture format or unpinned case-specific input: changing
        # either selector or native test invalidates the same parent-built bundle.
        sources = artifact.inventory(ROOT)
        for name in ("Tests/Compatibility/fixtures/managed-fuse-native.go",
                     "Tests/Compatibility/test_managed_fuse_interrupt.py",
                     "Guest/internal/storagefuse/native_interrupt_linux_test.go",
                     "Guest/internal/storagefuse/native_write_burst_linux_test.go",
                     "Guest/internal/storagefuse/native_stale_credentials_linux_test.go"):
            self.assertEqual(sources[name], artifact.digest((ROOT / name).read_bytes()))

    def test_elf_static_and_full_toolchain_contract(self):
        artifact.static_arm64(elf()); artifact.toolchain_proof(toolchain())
        for kind in ('arch','dynamic','short'):
            data=bytearray(elf())
            if kind=='arch': struct.pack_into('<H',data,18,62)
            if kind=='dynamic': struct.pack_into('<I',data,64,3)
            if kind=='short': data=data[:64]
            with self.assertRaises(ValueError): artifact.static_arm64(data)
        for raw in (b'', b'a'*64+b'  /usr/local/go/bin/go\0', toolchain()+toolchain(), toolchain().replace(b'bin/go',b'../go')):
            with self.assertRaises(ValueError): artifact.toolchain_proof(raw)

    def test_export_archive_names_types_lengths(self):
        files={'native.test':elf(),'setup':elf(),'toolchain.sha256':toolchain()}
        raw=builder.tar_bytes([(n,b,0o600) for n,b in files.items()])
        self.assertEqual(builder.unpack(raw),files)
        for names in (list(files)+['extra'],['../native.test','setup','toolchain.sha256'],['native.test','native.test','setup']):
            bad=builder.tar_bytes([(n,elf(),0o600) for n in names])
            with self.assertRaises(ValueError): builder.unpack(bad)
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w') as archive:
            member=tarfile.TarInfo('native.test'); member.type=tarfile.SYMTYPE; member.linkname='/other';archive.addfile(member)
        with self.assertRaises(ValueError): builder.unpack(output.getvalue())

    def test_endpoint_and_original_parent_lock(self):
        builder.endpoint('unix:///private/owned/docker.sock')
        for wrong in ('tcp://host:2375','unix://host/tmp/a','unix:///tmp/a?x','', 'unix:///'):
            with self.assertRaises(ValueError): builder.endpoint(wrong)
        with tempfile.TemporaryDirectory() as temp, patch.object(os,'getppid',return_value=123):
            p=Path(temp); (p/'pid').write_text('123\n')
            with patch.object(builder.claims, 'launcher_lock', return_value=p.absolute()):
                lock=builder.OriginalLock(p,123)
                try:
                    lock.check(); (p/'pid').write_text('124\n')
                    with self.assertRaises(ValueError): lock.check()
                finally: lock.close()
                with self.assertRaises(ValueError): builder.OriginalLock(p,999)
                other=p/'unrelated'; other.mkdir(); (other/'pid').write_text('123\n')
                with self.assertRaisesRegex(ValueError,'global compatibility lock'): builder.OriginalLock(other,123)

    def test_parser_exact_daemon_uuid_without_engine_access(self):
        approved='1af13675-8d46-4c32-8af5-e0c9b2b7fc69'
        arguments=['--host','unix:///owned/socket','--image-id','sha256:'+'a'*64,
                   '--lock','/owned/lock','--lock-pid','123','--destination','/owned/artifact',
                   '--mke2fs','/owned/formatter','--mke2fs-sha256','b'*64,'--daemon-id']
        with patch.object(builder,'OriginalLock') as lock, patch.object(builder,'run_bounded') as run, \
             patch.object(builder.sys,'stderr',io.StringIO()):
            parser=builder.argument_parser()
            self.assertEqual(parser.parse_args(arguments+[approved]).daemon_id,approved)
            for wrong in ('1af13675-8d46-4c32-8af5-e0c9b2b7fc68', '1af13675'+'b'*56, 'f'*64):
                with self.subTest(daemon_id=wrong), self.assertRaises(SystemExit) as caught:
                    parser.parse_args(arguments+[wrong])
                self.assertEqual(caught.exception.code,2)
            lock.assert_not_called(); run.assert_not_called()

    def test_daemon_identity_preflight_before_lock_or_docker(self):
        approved='1af13675-8d46-4c32-8af5-e0c9b2b7fc69'
        args=SimpleNamespace(host='unix:///owned/socket',daemon_id=approved,image_id='sha256:'+'a'*64,
                             mke2fs_sha256='b'*64,lock='/owned/lock',lock_pid=123)
        class Validated(Exception): pass
        with patch.object(builder,'OriginalLock',side_effect=Validated) as lock, \
             patch.object(builder,'run_bounded') as run:
            with self.assertRaises(Validated): builder.build(args)
            lock.assert_called_once_with(args.lock,args.lock_pid)
            for wrong in ('1af13675-8d46-4c32-8af5-e0c9b2b7fc68', '1af13675'+'b'*56, 'f'*64):
                lock.reset_mock(); args.daemon_id=wrong
                with self.subTest(daemon_id=wrong), self.assertRaises(ValueError): builder.build(args)
                lock.assert_not_called()
            run.assert_not_called()

    def test_running_cli_loses_parent_authority_and_is_reaped(self):
        import time
        processes=[]; original=builder.subprocess.Popen; checks=0
        def start(*args,**kwargs):
            process=original(*args,**kwargs); processes.append(process); return process
        def guard():
            nonlocal checks
            checks+=1
            if checks>1: raise ValueError('lost lock')
        with patch.object(builder.subprocess,'Popen',side_effect=start), self.assertRaisesRegex(ValueError,'lost lock'):
            builder.run_bounded([sys.executable,'-c','import time;time.sleep(10)'],time.monotonic()+2,guard=guard)
        self.assertEqual(len(processes),1); self.assertIsNotNone(processes[0].returncode)

    def test_complete_builder_flow_only_owned_container_and_cleanup(self):
        for case_id in artifact.SELECTIONS:
            with self.subTest(case=case_id):
                self.complete_builder_flow(case_id)

    def complete_builder_flow(self, case_id):
        selected = artifact.selection(case_id)
        script = builder.build_script(case_id)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); formatter=root/'formatter'; formatter.write_bytes(elf())
            args=SimpleNamespace(host='unix:///owned/socket',daemon_id='1af13675-8d46-4c32-8af5-e0c9b2b7fc69',image_id='sha256:'+'a'*64,
                lock='/owned/lock',lock_pid=123,destination=str(root/'artifact'),mke2fs=str(formatter),
                mke2fs_sha256=artifact.digest(elf()),docker='/owned/docker',case=case_id)
            records=[]; container={}; image={'Id':args.image_id,'RepoDigests':[artifact.BUILDER],'Architecture':'arm64','Os':'linux'}
            def run(command, deadline, **kwargs):
                verb=command[5:]; records.append(verb)
                if verb[0]=='info': return artifact.encode({'ID':args.daemon_id,'OSType':'linux','Architecture':'aarch64','CgroupVersion':'2'})
                if verb[:2]==['image','inspect']: return artifact.encode([image])
                if verb[0]=='create':
                    name=verb[verb.index('--name')+1]; label=verb[verb.index('--label')+1].split('=',1)[1]
                    container.update(Name='/'+name,Id='c'*64,Image=args.image_id,Config={'Labels':{builder.OWNER:label},'Cmd':['timeout','-k','2','220','sh','-ec',script]})
                    return b'c'*64+b'\n'
                if verb[:2]==['container','inspect']:
                    return artifact.encode([dict(container,State={'Running':False,'ExitCode':0,'OOMKilled':False})])
                if verb[0]=='start':
                    self.assertIsNotNone(kwargs['input_file'])
                    return builder.tar_bytes([('native.test',elf(),0o600),('setup',elf(),0o600),('toolchain.sha256',toolchain(),0o600)])
                if verb[0]=='rm': self.assertEqual(verb[1:],['-f','c'*64]); return b'c'*64+b'\n'
                if verb[:2]==['container','ls']: return b''
                raise AssertionError(verb)
            sources={'Guest/go.mod':b'module inert'}
            with patch.object(builder,'OriginalLock',return_value=Mock()),patch.object(builder,'run_bounded',side_effect=run),\
                 patch.object(builder,'container_policy') as policy,patch.object(artifact,'snapshot',return_value=sources),\
                 patch.object(artifact,'inventory',return_value={n:artifact.digest(b) for n,b in sources.items()}),patch('builtins.print'):
                builder.build(args)
            self.assertEqual(sum(r[0]=='create' for r in records),1)
            self.assertEqual(sum(r[0]=='start' for r in records),1)
            self.assertFalse(any(r[0] in ('pull','build','exec','volume','network','stop','prune') for r in records))
            create=next(r for r in records if r[0]=='create'); self.assertIn('--pull=never',create)
            self.assertNotIn('--mount',create); self.assertNotIn('-v',create)
            self.assertEqual(create[create.index('--pids-limit')+1],'64')
            self.assertEqual(create[create.index('--memory')+1],'1g')
            self.assertEqual(create[create.index('--memory-swap')+1],'1g')
            policy.assert_called_once()
            self.assertEqual(policy.call_args.args[1:], (args.image_id, case_id))
            self.assertEqual(create[-7:], [args.image_id, 'timeout', '-k', '2', '220', 'sh', '-ec', script][-7:])
            self.assertEqual(create[-1], script)
            self.assertEqual(json.loads((root/'artifact/plan.json').read_bytes())['selection'], selected)
            value=json.loads((root/'artifact/fixture.json').read_bytes())
            self.assertEqual(value['selection'], selected)
            self.assertEqual(value['cleanup'],{'container':'c'*64,'removed':True})
            self.assertEqual(value['builder']['limits'],artifact.LIMITS)
            self.assertEqual(value['formatter_sha256'],args.mke2fs_sha256)

    def test_inspected_hard_limits_and_exact_ownership(self):
        value={'Name':'/owned','Id':'c'*64,'Image':'sha256:'+'a'*64,
            'Config':{'Labels':{builder.OWNER:'token'},'Cmd':['timeout','-k','2','220','sh','-ec',builder.SCRIPT]},
            'HostConfig':{'Memory':1<<30,'MemorySwap':1<<30,'NanoCpus':2000000000,'PidsLimit':64,
                'ReadonlyRootfs':True,'NetworkMode':'none','Privileged':False,'Binds':None,'CapDrop':['ALL'],
                'Tmpfs':{'/work':'rw,nosuid,nodev,size=512m','/tmp':'rw,nosuid,nodev,size=32m'},
                'SecurityOpt':['no-new-privileges'],'Ulimits':[{'Name':'nofile','Soft':256,'Hard':256},{'Name':'core','Soft':0,'Hard':0}]}}
        builder.owned(value,'owned','token','c'*64); builder.container_policy(value,value['Image'])
        for name, wrong in [('Memory',0),('MemorySwap',-1),('PidsLimit',0),('NanoCpus',0),('ReadonlyRootfs',False),
                            ('NetworkMode','host'),('Privileged',True),('Binds',['/host:/src']),('Ulimits',[])]:
            changed=copy.deepcopy(value); changed['HostConfig'][name]=wrong
            with self.subTest(name=name),self.assertRaises(ValueError): builder.container_policy(changed,value['Image'])
        with self.assertRaises(ValueError): builder.owned(value,'other','token')
        with self.assertRaises(ValueError): builder.owned(value,'owned','other')
        self.assertIn('timeout -k 2 180 go test -c',builder.SCRIPT)
        self.assertIn('find /usr/local/go -type f',builder.SCRIPT)
        self.assertIn('cmp /work/toolchain.before',builder.SCRIPT)
        self.assertNotIn('go test -run',builder.SCRIPT)
        for case_id in artifact.SELECTIONS:
            selected = copy.deepcopy(value)
            selected['Config']['Cmd'][-1] = builder.build_script(case_id)
            builder.container_policy(selected, value['Image'], case_id)
            for other in artifact.SELECTIONS:
                if builder.build_script(other) != builder.build_script(case_id):
                    with self.subTest(case=case_id, wrong=other), self.assertRaises(ValueError):
                        builder.container_policy(selected, value['Image'], other)


if __name__=='__main__': unittest.main()
