#!/usr/bin/env python3
"""Guarded reference ONLY: prepare-local OR qualify -> seed -> [operator crash/restart] -> verify -> cleanup.

No ambient Docker context, SDK/pytest imports, pulls, shell, VM lifecycle, retry,
repair, or automatic cleanup. Prune/API-filter probes are NOT implemented; this
controller refuses that scope. A failed/interrupted phase is terminal: preserve
its ledger and resources for investigation, never query/adopt uncertain creates.

Every invocation requires --root, --run-id, --expected-daemon-id, --endpoint,
--proof-id (a fresh UUID for prepare-local or qualify), --compat-lock, --parent-lock-pid, and
--allow-disposable-reference. The parent process must own the compatibility
runner's mkdir/pid lock (Scripts/run-compat-tests.sh), and must serialize ALL VM
work. This tool NEVER acquires, steals or removes that global lock.

prepare-local and qualify require --go (canonical local executable), --go-sha256,
--source (volume-reference-probe.go), --source-sha256. Source is read as bounded
DATA then copied privately; GOTOOLCHAIN=local/GOPROXY=off prevent downloads. Use
reviewed private copies of this controller and adjacent volume_reference.py.

Only an existing owned Reference ready receipt and Docker 29.2.1 are accepted.
prepare-local builds/imports a fresh proof-labeled offline image, then records
local-ready: NO host bind/fixture or macOS oracle claim. qualify alone requires
Reference's sole same-path RW fixture and records qualified after real reads.
The proof mode is immutable; failed qualifications cannot resume or be converted.
Use a NEW UUID and private controller filename/directory beside the pinned
volume_reference.py; never replace a controller pinned by an older proof ledger.
Limits are per container: 2 CPU, 768 MiB RAM+swap,
128 PIDs, no network, readonly root, cap-drop ALL. Bind qualification adds ONLY
DAC_OVERRIDE; local-ext4 seed/verify adds no capabilities. Only one runs at a time.
Operation data <16 MiB (hard payload cap 64 MiB); API aggregate output <=1 MiB;
commands <=60 s, entire invocation <=10 min. Compiler cache is infrastructure,
not operation data. Require 2 GiB free before building; never run fill workloads.

seed emits ACK only AFTER external ack.json AND its parent are fsynced and the
acknowledged ledger transition is durable. Main operator must check that receipt
before Reference.destructive('crash', run_id)/restart. verify requires a later
Reference restart and changed guest boot ID; it mounts the existing volume RO
and only reads it. This is software VM-crash evidence, NOT power-loss proof.

Trust boundary matches Reference: same UID/root/pinned tools trusted; hostile
same-UID replacement/forgery and writable ACL ancestors are unsupported. No
claim of portable numeric ownership, file/RO bind or inotify qualification.
Host-owned fixture directories/files remain private (0700/0600); guest UID 0
alone cannot bypass their DAC checks when the guest sees a different owner.
Linux generic_permission() (fs/namei.c, v6.18) permits directory traversal and
file read/write with CAP_DAC_OVERRIDE, not arbitrary root privileges:
https://github.com/torvalds/linux/blob/v6.18/fs/namei.c
This capability is process-wide, NOT path-scoped and NOT a host capability.
Confinement relies on the trusted VM/VirtioFS backend, Reference's sole owned
export, and the inspected sole container mount of its exclusively created probe
subdirectory. It grants no additional export or mount access outside that owned
host fixture; readonly root, no-new-privileges and all other dropped caps remain.
Actual VirtioFS access still requires first real qualification; no UID mapping
or backend permission behavior is inferred from this source-level DAC fix.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import types
from typing import Any
import uuid

MIB = 1024 * 1024
MAX_PAYLOAD = 64 * MIB
API = '1.52'
REFERENCE_SHA = 'cc191c4159d66fe608f5c7414243d2d5c1ea201418e941cff81c6da985d9ab22'
FIXTURE_SHA = '7bfcadfc207fc20ffd27e3b320e87a7c99bdf39c526ceaa89adfb0bb3080fd38'
SCHEMA = 'cengine-volume-reference-proof-v1'
LABEL = 'dev.cengine.volume-reference'
PREPARATIONS = {'qualify':'bind', 'prepare-local':'local'}


def transitions(mode):
    require(mode in PREPARATIONS.values(), 'unknown proof mode')
    prepare, ready = ('qualify', 'qualified') if mode=='bind' else ('prepare-local', 'local-ready')
    return {'new':prepare+'-running', prepare+'-running':ready, ready:'seed-running',
            'seed-running':'acknowledged', 'acknowledged':'verify-running',
            'verify-running':'verified', 'verified':'cleanup-running', 'cleanup-running':'cleaned'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def source_bytes(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise RuntimeError('bounded regular single-link input required')
        data = stream.read(limit + 1)
        after = os.fstat(fd)
        stamp = lambda s: (s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_mtime_ns,s.st_ctime_ns)
        if len(data) > limit or stamp(before) != stamp(after):
            raise RuntimeError('input changed/oversized')
        return data


def load_reference():
    path = Path(__file__).resolve().with_name('volume_reference.py')
    data = source_bytes(path, MIB)
    if sha(data) != REFERENCE_SHA:
        raise RuntimeError('reviewed adjacent Reference SHA changed')
    module = types.ModuleType('pinned_reference')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


ref = load_reference()
require = ref.require


class ParentLock:
    def __init__(self, path, pid):
        self.path = ref.canonical(path)
        require(self.path.name == 'cengine-compat-run.lock', 'expected global compatibility lock')
        require(pid > 1 and pid == os.getppid(), 'lock owner must be the calling parent PID')
        self.pid = pid
        self.directory = ref.identity(self.path)
        self.record = ref.identity(self.path / 'pid', hashed=True)
        require(self.directory['mode'] == stat.S_IFDIR and self.directory['uid'] == os.getuid()
                and self.record['uid'] == os.getuid(), 'foreign compatibility lock owner')
        self.check()

    def check(self):
        ref.check_identity(self.path, self.directory)
        ref.check_identity(self.path / 'pid', self.record)
        require(source_bytes(self.path / 'pid', 32).strip() == str(self.pid).encode(),
                'compatibility lock PID mismatch')
        require(os.getppid() == self.pid, 'calling parent changed')
        os.kill(self.pid, 0)  # liveness only; never signal/steal/reset the lock


class Ledger:
    def __init__(self, root, initial=None):
        self.root = root
        if initial is not None:
            self.directory = ref.private_directory(root)
            self.state: dict[str, Any] = dict(initial, schema=SCHEMA, directory=self.directory, events=[])
            self.mode = self.state['mode']
            require(self.mode in PREPARATIONS.values() and self.state['phase']=='new', 'fresh proof mode required')
            ref.write_new(root / 'mode.json', encoded({'mode':self.mode}))
            self.mode_stamp = ref.identity(root / 'mode.json', hashed=True)
            self.state.setdefault('files', {})['mode.json'] = self.mode_stamp
            self.stamp = None
            self.save()
            ref.sync_directory(root.parent)
        else:
            self.directory = ref.identity(root)
            self.stamp = ref.identity(root / 'ledger.json', hashed=True)
            self.state = json.loads(source_bytes(root / 'ledger.json', 4*MIB))
            require(self.state['schema'] == SCHEMA and self.state['directory'] == self.directory,
                    'foreign proof ledger')
            require(len(self.state['events']) <= 500, 'event bound exceeded')
            for item in self.state['events']:
                require(re.fullmatch(r'event-[0-9]{4}\.json', item['name']), 'foreign event path')
                ref.check_identity(root / item['name'], item['identity'])
            for name, record in self.state.get('files', {}).items():
                require(name in {'mode.json','probe.go','probe','image.tar','ack.json'}, 'foreign artifact path')
                ref.check_identity(root / name, record)
            self.mode_stamp = self.state['files']['mode.json']
            self.mode = json.loads(source_bytes(root / 'mode.json', 1024))['mode']
            self.validate()

    def validate(self):
        require(self.state.get('mode')==self.mode, 'proof mode is immutable; use a fresh UUID')
        graph = transitions(self.mode)
        require(self.state['phase'] in set(graph) | {'cleaned'}, 'phase incompatible with proof mode')
        require(self.state.get('files', {}).get('mode.json')==self.mode_stamp, 'proof mode record changed')
        ref.check_identity(self.root / 'mode.json', self.mode_stamp)
        require(self.mode=='bind' or not any(key in self.state for key in ('fixture','qualification_backend')),
                'local-only proof cannot claim bind qualification/macOS oracle')

    def check_transition(self, phase):
        self.validate()
        require(transitions(self.mode).get(self.state['phase'])==phase,
                'failed/interrupted/out-of-order proof; preserve, never resume/adopt')

    def save(self):
        self.validate()
        ref.check_identity(self.root, self.directory)
        if self.stamp is not None:
            ref.check_identity(self.root / 'ledger.json', self.stamp)
        temp = self.root / ('.ledger-' + uuid.uuid4().hex)
        ref.write_new(temp, encoded(self.state))
        os.replace(temp, self.root / 'ledger.json')
        ref.sync_directory(self.root)
        self.stamp = ref.identity(self.root / 'ledger.json', hashed=True)

    def event(self, kind, **data):
        require(len(self.state['events']) < 500, 'event bound exceeded')
        name = f"event-{len(self.state['events']):04d}.json"
        ref.write_new(self.root / name, encoded({'kind':kind, 'time':time.time(), **data}))
        ref.sync_directory(self.root)
        self.state['events'].append({'name':name, 'identity':ref.identity(self.root / name, hashed=True)})
        self.save()

    def phase(self, phase):
        self.check_transition(phase)
        self.state['phase'] = phase
        self.event('phase', phase=phase, mode=self.mode)

    def file(self, name, data):
        ref.write_new(self.root / name, data)
        ref.sync_directory(self.root)
        self.state.setdefault('files', {})[name] = ref.identity(self.root / name, hashed=True)
        self.save()


def tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.mode, info.size = mode, len(data)
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


def image_archive(binary, labels):
    require(0 < len(binary) <= 16*MIB, 'binary bound')
    layer = tar([('probe', binary, 0o755)])
    config = encoded({'architecture':'arm64','os':'linux',
        'config':{'Cmd':['/probe','serve'], 'User':'0:0', 'Labels':labels},
        'rootfs':{'type':'layers','diff_ids':['sha256:'+sha(layer)]}})
    descriptor = lambda data, kind: {'mediaType':'application/vnd.oci.image.'+kind,
                                    'digest':'sha256:'+sha(data),'size':len(data)}
    manifest = encoded({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json',
                       'config':descriptor(config,'config.v1+json'),
                       'layers':[descriptor(layer,'layer.v1.tar')]})
    index = encoded({'schemaVersion':2,'manifests':[descriptor(manifest,'manifest.v1+json')]})
    archive = tar([('oci-layout',encoded({'imageLayoutVersion':'1.0.0'}),0o644),
                   ('index.json',index,0o644), *[('blobs/sha256/'+sha(data),data,0o644)
                                              for data in (config,layer,manifest)]])
    require(len(archive) <= MAX_PAYLOAD, 'archive bound')
    # Classic Docker uses config IDs; Docker's containerd store uses manifest IDs.
    # Both are source-derived BEFORE import, never discovered/adopted by a query.
    return archive, {'config':'sha256:'+sha(config), 'manifest':'sha256:'+sha(manifest)}


def loaded_image(output, candidates):
    rows = [json.loads(line) for line in output.splitlines() if line.strip()]
    require(rows and not any('error' in row or 'errorDetail' in row for row in rows), 'image load failed/uncertain')
    returned = []
    for row in rows:
        for line in row.get('stream','').splitlines():
            match = re.fullmatch(r'Loaded image(?: ID)?: (sha256:[0-9a-f]{64})', line)
            if match:
                returned.append(match[1])
    require(len(returned)==1 and returned[0] in candidates.values(),
            'exact source-derived image ID not returned; no query/adopt')
    return returned[0]


def container_config(image, labels, mount):
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'only verified image IDs; pulls forbidden')
    require(mount.get('Type') in ('bind','volume'), 'unsupported probe mount type')
    return {'Image':image, 'Cmd':['/probe','serve'], 'User':'0:0', 'Labels':labels,
            'NetworkDisabled':True, 'HostConfig':{
                'NetworkMode':'none', 'ReadonlyRootfs':True, 'NanoCpus':2_000_000_000,
                'Memory':768*MIB, 'MemorySwap':768*MIB, 'PidsLimit':128,
                'CapDrop':['ALL'], 'CapAdd':['DAC_OVERRIDE'] if mount['Type']=='bind' else [],
                'SecurityOpt':['no-new-privileges:true'],
                'RestartPolicy':{'Name':'no','MaximumRetryCount':0}, 'LogConfig':{'Type':'none'},
                'IpcMode':'private', 'Privileged':False,
                'Mounts':[mount]}}


ROUTES = {
    'GET': r'/(?:version|info|images/sha256:[0-9a-f]{64}/json|containers/[0-9a-f]{64}/json|volumes/vrp-[0-9a-f-]+|exec/[0-9a-f]{64}/json)',
    'POST': r'/(?:images/load\?quiet=1|containers/create\?name=vrp-[0-9a-f-]+|containers/[0-9a-f]{64}/(?:start|stop\?t=1|exec)|volumes/create|exec/[0-9a-f]{64}/start)',
    'DELETE': r'/(?:containers/[0-9a-f]{64}\?force=0&v=0|volumes/vrp-[0-9a-f-]+|images/sha256:[0-9a-f]{64}\?force=0&noprune=1)',
}


def request_allowed(method, path):
    require(method in ROUTES and re.fullmatch(ROUTES[method], path),
            'unallowlisted API request; pull/build/prune/context forbidden')


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


def exchange(path, method, target, body, content_type, timeout):
    connection = UnixHTTP(path, timeout)
    connection.connect()
    sock = connection.sock
    def expire():
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        connection.request(method, target, body=body,
                           headers={'Content-Type':content_type, 'Connection':'close'})
        response = connection.getresponse()
        result = response.read(MIB+1)
        require(len(result) <= MIB, 'API output bound exceeded')
        return response.status, result
    finally:
        timer.cancel()
        connection.close()


class Probe:
    def __init__(self, reference, args, parent, ledger, transport=exchange):
        self.ref, self.args, self.parent, self.log = reference, args, parent, ledger
        self.transport = transport
        self.deadline = time.monotonic()+600
        self.output = self.calls = 0
        self.labels = {LABEL:args.run_id, LABEL+'.proof':args.proof_id, LABEL+'.mode':ledger.mode}

    def guard(self):
        self.log.validate()
        self.parent.check()
        self.ref.guard()
        state = self.ref.state
        require(state['phase']=='ready' and state['run_id']==self.args.run_id
                and state['daemon_id']==self.args.expected_daemon_id
                and state['endpoint']==self.args.endpoint and state['engine_version']=='29.2.1',
                'reference identity/phase mismatch')
        require(time.monotonic() < self.deadline, 'total ten-minute deadline exceeded')

    def running(self, phase):
        self.log.validate()
        require(self.log.state['phase']==phase+'-running', 'out-of-order phase invocation')

    def bind_guard(self):
        self.running('qualify')
        require(self.log.mode=='bind' and self.ref.state.get('same_path_fixture')
                and self.ref.state.get('fixture'), 'bind qualification requires owned same-path fixture')

    def api(self, method, path, data=None, *, raw=None, statuses=(200,), stream=False) -> Any:
        request_allowed(method, path)
        self.guard()
        self.calls += 1
        require(self.calls <= 180, 'API request count bound')
        body = raw if raw is not None else (encoded(data) if data is not None else b'')
        require(len(body) <= (MAX_PAYLOAD if raw is not None else MIB), 'API payload bound')
        self.log.event('request', method=method, path=path, api=API,
                       body=data if raw is None else {'sha256':sha(body),'size':len(body)})
        status, output = self.transport(self.ref.socket, method,
            ('' if path=='/version' else '/v'+API)+path, body,
            'application/x-tar' if raw is not None else 'application/json',
            min(60, self.deadline-time.monotonic()))
        self.output += len(output)
        require(len(output) <= MIB and self.output <= MIB, 'aggregate API output bound')
        self.log.event('response', status=status, body_b64=base64.b64encode(output).decode())
        require(status in statuses, f'API {method} {path} failed ({status}); preserve evidence')
        return output if stream else (json.loads(output) if output else None)

    def preflight(self):
        self.guard()
        self.ref.instance({'Running'})
        self.ref.daemon()
        version = self.api('GET','/version')
        parse = lambda v: tuple(map(int,v.split('.')))
        require(version['Version']=='29.2.1' and parse(version['MinAPIVersion']) <= parse(API)
                <= parse(version['ApiVersion']), 'Docker API/version mismatch')
        info = self.api('GET','/info')
        require(info['ID']==self.args.expected_daemon_id, 'API daemon changed')
        self.log.event('backend-host', host=platform.platform(), reference=self.ref.state,
                       info=info, version=version)

    def build(self):
        args = self.args
        require(all((args.go,args.go_sha256,args.source,args.source_sha256)), 'preparation requires pinned Go and source')
        go = ref.canonical(args.go)
        go_pin = ref.identity(go, hashed=True)
        require(go_pin['sha256']==args.go_sha256 and os.access(go,os.X_OK), 'Go tool pin mismatch')
        data = source_bytes(Path(args.source), MIB)
        require(sha(data)==args.source_sha256==FIXTURE_SHA, 'reviewed Go fixture source pin mismatch')
        self.log.file('probe.go',data)
        fs = os.statvfs(self.log.root)
        require(fs.f_bavail*fs.f_frsize >= 2*1024**3, 'need 2 GiB free for offline compiler/cache')
        for name in ('home','cache','tmp'):
            ref.private_directory(self.log.root / name)
        env = {'PATH':'/usr/bin:/bin','HOME':str(self.log.root/'home'),
               'TMPDIR':str(self.log.root/'tmp'), 'GOCACHE':str(self.log.root/'cache'),
               'CGO_ENABLED':'0','GOOS':'linux','GOARCH':'arm64','GOWORK':'off',
               'GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOENV':'off',
               'GOFLAGS':'','GOMAXPROCS':'2','GO111MODULE':'off'}
        argv = [str(go),'build','-p=2','-trimpath','-buildvcs=false','-ldflags=-buildid=',
                '-o',str(self.log.root/'probe'),str(self.log.root/'probe.go')]
        self.log.event('offline-build', argv=argv, env=env, go=go_pin,
                       controller_sha256=sha(source_bytes(Path(__file__),MIB)), reference_sha256=REFERENCE_SHA)
        ref.check_identity(go,go_pin)
        with (self.log.root/'build.stdout').open('xb') as out, (self.log.root/'build.stderr').open('xb') as err:
            result = ref.run_bounded(argv, env=env, cwd=self.log.root, stdin=subprocess.DEVNULL,
                                     stdout=out,stderr=err,timeout=min(60,self.deadline-time.monotonic()),check=False)
        require(result.returncode==0,'offline build failed; no fallback')
        ref.check_identity(go,go_pin)
        binary = source_bytes(self.log.root/'probe',16*MIB)
        self.log.state.setdefault('files',{})['probe'] = ref.identity(self.log.root/'probe',hashed=True)
        archive, candidates = image_archive(binary,self.labels)
        self.log.file('image.tar',archive)
        for candidate in candidates.values():
            self.api('GET','/images/'+candidate+'/json',statuses=(404,))
        self.log.state['image_candidates']=candidates
        self.log.save()
        output = self.api('POST','/images/load?quiet=1',raw=archive,stream=True)
        image = loaded_image(output,candidates)
        self.log.state['image']=image
        self.log.state['image_created']=True
        self.log.save()
        inspection = self.api('GET','/images/'+image+'/json')
        require(inspection['Id']==image and inspection['Config']['Labels']==self.labels, 'loaded image mismatch')

    def owned_container(self, cid):
        require(cid in self.log.state.get('containers',[]), 'unrecorded container')
        obj = self.api('GET','/containers/'+cid+'/json')
        require(obj['Id']==cid and obj['Config']['Labels']==self.labels
                and obj['Image']==self.log.state['image'], 'foreign container')
        return obj

    def container(self, mount):
        if mount.get('Type')=='bind':
            self.bind_guard()
        require(not self.log.state.get('running'), 'only one container may run at a time')
        config = container_config(self.log.state['image'], self.labels, mount)
        obj = self.api('POST','/containers/create?name=vrp-'+str(uuid.uuid4()),config,statuses=(201,))
        cid = obj['Id']; require(re.fullmatch(r'[0-9a-f]{64}',cid), 'missing exact container ID')
        self.log.state.setdefault('containers',[]).append(cid)
        self.log.save()
        # Inspect create-time isolation BEFORE executing even the pinned inert
        # serve entrypoint. After start, prove runtime mounts/network again before
        # permitting any filesystem command. serve only sleeps; it never writes.
        validate_container(self.owned_container(cid),config,mount,running=False)
        self.api('POST','/containers/'+cid+'/start',statuses=(204,))
        self.log.state['running']=cid; self.log.save()
        validate_container(self.owned_container(cid),config,mount,running=True)
        return cid

    def stop(self, cid):
        self.owned_container(cid)
        self.api('POST','/containers/'+cid+'/stop?t=1',statuses=(204,304))
        self.log.state['running']=None; self.log.save()

    def execute(self, cid, *args):
        require(cid in self.log.state['containers'], 'foreign exec target')
        require(args and args[0] in {'backend','read','splice','mmap','write','sync','namespace','seed','verify'}, 'foreign probe command')
        cmd = ['/probe',*args]
        obj = self.api('POST','/containers/'+cid+'/exec',
                       {'AttachStdout':True,'AttachStderr':True,'Tty':False,'Cmd':cmd,'User':'0:0'},statuses=(201,))
        eid = obj['Id']; require(re.fullmatch(r'[0-9a-f]{64}',eid),'invalid exec ID')
        wire = self.api('POST','/exec/'+eid+'/start',{'Detach':False,'Tty':False},stream=True)
        stdout, stderr = decode_stream(wire)
        status = self.api('GET','/exec/'+eid+'/json')
        require(not status['Running'] and status['ExitCode']==0 and not stderr,
                'probe failed; no retry/repair (see preserved exec output)')
        return json.loads(stdout)

    def backend(self, cid, filesystem):
        proof = self.execute(cid,'backend','/work')
        validate_backend(proof,filesystem)
        return proof

    def prepare_local(self):
        self.running('prepare-local')
        self.build()
        self.log.phase('local-ready')

    def qualify(self):
        self.bind_guard()
        self.build()
        directory = self.ref.root/'fixture'/('probe-'+self.args.proof_id)
        self.guard()
        record = ref.private_directory(directory)
        self.log.state['fixture']={'path':str(directory),'identity':record}; self.log.save()
        cid = self.container({'Type':'bind','Source':str(directory),'Target':'/work','ReadOnly':False})
        proof = self.backend(cid,'virtiofs')
        self.log.state['qualification_backend']=proof; self.log.save()
        nonce = (self.args.proof_id+'-host').encode()
        for reader in ('read','splice','mmap'):
            path = directory/reader
            ref.write_new(path,nonce)
            ref.sync_directory(directory)
            previous = nonce
            rewrites = [nonce,b'changed-content-not-definition',b'p'*4097,
                        bytes(range(256))*16+b'\x00',b'end',b'',b'r'*8193]
            for index, data in enumerate(rewrites):
                if index:
                    # Host close precedes the FIRST guest open. No stat/sleep/retry.
                    fd=os.open(path,os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
                    with os.fdopen(fd,'wb') as stream:
                        require(stream.write(data)==len(data),'short host write')
                actual = self.execute(cid,reader,'/work',reader,str(len(data)))
                want = {'size':len(data),'sha256':sha(data)}
                self.log.event('first-reopen',reader=reader,index=index,previous_size=len(previous),expected=want,actual=actual)
                require(actual==want,'authoritative FIRST read failed; never retry')
                previous=data
        guest = (self.args.proof_id+'-guest').encode()
        result = self.execute(cid,'write','/work','guest',base64.b64encode(guest).decode())
        require(result=={'size':len(guest),'sha256':sha(guest)} and source_bytes(directory/'guest',MIB)==guest,
                'guest file/parent fsync not host-visible')
        ref.write_new(directory/'before',b'namespace'); ref.write_new(directory/'removed',b'unlink')
        os.rename(directory/'before',directory/'renamed'); os.unlink(directory/'removed')
        os.symlink('./renamed',directory/'literal'); ref.sync_directory(directory)
        require(self.execute(cid,'namespace','/work')=={'namespace':True},'namespace probe failed')
        require(source_bytes(directory/'guest-renamed',MIB)==b'namespace'
                and os.readlink(directory/'guest-literal')=='./guest-renamed'
                and not os.path.lexists(directory/'literal'),'guest namespace not host-visible')
        require(self.backend(cid,'virtiofs')['boot_id']==proof['boot_id'],'guest boot changed during qualification')
        self.ref.daemon(); self.stop(cid)
        self.log.phase('qualified')

    def volume(self):
        name = 'vrp-'+self.args.proof_id
        self.api('GET','/volumes/'+name,statuses=(404,))
        obj = self.api('POST','/volumes/create',{'Name':name,'Driver':'local','Labels':self.labels},statuses=(201,))
        require(obj['Name']==name and obj['Driver']=='local' and obj['Labels']==self.labels
                and not obj.get('Options'), 'volume create response uncertain/foreign')
        self.log.state['volume']=name; self.log.save()
        return name

    def owned_volume(self):
        name = self.log.state['volume']
        require(name=='vrp-'+self.args.proof_id,'foreign recorded volume')
        obj=self.api('GET','/volumes/'+name)
        require(obj['Name']==name and obj['Driver']=='local' and obj['Labels']==self.labels
                and not obj.get('Options'), 'volume ownership/backend changed')
        return name

    def seed(self):
        self.running('seed')
        name=self.volume()
        cid=self.container({'Type':'volume','Source':name,'Target':'/work','ReadOnly':False,
                            'VolumeOptions':{'NoCopy':True}})
        proof=self.backend(cid,'ext4')
        ack=self.execute(cid,'seed','/work',self.args.proof_id)
        require(ack.get('ACK') is True and 0 < ack['operation_bytes'] <= 16*MIB,
                'missing/bounded seed acknowledgement')
        validate_backend(ack['backend'],'ext4')
        require(ack['backend']['boot_id']==proof['boot_id'],'boot changed during seed')
        # Independent readback BEFORE acknowledging. Verification never rewrites.
        readback=self.execute(cid,'verify','/work',self.args.proof_id)
        require(readback['verified'] and readback['manifest']==ack['manifest'],'independent readback mismatch')
        self.ref.daemon()
        self.log.state['restart_count']=self.ref.state.get('restart_count',0)
        self.log.state['ack']=ack
        self.log.file('ack.json',encoded({'run_id':self.args.run_id,'proof_id':self.args.proof_id,
            'daemon_id':self.args.expected_daemon_id,'volume':name,'container':cid,'image':self.log.state['image'],
            'api':API,'mode':self.log.mode,'ack':ack,'files':self.log.state['files']}))
        self.log.phase('acknowledged')
        # Leave exact resources intact; main owns the crash/restart boundary.

    def verify(self):
        self.running('verify')
        require(self.ref.state.get('restart_count',0)==self.log.state['restart_count']+1,
                'verify needs exactly one later guarded Reference restart')
        name=self.owned_volume()
        self.log.state['running']=None  # prior VM crash stops non-restarting containers
        old=self.log.state['containers'][-1]
        require(not self.owned_container(old)['State']['Running'],'seed container unexpectedly restarted')
        cid=self.container({'Type':'volume','Source':name,'Target':'/work','ReadOnly':True,
                            'VolumeOptions':{'NoCopy':True}})
        result=self.execute(cid,'verify','/work',self.args.proof_id)
        validate_backend(result['backend'],'ext4')
        ack=self.log.state['ack']
        require(result['backend']['boot_id']!=ack['backend']['boot_id'], 'guest boot did not change')
        require(result['backend']['kernel']==ack['backend']['kernel'], 'guest kernel changed')
        require(result['verified'] and result['manifest']==ack['manifest'],'acknowledged data/metadata lost')
        self.log.event('crash-verified',result=result)
        self.ref.daemon(); self.stop(cid)
        self.log.phase('verified')

    def cleanup(self):
        self.running('cleanup')
        # Explicit only after successful verify. No force/prune/remove-volume side effects.
        for cid in self.log.state['containers']:
            obj=self.owned_container(cid)
            require(not obj['State']['Running'],'cleanup refuses running container')
            self.api('DELETE','/containers/'+cid+'?force=0&v=0',statuses=(204,))
        name=self.owned_volume()
        self.api('DELETE','/volumes/'+name,statuses=(204,))
        image=self.log.state['image']
        obj=self.api('GET','/images/'+image+'/json')
        require(self.log.state['image_created'] and obj['Id']==image and obj['Config']['Labels']==self.labels,
                'cleanup refuses foreign image')
        self.api('DELETE','/images/'+image+'?force=0&noprune=1')
        self.log.phase('cleaned')
        # Host fixture, compiler/cache and durable evidence deliberately retained.


def decode_stream(wire):
    output=[bytearray(),bytearray()]
    while wire:
        require(len(wire)>=8 and wire[0] in (1,2) and wire[1:4]==b'\0\0\0','invalid Docker stream frame')
        n=int.from_bytes(wire[4:8],'big')
        require(n <= len(wire)-8,'truncated Docker stream')
        output[wire[0]-1].extend(wire[8:8+n]); wire=wire[8+n:]
    return bytes(output[0]),bytes(output[1])


def validate_container(obj, config, mount, *, running):
    h=obj['HostConfig']
    require(mount.get('Type') in ('bind','volume'), 'unsupported probe mount type')
    # Docker may report the canonical CAP_ spelling; accept exactly one DAC
    # override for bind qualification, and only absent/null/empty for volumes.
    allowed_add = (['DAC_OVERRIDE'], ['CAP_DAC_OVERRIDE']) if mount['Type']=='bind' else (None, [])
    require(h.get('CapDrop')==['ALL'] and h.get('CapAdd') in allowed_add,
            'container capability allowance changed')
    for key in ('NanoCpus','Memory','MemorySwap','PidsLimit','NetworkMode','ReadonlyRootfs',
                'RestartPolicy','IpcMode','Privileged'):
        require(h[key]==config['HostConfig'][key], 'container resource/isolation bound changed: '+key)
    require(obj['State']['Running'] is running and obj['Config']['NetworkDisabled'] is True
            and obj['Config']['User']=='0:0' and obj['Config']['Cmd']==['/probe','serve'],
            'unexpected state/user/entrypoint/network configuration')
    require(h['SecurityOpt']==['no-new-privileges:true'] and h['LogConfig']['Type']=='none'
            and not h.get('Binds') and not h.get('Devices') and not h.get('VolumesFrom')
            and not h.get('PidMode') and not h.get('PortBindings'), 'unexpected isolation/host access')
    networks=obj['NetworkSettings']['Networks'] or {}
    require(set(networks) <= {'none'}, 'attached non-none network')
    for network in networks.values():
        require(not any(network.get(k) for k in ('IPAddress','GlobalIPv6Address','Gateway','IPv6Gateway','MacAddress')),
                'unexpected network address')
    mounts=obj['Mounts']
    require(len(mounts)==1 and mounts[0]['Destination']=='/work'
            and mounts[0]['Type']==mount['Type'] and mounts[0]['RW']==(not mount['ReadOnly']),
            'unexpected container mount')
    if mount['Type']=='bind':
        require(mounts[0]['Source']==mount['Source'], 'bind source must equal the exact host absolute path')
    else:
        require(mounts[0]['Name']==mount['Source'] and mounts[0]['Driver']=='local', 'foreign volume mount')


def validate_backend(proof, filesystem):
    magic={'virtiofs':'65735546','ext4':'ef53'}[filesystem]
    require(proof['statfs']==magic and str(uuid.UUID(proof['boot_id']))==proof['boot_id']
            and bool(proof['kernel']), 'missing actual statfs/kernel/boot evidence')
    lines=[line for line in proof['mountinfo'].splitlines() if len(line.split())>6 and line.split()[4]=='/work']
    tokens={'virtiofs','fuse.virtiofs'} if filesystem=='virtiofs' else {'ext4'}
    require(len(lines)==1 and ' - ' in lines[0]
            and lines[0].split(' - ',1)[1].split()[0] in tokens, 'actual mountinfo backend mismatch')


def parser():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('phase',choices=('qualify','prepare-local','seed','verify','cleanup'))
    for key in ('root','run-id','expected-daemon-id','endpoint','proof-id','compat-lock'):
        p.add_argument('--'+key,required=True)
    p.add_argument('--parent-lock-pid',type=int,required=True)
    p.add_argument('--allow-disposable-reference',action='store_true',required=True)
    for key in ('go','go-sha256','source','source-sha256'):
        p.add_argument('--'+key)
    return p


def main(argv=None):
    args=parser().parse_args(argv)
    require(args.allow_disposable_reference,'explicit disposable reference permission required')
    require(str(uuid.UUID(args.run_id))==args.run_id and str(uuid.UUID(args.proof_id))==args.proof_id,'canonical UUIDs required')
    parent=ParentLock(args.compat_lock,args.parent_lock_pid)
    with ref.Reference(args.root) as reference:
        # Guard BEFORE creating any proof files, invoking CLI, or opening the endpoint.
        require(reference.state['run_id']==args.run_id and reference.state['daemon_id']==args.expected_daemon_id
                and reference.state['endpoint']==args.endpoint and reference.state['phase']=='ready', 'foreign reference')
        path=reference.root/'artifacts'/('probe-'+args.proof_id)
        initial={'run_id':args.run_id,'proof_id':args.proof_id,'endpoint':args.endpoint,
                 'daemon_id':args.expected_daemon_id,'phase':'new','mode':PREPARATIONS.get(args.phase),'containers':[],
                 'controller_sha256':sha(source_bytes(Path(__file__),MIB))} if args.phase in PREPARATIONS else None
        ledger=Ledger(path,initial)
        require(all(ledger.state[key]==value for key,value in (
            ('run_id',args.run_id),('proof_id',args.proof_id),('endpoint',args.endpoint),
            ('daemon_id',args.expected_daemon_id),('controller_sha256',sha(source_bytes(Path(__file__),MIB))))), 'foreign/changed proof')
        ledger.check_transition(args.phase+'-running')
        probe=Probe(reference,args,parent,ledger)
        # Persist intent before any external preflight: failure/interruption is terminal.
        ledger.phase(args.phase+'-running')
        probe.preflight()
        getattr(probe,args.phase.replace('-','_'))()
        print(json.dumps({'phase':ledger.state['phase'],'mode':ledger.mode,'ledger':str(path/'ledger.json'),
                          'ACK':ledger.state['phase']=='acknowledged'}))


if __name__=='__main__':
    try:
        main()
    except (ref.Refusal,OSError,ValueError,KeyError,RuntimeError,subprocess.SubprocessError,http.client.HTTPException) as error:
        print(f'REFUSED; preserve resources and ledger: {error}',file=sys.stderr)
        sys.exit(2)
