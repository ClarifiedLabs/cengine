#!/usr/bin/env python3
r"""Disposable Docker 29.2.1 / API 1.52 volume-prune reference (stdlib only).

Usage (parent must already own the current UID's canonical runner claim;
this command never acquires a claim or authorizes a new disposable daemon):
  CLAIM=$(python3 Tests/Compatibility/helper_fixture_lifetime.py)
  python3 tools/volume_reference_prune.py --allow-disposable-reference \
    --root /canonical/new-reference --run-id UUID --proof-id FRESH-UUID \
    --expected-daemon-id ID --endpoint unix:///exact/owned/docker.sock \
    --compat-lock "$CLAIM" --parent-lock-pid PARENT

The shared claim is /private/tmp/cengine-compat-run-$(id -u).lock. If set,
CENGINE_COMPAT_LOCK must match it; HOME/TMPDIR must match runner policy. Do not
create an alternate claim for this tool. PARENT must be the actual calling parent.

Use a NEW dedicated Reference ready run, never an existing Colima installation.
Permission covers the ENTIRE disposable daemon: filters under test are NOT an
ownership boundary. First volume inventory must be empty. Six independent fixture
scenarios start empty; some have consecutive filter cases over their remaining
known set. Exactly 12 empty local volumes total, at most three present. Named
creates require prior 404; anonymous create omits Name and durably captures ONLY
the successful response's random name (unknown names cannot be pre-queried).

Only direct pinned Unix HTTP: no CLI, SDK, pytest, context, pull, image/container
operation, VM lifecycle, or Reference.invoke/instance/daemon (the latter invokes
a CLI). Direct /info implements Reference.daemon's checks and additionally pins
the observed kernel/platform before each mutation. Existing images/containers
are neither inspected nor touched. Active-volume protection is NOT covered: it
would need a container/image. Empty volumes cannot prove portable reclaimed bytes.

Fresh-only immutable volume-prune proof identity; fsynced intent precedes external
preflight. Every request/response has bounded durable evidence. A failure preserves
ALL remaining resources: no retry, adoption, resume, or automatic cleanup. Successful
cases alone permit exact DELETE of positively created remaining volumes, followed
by 404 and empty-inventory proof. Report/ledger remain under artifacts/prune-UUID.
Bounds: ten minutes total, sixty seconds/request, 64 KiB wire response, <=1 MiB
aggregate API request/response bytes AND event evidence; <=240 API calls.

Contract sources at Moby docker-v29.2.1 (6bc6209b88a7a834c91f77d848e025c79e0227a1):
https://github.com/moby/moby/blob/docker-v29.2.1/daemon/volume/service/service.go
  Create, AnonymousLabel, acceptedPruneFilters, Prune (local/unreferenced/no opts).
https://github.com/moby/moby/blob/docker-v29.2.1/daemon/volume/service/convert.go
  withPrune (default anonymous, all=true; invalid boolean is HTTP 400).
https://github.com/moby/moby/blob/docker-v29.2.1/daemon/volume/service/by.go
  byLabelFilter (positive conjunction; negative complement).
https://github.com/moby/moby/blob/docker-v29.2.1/daemon/server/router/volume/volume_routes.go
  postVolumesPrune (API >=1.42 anonymous default); unknown filter is HTTP 400.
Trust boundary matches pinned Reference: invoking UID/root trusted, no hostile
same-UID races, ACL-writable ancestors, or concurrent out-of-band daemon writers.
Engine-free tests are NOT live Docker qualification; a dedicated live gate remains.
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
import re
import socket
import stat
import sys
import threading
import time
import types
from typing import Any
import uuid
from urllib.parse import quote

MIB = 1024 * 1024
MAX_REPLY = 64 * 1024
MAX_CALLS = 240
REFERENCE_SHA = 'cc191c4159d66fe608f5c7414243d2d5c1ea201418e941cff81c6da985d9ab22'
API = '1.52'
MODE = 'volume-prune'
LABEL = 'dev.cengine.volume-reference'
COLOR = LABEL + '.color'
GROUP = LABEL + '.group'
ANONYMOUS = 'com.docker.volume.anonymous'
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'Tests/Compatibility'))
import helper_fixture_lifetime as claims


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def source_bytes(path, limit=MIB):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise RuntimeError('bounded single-link regular input required')
        data = stream.read(limit + 1)
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_nlink, s.st_uid,
                           s.st_gid, s.st_mtime_ns, s.st_ctime_ns)
        if len(data) > limit or stamp(before) != stamp(os.fstat(fd)):
            raise RuntimeError('input changed or oversized')
        return data


def load_reference():
    path = Path(__file__).resolve().with_name('volume_reference.py')
    data = source_bytes(path)
    if hashlib.sha256(data).hexdigest() != REFERENCE_SHA:
        raise RuntimeError('reviewed adjacent Reference SHA changed')
    module = types.ModuleType('pinned_prune_reference')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


ref = load_reference()
require = ref.require


class ParentLock:
    def __init__(self, path, pid):
        self.path = ref.canonical(path)
        require(self.path == claims.launcher_lock(), 'canonical global compatibility lock required, not a lookalike')
        require(type(pid) is int and pid > 1 and pid == os.getppid(), 'actual calling parent must own lock')
        self.pid = pid
        self.directory = ref.identity(self.path)
        self.record = ref.identity(self.path / 'pid', hashed=True)
        require(self.directory['mode'] == stat.S_IFDIR and self.directory['uid'] == os.getuid()
                and self.record['mode'] == stat.S_IFREG and self.record['uid'] == os.getuid(),
                'foreign global lock owner')
        self.check()

    def check(self):
        ref.check_identity(self.path, self.directory)
        ref.check_identity(self.path / 'pid', self.record)
        require(source_bytes(self.path / 'pid', 32).strip() == str(self.pid).encode()
                and os.getppid() == self.pid, 'global lock parent changed')
        os.kill(self.pid, 0)  # liveness only; never signal, acquire, steal, or remove


class Ledger:
    """Fresh-only ledger. There deliberately is no load/resume constructor."""
    def __init__(self, root, initial):
        require(initial.get('mode') == MODE and initial.get('phase') == 'new', 'immutable fresh prune mode required')
        self.root = root
        self.directory = ref.private_directory(root)
        self.proof = dict(initial)
        ref.write_new(root / 'proof.json', encoded(initial))
        self.proof_stamp = ref.identity(root / 'proof.json', hashed=True)
        self.state: dict[str, Any] = dict(initial, events=[], created={}, remaining=[], results=[])
        self.stamp = None
        self.event_bytes = 0
        self.phase_name = 'new'
        self.save()
        ref.sync_directory(root.parent)

    def validate(self):
        ref.check_identity(self.root, self.directory)
        ref.check_identity(self.root / 'proof.json', self.proof_stamp)
        require(all(self.state.get(k) == v for k, v in self.proof.items() if k != 'phase'),
                'proof identity/mode is immutable')
        require(self.state['phase'] == self.phase_name, 'phase tampering')
        if self.stamp is not None:
            ref.check_identity(self.root / 'ledger.json', self.stamp)
        for item in self.state['events']:
            ref.check_identity(self.root / item['name'], item['identity'])

    def save(self):
        self.validate()
        data = encoded(self.state)
        require(len(data) <= MIB, 'ledger bound')
        temp = self.root / ('.ledger-' + uuid.uuid4().hex)
        ref.write_new(temp, data)
        os.replace(temp, self.root / 'ledger.json')
        ref.sync_directory(self.root)
        self.stamp = ref.identity(self.root / 'ledger.json', hashed=True)

    def event(self, kind, **data):
        self.validate()
        payload = encoded({'kind': kind, 'time': time.time(), **data})
        require(len(self.state['events']) < 600 and self.event_bytes + len(payload) <= MIB, 'aggregate evidence bound')
        name = f"event-{len(self.state['events']):04d}.json"
        ref.write_new(self.root / name, payload)
        ref.sync_directory(self.root)
        self.event_bytes += len(payload)
        self.state['events'].append({'name': name, 'identity': ref.identity(self.root / name, hashed=True)})
        self.save()

    def phase(self, phase):
        self.validate()
        require({'new': 'running', 'running': 'completed'}.get(self.phase_name) == phase,
                'terminal/out-of-order proof; never resume')
        self.phase_name = self.state['phase'] = phase
        self.event('phase', phase=phase, mode=MODE)


class ExchangeError(RuntimeError):
    def __init__(self, message, partial):
        super().__init__(message)
        self.partial = partial


def exchange(path, method, target, body, timeout):
    """Bound the entire wire (including HTTP headers), even with slow trickles."""
    connection = http.client.HTTPConnection('localhost', timeout=timeout)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    connection.sock = sock
    raw = bytearray()
    expired = threading.Event()
    deadline = time.monotonic() + timeout

    def expire():
        expired.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        sock.connect(str(path))
        connection.request(method, target, body=body, headers={'Content-Type': 'application/json', 'Connection': 'close'})
        while True:
            block = sock.recv(min(8192, MAX_REPLY + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            require(len(raw) <= MAX_REPLY, 'wire response bound exceeded')
        fake: Any = types.SimpleNamespace(makefile=lambda *args: io.BytesIO(raw))
        response = http.client.HTTPResponse(fake)
        response.begin()
        output = response.read(MAX_REPLY + 1)
        require(len(output) <= MAX_REPLY and response.length in (None, 0), 'decoded response bound/truncated response')
        # HTTPResponse tolerates EOF in chunk trailers; evidence must be complete.
        require(not response.chunked or raw.endswith(b'\r\n\r\n'), 'truncated chunked trailer terminator')
        require(not expired.is_set() and time.monotonic() < deadline, 'request deadline expired; response uncertain')
        return response.status, output, bytes(raw)
    except Exception as error:
        raise ExchangeError(type(error).__name__ + ': ' + str(error)[:256], bytes(raw[:MAX_REPLY])) from error
    finally:
        timer.cancel()
        connection.close()


def prune_path(filters):
    return '/volumes/prune?filters=' + quote(encoded(filters).decode(), safe='')


# Literal expectations, not an implementation of the filtering algorithm under test.
# Case tuples: (name, filters, deleted fixture indices, expected HTTP status).
SCENARIOS = (
    ('default-all', ((False, {}), (True, {})), (
        ('default-anonymous-only', {}, (1,), 200),
        ('all-includes-named', {'all': ['true']}, (0,), 200))),
    ('label-key', ((False, {COLOR: 'red'}), (False, {})), (
        ('label-key', {'all': ['true'], 'label': [COLOR]}, (0,), 200),)),
    ('value-conjunction', ((False, {COLOR: 'red', GROUP: 'yes'}), (False, {COLOR: 'red'}),
                           (False, {COLOR: 'blue', GROUP: 'yes'})), (
        ('label-conjunction', {'all': ['true'], 'label': [COLOR + '=red', GROUP + '=yes']}, (0,), 200),
        ('label-value', {'all': ['true'], 'label': [COLOR + '=red']}, (1,), 200))),
    ('negative-key', ((False, {COLOR: 'red'}), (False, {})), (
        ('label-not-key', {'all': ['true'], 'label!': [COLOR]}, (1,), 200),)),
    ('negative-value', ((False, {COLOR: 'red'}), (False, {COLOR: 'blue'})), (
        ('label-not-value', {'all': ['true'], 'label!': [COLOR + '=red']}, (1,), 200),)),
    ('invalid', ((False, {}),), (
        ('unsupported-filter', {'all': ['true'], 'dangling': ['true']}, (), 400),
        ('malformed-all', {'all': ['not-a-bool']}, (), 400))),
)
PRUNE_PATHS = {prune_path(filters) for _, _, cases in SCENARIOS for _, filters, _, _ in cases}


def request_allowed(method, path, names):
    allowed = ((method == 'GET' and path in {'/version', '/info', '/volumes'})
               or (method == 'POST' and (path == '/volumes/create' or path in PRUNE_PATHS))
               or (method in {'GET', 'DELETE'} and any(path == '/volumes/' + name for name in names)))
    require(allowed, 'unallowlisted API route; volume-only exact targets required')


class Prune:
    def __init__(self, reference, args, parent, ledger, transport=exchange, deadline=None):
        self.ref, self.args, self.parent, self.log = reference, args, parent, ledger
        self.transport = transport
        self.deadline = deadline if deadline is not None else time.monotonic() + 600
        self.calls = self.api_bytes = 0
        self.terminal = False
        self.names = set()
        self.kernel = None
        self.labels = {LABEL: args.run_id, LABEL + '.proof': args.proof_id, LABEL + '.mode': MODE}

    def guard(self):
        require(not self.terminal, 'terminal failure; preserve, never resume/adopt')
        require(self.args.allow_disposable_reference, 'explicit disposable reference permission required')
        self.parent.check()
        self.ref.guard()
        self.log.validate()
        s = self.ref.state
        require(s['root'] == str(self.ref.root) == self.args.root and s['run_id'] == self.args.run_id
                and s['daemon_id'] == self.args.expected_daemon_id and s['endpoint'] == self.args.endpoint
                and s['phase'] == 'ready' and s['engine_version'] == '29.2.1', 'foreign reference identity/phase')
        require(s['endpoint'] == 'unix://' + str(self.ref.socket), 'foreign socket endpoint')
        relative = str(self.ref.socket.relative_to(self.ref.root))
        record = ref.identity(self.ref.socket)
        require(record['mode'] == stat.S_IFSOCK and s['records'].get(relative) == record, 'unowned/replaced socket')
        require(self.log.phase_name == 'running', 'operation intent must precede preflight')
        require(time.monotonic() < self.deadline, 'total ten-minute deadline exceeded')

    def api(self, method, path, data=None, status=200):
        try:
            request_allowed(method, path, self.names)
            self.guard()
            require(self.calls < MAX_CALLS, 'API call bound')
            body = encoded(data) if data is not None else b''
            require(len(body) <= 4096 and self.api_bytes + len(body) + MAX_REPLY <= MIB, 'aggregate API byte bound')
            # Reserve enough durable space for a maximum response before mutation.
            require(self.log.event_bytes + 2 * MAX_REPLY + 8192 <= MIB, 'aggregate evidence reservation bound')
            self.calls += 1
            target = ('' if path == '/version' else '/v' + API) + path
            self.log.event('request', method=method, target=target, body_b64=base64.b64encode(body).decode())
            self.guard()  # intent fsync may have taken time or lost parent ownership
            code, output, wire = self.transport(self.ref.socket, method, target, body, min(60, self.deadline - time.monotonic()))
            self.api_bytes += len(body) + len(wire)
            self.log.event('response', status=code, wire_b64=base64.b64encode(wire[:MAX_REPLY]).decode())
            require(len(wire) <= MAX_REPLY and len(output) <= MAX_REPLY and self.api_bytes <= MIB, 'API response bound')
            require(time.monotonic() < self.deadline, 'total deadline exceeded after response')
            require(code == status, f'API {method} {path}: expected {status}, got {code}')
            return json.loads(output) if output else None
        except BaseException as error:
            self.terminal = True
            try:
                self.log.event('terminal-failure', error=type(error).__name__, detail=str(error)[:512],
                               partial_wire_b64=base64.b64encode(getattr(error, 'partial', b'')[:MAX_REPLY]).decode())
            except BaseException:
                pass  # existing durable intent remains terminal even on disk failure
            raise

    def daemon(self):
        info = self.api('GET', '/info')
        require(info['ID'] == self.args.expected_daemon_id and info['ServerVersion'] == '29.2.1'
                and info['OSType'] == 'linux' and info['Architecture'] in ('aarch64', 'arm64')
                and isinstance(info['KernelVersion'], str) and bool(info['KernelVersion'])
                and not any('rootless' in str(x) for x in info.get('SecurityOptions', []))
                and info.get('Swarm', {}).get('LocalNodeState') == 'inactive', 'foreign daemon/kernel/platform')
        observed = (info['KernelVersion'], info['OSType'], info['Architecture'])
        require(self.kernel is None or self.kernel == observed, 'kernel/platform changed')
        self.kernel = observed
        return info

    def preflight(self):
        self.guard()
        version = self.api('GET', '/version')
        parse = lambda value: tuple(map(int, value.split('.')))
        require(version['Version'] == '29.2.1' and version['Os'] == 'linux' and version['Arch'] == 'arm64'
                and parse(version['MinAPIVersion']) <= parse(API) <= parse(version['ApiVersion']), 'Docker API/version/platform mismatch')
        info = self.daemon()
        self.log.event('backend', api=API, version=version, info=info)
        self.inventory(set())  # first GET /volumes MUST be empty, no label filtering

    def owned(self, obj, name):
        expected = self.log.state['created'][name]
        require(isinstance(obj, dict) and obj.get('Name') == name and obj.get('Driver') == 'local'
                and obj.get('Scope') == 'local' and obj.get('Options') in (None, {})
                and obj.get('Labels') == expected['labels'], 'foreign volume identity/backend')

    def inventory(self, expected):
        obj = self.api('GET', '/volumes')
        require(isinstance(obj, dict) and obj.get('Warnings') in (None, []) and 'Volumes' in obj,
                'incomplete volume inventory')
        rows = obj['Volumes']
        require(rows is None or isinstance(rows, list), 'invalid inventory')
        rows = [] if rows is None else rows
        require(len(rows) <= 12 and all(isinstance(v, dict) and isinstance(v.get('Name'), str) for v in rows), 'inventory bound/shape')
        names = [v['Name'] for v in rows]
        require(len(names) == len(set(names)) and set(names) == expected, 'foreign/nonempty volume inventory')
        for obj in rows:
            self.owned(obj, obj['Name'])

    def create(self, scenario, index, anonymous, extra):
        require(len(self.log.state['created']) < 12, 'total volume creation bound')
        name = f'vrpr-{self.args.proof_id}-{scenario}-{index}'
        labels = dict(self.labels, **extra, **{LABEL + '.operation': scenario + '-' + str(index)})
        config = {'Driver': 'local', 'Labels': labels}
        self.daemon()
        self.inventory(set(self.log.state['remaining']))
        if not anonymous:
            self.names.add(name)
            self.api('GET', '/volumes/' + name, status=404)
            config['Name'] = name
        obj = self.api('POST', '/volumes/create', config, status=201)
        if anonymous:
            name = obj.get('Name')
            require(isinstance(name, str) and re.fullmatch(r'[0-9a-f]{64}', name), 'missing exact anonymous response name; never query/adopt')
            labels = {**labels, ANONYMOUS: ''}
        require(name not in self.log.state['created'] and obj.get('Name') == name, 'duplicate/foreign create response')
        self.log.state['created'][name] = {'labels': labels, 'anonymous': anonymous}
        self.log.state['remaining'].append(name)
        self.log.event('created', name=name, anonymous=anonymous, labels=labels)
        self.names.add(name)  # only successful response permits subsequent queries
        self.owned(obj, name)
        return name

    def case(self, title, filters, expected, status):
        self.daemon()
        before = set(self.log.state['remaining'])
        require(expected <= before, 'invalid expected delete set')
        self.inventory(before)  # entire VM inventory, not filtered ownership labels
        self.log.event('case-intent', case=title, filters=filters, expected_deleted=sorted(expected), expected_status=status)
        obj = self.api('POST', prune_path(filters), status=status)
        if status == 200:
            deleted = obj.get('VolumesDeleted')
            require(isinstance(deleted, list) and all(isinstance(n, str) for n in deleted)
                    and len(deleted) == len(set(deleted)) and set(deleted) == expected,
                    'VolumesDeleted must equal exact expected set')
            require(type(obj.get('SpaceReclaimed')) is int and obj['SpaceReclaimed'] >= 0, 'invalid reclaimed bytes')
        else:
            require(isinstance(obj, dict) and isinstance(obj.get('message'), str) and bool(obj['message']), 'missing HTTP 400 error evidence')
        self.inventory(before - expected)
        for name in sorted(expected):
            self.api('GET', '/volumes/' + name, status=404)
        self.log.state['remaining'] = sorted(before - expected)
        self.log.state['results'].append({'case': title, 'deleted': sorted(expected), 'status': status})
        self.log.event('case-completed', case=title, deleted=sorted(expected), status=status)

    def cleanup_completed(self):
        # Called only after ALL cases in this fixture scenario have completed.
        for name in list(self.log.state['remaining']):
            self.daemon()
            self.inventory(set(self.log.state['remaining']))
            self.owned(self.api('GET', '/volumes/' + name), name)
            self.api('DELETE', '/volumes/' + name, status=204)
            self.api('GET', '/volumes/' + name, status=404)
            self.log.state['remaining'].remove(name)
            self.log.event('cleanup-deleted', name=name)
        self.inventory(set())

    def run(self):
        try:
            self.preflight()
            for scenario, specs, cases in SCENARIOS:
                self.inventory(set())
                self.log.event('scenario-intent', scenario=scenario)
                names = [self.create(scenario, i, anonymous, labels) for i, (anonymous, labels) in enumerate(specs)]
                for title, filters, indices, status in cases:
                    self.case(title, filters, {names[i] for i in indices}, status)
                self.log.event('scenario-completed', scenario=scenario)
                self.cleanup_completed()
            self.log.phase('completed')
        except BaseException:
            self.terminal = True
            raise  # NO cleanup, resume, discovery, or adoption on any failure


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for key in ('root', 'run-id', 'proof-id', 'expected-daemon-id', 'endpoint', 'compat-lock'):
        p.add_argument('--' + key, required=True)
    p.add_argument('--parent-lock-pid', type=int, required=True)
    p.add_argument('--allow-disposable-reference', action='store_true', required=True)
    return p


def main(argv=None):
    deadline = time.monotonic() + 600
    args = parser().parse_args(argv)
    require(args.allow_disposable_reference, 'explicit disposable reference permission required')
    require(str(uuid.UUID(args.run_id)) == args.run_id and str(uuid.UUID(args.proof_id)) == args.proof_id,
            'canonical run/proof UUID required')
    parent = ParentLock(args.compat_lock, args.parent_lock_pid)
    with ref.Reference(args.root) as reference:
        require(reference.state['root'] == args.root and reference.state['run_id'] == args.run_id
                and reference.state['daemon_id'] == args.expected_daemon_id
                and reference.state['endpoint'] == args.endpoint and reference.state['phase'] == 'ready'
                and reference.state['engine_version'] == '29.2.1', 'foreign reference')
        parent.check()  # before first proof filesystem mutation
        # Share the proof namespace with immutable probe ledgers: never reuse their UUID.
        require(not os.path.lexists(reference.root / 'artifacts' / ('probe-' + args.proof_id)), 'proof UUID already used by probe')
        path = reference.root / 'artifacts' / ('prune-' + args.proof_id)
        ledger = Ledger(path, {'mode': MODE, 'phase': 'new', 'run_id': args.run_id, 'proof_id': args.proof_id,
                              'root': args.root, 'endpoint': args.endpoint, 'daemon_id': args.expected_daemon_id,
                              'controller_sha256': hashlib.sha256(source_bytes(Path(__file__))).hexdigest(),
                              'reference_sha256': REFERENCE_SHA})
        ledger.phase('running')  # durable intent BEFORE any external preflight request
        probe = Prune(reference, args, parent, ledger, deadline=deadline)
        probe.run()
        print(json.dumps({'mode': MODE, 'phase': 'completed', 'ledger': str(path / 'ledger.json'),
                          'cases': ledger.state['results'], 'active_volume_protection': 'not covered (no image/container)',
                          'remaining_volumes': [], 'api_bytes': probe.api_bytes, 'api_calls': probe.calls}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ref.Refusal, OSError, ValueError, KeyError, RuntimeError, http.client.HTTPException) as error:
        print(f'REFUSED: {error}\nPreserve all resources and proof evidence; no automatic cleanup or resume.', file=sys.stderr)
        sys.exit(2)
