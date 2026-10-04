#!/usr/bin/env python3
"""Engine-free prune regression suite: python3 tools/tests/test-volume-reference-prune.py.

No Docker, VM, subprocess, image, container, pytest, SDK or external network.
The fake engine is an independent filter oracle; literal result sets are asserted.
"""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

PATH = Path(__file__).resolve().parents[1] / 'volume_reference_prune.py'
spec = importlib.util.spec_from_file_location('prune', PATH)
assert spec is not None and spec.loader is not None
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
RUN = '7ca0df3f-e945-4d97-b6ec-b787dbc2d730'
PROOF = '24299546-784f-42d2-969b-179232199f62'


class Engine:
    def __init__(self):
        self.volumes = {}
        self.calls = []
        self.created = []
        self.prunes = []
        self.loss: str | None = None
        self.bad_deleted = False
        self.bad_bytes = None
        self.info = {'ID': 'daemon', 'ServerVersion': '29.2.1', 'OSType': 'linux',
                     'Architecture': 'aarch64', 'KernelVersion': '6.18.0-test',
                     'SecurityOptions': [], 'Swarm': {'LocalNodeState': 'inactive'}}

    @staticmethod
    def matches(labels, term):
        key, sep, value = term.partition('=')
        return key in labels and (not sep or labels[key] == value)

    def __call__(self, socket_path, method, target, body, timeout):
        self.calls.append((method, target, json.loads(body) if body else None, timeout))
        path = target.removeprefix('/v1.52')
        status, obj = 200, {}
        if path == '/version':
            obj = {'Version': '29.2.1', 'ApiVersion': '1.53', 'MinAPIVersion': '1.44', 'Os': 'linux', 'Arch': 'arm64'}
        elif path == '/info':
            obj = copy.deepcopy(self.info)
        elif path == '/volumes':
            obj = {'Volumes': list(copy.deepcopy(self.volumes).values()), 'Warnings': []}
        elif path == '/volumes/create' and method == 'POST':
            request = json.loads(body)
            name = request.get('Name', f'{len(self.created) + 1:064x}')
            labels = dict(request['Labels'])
            if 'Name' not in request:
                labels[p.ANONYMOUS] = ''
            obj = {'Name': name, 'Labels': labels, 'Driver': 'local', 'Scope': 'local', 'Options': None}
            self.volumes[name] = copy.deepcopy(obj)
            self.created.append(name)
            status = 201
            if self.loss == 'create' or (self.loss == 'anonymous-create' and 'Name' not in request):
                raise TimeoutError('response lost after successful create')
        elif path.startswith('/volumes/prune?') and method == 'POST':
            filters = json.loads(parse_qs(urlsplit(path).query)['filters'][0])
            if any(key not in {'label', 'label!', 'all'} for key in filters) or filters.get('all', ['false'])[0] not in {'true', 'false'}:
                status, obj = 400, {'message': 'invalid filter'}
            else:
                labels = filters.get('label', [])
                if filters.get('all') != ['true']:
                    labels = [*labels, p.ANONYMOUS]
                deleted = []
                for name, volume in list(self.volumes.items()):
                    positive = all(self.matches(volume['Labels'], term) for term in labels)
                    negative = 'label!' in filters and all(self.matches(volume['Labels'], term) for term in filters['label!'])
                    if positive and not negative:
                        deleted.append(name)
                        del self.volumes[name]
                self.prunes.append(deleted)
                obj = {'VolumesDeleted': deleted + (['foreign'] if self.bad_deleted else []),
                       'SpaceReclaimed': self.bad_bytes if self.bad_bytes is not None else 0}
                if self.loss == 'prune':
                    raise TimeoutError('response lost after successful prune')
        elif path.startswith('/volumes/'):
            name = path.split('/')[-1]
            if method == 'DELETE':
                assert name in self.volumes
                del self.volumes[name]
                status, obj = 204, None
            elif name in self.volumes:
                obj = copy.deepcopy(self.volumes[name])
            else:
                status, obj = 404, {'message': 'no such volume'}
        else:
            raise AssertionError('forbidden request ' + method + ' ' + target)
        output = p.encoded(obj) if obj is not None else b''
        wire = f'HTTP/1.1 {status} Test\r\nContent-Length: {len(output)}\r\n\r\n'.encode() + output
        return status, output, wire


class PruneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='prune-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(self.sock.close)
        self.socket_path = self.root / 'docker.sock'
        self.sock.bind(str(self.socket_path))
        self.args = SimpleNamespace(root=str(self.root), run_id=RUN, proof_id=PROOF,
                                    expected_daemon_id='daemon', endpoint='unix://' + str(self.socket_path),
                                    allow_disposable_reference=True)
        self.reference = Mock()
        self.reference.root = self.root
        self.reference.socket = self.socket_path
        self.reference.state = {'root': str(self.root), 'run_id': RUN, 'daemon_id': 'daemon',
                                'endpoint': self.args.endpoint, 'phase': 'ready', 'engine_version': '29.2.1',
                                'records': {'docker.sock': p.ref.identity(self.socket_path)}}
        self.parent = Mock()
        self.ledger = p.Ledger(self.root / 'proof', {'mode': p.MODE, 'phase': 'new', 'proof_id': PROOF})
        self.ledger.phase('running')
        self.engine = Engine()
        self.probe = p.Prune(self.reference, self.args, self.parent, self.ledger, self.engine)

    def events(self):
        return [json.loads((self.ledger.root / item['name']).read_text()) for item in self.ledger.state['events']]

    def test_full_run_exact_sets_twelve_volumes_and_no_extras(self):
        self.probe.run()
        self.assertEqual(self.ledger.state['phase'], 'completed')
        self.assertEqual(len(self.engine.created), 12)
        self.assertEqual(self.engine.volumes, {})
        created = self.engine.created
        self.assertEqual(self.engine.prunes, [[created[1]], [created[0]], [created[2]], [created[4]],
                                             [created[5]], [created[8]], [created[10]]])
        self.assertEqual([r['status'] for r in self.ledger.state['results']], [200]*7 + [400, 400])
        self.assertEqual(self.ledger.state['remaining'], [])
        deletes = [target.rsplit('/', 1)[-1] for method, target, _, _ in self.engine.calls if method == 'DELETE']
        self.assertEqual(deletes, [created[i] for i in (3, 6, 7, 9, 11)])
        self.assertLessEqual(self.probe.calls, p.MAX_CALLS)
        self.assertLessEqual(self.probe.api_bytes, p.MIB)
        self.assertTrue(all(0 < call[3] <= 60 for call in self.engine.calls))
        self.reference.invoke.assert_not_called()
        self.reference.instance.assert_not_called()
        self.reference.daemon.assert_not_called()
        self.reference.destructive.assert_not_called()
        self.reference.restart.assert_not_called()
        self.assertTrue(all('/images' not in call[1] and '/containers' not in call[1] for call in self.engine.calls))

    def test_request_encoding_and_anonymous_capture_before_query(self):
        self.probe.run()
        requests = [e for e in self.events() if e['kind'] == 'request']
        prunes = [e['target'] for e in requests if '/prune?' in e['target']]
        self.assertEqual(prunes[0], '/v1.52/volumes/prune?filters=%7B%7D')
        self.assertIn('%22label%21%22', prunes[5])
        self.assertIn('%3Dred', prunes[4])
        self.assertNotIn('&', ''.join(prunes))
        creates = [call[2] for call in self.engine.calls if call[1] == '/v1.52/volumes/create']
        self.assertNotIn('Name', creates[1])
        self.assertTrue(all('Name' in c for i, c in enumerate(creates) if i != 1))
        events = self.events()
        anonymous = next(e for e in events if e['kind'] == 'created' and e['anonymous'])
        index = events.index(anonymous)
        self.assertFalse(any(anonymous['name'] in e.get('target', '') for e in events[:index]))
        self.assertTrue(all(c['Labels'][p.LABEL + '.mode'] == p.MODE for c in creates))
        self.assertEqual(len({c['Labels'][p.LABEL + '.operation'] for c in creates}), 12)

    def test_foreign_nonempty_inventory_refused_before_mutation(self):
        self.engine.volumes['foreign'] = {'Name': 'foreign'}
        with self.assertRaisesRegex(p.ref.Refusal, 'foreign/nonempty'):
            self.probe.run()
        self.assertFalse(any(method != 'GET' for method, _, _, _ in self.engine.calls))
        self.assertTrue(self.probe.terminal)
        self.assertIn('foreign', self.engine.volumes)

    def test_identity_root_daemon_endpoint_phase_and_socket_fail_closed(self):
        for key, value in [('root', '/foreign'), ('run_id', PROOF), ('daemon_id', 'foreign'),
                           ('endpoint', 'unix:///foreign'), ('phase', 'crashed'), ('engine_version', '29.2.0')]:
            with self.subTest(key=key), patch.dict(self.reference.state, {key: value}):
                self.probe.terminal = False
                with self.assertRaises(p.ref.Refusal):
                    self.probe.api('GET', '/info')
        self.assertEqual(self.engine.calls, [])
        self.probe.terminal = False
        self.socket_path.unlink()
        replacement = socket.socket(socket.AF_UNIX)
        self.addCleanup(replacement.close)
        replacement.bind(str(self.socket_path))
        with self.assertRaisesRegex(p.ref.Refusal, 'socket'):
            self.probe.api('GET', '/info')
        self.assertEqual(self.engine.calls, [])

    def test_reference_and_parent_guard_failure_prevents_transport(self):
        for guard in (self.reference.guard, self.parent.check):
            guard.side_effect = p.ref.Refusal('changed')
            self.probe.terminal = False
            with self.assertRaises(p.ref.Refusal):
                self.probe.api('GET', '/info')
            guard.side_effect = None
        self.assertEqual(self.engine.calls, [])

    def test_daemon_platform_kernel_rootless_and_swarm_guards(self):
        for key, value in [('ID', 'foreign'), ('ServerVersion', '29.2.0'), ('OSType', 'windows'),
                           ('Architecture', 'amd64'), ('KernelVersion', ''),
                           ('SecurityOptions', ['name=rootless']), ('Swarm', {'LocalNodeState': 'active'})]:
            with self.subTest(key=key), patch.dict(self.engine.info, {key: value}):
                with self.assertRaises(p.ref.Refusal):
                    self.probe.daemon()
        self.probe.daemon()
        self.engine.info['KernelVersion'] = 'changed'
        with self.assertRaisesRegex(p.ref.Refusal, 'kernel/platform changed'):
            self.probe.daemon()
        self.assertFalse(any(method != 'GET' for method, _, _, _ in self.engine.calls))

    def test_no_ambient_context(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://production:2375', 'DOCKER_CONTEXT': 'production',
                                    'HTTP_PROXY': 'http://bad', 'COLIMA_HOME': '/foreign'}):
            self.probe.preflight()
        self.assertEqual([c[1] for c in self.engine.calls], ['/version', '/v1.52/info', '/v1.52/volumes'])

    def test_no_permission_or_no_intent_prevents_transport(self):
        self.args.allow_disposable_reference = False
        with self.assertRaises(p.ref.Refusal):
            self.probe.api('GET', '/info')
        self.args.allow_disposable_reference = True
        self.probe.terminal = False
        self.ledger.phase_name = self.ledger.state['phase'] = 'new'
        with self.assertRaises(p.ref.Refusal):
            self.probe.api('GET', '/info')
        self.assertEqual(self.engine.calls, [])

    def test_route_allowlist_blocks_context_prunes_force_and_unowned_names(self):
        for method, path in [('POST', '/images/prune'), ('POST', '/containers/prune'), ('POST', '/build'),
                             ('POST', '/volumes/prune'), ('GET', 'http://foreign/info'),
                             ('DELETE', '/volumes/foreign'), ('GET', '/volumes?filters={}'),
                             ('POST', p.prune_path({'all': ['true']}) + '&extra=1')]:
            with self.assertRaises(p.ref.Refusal):
                p.request_allowed(method, path, {'known'})
        with self.assertRaises(p.ref.Refusal):
            p.request_allowed('DELETE', '/volumes/known?force=1', {'known'})

    def test_lost_create_and_prune_are_terminal_no_query_adopt_or_cleanup(self):
        for loss in ('create', 'anonymous-create', 'prune'):
            with self.subTest(loss=loss):
                engine = Engine()
                engine.loss = loss
                log = p.Ledger(self.root / loss, {'phase': 'new', 'mode': p.MODE})
                log.phase('running')
                probe = p.Prune(self.reference, self.args, self.parent, log, engine)
                with self.assertRaises(TimeoutError):
                    probe.run()
                self.assertEqual(engine.calls[-1][0], 'POST')
                count = len(engine.calls)
                with self.assertRaises(p.ref.Refusal):
                    probe.run()
                self.assertEqual(len(engine.calls), count)
                self.assertFalse(any(method == 'DELETE' for method, _, _, _ in engine.calls))
                self.assertTrue(engine.volumes)
                self.assertEqual(log.state['phase'], 'running')
                if loss == 'create':
                    self.assertEqual(log.state['created'], {})
                elif loss == 'anonymous-create':
                    self.assertEqual(set(log.state['created']), {engine.created[0]})
                    self.assertNotIn(engine.created[1], probe.names)
                    self.assertFalse(any(engine.created[1] in c[1] for c in engine.calls))
                with self.assertRaises(FileExistsError):
                    p.Ledger(log.root, {'phase': 'new', 'mode': p.MODE})

    def test_wrong_prune_set_or_negative_bytes_preserves_remaining(self):
        for key, value in [('bad_deleted', True), ('bad_bytes', -1), ('bad_bytes', True)]:
            engine = Engine()
            setattr(engine, key, value)
            log = p.Ledger(self.root / (key + str(value)), {'phase': 'new', 'mode': p.MODE})
            log.phase('running')
            probe = p.Prune(self.reference, self.args, self.parent, log, engine)
            with self.assertRaises(p.ref.Refusal):
                probe.run()
            self.assertTrue(probe.terminal)
            self.assertFalse(any(method == 'DELETE' for method, _, _, _ in engine.calls))
            self.assertEqual(len(engine.volumes), 1)

    def test_foreign_volume_appearing_before_prune_blocks_prune(self):
        self.probe.preflight()
        name = self.probe.create('test', 0, False, {})
        self.engine.volumes['foreign'] = {'Name': 'foreign'}
        with self.assertRaises(p.ref.Refusal):
            self.probe.case('all', {'all': ['true']}, {name}, 200)
        self.assertFalse(any('/prune?' in c[1] for c in self.engine.calls))
        self.assertIn(name, self.engine.volumes)

    def test_named_create_preexisting_404_required(self):
        self.probe.inventory = Mock()
        name = f'vrpr-{PROOF}-test-0'
        self.engine.volumes[name] = {'Name': name}
        with self.assertRaises(p.ref.Refusal):
            self.probe.create('test', 0, False, {})
        self.assertFalse(any(c[0] == 'POST' for c in self.engine.calls))

    def test_failed_fsync_prevents_request(self):
        with patch.object(p.ref, 'sync_directory', side_effect=OSError('EIO')):
            with self.assertRaises(OSError):
                self.probe.api('GET', '/info')
        self.assertEqual(self.engine.calls, [])
        self.assertTrue(self.probe.terminal)

    def test_ledger_mode_identity_event_and_file_tamper(self):
        with patch.dict(self.ledger.state, {'mode': 'local'}):
            with self.assertRaises(p.ref.Refusal):
                self.ledger.save()
        with patch.dict(self.ledger.state, {'proof_id': RUN}):
            with self.assertRaises(p.ref.Refusal):
                self.ledger.save()
        (self.ledger.root / 'event-0000.json').write_text('{}')
        with self.assertRaises(p.ref.Refusal):
            self.ledger.validate()
        log = p.Ledger(self.root / 'tamper', {'phase': 'new', 'mode': p.MODE})
        (log.root / 'proof.json').write_text('{}')
        with self.assertRaises(p.ref.Refusal):
            log.save()
        with self.assertRaises(p.ref.Refusal):
            p.Ledger(self.root / 'wrong-mode', {'phase': 'new', 'mode': 'bind'})

    def test_no_phase_resume_and_symlink_ledger(self):
        for phase in ('running', 'new', 'cleanup'):
            with self.assertRaises(p.ref.Refusal):
                self.ledger.phase(phase)
        (self.root / 'link').symlink_to(self.ledger.root)
        with self.assertRaises((OSError, p.ref.Refusal)):
            p.Ledger(self.root / 'link', {'phase': 'new', 'mode': p.MODE})

    def test_parent_global_path_actual_pid_replacement_and_liveness(self):
        lock = self.root / 'cengine-compat-run.lock'
        lock.mkdir(mode=0o700)
        (lock / 'pid').write_text(str(os.getppid()) + '\n')
        with patch.object(p.claims, 'launcher_lock', return_value=self.root / 'canonical'), \
                self.assertRaisesRegex(p.ref.Refusal, 'canonical global'):
            p.ParentLock(lock, os.getppid())
        with patch.object(p.claims, 'launcher_lock', return_value=lock):
            parent = p.ParentLock(lock, os.getppid())
            with self.assertRaises(p.ref.Refusal):
                p.ParentLock(lock, os.getpid())
            with patch.object(p.os, 'getppid', return_value=os.getppid() + 1):
                with self.assertRaises(p.ref.Refusal):
                    parent.check()
            with patch.object(p.os, 'kill', side_effect=ProcessLookupError):
                with self.assertRaises(ProcessLookupError):
                    parent.check()
            (lock / 'pid').rename(lock / 'old')
            (lock / 'pid').write_text(str(os.getppid()))
            with self.assertRaises(p.ref.Refusal):
                parent.check()
        self.assertTrue(lock.is_dir())

    def test_call_deadline_payload_response_and_aggregate_limits(self):
        for field, value in [('deadline', 0), ('calls', p.MAX_CALLS), ('api_bytes', p.MIB)]:
            probe = p.Prune(self.reference, self.args, self.parent, self.ledger, self.engine)
            setattr(probe, field, value)
            with self.assertRaises(p.ref.Refusal):
                probe.api('GET', '/info')
        with self.assertRaises(p.ref.Refusal):
            self.probe.api('POST', '/volumes/create', {'x': 'x'*4096})
        self.assertEqual(self.engine.calls, [])
        self.probe.terminal = False
        self.probe.transport = Mock(return_value=(200, b'{}', b'x'*(p.MAX_REPLY + 1)))
        with self.assertRaises(p.ref.Refusal):
            self.probe.api('GET', '/info')
        self.assertTrue(any(e['kind'] == 'response' for e in self.events()))
        with self.assertRaises(p.ref.Refusal):
            self.ledger.event('too-large', data='x'*p.MIB)

    def test_twelve_volume_hard_bound(self):
        self.ledger.state['created'] = {str(i): {} for i in range(12)}
        with self.assertRaisesRegex(p.ref.Refusal, 'creation bound'):
            self.probe.create('test', 0, False, {})
        self.assertEqual(self.engine.calls, [])

    def test_pinned_reference_source_and_no_imports_of_mutable_probe(self):
        self.assertEqual(p.hashlib.sha256(PATH.with_name('volume_reference.py').read_bytes()).hexdigest(), p.REFERENCE_SHA)
        with patch.object(p, 'source_bytes', return_value=b'print("unreviewed")'):
            with self.assertRaisesRegex(RuntimeError, 'SHA changed'):
                p.load_reference()
        self.assertNotIn('volume_reference_probe', PATH.read_text())

    def test_exchange_unix_http_wire_bounds_truncation_and_partial_failure(self):
        good = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        chunked = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n'
        for wire in (good, chunked):
            sock = Mock()
            sock.recv.side_effect = [wire, b'']
            with patch.object(p.socket, 'socket', return_value=sock) as factory:
                status, output, captured = p.exchange(self.socket_path, 'GET', '/v1.52/info', b'', 1)
            self.assertEqual((status, output, captured), (200, b'{}', wire))
            factory.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect.assert_called_once_with(str(self.socket_path))
            sock.close.assert_called_once()
            sent = b''.join(c.args[0] for c in sock.sendall.call_args_list)
            self.assertIn(b'GET /v1.52/info HTTP/1.1', sent)
            self.assertIn(b'Connection: close', sent)
        for chunks in ([good.replace(b'Length: 2', b'Length: 200'), b''],
                       [chunked[:-2], b''],
                       [b'x' * (p.MAX_REPLY + 1)], [good[:20], TimeoutError('lost')]):
            sock = Mock()
            sock.recv.side_effect = chunks
            with patch.object(p.socket, 'socket', return_value=sock):
                with self.assertRaises(p.ExchangeError) as caught:
                    p.exchange(self.socket_path, 'GET', '/v1.52/info', b'', 1)
            self.assertLessEqual(len(caught.exception.partial), p.MAX_REPLY)
            self.assertTrue(caught.exception.partial)
            sock.close.assert_called_once()

    def test_exchange_expired_complete_response_is_still_terminal(self):
        wire = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
        sock = Mock()
        timer = Mock()
        def start_timer(timeout, callback):
            # Deterministically expire while waiting for peer EOF, after a full body.
            def eof(*args):
                callback()
                return b''
            calls = iter([wire, None])
            sock.recv.side_effect = lambda *args: next(calls) or eof()
            return timer
        with patch.object(p.socket, 'socket', return_value=sock), patch.object(p.threading, 'Timer', side_effect=start_timer):
            with self.assertRaisesRegex(p.ExchangeError, 'deadline expired'):
                p.exchange(self.socket_path, 'GET', '/v1.52/info', b'', 1)
        sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        sock.close.assert_called_once()

    def test_cli_requires_optin_and_rejects_extra_options(self):
        with patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(SystemExit):
                p.parser().parse_args([])
            with self.assertRaises(SystemExit):
                p.parser().parse_args(['--resume'])

    def test_main_intent_precedes_preflight_and_failed_uuid_cannot_reopen(self):
        (self.root / 'artifacts').mkdir(mode=0o700)
        argv = ['--root', str(self.root), '--run-id', RUN, '--proof-id', PROOF,
                '--expected-daemon-id', 'daemon', '--endpoint', self.args.endpoint,
                '--compat-lock', str(p.claims.canonical_lock()), '--parent-lock-pid', str(os.getppid()),
                '--allow-disposable-reference']
        context = Mock(__enter__=Mock(return_value=self.reference), __exit__=Mock(return_value=False))
        def fail(probe):
            state = json.loads((probe.log.root / 'ledger.json').read_text())
            self.assertEqual((state['phase'], state['mode']), ('running', 'volume-prune'))
            raise TimeoutError('preflight failed')
        with patch.object(p, 'ParentLock', return_value=self.parent), patch.object(p.ref, 'Reference', return_value=context), \
                patch.object(p.Prune, 'preflight', fail):
            with self.assertRaises(TimeoutError):
                p.main(argv)
            with self.assertRaises(FileExistsError):
                p.main(argv)
        saved = json.loads((self.root / 'artifacts' / ('prune-' + PROOF) / 'ledger.json').read_text())
        self.assertEqual(saved['phase'], 'running')


if __name__ == '__main__':
    unittest.main()
