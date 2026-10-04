#!/usr/bin/env python3
"""Engine-free diagnostic regression; not native acceptance."""
import ast
import itertools
import re
import os
from pathlib import Path
import subprocess
import signal
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import managed_prepare_start_diagnostic as d
import managed_prepare_faults as proof

class Tests(unittest.TestCase):
    def round_trip(self, diagnostic):
        r, w = os.pipe()
        d.emit(w, diagnostic)
        return d.receive(SimpleNamespace(_start_diagnostic_fd=r))

    def test_all_finite_private_fields(self):
        self.assertEqual(self.round_trip(d.classify(409, d.CHANNEL)),
                         dict(category=d.PRIVATE_CATEGORIES[0], stage=None, kind=None, role=None, code=None))
        for stage, kind, role, code in itertools.product(d.STAGES[1:], d.KINDS, d.ROLES, d.CODES):
            value = dict(category=d.PRIVATE_CATEGORIES[0], stage=stage, kind=kind, role=role, code=code)
            text = d.CHANNEL + ' [phase=' + stage
            if kind is not None: text += ' operation=' + kind
            if role is not None: text += ' role=' + role
            if code is not None: text += ' guest-code=' + code
            self.assertEqual(d.classify(409, text + ']'), value)
            self.assertEqual(self.round_trip(value), value)
            self.assertEqual(len(d._private_frame(value)), 5)
        for kind, role, code in itertools.product(d.KINDS[1:], d.ROLES, d.CODES[1:]):
            value = dict(category=d.PRIVATE_CATEGORIES[1], stage=None, kind=kind, role=role, code=code)
            text = d.OPERATION + ' [operation=' + kind
            if role is not None: text += ' role=' + role
            text += ' guest=' + code + ']'
            self.assertEqual(d.classify(409, text), value)
            self.assertEqual(self.round_trip(value), value)

    def test_private_unknown_malformed_never_exports_text(self):
        channel = d.CHANNEL + ' [phase=guest-terminal operation=prepare role=runtime guest-code=terminal]'
        operation = d.OPERATION + ' [operation=prepare role=runtime guest=prepare]'
        for text in (channel, operation):
            for suffix in (' ', '\n', '\r\n', '\u200b', '\u00e9', '/private/path',
                           ' payload=secret', ' certificate=secret', 'x' * 1000000):
                self.assertEqual(d.classify(409, text + suffix), 'HTTP_CONFLICT_UNKNOWN')
            for bad in ('prefix ' + text, text[:-1], text + ']', text.replace(' ', '  '),
                        text.replace('prepare', 'unknown'), text.replace('runtime', '/private/name'),
                        text.replace('runtime', '-----BEGIN CERTIFICATE-----'),
                        text.replace('runtime', '\u0072\u0075\u006e\u0074\u0069\u006d\u0435'),
                        text[:-1] + ' extra=secret]', text[:-1] + ' role=runtime]',
                        text.replace('role=runtime', 'role='), text.replace('role=runtime', 'role==runtime'),
                        text.replace('operation=prepare role=runtime', 'role=runtime operation=prepare')):
                result = d.classify(409, bad)
                self.assertEqual(result, 'HTTP_CONFLICT_UNKNOWN')
                self.assertEqual(self.round_trip(result), result)
            self.assertEqual(d.classify(500, text), 'HTTP_INTERNAL_ERROR')
            self.assertEqual(d.classify(400, text), 'HTTP_OTHER')
        for bad in (d.CHANNEL + ' []', d.OPERATION, d.OPERATION + ' []',
                    d.CHANNEL + ' [operation=prepare]', d.CHANNEL + ' [phase=unknown]',
                    d.CHANNEL + ' [phase=guest-terminal guest-code=unknown]',
                    d.CHANNEL + ' [phase=guest-terminal guest=terminal]',
                    d.OPERATION + ' [operation=prepare]',
                    d.OPERATION + ' [operation=prepare guest=unknown]',
                    d.OPERATION + ' [phase=guest-terminal operation=prepare guest=terminal]'):
            self.assertEqual(d.classify(409, bad), 'HTTP_CONFLICT_UNKNOWN')

    def test_private_frame_rejects_missing_extra_invalid_and_open_writer(self):
        good = bytes([len(d.CATEGORIES), d.STAGES.index('guest-terminal'),
                      d.KINDS.index('prepare'), d.ROLES.index('runtime'), d.CODES.index('terminal')])
        invalid = [b'', *(good[:n] for n in range(1, len(good))), good + b'\x00',
                   good + b'x' * 64, bytes([len(d.CATEGORIES) + 1, 0, 0, 0, 0]),
                   bytes([len(d.CATEGORIES), 0, 1, 0, 0]), b'\x01' * 5,
                   bytes([len(d.CATEGORIES) + 1, 1, 1, 0, 1])]
        invalid += [good[:n] + b'\xff' + good[n+1:] for n in range(5)]
        for raw in invalid:
            r, w = os.pipe()
            os.write(w, raw); os.close(w)
            process = SimpleNamespace(_start_diagnostic_fd=r)
            self.assertEqual(d.receive(process), 'UNKNOWN')
            self.assertIsNone(process._start_diagnostic_fd)
        for raw in (b'\x01', good):
            r, w = os.pipe()
            try:
                os.write(w, raw)
                self.assertEqual(d.receive(SimpleNamespace(_start_diagnostic_fd=r)), 'UNKNOWN')
            finally: os.close(w)
        self.assertEqual(d.receive(SimpleNamespace()), 'UNKNOWN')
        self.assertEqual(d.receive(SimpleNamespace(_start_diagnostic_fd=None)), 'UNKNOWN')
        for value in ({}, {'category': d.PRIVATE_CATEGORIES[0]},
                      dict(category=d.PRIVATE_CATEGORIES[0], stage='/private', kind=None, role=None, code=None),
                      dict(category=d.PRIVATE_CATEGORIES[0], stage=None, kind=None, role=None, code=None, payload='secret'),
                      dict(category=d.PRIVATE_CATEGORIES[1], stage=None, kind=None, role=None, code=None)):
            self.assertEqual(self.round_trip(value), 'UNKNOWN')
        d.emit(None, d.classify(409, d.CHANNEL))

    def test_closed_tables_match_swift_producers(self):
        coordinator = (ROOT/'Sources/CEngineRuntime/PrivateWorkloadStorageCoordinator.swift').read_text()
        wire = (ROOT/'Sources/CEngineCore/WorkloadStorageProtocol.swift').read_text()
        def raw_values(source, name):
            body = re.search(r'\benum ' + name + r':[^\{]+\{([^}]+)\}', source).group(1)
            result = []
            for line in body.splitlines():
                if not line.strip(): continue
                self.assertTrue(line.strip().startswith('case '))
                for item in line.strip()[5:].split(','):
                    match = re.fullmatch(r'\s*([A-Za-z]+)(?: = "([a-z-]+)")?\s*', item)
                    self.assertIsNotNone(match)
                    result.append(match.group(2) or match.group(1))
            return tuple(result)
        self.assertEqual(d.STAGES[1:], raw_values(coordinator, 'Stage'))
        for name, table in (('Kind', d.KINDS), ('Role', d.ROLES), ('Code', d.CODES)):
            self.assertEqual(table[1:], raw_values(wire, name))
        self.assertIn('"' + d.CHANNEL + r'\(diagnostic)"', coordinator)
        for fragment in (r'" [phase=\(stage.rawValue)"', r'" operation=\(kind.rawValue)"',
                         r'" role=\(role.rawValue)"', r'" guest-code=\(guestCode.rawValue)"'):
            self.assertIn(fragment, coordinator)
        backend = (ROOT/'Sources/CEngineRuntime/RawManagedStorageBackend.swift').read_text()
        self.assertIn('"' + d.OPERATION + r' [operation=\(kind.rawValue)\(phaseRole) guest=\(code.rawValue)]"', backend)
        self.assertIn(r'" role=\($0.rawValue)"', backend)
        self.assertEqual(d.CATEGORIES, ('UNKNOWN', 'SUCCESS', 'MANAGED_STORAGE_OWNERSHIP_UNRESOLVED',
            'HTTP_CONFLICT_UNKNOWN', 'HTTP_INTERNAL_ERROR', 'HTTP_OTHER', 'CONNECTION_LOST'))
        self.assertLessEqual(d.MAX_FRAME, 8)

    def test_closed_classification(self):
        self.assertEqual(d.classify(409,d.OWNERSHIP), d.CATEGORIES[2])
        for secret in ('/private/name credential=secret', d.OWNERSHIP+' /private', 'x'*1000000, None, {}, b'secret'):
            self.assertEqual(d.classify(409,secret), 'HTTP_CONFLICT_UNKNOWN')
        self.assertEqual(d.classify(500,d.OWNERSHIP),'HTTP_INTERNAL_ERROR')
        self.assertEqual(d.classify(401,'private'),'HTTP_OTHER')

    def test_emit_strict_bound_and_closed_output(self):
        for category in (*d.CATEGORIES, 'private/path/secret'):
            r,w=os.pipe()
            d.emit(w,category)
            raw=os.read(r,2);os.close(r)
            self.assertEqual(len(raw),1)
            self.assertLess(raw[0],len(d.CATEGORIES))

    def test_full_pipe_does_not_block(self):
        r,w=os.pipe();os.set_blocking(w,False)
        try:
            while True: os.write(w,b'x'*4096)
        except BlockingIOError: pass
        d.emit(w, d.classify(409, d.CHANNEL));os.close(r)

    def test_actual_child_join_then_read(self):
        for raw in ('b"\\x01"', 'b""', 'b"\\xff"', 'b"\\x01\\x01"'):
            code=f'import os,sys;os.write(int(sys.argv[1]),{raw})'
            child=d.spawn([sys.executable,'-B','-c',code])
            self.assertEqual(child.wait(),0)
            self.assertEqual(d.receive(child),'SUCCESS' if raw=='b"\\x01"' else 'UNKNOWN')
            self.assertIsNone(child._start_diagnostic_fd)
            self.assertEqual(d.receive(child),'UNKNOWN')

    def test_empty_open_writer_nonblocking(self):
        r,w=os.pipe();os.set_blocking(r,False)
        self.assertEqual(d.receive(SimpleNamespace(_start_diagnostic_fd=r)),'UNKNOWN')
        os.close(w)

    def test_start_codes_and_private_error_not_exported(self):
        source=ast.parse((ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
        fn=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='_docker_start')
        ns={'proof':SimpleNamespace(pin=lambda _:None)}
        exec(compile(ast.Module(body=[fn],type_ignores=[]),'fixture','exec'),ns)
        class APIError(Exception): pass
        docker=ModuleType('docker');docker.errors=SimpleNamespace(APIError=APIError)
        private = d.CHANNEL + ' [phase=guest-terminal operation=prepare role=runtime guest-code=terminal]'
        operation = d.OPERATION + ' [operation=prepare guest=prepare]'
        for status,expected,category,explanation in (
            (409,49,d.CATEGORIES[2],d.OWNERSHIP), (500,50,'HTTP_INTERNAL_ERROR',d.OWNERSHIP),
            (404,51,'HTTP_OTHER',d.OWNERSHIP), (None,0,'SUCCESS',d.OWNERSHIP),
            (409,49,d.classify(409, private),private), (409,49,d.classify(409, operation),operation)):
            err=APIError('private path credential');err.response=SimpleNamespace(status_code=status);err.explanation=explanation
            client=Mock();client.api.start.side_effect=err if status else None
            docker.DockerClient=Mock(return_value=client)
            r,w=os.pipe()
            with patch.dict(sys.modules,{'docker':docker}):
                self.assertEqual(ns['_docker_start']('/private/socket','name',w),expected)
            self.assertEqual(d.receive(SimpleNamespace(_start_diagnostic_fd=r)), category)
            client.close.assert_called_once()
            with patch.dict(sys.modules,{'docker':docker}):
                self.assertEqual(ns['_docker_start']('/private/socket','name'),expected)

    def test_connection_loss_and_unknown_exception_output(self):
        source = ast.parse((ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
        fn = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == '_docker_start')
        ns = {'proof': SimpleNamespace(pin=lambda _: None)}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'fixture', 'exec'), ns)
        class APIError(Exception): pass
        loss = type('ConnectionError', (Exception,), {'__module__': 'requests.exceptions'})
        requests = ModuleType('requests.exceptions')
        requests.ConnectionError = loss
        docker = ModuleType('docker')
        docker.errors = SimpleNamespace(APIError=APIError)
        for error, category in ((loss('private socket'), 'CONNECTION_LOST'),
                                (RuntimeError('private secret'), 'UNKNOWN')):
            with self.subTest(category=category):
                client = Mock()
                client.api.start.side_effect = error
                docker.DockerClient = Mock(return_value=client)
                r, w = os.pipe()
                try:
                    with patch.dict(sys.modules, {'docker': docker, 'requests.exceptions': requests}):
                        if category == 'CONNECTION_LOST':
                            self.assertEqual(ns['_docker_start']('/private', 'name', w), 52)
                        else:
                            with self.assertRaises(RuntimeError) as caught:
                                ns['_docker_start']('/private', 'name', w)
                            self.assertIs(caught.exception, error)
                    self.assertEqual(os.read(r, 2), bytes([d.CATEGORIES.index(category)]))
                    client.close.assert_called_once()
                finally:
                    os.close(r)

    def test_missing_candidate_records_settled_start_but_never_accepts_it(self):
        source = ast.parse((ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
        functions = [next(n for n in ast.walk(source) if isinstance(n, ast.FunctionDef) and n.name == name)
                     for name in ('joined_start', 'wait_artifact')]
        for code, category in ((0, 'SUCCESS'), (49, 'MANAGED_STORAGE_OWNERSHIP_UNRESOLVED')):
            with self.subTest(code=code):
                raw = bytes([d.CATEGORIES.index(category)])
                child = d.spawn([sys.executable, '-B', '-c',
                    f'import os,sys;os.write(int(sys.argv[1]), {raw!r});sys.exit({code})'])
                child.wait(timeout=5)
                events = []
                def record(phase, **fields):
                    events.append(proof.decode(proof.canonical(dict(phase=phase, **fields))))
                ns = dict(proof=proof, signal=signal, remaining=lambda: 5, process=child,
                          record=record, io_case=None, early=True, case='normal',
                          fault_case='admitted-queued', NATURAL_FAILURE_CASES=(),
                          queue=Mock(), artifact=Mock(side_effect=FileNotFoundError),
                          time=SimpleNamespace(sleep=Mock()))
                exec(compile(ast.Module(body=functions, type_ignores=[]), 'fixture', 'exec'), ns)
                with self.assertRaises(ValueError): ns['wait_artifact']('.candidate.json')
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]['returncode'], code)
                self.assertEqual(events[0]['diagnostic'], category)
                self.assertIsNone(child._start_diagnostic_fd)
                ns['time'].sleep.assert_not_called()

    def test_early_missing_checkpoint_records_unexpected_start_before_rejecting(self):
        source = ast.parse((ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
        functions = [next(n for n in ast.walk(source) if isinstance(n, ast.FunctionDef) and n.name == name)
                     for name in ('joined_start', 'wait_artifact')]
        diagnostic = d.classify(409, d.CHANNEL + ' [phase=read-eof]')
        for case, suffix, code in (
            ('drain-durable-reply-lost', '.checkpoint.json', 49),
            ('drain-durable-reply-lost', '.storage-checkpoint.json', 49),
            ('normal', '.armed.json', 49),
            ('admitted-queued', '.checkpoint.json', 0),
        ):
            with self.subTest(case=case, suffix=suffix, code=code):
                raw = d._private_frame(diagnostic) if code else bytes([d.CATEGORIES.index('SUCCESS')])
                child = d.spawn([sys.executable, '-B', '-c',
                    f'import os,sys;os.write(int(sys.argv[1]), {raw!r});sys.exit({code})'])
                try:
                    child.wait(timeout=5)
                    events = []
                    def record(phase, **fields):
                        events.append(proof.decode(proof.canonical(dict(phase=phase, **fields))))
                    ns = dict(proof=proof, signal=signal, remaining=Mock(return_value=5), process=child,
                              record=record, io_case=None, early=True, case=case, fault_case=case,
                              NATURAL_FAILURE_CASES=(), queue=Mock(), artifact=Mock(side_effect=FileNotFoundError),
                              time=SimpleNamespace(sleep=Mock()))
                    exec(compile(ast.Module(body=functions, type_ignores=[]), 'fixture', 'exec'), ns)
                    message = 'real Docker start response' if code else 'unexpected settled start before checkpoint'
                    with self.assertRaisesRegex(ValueError, message):
                        ns['wait_artifact'](suffix, 8192)
                    self.assertEqual(events, [dict(phase='docker-start-joined', failed=False, returncode=code,
                        diagnostic=dict(category=d.PRIVATE_CATEGORIES[0], stage='read-eof') if code else 'SUCCESS')])
                    self.assertIsNone(child._start_diagnostic_fd)
                    ns['artifact'].assert_called_once_with(suffix, 8192)
                    ns['queue'].validate.assert_called_once_with()
                    ns['time'].sleep.assert_not_called()
                    self.assertEqual(ns['remaining'].call_count, 2)
                finally:
                    if child.poll() is None: child.kill()
                    child.wait(timeout=5)
                    d.discard(child)

    def test_early_expected_or_pending_start_still_requires_artifact_within_budget(self):
        source = ast.parse((ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
        fn = next(n for n in ast.walk(source) if isinstance(n, ast.FunctionDef) and n.name == 'wait_artifact')
        for status in (None, 0):
            with self.subTest(status=status):
                ns = dict(proof=proof, remaining=Mock(side_effect=[5, TimeoutError('campaign deadline')]),
                          process=SimpleNamespace(poll=Mock(return_value=status)), early=True,
                          case='drain-durable-reply-lost', io_case=None, NATURAL_FAILURE_CASES=(),
                          queue=Mock(), artifact=Mock(side_effect=FileNotFoundError), joined_start=Mock(),
                          time=SimpleNamespace(sleep=Mock()))
                exec(compile(ast.Module(body=[fn], type_ignores=[]), 'fixture', 'exec'), ns)
                with self.assertRaisesRegex(TimeoutError, 'campaign deadline'):
                    ns['wait_artifact']('.checkpoint.json')
                ns['joined_start'].assert_not_called()
                ns['artifact'].assert_called_once_with('.checkpoint.json', 65536)
                ns['time'].sleep.assert_called_once_with(0.025)

    def test_real_child_join_records_diagnostic_before_unchanged_guard(self):
        source = ast.parse((ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
        fn = next(n for n in ast.walk(source) if isinstance(n, ast.FunctionDef) and n.name == 'joined_start')
        def require(ok, message):
            if not ok: raise ValueError(message)
        for code, byte, failed, category, accepted in (
            (0, 1, False, 'SUCCESS', True),
            (49, 2, False, 'MANAGED_STORAGE_OWNERSHIP_UNRESOLVED', False),
            (50, 4, True, 'HTTP_INTERNAL_ERROR', True),
            (7, None, False, 'UNKNOWN', False),
            (49, d._private_frame(d.classify(409, d.CHANNEL + ' [phase=read-eof]')), False,
             dict(category=d.PRIVATE_CATEGORIES[0], stage='read-eof'), False),
            (49, d._private_frame(d.classify(409, d.CHANNEL)), False,
             dict(category=d.PRIVATE_CATEGORIES[0]), False),
            (49, d._private_frame(d.classify(409, d.OPERATION + ' [operation=prepare guest=prepare]')), False,
             dict(category=d.PRIVATE_CATEGORIES[1], kind='prepare', code='prepare'), False),
        ):
            with self.subTest(code=code, failed=failed):
                events = []
                raw = byte if type(byte) is bytes else bytes([byte]) if byte is not None else b''
                write = f'os.write(int(sys.argv[1]), {raw!r});'
                child = d.spawn([sys.executable, '-B', '-c', f'import os,sys;{write}sys.exit({code})'])
                def record(phase, **fields):
                    self.assertEqual(child.returncode, code)  # Actual wait preceded ledger publication.
                    # Exercise the real ledger serializer, not merely a permissive mock.
                    self.assertEqual(proof.decode(proof.canonical(fields)), fields)
                    events.append((phase, fields))
                ns = dict(proof=SimpleNamespace(require=require), signal=signal, remaining=lambda: 5,
                          record=record, io_case=None, early=False)
                exec(compile(ast.Module(body=[fn], type_ignores=[]), 'fixture', 'exec'), ns)
                try:
                    if accepted:
                        ns['joined_start'](child, failed=failed)
                    else:
                        with self.assertRaisesRegex(ValueError, 'real Docker start response'):
                            ns['joined_start'](child, failed=failed)
                    self.assertEqual(events, [('docker-start-joined', dict(failed=failed,
                        returncode=code, diagnostic=category))])
                    self.assertIsNone(child._start_diagnostic_fd)
                finally:
                    if child.poll() is None: child.kill()
                    child.wait(timeout=5)
                    d.discard(child)

    def test_spawn_uses_supplied_source_only_launcher(self):
        launch = Mock(wraps=subprocess.Popen)
        child = d.spawn([sys.executable, '-B', '-c',
            'import os,sys;os.write(int(sys.argv[1]), b"\\x01")'], popen=launch)
        try:
            self.assertEqual(child.wait(timeout=5), 0)
            self.assertEqual(d.receive(child), 'SUCCESS')
            launch.assert_called_once()
            argv = launch.call_args.args[0]
            self.assertEqual(launch.call_args.kwargs['pass_fds'], (int(argv[-1]),))
            source = ast.parse((ROOT/'Tests/Compatibility/test_managed_prepare_faults.py').read_text())
            fn = next(n for n in ast.walk(source) if isinstance(n, ast.FunctionDef) and n.name == 'start_request')
            call = next(n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'spawn')
            self.assertEqual(ast.unparse(next(k.value for k in call.keywords if k.arg == 'popen')), 'subprocess.Popen')
        finally:
            if child.poll() is None: child.kill()
            child.wait(timeout=5)
            d.discard(child)

if __name__=='__main__':unittest.main()
