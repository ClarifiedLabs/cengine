#!/usr/bin/env python3
"""Standard-library-only checks of the ordinary lifecycle DATA refusal/evidence gates."""
import ast
import copy
from contextlib import nullcontext
import subprocess
import sys
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Tests/Compatibility/test_storage_lifecycle_v2_runtime.py"
FUNCTIONS = {
    "committed_cold_edge", "frozen_committed_cold_proof", "recovered_committed_cold_proof", "committed_cold_births",
    "cold_signed_digest", "cold_predecessor", "frozen_cold_proof", "recovered_cold_proof", "observe_cold_births", "observe_cold_controller", "cold_attempt_births",
    "takeover_observation_shape", "takeover_pause_observation", "frozen_takeover_proof", "recovered_takeover_proof",
    "selected", "prerequisites", "progressed", "produced_while_absent", "native_snapshot",
    "parse_progress", "disk_identity", "progress_command", "fault_diagnostics",
    "qualify_initialization_fault", "resume_initialization", "lifecycle_owner",
    "replacement_receipts", "lifecycle_replacement_proof",
    "replacement_observation_shape", "replacement_pause_observation", "native_replacement_proof",
    "pending_replacement_artifacts", "frozen_replacement_proof",
    "wait_replacement_pause", "recovered_replacement_proof", "settled_replacement_proof",
}
CONSTANTS = {"FIRST_COLD_COMPLETION_FAULT", "FIRST_COLD_COMPLETION_REACHED", "COLD_L2_FAULT", "TAKEOVER_FAULTS", "ROOT", "FAULT_ENV", "FAULT", "FAULT_REACHED", "FAULT_STOPPED", "REPLACEMENT_FAULT", "REPLACEMENT_PAUSED"}
STDLIB_IMPORTS = {"__future__", "os", "pathlib", "re", "subprocess", "json", "uuid", "time", "hashlib"}

# Execute the real helpers, constants and imports, not copies or SDK stubs.
# Never load pytest/Docker imports, decorated fixtures or compatibility tests.
nodes = []
for node in ast.parse(SOURCE.read_text(), filename=str(SOURCE)).body:
    if isinstance(node, ast.Import) and all(alias.name in STDLIB_IMPORTS for alias in node.names):
        nodes.append(node)
    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in STDLIB_IMPORTS:
        nodes.append(node)
    elif isinstance(node, ast.Assign) and all(
        isinstance(target, ast.Name) and target.id in CONSTANTS for target in node.targets
    ):
        nodes.append(node)
    elif isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS:
        nodes.append(node)
R = ModuleType("lifecycle_runtime")
R.__file__ = str(SOURCE)
sys.path.insert(0, str(SOURCE.parent))
import managed_storage_recovery
R.replacement = managed_storage_recovery
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec", optimize=0), R.__dict__)
SELECTED = {}


class LifecycleRuntimeTests(unittest.TestCase):
    def test_loads_actual_helpers_without_compatibility_entrypoints(self):
        self.assertEqual(R.ROOT, ROOT)
        for name in FUNCTIONS:
            self.assertEqual(getattr(R, name).__code__.co_filename, str(SOURCE))
        for name in ("pytest", "APIError", "Mount", "image_cache", "shared"):
            self.assertNotIn(name, R.__dict__)
        self.assertFalse(any(name.startswith("test_") for name in R.__dict__))

    def test_native_snapshot_current_spec_rejects_removed_selector_and_wrong_fd(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); path = root / 'spec.json'
            daemon = SimpleNamespace(root=root, owner_binary=root / 'cengine')
            args = (str(daemon.owner_binary), 'vm-shim', '--spec', str(path), '--spec-sha256', 'a'*64,
                    '--storage-disk-fd', '3', '--storage-lifecycle-fd', '4')
            process = SimpleNamespace(arguments=args, pid=55, identity=(100, 2, 300), pidversion=8)
            status = dict(state='running', processIdentifier=55, processStartTime=100000002,
                          executableUUID='executable', shimLaunchUUID='launch', generation=1)
            spec = dict(kind='storage', containerID='cengine-storage')
            with patch.object(R, 'compatibility_runtime_processes', return_value=[process], create=True), \
                    patch.object(R, '_status', return_value=status, create=True):
                path.write_text(R.json.dumps(spec))
                self.assertEqual(set(R.native_snapshot(daemon, set())), {'storage'})
                for value in ('managed', 'lifecycle', None):
                    path.write_text(R.json.dumps({**spec, 'storageStartupMode': value}))
                    with self.subTest(selector=value), self.assertRaisesRegex(ValueError, 'retired storage startup selector'):
                        R.native_snapshot(daemon, set())
                path.write_text(R.json.dumps(spec))
                for wrong in (args[:-4], args[:-1]+('5',)):
                    process.arguments = wrong
                    with self.assertRaises(AssertionError): R.native_snapshot(daemon, set())
                process.arguments = args
                for field in ('processStartTime', 'executableUUID', 'shimLaunchUUID', 'generation'):
                    saved = status.pop(field)
                    with self.subTest(missing=field), self.assertRaises(AssertionError): R.native_snapshot(daemon, set())
                    status[field] = saved

    def test_only_absent_profile_is_inapplicable(self):
        self.assertTrue(R.selected({}))
        with self.assertRaises(ValueError):
            R.selected({"CENGINE_COMPAT_MANAGED_STORAGE": "1"})
        self.assertTrue(R.selected(SELECTED))
        self.assertFalse(R.selected(SELECTED, fault=True))
        self.assertTrue(R.selected({**SELECTED, R.FAULT_ENV: R.FAULT}, fault=True))
        for extra in ({"CENGINE_COMPAT_MANAGED_STORAGE": "0"},
                      {"CENGINE_COMPAT_SHARED_STORAGE": "unknown"},
                      {"CENGINE_STORAGE_LIFECYCLE_QUALIFICATION": "lifecycle-v2-native-v1"},
                      {"PREPARE_COMPATIBILITY_PROFILE": "anything"},
                      {R.FAULT_ENV: "unknown"}, {R.FAULT_ENV: R.FAULT}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                R.selected({**SELECTED, **extra})
        self.assertTrue(R.selected({R.FAULT_ENV: R.FAULT}, fault=True))

    def test_opted_in_missing_assets_fails_before_any_subprocess(self):
        with patch.object(R.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                R.prerequisites(SELECTED)
            run.assert_not_called()

    def test_prerequisites_use_renamed_helper_with_stable_signing_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            assets = root / "assets"
            assets.mkdir()
            environment = {**SELECTED, "CENGINE_BINARY": str(root / "cengine"),
                           "CENGINE_COMPAT_MANAGED_ASSET_DIR": str(assets),
                           "CENGINE_DEVELOPER_ID_APPLICATION": "Developer ID Application: Test (TEAM)"}
            for name in ("cengine", "cengine-helper", "cengine-storage-controller"):
                executable = root / name
                executable.write_text("fixture")
                executable.chmod(0o755)
            for key, name in (("CENGINE_KERNEL", "vmlinux"),
                              ("CENGINE_CONTAINER_INITRAMFS", "container-initramfs.cpio.gz"),
                              ("CENGINE_STORAGE_INITRAMFS", "storage-initramfs.cpio.gz")):
                (assets / name).touch()
                environment[key] = str(assets / name)
            with patch.object(R.subprocess, "run") as run:
                R.prerequisites(environment)
                self.assertEqual(run.call_count, 2)
                guard = run.call_args.args[0][2]
                self.assertIn('/cengine-helper" dev.cengine.network-helper.test-compat', guard)
                self.assertNotIn("cengine-network-helper", guard)
                command = run.call_args.args[0].copy()
            # Execute the actual shell composition, not just a string assertion.
            # Stub only installation/signing I/O; use the real policy selector.
            scripts = root / "Scripts"
            scripts.mkdir()
            (scripts / "helper_compatibility_policy.py").write_bytes(
                (ROOT / "Scripts/helper_compatibility_policy.py").read_bytes())
            (scripts / "compat-network-helper.sh").write_text(
                '. "$REAL_CHECKOUT/Scripts/compat-network-helper.sh"\n'
                'compat_network_helper_require() { compat_network_helper_select_policy; }\n')
            (scripts / "managed-signing.sh").write_text(
                'managed_signing_team() { printf TEAM; }\n'
                'managed_signing_verify() { :; }\n')
            fingerprint = scripts / "network-helper-fingerprint.sh"
            fingerprint.write_text('#!/bin/sh\nprintf fingerprint\\n')
            fingerprint.chmod(0o755)
            (assets / "disk-bootstrap.json").write_text('{"storageLifecycleVersion": 2}')
            command[4] = str(root)
            result = subprocess.run(command, env={
                "PATH": R.os.environ["PATH"], "REAL_CHECKOUT": str(ROOT), **environment,
            }, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "compatible lifecycle-v2")
            (root / "cengine-helper").rename(root / "cengine-network-helper")
            with patch.object(R.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "paired signed compatibility executable"):
                    R.prerequisites(environment)
                run.assert_not_called()

    def test_progress_requires_both_directions_same_fd_and_advance(self):
        before = (10, 11, "2:33", 42)
        self.assertTrue(R.progressed(before, (13, 14, "2:33", 49, 24)))
        for after in (None, before, (13, 11, "2:33", 49),
                      (13, 14, "2:34", 49), (13, 14, "2:33", 42),
                      (1, 14, "2:33", 49), (11, 12, "2:33", 49)):
            with self.subTest(after=after):
                self.assertFalse(R.progressed(before, after))

    def test_clock_bound_rejects_pre_kill_buffered_output(self):
        clock = (100.0, 20.0)
        self.assertFalse(R.produced_while_absent(None, clock, 103.0))
        for stamp in (20, 23, 24):
            self.assertFalse(R.produced_while_absent((90, 90, "2:33", 900, stamp), clock, 103.0))
        self.assertTrue(R.produced_while_absent((90, 90, "2:33", 900, 25), clock, 103.0))

    def test_parser_rejects_partial_wrong_peer_and_zero_identity(self):
        good = b"LIFECYCLE left 13 14 2:33 49 24\n"
        self.assertEqual(R.parse_progress(good, "left"), (13, 14, "2:33", 49, 24))
        for data in (good[:-1], good.replace(b"left", b"right"),
                     good.replace(b"2:33", b"2:0"), good.replace(b"49", b"0")):
            self.assertIsNone(R.parse_progress(data, "left"))
        self.assertEqual(R.parse_progress(good + b"LIFECYCLE left 14 ", "left"),
                         (13, 14, "2:33", 49, 24))

    def test_disk_identity_observes_inode_uuid_and_creation_time(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "infrastructure").mkdir()
            path = root / "infrastructure/volumes.ext4"
            data = bytearray(2048)
            data[1080:1082] = b"\x53\xef"
            data[1128:1144] = bytes(range(16))
            path.write_bytes(data)
            before = R.disk_identity(root)
            data[1288] = 1
            path.write_bytes(data)
            self.assertNotEqual(R.disk_identity(root), before)
            data[1288] = 0
            replacement = path.with_suffix(".next")
            replacement.write_bytes(data)
            replacement.replace(path)
            self.assertNotEqual(R.disk_identity(root), before)

    def test_fault_requires_exact_once_fault_and_clean_stop_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            daemon = SimpleNamespace(root=Path(temp))
            path = daemon.root / 'infrastructure/shim.log'
            path.parent.mkdir()
            good = (R.FAULT_REACHED + '\n' + R.FAULT_STOPPED + '\n').encode()
            for data, accepted in ((good, True), (b'', False),
                    (good + good, False), (good.splitlines()[0], False),
                    (good.replace(R.FAULT_STOPPED.encode(), b'EOF timeout kill'), False),
                    (b'prefix-' + good, False), (good + b'x' * 1048577, False)):
                path.write_bytes(data)
                if len(data) > 1048576:
                    with self.assertRaises(AssertionError):
                        R.qualify_initialization_fault(daemon, timeout=0)
                else:
                    self.assertEqual(R.qualify_initialization_fault(daemon, timeout=0), accepted)

    def test_fault_waits_passively_for_clean_callback_after_daemon_exit(self):
        for completion in ('clean', 'never', 'duplicate-injection', 'duplicate-clean'):
            with self.subTest(completion=completion), tempfile.TemporaryDirectory() as temp:
                # waitpid has returned; only the separate shim's log can advance.
                daemon = SimpleNamespace(root=Path(temp), process=SimpleNamespace(returncode=71))
                path = daemon.root / 'infrastructure/shim.log'
                path.parent.mkdir()
                path.write_text(R.FAULT_REACHED + '\n')
                elapsed = 0.0
                appended = False

                def sleep(delay):
                    nonlocal elapsed, appended
                    self.assertEqual(daemon.process.returncode, 71)
                    self.assertGreater(delay, 0)
                    self.assertLessEqual(delay, 0.1)
                    elapsed += delay
                    if elapsed >= 1.8 and not appended and completion != 'never':
                        appended = True
                        lines = [R.FAULT_STOPPED]
                        if completion == 'duplicate-injection':
                            lines.append(R.FAULT_REACHED)
                        elif completion == 'duplicate-clean':
                            lines.append(R.FAULT_STOPPED)
                        with path.open('a') as stream:
                            stream.write('\n'.join(lines) + '\n')

                clock = SimpleNamespace(monotonic=lambda: elapsed, sleep=Mock(side_effect=sleep))
                with patch.object(R, 'time', clock):
                    self.assertEqual(R.qualify_initialization_fault(daemon), completion == 'clean')
                self.assertGreaterEqual(elapsed, 1.8)
                if completion == 'never':
                    self.assertEqual(elapsed, 15)
                    self.assertEqual(path.read_text(), R.FAULT_REACHED + '\n')
                else:
                    self.assertLess(elapsed, 2)

    def test_fault_refuses_existing_duplicates_without_waiting(self):
        with tempfile.TemporaryDirectory() as temp:
            daemon = SimpleNamespace(root=Path(temp))
            path = daemon.root / 'infrastructure/shim.log'
            path.parent.mkdir()
            for reached, stopped in ((2, 0), (2, 1), (1, 2), (0, 2)):
                with self.subTest(reached=reached, stopped=stopped):
                    path.write_text((R.FAULT_REACHED + '\n') * reached
                                    + (R.FAULT_STOPPED + '\n') * stopped)
                    with patch.object(R, 'time', SimpleNamespace(monotonic=lambda: 0, sleep=Mock())):
                        self.assertFalse(R.qualify_initialization_fault(daemon))
                        R.time.sleep.assert_not_called()

    def test_fault_diagnostic_errors_are_not_retried_or_qualified(self):
        with tempfile.TemporaryDirectory() as temp:
            daemon = SimpleNamespace(root=Path(temp))
            with patch.object(R, 'time', SimpleNamespace(monotonic=lambda: 0, sleep=Mock())):
                with self.assertRaises(FileNotFoundError):
                    R.qualify_initialization_fault(daemon)
                for error in (PermissionError('unreadable'), OSError('unknown error')):
                    with self.subTest(error=type(error)), patch.object(Path, 'open', side_effect=error):
                        with self.assertRaises(type(error)):
                            R.qualify_initialization_fault(daemon)
                R.time.sleep.assert_not_called()

    def initialization_fixture(self, root):
        (root / 'infrastructure').mkdir()
        disk = bytearray(2048)
        disk[1080:1082] = b'\x53\xef'
        disk[1128:1144] = bytes(range(16))
        backing = root / 'infrastructure/volumes.ext4'
        backing.write_bytes(disk)
        marker = root / 'managed-storage-initialization/manifest.json'
        marker.parent.mkdir()
        marker.write_text(R.json.dumps({'version': 'storage-host-initialization.v2',
            'binding': {'version': 'storage-host-binding.v2',
                        'root': {'inode': root.stat().st_ino, 'volume_uuid': str(R.uuid.uuid4())}, 'ext4_uuid': str(R.uuid.UUID(bytes=bytes(range(16)))),
                        'backing': {'inode': backing.stat().st_ino, 'volume_uuid': str(R.uuid.uuid4())}}}))
        return backing, marker

    def test_resume_observes_same_disk_and_manifest_before_api_fixtures(self):
        for mutation in ('none', 'uuid', 'creation', 'inode', 'manifest', 'reinjected'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                backing, marker = self.initialization_fixture(root)
                events = []
                daemon = SimpleNamespace(root=root, root_retained=True, process=None, binary='same-fault-binary')

                def start(**kwargs):
                    if kwargs:
                        self.assertIs(kwargs['qualify_lifecycle_fault'], R.qualify_initialization_fault)
                        events.append('fault-start')
                        daemon.process = SimpleNamespace(returncode=71)
                        return
                    self.assertEqual(events, ['fault-start'])
                    events.append('resume-start')
                    (marker.parent / 'completed.json').write_text('{}')
                    (marker.parent / 'admitted.json').write_text('true')
                    if mutation in ('uuid', 'creation'):
                        data = bytearray(backing.read_bytes())
                        data[1128 if mutation == 'uuid' else 1288] ^= 1
                        backing.write_bytes(data)
                    elif mutation == 'inode':
                        replacement = backing.with_suffix('.next')
                        replacement.write_bytes(backing.read_bytes())
                        replacement.replace(backing)
                    elif mutation == 'manifest':
                        marker.write_bytes(marker.read_bytes() + b' ')
                daemon.start = start
                with patch.object(R, 'fault_diagnostics', return_value=(2, 2) if mutation == 'reinjected' else (1, 1)):
                    if mutation == 'none':
                        R.resume_initialization(daemon)
                    else:
                        with self.assertRaises(AssertionError):
                            R.resume_initialization(daemon)
                self.assertEqual(events, ['fault-start', 'resume-start'])

    def test_resume_rejects_old_initialization_and_binding_formats_before_restart(self):
        for mutation in ('old-marker', 'old-binding', 'missing-version', 'legacy-device'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                _, marker = self.initialization_fixture(root)
                value = R.json.loads(marker.read_bytes())
                if mutation == 'old-marker': value['version'] = 'storage-host-initialization.v1'
                elif mutation == 'old-binding': value['binding']['version'] = 'storage-host-binding.v1'
                elif mutation == 'missing-version': del value['binding']['version']
                else: value['binding']['backing']['device'] = 123
                marker.write_text(R.json.dumps(value))
                daemon = SimpleNamespace(root=root, root_retained=True, process=None, binary='same-fault-binary', start=Mock())
                with self.assertRaises((AssertionError, KeyError)):
                    R.resume_initialization(daemon)
                daemon.start.assert_called_once_with(qualify_lifecycle_fault=R.qualify_initialization_fault)

    def test_manual_override_precedes_client_and_both_refs_precede_start(self):
        tree = ast.parse(SOURCE.read_text())
        override = next(node for node in tree.body if getattr(node, 'name', None) == 'daemon')
        override.decorator_list = []
        namespace = dict(R.__dict__)
        namespace['resume_initialization'] = Mock()
        exec(compile(ast.Module(body=[override], type_ignores=[]), str(SOURCE), 'exec'), namespace)
        daemon = object()
        for case in ('RTM-117', 'RTM-118', 'RTM-119', 'RTM-120', 'RTM-121'):
            namespace['resume_initialization'].reset_mock()
            request = SimpleNamespace(node=SimpleNamespace(
                get_closest_marker=lambda name: SimpleNamespace(args=(case,))))
            self.assertIs(namespace['daemon'](daemon, request), daemon)
            self.assertEqual(namespace['resume_initialization'].call_count, case == 'RTM-119')
        test = next(node for node in tree.body if getattr(node, 'name', '') ==
                    'test_lifecycle_v2_first_initialization_failure_resumes')
        self.assertIn('indirect=True', ast.unparse(test.decorator_list[-1]))
        test.decorator_list = []
        events = []
        namespace.update(create_peer=lambda client, shared, name: (
            events.append('create-' + name) or SimpleNamespace(start=lambda: events.append('start-' + name))),
            mount_proof=lambda *args: None, fault_diagnostics=lambda daemon: (1, 1),
            exchange=lambda *args: events.append('DATA'))
        exec(compile(ast.Module(body=[test], type_ignores=[]), str(SOURCE), 'exec'), namespace)
        namespace[test.name](object(), daemon, object())
        self.assertEqual(events, ['create-left', 'create-right', 'start-left', 'start-right', 'DATA'])

    def replacement_fixture(self):
        uid = lambda: str(R.uuid.uuid4())
        identity = dict(store=uid(), generation=1, binding='a' * 64)
        context = dict(service_epoch=uid(), controller_epoch=1, controller_key='b' * 64)
        boot = dict(identity=identity, service_epoch=context['service_epoch'],
                    tls_root_sha256='c' * 64, server_spki='d' * 64, bootstrap_key='e' * 64)
        service = dict(grant=dict(identity=identity, new_key=context['controller_key'], expected_epoch=0,
                                 operation='initialize', id=uid(), serial=1),
                       context=context, boot=boot, open_revision=1)
        before = dict(version='storage-lifecycle.v2', identity=identity, currentService=service,
                      rootPublicKey='public-root', provenanceReference='provenance', current={'original': 'root-grant'},
                      revision=1, currentContext=dict(serviceEpoch=context['service_epoch'], controllerEpoch=1,
                                                     controllerKey=context['controller_key']))
        before['observedWorker'] = dict(context=copy.deepcopy(before['currentContext']), workerUUID=uid())
        after = copy.deepcopy(before)
        after['revision'] = 2
        new = after['currentService']
        new['context']['service_epoch'] = new['boot']['service_epoch'] = uid()
        new['boot'].update(tls_root_sha256='f' * 64, server_spki='0' * 64)
        new['open_revision'] = 2
        after['currentContext']['serviceEpoch'] = new['context']['service_epoch']
        after['observedWorker'] = dict(context=copy.deepcopy(after['currentContext']), workerUUID=uid())
        request, raw = R.replacement.worker_request(uid(), identity['store'], R.lifecycle_owner(before))
        change = dict(operation_id=request['operationUUID'], predecessor=service)
        after['latestServiceConfirmation'] = dict(request=change, successor=new)
        after['latestServiceRequest'] = dict(request=change, predecessorWorkerUUID=before['observedWorker']['workerUUID'], nowUnixSeconds=10)
        after['latestServiceChange'] = dict(operationID=request['operationUUID'], predecessor=before['currentContext'],
                                           successor=after['currentContext'], revision=2)
        proof = dict(controllerEpoch=1, controllerKey=context['controller_key'], rootPublicKey=before['rootPublicKey'])
        pending = dict(schema=1, counter=1, phase='pending', request=request, proof=proof)
        succeeded = dict(pending, phase='succeeded', successor=R.lifecycle_owner(after), containedContainerIDs=['a', 'b'],
                         ownerRequest=dict(operationUUID=request['operationUUID'], predecessor=request['predecessor'], nowUnixSeconds=10))
        return before, after, pending, succeeded, request, ['a', 'b'], 9, 11

    def test_v2_same_controller_replacement_correlates_actual_checkpoint_and_receipts(self):
        R.lifecycle_replacement_proof(*self.replacement_fixture())
        # Metadata can retain the latest native operation after successful commit.
        values = self.replacement_fixture()
        values[1].update(serviceReplacement={'completed': True}, nativeReplacementAttempted=True)
        R.lifecycle_replacement_proof(*values)

    def test_v2_refuses_legacy_missing_boot_fields_and_unsettled_owner(self):
        before = self.replacement_fixture()[0]
        mutations = [('version', 'storage-lifecycle.v1'), ('pendingService', {}), ('pendingCold', {}),
                     ('sealed', {}), ('currentContext', {}), ('rootPublicKey', '')]
        for field, value in mutations:
            record = copy.deepcopy(before)
            record[field] = value
            with self.subTest(field=field), self.assertRaises((AssertionError, KeyError)):
                R.lifecycle_owner(record)
        for field in ('tls_root_sha256', 'identity'):
            record = copy.deepcopy(before)
            del record['currentService']['boot'][field]
            with self.subTest(missing=field), self.assertRaises((AssertionError, KeyError)):
                R.lifecycle_owner(record)

    def test_v2_requires_complete_observed_worker_projection(self):
        for index in (0, 1):
            for path in (('observedWorker',), ('observedWorker', 'context'),
                         ('observedWorker', 'workerUUID'),
                         *(('observedWorker', 'context', key) for key in
                           ('serviceEpoch', 'controllerEpoch', 'controllerKey'))):
                record = self.replacement_fixture()[index]
                target = record
                for key in path[:-1]:
                    target = target[key]
                del target[path[-1]]
                with self.subTest(index=index, missing=path), self.assertRaises((AssertionError, KeyError)):
                    R.lifecycle_owner(record)

    def test_v2_rejects_stale_observed_worker_projection(self):
        before, after, *_ = self.replacement_fixture()
        after['observedWorker'] = copy.deepcopy(before['observedWorker'])
        with self.assertRaisesRegex(AssertionError, 'stale or mismatched'):
            R.lifecycle_owner(after)

    def test_v2_matches_observation_to_both_current_and_service_context(self):
        for field, value in (('serviceEpoch', str(R.uuid.uuid4())),
                             ('controllerEpoch', 2), ('controllerKey', 'f' * 64)):
            for target in ('observation', 'current', 'both'):
                record = self.replacement_fixture()[0]
                if target in ('observation', 'both'):
                    record['observedWorker']['context'][field] = value
                if target in ('current', 'both'):
                    record['currentContext'][field] = value
                with self.subTest(field=field, target=target), self.assertRaises(AssertionError):
                    R.lifecycle_owner(record)

    def test_v2_rejects_wrong_typed_or_noncanonical_projection(self):
        mutations = [
            (('observedWorker',), value) for value in (None, [], True, 'worker')
        ] + [
            (('observedWorker', 'context'), value) for value in (None, [], 1, 'context')
        ] + [
            (('observedWorker', 'workerUUID'), value)
            for value in (None, 1, True, [], {}, '', 'not-a-uuid',
                          'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', str(R.uuid.uuid1()))
        ] + [
            (prefix + (field,), value)
            for prefix in (('observedWorker', 'context'), ('currentContext',))
            for field, values in (('controllerEpoch', (True, 1.0, '1', None)),
                                  ('serviceEpoch', (1, None, [])), ('controllerKey', (1, None, [])))
            for value in values
        ]
        for path, value in mutations:
            record = self.replacement_fixture()[0]
            target = record
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path, value=value), self.assertRaises(
                    (AssertionError, ValueError, R.replacement.ProofFailure)):
                R.lifecycle_owner(record)

    def test_v2_boot_trust_neither_requires_nor_allows_worker_uuid(self):
        for record in self.replacement_fixture()[:2]:
            boot = record['currentService']['boot']
            self.assertNotIn('worker_uuid', boot)
            scope = R.lifecycle_owner(record)
            self.assertEqual(scope['workerUUID'], record['observedWorker']['workerUUID'])
            boot['worker_uuid'] = scope['workerUUID']
            with self.assertRaises(AssertionError):
                R.lifecycle_owner(record)

    def test_v2_rejects_mutated_identity_tls_scope_receipt_and_checkpoint(self):
        mutations = [
            (1, ('identity', 'generation'), 2), (1, ('rootPublicKey',), 'foreign-root'),
            (1, ('provenanceReference',), 'foreign'), (1, ('current',), {}),
            (1, ('currentService', 'context', 'controller_epoch'), 2),
            (1, ('currentService', 'context', 'controller_key'), 'f' * 64),
            (1, ('currentService', 'boot', 'tls_root_sha256'), 'c' * 64),
            (1, ('currentService', 'boot', 'server_spki'), 'd' * 64),
            (1, ('currentService', 'open_revision'), 1),
            (1, ('latestServiceRequest', 'nowUnixSeconds'), 8),
            (1, ('latestServiceChange', 'operationID'), str(R.uuid.uuid4())),
            (2, ('phase',), 'succeeded'), (2, ('counter',), True),
            (3, ('containedContainerIDs',), ['a']), (3, ('schema',), 2),
            (3, ('ownerRequest', 'nowUnixSeconds'), 12), (3, ('successor', 'workerUUID'), str(R.uuid.uuid4())),
        ]
        for index, fields, value in mutations:
            args = copy.deepcopy(self.replacement_fixture())
            target = args[index]
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = value
            with self.subTest(fields=fields), self.assertRaises((AssertionError, KeyError)):
                R.lifecycle_replacement_proof(*args)
        for field in ('workerUUID', 'serviceEpoch'):
            args = copy.deepcopy(self.replacement_fixture())
            if field == 'workerUUID':
                args[1]['observedWorker'][field] = args[0]['observedWorker'][field]
            else:
                old_epoch = args[0]['currentContext'][field]
                args[1]['currentService']['boot']['service_epoch'] = old_epoch
                args[1]['currentService']['context']['service_epoch'] = old_epoch
                args[1]['currentContext'][field] = old_epoch
                args[1]['observedWorker']['context'][field] = old_epoch
            with self.subTest(stale=field), self.assertRaisesRegex(AssertionError, 'fresh E and worker required'):
                R.lifecycle_replacement_proof(*args)

    def test_queue_correlates_owned_inode_and_never_accepts_failed_or_mutated_artifacts(self):
        before, after, pending, success, request, *_ = self.replacement_fixture()
        raw = R.replacement.worker_request(request['operationUUID'], request['store'], request['predecessor'])[1]
        stem = request['operationUUID']
        files = {stem + '.request.json': (raw, (1, 2, 3, 4, 'hash')),
                 stem + '.pending.json': (R.json.dumps(pending).encode(), (1, 3)),
                 stem + '.succeeded.json': (R.json.dumps(success).encode(), (1, 4))}
        def read(queue, name, maximum=1048576):
            if name not in files:
                raise FileNotFoundError(name)
            return files[name]
        validate = Mock()
        with patch.object(R.replacement, 'queue_file', side_effect=read), patch.object(
                R.replacement, 'settled_worker_artifacts') as settled:
            observed = R.replacement_receipts(7, validate, request, raw, (1, 2), timeout=0)
            self.assertEqual(observed, (pending, success, files))
            settled.assert_called_once_with(7, stem, files)
            with self.assertRaises(AssertionError):
                R.replacement_receipts(7, validate, request, raw, (9, 9), timeout=0)
            files[stem + '.failed.json'] = (b'{}', (1, 5))
            with self.assertRaises(AssertionError):
                R.replacement_receipts(7, validate, request, raw, (1, 2), timeout=0)
            del files[stem + '.failed.json']
            del files[stem + '.succeeded.json']
            with self.assertRaises(AssertionError):
                R.replacement_receipts(7, validate, request, raw, (1, 2), timeout=0)
            validate.assert_called()

    def test_queue_rejects_receipt_mutation_while_waiting_for_success(self):
        _, _, pending, success, request, *_ = self.replacement_fixture()
        raw = R.replacement.worker_request(request['operationUUID'], request['store'], request['predecessor'])[1]
        stem = request['operationUUID']
        reads = 0
        def read(queue, name, maximum=1048576):
            nonlocal reads
            if name.endswith('.failed.json') or name.endswith('.succeeded.json'):
                raise FileNotFoundError(name)
            if name.endswith('.request.json'):
                return raw, (1, 2)
            reads += 1
            return R.json.dumps(pending).encode(), (1, reads)
        with patch.object(R.replacement, 'queue_file', side_effect=read), patch.object(R.time, 'sleep'):
            with self.assertRaisesRegex(AssertionError, 'immutable replacement artifact changed'):
                R.replacement_receipts(7, Mock(), request, raw, (1, 2))
        self.assertEqual(reads, 2)

    def test_replacement_entry_keeps_native_exit_and_storage_only_snapshot_guards(self):
        tree = ast.parse(SOURCE.read_text())
        test = next(n for n in tree.body if getattr(n, 'name', '') ==
                    'test_lifecycle_v2_same_daemon_worker_replacement')
        code = ast.unparse(test)
        for token in ('replacement.publish_worker_request', 'replacement.exact_exit', '_kernel_process',
                      "['StatusCode'] == 137", "['ExitCode'] == 137", 'native_snapshot(daemon, set())',
                      'replacement.settled_worker_artifacts', 'disk_identity', 'replacement.disk_budget'):
            self.assertIn(token, code)
        self.assertNotIn('daemon.stop', code)
        self.assertNotIn('peer.stop', code)
        self.assertNotIn('peer.kill', code)
        self.assertIn('180', code)

    def test_replacement_profile_is_distinct_and_incomplete_selection_fails(self):
        env = {**SELECTED, R.FAULT_ENV: R.REPLACEMENT_FAULT}
        self.assertTrue(R.selected(env, fault=R.REPLACEMENT_FAULT))
        self.assertFalse(R.selected(SELECTED, fault=R.REPLACEMENT_FAULT))
        for profile, target in ((R.FAULT, R.REPLACEMENT_FAULT), (R.REPLACEMENT_FAULT, True),
                                (R.REPLACEMENT_FAULT, False), ('unknown', R.REPLACEMENT_FAULT)):
            with self.subTest(profile=profile, target=target), self.assertRaises(ValueError):
                R.selected({**SELECTED, R.FAULT_ENV: profile}, fault=target)
        for extra in ({'CENGINE_COMPAT_MANAGED_STORAGE': '0'}, {'CENGINE_COMPAT_SHARED_STORAGE': ''},
                      {'CENGINE_STORAGE_LIFECYCLE_QUALIFICATION': 'anything'}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                R.selected({**env, **extra}, fault=R.REPLACEMENT_FAULT)

    def test_image_cache_selects_replacement_profile_without_manual_start(self):
        tree = ast.parse(SOURCE.read_text())
        fixture = next(n for n in tree.body if getattr(n, 'name', '') == 'image_cache')
        fixture.decorator_list = []
        namespace = dict(R.__dict__)
        namespace.update(prerequisites=Mock(), pytest=SimpleNamespace(skip=Mock(), fail=Mock()))
        exec(compile(ast.Module(body=[fixture], type_ignores=[]), str(SOURCE), 'exec'), namespace)
        cache = object()
        for case, profile in (('RTM-119', R.FAULT), ('RTM-121', R.REPLACEMENT_FAULT),
                              ('RTM-129', R.COLD_L2_FAULT), ('RTM-130', R.COLD_L2_FAULT)):
            request = SimpleNamespace(node=SimpleNamespace(get_closest_marker=lambda name: SimpleNamespace(args=(case,))))
            with patch.dict(R.os.environ, {**SELECTED, R.FAULT_ENV: profile}, clear=True):
                self.assertIs(namespace['image_cache'](cache, request), cache)
                namespace['prerequisites'].assert_called()
                namespace['pytest'].skip.assert_not_called()
            with patch.dict(R.os.environ, {**SELECTED, R.FAULT_ENV: R.FAULT if case == 'RTM-121' else R.REPLACEMENT_FAULT}, clear=True):
                with self.assertRaises(ValueError):
                    namespace['image_cache'](cache, request)

    def recovery_fixture(self):
        before, changed, pending, _, request, *_ = self.replacement_fixture()
        before['serviceLinks'] = []
        frozen = copy.deepcopy(before)
        frozen['revision'] = 2
        change = copy.deepcopy(changed['latestServiceRequest']['request'])
        retained = dict(request=change, stageRequestID=str(R.uuid.uuid4()),
                        completionRequestID=str(R.uuid.uuid4()), predecessorWorkerUUID=request['predecessor']['workerUUID'],
                        nowUnixSeconds=10, lifetimeSeconds=300)
        frozen.update(pendingService=retained, nativeReplacementAttempted=True,
                      serviceReplacement=dict(predecessor_worker_uuid=request['predecessor']['workerUUID'],
                          configuration=dict(action='open', root_public_key=before['rootPublicKey'],
                              signed=dict(grant=before['currentService']['grant']), now_unix_seconds=10,
                              lifetime_seconds=300, reopen=dict(request=change, signature='public-signature'))))
        native = dict(observation=copy.deepcopy(changed['latestServiceConfirmation']),
                      predecessorWorkerUUID=before['observedWorker']['workerUUID'],
                      workerUUID=changed['observedWorker']['workerUUID'])
        after = copy.deepcopy(changed)
        after['revision'] = 4
        for field in ('latestServiceConfirmation', 'latestServiceRequest', 'latestServiceChange',
                      'serviceReplacement', 'nativeReplacementAttempted'):
            after[field] = None
        after['serviceLinks'] = [copy.deepcopy(changed['latestServiceChange'])]
        after['currentService']['context'].update(controller_epoch=2, controller_key='9' * 64)
        after['currentService']['grant'].update(operation='takeover', expected_epoch=1, new_key='9' * 64)
        after['currentContext'].update(controllerEpoch=2, controllerKey='9' * 64)
        after['observedWorker']['context'] = copy.deepcopy(after['currentContext'])
        grant = copy.deepcopy(after['currentService']['grant'])
        epoch = after['currentContext']['serviceEpoch']
        after['current'] = dict(original=dict(signed=dict(grant=grant, signature='public-takeover-signature'),
                                              serviceEpoch=epoch),
                                directResult=dict(grant=grant, service_epoch=epoch, revision=3))
        # Exercise retained history as well as the normal compacted checkpoint.
        # The saved native observation is independent of either HOST projection.
        after['references'] = [dict(recovery=dict(workerHistoryReference=R.replacement.digest(
            R.json.dumps(after['serviceLinks'][0], sort_keys=True, separators=(',', ':')).encode())))]
        return before, frozen, after, pending, request, native

    def test_recovery_matches_frozen_authorization_and_one_edge_then_takeover(self):
        before, frozen, after, pending, request, native = self.recovery_fixture()
        R.frozen_replacement_proof(before, frozen, pending, request, 9, 11, native)
        R.recovered_replacement_proof(before, frozen, after, request, native)

    def test_completed_adoption_accepts_retained_retry_metadata(self):
        before, frozen, after, _, request, native = self.recovery_fixture()
        expected = R.lifecycle_owner(after)
        # Opaque public retry metadata is deliberately not an authority input.
        after['adoptionRetry'] = dict(status={}, request={},
                                     prepareRequestID=str(R.uuid.uuid4()),
                                     completeRequestID=str(R.uuid.uuid4()))
        self.assertEqual(R.lifecycle_owner(after), expected)
        R.recovered_replacement_proof(before, frozen, after, request, native)
        R.settled_replacement_proof(after, copy.deepcopy(after))

    def test_retained_adoption_retry_does_not_allow_unfinished_states(self):
        for field in ('pending', 'pendingService', 'pendingTakeover', 'pendingCold', 'sealed', 'terminal'):
            before, frozen, after, _, request, native = self.recovery_fixture()
            after['adoptionRetry'] = dict(status={}, request={},
                                         prepareRequestID=str(R.uuid.uuid4()),
                                         completeRequestID=str(R.uuid.uuid4()))
            after[field] = {}
            with self.subTest(field=field):
                with self.assertRaisesRegex(AssertionError, 'unsettled lifecycle owner'):
                    R.lifecycle_owner(after)
                with self.assertRaisesRegex(AssertionError, 'unsettled lifecycle owner'):
                    R.recovered_replacement_proof(before, frozen, after, request, native)
                with self.assertRaisesRegex(AssertionError, 'unsettled lifecycle owner'):
                    R.settled_replacement_proof(after, copy.deepcopy(after))

    def test_frozen_cut_rejects_corrupt_or_completed_evidence(self):
        mutations = [(('nativeReplacementAttempted',), False), (('nativeReplacementAttempted',), 1),
                     (('pendingService', 'request', 'operation_id'), str(R.uuid.uuid4())),
                     (('pendingService', 'nowUnixSeconds'), 12), (('pendingService', 'lifetimeSeconds'), True),
                     (('pendingService', 'predecessorWorkerUUID'), str(R.uuid.uuid4())),
                     (('serviceReplacement', 'configuration', 'action'), 'initialize'),
                     (('serviceReplacement', 'configuration', 'root_public_key'), 'foreign'),
                     (('serviceReplacement', 'configuration', 'reopen', 'signature'), ''),
                     (('serviceReplacement', 'configuration', 'now_unix_seconds'), 11),
                     (('latestServiceConfirmation',), {}), (('pendingTakeover',), {}),
                     (('observedWorker', 'workerUUID'), str(R.uuid.uuid4())),
                     (('serviceLinks',), [{}]), (('identity', 'generation'), 2)]
        for path, value in mutations:
            before, frozen, _, pending, request, native = self.recovery_fixture()
            target = frozen
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises((AssertionError, KeyError)):
                R.frozen_replacement_proof(before, frozen, pending, request, 9, 11, native)
        before, frozen, _, pending, request, native = self.recovery_fixture()
        pending['proof']['controllerKey'] = 'foreign'
        with self.assertRaises(AssertionError):
            R.frozen_replacement_proof(before, frozen, pending, request, 9, 11, native)

    def test_recovery_rejects_extra_replacement_wrong_operation_tls_or_takeover(self):
        mutations = [(('latestServiceConfirmation',), {}), (('latestServiceRequest',), {}),
                     (('latestServiceChange',), {}), (('serviceReplacement',), {}),
                     (('nativeReplacementAttempted',), True),
                     (('serviceLinks', 0, 'operationID'), str(R.uuid.uuid4())),
                     (('serviceLinks', 0, 'predecessor', 'serviceEpoch'), str(R.uuid.uuid4())),
                     (('serviceLinks', 0, 'successor', 'serviceEpoch'), str(R.uuid.uuid4())),
                     (('serviceLinks', 0, 'successor', 'controllerEpoch'), 2),
                     (('serviceLinks', 0, 'successor', 'controllerKey'), '9' * 64),
                     (('serviceLinks', 0, 'revision'), 3),
                     (('current', 'original', 'serviceEpoch'), str(R.uuid.uuid4())),
                     (('current', 'original', 'signed', 'signature'), ''),
                     (('current', 'directResult', 'service_epoch'), str(R.uuid.uuid4())),
                     (('current', 'directResult', 'revision'), 2),
                     (('currentService', 'boot', 'tls_root_sha256'), 'c' * 64),
                     (('currentService', 'boot', 'server_spki'), 'd' * 64),
                     (('observedWorker', 'workerUUID'), 'invalid'),
                     (('currentService', 'context', 'controller_epoch'), 3),
                     (('currentService', 'grant', 'operation'), 'initialize'),
                     (('currentService', 'open_revision'), 3),
                     (('current',), {}), (('pendingService',), {}),
                     (('rootPublicKey',), 'foreign'), (('identity', 'generation'), 2)]
        for path, value in mutations:
            before, frozen, after, _, request, native = self.recovery_fixture()
            target = after
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises((AssertionError, KeyError, ValueError, R.replacement.ProofFailure)):
                R.recovered_replacement_proof(before, frozen, after, request, native)
        before, frozen, after, _, request, native = self.recovery_fixture()
        after['serviceLinks'] *= 2
        with self.assertRaises(AssertionError):
            R.recovered_replacement_proof(before, frozen, after, request, native)

    def test_canonical_takeover_compaction_uses_saved_native_cut_not_history(self):
        before, frozen, after, _, request, native = self.recovery_fixture()
        # complete clears latest*, and required() keeps only links referenced by
        # intent recovery.workerHistoryReference. Fresh pre-cut peers have none.
        self.assertTrue(all(after[field] is None for field in
                            ('latestServiceRequest', 'latestServiceConfirmation', 'latestServiceChange',
                             'serviceReplacement', 'nativeReplacementAttempted')))
        after['serviceLinks'] = []
        after['references'] = []
        R.recovered_replacement_proof(before, frozen, after, request, native)
        R.settled_replacement_proof(after, copy.deepcopy(after))
        with self.assertRaises((AssertionError, TypeError)):
            R.recovered_replacement_proof(before, frozen, after, request, None)

    def test_recovery_requires_frozen_operation_not_just_matching_new_epoch(self):
        for path in (('pendingService', 'request', 'operation_id'),
                     ('serviceReplacement', 'configuration', 'reopen', 'request', 'operation_id')):
            before, frozen, after, _, request, native = self.recovery_fixture()
            target = frozen
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = str(R.uuid.uuid4())
            with self.subTest(path=path), self.assertRaises(AssertionError):
                R.recovered_replacement_proof(before, frozen, after, request, native)

    def test_only_later_unreferenced_history_may_compact_without_service_change(self):
        _, _, after, _, _, _ = self.recovery_fixture()
        final = copy.deepcopy(after)
        R.settled_replacement_proof(after, final)
        final['serviceLinks'] = []
        final['references'] = []
        R.settled_replacement_proof(after, final)
        final['references'] = [dict(recovery=dict(workerHistoryReference='referenced'))]
        with self.assertRaisesRegex(AssertionError, 'referenced replacement history disappeared'):
            R.settled_replacement_proof(after, final)
        for path, value in ((('currentService', 'boot', 'tls_root_sha256'), '8' * 64),
                            (('observedWorker', 'workerUUID'), str(R.uuid.uuid4())),
                            (('latestServiceChange',), {}), (('serviceLinks',), [{}]),
                            (('current', 'directResult', 'revision'), 9)):
            final = copy.deepcopy(after)
            target = final
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(AssertionError):
                R.settled_replacement_proof(after, final)

    def observation_line(self, native):
        return (R.REPLACEMENT_PAUSED + ' ' + R.json.dumps(native, sort_keys=True, separators=(',', ':')) + '\n').encode()

    def test_replacement_cut_requires_exact_daemon_marker_not_shim_log(self):
        *_, native = self.recovery_fixture()
        good = self.observation_line(native)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            daemon = SimpleNamespace(log_path=root / 'daemon.log', root=root)
            (root / 'infrastructure').mkdir()
            (root / 'infrastructure/shim.log').write_bytes(good)
            for data, expected in ((b'', None), (good, (native, good)),
                                   (b'ordinary log\n' + good + b'other log\n', (native, good)),
                                   (good[:-1], None)):
                daemon.log_path.write_bytes(data)
                self.assertEqual(R.replacement_pause_observation(daemon), expected)
            for data in (b'prefix-' + good, good + good, (R.REPLACEMENT_PAUSED + '\n').encode(),
                         good.replace(b' ', b'\t', 1), good + b'x' * 1048577):
                daemon.log_path.write_bytes(data)
                with self.subTest(data=data[:100]), self.assertRaises(AssertionError):
                    R.replacement_pause_observation(daemon)

    def test_native_marker_rejects_duplicate_noncanonical_or_malformed_json(self):
        *_, native = self.recovery_fixture()
        good = self.observation_line(native)
        prefix, payload = good.split(b' ', 1)
        prefix += b' '
        for corrupt in (b'{}\n', b'null\n', b'[]\n', b'not-json\n',
                        payload.replace(b'{', b'{"workerUUID":"duplicate",', 1),
                        payload.replace(b'"open_revision":2', b'"open_revision":2,"open_revision":2'),
                        payload.replace(b'"open_revision":2', b'"open_revision":NaN'),
                        payload.replace(b'"open_revision":2', b'"open_revision":2.0'),
                        payload.replace(b'"open_revision":2', b'"open_revision":true'),
                        b' ' + payload, payload.rstrip() + b' \n', b'x' * 65537 + b'\n',
                        payload.replace(b'"workerUUID"', b'"unknownWorker"'),
                        payload.replace(b'"open_revision":2', b'"extra":0,"open_revision":2')):
            with self.subTest(payload=corrupt[:100]), tempfile.TemporaryDirectory() as temp:
                daemon = SimpleNamespace(log_path=Path(temp) / 'daemon.log')
                daemon.log_path.write_bytes(prefix + corrupt)
                with self.assertRaises((AssertionError, ValueError, TypeError)):
                    R.replacement_pause_observation(daemon)

    def test_saved_native_marker_detects_change_disappearance_or_new_pause(self):
        *_, native = self.recovery_fixture()
        with tempfile.TemporaryDirectory() as temp:
            daemon = SimpleNamespace(log_path=Path(temp) / 'daemon.log')
            good = self.observation_line(native)
            daemon.log_path.write_bytes(good)
            saved = R.replacement_pause_observation(daemon)
            tampered = copy.deepcopy(native)
            tampered['workerUUID'] = str(R.uuid.uuid4())
            for data in (self.observation_line(tampered), b'', good + good):
                daemon.log_path.write_bytes(data)
                with self.assertRaises(AssertionError):
                    assert R.replacement_pause_observation(daemon) == saved

    def test_native_cut_rejects_tampered_operation_worker_controller_tls_or_generation(self):
        mutations = [(('predecessorWorkerUUID',), str(R.uuid.uuid4())),
                     (('workerUUID',), 'invalid'),
                     (('observation', 'request', 'operation_id'), str(R.uuid.uuid4())),
                     (('observation', 'request', 'predecessor', 'open_revision'), 2),
                     (('observation', 'successor', 'grant', 'id'), str(R.uuid.uuid4())),
                     (('observation', 'successor', 'boot', 'identity', 'generation'), 2),
                     (('observation', 'successor', 'boot', 'tls_root_sha256'), 'c' * 64),
                     (('observation', 'successor', 'boot', 'server_spki'), 'd' * 64),
                     (('observation', 'successor', 'boot', 'bootstrap_key'), '0' * 64),
                     (('observation', 'successor', 'context', 'controller_epoch'), 2),
                     (('observation', 'successor', 'context', 'controller_key'), '9' * 64),
                     (('observation', 'successor', 'open_revision'), 1)]
        for path, value in mutations:
            before, frozen, _, pending, request, native = self.recovery_fixture()
            target = native
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises((AssertionError, ValueError, R.replacement.ProofFailure)):
                R.frozen_replacement_proof(before, frozen, pending, request, 9, 11, native)
        before, frozen, _, pending, request, native = self.recovery_fixture()
        native['workerUUID'] = native['predecessorWorkerUUID']
        with self.assertRaises(AssertionError):
            R.frozen_replacement_proof(before, frozen, pending, request, 9, 11, native)

    def test_native_cut_cannot_smuggle_consistent_controller_or_epoch_change(self):
        for mutation in ('controller', 'epoch'):
            before, frozen, _, pending, request, native = self.recovery_fixture()
            successor = native['observation']['successor']
            if mutation == 'controller':
                successor['grant'].update(operation='takeover', expected_epoch=1, new_key='9' * 64)
                successor['context'].update(controller_epoch=2, controller_key='9' * 64)
            else:
                successor['boot']['service_epoch'] = before['currentContext']['serviceEpoch']
                successor['context']['service_epoch'] = before['currentContext']['serviceEpoch']
            R.replacement_observation_shape(native)
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                R.frozen_replacement_proof(before, frozen, pending, request, 9, 11, native)

    def test_recovery_rejects_second_native_worker_or_fresh_tls_even_after_history_compacts(self):
        for field, value in (('worker', str(R.uuid.uuid4())), ('tls_root_sha256', '8' * 64),
                             ('server_spki', '8' * 64), ('open_revision', 3), ('epoch', str(R.uuid.uuid4()))):
            before, frozen, after, _, request, native = self.recovery_fixture()
            after['serviceLinks'], after['references'] = [], []
            if field == 'worker':
                after['observedWorker']['workerUUID'] = value
            elif field == 'open_revision':
                after['currentService']['open_revision'] = value
            elif field == 'epoch':
                after['currentService']['boot']['service_epoch'] = value
                after['currentService']['context']['service_epoch'] = value
                after['currentContext']['serviceEpoch'] = value
                after['observedWorker']['context']['serviceEpoch'] = value
                after['current']['original']['serviceEpoch'] = value
                after['current']['directResult']['service_epoch'] = value
            else:
                after['currentService']['boot'][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                R.recovered_replacement_proof(before, frozen, after, request, native)

    def pending_queue_fixture(self, root, pending, request):
        raw = R.replacement.worker_request(request['operationUUID'], request['store'], request['predecessor'])[1]
        stem = request['operationUUID']
        for suffix, data in (('.request.json', raw), ('.pending.json', R.json.dumps(pending).encode())):
            path = root / (stem + suffix)
            path.write_bytes(data)
            path.chmod(0o600)
        info = (root / (stem + '.request.json')).stat()
        return raw, (info.st_dev, info.st_ino)

    def test_departed_task_queue_cannot_synthesize_success_or_change_pending(self):
        for mutation in ('success', 'failure', 'missing', 'bytes', 'inode', 'wrong-claim', 'extra'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                *_, pending, request, native = self.recovery_fixture()
                raw, marker = self.pending_queue_fixture(root, pending, request)
                queue = R.os.open(root, R.os.O_RDONLY)
                try:
                    actual, seen = R.pending_replacement_artifacts(queue, Mock(), request, raw, marker)
                    self.assertEqual(actual, pending)
                    stem = request['operationUUID']
                    path = root / (stem + '.pending.json')
                    if mutation in ('success', 'failure', 'extra'):
                        suffix = {'success': '.succeeded.json', 'failure': '.failed.json', 'extra': '.writing'}[mutation]
                        (root / (stem + suffix)).write_text('{}')
                    elif mutation == 'missing':
                        path.unlink()
                    elif mutation == 'bytes':
                        path.write_bytes(path.read_bytes() + b' ')
                    elif mutation == 'inode':
                        other = path.with_suffix('.next')
                        other.write_bytes(path.read_bytes())
                        other.chmod(0o600)
                        other.replace(path)
                    else:
                        marker = (0, 0)
                    with self.assertRaises(AssertionError):
                        R.pending_replacement_artifacts(queue, Mock(), request, raw, marker, seen)
                finally:
                    R.os.close(queue)

    def test_fake_cut_wait_requires_genuine_pending_proof_and_live_daemon(self):
        for scenario in ('success', 'absent', 'partial', 'duplicate', 'exited', 'corrupt'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                before, frozen, _, pending, request, native = self.recovery_fixture()
                directory = root / 'queue'
                directory.mkdir()
                raw, marker = self.pending_queue_fixture(directory, pending, request)
                queue = R.os.open(directory, R.os.O_RDONLY)
                daemon = SimpleNamespace(log_path=root / 'daemon.log', process=Mock())
                daemon.process.poll.return_value = 0 if scenario == 'exited' else None
                daemon.log_path.write_text('')
                elapsed = 0
                def sleep(delay):
                    nonlocal elapsed
                    elapsed += delay
                    if scenario != 'absent':
                        line = self.observation_line(native)
                        daemon.log_path.write_bytes(line[:-1] if scenario == 'partial' else
                                                    line * (2 if scenario == 'duplicate' else 1))
                if scenario == 'corrupt':
                    frozen['nativeReplacementAttempted'] = False
                clock = SimpleNamespace(monotonic=lambda: elapsed, sleep=sleep, time=lambda: 11)
                try:
                    with patch.object(R, 'time', clock), patch.object(R.replacement, 'read_public', return_value=(frozen, 'stamp')):
                        call = lambda: R.wait_replacement_pause(daemon, root / 'state', before, queue, Mock(), request, raw, marker, 9, timeout=0.2)
                        if scenario == 'success':
                            result = call()
                            self.assertEqual(result[:2], (frozen, 'stamp'))
                        else:
                            with self.assertRaises(AssertionError):
                                call()
                    self.assertLessEqual(elapsed, 0.2)
                finally:
                    R.os.close(queue)

    def test_fake_entry_publishes_then_cuts_only_daemon_and_restarts_same_binary(self):
        tree = ast.parse(SOURCE.read_text())
        node = next(n for n in tree.body if getattr(n, 'name', '') ==
                    'test_lifecycle_v2_daemon_death_during_worker_replacement')
        node.decorator_list = []
        events = []
        before, frozen, after, _, request, native = self.recovery_fixture()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original_api = SimpleNamespace(pid=10, identity='api-old', pidversion=1)
            new_api = SimpleNamespace(pid=20, identity='api-new', pidversion=2)
            processes = {10: original_api}
            for pid in (11, 12, 13):
                processes[pid] = SimpleNamespace(pid=pid, identity=str(pid), pidversion=1,
                                                 arguments=('cengine', 'vm-shim'))
            snapshots = {'storage': {'native': (11, '11', 1)}, 'left': {'native': (12, '12', 1)},
                         'right': {'native': (13, '13', 1)}}
            record = before
            paused = 0
            seed = None
            daemon = SimpleNamespace(root=root, binary='same-fault', owner_binary='same-fault',
                                     process=SimpleNamespace(pid=10, poll=lambda: None))
            def stop(*, kill):
                self.assertTrue(kill)
                self.assertEqual(events[-1], 'native-cut')
                events.append('kill-daemon')
                del processes[10]
                daemon.process.poll = lambda: -9
            def start():
                nonlocal record
                self.assertEqual(events[-1], 'pending')
                self.assertEqual(daemon.binary, 'same-fault')
                events.append('normal-start')
                daemon.process = SimpleNamespace(pid=20, poll=lambda: None)
                processes[20] = new_api
                del processes[12], processes[13]
                record = after
            daemon.stop, daemon.start = stop, start
            def create(client, shared, name):
                events.append('create-' + name)
                return SimpleNamespace(id=name, start=lambda: events.append('start-' + name),
                    reload=lambda: None, wait=lambda **kw: {'StatusCode': 137},
                    attrs={'State': {'Running': False, 'ExitCode': 137}})
            def exchange(left, right, marker):
                nonlocal seed
                if seed is None:
                    seed = marker
                events.append('DATA')
            def execute(peer, command, *args):
                return (seed + '-' + args[0].removeprefix('/data/seed-')).encode() if command == 'cat' else b''
            def publish(queue, raw):
                events.append('publish-owned-request')
                return (1, 2)
            def cut(*args):
                nonlocal record, paused
                self.assertEqual(events[-1], 'publish-owned-request')
                record, paused = frozen, 1
                events.append('native-cut')
                return frozen, 'stamp', {}, (native, self.observation_line(native))
            def pending(*args):
                events.append('pending')
            replacement = SimpleNamespace(disk_budget=lambda *args: {'allocated': 1},
                read_public=lambda path: (record, 'stamp'), worker_request=lambda *args: (request, b'raw'),
                replacement_queue=lambda *args: nullcontext((7, lambda: None)),
                publish_worker_request=publish, exact_exit=lambda old, current: current is None)
            def snapshot(daemon, ids):
                if 10 not in processes and 20 not in processes:
                    # Old-E DATA EOF may already have failed the workload VMs;
                    # only the infrastructure VM must still be running at this cut.
                    self.assertFalse(ids, 'do not require old workloads running after worker replacement')
                return {'storage': snapshots['storage'], **{
                    id: snapshots.get(id, {'native': (30, 'fresh', 1)}) for id in ids}}
            namespace = dict(R.__dict__)
            namespace.update(replacement=replacement, create_peer=create, exchange=exchange, _exec=execute,
                mount_proof=lambda *args: None, disk_identity=lambda *args: 'disk',
                replacement_pause_observation=lambda daemon: (native, self.observation_line(native)) if paused else None,
                pending_replacement_artifacts=pending,
                wait_replacement_pause=cut, recovered_replacement_proof=Mock(), settled_replacement_proof=Mock(),
                lifecycle_owner=lambda record: R.lifecycle_owner(record),
                native_snapshot=snapshot,
                compatibility_runtime_processes=lambda *args, **kw: [p for p in processes.values() if p.pid != daemon.process.pid],
                _kernel_process=lambda pid: processes.get(pid), wait_for_value=lambda call, predicate, **kw: self.assertTrue(predicate(call())))
            module = ModuleType('test_managed_storage_recovery')
            module.parent_deadline = lambda deadline: nullcontext()
            exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), 'exec'), namespace)
            with patch.dict(sys.modules, {'test_managed_storage_recovery': module}):
                namespace[node.name](SimpleNamespace(ping=lambda: True), daemon, object())
            self.assertEqual(events[:4], ['create-left', 'create-right', 'start-left', 'start-right'])
            self.assertEqual(events.count('publish-owned-request'), 1)
            self.assertEqual(events.count('kill-daemon'), 1)
            self.assertEqual(events.count('normal-start'), 1)
            self.assertEqual(events.count('DATA'), 2)
            self.assertEqual(namespace['recovered_replacement_proof'].call_count, 1)
            self.assertEqual(namespace['settled_replacement_proof'].call_count, 1)

    def test_crash_entry_uses_real_queue_and_only_daemon_kill(self):
        tree = ast.parse(SOURCE.read_text())
        node = next(n for n in tree.body if getattr(n, 'name', '') ==
                    'test_lifecycle_v2_daemon_death_during_worker_replacement')
        code = ast.unparse(node)
        for text in ('replacement.publish_worker_request', 'wait_replacement_pause', 'daemon.stop(kill=True)',
                     'daemon.start()', 'replacement.exact_exit', "['StatusCode'] == 137", "['ExitCode'] == 137",
                     'recovered_replacement_proof', 'pending_replacement_artifacts', 'replacement.disk_budget',
                     'disk_identity', 'native_snapshot(daemon, ids)', 'native_snapshot(daemon, set())', '180'):
            self.assertIn(text, code)
        self.assertLess(code.index('wait_replacement_pause'), code.index('daemon.stop(kill=True)'))
        self.assertLess(code.index('daemon.stop(kill=True)'), code.index('daemon.start()'))
        self.assertLess(code.index('recovered_replacement_proof'), code.index('client.ping()'))
        self.assertLess(code.index('recovered_replacement_proof'), code.index('peer.wait('))
        self.assertEqual(code.count('replacement_pause_observation(daemon) == pause'), 3)
        for text in ('peer.kill', 'peer.stop', 'resume_initialization', 'replacement_receipts', 'settled_worker_artifacts'):
            self.assertNotIn(text, code)

    def takeover_fixture(self, profile):
        before = self.replacement_fixture()[0]
        initial = copy.deepcopy(before['currentService']['grant'])
        before['current'] = {'original': {'signed': {'grant': initial}}, 'directResult': {'grant': initial}}
        before['contexts'] = [{'context': copy.deepcopy(before['currentContext']), 'controller': copy.deepcopy(before['current'])}]
        before['references'] = [{'original': copy.deepcopy(before['currentContext'])}]
        grant = dict(initial, operation='takeover', id=str(R.uuid.uuid4()), serial=2, expected_epoch=1, new_key='f'*64)
        observation = dict(grant=grant, serviceEpoch=before['currentService']['boot']['service_epoch'],
                           workerUUID=before['observedWorker']['workerUUID'], openRevision=1)
        frozen = copy.deepcopy(before)
        frozen.update(revision=2, pending={'signed': {'grant': copy.deepcopy(grant)}, 'serviceEpoch': observation['serviceEpoch']})
        after = copy.deepcopy(before)
        successor = dict(grant, id=str(R.uuid.uuid4()), serial=3,
                         expected_epoch=1 + (profile == R.TAKEOVER_FAULTS[1]), new_key='0'*64)
        after['revision'] = 5
        after['currentService']['grant'] = successor
        after['currentService']['context'].update(controller_epoch=successor['expected_epoch']+1, controller_key=successor['new_key'])
        after['currentContext'].update(controllerEpoch=successor['expected_epoch']+1, controllerKey=successor['new_key'])
        after['observedWorker']['context'] = copy.deepcopy(after['currentContext'])
        after['current'] = {'original': {'signed': {'grant': successor}}, 'directResult': {'grant': successor}}
        return before, frozen, after, observation, profile

    def test_takeover_selection_is_exact_and_absence_only_skips(self):
        for profile in R.TAKEOVER_FAULTS:
            self.assertFalse(R.selected({}, fault=profile))
            self.assertTrue(R.selected({R.FAULT_ENV: profile}, fault=profile))
            for other in ('unknown', profile+' ', R.FAULT, *[p for p in R.TAKEOVER_FAULTS if p != profile]):
                with self.subTest(profile=profile, other=other), self.assertRaises(ValueError):
                    R.selected({R.FAULT_ENV: other}, fault=profile)

    def test_takeover_receipt_shape_rejects_malformed_or_secret_fields(self):
        good = self.takeover_fixture(R.TAKEOVER_FAULTS[0])[3]
        R.takeover_observation_shape(good)
        for key, value in [('openRevision', True), ('openRevision', 0), ('serviceEpoch', 'bad'),
                           ('workerUUID', 'bad'), ('signature', 'secret')]:
            malformed = copy.deepcopy(good); malformed[key] = value
            with self.subTest(key=key), self.assertRaises((AssertionError, ValueError)):
                R.takeover_observation_shape(malformed)
        for key, value in [('serial', True), ('expected_epoch', 2**64-1), ('new_key', 'secret'),
                           ('operation', 'initialize'), ('identity', {})]:
            malformed = copy.deepcopy(good); malformed['grant'][key] = value
            with self.subTest(key=key), self.assertRaises((AssertionError, ValueError)):
                R.takeover_observation_shape(malformed)

    def test_takeover_log_is_bounded_canonical_exact_cut_and_repeat(self):
        profile = R.TAKEOVER_FAULTS[0]
        value = self.takeover_fixture(profile)[3]
        marker = ('cengine.compat.lifecycle.'+profile+'.paused ').encode()
        payload = R.json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        line = marker+payload+b'\n'
        with tempfile.TemporaryDirectory() as temporary:
            daemon = SimpleNamespace(log_path=Path(temporary)/'daemon.log')
            daemon.log_path.write_bytes(line)
            self.assertEqual(R.takeover_pause_observation(daemon, profile), (value, line))
            self.assertIsNone(R.takeover_pause_observation(daemon, profile, 1))
            daemon.log_path.write_bytes(line+line)
            self.assertEqual(R.takeover_pause_observation(daemon, profile, 1), (value, line))
            for bad in (line+line, b'prefix '+line, marker+payload.replace(b'{', b'{"openRevision":1,', 1)+b'\n',
                        marker+R.json.dumps(value).encode()+b'\n', b'x'*1048577):
                daemon.log_path.write_bytes(bad)
                with self.subTest(bad=bad[:40]), self.assertRaises((AssertionError, ValueError)):
                    R.takeover_pause_observation(daemon, profile)
            daemon.log_path.write_bytes(line[:-1])
            self.assertIsNone(R.takeover_pause_observation(daemon, profile))
            daemon.log_path.write_bytes(line)
            with self.assertRaises(AssertionError): R.takeover_pause_observation(daemon, R.TAKEOVER_FAULTS[1])

    def test_takeover_receipts_prove_both_outcomes_and_serial_highwater(self):
        for profile in R.TAKEOVER_FAULTS:
            values = self.takeover_fixture(profile)
            R.recovered_takeover_proof(*values)
            mutations = [lambda v: v[2]['currentService']['grant'].update(serial=2),
                         lambda v: v[2]['currentService']['grant'].update(expected_epoch=9),
                         lambda v: v[2]['currentService']['boot'].update(tls_root_sha256='9'*64),
                         lambda v: v[2]['currentService'].update(open_revision=2),
                         lambda v: v[2].update(contexts=[]),
                         lambda v: v[1]['pending']['signed']['grant'].update(id=str(R.uuid.uuid4())),
                         lambda v: v[3].update(workerUUID=str(R.uuid.uuid4())),
                         lambda v: v[2].update(handoffRetry={})]
            for mutate in mutations:
                altered = copy.deepcopy(values)
                mutate(altered)
                with self.assertRaises((AssertionError, ValueError)):
                    R.recovered_takeover_proof(*altered)

    def test_takeover_entry_has_two_cuts_only_owned_kill_and_public_evidence(self):
        tree = ast.parse(SOURCE.read_text())
        node = next(n for n in tree.body if getattr(n, 'name', '') == 'test_lifecycle_v2_interrupted_live_takeover_recovers')
        code = ast.unparse(node)
        for text in ('range(2)', 'qualify_lifecycle_fault=qualify', 'paused.stop(kill=True)', 'daemon.start()',
                     'frozen_takeover_proof', 'recovered_takeover_proof', 'native_snapshot', 'progressed',
                     'RestartCount', 'disk_identity', 'replacement.disk_budget', 'produced_while_absent', 'spool_progress'):
            self.assertIn(text, code)
        self.assertLess(code.index('frozen_takeover_proof'), code.index('paused.stop(kill=True)'))
        self.assertNotIn('os.kill', code)
        self.assertNotIn('peer.kill', code)

    def test_original_fd_script_cannot_reopen_its_unlinked_path(self):
        script = R.progress_command("left", "right")[-1]
        self.assertEqual(script.count("exec 3>"), 1)
        self.assertLess(script.index("exec 3>"), script.index("rm /data/left.open"))
        self.assertLess(script.index("rm /data/left.open"), script.index("while test"))
        self.assertIn('"$i" >&3', script)
        self.assertIn("cat /data/right.progress", script)

    def test_ready_graceful_stop_has_no_escalation_or_post_ready_delay(self):
        tree = ast.parse(SOURCE.read_text())
        node = next(n for n in tree.body if getattr(n, 'name', '') == 'test_lifecycle_v2_ready_graceful_restarts')
        loop = next(n for n in node.body if isinstance(n, ast.For) and ast.unparse(n.iter) == 'range(3)')
        self.assertEqual(ast.unparse(loop.body[0]), 'daemon.start()')
        self.assertEqual(ast.unparse(loop.body[1]), 'daemon.process.terminate()')
        self.assertEqual(ast.unparse(loop.body[2]), 'assert daemon.process.wait(timeout=15) == 0')
        code = ast.unparse(node)
        self.assertNotIn('.kill(', code)
        self.assertNotIn('kill=True', code)
        self.assertNotIn('sleep(', code)
        for proof in ('native_snapshot', 'RestartCount', 'mount_proof', 'exchange'):
            self.assertIn(proof, code)

    def test_retained_history_revalidates_authenticated_storage_control_without_rewrites(self):
        tree = ast.parse(SOURCE.read_text())
        functions = {node.name: ast.unparse(node) for node in tree.body if isinstance(node, ast.FunctionDef)}
        wrapper = functions['test_lifecycle_v2_retained_history_allows_live_storage_control']
        self.assertIn("pytest.mark.compat('RTM-133')", wrapper)
        self.assertIn('cycles=2, live_reattachment=True, history_revalidation=True', wrapper)
        probe = functions['revalidate_storage_history']
        self.assertIn('client.networks.create(', probe)
        self.assertIn('network.remove()', probe)
        self.assertEqual(probe.count('native_snapshot(daemon, ids) == expected'), 2)
        self.assertEqual(probe.count('storage_launch_history(daemon.root) == history'), 2)
        for forbidden in ('write_bytes', 'write_text', 'signal_storage', 'SIGKILL', 'kill('):
            self.assertNotIn(forbidden, probe)
        cold = functions['strict_cold_restarts']
        self.assertIn('retained.get(path) == data', cold)
        self.assertIn('set(retained) - set(history)', cold)
        self.assertEqual(cold.count('revalidate_storage_history('), 2)

    def test_strict_cold_restarts_keep_live_always_peers_without_forced_fallback(self):
        tree = ast.parse(SOURCE.read_text())
        node = next(n for n in tree.body if getattr(n, 'name', '') ==
                    'strict_cold_restarts')
        wrappers = {n.name: ast.unparse(n) for n in tree.body if isinstance(n, ast.FunctionDef)}
        self.assertIn('cycles=2', wrappers['test_lifecycle_v2_two_strict_cold_restarts_with_live_peers'])
        self.assertIn('cycles=1, live_reattachment=True', wrappers['test_lifecycle_v2_cold_enrollment_survives_live_reattachment'])
        code = ast.unparse(node)
        calls = [n for n in ast.walk(node) if isinstance(n, ast.Call)]
        names = [ast.unparse(n.func) for n in calls]
        self.assertIn('_strict_shutdown', names)
        self.assertEqual(names.count('peer.start'), 1)  # First start only; cold starts are automatic.
        self.assertIn("peer.update(restart_policy={'Name': 'always'})", code)
        self.assertLess(code.index('peer.update('), code.index('peer.start()'))
        loop = next(n for n in ast.walk(node) if isinstance(n, ast.For) and ast.unparse(n.iter) == 'range(cycles)')
        body = [ast.unparse(n) for n in loop.body]
        stop = body.index('daemon.stop()')
        self.assertEqual(body[stop - 1], 'assert daemon.process.wait(timeout=15) == 0')
        self.assertEqual(body[stop - 2], 'daemon.process.terminate()')
        self.assertLess(code.index('_strict_shutdown(daemon)'), code.index('daemon.start()'))
        for forbidden in ('kill', 'signal_storage', 'stop', 'remove', 'restart', 'reset',
                          'terminate_compatibility_runtime', 'qualify_lifecycle_fault', 'publish_resource_update_failure'):
            self.assertFalse(any(name.split('.')[-1] == forbidden for name in names
                                 if name != 'daemon.stop'), forbidden)
        for forbidden in ('os.environ', 'FAULT', 'hook', 'write_bytes', 'write_text', 'unlink', 'rmtree', 'images.', 'pull('):
            self.assertNotIn(forbidden, code)
        for proof in ('native_snapshot(daemon, ids)', 'replacement.exact_exit', 'controllerEpoch',
                      'serviceEpoch', 'workerUUID', 'rootPublicKey', 'manifest', 'disk_identity',
                      'State', 'seed-', 'mount_proof', 'exchange', 'timeout=120'):
            self.assertIn(proof, code)
        self.assertFalse(any(ast.unparse(n.func) == 'peer.start' for n in ast.walk(loop) if isinstance(n, ast.Call)))
        live = next(n for n in ast.walk(node) if isinstance(n, ast.If) and ast.unparse(n.test) == 'live_reattachment')
        live_code = ast.unparse(live)
        for proof in ('native_snapshot(daemon, ids) == native', 'RestartCount', 'controllerEpoch',
                      "new['workerUUID'] == old['workerUUID']", 'seed-', 'mount_proof', 'exchange'):
            self.assertIn(proof, live_code)
        self.assertNotIn('peer.start()', live_code)
        strict_tree = ast.parse((SOURCE.parent / 'test_upgrade_recovery.py').read_text())
        strict = next(n for n in strict_tree.body if getattr(n, 'name', '') == '_strict_shutdown')
        strict_code = ast.unparse(strict)
        self.assertIn("'system', 'shutdown', '--for-upgrade'", strict_code)
        self.assertNotIn('terminate_compatibility_runtime', strict_code)
        self.assertNotIn('.stop(', strict_code)

    def cold_fixture(self):
        import base64
        uid = lambda: str(R.uuid.uuid4())
        before = self.replacement_fixture()[0]
        before['latestCold'] = None
        before['current'] = {'original': {'signed': {'grant': before['currentService']['grant']}}}
        root = before['rootPublicKey']
        signature = base64.b64encode(b's' * 64).decode()

        def edge(service, serial, bridge=None):
            operation = uid()
            grant = dict(operation='takeover', id=operation, identity=before['identity'], serial=serial,
                         expected_epoch=service['context']['controller_epoch'], new_key=str(serial) * 64)
            launch = dict(shim_launch_uuid=uid(), spec_sha256='a'*64, initramfs_sha256='b'*64,
                          ext4_uuid=uid(), bytes=1024)
            origin = dict(shimLaunchUUID=launch['shim_launch_uuid'], specSHA256=launch['spec_sha256'],
                          rootPublicKey=root, binding={'same': 'disk'})
            predecessor = R.cold_predecessor(service)
            signed = dict(signature=signature, request=dict(operation_id=operation, predecessor=predecessor,
                          takeover=dict(grant=grant, signature=signature), launch=launch))
            prepare = dict(operationID=operation, expectedPredecessor=predecessor, identity=before['identity'],
                           expectedAllocatedEpoch=serial, mountedGreeting={'launch': launch})
            request = dict(prepare=prepare, recipient={'childPID': 123}, prepareRequestID=uid(), completionRequestID=uid())
            prepared = dict(signedOpen=signed, successorOrigin=origin, baseEpoch=serial+1)
            if bridge is not None:
                prepared['recoveryBridge'] = bridge
            successor = copy.deepcopy(service)
            successor['grant'] = grant
            successor['context'] = dict(controller_epoch=grant['expected_epoch']+1,
                                        controller_key=grant['new_key'], service_epoch=uid())
            successor['boot'].update(service_epoch=successor['context']['service_epoch'],
                                     tls_root_sha256=str(serial)*64, server_spki=str(serial+1)*64)
            successor['open_revision'] = serial
            receipt = dict(grant=grant, service_epoch=successor['context']['service_epoch'], revision=serial)
            return request, prepared, successor, receipt

        request, prepared, intermediate, receipt = edge(before['currentService'], 2)
        pending = dict(request=request, prepared=prepared, bootAttempted=True)
        frozen = copy.deepcopy(before)
        frozen.update(revision=2, pendingCold=copy.deepcopy(pending))
        resolution = dict(resolutionID=uid(), identity=before['identity'], operationID=request['prepare']['operationID'],
                          signedOpenSHA256=R.cold_signed_digest(prepared['signedOpen']))
        bridge = dict(request=resolution, anchor=before['currentService'], receipt=receipt, successor=intermediate,
                      successorOrigin=prepared['successorOrigin'], baseEpoch=prepared['baseEpoch'])
        attempted = copy.deepcopy(pending)
        attempted['resolutionRequest'] = dict(value=resolution, requestID=uid())
        dead = dict(attempted=attempted, value=bridge, anchorService=before['currentService'],
                    anchor=dict(controller=before['current'], context=before['currentContext']))
        request2, prepared2, successor, receipt2 = edge(intermediate, 3, bridge)
        completion = dict(operationID=request2['prepare']['operationID'], signedOpenSHA256=R.cold_signed_digest(prepared2['signedOpen']),
                          successorOrigin=prepared2['successorOrigin'], baseEpoch=prepared2['baseEpoch'],
                          recoveryBridge=bridge, receipt=receipt2, successor=successor)
        def controller(req, prep, received):
            return dict(original=dict(signed=prep['signedOpen']['request']['takeover'], recipient=req['recipient'],
                                      requestID=req['completionRequestID'], serviceEpoch=received['service_epoch']), directResult=received)
        cold = dict(request=request2, prepared=prepared2, completion=completion, deadPredecessor=dead,
                    predecessorService=intermediate, predecessor={'controller': controller(request, prepared, receipt)})
        after = copy.deepcopy(before)
        context = successor['context']
        after.update(revision=3, currentService=successor, latestCold=cold,
                     current=controller(request2, prepared2, receipt2), currentContext=dict(serviceEpoch=context['service_epoch'],
                     controllerEpoch=context['controller_epoch'], controllerKey=context['controller_key']))
        after['observedWorker'] = dict(context=copy.deepcopy(after['currentContext']), workerUUID=uid())
        return copy.deepcopy((before, frozen, after))

    def committed_cold_fixture(self):
        before, attempted, after = self.cold_fixture()
        cold = after['latestCold']
        bridge = cold['deadPredecessor']['value']
        pending = attempted['pendingCold']
        completion = dict(operationID=pending['request']['prepare']['operationID'],
            signedOpenSHA256=R.cold_signed_digest(pending['prepared']['signedOpen']),
            successorOrigin=bridge['successorOrigin'], baseEpoch=bridge['baseEpoch'],
            receipt=bridge['receipt'], successor=bridge['successor'])
        context = bridge['successor']['context']
        frozen = copy.deepcopy(before)
        frozen.update(revision=2, pendingCold=None, observedWorker=None,
            current=cold['predecessor']['controller'], currentService=bridge['successor'],
            currentContext=dict(serviceEpoch=context['service_epoch'], controllerEpoch=context['controller_epoch'],
                                controllerKey=context['controller_key']),
            latestCold=dict(request=pending['request'], prepared=pending['prepared'], completion=completion,
                predecessor=dict(controller=before['current'], context=before['currentContext']),
                predecessorService=before['currentService']))
        cold.pop('deadPredecessor')
        cold['prepared'].pop('recoveryBridge')
        cold['completion'].pop('recoveryBridge')
        cold['predecessor'] = dict(controller=frozen['current'], context=frozen['currentContext'])
        return R.json.loads(R.json.dumps((before, frozen, after)))

    def test_committed_unenrolled_cold_exact_edges_without_l2_bridge(self):
        before, frozen, after = self.committed_cold_fixture()
        marker = R.FIRST_COLD_COMPLETION_REACHED
        self.assertEqual(R.frozen_committed_cold_proof(before, frozen, marker), frozen['latestCold'])
        R.recovered_committed_cold_proof(before, frozen, after, marker)
        # Swift's optional worker observation is omitted when absent, not JSON null.
        omitted = copy.deepcopy(frozen)
        omitted.pop('observedWorker')
        self.assertEqual(R.frozen_committed_cold_proof(before, omitted, marker), frozen['latestCold'])
        R.recovered_committed_cold_proof(before, omitted, after, marker)
        with self.assertRaises(AssertionError):
            R.lifecycle_owner(frozen)  # The ordinary enrolled-owner contract stays strict.
        for diagnostic in ('', marker + ' ', 'prefix ' + marker, marker + '\n' + marker,
                           'cengine.compat.lifecycle.after-cold-l2-before-a1-v1.injected'):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(AssertionError):
                R.frozen_committed_cold_proof(before, frozen, diagnostic)
        bad_fields = [
            ('currentContext.controllerEpoch', 4), ('current.directResult', {}),
            ('current.original.requestID', str(R.uuid.uuid4())), ('rootPublicKey', 'reset'),
            ('identity', {}), ('pendingCold', {}), ('resolvedDeadCold', {}),
            ('latestCold.predecessorService', {}), ('latestCold.predecessor.controller', {}),
            ('latestCold.predecessor.context', {}), ('latestCold.prepared.recoveryBridge', {}),
            ('latestCold.completion.recoveryBridge', {}), ('latestCold.deadPredecessor', {}),
            ('latestCold.completion.signedOpenSHA256', '0'*64), ('latestCold.completion.receipt.revision', 99),
            ('latestCold.completion.receipt.grant.expected_epoch', 99),
            ('latestCold.prepared.signedOpen.signature', 'bad'),
            ('latestCold.prepared.signedOpen.request.takeover.signature', 'bad'),
            ('latestCold.request.recipient', {}), ('latestCold.completion.baseEpoch', 99),
            ('latestCold.completion.successorOrigin.shimLaunchUUID', str(R.uuid.uuid4())),
        ]
        for phase in ('frozen', 'after'):
            for path, value in bad_fields:
                values = self.committed_cold_fixture()
                row = values[1 if phase == 'frozen' else 2]
                fields = path.split('.')
                for field in fields[:-1]: row = row[field]
                row[fields[-1]] = value
                with self.subTest(phase=phase, path=path), self.assertRaises((AssertionError, KeyError, TypeError, R.replacement.ProofFailure)):
                    R.recovered_committed_cold_proof(*values, marker)
        frozen['observedWorker'] = before['observedWorker']
        with self.assertRaises(AssertionError): R.frozen_committed_cold_proof(before, frozen, marker)
        before, frozen, after = self.committed_cold_fixture()
        after['observedWorker'] = None
        with self.assertRaises(AssertionError): R.recovered_committed_cold_proof(before, frozen, after, marker)

    def test_committed_cold_refuses_unknown_or_missing_owned_births(self):
        api = SimpleNamespace(pid=11, identity=(100, 1, 101), pidversion=1)
        child = SimpleNamespace(pid=12, identity=(100, 2, 102), pidversion=2)
        storage = SimpleNamespace(pid=13, identity=(100, 3, 103), pidversion=3)
        unknown = SimpleNamespace(pid=14, identity=(100, 4, 104), pidversion=4)
        cold = {'request': {'recipient': dict(daemonUniqueID=101, childPID=12, childUniqueID=102)}}
        R.committed_cold_births(11, cold, [api, child, storage], storage)
        for births in ([api, child], [api, storage], [api, child, unknown], [api, child, storage, unknown]):
            with self.subTest(births=births), self.assertRaises(AssertionError):
                R.committed_cold_births(11, cold, births, storage)

    def test_committed_cold_selection_and_native_no_authority_rewrite(self):
        profile = R.FIRST_COLD_COMPLETION_FAULT
        self.assertFalse(R.selected({}, fault=profile))
        self.assertTrue(R.selected({R.FAULT_ENV: profile}, fault=profile))
        for selected in (R.COLD_L2_FAULT, R.FAULT, R.REPLACEMENT_FAULT, *R.TAKEOVER_FAULTS, profile + ' '):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                R.selected({R.FAULT_ENV: selected}, fault=profile)
        with self.assertRaises(ValueError): R.selected({R.FAULT_ENV: profile})
        tree = ast.parse(SOURCE.read_text())
        fixture = next(n for n in tree.body if getattr(n, 'name', '') == 'image_cache')
        self.assertIn("('RTM-132',): FIRST_COLD_COMPLETION_FAULT", ast.unparse(fixture))
        node = next(n for n in tree.body if getattr(n, 'name', '') == 'test_lifecycle_v2_committed_unenrolled_cold_recovery')
        code = ast.unparse(node)
        names = [ast.unparse(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)]
        self.assertEqual(names.count('peer.start'), 1)
        self.assertEqual(names.count('daemon.start'), 2)
        self.assertIn('daemon.start(on_spawn=observe, qualify_lifecycle_fault=qualify)', code)
        self.assertLess(code.index('_strict_shutdown(daemon)'), code.index('daemon.start('))
        for proof in ('observe_cold_births', 'frozen_committed_cold_proof', 'recovered_committed_cold_proof',
                      'committed_cold_births', 'storage_target', 'replacement.exact_exit', 'replacement.signal_storage',
                      'before_signal', 'native_result', 'root_identity', 'manifest', 'disk_identity', 'seed-',
                      'exchange', 'mount_proof', 'log_offset', '65537', 'volume_id', 'mounts[peer.id]'):
            self.assertIn(proof, code)
        for forbidden in ('kill=True', 'terminate_compatibility_runtime', 'peer.stop(', 'peer.remove(',
                          'write_text', 'write_bytes', 'os.environ', 'unlink', 'rmtree', 'pull(', 'images.'):
            self.assertNotIn(forbidden, code)
        for assignment in (n for n in ast.walk(node) if isinstance(n, ast.Assign)):
            for target in assignment.targets:
                self.assertNotIn(ast.unparse(target), ('daemon.binary', 'daemon.owner_binary'))
        conftest = ast.parse((SOURCE.parent / 'conftest.py').read_text())
        daemon = next(n for n in conftest.body if isinstance(n, ast.ClassDef) and n.name == 'Daemon')
        start = next(n for n in daemon.body if getattr(n, 'name', '') == 'start')
        cold = next(n for n in ast.walk(start) if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'cold_fault' for t in n.targets)
                    and isinstance(n.value, ast.Compare))
        self.assertEqual(ast.literal_eval(cold.value.comparators[0]), (R.COLD_L2_FAULT, profile))
        for guard in ('self.binary.resolve() == self.owner_binary', 'compatibility_root_owned_by',
                      'compatibility_root_retained', 'returncode <= 0', 'retained_identity'):
            self.assertIn(guard, ast.unparse(start))

    def test_cold_signed_digest_matches_native_domain_and_canonical_bytes(self):
        source = (ROOT / 'Sources/CEngineCore/StorageLifecycleColdRootProtocol.swift').read_text()
        self.assertIn('hash(signedOpen, domain: "signed-open")', source)
        self.assertIn('cengine.storage-lifecycle-cold-root.\\(domain).v1\\0', source)
        wire = (ROOT / 'Sources/CEngineCore/StorageLifecycleProtocol.swift').read_text()
        self.assertIn('.sortedKeys', wire)
        self.assertIn('.withoutEscapingSlashes', wire)
        signed = {'signature': 'a/b=', 'request': {'z': 2, 'a': 1}}
        expected = R.hashlib.sha256(b'cengine.storage-lifecycle-cold-root.signed-open.v1\0' +
            b'{"request":{"a":1,"z":2},"signature":"a/b="}').hexdigest()
        self.assertEqual(R.cold_signed_digest(signed), expected)

    def test_cold_selection_requires_exact_helper_profile(self):
        self.assertFalse(R.selected({}, fault=R.COLD_L2_FAULT))
        self.assertTrue(R.selected({R.FAULT_ENV: R.COLD_L2_FAULT}, fault=R.COLD_L2_FAULT))
        for profile in (R.FAULT, R.REPLACEMENT_FAULT, *R.TAKEOVER_FAULTS, 'unknown'):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                R.selected({R.FAULT_ENV: profile}, fault=R.COLD_L2_FAULT)
        with self.assertRaises(ValueError): R.selected({R.FAULT_ENV: R.COLD_L2_FAULT})
        tree = ast.parse(SOURCE.read_text())
        fixture = next(n for n in tree.body if getattr(n, 'name', '') == 'image_cache')
        for case in ('RTM-129', 'RTM-130'):
            self.assertIn(f"('{case}',): COLD_L2_FAULT", ast.unparse(fixture))

    def test_cold_bridge_correlates_exact_frozen_attempt_and_two_edges(self):
        R.recovered_cold_proof(*self.cold_fixture())
        before, frozen, after = self.cold_fixture()
        self.assertEqual(R.frozen_cold_proof(before, frozen), frozen['pendingCold'])
        # HOST attempted alone can never pass the recovered-phase gate.
        with self.assertRaises((AssertionError, KeyError, TypeError)):
            R.recovered_cold_proof(before, frozen, frozen)
        paths = [
            ('pendingCold', {}), ('resolvedDeadCold', {}), ('identity', {}), ('rootPublicKey', 'reset'),
            ('latestCold.deadPredecessor.attempted.bootAttempted', False),
            ('latestCold.deadPredecessor.attempted.request.prepareRequestID', str(R.uuid.uuid4())),
            ('latestCold.deadPredecessor.attempted.request.completionRequestID', str(R.uuid.uuid4())),
            ('latestCold.deadPredecessor.attempted.prepared.signedOpen.signature', 'changed'),
            ('latestCold.deadPredecessor.attempted.prepared.signedOpen.request.takeover.signature', 'changed'),
            ('latestCold.deadPredecessor.attempted.prepared.signedOpen.request.launch.spec_sha256', 'f'*64),
            ('latestCold.deadPredecessor.attempted.prepared.successorOrigin.shimLaunchUUID', str(R.uuid.uuid4())),
            ('latestCold.deadPredecessor.value.request.signedOpenSHA256', '0'*64),
            ('latestCold.deadPredecessor.value.receipt.revision', 99),
            ('latestCold.deadPredecessor.anchor.controller', {}),
            ('latestCold.prepared.recoveryBridge', None), ('latestCold.completion.recoveryBridge', None),
            ('latestCold.completion.signedOpenSHA256', '0'*64), ('latestCold.completion.baseEpoch', 99),
            ('latestCold.predecessor.controller.original.signed', {}),
            ('latestCold.predecessorService', before['currentService']),
            ('currentContext.controllerEpoch', 2), ('current.directResult', {}),
            ('observedWorker.workerUUID', before['observedWorker']['workerUUID']),
        ]
        for path, value in paths:
            # JSON roundtrip deliberately removes fixture aliasing, as real reads do.
            altered = R.json.loads(R.json.dumps(after))
            row = altered
            fields = path.split('.')
            for field in fields[:-1]: row = row[field]
            row[fields[-1]] = value
            with self.subTest(path=path), self.assertRaises((AssertionError, KeyError, TypeError)):
                R.recovered_cold_proof(before, frozen, altered)

    def test_cold_frozen_attempt_refuses_authorized_only_or_changed_c1(self):
        before, frozen, _ = self.cold_fixture()
        for field, value in (('current', {}), ('currentContext', {}), ('currentService', {}), ('rootPublicKey', 'reset')):
            altered = copy.deepcopy(frozen); altered[field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError): R.frozen_cold_proof(before, altered)
        for field, value in (('bootAttempted', False), ('resolutionRequest', {}), ('prepared', None)):
            altered = copy.deepcopy(frozen); altered['pendingCold'][field] = value
            with self.subTest(field=field), self.assertRaises((AssertionError, AttributeError)):
                R.frozen_cold_proof(before, altered)

    def test_cold_passive_observer_requires_actual_new_births(self):
        api = SimpleNamespace(pid=11, identity=(100, 1, 101), pidversion=1, arguments=('engine', 'daemon'))
        storage = SimpleNamespace(pid=12, identity=(100, 2, 102), pidversion=2, arguments=('engine', 'vm-shim'))
        daemon = SimpleNamespace(owner_binary=Path('/engine'), root=Path('/root'),
                                 process=SimpleNamespace(pid=11, poll=Mock(side_effect=[None, 71])))
        with patch.object(R, 'compatibility_runtime_processes', side_effect=[[api, storage], []], create=True), \
                patch.object(R.replacement, 'read_public', return_value=({}, 'stamp')), \
                patch.object(R.time, 'sleep'):
            self.assertEqual(R.observe_cold_births(daemon, []), [api, storage])
        for rows, old in (([api], []), ([storage], []), ([api, storage], [storage])):
            daemon.process.poll = Mock(return_value=71)
            with patch.object(R, 'compatibility_runtime_processes', return_value=rows, create=True), \
                    patch.object(R.replacement, 'read_public', return_value=({}, 'stamp')), self.assertRaises(AssertionError):
                R.observe_cold_births(daemon, old)

    def test_cold_controller_is_observed_outside_scoped_engine_census(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'cengine'
            executable = binary.with_name('cengine-storage-controller')
            binary.touch(); executable.touch()
            daemon = SimpleNamespace(binary=binary, owner_binary=binary, root=Path(temporary),
                                     process=SimpleNamespace(pid=11, poll=Mock(return_value=71)))
            api = SimpleNamespace(pid=11, identity=(100, 1, 101), pidversion=1, arguments=(str(binary), 'daemon'))
            storage = SimpleNamespace(pid=13, identity=(100, 3, 103), pidversion=3, arguments=(str(binary), 'vm-shim'))
            child = SimpleNamespace(pid=12, identity=(100, 2, 102), pidversion=2, parent_pid=11,
                                    executable=str(executable), arguments=(str(executable), '--lifecycle-v2'))
            pending = {'request': {'recipient': dict(daemonUniqueID=101, childPID=12, childUniqueID=102)}}
            record = {'pendingCold': pending}
            with patch.object(R, '_kernel_process', side_effect=lambda pid: {11: api, 12: child}[pid], create=True), \
                    patch.object(R, 'compatibility_runtime_processes', return_value=[api, storage], create=True), \
                    patch.object(R.replacement, 'read_public', return_value=(record, 'stamp')):
                births = R.observe_cold_births(daemon, [])
                self.assertEqual(births, [api, storage, child])
                self.assertEqual(R.cold_attempt_births(11, pending, births), (api, child))
                for field, value in (('identity', (100, 2, 999)), ('executable', str(binary)),
                                     ('arguments', (str(executable), '--wrong')), ('parent_pid', 999), ('pidversion', None)):
                    bad = copy.copy(child); setattr(bad, field, value)
                    with self.subTest(field=field), patch.object(R, '_kernel_process', side_effect=lambda pid: bad if pid == 12 else api), \
                            self.assertRaises((AssertionError, RuntimeError, R.replacement.ProofFailure)):
                        R.observe_cold_controller(daemon, record)
                with patch.object(R, '_kernel_process', side_effect=[child, api, None]):
                    self.assertIsNone(R.observe_cold_controller(daemon, record))
                changed = copy.copy(child); changed.pidversion += 1
                with patch.object(R, '_kernel_process', side_effect=[child, api, changed]), self.assertRaises(AssertionError):
                    R.observe_cold_controller(daemon, record)
                with patch.object(R, '_kernel_process', return_value=None):
                    self.assertIsNone(R.observe_cold_controller(daemon, record))

    def test_cold_attempt_recipient_requires_native_birth_not_pid(self):
        api = SimpleNamespace(pid=11, identity=(100, 1, 101), pidversion=1)
        child = SimpleNamespace(pid=12, identity=(100, 2, 102), pidversion=2)
        pending = {'request': {'recipient': dict(daemonUniqueID=101, childPID=12, childUniqueID=102)}}
        self.assertEqual(R.cold_attempt_births(11, pending, [api, child]), (api, child))
        for field, value in (('daemonUniqueID', 999), ('childUniqueID', 999), ('childPID', 99)):
            altered = copy.deepcopy(pending); altered['request']['recipient'][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                R.cold_attempt_births(11, altered, [api, child])
        with self.assertRaises(AssertionError): R.cold_attempt_births(11, pending, [api, child, child])

    def test_cold_native_entry_never_resets_or_manufactures_phase(self):
        tree = ast.parse(SOURCE.read_text())
        node = next(n for n in tree.body if getattr(n, 'name', '') == 'interrupted_cold_l2_recovery')
        code = ast.unparse(node)
        names = [ast.unparse(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)]
        self.assertEqual(names.count('peer.start'), 1)
        self.assertEqual(names.count('daemon.start'), 2)
        self.assertIn('daemon.start(on_spawn=observe, qualify_lifecycle_fault=qualify)', code)
        self.assertLess(code.index('_strict_shutdown(daemon)'), code.index('daemon.start('))
        for proof in ('observe_cold_births', 'frozen_cold_proof', 'recovered_cold_proof', 'storage_target',
                      'replacement.exact_exit', 'replacement.signal_storage', 'before_signal',
                      'native_result', 'root_identity', 'manifest', 'disk_identity', 'seed-', 'exchange', 'mount_proof'):
            self.assertIn(proof, code)
        for forbidden in ('kill=True', 'terminate_compatibility_runtime', 'peer.stop(', 'peer.remove(',
                          'write_text', 'write_bytes', 'os.environ', 'unlink', 'rmtree', 'pull(', 'images.'):
            self.assertNotIn(forbidden, code)

    def test_exact_unique_registered_ids_and_no_runtime_fault_injection(self):
        source = (ROOT / "Tests/Compatibility/test_storage_lifecycle_v2_runtime.py").read_text()
        tree = ast.parse(source)
        ids = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "compat":
                ids.append(ast.literal_eval(node.args[0]))
        self.assertEqual(sorted(ids), ["RTM-117", "RTM-118", "RTM-119", "RTM-120", "RTM-121", "RTM-122", "RTM-123", "RTM-124", "RTM-125", "RTM-127", "RTM-128", "RTM-129", "RTM-130", "RTM-131", "RTM-132", "RTM-133"])
        ledger = (ROOT / "docs/docker-compatibility.md").read_text()
        for case in ids:
            self.assertEqual(ledger.count("| `" + case + "` |"), 1)
        self.assertNotIn("os.environ[", source)
        self.assertNotIn("os.kill(", source)
        self.assertNotIn("terminate_compatibility_runtime(", source)
        self.assertNotIn("shutil.rmtree", source)


if __name__ == "__main__":
    unittest.main()
