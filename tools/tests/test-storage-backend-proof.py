#!/usr/bin/env python3
"""Engine-free durable backend proof and integration-boundary regressions."""
import ast
import base64
import copy
import uuid
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import storage_backend_proof as proof
from lifecycle_backend_fixture import create_backend, canonical
import volume_probe
import test_volume_concurrency as concurrency
import test_disk_initialization as disk_initialization


def mounts(fs="fuse.managed-v3", source="managed-v3", root="/", destination="/data", options="rw"):
    return f"35 20 0:44 {root} {destination} rw,nosuid - {fs} {source} {options}\n"


class BackendProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.environment = patch.dict(os.environ, {}, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop("CENGINE_COMPAT_MANAGED_STORAGE", None)
        os.environ.pop("CENGINE_COMPAT_SHARED_STORAGE", None)
        os.environ.pop("CENGINE_CORPUS_SHARED_FS", None)
        self.path = create_backend(self.root)
        self.record = json.loads(self.path.read_bytes())
        self.state_path = self.path.with_name("state.json")
        self.state = json.loads(self.state_path.read_bytes())

    def save(self):
        self.path.write_bytes(canonical(self.record))

    def test_managed_proof_and_real_directory_identity(self):
        result = proof.verify_backend(self.root, "shared", mounts(), startup_mode="lifecycle")
        self.assertEqual(result["root_identity"], self.record["root"])
        self.assertEqual(result["lifecycle_manifest_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(result["mount"]["source"], "managed-v3")
        self.assertEqual(result["schema"], 1)

    def reject(self, message):
        with self.assertRaisesRegex(proof.BackendProofError, message):
            proof.verify_backend(self.root, "shared", mounts())

    def test_exact_owner_census_missing_files_and_commit_scratch(self):
        for name in ("lease", "state.json", "manifest.json"):
            path = self.path.with_name(name)
            held = self.root / name
            path.rename(held)
            self.reject("owner entries")
            held.rename(path)
        for name in ("commit.json", "candidate", ".scratch", "foreign"):
            path = self.path.with_name(name)
            path.write_bytes(b"")
            self.reject("owner entries")
            path.unlink()
        for path in self.path.parent.iterdir(): path.unlink()
        self.reject("owner entries")

    def test_all_private_modes_and_owner_uid_are_checked(self):
        paths = (self.root, self.path.parent, self.path, self.state_path, self.path.with_name("lease"),
                 self.root / "infrastructure", self.root / "infrastructure/volumes.ext4")
        for path in paths:
            mode = path.stat().st_mode & 0o7777
            for unsafe in (mode | 0o004, mode | 0o020, mode | 0o4000):
                with self.subTest(path=path, mode=oct(unsafe)):
                    path.chmod(unsafe)
                    self.reject("unsafe private")
                    path.chmod(mode)
        with patch.object(proof.os, "geteuid", return_value=os.geteuid() + 1):
            self.reject("unsafe private")

    def test_lease_size_backing_size_and_all_physical_identities(self):
        lease = self.path.with_name("lease")
        lease.write_bytes(b"x")
        self.reject("lease must be empty")
        lease.write_bytes(b"")
        backing = self.root / "infrastructure/volumes.ext4"
        with backing.open("r+b") as stream: stream.truncate(self.record["bytes"] + 1)
        self.reject("backing physical size")
        with backing.open("r+b") as stream: stream.truncate(self.record["bytes"])
        for field in ("root", "directory", "lease", "backing"):
            for part in ("inode", "volumeUUID"):
                bad = copy.deepcopy(self.record)
                bad[field][part] = str(uuid.uuid4()).upper() if part == "volumeUUID" else bad[field][part] + 1
                self.path.write_bytes(canonical(bad))
                with self.subTest(field=field, part=part): self.reject(f"{field} physical identity")
        self.save()
        self.record["identity"]["binding"] = "f" * 64
        self.save()
        self.reject("physical binding digest")

    def test_persistent_device_drift_preserves_stable_binding_but_old_formats_fail(self):
        from managed_prepare_lifecycle_evidence import manifest_binding
        original = manifest_binding(self.record)
        for field in ("root", "directory", "lease", "backing"):
            self.record[field]["device"] += 100
        self.save()
        self.assertEqual(manifest_binding(self.record), original)
        result = proof.verify_backend(self.root, "shared", mounts())
        self.assertEqual(result["lifecycle_manifest_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        for version in ("storage-lifecycle.v2", "storage-host-owner.v2"):
            self.record["version"] = version
            self.save()
            self.reject("durable lifecycle version")
        self.record["version"] = "storage-host-owner.v3"
        self.record["identity"]["binding"] = hashlib.sha256(
            b"cengine.storageauthority.binding.v2\0" + canonical(original)).hexdigest()
        self.save()
        self.reject("physical binding digest")

    def test_state_decode_correlation_and_semantic_shape(self):
        mutations = [(("identity", "generation"), 2), (("rootPublicKey",), "eHh4"),
            (("provenanceReference",), "f" * 64), (("version",), "storage-lifecycle.v1"),
            (("revision",), True), (("intentRevision",), -1), (("currentContext", "controllerEpoch"), 2),
            (("current", "original", "signed", "grant", "identity", "generation"), True),
            (("currentService", "grant", "serial"), 1.0),
            (("currentService", "open_revision"), 99), (("observedWorker", "context", "serviceEpoch"), str(uuid.uuid4())),
            (("current", "original", "recipient", "childPID"), 0), (("nativeReplacementAttempted",), False),
            (("pendingCold",), {}), (("adoptionRetry",), {}), (("serviceLinks",), [{}]), (("references",), [{}])]
        for keys, value in mutations:
            bad = copy.deepcopy(self.state)
            cursor = bad
            for key in keys[:-1]: cursor = cursor[key]
            cursor[keys[-1]] = value
            self.state_path.write_bytes(canonical(bad))
            with self.subTest(keys=keys): self.reject(".")
        for key in ("pendingCold", "latestCold", "contexts", "references"):
            bad = copy.deepcopy(self.state); del bad[key]
            self.state_path.write_bytes(canonical(bad))
            self.reject("object fields")
        for raw in (b"{}", b"null", b"{", canonical(self.state) + b"\n",
                    b'{"version":1,"version":2}', b"x" * (proof.MAXIMUM_BYTES + 1)):
            self.state_path.write_bytes(raw)
            self.reject(".")

    def test_replaced_open_entries_are_rechecked_after_decode(self):
        # Replace at the end of semantic validation, while every original FD is held.
        paths = (self.path, self.state_path, self.path.with_name("lease"),
                 self.root / "infrastructure/volumes.ext4", self.path.parent,
                 self.root / "infrastructure", self.root)
        validate = proof._checkpoint
        for index, path in enumerate(paths):
            held = path.with_name(path.name + "-held")
            def replace(*args):
                validate(*args)
                path.rename(held)
                if held.is_dir(): path.mkdir(mode=0o700)
                else:
                    path.write_bytes(held.read_bytes()); path.chmod(0o600)
            with self.subTest(path=path), patch.object(proof, "_checkpoint", side_effect=replace):
                self.reject("changed/replaced")
            if path.is_dir(): path.rmdir()
            else: path.unlink()
            held.rename(path)

    def test_census_and_file_mutation_during_inspection_are_rejected(self):
        validate = proof._checkpoint
        def change(*args):
            validate(*args)
            self.path.with_name("commit.json").write_bytes(b"candidate")
        with patch.object(proof, "_checkpoint", side_effect=change):
            self.reject("census changed|changed/replaced")
        self.path.with_name("commit.json").unlink()
        def mutate(*args):
            validate(*args)
            self.state_path.write_bytes(canonical({**self.state, "revision": 2}))
        with patch.object(proof, "_checkpoint", side_effect=mutate):
            self.reject("changed/replaced")

    def test_inspection_is_read_only_and_errors_remain_informative(self):
        paths = [self.root, self.path.parent, self.path, self.state_path, self.path.with_name("lease"),
                 self.root / "infrastructure/volumes.ext4"]
        before = [(p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_mode) for p in paths]
        proof.verify_backend(self.root, "shared", mounts())
        self.assertEqual(before, [(p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_mode) for p in paths])
        self.path.with_name("lease").write_bytes(b"x")
        with self.assertRaisesRegex(proof.BackendProofError, "lease must be empty") as error:
            proof.verify_backend(self.root, "shared", mounts())
        self.assertIsNone(error.exception.__cause__)

    def test_current_worker_replacement_and_reattach_shapes_are_accepted(self):
        import base64
        encoded = lambda value: base64.b64encode(value).decode()
        before = copy.deepcopy(self.state)
        old = before["currentContext"]
        fresh = {**old, "serviceEpoch": str(uuid.uuid4())}
        service = self.state["currentService"]
        service["context"]["service_epoch"] = fresh["serviceEpoch"]
        service["boot"].update(service_epoch=fresh["serviceEpoch"], tls_root_sha256="e" * 64, server_spki="f" * 64)
        service["open_revision"] = 2
        self.state["currentContext"] = fresh
        self.state["observedWorker"] = dict(context=fresh, workerUUID=str(uuid.uuid4()))
        request = dict(operation_id=str(uuid.uuid4()), predecessor=before["currentService"])
        retry = dict(request=request, stageRequestID=str(uuid.uuid4()), completionRequestID=str(uuid.uuid4()),
                     predecessorWorkerUUID=before["observedWorker"]["workerUUID"], nowUnixSeconds=100, lifetimeSeconds=300)
        link = dict(operationID=request["operation_id"], predecessor=old, successor=fresh, revision=2)
        self.state.update(latestServiceRequest=retry, latestServiceConfirmation=dict(request=request, successor=service),
                          latestServiceChange=link, serviceLinks=[link])
        self.state["contexts"].append(dict(context=fresh, controller=self.state["current"], serviceResult=link))
        self.state_path.write_bytes(canonical(self.state))
        proof.verify_backend(self.root, "shared", mounts())
        from managed_prepare_lifecycle_evidence import manifest_binding
        physical = manifest_binding(self.record)
        origin = dict(binding=dict(version="storage-host-binding.v2", store=self.record["identity"]["store"], root=physical["root"], backing=physical["backing"]["identity"],
            bytes=self.record["bytes"], ext4_uuid=self.record["ext4UUID"]), rootPublicKey=self.record["rootPublicKey"],
            shimLaunchUUID=str(uuid.uuid4()), specSHA256="d" * 64)
        adoption = dict(version="storage-lifecycle-adoption.v4", id=str(uuid.uuid4()), origin=origin, expectedEpoch=1,
            daemonAudit=encoded(b"a" * 32), daemonUniqueID=11, controllerAudit=encoded(b"b" * 32), controllerUniqueID=22, superseded=None)
        status = dict(origin=origin, shimAudit=encoded(b"c" * 32), shimUniqueID=33, baseEpoch=1, committedEpoch=1, allocatedEpoch=1)
        self.state["adoptionRetry"] = dict(status=status, request=adoption, prepareRequestID=str(uuid.uuid4()), completeRequestID=str(uuid.uuid4()))
        self.state_path.write_bytes(canonical(self.state))
        proof.verify_backend(self.root, "shared", mounts())
        self.state["adoptionRetry"]["request"]["expectedEpoch"] = 2
        self.state_path.write_bytes(canonical(self.state))
        self.reject("adoption retry correlation")

    def cold_pending_state(self):
        from managed_prepare_lifecycle_evidence import manifest_binding
        uid = lambda: str(uuid.uuid4())
        encoded = lambda value: base64.b64encode(value).decode()
        manifest, service = self.record, self.state['currentService']
        physical = manifest_binding(manifest)
        binding = dict(version='storage-host-binding.v2', store=manifest['identity']['store'],
            root=physical['root'], backing=physical['backing']['identity'],
            bytes=manifest['bytes'], ext4_uuid=manifest['ext4UUID'])
        origin = dict(binding=binding, rootPublicKey=manifest['rootPublicKey'], shimLaunchUUID=uid(), specSHA256='d'*64)
        recipient = dict(publicKey=encoded(b'z'*32), incarnation=uid(), daemonUniqueID=30, childUniqueID=40, childPID=200)
        launch = dict(shim_launch_uuid=uid(), spec_sha256='e'*64, initramfs_sha256='f'*64,
            ext4_uuid=manifest['ext4UUID'], bytes=manifest['bytes'])
        greeting = dict(version='storage-lifecycle-cold-shim.v2', channelID=uid(), purpose='cold',
            daemonUniqueID=recipient['daemonUniqueID'], rootPublicKey=manifest['rootPublicKey'], binding=binding,
            bootBinding=dict(shimLaunchUUID=launch['shim_launch_uuid'], guestBootNonce=uid(),
                ext4UUID=manifest['ext4UUID'], bytes=manifest['bytes']), launch=launch,
            heldBackingIdentity=dict(device=manifest['backing']['device'] + 101, **binding['backing']))
        context = service['context']
        prepare = dict(operationID=uid(), identity=manifest['identity'],
            expectedPredecessor=dict(current_grant=service['grant'], service_epoch=context['service_epoch'],
                controller_epoch=context['controller_epoch'], controller_key=context['controller_key'],
                open_revision=service['open_revision'], bootstrap_key=service['boot']['bootstrap_key']),
            expectedOrigin=origin, expectedAllocatedEpoch=1,
            candidate=dict(spki=encoded(bytes.fromhex('302a300506032b6570032100') + b'z'*32),
                pid=recipient['childPID'], incarnation=recipient['incarnation']),
            mountedGreeting=greeting, nowUnixSeconds=100, lifetimeSeconds=60)
        state = copy.deepcopy(self.state)
        state['pendingCold'] = dict(bootAttempted=False, request=dict(prepare=prepare, recipient=recipient,
            prepareRequestID=uid(), completionRequestID=uid()))
        return state

    def completed_cold_state(self, bridged=False):
        """Synthetic public correlations only; signatures do not prove authority."""
        uid = lambda: str(uuid.uuid4())
        encoded = lambda value: base64.b64encode(value).decode()
        digest = lambda prepared: hashlib.sha256(
            b'cengine.storage-lifecycle-cold-root.signed-open.v1\0' + canonical(prepared['signedOpen'])).hexdigest()

        def complete(before, key, bridge=None):
            request = self.cold_pending_state()['pendingCold']['request']
            prepare, recipient = request['prepare'], request['recipient']
            service, old = before['currentService'], before['currentContext']
            recipient['publicKey'] = encoded(key * 32)
            prepare['candidate']['spki'] = encoded(bytes.fromhex('302a300506032b6570032100') + key * 32)
            prepare['expectedPredecessor'] = dict(current_grant=service['grant'], service_epoch=old['serviceEpoch'],
                controller_epoch=old['controllerEpoch'], controller_key=old['controllerKey'],
                open_revision=service['open_revision'], bootstrap_key=service['boot']['bootstrap_key'])
            if bridge is not None:
                prepare['expectedOrigin'] = bridge['successorOrigin']
                prepare['expectedAllocatedEpoch'] = bridge['baseEpoch']
            grant = dict(operation='takeover', id=prepare['operationID'], identity=self.record['identity'],
                serial=service['grant']['serial'] + 1, expected_epoch=old['controllerEpoch'],
                new_key=hashlib.sha256(bytes.fromhex('302a300506032b6570032100') + key * 32).hexdigest())
            signed = dict(grant=grant, signature=encoded(b's' * 64))
            launch = prepare['mountedGreeting']['launch']
            prepared = dict(signedOpen=dict(request=dict(operation_id=prepare['operationID'],
                predecessor=prepare['expectedPredecessor'], takeover=signed, launch=launch,
                now_unix_seconds=prepare['nowUnixSeconds'], lifetime_seconds=prepare['lifetimeSeconds']),
                signature=encoded(b'o' * 64)), baseEpoch=prepare['expectedAllocatedEpoch'] + 1,
                successorOrigin=dict(binding=prepare['expectedOrigin']['binding'], rootPublicKey=self.record['rootPublicKey'],
                    shimLaunchUUID=launch['shim_launch_uuid'], specSHA256=launch['spec_sha256']))
            fresh = dict(serviceEpoch=uid(), controllerEpoch=old['controllerEpoch'] + 1, controllerKey=grant['new_key'])
            receipt = dict(grant=grant, nonce=encoded(b'n' * 32), service_epoch=fresh['serviceEpoch'],
                revision=service['open_revision'] + 1)
            successor = dict(grant=grant, context=dict(service_epoch=fresh['serviceEpoch'],
                controller_epoch=fresh['controllerEpoch'], controller_key=fresh['controllerKey']),
                open_revision=receipt['revision'], boot=dict(identity=self.record['identity'],
                    service_epoch=fresh['serviceEpoch'], bootstrap_key=service['boot']['bootstrap_key'],
                    tls_root_sha256=hashlib.sha256(key + b'tls').hexdigest(), server_spki=hashlib.sha256(key + b'spki').hexdigest()))
            completion = dict(operationID=prepare['operationID'], signedOpenSHA256=digest(prepared),
                successorOrigin=prepared['successorOrigin'], baseEpoch=prepared['baseEpoch'], receipt=receipt, successor=successor)
            if bridge is not None:
                prepared['recoveryBridge'] = bridge
                completion['recoveryBridge'] = bridge
            current = dict(original=dict(signed=signed, recipient=recipient, requestID=request['completionRequestID'],
                serviceEpoch=fresh['serviceEpoch']), directResult=receipt)
            cold = dict(request=request, prepared=prepared, completion=completion,
                predecessor=next(row for row in before['contexts'] if row['context'] == old), predecessorService=service)
            state = copy.deepcopy(before)
            state.update(current=current, currentContext=fresh, currentService=successor, pendingCold=None, latestCold=cold,
                observedWorker=dict(context=fresh, workerUUID=uid()), revision=before['revision'] + 1)
            state['contexts'].append(dict(context=fresh, controller=current))
            return state

        state = complete(self.state, b'z')
        if bridged:
            cold = state['latestCold']
            resolution = dict(resolutionID=uid(), identity=self.record['identity'],
                operationID=cold['request']['prepare']['operationID'], signedOpenSHA256=digest(cold['prepared']))
            value = dict(request=resolution, anchor=cold['predecessorService'], receipt=cold['completion']['receipt'],
                successor=cold['completion']['successor'], successorOrigin=cold['prepared']['successorOrigin'],
                baseEpoch=cold['prepared']['baseEpoch'])
            resolved = dict(attempted=dict(request=cold['request'], prepared=cold['prepared'], bootAttempted=True,
                resolutionRequest=dict(value=resolution, requestID=uid())), value=value,
                anchor=cold['predecessor'], anchorService=cold['predecessorService'])
            state = complete(state, b'y', value)
            state['latestCold']['deadPredecessor'] = resolved
        # Do not let shared fixture dictionaries silently correlate mutations.
        return json.loads(canonical(state))

    def correlate_dead_cold(self, state):
        """Keep redundant history, digests, and bridge copies equal after mutations."""
        cold = state['latestCold']
        dead = cold['deadPredecessor']
        attempted, value = dead['attempted'], dead['value']
        value['anchor'] = copy.deepcopy(dead['anchorService'])
        attempted['request']['prepare']['expectedPredecessor']['open_revision'] = dead['anchorService']['open_revision']
        attempted['prepared']['signedOpen']['request']['predecessor'] = copy.deepcopy(
            attempted['request']['prepare']['expectedPredecessor'])
        attempted['resolutionRequest']['value']['signedOpenSHA256'] = hashlib.sha256(
            b'cengine.storage-lifecycle-cold-root.signed-open.v1\0' + canonical(attempted['prepared']['signedOpen'])).hexdigest()
        value['request'] = copy.deepcopy(attempted['resolutionRequest']['value'])
        value['receipt']['revision'] = value['successor']['open_revision']
        cold['predecessor']['controller']['directResult'] = copy.deepcopy(value['receipt'])
        cold['predecessorService'] = copy.deepcopy(value['successor'])
        state['contexts'][0] = copy.deepcopy(dead['anchor'])
        state['contexts'][1] = copy.deepcopy(cold['predecessor'])
        cold['request']['prepare']['expectedPredecessor']['open_revision'] = value['successor']['open_revision']
        cold['prepared']['signedOpen']['request']['predecessor'] = copy.deepcopy(
            cold['request']['prepare']['expectedPredecessor'])
        cold['completion']['signedOpenSHA256'] = hashlib.sha256(
            b'cengine.storage-lifecycle-cold-root.signed-open.v1\0' + canonical(cold['prepared']['signedOpen'])).hexdigest()
        for location in ('prepared', 'completion'):
            cold[location]['recoveryBridge'] = copy.deepcopy(value)
        cold['completion']['receipt']['revision'] = cold['completion']['successor']['open_revision']
        state['current']['directResult'] = copy.deepcopy(cold['completion']['receipt'])
        state['currentService'] = copy.deepcopy(cold['completion']['successor'])
        state['contexts'][2]['controller'] = copy.deepcopy(state['current'])

    def test_dead_cold_resolution_excludes_anchor_and_final_grants(self):
        for source in ('anchor', 'current'):
            state = self.completed_cold_state(True)
            dead = state['latestCold']['deadPredecessor']
            controller = dead['anchor']['controller'] if source == 'anchor' else state['current']
            dead['attempted']['resolutionRequest']['value']['resolutionID'] = controller['original']['signed']['grant']['id']
            self.correlate_dead_cold(state)
            self.state_path.write_bytes(canonical(state))
            with self.subTest(source=source): self.reject('dead cold resolution correlation mismatch')

    def test_dead_cold_historical_revision_linkage(self):
        # anchor open, controller receipt, folded service result, dead open, final open
        cases = [
            (1, 2, None, 3, 4, None),
            (2, 1, None, 3, 4, 'dead cold predecessor revision mismatch'),
            (1, 2, None, 2, 3, 'dead cold successor did not advance'),
            (2, 1, 2, 3, 4, None),
            (2, 1, 3, 4, 5, 'dead cold folded predecessor revision mismatch'),
            (3, 1, 2, 4, 5, 'dead cold folded predecessor revision mismatch'),
            (2, 1, 3, 3, 4, 'dead cold successor did not advance'),
        ]
        for anchor_open, receipt, folded, dead_open, final_open, error in cases:
            state = self.completed_cold_state(True)
            cold = state['latestCold']; dead = cold['deadPredecessor']
            anchor = dead['anchor']
            anchor['controller']['directResult']['revision'] = receipt
            dead['anchorService']['open_revision'] = anchor_open
            if folded is not None:
                prior = {**anchor['context'], 'serviceEpoch': str(uuid.uuid4())}
                anchor['controller']['original']['serviceEpoch'] = prior['serviceEpoch']
                anchor['controller']['directResult']['service_epoch'] = prior['serviceEpoch']
                anchor['serviceResult'] = dict(operationID=str(uuid.uuid4()), predecessor=prior,
                    successor=copy.deepcopy(anchor['context']), revision=folded)
            dead['value']['successor']['open_revision'] = dead_open
            cold['completion']['successor']['open_revision'] = final_open
            self.correlate_dead_cold(state)
            self.state_path.write_bytes(canonical(state))
            with self.subTest(anchor_open=anchor_open, receipt=receipt, folded=folded, dead_open=dead_open):
                if error is None: proof.verify_backend(self.root, 'shared', mounts())
                else: self.reject(error)

    def test_dead_cold_successor_cannot_reuse_anchor_tls_or_spki(self):
        for field in ('tls_root_sha256', 'server_spki'):
            state = self.completed_cold_state(True)
            dead = state['latestCold']['deadPredecessor']
            dead['value']['successor']['boot'][field] = dead['anchorService']['boot'][field]
            self.correlate_dead_cold(state)
            self.state_path.write_bytes(canonical(state))
            with self.subTest(field=field): self.reject('dead cold successor did not advance')

    def test_completed_ordinary_and_bridged_cold_are_accepted(self):
        for bridged in (False, True):
            with self.subTest(bridged=bridged):
                state = self.completed_cold_state(bridged)
                self.state_path.write_bytes(canonical(state))
                result = proof.verify_backend(self.root, 'shared', mounts())
                self.assertEqual(result['mode'], 'lifecycle')
                self.assertEqual(len(state['contexts']), 3 if bridged else 2)

    def test_completed_cold_exact_fields_missing_history_and_nulls_fail_closed(self):
        for bridged in (False, True):
            state = self.completed_cold_state(bridged)
            paths = [('latestCold',), ('latestCold', 'prepared'), ('latestCold', 'completion')]
            if bridged:
                dead = ('latestCold', 'deadPredecessor')
                paths += [dead, dead + ('attempted',), dead + ('attempted', 'request'),
                    dead + ('attempted', 'prepared'), dead + ('attempted', 'resolutionRequest'),
                    dead + ('attempted', 'resolutionRequest', 'value'), dead + ('value',),
                    dead + ('anchor',), dead + ('anchorService',),
                    ('latestCold', 'prepared', 'recoveryBridge'), ('latestCold', 'completion', 'recoveryBridge')]
            for path in paths:
                node = state
                for key in path: node = node[key]
                for field in list(node) + ['unexpected']:
                    for action in ('null', 'delete') if field in node else ('extra',):
                        bad = copy.deepcopy(state)
                        cursor = bad
                        for key in path: cursor = cursor[key]
                        if action == 'delete': del cursor[field]
                        else: cursor[field] = None if action == 'null' else 'unexpected'
                        self.state_path.write_bytes(canonical(bad))
                        with self.subTest(bridged=bridged, path=path, field=field, action=action): self.reject('.')
            for index in range(len(state['contexts'])):
                bad = copy.deepcopy(state); del bad['contexts'][index]
                self.state_path.write_bytes(canonical(bad))
                with self.subTest(bridged=bridged, missing_context=index): self.reject('.')
        for field in ('deadPredecessor',):
            bad = self.completed_cold_state(); bad['latestCold'][field] = None
            self.state_path.write_bytes(canonical(bad)); self.reject('null optional')
        for location in ('prepared', 'completion'):
            bad = self.completed_cold_state(); bad['latestCold'][location]['recoveryBridge'] = None
            self.state_path.write_bytes(canonical(bad)); self.reject('null optional')

    def test_bridged_cold_rejects_changed_frozen_correlations(self):
        state = self.completed_cold_state(True)
        dead = ('latestCold', 'deadPredecessor')
        mutations = [
            (dead + ('attempted', 'bootAttempted'), False),
            (dead + ('attempted', 'prepared', 'recoveryBridge'), state['latestCold']['deadPredecessor']['value']),
            (dead + ('attempted', 'request', 'prepareRequestID'), 'not-a-uuid'),
            (dead + ('attempted', 'request', 'prepare', 'nowUnixSeconds'), 101),
            (dead + ('attempted', 'request', 'recipient', 'incarnation'), str(uuid.uuid4())),
            (dead + ('attempted', 'prepared', 'signedOpen', 'signature'), base64.b64encode(b'x' * 64).decode()),
            (dead + ('attempted', 'prepared', 'signedOpen', 'request', 'takeover', 'signature'), base64.b64encode(b'x' * 64).decode()),
            (dead + ('attempted', 'resolutionRequest', 'requestID'), state['latestCold']['deadPredecessor']['attempted']['request']['prepareRequestID']),
            (dead + ('attempted', 'resolutionRequest', 'value', 'signedOpenSHA256'), 'a' * 64),
            (dead + ('anchorService', 'open_revision'), 99),
            (dead + ('anchor', 'context', 'serviceEpoch'), str(uuid.uuid4())),
            (dead + ('anchor', 'controller', 'directResult', 'nonce'), base64.b64encode(b'x' * 32).decode()),
            (('latestCold', 'prepared', 'recoveryBridge', 'baseEpoch'), 99),
            (('latestCold', 'completion', 'recoveryBridge', 'baseEpoch'), 99),
            (('latestCold', 'predecessorService', 'boot', 'tls_root_sha256'), 'a' * 64),
            (('latestCold', 'completion', 'signedOpenSHA256'), 'a' * 64),
        ]
        for path, value in mutations:
            bad = copy.deepcopy(state); cursor = bad
            for key in path[:-1]: cursor = cursor[key]
            cursor[path[-1]] = value
            self.state_path.write_bytes(canonical(bad))
            with self.subTest(path=path): self.reject('.')

    def test_bridge_disposition_is_validated_not_just_compared(self):
        state = self.completed_cold_state(True)
        mutations = [(('request', 'identity', 'generation'), 2), (('request', 'operationID'), str(uuid.uuid4())),
            (('request', 'resolutionID'), state['current']['original']['signed']['grant']['id']),
            (('request', 'signedOpenSHA256'), 'a' * 64), (('baseEpoch',), 99),
            (('successorOrigin', 'shimLaunchUUID'), str(uuid.uuid4())),
            (('receipt', 'grant', 'serial'), 99), (('receipt', 'revision'), 99),
            (('successor', 'open_revision'), 99), (('successor', 'boot', 'service_epoch'), str(uuid.uuid4())),
            (('anchor', 'open_revision'), 99), (('recoveryBridge',), {})]
        for path, value in mutations:
            bad = copy.deepcopy(state); cold = bad['latestCold']; resolved = cold['deadPredecessor']
            cursor = resolved['value']
            for key in path[:-1]: cursor = cursor[key]
            cursor[path[-1]] = value
            # Keep all redundant bridge copies equal: semantic checks must reject.
            resolved['attempted']['resolutionRequest']['value'] = copy.deepcopy(resolved['value']['request'])
            cold['prepared']['recoveryBridge'] = copy.deepcopy(resolved['value'])
            cold['completion']['recoveryBridge'] = copy.deepcopy(resolved['value'])
            self.state_path.write_bytes(canonical(bad))
            with self.subTest(path=path): self.reject('.')

    def test_unresolved_dead_cold_is_explicitly_unsupported(self):
        for value in (None, {}, self.completed_cold_state(True)['latestCold']['deadPredecessor']):
            bad = copy.deepcopy(self.state); bad['resolvedDeadCold'] = value
            self.state_path.write_bytes(canonical(bad)); self.reject('unresolved resolvedDeadCold')

    def test_completed_bridge_cannot_coexist_with_top_level_dead_cold(self):
        state = self.completed_cold_state(True)
        state['resolvedDeadCold'] = copy.deepcopy(state['latestCold']['deadPredecessor'])
        self.state_path.write_bytes(canonical(state))
        self.reject('unresolved resolvedDeadCold')

    def test_cold_greeting_requires_v2_without_version_fallback(self):
        state = self.cold_pending_state()
        self.state_path.write_bytes(canonical(state))
        proof.verify_backend(self.root, 'shared', mounts())
        for version in ('storage-lifecycle-cold-shim.v1', 'storage-lifecycle-cold-shim.v999', 'unknown'):
            changed = copy.deepcopy(state)
            changed['pendingCold']['request']['prepare']['mountedGreeting']['version'] = version
            self.state_path.write_bytes(canonical(changed))
            with self.subTest(version=version): self.reject('cold greeting mismatch')

    def test_cold_v2_held_backing_remains_closed_and_stably_bound(self):
        state = self.cold_pending_state()
        self.state_path.write_bytes(canonical(state))
        proof.verify_backend(self.root, 'shared', mounts())  # Diagnostic device changed, stable projection did not.
        mutations = [dict(inode=self.record['backing']['inode'] + 1), dict(volume_uuid=str(uuid.uuid4())),
            dict(device=True), dict(device=-1), dict(extra=1)]
        for fields in mutations:
            changed = copy.deepcopy(state)
            changed['pendingCold']['request']['prepare']['mountedGreeting']['heldBackingIdentity'].update(fields)
            self.state_path.write_bytes(canonical(changed))
            with self.subTest(fields=fields): self.reject('.')
        for field in ('device', 'inode', 'volume_uuid'):
            changed = copy.deepcopy(state)
            del changed['pendingCold']['request']['prepare']['mountedGreeting']['heldBackingIdentity'][field]
            self.state_path.write_bytes(canonical(changed))
            with self.subTest(missing=field): self.reject('.')
        for fields in (dict(purpose='resumeReadOnly'), dict(extra=1)):
            changed = copy.deepcopy(state)
            changed['pendingCold']['request']['prepare']['mountedGreeting'].update(fields)
            self.state_path.write_bytes(canonical(changed))
            with self.subTest(greeting=fields): self.reject('.')

    def test_retired_selectors_and_mode_files_cannot_authorize_current_backend(self):
        for key in ("CENGINE_COMPAT_MANAGED_STORAGE", "CENGINE_COMPAT_SHARED_STORAGE"):
            for value in ("", "0", "1", "legacy", "managed", "lifecycle"):
                with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}), self.assertRaises(proof.BackendProofError):
                    proof.verify_backend(self.root, "shared", mounts())
        for mode in ("managed", "legacy", "lifecycle"):
            old = self.root / "shared-storage-mode.json"
            old.write_text(json.dumps(dict(schema=1, mode=mode, root=self.record["root"])))
            with self.assertRaises(proof.BackendProofError):
                proof.verify_backend(self.root, "shared", mounts())
            old.unlink()
        for mode in ("managed", "legacy"):
            with self.assertRaises(proof.BackendProofError):
                proof.capture_backend_root(self.root, mode)

    def test_disk_bootstrap_records_only_current_shared_backend(self):
        peer = object()
        daemon = SimpleNamespace(root=self.root, process=SimpleNamespace(args=["daemon"]))
        text = mounts(destination="/shared")
        with patch.object(disk_initialization, "_exec", return_value=text.encode()) as command:
            result = disk_initialization._shared_backend(daemon, peer)
        command.assert_called_once_with(peer, "cat", "/proc/self/mountinfo")
        self.assertEqual(result["mode"], "lifecycle")
        self.assertEqual(result["mount"]["raw"], text.strip())
        for bad in (text * 2, text.replace("/shared", "/other"), text.replace("fuse.managed-v3", "nfs")):
            with patch.object(disk_initialization, "_exec", return_value=bad.encode()), self.assertRaises(proof.BackendProofError):
                disk_initialization._shared_backend(daemon, peer)

    def test_disk_bootstrap_proves_backend_initially_and_after_restart(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_disk_initialization.py").read_text())
        test = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_"))
        calls = [n for n in ast.walk(test) if isinstance(n, ast.Call) and
                 isinstance(n.func, ast.Name) and n.func.id == "_shared_backend"]
        self.assertEqual(len(calls), 2)
        preserved = next(n for n in test.body if isinstance(n, ast.Try)).body
        preserved = next(n for n in preserved if isinstance(n, ast.FunctionDef) and n.name == "preserved")
        self.assertTrue(any(call in list(ast.walk(preserved)) for call in calls))

    def test_direct_source_is_cosmetic_not_dev_path(self):
        for source in ("/dev/vdb", "/proc/self/fd/5"):
            self.assertEqual(proof.verify_backend(self.root, "block", mounts("ext4", source))["topology"], "block")
        with self.assertRaises(proof.BackendProofError):
            proof.verify_backend(self.root, "block", mounts("ext4", "/dev/vdb", root="/subdir"))

    def test_wrong_shared_backend_and_wrong_source_rejected(self):
        for fs, source in (("nfs", "100.64.0.1:/"), ("nfs4", "100.64.0.1:/"),
                           ("ext4", "/dev/vdb"), ("fuse.other", "managed-v3"),
                           ("fuse.managed-v3", "pretend")):
            with self.subTest(fs=fs, source=source), self.assertRaises(proof.BackendProofError):
                proof.verify_backend(self.root, "shared", mounts(fs, source))

    def test_current_manifest_rejects_retired_shapes_and_bad_binding(self):
        for changes in (dict(version="storage-lifecycle.v1"), dict(mode="managed"),
                        dict(identity={**self.record["identity"], "binding": "b" * 64}),
                        dict(identity={**self.record["identity"], "generation": True}),
                        dict(bytes=True), dict(rootPublicKey="invalid")):
            self.path.write_bytes(canonical({**self.record, **changes}))
            with self.subTest(changes=changes), self.assertRaises(proof.BackendProofError):
                proof.verify_backend(self.root, "shared", mounts())

    def test_uncaptured_or_replaced_startup_root_rejected(self):
        saved = proof._ROOT_PINS.pop(str(self.root))
        with self.assertRaises(proof.BackendProofError):
            proof.verify_backend(self.root, "shared", mounts())
        proof._ROOT_PINS[str(self.root)] = {**saved, "identity": {**saved["identity"], "inode": saved["identity"]["inode"] + 1}}
        with self.assertRaises(proof.BackendProofError):
            proof.verify_backend(self.root, "shared", mounts())

    def test_copied_root_identity_rejected(self):
        self.record["root"]["inode"] += 1
        self.save()
        with self.assertRaises(proof.BackendProofError):
            proof.verify_backend(self.root, "shared", mounts())

    def test_numeric_bool_and_unknown_schema_rejected(self):
        for key, value in (("schema", True), ("schema", 2), ("mode", "auto"), ("extra", 1)):
            bad = {**self.record, key: value}
            self.path.write_bytes(canonical(bad))
            with self.assertRaises(proof.BackendProofError):
                proof.verify_backend(self.root, "shared", mounts())
        self.record["root"]["inode"] = True
        self.save()
        with self.assertRaises(proof.BackendProofError):
            proof.verify_backend(self.root, "shared", mounts())

    def test_duplicate_json_fields_rejected(self):
        self.path.write_text('{"schema":1,"schema":1,"mode":"managed","root":{}}')
        with self.assertRaises(proof.BackendProofError):
            proof.verify_backend(self.root, "shared", mounts())

    def test_missing_symlink_hardlink_fifo_and_oversized_file_rejected(self):
        self.path.unlink()
        with self.assertRaises(proof.BackendProofError):
            proof.verify_backend(self.root, "shared", mounts())
        other = self.root / "other"
        other.write_text(json.dumps(self.record))
        for kind in ("symlink", "hardlink", "fifo", "large"):
            if kind == "symlink": self.path.symlink_to(other)
            elif kind == "hardlink": os.link(other, self.path)
            elif kind == "fifo": os.mkfifo(self.path)
            else: self.path.write_bytes(b"x" * (proof.MAXIMUM_BYTES + 1))
            with self.subTest(kind=kind), self.assertRaises(proof.BackendProofError):
                proof.verify_backend(self.root, "shared", mounts())
            self.path.unlink()

    def test_startup_and_override_conflicts_rejected(self):
        for flag in ("0", "", "yes"):
            with patch.dict(os.environ, {"CENGINE_COMPAT_MANAGED_STORAGE": flag}), self.assertRaises(proof.BackendProofError):
                proof.verify_backend(self.root, "shared", mounts())
        for override in ("", "nfs", "nfs4", "ext4"):
            with patch.dict(os.environ, {"CENGINE_CORPUS_SHARED_FS": override}), self.assertRaises(proof.BackendProofError):
                proof.verify_backend(self.root, "shared", mounts())
        with self.assertRaises(proof.BackendProofError):
            proof.verify_backend(self.root, "shared", mounts(), startup_mode="legacy")

    def test_exact_destination_duplicates_and_malformed_mounts(self):
        text = mounts(destination="/nested")
        self.assertEqual(proof.verify_backend(self.root, "shared", text, "/nested")["mount"]["destination"], "/nested")
        for wrong in (text, mounts() * 2, "garbage", mounts().replace(" - ", " "), mounts() + "garbage"):
            with self.assertRaises(proof.BackendProofError):
                proof.verify_backend(self.root, "shared", wrong)

    def test_captured_startup_argv(self):
        self.assertEqual(proof.daemon_startup_mode(SimpleNamespace(process=SimpleNamespace(args=["daemon"]))), "lifecycle")
        for mode in ("legacy", "managed", "lifecycle", "unknown", ""):
            for arguments in (["daemon", "--shared-storage", mode], ["daemon", "--shared-storage=" + mode]):
                with self.subTest(arguments=arguments), self.assertRaises(proof.BackendProofError):
                    proof.daemon_startup_mode(SimpleNamespace(process=SimpleNamespace(args=arguments)))

    def test_readonly_probe_is_separate_and_historical_fixture_untouched(self):
        (self.root / "fixture.tar").write_bytes(b"historical")
        def build(argv, **kwargs):
            self.assertEqual(kwargs["env"]["GOOS"], "linux")
            self.assertEqual(kwargs["env"]["CGO_ENABLED"], "0")
            Path(argv[argv.index("-o") + 1]).write_bytes(b"test-linux-binary")
        with patch.object(volume_probe.subprocess, "run", side_effect=build):
            name, archive, hashes = volume_probe._mount_probe_archive(self.root)
        self.assertEqual((self.root / "fixture.tar").read_bytes(), b"historical")
        self.assertTrue(name.startswith("cengine-backend-proof-"))
        self.assertEqual(hashes["archive_sha256"], hashlib.sha256(archive).hexdigest())
        self.assertNotIn(b"/data", volume_probe.MOUNT_PROBE_SOURCE)
        self.assertNotIn(b"OpenFile", volume_probe.MOUNT_PROBE_SOURCE)

    def test_backend_proof_never_enters_compared_observations(self):
        text = (ROOT / "Tests/Compatibility/volume_probe.py").read_text()
        tree = ast.parse(text)
        execute = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "execute")
        calls = [n for n in ast.walk(execute) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "record_backend_mounts"]
        self.assertEqual(len(calls), 2)  # Initial mount and restart.
        self.assertIn('observation = {"id": step["id"], "result": outcome, "peer": peer}', text)

    def test_failed_start_journal_cannot_clear_cleanup_fence(self):
        directory = self.root / "events"
        directory.mkdir()
        container = SimpleNamespace(id="owned", client=SimpleNamespace(api=SimpleNamespace(
            adapters={"http+docker://": SimpleNamespace(socket_path="/not-used")}, _version="1.55")))
        with patch.object(concurrency.subprocess, "Popen", side_effect=OSError("spawn failed")), \
             patch.object(concurrency, "_record", side_effect=OSError("journal full")):
            with self.assertRaises(OSError):
                concurrency._simultaneous_start([container, container], directory)
        self.assertIn(directory, concurrency._UNSETTLED_STARTS)
        concurrency._UNSETTLED_STARTS.discard(directory)

    def test_ambiguous_start_persists_real_retention_marker_even_if_journal_fails(self):
        from conftest import Daemon
        from harness import COMPATIBILITY_RETAIN_FILE
        work = self.root / "owned-work"
        work.mkdir(mode=0o700)
        daemon = Daemon(binary=Path("/bin/true"), kernel=self.root / "unused-kernel",
                        container_initramfs=self.root / "unused-container",
                        storage_initramfs=self.root / "unused-storage", work=work)
        client = SimpleNamespace(api=SimpleNamespace(timeout=45))
        with patch.object(concurrency, "_record", side_effect=OSError("journal full")):
            with self.assertRaises(concurrency.UnsettledStarts):
                concurrency._fence_start_cleanup(daemon, client, self.root, 180, ["owned-container"], "owned-volume", "token")
        self.assertEqual(client.api.timeout, 180)
        self.assertTrue(daemon.root_retained)
        self.assertEqual(json.loads((work / COMPATIBILITY_RETAIN_FILE).read_text())["reason"], "cleanup-incomplete")
        self.assertIsNone(daemon.process)  # No daemon/VM was started.

    def test_concurrency_no_unjoinable_threads_and_retention_fence(self):
        text = (ROOT / "Tests/Compatibility/test_volume_concurrency.py").read_text()
        self.assertNotIn("threading.Thread", text)
        self.assertIn("process.kill()", text)
        self.assertIn("cleanup-fenced", text)
        self.assertIn('daemon.retain_root(reason=', text)
        self.assertIn('_start_marker(process, b"ready\\n", deadline)', text)
        self.assertIn('"client-local managed FUSE locking"', text)


if __name__ == "__main__":
    unittest.main()
