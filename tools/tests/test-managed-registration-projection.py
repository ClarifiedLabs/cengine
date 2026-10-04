#!/usr/bin/env python3
"""Host-only fixtures; not native acceptance or selector enablement."""
import ast
import base64
import copy
from pathlib import Path
import runpy
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_stale_consumer as s


def fixture(name, lifecycle=True):
    values = runpy.run_path(str(ROOT / "tools/tests/test-managed-stale-consumer.py"))["values"]
    value, binding, intent, boot = copy.deepcopy(values("same-e-existing-data"))
    binding["caseName"] = name; value["original"]["arm"]["caseName"] = name
    slot = intent["slots"][0]; slot["registerOperation"] = str(uuid.uuid4())
    ready = boot["ready"]
    ready.update(tlsRootDER=base64.b64encode(b"test-root").decode(), serverKey="6" * 64)
    retired = value["retirement"]; exact = retired["attachment"]["binding"]
    before = dict(schema=3, revision=19, store=dict(id=intent["store"], device_id="owned",
        root=dict(device=1, inode=1), exports=dict(device=1, inode=2)), epoch=intent["serviceEpoch"],
        controller=dict(epoch=intent["controllerEpoch"], key=intent["controllerKey"]),
        volumes={slot["volume"]: dict(id=slot["volume"], name="original", root=dict(device=1, inode=3))},
        volume_lifecycles={slot["volume"]: dict(phase="READY")},
        attachments={slot["attachment"]: dict(binding=copy.deepcopy(exact), phase="ACTIVE")}, prepares={})
    prepare = str(uuid.uuid4())
    planned = dict(exact, role="prepare", prepare=prepare, attachment=str(uuid.uuid4()), key="7" * 64)
    before["attachments"][planned["attachment"]] = dict(binding=planned, phase="DRAINED", retirement=str(uuid.uuid4()),
        receipt=dict(schema=3, revision=18, **{k: planned[k] for k in ("store", "volume", "attachment", "prepare", "launch")}))
    before["prepares"][prepare] = dict(id=prepare, attachments=[planned], phase="COMPLETED",
        attestation=dict(prepare=prepare, succeeded=True, clean_copy_up=True))
    after = copy.deepcopy(before); after["revision"] = 20; after["attachments"][slot["attachment"]] = copy.deepcopy(retired["attachment"])
    positive = copy.deepcopy(value["original"])
    positive.update(stage="begun", serverDERSHA256="", rootRequest=dict(node=19, requestSequence=2),
        originalOperation=dict(kind="data-getattr-root", sequence=1, errorClass="ok"))
    observed = copy.deepcopy(value["worker"]); observed["state"] = "observed"
    attempted = copy.deepcopy(exact)
    operation = slot["registerOperation"]
    if name == "attachment-key-reuse":
        attempted["attachment"] = str(uuid.uuid4()); operation = str(uuid.uuid4())
    value.update(positive=positive, registration=dict(binding=copy.deepcopy(binding), operation=operation,
        originalRegisterOperation=slot["registerOperation"], attempted=attempted,
        denial="BLOCKED" if name == "delayed-registration" else "CONFLICT",
        authority=dict(before=before, atProbe=copy.deepcopy(after), after=after, retirement=copy.deepcopy(retired)),
        service={k: ready[k] for k in ("storeUUID", "serviceEpoch", "workerUUID")},
        peer={**{k: ready[k] for k in ("tlsRootDER", "serverDER", "serverKey")}, "dataAddress": "192.0.2.1:2049"}, observed=observed))
    if lifecycle:
        root = runpy.run_path(str(ROOT / "tools/tests/test-managed-root-projection.py"))
        root['lifecycle_projection'](boot, value['registration']['authority'])
    return value, binding, intent, boot


class Registration(unittest.TestCase):
    def test_both_exact_chains_are_source_selected_not_native_acceptance(self):
        for name in s.REGISTRATION_CASES:
            args = fixture(name)
            self.assertEqual(s.correlated_result(*args), args[0])
            self.assertIn(name, s.IMPLEMENTED_CASES)
            self.assertFalse(s.selection(s.p.FULL_PROFILE, s.CASES, name)["fullAcceptance"])

    def test_schema_identity_context_and_current_receipt_boundaries(self):
        for name in s.REGISTRATION_CASES:
            args = fixture(name, lifecycle=False)
            self.assertEqual(s.correlated_result(*args), args[0])
            for mutation in ('identity', 'schema', 'context', 'receipt', 'format', 'current-key'):
                args = fixture(name); authority = args[0]['registration']['authority']
                if mutation == 'identity': del args[3]['lifecycleIdentity']
                elif mutation == 'format': args[3]['format'] = 'storage-lifecycle.v3'
                elif mutation == 'schema': authority['before']['schema'] = 3
                elif mutation == 'context': next(iter(authority['before']['prepares'].values())).pop('context')
                elif mutation == 'current-key': next(iter(authority['before']['prepares'].values()))['context']['controller_key'] = 'f'*64
                else: args[0]['retirement']['receipt']['schema'] = 4
                with self.subTest(name=name, mutation=mutation), self.assertRaises((ValueError, KeyError)):
                    s.correlated_result(*args)

    def test_live_predecessor_and_fresh_wire_proof_order(self):
        for name in s.REGISTRATION_CASES:
            self.assertTrue(s.observes_predecessor(name))
            self.assertIn(name, s.FRESH_GETATTR_CASES)
            self.assertEqual(s.original_version(name), 4)
        tree = ast.parse((ROOT / "Tests/Compatibility/managed_stale_consumer.py").read_text())
        live = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_live")
        call = next(node for node in ast.walk(live) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "correlated_result")
        route = call.args[3]
        self.assertIsInstance(route, ast.IfExp)
        self.assertEqual(ast.unparse(route), "oldboot if observes_predecessor(case) else newboot")
        source = ast.unparse(live)
        self.assertLess(source.index("joined_start(start_request())"), source.index("proof = fresh_getattr("))
        self.assertLess(source.index("proof = fresh_getattr("), source.index("record('original-consumer-fresh-owner-positive'"))

    def test_every_required_field_null_unknown_and_numeric_alias(self):
        for name in s.REGISTRATION_CASES:
            args = fixture(name); root = args[0]
            def walk(value, path=()):
                if isinstance(value, dict):
                    yield path, "unknown", True
                    for key, child in value.items():
                        yield path, key, None
                        yield path, key, "remove"
                        if type(child) is int: yield path, key, float(child)
                        yield from walk(child, path + (key,))
            for path, key, substitute in walk(root):
                changed = copy.deepcopy(root); at = changed
                for part in path: at = at[part]
                if substitute == "remove": del at[key]
                else: at[key] = substitute
                with self.subTest(name=name, path=path, key=key, substitute=substitute):
                    with self.assertRaises((ValueError, KeyError, TypeError)):
                        s.correlated_result(changed, *args[1:])


if __name__ == "__main__": unittest.main()
