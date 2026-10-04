#!/usr/bin/env python3
"""Engine-free RTM096 schema/selection/queue tests; never native PASS evidence."""
import ast
import copy
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p


def uid(): return str(uuid.uuid4())


def values():
    volume = {"id": uid(), "name": "owned-volume"}
    normal = dict(id=uid(), store=uid(), serviceEpoch=uid(), controllerEpoch=1, controllerKey="c"*64, container="d"*64, containerInstance=uid(), launch=uid(), prepare=uid(), specificationDigest="e"*64,
        mounts=[dict(volume=volume["id"], destination="/data", subpath="", mode="read-write")],
        slots=[dict(attachment=uid(), key="a"*64), dict(attachment=uid(), key="b"*64)])
    saved = dict(id=normal["container"], instanceID=normal["containerInstance"].upper(), mounts=[dict(kind="volume", source=volume["name"], destination="/data", readOnly=False, noCopy=False)])
    capture = p.capture_from_normal(normal, saved, volume, uid())
    scope = {k: normal[k] for k in p.SCOPE if k != "intent"}
    scope.update(intent=uid(), launch=uid(), prepare=uid())
    slots = [dict(volume=volume["id"], attachment=uid(), role=role, mode="read-write") for role in ("prepare", "runtime")]
    candidate = dict(version=1, profile=p.PROFILE, requestID=capture["requestID"], binding=dict(shimLaunchUUID=scope["launch"], guestBootNonce=uid()), scope=scope, mounts=capture["mounts"], slots=slots,
        credentials=[dict(attachment=slots[0]["attachment"], key="f"*64, certificateSHA256="1"*64)])
    return normal, saved, volume, capture, candidate


def armed():
    normal, _, _, capture, candidate = values()
    return p.arm_candidate(candidate, capture, {**normal, "intent": normal["id"]}, "first-child-published")


def observed(arm):
    def identity(inode, kind):
        return dict(inode=inode, generation=7, fileType=kind, handle=struct.pack("<II", inode, 7).hex())
    return dict(version=1, profile=p.PROFILE, requestID=arm["requestID"], armDigest=p.digest(p.canonical(arm)), stage="first-child-published", count=1, targetAttachment=arm["targetAttachment"], copyIntent=uid(), filesystemUUID="8"*32, manifestDigest="9"*64, manifestSize=10,
        root=identity(1, 16384), transaction=identity(2, 16384), published=identity(3, 32768), staged=identity(4, 32768),
        sourceAtimes={"root": 1700000001000000000, "a": 1700000002000000000, "z": 1700000003000000000})


def snapshot():
    def metadata(mode): return dict(mode=mode, uid=10001, gid=10002, atimeNS=1700000000000000000, mtimeNS=p.MTIME*10**9, xattrs={})
    return dict(command="snapshot", entries=["a", "z"], root=metadata(stat.S_IFDIR | 0o750), files={n: dict(**metadata(stat.S_IFREG | 0o640), size=len(b), sha256=p.digest(b), nlink=1) for n, b in p.FILES.items()},
        mountinfo="23 10 0:40 / /data rw - fuse.managed-v3 managed-v3 rw\n", parentFsynced=False)


class PrepareTests(unittest.TestCase):
    def test_fixture_requires_current_sole_v2_asset_metadata(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())
        guards = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Attribute) and node.func.attr == "require"
                  and len(node.args) == 2 and isinstance(node.args[1], ast.Constant)
                  and node.args[1].value == "exact explicit compatible asset metadata"]
        self.assertEqual(len(guards), 1)
        # Execute the actual fixture guard without importing pytest/docker or starting a VM.
        guard = compile(ast.Expression(body=guards[0]), "fixture-asset-metadata", "eval")
        metadata = dict(schemaVersion=1, protocolVersion=1, storageServiceBootVersion=2,
                        storageLifecycleVersion=2, workloadStorageBootVersion=1,
                        prepareCompatibilityProfile=p.PROFILE, prepareCompatibilitySourceSHA256="a" * 64)
        namespace = dict(proof=p, profile=p.PROFILE, source_sha256="a" * 64)
        eval(guard, {**namespace, "metadata": metadata})
        for field, expected in metadata.items():
            missing = {key: value for key, value in metadata.items() if key != field}
            with self.subTest(field=field, missing=True), self.assertRaises(ValueError):
                eval(guard, {**namespace, "metadata": missing})
            invalid = (0, 1 if expected == 2 else 2, True, str(expected), float(expected)) if type(expected) is int else ("wrong",)
            for value in invalid:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    eval(guard, {**namespace, "metadata": {**metadata, field: value}})

    def test_closed_selection_never_full_acceptance(self):
        result = p.selection(p.PROFILE, p.CASES)
        self.assertEqual(result["coverage"], "2/9")
        self.assertFalse(result["fullAcceptance"])
        self.assertEqual(result["missing"], ["A1", "A2", "A3", "A4", "A5", "A6", "A8"])
        for profile, cases in ((None, p.CASES), (p.PROFILE, []), (p.PROFILE, ["first-child-published"]), (p.PROFILE, [*p.CASES, "A8"]), ("*", p.CASES)):
            with self.assertRaises(ValueError): p.selection(profile, cases)

    def test_shared_go_swift_observation_vector(self):
        vector_root = ROOT / "Guest/internal/preparecompat/testdata"
        arm_vectors = json.loads((vector_root / "vectors.json").read_text())
        vectors = json.loads((vector_root / "observation-vectors.json").read_text())
        self.assertEqual(len(vectors), 1)
        for vector in vectors:
            raw = p.canonical(vector["observation"])
            self.assertEqual(raw.decode(), vector["canonical"])
            self.assertEqual(p.digest(raw), vector["sha256"])
            # The queue arm already has mount/slot/credential arrays normalized.
            arm = json.loads(next(v["canonical"] for v in arm_vectors if v["sha256"] == vector["observation"]["armDigest"]))
            self.assertEqual(p.observation(p.decode(raw), arm), vector["observation"])

    def test_cross_language_canonical_escape_vector(self):
        value = {"z": "é/<>\u2028\u2029\b\t\n\f\r\x00", "a": {"🦊": 1, "é": 2}}
        expected = '{"a":{"é":2,"🦊":1},"z":"é/<>\\u2028\\u2029\\b\\t\\n\\f\\r\\u0000"}'.encode()
        self.assertEqual(p.canonical(value), expected)
        self.assertEqual(p.decode(expected), value)

    def test_reject_noncanonical_duplicate_null_float(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":null}', b'{"a":1.0}', b'{"a":1}\n', b'{"z":1,"a":2}', b'{"a":NaN}', b'{"a":-0}'):
            with self.assertRaises(ValueError): p.decode(raw)
        with self.assertRaises(ValueError): p.decode(b"{}", maximum=1)

    def test_exact_public_digest_and_full_mounts_not_docker_hash(self):
        normal, saved, volume, capture, _ = values()
        self.assertEqual(capture["specificationDigest"], normal["specificationDigest"])
        self.assertEqual(set(capture), {"version", "requestID", "container", "containerInstance", "specificationDigest", "mounts"})
        for mutation in (lambda s: s["mounts"].append(copy.deepcopy(s["mounts"][0])), lambda s: s["mounts"][0].update(noCopy=True), lambda s: s["mounts"][0].update(subpath="a"), lambda s: s.update(instanceID=uid())):
            bad = copy.deepcopy(saved); mutation(bad)
            with self.assertRaises(ValueError): p.capture_from_normal(normal, bad, volume, uid())

    def test_candidate_exact_current_launch_and_no_runtime_credentials(self):
        normal, _, _, capture, candidate = values()
        arm = p.arm_candidate(candidate, capture, normal, "normal")
        self.assertEqual(arm["scope"], candidate["scope"])
        self.assertEqual(arm["slots"], sorted(candidate["slots"], key=lambda s: s["attachment"]))
        changes = [lambda c: c.update(profile="ordinary"), lambda c: c.update(version=True), lambda c: c.update(requestID=uid()),
            lambda c: c["scope"].update(specificationDigest="0"*64), lambda c: c["scope"].update(launch=normal["launch"]),
            lambda c: c["scope"].update(prepare=normal["prepare"]), lambda c: c["scope"].update(extra=1),
            lambda c: c["binding"].update(guestBootNonce="not-uuid"), lambda c: c["slots"].pop(),
            lambda c: c["slots"].append(copy.deepcopy(c["slots"][0])), lambda c: c["slots"][0].update(mode="read-only"),
            lambda c: c["slots"][1].update(attachment=c["slots"][0]["attachment"]),
            lambda c: c["credentials"].clear(), lambda c: c["credentials"].append(copy.deepcopy(c["credentials"][0])),
            lambda c: c["credentials"][0].update(attachment=c["slots"][1]["attachment"]),
            lambda c: c["credentials"][0].update(key="a"*64), lambda c: c["credentials"][0].update(certificateSHA256="F"*64),
            lambda c: c["credentials"][0].update(certificateDER="secret"), lambda c: c["mounts"][0].update(noCopy=True)]
        for mutation in changes:
            bad = copy.deepcopy(candidate); mutation(bad)
            with self.subTest(mutation=changes.index(mutation)), self.assertRaises(ValueError): p.arm_candidate(bad, capture, normal, "first-child-published")

    def test_observation_requires_every_exact_physical_control(self):
        arm = armed(); value = observed(arm)
        self.assertEqual(p.observation(value, arm), value)
        changes = [lambda o: o.update(count=2), lambda o: o.update(count=True), lambda o: o.update(requestID=uid()),
            lambda o: o.update(armDigest="0"*64), lambda o: o.update(filesystemUUID="0"*32), lambda o: o.update(manifestSize=0),
            lambda o: o.update(manifestSize=64*1024*1024+1), lambda o: o.update(path="private"),
            lambda o: o["published"].update(fileType=16384), lambda o: o["root"].update(inode=0),
            lambda o: o["staged"].update(handle="0"*16), lambda o: o.update(staged=copy.deepcopy(o["published"]))]
        for mutation in changes:
            bad = copy.deepcopy(value); mutation(bad)
            with self.assertRaises(ValueError): p.observation(bad, arm)
        arm["caseName"] = "normal"
        with self.assertRaises(ValueError): p.observation(value, arm)  # old digest remains rejected
        value["armDigest"] = p.digest(p.canonical(arm))
        self.assertEqual(p.observation(value, arm), value)  # normal observes without holding

    def test_normal_tree_complete_metadata_and_recovered_atime(self):
        baseline = snapshot(); p.snapshot(baseline)
        for mutation in (lambda v: v["entries"].append(".txn"), lambda v: v["files"]["z"].update(sha256="0"*64), lambda v: v["root"].update(uid=0), lambda v: v["root"].update(atimeNS=1), lambda v: v["files"]["a"].update(xattrs={"user.unexpected": ""})):
            value = copy.deepcopy(baseline); mutation(value)
            with self.assertRaises(ValueError): p.snapshot(value, baseline=baseline)
        empty = snapshot(); empty.update(command="empty", entries=[], files={}, parentFsynced=True)
        p.snapshot(empty, "empty")
        empty["parentFsynced"] = False
        with self.assertRaises(ValueError): p.snapshot(empty, "empty")

    def test_fixed_writer_closed_ack_requires_preserved_tree_and_metadata(self):
        baseline = snapshot()
        written = copy.deepcopy(baseline)
        written.update(command="writer", parentFsynced=True)
        self.assertEqual(p.snapshot(written, "writer", baseline=baseline), written)
        for mutate in (
            lambda v: v.update(command="snapshot"),
            lambda v: v.update(command="empty", entries=[], files={}),
            lambda v: v.update(parentFsynced=False),
            lambda v: v.update(parentFsynced=1),
            lambda v: v["entries"].append(".rtm103-writer"),
            lambda v: v["files"]["a"].update(sha256="0" * 64),
            lambda v: v["files"]["z"].update(atimeNS=1),
            lambda v: v["root"].update(mtimeNS=1),
            lambda v: v["root"].update(atimeNS=1),
            lambda v: v.update(writerSucceeded=True),
        ):
            bad = copy.deepcopy(written); mutate(bad)
            with self.assertRaises(ValueError): p.snapshot(bad, "writer", baseline=baseline)
        unknown = copy.deepcopy(written); unknown["command"] = "arbitrary-write"
        with self.assertRaises(ValueError): p.snapshot(unknown, "arbitrary-write")
        with self.assertRaises(ValueError): p.snapshot(written)  # No action substitution.

    def test_retry_uses_current_source_witness_not_old_destination_atime(self):
        arm = armed(); arm["caseName"] = "normal"
        checkpoint = observed(arm)
        baseline = snapshot(); preserved = copy.deepcopy(baseline)
        recovered = copy.deepcopy(baseline)
        recovered["root"]["atimeNS"] = checkpoint["sourceAtimes"]["root"]
        for name in p.FILES:
            recovered["files"][name]["atimeNS"] = checkpoint["sourceAtimes"][name]
        # Counterfactual: the formerly required first destination is stale.
        with self.assertRaises(ValueError): p.snapshot(recovered, baseline=baseline)
        p.retry_snapshot(recovered, baseline, checkpoint, arm)
        self.assertEqual(baseline, preserved)
        for mutate in (lambda v: v["root"].update(atimeNS=0),
                       lambda v: v["files"]["a"].update(atimeNS=0),
                       lambda v: v["files"]["z"].update(atimeNS=0),
                       lambda v: v["root"].update(uid=0),
                       lambda v: v["files"]["z"].update(mtimeNS=0),
                       lambda v: v["files"]["a"].update(sha256="0"*64),
                       lambda v: v["entries"].append(".transaction")):
            bad = copy.deepcopy(recovered); mutate(bad)
            with self.assertRaises(ValueError): p.retry_snapshot(bad, baseline, checkpoint, arm)
        for atimes in ({}, {"root": 1, "a": 2}, {"root": 1, "a": 2, "z": 3, "path": 4},
                       {"root": None, "a": 2, "z": 3}, {"root": True, "a": 2, "z": 3},
                       {"root": -1, "a": 2, "z": 3}, {"root": 2**63, "a": 2, "z": 3}):
            bad = copy.deepcopy(checkpoint); bad["sourceAtimes"] = atimes
            with self.assertRaises(ValueError): p.retry_snapshot(recovered, baseline, bad, arm)
        bad = copy.deepcopy(checkpoint); del bad["sourceAtimes"]
        with self.assertRaises(ValueError): p.retry_snapshot(recovered, baseline, bad, arm)
        wrong = copy.deepcopy(arm); wrong["requestID"] = uid()
        with self.assertRaises(ValueError): p.retry_snapshot(recovered, baseline, checkpoint, wrong)

    def test_full_image_a_z_bytes_and_metadata(self):
        archive, config = p.image_archive(b"probe-fixture-not-a-native-test", p.names("a"*32))
        with tarfile.open(fileobj=io.BytesIO(archive)) as outer:
            layer = outer.extractfile("layer.tar").read()
        self.assertEqual(config["rootfs"]["diff_ids"], ["sha256:" + p.digest(layer)])
        with tarfile.open(fileobj=io.BytesIO(layer)) as inner:
            self.assertEqual(inner.getnames(), ["probe", "data", "data/a", "data/z"])
            self.assertEqual((inner.getmember("data").uid, inner.getmember("data").gid, inner.getmember("data").mode), (10001, 10002, 0o750))
            for name, data in p.FILES.items(): self.assertEqual(inner.extractfile("data/" + name).read(), data)

    def test_queue_no_overwrite_no_symlink_and_changed_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve()
            with p.Directory(path) as directory:
                directory.publish("capture.json", {"version": 1})
                self.assertEqual(p.decode(directory.read("capture.json")[0]), {"version": 1})
                with self.assertRaises(FileExistsError): directory.publish("capture.json", {"version": 2})
                (path / "link.json").symlink_to(path / "capture.json")
                with self.assertRaises(OSError): directory.read("link.json")
                with self.assertRaises(ValueError): directory.read("../capture.json")
                os.link(path / "capture.json", path / "hard.json")
                with self.assertRaises(ValueError): directory.read("capture.json")
            (path / "child").mkdir(mode=0o700)
            with p.Directory(path / "child") as directory:
                (path / "child").rename(path / "old")
                (path / "child").mkdir(mode=0o700)
                with self.assertRaises(ValueError): directory.validate()

    def test_publication_single_link_and_pinned_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve()
            with p.Directory(path) as directory:
                directory.publish("candidate.json", {"version": 1})
                self.assertEqual((path / "candidate.json").stat().st_nlink, 1)
                raw, stamp = directory.read("candidate.json", pin_file=True)
                (path / "candidate.json").rename(path / "old.json")
                directory.publish("candidate.json", {"version": 1})
                self.assertEqual(raw, directory.read("candidate.json")[0])
                self.assertNotEqual(stamp, directory.read("candidate.json")[1])
            os.chmod(path, 0o755)
            with self.assertRaises(ValueError): p.Directory(path)
            with p.Directory(path, private=False) as directory: directory.validate()

    def test_fresh_retry_certificate_and_boot_nonce(self):
        normal, _, _, capture, candidate = values()
        previous = {**normal, "credentials": copy.deepcopy(candidate["credentials"])}
        with self.assertRaises(ValueError): p.arm_candidate(candidate, capture, previous, "normal")
        previous = {**normal, "binding": copy.deepcopy(candidate["binding"])}
        with self.assertRaises(ValueError): p.arm_candidate(candidate, capture, previous, "normal")

    def test_failed_prepare_is_not_death_or_runtime_publication(self):
        arm = armed()
        intent = {**arm["scope"], "id": arm["scope"]["intent"], "phase": "quarantined", "prepareCompleted": False, "quarantineReason": "start interrupted", "slots": copy.deepcopy(arm["slots"])}
        for slot in intent["slots"]:
            if slot["role"] == "prepare":
                slot["receipt"] = dict(store=intent["store"], volume=slot["volume"], attachment=slot["attachment"],
                    prepare=intent["prepare"], launch=intent["launch"], revision=10)
        p.failed_prepare(intent, arm)
        for mutation in (lambda i: i.update(phase="retired"), lambda i: i.update(prepareCompleted=True), lambda i: next(s for s in i["slots"] if s["role"] == "runtime").update(key="1"*64), lambda i: next(s for s in i["slots"] if s["role"] == "prepare").update(receipt=None)):
            bad = copy.deepcopy(intent); mutation(bad)
            with self.assertRaises(ValueError): p.failed_prepare(bad, arm)

    def shared_consumers(self, create):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "create_shared_consumers")
        namespace = {"proof": p}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "fixture-setup", "exec"), namespace)
        plan = p.names("a" * 32)
        client = SimpleNamespace(containers=SimpleNamespace(create=create))
        return namespace["create_shared_consumers"](client, SimpleNamespace(id="image"), SimpleNamespace(name=plan["volume"]), plan)

    def test_two_owned_references_created_without_starting_peer(self):
        def create(image, **options):
            value = Mock(name=options["name"])
            value.name = options["name"]
            value.attrs = {"Config": {"Labels": options["labels"]}}
            return value
        create = Mock(side_effect=create)
        container, peer, peer_plan = self.shared_consumers(create)
        self.assertEqual(create.call_count, 2)
        self.assertNotEqual(container.name, peer.name)
        self.assertEqual(peer.name, peer_plan["container"])
        self.assertEqual(peer.name, container.name + "-peer")
        for call in create.call_args_list:
            self.assertEqual(call.args, ("image",))
            self.assertEqual(call.kwargs["volumes"], {peer_plan["volume"]: {"bind": "/data", "mode": "rw"}})
            self.assertEqual(call.kwargs["labels"], {p.OWNER: peer_plan["owner"]})
            self.assertEqual((call.kwargs["network_mode"], call.kwargs["read_only"],
                              call.kwargs["mem_limit"], call.kwargs["pids_limit"]), ("none", True, "128m", 32))
        container.start.assert_not_called(); peer.start.assert_not_called()
        container.remove.assert_not_called(); peer.remove.assert_not_called()

    def test_shared_reference_ownership_mismatch_refused(self):
        for bad_name in (False, True):
            def create(image, **options):
                return SimpleNamespace(name="foreign" if bad_name else options["name"],
                    attrs={"Config": {"Labels": options["labels"] if bad_name else {p.OWNER: "foreign"}}})
            with self.assertRaises(ValueError): self.shared_consumers(create)

    def test_shared_setup_and_cleanup_order_in_actual_fixture(self):
        source = (ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text()
        self.assertLess(source.index("= create_shared_consumers("), source.index("joined_start(start_request())"))
        self.assertLess(source.index("proof.running_receipts(manifest, state, plan, container.id, normal"),
                        source.index('baseline = observe("root-snapshot" if root_case else "snapshot")'))
        self.assertLess(source.index("container.remove()"), source.index("peer.remove()"))
        self.assertLess(source.index("peer.reload(); proof.owned(peer"), source.index("peer.remove()"))
        self.assertLess(source.index("peer.remove()"), source.index("volume.remove()"))
        self.assertNotIn("peer.start", source)

    def test_host_exit_waits_follow_real_termination_triggers(self):
        source = (ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text()
        tree = ast.parse(source)
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run_prepare_case")
        calls = [n for n in ast.walk(run) if isinstance(n, ast.Call)]
        def named(name):
            return [n for n in calls if isinstance(n.func, ast.Name) and n.func.id == name]
        def waits(name):
            return [n for n in named("wait_exit") if len(n.args) == 1 and isinstance(n.args[0], ast.Name) and n.args[0].id == name]
        normal, current = waits("normal_process"), waits("current_process")
        self.assertEqual(len(normal), 1); self.assertEqual(len(current), 1)
        first_start = min(n.lineno for n in named("queue_start"))
        self.assertLess(first_start, normal[0].lineno)
        before = next(n for n in ast.walk(run) if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "before" for t in n.targets))
        self.assertLess(normal[0].lineno, before.lineno)
        removed = next(n for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr == "remove"
                       and isinstance(n.func.value, ast.Name) and n.func.value.id == "container")
        self.assertLess(removed.lineno, current[0].lineno)
        self.assertLess(source.index('stopped=True)'), source.index('= queue_start(queue,'))
        self.assertLess(source.index('wait_exit(current_process)'), source.index('"same daemon/storage through cleanup"'))
        # The shared lifecycle preserves the exact A7 signal join and adds a
        # separate actual-exit join only for naturally failed A1/A3/A6 channels.
        joined = waits("process")
        self.assertEqual(len(joined), 2)
        natural = next(n for n in ast.walk(run) if isinstance(n, ast.If)
                       and isinstance(n.test, ast.Name) and n.test.id == "natural_failure"
                       and any(call in joined for call in ast.walk(n)))
        self.assertEqual(sum(call in joined for call in ast.walk(natural)), 1)
        exit_events = [n.lineno for n in ast.walk(run) if isinstance(n, ast.Attribute) and n.attr == 'KQ_NOTE_EXIT']
        self.assertLess(min(exit_events), min(n.lineno for n in joined))
        failed_start = next(n for n in named('joined_start')
                            if any(k.arg == 'failed' and isinstance(k.value, ast.Constant) and k.value.value is True for k in n.keywords))
        self.assertLess(failed_start.lineno, max(n.lineno for n in joined))

    def fixture_function(self, name, **bindings):
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())
        functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
        self.assertEqual(len(functions), 1)
        constants = [n for n in tree.body if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == "NATURAL_FAILURE_CASES" for t in n.targets)]
        self.assertEqual(len(constants), 1)
        namespace = {"proof": p, "io_case": None, **bindings}
        exec(compile(ast.Module(body=[*constants, *functions], type_ignores=[]), "fixture-start-response", "exec"), namespace)
        return namespace[name]

    def docker_module(self):
        # Default tooling tests are stdlib-only. Exercise the actual fixture
        # function against an explicit SDK boundary double, never an engine.
        class APIError(Exception):
            def __init__(self, message, response=None):
                super().__init__(message)
                self.response = response
        module = ModuleType("docker")
        module.errors = SimpleNamespace(APIError=APIError)
        module.DockerClient = Mock()
        return module

    def test_docker_start_closed_http_statuses_and_client_close(self):
        docker = self.docker_module()
        class ErrorResponse(SimpleNamespace):
            def __bool__(self): return False  # requests error responses are falsey.
        start = self.fixture_function("_docker_start")
        for status, expected in ((409, 49), (500, 50), (400, 51), (401, 51), (403, 51),
                                 (404, 51), (503, 51), (None, 51)):
            with self.subTest(status=status):
                response = None
                if status is not None:
                    response = ErrorResponse(status_code=status)
                    self.assertFalse(response)
                error = docker.errors.APIError("closed test error", response=response)
                client = Mock(); client.api.start.side_effect = error
                docker.DockerClient = Mock(return_value=client)
                with patch.dict(sys.modules, {"docker": docker}):
                    self.assertEqual(start("/fixture.sock", "a" * 64), expected)
                docker.DockerClient.assert_called_once_with(base_url="unix:///fixture.sock", version="1.47", timeout=165)
                client.api.start.assert_called_once_with("a" * 64)
                client.close.assert_called_once_with()
        client = Mock(); docker.DockerClient = Mock(return_value=client)
        with patch.dict(sys.modules, {"docker": docker}):
            self.assertEqual(start("/fixture.sock", "a" * 64), 0)
        client.close.assert_called_once_with()

    def test_docker_start_transport_failure_is_not_api_failure(self):
        docker = self.docker_module()
        start = self.fixture_function("_docker_start")
        for error in (ConnectionError("test connection"), TimeoutError("test timeout")):
            # A lookalike response attribute must not turn a transport exception
            # into the SDK's APIError type and an accepted HTTP result.
            error.response = SimpleNamespace(status_code=409)
            client = Mock(); client.api.start.side_effect = error
            docker.DockerClient = Mock(return_value=client)
            with patch.dict(sys.modules, {"docker": docker}), self.assertRaises(type(error)) as raised:
                start("/fixture.sock", "a" * 64)
            self.assertIs(raised.exception, error)
            client.close.assert_called_once_with()

    def test_joined_start_exact_case_codes_and_evidence_before_rejection(self):
        import signal
        for early in (False, True):
            for case in p.FULL_CASES:
                for failed in (False, True):
                    expected = (49 if early and case in ("before-prepare-send", "data-partial-frame", "transaction-published-bind-reply-lost") else 50) if failed else 0
                    for code in (0, 1, 49, 50, 51, 255, -9, -15):
                        with self.subTest(early=early, case=case, failed=failed, code=code):
                            record = Mock(); process = Mock(); process.wait.return_value = code
                            joined = self.fixture_function("joined_start", signal=signal, early=early,
                                fault_case=case, remaining=lambda: 7, record=record)
                            if code == expected:
                                joined(process, failed=failed)
                            else:
                                with self.assertRaises(ValueError): joined(process, failed=failed)
                            process.wait.assert_called_once_with(timeout=7)
                            record.assert_called_once_with("docker-start-joined", failed=failed, returncode=code, diagnostic="UNKNOWN")
        for code in (True, None, "49", 49.0, -signal.NSIG, 256):
            record = Mock(); process = Mock(); process.wait.return_value = code
            joined = self.fixture_function("joined_start", signal=signal, early=True,
                fault_case="before-prepare-send", remaining=lambda: 7, record=record)
            with self.assertRaises(ValueError): joined(process, failed=True)
            record.assert_not_called()

    def test_early_checkpoint_wait_uses_same_closed_exit_codes(self):
        class EndWait(Exception): pass
        for case in p.FULL_CASES:
            expected = 0 if case in ("normal", "drain-durable-reply-lost") else 49 if case in ("before-prepare-send", "data-partial-frame", "transaction-published-bind-reply-lost") else 50
            for code in (None, 0, 49, 50, 51, -9):
                with self.subTest(case=case, code=code):
                    clock = Mock(); clock.sleep.side_effect = EndWait
                    process = Mock(); process.poll.return_value = code
                    events = Mock(); events.require.side_effect = p.require
                    # Let diagnostic collection return so the actual closed-exit
                    # guard must still reject, after joining the unexpected exit.
                    events.joined_start.return_value = None
                    wait = self.fixture_function("wait_artifact", early=True, case=case, process=process,
                        remaining=lambda: 7, queue=Mock(), artifact=Mock(side_effect=FileNotFoundError), time=clock,
                        joined_start=events.joined_start, proof=SimpleNamespace(require=events.require))
                    with self.assertRaises(EndWait if code in (None, expected) else ValueError):
                        wait(".checkpoint.json")
                    self.assertEqual(clock.sleep.call_count, int(code in (None, expected)))
                    expected_calls = [] if code in (None, expected) else [call.joined_start(process)]
                    expected_calls.append(call.require(code in (None, expected), "unexpected settled start before checkpoint"))
                    self.assertEqual(events.mock_calls, expected_calls)

    def test_registered_full_entries_refuse_partial_shards(self):
        source = (ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text()
        tree = ast.parse(source)
        registrations = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "compat"]
        self.assertEqual([n.args[0].value for n in registrations], ["RTM-096", "RTM-097", "RTM-098", "RTM-099", "RTM-100"])
        tests = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]
        self.assertEqual([n.name for n in tests], ["test_managed_prepare_ambiguity_full_acceptance", "test_managed_prepare_api_restart_recovery", "test_managed_prepare_worker_restart_recovery", "test_managed_prepare_storage_vm_recovery", "test_managed_prepare_io_failures"])
        for entry, identifier in zip(tests, ("RTM-096", "RTM-097", "RTM-098", "RTM-099", "RTM-100")):
            self.assertEqual(entry.args.args, [])
            self.assertEqual([ast.unparse(n) for n in entry.decorator_list], [f"pytest.mark.compat('{identifier}')"])
            self.assertEqual(len(entry.body), 1)
            self.assertEqual(ast.unparse(entry.body[0].value.func), "pytest.fail")
        for name in ("verify_docker_cli_target", "daemon_survived"):
            guard = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual(guard.args.args, [])
        for forbidden in ("pytest.skip", "parametrize", "terminate_drained_workloads", "signal_storage", "unittest.mock"):
            self.assertNotIn(forbidden, source)
        self.assertLess(source.index('record("checkpoint-external-fsync"'), source.index('proc_signal_with_audittoken'))
        self.assertIn('select.KQ_NOTE_EXIT', source)
        self.assertIn('joined_start(start, failed=True)', source)


if __name__ == "__main__": unittest.main()
