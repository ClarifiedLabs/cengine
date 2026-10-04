"""Original-aware two-restart follow-up; no RTM103 acceptance selector.

Uses existing owned Docker/daemon APIs. Public queue files select work; only the
signed runtime's real boot/Query/GETATTR paths produce evidence. No signal API.
"""
from __future__ import annotations
from contextlib import ExitStack
from dataclasses import replace
import copy
from pathlib import Path
import signal
import struct
import time
import uuid

import managed_prepare_faults as p
import managed_storage_recovery as recovery
import managed_stale_consumer as stale
import managed_takeover_lifecycle_evidence as lifecycle

FOLLOWUP_CASES = ("replayed-takeover", "legacy-connection", "second-service-exclusivity")
SOURCE_ENABLED_CASES = (*stale.IMPLEMENTED_CASES, *FOLLOWUP_CASES)

def followup_selection(profile, cases, case):
    """Separate source-ready route: caller owns prepared original/reader fixtures.

    Never route these through the replacement-based 165s PREPARE shard. Source
    readiness is not deployed/native acceptance; native remains independently gated.
    """
    p.require(profile == p.FULL_PROFILE and tuple(cases) == stale.CASES, "complete explicit RTM103 catalog required")
    p.require(case in FOLLOWUP_CASES, "fixed follow-up source selector")
    return dict(rtm="RTM-103", profile=profile, caseName=case, coverage="1/18", fullAcceptance=False, nativeAcceptance=False,
        executionRoute="two-api-restarts" if case == "replayed-takeover" else "service-isolation",
        missing=[name for name in stale.CASES if name != case])


ARM_VERSION = "original-takeover-arm.v1"
REGISTRY_FIELDS = {"schema", "revision", "store", "epoch", "controller", "volumes", "volume_lifecycles", "attachments", "prepares"}


def candidate(value, request, intent, generation):
    p.exact(value, {"request", "binding"})
    p.require(p.canonical(value["request"]) == p.canonical(request), "exact Arm request")
    b = value["binding"]; p.exact(b, stale.BINDING_FIELDS)
    p.integer(b["version"], 4, 4); p.integer(b["generation"], minimum=1)
    p.require(b["profile"] == p.FULL_PROFILE and b["caseName"] == "same-e-existing-data", "fixed GETATTR carrier")
    for k in ("requestID", "operationUUID"): p.require(b[k] == request[k], "Arm correlation")
    seed = copy.deepcopy(value); seed["binding"]["armDigest"] = "0" * 64
    p.require(b["armDigest"] == p.digest(p.canonical(seed)), "actual candidate digest")
    p.exact(b["scope"], p.SCOPE)
    p.require(b["scope"] == {k: intent["id" if k == "intent" else k] for k in p.SCOPE}, "actual live intent")
    p.require(intent["phase"] == "running" and intent["prepareCompleted"] is True, "published RUNNING")
    for key, selected in (("store", "store"), ("controllerEpoch", "epoch"), ("serviceEpoch", "serviceEpoch"),
                          ("container", "container"), ("containerInstance", "containerInstance")):
        p.require(b["scope"][key] == request[selected], "selected original " + key)
    slot = stale.runtime_slots(intent, "takeover")[0]
    p.require(b["targetAttachment"] == slot["attachment"] and b["key"] == slot["key"], "actual issued key")
    for k in ("key", "certificateSHA256", "armDigest"): p.pin(b[k])
    p.exact(b["boot"], {"shimLaunchUUID", "guestBootNonce"}); p.uid(b["boot"]["guestBootNonce"])
    p.require(b["generation"] == generation and b["boot"]["shimLaunchUUID"] == intent["launch"], "actual original generation")
    return b


def registry(value, owner, intent):
    if lifecycle.is_v2(owner):
        return lifecycle.registry(value, owner, intent)
    lifecycle.owner(owner)
    p.exact(value, REGISTRY_FIELDS)
    p.integer(value["schema"], 3, 3); p.integer(value["revision"], 2**64-1, 1)
    from managed_takeover_replay import transition
    proof = recovery.owner_proof(owner)
    p.exact(value["controller"], {"epoch", "key"})
    p.integer(value["controller"]["epoch"], 2**64-1, 1)
    p.require(value["store"]["id"] == proof["store"] and value["epoch"] == proof["serviceEpoch"]
        and value["controller"] == dict(epoch=proof["controllerEpoch"], key=transition(owner["transitions"][-1])[0]["grant"]["new_key"]), "authenticated Query scope")
    for name in ("volumes", "volume_lifecycles", "attachments", "prepares"): p.require(type(value[name]) is dict, "complete Query map")
    slot = stale.runtime_slots(intent, "takeover")[0]
    remote = value["attachments"][slot["attachment"]]
    p.require(remote["phase"] == "ACTIVE" and remote.get("receipt") is None and remote.get("retirement") is None
        and remote["binding"]["key"] == slot["key"] and remote["binding"]["volume"] == slot["volume"], "original DATA remains active")
    return value


def unchanged_registry(before, after, old_owner, new_owner, intent):
    p.require(lifecycle.is_v2(old_owner) == lifecycle.is_v2(new_owner), "same explicit Query owner format")
    if lifecycle.is_v2(old_owner): lifecycle.same_service_step(old_owner, new_owner)
    # Digest the pinned publication: v2 includes its fenced lifecycle identity;
    # v1's publication is the bare snapshot. These are not hidden-state hashes.
    before_digest, after_digest = p.digest(p.canonical(before)), p.digest(p.canonical(after))
    before = registry(before, old_owner, intent)
    after = registry(after, new_owner, intent)
    # Authority.Takeover commits exactly once. The rejected replay cannot commit;
    # no other authority mutation may be hidden among the controller transition.
    p.require(after["revision"] == before["revision"] + 1, "only legitimate takeover revision")
    for key in REGISTRY_FIELDS - {"controller", "revision"}:
        p.require(p.canonical(before[key]) == p.canonical(after[key]), "unchanged complete Query " + key)
    return dict(registryVerified=True, beforeSHA256=before_digest, afterSHA256=after_digest)


def positive_arm(binding, armed):
    from managed_takeover_replay import validate_original_arm
    validate_original_arm(binding, armed)
    return armed


def fresh_positive(binding, armed, released, original, original_intent, fresh_intent, *, controller_delta=1):
    positive_arm(binding, armed)
    p.require(p.canonical(released) == p.canonical(dict(arm=armed["arm"], stage="released")), "fresh joined Release")
    p.require(binding["scope"]["serviceEpoch"] == original["scope"]["serviceEpoch"]
        and binding["scope"]["store"] == original["scope"]["store"]
        and binding["scope"]["controllerEpoch"] == original["scope"]["controllerEpoch"] + controller_delta, "fresh current owner same service")
    for key in ("key", "certificateSHA256", "targetAttachment"):
        p.require(binding[key] != original[key], "fresh issued " + key)
    p.require(binding["boot"] != original["boot"] and binding["scope"]["launch"] != original["scope"]["launch"], "fresh actual client")
    p.require(stale.runtime_slots(original_intent, "takeover")[0]["volume"] == stale.runtime_slots(fresh_intent, "takeover")[0]["volume"], "same independent backing")
    return dict(freshGetattrVerified=True, binding=binding, evidence=armed, released=released)


def takeover_attestation(value, binding, replay_id, registry_before, owner=None):
    # CompatibilityStateDigest hashes private disk state plus hidden side-files,
    # not the public Query. Bind by request/worker/E/revision and compare the
    # actual before/after receipts; never fabricate this hash from a Snapshot.
    p.exact(value, {"before", "after"})
    before = value["before"]
    p.exact(before, {"request", "workerUUID", "caseName", "store", "serviceEpoch", "revision", "registrySHA256", "result"})
    p.exact(before["request"], {"requestID", "operationUUID", "armDigest", "challenge"})
    p.uid(before["workerUUID"]); p.uid(before["request"]["challenge"]); p.pin(before["registrySHA256"])
    p.integer(before["revision"], 2**64-1, 1)
    p.require(p.canonical(before) == p.canonical(value["after"]), "unchanged hidden registry across denied replay")
    p.require(before["caseName"] == "isolation-state" and before["result"] == "registry-state" and
        before["store"] == binding["scope"]["store"] and before["serviceEpoch"] == binding["scope"]["serviceEpoch"] and
        before["revision"] == registry_before["revision"], "same pre-takeover authority state")
    p.require(before["request"]["requestID"] == replay_id and before["request"]["operationUUID"] == binding["operationUUID"] and
        before["request"]["armDigest"] == binding["armDigest"], "denied replay and actual original Arm correlation")
    if owner is not None and lifecycle.is_v2(owner):
        p.require(before["workerUUID"] == lifecycle.owner(owner)["workerUUID"], "actual retained lifecycle worker")
    return value


def isolation_attestation(receipt, binding, registry_value, case, owner=None):
    # The producer's private journal/census digest is deliberately not Query's
    # digest. All three actual private observations must retain that same hash.
    p.require(case in ("legacy-connection", "second-service-exclusivity"), "fixed isolation case")
    p.exact(receipt, {"before", "observation", "after"})
    proof = receipt["observation"]
    for item in receipt.values():
        p.exact(item, {"request", "workerUUID", "caseName", "store", "serviceEpoch", "revision", "registrySHA256", "result"})
        p.exact(item["request"], {"requestID", "operationUUID", "armDigest", "challenge"})
        p.uid(item["workerUUID"]); p.uid(item["request"]["challenge"])
        p.integer(item["revision"], minimum=1); p.pin(item["registrySHA256"])
        for key in ("requestID", "operationUUID", "armDigest"):
            p.require(item["request"][key] == binding[key], "exact original isolation request")
    before = receipt["before"]
    p.require(p.canonical(before) == p.canonical(receipt["after"]) and before["caseName"] == "isolation-state"
        and before["result"] == "registry-state", "fresh private state receipts")
    for key in ("request", "workerUUID", "store", "serviceEpoch", "revision", "registrySHA256"):
        p.require(p.canonical(proof[key]) == p.canonical(before[key]), "independent private receipt equality " + key)
    expected = "legacy-tls-header-rejected" if case == "legacy-connection" else "second-owner-locked"
    p.require(proof["caseName"] == case and proof["result"] == expected and proof["store"] == binding["scope"]["store"]
        and proof["serviceEpoch"] == binding["scope"]["serviceEpoch"] and proof["revision"] == registry_value["revision"],
        "sealed unchanged authority proof")
    if owner is not None and lifecycle.is_v2(owner):
        p.require(proof["workerUUID"] == lifecycle.owner(owner)["workerUUID"], "actual retained lifecycle worker")
    return proof


class OriginalFixture:
    """Concrete adapter for two already-created, owned full-profile containers.

    Caller owns provisioning and final removal. This adapter starts/stops only
    these resources and retains native launch pins across the final API restart.
    It does not accept evidence-producing callbacks or replacement clients.
    """
    def __init__(self, daemon, container, reader, plan, reader_plan, remaining, record):
        self.daemon, self.container, self.reader = daemon, container, reader
        self.plan, self.reader_plan, self.remaining, self.record = plan, reader_plan, remaining, record
        self.stack = ExitStack(); self.started = []; self.files = {}; self.native_owners = {}
        p.require(container.id != reader.id and plan["volume"] == reader_plan["volume"], "independent same-volume reader")
        for item, selected in ((container, plan), (reader, reader_plan)):
            item.reload(); p.owned(item, "container", selected)
            p.require(item.attrs["State"]["Status"] == "created" and item.attrs["State"]["Running"] is False, "never-started owned fixture")

    def state(self):
        with p.Directory(self.daemon.root / "managed-storage", private=False) as d:
            manifest = p.decode(d.read("manifest.json", 1048576)[0], 1048576, canonical_only=False)
            state = p.decode(d.read("state.json", 1048576)[0], 1048576, canonical_only=False)
        p.require(manifest["store"] == state["store"] and manifest["mode"] == "managed" and not state["reconciliationRequired"], "reconciled actual store")
        return manifest, state

    def processes(self):
        import harness
        return harness.compatibility_runtime_processes(self.daemon.binary, roots=(self.daemon.root, Path("/")))

    def live(self, item, plan):
        import harness
        manifest, state = self.state()
        intents = [i for i in state["intents"].values() if i["container"] == item.id and i["phase"] == "running"]
        p.require(len(intents) == 1, "one actual running owner"); intent = intents[0]
        p.running_receipts(manifest, state, plan, item.id, intent["id"])
        matches = [v for v in self.processes() if len(v.arguments) == 6 and v.arguments[1:3] == ("vm-shim", "--spec")
            and Path(v.arguments[3]).parent.name.endswith("-" + intent["launch"])]
        p.require(len(matches) == 1, "one native original shim"); process = matches[0]
        native, saved, validate = self.stack.enter_context(p.workload_owner(process, self.daemon, plan, intent, manifest["root"]))
        stale.fixture_mounts(saved, intent, state, plan, "same-e-existing-data")
        retained = {"process": process}
        def check():
            current_process = retained["process"]
            validate(); p.require(harness._kernel_process(current_process.pid) == current_process, "same surviving native shim")
            _, current = self.state(); p.require(current["intents"][intent["id"]] == intent, "unchanged live original intent")
        check()
        self.native_owners[item.id] = retained
        return intent, int(Path(process.arguments[3]).parent.name[:20]), check

    def api_restarted(self, api):
        """Refresh only captured workloads after the owned API's joined SIGKILL."""
        import harness
        p.require(api is not self.daemon.process and api.poll() == -signal.SIGKILL,
            "joined owned API SIGKILL before workload refresh")
        refreshed = []
        for retained in self.native_owners.values():
            previous = retained["process"]
            observed = harness._kernel_process(previous.pid)
            p.require(observed == previous or (previous.parent_pid == api.pid
                and observed == replace(previous, parent_pid=1)),
                "exact workload or killed API child reparented to PID 1")
            refreshed.append((retained, observed))
        # Do not partially refresh the retained census if any workload changed.
        for retained, observed in refreshed:
            retained["process"] = observed

    def snapshot(self, item):
        from volume_probe import close_exec_stream
        self.remaining()
        api = item.client.api
        identifier = api.exec_create(item.id, ["/probe", "snapshot"], stdout=True, stderr=True)["Id"]
        stream = api.exec_start(identifier, socket=True); sock = getattr(stream, "_sock", stream)
        raw = bytearray()
        try:
            while True:
                sock.settimeout(min(5, self.remaining()))
                chunk = sock.recv(min(65536, 131073-len(raw)))
                if not chunk: break
                raw.extend(chunk); p.require(len(raw) <= 131072, "bounded backing observation")
        finally: close_exec_stream(stream)
        output = bytearray(); offset = 0
        while offset < len(raw):
            p.require(len(raw)-offset >= 8, "complete exec header")
            channel, size = struct.unpack(">BxxxI", raw[offset:offset+8])
            p.require(raw[offset+1:offset+4] == b"\0\0\0" and channel == 1 and size <= len(raw)-offset-8, "stdout-only backing proof")
            output.extend(raw[offset+8:offset+8+size]); offset += 8+size
        status = api.exec_inspect(identifier)
        p.require(status["Running"] is False and type(status["ExitCode"]) is int and status["ExitCode"] == 0, "joined independent snapshot")
        value = p.decode(bytes(output), 131072, canonical_only=False)
        p.snapshot(value); stale.mounted_fixture(value, "same-e-existing-data")
        return value

    def activate(self, queue, owner, item, instance, *, fresh=False, isolation_case=None):
        proof = lifecycle.owner(owner)
        request: dict = dict(version=ARM_VERSION, requestID=str(uuid.uuid4()), operationUUID=str(uuid.uuid4()),
            store=proof["store"], epoch=proof["controllerEpoch"], serviceEpoch=proof["serviceEpoch"], container=item.id, containerInstance=instance)
        if fresh or isolation_case is not None: request["positiveOnly"] = True
        if isolation_case is not None:
            p.require(isolation_case in ("legacy-connection", "second-service-exclusivity"), "fixed isolation case")
            request["isolationCase"] = isolation_case
        queue.publish("public-takeover-arm.capture.json", request)
        self.remaining(); self.started.append(item); item.start()
        plan = self.reader_plan if fresh else self.plan
        intent, generation, validate = self.live(item, plan)
        values = {}
        for phase in ("candidate", "armed", "registry") + (("isolation", "positive", "released") if isolation_case is not None else (("released",) if fresh else ())):
            name = request["requestID"] + ".public-takeover-arm." + phase + ".json"
            while True:
                self.remaining(); queue.validate(); validate()
                try:
                    pinned = queue.read(name, 65536, pin_file=True)
                    self.files[name] = pinned; raw = pinned[0]; break
                except FileNotFoundError: time.sleep(0.01)
            values[phase] = p.decode(raw, canonical_only=False)
        binding = candidate(values["candidate"], request, intent, generation)
        positive_arm(binding, values["armed"]); registry(values["registry"], owner, intent)
        return binding, values, intent, validate

    def prepare(self, owner, queue):
        from managed_prepare_worker_faults import prepared_peer_owner
        manifest, _ = self.state()
        with prepared_peer_owner(self.daemon, self.reader, self.reader_plan, manifest["root"], self.processes()) as (_, _, validate):
            validate(); self.started.append(self.reader); self.reader.start()
        self.reader_intent, _, self.validate_reader = self.live(self.reader, self.reader_plan)
        with prepared_peer_owner(self.daemon, self.container, self.plan, manifest["root"], self.processes()) as (_, prepared, validate):
            validate()
            self.binding, self.arm, self.intent, self.validate_original = self.activate(queue, owner, self.container, prepared["containerInstance"])
        p.require(stale.runtime_slots(self.reader_intent, "takeover")[0]["volume"] == stale.runtime_slots(self.intent, "takeover")[0]["volume"], "real shared backing")
        self.validate_original(); self.validate_reader()
        self.baseline = self.snapshot(self.reader)
        p.snapshot(self.snapshot(self.container), baseline=self.baseline)
        self.before = owner
        self.record("takeover-original-armed", binding=self.binding, armed=self.arm["armed"], registry=self.arm["registry"],
            backing={k:v for k,v in self.baseline.items() if k != "mountinfo"})
        return self.binding

    def finish(self, owner, queue, artifacts, replay_id):
        from managed_takeover_replay import recovered_original_positive
        self.validate_original(); self.validate_reader()
        p.require(p.canonical(artifacts["resumed"]) == p.canonical(self.arm["armed"]), "pinned resumed original")
        original = recovered_original_positive(artifacts["positive"], self.binding, self.arm["armed"])
        authority = unchanged_registry(self.arm["registry"], artifacts["registry"], self.before, owner, self.intent)
        takeover_attestation(artifacts["attestation"], self.binding, replay_id,
            registry(self.arm["registry"], self.before, self.intent), self.before)
        authority["hiddenRegistryVerified"] = True
        after = self.snapshot(self.reader); p.snapshot(after, baseline=self.baseline)
        self.validate_original(); self.validate_reader()
        self.record("takeover-independent-unchanged", registry=authority, backing={k:v for k,v in after.items() if k != "mountinfo"})
        # Only after the immutable registry comparison may a fresh registration
        # change authority state. Restart the independent reader, not original.
        self.reader.stop(timeout=1)
        fresh, values, intent, validate = self.activate(queue, owner, self.reader, self.reader_intent["containerInstance"], fresh=True)
        evidence = fresh_positive(fresh, values["armed"], values["released"], self.binding, self.intent, intent)
        p.snapshot(self.snapshot(self.reader), baseline=self.baseline); validate(); self.validate_original()
        for name, pinned in self.files.items():
            p.require(queue.read(name, 65536) == pinned, "final immutable Arm evidence")
        self.record("takeover-fresh-getattr", evidence=evidence)
        return dict(**original, **authority, freshGetattrVerified=True, backingVerified=True)

    def close(self):
        try:
            # No signal/PID fallback: failed stop remains a containment error.
            failure = None
            for item in reversed(list({v.id:v for v in self.started}.values())):
                try: item.stop(timeout=1)
                except Exception as error: failure = error
            if failure is not None: raise failure
        finally: self.stack.close()


def run_original_restarts(daemon, *, container, reader, plan, reader_plan, remaining, record):
    from managed_takeover_replay import run_control_restarts
    fixture = OriginalFixture(daemon, container, reader, plan, reader_plan, remaining, record)
    try: return run_control_restarts(daemon, remaining=remaining, record=record, original=fixture)
    finally: fixture.close()


def run_service_isolation(daemon, *, case, container, reader, plan, reader_plan, remaining, record):
    """Live diagnostic only; no native or full-acceptance promotion."""
    from managed_prepare_worker_faults import prepared_peer_owner
    from managed_takeover_replay import recovered_original_positive
    p.require(case in ("legacy-connection", "second-service-exclusivity"), "fixed isolation case")
    owner, owner_hash = lifecycle.read_owner(daemon.root)
    p.require(lifecycle.owner(owner)["controllerEpoch"] >= 2, "confirmed C2 before diagnostic")
    fixture = OriginalFixture(daemon, container, reader, plan, reader_plan, remaining, record)
    try:
        with p.Directory(daemon.root / "managed-prepare-compatibility") as queue:
            manifest, _ = fixture.state()
            with prepared_peer_owner(daemon, reader, reader_plan, manifest["root"], fixture.processes()) as (_, _, validate):
                validate(); fixture.started.append(reader); reader.start()
            reader_intent, _, validate_reader = fixture.live(reader, reader_plan)
            baseline = fixture.snapshot(reader)
            with prepared_peer_owner(daemon, container, plan, manifest["root"], fixture.processes()) as (_, prepared, validate):
                validate()
                binding, values, intent, validate_original = fixture.activate(queue, owner, container, prepared["containerInstance"], isolation_case=case)
            # The independent reader was mounted before the denied attempt. Its
            # baseline is not synthesized from a post-probe original snapshot.
            p.require(stale.runtime_slots(reader_intent, "isolation")[0]["volume"] == stale.runtime_slots(intent, "isolation")[0]["volume"], "same independent backing")
            proof = isolation_attestation(values["isolation"], binding, registry(values["registry"], owner, intent), case, owner)
            original = recovered_original_positive(values["positive"], binding, values["armed"])
            p.require(p.canonical(values["released"]) == p.canonical(values["positive"]["released"]), "exact joined original Release")
            validate_original(); validate_reader()
            p.snapshot(fixture.snapshot(reader), baseline=baseline)
            p.snapshot(fixture.snapshot(container), baseline=baseline)
            record("service-isolation-unchanged", case=case, proof=proof, original=original)
            # Only after unchanged proof may a new registration mutate registry.
            reader.stop(timeout=1)
            fresh, fresh_values, fresh_intent, validate_fresh = fixture.activate(queue, owner, reader, reader_intent["containerInstance"], fresh=True)
            fresh_proof = fresh_positive(fresh, fresh_values["armed"], fresh_values["released"], binding, intent, fresh_intent, controller_delta=0)
            p.snapshot(fixture.snapshot(reader), baseline=baseline)
            validate_fresh(); validate_original()
            p.require(lifecycle.read_owner(daemon.root) == (owner, owner_hash), "unchanged actual controller owner")
            for name, pinned in fixture.files.items():
                p.require(queue.read(name, 65536) == pinned, "final immutable isolation evidence")
            record("service-isolation-fresh-getattr", case=case, evidence=fresh_proof)
            return dict(caseName=case, originalOperationVerified=True, registryVerified=True, backingVerified=True,
                freshGetattrVerified=True, nativeAcceptance=False, fullAcceptance=False)
    finally:
        fixture.close()
