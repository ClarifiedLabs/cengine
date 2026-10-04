"""Closed worker-A5/private-BOUND active ACK pair; observations never grant authority."""
from contextlib import ExitStack
from pathlib import Path
import os
import uuid

import managed_prepare_faults as p
import managed_storage_recovery as r


# These fixtures request 128 MiB Docker limits. VirtualMachineMemory.capacity
# includes the guest reserve and produces this 256 MiB VM capacity; the persisted
# shim spec is a capacity, not a Docker limit. Do not invent a 512 MiB floor.
ACK_VM_CAPACITY = 256 * 1024**2


def four_owner_ids(containers, ack_containers, interrupted):
    p.require(len(containers) == len(set(containers)) == 4 and
        len(ack_containers) == len(set(ack_containers)) == 2 and
        set(ack_containers) < set(containers) and interrupted in set(containers) - set(ack_containers),
        "exact four owners: PREPARE pair plus independent ACK pair")
    for container in containers: p.pin(container)


def active_receipts(manifest, state, volume, containers, arm=None):
    result = r.exact_receipts(manifest, state, volume, containers)
    for intent in result["intents"]:
        raw = state["intents"][intent["id"]]
        runtime = next(slot for slot in raw["slots"] if slot["role"] == "runtime")
        p.require(runtime["retireOperation"] not in state["operations"] and
            runtime["retireOperation"] not in state["operationDigests"], "ACK runtime retirement not submitted")
        if arm is not None:
            p.require(result["volume"] not in {s["volume"] for s in arm["slots"]} and
                intent["container"] != arm["scope"]["container"] and
                all(intent[k] == arm["scope"][k] for k in ("serviceEpoch", "controllerEpoch")) and
                result["store"] == arm["scope"]["store"], "independent ACK volume in held worker context")
    return result


def receipt_evidence(receipts):
    """Keep active (not drained) slots explicit in the non-null PREPARE ledger."""
    intents = []
    for intent in receipts["intents"]:
        slots = []
        for slot in intent["slots"]:
            value = dict(slot)
            if value["receipt"] is None:
                p.require(value["role"] == "runtime" and intent["phase"] == "running",
                    "only active runtime receipt may be absent")
                del value["receipt"]
            value["receiptPresent"] = "receipt" in value
            slots.append(value)
        intents.append({**intent, "slots": slots})
    result = {**receipts, "intents": intents}
    p.canonical(result)  # Other nulls/malformed evidence still fail closed.
    return result


def unchanged_ack(before, after, *, command):
    r.worker_snapshot_proof(before, command="ack")
    r.worker_snapshot_proof(after, command=command)
    keys = ("entries", "root", "file", "sha256", "root_xattrs", "file_xattrs", "seed", "seed_sha256", "inode", "seed_inode")
    p.require(all(before[k] == after[k] for k in keys), "exact ACK bytes namespace metadata before rewriting")


def four_owner_inventory(daemon, containers, census, workload, peer, peer_proof, validate_peer, ack):
    four_owner_ids(containers, ack.ids, ack.interrupted)
    p.require(peer_proof["container"] in set(containers) - set(ack.ids) - {ack.interrupted}, "separate prepared peer")
    owners = (workload, peer, *ack.processes)
    p.require(len({v.pid for v in owners}) == 4 and all(v in census for v in owners), "four live captured owners")
    p.require(len(census) <= 8, "four-owner campaign exceeds unchanged eight-process budget")
    root = r.runtime_root_path(daemon.root)
    with p.Directory(root / "containers", private=False) as directory:
        p.require(sorted(os.listdir(directory.fd)) == sorted(containers), "complete canonical four-container census")
    selected = [v for v in census if len(v.arguments) >= 4 and v.arguments[1:3] == ("vm-shim", "--spec")
        and root / "containers" in Path(v.arguments[3]).parents]
    p.require({v.pid: v for v in selected} == {v.pid: v for v in owners}, "complete native four-owner census")
    validate_peer(); ack.validate()


def vm_start_failure(code, diagnostic):
    """Only genuine HTTP 500 or exact SDK disconnect after a selected VM cut.

    Eager old-API containment may finish the failed start before API SIGKILL.
    Neither this response nor its diagnostic is native exit or drain evidence.
    """
    p.require(type(code) is int and ((code == 50 and diagnostic == "HTTP_INTERNAL_ERROR") or
        (code == 52 and diagnostic == "CONNECTION_LOST")), "closed VM cut failed start response")
    return code


def unexposed_vm_peer(state, peer_proof):
    """An unchanged legacy prepared shim never acquired managed credentials.

    No intent at all is required; an interrupted intent with an unissued runtime
    slot is still storage-exposed and must be positively contained.
    """
    container = p.pin(peer_proof["container"])
    p.uid(peer_proof["containerInstance"])
    p.require(isinstance(state.get("intents"), dict), "complete managed intent inventory")
    for intent in state["intents"].values():
        p.require(p.pin(intent["container"]) != container, "unstarted peer has no managed intent or issued credentials")
    return peer_proof


def revalidate_vm_peer(daemon, client, peer, peer_plan, root_identity, census, expected_survivors,
                       original_owner, containers, read_state, record):
    """After API reattachment, retain the original unstarted peer before any ACK restart."""
    import harness
    from managed_prepare_worker_faults import prepared_peer_owner
    p.require(len(containers) == len(set(containers)) == 4, "complete four-container API inventory")
    for container in containers: p.pin(container)
    peer.reload()
    observed = [container.id for container in client.containers.list(all=True)]
    p.require(len(observed) == len(set(observed)) == 4 and set(observed) == set(containers),
        "unchanged four-container API inventory")
    root = r.runtime_root_path(daemon.root)
    with p.Directory(root / "containers", private=False) as directory:
        p.require(sorted(os.listdir(directory.fd)) == sorted(containers), "unchanged canonical four-container inventory")
    p.require(len(census) == len({v.pid for v in census}) and
        len(expected_survivors) == len({v.pid for v in expected_survivors}) and
        {v.pid: v for v in census} == {v.pid: v for v in expected_survivors} and
        all(harness._kernel_process(v.pid) == v for v in census), "unchanged post-recovery survivor incarnations")
    # Reopen descriptors and compare the original proof, never invoke the closed
    # pre-restart context's validator or accept a newly captured replacement.
    with prepared_peer_owner(daemon, peer, peer_plan, root_identity, census) as current:
        p.require(current[0] == original_owner[0] and current[1] == original_owner[1],
            "same original unstarted peer generation and container instance")
        current[2]()
        manifest, state, hashes = read_state()
        p.require(manifest["root"] == root_identity, "same physical root after API reattachment")
        unexposed_vm_peer(state, current[1])
        record("storage-unstarted-peer-revalidated", native=current[1], journal=hashes)


def resource_budget(census, starts, *, reserve=0, memory_reserve=0, idle=()):
    """Count parent/start children; only positively owned never-booted peers are idle."""
    p.require(len(census) + 1 + sum(child.poll() is None for child in starts) + reserve <= 8,
        "eight-process parent ACK budget")
    p.require(all(v in census for v in idle), "idle owner in exact census")
    memory = memory_reserve
    for process in census:
        args = process.arguments
        if process not in idle and len(args) >= 4 and args[1:3] == ("vm-shim", "--spec"):
            path = Path(args[3])
            with p.Directory(path.parent, private=False) as directory:
                raw, _ = directory.read(path.name, 1024 * 1024)
            spec = p.decode(raw, 1024 * 1024, canonical_only=False)
            memory += p.integer(spec["memoryBytes"], minimum=ACK_VM_CAPACITY)
    p.require(memory <= 2 * 1024**3, "two-GiB aggregate ACK VM budget")


class ActiveACK:
    """Owned extension of the existing 165-second runner, not a separate clock."""
    def __init__(self, daemon, client, probe, pin, *, read_state, target, observe, start, join,
                 processes, remaining, record, ledger, files, wait_exit, budget_check=None):
        self.daemon, self.client = daemon, client
        self.read_state, self.target, self.observe = read_state, target, observe
        self.start, self.join, self.census, self.remaining = start, join, processes, remaining
        self.record, self.ledger, self.files, self.wait_exit = record, ledger, files, wait_exit
        self.budget_check = budget_check
        self.stack = ExitStack()
        try:
            p.pin(pin)
            path = Path(probe)
            with p.Directory(path.parent, private=False) as directory:
                raw, _ = directory.read(path.name, 8 * 1024 * 1024)
            p.require(raw, "nonempty bounded ACK helper")
            p.require(p.digest(raw) == pin, "pinned existing recovery helper")
            self.plan = r.names(uuid.uuid4().hex, "RTM-084")
            archive, config = r.image_archive(raw, self.plan)
            record("active-ack-image", probeSHA256=pin, archiveSHA256=p.digest(archive), plan=self.plan)
            remaining(); client.images.load(archive)
            self.image = r.owned(client.images.get(self.plan["image"]), "image", self.plan["image"], self.plan["owner"])
            p.require(self.image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"], "ACK image layers")
            self.volume = r.owned(client.volumes.create(self.plan["volume"], labels={r.OWNER: self.plan["owner"]}),
                "volume", self.plan["volume"], self.plan["owner"])
            self.containers = []
            for name in self.plan["containers"]:
                remaining(); self.budget(reserve=1, memory_reserve=ACK_VM_CAPACITY)
                c = client.containers.create(self.image.id, name=name, network_mode="none", read_only=True,
                    mem_limit="128m", pids_limit=32, volumes={self.volume.name: {"bind": "/data", "mode": "rw"}},
                    labels={r.OWNER: self.plan["owner"], p.OWNER: self.plan["owner"]})
                self.containers.append(r.owned(c, "container", name, self.plan["owner"]))
                p.require(len(processes()) <= 8, "four-owner campaign exceeds unchanged eight-process budget")
            self.ids = [c.id for c in self.containers]
            for c in self.containers:
                self.budget(reserve=1); join(start(c)); self.budget()
            manifest, state, hashes = read_state()
            self.receipts = active_receipts(manifest, state, self.volume.name, self.ids)
            self.processes, self.validators = [], []
            for c, intent in zip(self.containers, self.receipts["intents"]):
                native = target(intent)
                owned, _, validate = self.stack.enter_context(p.workload_owner(native, daemon,
                    dict(container=c.name, owner=self.plan["owner"]), intent, manifest["root"]))
                self.processes.append(native); self.validators.append(validate)
                record("active-ack-owner", native=owned)
            self.ack = observe("worker-ack", self.containers[0])
            peer = observe("worker-ack-peer", self.containers[1])
            unchanged_ack(self.ack, peer, command="ack-peer")
            self.validate()
            record("active-ack-external-fsync", containers=self.ids, receipts=receipt_evidence(self.receipts), journal=hashes,
                snapshot={k: v for k, v in self.ack.items() if k != "mountinfo"})
            p.verify_full_ledger(ledger, files)
        except BaseException:
            self.stack.close()
            raise

    def budget(self, *, reserve=0, memory_reserve=0):
        self.remaining()
        if getattr(self, "budget_check", None) is not None:
            self.budget_check(reserve=reserve, memory_reserve=memory_reserve)
        # Conservatively reserve one replacement shim before mutating. The
        # parent's process supervisor still owns continuous enforcement.
        p.require(len(self.census()) + reserve <= 8,
            "four-owner campaign exceeds unchanged eight-process budget")

    def validate(self, arm=None):
        import harness
        self.remaining()
        manifest, state, _ = self.read_state()
        current = active_receipts(manifest, state, self.volume.name, self.ids, arm)
        p.require(current["intents"] == self.receipts["intents"] and current["volume"] == self.receipts["volume"],
            "ACK consumers still active and unchanged")
        p.require(len(self.census()) <= 8, "four-owner campaign exceeds unchanged eight-process budget")
        for c, native, validate in zip(self.containers, self.processes, self.validators):
            validate(); c.reload()
            p.require(c.attrs["State"]["Running"] is True and harness._kernel_process(native.pid) == native,
                "ACK owner died prematurely or stopped before abrupt exit")
        p.verify_full_ledger(self.ledger, self.files)

    def reattach(self, client):
        """After explicit API recovery, reopen only the same positively owned IDs."""
        self.client = client
        self.containers = [r.owned(client.containers.get(c.id), "container", c.name, self.plan["owner"])
            for c in self.containers]
        self.volume = r.owned(client.volumes.get(self.volume.name), "volume", self.plan["volume"], self.plan["owner"])
        self.image = r.owned(client.images.get(self.image.id), "image", self.plan["image"], self.plan["owner"])

    def recover(self, context, *, storage_vm=False):
        # Only after actual death and production containment of every old owner.
        self.stack.close()
        for c in self.containers:
            self.budget(reserve=1); self.join(self.start(c)); self.budget()
        manifest, state, hashes = self.read_state()
        current = active_receipts(manifest, state, self.volume.name, self.ids)
        r.fresh_receipts(self.receipts, current, context, rtm="RTM-079" if storage_vm else "RTM-084")
        native = []
        with ExitStack() as owners:
            for c, intent in zip(self.containers, current["intents"]):
                process = self.target(intent); native.append(process)
                owned, _, validate = owners.enter_context(p.workload_owner(process, self.daemon,
                    dict(container=c.name, owner=self.plan["owner"]), intent, manifest["root"]))
                validate(); self.record("active-ack-recovered-owner", native=owned, journal=hashes)
                unchanged_ack(self.ack, self.observe("worker-verify", c), command="verify")
            self.record("active-ack-preserved-before-write", context=context, receipts=receipt_evidence(current))
            p.verify_full_ledger(self.ledger, self.files)
            self.observe("worker-write", self.containers[0])
            value = self.observe("worker-verify-written", self.containers[1])
            r.worker_snapshot_proof(value, command="verify", written=True)
        for c in self.containers:
            self.remaining(); c.stop(timeout=1)
        manifest, state, _ = self.read_state()
        r.exact_receipts(manifest, state, self.volume.name, self.ids,
            ids=[i["id"] for i in current["intents"]], stopped=True)
        for c, process in zip(self.containers, native):
            c.reload(); r.owned(c, "container", c.name, self.plan["owner"]); c.remove(); self.wait_exit(process)
        self.volume.reload(); r.owned(self.volume, "volume", self.plan["volume"], self.plan["owner"]); self.volume.remove()
        self.image.reload(); r.owned(self.image, "image", self.plan["image"], self.plan["owner"]); self.client.images.remove(self.image.id)
        self.record("active-ack-fresh-write-cleanup", acknowledged=True)
