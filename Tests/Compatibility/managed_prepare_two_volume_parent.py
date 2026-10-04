"""Actual two-container parent lifecycle; public proof helpers never launch it.

Both containers mount both shared volumes. The peer reverses the destinations so
our existing pinned /data probe independently inspects/writes each backing.
Only the second volume is emptied: the first complete tree must stay byte-exact.
"""
import copy
from dataclasses import replace
import io
from pathlib import Path
import tarfile
import signal
import uuid

import managed_prepare_faults as p
import managed_prepare_two_volume_drain as drain
from managed_stale_consumer import fixture_receipts, mounted_fixture
from managed_storage_recovery import exact_exit, unchanged_processes


def image_archive(binary, plan):
    """Same pinned helper and immutable a/z source at both fixed destinations."""
    original, config = p.image_archive(binary, plan, second_mount=True)
    with tarfile.open(fileobj=io.BytesIO(original)) as archive:
        layer = archive.extractfile("layer.tar").read()
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(layer)) as source, tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as target:
        for item in source:
            raw = source.extractfile(item).read() if item.isfile() else None
            target.addfile(item, io.BytesIO(raw) if raw is not None else None)
            if item.name in ("data/a", "data/z"):
                duplicate = copy.copy(item)
                duplicate.name = item.name.replace("data/", "other/", 1)
                target.addfile(duplicate, io.BytesIO(raw))
    layer = output.getvalue()
    config["rootfs"]["diff_ids"] = ["sha256:" + p.digest(layer)]
    raw = p.canonical(config)
    name = p.digest(raw) + ".json"
    manifest = p.canonical([dict(Config=name, RepoTags=[plan["image"]], Layers=["layer.tar"])])
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for leaf, data in ((name, raw), ("layer.tar", layer), ("manifest.json", manifest)):
            item = tarfile.TarInfo(leaf)
            item.mode, item.mtime, item.size = 0o644, p.MTIME, len(data)
            archive.addfile(item, io.BytesIO(data))
    return output.getvalue(), config


def resource_budget(census, starts):
    # Include this parent and its live start children, not only VM processes.
    p.require(len(census) + 1 + sum(child.poll() is None for child in starts) <= 8, "eight-process parent budget")
    memory = 0
    for process in census:
        args = process.arguments
        if len(args) >= 4 and args[1:3] == ("vm-shim", "--spec"):
            path = Path(args[3])
            with p.Directory(path.parent, private=False) as directory:
                raw, _ = directory.read(path.name, 1024 * 1024)
            spec = p.decode(raw, 1024 * 1024, canonical_only=False)
            # VZ's minimum is 512MiB, regardless of a lower container limit.
            memory += max(512 * 1024**2, p.integer(spec["memoryBytes"], minimum=1))
    p.require(memory <= 2 * 1024**3, "two-GiB aggregate VM budget")


def receipts(manifest, state, plan, extra_plan, container, intent, *, stopped=False):
    return fixture_receipts(manifest, state, plan, container.id, intent["id"], "wrong-volume", extra_plan, stopped=stopped)


def mounts(value):
    mounted_fixture(value, "wrong-volume")
    return value


def fresh_owner(previous, current, context, *, same_container=True):
    p.require(current["phase"] == "running" and current["prepareCompleted"] is True, "fresh completed runtime")
    p.require(all(current[k] == context[k] for k in context), "fresh recovered authority context")
    if same_container:
        p.require(all(current[k] == previous[k] for k in ("store", "container", "containerInstance", "specificationDigest", "mounts")), "same owned container and both mounts")
    p.require(all(current[k] != previous[k] for k in ("id", "launch", "prepare")), "fresh owner operations")
    old, new = previous["slots"], current["slots"]
    p.require(len(new) == 4 and {s["volume"] for s in new} == {s["volume"] for s in old}, "same two backing volumes")
    p.require({s["attachment"] for s in new}.isdisjoint(s["attachment"] for s in old), "fresh four attachments")
    for slot in new:
        p.pin(slot["key"])
        p.require(slot["key"] not in {s.get("key") for s in old}, "fresh installed keys")
    p.require(current.get("predecessor") is None and previous.get("successor") is None, "completed-set restart without replacement link")


def retained_cut(*, arm, worker, wait_artifact, artifact, read_state, record, validate_peer):
    """All external durable evidence precedes helper entry; no synthesized hold."""
    checkpoint = drain.storage_observation(wait_artifact(".storage-checkpoint.json", 8192), arm, worker)
    physical = drain.physical_observation(wait_artifact(".checkpoint.json", 8192), arm)
    record("two-volume-checkpoints-external-fsync", storage=checkpoint, physical=physical)
    held = wait_artifact(".storage-held.json")
    _, state, hashes = read_state()
    intent = drain.prefault_evidence(state, held, arm, checkpoint, worker)
    validate_peer()
    record("two-volume-host-gap-external-fsync", state=state, journal=hashes, held=held)
    def held_reader():
        validate_peer()
        artifact(".checkpoint.json", 8192)
        artifact(".storage-checkpoint.json", 8192)
        value = artifact(".storage-held.json")
        drain.storage_status(value, arm, worker, checkpoint)
        return value
    held_reader()
    return intent, checkpoint, physical, held_reader


def stopped_peer_owner(daemon, process, retired, validate_launch, validate_state):
    """Keep historical receipts fixed; refresh only the exact joined-API live pin."""
    import harness
    refreshed = False
    def validate():
        validate_launch()
        p.require(harness._kernel_process(process.pid) == owner[0], "live exact stopped peer owner")
        validate_state()
    def api_joined_refresh(api, survivors):
        nonlocal refreshed
        p.require(not refreshed and daemon.process.pid == api.pid
            and daemon.process.returncode == -signal.SIGKILL
            and exact_exit(api, harness._kernel_process(api.pid)), "joined exact API exit before stopped peer refresh")
        selected = [v for v in survivors if v.pid == process.pid]
        p.require(len(selected) == 1, "one refreshed stopped peer")
        current = selected[0]
        p.require(current == process or (process.parent_pid == api.pid
            and current == replace(process, parent_pid=1)), "exact stopped peer API reparenting")
        # The old API is gone: validate pinned files, not Docker metadata.
        validate_launch()
        p.require(harness._kernel_process(process.pid) == current, "same refreshed live stopped peer")
        owner[0] = current
        refreshed = True
    validate.api_joined_refresh = api_joined_refresh
    owner = [process, retired, validate]
    return owner


def run(daemon, *, staged, client, container, peer, peer_plan, image, volume, extra_volume, plan, extra_plan,
        config, normal, normal_process, baseline, manifest, volume_records, read_state, observe, target,
        start_request, joined_start, wait_exit, processes, remaining, ledger, files, record, queue_start,
        pending, reattach, metadata):
    import harness
    from managed_prepare_storage_vm_faults import restart_storage_at_two_volume_drain
    from managed_prepare_service_faults import verify_api_owner_final

    # The second owner's /data is the original owner's /other, not a third volume.
    reverse_plan = {**peer_plan, "volume": extra_plan["volume"]}
    reverse_extra = plan
    joined_start(start_request(peer))
    manifest, state, _ = read_state()
    peers = [i for i in state["intents"].values() if i["container"] == peer.id and i["phase"] == "running"]
    p.require(len(peers) == 1, "one positively owned peer runtime")
    peer_normal = receipts(manifest, state, reverse_plan, reverse_extra, peer, peers[0])
    peer_process = target(peer_normal)
    peer_baseline = mounts(observe("snapshot", peer))
    with p.workload_owner(peer_process, daemon, peer_plan, peer_normal, manifest["root"]) as (native, saved, validate_launch):
        drain.capture_from_normal(peer_normal, saved, list(reversed(volume_records)), str(uuid.uuid4()))
        validate_launch()
        record("two-volume-peer-owned", native=native)
        # Leave volume one untouched. Empty only the selected second volume so
        # its returning physical A8 witness exists and supplies source atimes.
        mounts(observe("empty", peer))
        peer.stop(timeout=1)
        container.stop(timeout=1)
        manifest, state, hashes = read_state()
        receipts(manifest, state, plan, extra_plan, container, normal, stopped=True)
        receipts(manifest, state, reverse_plan, reverse_extra, peer, peer_normal, stopped=True)
        peer_retired = copy.deepcopy(state["intents"][peer_normal["id"]])
        def validate_peer_state():
            peer.reload(); p.owned(peer, "container", peer_plan)
            p.require(peer.attrs["State"]["Running"] is False, "peer remains stopped at cut")
            _, live, _ = read_state()
            p.require(live["intents"][peer_normal["id"]] == peer_retired, "peer completed/drained intent unchanged")
        peer_owner = stopped_peer_owner(daemon, peer_process, peer_retired, validate_launch, validate_peer_state)
        validate_peer = peer_owner[2]
        validate_peer()
        record("two-volume-normal-stopped", journal=hashes)
        with p.Directory(daemon.root / "managed-prepare-compatibility") as queue:
            start, arm, wait_artifact, artifact, seen = queue_start(queue, {**normal, "intent": normal["id"]}, drain.CASE)
            wait_exit(normal_process)
            process, _ = pending()
            before = processes()
            p.require(process in before and peer_process in before and start.poll() is None, "two independent owned containers before cut")
            armed = wait_artifact(".storage-armed.json")
            worker = p.uid(armed["query"]["workerUUID"])
            p.require(armed["query"] == drain.storage_query(arm, worker) and armed["state"] == "armed", "actual two-volume storage arm")
            interrupted, checkpoint, physical, held_reader = retained_cut(arm=arm, worker=worker,
                wait_artifact=wait_artifact, artifact=artifact, read_state=read_state, record=record, validate_peer=validate_peer)
            # Shared audited storage death / actual exit / explicit API recovery.
            before, context, recovered_owner = restart_storage_at_two_volume_drain(daemon, process, before, interrupted, arm,
                checkpoint, ledger, files, record, processes, remaining, start, read_state, metadata["storageInitramfsSHA256"],
                held_reader=held_reader, worker=worker, physical=physical,
                peer_owner=peer_owner)
            process = next(v for v in before if v.pid == process.pid)
            joined_start(start, failed=True, disconnected=True, vm_recovery=True)
            unchanged_processes(before, processes(), process)
            client, container, peer, volume, extra_volume, image = reattach()
            manifest, recovered_state, hashes = read_state()
            completed = copy.deepcopy(recovered_state["intents"][interrupted["id"]])
            p.require(completed["phase"] == "retired" and completed["prepareCompleted"] is True, "helper joined completed-set recovery")
            # No new capture or arm: existing complete trees, never NORMAL replay.
            joined_start(start_request(container))
            joined_start(start_request(peer))
            manifest, state, hashes = read_state()
            running = []
            for selected, selected_plan, other_plan, old in ((container, plan, extra_plan, completed),
                    (peer, reverse_plan, reverse_extra, peer_retired)):
                matches = [i for i in state["intents"].values() if i["container"] == selected.id and i["phase"] == "running"]
                p.require(len(matches) == 1, "one fresh two-mount owner")
                current = receipts(manifest, state, selected_plan, other_plan, selected, matches[0])
                fresh_owner(old, current, context)
                fresh_owner(completed, current, context, same_container=selected is container)
                current_process = target(current)
                with p.workload_owner(current_process, daemon, selected_plan, current, manifest["root"]) as (owner, current_saved, validate):
                    validate()
                    ordered = volume_records if selected is container else list(reversed(volume_records))
                    drain.capture_from_normal(current, current_saved, ordered, str(uuid.uuid4()))
                    record("two-volume-fresh-owner", native=owner)
                running.append((selected, selected_plan, other_plan, current, current_process))
            p.require(state["intents"][completed["id"]] == completed, "old completed receipts and operations immutable, no ReplacePrepare")
            expected_second = copy.deepcopy(peer_baseline)
            expected_second["root"]["atimeNS"] = physical["sourceAtimes"]["root"]
            for name in p.FILES: expected_second["files"][name]["atimeNS"] = physical["sourceAtimes"][name]
            # Exact namespace excludes staging/transaction names on BOTH volumes.
            # Complete metadata is verified before either fresh writer is invoked.
            for selected, expected in ((container, baseline), (peer, expected_second)):
                p.snapshot(mounts(observe("snapshot", selected)), baseline=expected)
            record("two-volume-all-staging-clean", volumes=[v["id"] for v in volume_records], journal=hashes)
            for selected, expected in ((container, baseline), (peer, expected_second)):
                p.snapshot(mounts(observe("writer", selected)), "writer", baseline=expected)
                p.snapshot(mounts(observe("snapshot", selected)), baseline=expected)
            for name, original in seen.items():
                p.require(queue.read(name, 8192 if name.endswith(".checkpoint.json") else 65536) == original, "all retained carrier evidence immutable")
            image.reload(); p.owned(image, "image", plan)
            p.require(image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"], "same immutable dual source image")
            for selected, selected_plan, other_plan, current, current_process in running:
                selected.stop(timeout=1)
                manifest, state, hashes = read_state()
                receipts(manifest, state, selected_plan, other_plan, selected, current, stopped=True)
                selected.reload(); p.owned(selected, "container", selected_plan); selected.remove()
                wait_exit(current_process)
            survivors = [v for v in before if v not in (process, peer_process)]
            p.require({v.pid: v for v in processes()} == {v.pid: v for v in survivors}, "only exact recovered API/storage survive owned cleanup")
            for selected, selected_plan in ((volume, plan), (extra_volume, extra_plan)):
                selected.reload(); p.owned(selected, "volume", selected_plan); selected.remove()
            client.images.remove(image.id)
            owner_hash = verify_api_owner_final(daemon, recovered_owner)
            record("two-volume-owned-cleanup", ownerSHA256=owner_hash, journal=hashes)
            p.verify_full_ledger(ledger, files)
            return dict(**staged, result="initial-cut-passed", execution="actual-docker-runtime", store=manifest["store"],
                runID=str(uuid.UUID(plan["owner"])), evidenceSHA256=p.digest(p.canonical({name: value[1][-1] for name, value in files.items()})))
