"""Retained selected-configuration observation; never workload/boot authority.

Wire source: ManagedStorageLifecyclePeerObservation.swift. ROOT and the actual
native storage launch are independently correlated; existing workload proof is
still mandatory. No address or TLS bytes are synthesized from checkpoint pins.
"""
from contextlib import ExitStack
import os
from pathlib import Path
import socket
import uuid

import managed_prepare_faults as p
import managed_original_lifecycle_evidence as original
import managed_prepare_lifecycle_evidence as lifecycle


def observation(raw, projection):
    value = p.decode(raw, 65536)
    p.exact(value, {"version", "binding", "ready", "peer"})
    p.integer(value["version"], 1, 1)
    binding, ready, peer = value["binding"], value["ready"], value["peer"]
    p.exact(binding, {"shimLaunchUUID", "guestBootNonce", "ext4UUID", "bytes"})
    for field in ("shimLaunchUUID", "guestBootNonce"): p.uid(binding[field])
    p.integer(binding["bytes"], 2**63 - 1, 1)
    filesystem = binding["ext4UUID"]
    p.require(type(filesystem) is str and str(uuid.UUID(filesystem)) == filesystem
        and uuid.UUID(filesystem).int != 0, "canonical nonzero ext4 UUID")
    p.exact(ready, {"identity", "service_epoch", "worker_uuid", "controller_epoch", "controller_key",
        "revision", "open_revision", "bootstrap_key", "tls_root_der", "server_der", "server_spki"})
    p.exact(ready["identity"], {"store", "generation", "binding"})
    p.uid(ready["identity"]["store"]); p.integer(ready["identity"]["generation"], minimum=1)
    p.pin(ready["identity"]["binding"])
    for field in ("service_epoch", "worker_uuid"): p.uid(ready[field])
    for field in ("controller_epoch", "revision", "open_revision"): p.integer(ready[field], minimum=1)
    for field in ("controller_key", "bootstrap_key", "server_spki"): p.pin(ready[field])
    record = projection["workerEvidence"]
    owner, _ = original.owner(record)
    checkpoint = record["checkpoint"]
    service = checkpoint["currentService"]
    p.require(ready["identity"] == checkpoint["identity"] == service["boot"]["identity"]
        and ready["worker_uuid"] == checkpoint["observedWorker"]["workerUUID"]
        and all(ready[key] == service["context"][key] for key in service["context"])
        and ready["bootstrap_key"] == service["boot"]["bootstrap_key"]
        and ready["server_spki"] == service["boot"]["server_spki"]
        and ready["revision"] >= ready["open_revision"] == service["open_revision"],
        "exact ROOT service identity/context/open revision and observed worker")
    p.require(binding["ext4UUID"] == owner["ext4UUID"] and binding["bytes"] == owner["bytes"],
        "exact ROOT physical backing selection")
    p.exact(peer, {"tlsRootDER", "serverDER", "serverKey", "dataAddress"})
    p.require(peer["tlsRootDER"] == ready["tls_root_der"] and peer["serverDER"] == ready["server_der"]
        and peer["serverKey"] == ready["server_spki"], "exact selected peer Ready bytes")
    address = peer["dataAddress"]
    p.require(type(address) is str and 0 < len(address.encode()) <= 45 and "\0" not in address,
        "actual bounded IP address")
    valid = False
    for family in (socket.AF_INET, socket.AF_INET6):
        try: socket.inet_pton(family, address); valid = True
        except OSError: pass
    p.require(valid, "actual IP string, not guessed host/port")
    original.comparison(projection, peer)  # Existing bounded DER/SPKI/hash comparison.
    return value, owner


class PeerReader:
    """Keep both immutable observations and native generation inputs open to finish."""
    def __init__(self, daemon, processes):
        self.daemon, self.processes = daemon, processes
        self.stack = ExitStack()
        self.directories, self.files, self.selections = {}, {}, []

    def __enter__(self):
        try:
            self.root = self.stack.enter_context(p.Directory(self.daemon.root))
            self.queue = self.directory(self.root.path / "managed-prepare-compatibility")
            return self
        except BaseException:
            self.stack.close(); raise

    def directory(self, path):
        path = Path(path)
        if path not in self.directories:
            self.directories[path] = self.stack.enter_context(p.Directory(path))
        return self.directories[path]

    def retained(self, path, maximum):
        path = Path(path)
        directory = self.directory(path.parent)
        pinned = directory.read(path.name, maximum, pin_file=path not in self.files)
        if path in self.files:
            p.require(pinned == self.files[path][0], "immutable peer/native input changed")
        else: self.files[path] = pinned, maximum
        return pinned

    def native_read(self, path):
        pinned = self.retained(path, 1048576)
        return p.decode(pinned[0], 1048576, canonical_only=False), pinned[1][-1]

    def __call__(self, projection):
        p.require(original.is_v2(projection), "explicit v2 peer observation")
        owner, _ = original.owner(projection["workerEvidence"])
        epoch = p.integer(projection["workerEvidence"]["checkpoint"]["currentService"]["context"]["controller_epoch"], minimum=1)
        name = "lifecycle-peer-" + p.uid(owner["workerUUID"]) + "-" + str(epoch) + ".json"
        pinned = self.retained(self.queue.path / name, 65536)
        value, owner = observation(pinned[0], projection)
        info = os.fstat(self.root.fd)
        p.require((info.st_dev, info.st_ino) == (owner["root"]["device"], owner["root"]["inode"]),
            "actual physical ROOT directory")
        binding = value["binding"]
        if self.selections:
            p.require(binding == self.selections[0][0], "same native boot for worker replacement")
        native_owner = {**owner, "shimLaunchUUID": binding["shimLaunchUUID"]}
        selected = lifecycle.storage_target(self.daemon, native_owner, self.processes(), self.native_read)
        self.selections.append((binding, native_owner, selected))
        p.require(len(self.selections) <= 2, "bounded predecessor/successor peer selection")
        self.validate()
        return value["peer"]

    def validate(self):
        self.root.validate()
        for path, (pinned, maximum) in list(self.files.items()):
            p.require(self.directory(path.parent).read(path.name, maximum) == pinned,
                "retained immutable peer/native input changed")
        for _, owner, selected in self.selections:
            p.require(lifecycle.storage_target(self.daemon, owner, self.processes(), self.native_read) == selected,
                "same actual native storage owner through finish")

    def __exit__(self, *_):
        try: self.validate()
        finally: self.stack.close()
