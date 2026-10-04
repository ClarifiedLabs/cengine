"""RTM-100 finite IO-fault inventory; report-only, never an authority credential.

The existing signed full PREPARE carrier owns activation. Selection freezes the
complete finite matrix; only actual fixture completion creates retained outcomes.
Source/unit checks and serialized receipts never constitute native acceptance.
"""
import copy
from dataclasses import asdict, dataclass
import os

import managed_prepare_faults as p


@dataclass(frozen=True)
class IOCase:
    name: str
    point: str
    owner: str
    operation: str
    occurrence: int
    errno: str
    expected: str


# One exact owner operation and its first occurrence, not the next global fsync.
# Authority EIO/ENOSPC preserves the existing durable uncertainty contract;
# workload syscall errors must complete supported rollback and actual drain.
_POINTS = (
    ("copy-operation-write", "storage-authority", "begin", "sticky-uncertainty"),
    ("copy-operation-sync", "storage-authority", "begin", "sticky-uncertainty"),
    ("provision-rename", "storage-authority", "provision", "sticky-uncertainty"),
    ("provision-parent-sync", "storage-authority", "provision", "sticky-uncertainty"),
    ("child-data-fsync", "workload-supervisor", "copy-first-child", "recoverable"),
    ("manifest-write", "workload-supervisor", "write-manifest", "recoverable"),
    ("manifest-fsync", "workload-supervisor", "write-manifest", "recoverable"),
    ("manifest-rename-parent-sync", "workload-supervisor", "publish-manifest", "recoverable"),
    ("seal-persist", "storage-authority", "seal", "sticky-uncertainty"),
    ("public-child-rename", "workload-supervisor", "publish-first-child", "recoverable"),
    ("public-directory-sync", "workload-supervisor", "publish-first-child", "recoverable"),
    ("root-metadata", "workload-supervisor", "apply-root-metadata", "recoverable"),
    ("root-fsync", "workload-supervisor", "sync-published-root", "recoverable"),
    ("cleaning-persist", "storage-authority", "cleanup", "sticky-uncertainty"),
    ("child-unlink-parent-sync", "storage-authority", "finish", "sticky-uncertainty"),
    ("manifest-unlink-parent-sync", "storage-authority", "finish", "sticky-uncertainty"),
    ("transaction-unlink-parent-sync", "storage-authority", "finish", "sticky-uncertainty"),
    ("root-restoration-syncfs", "storage-authority", "finish", "sticky-uncertainty"),
    ("finish-persist", "storage-authority", "finish", "sticky-uncertainty"),
    ("retire-intent-persist", "storage-authority", "retire", "sticky-uncertainty"),
    ("retire-barrier-persist", "storage-authority", "retire", "sticky-uncertainty"),
    ("retire-receipt-persist", "storage-authority", "retire", "sticky-uncertainty"),
    ("retire-barrier-clear-persist", "storage-authority", "retire", "sticky-uncertainty"),
)
CASE_DEFINITIONS = tuple(
    IOCase(f"io-{error.lower()}-{point}", point, owner, operation, 1, error, expected)
    for point, owner, operation, expected in _POINTS for error in ("EIO", "ENOSPC")
)
CASES = tuple(case.name for case in CASE_DEFINITIONS)


def inventory():
    """Fresh report data; callers cannot mutate the frozen case definitions."""
    return {"rtm": "RTM-100", "profile": p.FULL_PROFILE, "caseCount": len(CASES),
            "cases": [asdict(case) for case in CASE_DEFINITIONS],
            "fullAcceptance": False, "nativeExecuted": False}


def selection(profile, cases, fault_case):
    """Validate an exact finite plan before any engine access, not admission."""
    p.require(type(profile) is str and profile == p.FULL_PROFILE, "exact signed full profile required")
    p.require(type(cases) in (tuple, list) and tuple(cases) == CASES, "complete ordered RTM-100 inventory required")
    p.require(type(fault_case) is str and fault_case in CASES, "one closed IO fault per fresh owned run")
    selected = CASE_DEFINITIONS[CASES.index(fault_case)]
    return {"rtm": "RTM-100", "profile": profile, "faultCase": asdict(selected), "fullAcceptance": False}


def require_deployed_case(profile, cases, fault_case):
    """Closed parent selection only; live signed host/guest still own admission."""
    return selection(profile, cases, fault_case)


def case_definition(name):
    p.require(type(name) is str and name in CASES, "closed IO case")
    return CASE_DEFINITIONS[CASES.index(name)]


def expected_start_exit(selected, *, phase):
    """Exact Docker-start subprocess code, not an either/or HTTP oracle."""
    p.require(type(selected) is IOCase and selected == case_definition(selected.name), "closed IO case definition")
    p.require(phase in ("initial-failure", "quarantine-retry"), "closed IO start phase")
    family = (selected.owner, selected.expected)
    p.require(family in (("workload-supervisor", "recoverable"),
                        ("storage-authority", "sticky-uncertainty")), "closed IO failure family")
    if phase == "quarantine-retry":
        p.require(selected.expected == "sticky-uncertainty", "sticky quarantine retry required")
        return 49  # Existing quarantine guard: HTTP 409, independent of first failure.
    return 49 if family == ("workload-supervisor", "recoverable") else 50  # HTTP 409 / 500.


def arm_candidate(candidate, capture, previous, case):
    case_definition(case)
    return p._arm_candidate(candidate, capture, previous, case, version=3,
                            profile=p.FULL_PROFILE, cases=CASES)


def storage_query(arm, worker):
    selected = case_definition(arm["caseName"])
    p.require(selected.owner == "storage-authority" and type(arm["version"]) is int
              and arm["version"] == 3 and arm["profile"] == p.FULL_PROFILE, "authority IO arm")
    return dict(version=3, profile=p.FULL_PROFILE, requestID=p.uid(arm["requestID"]),
                armDigest=p.digest(p.canonical(arm)), workerUUID=p.uid(worker))


def io_cut(value, selected, *, storage):
    fields = {"point", "errno", "occurrence"}
    p.exact(value, fields | ({"requestSequence", "retireOperation"} if storage else set()))
    p.require(value["point"] == selected.point and value["errno"] == selected.errno
              and type(value["occurrence"]) is int and value["occurrence"] == 1, "exact one injected operation/errno")
    if storage:
        p.integer(value["requestSequence"])
        if selected.operation == "retire":
            p.require(value["requestSequence"] == 0, "retirement is not a DATA request")
            p.uid(value["retireOperation"])
        else:
            p.require(value["requestSequence"] > 0 and value["retireOperation"] == "", "actual owned DATA request")
    return value


def observation(value, arm, worker=None):
    selected = case_definition(arm["caseName"])
    p.require(type(arm["version"]) is int and arm["version"] == 3
              and arm["profile"] == p.FULL_PROFILE, "signed full-profile IO arm")
    query = (storage_query(arm, worker) if selected.owner == "storage-authority" else
             dict(version=3, profile=p.FULL_PROFILE, requestID=p.uid(arm["requestID"]),
                  armDigest=p.digest(p.canonical(arm))))
    storage = selected.owner == "storage-authority"
    p.require(storage == (worker is not None), "correct observation owner domain")
    payload = {"io"} if storage else {"copyIntent", "point", "errno", "occurrence"}
    p.exact(value, {*query, "stage", "count", "targetAttachment", *payload})
    p.require(all(type(value[k]) is type(v) and value[k] == v for k, v in query.items())
              and value["stage"] == selected.name and type(value["count"]) is int
              and value["count"] == 1 and value["targetAttachment"] == arm["targetAttachment"],
              "IO checkpoint exact arm/worker/owner")
    if storage:
        io_cut(value["io"], selected, storage=True)
    else:
        p.uid(value["copyIntent"])
        io_cut({k: value[k] for k in ("point", "errno", "occurrence")}, selected, storage=False)
    p.require(len(p.canonical(value)) <= 8192, "bounded IO observation")
    return value


def armed_status(value, arm, worker):
    p.exact(value, {"query", "state", "retirementStarted", "acceptedInFlight",
                    "lateAdmissionRejected", "receiptReplayCount"})
    p.require(p.canonical(value["query"]) == p.canonical(storage_query(arm, worker))
              and value["state"] == "armed" and value["retirementStarted"] is False
              and value["lateAdmissionRejected"] is False
              and type(value["acceptedInFlight"]) is int and value["acceptedInFlight"] == 0
              and type(value["receiptReplayCount"]) is int and value["receiptReplayCount"] == 0,
              "actual initial authority IO acknowledgment")
    return value


def sticky_intent(state, arm):
    p.require(case_definition(arm["caseName"]).expected == "sticky-uncertainty", "sticky case required")
    intent = state["intents"][arm["scope"]["intent"]]
    p.require(all(intent[k if k != "intent" else "id"] == v for k, v in arm["scope"].items()), "sticky exact scope")
    p.require(intent["phase"] == "quarantined" and intent["prepareCompleted"] is False
              and intent.get("quarantineReason") and intent.get("successor") is None, "durable unresolved PREPARE quarantine")
    p.require(len(intent["slots"]) == len(arm["slots"]), "complete sticky slots")
    p.require(sorted(({k: s[k] for k in ("volume", "attachment", "role", "mode")} for s in intent["slots"]),
                     key=lambda s: s["attachment"]) == arm["slots"], "same full attachment census")
    keys = {c["attachment"]: c["key"] for c in arm["credentials"]}
    for slot in intent["slots"]:
        p.require(slot.get("receipt") is None, "no successful drain receipt on uncertain IO")
        p.require(slot.get("key") == (keys[slot["attachment"]] if slot["role"] == "prepare" else None),
                  "no runtime grant or changed PREPARE credential")
    return copy.deepcopy(intent)


def sticky_unchanged(before, after, arm):
    sticky_intent(before, arm); sticky_intent(after, arm)
    p.require(before == after, "refused retry must not mutate uncertain journal or admit another initializer")


_LIVE_OUTCOMES = {}


class IOOutcome:
    """Same retained external-ledger model as RTM096; serialized rows cannot pass."""
    def __init__(self):
        raise TypeError("only the completed live IO fixture creates IOOutcome")

    @property
    def receipt(self):
        return copy.deepcopy(self._receipt)

    def validate(self):
        p.require(_LIVE_OUTCOMES.get(id(self)) is self, "retained direct IO outcome required")
        p.verify_full_ledger(self._directory, self._files)
        validate_case_evidence([p.decode(self._files[name][0]) for name in sorted(self._files)], self._receipt)
        return self.receipt

    def close(self):
        _LIVE_OUTCOMES.pop(id(self), None)
        self._directory.close()


def carrier_census(queue):
    """Pin the COMPLETE queue, so an extra retry artifact cannot hide."""
    queue.validate()
    with os.scandir(queue.fd) as entries:
        names = sorted(entry.name for entry in entries)
    p.require(len(names) <= 257, "bounded complete carrier census")
    return {name: queue.read(name, 65536, pin_file=True) for name in names}


def preserve_observed_carrier(census, observed):
    p.require(all(census.get(name) == original for name, original in observed.items()),
              "complete census must preserve originally validated carrier evidence")


def validate_case_evidence(rows, receipt):
    """Rejection-only structural corroboration, never a receipt-to-capability API."""
    p.require(type(rows) is list and rows and rows[-1] == {"phase": "io-case-result", **receipt}, "exact terminal IO result")
    selected = case_definition(receipt["caseName"])
    phases = {row["phase"] for row in rows}
    common = {"plan", "assets", "both-created", "normal-owned", "normal-stopped-drained",
              "capture-intent", "arm-intent", "guest-armed", "checkpoint-external-fsync",
              "production-channel-failure-contained", "docker-start-joined"}
    required = ({"sticky-quarantine-no-drain", "sticky-evidence-retained"} if selected.expected == "sticky-uncertainty"
                else {"production-quarantine-drain", "retry-source-witness", "recovered-runtime", "owned-cleanup"})
    p.require(common | required <= phases and "failure" not in phases, "complete live IO lifecycle evidence required")
    p.require(rows[0]["phase"] == "plan" and rows[0]["staged"]["faultCase"] == asdict(selected), "predeclared exact IO case")
    p.require(p.digest(p.canonical([p.digest(p.canonical(row)) for row in rows[:-1]])) == receipt["evidenceSHA256"], "complete IO ledger hash")


def aggregate(outcomes):
    p.require(type(outcomes) is list and len(outcomes) == len(CASES)
              and all(type(o) is IOOutcome for o in outcomes), "46 retained direct IO outcomes required")
    rows = [o.validate() for o in outcomes]
    cases, runs, stores, directories = set(), set(), set(), set()
    for outcome, row in zip(outcomes, rows):
        p.exact(row, {"rtm", "profile", "caseName", "runID", "store", "result", "expected", "execution", "evidenceSHA256", "fullAcceptance"})
        selected = case_definition(row["caseName"])
        p.require(row["rtm"] == "RTM-100" and row["profile"] == p.FULL_PROFILE
                  and row["expected"] == selected.expected and row["result"] == selected.expected + "-passed"
                  and row["execution"] == "actual-docker-runtime" and row["fullAcceptance"] is False, "exact predeclared IO outcome")
        p.uid(row["runID"]); p.uid(row["store"]); p.pin(row["evidenceSHA256"])
        directory = p.Directory.stamp(os.fstat(outcome._directory.fd))[:2]
        p.require(row["caseName"] not in cases and row["runID"] not in runs and row["store"] not in stores
                  and directory not in directories, "unique case/fresh Daemon/external ledger")
        cases.add(row["caseName"]); runs.add(row["runID"]); stores.add(row["store"]); directories.add(directory)
    p.require(cases == set(CASES), "complete exact RTM-100 matrix")
    return dict(rtm="RTM-100", result="full-acceptance-passed", cases=len(CASES),
                recoverableCases=16, stickyContainedCases=30, physicalPowerLoss=False,
                receiptsSHA256=p.digest(p.canonical(sorted(rows, key=lambda row: row["caseName"]))))
