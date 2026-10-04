#!/usr/bin/env python3
"""Parent-owned RTM-096 full, RTM-097/099 restart, RTM-100 IO and RTM-103 campaigns.

Invoke through tools/managed-prepare-matrix.sh, which builds and signs the
managed test-compat pair, validates the caller-provided full-nine assets and
the installed helper, exports the helper environment and takes the compat lock.

Each cell runs on a fresh retained Daemon: one owned work root, one external
evidence directory, one live outcome. Complete live campaigns aggregate through
their proof validator; receipts and partial selections never do. RTM-100 has 46
cells (16 recoverable, 30 sticky). Sticky roots remain retained for explicit
parent investigation/disposal. They live outside reset's temporary-root scan:
a successful wrapper cleanup is not proof of their disposal. Any failure retains
its root and evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "Tests/Compatibility"))

import conftest  # noqa: E402
import harness  # noqa: E402
import managed_original_followup_parent as followup_parent  # noqa: E402
import managed_prepare_faults as proof  # noqa: E402
import managed_prepare_restart_matrix as matrix  # noqa: E402
import managed_prepare_vm_boundaries as vm  # noqa: E402
import managed_stale_consumer as stale  # noqa: E402
import test_managed_prepare_faults as fixture  # noqa: E402

CAMPAIGNS = {"RTM-096": list(proof.FULL_CASES),
    **{rtm: list(proof.FULL_CASES) for rtm in matrix.MATRICES}, "RTM-103": list(stale.IMPLEMENTED_CASES)}
# stale.IMPLEMENTED_CASES stays unchanged; the runner unions the three
# source-ready follow-up routes, each dispatched with its own per-route budget.
CAMPAIGNS["RTM-103"] += list(followup_parent.FOLLOWUP_CASES)
# Keep this catalog assignment self-contained for offline runner discovery,
# which evaluates catalog assignments without importing the engine fixtures.
CAMPAIGNS["RTM-100"] = list(__import__("managed_prepare_io_faults").CASES)
# Nine worker-exit cells: held A4/A5 keep the strict StorageRelease route; the
# other seven cuts use the generic checkpoint-exit route. Per-cell reports only;
# never aggregate these as nine.
CAMPAIGNS["RTM-098"] = [case for case in proof.FULL_CASES
    if case in set(proof.WORKER_EXIT_CASES) | set(proof.CHECKPOINT_EXIT_CASES)]
# Explicit opt-in only; never extend a default campaign or aggregate addons.
ADDON_CASES = {"RTM-098": ("worker-a5-active-ack",),
    "RTM-099": ("vm-two-volume-drain-reply-gap", *vm.CASES, "vm-private-bound-active-ack")}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def selected_cases(rtm: str, cases=None) -> list[str]:
    require(rtm in CAMPAIGNS, "unknown campaign")
    selected = list(CAMPAIGNS[rtm] if cases is None else cases)
    require(all(case in CAMPAIGNS[rtm] or case in ADDON_CASES.get(rtm, ()) for case in selected),
            "case outside the selected campaign")
    require(len(selected) == len(set(selected)), "duplicate case selection")
    return selected


def is_active_ack(rtm: str, case: str) -> bool:
    return (rtm, case) in (("RTM-098", "worker-a5-active-ack"), ("RTM-099", "vm-private-bound-active-ack"))


def prepare_descriptor_budget(*, io_count=0, evidence_root=None) -> int:
    # Nine live MatrixOutcomes intentionally retain every evidence inode until
    # aggregation (up to 60 files + pinned ancestors each), while the next cell
    # owns its own queue/ledger. Darwin's default 256 cannot hold that proof.
    # Set a bounded parent budget before starting any VM; do not drop pins or
    # turn serialized receipts into live outcomes to work around exhaustion.
    required = 2048
    if io_count:
        require(type(io_count) is int and 0 < io_count <= len(CAMPAIGNS["RTM-100"]), "bounded IO ledger count")
        require(isinstance(evidence_root, Path), "IO evidence path required")
        # record() caps each ledger at 60 files. Directory pins every ancestor,
        # including / and the per-cell leaf. Reserve 1024 more descriptors
        # for the active queue (up to 257 files, censused twice), duplicate
        # ledger and runtime overhead; small selections keep the existing 2048.
        pins_per_ledger = 60 + len(evidence_root.resolve().parts) + 1
        needed = max(2048, 1024 + io_count * pins_per_ledger)
        require(needed <= 8192, "IO evidence path exceeds bounded descriptor budget")
        required = ((needed + 1023) // 1024) * 1024
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY or soft >= required:
        return soft
    require(hard == resource.RLIM_INFINITY or hard >= required,
            f"matrix requires a descriptor hard limit of at least {required}")
    resource.setrlimit(resource.RLIMIT_NOFILE, (required, hard))
    actual, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    require(actual == resource.RLIM_INFINITY or actual >= required, "matrix descriptor budget not installed")
    return actual


def sha256(path: Path, maximum=64 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            maximum -= len(chunk)
            require(maximum >= 0, "bounded file digest")
            digest.update(chunk)
    return digest.hexdigest()


def build_probe(output: Path, *, active_ack: bool = False) -> tuple[Path, str]:
    """Pinned offline linux/arm64 build of one fixed Go helper."""
    require(type(active_ack) is bool, "boolean ACK probe selection required")
    name = "managed-storage-recovery" if active_ack else "managed-prepare-faults"
    go = subprocess.run(["/bin/sh", str(REPO_ROOT / "Scripts/ensure-go-toolchain.sh")], check=True,
                        text=True, stdout=subprocess.PIPE).stdout.strip()
    output.mkdir(parents=True, exist_ok=True)
    probe = output / name
    cache = output / "go-cache"
    env = {key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ}
    env.update(TMPDIR=os.environ.get("TMPDIR", "/tmp"), GOCACHE=str(cache / "build"), GOMODCACHE=str(cache / "mod"),
               GOENV="off", GOFLAGS="", GOWORK="off", GO111MODULE="on", GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off",
               CGO_ENABLED="0", GOOS="linux", GOARCH="arm64", GOARM64="v8.0")
    subprocess.run([go, "build", "-mod=vendor", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=",
                    "-o", str(probe), f"../Tests/Compatibility/fixtures/{name}.go"],
                   cwd=REPO_ROOT / "Guest", env=env, check=True)
    return probe, sha256(probe)


def asset_metadata(assets: Path) -> dict:
    subprocess.run([sys.executable, str(REPO_ROOT / "Scripts/check-managed-guest-assets.py"), str(assets)], check=True)
    metadata = json.loads((assets / "disk-bootstrap.json").read_text())
    require(metadata.get("prepareCompatibilityProfile") == proof.FULL_PROFILE, "full-nine profile assets required")
    pin = subprocess.run([sys.executable, str(REPO_ROOT / "Scripts/prepare_compatibility_assets.py"), "source-pin", str(REPO_ROOT)],
                         check=True, text=True, stdout=subprocess.PIPE).stdout.strip()
    require(metadata.get("prepareCompatibilitySourceSHA256") == pin, "assets were built from a different guest source tree")
    return metadata


def expected_commit(binary: Path) -> str:
    version = subprocess.run([str(binary), "version"], check=True, text=True, stdout=subprocess.PIPE).stdout
    commit = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"], cwd=REPO_ROOT, check=True,
                            text=True, stdout=subprocess.PIPE).stdout.strip()
    require(version.strip(), "binary reports a version")
    return commit


# The fixture pins directories by physical path (or the /tmp alias only), and
# the daemon spells its generation paths canonically, so cell roots must not
# live under a symlinked temporary directory such as /var/folders. The prior
# native campaigns used this owner-private cache location for the same reason.
WORK_PARENT = Path.home() / "Library/Caches/cengine-compat-matrix"


def run_cell(rtm: str, case: str, *, binary: Path, assets: Path, probe: Path, probe_sha256: str,
             source_sha256: str, commit: str, evidence_root: Path, log,
             ack_probe: Path | None = None, ack_probe_sha256: str | None = None):
    selected_cases(rtm, [case])
    active_ack = is_active_ack(rtm, case)
    if active_ack:
        require(isinstance(ack_probe, Path) and ack_probe.is_file(), "ACK addon requires a built probe")
        proof.pin(ack_probe_sha256)
        require(sha256(ack_probe) == ack_probe_sha256, "ACK probe hash mismatch")
    else:
        require(ack_probe is None and ack_probe_sha256 is None, "ACK probe only allowed for its addon")
    WORK_PARENT.mkdir(mode=0o700, exist_ok=True)
    require(WORK_PARENT.resolve() == WORK_PARENT and not WORK_PARENT.stat().st_mode & 0o077, "owner-private physical work parent")
    work = Path(tempfile.mkdtemp(prefix="cengine-compat-", dir=str(WORK_PARENT)))
    require(len(os.fsencode(work / "run/docker.sock")) < 104, "Darwin API socket path bound")
    daemon = conftest.Daemon(binary=binary, kernel=assets / "vmlinux",
                             container_initramfs=assets / "container-initramfs.cpio.gz",
                             storage_initramfs=assets / "storage-initramfs.cpio.gz", work=work)
    receipt = harness.preretain_compatibility_root(work, binary)
    daemon._managed_fixture_retention = True
    evidence = evidence_root / f"{rtm}-{case}-{work.name}"
    evidence.mkdir(mode=0o700)
    log(f"{rtm} {case}: daemon root {work}")
    started = time.monotonic()
    outcome = None
    clean = False
    try:
        daemon.start()
        if active_ack:
            shard = fixture.run_worker_a5_active_ack_shard if rtm == "RTM-098" else fixture.run_storage_private_active_ack_shard
            outcome = shard(daemon, profile=proof.FULL_PROFILE,
                probe=probe, probe_sha256=probe_sha256, ack_probe=ack_probe, ack_probe_sha256=ack_probe_sha256,
                source_sha256=source_sha256, expected_commit=commit, evidence=evidence)
            proof.exact(outcome, {"rtm", "boundary", "result", "fullAcceptance", "profile", "execution",
                                  "runID", "store", "evidenceSHA256"})
            require(outcome["rtm"] == rtm and outcome["boundary"] == case
                    and outcome["result"] == "initial-cut-passed" and outcome["fullAcceptance"] is False
                    and outcome["profile"] == proof.FULL_PROFILE and outcome["execution"] == "actual-docker-runtime",
                    "exact ACK addon report required")
            proof.uid(outcome["runID"]); proof.uid(outcome["store"]); proof.pin(outcome["evidenceSHA256"])
            log(f"{rtm} {case}: {outcome['result']} in {time.monotonic() - started:.2f}s (no full matrix acceptance)")
        elif rtm == "RTM-099" and case in vm.CASES:
            # These entries require the complete ordered VM catalog, even for one cut.
            shard = {"vm-private-bound": fixture.run_storage_private_shard,
                     "vm-root-synced-before-cleanup": fixture.run_storage_root_shard,
                     "vm-cleaning-transaction-removed": fixture.run_storage_cleaning_shard}[case]
            outcome = shard(daemon, profile=proof.FULL_PROFILE, cases=vm.CASES,
                probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256,
                expected_commit=commit, evidence=evidence)
            selected = vm.selection(proof.FULL_PROFILE, vm.CASES, case)
            proof.exact(outcome, {*selected, "rtm", "boundary", "result", "execution",
                                  "runID", "store", "evidenceSHA256"})
            require(all(outcome[key] == value for key, value in selected.items())
                    and outcome["rtm"] == rtm and outcome["boundary"] == case
                    and outcome["result"] == "initial-cut-passed" and outcome["fullAcceptance"] is False
                    and outcome["execution"] == "actual-docker-runtime", "exact RTM-099 VM addon report required")
            proof.uid(outcome["runID"]); proof.uid(outcome["store"]); proof.pin(outcome["evidenceSHA256"])
            log(f"{rtm} {case}: {outcome['result']} in {time.monotonic() - started:.2f}s (no full matrix acceptance)")
        elif rtm == "RTM-099" and case == "vm-two-volume-drain-reply-gap":
            # This fixture requires its singleton catalog, not the full-nine matrix catalog.
            outcome = fixture.run_two_volume_drain_shard(daemon, profile=proof.FULL_PROFILE, cases=(case,),
                probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256,
                expected_commit=commit, evidence=evidence)
            proof.exact(outcome, {"rtm", "boundary", "caseName", "runnable", "result", "fullAcceptance",
                                  "profile", "execution", "runID", "store", "evidenceSHA256"})
            require(outcome["rtm"] == rtm and outcome["boundary"] == case and outcome["caseName"] == case
                    and outcome["runnable"] is True and outcome["result"] == "initial-cut-passed"
                    and outcome["fullAcceptance"] is False and outcome["profile"] == proof.FULL_PROFILE
                    and outcome["execution"] == "actual-docker-runtime", "exact RTM-099 two-volume addon report required")
            proof.uid(outcome["runID"]); proof.uid(outcome["store"]); proof.pin(outcome["evidenceSHA256"])
            log(f"{rtm} {case}: {outcome['result']} in {time.monotonic() - started:.2f}s (no full matrix acceptance)")
        elif rtm == "RTM-103" and case in followup_parent.FOLLOWUP_CASES:
            outcome = followup_parent.run_followup_route(daemon, case=case, profile=proof.FULL_PROFILE, cases=stale.CASES,
                probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=commit,
                evidence=evidence, log=log)
            require(type(outcome) is dict and outcome.get("rtm") == "RTM-103" and outcome.get("caseName") == case
                    and outcome.get("result") == "followup-route-passed" and outcome.get("execution") == "actual-docker-runtime"
                    and outcome.get("fullAcceptance") is False and outcome.get("nativeAcceptance") is False,
                    "exact RTM-103 follow-up route report required")
            log(f"{rtm} {case}: {outcome['result']} in {time.monotonic() - started:.2f}s")
        elif rtm == "RTM-103":
            outcome = fixture.run_original_consumer_shard(daemon, profile=proof.FULL_PROFILE, cases=stale.CASES, case=case,
                probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=commit, evidence=evidence)
            require(type(outcome) is dict and outcome.get("rtm") == "RTM-103" and outcome.get("caseName") == case
                    and outcome.get("result") == "case-passed" and outcome.get("execution") == "actual-docker-runtime"
                    and outcome.get("fullAcceptance") is False, "exact RTM-103 case report required")
            log(f"{rtm} {case}: {outcome['result']} in {time.monotonic() - started:.2f}s")
        elif rtm == "RTM-098":
            shard = fixture.run_checkpoint_exit_shard if case in proof.CHECKPOINT_EXIT_CASES else fixture.run_worker_admission_shard
            outcome = shard(daemon, profile=proof.FULL_PROFILE, fault_case=case,
                probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=commit, evidence=evidence)
            require(type(outcome) is dict and outcome.get("rtm") == rtm and outcome.get("caseName") == case
                    and outcome.get("result") == "initial-cut-passed" and outcome.get("execution") == "actual-docker-runtime"
                    and outcome.get("fullAcceptance") is False, "exact worker cut report required")
            log(f"{rtm} {case}: {outcome['result']} in {time.monotonic() - started:.2f}s (no full matrix acceptance)")
        elif rtm == "RTM-096":
            outcome = fixture.run_full_shard(daemon, profile=proof.FULL_PROFILE, cases=proof.FULL_CASES,
                fault_case=case, probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256,
                expected_commit=commit, evidence=evidence)
            require(type(outcome) is proof.FullOutcome, "actual live FullOutcome required")
            row = outcome.validate()
            log(f"{rtm} {case}: {row['result']} in {time.monotonic() - started:.2f}s")
        elif rtm == "RTM-100":
            import managed_prepare_io_faults as io
            outcome = fixture.run_io_shard(daemon, profile=proof.FULL_PROFILE, cases=io.CASES,
                fault_case=case, probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256,
                expected_commit=commit, evidence=evidence)
            require(type(outcome) is io.IOOutcome, "actual live IOOutcome required")
            row = outcome.validate()
            proof.exact(row, {"rtm", "profile", "caseName", "runID", "store", "result", "expected",
                              "execution", "evidenceSHA256", "fullAcceptance"})
            expected = io.case_definition(case).expected
            require(row["rtm"] == rtm and row["profile"] == proof.FULL_PROFILE and row["caseName"] == case
                    and row["expected"] == expected and row["result"] == expected + "-passed"
                    and row["execution"] == "actual-docker-runtime" and row["fullAcceptance"] is False,
                    "exact predeclared IO outcome required")
            proof.uid(row["runID"]); proof.uid(row["store"]); proof.pin(row["evidenceSHA256"])
            log(f"{rtm} {case}: {row['result']} in {time.monotonic() - started:.2f}s")
        else:
            outcome = fixture.run_restart_matrix_shard(daemon, rtm=rtm, profile=proof.FULL_PROFILE, cases=proof.FULL_CASES,
                fault_case=case, probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256,
                expected_commit=commit, evidence=evidence)
            require(type(outcome) is matrix.MatrixOutcome, "actual live MatrixOutcome required")
            row = outcome.validate()
            log(f"{rtm} {case}: {row['result']} variant={row['variant']} in {time.monotonic() - started:.2f}s")
        clean = True
        return outcome
    finally:
        try:
            daemon.stop()
        finally:
            remaining = harness.terminate_compatibility_runtime(binary, roots=(daemon.root,))
            if remaining:
                log(f"{rtm} {case}: terminated {[p.pid for p in remaining]} at teardown")
        if clean and not daemon._retain_root and daemon.process is not None and daemon.process.poll() is not None \
                and not harness.compatibility_runtime_processes(binary, roots=(daemon.root,)):
            if harness.release_compatibility_root(work, binary, receipt) and harness.remove_compatibility_root(work, binary):
                log(f"{rtm} {case}: owned root removed")
            else:
                log(f"{rtm} {case}: owned root retained (release refused) {work}")
        else:
            log(f"{rtm} {case}: root retained for evidence {work}")


def admit_environment(assets: Path) -> Path:
    """Close the direct entry route before producing any campaign evidence."""
    for key in ("CENGINE_COMPAT_MANAGED_STORAGE", "CENGINE_COMPAT_SHARED_STORAGE"):
        require(key not in os.environ, f"{key} is retired; lifecycle is the default")
    for key, expected in (
        ("PREPARE_COMPATIBILITY_PROFILE", proof.FULL_PROFILE),
        ("CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY", proof.FULL_PROFILE),
        ("CENGINE_COMPAT_REQUIRE_EXACT_HELPER", "1"),
    ):
        require(os.environ.get(key) == expected, f"{key}={expected} required")
    for key in ("CENGINE_STORAGE_LIFECYCLE_QUALIFICATION", "CENGINE_COMPAT_LIFECYCLE_FAULT"):
        require(not os.environ.get(key), f"{key} cannot be combined with the full PREPARE matrix")
    require(os.environ.get("CENGINE_DEVELOPER_ID_APPLICATION"), "signed managed campaign identity required")
    require(os.environ.get("XCODE_COMPAT_CONFIGURATION", "test-compat") == "test-compat",
            "derived test-compat configuration required")
    derived = (REPO_ROOT / (os.environ.get("XCODE_DERIVED_DATA") or ".build/xcode-derived")).resolve()
    require(os.environ.get("CENGINE_BINARY"), "CENGINE_BINARY required")
    binary = (REPO_ROOT / os.environ["CENGINE_BINARY"]).resolve()
    require(binary == derived / "Build/Products/test-compat/cengine" and binary.is_file(),
            "derived test-compat binary required")
    selected_assets = os.environ.get("CENGINE_COMPAT_MANAGED_ASSET_DIR")
    require(selected_assets and (REPO_ROOT / selected_assets).resolve() == assets,
            "selected managed assets must match --assets")
    fingerprint = os.environ.get("CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT")
    require(fingerprint, "helper environment required; use tools/managed-prepare-matrix.sh")
    # Reuse the read-only installed/signature/exact-code/authenticated-health
    # checks, not a wrapper receipt. ROOT is required by the shared policy gate.
    subprocess.run(["/bin/sh", "-eu", "-c", '''
ROOT=$1
. "$ROOT/Scripts/compat-network-helper.sh"
[ "${CENGINE_NETWORK_HELPER_SERVICE_NAME:-}" = "$compat_network_helper_service_name" ] &&
[ "${CENGINE_NETWORK_HELPER_IDENTIFIER:-}" = "$compat_network_helper_label" ] &&
[ "${CENGINE_NETWORK_HELPER_AUTH_TOKEN_FILE:-}" = "$compat_network_helper_token_path" ] &&
[ "${CENGINE_COMPAT_NETWORK_HELPER_LABEL:-}" = "$compat_network_helper_label" ] || {
    echo 'managed PREPARE requires the exported compatibility helper environment' >&2
    exit 2
}
compat_network_helper_require "$CENGINE_BINARY" "$CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT"
''', "managed-prepare-admission", str(REPO_ROOT)], check=True, cwd=REPO_ROOT,
        env={**os.environ, "CENGINE_BINARY": str(binary), "CENGINE_COMPAT_MANAGED_ASSET_DIR": str(assets)})
    return binary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rtm", required=True, choices=sorted(CAMPAIGNS))
    parser.add_argument("--case", action="append",
                        help="one or more campaign cases (RTM-098 also accepts worker-a5-active-ack; "
                             "RTM-099 also accepts vm-private-bound, vm-root-synced-before-cleanup, "
                             "vm-cleaning-transaction-removed, vm-private-bound-active-ack, "
                             "vm-two-volume-drain-reply-gap); RTM-100 defaults to all 46 IO cases; "
                             "subsets never aggregate; default excludes addons")
    parser.add_argument("--assets", required=True, type=Path, help="full-nine profile managed guest asset directory")
    parser.add_argument("--evidence", required=True, type=Path, help="external evidence root (created if absent)")
    parser.add_argument("--continue-on-failure", action="store_true",
                        help="keep running later cells after a failed cell (its root and evidence stay retained); no aggregate")
    arguments = parser.parse_args()
    cases = selected_cases(arguments.rtm, arguments.case)
    assets = arguments.assets.resolve()
    binary = admit_environment(assets)
    evidence_root = arguments.evidence.resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    log_path = evidence_root / f"runner-{arguments.rtm}-{stamp}.log"
    def log(message):
        line = f"{time.strftime('%H:%M:%S')} {message}"
        print(line, flush=True)
        with log_path.open("a") as stream:
            stream.write(line + "\n")
    metadata = asset_metadata(assets)
    probe, probe_sha256 = build_probe(evidence_root / "probe")
    ack_probe = ack_probe_sha256 = None
    if any(is_active_ack(arguments.rtm, case) for case in cases):
        ack_probe, ack_probe_sha256 = build_probe(evidence_root / "ack-probe", active_ack=True)
    commit = expected_commit(binary)
    descriptors = prepare_descriptor_budget(io_count=len(cases), evidence_root=evidence_root) \
        if arguments.rtm == "RTM-100" else prepare_descriptor_budget()
    log(f"campaign {arguments.rtm} cases={cases} commit={commit} probe={probe_sha256} assets={assets} descriptorLimit={descriptors}")
    outcomes = []
    failures = {}
    result = {"rtm": arguments.rtm, "commit": commit, "probeSHA256": probe_sha256, "cases": {}, "fullAcceptance": False}
    try:
        for case in cases:
            ack_args = dict(ack_probe=ack_probe, ack_probe_sha256=ack_probe_sha256) \
                if is_active_ack(arguments.rtm, case) else {}
            try:
                outcome = run_cell(arguments.rtm, case, binary=binary, assets=assets, probe=probe, probe_sha256=probe_sha256,
                                   source_sha256=metadata["prepareCompatibilitySourceSHA256"], commit=commit,
                                   evidence_root=evidence_root, log=log, **ack_args)
            except BaseException as error:
                # pytest.fail raises an OutcomeException (a BaseException); it is a
                # failed cell like any other. Only interrupts and exits end the campaign.
                if not arguments.continue_on_failure or isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                failures[case] = {"type": type(error).__name__, "message": str(error)[:2000]}
                result["cases"][case] = {"result": "failed-retained", **failures[case]}
                log(f"{arguments.rtm} {case}: FAILED (continuing): {type(error).__name__}: {str(error)[:300]}")
                continue
            outcomes.append(outcome)
            result["cases"][case] = outcome if isinstance(outcome, dict) else outcome.receipt
        if failures:
            result["failures"] = failures
            log(f"{arguments.rtm}: {len(outcomes)}/{len(cases)} cells passed, {len(failures)} failed; no aggregate")
            return 1
        if arguments.rtm == "RTM-096" and set(cases) == set(proof.FULL_CASES) and len(outcomes) == 9:
            aggregate = proof.aggregate_full(outcomes)
            result.update(aggregate=aggregate, fullAcceptance=aggregate["fullAcceptance"])
            log(f"{arguments.rtm}: {aggregate['result']}")
        elif arguments.rtm in matrix.MATRICES and set(cases) == set(proof.FULL_CASES) and len(outcomes) == 9:
            aggregate = matrix.aggregate_matrix(outcomes, arguments.rtm)
            result.update(aggregate=aggregate, fullAcceptance=aggregate["fullAcceptance"])
            log(f"{arguments.rtm}: {aggregate['result']} variants={aggregate['variants']}")
        elif arguments.rtm == "RTM-100" and set(cases) == set(CAMPAIGNS["RTM-100"]) and len(outcomes) == len(CAMPAIGNS["RTM-100"]):
            import managed_prepare_io_faults as io
            aggregate = io.aggregate(outcomes)
            result.update(aggregate=aggregate, fullAcceptance=True)
            log(f"{arguments.rtm}: {aggregate['result']}")
        else:
            log(f"{arguments.rtm}: {len(outcomes)}/{len(cases)} cells passed; no aggregate")
        return 0
    except BaseException as error:
        result["failure"] = {"type": type(error).__name__, "message": str(error)[:2000]}
        log(f"{arguments.rtm}: FAILED after {len(outcomes)} cells: {type(error).__name__}: {str(error)[:400]}")
        raise
    finally:
        (evidence_root / f"runner-{arguments.rtm}-{stamp}-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        for outcome in outcomes:
            if not isinstance(outcome, dict): outcome.close()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
