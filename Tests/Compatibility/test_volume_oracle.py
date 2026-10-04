"""Opt-in reference-first volume controls; remove only run-owned resources.

Docker local volumes are the Linux control, not cengine block/shared evidence.
Bind fixtures are deliberately excluded: Colima host sharing is not a Docker
Desktop/macOS numeric metadata oracle. No prune, daemon restart, or context edits.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

import docker
import pytest

from harness import managed_docker_environment
import test_compose as compose_cases
import test_upstream_volumes as primitive_cases
from volume_probe import (
    ARTIFACT_ROOT, REPO_ROOT, execute, plans_from_environment, prepare_artifacts,
    replay_fixture, same_unix_endpoint, mismatch_signature, reduce_endpoints,
)

pytestmark = [
    pytest.mark.oracle,
    pytest.mark.skipif(
        not os.environ.get("DOCKER_REFERENCE_HOST"),
        reason="requires explicit DOCKER_REFERENCE_HOST (owned-resource cleanup only)",
    ),
]


@pytest.fixture
def volume_oracle_environment():
    # pytest_sessionstart has validated the invoking runner's Docker/Buildx
    # directories. Copy that client environment; never select a global context.
    return managed_docker_environment()


@pytest.fixture
def volume_reference(daemon):
    host = os.environ["DOCKER_REFERENCE_HOST"]
    if same_unix_endpoint(host, daemon.socket):
        pytest.fail("reference and cengine endpoints must differ")
    reference = docker.DockerClient(base_url=host, timeout=180, version="auto")
    try:
        version = reference.version()
        if version.get("Platform", {}).get("Name", "").lower() == "cengine":
            pytest.fail("DOCKER_REFERENCE_HOST must select reference Docker, not cengine")
        assert version.get("Os") == "linux", version
        assert version.get("Arch") in ("arm64", "aarch64"), version
        reference.ping()
        yield reference
    finally:
        reference.close()


def _sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _environment_artifact(directory, daemon, clients, environment, image):
    """Persist provenance outside the disposable daemon, before workload calls."""
    assets = {
        name: {"path": str(getattr(daemon, name)), "sha256": _sha256(getattr(daemon, name))}
        for name in ("binary", "kernel", "container_initramfs", "storage_initramfs")
    }
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=True,
        capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    compose = subprocess.run(
        ["docker", "compose", "version", "--short"], env=environment, check=True,
        capture_output=True, text=True, timeout=30,
    ).stdout.strip()
    inputs = [Path(__file__), Path(primitive_cases.__file__), Path(compose_cases.__file__),
              REPO_ROOT / "Tests/Compatibility/volume_probe.py",
              REPO_ROOT / "Tests/Compatibility/fixtures/volume-probe.go"]
    inputs.extend(sorted(compose_cases.UPSTREAM_VOLUMES_FIXTURE.glob("*")))
    metadata = {
        "revision": revision, "assets": assets, "compose_version": compose,
        "image": image, "platform": "linux/arm64",
        "source_sha256": {str(path.relative_to(REPO_ROOT)): _sha256(path) for path in inputs},
        "endpoints": {
            label: {"version": client.version(), "host": host}
            for label, client, host in clients
        },
        "reference_storage": "Docker local volume control; no cengine backend assertion",
        "excluded": ["bind mounts / Colima host-sharing metadata", "prune", "daemon crashes"],
    }
    (directory / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")


def _curated_artifacts(daemon, reference, client, environment):
    directory = ARTIFACT_ROOT / ("curated-" + uuid.uuid4().hex)
    directory.mkdir(parents=True)
    print(f"curated volume oracle artifacts: {directory}")
    _environment_artifact(directory, daemon, [
        ("docker", reference, os.environ["DOCKER_REFERENCE_HOST"]),
        ("cengine", client, f"unix://{daemon.socket}"),
    ], environment, primitive_cases.IMAGE)
    # The reference must pull the exact input, never an ambient Alpine tag.
    reference.images.pull(primitive_cases.IMAGE, platform="linux/arm64")
    images = {}
    for label, endpoint in (("docker", reference), ("cengine", client)):
        image = endpoint.images.get(primitive_cases.IMAGE)
        assert image.attrs["Os"] == "linux" and image.attrs["Architecture"] == "arm64"
        images[label] = {key: image.attrs.get(key) for key in (
            "Id", "RepoDigests", "Os", "Architecture", "RootFS",
        )}
    (directory / "images.json").write_text(json.dumps(images, indent=2) + "\n")
    # Docker's containerd store exposes a manifest/index ID; cengine exposes
    # the config ID. Compare the pinned repository input and uncompressed
    # layer identities, not these different engine-specific ID namespaces.
    for observed in images.values():
        assert primitive_cases.IMAGE in observed["RepoDigests"], images
    assert images["docker"]["RootFS"] == images["cengine"]["RootFS"], images
    return directory


@contextmanager
def _case_artifact(directory, label, symbol, daemon=None):
    record = {"case": symbol, "endpoint": label, "status": "started"}
    path = directory / f"{label}.json"
    path.write_text(json.dumps(record, indent=2) + "\n")
    try:
        yield record
        record["status"] = "passed"
    except BaseException as error:
        record.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        if daemon is not None and (daemon.root / "volume-storage.json").exists():
            record["backend_storage"] = json.loads((daemon.root / "volume-storage.json").read_text())
        path.write_text(json.dumps(record, indent=2) + "\n")


PRIMITIVE_CASES = [
    ("test_empty_nocopy_volume_is_populated_by_later_copy", ("daemon", "client")),
    ("test_same_volume_alias_destinations_share_mutations", ("daemon", "client")),
    ("test_volume_file_subpath_over_new_and_existing_targets", ("daemon", "client")),
    ("test_missing_volume_subpath_fails_at_start", ("daemon", "client")),
    ("test_volume_remove_rejects_stopped_container_reference", ("client",)),
    ("test_rm_v_removes_anonymous_but_retains_named_volume", ("client",)),
]


@pytest.mark.compat("ORC-021")
def test_curated_volume_primitives_match_reference(
    daemon, client, volume_reference, volume_oracle_environment, tmp_path,
):
    """Six identical-assertion controls plus a separate rejection diagnostic.

    Invalid copy modes are intentionally excluded from exact API-class equality:
    Docker may return 500, while cengine's supported validation policy is 400.
    The diagnostic tests common rejection semantics and records the difference;
    it is NOT a seventh passing exact-class or byte-equivalence oracle case.
    """
    # The compatibility ledger requires exactly one collected item per ID.
    for symbol, arguments in PRIMITIVE_CASES:
        _run_primitive_case(
            daemon, client, volume_reference, volume_oracle_environment, symbol, arguments, tmp_path,
        )
    _run_invalid_copy_rejection_diagnostic(
        daemon, client, volume_reference, volume_oracle_environment, tmp_path,
    )


def _run_invalid_copy_rejection_diagnostic(
    daemon, client, volume_reference, volume_oracle_environment, tmp_path,
):
    # Invalid flags fail before host-path access; no bind fixture is mounted.
    directory = _curated_artifacts(daemon, volume_reference, client, volume_oracle_environment)
    disposition = {
        "case": "invalid_copy_mode_observations", "status": "started",
        "classification": "API validation class", "exact_class_oracle": False,
        "disposition": "intentional cengine 400; compare common rejection semantics only",
        "error_text_policy": "raw evidence retained, not compared for equality",
        "endpoints": {},
    }
    path = directory / "rejection-disposition.json"
    path.write_text(json.dumps(disposition, indent=2) + "\n")
    try:
        # Capture all three reference rejections FIRST; do not normalize 500 to 400.
        for label, endpoint, proof_daemon in (("docker", volume_reference, None),
                                               ("cengine", client, daemon)):
            with _case_artifact(directory, label, disposition["case"], proof_daemon) as record:
                record.update(comparison="common rejection semantics only", exact_class_oracle=False)
                observations = record["observations"] = []
                disposition["endpoints"][label] = observations
                primitive_cases.invalid_copy_mode_observations(
                    endpoint, tmp_path, observations=observations,
                )
                if label == "cengine":
                    for observation in observations:
                        assert observation["status_code"] == 400, observation
        disposition["status"] = "common-rejection-semantics-passed"
    except BaseException as error:
        disposition.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        disposition["status_differences"] = [
            {"source_kind": expected["source_kind"], "mode": expected["mode"],
             "docker": expected["status_code"], "cengine": actual["status_code"]}
            for expected, actual in zip(disposition["endpoints"].get("docker", []),
                                        disposition["endpoints"].get("cengine", []))
            if expected["status_code"] != actual["status_code"]
        ]
        path.write_text(json.dumps(disposition, indent=2) + "\n")


def _run_primitive_case(
    daemon, client, volume_reference, volume_oracle_environment, symbol, arguments, tmp_path,
):
    directory = _curated_artifacts(daemon, volume_reference, client, volume_oracle_environment)
    scenario = getattr(primitive_cases, symbol)
    # Identical assertions and immutable image on Docker FIRST, then cengine.
    for label, endpoint, proof_daemon in (("docker", volume_reference, None),
                                           ("cengine", client, daemon)):
        with _case_artifact(directory, label, symbol, proof_daemon):
            fixtures = {"daemon": proof_daemon, "client": endpoint, "tmp_path": tmp_path}
            scenario(*(fixtures[name] for name in arguments))


COMPOSE_CASES = [
    "test_compose_external_volume_switches_identity_and_content",
    "test_compose_approved_volume_definition_change_recreates_data",
    "test_compose_anonymous_volume_inheritance_and_renewal",
    "test_compose_no_deps_recreates_only_selected_service",
]


@pytest.mark.compat("ORC-022")
def test_curated_compose_volumes_match_reference(
    daemon, client, volume_reference, volume_oracle_environment, request,
):
    for symbol in COMPOSE_CASES:
        _run_compose_case(
            daemon, client, volume_reference, volume_oracle_environment, request, symbol,
        )


def _run_compose_case(
    daemon, client, volume_reference, volume_oracle_environment, request, symbol,
):
    directory = _curated_artifacts(daemon, volume_reference, client, volume_oracle_environment)
    for label, endpoint_client, host, proof_daemon in (
        ("docker", volume_reference, os.environ["DOCKER_REFERENCE_HOST"], None),
        ("cengine", client, f"unix://{daemon.socket}", daemon),
    ):
        endpoint = compose_cases.VolumeComposeEndpoint(
            host=host, work=daemon.work, environment=dict(volume_oracle_environment),
            daemon=proof_daemon,
        )
        with _case_artifact(directory, label, symbol, proof_daemon):
            with compose_cases.upstream_volume_project_context(endpoint, endpoint_client, request) as project:
                getattr(compose_cases, symbol)(endpoint, project, endpoint_client)


@pytest.mark.compat("ORC-020")
def test_serial_volume_filesystem_matches_reference(
    daemon, client, volume_reference, volume_oracle_environment,
):
    fixture = None
    if os.environ.get("CENGINE_VOLUME_PROBE_PLAN"):
        fixture = replay_fixture(os.environ["CENGINE_VOLUME_PROBE_PLAN"])
    for plan in plans_from_environment():
        directory, image = prepare_artifacts(plan, daemon_root=daemon.root, fixture=fixture)
        if fixture is None:
            fixture = replay_fixture(directory / "plan.json")
        _environment_artifact(directory, daemon, [
            ("docker", volume_reference, os.environ["DOCKER_REFERENCE_HOST"]),
            ("cengine", client, f"unix://{daemon.socket}"),
        ], volume_oracle_environment, image)
        print(f"volume probe replay: CENGINE_VOLUME_PROBE_PLAN={directory / 'plan.json'}")
        for storage in ("block", "shared"):
            expected = execute(volume_reference, plan, image, storage, directory, "docker")
            actual = execute(
                client, plan, image, storage, directory, "cengine",
                backend_proof=lambda name: json.loads(
                    (daemon.root / "volume-storage.json").read_text()
                )[name],
            )
            if actual != expected:
                signature = mismatch_signature(expected, actual)
                _, minimized = reduce_endpoints(
                    plan, fixture, volume_reference, client, storage,
                    root=directory / "reduction",
                    backend_proof=lambda name: json.loads(
                        (daemon.root / "volume-storage.json").read_text()
                    )[name],
                    signature=signature,
                )
                pytest.fail(f"{storage} filesystem mismatch; minimized replay: {minimized}")
