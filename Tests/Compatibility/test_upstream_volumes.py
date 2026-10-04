"""Curated upstream volume primitives, not wholesale upstream suite ports.

Sources (exact test names appear below):
* Moby fce9664cc153ea3da5a3057957a65be9bda30de8
* Podman e967db5f23d65df653790547ec6146fe8ccabd9f
* Rancher Desktop a65e92ed4524e5be57be0c7fd16c999041fc239f

Existing VOL-002/003/004 and RTM-053/054 cover initial copy-up, nocopy,
directory subpaths and ownership. These cases add distinct transitions and
request shapes. Backend selection is asserted, never inferred from success.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import json
import re
import stat
import uuid

import docker
import pytest
from docker.types import Mount

from storage_backend_proof import daemon_startup_mode


IMAGE = "alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"


def _create_volume(client, prefix):
    token = uuid.uuid4().hex
    volume = client.volumes.create(
        f"{prefix}-{token}", labels={"dev.cengine.compat.owner": token},
    )
    assert volume.attrs.get("Labels", {}).get("dev.cengine.compat.owner") == token
    return volume


def _remove_container(container):
    try:
        container.remove(force=True, v=True)
    except docker.errors.NotFound:
        pass


def _remove_volume(volume):
    try:
        volume.remove()
    except docker.errors.NotFound:
        pass


def _cleanup(containers=(), volumes=()):
    # ExitStack attempts every owned resource even if an earlier delete fails.
    with ExitStack() as stack:
        for volume in volumes:
            stack.callback(_remove_volume, volume)
        for container in containers:
            stack.callback(_remove_container, container)


@contextmanager
def _backend_volume(client, storage):
    volume = _create_volume(client, f"upstream-{storage}")
    containers = []
    try:
        if storage == "shared":
            # A second known consumer must exist BEFORE the first start.
            # This does not test promotion of an already block-backed volume.
            containers.append(client.containers.create(
                IMAGE, ["true"],
                mounts=[Mount("/keeper", volume.name, type="volume", no_copy=True)],
            ))
        yield volume, containers
    finally:
        _cleanup(containers, [volume])


def _assert_backend(daemon, volume, storage):
    # Explicit oracle reuse passes None for Docker's local-volume control.
    # Docker has no cengine block/shared selector; never fabricate that proof.
    # Normal cengine tests always pass their real daemon and require evidence.
    if daemon is None:
        return
    modes = json.loads((daemon.root / "volume-storage.json").read_text())
    assert modes[volume.name] == storage, (volume.name, modes)


def _run(container):
    container.start()
    result = container.wait(timeout=60)
    output = container.logs()
    assert result["StatusCode"] == 0, output.decode(errors="replace")
    return output


@pytest.mark.compat("RTM-060")
def test_empty_nocopy_volume_is_populated_by_later_copy(daemon, client: docker.DockerClient):
    """Moby integration-cli/docker_cli_run_test.go::TestRunVolumeCopyFlag.

    Use the pinned image's /etc/apk instead of building /foo/bar. Structured
    NoCopy replaces legacy :nocopy (unsupported here). Unlike upstream's
    retained stopped consumers, block mode removes the first container before
    creating its replacement. Late sharing is explicitly NOT covered.
    """
    for storage in ("block", "shared"):
        with _backend_volume(client, storage) as (volume, containers):
            first = client.containers.create(
                IMAGE, ["sh", "-ec", 'for entry in /etc/apk/.[!.]* /etc/apk/..?* /etc/apk/*; do '
                        'test -e "$entry" || test -L "$entry" || continue; '
                        'test "$entry" = /etc/apk/lost+found; '
                        'test -d "$entry"; test ! -L "$entry"; '
                        'test -z "$(ls -A "$entry")"; done'],
                mounts=[Mount("/etc/apk", volume.name, type="volume", no_copy=True)],
            )
            containers.append(first)
            _run(first)
            _assert_backend(daemon, volume, storage)
            first.remove()
            containers.remove(first)
            second = client.containers.create(
                IMAGE, ["sh", "-ec", "test -s /etc/apk/repositories; test -s /etc/apk/arch"],
                mounts=[Mount("/etc/apk", volume.name, type="volume")],
            )
            containers.append(second)
            _run(second)
            _assert_backend(daemon, volume, storage)


@pytest.mark.compat("VOL-020")
def test_invalid_copy_modes_reject_container_creation(client: docker.DockerClient, tmp_path):
    """Moby integration-cli/docker_cli_run_test.go::TestRunVolumeCopyFlag.

    Select named :copy and bind :copy/:nocopy; do not claim volumes-from or
    supported legacy named :nocopy. These are API validation, not VM cases.
    """
    for observation in invalid_copy_mode_observations(client, tmp_path):
        # cengine intentionally classifies invalid modes as client input errors.
        assert observation["status_code"] == 400, observation


def invalid_copy_mode_observations(client, tmp_path, *, observations=None):
    """Require create-time rejection without resources; retain exact API evidence.

    Docker 29.2.1/API 1.53 returns 500 for at least named :copy. The shared
    rejection contract allows only 400/500 with a copy-mode error, NOT arbitrary
    server failures. Callers enforce engine-specific status policy separately.
    An optional observation sink preserves partial evidence on assertion failure.
    """
    if observations is None:
        observations = []
    volume = _create_volume(client, "invalid-copy")
    try:
        for source_kind, source, mode in (
            ("named", volume.name, "copy"),
            ("bind", str(tmp_path), "copy"),
            ("bind", str(tmp_path), "nocopy"),
        ):
            token = uuid.uuid4().hex
            name = f"invalid-copy-{token}"
            observation = {
                "source_kind": source_kind, "source": source, "mode": mode,
                "phase": "create", "container_name": name, "volume_name": volume.name,
                "status_code": None, "container_absent": False,
                "volume_absent_after_cleanup": False,
            }
            observations.append(observation)
            try:
                with pytest.raises(docker.errors.APIError) as caught:
                    client.containers.create(
                        IMAGE, ["true"], name=name,
                        labels={"dev.cengine.compat.owner": token},
                        volumes={source: {"bind": "/data", "mode": mode}},
                    )
                error = caught.value
                observation.update(
                    status_code=error.response.status_code,
                    error=str(error), explanation=error.explanation,
                    response_body=error.response.text, request_url=error.response.url,
                )
                with pytest.raises(docker.errors.NotFound):
                    client.containers.get(name)
                observation["container_absent"] = True
                assert observation["status_code"] in (400, 500), observation
                assert "copy" in error.explanation.lower(), observation
                # Names themselves contain "invalid-copy"; a storage failure
                # mentioning a name is not evidence of mode validation.
                explanation = error.explanation.lower()
                for identity in (name, volume.name, str(tmp_path)):
                    explanation = explanation.replace(identity.lower(), "<resource>")
                assert re.search(rf"\b{mode}\b", explanation), observation
                assert re.search(
                    r"\binvalid (?:mode|volume specification|bind mount(?: option)?)\b"
                    rf"|\b{mode} is only valid for volume mounts\b",
                    explanation,
                ), observation
            finally:
                try:
                    unexpected = client.containers.get(name)
                except docker.errors.NotFound:
                    pass
                else:
                    if unexpected.labels.get("dev.cengine.compat.owner") == token:
                        _remove_container(unexpected)
    finally:
        _remove_volume(volume)
        with pytest.raises(docker.errors.NotFound):
            client.volumes.get(volume.name)
        for observation in observations:
            observation["volume_absent_after_cleanup"] = True
    return observations


@pytest.mark.compat("VOL-021")
def test_volume_remove_rejects_stopped_container_reference(client: docker.DockerClient):
    """Moby integration-cli/docker_cli_volume_test.go::TestVolumeCLIRm.

    A created (not running) consumer still protects its volume. Force removal
    and global prune are excluded; prune label filters are unsupported here.
    """
    volume = _create_volume(client, "remove-used")
    container = None
    try:
        container = client.containers.create(
            IMAGE, ["true"], mounts=[Mount("/data", volume.name, type="volume")],
        )
        with pytest.raises(docker.errors.APIError) as caught:
            volume.remove()
        assert caught.value.response.status_code == 409
        assert "in use" in caught.value.explanation.lower()
        assert client.volumes.get(volume.name).name == volume.name
        container.remove()
        container = None
        volume.remove()
        with pytest.raises(docker.errors.NotFound):
            client.volumes.get(volume.name)
    finally:
        _cleanup([container] if container is not None else [], [volume])


@pytest.mark.compat("VOL-022")
def test_rm_v_removes_anonymous_but_retains_named_volume(client: docker.DockerClient):
    """Podman test/e2e/run_volume_test.go::podman rm -v removes anonymous
    volume / podman rm -v retains named volume. Use a structured anonymous
    mount: the SDK's volumes-list convenience also emits HostConfig.Binds.
    """
    volume = _create_volume(client, "rm-v")
    container = None
    anonymous = None
    try:
        container = client.containers.create(
            IMAGE, ["true"],
            mounts=[Mount("/named", volume.name, type="volume"),
                    Mount("/anonymous", "", type="volume")],
        )
        _run(container)
        container.reload()
        mounts = {mount["Destination"]: mount for mount in container.attrs["Mounts"]}
        assert mounts["/named"]["Name"] == volume.name
        assert mounts["/anonymous"]["Type"] == "volume", mounts
        anonymous = client.volumes.get(mounts["/anonymous"]["Name"])
        assert anonymous.name != volume.name
        container.remove(v=True)
        container = None
        with pytest.raises(docker.errors.NotFound):
            client.volumes.get(anonymous.name)
        assert client.volumes.get(volume.name).name == volume.name
    finally:
        _cleanup(
            [container] if container is not None else [],
            [volume, anonymous] if anonymous is not None else [volume],
        )


@pytest.mark.compat("RTM-061")
def test_same_volume_alias_destinations_share_mutations(daemon, client: docker.DockerClient):
    """Podman test/e2e/run_volume_test.go::same volume in multiple places
    does not deadlock. Add bidirectional data assertions; omit SELinux flags.
    """
    for storage in ("block", "shared"):
        with _backend_volume(client, storage) as (volume, containers):
            container = client.containers.create(
                IMAGE, ["sh", "-ec", "printf first >/one/value; "
                        "test \"$(cat /two/value)\" = first; "
                        "mv /two/value /two/renamed; test ! -e /one/value; "
                        "test \"$(cat /one/renamed)\" = first"],
                mounts=[Mount(target, volume.name, type="volume", no_copy=True)
                        for target in ("/one", "/two")],
            )
            containers.append(container)
            _run(container)
            _assert_backend(daemon, volume, storage)
            container.reload()
            mounts = {mount["Destination"]: mount for mount in container.attrs["Mounts"]}
            assert mounts["/one"]["Name"] == mounts["/two"]["Name"] == volume.name


@pytest.mark.compat("RTM-062")
def test_volume_file_subpath_over_new_and_existing_targets(daemon, client: docker.DockerClient):
    """Moby integration/volume/mount_test.go::TestRunMountVolumeSubdir,
    cases 'file' and 'file over existing target'. /etc/alpine-release replaces
    /etc/localtime because the pinned Alpine fixture provides the former.
    """
    for storage in ("block", "shared"):
        with _backend_volume(client, storage) as (volume, containers):
            seed = client.containers.create(
                IMAGE, ["sh", "-ec", "printf from-volume >/seed/file"],
                mounts=[Mount("/seed", volume.name, type="volume", no_copy=True)],
            )
            containers.append(seed)
            _run(seed)
            _assert_backend(daemon, volume, storage)
            # Sequential block users must not create a late-sharing request.
            seed.remove()
            containers.remove(seed)
            for target in ("/file-target", "/etc/alpine-release"):
                container = client.containers.create(
                    IMAGE, ["cat", target],
                    mounts=[Mount(target, volume.name, type="volume", no_copy=True,
                                  read_only=True, subpath="file")],
                )
                containers.append(container)
                assert _run(container) == b"from-volume"
                _assert_backend(daemon, volume, storage)
                container.remove()
                containers.remove(container)


@pytest.mark.compat("RTM-063")
def test_missing_volume_subpath_fails_at_start(daemon, client: docker.DockerClient):
    """Moby integration/volume/mount_test.go::TestRunMountVolumeSubdir,
    'not existing'. Do not duplicate existing traversal/symlink-escape tests.
    """
    for storage in ("block", "shared"):
        with _backend_volume(client, storage) as (volume, containers):
            command = ["sh", "-ec", "printf subpath-started; printf marker >/data/marker"]
            mounts = [Mount("/data", volume.name, type="volume", no_copy=True,
                            subpath="not-existing-path")]
            container = client.containers.create(IMAGE, command, mounts=mounts)
            containers.append(container)
            with pytest.raises(docker.errors.APIError) as caught:
                container.start()
            _assert_missing_subpath_error(daemon, storage, caught.value)
            _assert_backend(daemon, volume, storage)
            container.reload()
            assert container.attrs["State"]["Running"] is False
            output = container.logs()
            assert b"subpath-started" not in output, output
            container.remove()
            containers.remove(container)

            # A generic channel failure alone is not a missing-subpath verdict.
            # Prove the same volume remains usable and the path is still absent,
            # then create it and require the identical workload/mount to succeed.
            # Remove each block consumer before constructing its replacement.
            seed = client.containers.create(
                IMAGE, ["sh", "-ec", "test ! -e /data/not-existing-path; "
                        "mkdir /data/not-existing-path"],
                mounts=[Mount("/data", volume.name, type="volume", no_copy=True)],
            )
            containers.append(seed)
            _run(seed)
            _assert_backend(daemon, volume, storage)
            seed.remove()
            containers.remove(seed)
            repaired = client.containers.create(IMAGE, command, mounts=mounts)
            containers.append(repaired)
            assert _run(repaired) == b"subpath-started"
            _assert_backend(daemon, volume, storage)


def _assert_missing_subpath_error(daemon, storage, error):
    # Docker reports 404/500. Managed private-channel launch refusals use
    # a closed 409 vocabulary; do not accept unrelated ownership/fence conflicts
    # or broaden the Docker reference's policy. The caller also proves absence,
    # nonexecution and successful use after creating the missing path.
    status = error.response.status_code
    if status == 409:
        assert storage == "shared" and daemon is not None
        assert daemon_startup_mode(daemon) == "lifecycle"
        assert error.explanation == (
            "private workload storage channel refused; preserve generation evidence"
        ), error.explanation
    else:
        assert status in (404, 500), (storage, status, error.explanation)


@pytest.mark.compat("RTM-064")
def test_missing_bind_source_legacy_creates_but_mount_rejects(client: docker.DockerClient, tmp_path):
    """Rancher Desktop bats/tests/containers/volumes.bats::host directory
    does not exist, plus Docker --mount's no-implicit-source-creation contrast.
    SDK Binds/Mounts retain the corresponding CLI request shapes.
    """
    missing = tmp_path / "missing-mount"
    container = None
    try:
        # Validation may occur on create or start, but must precede workload IO.
        with pytest.raises(docker.errors.APIError) as caught:
            container = client.containers.create(
                IMAGE, ["touch", "/data/should-not-run"],
                mounts=[Mount("/data", str(missing), type="bind")],
            )
            container.start()
        assert "exist" in caught.value.explanation.lower()
        assert not missing.exists()
    finally:
        if container is not None:
            _remove_container(container)

    legacy = tmp_path / "missing-legacy"
    container = client.containers.create(
        IMAGE, ["sh", "-ec", "printf created >/data/marker"],
        volumes={str(legacy): {"bind": "/data", "mode": "rw"}},
    )
    try:
        _run(container)
        assert (legacy / "marker").read_bytes() == b"created"
    finally:
        _remove_container(container)


@pytest.mark.compat("RTM-065")
def test_bind_paths_with_spaces_and_nonascii(client: docker.DockerClient, tmp_path):
    """Rancher Desktop bats/tests/containers/volumes.bats::directory contains
    space / directory contains non-ascii. Check separate paths, without shell
    interpolation of host paths or reliance on host ownership translation.
    """
    for name in ("hello world", "snow☃man"):
        source = tmp_path / name
        source.mkdir()
        container = client.containers.create(
            IMAGE, ["sh", "-ec", "printf path-ok >/data/marker"],
            volumes={str(source): {"bind": "/data", "mode": "rw"}},
        )
        try:
            _run(container)
            assert (source / "marker").read_bytes() == b"path-ok"
        finally:
            _remove_container(container)


@pytest.mark.compat("RTM-066")
def test_single_file_bind_preserves_writes_and_chmod(client: docker.DockerClient, tmp_path):
    """Rancher Desktop bats/tests/containers/volumes.bats::read-write single
    file using --mount / change file permissions. Limit to ordinary mode bits;
    UID/GID remapping and Linux-only ownership expectations are not claimed.
    """
    source = tmp_path / "mounted-file"
    source.write_bytes(b"host-seed")
    source.chmod(0o600)
    container = client.containers.create(
        IMAGE, ["sh", "-ec", 'test "$(cat /file)" = host-seed; '
                "printf guest-write >/file; chmod 755 /file; stat -c %a /file"],
        mounts=[Mount("/file", str(source), type="bind")],
    )
    try:
        assert _run(container).strip() == b"755"
        assert source.read_bytes() == b"guest-write"
        assert stat.S_IMODE(source.stat().st_mode) == 0o755
    finally:
        _remove_container(container)
