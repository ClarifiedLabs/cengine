#!/usr/bin/env python3
"""Engine-free RTM-077 ownership, lifecycle, identity, and retention regressions.

Run with .build/compat-venv/bin/python; no daemon, Docker socket, or raw disk IO.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import docker
from requests import Response

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import test_failed_start_storage as subject


PAYLOAD = b"rtm077-userdata-owned\n"


class Scenario:
    def __init__(self, work):
        self.events = []
        self.evidence = []
        self.exists = False
        self.entry = True  # The unmodified image already has /bin/sh.
        self.data_written = False
        self.daemon_running = True
        self.retained = False
        self.replacement_after_remove = False
        self.daemon = SimpleNamespace(
            root=work / "root", work=work, binary=work / "unused-cengine",
            process=SimpleNamespace(poll=lambda: None if self.daemon_running else 0),
            start=self.start_daemon, retain_root=self.retain,
        )
        self.target = SimpleNamespace(
            id="container-id", name="rtm077-owned", attrs={
                "Config": {"Labels": {subject.OWNER_LABEL: "owned"}},
                "Path": "/bin/sh", "Args": ["-ec", "sleep 1800"],
                "State": {"Status": "exited", "Running": False, "Paused": False,
                          "Restarting": False, "Dead": False, "Pid": 0, "ExitCode": 137},
            }, start=self.start, stop=self.stop, reload=lambda: None,
            put_archive=Mock(side_effect=AssertionError("archive PUT must not be required")),
            get_archive=Mock(side_effect=AssertionError("archive GET must not be required")),
            remove=self.remove,
        )
        self.client = SimpleNamespace(
            api=SimpleNamespace(timeout=23),
            containers=SimpleNamespace(create=self.create, get=self.get),
        )
        self.snapshot = {"directory": (1, 2), "disk": (1, 3, 4096),
                         "journal": {"ext4UUID": "recorded-uuid"},
                         "raw": {phase: phase.encode() for phase in ("created", "spent", "initialized")}}

    def create(self, image, command, **options):
        assert image == subject.ALPINE and command == []
        assert options == {"entrypoint": ["/bin/sh", "-ec", "sleep 1800"], "name": "rtm077-owned",
                           "labels": {"dev.cengine.compat": "true", subject.OWNER_LABEL: "owned"},
                           "network_mode": "none"}
        self.exists = True
        self.events.append("create")
        return self.target

    def get(self, name):
        # Keep lookup independent of mutated attrs so guard tests exercise the
        # production identity checks, not a fake-client precondition.
        assert name in ("rtm077-owned", "container-id")
        if not self.exists:
            if self.replacement_after_remove and name == "container-id":
                # Another client recreates the name/label after original deletion.
                self.exists = True
                self.target.id = "replacement-id"
            raise docker.errors.NotFound("removed")
        return self.target

    def start(self):
        assert self.daemon_running
        if not self.entry:
            assert self.data_written
            self.events.append("failed-start")
            response = Response()
            response.status_code = 500
            raise docker.errors.APIError("failed", response=response,
                                         explanation="workload failed before becoming ready: EOF")
        self.events.append("start")
        self.target.attrs["State"].update(Status="running", Running=True, Pid=42)

    def stop(self, *, timeout):
        assert timeout == 5
        self.events.append("stop")
        self.target.attrs["State"].update(Status="exited", Running=False, Pid=0)

    def execute(self, target, *command):
        assert target is self.target and self.target.attrs["State"]["Running"]
        assert command[:3] == ("/bin/busybox", "sh", "-ec")
        if "mv " in command[-1]:
            script = command[-1]
            assert script.count("mv ") == 1
            assert "mv /bin/sh /rtm077-entry.disabled" in script
            assert "test ! -e /bin/sh" in script and "test ! -L /bin/sh" in script
            assert "test -L /rtm077-entry.disabled || test -f /rtm077-entry.disabled" in script
            assert "chown 1042:1043 /rtm077-data /rtm077-data/payload" in script
            assert "chmod 2750 /rtm077-data" in script and "chmod 640 /rtm077-data/payload" in script
            assert "'rtm077-userdata-owned' > /rtm077-data/payload" in script
            assert script.strip().endswith("sync")
            self.entry = False
            self.data_written = True
            self.events.append("write-and-disable-entry")
            return b""
        assert self.data_written and not self.entry
        assert command[-1] == ("cat /rtm077-data/payload; "
                                "stat -c '%u:%g:%a' /rtm077-data /rtm077-data/payload")
        self.events.append("read-userdata")
        return PAYLOAD + b"1042:1043:2750\n1042:1043:640\n"

    def remove(self, **options):
        self.events.append("remove")
        self.exists = False

    def quiesce(self, daemon, *, record):
        assert daemon is self.daemon and not self.target.attrs["State"]["Running"]
        self.events.append("quiesce")
        self.daemon_running = False
        return {"cleanup_matched_pids": [], "remaining_matched_pids": []}

    def claim(self, daemon, disk, journal, *, quiescence, role, record):
        assert daemon is self.daemon and not self.daemon_running
        assert disk == self.daemon.root / "containers/container-id/root.ext4"
        assert journal == self.snapshot["journal"] and role == "failed-start-root"
        assert not quiescence["remaining_matched_pids"]
        self.events.append("read-host-uuid")
        return journal["ext4UUID"]

    def start_daemon(self):
        assert not self.daemon_running
        self.events.append("cold-start")
        self.daemon_running = True

    def retain(self, *, reason):
        assert reason == "unsafe-disk-phase"
        self.retained = True
        self.events.append("retain")


class FailedStartStorageTests(unittest.TestCase):
    def run_scenario(self, *, changed_snapshot=None, snapshot_index=2, claim_failure=False,
                     marker_failure=False, create_failure=False, userdata_failure=False,
                     remove_leaves_root=False, replacement_after_remove=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        scenario = Scenario(work)
        scenario.replacement_after_remove = replacement_after_remove
        if create_failure:
            # No actual disk IO: model an ambiguous create whose later metadata
            # lookup is NotFound, even though host storage may have committed.
            scenario.client.containers.create = Mock(side_effect=TimeoutError("create reply lost"))
        snapshot = Mock(return_value=scenario.snapshot)
        if changed_snapshot is not None:
            changed = deepcopy(scenario.snapshot)
            changed_snapshot(changed)
            snapshot.side_effect = [scenario.snapshot] * snapshot_index + [changed]
        claim = Mock(side_effect=TimeoutError("claim refused") if claim_failure else scenario.claim)
        if marker_failure:
            def retain(**kwargs):
                scenario.retain(**kwargs)
                raise OSError("marker full")
            scenario.daemon.retain_root = retain
        def execute(target, *command):
            result = scenario.execute(target, *command)
            return b"changed userdata or metadata" if userdata_failure and result else result
        if remove_leaves_root:
            (scenario.daemon.root / "containers/container-id").mkdir(parents=True)
        with patch.object(subject, "__file__", str(work / "Tests/Compatibility/test.py")), \
                patch.object(subject.uuid, "uuid4", return_value=SimpleNamespace(hex="owned")), \
                patch.object(subject, "_root_snapshot", snapshot), \
                patch.object(subject, "_host_uuid", claim), \
                patch.object(subject, "_quiesce", scenario.quiesce), \
                patch.object(subject, "_exec", execute):
            if changed_snapshot or claim_failure or create_failure or userdata_failure or remove_leaves_root:
                with self.assertRaises((AssertionError, TimeoutError)):
                    subject.test_failed_start_preserves_writable_root_and_metadata(
                        scenario.client, scenario.daemon)
            else:
                subject.test_failed_start_preserves_writable_root_and_metadata(scenario.client, scenario.daemon)
        self.assertEqual(scenario.client.api.timeout, 23)
        scenario.target.put_archive.assert_not_called()
        scenario.target.get_archive.assert_not_called()
        scenario.evidence = json.loads((work / ".build/failed-start-storage/owned/evidence.json").read_text())
        self.assertLessEqual(len(scenario.evidence), 32)
        self.assertLessEqual(len(json.dumps(scenario.evidence).encode()), 64 * 1024)
        return scenario, claim

    def test_two_failures_cold_restart_and_explicit_remove_without_archives(self):
        scenario, claim = self.run_scenario()
        self.assertEqual(scenario.events, [
            "create", "start", "write-and-disable-entry", "read-userdata", "stop",
            "failed-start", "quiesce", "read-host-uuid", "cold-start",
            "failed-start", "quiesce", "read-host-uuid", "cold-start", "remove",
        ])
        self.assertEqual(claim.call_count, 2)
        self.assertFalse(scenario.retained)
        self.assertFalse(scenario.exists)
        self.assertFalse(scenario.entry)  # Never restore the executable to make cleanup pass.
        initial = next(event for event in scenario.evidence if event["phase"] == "initial-userdata-verified")
        self.assertFalse(initial["post_failure_userdata_read"])
        self.assertIn("in-place userdata corruption", initial["limitation"])
        self.assertEqual(scenario.evidence[-1]["phase"], "explicit-remove-verified")

    def test_stopped_requires_exact_effective_executable_and_arguments(self):
        scenario = Scenario(Path("unused"))
        self.assertEqual(subject._stopped(scenario.target)["Status"], "exited")
        for field, value in (("Path", "/bin/busybox"), ("Args", ["-ec", "true"]),
                             ("Args", [])):
            with self.subTest(field=field, value=value):
                with patch.dict(scenario.target.attrs, {field: value}):
                    with self.assertRaises(AssertionError):
                        subject._stopped(scenario.target)

    def test_initial_userdata_and_metadata_must_be_verified_before_failed_start(self):
        scenario, claim = self.run_scenario(userdata_failure=True)
        self.assertTrue(scenario.retained)
        self.assertNotIn("failed-start", scenario.events)
        self.assertNotIn("remove", scenario.events)
        claim.assert_not_called()

    def test_root_snapshot_records_exact_disk_identity_size_and_all_journals(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            scenario = Scenario(work)
            directory = scenario.daemon.root / "containers/container-id"
            directory.mkdir(parents=True)
            disk = directory / "root.ext4"
            disk.write_bytes(b"metadata-only test file")
            with patch.object(subject, "compatibility_root_owned_by", return_value=True), \
                    patch.object(subject, "_journal", return_value=(scenario.snapshot["journal"],
                                                                  scenario.snapshot["raw"])) as journal:
                observed = subject._root_snapshot(scenario.daemon, "container-id")
            self.assertEqual(observed["directory"], (directory.stat().st_dev, directory.stat().st_ino))
            self.assertEqual(observed["disk"], (disk.stat().st_dev, disk.stat().st_ino, disk.stat().st_size))
            self.assertEqual(observed["raw"], scenario.snapshot["raw"])
            journal.assert_called_once_with(disk)

    def test_root_snapshot_refuses_unowned_root_symlink_or_hardlinked_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            scenario = Scenario(work)
            directory = scenario.daemon.root / "containers/container-id"
            directory.mkdir(parents=True)
            original = work / "original"
            original.write_bytes(b"not a disk")
            disk = directory / "root.ext4"
            disk.symlink_to(original)
            with patch.object(subject, "compatibility_root_owned_by", return_value=True), \
                    patch.object(subject, "_journal") as journal:
                with self.assertRaises(AssertionError):
                    subject._root_snapshot(scenario.daemon, "container-id")
                disk.unlink()
                os.link(original, disk)
                with self.assertRaises(AssertionError):
                    subject._root_snapshot(scenario.daemon, "container-id")
                journal.assert_not_called()
            with patch.object(subject, "compatibility_root_owned_by", return_value=False):
                with self.assertRaises(AssertionError):
                    subject._root_snapshot(scenario.daemon, "container-id")

    def test_ambiguous_create_retains_even_when_metadata_lookup_would_be_not_found(self):
        scenario, claim = self.run_scenario(create_failure=True)
        self.assertEqual(scenario.events, ["retain"])
        self.assertTrue(scenario.retained)
        with self.assertRaises(docker.errors.NotFound):
            scenario.get("rtm077-owned")
        claim.assert_not_called()

    def test_root_identity_size_or_any_journal_change_retains_before_claim_or_cleanup(self):
        changes = [lambda value: value.update(directory=(1, 99)),
                   lambda value: value.update(disk=(1, 99, 4096)),
                   lambda value: value.update(disk=(1, 3, 8192)),
                   lambda value: value["journal"].update(ext4UUID="changed-uuid")]
        changes += [lambda value, phase=phase: value["raw"].update({phase: b"changed"})
                    for phase in ("created", "spent", "initialized")]
        for index, change in enumerate(changes):
            with self.subTest(change=index):
                scenario, claim = self.run_scenario(changed_snapshot=change)
                self.assertTrue(scenario.retained)
                self.assertNotIn("remove", scenario.events)
                self.assertNotIn("quiesce", scenario.events)
                claim.assert_not_called()

    def test_cold_restart_replacement_retains_before_second_attempt_or_cleanup(self):
        scenario, claim = self.run_scenario(
            changed_snapshot=lambda value: value.update(disk=(1, 99, 4096)), snapshot_index=4)
        self.assertTrue(scenario.retained)
        self.assertEqual(scenario.events.count("failed-start"), 1)
        self.assertEqual(scenario.events.count("cold-start"), 1)
        self.assertNotIn("remove", scenario.events)
        self.assertEqual(claim.call_count, 1)

    def test_unsafe_claim_retains_without_daemon_restart_even_if_marker_io_fails(self):
        scenario, _ = self.run_scenario(claim_failure=True, marker_failure=True)
        self.assertTrue(scenario.retained)
        self.assertNotIn("cold-start", scenario.events)
        self.assertNotIn("remove", scenario.events)

    def test_explicit_remove_must_delete_owned_host_directory(self):
        scenario, claim = self.run_scenario(remove_leaves_root=True)
        self.assertTrue(scenario.retained)
        self.assertEqual(scenario.events.count("remove"), 1)
        self.assertEqual(claim.call_count, 2)
        self.assertNotIn("explicit-remove-verified", [event["phase"] for event in scenario.evidence])

    def test_cleanup_guard_requires_exact_name_owner_and_id(self):
        scenario = Scenario(Path("unused"))
        scenario.exists = True
        for field, value in (("name", "foreign"), ("id", "foreign")):
            with self.subTest(field=field), patch.object(scenario.target, field, value):
                with self.assertRaises(AssertionError):
                    subject._owned_container(scenario.client, "rtm077-owned", "owned", "container-id")
        scenario.target.attrs["Config"]["Labels"][subject.OWNER_LABEL] = "foreign"
        with self.assertRaises(AssertionError):
            subject._owned_container(scenario.client, "rtm077-owned", "owned", "container-id")
        self.assertNotIn("remove", scenario.events)
        replacement, _ = self.run_scenario(replacement_after_remove=True)
        self.assertTrue(replacement.exists)
        self.assertEqual(replacement.target.id, "replacement-id")
        self.assertEqual(replacement.events.count("remove"), 1)


if __name__ == "__main__":
    unittest.main()
