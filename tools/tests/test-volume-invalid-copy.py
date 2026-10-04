#!/usr/bin/env python3
"""Engine-free invalid-copy rejection evidence, policy, and ownership regressions."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import docker
import pytest
from requests import Response

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import test_upstream_volumes as primitives
import test_volume_oracle as oracle


class FakeClient:
    def __init__(self, statuses=(400, 400, 400), *, label="engine", events=None,
                 explanation=None, leak=False, owned=True, succeed=False,
                 transport_error=False, cleanup_error=False):
        self.statuses = statuses
        self.label = label
        self.events = events if events is not None else []
        self.explanation = explanation
        self.leak, self.owned, self.succeed = leak, owned, succeed
        self.transport_error, self.cleanup_error = transport_error, cleanup_error
        self.created = []
        self.errors = []
        self.server_containers = {}
        self.server_volumes = {}
        self.volumes = SimpleNamespace(create=self.create_volume, get=self.get_volume)
        self.containers = SimpleNamespace(create=self.create_container, get=self.get_container)

    def get_volume(self, name):
        if name not in self.server_volumes:
            raise docker.errors.NotFound(name)
        return self.server_volumes[name]

    def create_volume(self, name, *, labels):
        def remove():
            self.events.append((self.label, "remove-volume"))
            del self.server_volumes[name]

        volume = SimpleNamespace(name=name, attrs={"Labels": labels}, remove=remove)
        self.server_volumes[name] = volume
        return volume

    def get_container(self, name):
        if name not in self.server_containers:
            raise docker.errors.NotFound(name)
        return self.server_containers[name]

    def create_container(self, image, command, **kwargs):
        index = len(self.created)
        self.created.append(kwargs)
        source, mount = next(iter(kwargs["volumes"].items()))
        mode = mount["mode"]
        self.events.append((self.label, "create", mode))
        assert image == primitives.IMAGE and command == ["true"]
        assert mount["bind"] == "/data"
        name = kwargs["name"]

        def remove(**options):
            assert options == {"force": True, "v": True}
            self.events.append((self.label, "remove-container"))
            if self.cleanup_error:
                raise RuntimeError("synthetic container cleanup failure")
            del self.server_containers[name]

        if self.leak or self.succeed:
            labels = kwargs["labels"] if self.owned else {"dev.cengine.compat.owner": "other-run"}
            self.server_containers[name] = SimpleNamespace(labels=labels, remove=remove)
        if self.succeed:
            return self.server_containers[name]
        if self.transport_error:
            raise RuntimeError("synthetic create transport failure")
        explanation = (self.explanation[index] if isinstance(self.explanation, list)
                       else self.explanation) or f'invalid mode: {mode} for "{source}"'
        response = Response()
        response.status_code = self.statuses[index]
        response.url = f"http+docker://localhost/v1.53/containers/create?name={name}"
        response.encoding = "utf-8"
        response._content = (json.dumps({"message": explanation}) + "\n").encode()
        error = docker.errors.APIError("synthetic response", response=response, explanation=explanation)
        self.errors.append(error)
        raise error


class InvalidCopyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def assert_clean(self, client):
        self.assertFalse(client.server_containers)
        self.assertFalse(client.server_volumes)

    def test_captures_all_three_raw_statuses_messages_phase_and_absence(self):
        client = FakeClient((500, 400, 500))  # Synthetic; not claims about the unobserved modes.
        observations = primitives.invalid_copy_mode_observations(client, self.root)
        self.assertEqual([item["status_code"] for item in observations], [500, 400, 500])
        self.assertEqual([(item["source_kind"], item["mode"]) for item in observations],
                         [("named", "copy"), ("bind", "copy"), ("bind", "nocopy")])
        for item, error in zip(observations, client.errors):
            self.assertEqual(item["phase"], "create")
            self.assertEqual(item["error"], str(error))
            self.assertEqual(item["explanation"], error.explanation)
            self.assertEqual(item["response_body"], error.response.text)
            self.assertEqual(item["request_url"], error.response.url)
            self.assertTrue(item["container_absent"])
            self.assertTrue(item["volume_absent_after_cleanup"])
        self.assert_clean(client)

    def test_standalone_requires_400_for_every_mode_after_cleanup(self):
        client = FakeClient()
        primitives.test_invalid_copy_modes_reject_container_creation(client, self.root)
        self.assert_clean(client)
        for index in range(3):
            with self.subTest(index=index):
                statuses = [400, 400, 400]
                statuses[index] = 500
                client = FakeClient(statuses)
                with self.assertRaises(AssertionError):
                    primitives.test_invalid_copy_modes_reject_container_creation(client, self.root)
                self.assertEqual(len(client.created), 3)
                self.assert_clean(client)

    def test_cengine_validation_wording_is_accepted_without_changing_evidence(self):
        messages = ["invalid bind mount option: copy", "invalid bind mount option: copy",
                    "nocopy is only valid for volume mounts"]
        client = FakeClient(explanation=messages)
        observations = primitives.invalid_copy_mode_observations(client, self.root)
        self.assertEqual([item["explanation"] for item in observations], messages)
        self.assert_clean(client)

    def test_wrapped_volume_specification_error_retains_raw_mode_evidence(self):
        messages = [f'invalid volume specification: "source:/data:{mode}"'
                    for mode in ("copy", "copy", "nocopy")]
        client = FakeClient((500, 500, 400), explanation=messages)
        observations = primitives.invalid_copy_mode_observations(client, self.root)
        self.assertEqual([item["explanation"] for item in observations], messages)
        self.assert_clean(client)

    def test_rejects_unexpected_status_and_unrelated_server_error_with_evidence(self):
        for status, explanation in (
            (401, "invalid mode: copy"), (404, "invalid mode: copy"),
            (503, "invalid mode: copy"), (500, "storage unavailable"),
            (500, "volume invalid-copy-test is unavailable: storage backend failure"),
            (500, "failed to copy volume data: storage backend failure"),
        ):
            with self.subTest(status=status, explanation=explanation):
                client = FakeClient((status,), explanation=explanation)
                observations = []
                with self.assertRaises(AssertionError):
                    primitives.invalid_copy_mode_observations(client, self.root, observations=observations)
                self.assertEqual(observations[0]["status_code"], status)
                self.assertEqual(observations[0]["explanation"], explanation)
                self.assertTrue(observations[0]["container_absent"])
                self.assertTrue(observations[0]["volume_absent_after_cleanup"])
                self.assert_clean(client)

    def test_success_leak_and_transport_failure_still_remove_owned_resources(self):
        for options, error in (({"succeed": True}, pytest.fail.Exception),
                               ({"leak": True}, pytest.fail.Exception),
                               ({"leak": True, "transport_error": True}, RuntimeError)):
            with self.subTest(options=options):
                client = FakeClient(**options)
                with self.assertRaises(error):
                    primitives.invalid_copy_mode_observations(client, self.root)
                self.assert_clean(client)
                self.assertIn(("engine", "remove-container"), client.events)

    def test_cleanup_failure_still_attempts_volume_cleanup(self):
        client = FakeClient(leak=True, cleanup_error=True)
        with self.assertRaisesRegex(RuntimeError, "cleanup failure"):
            primitives.invalid_copy_mode_observations(client, self.root)
        self.assertIn(("engine", "remove-volume"), client.events)
        self.assertFalse(client.server_volumes)

    def test_never_removes_foreign_container(self):
        client = FakeClient(leak=True, owned=False)
        with self.assertRaises(pytest.fail.Exception):
            primitives.invalid_copy_mode_observations(client, self.root)
        self.assertEqual(len(client.server_containers), 1)
        self.assertNotIn(("engine", "remove-container"), client.events)
        self.assertIn(("engine", "remove-volume"), client.events)

    def run_diagnostic(self, reference, client):
        # Provenance/image setup is unchanged and deliberately mocked: no engine calls.
        daemon = SimpleNamespace(root=self.root)
        with patch.object(oracle, "_curated_artifacts", return_value=self.root):
            oracle._run_invalid_copy_rejection_diagnostic(daemon, client, reference, {}, self.root)

    def artifact(self, name):
        return json.loads((self.root / name).read_text())

    def test_oracle_reference_first_retains_difference_without_exact_class_claim(self):
        events = []
        reference = FakeClient((500, 400, 500), label="docker", events=events)
        client = FakeClient(label="cengine", events=events)
        self.run_diagnostic(reference, client)
        self.assertEqual([event[0] for event in events if event[1] == "create"],
                         ["docker"] * 3 + ["cengine"] * 3)
        for label, statuses in (("docker", [500, 400, 500]), ("cengine", [400, 400, 400])):
            record = self.artifact(label + ".json")
            self.assertEqual(record["status"], "passed")
            self.assertFalse(record["exact_class_oracle"])
            self.assertEqual(record["comparison"], "common rejection semantics only")
            self.assertEqual([item["status_code"] for item in record["observations"]], statuses)
            self.assertTrue(all(item["response_body"] for item in record["observations"]))
        disposition = self.artifact("rejection-disposition.json")
        self.assertEqual(disposition["status"], "common-rejection-semantics-passed")
        self.assertEqual(disposition["classification"], "API validation class")
        self.assertIn("intentional cengine 400", disposition["disposition"])
        self.assertFalse(disposition["exact_class_oracle"])
        self.assertEqual(disposition["status_differences"], [
            {"source_kind": "named", "mode": "copy", "docker": 500, "cengine": 400},
            {"source_kind": "bind", "mode": "nocopy", "docker": 500, "cengine": 400},
        ])
        self.assert_clean(reference)
        self.assert_clean(client)

    def test_oracle_cengine_500_fails_but_saves_all_evidence_and_cleans_up(self):
        reference = FakeClient((500, 400, 400))
        client = FakeClient((400, 500, 400))
        with self.assertRaises(AssertionError):
            self.run_diagnostic(reference, client)
        record = self.artifact("cengine.json")
        self.assertEqual(record["status"], "failed")
        self.assertEqual([item["status_code"] for item in record["observations"]], [400, 500, 400])
        self.assertEqual(self.artifact("rejection-disposition.json")["status"], "failed")
        self.assert_clean(reference)
        self.assert_clean(client)

    def test_bad_reference_rejection_fails_before_cengine_with_partial_artifacts(self):
        reference = FakeClient((500,), explanation="storage unavailable")
        client = FakeClient()
        with self.assertRaises(AssertionError):
            self.run_diagnostic(reference, client)
        record = self.artifact("docker.json")
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["observations"][0]["explanation"], "storage unavailable")
        self.assertTrue(record["observations"][0]["volume_absent_after_cleanup"])
        self.assertEqual(self.artifact("rejection-disposition.json")["status"], "failed")
        self.assertFalse(client.created)
        self.assert_clean(reference)

    def test_six_existing_comparisons_unchanged_then_separate_diagnostic(self):
        expected = [
            ("test_empty_nocopy_volume_is_populated_by_later_copy", ("daemon", "client")),
            ("test_same_volume_alias_destinations_share_mutations", ("daemon", "client")),
            ("test_volume_file_subpath_over_new_and_existing_targets", ("daemon", "client")),
            ("test_missing_volume_subpath_fails_at_start", ("daemon", "client")),
            ("test_volume_remove_rejects_stopped_container_reference", ("client",)),
            ("test_rm_v_removes_anonymous_but_retains_named_volume", ("client",)),
        ]
        self.assertEqual(oracle.PRIMITIVE_CASES, expected)
        events = []
        with patch.object(oracle, "_run_primitive_case", side_effect=lambda *args: events.append(args[4])), \
                patch.object(oracle, "_run_invalid_copy_rejection_diagnostic",
                             side_effect=lambda *args: events.append("rejection-diagnostic")):
            oracle.test_curated_volume_primitives_match_reference(None, None, None, {}, self.root)
        self.assertEqual(events, [symbol for symbol, _ in expected] + ["rejection-diagnostic"])


if __name__ == "__main__":
    unittest.main()
