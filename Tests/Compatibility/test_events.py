"""Docker event-stream compatibility contracts."""

from __future__ import annotations

import os
import json
import time

import docker
import pytest


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")


@pytest.mark.compat("EVT-001")
def test_filtered_container_events(client: docker.DockerClient):
    key = "dev.cengine.events"
    value = str(time.time_ns())
    name = f"compat-events-{value}"
    response = client.api._get(
        client.api._url("/events"),
        params={"filters": json.dumps({"type": ["container"], "container": [name], "label": [f"{key}={value}"]})},
        stream=True, timeout=10,
    )
    events: list[dict] = []
    actions: set[str] = set()

    try:
        response.raise_for_status()
        # Response headers establish the subscription before generating events.
        container = client.containers.create(IMAGE, command=["true"], name=name, labels={key: value})
        container.start()
        assert container.wait(timeout=60)["StatusCode"] == 0
        container.remove()
        for line in response.iter_lines():
            if not line:
                continue
            event = json.loads(line)
            events.append(event)
            actions.add(event["Action"])
            if event.get("Action") == "destroy":
                break
    finally:
        response.close()
    assert actions >= {"create", "start", "die", "destroy"}, json.dumps(events, indent=2)
    assert all(event["Type"] == "container" for event in events)


@pytest.mark.compat("RTM-055")
def test_default_events_do_not_replay_deleted_containers(client: docker.DockerClient):
    key = "dev.cengine.events"
    value = str(time.time_ns())
    labels = {key: value}
    stale = client.containers.create(IMAGE, command=["true"], labels=labels)
    stale.remove()

    response = client.api._get(
        client.api._url("/events"),
        params={"filters": json.dumps({"type": ["container"], "label": [f"{key}={value}"]})},
        stream=True, timeout=10,
    )
    try:
        response.raise_for_status()
        live = client.containers.create(IMAGE, command=["true"], labels=labels)
        live.remove()
        stream = (json.loads(line) for line in response.iter_lines() if line)
        events = [next(stream), next(stream)]
        assert [event["Action"] for event in events] == ["create", "destroy"], events
        assert all(event["Actor"]["ID"] == live.id for event in events), events
    finally:
        response.close()


@pytest.mark.compat("EVT-002")
def test_historical_events_honor_time_window_and_jsonl(client: docker.DockerClient):
    name = f"compat-event-history-{time.time_ns()}"
    since = time.time() - 1
    container = client.containers.create(IMAGE, command=["true"], name=name)
    container.start()
    assert container.wait(timeout=60)["StatusCode"] == 0
    container.remove()
    until = time.time()

    response = client.api._get(
        client.api._url("/events"),
        params={"since": since, "until": until, "filters": json.dumps({"container": [name]})},
        headers={"Accept": "application/jsonl"}, stream=True,
    )
    try:
        events = [json.loads(line) for line in response.iter_lines() if line]
        assert response.headers["Content-Type"] == "application/jsonl"
    finally:
        response.close()
    assert {event["Action"] for event in events} >= {"create", "start", "die", "destroy"}


@pytest.mark.compat("EVT-003")
def test_historical_image_pull_and_load_events_honor_filters(client: docker.DockerClient):
    since = time.time() - 1
    image = client.images.pull(IMAGE)
    archive = b"".join(image.save(named=True))
    client.images.load(archive)
    until = time.time()

    response = client.api._get(
        client.api._url("/events"),
        params={
            "since": since,
            "until": until,
            "filters": json.dumps({
                "type": ["image"],
                "event": ["pull", "load"],
                "image": [IMAGE, image.id],
            }),
        },
        stream=True,
    )
    try:
        events = [json.loads(line) for line in response.iter_lines() if line]
    finally:
        response.close()

    assert {event["Action"] for event in events} >= {"pull", "load"}, json.dumps(events, indent=2)
    assert all(event["Type"] == "image" for event in events)
    assert all(event["Actor"]["Attributes"].get("name") for event in events)


@pytest.mark.compat("EVT-004")
def test_container_events_match_image_filter_with_tag_stripping(client: docker.DockerClient):
    name = f"compat-event-image-{time.time_ns()}"
    image_name = IMAGE.split("@", maxsplit=1)[0]
    leaf = image_name.rsplit("/", maxsplit=1)[-1]
    if ":" in leaf:
        image_name = image_name.rsplit(":", maxsplit=1)[0]

    since = time.time() - 1
    container = client.containers.create(IMAGE, command=["true"], name=name)
    container.start()
    assert container.wait(timeout=60)["StatusCode"] == 0
    container.remove()
    until = time.time()

    response = client.api._get(
        client.api._url("/events"),
        params={
            "since": since,
            "until": until,
            "filters": json.dumps({
                "type": ["container"],
                "container": [name],
                "image": [image_name],
            }),
        },
        stream=True,
    )
    try:
        events = [json.loads(line) for line in response.iter_lines() if line]
    finally:
        response.close()

    assert {event["Action"] for event in events} >= {"create", "start", "die", "destroy"}, json.dumps(events, indent=2)
    assert all(event["Actor"]["Attributes"].get("image") for event in events)


@pytest.mark.compat("EVT-005")
def test_event_filters_accept_boolean_maps_and_ignore_false_entries(client: docker.DockerClient):
    since = time.time() - 1
    image = client.images.get(IMAGE)
    client.images.load(b"".join(image.save(named=True)))
    container = client.containers.create(
        IMAGE, command=["true"], name=f"compat-event-map-{time.time_ns()}"
    )
    until = time.time()

    response = client.api._get(
        client.api._url("/events"),
        params={
            "since": since,
            "until": until,
            "filters": json.dumps({"type": {"container": True, "image": False}}),
        },
        stream=True,
    )
    try:
        events = [json.loads(line) for line in response.iter_lines() if line]
    finally:
        response.close()

    assert any(event["Actor"]["ID"] == container.id for event in events), json.dumps(events, indent=2)
    assert all(event["Type"] == "container" for event in events), json.dumps(events, indent=2)
