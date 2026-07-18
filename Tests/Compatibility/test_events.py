"""Docker event-stream compatibility contracts."""

from __future__ import annotations

import os
import json
import threading
import time

import docker
import pytest


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")


@pytest.mark.compat("EVT-001")
def test_filtered_container_events(client: docker.DockerClient):
    key = "dev.cengine.events"
    value = str(time.time_ns())
    name = f"compat-events-{value}"
    container = client.containers.create(IMAGE, command=["true"], name=name, labels={key: value})
    stream = client.events(
        decode=True,
        filters={"type": "container", "container": name, "label": f"{key}={value}"},
    )
    events: list[dict] = []
    actions: set[str] = set()
    ready = threading.Event()

    def consume() -> None:
        for event in stream:
            events.append(dict(event))
            actions.add(event["Action"])
            ready.set()
            if event.get("Action") == "destroy":
                return

    reader = threading.Thread(target=consume)
    reader.start()
    assert ready.wait(timeout=10), "event history did not establish the stream subscription"
    container.start()
    assert container.wait(timeout=60)["StatusCode"] == 0
    container.remove()
    reader.join(timeout=10)
    stream.close()
    assert not reader.is_alive()
    assert actions >= {"create", "start", "die", "destroy"}, json.dumps(events, indent=2)
    assert all(event["Type"] == "container" for event in events)


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
