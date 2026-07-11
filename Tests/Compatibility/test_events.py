"""Docker event-stream compatibility contracts."""

from __future__ import annotations

import os
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
    stream = client.events(
        decode=True,
        filters={"type": "container", "container": name, "label": f"{key}={value}"},
    )
    events: list[dict] = []

    def consume() -> None:
        for event in stream:
            events.append(event)
            if event.get("Action") == "destroy":
                return

    reader = threading.Thread(target=consume)
    reader.start()
    time.sleep(0.2)
    container = client.containers.create(IMAGE, command=["true"], name=name, labels={key: value})
    container.start()
    assert container.wait(timeout=60)["StatusCode"] == 0
    container.remove()
    reader.join(timeout=10)
    stream.close()
    assert not reader.is_alive()
    assert {event["Action"] for event in events} >= {"create", "start", "die", "destroy"}
    assert all(event["Type"] == "container" for event in events)
