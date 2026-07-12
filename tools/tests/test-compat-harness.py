#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "Tests" / "Compatibility"))

from harness import DOCKER_ENDPOINT_VARIABLES, docker_environment  # noqa: E402


def main() -> None:
    ambient = {
        "PATH": "/test/bin",
        "DOCKER_HOST": "tcp://ambient.example:2376",
        **{key: f"ambient-{key.lower()}" for key in DOCKER_ENDPOINT_VARIABLES},
    }
    environment = docker_environment(pathlib.Path("/tmp/cengine/docker.sock"), base=ambient)

    assert environment["PATH"] == ambient["PATH"]
    assert environment["DOCKER_HOST"] == "unix:///tmp/cengine/docker.sock"
    for key in DOCKER_ENDPOINT_VARIABLES:
        assert key not in environment

    explicit = docker_environment("tcp://127.0.0.1:2375", base={})
    assert explicit == {"DOCKER_HOST": "tcp://127.0.0.1:2375"}

    compatibility_root = REPO_ROOT / "Tests" / "Compatibility"
    for path in compatibility_root.glob("*.py"):
        if path.name == "harness.py":
            continue
        source = path.read_text()
        assert "DOCKER_HOST" not in source, f"{path} bypasses docker_environment"
        assert "os.environ.copy()" not in source, f"{path} copies an unsanitized environment"


if __name__ == "__main__":
    main()
